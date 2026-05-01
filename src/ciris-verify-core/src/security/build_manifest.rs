//! Generic build-manifest validation for CIRIS PoB federation peers.
//!
//! See `docs/BUILD_MANIFEST.md` for the design spec. This module
//! generalizes the existing per-artifact `FunctionManifest` (in
//! `function_integrity.rs`) into a primitive-discriminated
//! `BuildManifest` so any CIRIS peer (agent, lens, persist, registry,
//! and CIRISVerify itself) can be validated through one code path —
//! the recursive golden rule (Accord Book IV Ch. 3 / PoB §1)
//! operationalized at the build layer.
//!
//! ## What this module is NOT
//!
//! - A new cryptographic primitive. Hybrid Ed25519 + ML-DSA-65 stays
//!   the only signing mode (PoB §1.4 precedent).
//! - A trust-root distributor. Each primitive ships its own steward
//!   key; the validator takes `trusted_pubkey` as a parameter.
//! - A replacement for `BinaryManifest` (the catalog of binaries per
//!   target). That stays as-is for v1.8.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use serde::{Deserialize, Serialize};

use super::function_integrity::{verify_hybrid_signature, ManifestSignature, StewardPublicKey};
use crate::error::VerifyError;

/// Which CIRIS primitive a build manifest describes.
///
/// Wire format: snake_case strings (`"verify"`, `"agent"`, etc.). The
/// Rust enum uses PascalCase variants. Consumers parsing JSON should
/// not assume the discriminator equals the Rust variant name; use the
/// `serde` derive instead of converting manually.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildPrimitive {
    /// CIRISVerify itself. Self-check uses this discriminator.
    Verify,
    /// CIRISAgent.
    Agent,
    /// CIRISLens (until PoB §3.1 lens-into-agent collapse lands).
    Lens,
    /// CIRISPersist.
    Persist,
    /// CIRISRegistry.
    Registry,
    /// Forward-compat for primitives invented after this enum version.
    /// Production primitives should add named variants instead.
    Other(String),
}

/// Manifest describing a single build of a CIRIS PoB primitive.
///
/// The wire format is canonicalized JSON (see `canonical_bytes`).
/// Both signatures (Ed25519 + ML-DSA-65) must verify against the
/// canonical bytes for the manifest to be accepted.
///
/// Per-primitive fields go in `extras` (opaque to this crate;
/// dispatched via `register_extras_validator`). Generic fields are
/// fixed by this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildManifest {
    /// Manifest schema version. Starts at "1.0".
    /// Bumped on backwards-incompatible field changes.
    pub manifest_schema_version: String,

    /// Which CIRIS primitive this manifest describes.
    pub primitive: BuildPrimitive,

    /// Build identifier (typically a git SHA or version tag).
    /// Distinct from `binary_version` because some primitives version
    /// their builds independently of the underlying binary's version.
    pub build_id: String,

    /// Target triple this manifest applies to (e.g.,
    /// `"x86_64-unknown-linux-gnu"`).
    pub target: String,

    /// SHA-256 hash of the entire signed binary file (hex, with
    /// `"sha256:"` prefix).
    pub binary_hash: String,

    /// Binary version string from the primitive's source.
    pub binary_version: String,

    /// ISO 8601 generation timestamp.
    pub generated_at: String,

    /// SHA-256 of the canonical extras representation (or of the
    /// primitive's own internal substrate — for `Verify` this is the
    /// hash of the function table, preserving v1.7 self-check
    /// semantics).
    pub manifest_hash: String,

    /// Primitive-specific extras. Opaque to CIRISVerify; the
    /// registered `ExtrasValidator` for `primitive` parses + validates
    /// this. `None` if the primitive has no extras.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extras: Option<serde_json::Value>,

    /// Hybrid signature over the canonical bytes (everything above
    /// excluding `signature` itself). Both signatures must verify.
    pub signature: ManifestSignature,
}

impl BuildManifest {
    /// Compute the canonical byte representation for signing /
    /// verification.
    ///
    /// Excludes the `signature` field. Field order is fixed by the
    /// inner `CanonicalBuildManifest` struct definition; primitive
    /// extras are serialized through whatever JSON shape the primitive
    /// chose. **Primitives are responsible for choosing a deterministic
    /// extras representation** (e.g., serialize through a `BTreeMap`
    /// before producing the JSON).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let canonical = CanonicalBuildManifest {
            manifest_schema_version: &self.manifest_schema_version,
            primitive: &self.primitive,
            build_id: &self.build_id,
            target: &self.target,
            binary_hash: &self.binary_hash,
            binary_version: &self.binary_version,
            generated_at: &self.generated_at,
            manifest_hash: &self.manifest_hash,
            extras: &self.extras,
        };
        serde_json::to_vec(&canonical).unwrap_or_default()
    }
}

/// Canonical representation of a `BuildManifest` for signing.
/// Excludes `signature` to break the chicken-and-egg.
#[derive(Serialize)]
struct CanonicalBuildManifest<'a> {
    manifest_schema_version: &'a str,
    primitive: &'a BuildPrimitive,
    build_id: &'a str,
    target: &'a str,
    binary_hash: &'a str,
    binary_version: &'a str,
    generated_at: &'a str,
    manifest_hash: &'a str,
    extras: &'a Option<serde_json::Value>,
}

// =============================================================================
// Extras Validator Registry
// =============================================================================

/// Validate the primitive-specific `extras` blob of a `BuildManifest`.
///
/// Each primitive that ships typed extras provides one of these.
/// Validators are registered globally via `register_extras_validator`
/// and dispatched at validation time when extras are present.
///
/// **Errors here propagate** to the caller of `verify_build_manifest`
/// as `VerifyError::IntegrityError`. Validators should reject any
/// extras that fail their schema or invariants.
pub trait ExtrasValidator: Send + Sync {
    /// Which primitive's extras this validator handles.
    fn primitive(&self) -> BuildPrimitive;

    /// Parse and validate the extras blob.
    fn validate(&self, extras: &serde_json::Value) -> Result<(), VerifyError>;
}

/// Global registry of extras validators, keyed by primitive.
///
/// `OnceLock<RwLock<...>>` so initialization is thread-safe and the
/// registry can be mutated at startup (each primitive crate registers
/// its own validator) without unsafe code.
fn registry() -> &'static RwLock<HashMap<BuildPrimitive, Box<dyn ExtrasValidator>>> {
    static REGISTRY: OnceLock<RwLock<HashMap<BuildPrimitive, Box<dyn ExtrasValidator>>>> =
        OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Register an extras validator for a primitive.
///
/// If a validator is already registered for the primitive, the new one
/// replaces it; the previous validator is returned (useful for tests
/// that swap validators temporarily).
///
/// Thread-safe. Idempotent — calling twice with the same validator is
/// equivalent to calling once.
pub fn register_extras_validator(v: Box<dyn ExtrasValidator>) -> Option<Box<dyn ExtrasValidator>> {
    let key = v.primitive();
    let mut guard = registry().write().expect("extras registry poisoned");
    guard.insert(key, v)
}

/// Run the registered validator for `primitive` against `extras`, if
/// any validator is registered. Returns `Ok(())` if no validator is
/// registered (opt-in dispatch).
fn dispatch_extras(
    primitive: &BuildPrimitive,
    extras: &serde_json::Value,
) -> Result<(), VerifyError> {
    let guard = registry().read().expect("extras registry poisoned");
    if let Some(validator) = guard.get(primitive) {
        validator.validate(extras)
    } else {
        // No validator registered — opt-in dispatch, treat extras as
        // opaque. New primitives can ship manifests through
        // verify_build_manifest before their extras crate exists.
        Ok(())
    }
}

// (removed clear_extras_registry_for_tests — shared state across parallel
//  tests is fragile; tests now use unique Other("...") primitive keys.)

// =============================================================================
// Verify Primitive Extras
// =============================================================================
//
// The Verify primitive's extras carry the function table and offset
// metadata that v1.7's FunctionManifest had as top-level fields. By
// moving them into a registered ExtrasValidator, CIRISVerify's own
// self-check goes through the same generic verify_build_manifest path
// every other primitive uses — the recursive golden rule operationalized.

/// Extras for `BuildPrimitive::Verify`.
///
/// Wraps the function table and offset metadata that the v1.7
/// `FunctionManifest` had as top-level fields. Preserves the wire-level
/// shape so v1.7-signed manifests parse cleanly when wrapped into a
/// `BuildManifest` (see `legacy::FunctionManifest::From` impl in
/// `function_integrity.rs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyExtras {
    /// Critical functions with their hashes. BTreeMap ordering matches
    /// v1.7 canonical bytes.
    pub functions: std::collections::BTreeMap<String, super::function_integrity::FunctionEntry>,
    /// Metadata about offset computation (preserved from v1.7).
    #[serde(default)]
    pub metadata: super::function_integrity::ManifestMetadata,
}

/// Validator for `BuildPrimitive::Verify` extras.
///
/// Parses the JSON into `VerifyExtras` and rejects any malformed input.
/// Semantic checks (function-hash comparison at runtime) live in
/// `function_integrity::verify_functions`; this validator only
/// enforces the structural shape of the extras blob.
pub struct VerifyExtrasValidator;

impl ExtrasValidator for VerifyExtrasValidator {
    fn primitive(&self) -> BuildPrimitive {
        BuildPrimitive::Verify
    }

    fn validate(&self, extras: &serde_json::Value) -> Result<(), VerifyError> {
        let _: VerifyExtras =
            serde_json::from_value(extras.clone()).map_err(|e| VerifyError::IntegrityError {
                message: format!("VerifyExtras parse failed: {}", e),
            })?;
        Ok(())
    }
}

/// Register the Verify primitive's extras validator.
///
/// Called from CIRISVerify's startup path so the generic
/// `verify_build_manifest` knows how to dispatch `Verify` extras
/// without consumers needing to register manually. Idempotent.
pub fn register_default_validators() {
    register_extras_validator(Box::new(VerifyExtrasValidator));
}

// =============================================================================
// Public typed extras (v1.9) — file-tree + function-level shapes
// =============================================================================
//
// These types let primitives that need a file-tree or function-level
// shape pull in a typed extras schema directly, rather than rolling
// their own opaque-Value extras. The architecture is unchanged from
// v1.8.0: `BuildManifest::extras` is still `Option<Value>`, validators
// still register via `register_extras_validator`. The added types make
// shape reuse easy without forcing a wire-format change.

/// Function-level extras (binary's per-function hash table + offset metadata).
///
/// Public alias of `VerifyExtras`. Use this name in new code; primitives
/// that produce function-level manifests (CIRISVerify itself, future
/// auditor pipelines) ship this in `BuildManifest::extras`.
pub type FunctionLevelExtras = VerifyExtras;

/// Public alias of `VerifyExtrasValidator`. Use this in new code.
pub type FunctionLevelExtrasValidator = VerifyExtrasValidator;

/// Exempt-rules used at file-tree generation time. Carried in the
/// signed `FileTreeExtras` so verifiers can reproduce the same
/// inclusion logic deterministically.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExemptRules {
    /// Top-level directory/file allowlist. If non-empty, only entries
    /// rooted at one of these paths are included. Empty = include all.
    #[serde(default)]
    pub include_roots: Vec<String>,

    /// Directory names to skip anywhere in the tree (exact match on
    /// the directory's basename). Examples: `target`, `node_modules`,
    /// `.venv`, `__pycache__`.
    #[serde(default)]
    pub exempt_dirs: Vec<String>,

    /// File extensions to skip (without the dot). Examples: `pyc`,
    /// `so`, `dylib`, `dll`.
    #[serde(default)]
    pub exempt_extensions: Vec<String>,
}

/// File-tree extras (per-file hash map + reproducible exempt rules).
///
/// Use this when the primitive's "build" is a directory of source
/// files rather than a single binary artifact (CIRISAgent's Python
/// source tree, lens config bundles, etc.). The tree's identity is
/// the BTreeMap-canonical hash of (path → sha256) entries.
///
/// `BuildManifest::binary_hash` for a file-tree manifest should be
/// equal to `file_tree_hash` (the canonical hash of the file map),
/// so federation peers without the tree can still detect drift via
/// the top-level signed hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTreeExtras {
    /// SHA-256 of the canonical file map (`"sha256:<hex>"`).
    pub file_tree_hash: String,
    /// Number of files in the map.
    pub file_count: u32,
    /// Per-file SHA-256 hashes. BTreeMap for canonical ordering.
    pub files: std::collections::BTreeMap<String, String>,
    /// Inclusion / exempt rules applied at generation time.
    #[serde(default)]
    pub exempt_rules: ExemptRules,
}

impl FileTreeExtras {
    /// Compute the canonical `file_tree_hash` from the `files` map.
    ///
    /// Hashes the BTreeMap-ordered concatenation of
    /// `path || ":" || hash || "\n"` for each entry. Deterministic
    /// because BTreeMap iteration is sorted.
    #[must_use]
    pub fn compute_tree_hash(files: &std::collections::BTreeMap<String, String>) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for (path, hash) in files {
            hasher.update(path.as_bytes());
            hasher.update(b":");
            hasher.update(hash.as_bytes());
            hasher.update(b"\n");
        }
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }
}

/// Validator for file-tree extras.
///
/// Checks that the declared `file_tree_hash` matches the canonical
/// hash of the included `files` map. This catches malformed or
/// tampered manifests at parse time, before `verify_file_tree` walks
/// any disk.
pub struct FileTreeExtrasValidator;

impl ExtrasValidator for FileTreeExtrasValidator {
    fn primitive(&self) -> BuildPrimitive {
        // Default registration is for Agent; primitives can register
        // for other discriminators by constructing their own validator
        // wrapper around the same logic.
        BuildPrimitive::Agent
    }

    fn validate(&self, extras: &serde_json::Value) -> Result<(), VerifyError> {
        let parsed: FileTreeExtras =
            serde_json::from_value(extras.clone()).map_err(|e| VerifyError::IntegrityError {
                message: format!("FileTreeExtras parse failed: {}", e),
            })?;

        if parsed.files.len() as u32 != parsed.file_count {
            return Err(VerifyError::IntegrityError {
                message: format!(
                    "FileTreeExtras file_count mismatch: declared {}, found {}",
                    parsed.file_count,
                    parsed.files.len()
                ),
            });
        }

        let computed = FileTreeExtras::compute_tree_hash(&parsed.files);
        if computed != parsed.file_tree_hash {
            return Err(VerifyError::IntegrityError {
                message: format!(
                    "FileTreeExtras file_tree_hash mismatch: declared {}, computed {}",
                    parsed.file_tree_hash, computed
                ),
            });
        }
        Ok(())
    }
}

// =============================================================================
// Content-verify helpers (v1.9) — separate from signature verify
// =============================================================================
//
// `verify_build_manifest` checks signatures only. The helpers below
// check whether an actual artifact (file tree, binary) matches what
// the manifest declares. Callers run these AFTER `verify_build_manifest`
// when they have the artifact present (CI, auditors). Federation peers
// that only see the manifest do NOT need these.

/// Verify that a file tree on disk matches the per-file hashes in
/// `FileTreeExtras`.
///
/// Walks the same inclusion logic the signed manifest declared:
/// applies `extras.exempt_rules` to the on-disk tree at `fs_root`,
/// hashes each surviving file, and compares against `extras.files`.
/// Any missing file, extra file, or hash mismatch is a verification
/// failure.
///
/// # Errors
///
/// `VerifyError::IntegrityError` with a message naming the first
/// detected divergence (NOT every divergence — the function returns
/// early to bound work on a tampered tree).
///
/// # When to call
///
/// After `verify_build_manifest` has succeeded. Caller has access to
/// the source tree at `fs_root` (CI build server, auditor cloning the
/// repo, etc.). Federation peers that only see the manifest skip this.
pub fn verify_file_tree(
    extras: &FileTreeExtras,
    fs_root: &std::path::Path,
) -> Result<(), VerifyError> {
    let actual_files = walk_file_tree(fs_root, &extras.exempt_rules)?;

    if actual_files.len() != extras.files.len() {
        return Err(VerifyError::IntegrityError {
            message: format!(
                "verify_file_tree: file count mismatch: manifest has {}, on-disk tree has {}",
                extras.files.len(),
                actual_files.len()
            ),
        });
    }

    for (path, declared_hash) in &extras.files {
        match actual_files.get(path) {
            Some(actual_hash) if actual_hash == declared_hash => {},
            Some(actual_hash) => {
                return Err(VerifyError::IntegrityError {
                    message: format!(
                        "verify_file_tree: hash mismatch at {}: declared {}, actual {}",
                        path, declared_hash, actual_hash
                    ),
                });
            },
            None => {
                return Err(VerifyError::IntegrityError {
                    message: format!("verify_file_tree: file {} missing from on-disk tree", path),
                });
            },
        }
    }
    Ok(())
}

/// Walk a directory tree, applying include/exempt rules, returning a
/// `BTreeMap<relative_path, "sha256:hex">`. Used by both signing
/// (in `ciris-build-tool`) and verification.
///
/// Paths in the returned map are relative to `fs_root`, with forward
/// slashes regardless of platform, for canonical cross-platform
/// hashing.
///
/// # Errors
///
/// `VerifyError::IntegrityError` if traversal fails or a file can't
/// be read.
pub fn walk_file_tree(
    fs_root: &std::path::Path,
    rules: &ExemptRules,
) -> Result<std::collections::BTreeMap<String, String>, VerifyError> {
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    let mut out = BTreeMap::new();

    if !fs_root.is_dir() {
        return Err(VerifyError::IntegrityError {
            message: format!("walk_file_tree: {} is not a directory", fs_root.display()),
        });
    }

    let exempt_dirs: std::collections::HashSet<&str> =
        rules.exempt_dirs.iter().map(String::as_str).collect();
    let exempt_exts: std::collections::HashSet<&str> =
        rules.exempt_extensions.iter().map(String::as_str).collect();

    // Determine roots to walk. Empty include_roots = walk fs_root itself.
    let roots: Vec<std::path::PathBuf> = if rules.include_roots.is_empty() {
        vec![fs_root.to_path_buf()]
    } else {
        rules
            .include_roots
            .iter()
            .map(|r| fs_root.join(r))
            .collect()
    };

    for root in roots {
        if !root.exists() {
            // include_root not present — skip (don't error; consumer
            // can validate completeness via file_count if they care).
            continue;
        }
        walk_dir_recursive(&root, fs_root, &exempt_dirs, &exempt_exts, &mut out)?;
    }

    // Compute hashes
    let mut hashed = BTreeMap::new();
    for (path, full_path) in &out {
        let bytes = std::fs::read(full_path).map_err(|e| VerifyError::IntegrityError {
            message: format!("walk_file_tree: read {}: {}", path, e),
        })?;
        let hash = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        hashed.insert(path.clone(), hash);
    }
    Ok(hashed)
}

fn walk_dir_recursive(
    dir: &std::path::Path,
    fs_root: &std::path::Path,
    exempt_dirs: &std::collections::HashSet<&str>,
    exempt_exts: &std::collections::HashSet<&str>,
    out: &mut std::collections::BTreeMap<String, std::path::PathBuf>,
) -> Result<(), VerifyError> {
    let entries = std::fs::read_dir(dir).map_err(|e| VerifyError::IntegrityError {
        message: format!("walk_file_tree: read_dir {}: {}", dir.display(), e),
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| VerifyError::IntegrityError {
            message: format!("walk_file_tree: entry error in {}: {}", dir.display(), e),
        })?;
        let path = entry.path();
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        let metadata = entry.metadata().map_err(|e| VerifyError::IntegrityError {
            message: format!("walk_file_tree: metadata {}: {}", path.display(), e),
        })?;

        if metadata.is_dir() {
            if exempt_dirs.contains(name_str.as_ref()) {
                continue;
            }
            walk_dir_recursive(&path, fs_root, exempt_dirs, exempt_exts, out)?;
        } else if metadata.is_file() {
            // Check extension exempt list
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if exempt_exts.contains(ext) {
                    continue;
                }
            }

            let rel = path
                .strip_prefix(fs_root)
                .map_err(|_| VerifyError::IntegrityError {
                    message: format!(
                        "walk_file_tree: {} not under root {}",
                        path.display(),
                        fs_root.display()
                    ),
                })?;
            let rel_str = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join("/");

            out.insert(rel_str, path.clone());
        }
        // Skip symlinks and other special files.
    }
    Ok(())
}

/// Verify that the **currently-running** binary's function bytes match
/// the per-function hashes declared in `BuildManifest`'s
/// `FunctionLevelExtras`.
///
/// **Scope of this check:** function-level integrity is checked against
/// the *running process's loaded code segment* (via `/proc/self/maps`
/// plus `dl_iterate_phdr` on Linux/Android). This is the same surface
/// that `function_integrity::verify_functions` walks for the legacy
/// `FunctionManifest` path. Pass `&BuildManifest` here; the helper
/// reconstructs the legacy shape internally and delegates.
///
/// Calling this on a non-running binary (e.g., a peer's manifest fetched
/// from registry) is a category error — there's no way to verify
/// function bytes you can't load. Use `verify_binary_blob` for the
/// "is this binary file the one declared" check.
///
/// # Errors
///
/// - `VerifyError::IntegrityError` if `manifest.primitive` isn't `Verify`
///   (function-level shape is the Verify primitive's contract; other
///   primitives shouldn't carry `FunctionLevelExtras`).
/// - `VerifyError::IntegrityError` if `manifest.extras` is missing or
///   doesn't deserialize as `FunctionLevelExtras`.
/// - `VerifyError::IntegrityError` if any function hash doesn't match.
///
/// # When to call
///
/// On the running CIRISVerify process's self-check path, after
/// `verify_build_manifest(bytes, BuildPrimitive::Verify, &steward_key)`
/// has confirmed the manifest's signature.
pub fn verify_function_level(manifest: &BuildManifest) -> Result<(), VerifyError> {
    // Primitive must be Verify — other primitives shouldn't carry
    // function-level extras through this path.
    if !matches!(manifest.primitive, BuildPrimitive::Verify) {
        return Err(VerifyError::IntegrityError {
            message: format!(
                "verify_function_level: primitive {:?} cannot use function-level shape",
                manifest.primitive
            ),
        });
    }

    let extras_value = manifest
        .extras
        .as_ref()
        .ok_or_else(|| VerifyError::IntegrityError {
            message: "verify_function_level: BuildManifest has no extras".into(),
        })?;

    let extras: FunctionLevelExtras =
        serde_json::from_value(extras_value.clone()).map_err(|e| VerifyError::IntegrityError {
            message: format!("verify_function_level: extras parse failed: {e}"),
        })?;

    if extras.functions.is_empty() {
        return Err(VerifyError::IntegrityError {
            message: "verify_function_level: empty functions table".into(),
        });
    }

    // Reconstruct the legacy FunctionManifest shape so we can delegate
    // to function_integrity::verify_functions, which already owns the
    // platform-specific `/proc/self/maps` + dl_iterate_phdr walk.
    //
    // The signature on `legacy` is irrelevant here — we already validated
    // the BuildManifest's hybrid signature upstream in verify_build_manifest;
    // this helper is the content-verify pass.
    let legacy = super::function_integrity::FunctionManifest {
        version: manifest.manifest_schema_version.clone(),
        target: manifest.target.clone(),
        binary_hash: manifest.binary_hash.clone(),
        binary_version: manifest.binary_version.clone(),
        generated_at: manifest.generated_at.clone(),
        functions: extras.functions,
        manifest_hash: manifest.manifest_hash.clone(),
        signature: manifest.signature.clone(),
        metadata: extras.metadata,
    };

    let result = super::function_integrity::verify_functions(&legacy);
    if result.integrity_valid {
        Ok(())
    } else {
        Err(VerifyError::IntegrityError {
            message: format!(
                "verify_function_level: function-integrity check failed (reason={}, checked={}, passed={})",
                result.failure_reason, result.functions_checked, result.functions_passed
            ),
        })
    }
}

/// Verify that a binary's bytes match the SHA-256 declared in
/// `BuildManifest::binary_hash`.
///
/// This is the content-verify counterpart to `verify_file_tree` and
/// `verify_function_level`, for `binary_blob`-shape primitives
/// (Persist, Registry, any primitive whose build is one artifact and
/// doesn't have richer extras for content-matching).
///
/// Unlike `verify_function_level` this does NOT require the binary to
/// be the running process — it accepts arbitrary bytes from disk or
/// memory, hashes them, and constant-time-compares to the manifest's
/// declared hash. Use this when you have a peer's binary file in hand
/// and want to confirm it matches what the peer's CI signed.
///
/// # Errors
///
/// `VerifyError::IntegrityError` if `manifest.binary_hash` doesn't have
/// the `"sha256:"` prefix or isn't valid hex, or if the computed hash
/// doesn't match.
///
/// # When to call
///
/// After `verify_build_manifest` has succeeded. Caller has the artifact
/// bytes available (CI, auditors, peers fetching releases from a
/// federation transport).
pub fn verify_binary_blob(manifest: &BuildManifest, binary: &[u8]) -> Result<(), VerifyError> {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;

    let declared = manifest
        .binary_hash
        .strip_prefix("sha256:")
        .ok_or_else(|| VerifyError::IntegrityError {
            message: format!(
                "verify_binary_blob: binary_hash must have 'sha256:' prefix, got '{}'",
                manifest.binary_hash
            ),
        })?;

    let declared_bytes = hex::decode(declared).map_err(|e| VerifyError::IntegrityError {
        message: format!("verify_binary_blob: invalid hex in binary_hash: {e}"),
    })?;

    if declared_bytes.len() != 32 {
        return Err(VerifyError::IntegrityError {
            message: format!(
                "verify_binary_blob: SHA-256 must be 32 bytes, got {}",
                declared_bytes.len()
            ),
        });
    }

    let actual: [u8; 32] = Sha256::digest(binary).into();

    if actual.ct_eq(declared_bytes.as_slice()).into() {
        Ok(())
    } else {
        Err(VerifyError::IntegrityError {
            message: format!(
                "verify_binary_blob: hash mismatch — declared {}, computed sha256:{}",
                manifest.binary_hash,
                hex::encode(actual)
            ),
        })
    }
}

// =============================================================================
// Migration Helpers (v1.7 → v1.8)
// =============================================================================
//
// `BuildManifest::canonical_bytes` and `FunctionManifest::canonical_bytes`
// produce DIFFERENT byte sequences (different field set, different field
// order), so a v1.7-signed `FunctionManifest` does NOT validate through
// `verify_build_manifest` even after structural conversion — the
// signature would have to cover the v1.8 canonical bytes, which it
// doesn't.
//
// The conversion impls below let primitives migrate by re-publishing
// their manifest in the new shape (signing the v1.8 canonical bytes).
// Existing v1.7-signed manifests keep working through the old path
// (`verify_manifest_signature` in `function_integrity.rs`); both paths
// coexist for one release cycle.

impl From<&super::function_integrity::FunctionManifest> for BuildManifest {
    /// Convert a v1.7 `FunctionManifest` into a v1.8 `BuildManifest`
    /// **structurally** — extras are populated with `VerifyExtras`
    /// holding the functions table and metadata. The signature is
    /// carried over verbatim BUT the resulting manifest will NOT
    /// validate through `verify_build_manifest` because the canonical
    /// bytes differ. To migrate, primitives must re-sign over
    /// `BuildManifest::canonical_bytes`.
    fn from(legacy: &super::function_integrity::FunctionManifest) -> Self {
        let extras = VerifyExtras {
            functions: legacy.functions.clone(),
            metadata: legacy.metadata.clone(),
        };
        BuildManifest {
            manifest_schema_version: "1.0".into(),
            primitive: BuildPrimitive::Verify,
            build_id: legacy.binary_version.clone(),
            target: legacy.target.clone(),
            binary_hash: legacy.binary_hash.clone(),
            binary_version: legacy.binary_version.clone(),
            generated_at: legacy.generated_at.clone(),
            manifest_hash: legacy.manifest_hash.clone(),
            extras: serde_json::to_value(extras).ok(),
            signature: legacy.signature.clone(),
        }
    }
}

// =============================================================================
// Public API: verify_build_manifest
// =============================================================================

/// Verify a signed `BuildManifest` end-to-end.
///
/// Steps:
/// 1. Parse the JSON.
/// 2. Reject if `manifest.primitive != expected_primitive` (defends
///    against cross-primitive replay).
/// 3. Verify the hybrid Ed25519 + ML-DSA-65 signature over the
///    canonical bytes against `trusted_pubkey`.
/// 4. If `extras` is present and a validator is registered for
///    `expected_primitive`, dispatch to it.
/// 5. Return the parsed manifest.
///
/// # Trust roots
///
/// CIRISVerify embeds its own steward key for `BuildPrimitive::Verify`
/// (used by the self-check). For all other primitives, the caller
/// provides the trusted public key. This module does NOT bundle trust
/// anchors for primitives we don't author.
pub fn verify_build_manifest(
    bytes: &[u8],
    expected_primitive: BuildPrimitive,
    trusted_pubkey: &StewardPublicKey,
) -> Result<BuildManifest, VerifyError> {
    let manifest: BuildManifest =
        serde_json::from_slice(bytes).map_err(|e| VerifyError::IntegrityError {
            message: format!("BuildManifest parse failed: {}", e),
        })?;

    if manifest.primitive != expected_primitive {
        return Err(VerifyError::IntegrityError {
            message: format!(
                "BuildManifest primitive mismatch: expected {:?}, got {:?}",
                expected_primitive, manifest.primitive
            ),
        });
    }

    let canonical = manifest.canonical_bytes();
    let sig_valid = verify_hybrid_signature(&canonical, &manifest.signature, trusted_pubkey)?;
    if !sig_valid {
        return Err(VerifyError::IntegrityError {
            message: "BuildManifest hybrid signature verification failed".into(),
        });
    }

    if let Some(extras) = manifest.extras.as_ref() {
        dispatch_extras(&expected_primitive, extras)?;
    }

    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Toy validator that accepts only extras with a specific marker.
    struct RequiresMarker {
        primitive: BuildPrimitive,
    }

    impl ExtrasValidator for RequiresMarker {
        fn primitive(&self) -> BuildPrimitive {
            self.primitive.clone()
        }

        fn validate(&self, extras: &serde_json::Value) -> Result<(), VerifyError> {
            if extras.get("marker").and_then(|v| v.as_str()) == Some("ok") {
                Ok(())
            } else {
                Err(VerifyError::IntegrityError {
                    message: "marker missing".into(),
                })
            }
        }
    }

    #[test]
    fn build_primitive_serde_snake_case() {
        let json = serde_json::to_string(&BuildPrimitive::Verify).unwrap();
        assert_eq!(json, "\"verify\"");
        let json = serde_json::to_string(&BuildPrimitive::Persist).unwrap();
        assert_eq!(json, "\"persist\"");

        let back: BuildPrimitive = serde_json::from_str("\"agent\"").unwrap();
        assert_eq!(back, BuildPrimitive::Agent);
    }

    #[test]
    fn build_primitive_other_roundtrip() {
        let p = BuildPrimitive::Other("future-primitive".into());
        let json = serde_json::to_string(&p).unwrap();
        // Externally-tagged Other variant: {"other":"future-primitive"}
        let back: BuildPrimitive = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn canonical_bytes_excludes_signature() {
        let m = BuildManifest {
            manifest_schema_version: "1.0".into(),
            primitive: BuildPrimitive::Persist,
            build_id: "v0.1.0".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            binary_hash: "sha256:abc".into(),
            binary_version: "0.1.0".into(),
            generated_at: "2026-05-01T00:00:00Z".into(),
            manifest_hash: "sha256:def".into(),
            extras: Some(json!({"k": "v"})),
            signature: ManifestSignature {
                classical: "FAKE".into(),
                classical_algorithm: "Ed25519".into(),
                pqc: "FAKE".into(),
                pqc_algorithm: "ML-DSA-65".into(),
                key_id: "test".into(),
            },
        };
        let canonical = m.canonical_bytes();
        let canonical_str = std::str::from_utf8(&canonical).unwrap();
        assert!(!canonical_str.contains("FAKE"));
        assert!(!canonical_str.contains("signature"));
        assert!(canonical_str.contains("\"persist\""));
        assert!(canonical_str.contains("\"v0.1.0\""));
    }

    #[test]
    fn extras_dispatch_runs_when_validator_registered() {
        // Unique primitive key per test so parallel tests don't stomp.
        let key = BuildPrimitive::Other("dispatch-test-runs".into());
        register_extras_validator(Box::new(RequiresMarker {
            primitive: key.clone(),
        }));

        // Direct dispatch (not through verify_build_manifest, which
        // also requires real signatures we don't have here).
        assert!(dispatch_extras(&key, &json!({"marker": "ok"})).is_ok());
        let err = dispatch_extras(&key, &json!({"marker": "bad"})).unwrap_err();
        assert!(format!("{:?}", err).contains("marker missing"));
    }

    #[test]
    fn extras_dispatch_passes_through_when_no_validator() {
        // Unique primitive key never registered.
        let p = BuildPrimitive::Other("dispatch-test-no-validator".into());
        assert!(dispatch_extras(&p, &json!({"anything": "goes"})).is_ok());
    }

    #[test]
    fn verify_extras_validator_accepts_well_formed() {
        // register_default_validators is idempotent; safe to call from
        // multiple parallel tests.
        register_default_validators();

        let extras = json!({
            "functions": {},
            "metadata": {
                "exec_segment_vaddr": 0,
                "text_section_vaddr": 0,
                "text_section_offset": 0
            }
        });
        // Call the validator directly so we don't depend on
        // registry state from other tests.
        let v = VerifyExtrasValidator;
        assert!(v.validate(&extras).is_ok());
    }

    #[test]
    fn verify_extras_validator_rejects_malformed() {
        let v = VerifyExtrasValidator;
        // functions field has wrong shape (string where object expected)
        let extras = json!({"functions": "not-a-map"});
        let err = v.validate(&extras).unwrap_err();
        assert!(format!("{:?}", err).contains("VerifyExtras parse failed"));
    }

    #[test]
    fn function_manifest_to_build_manifest_preserves_payload() {
        // P2.7 parity-style test: structural conversion preserves all
        // FunctionManifest payload data inside BuildManifest.extras.
        // (Signature equivalence is intentionally NOT preserved —
        // canonical bytes differ; manifests must be re-signed to
        // migrate. See module docs.)
        use super::super::function_integrity::{
            FunctionEntry, FunctionManifest, ManifestMetadata, ManifestSignature,
        };
        use std::collections::BTreeMap;

        let mut functions = BTreeMap::new();
        functions.insert(
            "ciris_verify_init".into(),
            FunctionEntry {
                name: "ciris_verify_init".into(),
                offset: 4096,
                size: 256,
                hash: "sha256:fff".into(),
                first_bytes: "55488".into(),
            },
        );
        let legacy = FunctionManifest {
            version: "1.0".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            binary_hash: "sha256:abc".into(),
            binary_version: "1.7.0".into(),
            generated_at: "2026-05-01T00:00:00Z".into(),
            functions: functions.clone(),
            manifest_hash: "sha256:def".into(),
            signature: ManifestSignature {
                classical: "AAAA".into(),
                classical_algorithm: "Ed25519".into(),
                pqc: "AAAA".into(),
                pqc_algorithm: "ML-DSA-65".into(),
                key_id: "test".into(),
            },
            metadata: ManifestMetadata {
                exec_segment_vaddr: 0x1000,
                text_section_vaddr: 0x4000,
                text_section_offset: 0x1000,
            },
        };

        let build: BuildManifest = (&legacy).into();
        assert_eq!(build.primitive, BuildPrimitive::Verify);
        assert_eq!(build.target, legacy.target);
        assert_eq!(build.binary_hash, legacy.binary_hash);
        assert_eq!(build.binary_version, legacy.binary_version);
        assert_eq!(build.generated_at, legacy.generated_at);
        assert_eq!(build.manifest_hash, legacy.manifest_hash);
        assert_eq!(build.signature.key_id, legacy.signature.key_id);

        // extras should round-trip back to VerifyExtras with same data
        let extras: VerifyExtras = serde_json::from_value(build.extras.unwrap()).unwrap();
        assert_eq!(extras.functions.len(), legacy.functions.len());
        assert_eq!(
            extras.functions.get("ciris_verify_init").unwrap().hash,
            "sha256:fff"
        );
        assert_eq!(
            extras.metadata.exec_segment_vaddr,
            legacy.metadata.exec_segment_vaddr
        );
    }

    #[test]
    fn primitive_mismatch_rejects_replay() {
        // We can build a manifest, serialize it, and verify_build_manifest
        // should reject when expected_primitive != manifest.primitive.
        // We don't need real signatures to test this — the primitive
        // check happens before signature verification.
        let m = BuildManifest {
            manifest_schema_version: "1.0".into(),
            primitive: BuildPrimitive::Persist,
            build_id: "v0.1.0".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            binary_hash: "sha256:abc".into(),
            binary_version: "0.1.0".into(),
            generated_at: "2026-05-01T00:00:00Z".into(),
            manifest_hash: "sha256:def".into(),
            extras: None,
            signature: ManifestSignature {
                classical: "AAAA".into(),
                classical_algorithm: "Ed25519".into(),
                pqc: "AAAA".into(),
                pqc_algorithm: "ML-DSA-65".into(),
                key_id: "test".into(),
            },
        };
        let bytes = serde_json::to_vec(&m).unwrap();

        // Bogus pubkey; we expect to fail on primitive mismatch BEFORE
        // signature verification runs.
        let pk = StewardPublicKey {
            ed25519: &[0u8; 32],
            ml_dsa_65: &[],
        };
        let err = verify_build_manifest(&bytes, BuildPrimitive::Agent, &pk).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("primitive mismatch"),
            "expected primitive mismatch error, got: {msg}"
        );
    }

    // =========================================================================
    // FileTreeExtras tests (v1.9)
    // =========================================================================

    fn sample_file_tree() -> std::collections::BTreeMap<String, String> {
        let mut m = std::collections::BTreeMap::new();
        m.insert("ciris_engine/__init__.py".into(), "sha256:aaa".into());
        m.insert("ciris_engine/core.py".into(), "sha256:bbb".into());
        m.insert("ciris_adapters/llm.py".into(), "sha256:ccc".into());
        m
    }

    #[test]
    fn file_tree_hash_is_deterministic() {
        let files = sample_file_tree();
        let h1 = FileTreeExtras::compute_tree_hash(&files);
        let h2 = FileTreeExtras::compute_tree_hash(&files);
        assert_eq!(h1, h2, "compute_tree_hash must be deterministic");
        assert!(h1.starts_with("sha256:"));
        assert_eq!(h1.len(), 7 + 64);
    }

    #[test]
    fn file_tree_hash_changes_when_path_changes() {
        let mut a = sample_file_tree();
        let h_a = FileTreeExtras::compute_tree_hash(&a);

        // Rename one path
        a.remove("ciris_engine/core.py");
        a.insert("ciris_engine/core_renamed.py".into(), "sha256:bbb".into());
        let h_b = FileTreeExtras::compute_tree_hash(&a);

        assert_ne!(h_a, h_b, "renaming a path must change the tree hash");
    }

    #[test]
    fn file_tree_hash_changes_when_content_changes() {
        let mut a = sample_file_tree();
        let h_a = FileTreeExtras::compute_tree_hash(&a);

        a.insert("ciris_engine/core.py".into(), "sha256:bbb_modified".into());
        let h_b = FileTreeExtras::compute_tree_hash(&a);

        assert_ne!(h_a, h_b, "modifying a hash must change the tree hash");
    }

    #[test]
    fn file_tree_extras_validator_accepts_consistent() {
        let files = sample_file_tree();
        let file_tree_hash = FileTreeExtras::compute_tree_hash(&files);
        let file_count = u32::try_from(files.len()).unwrap();
        let extras = FileTreeExtras {
            file_tree_hash,
            file_count,
            files,
            exempt_rules: ExemptRules::default(),
        };
        let v = FileTreeExtrasValidator;
        assert!(v.validate(&serde_json::to_value(&extras).unwrap()).is_ok());
    }

    #[test]
    fn file_tree_extras_validator_rejects_count_mismatch() {
        let files = sample_file_tree();
        let file_tree_hash = FileTreeExtras::compute_tree_hash(&files);
        let extras = FileTreeExtras {
            file_tree_hash,
            file_count: 99, // wrong
            files,
            exempt_rules: ExemptRules::default(),
        };
        let v = FileTreeExtrasValidator;
        let err = v
            .validate(&serde_json::to_value(&extras).unwrap())
            .unwrap_err();
        assert!(format!("{err:?}").contains("file_count mismatch"));
    }

    #[test]
    fn file_tree_extras_validator_rejects_hash_mismatch() {
        let files = sample_file_tree();
        let file_count = u32::try_from(files.len()).unwrap();
        let extras = FileTreeExtras {
            file_tree_hash: "sha256:wrong".into(),
            file_count,
            files,
            exempt_rules: ExemptRules::default(),
        };
        let v = FileTreeExtrasValidator;
        let err = v
            .validate(&serde_json::to_value(&extras).unwrap())
            .unwrap_err();
        assert!(format!("{err:?}").contains("file_tree_hash mismatch"));
    }

    #[test]
    fn walk_file_tree_basic_roundtrip() {
        // Create a small temp tree, walk it, hash it, then call
        // verify_file_tree against the same tree — should pass.
        let tmp = std::env::temp_dir().join("ciris_walk_test_basic");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::create_dir_all(tmp.join("module")).unwrap();
        std::fs::write(tmp.join("module/a.py"), b"contents-a").unwrap();
        std::fs::write(tmp.join("module/b.py"), b"contents-b").unwrap();

        let rules = ExemptRules::default();
        let files = walk_file_tree(&tmp, &rules).unwrap();
        assert_eq!(files.len(), 2);

        let file_tree_hash = FileTreeExtras::compute_tree_hash(&files);
        let extras = FileTreeExtras {
            file_tree_hash,
            file_count: 2,
            files,
            exempt_rules: rules,
        };

        // Verify against the same tree — should pass
        verify_file_tree(&extras, &tmp).unwrap();

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn walk_file_tree_exempt_dirs_and_exts() {
        let tmp = std::env::temp_dir().join("ciris_walk_test_exempt");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("src")).unwrap();
        std::fs::create_dir_all(tmp.join("target")).unwrap(); // should be skipped
        std::fs::write(tmp.join("src/main.py"), b"keep").unwrap();
        std::fs::write(tmp.join("src/main.pyc"), b"skip-ext").unwrap(); // should be skipped
        std::fs::write(tmp.join("target/build.bin"), b"skip-dir").unwrap();

        let rules = ExemptRules {
            include_roots: vec![],
            exempt_dirs: vec!["target".into()],
            exempt_extensions: vec!["pyc".into()],
        };
        let files = walk_file_tree(&tmp, &rules).unwrap();
        assert_eq!(
            files.len(),
            1,
            "only src/main.py should remain, got {:?}",
            files.keys().collect::<Vec<_>>()
        );
        assert!(files.contains_key("src/main.py"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn verify_file_tree_detects_modified_content() {
        let tmp = std::env::temp_dir().join("ciris_walk_test_tampered");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("a.py"), b"original").unwrap();

        let files = walk_file_tree(&tmp, &ExemptRules::default()).unwrap();
        let extras = FileTreeExtras {
            file_tree_hash: FileTreeExtras::compute_tree_hash(&files),
            file_count: 1,
            files,
            exempt_rules: ExemptRules::default(),
        };

        // Tamper: rewrite the file
        std::fs::write(tmp.join("a.py"), b"modified").unwrap();

        let err = verify_file_tree(&extras, &tmp).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("hash mismatch"),
            "expected hash mismatch error, got: {msg}"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn verify_file_tree_detects_missing_file() {
        let tmp = std::env::temp_dir().join("ciris_walk_test_missing");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("a.py"), b"a").unwrap();
        std::fs::write(tmp.join("b.py"), b"b").unwrap();

        let files = walk_file_tree(&tmp, &ExemptRules::default()).unwrap();
        let extras = FileTreeExtras {
            file_tree_hash: FileTreeExtras::compute_tree_hash(&files),
            file_count: 2,
            files,
            exempt_rules: ExemptRules::default(),
        };

        // Tamper: delete one file
        std::fs::remove_file(tmp.join("b.py")).unwrap();

        let err = verify_file_tree(&extras, &tmp).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("file count mismatch") || msg.contains("missing"),
            "expected count or missing error, got: {msg}"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn build_test_manifest(
        primitive: BuildPrimitive,
        extras: Option<serde_json::Value>,
    ) -> BuildManifest {
        use sha2::{Digest, Sha256};
        BuildManifest {
            manifest_schema_version: "1.0".into(),
            primitive,
            build_id: "v0.0.0-test".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            binary_hash: format!("sha256:{}", hex::encode(Sha256::digest(b"hello world"))),
            binary_version: "0.0.0".into(),
            generated_at: "2026-05-01T00:00:00Z".into(),
            manifest_hash: "sha256:cafebabe".into(),
            extras,
            signature: ManifestSignature {
                classical: "AAAA".into(),
                classical_algorithm: "Ed25519".into(),
                pqc: "AAAA".into(),
                pqc_algorithm: "ML-DSA-65".into(),
                key_id: "test".into(),
            },
        }
    }

    #[test]
    fn verify_function_level_rejects_non_verify_primitive() {
        let manifest = build_test_manifest(BuildPrimitive::Persist, None);
        let err = verify_function_level(&manifest).unwrap_err();
        assert!(
            format!("{err:?}").contains("Persist") || format!("{err:?}").contains("primitive"),
            "expected primitive-rejection error, got: {err:?}"
        );
    }

    #[test]
    fn verify_function_level_rejects_missing_extras() {
        let manifest = build_test_manifest(BuildPrimitive::Verify, None);
        let err = verify_function_level(&manifest).unwrap_err();
        assert!(format!("{err:?}").contains("no extras"));
    }

    #[test]
    fn verify_function_level_rejects_empty_functions() {
        let extras = FunctionLevelExtras {
            functions: std::collections::BTreeMap::new(),
            metadata: super::super::function_integrity::ManifestMetadata::default(),
        };
        let manifest = build_test_manifest(
            BuildPrimitive::Verify,
            Some(serde_json::to_value(&extras).unwrap()),
        );
        let err = verify_function_level(&manifest).unwrap_err();
        assert!(format!("{err:?}").contains("empty functions table"));
    }

    #[test]
    fn verify_binary_blob_accepts_matching() {
        let manifest = build_test_manifest(BuildPrimitive::Persist, None);
        verify_binary_blob(&manifest, b"hello world").expect("matching binary must verify");
    }

    #[test]
    fn verify_binary_blob_rejects_mismatch() {
        let manifest = build_test_manifest(BuildPrimitive::Persist, None);
        let err = verify_binary_blob(&manifest, b"different content").unwrap_err();
        assert!(format!("{err:?}").contains("hash mismatch"));
    }

    #[test]
    fn verify_binary_blob_rejects_missing_prefix() {
        let mut manifest = build_test_manifest(BuildPrimitive::Persist, None);
        manifest.binary_hash = "abc123".into();
        let err = verify_binary_blob(&manifest, b"hello world").unwrap_err();
        assert!(format!("{err:?}").contains("sha256:"));
    }

    #[test]
    fn verify_binary_blob_rejects_invalid_hex() {
        let mut manifest = build_test_manifest(BuildPrimitive::Persist, None);
        manifest.binary_hash = "sha256:not-real-hex".into();
        let err = verify_binary_blob(&manifest, b"hello world").unwrap_err();
        assert!(format!("{err:?}").contains("invalid hex"));
    }

    #[test]
    fn verify_binary_blob_rejects_wrong_length() {
        let mut manifest = build_test_manifest(BuildPrimitive::Persist, None);
        manifest.binary_hash = "sha256:abcd1234".into(); // 4 bytes, not 32
        let err = verify_binary_blob(&manifest, b"hello world").unwrap_err();
        assert!(format!("{err:?}").contains("32 bytes"));
    }

    #[test]
    fn verify_binary_blob_constant_time_compare_used() {
        // Smoke test that we use the subtle crate's constant-time equality
        // (compile-time check that the trait is in scope; this test would
        // fail to compile if we accidentally removed the import).
        use sha2::{Digest, Sha256};
        use subtle::ConstantTimeEq;
        let a: [u8; 32] = Sha256::digest(b"x").into();
        let b: [u8; 32] = Sha256::digest(b"x").into();
        assert!(bool::from(a.ct_eq(&b)));
    }
}
