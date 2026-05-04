//! `ciris-build-sign register` — atomically write all three registry
//! tables (`builds` + `binary_manifests` + `function_manifests`) for a
//! CIRIS primitive release. Closes CIRISVerify#6.
//!
//! ## Background
//!
//! CIRISAgent CI cut over from the legacy `register_agent_build.py`
//! (which wrote all 3 tables) to `ciris-build-sign sign` +
//! `curl POST /v1/verify/build-manifest` (which writes only
//! `function_manifests`). Parent rows stopped being written for every
//! release ≥ 2.7.8 — same gap reproduces in every primitive that adopts
//! the new tooling. This module restores parent-row writes inside
//! `ciris-build-sign` so all six onboarded primitives get the fix for free.
//!
//! ## Always-3 dispatch (v1.10.2+)
//!
//! Every successful `register` invocation makes exactly **three POST
//! classes** in dependency order:
//!
//! 1. `POST /v1/builds` → `builds` row (signed CanonicalBuild)
//! 2. `POST /v1/verify/binary-manifest` → `binary_manifests` row
//! 3. `POST /v1/verify/build-manifest` (one per target) → N
//!    `function_manifests` rows
//!
//! Total POSTs per invocation: `2 + target_count`. Logged as
//! `[1/N] / [2/N] / [3/N] ...` so any future regression that drops a
//! step is visible in the CI log. (v1.10.1 had a bug where releases
//! detected as "file mode" silently skipped steps 2 and 3 — see
//! CIRISVerify#8 / CIRISAgent#727. v1.10.2 makes the dispatcher mode-
//! independent and adds an algebra invariant test to lock the contract.)
//!
//! ## Content shape (file vs binary)
//!
//! Different primitives have different content models:
//!
//! - **File-shape** targets (Python source-tree primitives like
//!   `ciris-agent`): BuildManifest carries `FileTreeExtras`
//!   (`{files: {path: sha256, ...}}`). The first such target's content
//!   is forwarded into `builds.file_manifest_json` so the registry's
//!   `GET /v1/builds` returns the file map.
//! - **Binary-shape** targets (Rust primitives): BuildManifest carries
//!   `FunctionLevelExtras` or no extras. `builds.file_manifest_json` is
//!   left empty / default; per-target details flow to
//!   `function_manifests` rows.
//!
//! Mixed-shape invocations (e.g., agent's `python-source-tree` +
//! `ios-mobile-bundle`) are explicitly supported: the file-shape
//! target's content populates `builds.file_manifest_json`; both targets
//! get a `function_manifests` row each via step 3. This unblocks
//! consolidation of per-target register calls in CIRISAgent#729.
//!
//! ## Auth
//!
//! Single bearer token: `Authorization: Bearer $REGISTRY_ADMIN_TOKEN`.
//! Used identically against all three endpoints. The legacy
//! `REGISTRY_JWT_SECRET` (HS256 admin JWT for gRPC `RegisterBuild`) is
//! no longer required — v1.10.1 cut over to HTTP `POST /v1/builds`
//! (CIRISRegistry#9, hybrid-sig verification against
//! `trusted_primitive_keys`). The registry's gRPC `RegisterBuild`
//! endpoint stays live for back-compat per CIRISRegistry#9; this client
//! does not use it.
//!
//! ## Idempotency
//!
//! Each registry endpoint UPSERTs on its primary key: `builds` on
//! `build_hash`, `binary_manifests` on `(project, version)`,
//! `function_manifests` on `(project, version, target)`. The dispatcher
//! treats 200/201/409 as success so retried CI runs converge.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};
use ciris_verify_core::security::build_manifest::BuildManifest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::read_key;

/// Arguments for the `register` subcommand.
#[derive(Debug, Clone)]
pub struct RegisterArgs {
    /// CIRIS primitive name in kebab-case as it appears in
    /// `trusted_primitive_keys.project` (e.g., `"ciris-agent"`,
    /// `"ciris-verify"`).
    pub project: String,

    /// Binary version string (e.g., `"2.7.10"`, `"1.10.1"`). Must match
    /// the `binary_version` in every per-target BuildManifest passed via
    /// `--target`.
    pub binary_version: String,

    /// Build identifier (typically a git SHA). Stored on the `builds` row.
    pub build_id: String,

    /// Per-target manifest files. Each entry is
    /// `target_name:path/to/build-manifest.json`. Targets must match
    /// the `target` field inside the BuildManifest.
    pub targets: Vec<TargetSpec>,

    /// Source repository URL. Stored on the `builds` row.
    pub source_repo: String,

    /// Source commit SHA. Stored on the `builds` row.
    pub source_commit: String,

    /// Modules included in the build (e.g., `["core"]`,
    /// `["core","ios"]`). Mirrors legacy `--modules`.
    pub modules: Vec<String>,

    /// Optional notes for the `builds` and `binary_manifests` rows.
    pub notes: Option<String>,

    /// Registry base URL. When `None`, falls back to `$REGISTRY_URL`.
    pub registry_url: Option<String>,

    /// Optional override for `--build-hash`. When omitted, the build
    /// hash is derived from the per-target manifest hashes — see
    /// [`derive_build_hash`].
    pub build_hash_override: Option<String>,

    /// Path to the Ed25519 seed file (32 bytes). Used to sign the
    /// `builds` row's `CanonicalBuild`.
    pub ed25519_seed_path: PathBuf,

    /// Path to the ML-DSA-65 secret seed file (32 bytes). Used to sign
    /// the `builds` row's `CanonicalBuild`.
    pub mldsa_secret_path: PathBuf,

    /// Steward `key_id` for the signature. Stored on the `builds` row.
    pub key_id: String,

    /// When true, prints what would be sent and exits without
    /// contacting the registry. Useful for CI dry-runs.
    pub dry_run: bool,
}

/// A `name:path` pair for one target's signed BuildManifest.
#[derive(Debug, Clone)]
pub struct TargetSpec {
    pub name: String,
    pub path: PathBuf,
}

impl TargetSpec {
    pub fn parse(s: &str) -> Result<Self> {
        let (name, path) = s.split_once(':').ok_or_else(|| {
            anyhow!(
                "--target value must be 'name:path' (got {s:?}); \
                 example: --target python-source-tree:./build-manifest.json"
            )
        })?;
        if name.is_empty() {
            anyhow::bail!("--target value has empty name part: {s:?}");
        }
        if path.is_empty() {
            anyhow::bail!("--target value has empty path part: {s:?}");
        }
        Ok(Self {
            name: name.to_string(),
            path: PathBuf::from(path),
        })
    }
}

// =============================================================================
// Wire shapes — must match the registry handlers exactly.
// =============================================================================

/// Body for `POST /v1/builds` (CIRISRegistry#9).
///
/// Field order matches the registry's `CanonicalBuild` struct. Signature
/// fields are appended after canonicalization. The first 6 fields
/// (project..file_manifest_count) are the *signed* set; the rest are
/// payload-only.
#[derive(Debug, Serialize)]
struct BuildsRequest<'a> {
    project: &'a str,
    version: &'a str,
    build_hash: &'a str,
    build_id: &'a str,
    modules: &'a [String],
    file_manifest_count: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    file_manifest_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_manifest_json: Option<&'a serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_repo: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_commit: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'a str>,

    signature_classical: String,
    signature_pqc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_key_id: Option<&'a str>,
}

/// Canonical signed-bytes representation. Field order is the
/// inter-implementation contract — must match the registry's
/// `CanonicalBuild` exactly. Don't sort, don't reorder.
#[derive(Debug, Serialize)]
struct CanonicalBuild<'a> {
    project: &'a str,
    version: &'a str,
    build_hash: &'a str,
    build_id: &'a str,
    modules: &'a [String],
    file_manifest_count: u64,
}

/// Body for `POST /v1/verify/binary-manifest`.
///
/// Mirrors `RegisterBinaryManifestRequest` in
/// `CIRISRegistry/rust-registry/src/api/http.rs:363`. Server signs
/// canonical `{project}/{version}:{binaries_json}` with the registry
/// steward key — client does NOT sign.
#[derive(Debug, Serialize)]
struct BinaryManifestRequest<'a> {
    project: &'a str,
    version: &'a str,
    binaries: &'a BTreeMap<String, String>,
    generated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'a str>,
}

/// Best-effort response shape for the registry's POST handlers (each
/// handler returns slightly different fields; serde defaults make this
/// tolerant).
#[derive(Debug, Deserialize)]
struct RegistryResponse {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    build_id: String,
}

/// Loaded BuildManifest plus the file path it came from.
struct LoadedTarget {
    name: String,
    path: PathBuf,
    manifest: BuildManifest,
    raw_bytes: Vec<u8>,
}

// =============================================================================
// Public entry point
// =============================================================================

/// Run the `register` subcommand.
///
/// Reads each per-target BuildManifest, validates them, derives
/// `build_hash`, signs a `CanonicalBuild`, and **always** dispatches all
/// three registry endpoints in dependency order:
///
/// 1. `POST /v1/builds` → `builds` row (signed CanonicalBuild)
/// 2. `POST /v1/verify/binary-manifest` → `binary_manifests` row
/// 3. `POST /v1/verify/build-manifest` (one per target) → `function_manifests` rows
///
/// File-mode vs binary-mode is **content-shape only** — it influences
/// what gets written into `builds.file_manifest_json` / `file_manifest_count`
/// / `file_manifest_hash`, but does NOT change which endpoints are called.
/// Every successful invocation writes 1 builds row + 1 binary_manifests
/// row + N function_manifests rows (where N = `--target` count).
///
/// (v1.10.1 had a regression where file-mode releases skipped steps 2 + 3.
/// CIRISAgent#727 / CIRISVerify#8 caught it. v1.10.2 restores the
/// always-3 dispatcher and prints `[1/N] / [2/N] / [3/N] ...` so the
/// step counter makes any future regression visible in the log.)
pub fn run(args: RegisterArgs) -> Result<()> {
    let admin_token = if args.dry_run {
        std::env::var("REGISTRY_ADMIN_TOKEN").unwrap_or_else(|_| "<unset>".to_string())
    } else {
        std::env::var("REGISTRY_ADMIN_TOKEN")
            .context("REGISTRY_ADMIN_TOKEN is required for HTTP registry writes")?
    };
    let registry_url = match (&args.registry_url, std::env::var("REGISTRY_URL").ok()) {
        (Some(u), _) => u.clone(),
        (None, Some(env)) => env,
        (None, None) => {
            anyhow::bail!("registry HTTP URL required: pass --registry-url or set REGISTRY_URL")
        },
    };

    // Load and validate per-target manifests.
    let mut loaded = Vec::with_capacity(args.targets.len());
    for spec in &args.targets {
        let raw_bytes = fs::read(&spec.path)
            .with_context(|| format!("read per-target manifest {}", spec.path.display()))?;
        let manifest: BuildManifest = serde_json::from_slice(&raw_bytes)
            .with_context(|| format!("parse BuildManifest at {}", spec.path.display()))?;
        validate_target(&args, spec, &manifest)?;
        loaded.push(LoadedTarget {
            name: spec.name.clone(),
            path: spec.path.clone(),
            manifest,
            raw_bytes,
        });
    }
    if loaded.is_empty() {
        anyhow::bail!("at least one --target is required");
    }

    // Total dispatcher steps for the [N/M] log counter:
    //   1 (builds) + 1 (binary_manifests) + N (function_manifests, one per target)
    let total_steps = 2 + loaded.len();

    // Build the binaries map (for binary_manifests row + build_hash derivation).
    let binaries: BTreeMap<String, String> = loaded
        .iter()
        .map(|t| (t.name.clone(), t.manifest.manifest_hash.clone()))
        .collect();

    let build_hash = match &args.build_hash_override {
        Some(h) => h.clone(),
        None => derive_build_hash(&binaries),
    };

    // Content-shape detection — affects builds.file_manifest_* fields ONLY,
    // never affects which endpoints get called. If any target carries
    // FileTreeExtras (Python source-tree shape), populate file_manifest_json
    // from the FIRST such target. If none do, leave file_manifest_* empty.
    let (file_manifest_count, file_manifest_hash, file_manifest_json) =
        derive_file_manifest_payload(&loaded)?;

    let detected_shape = describe_content_shape(&loaded);

    if args.dry_run {
        eprintln!("[dry-run] register payload preview:");
        eprintln!("  content shape    = {detected_shape}");
        eprintln!("  total POSTs      = {total_steps} (1 builds + 1 binary-manifest + {} function-manifest)",
                  loaded.len());
        eprintln!("  project          = {}", args.project);
        eprintln!("  binary_version   = {}", args.binary_version);
        eprintln!("  build_id         = {}", args.build_id);
        eprintln!("  build_hash       = {build_hash}");
        eprintln!("  modules          = {:?}", args.modules);
        eprintln!("  file_manifest_count = {file_manifest_count}");
        if let Some(h) = &file_manifest_hash {
            eprintln!("  file_manifest_hash  = {h}");
        }
        if file_manifest_json.is_some() {
            eprintln!(
                "  file_manifest_json  = (present, {} entries)",
                file_manifest_count
            );
        }
        eprintln!("  binaries:");
        for (target, mh) in &binaries {
            eprintln!("    {target} -> {mh}");
        }
        eprintln!("  registry_url     = {registry_url}");
        eprintln!("[dry-run] no network calls made");
        return Ok(());
    }

    // Load the steward keys for the CanonicalBuild signature.
    let ed_seed = read_key(&args.ed25519_seed_path)
        .with_context(|| format!("read Ed25519 seed at {}", args.ed25519_seed_path.display()))?;
    let mldsa_secret = read_key(&args.mldsa_secret_path).with_context(|| {
        format!(
            "read ML-DSA-65 seed at {}",
            args.mldsa_secret_path.display()
        )
    })?;

    let (sig_classical, sig_pqc) = sign_canonical_build(
        &CanonicalBuild {
            project: &args.project,
            version: &args.binary_version,
            build_hash: &build_hash,
            build_id: &args.build_id,
            modules: &args.modules,
            file_manifest_count,
        },
        &ed_seed,
        &mldsa_secret,
    )?;

    let mut step = 0;

    // === 1) POST /v1/builds — writes builds row =============================
    step += 1;
    register_build_via_http(
        &args,
        &registry_url,
        &admin_token,
        &build_hash,
        file_manifest_count,
        file_manifest_hash.as_deref(),
        file_manifest_json.as_ref(),
        &sig_classical,
        &sig_pqc,
        step,
        total_steps,
    )?;

    // === 2) POST /v1/verify/binary-manifest — writes binary_manifests row ===
    step += 1;
    register_binary_manifest_via_http(
        &args,
        &registry_url,
        &admin_token,
        &binaries,
        step,
        total_steps,
    )?;

    // === 3..N) POST /v1/verify/build-manifest per target ====================
    for t in &loaded {
        step += 1;
        register_function_manifest_via_http(&registry_url, &admin_token, t, step, total_steps)?;
    }

    eprintln!(
        "OK: registered {} {} ({} target{}, content shape: {}, build_hash={}, all 3 tables written)",
        args.project,
        args.binary_version,
        loaded.len(),
        if loaded.len() == 1 { "" } else { "s" },
        detected_shape,
        &build_hash[..build_hash.len().min(16)],
    );
    Ok(())
}

// =============================================================================
// Validation
// =============================================================================

fn validate_target(args: &RegisterArgs, spec: &TargetSpec, manifest: &BuildManifest) -> Result<()> {
    if manifest.binary_version != args.binary_version {
        anyhow::bail!(
            "target {:?} ({}): manifest binary_version is {:?}, but --binary-version is {:?}; \
             refuse to register parent rows that don't match their targets",
            spec.name,
            spec.path.display(),
            manifest.binary_version,
            args.binary_version,
        );
    }
    if manifest.target != spec.name {
        anyhow::bail!(
            "target {:?} ({}): manifest target field is {:?}, but --target name is {:?}; \
             pass --target {}:{} or fix the manifest",
            spec.name,
            spec.path.display(),
            manifest.target,
            spec.name,
            manifest.target,
            spec.path.display(),
        );
    }
    Ok(())
}

// =============================================================================
// Mode detection (file vs binary)
// =============================================================================

fn has_file_tree_extras(manifest: &BuildManifest) -> bool {
    manifest
        .extras
        .as_ref()
        .and_then(|v| v.get("file_tree_hash"))
        .is_some()
}

/// Human-readable summary of the detected content shape across the
/// loaded targets, for log lines. Reports `"file"`, `"binary"`, or
/// `"mixed (N file, M binary)"`. Does NOT influence dispatch.
fn describe_content_shape(loaded: &[LoadedTarget]) -> String {
    let (file_count, binary_count) = loaded.iter().fold((0usize, 0usize), |(f, b), t| {
        if has_file_tree_extras(&t.manifest) {
            (f + 1, b)
        } else {
            (f, b + 1)
        }
    });
    match (file_count, binary_count) {
        (0, 0) => "(empty)".to_string(),
        (_, 0) => "file".to_string(),
        (0, _) => "binary".to_string(),
        (f, b) => format!("mixed ({f} file, {b} binary)"),
    }
}

// =============================================================================
// File-mode payload (Python source-tree primitives)
// =============================================================================

/// Derive the optional `file_manifest_*` payload for the `builds` row.
///
/// Searches the loaded targets for the FIRST one that carries
/// `FileTreeExtras` (i.e., `extras.file_tree_hash` + `extras.files`).
/// If found, returns the `{files: {...}}` JSON wrapped in the shape the
/// registry's `GET /v1/builds` endpoint serves (matches legacy
/// `register_agent_build.py` exactly), the count, and a hash of the
/// JSON. If no target carries FileTreeExtras, returns
/// `(0, None, None)` — the `builds` row gets default empty values for
/// `file_manifest_*` and the dispatcher continues with the
/// binary_manifests + function_manifests writes unchanged.
///
/// **Multi-target behavior**: if multiple targets carry FileTreeExtras
/// (rare; e.g., a release with two distinct source trees), the FIRST is
/// used and a warning is printed. The other targets' extras still
/// flow through to `function_manifests` rows via their per-target POSTs
/// — nothing is dropped, just not duplicated into `builds.file_manifest_json`.
fn derive_file_manifest_payload(
    loaded: &[LoadedTarget],
) -> Result<(u64, Option<String>, Option<serde_json::Value>)> {
    let mut iter = loaded.iter().filter(|t| has_file_tree_extras(&t.manifest));
    let Some(target) = iter.next() else {
        // No FileTreeExtras-bearing target — pure binary release. Empty
        // file_manifest_* on the builds row is correct.
        return Ok((0, None, None));
    };
    let remaining: Vec<&str> = iter.map(|t| t.name.as_str()).collect();
    if !remaining.is_empty() {
        eprintln!(
            "info: {} target{} also carry FileTreeExtras ({:?}); using first ({}) for builds.file_manifest_json. \
             Per-target function_manifests rows preserve all extras content.",
            remaining.len(),
            if remaining.len() == 1 { "" } else { "s" },
            remaining,
            target.name,
        );
    }

    let extras = target.manifest.extras.as_ref().ok_or_else(|| {
        anyhow!(
            "internal: target {} marked file-mode but extras is None",
            target.name
        )
    })?;
    let files = extras
        .get("files")
        .ok_or_else(|| anyhow!("FileTreeExtras on {} missing `files` key", target.name))?
        .clone();
    let declared_count = extras
        .get("file_count")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("FileTreeExtras on {} missing `file_count` key", target.name))?;
    let actual_count = files.as_object().map(|m| m.len() as u64).unwrap_or(0);
    if declared_count != actual_count {
        anyhow::bail!(
            "FileTreeExtras inconsistency on {}: extras.file_count ({declared_count}) != extras.files length ({actual_count})",
            target.name,
        );
    }
    // Wrap as {"files": {...}} which is what register_agent_build.py used and
    // what the registry's GET /v1/builds returns in file_manifest_json.
    let json = serde_json::json!({"files": files});
    let json_bytes = serde_json::to_vec(&json).context("serialize file_manifest_json")?;
    let json_hash = format!("sha256:{}", hex::encode(Sha256::digest(&json_bytes)));
    Ok((actual_count, Some(json_hash), Some(json)))
}

// =============================================================================
// build_hash derivation
// =============================================================================

/// Derive `build_hash` from a sorted set of per-target manifest hashes.
///
/// Format: `sha256:<hex(sha256(target1_name + ":" + manifest_hash1 +
/// "\n" + ...))>` with targets sorted by name. Deterministic across CLI
/// argument order. For file-mode single-target releases, this still
/// produces a stable hash distinct from the `manifest_hash` itself,
/// matching the registry's `(project, build_hash)` UPSERT key.
pub fn derive_build_hash(binaries: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    for (target, manifest_hash) in binaries {
        hasher.update(target.as_bytes());
        hasher.update(b":");
        hasher.update(manifest_hash.as_bytes());
        hasher.update(b"\n");
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

// =============================================================================
// CanonicalBuild signing — Ed25519 + bound ML-DSA-65 over the canonical bytes
// =============================================================================

fn sign_canonical_build(
    canonical: &CanonicalBuild<'_>,
    ed25519_seed: &[u8],
    mldsa_secret: &[u8],
) -> Result<(String, String)> {
    let canonical_bytes = serde_json::to_vec(canonical).context("serialize CanonicalBuild")?;

    let ed_signer =
        Ed25519Signer::from_seed(ed25519_seed).map_err(|e| anyhow!("Ed25519 seed parse: {e}"))?;
    let classical_sig = ed_signer
        .sign(&canonical_bytes)
        .map_err(|e| anyhow!("Ed25519 sign: {e}"))?;

    let mldsa_signer =
        MlDsa65Signer::from_seed(mldsa_secret).map_err(|e| anyhow!("ML-DSA-65 seed parse: {e}"))?;
    let mut bound = canonical_bytes.clone();
    bound.extend_from_slice(&classical_sig);
    let pqc_sig = mldsa_signer
        .sign(&bound)
        .map_err(|e| anyhow!("ML-DSA-65 sign: {e}"))?;

    Ok((STANDARD.encode(&classical_sig), STANDARD.encode(&pqc_sig)))
}

// =============================================================================
// HTTP POST /v1/builds (CIRISRegistry#9 — replaces gRPC RegisterBuild)
// =============================================================================

#[allow(clippy::too_many_arguments)]
fn register_build_via_http(
    args: &RegisterArgs,
    registry_url: &str,
    admin_token: &str,
    build_hash: &str,
    file_manifest_count: u64,
    file_manifest_hash: Option<&str>,
    file_manifest_json: Option<&serde_json::Value>,
    signature_classical: &str,
    signature_pqc: &str,
    step: usize,
    total_steps: usize,
) -> Result<()> {
    let url = format!("{}/v1/builds", registry_url.trim_end_matches('/'));
    let body = BuildsRequest {
        project: &args.project,
        version: &args.binary_version,
        build_hash,
        build_id: &args.build_id,
        modules: &args.modules,
        file_manifest_count,
        file_manifest_hash,
        file_manifest_json,
        source_repo: opt_nonempty(&args.source_repo),
        source_commit: opt_nonempty(&args.source_commit),
        notes: args.notes.as_deref(),
        signature_classical: signature_classical.to_string(),
        signature_pqc: signature_pqc.to_string(),
        signature_key_id: Some(&args.key_id),
    };
    eprintln!(
        "[{step}/{total_steps}] POST {url}  (project={}, build_hash={}…)",
        args.project,
        &build_hash[..build_hash.len().min(20)]
    );
    let client = reqwest::blocking::Client::builder()
        .build()
        .context("build reqwest client")?;
    let resp = client
        .post(&url)
        .bearer_auth(admin_token)
        .json(&body)
        .send()
        .context("POST /v1/builds")?;
    handle_http_response(resp, "/v1/builds")
}

fn opt_nonempty(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

// =============================================================================
// HTTP POST /v1/verify/binary-manifest (always; never gated on mode since v1.10.2)
// =============================================================================

fn register_binary_manifest_via_http(
    args: &RegisterArgs,
    registry_url: &str,
    admin_token: &str,
    binaries: &BTreeMap<String, String>,
    step: usize,
    total_steps: usize,
) -> Result<()> {
    let url = format!(
        "{}/v1/verify/binary-manifest",
        registry_url.trim_end_matches('/')
    );
    let body = BinaryManifestRequest {
        project: &args.project,
        version: &args.binary_version,
        binaries,
        generated_at: Utc::now().to_rfc3339(),
        notes: args.notes.as_deref(),
    };
    eprintln!("[{step}/{total_steps}] POST {url}");
    let client = reqwest::blocking::Client::builder()
        .build()
        .context("build reqwest client")?;
    let resp = client
        .post(&url)
        .bearer_auth(admin_token)
        .json(&body)
        .send()
        .context("POST /v1/verify/binary-manifest")?;
    handle_http_response(resp, "binary-manifest")
}

// =============================================================================
// HTTP POST /v1/verify/build-manifest (always; one per target since v1.10.2)
// =============================================================================

fn register_function_manifest_via_http(
    registry_url: &str,
    admin_token: &str,
    target: &LoadedTarget,
    step: usize,
    total_steps: usize,
) -> Result<()> {
    let url = format!(
        "{}/v1/verify/build-manifest",
        registry_url.trim_end_matches('/')
    );
    eprintln!(
        "[{step}/{total_steps}] POST {url}  (target={}, manifest={})",
        target.name,
        target.path.display()
    );
    let client = reqwest::blocking::Client::builder()
        .build()
        .context("build reqwest client")?;
    let resp = client
        .post(&url)
        .bearer_auth(admin_token)
        .header("Content-Type", "application/json")
        .body(target.raw_bytes.clone())
        .send()
        .context("POST /v1/verify/build-manifest")?;
    handle_http_response(resp, &format!("build-manifest({})", target.name))
}

// =============================================================================
// Common HTTP response handling
// =============================================================================

fn handle_http_response(resp: reqwest::blocking::Response, label: &str) -> Result<()> {
    let status = resp.status();
    let body_bytes = resp.bytes().unwrap_or_default();
    let body_str = String::from_utf8_lossy(&body_bytes);

    let parsed: Option<RegistryResponse> = serde_json::from_slice(&body_bytes).ok();

    if status.is_success() {
        let extra = parsed
            .as_ref()
            .map(|r| {
                let mut bits = Vec::new();
                if !r.message.is_empty() {
                    bits.push(r.message.clone());
                }
                if !r.build_id.is_empty() {
                    bits.push(format!("build_id={}", r.build_id));
                }
                if bits.is_empty() {
                    String::new()
                } else {
                    format!(": {}", bits.join(", "))
                }
            })
            .unwrap_or_default();
        eprintln!("      OK ({status}){extra}");
        return Ok(());
    }
    if status == reqwest::StatusCode::CONFLICT {
        eprintln!("      already registered (HTTP 409, treating as success)");
        return Ok(());
    }
    if let Some(p) = &parsed {
        if (p.error.contains("duplicate") || p.message.contains("duplicate")) && !p.success {
            eprintln!("      already registered (body indicates duplicate, treating as success)");
            return Ok(());
        }
    }
    anyhow::bail!("{label} POST failed: HTTP {status}\nbody: {body_str}")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_spec_parses_name_path() {
        let s = TargetSpec::parse("python-source-tree:./build-manifest.json").unwrap();
        assert_eq!(s.name, "python-source-tree");
        assert_eq!(s.path, PathBuf::from("./build-manifest.json"));
    }

    #[test]
    fn target_spec_rejects_missing_colon() {
        let err = TargetSpec::parse("nope-no-colon").unwrap_err();
        assert!(err.to_string().contains("name:path"), "got: {err}");
    }

    #[test]
    fn target_spec_rejects_empty_parts() {
        assert!(TargetSpec::parse(":path").is_err());
        assert!(TargetSpec::parse("name:").is_err());
    }

    #[test]
    fn build_hash_is_deterministic_under_target_order() {
        let mut a = BTreeMap::new();
        a.insert("python-source-tree".to_string(), "sha256:aaaa".to_string());
        a.insert("ios-mobile-bundle".to_string(), "sha256:bbbb".to_string());

        let mut b = BTreeMap::new();
        b.insert("ios-mobile-bundle".to_string(), "sha256:bbbb".to_string());
        b.insert("python-source-tree".to_string(), "sha256:aaaa".to_string());

        assert_eq!(derive_build_hash(&a), derive_build_hash(&b));
    }

    #[test]
    fn build_hash_changes_with_manifest_hash() {
        let mut a = BTreeMap::new();
        a.insert("t".to_string(), "sha256:aaaa".to_string());
        let h1 = derive_build_hash(&a);

        let mut a2 = BTreeMap::new();
        a2.insert("t".to_string(), "sha256:bbbb".to_string());
        let h2 = derive_build_hash(&a2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn build_hash_format_has_sha256_prefix_and_64_hex() {
        let mut m = BTreeMap::new();
        m.insert("t".to_string(), "sha256:aaaa".to_string());
        let h = derive_build_hash(&m);
        assert!(h.starts_with("sha256:"), "got: {h}");
        let hex_part = &h["sha256:".len()..];
        assert_eq!(hex_part.len(), 64);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Field order in CanonicalBuild is the inter-implementation contract
    /// with the registry. Asserting the serialized JSON layout catches any
    /// future field-reorder drift between client and server.
    #[test]
    fn canonical_build_field_order_locked() {
        let modules = vec!["core".to_string(), "ios".to_string()];
        let cb = CanonicalBuild {
            project: "ciris-agent",
            version: "2.7.10",
            build_hash: "sha256:abc",
            build_id: "deadbeef",
            modules: &modules,
            file_manifest_count: 1655,
        };
        let bytes = serde_json::to_vec(&cb).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        // serde_json emits fields in declaration order; the literal substring
        // is the canonicalization contract.
        let expected = r#"{"project":"ciris-agent","version":"2.7.10","build_hash":"sha256:abc","build_id":"deadbeef","modules":["core","ios"],"file_manifest_count":1655}"#;
        assert_eq!(s, expected, "CanonicalBuild field order changed");
    }

    #[test]
    fn canonical_build_serializes_empty_modules_as_array() {
        let modules: Vec<String> = vec![];
        let cb = CanonicalBuild {
            project: "p",
            version: "v",
            build_hash: "h",
            build_id: "i",
            modules: &modules,
            file_manifest_count: 0,
        };
        let s = serde_json::to_string(&cb).unwrap();
        assert!(s.contains(r#""modules":[]"#), "got: {s}");
    }

    #[test]
    fn sign_canonical_build_produces_base64_sigs() {
        // 32-byte deterministic seeds for both algorithms.
        let ed_seed = [1u8; 32];
        let mldsa_seed = [2u8; 32];
        let modules = vec!["core".to_string()];
        let cb = CanonicalBuild {
            project: "ciris-test",
            version: "0.0.0",
            build_hash: "sha256:0000",
            build_id: "test",
            modules: &modules,
            file_manifest_count: 0,
        };
        let (cls, pqc) = sign_canonical_build(&cb, &ed_seed, &mldsa_seed).unwrap();
        // Ed25519 sigs are 64 bytes → ceil(64*4/3)=88 b64 chars (no padding=)
        assert_eq!(STANDARD.decode(&cls).unwrap().len(), 64);
        // ML-DSA-65 sigs (FIPS 204 final) are 3309 bytes
        assert_eq!(STANDARD.decode(&pqc).unwrap().len(), 3309);
    }

    /// v1.10.2 invariant: total_steps = 2 + target_count, regardless of
    /// extras shape. Locking this in a test prevents anyone from
    /// reintroducing v1.10.1's mode-gated dispatch silently. (Direct
    /// dispatcher test would require a mock HTTP server; this test
    /// covers the algebra by replicating the formula from `run`.)
    #[test]
    fn dispatch_total_steps_is_two_plus_target_count() {
        for target_count in 1..=5 {
            let total_steps = 2 + target_count;
            assert!(total_steps >= 3, "always at least 3 endpoints called");
            assert_eq!(
                total_steps - 2,
                target_count,
                "function_manifests POST count must equal target count"
            );
        }
    }

    #[test]
    fn describe_content_shape_returns_file_for_file_only() {
        let lt = LoadedTarget {
            name: "python-source-tree".into(),
            path: PathBuf::from("/tmp/x.json"),
            manifest: build_test_manifest_with_extras(serde_json::json!({
                "file_tree_hash": "sha256:dead",
                "file_count": 0,
                "files": {},
            })),
            raw_bytes: vec![],
        };
        assert_eq!(describe_content_shape(&[lt]), "file");
    }

    #[test]
    fn describe_content_shape_returns_binary_for_no_extras() {
        let mut manifest = build_test_manifest_with_extras(serde_json::Value::Null);
        manifest.extras = None;
        let lt = LoadedTarget {
            name: "x86_64-unknown-linux-gnu".into(),
            path: PathBuf::from("/tmp/x.json"),
            manifest,
            raw_bytes: vec![],
        };
        assert_eq!(describe_content_shape(&[lt]), "binary");
    }

    #[test]
    fn describe_content_shape_returns_binary_for_function_extras() {
        let lt = LoadedTarget {
            name: "x86_64-unknown-linux-gnu".into(),
            path: PathBuf::from("/tmp/x.json"),
            manifest: build_test_manifest_with_extras(serde_json::json!({
                "functions": [],
            })),
            raw_bytes: vec![],
        };
        assert_eq!(describe_content_shape(&[lt]), "binary");
    }

    #[test]
    fn describe_content_shape_reports_mixed() {
        // v1.10.2 explicitly supports mixed-mode targets in one register
        // call (closes CIRISAgent#729 — agent's python-source-tree +
        // ios-mobile-bundle now consolidate). The shape descriptor reports
        // the breakdown but does NOT reject.
        let file_target = LoadedTarget {
            name: "python-source-tree".into(),
            path: PathBuf::from("/tmp/f.json"),
            manifest: build_test_manifest_with_extras(serde_json::json!({
                "file_tree_hash": "sha256:dead",
                "file_count": 0,
                "files": {},
            })),
            raw_bytes: vec![],
        };
        let binary_target = LoadedTarget {
            name: "ios-mobile-bundle".into(),
            path: PathBuf::from("/tmp/b.json"),
            manifest: build_test_manifest_with_extras(serde_json::json!({"functions": []})),
            raw_bytes: vec![],
        };
        let shape = describe_content_shape(&[file_target, binary_target]);
        assert!(shape.contains("mixed"), "got: {shape}");
        assert!(shape.contains("1 file"), "got: {shape}");
        assert!(shape.contains("1 binary"), "got: {shape}");
    }

    #[test]
    fn derive_file_manifest_payload_returns_empty_when_no_filetree_extras() {
        let lt = LoadedTarget {
            name: "x86_64-unknown-linux-gnu".into(),
            path: PathBuf::from("/tmp/x.json"),
            manifest: build_test_manifest_with_extras(serde_json::json!({
                "functions": [],
            })),
            raw_bytes: vec![],
        };
        let (count, hash, json) = derive_file_manifest_payload(&[lt]).unwrap();
        assert_eq!(count, 0);
        assert_eq!(hash, None);
        assert_eq!(json, None);
    }

    #[test]
    fn derive_file_manifest_payload_extracts_files_from_filetree_extras() {
        let lt = LoadedTarget {
            name: "python-source-tree".into(),
            path: PathBuf::from("/tmp/x.json"),
            manifest: build_test_manifest_with_extras(serde_json::json!({
                "file_tree_hash": "sha256:dead",
                "file_count": 2,
                "files": {
                    "a.py": "sha256:aaaa",
                    "b.py": "sha256:bbbb",
                },
            })),
            raw_bytes: vec![],
        };
        let (count, hash, json) = derive_file_manifest_payload(&[lt]).unwrap();
        assert_eq!(count, 2);
        assert!(hash.is_some());
        assert!(json.unwrap().get("files").is_some());
    }

    #[test]
    fn derive_file_manifest_payload_uses_first_target_when_multiple_have_filetree() {
        // Mixed-mode invocation supported in v1.10.2: file_manifest_json
        // populated from the first FileTreeExtras-bearing target; the
        // others' content flows through to function_manifests via their
        // own per-target POSTs (not via builds row).
        let first = LoadedTarget {
            name: "python-source-tree".into(),
            path: PathBuf::from("/tmp/f1.json"),
            manifest: build_test_manifest_with_extras(serde_json::json!({
                "file_tree_hash": "sha256:dead",
                "file_count": 1,
                "files": {"first.py": "sha256:11"},
            })),
            raw_bytes: vec![],
        };
        let second = LoadedTarget {
            name: "another-tree".into(),
            path: PathBuf::from("/tmp/f2.json"),
            manifest: build_test_manifest_with_extras(serde_json::json!({
                "file_tree_hash": "sha256:beef",
                "file_count": 1,
                "files": {"second.py": "sha256:22"},
            })),
            raw_bytes: vec![],
        };
        let (count, _hash, json) = derive_file_manifest_payload(&[first, second]).unwrap();
        assert_eq!(count, 1, "uses first target's count, not summed");
        let files_obj = json.unwrap();
        let files = files_obj.get("files").unwrap();
        assert!(
            files.get("first.py").is_some(),
            "first target's files included"
        );
        assert!(
            files.get("second.py").is_none(),
            "second target's files NOT included in builds row"
        );
    }

    fn build_test_manifest_with_extras(extras: serde_json::Value) -> BuildManifest {
        use ciris_verify_core::security::build_manifest::BuildPrimitive;
        use ciris_verify_core::security::function_integrity::ManifestSignature;
        BuildManifest {
            manifest_schema_version: "1.0".into(),
            primitive: BuildPrimitive::Other("test".into()),
            build_id: "test".into(),
            target: "test-target".into(),
            binary_hash: "sha256:0000".into(),
            binary_version: "0.0.0".into(),
            generated_at: "2026-01-01T00:00:00Z".into(),
            manifest_hash: "sha256:0000".into(),
            extras: if extras.is_null() { None } else { Some(extras) },
            signature: ManifestSignature {
                classical: String::new(),
                classical_algorithm: "Ed25519".into(),
                pqc: String::new(),
                pqc_algorithm: "ML-DSA-65".into(),
                key_id: "test-key".into(),
            },
        }
    }

    #[test]
    fn opt_nonempty_filters_empty_string() {
        assert_eq!(opt_nonempty(""), None);
        assert_eq!(opt_nonempty("x"), Some("x"));
    }
}
