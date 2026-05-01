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
}
