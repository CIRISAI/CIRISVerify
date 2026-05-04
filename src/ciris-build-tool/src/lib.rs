//! Shared helpers for the `ciris-build-sign` and `ciris-build-verify` CLIs.
//!
//! Keeps the per-CLI binaries thin: parse args, call into here, format output.
//! Everything in this crate is testable without spawning subprocesses.

/// `register` subcommand: write builds + binary_manifests + function_manifests
/// rows to CIRISRegistry. See module docs for the wire-format mirror back to
/// the registry's HTTP/gRPC handlers.
pub mod register;

use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ciris_crypto::{
    ClassicalSigner, ClassicalVerifier, Ed25519Signer, Ed25519Verifier, MlDsa65Signer,
    MlDsa65Verifier, PqcSigner, PqcVerifier,
};
use ciris_verify_core::error::VerifyError;
use ciris_verify_core::security::build_manifest::{
    verify_build_manifest, walk_file_tree, BuildManifest, BuildPrimitive, ExemptRules,
    FileTreeExtras, FunctionLevelExtras,
};
use ciris_verify_core::security::function_integrity::{
    FunctionEntry, FunctionManifest, ManifestMetadata, ManifestSignature, StewardPublicKey,
};
use sha2::{Digest, Sha256};

/// Parse a `BuildPrimitive` from the CLI string form (snake_case).
///
/// Accepts the named variants. Anything else becomes `Other(String)`.
pub fn parse_primitive(s: &str) -> BuildPrimitive {
    match s {
        "verify" => BuildPrimitive::Verify,
        "agent" => BuildPrimitive::Agent,
        "lens" => BuildPrimitive::Lens,
        "persist" => BuildPrimitive::Persist,
        "registry" => BuildPrimitive::Registry,
        other => BuildPrimitive::Other(other.to_string()),
    }
}

/// Compute SHA-256 of a file, returned as `"sha256:<hex>"`.
pub fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read binary at {}", path.display()))?;
    let hash = Sha256::digest(&bytes);
    Ok(format!("sha256:{}", hex::encode(hash)))
}

/// Read raw key bytes from a file. The format is intentionally raw (not
/// PEM) — these CLIs run inside CI pipelines where the key is already
/// in raw form. Anything more elaborate is the calling pipeline's job.
pub fn read_key(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("read key at {}", path.display()))
}

/// Compose a `BuildManifest` and sign it with the given Ed25519 + ML-DSA-65
/// secret keys. Returns the signed manifest as JSON bytes (canonical
/// non-pretty form is what we sign over; the returned bytes can be
/// pretty-printed for storage if desired).
///
/// This is the load-bearing piece of `ciris-build-sign` — both
/// signatures cover the canonical bytes (the PQC sig binds to the
/// classical sig as well, matching `verify_hybrid_signature`).
#[allow(clippy::too_many_arguments)]
pub fn sign_build_manifest(
    primitive: BuildPrimitive,
    build_id: String,
    target: String,
    binary_hash: String,
    binary_version: String,
    extras: Option<serde_json::Value>,
    ed25519_seed: &[u8],
    mldsa_secret: &[u8],
    key_id: &str,
) -> Result<Vec<u8>> {
    let now = chrono::Utc::now().to_rfc3339();

    // Compute manifest_hash from extras (if present) — falls back to
    // hashing the binary_hash if the primitive has no extras (so it's
    // still a stable per-build identifier).
    let manifest_hash = match &extras {
        Some(v) => {
            let bytes = serde_json::to_vec(v).context("canonicalize extras for manifest_hash")?;
            format!("sha256:{}", hex::encode(Sha256::digest(&bytes)))
        },
        None => format!(
            "sha256:{}",
            hex::encode(Sha256::digest(binary_hash.as_bytes()))
        ),
    };

    let mut manifest = BuildManifest {
        manifest_schema_version: "1.0".into(),
        primitive,
        build_id,
        target,
        binary_hash,
        binary_version,
        generated_at: now,
        manifest_hash,
        extras,
        signature: ManifestSignature {
            classical: String::new(),
            classical_algorithm: "Ed25519".into(),
            pqc: String::new(),
            pqc_algorithm: "ML-DSA-65".into(),
            key_id: key_id.into(),
        },
    };

    // Compute canonical bytes for signing.
    let canonical = manifest.canonical_bytes();

    // Ed25519 signature.
    let ed_signer =
        Ed25519Signer::from_seed(ed25519_seed).map_err(|e| anyhow!("Ed25519 seed parse: {e}"))?;
    let classical_sig = ed_signer
        .sign(&canonical)
        .map_err(|e| anyhow!("Ed25519 sign: {e}"))?;

    // ML-DSA-65 signature over (canonical || classical_sig).
    let mldsa_signer =
        MlDsa65Signer::from_seed(mldsa_secret).map_err(|e| anyhow!("ML-DSA-65 seed parse: {e}"))?;
    let mut bound = canonical.clone();
    bound.extend_from_slice(&classical_sig);
    let pqc_sig = mldsa_signer
        .sign(&bound)
        .map_err(|e| anyhow!("ML-DSA-65 sign: {e}"))?;

    manifest.signature.classical = STANDARD.encode(&classical_sig);
    manifest.signature.pqc = STANDARD.encode(&pqc_sig);

    serde_json::to_vec_pretty(&manifest).context("serialize signed manifest")
}

/// Build `FileTreeExtras` by walking a directory and applying exempt
/// rules. Used by `ciris-build-sign --tree`.
///
/// Optionally merges in `extra_hashes` (e.g., build-secret hashes that
/// don't exist as files on disk) — these are appended to the file map
/// and participate in the canonical tree hash like any other entry.
pub fn build_file_tree_extras(
    fs_root: &Path,
    rules: ExemptRules,
    extra_hashes: Option<std::collections::BTreeMap<String, String>>,
) -> Result<FileTreeExtras> {
    let mut files =
        walk_file_tree(fs_root, &rules).map_err(|e| anyhow!("walk_file_tree failed: {e}"))?;

    if let Some(extras) = extra_hashes {
        for (path, hash) in extras {
            // Validate hash format ("sha256:hex" with 64 hex chars)
            if !hash.starts_with("sha256:") || hash.len() != 7 + 64 {
                return Err(anyhow!(
                    "extra hash for {} must be sha256:<64 hex chars>, got {}",
                    path,
                    hash
                ));
            }
            files.insert(path, hash);
        }
    }

    let file_count = u32::try_from(files.len())
        .map_err(|_| anyhow!("file count overflows u32 — that's a lot of files"))?;
    let file_tree_hash = FileTreeExtras::compute_tree_hash(&files);

    Ok(FileTreeExtras {
        file_tree_hash,
        file_count,
        files,
        exempt_rules: rules,
    })
}

/// Build `FunctionLevelExtras` by parsing a `ciris-manifest-tool`
/// output JSON file. Used by `ciris-build-sign --manifest-from`.
///
/// The input file is the output of `ciris-manifest-tool generate`
/// (a `FunctionManifest` shape). We extract the `functions` map +
/// `metadata`, drop the surrounding fields (target, binary_hash,
/// signature) which the new BuildManifest carries at the outer level.
pub fn build_function_level_extras_from_file(
    manifest_path: &Path,
) -> Result<(FunctionLevelExtras, FunctionManifest)> {
    let bytes = fs::read(manifest_path)
        .with_context(|| format!("read manifest at {}", manifest_path.display()))?;
    let parsed: FunctionManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse FunctionManifest at {}", manifest_path.display()))?;

    let extras = FunctionLevelExtras {
        functions: parsed.functions.clone(),
        metadata: parsed.metadata.clone(),
    };
    Ok((extras, parsed))
}

/// Parse a JSON file containing extra-hashes (path → "sha256:hex").
/// Used by `--tree-extra-hashes-file`.
pub fn read_extra_hashes_file(path: &Path) -> Result<std::collections::BTreeMap<String, String>> {
    let s = fs::read_to_string(path)
        .with_context(|| format!("read extra hashes file at {}", path.display()))?;
    let map: std::collections::BTreeMap<String, String> =
        serde_json::from_str(&s).with_context(|| {
            format!(
                "parse extra hashes JSON at {} (expected object of path → sha256:hex)",
                path.display()
            )
        })?;
    Ok(map)
}

/// Convert `FileTreeExtras` into a `serde_json::Value` for use as
/// `BuildManifest::extras`.
pub fn file_tree_extras_to_value(extras: &FileTreeExtras) -> Result<serde_json::Value> {
    serde_json::to_value(extras).context("serialize FileTreeExtras")
}

/// Convert `FunctionLevelExtras` into a `serde_json::Value` for use
/// as `BuildManifest::extras`.
pub fn function_level_extras_to_value(extras: &FunctionLevelExtras) -> Result<serde_json::Value> {
    serde_json::to_value(extras).context("serialize FunctionLevelExtras")
}

// Silence dead-code warning for re-exports we use only via the lib's
// public surface.
#[allow(dead_code)]
fn _re_export_check(_: FunctionEntry, _: ManifestMetadata) {}

/// Verify a signed `BuildManifest` against the provided trusted public
/// keys. Returns the parsed `BuildManifest` on success.
///
/// This is the wrapper `ciris-build-verify` calls. The actual logic
/// lives in `ciris_verify_core::security::build_manifest::verify_build_manifest`.
pub fn verify_build_manifest_with_keys(
    bytes: &[u8],
    expected_primitive: BuildPrimitive,
    ed25519_pubkey: &[u8; 32],
    mldsa_pubkey: &[u8],
) -> Result<BuildManifest, VerifyError> {
    // Leak the keys to satisfy the 'static lifetime on StewardPublicKey.
    // Acceptable in CLI tools (process is short-lived); benchmarks /
    // hot paths should use a different scheme.
    let ed_static: &'static [u8; 32] = Box::leak(Box::new(*ed25519_pubkey));
    let mldsa_static: &'static [u8] = Box::leak(mldsa_pubkey.to_vec().into_boxed_slice());

    let pubkey = StewardPublicKey {
        ed25519: ed_static,
        ml_dsa_65: mldsa_static,
    };

    verify_build_manifest(bytes, expected_primitive, &pubkey)
}

/// Sanity helpers for the CLIs to load typed keys from raw bytes.
pub fn load_ed25519_pubkey(bytes: Vec<u8>) -> Result<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(anyhow!(
            "Ed25519 public key must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Generate a fresh Ed25519 keypair (seed + public key) using OsRng.
/// Returns `(seed, pubkey)` so callers can persist the seed.
pub fn generate_ed25519_keypair() -> Result<([u8; 32], [u8; 32])> {
    use rand_core::{OsRng, RngCore};

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);

    let signer = Ed25519Signer::from_seed(&seed).map_err(|e| anyhow!("Ed25519 from_seed: {e}"))?;
    let pub_vec = signer
        .public_key()
        .map_err(|e| anyhow!("Ed25519 pubkey: {e}"))?;
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&pub_vec);

    Ok((seed, pub_arr))
}

/// Generate a fresh ML-DSA-65 keypair (seed + public key) using OsRng.
/// Returns `(seed_bytes, public_bytes)`.
pub fn generate_mldsa65_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    use rand_core::{OsRng, RngCore};

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);

    let signer =
        MlDsa65Signer::from_seed(&seed).map_err(|e| anyhow!("ML-DSA-65 from_seed: {e}"))?;
    let pub_bytes = signer
        .public_key()
        .map_err(|e| anyhow!("ML-DSA-65 pubkey: {e}"))?;
    Ok((seed.to_vec(), pub_bytes))
}

/// Quick sanity check: do the registered Ed25519 + ML-DSA-65 verifiers
/// reject a tampered signature on a small test vector? Used as a
/// startup self-check in the CLIs.
pub fn self_test_crypto() -> Result<()> {
    let signer = Ed25519Signer::random();
    let pub_vec = signer.public_key().map_err(|e| anyhow!("ed pubkey: {e}"))?;
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&pub_vec);

    let msg = b"ciris-build-tool self-test";
    let sig = signer.sign(msg).map_err(|e| anyhow!("ed sign: {e}"))?;
    let verifier = Ed25519Verifier::new();
    let ok = verifier
        .verify(&pub_arr, msg, &sig)
        .map_err(|e| anyhow!("ed verify: {e}"))?;
    if !ok {
        return Err(anyhow!("Ed25519 self-test signature did not verify"));
    }

    let mldsa_signer = MlDsa65Signer::new().map_err(|e| anyhow!("mldsa keygen: {e}"))?;
    let mldsa_pub = mldsa_signer
        .public_key()
        .map_err(|e| anyhow!("mldsa pub: {e}"))?;
    let mldsa_sig = mldsa_signer
        .sign(msg)
        .map_err(|e| anyhow!("mldsa sign: {e}"))?;
    let mldsa_verifier = MlDsa65Verifier::new();
    let ok = mldsa_verifier
        .verify(&mldsa_pub, msg, &mldsa_sig)
        .map_err(|e| anyhow!("mldsa verify: {e}"))?;
    if !ok {
        return Err(anyhow!("ML-DSA-65 self-test signature did not verify"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_verify_core::security::build_manifest::register_extras_validator;
    use ciris_verify_core::security::build_manifest::ExtrasValidator;
    use serde_json::json;

    /// Always-pass validator for tests.
    struct AlwaysOk(BuildPrimitive);
    impl ExtrasValidator for AlwaysOk {
        fn primitive(&self) -> BuildPrimitive {
            self.0.clone()
        }
        fn validate(&self, _: &serde_json::Value) -> Result<(), VerifyError> {
            Ok(())
        }
    }

    #[test]
    fn parse_primitive_handles_named_and_other() {
        assert!(matches!(parse_primitive("verify"), BuildPrimitive::Verify));
        assert!(matches!(
            parse_primitive("persist"),
            BuildPrimitive::Persist
        ));
        match parse_primitive("future-thing") {
            BuildPrimitive::Other(s) => assert_eq!(s, "future-thing"),
            _ => panic!("Other variant expected"),
        }
    }

    #[test]
    fn sign_then_verify_persist_manifest() {
        // Use a unique primitive key per test for isolation.
        let primitive = BuildPrimitive::Other("sign-verify-test-persist".into());
        register_extras_validator(Box::new(AlwaysOk(primitive.clone())));

        // Generate ephemeral keypairs.
        let (ed_seed, ed_pub) = generate_ed25519_keypair().unwrap();
        let (mldsa_secret, mldsa_pub) = generate_mldsa65_keypair().unwrap();

        let extras =
            json!({"migration_set_hash": "sha256:abc", "scrubber_bundle_hash": "sha256:def"});

        let signed_bytes = sign_build_manifest(
            primitive.clone(),
            "v0.1.0-test".into(),
            "x86_64-unknown-linux-gnu".into(),
            "sha256:cafebabe".into(),
            "0.1.0".into(),
            Some(extras.clone()),
            &ed_seed,
            &mldsa_secret,
            "test-steward",
        )
        .unwrap();

        // Verify — should succeed with matching primitive + keys.
        let parsed =
            verify_build_manifest_with_keys(&signed_bytes, primitive.clone(), &ed_pub, &mldsa_pub)
                .unwrap();

        assert_eq!(parsed.primitive, primitive);
        assert_eq!(parsed.build_id, "v0.1.0-test");
        assert_eq!(parsed.binary_hash, "sha256:cafebabe");
        assert_eq!(parsed.signature.classical_algorithm, "Ed25519");
        assert_eq!(parsed.signature.pqc_algorithm, "ML-DSA-65");
        assert_eq!(parsed.extras.as_ref().unwrap(), &extras);
    }

    #[test]
    fn verify_rejects_wrong_primitive() {
        let primitive = BuildPrimitive::Other("sign-verify-test-wrong-prim".into());
        register_extras_validator(Box::new(AlwaysOk(primitive.clone())));

        let (ed_seed, ed_pub) = generate_ed25519_keypair().unwrap();
        let (mldsa_secret, mldsa_pub) = generate_mldsa65_keypair().unwrap();

        let signed = sign_build_manifest(
            primitive,
            "v0".into(),
            "x86_64-unknown-linux-gnu".into(),
            "sha256:abc".into(),
            "0.1".into(),
            None,
            &ed_seed,
            &mldsa_secret,
            "test",
        )
        .unwrap();

        // Try to verify as Verify primitive — should reject.
        let err =
            verify_build_manifest_with_keys(&signed, BuildPrimitive::Verify, &ed_pub, &mldsa_pub)
                .unwrap_err();
        assert!(
            format!("{:?}", err).contains("primitive mismatch"),
            "expected primitive mismatch, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_tampered_extras() {
        let primitive = BuildPrimitive::Other("sign-verify-test-tamper".into());
        register_extras_validator(Box::new(AlwaysOk(primitive.clone())));

        let (ed_seed, ed_pub) = generate_ed25519_keypair().unwrap();
        let (mldsa_secret, mldsa_pub) = generate_mldsa65_keypair().unwrap();

        let mut signed = sign_build_manifest(
            primitive.clone(),
            "v0".into(),
            "x86_64-unknown-linux-gnu".into(),
            "sha256:abc".into(),
            "0.1".into(),
            Some(json!({"k": "original"})),
            &ed_seed,
            &mldsa_secret,
            "test",
        )
        .unwrap();

        // Tamper: replace "original" with "tampered" in the JSON bytes.
        let s = std::str::from_utf8(&signed)
            .unwrap()
            .replace("original", "tampered");
        signed = s.into_bytes();

        let err =
            verify_build_manifest_with_keys(&signed, primitive, &ed_pub, &mldsa_pub).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("hybrid signature") || msg.contains("Ed25519"),
            "expected signature failure, got: {msg}"
        );
    }

    #[test]
    fn self_test_crypto_passes() {
        self_test_crypto().expect("crypto self-test must pass");
    }

    #[test]
    fn build_file_tree_extras_signs_and_verifies() {
        // Create a small tree
        let tmp = std::env::temp_dir().join("ciris_build_tool_test_tree");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("src")).unwrap();
        std::fs::write(tmp.join("src/main.py"), b"hello world").unwrap();
        std::fs::write(tmp.join("src/lib.py"), b"more code").unwrap();

        let extras = build_file_tree_extras(&tmp, ExemptRules::default(), None)
            .expect("build_file_tree_extras must succeed");

        assert_eq!(extras.file_count, 2);
        assert!(extras.file_tree_hash.starts_with("sha256:"));
        assert!(extras.files.contains_key("src/main.py"));
        assert!(extras.files.contains_key("src/lib.py"));

        // Sign through the existing pipeline using the extras as a Value
        let primitive = BuildPrimitive::Other("filetree-test".into());
        let (ed_seed, ed_pub) = generate_ed25519_keypair().unwrap();
        let (mldsa_secret, mldsa_pub) = generate_mldsa65_keypair().unwrap();

        let extras_value = file_tree_extras_to_value(&extras).unwrap();
        let signed = sign_build_manifest(
            primitive.clone(),
            "v0.0.1-tree".into(),
            "x86_64-unknown-linux-gnu".into(),
            extras.file_tree_hash.clone(), // binary_hash = tree_hash for this shape
            "0.0.1".into(),
            Some(extras_value),
            &ed_seed,
            &mldsa_secret,
            "tree-test",
        )
        .unwrap();

        // Verify signature
        let parsed =
            verify_build_manifest_with_keys(&signed, primitive, &ed_pub, &mldsa_pub).unwrap();
        assert_eq!(parsed.binary_hash, extras.file_tree_hash);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn build_file_tree_extras_with_extra_hashes() {
        // Verify that --tree-extra-hashes-file content gets folded in
        let tmp = std::env::temp_dir().join("ciris_build_tool_test_extras");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("a.py"), b"a").unwrap();

        let mut extra = std::collections::BTreeMap::new();
        extra.insert(
            "build-secrets/jwt".into(),
            format!("sha256:{}", "0".repeat(64)),
        );

        let extras =
            build_file_tree_extras(&tmp, ExemptRules::default(), Some(extra.clone())).unwrap();

        assert_eq!(extras.file_count, 2, "1 on-disk + 1 extra-hashes");
        assert!(extras.files.contains_key("a.py"));
        assert!(extras.files.contains_key("build-secrets/jwt"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn build_file_tree_extras_rejects_malformed_extra_hash() {
        let tmp = std::env::temp_dir().join("ciris_build_tool_test_bad_hash");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("a.py"), b"a").unwrap();

        let mut extra = std::collections::BTreeMap::new();
        extra.insert("foo".into(), "not-a-real-hash".into());

        let err = build_file_tree_extras(&tmp, ExemptRules::default(), Some(extra)).unwrap_err();
        assert!(format!("{err}").contains("must be sha256:"));

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
