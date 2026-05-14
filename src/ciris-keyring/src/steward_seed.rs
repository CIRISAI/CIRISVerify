//! Single-call steward seed loader (CIRISVerify#20, v2.1.0+).
//!
//! Returns `(Arc<dyn HardwareSigner>, Option<Arc<dyn PqcSigner>>)` from
//! filesystem seed files in one shot. Federation consumers (CIRISEdge,
//! CIRISPersist, CIRISLensCore, sovereign agents) each wrap these Arcs in
//! their own domain `StewardSigner` types — before v2.1.0 each crate
//! reinvented the seed→Arcs glue (read 32 bytes, validate length,
//! construct signer, optionally load PQC, fail-coherently on
//! both-or-neither, etc.).
//!
//! The traits and platform impls already exist — `Ed25519SoftwareSigner`
//! for classical (with `from_bytes` taking the 32-byte raw seed) and
//! `MlDsa65SoftwareSigner::from_seed_file` for PQC. This module is the
//! glue.
//!
//! ## Config shape
//!
//! Mirrors the proven [`StewardSignerConfig`] pattern from CIRISPersist
//! `src/signing/mod.rs:75`: separate `key_id` + `key_path` for classical,
//! optional `pqc_key_id` + `pqc_key_path` for PQC. Both-or-neither on the
//! PQC pair — caller passing one without the other gets a typed error
//! before the file system is touched.
//!
//! ## Software-only today
//!
//! v2.1.0 returns a software-backed `Ed25519SoftwareSigner` wrapped in
//! `Arc<dyn HardwareSigner>`. The trait is satisfied; the implementation
//! is software. Hardware-backed steward keys (TPM / Android Keystore /
//! iOS Secure Enclave) are a future extension — a hardware-bound steward
//! is identified by alias only, doesn't have an on-disk seed, and won't
//! flow through this loader. Hardware-backed callers use
//! [`crate::get_platform_signer`] directly.

use std::path::PathBuf;
use std::sync::Arc;

use crate::error::KeyringError;
use crate::pqc::{MlDsa65SoftwareSigner, PqcSigner};
use crate::signer::HardwareSigner;
use crate::software::Ed25519SoftwareSigner;

/// Configuration for [`load_steward_seed`].
///
/// Mirrors `CIRISPersist::signing::StewardSignerConfig` exactly so persist
/// can adopt this loader without reshaping its callers. Field semantics:
///
/// - `key_id`: steward identity name (e.g. `"persist-steward"`,
///   `"edge-steward"`, `"<deployment>-steward"`). Surfaced as the
///   `HardwareSigner::current_alias()` of the returned classical signer.
/// - `key_path`: filesystem path to a 32-byte raw Ed25519 seed. Read
///   permission required; the OS handles the chmod check.
/// - `pqc_key_id` + `pqc_key_path`: optional ML-DSA-65 steward
///   identity. Both must be set together or both omitted — the loader
///   returns `KeyringError::InvalidKey` if the pair is mismatched.
#[derive(Debug, Clone)]
pub struct StewardSeedConfig {
    /// Steward identity key_id for the classical signer.
    pub key_id: String,
    /// Filesystem path to the 32-byte raw Ed25519 seed.
    pub key_path: PathBuf,
    /// Optional ML-DSA-65 steward identity key_id. Both-or-neither with
    /// `pqc_key_path`.
    pub pqc_key_id: Option<String>,
    /// Filesystem path to the 32-byte raw ML-DSA-65 seed. Both-or-neither
    /// with `pqc_key_id`.
    pub pqc_key_path: Option<PathBuf>,
}

/// Load a steward identity from filesystem seeds and return the
/// classical + optional PQC signers as trait-object Arcs.
///
/// # Behavior
///
/// 1. Validates the PQC config pair (both `pqc_key_id` and `pqc_key_path`
///    set, or both `None`). Fails fast with `KeyringError::InvalidKey`
///    before touching the filesystem if the pair is inconsistent.
/// 2. Reads the Ed25519 seed at `config.key_path`. Validates it's
///    exactly 32 bytes via `Ed25519SoftwareSigner::from_bytes`.
/// 3. Wraps in `Arc<dyn HardwareSigner>`.
/// 4. If PQC config is present, reads the ML-DSA-65 seed at
///    `config.pqc_key_path` via `MlDsa65SoftwareSigner::from_seed_file`.
///    Wraps in `Arc<dyn PqcSigner>`.
/// 5. Returns `(classical, Option<pqc>)`.
///
/// # Errors
///
/// - `KeyringError::InvalidKey` for inconsistent PQC config, malformed
///   seed length, or unparseable seed bytes.
/// - `KeyringError::OperationFailed` for filesystem I/O errors reading
///   either seed file.
///
/// # Async signature
///
/// The function is `async` for forward-compat with future hardware-backed
/// loading paths (TPM / OS-keyring) that need to await platform daemons.
/// Today's software-only implementation does no async work — callers
/// blocking on it in a sync context pay only the future-poll overhead.
///
/// # Example
///
/// ```no_run
/// use std::path::PathBuf;
/// use ciris_keyring::{load_steward_seed, StewardSeedConfig};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let (classical, pqc) = load_steward_seed(StewardSeedConfig {
///     key_id: "persist-steward".into(),
///     key_path: PathBuf::from("/etc/ciris/persist-steward.seed"),
///     pqc_key_id: Some("persist-steward-pqc".into()),
///     pqc_key_path: Some(PathBuf::from("/etc/ciris/persist-steward.pqc.seed")),
/// }).await?;
///
/// assert!(pqc.is_some());
/// // Hand classical + pqc to your domain wrapper (StewardSigner / Edge / Persist / ...).
/// # Ok(())
/// # }
/// ```
pub async fn load_steward_seed(
    config: StewardSeedConfig,
) -> Result<(Arc<dyn HardwareSigner>, Option<Arc<dyn PqcSigner>>), KeyringError> {
    // 1. Validate PQC config pair before touching the filesystem.
    match (&config.pqc_key_id, &config.pqc_key_path) {
        (None, None) | (Some(_), Some(_)) => {},
        _ => {
            return Err(KeyringError::InvalidKey {
                reason: "pqc_key_id and pqc_key_path must both be set or both omitted".into(),
            });
        },
    }

    // 2. Read Ed25519 seed.
    let path_str = config.key_path.display().to_string();
    let seed_bytes =
        std::fs::read(&config.key_path).map_err(|e| KeyringError::OperationFailed {
            reason: format!("reading Ed25519 steward seed from {path_str}: {e}"),
        })?;

    // 3. Construct classical signer (Ed25519SoftwareSigner validates the
    //    32-byte length internally and returns InvalidKey if wrong).
    let classical_software = Ed25519SoftwareSigner::from_bytes(&seed_bytes, &config.key_id)?;
    tracing::info!(
        key_id = config.key_id.as_str(),
        seed_path = path_str.as_str(),
        "load_steward_seed: classical Ed25519 steward identity loaded"
    );
    let classical: Arc<dyn HardwareSigner> = Arc::new(classical_software);

    // 4. PQC, if configured.
    let pqc: Option<Arc<dyn PqcSigner>> = match (&config.pqc_key_id, &config.pqc_key_path) {
        (Some(id), Some(path)) => {
            let path_str = path.display().to_string();
            let signer = MlDsa65SoftwareSigner::from_seed_file(path, id)?;
            tracing::info!(
                pqc_key_id = id.as_str(),
                pqc_seed_path = path_str.as_str(),
                "load_steward_seed: PQC ML-DSA-65 steward identity loaded"
            );
            Some(Arc::new(signer) as Arc<dyn PqcSigner>)
        },
        _ => None,
    };

    Ok((classical, pqc))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_seed(path: &std::path::Path, bytes: &[u8]) {
        std::fs::write(path, bytes).expect("write test seed");
    }

    #[tokio::test]
    async fn loads_classical_only_when_pqc_omitted() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let seed_path = tmp.path().join("ed25519.seed");
        write_seed(&seed_path, &[0x42u8; 32]);

        let (classical, pqc) = load_steward_seed(StewardSeedConfig {
            key_id: "test-steward".into(),
            key_path: seed_path,
            pqc_key_id: None,
            pqc_key_path: None,
        })
        .await
        .expect("load ok");

        assert!(pqc.is_none(), "PQC should be None when both fields omitted");
        // Classical should have a public key (Ed25519 is deterministic from seed).
        let pubkey = classical.public_key().await.expect("public_key");
        assert_eq!(pubkey.len(), 32, "Ed25519 public key is 32 bytes");
    }

    #[tokio::test]
    async fn loads_classical_plus_pqc_when_both_provided() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let ed_path = tmp.path().join("ed25519.seed");
        let pqc_path = tmp.path().join("mldsa.seed");
        write_seed(&ed_path, &[0x42u8; 32]);
        write_seed(&pqc_path, &[0x07u8; 32]);

        let (classical, pqc) = load_steward_seed(StewardSeedConfig {
            key_id: "test-steward".into(),
            key_path: ed_path,
            pqc_key_id: Some("test-steward-pqc".into()),
            pqc_key_path: Some(pqc_path),
        })
        .await
        .expect("load ok");

        assert_eq!(classical.public_key().await.expect("ed pubkey").len(), 32);
        let pqc = pqc.expect("PQC should be Some");
        let pqc_pub = pqc.public_key().await.expect("pqc pubkey");
        // ML-DSA-65 public keys are 1952 bytes per FIPS 204.
        assert_eq!(pqc_pub.len(), 1952);
    }

    /// Helper — `Arc<dyn Trait>` doesn't implement Debug so the standard
    /// `.expect_err(...)` chain doesn't compile against this signature.
    /// Match explicitly to extract the error.
    async fn expect_err_loading(cfg: StewardSeedConfig) -> KeyringError {
        match load_steward_seed(cfg).await {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        }
    }

    #[tokio::test]
    async fn rejects_pqc_id_without_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let seed_path = tmp.path().join("ed25519.seed");
        write_seed(&seed_path, &[0u8; 32]);

        let err = expect_err_loading(StewardSeedConfig {
            key_id: "test".into(),
            key_path: seed_path,
            pqc_key_id: Some("orphan".into()),
            pqc_key_path: None,
        })
        .await;
        match err {
            KeyringError::InvalidKey { reason } => {
                assert!(reason.contains("pqc_key_id"));
                assert!(reason.contains("pqc_key_path"));
            },
            other => panic!("expected InvalidKey, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_pqc_path_without_id() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let ed_path = tmp.path().join("ed25519.seed");
        let orphan_pqc = tmp.path().join("orphan.seed");
        write_seed(&ed_path, &[0u8; 32]);
        write_seed(&orphan_pqc, &[0u8; 32]);

        let err = expect_err_loading(StewardSeedConfig {
            key_id: "test".into(),
            key_path: ed_path,
            pqc_key_id: None,
            pqc_key_path: Some(orphan_pqc),
        })
        .await;
        assert!(matches!(err, KeyringError::InvalidKey { .. }));
    }

    #[tokio::test]
    async fn rejects_wrong_length_ed25519_seed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let seed_path = tmp.path().join("short.seed");
        write_seed(&seed_path, &[0u8; 16]); // wrong length

        let err = expect_err_loading(StewardSeedConfig {
            key_id: "test".into(),
            key_path: seed_path,
            pqc_key_id: None,
            pqc_key_path: None,
        })
        .await;
        assert!(matches!(err, KeyringError::InvalidKey { .. }));
    }

    #[tokio::test]
    async fn surfaces_filesystem_error_on_missing_seed() {
        let err = expect_err_loading(StewardSeedConfig {
            key_id: "test".into(),
            key_path: PathBuf::from("/nonexistent/path/to/seed"),
            pqc_key_id: None,
            pqc_key_path: None,
        })
        .await;
        assert!(matches!(err, KeyringError::OperationFailed { .. }));
    }
}
