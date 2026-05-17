//! Single-call local signing-identity seed loader (CIRISVerify#20 v2.1.0;
//! renamed from `steward_seed` in v2.4.0 — see "Naming" below).
//!
//! Returns `(Arc<dyn HardwareSigner>, Option<Arc<dyn PqcSigner>>)` from
//! filesystem seed files in one shot. Federation consumers (CIRISEdge,
//! CIRISPersist, CIRISLensCore, sovereign agents) each wrap these Arcs
//! in their own domain signer types — before v2.1.0 each crate
//! reinvented the seed→Arcs glue (read 32 bytes, validate length,
//! construct signer, optionally load PQC, fail-coherently on
//! both-or-neither, etc.).
//!
//! The traits and platform impls already exist — `Ed25519SoftwareSigner`
//! for classical (with `from_bytes` taking the 32-byte raw seed) and
//! `MlDsa65SoftwareSigner::from_seed_file` for PQC. This module is the
//! glue.
//!
//! ## Naming (v2.4.0)
//!
//! v2.1.0 shipped this as `load_steward_seed` / `StewardSeedConfig` —
//! incorrect vocabulary. **"Steward"** in CIRIS means a bootstrap-trusted
//! root identity (the entries in `bootstrap_stewards.json`, e.g. the
//! CIRISRegistry primary signing key). What this loader actually loads
//! is a deployment's *local* signing identity (persist's signer, edge's
//! signer, an agent's signer) — keys the deployment owns and signs its
//! own work with, not the trust anchor it was born knowing about.
//!
//! v2.4.0 renames to `load_local_seed` / `LocalSeedConfig` to match
//! CIRISPersist v1.5.1 + CIRISEdge `LocalSigner` vocabulary. The
//! `steward_seed` module survives one minor cycle as deprecated
//! re-exports; removal in v2.5.0.
//!
//! ## Config shape
//!
//! Separate `key_id` + `key_path` for classical, optional `pqc_key_id` +
//! `pqc_key_path` for PQC. Both-or-neither on the PQC pair — caller
//! passing one without the other gets a typed error before the file
//! system is touched.
//!
//! ## Software-only today
//!
//! v2.1.0 returns a software-backed `Ed25519SoftwareSigner` wrapped in
//! `Arc<dyn HardwareSigner>`. The trait is satisfied; the implementation
//! is software. Hardware-backed local signing keys (TPM / Android
//! Keystore / iOS Secure Enclave) are a future extension — a
//! hardware-bound identity is identified by alias only, doesn't have an
//! on-disk seed, and won't flow through this loader. Hardware-backed
//! callers use [`crate::get_platform_signer`] directly.

use std::path::PathBuf;
use std::sync::Arc;

use crate::error::KeyringError;
use crate::pqc::{MlDsa65SoftwareSigner, PqcSigner};
use crate::signer::HardwareSigner;
use crate::software::Ed25519SoftwareSigner;

/// Configuration for [`load_local_seed`].
///
/// Field semantics:
///
/// - `key_id`: local signing-identity name (e.g. `"persist-local"`,
///   `"edge-local"`, `"<deployment>-local"`). Surfaced as the
///   `HardwareSigner::current_alias()` of the returned classical signer.
/// - `key_path`: filesystem path to a 32-byte raw Ed25519 seed. Read
///   permission required; the OS handles the chmod check.
/// - `pqc_key_id` + `pqc_key_path`: optional ML-DSA-65 local signing
///   identity. Both must be set together or both omitted — the loader
///   returns `KeyringError::InvalidKey` if the pair is mismatched.
#[derive(Debug, Clone)]
pub struct LocalSeedConfig {
    /// Local signing-identity key_id for the classical signer.
    pub key_id: String,
    /// Filesystem path to the 32-byte raw Ed25519 seed.
    pub key_path: PathBuf,
    /// Optional ML-DSA-65 local signing-identity key_id. Both-or-neither
    /// with `pqc_key_path`.
    pub pqc_key_id: Option<String>,
    /// Filesystem path to the 32-byte raw ML-DSA-65 seed. Both-or-neither
    /// with `pqc_key_id`.
    pub pqc_key_path: Option<PathBuf>,
}

/// Load a local signing identity from filesystem seeds and return the
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
/// use ciris_keyring::{load_local_seed, LocalSeedConfig};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let (classical, pqc) = load_local_seed(LocalSeedConfig {
///     key_id: "persist-local".into(),
///     key_path: PathBuf::from("/etc/ciris/persist-local.seed"),
///     pqc_key_id: Some("persist-local-pqc".into()),
///     pqc_key_path: Some(PathBuf::from("/etc/ciris/persist-local.pqc.seed")),
/// }).await?;
///
/// assert!(pqc.is_some());
/// // Hand classical + pqc to your domain wrapper (LocalSigner / Edge / Persist / ...).
/// # Ok(())
/// # }
/// ```
pub async fn load_local_seed(
    config: LocalSeedConfig,
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
            reason: format!("reading Ed25519 local seed from {path_str}: {e}"),
        })?;

    // 3. Construct classical signer (Ed25519SoftwareSigner validates the
    //    32-byte length internally and returns InvalidKey if wrong).
    let classical_software = Ed25519SoftwareSigner::from_bytes(&seed_bytes, &config.key_id)?;
    tracing::info!(
        key_id = config.key_id.as_str(),
        seed_path = path_str.as_str(),
        "load_local_seed: classical Ed25519 local identity loaded"
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
                "load_local_seed: PQC ML-DSA-65 local identity loaded"
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

        let (classical, pqc) = load_local_seed(LocalSeedConfig {
            key_id: "test-local".into(),
            key_path: seed_path,
            pqc_key_id: None,
            pqc_key_path: None,
        })
        .await
        .expect("load ok");

        assert!(pqc.is_none(), "PQC should be None when both fields omitted");
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

        let (classical, pqc) = load_local_seed(LocalSeedConfig {
            key_id: "test-local".into(),
            key_path: ed_path,
            pqc_key_id: Some("test-local-pqc".into()),
            pqc_key_path: Some(pqc_path),
        })
        .await
        .expect("load ok");

        assert_eq!(classical.public_key().await.expect("ed pubkey").len(), 32);
        let pqc = pqc.expect("PQC should be Some");
        let pqc_pub = pqc.public_key().await.expect("pqc pubkey");
        assert_eq!(pqc_pub.len(), 1952);
    }

    async fn expect_err_loading(cfg: LocalSeedConfig) -> KeyringError {
        match load_local_seed(cfg).await {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        }
    }

    #[tokio::test]
    async fn rejects_pqc_id_without_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let seed_path = tmp.path().join("ed25519.seed");
        write_seed(&seed_path, &[0u8; 32]);

        let err = expect_err_loading(LocalSeedConfig {
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

        let err = expect_err_loading(LocalSeedConfig {
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
        write_seed(&seed_path, &[0u8; 16]);

        let err = expect_err_loading(LocalSeedConfig {
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
        let err = expect_err_loading(LocalSeedConfig {
            key_id: "test".into(),
            key_path: PathBuf::from("/nonexistent/path/to/seed"),
            pqc_key_id: None,
            pqc_key_path: None,
        })
        .await;
        assert!(matches!(err, KeyringError::OperationFailed { .. }));
    }
}
