//! Backend-agnostic federation-identity creation — the one core both the
//! `ciris-verify identity create` CLI and the FFI (`ciris_verify_create_
//! federation_identity`, for the KMP client's mobile/desktop UI) call.
//!
//! The caller opens a hardware Ed25519 [`HardwareSigner`] for whatever backend
//! fits the platform — a YubiKey PIV token (desktop), a Secure Enclave /
//! StrongBox / TPM-sealed key (mobile/desktop, auto-provisioned by
//! `get_platform_ed25519_signer`), or a software key (test). This module then
//! does the platform-independent rest: derive the federation `key_id`, attach
//! the software ML-DSA-65 PQC half (a stable seed under `~/ciris/keys`), and
//! emit the self-signed genesis [`SignedCegObject`] for the
//! [`crate::ceg_outbox`].
//!
//! **Provisioning split.** *Generating* the hardware key is backend-specific
//! and stays with the caller: `get_platform_ed25519_signer` creates the sealed
//! key on first open (mobile/desktop SE), while a YubiKey PIV slot is
//! provisioned out-of-band with `ykman` (the CLI's `--provision`) because PIV
//! slot policy + the slot certificate are PIV-applet operations, not PKCS#11.
//! By the time a signer reaches this module the key exists.

use std::sync::Arc;

use ciris_keyring::{HardwareSigner, KeyringError};
use sha2::{Digest, Sha256};

use crate::ceg_outbox::{keys_dir, sanitize_segment, SignedCegObject};
use crate::error::VerifyError;
use crate::federation_self_record::produce_self_key_record;
use crate::self_at_login::HardwareRootedIdentity;

/// The CEG `kind` of a genesis federation key record.
pub const FEDERATION_KEY_RECORD_KIND: &str = "federation_key_record";

fn keyring_err(e: KeyringError) -> VerifyError {
    VerifyError::IntegrityError {
        message: format!("hardware signer fault: {e}"),
    }
}

fn crypto_err(e: ciris_crypto::CryptoError) -> VerifyError {
    VerifyError::IntegrityError {
        message: format!("ML-DSA-65 signer: {e}"),
    }
}

/// The outcome of creating a federation identity.
pub struct CreatedIdentity {
    /// The federation `key_id` (caller-chosen, else `sha256(ed_pubkey)` hex).
    pub key_id: String,
    /// The signed CEG object to relay (a self-signed genesis `KeyRecord`).
    pub object: SignedCegObject,
}

/// Create a self-signed genesis federation identity from an already-opened
/// hardware Ed25519 signer.
///
/// `hw_signer` MUST be Ed25519 (the federation classical half) and its key MUST
/// already exist (the caller provisioned it). The software ML-DSA-65 half is a
/// stable seed loaded-or-created under `~/ciris/keys/<key_id>.mldsa.seed`.
/// `valid_from` is caller-supplied RFC-3339 (clock-free for reproducible bytes).
///
/// Returns the `key_id` + the [`SignedCegObject`]; the caller writes it to the
/// outbox ([`SignedCegObject::write_to_outbox`]).
///
/// # Errors
///
/// [`VerifyError`] if the signer is not Ed25519, the pubkey/seed cannot be
/// read, or signing fails.
pub async fn create_federation_identity(
    hw_signer: Arc<dyn HardwareSigner>,
    identity_type: &str,
    fed_key_id: Option<String>,
    valid_from: &str,
) -> Result<CreatedIdentity, VerifyError> {
    let ed_pub = hw_signer.public_key().await.map_err(keyring_err)?;
    let key_id = fed_key_id.unwrap_or_else(|| hex::encode(Sha256::digest(&ed_pub)));

    let seed = load_or_create_mldsa_seed(&keys_dir(), &key_id).map_err(|e| {
        VerifyError::IntegrityError {
            message: format!("ML-DSA-65 seed: {e}"),
        }
    })?;
    let mldsa = ciris_crypto::MlDsa65Signer::from_seed(&seed).map_err(crypto_err)?;

    let identity = HardwareRootedIdentity::new(key_id.clone(), hw_signer, mldsa)?;
    let record = produce_self_key_record(&identity, identity_type, valid_from).await?;
    let body = serde_json::to_value(&record).map_err(|e| VerifyError::IntegrityError {
        message: format!("serialize key record: {e}"),
    })?;

    let object = SignedCegObject::new(FEDERATION_KEY_RECORD_KIND, &key_id, valid_from, body);
    Ok(CreatedIdentity { key_id, object })
}

/// Load the 32-byte ML-DSA-65 seed for `key_id` from
/// `<keys>/<sanitized key_id>.mldsa.seed`, or create one with the fail-secure
/// CSPRNG. On unix the file is created `0600` **atomically** (an exclusive
/// `create_new` with mode set) so the seed is never momentarily world-readable
/// and two concurrent runs can't both mint a key. `key_id` is sanitized to a
/// single path segment so a `--fed-key-id` override can't escape the keys dir.
///
/// # Errors
///
/// A string describing the CSPRNG / filesystem / length fault.
pub fn load_or_create_mldsa_seed(
    keys_dir: &std::path::Path,
    key_id: &str,
) -> Result<Vec<u8>, String> {
    let path = keys_dir.join(format!("{}.mldsa.seed", sanitize_segment(key_id)));

    if path.exists() {
        return read_seed(&path);
    }

    let mut seed = vec![0u8; 32];
    ciris_crypto::random::fill(&mut seed).map_err(|e| format!("CSPRNG: {e}"))?;
    std::fs::create_dir_all(keys_dir).map_err(|e| format!("create {}: {e}", keys_dir.display()))?;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(&path) {
        Ok(mut f) => {
            use std::io::Write;
            f.write_all(&seed)
                .map_err(|e| format!("write seed {}: {e}", path.display()))?;
            Ok(seed)
        },
        // A concurrent run won the race — read its seed.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read_seed(&path),
        Err(e) => Err(format!("create seed {}: {e}", path.display())),
    }
}

fn read_seed(path: &std::path::Path) -> Result<Vec<u8>, String> {
    let seed = std::fs::read(path).map_err(|e| format!("read seed {}: {e}", path.display()))?;
    if seed.len() != 32 {
        return Err(format!(
            "seed {} is {} bytes, expected 32 (refusing to mint a different identity)",
            path.display(),
            seed.len()
        ));
    }
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("ciris-fedid-{tag}-{}", std::process::id()))
    }

    #[test]
    fn seed_create_then_load_is_stable_and_0600() {
        let dir = tmp("seed");
        let _ = std::fs::remove_dir_all(&dir);
        let a = load_or_create_mldsa_seed(&dir, "key-1").unwrap();
        assert_eq!(a.len(), 32);
        let b = load_or_create_mldsa_seed(&dir, "key-1").unwrap();
        assert_eq!(a, b, "second call must return the SAME seed");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("key-1.mldsa.seed"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_wrong_length_rejected() {
        let dir = tmp("badlen");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("k.mldsa.seed"), [0u8; 16]).unwrap();
        assert!(load_or_create_mldsa_seed(&dir, "k")
            .unwrap_err()
            .contains("expected 32"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fed_key_id_cannot_escape_keys_dir() {
        let dir = tmp("traversal");
        let _ = std::fs::remove_dir_all(&dir);
        load_or_create_mldsa_seed(&dir, "../../etc/evil").unwrap();
        let entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "one sanitized file, no subdirs");
        assert!(!entries[0]
            .file_name()
            .to_string_lossy()
            .contains(std::path::MAIN_SEPARATOR));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn create_identity_from_software_ed25519_signer() {
        // A software Ed25519 HardwareSigner stands in for a YubiKey / SE — the
        // core is backend-agnostic, so this exercises the whole flow.
        let dir = tmp("create");
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var(crate::ceg_outbox::CIRIS_HOME_ENV, &dir);

        let hw: Arc<dyn HardwareSigner> =
            Arc::new(ciris_keyring::Ed25519SoftwareSigner::from_bytes(&[9u8; 32], "fed").unwrap());
        let created = create_federation_identity(hw, "user", None, "2026-06-18T00:00:00Z")
            .await
            .unwrap();

        assert_eq!(created.object.kind, FEDERATION_KEY_RECORD_KIND);
        assert_eq!(created.object.key_id, created.key_id);
        // The body is the SignedKeyRecord wrapper { record: {...} } — the exact
        // `peer_key_record` shape CIRISServer accepts; signature inside `body`.
        let rec = &created.object.body["record"];
        assert_eq!(rec["scrub_key_id"], rec["key_id"], "self-signed genesis");
        assert_eq!(rec["identity_type"], "user");
        assert_eq!(rec["algorithm"], "hybrid");
        assert!(created.object.signatures.is_none());

        std::env::remove_var(crate::ceg_outbox::CIRIS_HOME_ENV);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
