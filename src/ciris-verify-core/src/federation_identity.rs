//! Backend-agnostic federation-identity creation — the one core both the
//! `ciris-verify identity create` CLI and the FFI (`ciris_verify_create_
//! federation_identity`, for the KMP client's mobile/desktop UI) call.
//!
//! The caller opens a hardware Ed25519 [`HardwareSigner`] for whatever backend
//! fits the platform — a YubiKey PIV token (desktop), a Secure Enclave /
//! StrongBox / TPM-sealed key (mobile/desktop, auto-provisioned by
//! `get_platform_ed25519_signer`), or a software key (test). This module then
//! does the platform-independent rest: derive the federation `key_id`, attach
//! the ML-DSA-65 PQC half whose seed is **sealed at rest** by the platform
//! secure storage (#71 `get_platform_sealed_mldsa65_signer` — TPM with
//! `--features tpm`, SE / StrongBox on mobile, software AES-GCM-sealed
//! fallback), and emit the self-signed genesis [`SignedCegObject`] for the
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

use crate::ceg_outbox::{keys_dir, SignedCegObject};
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

    // The ML-DSA-65 PQC half: TPM/SE-sealed at rest (#71). The 32-byte seed is
    // sealed under the platform secure storage (TPM with `--features tpm`,
    // Secure Enclave / StrongBox on mobile; software-sealed AES-GCM fallback
    // otherwise — never a plaintext file) and unsealed only transiently to
    // sign. Auto-generates + seals on first call, adopts the sealed seed after.
    let mldsa = ciris_keyring::get_platform_sealed_mldsa65_signer(&key_id, keys_dir())
        .map_err(keyring_err)?;

    let identity = HardwareRootedIdentity::new(key_id.clone(), hw_signer, Arc::from(mldsa))?;
    let record = produce_self_key_record(&identity, identity_type, valid_from).await?;
    let body = serde_json::to_value(&record).map_err(|e| VerifyError::IntegrityError {
        message: format!("serialize key record: {e}"),
    })?;

    let object = SignedCegObject::new(FEDERATION_KEY_RECORD_KIND, &key_id, valid_from, body);
    Ok(CreatedIdentity { key_id, object })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("ciris-fedid-{tag}-{}", std::process::id()))
    }

    #[tokio::test]
    // The env-serialization guard is intentionally held across the await — the
    // CIRIS_HOME env must stay set through the async create, and this is a
    // single-threaded test runtime (no deadlock risk).
    #[allow(clippy::await_holding_lock)]
    async fn create_identity_from_software_ed25519_signer() {
        // A software Ed25519 HardwareSigner stands in for a YubiKey / SE — the
        // core is backend-agnostic, so this exercises the whole flow.
        let _g = crate::ceg_outbox::CIRIS_HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
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
