//! Hardware-rooted symmetric key derivation (CIRISVerify#25, v2.5.0+).
//!
//! Named-key HKDF-SHA256 derivation: load a seed from a hardware-backed
//! [`SecureBlobStorage`] (TPM / Android Keystore / iOS Secure Enclave, or
//! the software fallback), then derive a 256-bit symmetric key from it.
//!
//! ## Why this lives in `ciris-verify-core`
//!
//! v2.4.0 shipped this capability only as a method on `ciris-verify-ffi`'s
//! `CirisVerifyHandle`. But `ciris-verify-ffi` builds `cdylib` + `staticlib`
//! only — no `rlib` — so no Rust crate can `use` it; the capability was
//! reachable solely through the C ABI.
//!
//! CIRISPersist's `secrets-hw` (CIRISPersist#87) needs hardware-rooted
//! symmetric derivation for the secrets-store master key, and persist
//! links `ciris-verify-core` directly. The CIRIS design principle is
//! "persist calls verify for every crypto op, never rolls its own" — so
//! the derivation belongs in the rlib where Rust consumers reach it.
//!
//! `ciris-verify-ffi`'s `CirisVerifyHandle::derive_symmetric_key` now
//! delegates here; the C ABI is unchanged.

use ciris_keyring::storage::SecureBlobStorage;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::VerifyError;

/// HKDF salt for named-key symmetric derivation.
///
/// Domain-separates this derivation from every other HKDF use in the
/// stack. **Stable wire constant** — changing it invalidates every
/// previously-derived key, so it must never change without a coordinated
/// migration.
const NAMED_KEY_DERIVE_SALT: &[u8] = b"CIRIS-named-key-derive-v1";

/// Length of a derived symmetric key in bytes (256-bit).
pub const DERIVED_KEY_LEN: usize = 32;

/// Derive a 256-bit symmetric key from a stored named-key seed.
///
/// Loads the seed for `key_id` from `storage`, then runs HKDF-SHA256:
///
/// ```text
/// PRK = HKDF-Extract(salt = "CIRIS-named-key-derive-v1", IKM = seed)
/// key = HKDF-Expand(PRK, info = context, L = 32)
/// ```
///
/// `context` domain-separates multiple derived keys from a single seed —
/// pass a stable, caller-meaningful string (e.g.
/// `"secrets-store-master-v1"`). The same `(seed, context)` always
/// yields the same key; a different `context` yields an independent key.
///
/// # Errors
///
/// - [`VerifyError::KeyringError`] if the seed for `key_id` can't be
///   loaded from `storage` (missing key, storage backend failure).
/// - [`VerifyError::IntegrityError`] if HKDF expansion fails. This is
///   unreachable for the fixed 32-byte output (HKDF-Expand only fails
///   when the requested length exceeds `255 * HashLen`), but it's mapped
///   rather than `unwrap`'d so a future longer-output variant can't
///   panic.
pub fn derive_symmetric_key(
    storage: &dyn SecureBlobStorage,
    key_id: &str,
    context: &str,
) -> Result<Vec<u8>, VerifyError> {
    let seed = storage.load(key_id)?;
    let hkdf = Hkdf::<Sha256>::new(Some(NAMED_KEY_DERIVE_SALT), &seed);
    let mut derived = [0u8; DERIVED_KEY_LEN];
    hkdf.expand(context.as_bytes(), &mut derived)
        .map_err(|_| VerifyError::IntegrityError {
            message: "HKDF-SHA256 expand failed for symmetric key derivation".to_string(),
        })?;
    Ok(derived.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_keyring::storage::SoftwareSecureBlobStorage;

    fn storage_with_seed(
        dir: &std::path::Path,
        key_id: &str,
        seed: &[u8],
    ) -> SoftwareSecureBlobStorage {
        let storage = SoftwareSecureBlobStorage::new("test", dir).expect("storage");
        storage.store(key_id, seed).expect("store seed");
        storage
    }

    #[test]
    fn derives_32_byte_key() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_with_seed(tmp.path(), "k1", &[0x11u8; 32]);
        let key = derive_symmetric_key(&storage, "k1", "ctx-a").unwrap();
        assert_eq!(key.len(), DERIVED_KEY_LEN);
    }

    #[test]
    fn derivation_is_deterministic() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_with_seed(tmp.path(), "k1", &[0x22u8; 32]);
        let a = derive_symmetric_key(&storage, "k1", "secrets-store-master-v1").unwrap();
        let b = derive_symmetric_key(&storage, "k1", "secrets-store-master-v1").unwrap();
        assert_eq!(a, b, "same (seed, context) must yield the same key");
    }

    #[test]
    fn different_context_yields_independent_key() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_with_seed(tmp.path(), "k1", &[0x33u8; 32]);
        let a = derive_symmetric_key(&storage, "k1", "context-one").unwrap();
        let b = derive_symmetric_key(&storage, "k1", "context-two").unwrap();
        assert_ne!(a, b, "different context must yield a different key");
    }

    #[test]
    fn different_seed_yields_independent_key() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = SoftwareSecureBlobStorage::new("test", tmp.path()).unwrap();
        storage.store("k-a", &[0x44u8; 32]).unwrap();
        storage.store("k-b", &[0x55u8; 32]).unwrap();
        let a = derive_symmetric_key(&storage, "k-a", "same-ctx").unwrap();
        let b = derive_symmetric_key(&storage, "k-b", "same-ctx").unwrap();
        assert_ne!(a, b, "different seed must yield a different key");
    }

    #[test]
    fn missing_key_id_is_keyring_error() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = SoftwareSecureBlobStorage::new("test", tmp.path()).unwrap();
        let err = derive_symmetric_key(&storage, "no-such-key", "ctx").unwrap_err();
        assert!(
            matches!(err, VerifyError::KeyringError(_)),
            "expected KeyringError, got: {err:?}"
        );
    }

    /// Lock the wire constant: the derived key for a fixed (seed, context)
    /// must not drift. If this fails, the HKDF salt, hash, or expand call
    /// changed — and every previously-derived key in the field is now
    /// invalid. That break is intentional only under a coordinated
    /// migration; otherwise this test is the tripwire.
    ///
    /// KAT inputs: seed = `[0x01; 32]`, context = `"kat-context"`,
    /// salt = `"CIRIS-named-key-derive-v1"`.
    #[test]
    fn known_answer_is_stable() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_with_seed(tmp.path(), "kat", &[0x01u8; 32]);
        let key = derive_symmetric_key(&storage, "kat", "kat-context").unwrap();
        assert_eq!(
            hex::encode(&key),
            KNOWN_ANSWER_KAT,
            "HKDF derivation drifted from recorded KAT"
        );
    }

    /// Recorded known-answer for [`known_answer_is_stable`]. Computed from
    /// the v2.5.0 implementation.
    const KNOWN_ANSWER_KAT: &str =
        "ce04cd7fef9096d64a46853f1d2d25d15f1d6eed5d4ceb36b824400a6afed697";
}
