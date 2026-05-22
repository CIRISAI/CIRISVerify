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

/// HKDF salt for transport-identity seed derivation (CIRISVerify#29
/// WS-1, v2.10.0+). A distinct salt from [`NAMED_KEY_DERIVE_SALT`] so a
/// transport seed and a symmetric key derived from the *same* local seed
/// are cryptographically independent — domain separation, not just a
/// different `info` string. **Stable wire constant.**
const TRANSPORT_IDENTITY_DERIVE_SALT: &[u8] = b"CIRIS-transport-identity-v1";

/// Length of a derived symmetric key in bytes (256-bit).
pub const DERIVED_KEY_LEN: usize = 32;

/// Length of a derived transport-identity seed in bytes (256-bit).
pub const TRANSPORT_SEED_LEN: usize = 32;

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

/// Derive a deterministic 256-bit transport-identity seed from a stored
/// local-identity seed (CIRISVerify#29 WS-1).
///
/// A federation member's mesh *transport identity* (for Reticulum, the
/// `hash(x25519‖ed25519)` destination) must be a separate key from its
/// federation signing key — AV-17 keeps the federation seed out of the
/// transport process. This function lets a member derive that transport
/// key material **deterministically from its one `local_seed`** instead
/// of generating and storing a second seed:
///
/// ```text
/// PRK  = HKDF-Extract(salt = "CIRIS-transport-identity-v1", IKM = seed)
/// tseed = HKDF-Expand(PRK, info = interface, L = 32)
/// ```
///
/// The return value is **seed material, not a keypair.** CIRISVerify
/// stays transport-agnostic: the transport layer (CIRISEdge / Reticulum)
/// instantiates the actual x25519 + ed25519 identity from these 32
/// bytes. CIRISVerify owns the *derivation*; edge owns the transport
/// *semantics* — the same layering as [`crate::federation_envelope`].
///
/// `interface` domain-separates a multi-homed member's transport seeds:
/// one member, one identity, but reachable on several interfaces (e.g.
/// `"lora"`, `"ip-reticulum"`) — each a distinct, independent transport
/// seed from the same local seed. Pass `""` for a single-homed member.
///
/// This derivation is independent of [`derive_symmetric_key`] by
/// construction: a different HKDF salt means a transport seed and a
/// symmetric key derived from the *same* local seed share no
/// computable relationship.
///
/// # Errors
///
/// - [`VerifyError::KeyringError`] if the seed for `key_id` can't be
///   loaded from `storage`.
/// - [`VerifyError::IntegrityError`] if HKDF expansion fails (unreachable
///   for the fixed 32-byte output; mapped rather than `unwrap`'d).
pub fn derive_transport_identity(
    storage: &dyn SecureBlobStorage,
    key_id: &str,
    interface: &str,
) -> Result<Vec<u8>, VerifyError> {
    let seed = storage.load(key_id)?;
    let hkdf = Hkdf::<Sha256>::new(Some(TRANSPORT_IDENTITY_DERIVE_SALT), &seed);
    let mut derived = [0u8; TRANSPORT_SEED_LEN];
    hkdf.expand(interface.as_bytes(), &mut derived)
        .map_err(|_| VerifyError::IntegrityError {
            message: "HKDF-SHA256 expand failed for transport-identity derivation".to_string(),
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

    // ---- transport-identity derivation (WS-1) ---------------------------

    #[test]
    fn transport_seed_is_32_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_with_seed(tmp.path(), "k1", &[0x11u8; 32]);
        let seed = derive_transport_identity(&storage, "k1", "lora").unwrap();
        assert_eq!(seed.len(), TRANSPORT_SEED_LEN);
    }

    #[test]
    fn transport_derivation_is_deterministic() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_with_seed(tmp.path(), "k1", &[0x22u8; 32]);
        let a = derive_transport_identity(&storage, "k1", "ip-reticulum").unwrap();
        let b = derive_transport_identity(&storage, "k1", "ip-reticulum").unwrap();
        assert_eq!(
            a, b,
            "same (seed, interface) must yield the same transport seed"
        );
    }

    #[test]
    fn transport_different_interface_yields_independent_seed() {
        // Multi-homing: one member, one identity, several interfaces —
        // each interface gets its own independent transport seed.
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_with_seed(tmp.path(), "k1", &[0x33u8; 32]);
        let lora = derive_transport_identity(&storage, "k1", "lora").unwrap();
        let ip = derive_transport_identity(&storage, "k1", "ip-reticulum").unwrap();
        assert_ne!(
            lora, ip,
            "different interface must yield an independent seed"
        );
    }

    #[test]
    fn transport_different_local_seed_yields_independent_seed() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = SoftwareSecureBlobStorage::new("test", tmp.path()).unwrap();
        storage.store("k-a", &[0x44u8; 32]).unwrap();
        storage.store("k-b", &[0x55u8; 32]).unwrap();
        let a = derive_transport_identity(&storage, "k-a", "iface").unwrap();
        let b = derive_transport_identity(&storage, "k-b", "iface").unwrap();
        assert_ne!(
            a, b,
            "different local seed must yield a different transport seed"
        );
    }

    #[test]
    fn transport_missing_key_id_is_keyring_error() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = SoftwareSecureBlobStorage::new("test", tmp.path()).unwrap();
        let err = derive_transport_identity(&storage, "no-such-key", "iface").unwrap_err();
        assert!(matches!(err, VerifyError::KeyringError(_)), "got: {err:?}");
    }

    /// Domain separation: a transport seed and a symmetric key derived
    /// from the **same local seed** with the **same context/interface
    /// string** must be cryptographically independent — the distinct
    /// HKDF salt is what guarantees it. If this fails, the two salts
    /// collided or one was dropped.
    #[test]
    fn transport_seed_independent_of_symmetric_key() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_with_seed(tmp.path(), "k1", &[0x66u8; 32]);
        let sym = derive_symmetric_key(&storage, "k1", "shared-string").unwrap();
        let tport = derive_transport_identity(&storage, "k1", "shared-string").unwrap();
        assert_ne!(
            sym, tport,
            "same seed + same info but different salt must be independent"
        );
    }

    /// Wire-constant tripwire for transport-identity derivation — see
    /// [`known_answer_is_stable`]. KAT inputs: seed = `[0x01; 32]`,
    /// interface = `"kat-iface"`, salt = `"CIRIS-transport-identity-v1"`.
    #[test]
    fn transport_known_answer_is_stable() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = storage_with_seed(tmp.path(), "kat", &[0x01u8; 32]);
        let seed = derive_transport_identity(&storage, "kat", "kat-iface").unwrap();
        assert_eq!(
            hex::encode(&seed),
            TRANSPORT_KNOWN_ANSWER_KAT,
            "transport-identity HKDF derivation drifted from recorded KAT"
        );
    }

    /// Recorded known-answer for [`transport_known_answer_is_stable`].
    /// Computed from the v2.10.0 implementation.
    const TRANSPORT_KNOWN_ANSWER_KAT: &str =
        "03a24e18005a6df71f9515638e378a4734afb2704c46d2946f71ddd18b069d7d";
}
