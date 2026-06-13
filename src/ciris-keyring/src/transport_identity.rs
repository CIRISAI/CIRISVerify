//! Keyring-backed storage for the Reticulum (RNS) **transport identity**
//! (CIRISVerify#68; consumer CIRISEdge#99).
//!
//! The RNS transport identity is 64 raw private-key bytes —
//! `x25519_priv (32) ‖ ed25519_priv (32)` — that Reticulum/leviculum
//! loads via `Identity::from_private_key_bytes`. CIRISEdge writes those
//! bytes to a `chmod 600` plaintext file at the operator-configured
//! `identity_path`. The **federation signing key** has been keyring-backed
//! since the CIRISPersist AV-25 closure; the **transport identity** has
//! not — so filesystem-exfil, backup-leakage, and snapshot-leakage all hit
//! it today. The trust root stays intact (forging a federation envelope
//! still needs the signing key), but an attacker who lifts the transport
//! identity can stand up a peer claiming the edge's RNS destination and
//! reroute traffic. Hardware-backed at-rest closes that.
//!
//! This module gives the transport identity the same per-tier hardware
//! protection the wallet seed already has, by riding the existing
//! [`SecureBlobStorage`] backends ([`crate::storage`]): TPM 2.0 sealed
//! object (Linux/Windows), Secure Enclave (iOS/macOS), Keystore/StrongBox
//! (Android), and an encrypted software fallback. There are no new per-tier
//! backends — [`BlobTransportKeystore`] is a thin, length-typed adapter
//! over whatever tier [`crate::storage::create_platform_storage`] selects.
//!
//! ## AV-17 — at-rest vs. transient-in-process (a deliberate carve-out)
//!
//! `HardwareSigner` enforces AV-17 strictly: the private seed never enters
//! the consuming process's memory. This surface **cannot** match that,
//! because Reticulum's `Identity::from_private_key_bytes` consumes the raw
//! 64-byte buffer for its own crypto — the bytes are necessarily in the
//! edge process's memory transiently, from the [`TransportIdentityKeystore::load`]
//! return until the `Identity` is constructed. So the guarantee here is
//! **hardware-backed at rest, transient in process, scrubbed after** — which
//! still defeats the realistic threat (filesystem / backup / snapshot /
//! multi-tenant-fs exfil), which is the whole point. The stronger property
//! (Reticulum operations performed entirely inside the secure boundary,
//! raw bytes never exposed) would require leviculum to expose only
//! sign/decrypt ops instead of `from_private_key_bytes`; that is tracked
//! separately if it ever becomes load-bearing.
//!
//! `generate_and_store` scrubs its transient buffer after storing.
//! [`TransportIdentityKeystore::load`] returns the 64 bytes by value — the
//! caller owns them and SHOULD zeroize after constructing the `Identity`.

use std::path::PathBuf;

use crate::error::KeyringError;
use crate::storage::{create_platform_storage, SecureBlobStorage};

/// Length of an RNS transport identity: `x25519_priv (32) ‖ ed25519_priv (32)`.
pub const TRANSPORT_IDENTITY_LEN: usize = 64;

/// Keyring-backed store for the 64-byte RNS transport identity.
///
/// Companion of `HardwareSigner` / `PqcSigner` — same lifecycle shape, a
/// different key class. `Send + Sync` (and the concrete impl is `'static`)
/// so a consumer can hold an `Arc<dyn TransportIdentityKeystore>` alongside
/// its `Arc<dyn HardwareSigner>`.
pub trait TransportIdentityKeystore: Send + Sync {
    /// Store the 64-byte transport identity under `key_id`, overwriting any
    /// existing entry. `key_id` is typically derived from the federation
    /// `signer_key_id` so the two co-locate in keyring scoping.
    ///
    /// **This is also the import/adopt primitive for migration** (CIRISEdge#99,
    /// "the load-bearing part"): a deployment with an existing identity at its
    /// on-disk `identity_path` reads those 64 bytes and `store`s them here —
    /// the destination hash is preserved, so peer routing tables and signed
    /// announces keep working (auto-*regeneration* on upgrade is unacceptable;
    /// adopting the bytes verbatim is the whole point). The caller does the
    /// file read + archive (`.migrated-<ts>`); this never touches the filesystem
    /// path. Adopting bytes from a token-held key works identically — `store`
    /// is byte-source-agnostic; it does not validate keypair structure (that's
    /// Reticulum's job at `Identity::from_private_key_bytes`).
    fn store(&self, key_id: &str, bytes: &[u8; TRANSPORT_IDENTITY_LEN])
        -> Result<(), KeyringError>;

    /// Load the transport identity. `Ok(None)` means no entry is present
    /// (the migration trigger for a fresh install). A stored blob whose
    /// length is not exactly 64 is a hard [`KeyringError::InvalidKey`] —
    /// fail-closed, never a silently-truncated identity.
    fn load(&self, key_id: &str) -> Result<Option<[u8; TRANSPORT_IDENTITY_LEN]>, KeyringError>;

    /// Generate a fresh 64-byte identity from the OS CSPRNG and store it
    /// atomically (durable before return). The transient buffer is scrubbed
    /// after the store.
    fn generate_and_store(&self, key_id: &str) -> Result<(), KeyringError>;

    /// Delete the stored identity. `Ok(())` even if absent (idempotent) —
    /// for rotation / migration cleanup.
    fn delete(&self, key_id: &str) -> Result<(), KeyringError>;

    /// Whether the backing tier is hardware-backed (TPM / SE / StrongBox).
    /// Mirrors [`SecureBlobStorage::is_hardware_backed`] so a consumer can
    /// surface the at-rest posture honestly.
    fn is_hardware_backed(&self) -> bool;
}

/// A [`TransportIdentityKeystore`] backed by any [`SecureBlobStorage`] tier.
///
/// This is the whole implementation: the per-tier hardware backends already
/// exist for the wallet seed, so the transport identity rides them with a
/// length-typed adapter rather than a parallel backend per platform.
pub struct BlobTransportKeystore {
    storage: Box<dyn SecureBlobStorage>,
}

impl BlobTransportKeystore {
    /// Wrap an explicit storage backend (e.g. a `SoftwareSecureBlobStorage`
    /// in tests, or a specific tier).
    #[must_use]
    pub fn new(storage: Box<dyn SecureBlobStorage>) -> Self {
        Self { storage }
    }

    /// Build over the best storage tier this platform offers
    /// ([`create_platform_storage`]): TPM/SE/StrongBox where available,
    /// encrypted software fallback otherwise.
    pub fn platform(
        alias: impl Into<String>,
        storage_dir: impl Into<PathBuf>,
    ) -> Result<Self, KeyringError> {
        Ok(Self::new(create_platform_storage(alias, storage_dir)?))
    }
}

impl TransportIdentityKeystore for BlobTransportKeystore {
    fn store(
        &self,
        key_id: &str,
        bytes: &[u8; TRANSPORT_IDENTITY_LEN],
    ) -> Result<(), KeyringError> {
        self.storage.store(key_id, &bytes[..])
    }

    fn load(&self, key_id: &str) -> Result<Option<[u8; TRANSPORT_IDENTITY_LEN]>, KeyringError> {
        match self.storage.load(key_id) {
            Ok(raw) => {
                let arr: [u8; TRANSPORT_IDENTITY_LEN] =
                    raw.as_slice()
                        .try_into()
                        .map_err(|_| KeyringError::InvalidKey {
                            reason: format!(
                                "transport identity {key_id} is {} bytes, expected {}",
                                raw.len(),
                                TRANSPORT_IDENTITY_LEN
                            ),
                        })?;
                Ok(Some(arr))
            },
            // Absent entry is a normal "fresh install" signal, not an error.
            Err(KeyringError::KeyNotFound { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn generate_and_store(&self, key_id: &str) -> Result<(), KeyringError> {
        use rand_core::{OsRng, RngCore};

        let mut bytes = [0u8; TRANSPORT_IDENTITY_LEN];
        OsRng.fill_bytes(&mut bytes);
        let result = self.storage.store(key_id, &bytes[..]);
        // Best-effort scrub of the transient buffer. The threat model this
        // closes is at-rest exfil (the AV-17 carve-out concedes transient
        // in-memory exposure), so this is hygiene, not a load-bearing barrier.
        bytes.iter_mut().for_each(|b| *b = 0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        result
    }

    fn delete(&self, key_id: &str) -> Result<(), KeyringError> {
        self.storage.delete(key_id)
    }

    fn is_hardware_backed(&self) -> bool {
        self.storage.is_hardware_backed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SoftwareSecureBlobStorage;

    fn software_keystore(dir: &std::path::Path) -> BlobTransportKeystore {
        let storage = SoftwareSecureBlobStorage::new("test-transport", dir).unwrap();
        BlobTransportKeystore::new(Box::new(storage))
    }

    fn tmpdir() -> std::path::PathBuf {
        // Per-test unique dir under the OS temp root; OsRng for the suffix so
        // parallel tests don't collide (the keyring forbids Date/rand-free).
        use rand_core::{OsRng, RngCore};
        let mut suffix = [0u8; 8];
        OsRng.fill_bytes(&mut suffix);
        let mut p = std::env::temp_dir();
        p.push(format!("ciris-transport-test-{}", hex_lower(&suffix)));
        p
    }

    fn hex_lower(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn store_then_load_round_trips() {
        let dir = tmpdir();
        let ks = software_keystore(&dir);
        let id = [7u8; TRANSPORT_IDENTITY_LEN];
        ks.store("edge-rns-v1", &id).unwrap();
        assert_eq!(ks.load("edge-rns-v1").unwrap(), Some(id));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_absent_is_none_not_error() {
        let dir = tmpdir();
        let ks = software_keystore(&dir);
        assert_eq!(ks.load("never-stored").unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_and_store_yields_loadable_nonzero_identity() {
        let dir = tmpdir();
        let ks = software_keystore(&dir);
        ks.generate_and_store("edge-rns-v1").unwrap();
        let loaded = ks
            .load("edge-rns-v1")
            .unwrap()
            .expect("present after generate");
        // Overwhelmingly not all-zero (a dead RNG would be).
        assert!(loaded.iter().any(|&b| b != 0));
        // A second generate replaces it with different bytes.
        ks.generate_and_store("edge-rns-v1").unwrap();
        let loaded2 = ks.load("edge-rns-v1").unwrap().unwrap();
        assert_ne!(loaded, loaded2, "regenerate must rotate the identity");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_length_blob_is_invalid_key_not_silent_truncation() {
        let dir = tmpdir();
        // Store a 32-byte blob directly via the underlying storage, then load
        // through the typed keystore — must fail closed, never truncate.
        let storage = SoftwareSecureBlobStorage::new("test-transport", &dir).unwrap();
        storage.store("edge-rns-v1", &[1u8; 32]).unwrap();
        let ks = BlobTransportKeystore::new(Box::new(storage));
        assert!(matches!(
            ks.load("edge-rns-v1"),
            Err(KeyringError::InvalidKey { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_is_idempotent() {
        let dir = tmpdir();
        let ks = software_keystore(&dir);
        ks.store("edge-rns-v1", &[3u8; TRANSPORT_IDENTITY_LEN])
            .unwrap();
        ks.delete("edge-rns-v1").unwrap();
        assert_eq!(ks.load("edge-rns-v1").unwrap(), None);
        // Deleting an absent key is Ok.
        ks.delete("edge-rns-v1").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_existing_identity_migration_flow() {
        // Mirror CIRISEdge#99's load_or_generate_identity exactly:
        //   keyring miss → adopt the existing on-disk bytes → keyring hit,
        //   WITHOUT regenerating (the destination hash must be preserved).
        let dir = tmpdir();
        let ks = software_keystore(&dir);
        let key_id = "edge-rns-v1";

        // 1. Fresh keyring: load is None → migration trigger.
        assert_eq!(ks.load(key_id).unwrap(), None);

        // 2. "Read the existing identity_path file" — the 64 bytes edge already
        //    has on disk. Import them verbatim via `store` (NOT generate).
        let existing_on_disk = [0x5Au8; TRANSPORT_IDENTITY_LEN];
        ks.store(key_id, &existing_on_disk).unwrap();

        // 3. Now the keyring has it — and it is byte-identical to the file, so
        //    the RNS destination hash is unchanged and peer routing survives.
        assert_eq!(ks.load(key_id).unwrap(), Some(existing_on_disk));

        // 4. A subsequent start takes the keyring-hit branch and never touches
        //    generate_and_store — re-importing the same bytes is idempotent.
        ks.store(key_id, &existing_on_disk).unwrap();
        assert_eq!(ks.load(key_id).unwrap(), Some(existing_on_disk));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keystore_is_object_safe_send_sync() {
        // The cohabitation requirement: edge holds Arc<dyn …>.
        let dir = tmpdir();
        let ks: std::sync::Arc<dyn TransportIdentityKeystore> =
            std::sync::Arc::new(software_keystore(&dir));
        fn assert_send_sync<T: Send + Sync + ?Sized>(_: &T) {}
        assert_send_sync(&*ks);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
