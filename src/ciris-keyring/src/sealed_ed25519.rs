//! TPM/SE-sealed **Ed25519** federation signing key (CIRISVerify#70).
//!
//! The signer analog of [`crate::transport_identity::BlobTransportKeystore`]
//! (#68): it seals a 32-byte **Ed25519 seed** via [`SecureBlobStorage`] (the
//! best hardware tier available — TPM 2.0 / Secure Enclave / Keystore, else
//! an encrypted software fallback) and loads it into an
//! [`Ed25519SoftwareSigner`] for use. So the seed never sits in plaintext at
//! rest, **while `public_key()` stays a 32-byte Ed25519 key** — which is what
//! the federation/Reticulum identity requires (`key_id = sha256(ed25519_pubkey)`
//! and the AV-42 authenticated-announce path both demand the 32-byte form).
//!
//! ## Why this exists
//!
//! `get_platform_signer` / `create_hardware_signer` on a firmware TPM returns
//! a **TPM-native ECDSA-P256** key (65-byte uncompressed pubkey) — correct for
//! ECDSA use cases, but unusable as the **Ed25519-rooted** federation signing
//! identity (CIRISServer's Reticulum announce fails: *"federation Ed25519
//! pubkey must be 32 bytes, got 65"*). `get_platform_ed25519_signer` is the
//! algorithm-preserving alternative: hardware custody of the seed, Ed25519 on
//! the wire. The TPM-native ECDSA path stays correct for ECDSA callers.
//!
//! ## Lifecycle (mirrors #68)
//!
//! - **Adopt sealed** — a seed already sealed at `seed_dir` is loaded verbatim
//!   (key_id preserved across restarts).
//! - **Adopt existing** — [`SealedEd25519Signer::adopt`] seals a caller-supplied
//!   32-byte seed **byte-identically** (the software-Ed25519 → TPM migration:
//!   the destination hash / `key_id` is unchanged, so announces and routing
//!   survive). Only seals if no sealed seed is present yet — idempotent.
//! - **Generate** — [`SealedEd25519Signer::open_or_create`] (`None`) on a fresh `seed_dir`
//!   generates a 32-byte seed from the OS CSPRNG and seals it.
//!
//! Same AV-17 carve-out as #68: hardware-backed at rest; the seed is in
//! process memory transiently while the Ed25519 signer holds it (signing is
//! software over a sealed-at-rest seed), and the load-time buffer is scrubbed.

use std::path::PathBuf;

use async_trait::async_trait;

use crate::error::KeyringError;
use crate::signer::{HardwareSigner, KeyGenConfig};
use crate::software::Ed25519SoftwareSigner;
use crate::storage::{create_platform_storage, SecureBlobStorage};
use crate::types::{ClassicalAlgorithm, HardwareType, PlatformAttestation, StorageDescriptor};

/// SecureBlobStorage key the sealed Ed25519 seed lives under.
const SEED_KEY_ID: &str = "ed25519.seed";
/// Ed25519 seed length.
const SEED_LEN: usize = 32;

/// A [`HardwareSigner`] whose Ed25519 seed is sealed at rest by the platform's
/// best [`SecureBlobStorage`] tier, while signing in Ed25519.
pub struct SealedEd25519Signer {
    inner: Ed25519SoftwareSigner,
    storage: Box<dyn SecureBlobStorage>,
    alias: String,
    seed_dir: PathBuf,
}

impl SealedEd25519Signer {
    /// Open the sealed Ed25519 signer at `seed_dir`.
    ///
    /// Resolution order: a sealed seed already present is adopted verbatim;
    /// otherwise, if `adopt_seed` is `Some`, that 32-byte seed is sealed
    /// byte-identically (the software→hardware migration); otherwise a fresh
    /// seed is generated from the OS CSPRNG and sealed.
    pub fn open_or_create(
        alias: impl Into<String>,
        seed_dir: impl Into<PathBuf>,
        adopt_seed: Option<&[u8; SEED_LEN]>,
    ) -> Result<Self, KeyringError> {
        let alias = alias.into();
        let seed_dir = seed_dir.into();

        // Deliberate first-seal: re-open if present, else seal. Re-open paths
        // must NOT come through here with `None` (that would mint a fresh key
        // on a missing seed — the #134 hazard); they use `open_existing`.
        match Self::open_existing(alias.clone(), seed_dir.clone()) {
            Ok(signer) => Ok(signer),
            Err(KeyringError::KeyNotFound { .. }) => {
                let storage = create_platform_storage(&alias, &seed_dir)?;
                let mut s = [0u8; SEED_LEN];
                match adopt_seed {
                    Some(existing) => s.copy_from_slice(existing),
                    None => {
                        use rand_core::{OsRng, RngCore};
                        OsRng.fill_bytes(&mut s);
                    },
                }
                storage.store(SEED_KEY_ID, &s)?;
                let inner = Ed25519SoftwareSigner::from_bytes(&s, alias.clone())?;
                s.iter_mut().for_each(|b| *b = 0);
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
                Ok(Self {
                    inner,
                    storage,
                    alias,
                    seed_dir,
                })
            },
            Err(e) => Err(e),
        }
    }

    /// **Re-open** an existing sealed Ed25519 signer — **load-only**. Errors
    /// [`KeyringError::KeyNotFound`] if no sealed seed is present at `seed_dir`.
    /// Re-opening an identity must never mint a fresh seed (it would swap the
    /// key for an unverifiable one; CIRISVerify#134). The deliberate first-seal
    /// is [`Self::adopt`] / [`Self::open_or_create`].
    pub fn open_existing(
        alias: impl Into<String>,
        seed_dir: impl Into<PathBuf>,
    ) -> Result<Self, KeyringError> {
        let alias = alias.into();
        let seed_dir = seed_dir.into();
        let storage = create_platform_storage(&alias, &seed_dir)?;

        // `KeyNotFound` propagates — re-open does NOT fabricate a seed (#134).
        let raw = storage.load(SEED_KEY_ID)?;
        let mut seed: [u8; SEED_LEN] =
            raw.as_slice()
                .try_into()
                .map_err(|_| KeyringError::InvalidKey {
                    reason: format!(
                        "sealed Ed25519 seed is {} bytes, expected {SEED_LEN}",
                        raw.len()
                    ),
                })?;

        let inner = Ed25519SoftwareSigner::from_bytes(&seed, alias.clone())?;
        // Scrub the local seed copy; the live key now lives in `inner`, the
        // durable copy is sealed in `storage` (AV-17 carve-out: at-rest is the
        // threat this closes — the seed is necessarily in memory while held).
        seed.iter_mut().for_each(|b| *b = 0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        Ok(Self {
            inner,
            storage,
            alias,
            seed_dir,
        })
    }

    /// **Re-open** an existing sealed signer (load-only). Errors
    /// [`KeyringError::KeyNotFound`] if absent — re-opening never mints
    /// (CIRISVerify#134). Use [`Self::adopt`] / [`Self::open_or_create`] for the
    /// deliberate first-seal.
    pub fn open(
        alias: impl Into<String>,
        seed_dir: impl Into<PathBuf>,
    ) -> Result<Self, KeyringError> {
        Self::open_existing(alias, seed_dir)
    }

    /// Adopt an existing 32-byte Ed25519 `seed` byte-identically (the
    /// software-Ed25519 → hardware-sealed migration). Seals it only if no
    /// sealed seed is present yet, so it's idempotent and never clobbers an
    /// already-migrated key.
    pub fn adopt(
        alias: impl Into<String>,
        seed_dir: impl Into<PathBuf>,
        seed: &[u8; SEED_LEN],
    ) -> Result<Self, KeyringError> {
        Self::open_or_create(alias, seed_dir, Some(seed))
    }
}

/// Best-tier sealed **Ed25519** federation signer (CIRISVerify#70) — the
/// Ed25519 counterpart to `get_platform_signer` (which yields TPM-native
/// ECDSA). Auto-detects the hardware tier with software fallback. **Re-opens** a
/// previously-sealed seed; errors `KeyNotFound` if absent — it never mints, so a
/// missing seed surfaces instead of silently swapping the identity (#134;
/// deliberate first-seal is `SealedEd25519Signer::adopt` / `open_or_create`).
/// Returns a `Box<dyn HardwareSigner>` whose `public_key()` is the 32-byte Ed25519 key,
/// ready for `ciris_persist::Engine::with_hardware_signer` /
/// `ciris_edge::LocalSigner`.
pub fn get_platform_ed25519_signer(
    alias: &str,
    seed_dir: impl Into<PathBuf>,
) -> Result<Box<dyn HardwareSigner>, KeyringError> {
    Ok(Box::new(SealedEd25519Signer::open(alias, seed_dir)?))
}

#[async_trait]
impl HardwareSigner for SealedEd25519Signer {
    fn algorithm(&self) -> ClassicalAlgorithm {
        ClassicalAlgorithm::Ed25519
    }

    fn hardware_type(&self) -> HardwareType {
        // Reflect the actual at-rest tier: the seed is hardware-sealed only if
        // the storage backend is hardware-backed; otherwise it's software.
        if self.storage.is_hardware_backed() {
            crate::platform::detect_hardware_type().hardware_type
        } else {
            HardwareType::SoftwareOnly
        }
    }

    async fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
        self.inner.public_key().await
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        self.inner.sign(data).await
    }

    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
        self.inner.attestation().await
    }

    async fn generate_key(&self, config: &KeyGenConfig) -> Result<(), KeyringError> {
        if config.require_hardware && !self.storage.is_hardware_backed() {
            return Err(KeyringError::HardwareError {
                reason: "hardware sealing required but SecureBlobStorage tier is software-only"
                    .into(),
            });
        }
        // The seed was generated+sealed (or adopted) at construction; a second
        // generate over the same alias is a no-op-or-conflict, not a silent
        // re-key (re-keying would change the federation key_id).
        if self.storage.exists(SEED_KEY_ID) {
            return Err(KeyringError::KeyAlreadyExists {
                alias: self.alias.clone(),
            });
        }
        Ok(())
    }

    async fn key_exists(&self, alias: &str) -> Result<bool, KeyringError> {
        Ok(alias == self.alias && self.storage.exists(SEED_KEY_ID))
    }

    async fn delete_key(&self, alias: &str) -> Result<(), KeyringError> {
        if alias != self.alias {
            return Err(KeyringError::KeyNotFound {
                alias: alias.to_string(),
            });
        }
        self.storage.delete(SEED_KEY_ID)
    }

    fn current_alias(&self) -> &str {
        &self.alias
    }

    fn storage_descriptor(&self) -> StorageDescriptor {
        // The wrapper is the right place to describe the real location (see the
        // note on Ed25519SoftwareSigner::storage_descriptor): the seed lives in
        // a hardware-sealed blob when the tier is hardware-backed.
        if self.storage.is_hardware_backed() {
            StorageDescriptor::Hardware {
                hardware_type: crate::platform::detect_hardware_type().hardware_type,
                blob_path: None,
            }
        } else {
            StorageDescriptor::SoftwareFile {
                path: self.seed_dir.join(format!("{}.{SEED_KEY_ID}", self.alias)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};

    fn tmpdir() -> PathBuf {
        use rand_core::{OsRng, RngCore};
        let mut suffix = [0u8; 8];
        OsRng.fill_bytes(&mut suffix);
        let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
        let mut p = std::env::temp_dir();
        p.push(format!("ciris-sealed-ed25519-{hex}"));
        p
    }

    /// The core #70 fix: the federation signer's pubkey is **32-byte Ed25519**,
    /// not a 65-byte ECDSA pubkey.
    #[tokio::test]
    async fn pubkey_is_32_byte_ed25519_and_signs() {
        let dir = tmpdir();
        // Mint (deliberate first-seal) — re-open is load-only now (#134).
        let signer = SealedEd25519Signer::open_or_create("fed-key", &dir, None).unwrap();
        assert_eq!(signer.algorithm(), ClassicalAlgorithm::Ed25519);
        let pk = signer.public_key().await.unwrap();
        assert_eq!(pk.len(), 32, "federation pubkey must be 32-byte Ed25519");

        // Real Ed25519 verification of a produced signature.
        let msg = b"reticulum announce";
        let sig = signer.sign(msg).await.unwrap();
        let vk = VerifyingKey::from_bytes(pk.as_slice().try_into().unwrap()).unwrap();
        let signature = Signature::from_slice(&sig).unwrap();
        assert!(vk.verify(msg, &signature).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Adopt an existing software seed byte-identically: the pubkey (hence the
    /// federation key_id) is exactly the seed's Ed25519 pubkey.
    #[tokio::test]
    async fn adopt_existing_seed_preserves_pubkey() {
        let dir = tmpdir();
        let seed = [0x42u8; SEED_LEN];
        let expected_pk = SigningKey::from_bytes(&seed).verifying_key().to_bytes();

        let signer = SealedEd25519Signer::adopt("fed-key", &dir, &seed).unwrap();
        assert_eq!(signer.public_key().await.unwrap(), expected_pk.to_vec());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Sealed seed survives reopen (same key_id across restarts) and re-adopt
    /// is idempotent (does not clobber the migrated key).
    #[tokio::test]
    async fn sealed_seed_persists_and_readopt_is_idempotent() {
        let dir = tmpdir();
        let pk1 = {
            // Mint (deliberate first-seal).
            let s = SealedEd25519Signer::open_or_create("fed-key", &dir, None).unwrap();
            s.public_key().await.unwrap()
        };
        // Reopen (load-only) → same key.
        let pk2 = {
            let s = SealedEd25519Signer::open("fed-key", &dir).unwrap();
            s.public_key().await.unwrap()
        };
        assert_eq!(pk1, pk2, "sealed seed must survive reopen");

        // adopt() with a DIFFERENT seed must NOT overwrite the already-sealed key.
        let other = [0x99u8; SEED_LEN];
        let s = SealedEd25519Signer::adopt("fed-key", &dir, &other).unwrap();
        assert_eq!(
            s.public_key().await.unwrap(),
            pk1,
            "re-adopt must not clobber"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn tier_reporting_is_honest() {
        // The honesty invariant (env-independent): `hardware_type` reports
        // `SoftwareOnly` IFF `storage_descriptor` is a `SoftwareFile`. The
        // signer never claims hardware backing it lacks, nor hides backing it
        // has. On a software box this lands on the SoftwareFile arm; on a
        // TPM/SE box with the platform feature (e.g. `--features tpm`, the
        // Linux release wheel) it lands on the Hardware arm. Either is honest;
        // a disagreement is the bug.
        let dir = tmpdir();
        let signer = SealedEd25519Signer::open_or_create("fed-key", &dir, None).unwrap();
        let tier_is_software = signer.hardware_type() == HardwareType::SoftwareOnly;
        let descriptor_is_software = matches!(
            signer.storage_descriptor(),
            StorageDescriptor::SoftwareFile { .. }
        );
        assert_eq!(
            tier_is_software, descriptor_is_software,
            "hardware_type and storage_descriptor must agree on the backing tier"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn delete_then_key_absent() {
        let dir = tmpdir();
        let signer = SealedEd25519Signer::open_or_create("fed-key", &dir, None).unwrap();
        assert!(signer.key_exists("fed-key").await.unwrap());
        signer.delete_key("fed-key").await.unwrap();
        assert!(!signer.key_exists("fed-key").await.unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn holds_as_arc_dyn_hardware_signer() {
        // The CIRISServer consumption: Arc<dyn HardwareSigner> for persist/edge.
        let dir = tmpdir();
        // Mint first; the factory re-opens (load-only) now (#134).
        SealedEd25519Signer::open_or_create("fed-key", &dir, None).unwrap();
        let signer: std::sync::Arc<dyn HardwareSigner> =
            std::sync::Arc::from(get_platform_ed25519_signer("fed-key", &dir).unwrap());
        assert_eq!(signer.public_key().await.unwrap().len(), 32);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #134 regression: re-opening a non-existent sealed seed must FAIL, never
    /// silently mint a fresh key (which would swap the federation identity).
    #[tokio::test]
    async fn open_fails_loud_on_missing_seed() {
        let dir = tmpdir();
        assert!(matches!(
            SealedEd25519Signer::open("fed-key", &dir),
            Err(KeyringError::KeyNotFound { .. })
        ));
        assert!(matches!(
            SealedEd25519Signer::open_existing("fed-key", &dir),
            Err(KeyringError::KeyNotFound { .. })
        ));
        assert!(
            get_platform_ed25519_signer("fed-key", &dir).is_err(),
            "the factory re-opens — it must not mint on a missing seed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
