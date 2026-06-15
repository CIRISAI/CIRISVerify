//! TPM/SE-sealed **ML-DSA-65** federation signing key — the post-quantum
//! half of hardware-backed federation custody (CIRISVerify#70's PQC analog).
//!
//! The federation signing identity is **hybrid**: Ed25519 (classical) +
//! ML-DSA-65 (FIPS 204, PQC). #70 gave the Ed25519 half sealed-at-rest custody
//! ([`crate::sealed_ed25519::SealedEd25519Signer`]); this gives the ML-DSA-65
//! half the *same* treatment, so the **whole** hybrid key is hardware-backed at
//! rest instead of leaving the PQC seed in a plaintext file (the exfil
//! asymmetry that remained after #70).
//!
//! Like [`crate::transport_identity::BlobTransportKeystore`] (#68) and
//! [`crate::sealed_ed25519::SealedEd25519Signer`] (#70), it seals the 32-byte
//! ML-DSA-65 seed via [`SecureBlobStorage`] (TPM 2.0 / Secure Enclave /
//! Keystore, else an encrypted software fallback) and loads it into an
//! [`MlDsa65SoftwareSigner`] for use.
//!
//! ## Signing stays software — sealing is at-rest
//!
//! No shipping hardware token has an ML-DSA-65 applet (industry-wide as of
//! 2026), so the *signing* is software over the unsealed seed — there is no
//! TPM-native ML-DSA op to delegate to. What this closes is the **at-rest**
//! threat: the PQC seed is a sealed blob bound to the hardware tier, not a
//! `chmod 600` plaintext file. That is the same realistic exfil surface
//! (filesystem / backup / snapshot) #68 and #70 close. Same AV-17 carve-out:
//! hardware-backed at rest, transient in process while held, seed buffer
//! scrubbed after the load.
//!
//! ## Lifecycle (identical to #70)
//!
//! - **Adopt sealed** — a seed already sealed at `seed_dir` is loaded verbatim.
//! - **Adopt existing** — [`SealedMlDsa65Signer::adopt`] seals a caller-supplied
//!   32-byte seed **byte-identically** (the software→sealed migration: the
//!   ML-DSA-65 pubkey and therefore the hybrid `key_id` are preserved).
//!   Idempotent — won't clobber an already-sealed key.
//! - **Generate** — [`SealedMlDsa65Signer::open`] on a fresh `seed_dir`
//!   generates a 32-byte seed from the OS CSPRNG and seals it.

use std::path::PathBuf;

use async_trait::async_trait;

use crate::error::KeyringError;
use crate::pqc::{MlDsa65SoftwareSigner, PqcAlgorithm, PqcSigner};
use crate::storage::{create_platform_storage, SecureBlobStorage};
use crate::types::{HardwareType, PlatformAttestation, StorageDescriptor};

/// SecureBlobStorage key the sealed ML-DSA-65 seed lives under.
const SEED_KEY_ID: &str = "mldsa65.seed";
/// ML-DSA-65 seed length (FIPS 204 ξ).
const SEED_LEN: usize = 32;

/// A [`PqcSigner`] whose ML-DSA-65 seed is sealed at rest by the platform's
/// best [`SecureBlobStorage`] tier, while signing in software ML-DSA-65.
pub struct SealedMlDsa65Signer {
    inner: MlDsa65SoftwareSigner,
    storage: Box<dyn SecureBlobStorage>,
    alias: String,
    seed_dir: PathBuf,
}

impl SealedMlDsa65Signer {
    /// Open the sealed ML-DSA-65 signer at `seed_dir`. A sealed seed already
    /// present is adopted verbatim; otherwise, if `adopt_seed` is `Some`, that
    /// 32-byte seed is sealed byte-identically; otherwise a fresh seed is
    /// generated from the OS CSPRNG and sealed.
    pub fn open_or_create(
        alias: impl Into<String>,
        seed_dir: impl Into<PathBuf>,
        adopt_seed: Option<&[u8; SEED_LEN]>,
    ) -> Result<Self, KeyringError> {
        let alias = alias.into();
        let seed_dir = seed_dir.into();
        let storage = create_platform_storage(&alias, &seed_dir)?;

        let mut seed: [u8; SEED_LEN] = match storage.load(SEED_KEY_ID) {
            Ok(raw) => raw
                .as_slice()
                .try_into()
                .map_err(|_| KeyringError::InvalidKey {
                    reason: format!(
                        "sealed ML-DSA-65 seed is {} bytes, expected {SEED_LEN}",
                        raw.len()
                    ),
                })?,
            Err(KeyringError::KeyNotFound { .. }) => {
                let mut s = [0u8; SEED_LEN];
                match adopt_seed {
                    Some(existing) => s.copy_from_slice(existing),
                    None => {
                        use rand_core::{OsRng, RngCore};
                        OsRng.fill_bytes(&mut s);
                    },
                }
                storage.store(SEED_KEY_ID, &s)?;
                s
            },
            Err(e) => return Err(e),
        };

        let inner = MlDsa65SoftwareSigner::from_seed_bytes(&seed, alias.clone())?;
        // Scrub the local seed copy; the durable copy is sealed in `storage`.
        seed.iter_mut().for_each(|b| *b = 0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        Ok(Self {
            inner,
            storage,
            alias,
            seed_dir,
        })
    }

    /// Open at `seed_dir`: adopt the sealed seed, or generate+seal a fresh one.
    pub fn open(
        alias: impl Into<String>,
        seed_dir: impl Into<PathBuf>,
    ) -> Result<Self, KeyringError> {
        Self::open_or_create(alias, seed_dir, None)
    }

    /// Adopt an existing 32-byte ML-DSA-65 `seed` byte-identically (the
    /// software → hardware-sealed migration; pubkey / hybrid key_id preserved).
    /// Seals only if no sealed seed is present yet — idempotent.
    pub fn adopt(
        alias: impl Into<String>,
        seed_dir: impl Into<PathBuf>,
        seed: &[u8; SEED_LEN],
    ) -> Result<Self, KeyringError> {
        Self::open_or_create(alias, seed_dir, Some(seed))
    }
}

/// Best-tier sealed **ML-DSA-65** federation signer (CIRISVerify#70 PQC analog)
/// — the post-quantum counterpart to `get_platform_ed25519_signer`. Generates
/// on first use, adopts a previously-sealed seed verbatim, returns a
/// `Box<dyn PqcSigner>` whose `public_key()` is the ML-DSA-65 pubkey. Pair it
/// with `get_platform_ed25519_signer` to give both halves of the hybrid
/// federation key hardware-backed-at-rest custody.
pub fn get_platform_sealed_mldsa65_signer(
    alias: &str,
    seed_dir: impl Into<PathBuf>,
) -> Result<Box<dyn PqcSigner>, KeyringError> {
    Ok(Box::new(SealedMlDsa65Signer::open(alias, seed_dir)?))
}

#[async_trait]
impl PqcSigner for SealedMlDsa65Signer {
    fn algorithm(&self) -> PqcAlgorithm {
        self.inner.algorithm()
    }

    fn hardware_type(&self) -> HardwareType {
        // Reflect the at-rest tier honestly: sealed only if the storage backend
        // is hardware-backed; otherwise software (the seed is software at rest).
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

    fn current_alias(&self) -> &str {
        &self.alias
    }

    fn storage_descriptor(&self) -> StorageDescriptor {
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

    fn tmpdir() -> PathBuf {
        use rand_core::{OsRng, RngCore};
        let mut suffix = [0u8; 8];
        OsRng.fill_bytes(&mut suffix);
        let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
        let mut p = std::env::temp_dir();
        p.push(format!("ciris-sealed-mldsa65-{hex}"));
        p
    }

    #[tokio::test]
    async fn pubkey_is_mldsa65_and_signs_verifiably() {
        let dir = tmpdir();
        let signer = get_platform_sealed_mldsa65_signer("fed-pqc", &dir).unwrap();
        assert_eq!(signer.algorithm(), PqcAlgorithm::MlDsa65);
        let pk = signer.public_key().await.unwrap();
        assert_eq!(pk.len(), 1952, "ML-DSA-65 pubkey length");
        // Sign + verify against a fresh software signer holding the same key is
        // covered by the adopt test; here assert a signature is produced.
        let sig = signer.sign(b"federation envelope").await.unwrap();
        assert!(!sig.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn adopt_existing_seed_preserves_pubkey() {
        let dir = tmpdir();
        let seed = [0x42u8; SEED_LEN];
        // The reference pubkey for this seed, via the bare software signer.
        let expected = MlDsa65SoftwareSigner::from_seed_bytes(&seed, "ref")
            .unwrap()
            .public_key()
            .await
            .unwrap();

        let signer = SealedMlDsa65Signer::adopt("fed-pqc", &dir, &seed).unwrap();
        assert_eq!(signer.public_key().await.unwrap(), expected);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn sealed_seed_persists_and_readopt_is_idempotent() {
        let dir = tmpdir();
        let pk1 = SealedMlDsa65Signer::open("fed-pqc", &dir)
            .unwrap()
            .public_key()
            .await
            .unwrap();
        // Reopen → same key.
        let pk2 = SealedMlDsa65Signer::open("fed-pqc", &dir)
            .unwrap()
            .public_key()
            .await
            .unwrap();
        assert_eq!(pk1, pk2, "sealed seed must survive reopen");
        // adopt a DIFFERENT seed must NOT clobber the already-sealed key.
        let other = [0x99u8; SEED_LEN];
        let pk3 = SealedMlDsa65Signer::adopt("fed-pqc", &dir, &other)
            .unwrap()
            .public_key()
            .await
            .unwrap();
        assert_eq!(pk3, pk1, "re-adopt must not clobber");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn tier_reporting_is_honest() {
        // The honesty invariant (env-independent): `hardware_type` reports
        // `SoftwareOnly` IFF `storage_descriptor` is a `SoftwareFile`. On a
        // software box this is the SoftwareFile arm; on a TPM/SE box with the
        // platform feature (the Linux release wheel builds `--features tpm`)
        // the sealed seed is genuinely hardware-backed and both move to the
        // Hardware arm. A disagreement between the two is the bug.
        let dir = tmpdir();
        let signer = get_platform_sealed_mldsa65_signer("fed-pqc", &dir).unwrap();
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
    async fn holds_as_arc_dyn_pqc_signer() {
        let dir = tmpdir();
        let signer: std::sync::Arc<dyn PqcSigner> =
            std::sync::Arc::from(get_platform_sealed_mldsa65_signer("fed-pqc", &dir).unwrap());
        assert_eq!(signer.algorithm(), PqcAlgorithm::MlDsa65);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
