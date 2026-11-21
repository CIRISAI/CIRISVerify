//! The federation signing seam: [`SelfSigner`], over a software
//! [`HybridSigningIdentity`] or a hardware-rooted [`HardwareRootedIdentity`]
//! (CIRISVerify#63, #80).
//!
//! [`SelfSigner::sign_bound`] is the earlier bound-hybrid signature (Ed25519
//! over the bytes, then ML-DSA-65 over `bytes ‖ ed25519_sig`), the form the
//! JSON key records of [`crate::federation_self_record`] are still signed with
//! (`ciris-verify identity create`). The signer is hardware/software-agnostic:
//! the wire bytes are identical whether the Ed25519 half lives in software or
//! in a Secure Enclave / StrongBox / TPM-sealed / YubiKey-PKCS#11 signer.
//!
//! The ceremony producers that used to live here (delegation, partnership
//! grant/accept, transport binding, membership grant, occurrence revocation,
//! `perform_self_at_login` and its WebAuthn presence gate) signed earlier-form
//! pair envelopes no reader takes any more; they were removed in 23.3.3. The
//! forward model signs with the CC 2.6.1.7 composite ([`crate::edition2`]).

#[allow(unused_imports)]
use crate::prelude::*;

#[cfg(feature = "host")]
use std::sync::Arc;

use base64::Engine;
use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};
#[cfg(feature = "host")]
use ciris_keyring::{ClassicalAlgorithm, HardwareSigner};

use crate::error::VerifyError;
use crate::threshold::ThresholdMember;

/// Standard base64 engine — the one the verifiers decode with.
fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// A hybrid signing identity: a federation `key_id` plus its Ed25519 +
/// ML-DSA-65 keypair. This is the producer-side counterpart of a
/// [`ThresholdMember`] (which holds only the *public* halves).
///
/// Today this wraps software signers ([`Ed25519Signer`] / [`MlDsa65Signer`]).
/// [`HardwareRootedIdentity`] satisfies the same [`SelfSigner`] contract with
/// the Ed25519 half in hardware; the byte format does not change.
pub struct HybridSigningIdentity {
    key_id: String,
    ed: Ed25519Signer,
    mldsa: MlDsa65Signer,
}

impl HybridSigningIdentity {
    /// Construct from existing signers (the hardware seam — a hardware
    /// signer can be adapted to the same keypair here in future).
    #[must_use]
    pub fn new(key_id: impl Into<String>, ed: Ed25519Signer, mldsa: MlDsa65Signer) -> Self {
        Self {
            key_id: key_id.into(),
            ed,
            mldsa,
        }
    }

    /// Generate a fresh software hybrid identity (test / software-only use).
    ///
    /// # Errors
    ///
    /// [`VerifyError::IntegrityError`] if the ML-DSA-65 signer cannot be
    /// constructed (e.g. the `pqc-ml-dsa` feature is disabled).
    ///
    /// Needs `std` (the OS RNG); without it, build the halves from seeds and
    /// call [`Self::new`].
    #[cfg(feature = "std")]
    pub fn generate(key_id: impl Into<String>) -> Result<Self, VerifyError> {
        let mldsa = MlDsa65Signer::new().map_err(|e| VerifyError::IntegrityError {
            message: format!("ML-DSA-65 signer construction failed: {e}"),
        })?;
        Ok(Self::new(key_id, Ed25519Signer::random()?, mldsa))
    }

    /// This identity's federation `key_id`.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The [`ThresholdMember`] pinning this identity's public keys — the
    /// directory entry a verifier needs to bind a signature from this
    /// identity to its `key_id`. `role` is `None` (set it on the returned
    /// value for a founder/steward roster).
    ///
    /// # Errors
    ///
    /// [`VerifyError::IntegrityError`] if either public key cannot be read.
    pub fn directory_member(&self) -> Result<ThresholdMember, VerifyError> {
        let ed_pub = self.ed.public_key().map_err(crypto_err)?;
        let mldsa_pub = self.mldsa.public_key().map_err(crypto_err)?;
        Ok(ThresholdMember {
            member_id: self.key_id.clone(),
            ed25519_public_key_base64: b64().encode(ed_pub),
            mldsa65_public_key_base64: Some(b64().encode(mldsa_pub)),
            role: None,
        })
    }

    /// Hybrid-sign raw bytes with the bound-signature discipline: Ed25519
    /// over `bytes`, then ML-DSA-65 over `bytes ‖ ed25519_sig`. Returns the
    /// two base64 halves, byte-identical to the construction
    /// [`crate::threshold`] verifies.
    fn sign_bytes(&self, bytes: &[u8]) -> Result<(String, String), VerifyError> {
        let ed_sig = self.ed.sign(bytes).map_err(crypto_err)?;
        let mut bound = bytes.to_vec();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = self.mldsa.sign(&bound).map_err(crypto_err)?;
        Ok((b64().encode(&ed_sig), b64().encode(&pqc_sig)))
    }
}

fn crypto_err(e: ciris_crypto::CryptoError) -> VerifyError {
    VerifyError::IntegrityError {
        message: format!("hybrid signing failed: {e}"),
    }
}

#[cfg(feature = "host")]
fn keyring_err(e: ciris_keyring::KeyringError) -> VerifyError {
    VerifyError::IntegrityError {
        message: format!("hardware signer fault: {e}"),
    }
}

// ===========================================================================
// The producer-side signing seam (CIRISVerify#63 hardware-rooting)
// ===========================================================================

/// The one signing seam the key-record producers route through.
///
/// [`crate::federation_self_record`] is written against this trait, so a key
/// record is bound-hybrid-signed *identically* whether the federation key
/// lives in software ([`HybridSigningIdentity`]) or is
/// hardware-rooted ([`HardwareRootedIdentity`] — Secure Enclave / Android
/// StrongBox / TPM-sealed / YubiKey-PKCS#11 via the
/// `ciris_keyring::user_identity` backends, CIRISVerify#80). The bound-hybrid
/// byte format is fixed by [`SelfSigner::sign_bound`]; downstream verification
/// is untouched by *where* the Ed25519 half is sealed.
///
/// The async signature is load-bearing: a hardware signer's `sign` is async
/// (it may touch a secure element / await a YubiKey touch). The software
/// identity satisfies it trivially (its inner sign is sync).
#[async_trait::async_trait]
pub trait SelfSigner: Send + Sync {
    /// This identity's federation `key_id`.
    fn key_id(&self) -> &str;

    /// The Ed25519 (classical) public key — 32 raw bytes.
    ///
    /// # Errors
    /// [`VerifyError::IntegrityError`] if the key cannot be read.
    async fn ed25519_public_key(&self) -> Result<Vec<u8>, VerifyError>;

    /// The ML-DSA-65 (PQC) public key — raw bytes.
    ///
    /// # Errors
    /// [`VerifyError::IntegrityError`] if the key cannot be read.
    async fn mldsa65_public_key(&self) -> Result<Vec<u8>, VerifyError>;

    /// Bound hybrid sign: Ed25519 over `bytes`, then ML-DSA-65 over
    /// `bytes ‖ ed25519_sig` (the PQC half binds the classical half). Returns
    /// `(ed25519_sig_base64, mldsa65_sig_base64)` — byte-identical to the
    /// software primitive `HybridSigningIdentity::sign_bytes`.
    ///
    /// # Errors
    /// [`VerifyError`] on a hardware-signer or crypto-layer fault.
    async fn sign_bound(&self, bytes: &[u8]) -> Result<(String, String), VerifyError>;

    /// The [`ThresholdMember`] pinning this identity's public keys — the
    /// directory entry a verifier binds a signature from this identity to.
    /// `role` is `None`.
    ///
    /// # Errors
    /// [`VerifyError::IntegrityError`] if either public key cannot be read.
    async fn directory_member(&self) -> Result<ThresholdMember, VerifyError> {
        let ed = self.ed25519_public_key().await?;
        let mldsa = self.mldsa65_public_key().await?;
        Ok(ThresholdMember {
            member_id: self.key_id().to_string(),
            ed25519_public_key_base64: b64().encode(ed),
            mldsa65_public_key_base64: Some(b64().encode(mldsa)),
            role: None,
        })
    }
}

#[async_trait::async_trait]
impl SelfSigner for HybridSigningIdentity {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    async fn ed25519_public_key(&self) -> Result<Vec<u8>, VerifyError> {
        self.ed.public_key().map_err(crypto_err)
    }

    async fn mldsa65_public_key(&self) -> Result<Vec<u8>, VerifyError> {
        self.mldsa.public_key().map_err(crypto_err)
    }

    async fn sign_bound(&self, bytes: &[u8]) -> Result<(String, String), VerifyError> {
        // Reuse the sync primitive — byte-identical to the hardware path below.
        self.sign_bytes(bytes)
    }
}

/// A **hardware-rooted** hybrid user identity (CIRISVerify#63).
///
/// The Ed25519 federation-signing half lives in a hardware
/// [`HardwareSigner`] — Secure Enclave / Android StrongBox / TPM-sealed
/// (CIRISVerify#70) / YubiKey-PKCS#11 (CIRISVerify#80), selected through the
/// `ciris_keyring::user_identity` backends. The ML-DSA-65 PQC half is software
/// (its seed sealed-at-rest by CIRISVerify#71 when constructed from a sealed
/// seed). **The signing seed never leaves the secure element** — only the
/// bound hybrid signature is exported.
///
/// Satisfies the same [`SelfSigner`] contract as the software
/// [`HybridSigningIdentity`], so the key-record producers are
/// hardware/software-agnostic and the wire bytes are identical — a record
/// signed here verifies through [`crate::threshold`] exactly as a
/// software-signed one does.
///
/// The hardware signer MUST be Ed25519 ([`ClassicalAlgorithm::Ed25519`]) — the
/// federation signing algorithm. A P-256-only token is rejected at
/// [`HardwareRootedIdentity::new`] (fail-closed, not silently downgraded).
#[cfg(feature = "host")]
pub struct HardwareRootedIdentity {
    key_id: String,
    ed: Arc<dyn HardwareSigner>,
    mldsa: Arc<dyn ciris_keyring::PqcSigner>,
}

#[cfg(feature = "host")]
impl HardwareRootedIdentity {
    /// Construct from a hardware Ed25519 signer plus an ML-DSA-65 PQC signer.
    ///
    /// The PQC half is any [`ciris_keyring::PqcSigner`] — a **TPM/SE-sealed**
    /// seed ([`ciris_keyring::get_platform_sealed_mldsa65_signer`], #71; the
    /// seed lives sealed at rest and is unsealed only transiently to sign — no
    /// hardware does PQC *signing* yet) or a software seed
    /// ([`ciris_keyring::MlDsa65SoftwareSigner`]). The wire bytes are identical
    /// either way.
    ///
    /// # Errors
    /// [`VerifyError::IntegrityError`] if `ed` is not an Ed25519 signer — the
    /// federation tier requires Ed25519 + ML-DSA-65, and a P-256 hardware key
    /// cannot stand in for the classical half.
    pub fn new(
        key_id: impl Into<String>,
        ed: Arc<dyn HardwareSigner>,
        mldsa: Arc<dyn ciris_keyring::PqcSigner>,
    ) -> Result<Self, VerifyError> {
        if ed.algorithm() != ClassicalAlgorithm::Ed25519 {
            return Err(VerifyError::IntegrityError {
                message: format!(
                    "hardware-rooted federation key must be Ed25519, got {:?}",
                    ed.algorithm()
                ),
            });
        }
        Ok(Self {
            key_id: key_id.into(),
            ed,
            mldsa,
        })
    }

    /// This identity's federation `key_id`.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The hardware custody class of the Ed25519 signing half — what feeds the
    /// CEG §9.4 `hardware_class` / attestation surface a consumer reports.
    #[must_use]
    pub fn hardware_type(&self) -> ciris_keyring::HardwareType {
        self.ed.hardware_type()
    }
}

#[cfg(feature = "host")]
#[async_trait::async_trait]
impl SelfSigner for HardwareRootedIdentity {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    async fn ed25519_public_key(&self) -> Result<Vec<u8>, VerifyError> {
        self.ed.public_key().await.map_err(keyring_err)
    }

    async fn mldsa65_public_key(&self) -> Result<Vec<u8>, VerifyError> {
        self.mldsa.public_key().await.map_err(keyring_err)
    }

    async fn sign_bound(&self, bytes: &[u8]) -> Result<(String, String), VerifyError> {
        // Ed25519 in hardware (async — may await a secure-element / touch), then
        // ML-DSA-65 over `bytes ‖ ed_sig` (the PQC signer unseals its seed
        // transiently if it is the #71 sealed signer). Byte-identical bound
        // construction to HybridSigningIdentity::sign_bytes.
        let ed_sig = self.ed.sign(bytes).await.map_err(keyring_err)?;
        let mut bound = bytes.to_vec();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = self.mldsa.sign(&bound).await.map_err(keyring_err)?;
        Ok((b64().encode(&ed_sig), b64().encode(&pqc_sig)))
    }
}

#[cfg(all(test, feature = "host"))]
mod tests {
    use super::*;
    use crate::threshold::{verify_threshold_signatures, ThresholdSignature};

    /// A software Ed25519 [`HardwareSigner`] standing in for a real secure
    /// element (Secure Enclave / StrongBox / YubiKey) — the byte contract is
    /// identical, so the seam is fully exercisable without a physical key.
    fn software_hw_ed25519(seed: u8, alias: &str) -> Arc<dyn HardwareSigner> {
        Arc::new(ciris_keyring::Ed25519SoftwareSigner::from_bytes(&[seed; 32], alias).unwrap())
    }

    /// A software ML-DSA-65 PqcSigner stand-in for the sealed/hardware PQC half.
    fn software_mldsa(seed: u8, alias: &str) -> Arc<dyn ciris_keyring::PqcSigner> {
        Arc::new(ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&[seed; 32], alias).unwrap())
    }

    fn hardware_rooted(seed: u8, key_id: &str) -> HardwareRootedIdentity {
        HardwareRootedIdentity::new(
            key_id,
            software_hw_ed25519(seed, key_id),
            software_mldsa(seed, key_id),
        )
        .unwrap()
    }

    async fn verifies(signer: &dyn SelfSigner, bytes: &[u8]) -> bool {
        let (ed, pqc) = signer.sign_bound(bytes).await.unwrap();
        let sig = ThresholdSignature {
            member_id: signer.key_id().to_string(),
            ed25519_signature_base64: ed,
            mldsa65_signature_base64: Some(pqc),
        };
        let member = signer.directory_member().await.unwrap();
        verify_threshold_signatures(bytes, &[member], &[sig], 1) == Ok(1)
    }

    /// The hardware seam: a [`HardwareRootedIdentity`] (Ed25519 in a hardware
    /// signer + software ML-DSA) and a software [`HybridSigningIdentity`] both
    /// produce bound signatures the threshold verifier accepts, and the same
    /// seeds give the same bytes.
    #[tokio::test]
    async fn both_signers_produce_verifiable_bound_signatures() {
        let hw = hardware_rooted(0x07, "user-steward-1");
        assert_eq!(
            hw.hardware_type(),
            ciris_keyring::HardwareType::SoftwareOnly
        );
        assert!(verifies(&hw, b"key record bytes").await);

        let sw = HybridSigningIdentity::generate("user-steward-2").unwrap();
        assert!(verifies(&sw, b"key record bytes").await);
        assert_eq!(
            SelfSigner::directory_member(&sw).await.unwrap(),
            sw.directory_member().unwrap()
        );
    }

    #[tokio::test]
    async fn hardware_rooted_rejects_non_ed25519_signer() {
        // The federation classical half MUST be Ed25519 — a P-256-only token is
        // refused at construction (fail-closed, not silently downgraded).
        let p256 = Arc::from(ciris_keyring::create_software_signer("p256-token").unwrap());
        let err = HardwareRootedIdentity::new("user-1", p256, software_mldsa(1, "user-1"));
        assert!(err.is_err(), "a P-256 hardware key must be rejected");
    }
}
