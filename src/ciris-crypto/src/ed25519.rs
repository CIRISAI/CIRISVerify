//! Ed25519 signature operations.
//!
//! Used for steward signatures and software-only deployments.
//! Note: Most mobile hardware HSMs do NOT support Ed25519.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
#[cfg(not(feature = "random"))]
use rand_core::OsRng;

use crate::error::CryptoError;
use crate::hybrid::{ClassicalSigner, ClassicalVerifier};
use crate::types::ClassicalAlgorithm;

/// Ed25519 signer.
pub struct Ed25519Signer {
    signing_key: SigningKey,
}

impl Ed25519Signer {
    /// Create a new signer with a freshly generated random key.
    ///
    /// # Fail-secure (CIRISVerify#74)
    ///
    /// The 32-byte seed is drawn through [`crate::random::fill`], which
    /// reads the latched SP 800-90B startup RNG health verdict
    /// ([`crate::rng_health::is_rng_failed`]) before drawing. If the OS
    /// entropy source failed that check, the draw is refused and this
    /// returns `CryptoError::RngHealthCheckFailed` WITHOUT generating a
    /// key — so a broken-entropy environment cannot mint a predictable
    /// long-term identity key. (Previously this drew `OsRng` directly,
    /// bypassing the latch — the bug fixed here.)
    ///
    /// When the `random` feature is disabled the facade is not compiled;
    /// in that build the seed is drawn directly from `OsRng` (no latch
    /// exists to consult).
    ///
    /// # Errors
    ///
    /// `CryptoError::RngHealthCheckFailed` if the RNG health latch is
    /// `Failed` (fail-secure; no key generated). Other variants only on
    /// the rare platforms where the OS entropy source itself errors.
    pub fn random() -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        #[cfg(feature = "random")]
        {
            crate::random::fill(&mut seed)?;
        }
        #[cfg(not(feature = "random"))]
        {
            use rand_core::RngCore;
            OsRng
                .try_fill_bytes(&mut seed)
                .map_err(|e| CryptoError::invalid_private_key(format!("OsRng seed draw: {e}")))?;
        }
        Self::from_seed(&seed)
    }

    /// Create a signer from seed bytes (32 bytes).
    ///
    /// # Errors
    ///
    /// Returns error if the seed is not exactly 32 bytes.
    pub fn from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        if seed.len() != 32 {
            return Err(CryptoError::invalid_private_key(format!(
                "Ed25519 seed must be 32 bytes, got {}",
                seed.len()
            )));
        }

        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(seed);

        Ok(Self {
            signing_key: SigningKey::from_bytes(&seed_array),
        })
    }

    /// Get the verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl ClassicalSigner for Ed25519Signer {
    fn algorithm(&self) -> ClassicalAlgorithm {
        ClassicalAlgorithm::Ed25519
    }

    fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.signing_key.verifying_key().to_bytes().to_vec())
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signature = self.signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
}

/// Ed25519 verifier.
pub struct Ed25519Verifier;

impl Ed25519Verifier {
    /// Create a new verifier.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for Ed25519Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ClassicalVerifier for Ed25519Verifier {
    fn verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        // Parse public key
        if public_key.len() != 32 {
            return Err(CryptoError::invalid_public_key(format!(
                "Ed25519 public key must be 32 bytes, got {}",
                public_key.len()
            )));
        }

        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(public_key);

        let vk = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| CryptoError::invalid_public_key(e.to_string()))?;

        // Parse signature
        if signature.len() != 64 {
            return Err(CryptoError::invalid_signature(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                signature.len()
            )));
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);

        let sig = Signature::from_bytes(&sig_bytes);

        // Verify
        match vk.verify(data, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let signer = Ed25519Signer::random().unwrap();
        let verifier = Ed25519Verifier::new();

        let data = b"test message";
        let signature = signer.sign(data).unwrap();
        let public_key = signer.public_key().unwrap();

        assert_eq!(signature.len(), 64);
        assert_eq!(public_key.len(), 32);

        let valid = verifier.verify(&public_key, data, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_ed25519_from_seed() {
        let seed = [42u8; 32];
        let signer1 = Ed25519Signer::from_seed(&seed).unwrap();
        let signer2 = Ed25519Signer::from_seed(&seed).unwrap();

        // Same seed should produce same key
        assert_eq!(signer1.public_key().unwrap(), signer2.public_key().unwrap());
    }

    /// CIRISVerify#74 fail-secure proof: when the SP 800-90B RNG health
    /// latch is forced `Failed`, keygen refuses to draw and returns
    /// `RngHealthCheckFailed` rather than minting a (potentially
    /// predictable) identity key.
    #[cfg(feature = "random")]
    #[test]
    fn random_fails_secure_when_rng_marked_failed() {
        crate::rng_health::test_support::with_forced_failed(|| {
            // Signer holds key material and is intentionally not `Debug`,
            // so assert on the variant directly rather than `unwrap_err`.
            assert!(
                matches!(
                    Ed25519Signer::random(),
                    Err(CryptoError::RngHealthCheckFailed(_))
                ),
                "keygen must fail-secure on failed RNG latch"
            );
        });
        // Latch restored: keygen works again.
        assert!(Ed25519Signer::random().is_ok());
    }
}
