//! ML-DSA (FIPS 204) post-quantum signature operations.
//!
//! This module provides ML-DSA-65 signing and verification.
//! ML-DSA-65 (formerly Dilithium3) is the MINIMUM required PQC algorithm.
//!
//! ## Key Sizes
//!
//! - Public key: 1,952 bytes
//! - Secret key: 4,032 bytes
//! - Signature: 3,293 bytes
//!
//! ## Security Level
//!
//! ML-DSA-65 provides ~192-bit classical security, meeting CIRISVerify requirements.

use crate::error::CryptoError;
use crate::hybrid::{PqcSigner, PqcVerifier};
use crate::types::PqcAlgorithm;

#[cfg(feature = "pqc-ml-dsa")]
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Seed, Signature, SigningKey, VerifyingKey};

#[cfg(feature = "pqc-ml-dsa")]
use ml_dsa::signature::{Signer, Verifier};

/// ML-DSA-65 signer.
///
/// This provides post-quantum signature generation using ML-DSA-65 (FIPS 204).
pub struct MlDsa65Signer {
    #[cfg(feature = "pqc-ml-dsa")]
    signing_key: SigningKey<MlDsa65>,
    #[cfg(feature = "pqc-ml-dsa")]
    verifying_key: VerifyingKey<MlDsa65>,
    #[cfg(not(feature = "pqc-ml-dsa"))]
    _private: (),
}

impl MlDsa65Signer {
    /// Create a new signer with a randomly generated key pair.
    ///
    /// # Errors
    ///
    /// Returns error if PQC feature is not enabled.
    #[cfg(feature = "pqc-ml-dsa")]
    pub fn new() -> Result<Self, CryptoError> {
        use rand_core::{OsRng, RngCore};

        // Generate a random 32-byte seed using the system CSPRNG
        let mut seed_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut seed_bytes);

        Self::from_seed(&seed_bytes)
    }

    /// Create a new signer with a randomly generated key pair.
    #[cfg(not(feature = "pqc-ml-dsa"))]
    pub fn new() -> Result<Self, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm {
            algorithm: "ML-DSA-65: Enable pqc-ml-dsa feature".into(),
        })
    }

    /// Create a signer from seed bytes.
    ///
    /// # Arguments
    ///
    /// * `seed` - 32-byte seed for deterministic key generation
    ///
    /// # Errors
    ///
    /// Returns error if seed is wrong length or PQC feature not enabled.
    #[cfg(feature = "pqc-ml-dsa")]
    pub fn from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        if seed.len() != 32 {
            return Err(CryptoError::invalid_private_key(format!(
                "ML-DSA-65 seed must be 32 bytes, got {}",
                seed.len()
            )));
        }

        let seed = Seed::try_from(seed)
            .map_err(|e| CryptoError::invalid_private_key(format!("Seed construction: {e}")))?;

        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Create a signer from seed bytes (stub when feature disabled).
    #[cfg(not(feature = "pqc-ml-dsa"))]
    pub fn from_seed(_seed: &[u8]) -> Result<Self, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm {
            algorithm: "ML-DSA-65: Enable pqc-ml-dsa feature".into(),
        })
    }
}

impl PqcSigner for MlDsa65Signer {
    fn algorithm(&self) -> PqcAlgorithm {
        PqcAlgorithm::MlDsa65
    }

    #[cfg(feature = "pqc-ml-dsa")]
    fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
        let encoded = self.verifying_key.encode();
        Ok(encoded.to_vec())
    }

    #[cfg(not(feature = "pqc-ml-dsa"))]
    fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm {
            algorithm: "ML-DSA-65 not implemented".into(),
        })
    }

    #[cfg(feature = "pqc-ml-dsa")]
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signature: Signature<MlDsa65> = self.signing_key.sign(data);
        let encoded = signature.encode();
        Ok(encoded.to_vec())
    }

    #[cfg(not(feature = "pqc-ml-dsa"))]
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm {
            algorithm: "ML-DSA-65 not implemented".into(),
        })
    }
}

/// ML-DSA-65 verifier.
pub struct MlDsa65Verifier;

impl MlDsa65Verifier {
    /// Create a new verifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for MlDsa65Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl PqcVerifier for MlDsa65Verifier {
    #[cfg(feature = "pqc-ml-dsa")]
    fn verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        // Parse public key: &[u8] -> EncodedVerifyingKey -> VerifyingKey
        let encoded_vk = EncodedVerifyingKey::<MlDsa65>::try_from(public_key)
            .map_err(|e| CryptoError::invalid_public_key(format!("ML-DSA-65: {e}")))?;
        let vk = VerifyingKey::<MlDsa65>::decode(&encoded_vk);

        // Parse signature: &[u8] -> Signature
        let sig = Signature::<MlDsa65>::try_from(signature)
            .map_err(|e| CryptoError::invalid_signature(format!("ML-DSA-65: {e}")))?;

        // Verify
        match vk.verify(data, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    #[cfg(not(feature = "pqc-ml-dsa"))]
    fn verify(
        &self,
        _public_key: &[u8],
        _data: &[u8],
        _signature: &[u8],
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm {
            algorithm: "ML-DSA-65: Enable pqc-ml-dsa feature".into(),
        })
    }
}

#[cfg(all(test, feature = "pqc-ml-dsa"))]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_sign_verify() {
        let signer = MlDsa65Signer::new().unwrap();
        let verifier = MlDsa65Verifier::new();

        let data = b"test message for ML-DSA-65";
        let signature = signer.sign(data).unwrap();
        let public_key = signer.public_key().unwrap();

        // Check sizes
        assert_eq!(
            public_key.len(),
            1952,
            "ML-DSA-65 public key should be 1952 bytes"
        );
        assert_eq!(
            signature.len(),
            3309,
            "ML-DSA-65 signature should be 3309 bytes"
        );

        // Verify
        let valid = verifier.verify(&public_key, data, &signature).unwrap();
        assert!(valid, "Signature should verify");
    }

    #[test]
    fn test_ml_dsa_invalid_signature() {
        let signer = MlDsa65Signer::new().unwrap();
        let verifier = MlDsa65Verifier::new();

        let data = b"test message";
        let mut signature = signer.sign(data).unwrap();
        signature[0] ^= 0xFF; // Corrupt signature

        let public_key = signer.public_key().unwrap();
        // Corrupted signature should fail to parse or verify
        let result = verifier.verify(&public_key, data, &signature);
        match result {
            Ok(valid) => assert!(!valid, "Corrupted signature should not verify"),
            Err(_) => {}, // Parsing error is also acceptable
        }
    }

    #[test]
    fn test_ml_dsa_wrong_data() {
        let signer = MlDsa65Signer::new().unwrap();
        let verifier = MlDsa65Verifier::new();

        let signature = signer.sign(b"message 1").unwrap();
        let public_key = signer.public_key().unwrap();

        let valid = verifier
            .verify(&public_key, b"message 2", &signature)
            .unwrap();
        assert!(!valid, "Signature should not verify for different data");
    }

    #[test]
    fn test_ml_dsa_from_seed_deterministic() {
        let seed = [42u8; 32];
        let signer1 = MlDsa65Signer::from_seed(&seed).unwrap();
        let signer2 = MlDsa65Signer::from_seed(&seed).unwrap();

        // Same seed should produce same key
        assert_eq!(
            signer1.public_key().unwrap(),
            signer2.public_key().unwrap(),
            "Same seed should produce same key"
        );
    }

    #[test]
    fn test_ml_dsa_algorithm() {
        let signer = MlDsa65Signer::new().unwrap();
        assert_eq!(signer.algorithm(), PqcAlgorithm::MlDsa65);
        assert!(signer.algorithm().meets_minimum_requirement());
    }
}

#[cfg(all(test, not(feature = "pqc-ml-dsa")))]
mod tests_disabled {
    use super::*;

    #[test]
    fn test_ml_dsa_disabled() {
        let result = MlDsa65Signer::new();
        assert!(matches!(
            result,
            Err(CryptoError::UnsupportedAlgorithm { .. })
        ));
    }
}
