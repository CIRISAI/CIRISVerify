//! ECDSA P-256 signature operations.
//!
//! This module provides ECDSA P-256 (secp256r1) signing and verification,
//! the primary classical algorithm for hardware-bound signatures.

use p256::ecdsa::{
    SigningKey, VerifyingKey,
    Signature,
    signature::{Signer, Verifier},
};
use p256::elliptic_curve::rand_core::OsRng;

use crate::error::CryptoError;
use crate::types::ClassicalAlgorithm;
use crate::hybrid::{ClassicalSigner, ClassicalVerifier};

/// ECDSA P-256 signer.
pub struct P256Signer {
    signing_key: SigningKey,
}

impl P256Signer {
    /// Create a new signer with a random key.
    #[must_use]
    pub fn random() -> Self {
        Self {
            signing_key: SigningKey::random(&mut OsRng),
        }
    }

    /// Create a signer from an existing key.
    ///
    /// # Errors
    ///
    /// Returns error if the key bytes are invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_bytes(bytes.into())
            .map_err(|e| CryptoError::invalid_private_key(e.to_string()))?;

        Ok(Self { signing_key })
    }

    /// Get the verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl ClassicalSigner for P256Signer {
    fn algorithm(&self) -> ClassicalAlgorithm {
        ClassicalAlgorithm::EcdsaP256
    }

    fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
        let vk = self.signing_key.verifying_key();
        let encoded = vk.to_encoded_point(false); // Uncompressed
        Ok(encoded.as_bytes().to_vec())
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signature: Signature = self.signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
}

/// ECDSA P-256 verifier.
pub struct P256Verifier;

impl P256Verifier {
    /// Create a new verifier.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for P256Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ClassicalVerifier for P256Verifier {
    fn verify(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        // Parse public key
        let vk = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|e| CryptoError::invalid_public_key(e.to_string()))?;

        // Parse signature
        let sig = Signature::from_slice(signature)
            .map_err(|e| CryptoError::invalid_signature(e.to_string()))?;

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
    fn test_p256_sign_verify() {
        let signer = P256Signer::random();
        let verifier = P256Verifier::new();

        let data = b"test message";
        let signature = signer.sign(data).unwrap();
        let public_key = signer.public_key().unwrap();

        let valid = verifier.verify(&public_key, data, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_p256_invalid_signature() {
        let signer = P256Signer::random();
        let verifier = P256Verifier::new();

        let data = b"test message";
        let mut signature = signer.sign(data).unwrap();
        signature[0] ^= 0xFF; // Corrupt signature

        let public_key = signer.public_key().unwrap();
        let valid = verifier.verify(&public_key, data, &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_p256_wrong_data() {
        let signer = P256Signer::random();
        let verifier = P256Verifier::new();

        let signature = signer.sign(b"message 1").unwrap();
        let public_key = signer.public_key().unwrap();

        let valid = verifier.verify(&public_key, b"message 2", &signature).unwrap();
        assert!(!valid);
    }
}
