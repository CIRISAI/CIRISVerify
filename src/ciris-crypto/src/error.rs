//! Cryptographic error types.

use thiserror::Error;

use crate::types::{ClassicalAlgorithm, PqcAlgorithm};

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Invalid signature format or length.
    #[error("Invalid signature: {reason}")]
    InvalidSignature {
        /// Reason the signature is invalid.
        reason: String,
    },

    /// Signature verification failed.
    #[error("Signature verification failed")]
    VerificationFailed,

    /// Classical signature verification failed (in hybrid mode).
    #[error("Classical signature verification failed: {algorithm:?}")]
    ClassicalVerificationFailed {
        /// The algorithm that failed.
        algorithm: ClassicalAlgorithm,
    },

    /// PQC signature verification failed (in hybrid mode).
    #[error("PQC signature verification failed: {algorithm:?}")]
    PqcVerificationFailed {
        /// The algorithm that failed.
        algorithm: PqcAlgorithm,
    },

    /// Invalid public key format or length.
    #[error("Invalid public key: {reason}")]
    InvalidPublicKey {
        /// Reason the key is invalid.
        reason: String,
    },

    /// Invalid private key format or length.
    #[error("Invalid private key: {reason}")]
    InvalidPrivateKey {
        /// Reason the key is invalid.
        reason: String,
    },

    /// Key generation failed.
    #[error("Key generation failed: {reason}")]
    KeyGenerationFailed {
        /// Reason for the failure.
        reason: String,
    },

    /// Signing operation failed.
    #[error("Signing failed: {reason}")]
    SigningFailed {
        /// Reason for the failure.
        reason: String,
    },

    /// Algorithm not supported.
    #[error("Algorithm not supported: {algorithm}")]
    UnsupportedAlgorithm {
        /// The unsupported algorithm.
        algorithm: String,
    },

    /// PQC algorithm does not meet minimum security requirements.
    #[error("PQC algorithm {algorithm:?} does not meet minimum requirement (ML-DSA-65+)")]
    InsufficientPqcSecurity {
        /// The insufficient algorithm.
        algorithm: PqcAlgorithm,
    },

    /// Crypto kind mismatch.
    #[error("Crypto kind mismatch: expected {expected:?}, got {actual:?}")]
    CryptoKindMismatch {
        /// Expected crypto kind.
        expected: [u8; 4],
        /// Actual crypto kind.
        actual: [u8; 4],
    },

    /// Missing signature component in hybrid mode.
    #[error("Missing {component} signature in hybrid mode")]
    MissingSignatureComponent {
        /// The missing component (classical or pqc).
        component: String,
    },

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    // v2.0+ — federation symmetric / KDF errors. Kept distinct from
    // signature variants so callers can match on tampering vs.
    // operational failure cleanly.
    /// AES-256-GCM operation failed (encrypt or decrypt).
    /// Decrypt failures most commonly mean tampered ciphertext; encrypt
    /// failures are operational (allocation, etc.).
    #[error("AES-256-GCM {operation} failed: {reason}")]
    AesGcm {
        /// `"encrypt"` or `"decrypt"`.
        operation: &'static str,
        /// Underlying reason from the AEAD library or the caller's input.
        reason: String,
    },

    /// KDF parameters out of range. HKDF refuses outputs longer than
    /// `255 * HashLen` per RFC 5869; PBKDF2 refuses zero iterations.
    #[error("KDF parameter error: {0}")]
    KdfParameter(String),
}

impl CryptoError {
    /// Create an invalid signature error.
    #[must_use]
    pub fn invalid_signature(reason: impl Into<String>) -> Self {
        Self::InvalidSignature {
            reason: reason.into(),
        }
    }

    /// Create an invalid public key error.
    #[must_use]
    pub fn invalid_public_key(reason: impl Into<String>) -> Self {
        Self::InvalidPublicKey {
            reason: reason.into(),
        }
    }

    /// Create an invalid private key error.
    #[must_use]
    pub fn invalid_private_key(reason: impl Into<String>) -> Self {
        Self::InvalidPrivateKey {
            reason: reason.into(),
        }
    }

    /// Create a signing failed error.
    #[must_use]
    pub fn signing_failed(reason: impl Into<String>) -> Self {
        Self::SigningFailed {
            reason: reason.into(),
        }
    }

    /// Create a key generation failed error.
    #[must_use]
    pub fn key_generation_failed(reason: impl Into<String>) -> Self {
        Self::KeyGenerationFailed {
            reason: reason.into(),
        }
    }
}
