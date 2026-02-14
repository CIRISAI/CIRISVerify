//! # ciris-crypto
//!
//! Hybrid cryptography (classical + post-quantum) for CIRISVerify.
//!
//! This crate implements the dual-signature system required by CIRISVerify:
//! - **Classical**: ECDSA P-256 (hardware-compatible) or Ed25519
//! - **Post-Quantum**: ML-DSA-65 (FIPS 204)
//!
//! ## Signature Binding
//!
//! The PQC signature MUST cover the classical signature to prevent stripping attacks:
//!
//! ```text
//! signed_payload = data || classical_signature
//! pqc_signature = Sign_ML-DSA(key, signed_payload)
//! ```
//!
//! Both signatures must verify for the combined signature to be valid.
//!
//! ## CryptoKind Pattern
//!
//! Following Veilid's design, all signatures are tagged with their algorithm:
//!
//! ```rust,ignore
//! pub const CRYPTO_KIND_CIRIS_V1: CryptoKind = *b"CIR1";
//! ```
//!
//! This enables crypto agility and clear algorithm identification.

#![warn(missing_docs)]
#![warn(clippy::all)]

mod error;
mod hybrid;
mod types;

#[cfg(feature = "ecdsa-p256")]
mod ecdsa;

#[cfg(feature = "ed25519")]
mod ed25519;

// PQC implementations behind feature flags
#[cfg(feature = "pqc-ml-dsa")]
mod ml_dsa;

pub use error::CryptoError;
pub use hybrid::{
    ClassicalSigner, ClassicalVerifier, HybridSigner, HybridVerifier, PqcSigner, PqcVerifier,
};
pub use types::{
    ClassicalAlgorithm, CryptoKind, HybridSignature, PqcAlgorithm, SignatureMode,
    TaggedClassicalSignature, TaggedPqcSignature, CRYPTO_KIND_CIRIS_V1,
};

#[cfg(feature = "ecdsa-p256")]
pub use ecdsa::{P256Signer, P256Verifier};

#[cfg(feature = "ed25519")]
pub use ed25519::{Ed25519Signer, Ed25519Verifier};

#[cfg(feature = "pqc-ml-dsa")]
pub use ml_dsa::{MlDsa65Signer, MlDsa65Verifier};

/// Constant-time byte comparison.
///
/// Compares two byte slices in constant time to prevent timing attacks.
/// Returns `true` if the slices are equal, `false` otherwise.
///
/// # Security
///
/// This function MUST be used for all cryptographic comparisons
/// (signatures, MACs, hashes) to prevent timing side-channels.
///
/// Uses the `subtle` crate's `ConstantTimeEq` trait for the comparison.
/// The length check still returns early, but length is typically not secret.
/// For cases where length is secret, callers should pad to equal length.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    if a.len() != b.len() {
        // Still early-return on length, but length is typically not secret.
        // For cases where length is secret, callers should pad to equal length.
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_equal() {
        let a = [1u8, 2, 3, 4, 5];
        let b = [1u8, 2, 3, 4, 5];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_different() {
        let a = [1u8, 2, 3, 4, 5];
        let b = [1u8, 2, 3, 4, 6];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_different_length() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4, 5];
        assert!(!constant_time_eq(&a, &b));
    }
}
