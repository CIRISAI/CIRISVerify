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

// secp256k1 for EVM wallet signing
#[cfg(feature = "secp256k1")]
pub mod secp256k1;

// PQC implementations behind feature flags
#[cfg(feature = "pqc-ml-dsa")]
mod ml_dsa;

// v2.0+ federation symmetric / KDF / MAC / RNG primitives. Each is
// gated by its own feature so consumers pull in only what they need.
// See CIRISVerify#7.
#[cfg(feature = "aes-gcm")]
pub mod aes_gcm;

/// CC 5.1 `CLM-epoch-keying` (CIRISVerify#193) — per-(stream_id, epoch) DEK +
/// stream-nonce HKDF derivation. Unconditional: `hkdf` + `sha2` are non-optional.
pub mod epoch_key;

#[cfg(feature = "kdf")]
pub mod kdf;

#[cfg(feature = "hmac")]
pub mod hmac;

#[cfg(feature = "random")]
pub mod random;

// v4.9.0+ (CIRISVerify#55 Gap H): SP 800-90B startup RNG health-check +
// fail-secure gate read by `random::fill`. Gated alongside `random`
// since it shares the `rand_core::OsRng` entropy path and exists to
// guard it.
#[cfg(feature = "random")]
pub mod rng_health;

// v4.4.0+ — X25519 ECDH primitive + HPKE-shape key-grant wrap
// (CIRISVerify#44 / CIRISNodeCore MEDIA_SHARING.md §6.3).
#[cfg(feature = "x25519")]
pub mod x25519;

#[cfg(feature = "key-grant")]
pub mod key_grant;

// v4.6.0+ — ML-KEM-768 (FIPS 203) PQ-KEM primitive + hybrid KEX
// (X25519 + ML-KEM-768 with HKDF-SHA256 binding). Closes Fed TM
// §3.3 Gap C / CIRISVerify#47.
#[cfg(feature = "ml-kem")]
pub mod ml_kem;

#[cfg(feature = "hybrid-kex")]
pub mod hybrid_kex;

// v8.x+ — deterministic self content-encryption keypair derivation
// (X25519 + ML-KEM-768) from the Ed25519 base seed (CIRISVerify#151).
#[cfg(feature = "self-enc")]
pub mod self_enc;

// v6.3.0+ — scope-native privacy surface (CIRISVerify#82, CEWP
// SCOPE_PRIVACY.md). First cut in the cross-cdylib lockstep cascade:
// XChaCha20-Poly1305 AEAD, HPKE mode_base over the X-Wing hybrid KEM,
// and the §2.2/§2.4 record_id/symbol-key derivation helpers. HKDF-SHA3-256
// and HMAC-SHA3-256 are added in-module to `kdf` / `hmac`.
#[cfg(feature = "xchacha")]
pub mod xchacha;

#[cfg(feature = "hpke")]
pub mod hpke;

#[cfg(feature = "scope-privacy")]
pub mod scope_privacy;

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

// v4.9.0+ (CIRISVerify#55 Gap H): surface the startup health-check
// entry points at the crate root so consumers can run the gate at
// process init without spelling out the module path. Mirrors how the
// signer types are hoisted above; the `random` module itself stays
// module-pathed (`crate::random::{fill,bytes}`) per its existing style.
#[cfg(feature = "random")]
pub use rng_health::{is_rng_failed, run_startup_health_check, RngHealth};

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
