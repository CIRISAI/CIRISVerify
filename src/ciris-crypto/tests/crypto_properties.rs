//! Property-based tests for cryptographic operations.
//!
//! These tests verify mathematical invariants of cryptographic operations
//! using proptest to generate arbitrary inputs.

use ciris_crypto::constant_time_eq;
use ciris_crypto::{ClassicalSigner, ClassicalVerifier};
use ciris_crypto::{Ed25519Signer, Ed25519Verifier, P256Signer, P256Verifier};
use proptest::prelude::*;

/// Strategy for generating binary data of specified size range.
fn binary_data(min: usize, max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), min..=max)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_shrink_iters: 1000,
        ..ProptestConfig::default()
    })]

    // ========================================================================
    // ECDSA P-256 Properties
    // ========================================================================

    /// ECDSA signatures are deterministic for the same key and message.
    #[test]
    fn ecdsa_sign_deterministic(data in binary_data(1, 1024)) {
        let signer = P256Signer::random();
        let sig1 = signer.sign(&data).unwrap();
        let sig2 = signer.sign(&data).unwrap();

        // Same key + same data = same signature (RFC 6979 deterministic)
        prop_assert_eq!(sig1, sig2);
    }

    /// ECDSA sign-verify roundtrip always succeeds.
    #[test]
    fn ecdsa_roundtrip(data in binary_data(0, 2048)) {
        let signer = P256Signer::random();
        let verifier = P256Verifier::new();

        let signature = signer.sign(&data).unwrap();
        let public_key = signer.public_key().unwrap();

        prop_assert!(verifier.verify(&public_key, &data, &signature).unwrap());
    }

    /// ECDSA verification fails for tampered data.
    #[test]
    fn ecdsa_tampered_data_fails(
        data in binary_data(1, 1024),
        tamper_idx in any::<prop::sample::Index>()
    ) {
        let signer = P256Signer::random();
        let verifier = P256Verifier::new();

        let signature = signer.sign(&data).unwrap();
        let public_key = signer.public_key().unwrap();

        // Tamper with data
        let mut tampered = data.clone();
        let idx = tamper_idx.index(tampered.len());
        tampered[idx] ^= 0xFF;

        // Verification should fail
        prop_assert!(!verifier.verify(&public_key, &tampered, &signature).unwrap());
    }

    /// ECDSA verification fails for wrong key.
    #[test]
    fn ecdsa_wrong_key_fails(data in binary_data(1, 1024)) {
        let signer1 = P256Signer::random();
        let signer2 = P256Signer::random();
        let verifier = P256Verifier::new();

        let signature = signer1.sign(&data).unwrap();
        let wrong_key = signer2.public_key().unwrap();

        // Verification with wrong key should fail
        prop_assert!(!verifier.verify(&wrong_key, &data, &signature).unwrap());
    }

    /// ECDSA signatures have correct size (64 bytes for P-256).
    #[test]
    fn ecdsa_signature_size(data in binary_data(1, 1024)) {
        let signer = P256Signer::random();
        let signature = signer.sign(&data).unwrap();

        prop_assert_eq!(signature.len(), 64);
    }

    /// ECDSA public keys have correct size (65 bytes uncompressed).
    #[test]
    fn ecdsa_public_key_size(_seed in any::<u64>()) {
        let signer = P256Signer::random();
        let public_key = signer.public_key().unwrap();

        // Uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes)
        prop_assert_eq!(public_key.len(), 65);
        prop_assert_eq!(public_key[0], 0x04);
    }

    // ========================================================================
    // Ed25519 Properties
    // ========================================================================

    /// Ed25519 sign-verify roundtrip always succeeds.
    #[test]
    fn ed25519_roundtrip(data in binary_data(0, 2048)) {
        let signer = Ed25519Signer::random();
        let verifier = Ed25519Verifier::new();

        let signature = signer.sign(&data).unwrap();
        let public_key = signer.public_key().unwrap();

        prop_assert!(verifier.verify(&public_key, &data, &signature).unwrap());
    }

    /// Ed25519 signatures have correct size (64 bytes).
    #[test]
    fn ed25519_signature_size(data in binary_data(1, 1024)) {
        let signer = Ed25519Signer::random();
        let signature = signer.sign(&data).unwrap();

        prop_assert_eq!(signature.len(), 64);
    }

    /// Ed25519 public keys have correct size (32 bytes).
    #[test]
    fn ed25519_public_key_size(_seed in any::<u64>()) {
        let signer = Ed25519Signer::random();
        let public_key = signer.public_key().unwrap();

        prop_assert_eq!(public_key.len(), 32);
    }

    /// Ed25519 verification fails for tampered signature.
    #[test]
    fn ed25519_tampered_signature_fails(
        data in binary_data(1, 1024),
        tamper_idx in 0usize..64
    ) {
        let signer = Ed25519Signer::random();
        let verifier = Ed25519Verifier::new();

        let signature = signer.sign(&data).unwrap();
        let public_key = signer.public_key().unwrap();

        // Tamper with signature
        let mut tampered_sig = signature.clone();
        tampered_sig[tamper_idx] ^= 0xFF;

        // Verification should fail (or return error for invalid signature)
        let result = verifier.verify(&public_key, &data, &tampered_sig);
        // Invalid signature format error is also acceptable
        if let Ok(valid) = result {
            prop_assert!(!valid);
        }
    }

    // ========================================================================
    // Constant-Time Comparison Properties
    // ========================================================================

    /// Constant-time comparison is reflexive (a == a).
    #[test]
    fn constant_time_reflexive(data in binary_data(0, 256)) {
        prop_assert!(constant_time_eq(&data, &data));
    }

    /// Constant-time comparison is symmetric (a == b implies b == a).
    #[test]
    fn constant_time_symmetric(
        a in binary_data(0, 256),
        b in binary_data(0, 256)
    ) {
        prop_assert_eq!(constant_time_eq(&a, &b), constant_time_eq(&b, &a));
    }

    /// Constant-time comparison detects single-byte differences.
    #[test]
    fn constant_time_detects_difference(
        data in binary_data(1, 256),
        idx in any::<prop::sample::Index>()
    ) {
        let mut modified = data.clone();
        let idx = idx.index(modified.len());
        modified[idx] ^= 0x01;

        prop_assert!(!constant_time_eq(&data, &modified));
    }

    /// Constant-time comparison detects length differences.
    #[test]
    fn constant_time_length_sensitive(data in binary_data(1, 256)) {
        let shorter: Vec<u8> = data.iter().take(data.len() - 1).copied().collect();

        prop_assert!(!constant_time_eq(&data, &shorter));
    }
}

// ============================================================================
// Non-proptest Deterministic Tests
// ============================================================================

#[test]
fn test_ecdsa_empty_message() {
    let signer = P256Signer::random();
    let verifier = P256Verifier::new();

    let data = b"";
    let signature = signer.sign(data).unwrap();
    let public_key = signer.public_key().unwrap();

    assert!(verifier.verify(&public_key, data, &signature).unwrap());
}

#[test]
fn test_ed25519_from_seed_deterministic() {
    let seed = [42u8; 32];
    let signer1 = Ed25519Signer::from_seed(&seed).unwrap();
    let signer2 = Ed25519Signer::from_seed(&seed).unwrap();

    let data = b"test data";
    let sig1 = signer1.sign(data).unwrap();
    let sig2 = signer2.sign(data).unwrap();

    assert_eq!(sig1, sig2);
    assert_eq!(signer1.public_key().unwrap(), signer2.public_key().unwrap());
}

#[test]
fn test_different_keys_different_signatures() {
    let signer1 = P256Signer::random();
    let signer2 = P256Signer::random();

    let data = b"test data";
    let sig1 = signer1.sign(data).unwrap();
    let sig2 = signer2.sign(data).unwrap();

    // Different keys should produce different signatures
    assert_ne!(sig1, sig2);
}

#[test]
fn test_constant_time_eq_empty() {
    assert!(constant_time_eq(&[], &[]));
    assert!(!constant_time_eq(&[], &[0]));
    assert!(!constant_time_eq(&[0], &[]));
}

#[test]
fn test_ed25519_different_data_different_signatures() {
    let signer = Ed25519Signer::random();

    let data1 = b"message one";
    let data2 = b"message two";

    let sig1 = signer.sign(data1).unwrap();
    let sig2 = signer.sign(data2).unwrap();

    // Different data should produce different signatures
    assert_ne!(sig1, sig2);
}

#[test]
fn test_p256_large_message() {
    let signer = P256Signer::random();
    let verifier = P256Verifier::new();

    let data = vec![0x42u8; 10_000]; // 10KB message

    let signature = signer.sign(&data).unwrap();
    let public_key = signer.public_key().unwrap();

    assert!(verifier.verify(&public_key, &data, &signature).unwrap());
}
