//! AES-256-GCM authenticated encryption (CIRISVerify#7, v2.0.0+).
//!
//! AES-256-GCM is the federation's only AEAD. Used for:
//! - `EncryptedSecretRecord` per-secret encryption (CIRISPersist#19)
//! - Caller-managed transport encryption when the wire isn't already
//!   protected (e.g. agent ↔ persist secrets that need confidentiality
//!   beyond the transport's TLS layer).
//!
//! ## Algorithm
//!
//! - **Cipher**: AES-256 with 32-byte (256-bit) key.
//! - **AEAD mode**: GCM with 12-byte (96-bit) nonce.
//! - **Tag**: 16 bytes appended to the ciphertext (RustCrypto default).
//!
//! ## Nonce policy
//!
//! Nonce reuse with the same key is catastrophic for GCM (full plaintext
//! recovery + forgery). This module **does not** detect or prevent reuse —
//! that is the caller's responsibility. Recommended caller patterns:
//!
//! - **Random nonce**: 96 bits is large enough that birthday-bound reuse
//!   probability stays acceptable for ~2³² messages per key. Use
//!   `ciris_crypto::random::fill` (when the `random` feature is on) or
//!   any other CSRNG.
//! - **Counter nonce**: caller-managed monotonic counter. Cheaper but
//!   demands strict per-key state.
//!
//! No nonce reuse detection at this layer means the federation's
//! threat model assumes well-behaved callers; misuse is reportable as
//! a key-compromise event, not a library bug.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};

use crate::error::CryptoError;

/// Encrypt `plaintext` with `key` and `nonce` using AES-256-GCM. Returns
/// `ciphertext || tag` (the standard appended-tag layout). Tag is 16 bytes.
///
/// # Errors
///
/// `CryptoError::AesGcm { operation: "encrypt", .. }` if the cipher
/// rejects the inputs (extremely rare for valid 32/12-byte key/nonce).
pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|e| CryptoError::AesGcm {
            operation: "encrypt",
            reason: e.to_string(),
        })
}

/// Decrypt `ciphertext` (which must include the trailing 16-byte tag)
/// with `key` and `nonce`. Returns the plaintext on success.
///
/// # Errors
///
/// `CryptoError::AesGcm { operation: "decrypt", .. }` on tag mismatch
/// (tampered ciphertext, wrong key, or wrong nonce). The error message
/// does NOT distinguish these cases — that's intentional; callers
/// shouldn't be making distinctions on a failed AEAD decrypt.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| CryptoError::AesGcm {
            operation: "decrypt",
            reason: e.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip — basic correctness.
    #[test]
    fn round_trip() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let plaintext = b"persist secret material";
        let ct = encrypt(&key, &nonce, plaintext).unwrap();
        // Ciphertext = plaintext + 16-byte tag.
        assert_eq!(ct.len(), plaintext.len() + 16);
        let pt = decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    /// Empty plaintext is valid input — produces a 16-byte ciphertext
    /// (just the tag). Locks behavior for callers that may encrypt
    /// empty placeholders.
    #[test]
    fn empty_plaintext_round_trip() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let ct = encrypt(&key, &nonce, b"").unwrap();
        assert_eq!(ct.len(), 16);
        assert_eq!(decrypt(&key, &nonce, &ct).unwrap(), b"");
    }

    /// Wrong key fails decrypt with the AesGcm error variant.
    #[test]
    fn wrong_key_fails_decrypt() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let ct = encrypt(&key, &nonce, b"hi").unwrap();
        let wrong = [9u8; 32];
        let err = decrypt(&wrong, &nonce, &ct).unwrap_err();
        match err {
            CryptoError::AesGcm { operation, .. } => assert_eq!(operation, "decrypt"),
            other => panic!("expected AesGcm decrypt err, got {other:?}"),
        }
    }

    /// Wrong nonce fails decrypt — same shape as wrong key. Caller
    /// can't distinguish the two and shouldn't be trying to.
    #[test]
    fn wrong_nonce_fails_decrypt() {
        let key = [3u8; 32];
        let ct = encrypt(&key, &[4u8; 12], b"hi").unwrap();
        let err = decrypt(&key, &[5u8; 12], &ct).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::AesGcm {
                operation: "decrypt",
                ..
            }
        ));
    }

    /// Tag mutation = tampered ciphertext = decrypt fails.
    #[test]
    fn tampered_tag_fails_decrypt() {
        let key = [6u8; 32];
        let nonce = [7u8; 12];
        let mut ct = encrypt(&key, &nonce, b"the brown fox").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 1; // flip a bit in the tag
        assert!(decrypt(&key, &nonce, &ct).is_err());
    }

    /// NIST GCM test vector — locks against algorithm regression
    /// across RustCrypto bumps. From NIST GCM Test Vectors,
    /// gcmEncryptExtIV256.rsp Count=0 (Keylen=256, IVlen=96, PTlen=0,
    /// AADlen=0, Taglen=128).
    ///
    /// Source:
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip>
    #[test]
    fn nist_vector_keylen_256_iv_96_pt_0() {
        let key: [u8; 32] =
            hex_literal("b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4");
        let nonce: [u8; 12] = hex_literal("516c33929df5a3284ff463d7");
        // PT empty; expected tag from NIST vectors.
        let expected_tag: [u8; 16] = hex_literal("bdc1ac884d332457a1d2664f168c76f0");
        let ct = encrypt(&key, &nonce, b"").unwrap();
        // Empty plaintext → ciphertext is just the 16-byte tag.
        assert_eq!(ct, expected_tag);
        assert_eq!(decrypt(&key, &nonce, &ct).unwrap(), b"");
    }

    /// Helper — hex string to fixed-length array. Asserts length at
    /// runtime; const-eval-friendly only because tests are debug builds.
    fn hex_literal<const N: usize>(s: &str) -> [u8; N] {
        let bytes = hex::decode(s).expect("valid hex");
        assert_eq!(bytes.len(), N);
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }
}
