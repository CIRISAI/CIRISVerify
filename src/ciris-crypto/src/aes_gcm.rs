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
//! - **Tag**: 16 bytes appended to the ciphertext.
//! - **AAD**: none (empty) — this layer encrypts opaque blobs.
//!
//! ## Backend (v2.8.0+, CIRISVerify#26)
//!
//! Implemented over [`ring`]'s `aead`. v2.0–v2.7 used RustCrypto
//! `aes-gcm`, which measured ~1 GiB/s — 3–5× below ring/OpenSSL because
//! RustCrypto's GHASH lacks the hand-tuned CLMUL assembly. The switch
//! to ring buys that 3–5× **at zero build cost**: ring is already a
//! universal dependency in this workspace — `rustls` pulls it via
//! `reqwest` and `hickory-resolver`, and `ciris-verify-ffi` builds it
//! explicitly for Android and iOS. Its assembly is already compiled,
//! already cross-compiled to every target, already linked, and already
//! trusted for every TLS handshake. Using it for AES-GCM adds no new
//! toolchain and no new cross-compile surface.
//!
//! **Wire format is unchanged.** AES-256-GCM is a deterministic
//! standard: for a given key/nonce/plaintext, ring and RustCrypto emit
//! byte-identical `ciphertext || tag`. Blobs sealed by a ≤ v2.7 build
//! decrypt cleanly here and vice versa. The NIST GCM known-answer test
//! below is the lock on that guarantee.
//!
//! ## Nonce policy
//!
//! Nonce reuse with the same key is catastrophic for GCM (full plaintext
//! recovery + forgery). This module **does not** detect or prevent reuse —
//! that is the caller's responsibility. ring's API names the
//! explicit-nonce constructor [`Nonce::assume_unique_for_key`] precisely
//! to flag that footgun. Recommended caller patterns:
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
//!
//! [`ring`]: https://docs.rs/ring
//! [`Nonce::assume_unique_for_key`]: https://docs.rs/ring/latest/ring/aead/struct.Nonce.html

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

use crate::error::CryptoError;

/// Build a `LessSafeKey` for AES-256-GCM from raw key bytes.
///
/// `LessSafeKey` is ring's explicit-caller-supplied-nonce variant — the
/// right fit here because this module's contract is caller-managed
/// nonces (see the module-level nonce policy). The `key` length is fixed
/// at 32 bytes by the type, so `UnboundKey::new` only fails on internal
/// invariants — mapped to `CryptoError::AesGcm` rather than panicked.
fn cipher(key: &[u8; 32], operation: &'static str) -> Result<LessSafeKey, CryptoError> {
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| CryptoError::AesGcm {
        operation,
        reason: "AES-256-GCM key initialization failed".to_string(),
    })?;
    Ok(LessSafeKey::new(unbound))
}

/// Encrypt `plaintext` with `key` and `nonce` using AES-256-GCM. Returns
/// `ciphertext || tag` (the standard appended-tag layout). Tag is 16 bytes.
///
/// # Errors
///
/// `CryptoError::AesGcm { operation: "encrypt", .. }` if the cipher
/// rejects the inputs (extremely rare for valid 32/12-byte key/nonce).
pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = cipher(key, "encrypt")?;
    // ring seals in place and appends the 16-byte tag; `in_out` starts
    // as the plaintext and ends as `ciphertext || tag`.
    let mut in_out = plaintext.to_vec();
    cipher
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::empty(),
            &mut in_out,
        )
        .map_err(|_| CryptoError::AesGcm {
            operation: "encrypt",
            reason: "AES-256-GCM seal failed".to_string(),
        })?;
    Ok(in_out)
}

/// Decrypt `ciphertext` (which must include the trailing 16-byte tag)
/// with `key` and `nonce`. Returns the plaintext on success.
///
/// # Errors
///
/// `CryptoError::AesGcm { operation: "decrypt", .. }` on tag mismatch
/// (tampered ciphertext, wrong key, or wrong nonce) or a malformed
/// ciphertext shorter than the 16-byte tag. The error message does NOT
/// distinguish these cases — that's intentional; callers shouldn't be
/// making distinctions on a failed AEAD decrypt.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = cipher(key, "decrypt")?;
    // ring opens in place: it decrypts `in_out` and returns the
    // plaintext sub-slice (tag stripped). We take its length, drop the
    // borrow, then truncate `in_out` down to the plaintext — one
    // allocation total, no second copy.
    let mut in_out = ciphertext.to_vec();
    let plaintext_len = cipher
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::empty(),
            &mut in_out,
        )
        .map_err(|_| CryptoError::AesGcm {
            operation: "decrypt",
            reason: "AES-256-GCM open failed (tag mismatch or malformed ciphertext)".to_string(),
        })?
        .len();
    in_out.truncate(plaintext_len);
    Ok(in_out)
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

    /// A ciphertext shorter than the 16-byte tag is malformed — decrypt
    /// must reject it, not panic.
    #[test]
    fn short_ciphertext_fails_decrypt() {
        let key = [8u8; 32];
        let nonce = [9u8; 12];
        assert!(decrypt(&key, &nonce, &[0u8; 8]).is_err());
        assert!(decrypt(&key, &nonce, b"").is_err());
    }

    /// NIST GCM known-answer vector — the cross-backend wire-format lock.
    ///
    /// This exact vector passed under the RustCrypto `aes-gcm` backend
    /// (v2.0–v2.7); it must still pass under `ring` (v2.8.0+). Because it
    /// does, AES-256-GCM is byte-identical across the backend switch —
    /// blobs sealed by an older build decrypt cleanly here, and vice
    /// versa. From NIST GCM Test Vectors, gcmEncryptExtIV256.rsp Count=0
    /// (Keylen=256, IVlen=96, PTlen=0, AADlen=0, Taglen=128).
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
