//! XChaCha20-Poly1305 authenticated encryption (CIRISVerify#82, v6.3.0+).
//!
//! The extended-nonce ChaCha20-Poly1305 AEAD — 24-byte (192-bit) nonce,
//! large enough that random nonces never collide in practice. This is the
//! scope-native-privacy cipher (CEWP SCOPE_PRIVACY.md):
//!
//! - §2.4 `symbol_envelope` — each RaptorQ symbol fragment is sealed under a
//!   per-symbol `symbol_key` ([`crate::scope_privacy::derive_symbol_key`]).
//! - §3.1 uniform AEAD framing — every outbound envelope (real or synthetic
//!   cover) is XChaCha20-Poly1305-framed so the two are wire-indistinguishable.
//!
//! Parallel in shape to [`crate::aes_gcm`] (`seal`/`open`, appended 16-byte
//! tag, empty AAD, caller-managed nonces). Same misuse caveat: nonce reuse
//! under one key is catastrophic — the 192-bit nonce makes *random* nonces
//! safe for effectively unbounded message counts, which is exactly why the
//! extended-nonce variant is the right fit for the per-symbol fan-out.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};

use crate::error::CryptoError;

/// XChaCha20-Poly1305 nonce length (24 bytes / 192 bits).
pub const NONCE_LEN: usize = 24;

/// Poly1305 authentication tag length (16 bytes), appended to the ciphertext.
pub const TAG_LEN: usize = 16;

/// Build an [`XChaCha20Poly1305`] cipher from raw key bytes.
///
/// The `key` length is fixed at 32 bytes by the array type, so
/// `new_from_slice` only fails on internal invariants — mapped to
/// [`CryptoError::Xchacha`] rather than panicked. Parallel to
/// [`crate::aes_gcm`]'s `cipher` helper.
fn cipher(key: &[u8; 32], operation: &'static str) -> Result<XChaCha20Poly1305, CryptoError> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::Xchacha {
        operation,
        reason: "XChaCha20-Poly1305 key initialization failed".to_string(),
    })
}

/// Seal `plaintext` under `key` + `nonce`. Returns `ciphertext || tag`.
///
/// The 16-byte Poly1305 tag is appended to the ciphertext (the standard
/// `chacha20poly1305` layout), so the output is `plaintext.len() + 16`
/// bytes. AAD is empty — this layer seals opaque envelopes.
///
/// # Errors
///
/// [`CryptoError::Xchacha`] `{ operation: "seal", .. }` on an AEAD fault
/// (extremely rare for a valid 32/24-byte key/nonce).
pub fn seal(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = cipher(key, "seal")?;
    // `Aead::encrypt` returns `ciphertext || tag` (empty AAD).
    cipher
        .encrypt(XNonce::from_slice(nonce), plaintext)
        .map_err(|_| CryptoError::Xchacha {
            operation: "seal",
            reason: "XChaCha20-Poly1305 seal failed".to_string(),
        })
}

/// Open `ciphertext` (trailing 16-byte tag included) under `key` + `nonce`.
///
/// # Errors
///
/// [`CryptoError::Xchacha`] `{ operation: "open", .. }` on tag mismatch
/// (tampered ciphertext, wrong key, or wrong nonce) or a malformed input
/// shorter than the 16-byte tag. The error message does NOT distinguish
/// these cases — that's intentional; a failed AEAD open is opaque and
/// callers must not branch on the reason.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = cipher(key, "open")?;
    cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::Xchacha {
            operation: "open",
            reason: "XChaCha20-Poly1305 open failed (tag mismatch or malformed ciphertext)"
                .to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::Payload;

    /// Round-trip — basic correctness.
    #[test]
    fn round_trip() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; NONCE_LEN];
        let plaintext = b"scope-native privacy symbol fragment";
        let ct = seal(&key, &nonce, plaintext).unwrap();
        // Ciphertext = plaintext + 16-byte tag.
        assert_eq!(ct.len(), plaintext.len() + TAG_LEN);
        let pt = open(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    /// Empty plaintext is valid input — produces a 16-byte ciphertext (just
    /// the tag). Locks behavior for callers sealing empty cover envelopes
    /// (§3.1 synthetic-cover framing).
    #[test]
    fn empty_plaintext_round_trip() {
        let key = [0u8; 32];
        let nonce = [0u8; NONCE_LEN];
        let ct = seal(&key, &nonce, b"").unwrap();
        assert_eq!(ct.len(), TAG_LEN);
        assert_eq!(open(&key, &nonce, &ct).unwrap(), b"");
    }

    /// Wrong key fails open with the Xchacha error variant — opaque, no
    /// distinction from a wrong nonce or a tampered tag.
    #[test]
    fn wrong_key_fails_open() {
        let key = [1u8; 32];
        let nonce = [2u8; NONCE_LEN];
        let ct = seal(&key, &nonce, b"hi").unwrap();
        let wrong = [9u8; 32];
        let err = open(&wrong, &nonce, &ct).unwrap_err();
        match err {
            CryptoError::Xchacha { operation, .. } => assert_eq!(operation, "open"),
            other => panic!("expected Xchacha open err, got {other:?}"),
        }
    }

    /// Wrong nonce fails open — same opaque shape as wrong key.
    #[test]
    fn wrong_nonce_fails_open() {
        let key = [3u8; 32];
        let ct = seal(&key, &[4u8; NONCE_LEN], b"hi").unwrap();
        let err = open(&key, &[5u8; NONCE_LEN], &ct).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::Xchacha {
                operation: "open",
                ..
            }
        ));
    }

    /// Tag mutation = tampered ciphertext = open fails.
    #[test]
    fn tampered_tag_fails_open() {
        let key = [6u8; 32];
        let nonce = [7u8; NONCE_LEN];
        let mut ct = seal(&key, &nonce, b"the brown fox").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 1; // flip a bit in the tag
        assert!(open(&key, &nonce, &ct).is_err());
    }

    /// A ciphertext shorter than the 16-byte tag is malformed — open must
    /// reject it, not panic.
    #[test]
    fn short_ciphertext_fails_open() {
        let key = [8u8; 32];
        let nonce = [9u8; NONCE_LEN];
        assert!(open(&key, &nonce, &[0u8; 8]).is_err());
        assert!(open(&key, &nonce, b"").is_err());
    }

    /// Independent KAT — the canonical AEAD_XCHACHA20_POLY1305 vector from
    /// draft-irtf-cfrg-xchacha-03 Appendix A.3.1.
    ///
    /// This is a TRUE independent vector (published, not crate-generated):
    /// it proves the `chacha20poly1305` crate computes the canonical
    /// XChaCha20-Poly1305 construction byte-for-byte. NOTE: the draft
    /// vector carries a non-empty AAD (`50515253c0c1c2c3c4c5c6c7`), so it
    /// is exercised through the crate's AAD-capable `Payload` API directly
    /// rather than this module's empty-AAD `seal`/`open` — the module's
    /// `seal` is the empty-AAD specialization of this same construction,
    /// regression-locked separately below.
    ///
    /// Source:
    /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03>
    #[test]
    fn xchacha_draft03_a_3_1_known_answer() {
        let key: [u8; 32] =
            hex_literal("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce: [u8; NONCE_LEN] =
            hex_literal("404142434445464748494a4b4c4d4e4f5051525354555657");
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plaintext = hex::decode(concat!(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173",
            "73206f66202739393a204966204920636f756c64206f6666657220796f75206f",
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73",
            "637265656e20776f756c642062652069742e",
        ))
        .unwrap();
        // Published `ciphertext || tag`.
        let expected = hex::decode(concat!(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
            "21f9664c97637da9768812f615c68b13b52e",
            "c0875924c1c7987947deafd8780acf49", // tag
        ))
        .unwrap();

        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(ct, expected, "draft-03 A.3.1 ciphertext mismatch");

        // And the inverse direction round-trips back to plaintext.
        let pt = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &expected,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(pt, plaintext);
    }

    /// Self-contained empty-AAD full-output KAT — the external lock on this
    /// module's `seal` path (the one path otherwise only checked against
    /// itself).
    ///
    /// draft-03 A.3.1 key/nonce, the first 20 plaintext bytes, EMPTY AAD.
    /// The expected `ciphertext || tag` was independently verified via
    /// libsodium `crypto_aead_xchacha20poly1305_ietf` (empty AAD), so this is
    /// a true external vector, not a regression lock. The 20-byte body is the
    /// AAD-independent draft-03 prefix; the tag is the empty-AAD Poly1305 over
    /// it (differs from the draft tag, which is taken over a non-empty AAD).
    #[test]
    fn empty_aad_seal_full_output_locked() {
        let key: [u8; 32] =
            hex_literal("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce: [u8; NONCE_LEN] =
            hex_literal("404142434445464748494a4b4c4d4e4f5051525354555657");
        let pt = b"Ladies and Gentlemen";
        // body (AAD-independent draft-03 prefix) || empty-AAD Poly1305 tag.
        let expected = hex::decode(
            "bd6d179d3e83d43b9576579493c0e939572a1700\
             05c1a867e11e7aa0743c2fea31314840",
        )
        .unwrap();
        let ct = seal(&key, &nonce, pt).unwrap();
        assert_eq!(ct, expected.as_slice());
        assert_eq!(open(&key, &nonce, &ct).unwrap(), pt);
    }

    /// Helper — hex string to fixed-length array. Mirrors `aes_gcm.rs`.
    fn hex_literal<const N: usize>(s: &str) -> [u8; N] {
        let bytes = hex::decode(s).expect("valid hex");
        assert_eq!(bytes.len(), N);
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }
}
