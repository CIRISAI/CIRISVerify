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

/// Encrypt with **associated data** (CIRISVerify#279, CIRISPersist#831).
///
/// Same key / nonce / appended-tag conventions as [`encrypt`]; the only
/// difference is that `aad` is authenticated (never encrypted) and must be
/// presented byte-for-byte to [`decrypt_aad`] or the tag fails.
///
/// ## Why this exists beside the AAD-empty pair
///
/// The AAD-empty pair encrypts *opaque* blobs. Persist seals blobs through
/// it, and edge's chat migration onto community-cohort blobs needs a
/// ciphertext **bound to its referencing row** — author, signed instant,
/// epoch — so a ciphertext lifted onto another validly-signed row does not
/// open. A row-side commitment cannot give that property under a
/// per-epoch *shared* DEK (anyone holding the DEK can re-seal); AEAD
/// associated data can, because the binding is inside the tag.
///
/// The AAD-empty pair is untouched and its NIST KAT still holds: an
/// `encrypt_aad` ciphertext does not open under [`decrypt`], and vice
/// versa — that mutual refusal is asserted by test, since it *is* the
/// binding property.
///
/// # Errors
///
/// `CryptoError::AesGcm { operation: "encrypt", .. }` if the cipher rejects
/// the inputs.
pub fn encrypt_aad(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = cipher(key, "encrypt")?;
    let mut in_out = plaintext.to_vec();
    cipher
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| CryptoError::AesGcm {
            operation: "encrypt",
            reason: "AES-256-GCM seal (with AAD) failed".to_string(),
        })?;
    Ok(in_out)
}

/// Decrypt a ciphertext produced by [`encrypt_aad`], presenting the same
/// `aad`. Returns the plaintext on success.
///
/// # Errors
///
/// `CryptoError::AesGcm { operation: "decrypt", .. }` on tag mismatch —
/// which now also covers **wrong or missing AAD**, exactly as intended: a
/// blob presented against the wrong row is indistinguishable from a
/// tampered blob, and callers should not be distinguishing them.
pub fn decrypt_aad(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = cipher(key, "decrypt")?;
    let mut in_out = ciphertext_and_tag.to_vec();
    let plaintext_len = cipher
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| CryptoError::AesGcm {
            operation: "decrypt",
            reason: "AES-256-GCM open (with AAD) failed (tag mismatch, wrong AAD, or malformed ciphertext)"
                .to_string(),
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

    // ---- associated data (CIRISVerify#279) ------------------------------

    /// Round-trip with AAD.
    #[test]
    fn aad_round_trip() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let aad = b"author=A|signed_at=1|epoch=7";
        let ct = encrypt_aad(&key, &nonce, aad, b"row payload").unwrap();
        assert_eq!(ct.len(), b"row payload".len() + 16);
        assert_eq!(decrypt_aad(&key, &nonce, aad, &ct).unwrap(), b"row payload");
    }

    /// **The binding property.** The same ciphertext presented against a
    /// different row (different AAD) must not open — this is what a
    /// row-side commitment under a shared DEK cannot give and AAD can.
    #[test]
    fn aad_mismatch_refuses() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let ct = encrypt_aad(&key, &nonce, b"row-A", b"secret").unwrap();
        let err = decrypt_aad(&key, &nonce, b"row-B", &ct).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::AesGcm {
                operation: "decrypt",
                ..
            }
        ));
        // …and a bit-flip inside the AAD is likewise a refusal.
        assert!(decrypt_aad(&key, &nonce, b"row-a", &ct).is_err());
    }

    /// **Cross-refusal, both directions.** An `encrypt_aad` ciphertext must
    /// not open under the AAD-empty `decrypt`, and an AAD-empty `encrypt`
    /// ciphertext must not open under `decrypt_aad` with non-empty AAD.
    /// Otherwise a caller could strip the binding by choosing the other
    /// entry point.
    #[test]
    fn aad_and_empty_pairs_refuse_each_other() {
        let key = [3u8; 32];
        let nonce = [4u8; 12];
        let with_aad = encrypt_aad(&key, &nonce, b"row", b"pt").unwrap();
        assert!(
            decrypt(&key, &nonce, &with_aad).is_err(),
            "AAD-empty decrypt must refuse an AAD ciphertext"
        );
        let without = encrypt(&key, &nonce, b"pt").unwrap();
        assert!(
            decrypt_aad(&key, &nonce, b"row", &without).is_err(),
            "decrypt_aad must refuse an AAD-empty ciphertext"
        );
    }

    /// Empty AAD through the new pair is byte-identical to the old pair —
    /// so the two entry points agree on the degenerate case and the
    /// existing AAD-empty KAT constrains `encrypt_aad(.., b"", ..)` too.
    #[test]
    fn aad_empty_is_identical_to_the_plain_pair() {
        let key = [5u8; 32];
        let nonce = [6u8; 12];
        assert_eq!(
            encrypt_aad(&key, &nonce, b"", b"same").unwrap(),
            encrypt(&key, &nonce, b"same").unwrap()
        );
    }

    /// NIST GCM known-answer vector with **non-empty AAD** — the cross-impl
    /// lock for the new pair. From NIST `gcmEncryptExtIV256.rsp`
    /// `[Keylen = 256] [IVlen = 96] [PTlen = 128] [AADlen = 128] [Taglen = 128]`
    /// Count = 0, extracted from the official `gcmtestvectors.zip` and
    /// **independently cross-checked byte-for-byte** against the copy
    /// RustCrypto vendors in `aes-gcm-0.10.3/tests/aes256gcm.rs` — two
    /// sources, so the fixture is not merely what this code emits.
    ///
    /// Source:
    /// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip>
    #[test]
    fn nist_vector_keylen_256_iv_96_pt_128_aad_128() {
        let key: [u8; 32] =
            hex_literal("92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b");
        let nonce: [u8; 12] = hex_literal("ac93a1a6145299bde902f21a");
        let pt: [u8; 16] = hex_literal("2d71bcfa914e4ac045b2aa60955fad24");
        let aad: [u8; 16] = hex_literal("1e0889016f67601c8ebea4943bc23ad6");
        let expected_ct: [u8; 16] = hex_literal("8995ae2e6df3dbf96fac7b7137bae67f");
        let expected_tag: [u8; 16] = hex_literal("eca5aa77d51d4a0a14d9c51e1da474ab");

        let out = encrypt_aad(&key, &nonce, &aad, &pt).unwrap();
        assert_eq!(&out[..16], &expected_ct, "ciphertext");
        assert_eq!(&out[16..], &expected_tag, "tag");
        assert_eq!(decrypt_aad(&key, &nonce, &aad, &out).unwrap(), pt);
        // And the AAD is load-bearing for this vector too.
        assert!(decrypt(&key, &nonce, &out).is_err());
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
