//! HPKE `mode_base` (RFC 9180 §5.1.1) over X-Wing: the MLS Welcome wrap
//! (CC 5.4.4, CIRISVerify#324).
//!
//! An MLS Welcome is sealed to the invitee's static X-Wing key. The suite is
//! RFC 9180's own, with nothing private in it:
//!
//! | | id | |
//! |---|---|---|
//! | KEM | `0x647a` | X-Wing, draft-connolly-cfrg-xwing-kem-11 ([`crate::xwing`]); the id draft-ietf-hpke-pq lists |
//! | KDF | `0x0001` | HKDF-SHA256 |
//! | AEAD | `0x0002` | AES-256-GCM |
//!
//! `suite_id = "HPKE" ‖ I2OSP(0x647a, 2) ‖ I2OSP(0x0001, 2) ‖ I2OSP(0x0002, 2)`
//! ([`HPKE_SUITE_ID`]). X-Wing's HPKE binding (draft §5.6) makes `Encap` its
//! `Encapsulate` and `Decap` its `Decapsulate`: the X-Wing shared secret *is*
//! HPKE's `shared_secret`, and `enc` is the 1120-byte `ct_M ‖ ct_X`. The key
//! schedule is RFC 9180 §5.1 (`mode = 0x00`, empty `psk` / `psk_id`), and a
//! single-shot seal uses `seq = 0`, so the AEAD nonce is `base_nonce`.
//!
//! **The invitee's key** is an [`XWingSecretKey`] made from its 32-byte seed by
//! X-Wing §5.2. HPKE `DeriveKeyPair` is not used: it applies a labelled
//! SHAKE256 and would derive a different key from the same input (CC ruling on
//! #324).
//!
//! **`mode_auth` does not exist** for X-Wing (no `AuthEncap`). The sender is
//! authenticated by the inviter's hybrid signature over the encapsulation
//! (CC 5.4.4): [`encap_signing_bytes`] returns the bytes that signature covers.
//!
//! **Known answers.** `tests::hpke_pq_vector_0x647a_*` reproduce the
//! draft-ietf-hpke-pq vector for KEM `0x647a` + HKDF-SHA256 (with that vector's
//! ChaCha20-Poly1305 AEAD id in its `suite_id`; the key schedule is the same
//! for any 32-byte-key, 12-byte-nonce AEAD). The suite's own vectors, for
//! AES-256-GCM, are in `tests/vectors/xwing/hpke_xwing_aes256gcm.json`.
//!
//! The pre-23.0.0 suite is [`legacy_x25519mlkem768`], open-only.

#[allow(unused_imports)]
use crate::prelude::*;
use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::xwing::{XWingPublicKey, XWingSecretKey, XWING_CIPHERTEXT_LEN};

#[path = "hpke_legacy.rs"]
pub mod legacy_x25519mlkem768;

/// HPKE KEM id of X-Wing.
pub const KEM_ID_XWING: u16 = 0x647a;
/// HPKE KDF id of HKDF-SHA256.
pub const KDF_ID_HKDF_SHA256: u16 = 0x0001;
/// HPKE AEAD id of AES-256-GCM.
pub const AEAD_ID_AES_256_GCM: u16 = 0x0002;

/// RFC 9180 §5.1 `suite_id` of this suite:
/// `"HPKE" ‖ I2OSP(0x647a, 2) ‖ I2OSP(0x0001, 2) ‖ I2OSP(0x0002, 2)`.
pub const HPKE_SUITE_ID: [u8; 10] = suite_id(KEM_ID_XWING, KDF_ID_HKDF_SHA256, AEAD_ID_AES_256_GCM);

const fn suite_id(kem: u16, kdf: u16, aead: u16) -> [u8; 10] {
    let k = kem.to_be_bytes();
    let d = kdf.to_be_bytes();
    let a = aead.to_be_bytes();
    [b'H', b'P', b'K', b'E', k[0], k[1], d[0], d[1], a[0], a[1]]
}

/// RFC 9180 §4 version label.
const HPKE_V1: &[u8] = b"HPKE-v1";
/// AES-256-GCM key length (`Nk`).
const NK: usize = 32;
/// AES-256-GCM nonce length (`Nn`).
const NN: usize = 12;
/// HKDF-SHA256 output length (`Nh`).
const NH: usize = 32;

/// The output of [`seal_base`]: `enc` and the AEAD `ciphertext ‖ tag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HpkeSealed {
    /// The X-Wing encapsulation `enc = ct_M ‖ ct_X` (1120 bytes).
    pub encapsulation: Vec<u8>,
    /// AES-256-GCM `ciphertext ‖ tag`.
    pub ciphertext: Vec<u8>,
}

fn err(operation: &'static str, reason: &str) -> CryptoError {
    CryptoError::Hpke {
        operation,
        reason: reason.to_string(),
    }
}

/// `LabeledExtract(salt, label, ikm)` (RFC 9180 §4).
fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; NH]> {
    let mut labeled_ikm = Zeroizing::new(Vec::with_capacity(
        HPKE_V1.len() + suite.len() + label.len() + ikm.len(),
    ));
    labeled_ikm.extend_from_slice(HPKE_V1);
    labeled_ikm.extend_from_slice(suite);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled_ikm);
    let mut out = Zeroizing::new([0u8; NH]);
    out.copy_from_slice(&prk);
    out
}

/// `LabeledExpand(prk, label, info, L)` (RFC 9180 §4), `L` ≤ 255·Nh.
fn labeled_expand(
    suite: &[u8],
    prk: &[u8; NH],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let l = u16::try_from(out.len()).map_err(|_| err("key_schedule", "length overflows u16"))?;
    let mut labeled_info =
        Vec::with_capacity(2 + HPKE_V1.len() + suite.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&l.to_be_bytes());
    labeled_info.extend_from_slice(HPKE_V1);
    labeled_info.extend_from_slice(suite);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| err("key_schedule", "PRK length"))?
        .expand(&labeled_info, out)
        .map_err(|_| err("key_schedule", "HKDF-Expand failed"))
}

/// The RFC 9180 §5.1 key schedule for `mode_base`.
struct Context {
    key: Zeroizing<[u8; NK]>,
    base_nonce: [u8; NN],
    #[cfg_attr(not(test), allow(dead_code))]
    exporter_secret: Zeroizing<[u8; NH]>,
}

fn key_schedule_base(
    suite: &[u8],
    shared_secret: &[u8],
    info: &[u8],
) -> Result<Context, CryptoError> {
    let psk_id_hash = labeled_extract(suite, &[], b"psk_id_hash", &[]);
    let info_hash = labeled_extract(suite, &[], b"info_hash", info);
    let mut ctx = Vec::with_capacity(1 + 2 * NH);
    ctx.push(0x00);
    ctx.extend_from_slice(psk_id_hash.as_ref());
    ctx.extend_from_slice(info_hash.as_ref());
    let secret = labeled_extract(suite, shared_secret, b"secret", &[]);
    let mut key = Zeroizing::new([0u8; NK]);
    labeled_expand(suite, &secret, b"key", &ctx, key.as_mut())?;
    let mut base_nonce = [0u8; NN];
    labeled_expand(suite, &secret, b"base_nonce", &ctx, &mut base_nonce)?;
    let mut exporter_secret = Zeroizing::new([0u8; NH]);
    labeled_expand(suite, &secret, b"exp", &ctx, exporter_secret.as_mut())?;
    Ok(Context {
        key,
        base_nonce,
        exporter_secret,
    })
}

fn aead_key(key: &[u8; NK], operation: &'static str) -> Result<LessSafeKey, CryptoError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| err(operation, "AES-256-GCM key init failed"))
}

fn seal_with_shared_secret(
    shared_secret: &[u8],
    encapsulation: Vec<u8>,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeSealed, CryptoError> {
    let ctx = key_schedule_base(&HPKE_SUITE_ID, shared_secret, info)?;
    let mut in_out = plaintext.to_vec();
    aead_key(&ctx.key, "seal_base")?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(ctx.base_nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| err("seal_base", "AES-256-GCM seal failed"))?;
    Ok(HpkeSealed {
        encapsulation,
        ciphertext: in_out,
    })
}

/// `SealBase(pkR, info, aad, pt)` (RFC 9180 §6.1) with the encapsulation's
/// randomness from `rng`.
///
/// # Errors
/// [`CryptoError::Hpke`] on an AEAD fault.
pub fn seal_base_with_rng(
    recipient: &XWingPublicKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<HpkeSealed, CryptoError> {
    let (enc, ss) = recipient.encapsulate_with_rng(rng);
    seal_with_shared_secret(ss.as_ref(), enc.to_vec(), info, aad, plaintext)
}

/// `SealBase(pkR, info, aad, pt)` with randomness from the health-latched RNG.
///
/// # Errors
/// [`CryptoError::RngHealthCheckFailed`] if the RNG latch has failed;
/// [`CryptoError::Hpke`] on an AEAD fault.
pub fn seal_base(
    recipient: &XWingPublicKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeSealed, CryptoError> {
    let (enc, ss) = recipient.encapsulate()?;
    seal_with_shared_secret(ss.as_ref(), enc.to_vec(), info, aad, plaintext)
}

/// `OpenBase(enc, skR, info, aad, ct)` (RFC 9180 §6.1).
///
/// # Errors
/// [`CryptoError::Hpke`] `{ operation: "open_base" }`, opaque: a wrong key, a
/// tampered `enc` or ciphertext, a different `info` or `aad`, and a malformed
/// `enc` are not distinguished.
pub fn open_base(
    recipient: &XWingSecretKey,
    sealed: &HpkeSealed,
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let opaque = || err("open_base", "AEAD open failed");
    let ss = recipient
        .decapsulate(&sealed.encapsulation)
        .map_err(|_| opaque())?;
    let ctx = key_schedule_base(&HPKE_SUITE_ID, ss.as_ref(), info)?;
    let mut in_out = sealed.ciphertext.clone();
    let len = aead_key(&ctx.key, "open_base")?
        .open_in_place(
            Nonce::assume_unique_for_key(ctx.base_nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| opaque())?
        .len();
    in_out.truncate(len);
    Ok(in_out)
}

/// The bytes the inviter's hybrid signature covers (CC 5.4.4): the
/// encapsulation `enc = ct_M ‖ ct_X`, all 1120 bytes, as sent.
///
/// The X-Wing ciphertext has a fixed length and one encoding, so it is signed
/// as is, with no framing. (CC restates `encap_signing_bytes` over the X-Wing
/// ciphertext in rc20; this follows the ruling sent to verify on #324.)
///
/// # Errors
/// [`CryptoError::InvalidCiphertext`] if `sealed.encapsulation` is not 1120
/// bytes: a signature is never made or checked over a malformed `enc`.
pub fn encap_signing_bytes(sealed: &HpkeSealed) -> Result<Vec<u8>, CryptoError> {
    if sealed.encapsulation.len() != XWING_CIPHERTEXT_LEN {
        return Err(CryptoError::InvalidCiphertext {
            reason: format!(
                "X-Wing encapsulation must be {XWING_CIPHERTEXT_LEN} bytes, got {}",
                sealed.encapsulation.len()
            ),
        });
    }
    Ok(sealed.encapsulation.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::SeedableRng;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn suite_id_is_rfc_9180_form() {
        assert_eq!(HPKE_SUITE_ID, *b"HPKE\x64\x7a\x00\x01\x00\x02");
    }

    /// draft-ietf-hpke-pq test vector for KEM 0x647a, KDF HKDF-SHA256, AEAD
    /// ChaCha20-Poly1305 (0x0003), from hpkewg/hpke-pq `test-vectors.json`.
    /// Checks X-Wing as the HPKE KEM (pk from skRm, Encap with ikmE as the
    /// 64-byte randomness, Decap) and the key schedule (key, base_nonce,
    /// exporter_secret) under that vector's own suite_id.
    #[test]
    fn hpke_pq_vector_0x647a_kem_and_key_schedule() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/vectors/xwing/hpke_pq_0x647a_hkdf_sha256_chacha20poly1305.json"
        ))
        .unwrap();
        let s = |k: &str| h(v[k].as_str().unwrap());
        let sk = XWingSecretKey::from_seed(s("skRm").try_into().unwrap());
        assert_eq!(sk.public_key().as_bytes().to_vec(), s("pkRm"), "pkRm");
        let pk = XWingPublicKey::from_bytes(&s("pkRm")).unwrap();
        let (enc, ss) = pk.encapsulate_derand(&s("ikmE").try_into().unwrap());
        assert_eq!(enc.to_vec(), s("enc"), "enc");
        assert_eq!(ss.to_vec(), s("shared_secret"), "shared_secret");
        assert_eq!(sk.decapsulate(&enc).unwrap().to_vec(), s("shared_secret"));

        let suite = suite_id(0x647a, 0x0001, 0x0003);
        assert_eq!(suite.to_vec(), s("suite_id"));
        let ctx = key_schedule_base(&suite, &s("shared_secret"), &s("info")).unwrap();
        assert_eq!(ctx.key.to_vec(), s("key"), "key");
        assert_eq!(ctx.base_nonce.to_vec(), s("base_nonce"), "base_nonce");
        assert_eq!(
            ctx.exporter_secret.to_vec(),
            s("exporter_secret"),
            "exporter_secret"
        );
    }

    /// The suite's own known answers (AES-256-GCM), generated by an
    /// independent Python RFC 9180 key schedule over the X-Wing shared secret
    /// from the vector above.
    #[test]
    fn suite_known_answers() {
        let all: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../tests/vectors/xwing/hpke_xwing_aes256gcm.json"
        ))
        .unwrap();
        assert!(!all.is_empty());
        for v in &all {
            let s = |k: &str| h(v[k].as_str().unwrap());
            assert_eq!(s("suite_id"), HPKE_SUITE_ID.to_vec());
            let sk = XWingSecretKey::from_seed(s("skRm").try_into().unwrap());
            let pk = sk.public_key();
            let (enc, ss) = pk.encapsulate_derand(&s("ikmE").try_into().unwrap());
            assert_eq!(ss.to_vec(), s("shared_secret"));
            let ctx = key_schedule_base(&HPKE_SUITE_ID, ss.as_ref(), &s("info")).unwrap();
            assert_eq!(ctx.key.to_vec(), s("key"));
            assert_eq!(ctx.base_nonce.to_vec(), s("base_nonce"));
            assert_eq!(ctx.exporter_secret.to_vec(), s("exporter_secret"));
            let sealed =
                seal_with_shared_secret(ss.as_ref(), enc.to_vec(), &s("info"), &s("aad"), &s("pt"))
                    .unwrap();
            assert_eq!(sealed.ciphertext, s("ct"), "ct");
            assert_eq!(
                encap_signing_bytes(&sealed).unwrap(),
                s("enc"),
                "signed bytes are enc"
            );
            assert_eq!(
                open_base(&sk, &sealed, &s("info"), &s("aad")).unwrap(),
                s("pt")
            );
        }
    }

    fn fixture() -> (XWingSecretKey, XWingPublicKey, rand_chacha::ChaCha20Rng) {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([5; 32]);
        let sk = XWingSecretKey::generate_with_rng(&mut rng);
        let pk = sk.public_key();
        (sk, pk, rng)
    }

    #[test]
    fn round_trip_and_every_tamper_fails_opaquely() {
        let (sk, pk, mut rng) = fixture();
        let (info, aad, pt) = (
            b"ciris-mls-welcome".as_slice(),
            b"group-42".as_slice(),
            b"welcome".as_slice(),
        );
        let sealed = seal_base_with_rng(&pk, info, aad, pt, &mut rng).unwrap();
        assert_eq!(sealed.encapsulation.len(), 1120);
        assert_eq!(open_base(&sk, &sealed, info, aad).unwrap(), pt);
        assert_eq!(
            open_base(
                &sk,
                &seal_base_with_rng(&pk, b"", b"", b"", &mut rng).unwrap(),
                b"",
                b""
            )
            .unwrap(),
            b""
        );

        let expect_opaque = |r: Result<Vec<u8>, CryptoError>| match r {
            Err(CryptoError::Hpke {
                operation: "open_base",
                reason,
            }) => assert_eq!(reason, "AEAD open failed"),
            other => panic!("expected opaque open failure, got {other:?}"),
        };
        expect_opaque(open_base(
            &XWingSecretKey::from_seed([1; 32]),
            &sealed,
            info,
            aad,
        ));
        expect_opaque(open_base(&sk, &sealed, b"other", aad));
        expect_opaque(open_base(&sk, &sealed, info, b"other"));
        for i in [0, 1087, 1088, 1119] {
            let mut t = sealed.clone();
            t.encapsulation[i] ^= 1;
            expect_opaque(open_base(&sk, &t, info, aad));
        }
        let mut t = sealed.clone();
        t.encapsulation.pop();
        expect_opaque(open_base(&sk, &t, info, aad));
        assert!(encap_signing_bytes(&t).is_err());
        let mut t = sealed.clone();
        *t.ciphertext.last_mut().unwrap() ^= 1;
        expect_opaque(open_base(&sk, &t, info, aad));
        let mut t = sealed;
        t.ciphertext.truncate(10);
        expect_opaque(open_base(&sk, &t, info, aad));
    }

    #[test]
    fn fresh_seals_differ() {
        let (_, pk, mut rng) = fixture();
        let a = seal_base_with_rng(&pk, b"i", b"a", b"p", &mut rng).unwrap();
        let b = seal_base_with_rng(&pk, b"i", b"a", b"p", &mut rng).unwrap();
        assert_ne!(a.encapsulation, b.encapsulation);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn legacy_suite_does_not_open_new_wraps() {
        // Different KEM, different suite_id: the two suites never cross.
        assert_ne!(
            HPKE_SUITE_ID.as_slice(),
            legacy_x25519mlkem768::LEGACY_SUITE_LABEL
        );
        assert_eq!(
            legacy_x25519mlkem768::LEGACY_SUITE_LABEL,
            b"HPKE-xwing-hkdf-sha256-aes256gcm-v1",
            "the legacy label is KDF input and never changes"
        );
    }
}
