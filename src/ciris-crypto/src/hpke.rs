//! HPKE mode_base (RFC 9180 §5.1.1) over the X-Wing hybrid KEM
//! (CIRISVerify#82, v6.3.0+).
//!
//! The single-shot public-key encryption primitive for the scope-native
//! privacy MLS Welcome wrap (CEWP SCOPE_PRIVACY.md §3.3): an MLS Welcome is
//! sealed under the invitee's static X-Wing public key. **mode_base only** —
//! X-Wing structurally has no AuthEncap (draft-connolly-cfrg-xwing-kem;
//! confirmed draft-ietf-hpke-pq §7.2), so authenticated-KEM modes are
//! unavailable. Sender authentication is provided out-of-band by an ML-DSA-65
//! signature over the encapsulation (see the module example) — *not* by the
//! KEM. Both halves of ciphersuite 0x004D are exercised: X-Wing for
//! confidentiality, ML-DSA-65 for sender auth.
//!
//! ## KEM
//!
//! The KEM is the existing [`crate::hybrid_kex`] X-Wing (X25519 + ML-KEM-768,
//! HKDF-SHA256-bound). [`crate::hybrid_kex::initiate_hybrid`] *is* HPKE
//! `Encap` (returns the [`HybridHandshakeMsg`] encapsulation + the shared
//! secret); [`crate::hybrid_kex::respond_hybrid_with_public`] *is* `Decap`.
//! On top of the KEM shared secret this module runs the RFC 9180 §5.1
//! `KeySchedule` (HKDF-SHA256, `mode_base`) to derive the AEAD key + base
//! nonce, then seals with AES-256-GCM.
//!
//! ## Key schedule (RFC 9180 §4 / §5.1, mode_base)
//!
//! The `hybrid_kex` shared secret is treated as HPKE's KEM `shared_secret`
//! (it is already KEM-bound — black-boxed here). With KDF = HKDF-SHA256
//! (`Nh = 32`) and AEAD = AES-256-GCM (`Nk = 32`, `Nn = 12`):
//!
//! ```text
//! LabeledExtract(salt, label, ikm)
//!     = HKDF-Extract(salt, "HPKE-v1" ++ suite_id ++ label ++ ikm)        -> PRK (Nh)
//! LabeledExpand(prk, label, info, L)
//!     = HKDF-Expand(prk, I2OSP(L,2) ++ "HPKE-v1" ++ suite_id ++ label ++ info, L)
//!
//! mode_base = 0x00, psk = "", psk_id = "":
//!     psk_id_hash          = LabeledExtract("", "psk_id_hash", psk_id)
//!     info_hash            = LabeledExtract("", "info_hash", info)
//!     key_schedule_context = 0x00 ++ psk_id_hash ++ info_hash
//!     secret               = LabeledExtract(shared_secret, "secret", psk)
//!     key                  = LabeledExpand(secret, "key", ksc, Nk=32)
//!     base_nonce           = LabeledExpand(secret, "base_nonce", ksc, Nn=12)
//! ```
//!
//! Single-shot ⇒ `seq = 0` ⇒ the per-message nonce is exactly `base_nonce`.
//! `suite_id` is [`HPKE_SUITE_ID`] used consistently as the suite-id bytes in
//! every Labeled* call. NB this is *not* the canonical RFC 9180
//! `"HPKE" ‖ I2OSP(kem,2) ‖ I2OSP(kdf,2) ‖ I2OSP(aead,2)` byte form — X-Wing
//! has no IANA KEM-id, so a private-use ASCII suite-id string is pinned here
//! and flagged for cross-impl confirmation (see the const).
//!
//! ## AEAD + AAD
//!
//! [`crate::aes_gcm`] hardcodes an empty AAD, but HPKE binds the caller's
//! `aad` into every `Seal`/`Open` (RFC 9180 §5.2). So this module runs its
//! own `ring::aead` AES-256-GCM seal/open (mirroring `aes_gcm.rs`'s ring
//! usage) and passes the real `aad` via `Aad::from(aad)`. The key-schedule
//! `info` and the per-message `aad` are therefore bound at their correct,
//! distinct layers (info → key derivation, aad → AEAD).
//!
//! ## Sender authentication (caller-composed)
//!
//! ```ignore
//! let sealed = hpke::seal_base(&invitee_pub, info, aad, welcome)?;
//! let sig = MlDsa65Signer::from_seed(&inviter_seed)?
//!     .sign(&hpke::encap_signing_bytes(&sealed.encapsulation));   // sign the encap
//! // transmit (sealed, sig, inviter_pk); recipient verifies sig BEFORE open_base.
//! ```

use hkdf::Hkdf;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use sha2::Sha256;

use crate::error::CryptoError;
use crate::hybrid_kex::{self, HybridHandshakeMsg};

/// HPKE suite identifier for this construction (RFC 9180 §5.1 `suite_id`).
/// `"HPKE"` ‖ KEM-id ‖ KDF-id ‖ AEAD-id. The KEM-id is a private-use value
/// for X-Wing (no IANA KEM-id is allocated); KDF = HKDF-SHA256 (0x0001),
/// AEAD = AES-256-GCM (0x0002). **Cross-impl flag:** pinned here, flagged for
/// CEWP/CIRISEdge cross-confirmation before the wire value is frozen.
pub const HPKE_SUITE_ID: &[u8] = b"HPKE-xwing-hkdf-sha256-aes256gcm-v1";

/// RFC 9180 §4 version label, prefixed onto every Labeled* invocation.
const HPKE_V1: &[u8] = b"HPKE-v1";

/// AEAD key length (`Nk`) for AES-256-GCM.
const NK: usize = 32;
/// AEAD nonce length (`Nn`) for AES-256-GCM.
const NN: usize = 12;

/// An invitee's static X-Wing public key (the HPKE recipient key `pkR`).
#[derive(Debug, Clone)]
pub struct XWingRecipientPublic {
    /// Long-term X25519 public key (32 bytes).
    pub x25519_pub: [u8; 32],
    /// Long-term ML-KEM-768 public key.
    pub mlkem768_pub: Vec<u8>,
}

/// An invitee's static X-Wing secret key (`skR`). Carries the ML-KEM public
/// half too — `respond_hybrid_with_public` binds it into the shared-secret
/// salt, so Decap needs it.
#[derive(Debug, Clone)]
pub struct XWingRecipientSecret {
    /// Long-term X25519 secret key (32 bytes).
    pub x25519_priv: [u8; 32],
    /// Long-term ML-KEM-768 secret key.
    pub mlkem768_priv: Vec<u8>,
    /// Long-term ML-KEM-768 public key (for salt binding).
    pub mlkem768_pub: Vec<u8>,
}

/// The output of [`seal_base`]: the KEM encapsulation + the AEAD ciphertext.
#[derive(Debug, Clone)]
pub struct HpkeSealed {
    /// The X-Wing encapsulation (`enc`) — the ephemeral X25519 pubkey +
    /// ML-KEM-768 ciphertext.
    pub encapsulation: HybridHandshakeMsg,
    /// AES-256-GCM `ciphertext || tag`.
    pub ciphertext: Vec<u8>,
}

/// RFC 9180 §4 `LabeledExtract`:
/// `HKDF-Extract(salt, "HPKE-v1" ‖ suite_id ‖ label ‖ ikm)` → PRK (`Nh = 32`).
fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut labeled_ikm =
        Vec::with_capacity(HPKE_V1.len() + HPKE_SUITE_ID.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(HPKE_V1);
    labeled_ikm.extend_from_slice(HPKE_SUITE_ID);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let (prk, _hk) = Hkdf::<Sha256>::extract(salt_opt, &labeled_ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

/// RFC 9180 §4 `LabeledExpand`:
/// `HKDF-Expand(prk, I2OSP(L,2) ‖ "HPKE-v1" ‖ suite_id ‖ label ‖ info, L)`.
///
/// `L` must fit in two bytes and `L <= 255 * Nh = 8160` (HKDF-Expand cap).
/// Both call sites here use `L = 32` and `L = 12`, well within range; an
/// expand failure is mapped through the caller's `operation` tag.
fn labeled_expand(
    prk: &[u8; 32],
    label: &[u8],
    info: &[u8],
    l: usize,
    operation: &'static str,
) -> Result<Vec<u8>, CryptoError> {
    let l_u16 = u16::try_from(l).map_err(|_| CryptoError::Hpke {
        operation,
        reason: "labeled_expand length overflows u16".to_string(),
    })?;
    let mut labeled_info =
        Vec::with_capacity(2 + HPKE_V1.len() + HPKE_SUITE_ID.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&l_u16.to_be_bytes());
    labeled_info.extend_from_slice(HPKE_V1);
    labeled_info.extend_from_slice(HPKE_SUITE_ID);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);

    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| CryptoError::Hpke {
        operation,
        reason: "HKDF from_prk failed".to_string(),
    })?;
    let mut out = vec![0u8; l];
    hk.expand(&labeled_info, &mut out)
        .map_err(|_| CryptoError::Hpke {
            operation,
            reason: "HKDF-Expand failed".to_string(),
        })?;
    Ok(out)
}

/// RFC 9180 §5.1 `KeyScheduleS`/`KeyScheduleR` for `mode_base`
/// (`mode = 0x00`, `psk = ""`, `psk_id = ""`). Both sender and recipient run
/// the identical schedule over the shared KEM secret, so one function serves
/// `seal` and `open`. Returns `(key[Nk], base_nonce[Nn])`. Single-shot ⇒
/// `seq = 0` ⇒ the message nonce is `base_nonce` verbatim.
fn key_schedule_base(
    shared_secret: &[u8; 32],
    info: &[u8],
    operation: &'static str,
) -> Result<([u8; NK], [u8; NN]), CryptoError> {
    // mode_base: psk and psk_id are both empty.
    let psk_id_hash = labeled_extract(&[], b"psk_id_hash", &[]);
    let info_hash = labeled_extract(&[], b"info_hash", info);

    // key_schedule_context = mode(0x00) ‖ psk_id_hash ‖ info_hash
    let mut key_schedule_context = Vec::with_capacity(1 + 32 + 32);
    key_schedule_context.push(0x00);
    key_schedule_context.extend_from_slice(&psk_id_hash);
    key_schedule_context.extend_from_slice(&info_hash);

    // secret = LabeledExtract(shared_secret, "secret", psk="")
    let secret = labeled_extract(shared_secret, b"secret", &[]);

    let key = labeled_expand(&secret, b"key", &key_schedule_context, NK, operation)?;
    let base_nonce = labeled_expand(&secret, b"base_nonce", &key_schedule_context, NN, operation)?;

    let mut key_arr = [0u8; NK];
    key_arr.copy_from_slice(&key);
    let mut nonce_arr = [0u8; NN];
    nonce_arr.copy_from_slice(&base_nonce);
    Ok((key_arr, nonce_arr))
}

/// AES-256-GCM seal honoring a real `aad` — the AEAD half of HPKE `Seal`.
///
/// `crate::aes_gcm` hardcodes empty AAD, so HPKE (which must bind the
/// caller's `aad`, RFC 9180 §5.2) runs its own `ring::aead` here, mirroring
/// `aes_gcm.rs`'s `LessSafeKey` usage but passing `Aad::from(aad)`. Returns
/// `ciphertext || tag` (16-byte tag appended).
fn aead_seal(
    key: &[u8; NK],
    nonce: &[u8; NN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| CryptoError::Hpke {
        operation: "seal_base",
        reason: "AES-256-GCM key init failed".to_string(),
    })?;
    let cipher = LessSafeKey::new(unbound);
    let mut in_out = plaintext.to_vec();
    cipher
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| CryptoError::Hpke {
            operation: "seal_base",
            reason: "AES-256-GCM seal failed".to_string(),
        })?;
    Ok(in_out)
}

/// AES-256-GCM open honoring a real `aad` — the AEAD half of HPKE `Open`.
/// Opaque on failure: tag mismatch (tampered ct, wrong key, wrong nonce,
/// wrong aad) and a too-short ciphertext all collapse to one error.
fn aead_open(
    key: &[u8; NK],
    nonce: &[u8; NN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| CryptoError::Hpke {
        operation: "open_base",
        reason: "AEAD open failed".to_string(),
    })?;
    let cipher = LessSafeKey::new(unbound);
    let mut in_out = ciphertext.to_vec();
    let plaintext_len = cipher
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| CryptoError::Hpke {
            operation: "open_base",
            reason: "AEAD open failed".to_string(),
        })?
        .len();
    in_out.truncate(plaintext_len);
    Ok(in_out)
}

/// HPKE `SealBase` (RFC 9180 §6.1): encrypt `plaintext` to `recipient` under
/// application `info` + `aad`.
///
/// # Errors
///
/// [`CryptoError::Hpke`] `{ operation: "seal_base", .. }` on a KEM or AEAD fault.
pub fn seal_base(
    recipient: &XWingRecipientPublic,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeSealed, CryptoError> {
    // Encap: hybrid_kex::initiate_hybrid returns (encapsulation, shared_secret).
    let (encapsulation, shared_secret) =
        hybrid_kex::initiate_hybrid(&recipient.x25519_pub, &recipient.mlkem768_pub).map_err(
            |e| CryptoError::Hpke {
                operation: "seal_base",
                reason: format!("KEM encap failed: {e}"),
            },
        )?;

    let (key, base_nonce) = key_schedule_base(&shared_secret, info, "seal_base")?;
    // Single-shot ⇒ seq = 0 ⇒ message nonce = base_nonce.
    let ciphertext = aead_seal(&key, &base_nonce, aad, plaintext)?;

    Ok(HpkeSealed {
        encapsulation,
        ciphertext,
    })
}

/// HPKE `OpenBase` (RFC 9180 §6.1): decrypt `sealed` for `recipient` under the
/// same `info` + `aad`.
///
/// # Errors
///
/// [`CryptoError::Hpke`] `{ operation: "open_base", .. }` on a Decap or AEAD
/// fault (opaque — tampering vs. wrong-key are not distinguished).
pub fn open_base(
    recipient: &XWingRecipientSecret,
    sealed: &HpkeSealed,
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Decap: hybrid_kex::respond_hybrid_with_public recomputes the shared
    // secret. A wrong recipient key / tampered encapsulation diverges the
    // shared secret (the KEM doesn't error), which then fails the AEAD tag —
    // opaque, as required.
    let shared_secret = hybrid_kex::respond_hybrid_with_public(
        &recipient.x25519_priv,
        &recipient.mlkem768_priv,
        &recipient.mlkem768_pub,
        &sealed.encapsulation,
    )
    .map_err(|_| CryptoError::Hpke {
        operation: "open_base",
        reason: "AEAD open failed".to_string(),
    })?;

    let (key, base_nonce) = key_schedule_base(&shared_secret, info, "open_base")?;
    aead_open(&key, &base_nonce, aad, &sealed.ciphertext)
}

/// The canonical bytes an ML-DSA-65 sender-auth signature covers — the
/// serialized X-Wing encapsulation. Pinned encoding so producer + verifier
/// agree:
///
/// ```text
/// x25519_ephemeral_pub (32 B) ‖ I2OSP(len(mlkem768_ciphertext), 4) ‖ mlkem768_ciphertext
/// ```
///
/// The `algorithm` string is intentionally **excluded** — only the wire key
/// material is covered, so the signature binds the actual encapsulated DH +
/// KEM ciphertext the recipient will decapsulate, independent of label drift.
/// The 4-byte big-endian length prefix makes the encoding unambiguous
/// (length-delimited, no separator collision).
#[must_use]
pub fn encap_signing_bytes(encapsulation: &HybridHandshakeMsg) -> Vec<u8> {
    let ct = &encapsulation.mlkem768_ciphertext;
    // Invariant: the ML-KEM-768 ciphertext is a fixed 1088 B, so the u32
    // length prefix is always exact — the `unwrap_or(u32::MAX)` clamp below is
    // unreachable, not a silent truncation. Asserted in debug builds.
    debug_assert!(
        ct.len() <= u32::MAX as usize,
        "ML-KEM ciphertext length fits u32"
    );
    let mut out = Vec::with_capacity(32 + 4 + ct.len());
    out.extend_from_slice(&encapsulation.x25519_ephemeral_pub);
    // Length-prefix the variable-length ML-KEM ciphertext (u32 big-endian).
    // ct.len() is the ML-KEM-768 ciphertext (1088 B), well within u32.
    let len = u32::try_from(ct.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(ct);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ml_kem, x25519};

    /// Build a fresh X-Wing recipient keypair (public + secret halves).
    fn fresh_recipient() -> (XWingRecipientPublic, XWingRecipientSecret) {
        let (x_sk, x_pk) = x25519::generate_ephemeral_keypair().unwrap();
        let (mlkem_sk, mlkem_pk) = ml_kem::generate_keypair().unwrap();
        let public = XWingRecipientPublic {
            x25519_pub: x_pk,
            mlkem768_pub: mlkem_pk.clone(),
        };
        let secret = XWingRecipientSecret {
            x25519_priv: x_sk,
            mlkem768_priv: mlkem_sk,
            mlkem768_pub: mlkem_pk,
        };
        (public, secret)
    }

    /// Headline correctness: seal → open recovers the plaintext.
    #[test]
    fn round_trip_recovers_plaintext() {
        let (pk, sk) = fresh_recipient();
        let info = b"ciris-mls-welcome-v1";
        let aad = b"group-id-42";
        let pt = b"the sealed MLS Welcome message";
        let sealed = seal_base(&pk, info, aad, pt).unwrap();
        let opened = open_base(&sk, &sealed, info, aad).unwrap();
        assert_eq!(opened, pt);
    }

    /// Empty plaintext / info / aad all round-trip (boundary case).
    #[test]
    fn round_trip_empty_inputs() {
        let (pk, sk) = fresh_recipient();
        let sealed = seal_base(&pk, b"", b"", b"").unwrap();
        // Empty plaintext ⇒ ciphertext is just the 16-byte tag.
        assert_eq!(sealed.ciphertext.len(), 16);
        assert_eq!(open_base(&sk, &sealed, b"", b"").unwrap(), b"");
    }

    /// Wrong recipient secret key → open fails (opaque). The KEM yields a
    /// divergent shared secret which fails the AEAD tag.
    #[test]
    fn wrong_recipient_key_fails_open() {
        let (pk, _sk) = fresh_recipient();
        let (_pk2, wrong_sk) = fresh_recipient();
        let sealed = seal_base(&pk, b"info", b"aad", b"secret").unwrap();
        let err = open_base(&wrong_sk, &sealed, b"info", b"aad").unwrap_err();
        match err {
            CryptoError::Hpke { operation, .. } => assert_eq!(operation, "open_base"),
            other => panic!("expected Hpke open_base err, got {other:?}"),
        }
    }

    /// Tampered AEAD ciphertext → open fails.
    #[test]
    fn tampered_ciphertext_fails_open() {
        let (pk, sk) = fresh_recipient();
        let mut sealed = seal_base(&pk, b"info", b"aad", b"secret payload").unwrap();
        sealed.ciphertext[0] ^= 0x01;
        assert!(open_base(&sk, &sealed, b"info", b"aad").is_err());
    }

    /// Tampered AEAD tag (last byte) → open fails.
    #[test]
    fn tampered_tag_fails_open() {
        let (pk, sk) = fresh_recipient();
        let mut sealed = seal_base(&pk, b"info", b"aad", b"secret payload").unwrap();
        let last = sealed.ciphertext.len() - 1;
        sealed.ciphertext[last] ^= 0x01;
        assert!(open_base(&sk, &sealed, b"info", b"aad").is_err());
    }

    /// Tampered encapsulation (flip a byte of the ML-KEM ciphertext) → the
    /// recovered shared secret diverges → open fails.
    #[test]
    fn tampered_encapsulation_mlkem_fails_open() {
        let (pk, sk) = fresh_recipient();
        let mut sealed = seal_base(&pk, b"info", b"aad", b"secret").unwrap();
        sealed.encapsulation.mlkem768_ciphertext[0] ^= 0x01;
        assert!(open_base(&sk, &sealed, b"info", b"aad").is_err());
    }

    /// Tampered encapsulation (swap the ephemeral X25519 pubkey) → diverged
    /// shared secret → open fails.
    #[test]
    fn tampered_encapsulation_ephemeral_fails_open() {
        let (pk, sk) = fresh_recipient();
        let mut sealed = seal_base(&pk, b"info", b"aad", b"secret").unwrap();
        let (_, attacker_eph) = x25519::generate_ephemeral_keypair().unwrap();
        sealed.encapsulation.x25519_ephemeral_pub = attacker_eph;
        assert!(open_base(&sk, &sealed, b"info", b"aad").is_err());
    }

    /// Different `info` at open → wrong key-schedule key → open fails.
    #[test]
    fn different_info_fails_open() {
        let (pk, sk) = fresh_recipient();
        let sealed = seal_base(&pk, b"info-A", b"aad", b"secret").unwrap();
        assert!(open_base(&sk, &sealed, b"info-B", b"aad").is_err());
    }

    /// Different `aad` at open → AEAD tag mismatch → open fails.
    #[test]
    fn different_aad_fails_open() {
        let (pk, sk) = fresh_recipient();
        let sealed = seal_base(&pk, b"info", b"aad-A", b"secret").unwrap();
        assert!(open_base(&sk, &sealed, b"info", b"aad-B").is_err());
    }

    /// `encap_signing_bytes` is deterministic for a fixed encapsulation.
    #[test]
    fn encap_signing_bytes_deterministic() {
        let (pk, _sk) = fresh_recipient();
        let sealed = seal_base(&pk, b"info", b"aad", b"secret").unwrap();
        let a = encap_signing_bytes(&sealed.encapsulation);
        let b = encap_signing_bytes(&sealed.encapsulation);
        assert_eq!(a, b);
        // Encoding: 32-byte eph pub + 4-byte len prefix + ciphertext.
        assert_eq!(
            a.len(),
            32 + 4 + sealed.encapsulation.mlkem768_ciphertext.len()
        );
        // First 32 bytes are the ephemeral X25519 pubkey verbatim.
        assert_eq!(a[..32], sealed.encapsulation.x25519_ephemeral_pub);
        // Next 4 bytes are the big-endian ML-KEM ciphertext length.
        let ct_len = sealed.encapsulation.mlkem768_ciphertext.len() as u32;
        assert_eq!(a[32..36], ct_len.to_be_bytes());
    }

    /// `encap_signing_bytes` is sensitive to any change in the encapsulation.
    #[test]
    fn encap_signing_bytes_sensitivity() {
        let (pk, _sk) = fresh_recipient();
        let sealed = seal_base(&pk, b"info", b"aad", b"secret").unwrap();
        let base = encap_signing_bytes(&sealed.encapsulation);

        let mut e1 = sealed.encapsulation.clone();
        e1.x25519_ephemeral_pub[0] ^= 0x01;
        assert_ne!(base, encap_signing_bytes(&e1));

        let mut e2 = sealed.encapsulation.clone();
        e2.mlkem768_ciphertext[0] ^= 0x01;
        assert_ne!(base, encap_signing_bytes(&e2));

        // The algorithm string is intentionally NOT covered.
        let mut e3 = sealed.encapsulation.clone();
        e3.algorithm = "tampered-alg".to_string();
        assert_eq!(base, encap_signing_bytes(&e3));
    }

    /// Two seals to the same recipient use fresh ephemeral KEM material, so
    /// their encapsulations (and ciphertexts) differ — sanity that nothing is
    /// pinned to a static nonce.
    #[test]
    fn fresh_seals_differ() {
        let (pk, _sk) = fresh_recipient();
        let a = seal_base(&pk, b"info", b"aad", b"secret").unwrap();
        let b = seal_base(&pk, b"info", b"aad", b"secret").unwrap();
        assert_ne!(
            a.encapsulation.x25519_ephemeral_pub,
            b.encapsulation.x25519_ephemeral_pub
        );
    }

    /// Key-schedule drift-lock KAT — INDEPENDENT cross-check. The expected
    /// `key` + `base_nonce` were produced by an independent Python
    /// reimplementation of the exact RFC 9180 §4 labeled `mode_base` schedule
    /// using `HPKE_SUITE_ID` (not self-derived from this Rust). A mismatch
    /// means a real schedule discrepancy between the two impls. Because the
    /// canonical RFC 9180 vectors are keyed to the standard DHKEM suite-ids,
    /// this X-Wing private-use `suite_id` has no published IETF vector; this
    /// Python↔Rust agreement is the next best cross-impl lock until CEWP
    /// freezes `HPKE_SUITE_ID` and publishes an official vector.
    #[test]
    fn key_schedule_kat_independent_python() {
        let shared_secret = [0x01u8; 32];
        let info = b"ciris-scope-privacy-welcome-v1";
        let expected_key: [u8; 32] =
            hex_to_array("3fc2a490a4e65ec73b4445abc29b60674410dfd5b5383bd5df02e6468369660f");
        let expected_base_nonce: [u8; 12] = hex_to_array("1c53f938fbd16dc53825c59f");

        let (key, base_nonce) = key_schedule_base(&shared_secret, info, "seal_base").unwrap();
        assert_eq!(
            key, expected_key,
            "key-schedule `key` diverged from the independent Python KAT"
        );
        assert_eq!(
            base_nonce, expected_base_nonce,
            "key-schedule `base_nonce` diverged from the independent Python KAT"
        );
    }

    /// Hex string → fixed-length array (test helper for the KAT).
    fn hex_to_array<const N: usize>(s: &str) -> [u8; N] {
        let bytes = hex::decode(s).expect("valid hex");
        assert_eq!(bytes.len(), N, "hex length mismatch");
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }

    /// Internal-consistency lock on the RFC 9180 §4 key schedule: the same
    /// `shared_secret` + `info` derives a stable, deterministic `(key,
    /// base_nonce)`, and any change to `shared_secret` or `info` changes the
    /// derivation. No published RFC 9180 base-mode key-schedule intermediate
    /// vector was used (the canonical RFC 9180 test vectors are keyed to the
    /// DHKEM suite-ids, not this X-Wing private-use suite_id), so this is an
    /// internal-consistency check, not a cross-impl KAT. **Cross-impl flag:**
    /// the schedule should be re-locked against a CEWP-published vector once
    /// `HPKE_SUITE_ID` is frozen.
    #[test]
    fn key_schedule_internal_consistency() {
        let ss = [0x11u8; 32];
        let (k1, n1) = key_schedule_base(&ss, b"info", "seal_base").unwrap();
        let (k2, n2) = key_schedule_base(&ss, b"info", "seal_base").unwrap();
        assert_eq!(k1, k2);
        assert_eq!(n1, n2);

        // Different info → different key + nonce.
        let (k3, n3) = key_schedule_base(&ss, b"other-info", "seal_base").unwrap();
        assert!(k1 != k3 || n1 != n3);

        // Different shared secret → different key + nonce.
        let ss2 = [0x22u8; 32];
        let (k4, n4) = key_schedule_base(&ss2, b"info", "seal_base").unwrap();
        assert!(k1 != k4 || n1 != n4);

        // Shapes.
        assert_eq!(k1.len(), 32);
        assert_eq!(n1.len(), 12);
    }

    /// `labeled_extract` / `labeled_expand` are themselves deterministic and
    /// label-separated — a direct check on the §4 primitives underneath the
    /// schedule.
    #[test]
    fn labeled_primitives_label_separation() {
        let prk_a = labeled_extract(&[], b"psk_id_hash", &[]);
        let prk_b = labeled_extract(&[], b"info_hash", &[]);
        // Different labels over identical (salt, ikm) → different PRK.
        assert_ne!(prk_a, prk_b);

        let prk = labeled_extract(b"ss", b"secret", &[]);
        let key = labeled_expand(&prk, b"key", b"ctx", NK, "seal_base").unwrap();
        let nonce = labeled_expand(&prk, b"base_nonce", b"ctx", NN, "seal_base").unwrap();
        assert_eq!(key.len(), NK);
        assert_eq!(nonce.len(), NN);
        // Different expand label → different output prefix.
        assert_ne!(key[..NN], nonce[..]);
    }
}
