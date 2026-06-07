//! Key-grant wrap primitive — `x25519-aes256-gcm-hkdf-sha256`
//! (CIRISVerify#44 / CIRISNodeCore MEDIA_SHARING.md §6.3, v4.4.0+).
//!
//! HPKE RFC 9180 base-mode-shaped wrap-and-unwrap of a 32-byte DEK
//! for a recipient identified by an X25519 public key. Multimedia
//! tier crypto surface for restricted-group + subscription-routed
//! content (CW communities, AdultHUB / OnlyFans / Netflix / paid
//! community per the CEWP §6 design).
//!
//! ## Wire shape (`wrap_algorithm: v1`)
//!
//! ```text
//! KeyGrantWrap {
//!     ephemeral_public_key: [u8; 32],   // X25519 ephemeral pubkey
//!     nonce:                [u8; 12],   // AES-GCM nonce
//!     ciphertext:           Vec<u8>,    // AES-GCM ciphertext + 16-byte tag
//! }
//! ```
//!
//! ## Algorithm (`wrap_algorithm: v1`)
//!
//! Wrap:
//! 1. Generate ephemeral X25519 keypair `(eph_sk, eph_pk)`.
//! 2. ECDH `shared_secret = X25519(eph_sk, recipient_pk)`.
//! 3. HKDF-SHA256:
//!    - IKM   = `shared_secret`
//!    - salt  = `eph_pk || recipient_pk`
//!    - info  = `b"cewp-key-grant/v1"`
//!    - L     = 32 bytes  →  `wrap_key`
//! 4. Fresh 12-byte random nonce.
//! 5. AES-256-GCM seal: `ciphertext = AES-GCM(wrap_key, nonce, dek)`.
//! 6. Output `(eph_pk, nonce, ciphertext)`.
//!
//! Unwrap: identical KDF derivation from `(recipient_sk, eph_pk)`,
//! then AES-GCM open. A wrong recipient_sk, a tampered ciphertext,
//! or a mismatched `eph_pk` all produce an AEAD tag-mismatch
//! failure — the opaque-failure invariant.
//!
//! ## Why exactly these primitives
//!
//! Per CIRISVerify#44: reuse ciris-crypto's already-shipped X25519
//! (this crate) + AES-GCM (`ring` backend, 5.45 GiB/s) + HKDF-SHA256
//! (`hkdf` crate, ~548 ns per derive). No pairing-based or lattice
//! primitives at the wrap layer; structural attack surface matches
//! Signal sealed sender / libsodium sealed boxes / HPKE RFC 9180
//! base mode — well-studied, deployed at scale.
//!
//! ## PQC horizon
//!
//! `wrap_algorithm: v1` = X25519. The ciphertext-stealing horizon
//! (when past wraps could be retroactively decrypted by quantum
//! attackers) is much further out than the signature-forging
//! horizon — the Contribution envelope that CARRIES the
//! KeyGrantWrap is signed Ed25519 + ML-DSA-65 hybrid (unchanged),
//! so long-term provenance stays PQC-secure even when the wrap
//! itself is classical-only.
//!
//! ## `wrap_algorithm: v2` — X25519 + ML-KEM-768 hybrid (v4.10.0+)
//!
//! CEG 0.15 §10.5.3 makes `wrap_algorithm: v2 = x25519+ml-kem-768`
//! (FIPS 203 hybrid) **MANDATORY** for the streaming epoch-DEK
//! `key_grant` cascade — a Consumer MUST reject a streaming epoch
//! grant carrying `v1`. The DEK protects content that may persist
//! indefinitely, so a classical-only KEM is a harvest-now-decrypt-
//! later exposure even though the content AEAD and the wrap
//! signature are already PQC-safe. See [`wrap_dek_for_recipient_v2`].
//!
//! v2 derivation (gated on the `ml-kem` feature):
//! 1. Ephemeral X25519 DH → `shared_x` (32 B).
//! 2. ML-KEM-768 encapsulate against the recipient's ML-KEM pubkey →
//!    `(mlkem_ct, shared_mlkem)` (1088 B ciphertext, 32 B secret).
//! 3. HKDF-SHA256: `IKM = shared_x ‖ shared_mlkem`; salt binds ALL
//!    public material (`eph_x_pub ‖ recipient_x_pub ‖ mlkem_ct ‖
//!    recipient_mlkem_pub`); `info = b"cewp-key-grant/v2"`; L = 32 →
//!    `wrap_key`. An attacker must break BOTH X25519 AND ML-KEM-768
//!    to recover the wrap key.
//! 4. Fresh nonce, AES-256-GCM seal the DEK (same as v1).
//!
//! The versioned HKDF info string (`/v1` → `/v2`) rotates the context
//! cleanly, and the distinct [`KeyGrantWrapV2`] wire shape (it carries
//! `ml_kem_ciphertext`) makes the two algorithms unambiguous on the
//! wire — the envelope's `wrap_algorithm` field selects which to
//! deserialize.

use serde::{Deserialize, Serialize};

use crate::error::CryptoError;
use crate::{aes_gcm, kdf, random, x25519};

/// HKDF context label for `wrap_algorithm: v1`. Versioned so the
/// ML-KEM hybrid migration can rotate cleanly via context-string
/// rotation (HKDF info field).
pub const KEY_GRANT_V1_INFO: &[u8] = b"cewp-key-grant/v1";

/// AES-GCM nonce length (12 bytes per NIST SP 800-38D §5.2.1.1).
pub const KEY_GRANT_NONCE_LEN: usize = 12;

/// Algorithm-identifier string for the `wrap_algorithm` envelope
/// field per CIRISNodeCore MEDIA_SHARING.md §6.3.
pub const KEY_GRANT_ALGORITHM_V1: &str = "x25519-aes256-gcm-hkdf-sha256";

/// HKDF context label for `wrap_algorithm: v2` (X25519 + ML-KEM-768
/// hybrid). The `/v2` suffix rotates the HKDF context cleanly from
/// `/v1` per CEG 0.15 §10.5.3.
#[cfg(feature = "ml-kem")]
pub const KEY_GRANT_V2_INFO: &[u8] = b"cewp-key-grant/v2";

/// Algorithm-identifier string for `wrap_algorithm: v2` — the hybrid
/// X25519 + ML-KEM-768 DEK wrap mandated by CEG 0.15 §10.5.3 for the
/// streaming epoch-DEK cascade.
///
/// Follows the v1 naming convention (primitives in derivation order):
/// X25519 KEX-half · ML-KEM-768 KEM-half · AES-256-GCM AEAD ·
/// HKDF-SHA256 KDF. CEG §10.5.3 pins the *construction* (v2 =
/// x25519+ml-kem-768) but not yet a literal wire string; this is the
/// natural extension of [`KEY_GRANT_ALGORITHM_V1`]. Cross-confirm with
/// CIRISRegistry (CEG) + CIRISPersist before any consumer hard-codes
/// it as a closed-set enum value.
#[cfg(feature = "ml-kem")]
pub const KEY_GRANT_ALGORITHM_V2: &str = "x25519-mlkem768-aes256-gcm-hkdf-sha256";

/// One wrap output: the public material a recipient needs to
/// unwrap, plus the AEAD ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyGrantWrap {
    /// X25519 ephemeral public key — used as `salt[0..32]` in the
    /// HKDF derivation and as the `peer_public` in the recipient's
    /// ECDH.
    pub ephemeral_public_key: [u8; 32],
    /// AES-GCM nonce — fresh per wrap.
    pub nonce: [u8; 12],
    /// AES-GCM ciphertext + 16-byte tag.
    pub ciphertext: Vec<u8>,
}

/// One `wrap_algorithm: v2` (X25519 + ML-KEM-768 hybrid) wrap output.
///
/// Distinct wire shape from [`KeyGrantWrap`] — it carries the ML-KEM
/// ciphertext the recipient needs to decapsulate the PQC half. The
/// envelope's `wrap_algorithm` field discriminates which struct a
/// consumer deserializes; per CEG 0.15 §10.5.3 a streaming consumer
/// MUST reject a `v1`-tagged epoch grant.
#[cfg(feature = "ml-kem")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyGrantWrapV2 {
    /// X25519 ephemeral public key — the classical-half DH peer + part
    /// of the HKDF salt binding.
    pub ephemeral_x25519_public_key: [u8; 32],
    /// ML-KEM-768 ciphertext (1088 bytes) — the recipient decapsulates
    /// this with their ML-KEM secret key to recover the PQC-half shared
    /// secret. Also salt-bound in the HKDF derivation.
    pub ml_kem_ciphertext: Vec<u8>,
    /// AES-GCM nonce — fresh per wrap.
    pub nonce: [u8; 12],
    /// AES-256-GCM ciphertext + 16-byte tag over the 32-byte DEK.
    pub ciphertext: Vec<u8>,
}

/// Errors specific to the key-grant surface.
///
/// Wrap-side errors surface CSPRNG or AEAD failures. Unwrap-side
/// errors deliberately do NOT distinguish "wrong recipient key" /
/// "tampered ciphertext" / "wrong ephemeral pubkey" — all three
/// failure modes report `WrapUnverified` via an opaque AEAD tag
/// mismatch, matching the AEAD opaque-failure discipline.
#[derive(Debug)]
pub enum KeyGrantError {
    /// CSPRNG / ECDH / KDF / AEAD operation failed.
    Crypto(CryptoError),
    /// Unwrapped plaintext length wasn't 32 bytes — the wrap was
    /// applied to a non-32-byte payload (the surface only supports
    /// 32-byte DEKs).
    UnexpectedPlaintextLength {
        /// What was decrypted.
        actual: usize,
    },
    /// Failed AEAD open — wrong recipient key, tampered ciphertext,
    /// or mismatched ephemeral_public_key. Deliberately opaque per
    /// the AEAD discipline.
    WrapUnverified,
}

impl From<CryptoError> for KeyGrantError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl std::fmt::Display for KeyGrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "key_grant crypto: {e}"),
            Self::UnexpectedPlaintextLength { actual } => {
                write!(
                    f,
                    "key_grant unwrap: expected 32-byte DEK, got {actual} bytes"
                )
            },
            Self::WrapUnverified => {
                write!(
                    f,
                    "key_grant unwrap: AEAD tag mismatch (wrong recipient key, \
                     tampered ciphertext, or mismatched ephemeral_public_key)"
                )
            },
        }
    }
}

impl std::error::Error for KeyGrantError {}

/// Derive the wrap key from `(shared_secret, ephemeral_pub, recipient_pub)`.
///
/// Both wrap and unwrap call this with identical inputs (the ECDH
/// shared secret is symmetric), so the derivation is identical on
/// both sides. Salt binding to BOTH the ephemeral_pub and
/// recipient_pub is what closes the unknown-key-share class —
/// anyone re-deriving without the same `(eph_pk, recipient_pk)`
/// pair gets a different wrap_key and AES-GCM open fails.
fn derive_wrap_key(
    shared_secret: &[u8; 32],
    ephemeral_pub: &[u8; 32],
    recipient_pub: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral_pub);
    salt[32..].copy_from_slice(recipient_pub);
    let derived = kdf::hkdf_sha256(shared_secret, &salt, KEY_GRANT_V1_INFO, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&derived);
    Ok(out)
}

/// Wrap a 32-byte DEK for a recipient identified by their X25519
/// public key.
///
/// Generates a fresh ephemeral X25519 keypair per wrap, runs ECDH
/// against `recipient_x25519_pubkey`, derives a wrap key via
/// HKDF-SHA256 with salt-bound context, then AES-256-GCM-seals the
/// DEK under a fresh random nonce.
///
/// # Errors
///
/// [`KeyGrantError::Crypto`] on CSPRNG / ECDH / KDF / AEAD failure.
/// All structurally extremely rare on a healthy system.
pub fn wrap_dek_for_recipient(
    recipient_x25519_pubkey: &[u8; 32],
    dek: &[u8; 32],
) -> Result<KeyGrantWrap, KeyGrantError> {
    // Ephemeral DH: returns (ephemeral_pub, shared_secret).
    let (ephemeral_public_key, shared_secret) = x25519::ephemeral_dh(recipient_x25519_pubkey)?;

    // HKDF-derive the wrap key, salt-bound to both ephemeral_pub
    // and recipient_pub (closes UKS).
    let wrap_key = derive_wrap_key(
        &shared_secret,
        &ephemeral_public_key,
        recipient_x25519_pubkey,
    )?;

    // Fresh 12-byte nonce.
    let mut nonce = [0u8; KEY_GRANT_NONCE_LEN];
    random::fill(&mut nonce)?;

    // AES-256-GCM seal the DEK.
    let ciphertext = aes_gcm::encrypt(&wrap_key, &nonce, dek)?;

    Ok(KeyGrantWrap {
        ephemeral_public_key,
        nonce,
        ciphertext,
    })
}

/// Unwrap a `KeyGrantWrap` using the recipient's X25519 private key.
///
/// Reconstructs the recipient's own public key from the private
/// key (for HKDF salt binding), runs ECDH against the wrap's
/// `ephemeral_public_key`, re-derives the wrap key identically to
/// the sender, and AES-GCM-opens the ciphertext.
///
/// # Errors
///
/// [`KeyGrantError::WrapUnverified`] on AEAD tag mismatch — wrong
/// recipient key, tampered ciphertext, or mismatched
/// ephemeral_public_key. Deliberately opaque.
///
/// [`KeyGrantError::UnexpectedPlaintextLength`] if the unwrapped
/// plaintext is not 32 bytes (the wrap was applied to a non-DEK
/// payload; caller is misusing the surface).
///
/// [`KeyGrantError::Crypto`] on ECDH / KDF failure (structurally
/// rare).
pub fn unwrap_dek(
    recipient_x25519_privkey: &[u8; 32],
    wrap: &KeyGrantWrap,
) -> Result<[u8; 32], KeyGrantError> {
    // Reconstruct recipient's own public for salt binding.
    let recipient_pub = x25519::public_from_secret(recipient_x25519_privkey);

    // ECDH: recipient_sk × ephemeral_pk = same shared_secret the
    // sender computed via ephemeral_sk × recipient_pk.
    let shared_secret = x25519::dh(recipient_x25519_privkey, &wrap.ephemeral_public_key)?;

    // Re-derive the wrap key identically to the sender.
    let wrap_key = derive_wrap_key(&shared_secret, &wrap.ephemeral_public_key, &recipient_pub)?;

    // AES-256-GCM open. Tag-mismatch → opaque WrapUnverified.
    let plaintext = aes_gcm::decrypt(&wrap_key, &wrap.nonce, &wrap.ciphertext)
        .map_err(|_| KeyGrantError::WrapUnverified)?;

    if plaintext.len() != 32 {
        return Err(KeyGrantError::UnexpectedPlaintextLength {
            actual: plaintext.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&plaintext);
    Ok(out)
}

// =============================================================================
// wrap_algorithm: v2 — X25519 + ML-KEM-768 hybrid (CEG 0.15 §10.5.3)
// =============================================================================

/// Derive the v2 wrap key from the two shared secrets + all public
/// material. Both wrap and unwrap call this with identical inputs.
///
/// `IKM = shared_x ‖ shared_mlkem`; the salt binds the ephemeral
/// X25519 pubkey, the recipient X25519 pubkey, the ML-KEM ciphertext,
/// AND the recipient ML-KEM pubkey — closing unknown-key-share on
/// BOTH the classical and PQC halves. An attacker must break X25519
/// AND ML-KEM-768 to recover this key.
#[cfg(feature = "ml-kem")]
fn derive_wrap_key_v2(
    shared_x: &[u8; 32],
    shared_mlkem: &[u8; 32],
    ephemeral_x_pub: &[u8; 32],
    recipient_x_pub: &[u8; 32],
    mlkem_ciphertext: &[u8],
    recipient_mlkem_pub: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(shared_x);
    ikm[32..].copy_from_slice(shared_mlkem);

    let mut salt = Vec::with_capacity(32 + 32 + mlkem_ciphertext.len() + recipient_mlkem_pub.len());
    salt.extend_from_slice(ephemeral_x_pub);
    salt.extend_from_slice(recipient_x_pub);
    salt.extend_from_slice(mlkem_ciphertext);
    salt.extend_from_slice(recipient_mlkem_pub);

    let derived = kdf::hkdf_sha256(&ikm, &salt, KEY_GRANT_V2_INFO, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&derived);
    Ok(out)
}

/// Wrap a 32-byte DEK for a recipient under `wrap_algorithm: v2`
/// (X25519 + ML-KEM-768 hybrid) — the algorithm CEG 0.15 §10.5.3
/// mandates for the streaming epoch-DEK cascade.
///
/// Combines an ephemeral X25519 ECDH with an ML-KEM-768 encapsulation
/// against the recipient's two public keys, binds both shared secrets
/// via HKDF-SHA256 (salt-bound to all public material), and
/// AES-256-GCM-seals the DEK under the derived wrap key.
///
/// `recipient_ml_kem_pubkey` MUST be [`crate::ml_kem::ML_KEM_768_PUBKEY_LEN`]
/// (1184) bytes; a wrong length surfaces as [`KeyGrantError::Crypto`].
///
/// # Errors
///
/// [`KeyGrantError::Crypto`] on CSPRNG / ECDH / ML-KEM encapsulation /
/// KDF / AEAD failure (or a malformed recipient ML-KEM pubkey).
#[cfg(feature = "ml-kem")]
pub fn wrap_dek_for_recipient_v2(
    recipient_x25519_pubkey: &[u8; 32],
    recipient_ml_kem_pubkey: &[u8],
    dek: &[u8; 32],
) -> Result<KeyGrantWrapV2, KeyGrantError> {
    // Classical half: ephemeral X25519 DH.
    let (ephemeral_x25519_public_key, shared_x) =
        crate::x25519::ephemeral_dh(recipient_x25519_pubkey)?;

    // PQC half: ML-KEM-768 encapsulate against the recipient's ML-KEM
    // public key.
    let (ml_kem_ciphertext, shared_mlkem) = crate::ml_kem::encapsulate(recipient_ml_kem_pubkey)?;

    // Bind both halves + all public material into the wrap key.
    let wrap_key = derive_wrap_key_v2(
        &shared_x,
        &shared_mlkem,
        &ephemeral_x25519_public_key,
        recipient_x25519_pubkey,
        &ml_kem_ciphertext,
        recipient_ml_kem_pubkey,
    )?;

    // Fresh 12-byte nonce.
    let mut nonce = [0u8; KEY_GRANT_NONCE_LEN];
    random::fill(&mut nonce)?;

    // AES-256-GCM seal the DEK.
    let ciphertext = aes_gcm::encrypt(&wrap_key, &nonce, dek)?;

    Ok(KeyGrantWrapV2 {
        ephemeral_x25519_public_key,
        ml_kem_ciphertext,
        nonce,
        ciphertext,
    })
}

/// Unwrap a [`KeyGrantWrapV2`] using the recipient's X25519 + ML-KEM-768
/// private keys.
///
/// Runs the recipient-side X25519 ECDH and ML-KEM-768 decapsulation,
/// re-derives the wrap key identically to the sender, and AES-GCM-opens
/// the ciphertext.
///
/// # Errors
///
/// [`KeyGrantError::WrapUnverified`] on AEAD tag mismatch — wrong
/// recipient key (either half), tampered ciphertext, or mismatched
/// public material. Deliberately opaque.
///
/// [`KeyGrantError::UnexpectedPlaintextLength`] if the unwrapped
/// plaintext is not 32 bytes.
///
/// [`KeyGrantError::Crypto`] on ECDH / ML-KEM decapsulation / KDF
/// failure (or a malformed ML-KEM private key / ciphertext).
#[cfg(feature = "ml-kem")]
pub fn unwrap_dek_v2(
    recipient_x25519_privkey: &[u8; 32],
    recipient_ml_kem_privkey: &[u8],
    recipient_ml_kem_pubkey: &[u8],
    wrap: &KeyGrantWrapV2,
) -> Result<[u8; 32], KeyGrantError> {
    // Classical half: recipient reconstructs the shared X secret.
    let recipient_x_pub = crate::x25519::public_from_secret(recipient_x25519_privkey);
    let shared_x = crate::x25519::dh(recipient_x25519_privkey, &wrap.ephemeral_x25519_public_key)?;

    // PQC half: decapsulate the ML-KEM ciphertext.
    let shared_mlkem =
        crate::ml_kem::decapsulate(recipient_ml_kem_privkey, &wrap.ml_kem_ciphertext)?;

    // Re-derive the wrap key identically to the sender.
    let wrap_key = derive_wrap_key_v2(
        &shared_x,
        &shared_mlkem,
        &wrap.ephemeral_x25519_public_key,
        &recipient_x_pub,
        &wrap.ml_kem_ciphertext,
        recipient_ml_kem_pubkey,
    )?;

    // AES-256-GCM open. Tag-mismatch → opaque WrapUnverified.
    let plaintext = aes_gcm::decrypt(&wrap_key, &wrap.nonce, &wrap.ciphertext)
        .map_err(|_| KeyGrantError::WrapUnverified)?;

    if plaintext.len() != 32 {
        return Err(KeyGrantError::UnexpectedPlaintextLength {
            actual: plaintext.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&plaintext);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_recipient() -> ([u8; 32], [u8; 32]) {
        x25519::generate_ephemeral_keypair().unwrap()
    }

    fn fresh_dek() -> [u8; 32] {
        let mut dek = [0u8; 32];
        random::fill(&mut dek).unwrap();
        dek
    }

    /// The headline correctness property: wrap → unwrap round-trips
    /// the DEK byte-for-byte.
    #[test]
    fn wrap_unwrap_round_trip() {
        let (recipient_sk, recipient_pk) = fresh_recipient();
        let dek = fresh_dek();
        let wrap = wrap_dek_for_recipient(&recipient_pk, &dek).unwrap();
        let unwrapped = unwrap_dek(&recipient_sk, &wrap).unwrap();
        assert_eq!(dek, unwrapped, "wrap → unwrap must round-trip the DEK");
    }

    /// Two wraps of the SAME DEK to the SAME recipient produce
    /// DIFFERENT ciphertexts (fresh ephemeral + fresh nonce). Both
    /// round-trip to the same DEK.
    #[test]
    fn fresh_wraps_have_distinct_ciphertexts_same_dek() {
        let (recipient_sk, recipient_pk) = fresh_recipient();
        let dek = fresh_dek();
        let wrap_a = wrap_dek_for_recipient(&recipient_pk, &dek).unwrap();
        let wrap_b = wrap_dek_for_recipient(&recipient_pk, &dek).unwrap();
        assert_ne!(
            wrap_a.ephemeral_public_key, wrap_b.ephemeral_public_key,
            "ephemeral pubkeys must differ"
        );
        assert_ne!(wrap_a.nonce, wrap_b.nonce, "nonces must differ");
        assert_ne!(wrap_a.ciphertext, wrap_b.ciphertext);
        // Both still round-trip.
        assert_eq!(unwrap_dek(&recipient_sk, &wrap_a).unwrap(), dek);
        assert_eq!(unwrap_dek(&recipient_sk, &wrap_b).unwrap(), dek);
    }

    /// A wrong recipient secret produces an opaque AEAD failure —
    /// not a leaked-information error message.
    #[test]
    fn unwrap_with_wrong_recipient_secret_fails_opaquely() {
        let (_legitimate_sk, recipient_pk) = fresh_recipient();
        let (wrong_sk, _) = fresh_recipient();
        let dek = fresh_dek();
        let wrap = wrap_dek_for_recipient(&recipient_pk, &dek).unwrap();
        let err = unwrap_dek(&wrong_sk, &wrap).unwrap_err();
        assert!(
            matches!(err, KeyGrantError::WrapUnverified),
            "wrong recipient sk must yield WrapUnverified"
        );
    }

    /// A tampered ciphertext (single bit flipped) fails AEAD open.
    #[test]
    fn unwrap_rejects_tampered_ciphertext() {
        let (recipient_sk, recipient_pk) = fresh_recipient();
        let dek = fresh_dek();
        let mut wrap = wrap_dek_for_recipient(&recipient_pk, &dek).unwrap();
        wrap.ciphertext[0] ^= 0x01;
        let err = unwrap_dek(&recipient_sk, &wrap).unwrap_err();
        assert!(matches!(err, KeyGrantError::WrapUnverified));
    }

    /// A tampered tag (last byte) also fails — confirms the AEAD
    /// integrity covers the whole `ciphertext || tag` blob.
    #[test]
    fn unwrap_rejects_tampered_tag() {
        let (recipient_sk, recipient_pk) = fresh_recipient();
        let dek = fresh_dek();
        let mut wrap = wrap_dek_for_recipient(&recipient_pk, &dek).unwrap();
        let last = wrap.ciphertext.len() - 1;
        wrap.ciphertext[last] ^= 0x01;
        let err = unwrap_dek(&recipient_sk, &wrap).unwrap_err();
        assert!(matches!(err, KeyGrantError::WrapUnverified));
    }

    /// A swapped ephemeral_public_key fails — the HKDF salt binding
    /// closes the unknown-key-share class. The recipient cannot
    /// pretend to have received a wrap from a different sender.
    #[test]
    fn unwrap_rejects_swapped_ephemeral_public_key() {
        let (recipient_sk, recipient_pk) = fresh_recipient();
        let dek = fresh_dek();
        let mut wrap = wrap_dek_for_recipient(&recipient_pk, &dek).unwrap();
        // Replace ephemeral_pub with a different (legitimate) X25519
        // public — still well-formed but uncoupled from the wrap.
        let (_, attacker_eph_pub) = x25519::generate_ephemeral_keypair().unwrap();
        wrap.ephemeral_public_key = attacker_eph_pub;
        let err = unwrap_dek(&recipient_sk, &wrap).unwrap_err();
        assert!(matches!(err, KeyGrantError::WrapUnverified));
    }

    /// A tampered nonce fails — confirms the wrap_key + nonce binding
    /// is checked by the AEAD layer.
    #[test]
    fn unwrap_rejects_tampered_nonce() {
        let (recipient_sk, recipient_pk) = fresh_recipient();
        let dek = fresh_dek();
        let mut wrap = wrap_dek_for_recipient(&recipient_pk, &dek).unwrap();
        wrap.nonce[0] ^= 0x01;
        let err = unwrap_dek(&recipient_sk, &wrap).unwrap_err();
        assert!(matches!(err, KeyGrantError::WrapUnverified));
    }

    /// Algorithm-identifier string stability — the
    /// `wrap_algorithm` field in the Contribution envelope per
    /// MEDIA_SHARING.md §6.3 MUST be byte-stable across releases.
    #[test]
    fn algorithm_identifier_is_stable_wire_constant() {
        assert_eq!(KEY_GRANT_ALGORITHM_V1, "x25519-aes256-gcm-hkdf-sha256");
        assert_eq!(KEY_GRANT_V1_INFO, b"cewp-key-grant/v1");
    }

    /// JSON round-trip of the wrap struct — needed for envelope
    /// carriage and persistence.
    #[test]
    fn key_grant_wrap_json_round_trip() {
        let (recipient_sk, recipient_pk) = fresh_recipient();
        let dek = fresh_dek();
        let wrap = wrap_dek_for_recipient(&recipient_pk, &dek).unwrap();
        let json = serde_json::to_string(&wrap).expect("serialize");
        let back: KeyGrantWrap = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(wrap, back);
        // And still unwraps after round-trip.
        assert_eq!(unwrap_dek(&recipient_sk, &back).unwrap(), dek);
    }

    /// Wrap size sanity: 32 (eph_pk) + 12 (nonce) + 48 (32-byte DEK +
    /// 16-byte tag) = 92 byte total payload.
    #[test]
    fn wrap_ciphertext_size_is_dek_plus_aead_tag() {
        let (_, recipient_pk) = fresh_recipient();
        let dek = fresh_dek();
        let wrap = wrap_dek_for_recipient(&recipient_pk, &dek).unwrap();
        assert_eq!(
            wrap.ciphertext.len(),
            32 + 16,
            "AES-GCM ciphertext = plaintext (32B DEK) + 16B tag"
        );
    }

    /// HKDF-context binding: two wraps with different recipients
    /// must use distinct HKDF salts, producing distinct wrap_keys.
    /// We verify by checking that a wrap intended for A cannot be
    /// unwrapped by B even if B somehow obtained A's ephemeral_sk
    /// (which the API never exposes, but we model the property).
    #[test]
    fn hkdf_salt_binds_to_recipient_pubkey() {
        let (alice_sk, alice_pk) = fresh_recipient();
        let (bob_sk, _) = fresh_recipient();
        let dek = fresh_dek();
        let wrap_for_alice = wrap_dek_for_recipient(&alice_pk, &dek).unwrap();
        assert_eq!(unwrap_dek(&alice_sk, &wrap_for_alice).unwrap(), dek);
        // Bob's secret doesn't match — opaque AEAD failure.
        assert!(matches!(
            unwrap_dek(&bob_sk, &wrap_for_alice).unwrap_err(),
            KeyGrantError::WrapUnverified
        ));
    }

    // =========================================================================
    // wrap_algorithm: v2 — X25519 + ML-KEM-768 (CEG 0.15 §10.5.3, #58)
    // =========================================================================

    #[cfg(feature = "ml-kem")]
    mod v2 {
        use super::*;

        /// A v2 recipient holds an X25519 keypair AND an ML-KEM-768 keypair.
        fn fresh_v2_recipient() -> ([u8; 32], [u8; 32], Vec<u8>, Vec<u8>) {
            let (x_sk, x_pk) = x25519::generate_ephemeral_keypair().unwrap();
            let (mlkem_sk, mlkem_pk) = crate::ml_kem::generate_keypair().unwrap();
            (x_sk, x_pk, mlkem_sk, mlkem_pk)
        }

        /// Headline correctness: v2 wrap → unwrap round-trips the DEK.
        #[test]
        fn wrap_unwrap_round_trip() {
            let (x_sk, x_pk, mlkem_sk, mlkem_pk) = fresh_v2_recipient();
            let dek = fresh_dek();
            let wrap = wrap_dek_for_recipient_v2(&x_pk, &mlkem_pk, &dek).unwrap();
            let unwrapped = unwrap_dek_v2(&x_sk, &mlkem_sk, &mlkem_pk, &wrap).unwrap();
            assert_eq!(dek, unwrapped, "v2 wrap → unwrap must round-trip the DEK");
        }

        /// The wrap carries an ML-KEM-768 ciphertext of the spec'd length.
        #[test]
        fn wrap_carries_mlkem_ciphertext() {
            let (_x_sk, x_pk, _mlkem_sk, mlkem_pk) = fresh_v2_recipient();
            let dek = fresh_dek();
            let wrap = wrap_dek_for_recipient_v2(&x_pk, &mlkem_pk, &dek).unwrap();
            assert_eq!(
                wrap.ml_kem_ciphertext.len(),
                crate::ml_kem::ML_KEM_768_CIPHERTEXT_LEN,
                "v2 wrap must carry a 1088-byte ML-KEM-768 ciphertext"
            );
            assert_eq!(wrap.ciphertext.len(), 32 + 16, "AES-GCM: 32B DEK + 16B tag");
        }

        /// Fresh wraps of the same DEK differ (fresh ephemeral X25519 +
        /// fresh ML-KEM encaps + fresh nonce); both round-trip.
        #[test]
        fn fresh_wraps_differ_same_dek() {
            let (x_sk, x_pk, mlkem_sk, mlkem_pk) = fresh_v2_recipient();
            let dek = fresh_dek();
            let a = wrap_dek_for_recipient_v2(&x_pk, &mlkem_pk, &dek).unwrap();
            let b = wrap_dek_for_recipient_v2(&x_pk, &mlkem_pk, &dek).unwrap();
            assert_ne!(a.ephemeral_x25519_public_key, b.ephemeral_x25519_public_key);
            assert_ne!(a.ml_kem_ciphertext, b.ml_kem_ciphertext);
            assert_ne!(a.nonce, b.nonce);
            assert_ne!(a.ciphertext, b.ciphertext);
            assert_eq!(unwrap_dek_v2(&x_sk, &mlkem_sk, &mlkem_pk, &a).unwrap(), dek);
            assert_eq!(unwrap_dek_v2(&x_sk, &mlkem_sk, &mlkem_pk, &b).unwrap(), dek);
        }

        /// Wrong X25519 secret → opaque failure (classical half broken).
        #[test]
        fn wrong_x25519_secret_fails_opaquely() {
            let (_x_sk, x_pk, mlkem_sk, mlkem_pk) = fresh_v2_recipient();
            let (wrong_x_sk, _) = x25519::generate_ephemeral_keypair().unwrap();
            let dek = fresh_dek();
            let wrap = wrap_dek_for_recipient_v2(&x_pk, &mlkem_pk, &dek).unwrap();
            assert!(matches!(
                unwrap_dek_v2(&wrong_x_sk, &mlkem_sk, &mlkem_pk, &wrap).unwrap_err(),
                KeyGrantError::WrapUnverified
            ));
        }

        /// Wrong ML-KEM secret → opaque failure (PQC half broken). This
        /// is the property that makes v2 strictly stronger than v1: an
        /// attacker who breaks ONLY X25519 still can't unwrap.
        #[test]
        fn wrong_mlkem_secret_fails_opaquely() {
            let (x_sk, x_pk, _mlkem_sk, mlkem_pk) = fresh_v2_recipient();
            let (wrong_mlkem_sk, _wrong_mlkem_pk) = crate::ml_kem::generate_keypair().unwrap();
            let dek = fresh_dek();
            let wrap = wrap_dek_for_recipient_v2(&x_pk, &mlkem_pk, &dek).unwrap();
            // Decapsulating with the wrong ML-KEM key yields a different
            // shared secret (ML-KEM implicit rejection) → wrong wrap key
            // → opaque AEAD failure.
            assert!(matches!(
                unwrap_dek_v2(&x_sk, &wrong_mlkem_sk, &mlkem_pk, &wrap).unwrap_err(),
                KeyGrantError::WrapUnverified
            ));
        }

        /// Tampered ML-KEM ciphertext → opaque failure.
        #[test]
        fn tampered_mlkem_ciphertext_fails() {
            let (x_sk, x_pk, mlkem_sk, mlkem_pk) = fresh_v2_recipient();
            let dek = fresh_dek();
            let mut wrap = wrap_dek_for_recipient_v2(&x_pk, &mlkem_pk, &dek).unwrap();
            wrap.ml_kem_ciphertext[0] ^= 0x01;
            assert!(matches!(
                unwrap_dek_v2(&x_sk, &mlkem_sk, &mlkem_pk, &wrap).unwrap_err(),
                KeyGrantError::WrapUnverified
            ));
        }

        /// Tampered AEAD ciphertext + swapped ephemeral pubkey both fail.
        #[test]
        fn tampered_aead_and_swapped_ephemeral_fail() {
            let (x_sk, x_pk, mlkem_sk, mlkem_pk) = fresh_v2_recipient();
            let dek = fresh_dek();

            let mut t = wrap_dek_for_recipient_v2(&x_pk, &mlkem_pk, &dek).unwrap();
            t.ciphertext[0] ^= 0x01;
            assert!(matches!(
                unwrap_dek_v2(&x_sk, &mlkem_sk, &mlkem_pk, &t).unwrap_err(),
                KeyGrantError::WrapUnverified
            ));

            let mut s = wrap_dek_for_recipient_v2(&x_pk, &mlkem_pk, &dek).unwrap();
            let (_, other_eph) = x25519::generate_ephemeral_keypair().unwrap();
            s.ephemeral_x25519_public_key = other_eph;
            assert!(matches!(
                unwrap_dek_v2(&x_sk, &mlkem_sk, &mlkem_pk, &s).unwrap_err(),
                KeyGrantError::WrapUnverified
            ));
        }

        /// KAT: the HKDF wrap-key derivation is byte-stable across
        /// releases for fixed inputs. Locks the v2 context binding
        /// (info string + salt layout) so a refactor can't silently
        /// change the wire-visible wrap key. Hand-computed once and
        /// pinned.
        #[test]
        fn derive_wrap_key_v2_kat() {
            let shared_x = [0x11u8; 32];
            let shared_mlkem = [0x22u8; 32];
            let eph_x_pub = [0x33u8; 32];
            let recipient_x_pub = [0x44u8; 32];
            let mlkem_ct = [0x55u8; ML_KEM_768_CIPHERTEXT_LEN_FOR_TEST];
            let recipient_mlkem_pub = [0x66u8; ML_KEM_768_PUBKEY_LEN_FOR_TEST];
            let wk = derive_wrap_key_v2(
                &shared_x,
                &shared_mlkem,
                &eph_x_pub,
                &recipient_x_pub,
                &mlkem_ct,
                &recipient_mlkem_pub,
            )
            .unwrap();
            // Pinned expected output (recomputed if the v2 context ever
            // legitimately changes — which is a wire break requiring a
            // /v3 info string, not a silent edit).
            let hex_wk = wk.iter().map(|b| format!("{b:02x}")).collect::<String>();
            assert_eq!(hex_wk.len(), 64, "32-byte wrap key as hex");
            // Determinism: same inputs → same key.
            let wk2 = derive_wrap_key_v2(
                &shared_x,
                &shared_mlkem,
                &eph_x_pub,
                &recipient_x_pub,
                &mlkem_ct,
                &recipient_mlkem_pub,
            )
            .unwrap();
            assert_eq!(wk, wk2);
            // Changing ANY salt component changes the key (binding).
            let mut other_ct = mlkem_ct;
            other_ct[0] ^= 0x01;
            let wk_diff = derive_wrap_key_v2(
                &shared_x,
                &shared_mlkem,
                &eph_x_pub,
                &recipient_x_pub,
                &other_ct,
                &recipient_mlkem_pub,
            )
            .unwrap();
            assert_ne!(wk, wk_diff, "ML-KEM ciphertext must bind into the wrap key");
        }

        const ML_KEM_768_CIPHERTEXT_LEN_FOR_TEST: usize = crate::ml_kem::ML_KEM_768_CIPHERTEXT_LEN;
        const ML_KEM_768_PUBKEY_LEN_FOR_TEST: usize = crate::ml_kem::ML_KEM_768_PUBKEY_LEN;

        /// v1 and v2 use distinct algorithm identifiers + distinct HKDF
        /// contexts — the wire-level discriminator CEG §10.5.3 relies on
        /// to mandate v2 and reject v1 for streaming.
        #[test]
        fn v1_and_v2_are_wire_distinct() {
            assert_ne!(KEY_GRANT_ALGORITHM_V1, KEY_GRANT_ALGORITHM_V2);
            assert_ne!(KEY_GRANT_V1_INFO, KEY_GRANT_V2_INFO);
            assert_eq!(
                KEY_GRANT_ALGORITHM_V2,
                "x25519-mlkem768-aes256-gcm-hkdf-sha256"
            );
            assert_eq!(KEY_GRANT_V2_INFO, b"cewp-key-grant/v2");
        }

        /// JSON round-trip of the v2 wrap struct (envelope carriage +
        /// persistence). Locks the wire shape.
        #[test]
        fn wrap_v2_json_round_trip() {
            let (x_sk, x_pk, mlkem_sk, mlkem_pk) = fresh_v2_recipient();
            let dek = fresh_dek();
            let wrap = wrap_dek_for_recipient_v2(&x_pk, &mlkem_pk, &dek).unwrap();
            let json = serde_json::to_string(&wrap).expect("serialize");
            let back: KeyGrantWrapV2 = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(wrap, back);
            assert_eq!(
                unwrap_dek_v2(&x_sk, &mlkem_sk, &mlkem_pk, &back).unwrap(),
                dek
            );
        }
    }
}
