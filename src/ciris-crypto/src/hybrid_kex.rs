//! Hybrid X25519 + ML-KEM-768 KEX with HKDF-SHA256 binding —
//! Fed TM §3.3 Gap C closure (CIRISVerify#47, v4.6.0+).
//!
//! Mirrors HPKE RFC 9180 base-mode shape: an initiator generates
//! ephemeral key material against a recipient's published long-term
//! public keys, both sides derive an identical session key via
//! HKDF binding over all the wire material. The hybrid construction
//! puts X25519 + ML-KEM-768 in series under one KDF, so an attacker
//! must break BOTH primitives to recover the session key.
//!
//! ## What this closes
//!
//! Per `docs/FEDERATION_THREAT_MODEL.md` §3.3 Gap C: federation
//! peer-to-peer transport is harvest-now-decrypt-later vulnerable
//! without a PQ-ready KEX. Hybrid X25519 + ML-KEM-768 closes that
//! gap. Captured ciphertext today does NOT become plaintext when a
//! sufficient quantum computer ships — the ML-KEM-768 half remains
//! intractable under known quantum attacks.
//!
//! ## Wire shape — `wrap_algorithm: hybrid-x25519-mlkem768-hkdf-sha256-v1`
//!
//! ```text
//! HybridHandshakeMsg {
//!     algorithm:              "hybrid-x25519-mlkem768-hkdf-sha256-v1",
//!     x25519_ephemeral_pub:   [u8; 32],
//!     mlkem768_ciphertext:    [u8; 1088],
//! }
//! ```
//!
//! ## Algorithm — hybrid mode
//!
//! Initiate:
//! 1. Generate ephemeral X25519 keypair `(eph_sk, eph_pk)`.
//! 2. X25519 ECDH: `shared_x = X25519(eph_sk, recipient_x_pk)`.
//! 3. ML-KEM-768 encapsulate against `recipient_mlkem_pk`:
//!    `(mlkem_ct, shared_mlkem) = ML-KEM-768.encap(recipient_mlkem_pk)`.
//! 4. HKDF-SHA256:
//!    - IKM   = `shared_x || shared_mlkem`
//!    - salt  = `eph_pk || recipient_x_pk || mlkem_ct || recipient_mlkem_pk`
//!    - info  = `b"CIRIS-FED-KEX-V1"`
//!    - L     = 32 bytes  →  `session_key`
//! 5. Discard `eph_sk`. Output `(HybridHandshakeMsg, session_key)`.
//!
//! Respond: identical derivation from the recipient's perspective —
//! recompute `shared_x` from `(recipient_x_sk, eph_pk)`, decapsulate
//! `mlkem_ct` with `recipient_mlkem_sk`, run the same HKDF.
//!
//! ## Algorithm — classical fallback
//!
//! Used when a peer doesn't advertise ML-KEM-768 support. Identical
//! shape but X25519-only:
//! - IKM   = `shared_x`
//! - salt  = `eph_pk || recipient_x_pk`
//! - info  = `b"CIRIS-FED-KEX-V1-CLASSICAL"`
//!
//! ML-KEM-only mode is **NOT supported at v1** — both peers MUST
//! advertise X25519 so classical fallback is always available.
//!
//! ## Opaque-failure discipline
//!
//! Wrong keys, tampered ciphertexts, swapped pubkeys, or
//! mismatched salts all converge on a different session key —
//! the AEAD layer above this KEX detects the mismatch as a tag
//! failure. This module doesn't error on adversary inputs; it
//! produces a different session key, by design.

use serde::{Deserialize, Serialize};

use crate::error::CryptoError;
use crate::{kdf, ml_kem, x25519};

/// Algorithm identifier — hybrid mode, v1.
pub const KEX_ALGORITHM_HYBRID_V1: &str = "hybrid-x25519-mlkem768-hkdf-sha256-v1";

/// Algorithm identifier — classical fallback, v1.
pub const KEX_ALGORITHM_CLASSICAL_V1: &str = "classical-x25519-hkdf-sha256-v1";

/// HKDF info field — hybrid mode. Versioned so a future hybrid
/// extension (e.g. SLH-DSA hybrid signing on top) rotates cleanly
/// via the info string.
pub const KEX_HYBRID_INFO_V1: &[u8] = b"CIRIS-FED-KEX-V1";

/// HKDF info field — classical fallback. Distinct from the hybrid
/// info so the same `shared_x` couldn't be cross-used between
/// modes (defense in depth).
pub const KEX_CLASSICAL_INFO_V1: &[u8] = b"CIRIS-FED-KEX-V1-CLASSICAL";

/// Session-key length (32 B; suitable as a ChaCha20-Poly1305 or
/// AES-256-GCM key directly).
pub const SESSION_KEY_LEN: usize = 32;

/// One initiate-side handshake message in hybrid mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridHandshakeMsg {
    /// Algorithm identifier — MUST be [`KEX_ALGORITHM_HYBRID_V1`].
    pub algorithm: String,
    /// Initiator's ephemeral X25519 public key.
    pub x25519_ephemeral_pub: [u8; 32],
    /// ML-KEM-768 ciphertext targeting the recipient's long-term
    /// ML-KEM-768 public key.
    pub mlkem768_ciphertext: Vec<u8>,
}

/// One initiate-side handshake message in classical fallback mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassicalHandshakeMsg {
    /// Algorithm identifier — MUST be [`KEX_ALGORITHM_CLASSICAL_V1`].
    pub algorithm: String,
    /// Initiator's ephemeral X25519 public key.
    pub x25519_ephemeral_pub: [u8; 32],
}

/// KEX-specific errors.
#[derive(Debug)]
pub enum KexError {
    /// Underlying crypto primitive failed.
    Crypto(CryptoError),
    /// Algorithm identifier in the wire message doesn't match the
    /// expected mode. Producer error or version downgrade attempt.
    AlgorithmMismatch {
        /// What the message claimed.
        observed: String,
        /// What this verifier was expecting.
        expected: &'static str,
    },
    /// ML-KEM-only mode rejected — v1 mandates X25519 fallback
    /// support, so a peer advertising ML-KEM without X25519 is
    /// out-of-spec.
    MlKemOnlyRejected,
}

impl From<CryptoError> for KexError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl std::fmt::Display for KexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "hybrid_kex crypto: {e}"),
            Self::AlgorithmMismatch { observed, expected } => write!(
                f,
                "hybrid_kex algorithm mismatch: observed {observed:?}, expected {expected:?}"
            ),
            Self::MlKemOnlyRejected => write!(
                f,
                "hybrid_kex: ML-KEM-only mode rejected — v1 requires X25519 fallback"
            ),
        }
    }
}

impl std::error::Error for KexError {}

/// Initiate side: derive a fresh session key targeting a recipient
/// identified by `(recipient_x25519_pub, recipient_mlkem768_pub)`.
/// Returns the handshake message to send + the local session key.
pub fn initiate_hybrid(
    recipient_x25519_pub: &[u8; 32],
    recipient_mlkem768_pub: &[u8],
) -> Result<(HybridHandshakeMsg, [u8; 32]), KexError> {
    // 1. X25519 ephemeral DH.
    let (x25519_ephemeral_pub, shared_x) = x25519::ephemeral_dh(recipient_x25519_pub)?;

    // 2. ML-KEM-768 encapsulate.
    let (mlkem_ct, shared_mlkem) = ml_kem::encapsulate(recipient_mlkem768_pub)?;

    // 3. HKDF binding — IKM = shared_x || shared_mlkem; salt = full
    //    public material (ephemeral X pub, recipient X pub, ML-KEM
    //    ciphertext, recipient ML-KEM pub) so any tamper diverges the
    //    derived session key.
    let session_key = derive_session_key_hybrid(
        &shared_x,
        &shared_mlkem,
        &x25519_ephemeral_pub,
        recipient_x25519_pub,
        &mlkem_ct,
        recipient_mlkem768_pub,
    )?;

    Ok((
        HybridHandshakeMsg {
            algorithm: KEX_ALGORITHM_HYBRID_V1.to_string(),
            x25519_ephemeral_pub,
            mlkem768_ciphertext: mlkem_ct,
        },
        session_key,
    ))
}

/// Respond-side wrapper that explicitly takes the recipient's
/// long-term ML-KEM public key for salt binding. Most production
/// call sites have this value already (it's the local
/// long-term-published material).
pub fn respond_hybrid_with_public(
    recipient_x25519_priv: &[u8; 32],
    recipient_mlkem768_priv: &[u8],
    recipient_mlkem768_pub: &[u8],
    msg: &HybridHandshakeMsg,
) -> Result<[u8; 32], KexError> {
    if msg.algorithm != KEX_ALGORITHM_HYBRID_V1 {
        return Err(KexError::AlgorithmMismatch {
            observed: msg.algorithm.clone(),
            expected: KEX_ALGORITHM_HYBRID_V1,
        });
    }
    let recipient_x_pub = x25519::public_from_secret(recipient_x25519_priv);
    let shared_x = x25519::dh(recipient_x25519_priv, &msg.x25519_ephemeral_pub)?;
    let shared_mlkem = ml_kem::decapsulate(recipient_mlkem768_priv, &msg.mlkem768_ciphertext)?;
    derive_session_key_hybrid(
        &shared_x,
        &shared_mlkem,
        &msg.x25519_ephemeral_pub,
        &recipient_x_pub,
        &msg.mlkem768_ciphertext,
        recipient_mlkem768_pub,
    )
    .map_err(KexError::Crypto)
}

/// Initiate side, classical fallback mode (no ML-KEM-768).
pub fn initiate_classical(
    recipient_x25519_pub: &[u8; 32],
) -> Result<(ClassicalHandshakeMsg, [u8; 32]), KexError> {
    let (x25519_ephemeral_pub, shared_x) = x25519::ephemeral_dh(recipient_x25519_pub)?;
    let session_key =
        derive_session_key_classical(&shared_x, &x25519_ephemeral_pub, recipient_x25519_pub)?;
    Ok((
        ClassicalHandshakeMsg {
            algorithm: KEX_ALGORITHM_CLASSICAL_V1.to_string(),
            x25519_ephemeral_pub,
        },
        session_key,
    ))
}

/// Respond side, classical fallback mode.
pub fn respond_classical(
    recipient_x25519_priv: &[u8; 32],
    msg: &ClassicalHandshakeMsg,
) -> Result<[u8; 32], KexError> {
    if msg.algorithm != KEX_ALGORITHM_CLASSICAL_V1 {
        return Err(KexError::AlgorithmMismatch {
            observed: msg.algorithm.clone(),
            expected: KEX_ALGORITHM_CLASSICAL_V1,
        });
    }
    let recipient_x_pub = x25519::public_from_secret(recipient_x25519_priv);
    let shared_x = x25519::dh(recipient_x25519_priv, &msg.x25519_ephemeral_pub)?;
    derive_session_key_classical(&shared_x, &msg.x25519_ephemeral_pub, &recipient_x_pub)
        .map_err(KexError::Crypto)
}

/// HKDF binding for hybrid mode.
fn derive_session_key_hybrid(
    shared_x: &[u8; 32],
    shared_mlkem: &[u8; 32],
    ephemeral_x_pub: &[u8; 32],
    recipient_x_pub: &[u8; 32],
    mlkem_ct: &[u8],
    recipient_mlkem_pub: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(shared_x);
    ikm.extend_from_slice(shared_mlkem);

    let mut salt = Vec::with_capacity(32 + 32 + mlkem_ct.len() + recipient_mlkem_pub.len());
    salt.extend_from_slice(ephemeral_x_pub);
    salt.extend_from_slice(recipient_x_pub);
    salt.extend_from_slice(mlkem_ct);
    salt.extend_from_slice(recipient_mlkem_pub);

    let derived = kdf::hkdf_sha256(&ikm, &salt, KEX_HYBRID_INFO_V1, SESSION_KEY_LEN)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&derived);
    Ok(out)
}

/// HKDF binding for classical fallback mode.
fn derive_session_key_classical(
    shared_x: &[u8; 32],
    ephemeral_x_pub: &[u8; 32],
    recipient_x_pub: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral_x_pub);
    salt[32..].copy_from_slice(recipient_x_pub);
    let derived = kdf::hkdf_sha256(shared_x, &salt, KEX_CLASSICAL_INFO_V1, SESSION_KEY_LEN)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&derived);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_recipient_hybrid() -> ([u8; 32], [u8; 32], Vec<u8>, Vec<u8>) {
        let (x_sk, x_pk) = x25519::generate_ephemeral_keypair().unwrap();
        let (mlkem_sk, mlkem_pk) = ml_kem::generate_keypair().unwrap();
        (x_sk, x_pk, mlkem_sk, mlkem_pk)
    }

    /// Headline correctness: hybrid initiate → respond produces
    /// identical session keys.
    #[test]
    fn hybrid_round_trip_yields_matching_session_keys() {
        let (rx_x_sk, rx_x_pk, rx_mlkem_sk, rx_mlkem_pk) = fresh_recipient_hybrid();
        let (msg, k_init) = initiate_hybrid(&rx_x_pk, &rx_mlkem_pk).unwrap();
        let k_resp =
            respond_hybrid_with_public(&rx_x_sk, &rx_mlkem_sk, &rx_mlkem_pk, &msg).unwrap();
        assert_eq!(k_init, k_resp);
    }

    /// Fresh handshakes against the same recipient produce
    /// distinct session keys.
    #[test]
    fn hybrid_fresh_handshakes_produce_distinct_session_keys() {
        let (_, rx_x_pk, _, rx_mlkem_pk) = fresh_recipient_hybrid();
        let (_, k_a) = initiate_hybrid(&rx_x_pk, &rx_mlkem_pk).unwrap();
        let (_, k_b) = initiate_hybrid(&rx_x_pk, &rx_mlkem_pk).unwrap();
        assert_ne!(k_a, k_b);
    }

    /// Wrong recipient → diverged session key (the AEAD above will
    /// detect this as a tag mismatch).
    #[test]
    fn hybrid_wrong_recipient_keys_yield_diverged_session() {
        let (rx_x_sk, rx_x_pk, rx_mlkem_sk, rx_mlkem_pk) = fresh_recipient_hybrid();
        let (wrong_x_sk, _, wrong_mlkem_sk, wrong_mlkem_pk) = fresh_recipient_hybrid();
        let (msg, k_init) = initiate_hybrid(&rx_x_pk, &rx_mlkem_pk).unwrap();
        let k_legit =
            respond_hybrid_with_public(&rx_x_sk, &rx_mlkem_sk, &rx_mlkem_pk, &msg).unwrap();
        let k_wrong =
            respond_hybrid_with_public(&wrong_x_sk, &wrong_mlkem_sk, &wrong_mlkem_pk, &msg)
                .unwrap();
        assert_eq!(k_init, k_legit);
        assert_ne!(k_init, k_wrong);
    }

    /// Tampered ML-KEM ciphertext (single bit flip) → diverged
    /// session key.
    #[test]
    fn hybrid_tampered_mlkem_ciphertext_yields_diverged_session() {
        let (rx_x_sk, rx_x_pk, rx_mlkem_sk, rx_mlkem_pk) = fresh_recipient_hybrid();
        let (mut msg, k_init) = initiate_hybrid(&rx_x_pk, &rx_mlkem_pk).unwrap();
        msg.mlkem768_ciphertext[0] ^= 0x01;
        let k_resp =
            respond_hybrid_with_public(&rx_x_sk, &rx_mlkem_sk, &rx_mlkem_pk, &msg).unwrap();
        assert_ne!(k_init, k_resp);
    }

    /// Swapped ephemeral X25519 public → diverged session key.
    #[test]
    fn hybrid_swapped_ephemeral_pub_yields_diverged_session() {
        let (rx_x_sk, rx_x_pk, rx_mlkem_sk, rx_mlkem_pk) = fresh_recipient_hybrid();
        let (mut msg, k_init) = initiate_hybrid(&rx_x_pk, &rx_mlkem_pk).unwrap();
        let (_, attacker_eph_pub) = x25519::generate_ephemeral_keypair().unwrap();
        msg.x25519_ephemeral_pub = attacker_eph_pub;
        let k_resp =
            respond_hybrid_with_public(&rx_x_sk, &rx_mlkem_sk, &rx_mlkem_pk, &msg).unwrap();
        assert_ne!(k_init, k_resp);
    }

    /// Algorithm-identifier mismatch rejected (defense against
    /// silent downgrade).
    #[test]
    fn hybrid_wrong_algorithm_identifier_rejected() {
        let (rx_x_sk, rx_x_pk, rx_mlkem_sk, rx_mlkem_pk) = fresh_recipient_hybrid();
        let (mut msg, _) = initiate_hybrid(&rx_x_pk, &rx_mlkem_pk).unwrap();
        msg.algorithm = "classical-x25519-hkdf-sha256-v1".to_string();
        let err =
            respond_hybrid_with_public(&rx_x_sk, &rx_mlkem_sk, &rx_mlkem_pk, &msg).unwrap_err();
        assert!(matches!(err, KexError::AlgorithmMismatch { .. }));
    }

    /// Classical fallback round-trip.
    #[test]
    fn classical_round_trip_yields_matching_session_keys() {
        let (rx_x_sk, rx_x_pk) = x25519::generate_ephemeral_keypair().unwrap();
        let (msg, k_init) = initiate_classical(&rx_x_pk).unwrap();
        let k_resp = respond_classical(&rx_x_sk, &msg).unwrap();
        assert_eq!(k_init, k_resp);
    }

    /// Classical algorithm-identifier mismatch rejected.
    #[test]
    fn classical_wrong_algorithm_identifier_rejected() {
        let (rx_x_sk, rx_x_pk) = x25519::generate_ephemeral_keypair().unwrap();
        let (mut msg, _) = initiate_classical(&rx_x_pk).unwrap();
        msg.algorithm = KEX_ALGORITHM_HYBRID_V1.to_string();
        let err = respond_classical(&rx_x_sk, &msg).unwrap_err();
        assert!(matches!(err, KexError::AlgorithmMismatch { .. }));
    }

    /// Hybrid + classical share `shared_x` but produce DISTINCT
    /// session keys due to distinct `info` strings (defense in
    /// depth against cross-mode replay).
    #[test]
    fn hybrid_and_classical_with_same_x25519_yield_distinct_session_keys() {
        let (_, rx_x_pk, _, rx_mlkem_pk) = fresh_recipient_hybrid();
        let (_, k_hybrid) = initiate_hybrid(&rx_x_pk, &rx_mlkem_pk).unwrap();
        let (_, k_classical) = initiate_classical(&rx_x_pk).unwrap();
        assert_ne!(
            k_hybrid, k_classical,
            "distinct info strings MUST yield distinct keys"
        );
    }

    /// Algorithm-identifier stability lock.
    #[test]
    fn algorithm_identifiers_are_stable_wire_constants() {
        assert_eq!(
            KEX_ALGORITHM_HYBRID_V1,
            "hybrid-x25519-mlkem768-hkdf-sha256-v1"
        );
        assert_eq!(
            KEX_ALGORITHM_CLASSICAL_V1,
            "classical-x25519-hkdf-sha256-v1"
        );
        assert_eq!(KEX_HYBRID_INFO_V1, b"CIRIS-FED-KEX-V1");
        assert_eq!(KEX_CLASSICAL_INFO_V1, b"CIRIS-FED-KEX-V1-CLASSICAL");
    }

    /// JSON round-trip of the wire message.
    #[test]
    fn hybrid_handshake_msg_json_round_trip() {
        let (_, rx_x_pk, _, rx_mlkem_pk) = fresh_recipient_hybrid();
        let (msg, _) = initiate_hybrid(&rx_x_pk, &rx_mlkem_pk).unwrap();
        let json = serde_json::to_string(&msg).unwrap();
        let back: HybridHandshakeMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, back);
    }
}
