//! §19.0 canonicalization boundary — the binary signed-preimage framing and
//! the PQC-mandatory bound-hybrid gate every §19 object rides (CEG 1.0-RC11).
//!
//! §19 objects are **transport/substrate framing**, NOT §4 Contributions: they
//! never instantiate an `attestation_type`, never enter §0.9 JCS. Instead each
//! signs a **binary, length-prefixed, big-endian, domain-separated preimage**
//! (the same `signing_bytes` carve-out §10.1.5.3 drew for Verify). Applying JCS
//! to a §19 object is non-conformant — its signatures will not verify cross-impl.
//!
//! ## The two load-bearing invariants this module owns
//!
//! - **PQC-mandatory (§19.0 / §10.1.5.1.1, the F-2 gate).** Every §19 object
//!   carries the bound hybrid pair — Ed25519 over the preimage, then ML-DSA-65
//!   over `preimage ‖ ed25519_sig`. [`verify_bound_hybrid`] rejects any object
//!   lacking a valid ML-DSA-65 half: there is no `require_hybrid: false` posture
//!   and no "classical-only at ingest" path (a §19 object is federation-tier
//!   and a CRQC adversary who breaks Ed25519 alone must not forge one). This is
//!   the same discipline [`crate::threshold::HybridPolicy::RequireHybrid`]
//!   enforces for JCS envelopes, here for the binary preimage path.
//! - **Verify at the gate, never trust an in-band flag (the F-5 rule).** A
//!   verdict function MUST recompute the verification itself; a wire-carried
//!   `verified: bool` is forgeable and MUST be `#[serde(skip)]` / non-wire.
//!   This module exposes only *functions that verify*, never a trusted-flag path.
//!
//! ## Framing (§19.0)
//!
//! [`Preimage`] builds `domain ‖ fields`, with each **variable-length** field
//! length-prefixed `u32` big-endian and integers encoded big-endian — the
//! unambiguous, cross-impl-stable encoding. Fixed-width fields (e.g. a 32-byte
//! `stream_id`) are appended raw. The exact field *set/order* for each shape is
//! pinned by its §19 subsection; several shapes (`SignedClaim`,
//! `SignedRelayCapacity`, the fountain claims) gain fields under CIRISEdge#143
//! and are byte-frozen by the §19.6 / #57 conformance vectors — this module
//! owns the **framing rules and the PQC gate**, which are stable now.

use ciris_crypto::{ClassicalVerifier, Ed25519Verifier, MlDsa65Verifier, PqcVerifier};

// ---- pinned domain separators (§19.0) ---------------------------------

/// `SignedRelayCapacity` domain separator (§19.4 N8).
pub const DOMAIN_RELAY_CAPACITY: &[u8] = b"CIRISALM-CAPv2\0\0";
/// `FountainHoldingClaim` domain separator (§19.3).
pub const DOMAIN_HOLDING_CLAIM: &[u8] = b"ciris-edge/holding-claim/v1";
/// `FountainCompressRequest` domain separator (§19.3).
pub const DOMAIN_COMPRESS_REQUEST: &[u8] = b"ciris-edge/compress-request/v1";
/// Recursive-bootstrap `SignedClaim` domain separator (§19.2).
pub const DOMAIN_SIGNED_CLAIM: &[u8] = b"CIRIS-CLAIM-v1\0\0";
/// WholenessWitness signed-preimage domain separator (§19.1). Distinct from the
/// [`WW_EMPTY_SENTINEL`] (which seeds the empty Merkle root, not the preimage).
pub const DOMAIN_WITNESS_PREIMAGE: &[u8] = b"WW-PREIMAGE-v1\0\0";
/// WholenessWitness empty-tree Merkle sentinel (§19.1).
pub const WW_EMPTY_SENTINEL: &[u8] = b"WW-v1-empty";

/// Length of an Ed25519 public key / the raw signature is 64; pubkey 32.
const ED25519_PUBKEY_LEN: usize = 32;

/// Why a §19 holonomic verification failed. Coarse by design (enough for audit,
/// never granular enough to aid forgery — the opaque-failure discipline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HolonomicError {
    /// The Ed25519 (classical) half did not verify against the pinned pubkey.
    ClassicalSignatureInvalid,
    /// The object carries no ML-DSA-65 half, or it did not verify. §19 is
    /// PQC-mandatory at the gate — classical-only is non-conformant.
    PqcHalfMissingOrInvalid,
    /// A public-key or signature field had the wrong length / failed to decode.
    MalformedKeyOrSignature,
    /// A structural invariant failed (caller supplies the specific reason).
    Invariant {
        /// Short machine-readable reason tag, e.g. `"leaf_order"`,
        /// `"cycle"`, `"depth_cap"`, `"anonymous_leaf"`.
        reason: &'static str,
    },
}

impl std::fmt::Display for HolonomicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClassicalSignatureInvalid => write!(f, "§19 classical signature invalid"),
            Self::PqcHalfMissingOrInvalid => {
                write!(f, "§19 ML-DSA-65 half missing or invalid (PQC-mandatory)")
            },
            Self::MalformedKeyOrSignature => write!(f, "§19 malformed key or signature"),
            Self::Invariant { reason } => write!(f, "§19 invariant failed: {reason}"),
        }
    }
}

impl std::error::Error for HolonomicError {}

/// Builder for a §19.0 binary signed preimage: `domain ‖ fields`, variable
/// fields `u32`-BE length-prefixed, integers big-endian, fixed fields raw.
///
/// Construct with [`Preimage::new`] (the domain separator), append fields, then
/// [`Preimage::finish`]. Producer and verifier MUST build byte-identical
/// preimages — this builder is the single shared construction.
#[derive(Debug, Clone)]
pub struct Preimage {
    buf: Vec<u8>,
}

impl Preimage {
    /// Start a preimage with its pinned domain separator (one of the
    /// `DOMAIN_*` constants).
    #[must_use]
    pub fn new(domain: &[u8]) -> Self {
        Self {
            buf: domain.to_vec(),
        }
    }

    /// Append a fixed-width field verbatim (no length prefix) — e.g. a 32-byte
    /// `stream_id` or a key hash whose width is structurally fixed.
    #[must_use]
    pub fn fixed(mut self, bytes: &[u8]) -> Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Append a variable-length field, **`u32`** big-endian length-prefixed
    /// (the WholenessWitness / SignedClaim string fields, per the v4.1.2
    /// vectors).
    #[must_use]
    pub fn lp(mut self, bytes: &[u8]) -> Self {
        self.buf
            .extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Append a variable-length field, **`u64`** big-endian length-prefixed (the
    /// fountain holding-claim / compress-request fields, per the v4.1.2 vectors).
    #[must_use]
    pub fn lp_u64(mut self, bytes: &[u8]) -> Self {
        self.buf
            .extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Append a `u64` big-endian (counters, epochs, unix-ms timestamps).
    #[must_use]
    pub fn u64_be(mut self, n: u64) -> Self {
        self.buf.extend_from_slice(&n.to_be_bytes());
        self
    }

    /// Append a `u32` big-endian.
    #[must_use]
    pub fn u32_be(mut self, n: u32) -> Self {
        self.buf.extend_from_slice(&n.to_be_bytes());
        self
    }

    /// Append a `u16` big-endian (schema version fields).
    #[must_use]
    pub fn u16_be(mut self, n: u16) -> Self {
        self.buf.extend_from_slice(&n.to_be_bytes());
        self
    }

    /// Append a single byte (presence flags: `0x01` Some / `0x00` None).
    #[must_use]
    pub fn u8(mut self, b: u8) -> Self {
        self.buf.push(b);
        self
    }

    /// Append an optional UTF-8 field with a presence flag: `0x01 ‖ u32-lp(s)`
    /// when `Some`, a single `0x00` when `None` (the SignedClaim owner-binding
    /// trio encoding, per the v4.1.2 vectors).
    #[must_use]
    pub fn opt_lp(self, value: Option<&str>) -> Self {
        match value {
            Some(s) => self.u8(0x01).lp(s.as_bytes()),
            None => self.u8(0x00),
        }
    }

    /// The finished preimage bytes — the input to [`verify_bound_hybrid`].
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// The bound hybrid signature pair over a §19 preimage. The ML-DSA-65 half is
/// `Option` only to model the wire (a malformed/absent half is possible to
/// *receive*) — [`verify_bound_hybrid`] treats `None` as a hard reject, never
/// as "classical-only acceptable" (the §19.0 PQC-mandatory rule).
#[derive(Debug, Clone)]
pub struct BoundHybridSig<'a> {
    /// Ed25519 signature over `preimage`.
    pub ed25519: &'a [u8],
    /// ML-DSA-65 signature over `preimage ‖ ed25519_sig`. `None` on the wire =
    /// rejected at the gate.
    pub mldsa65: Option<&'a [u8]>,
}

/// Verify a §19 object's bound hybrid signature over `preimage`, **PQC-mandatory**
/// (§19.0 / §10.1.5.1.1, the F-2 gate).
///
/// Both halves MUST verify against the caller-pinned public keys:
/// 1. Ed25519 over `preimage`;
/// 2. ML-DSA-65 over `preimage ‖ ed25519_sig` (the bound-signature rule — the
///    PQC half commits to the exact classical signature, so a broken-Ed25519
///    adversary cannot graft a forged classical half onto a valid PQC half).
///
/// A missing ML-DSA-65 half (`sig.mldsa65 == None`) is
/// [`HolonomicError::PqcHalfMissingOrInvalid`] — there is no classical-only path
/// at the §19 gate. The caller MUST treat `Ok(())` as the *only* admit signal
/// and MUST NOT consult any wire-carried `verified` flag (F-5).
///
/// # Errors
///
/// [`HolonomicError::ClassicalSignatureInvalid`] /
/// [`HolonomicError::PqcHalfMissingOrInvalid`] /
/// [`HolonomicError::MalformedKeyOrSignature`].
pub fn verify_bound_hybrid(
    preimage: &[u8],
    sig: &BoundHybridSig<'_>,
    ed25519_pubkey: &[u8],
    mldsa65_pubkey: &[u8],
) -> Result<(), HolonomicError> {
    if ed25519_pubkey.len() != ED25519_PUBKEY_LEN {
        return Err(HolonomicError::MalformedKeyOrSignature);
    }

    // 1. Classical half over the preimage.
    let ed = Ed25519Verifier::new();
    if !matches!(ed.verify(ed25519_pubkey, preimage, sig.ed25519), Ok(true)) {
        return Err(HolonomicError::ClassicalSignatureInvalid);
    }

    // 2. PQC half over `preimage ‖ ed25519_sig` — MANDATORY. `None` → reject.
    let Some(pqc_sig) = sig.mldsa65 else {
        return Err(HolonomicError::PqcHalfMissingOrInvalid);
    };
    if mldsa65_pubkey.is_empty() {
        return Err(HolonomicError::PqcHalfMissingOrInvalid);
    }
    let mut bound = preimage.to_vec();
    bound.extend_from_slice(sig.ed25519);
    let mldsa = MlDsa65Verifier::new();
    if !matches!(mldsa.verify(mldsa65_pubkey, &bound, pqc_sig), Ok(true)) {
        return Err(HolonomicError::PqcHalfMissingOrInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};

    struct Id {
        ed: Ed25519Signer,
        mldsa: MlDsa65Signer,
    }
    impl Id {
        fn new() -> Self {
            Self {
                ed: Ed25519Signer::random().unwrap(),
                mldsa: MlDsa65Signer::new().unwrap(),
            }
        }
        fn ed_pub(&self) -> Vec<u8> {
            self.ed.public_key().unwrap()
        }
        fn mldsa_pub(&self) -> Vec<u8> {
            self.mldsa.public_key().unwrap()
        }
        /// Sign a preimage with the bound-hybrid discipline.
        fn sign(&self, preimage: &[u8]) -> (Vec<u8>, Vec<u8>) {
            let ed_sig = self.ed.sign(preimage).unwrap();
            let mut bound = preimage.to_vec();
            bound.extend_from_slice(&ed_sig);
            let pqc_sig = self.mldsa.sign(&bound).unwrap();
            (ed_sig, pqc_sig)
        }
    }

    #[test]
    fn preimage_framing_is_deterministic_and_domain_separated() {
        let a = Preimage::new(DOMAIN_HOLDING_CLAIM)
            .fixed(&[0xAB; 32])
            .u64_be(7)
            .lp(b"hello")
            .finish();
        let b = Preimage::new(DOMAIN_HOLDING_CLAIM)
            .fixed(&[0xAB; 32])
            .u64_be(7)
            .lp(b"hello")
            .finish();
        assert_eq!(a, b, "same inputs → same bytes");
        // Different domain → different bytes (no cross-domain collision).
        let c = Preimage::new(DOMAIN_COMPRESS_REQUEST)
            .fixed(&[0xAB; 32])
            .u64_be(7)
            .lp(b"hello")
            .finish();
        assert_ne!(a, c);
        // Length-prefix disambiguates concatenation: lp("a")+lp("bc") != lp("ab")+lp("c").
        let x = Preimage::new(b"d").lp(b"a").lp(b"bc").finish();
        let y = Preimage::new(b"d").lp(b"ab").lp(b"c").finish();
        assert_ne!(x, y);
    }

    #[test]
    fn bound_hybrid_round_trips() {
        let id = Id::new();
        let preimage = Preimage::new(DOMAIN_SIGNED_CLAIM).lp(b"claim").finish();
        let (ed_sig, pqc_sig) = id.sign(&preimage);
        let sig = BoundHybridSig {
            ed25519: &ed_sig,
            mldsa65: Some(&pqc_sig),
        };
        assert!(verify_bound_hybrid(&preimage, &sig, &id.ed_pub(), &id.mldsa_pub()).is_ok());
    }

    #[test]
    fn missing_pqc_half_is_rejected_pqc_mandatory() {
        let id = Id::new();
        let preimage = Preimage::new(DOMAIN_SIGNED_CLAIM).lp(b"claim").finish();
        let (ed_sig, _pqc) = id.sign(&preimage);
        // Classical half is perfectly valid; PQC half absent → reject (F-2).
        let sig = BoundHybridSig {
            ed25519: &ed_sig,
            mldsa65: None,
        };
        assert_eq!(
            verify_bound_hybrid(&preimage, &sig, &id.ed_pub(), &id.mldsa_pub()),
            Err(HolonomicError::PqcHalfMissingOrInvalid)
        );
    }

    #[test]
    fn stripped_pqc_with_grafted_classical_is_rejected() {
        // Downgrade attack: attacker forges the classical half (simulated here
        // as a valid sign under a DIFFERENT key) and drops PQC. Must reject.
        let id = Id::new();
        let attacker = Id::new();
        let preimage = Preimage::new(DOMAIN_SIGNED_CLAIM).lp(b"claim").finish();
        let (att_ed, _) = attacker.sign(&preimage);
        let sig = BoundHybridSig {
            ed25519: &att_ed,
            mldsa65: None,
        };
        // Against the real id's keys, the attacker's classical sig fails first;
        // even if it passed, the missing PQC half is fatal.
        assert!(verify_bound_hybrid(&preimage, &sig, &id.ed_pub(), &id.mldsa_pub()).is_err());
    }

    #[test]
    fn tampered_preimage_fails() {
        let id = Id::new();
        let preimage = Preimage::new(DOMAIN_SIGNED_CLAIM).lp(b"claim").finish();
        let (ed_sig, pqc_sig) = id.sign(&preimage);
        let tampered = Preimage::new(DOMAIN_SIGNED_CLAIM).lp(b"CLAIM").finish();
        let sig = BoundHybridSig {
            ed25519: &ed_sig,
            mldsa65: Some(&pqc_sig),
        };
        assert_eq!(
            verify_bound_hybrid(&tampered, &sig, &id.ed_pub(), &id.mldsa_pub()),
            Err(HolonomicError::ClassicalSignatureInvalid)
        );
    }

    #[test]
    fn wrong_pqc_key_rejected() {
        let id = Id::new();
        let other = Id::new();
        let preimage = Preimage::new(DOMAIN_SIGNED_CLAIM).lp(b"claim").finish();
        let (ed_sig, pqc_sig) = id.sign(&preimage);
        let sig = BoundHybridSig {
            ed25519: &ed_sig,
            mldsa65: Some(&pqc_sig),
        };
        // Right Ed25519 key, wrong ML-DSA key → PQC half fails.
        assert_eq!(
            verify_bound_hybrid(&preimage, &sig, &id.ed_pub(), &other.mldsa_pub()),
            Err(HolonomicError::PqcHalfMissingOrInvalid)
        );
    }
}
