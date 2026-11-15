//! §19.0 canonicalization boundary — the binary signed-preimage framing and
//! the PQC-mandatory composite-signature gate every §19 object rides (CEG 1.0-RC11).
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
//!   carries one composite ML-DSA-65-Ed25519 signature (CC 2.6.1.7) over its
//!   preimage. [`verify_composite`] accepts only a signature whose two halves
//!   both verify; neither half verifies alone, so there is no
//!   `require_hybrid: false` posture and no "classical-only at ingest" path (a
//!   §19 object is federation-tier and a CRQC adversary who breaks Ed25519
//!   alone must not forge one).
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
//! `SignedRelayCapacity`, the holding claim and compress request) gain fields under CIRISEdge#143
//! and are byte-frozen by the §19.6 / #57 conformance vectors — this module
//! owns the **framing rules and the PQC gate**, which are stable now.

#[allow(unused_imports)]
use crate::prelude::*;

use ciris_crypto::composite::{CompositePublicKey, SIGNATURE_LEN};

// ---- pinned domain separators (§19.0) ---------------------------------

/// `SignedRelayCapacity` domain separator (§19.4 N8).
pub const DOMAIN_RELAY_CAPACITY: &[u8] = b"CIRISALM-CAPv2\0\0";
/// `HoldingClaim` domain separator (§19.3).
pub const DOMAIN_HOLDING_CLAIM: &[u8] = b"ciris-edge/holding-claim/v1";
/// `CompressRequest` domain separator (§19.3).
pub const DOMAIN_COMPRESS_REQUEST: &[u8] = b"ciris-edge/compress-request/v1";
/// Recursive-bootstrap `SignedClaim` domain separator (§19.2).
pub const DOMAIN_SIGNED_CLAIM: &[u8] = b"CIRIS-CLAIM-v1\0\0";
/// WholenessWitness signed-preimage domain separator (§19.1). Distinct from the
/// [`WW_EMPTY_SENTINEL`] (which seeds the empty Merkle root, not the preimage).
pub const DOMAIN_WITNESS_PREIMAGE: &[u8] = b"WW-PREIMAGE-v1\0\0";
/// WholenessWitness empty-tree Merkle sentinel (§19.1).
pub const WW_EMPTY_SENTINEL: &[u8] = b"WW-v1-empty";
/// §19.7.1 `AggregationMetaV1` domain separator — exactly 16 bytes
/// (`"AGG-META-v1"` + five `\0`).
pub const DOMAIN_AGG_META: &[u8] = b"AGG-META-v1\0\0\0\0\0";
/// CC 6.1.5.2 §Q `StorageBudgetV1` domain separator (CIRISVerify#170) — exactly
/// 16 bytes (`"CIRIS-STG-BUDGET"`, no padding). Byte-identical to the value
/// CIRISEdge v8.5.0 first signed under, so existing shapes verify unchanged.
pub const DOMAIN_STORAGE_BUDGET: &[u8] = b"CIRIS-STG-BUDGET";
/// CC 6.1.5.2 §Q `CorpusWantV1` domain separator (CIRISVerify#170) — exactly 16
/// bytes (`"CIRIS-WANT-HAVE"` + one trailing `\0`).
pub const DOMAIN_CORPUS_WANT: &[u8] = b"CIRIS-WANT-HAVE\0";

/// Why a substrate verification failed. Coarse by design (enough for audit,
/// never granular enough to aid forgery — the opaque-failure discipline).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HolonomicError {
    /// The composite signature did not verify against the pinned composite
    /// public key. Deliberately silent on which half failed (CC 2.6.1.7).
    SignatureInvalid,
    /// A public-key or signature field had the wrong length / failed to decode.
    MalformedKeyOrSignature,
    /// A structural invariant failed (caller supplies the specific reason).
    Invariant {
        /// Short machine-readable reason tag, e.g. `"leaf_order"`,
        /// `"cycle"`, `"depth_cap"`, `"anonymous_leaf"`.
        reason: &'static str,
    },
}

impl core::fmt::Display for HolonomicError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SignatureInvalid => write!(f, "§19 composite signature invalid"),
            Self::MalformedKeyOrSignature => write!(f, "§19 malformed key or signature"),
            Self::Invariant { reason } => write!(f, "§19 invariant failed: {reason}"),
        }
    }
}

impl core::error::Error for HolonomicError {}

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
    /// holding-claim / compress-request fields, per the v4.1.2 vectors).
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

    /// The finished preimage bytes — the input to [`verify_composite`].
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Verify a §19 object's composite ML-DSA-65-Ed25519 signature over
/// `preimage`, **PQC-mandatory** (§19.0 / §10.1.5.1.1, the F-2 gate).
///
/// `sig` is the 3373-byte composite signature `mldsaSig ‖ ed25519Sig` and
/// `composite_pubkey` the caller-pinned 1984-byte composite public key
/// `mldsaPK ‖ ed25519PK` (CC 2.6.1.7). Both halves sign the message
/// representative `M' = Prefix ‖ Label ‖ 0x00 ‖ SHA-512(preimage)`, with the
/// label as the ML-DSA-65 context, so neither half verifies alone and a
/// broken-Ed25519 adversary cannot forge one. The failure does not say which
/// half failed. The caller MUST treat `Ok(())` as the *only* admit signal and
/// MUST NOT consult any wire-carried `verified` flag (F-5).
///
/// # Errors
///
/// [`HolonomicError::MalformedKeyOrSignature`] for a wrong-length or
/// undecodable key or a wrong-length signature;
/// [`HolonomicError::SignatureInvalid`] for a signature that does not verify.
pub fn verify_composite(
    preimage: &[u8],
    sig: &[u8],
    composite_pubkey: &[u8],
) -> Result<(), HolonomicError> {
    if sig.len() != SIGNATURE_LEN {
        return Err(HolonomicError::MalformedKeyOrSignature);
    }
    let pk = CompositePublicKey::from_bytes(composite_pubkey)
        .map_err(|_| HolonomicError::MalformedKeyOrSignature)?;
    pk.verify(preimage, sig)
        .map_err(|_| HolonomicError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::composite::{CompositeSigningKey, MLDSA65_PK_LEN, MLDSA65_SIG_LEN};

    fn key(n: u8) -> CompositeSigningKey {
        CompositeSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(1); 32])
    }

    fn claim() -> Vec<u8> {
        Preimage::new(DOMAIN_SIGNED_CLAIM).lp(b"claim").finish()
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
    fn composite_round_trips() {
        let k = key(1);
        let preimage = claim();
        let sig = k.sign(&preimage).unwrap();
        assert!(verify_composite(&preimage, &sig, k.public_key().as_bytes()).is_ok());
    }

    #[test]
    fn wrong_length_signature_is_malformed() {
        let k = key(1);
        let preimage = claim();
        let sig = k.sign(&preimage).unwrap();
        let pk = k.public_key().as_bytes();
        // A bare Ed25519-length signature (the old "classical only" shape).
        assert_eq!(
            verify_composite(&preimage, &sig[MLDSA65_SIG_LEN..], pk),
            Err(HolonomicError::MalformedKeyOrSignature)
        );
        // The ML-DSA half alone (the old "PQC half only" shape).
        assert_eq!(
            verify_composite(&preimage, &sig[..MLDSA65_SIG_LEN], pk),
            Err(HolonomicError::MalformedKeyOrSignature)
        );
        assert_eq!(
            verify_composite(&preimage, &[], pk),
            Err(HolonomicError::MalformedKeyOrSignature)
        );
    }

    #[test]
    fn wrong_length_key_is_malformed() {
        let k = key(1);
        let preimage = claim();
        let sig = k.sign(&preimage).unwrap();
        let pk = k.public_key().as_bytes();
        assert_eq!(
            verify_composite(&preimage, &sig, &pk[..pk.len() - 1]),
            Err(HolonomicError::MalformedKeyOrSignature)
        );
        // A bare Ed25519 key (the old separate classical key).
        assert_eq!(
            verify_composite(&preimage, &sig, &pk[MLDSA65_PK_LEN..]),
            Err(HolonomicError::MalformedKeyOrSignature)
        );
    }

    #[test]
    fn flipped_byte_in_either_half_is_signature_invalid() {
        let k = key(1);
        let preimage = claim();
        let sig = k.sign(&preimage).unwrap();
        let pk = k.public_key().as_bytes();
        for i in [0, MLDSA65_SIG_LEN - 1, MLDSA65_SIG_LEN, sig.len() - 1] {
            let mut bad = sig.clone();
            bad[i] ^= 1;
            assert_eq!(
                verify_composite(&preimage, &bad, pk),
                Err(HolonomicError::SignatureInvalid),
                "byte {i}"
            );
        }
    }

    #[test]
    fn signature_under_other_key_is_signature_invalid() {
        let k = key(1);
        let other = key(7);
        let preimage = claim();
        let sig = other.sign(&preimage).unwrap();
        assert_eq!(
            verify_composite(&preimage, &sig, k.public_key().as_bytes()),
            Err(HolonomicError::SignatureInvalid)
        );
    }

    #[test]
    fn tampered_preimage_fails() {
        let k = key(1);
        let preimage = claim();
        let sig = k.sign(&preimage).unwrap();
        let tampered = Preimage::new(DOMAIN_SIGNED_CLAIM).lp(b"CLAIM").finish();
        assert_eq!(
            verify_composite(&tampered, &sig, k.public_key().as_bytes()),
            Err(HolonomicError::SignatureInvalid)
        );
    }
}
