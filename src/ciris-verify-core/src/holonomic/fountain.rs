//! §19.3 Fountain storage + swarm rarity (CEG 1.0-RC11).
//!
//! Content is RaptorQ-coded into source + repair symbols; peers retain symbols
//! and coordinate rarest-first so content survives churn. This module owns the
//! verifier-side invariants — the ones an adversary would exploit to force-evict
//! or to keep revoked content alive:
//!
//! - **N5 (retention respects revocation — fail-secure).** A withdrawn/revoked
//!   `content_id` is evict-eligible **regardless of rarity**; an active
//!   `withdraws` / `consent:state:revoked` overrides the max-rarity "keep"
//!   signal; unknown consent state defaults to *not retained as rare*
//!   ([`retention_decision`]). "Reconstitute from any fragment" must never
//!   resurrect deleted content.
//! - **N6 (possession-bound claims).** An unverified `FountainHoldingClaim` MUST
//!   NOT lower another peer's retention priority — else rarity is a forgeable
//!   force-evict channel. [`holding_claim_counts_toward_rarity`] gates this.
//! - **N7 (symbol integrity).** Reconstruction MUST verify each symbol against
//!   the manifest's signed per-symbol SHA-256 ([`verify_symbol`]) so a
//!   swarm-sourced symbol cannot poison a decode.
//! - **SR-2/3.** Anonymous-tier content is exempt from swarm-mandatory retention
//!   (LRU-only) — no holding claim, no rarest-first biasing (a caller concern).
//!
//! The `FountainHoldingClaim` / `FountainCompressRequest` **signed preimages**
//! are PIN-NORMATIVE (`symbol_ids` sorted ascending before signing); the exact
//! field set is byte-frozen by the §19.6 vectors (CIRISEdge#143). The holding
//! claim is a **specialization of `holds_bytes:sha256:*`** ([§10.1.2]) and MUST
//! NOT create a second who-holds-what directory; it inherits the §10.1.4
//! `cohort_scope: self | family` suppression.

use sha2::{Digest, Sha256};

use super::preimage::{BoundHybridSig, HolonomicError, Preimage, DOMAIN_HOLDING_CLAIM};

/// Consent state of a content id, as resolved by the caller from the
/// `withdraws` / `consent:state:*` records (§3.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentState {
    /// Consent is active — content may be retained (rarity applies normally).
    Active,
    /// `withdraws` or `consent:state:revoked` — evict-eligible regardless of rarity.
    Withdrawn,
    /// Consent state is unknown — default *not retained as rare* (fail-secure).
    Unknown,
}

/// The retention verdict for a content id under N5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionDecision {
    /// May be retained, and rarity-bias may keep it alive.
    RetainRare,
    /// May be retained but MUST NOT be kept solely by rarity (LRU-eligible).
    RetainNonRare,
    /// Evict-eligible regardless of rarity (revoked/withdrawn).
    EvictEligible,
}

/// N5: decide retention for a content id from its consent state and rarity. A
/// withdrawn/revoked id is **always** evict-eligible (rarity cannot override the
/// deletion-SLA / decay); unknown consent never earns rare-retention.
#[must_use]
pub fn retention_decision(consent: ConsentState, is_rare: bool) -> RetentionDecision {
    match consent {
        ConsentState::Withdrawn => RetentionDecision::EvictEligible,
        ConsentState::Unknown => RetentionDecision::RetainNonRare,
        ConsentState::Active => {
            if is_rare {
                RetentionDecision::RetainRare
            } else {
                RetentionDecision::RetainNonRare
            }
        },
    }
}

/// N6: may this holding claim count toward another peer's rarity calculation?
/// Only if its possession is proven (it answered a symbol challenge, or carries
/// a proof-of-possession). Unverified claims MUST NOT lower retention priority.
#[must_use]
pub fn holding_claim_counts_toward_rarity(possession_proven: bool) -> bool {
    possession_proven
}

/// N7: verify a swarm-sourced symbol against the manifest's signed per-symbol
/// SHA-256 (constant-time-ish exact compare). A non-matching symbol MUST NOT
/// enter a decode.
#[must_use]
pub fn verify_symbol(symbol_bytes: &[u8], manifest_symbol_sha256: &[u8; 32]) -> bool {
    let got: [u8; 32] = Sha256::digest(symbol_bytes).into();
    ciris_crypto::constant_time_eq(&got, manifest_symbol_sha256)
}

/// A `FountainHoldingClaim` as parsed off the wire (the fields the §19.3 signed
/// preimage covers). `symbol_ids` are sorted ascending before signing/verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FountainHoldingClaim {
    /// The holder peer's id.
    pub peer_id: String,
    /// `sha256` content id this claim is about (the `holds_bytes:sha256:*` key).
    pub content_id: [u8; 32],
    /// Symbol ids the holder claims to have. MUST be sorted ascending.
    pub symbol_ids: Vec<u32>,
}

impl FountainHoldingClaim {
    /// Build the §19.3 signed preimage (`b"ciris-edge/holding-claim/v1"` ‖
    /// peer_id ‖ content_id ‖ sorted symbol_ids). `symbol_ids` are sorted
    /// ascending here so producer and verifier agree on the bytes (§19.3 PIN).
    #[must_use]
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut ids = self.symbol_ids.clone();
        ids.sort_unstable();
        let mut pre = Preimage::new(DOMAIN_HOLDING_CLAIM)
            .lp(self.peer_id.as_bytes())
            .fixed(&self.content_id)
            .u32_be(ids.len() as u32);
        for id in ids {
            pre = pre.u32_be(id);
        }
        pre.finish()
    }
}

/// Verify a `FountainHoldingClaim`'s bound-hybrid signature (PQC-mandatory,
/// §19.0). Returns the verified claim's content id / symbol set for the holder
/// directory on success. **N5/N6 are separate gates** — a verified *signature*
/// does not by itself license retention or rarity-counting.
///
/// # Errors
///
/// [`HolonomicError`] from the signature gate.
pub fn verify_holding_claim(
    claim: &FountainHoldingClaim,
    sig: &BoundHybridSig<'_>,
    ed25519_pubkey: &[u8],
    mldsa65_pubkey: &[u8],
) -> Result<(), HolonomicError> {
    let preimage = claim.signing_preimage();
    super::preimage::verify_bound_hybrid(&preimage, sig, ed25519_pubkey, mldsa65_pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};

    #[test]
    fn n5_withdrawn_is_evict_eligible_even_if_rare() {
        assert_eq!(
            retention_decision(ConsentState::Withdrawn, true),
            RetentionDecision::EvictEligible
        );
        assert_eq!(
            retention_decision(ConsentState::Unknown, true),
            RetentionDecision::RetainNonRare
        );
        assert_eq!(
            retention_decision(ConsentState::Active, true),
            RetentionDecision::RetainRare
        );
    }

    #[test]
    fn n6_unverified_claim_does_not_count() {
        assert!(!holding_claim_counts_toward_rarity(false));
        assert!(holding_claim_counts_toward_rarity(true));
    }

    #[test]
    fn n7_symbol_integrity() {
        let sym = b"raptorq-symbol-bytes";
        let digest: [u8; 32] = Sha256::digest(sym).into();
        assert!(verify_symbol(sym, &digest));
        let mut bad = digest;
        bad[0] ^= 1;
        assert!(!verify_symbol(sym, &bad));
    }

    #[test]
    fn holding_claim_preimage_is_symbol_order_independent() {
        let c1 = FountainHoldingClaim {
            peer_id: "p".into(),
            content_id: [9u8; 32],
            symbol_ids: vec![3, 1, 2],
        };
        let c2 = FountainHoldingClaim {
            peer_id: "p".into(),
            content_id: [9u8; 32],
            symbol_ids: vec![1, 2, 3],
        };
        assert_eq!(c1.signing_preimage(), c2.signing_preimage());
    }

    #[test]
    fn holding_claim_round_trips_and_is_pqc_mandatory() {
        let ed = Ed25519Signer::random().unwrap();
        let mldsa = MlDsa65Signer::new().unwrap();
        let claim = FountainHoldingClaim {
            peer_id: "holder-1".into(),
            content_id: [0x55u8; 32],
            symbol_ids: vec![5, 1, 9, 2],
        };
        let pre = claim.signing_preimage();
        let ed_sig = ed.sign(&pre).unwrap();
        let mut bound = pre.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa.sign(&bound).unwrap();

        let good = BoundHybridSig {
            ed25519: &ed_sig,
            mldsa65: Some(&pqc_sig),
        };
        assert!(verify_holding_claim(
            &claim,
            &good,
            &ed.public_key().unwrap(),
            &mldsa.public_key().unwrap()
        )
        .is_ok());

        // PQC-mandatory: classical-only is rejected.
        let classical_only = BoundHybridSig {
            ed25519: &ed_sig,
            mldsa65: None,
        };
        assert_eq!(
            verify_holding_claim(
                &claim,
                &classical_only,
                &ed.public_key().unwrap(),
                &mldsa.public_key().unwrap()
            ),
            Err(HolonomicError::PqcHalfMissingOrInvalid)
        );
    }
}
