//! §19.7 forever-memory aggregation pyramid — `AggregationMetaV1` verifiers
//! (CEG 1.0-RC14, CIRISVerify#79).
//!
//! §19.7 reframes revocation / retirement / capacity-eviction / aging as **one
//! pressure-driven operator**: a monotonic descent of an item's fidelity toward
//! and below the **noise floor** (the individual-recoverability boundary).
//! Descent never terminates at zero — the *collective gist* (a picture of a
//! thousand pictures) persists below the floor forever, so the federation
//! remembers all of history in **O(log T)** via N→1 aggregation. This module is
//! the verifier side of the aggregation-tier metadata that tags that pyramid.
//!
//! Three pinned surfaces (§19.7.1–.3):
//! - **[`AggregationMetaV1`]** — the per-tier wire shape. CEG-canonical (no edge
//!   reference impl predates it: Persist v8.3.0 stores `aggregation_meta`
//!   *opaque*, the wire-churn firewall). Its preimage rides the §19.0 binary
//!   framing (u32-lp, big-endian, the 16-byte `b"AGG-META-v1\0\0\0\0\0"` domain)
//!   and a PQC-mandatory bound-hybrid signature ([`verify_aggregation_meta`]).
//! - **[`member_commitment`] / [`verify_member_commitment`]** (§19.7.1.1) — the
//!   Merkle root over the tier's source member ids, computed by the **§19.1
//!   WholenessWitness construction reused verbatim** ([`super::compute_merkle_root`]),
//!   so the federation carries one aggregation/witness Merkle scheme, not a third.
//! - **[`EjectionVerdict`] / [`ejection_verdict`]** (§19.7.3) — the tier-aware
//!   retirement surface persist consumes, the canonical superset of v5.9.0's
//!   [`super::fountain::RetentionDecision`]. The §19.3 N5 mapping is load-bearing:
//!   a revoked item → [`EjectionVerdict::EjectHardDelete`] (the fastest descent,
//!   **never** tier-shed); capacity pressure → [`EjectionVerdict::EjectToTier`].
//!
//! **Vector authorship.** Per §19.7's conformance note, no reference impl
//! defined these bytes, so the *first* conformant implementation generates the
//! §19.6/#57 vectors and a second reproduces them. **CIRISVerify is that first
//! impl** — `tests/conformance_vectors_v19_7.rs` emits the canonical vectors
//! from this module; Edge/Persist reproduce them byte-for-byte to lift §19.7
//! from RC-grade to 1.0.

use super::fountain::ConsentState;
use super::preimage::{
    verify_bound_hybrid, BoundHybridSig, HolonomicError, Preimage, DOMAIN_AGG_META,
};

/// One tier of the §19.7 memory pyramid — which content, at what aggregation
/// tier, over which source members, by which mechanical operator. A substrate
/// wire shape (NOT a §4 attestation); byte layout pinned by §19.7.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregationMetaV1 {
    /// Schema version (`1`).
    pub version: u32,
    /// The root content this pyramid is for.
    pub content_id: String,
    /// `"trace" | "blob" | "av_chunk" | …`.
    pub corpus_kind: String,
    /// `0` = source granularity; higher = more aggregated.
    pub tier: u32,
    /// Opaque codec id, e.g. `"raptorq-pyramid-v1"`.
    pub aggregation_algorithm_id: String,
    /// N members aggregated into this tier (the descent fan-in).
    pub source_count: u32,
    /// §19.7.1.1 Merkle root over the source member ids (raw 32 bytes).
    pub member_commitment: [u8; 32],
    /// What survives below the floor (codec-specific, canonical).
    pub noise_floor_descriptor: String,
}

impl AggregationMetaV1 {
    /// Build the §19.7.1 canonical signing preimage (normative byte order):
    /// `AGG-META-v1\0\0\0\0\0 ‖ u32(version) ‖ lp(content_id) ‖ lp(corpus_kind)
    /// ‖ u32(tier) ‖ lp(aggregation_algorithm_id) ‖ u32(source_count) ‖
    /// member_commitment[32] ‖ lp(noise_floor_descriptor)`, where
    /// `lp(x) = u32_be(len) ‖ utf8(x)` (the §19.0 u32 length-prefix).
    #[must_use]
    pub fn signing_preimage(&self) -> Vec<u8> {
        Preimage::new(DOMAIN_AGG_META)
            .u32_be(self.version)
            .lp(self.content_id.as_bytes())
            .lp(self.corpus_kind.as_bytes())
            .u32_be(self.tier)
            .lp(self.aggregation_algorithm_id.as_bytes())
            .u32_be(self.source_count)
            .fixed(&self.member_commitment)
            .lp(self.noise_floor_descriptor.as_bytes())
            .finish()
    }
}

/// §19.7.1.1: the `member_commitment` Merkle root over a tier's source member
/// ids — the §19.1 WholenessWitness construction reused verbatim
/// (`leaf = SHA-256(utf8(member_id))`, lexicographic order, odd-node
/// duplication, `WW-v1-empty` empty sentinel). Lets any verifier confirm a tier
/// was aggregated from exactly the claimed sources without holding the sources.
#[must_use]
pub fn member_commitment(source_member_ids: &[String]) -> [u8; 32] {
    let leaves: Vec<Vec<u8>> = source_member_ids
        .iter()
        .map(|id| id.as_bytes().to_vec())
        .collect();
    super::compute_merkle_root(&leaves)
}

/// §19.7.1.1 descent-integrity check: does `source_member_ids` re-derive the
/// tier's committed `member_commitment` byte-for-byte? Order-independent (the
/// Merkle sorts lexicographically), so the caller need not pre-sort.
#[must_use]
pub fn verify_member_commitment(meta: &AggregationMetaV1, source_member_ids: &[String]) -> bool {
    member_commitment(source_member_ids) == meta.member_commitment
}

/// §19.7.2 descent order: the **lexicographic member-id order** that
/// `member_commitment` commits to. A list returned in this order re-derives the
/// parent tier's `member_commitment` (the descent-integrity contract). Pure and
/// deterministic — `descend` (which *fetches* the tier-(n−1) members) is the
/// substrate's; this is the order it must return them in.
#[must_use]
pub fn descend_order(member_ids: &[String]) -> Vec<String> {
    let mut v = member_ids.to_vec();
    v.sort_unstable();
    v
}

/// Outcome of [`verify_aggregation_meta`]. PQC-mandatory (§19.0 / §10.1.5.1.1) —
/// there is no classical-only acceptance for a federation-tier aggregation tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregationMetaVerification {
    /// Both halves verified — admissible at ingest.
    HybridVerified,
    /// Verification failed (bad/absent classical or ML-DSA-65 half).
    Failed,
}

/// Verify an `AggregationMetaV1` tier's bound-hybrid signature over its §19.7.1
/// canonical preimage (PQC-mandatory). The §10.1.5.1.1 store-path rule applies:
/// a substrate MUST reject a tier whose ML-DSA-65 half is missing/invalid **at
/// ingest and before persistence** — pass only [`AggregationMetaVerification::HybridVerified`].
#[must_use]
pub fn verify_aggregation_meta(
    meta: &AggregationMetaV1,
    sig_ed25519: &[u8],
    sig_ml_dsa_65: &[u8],
    ed25519_pubkey: &[u8],
    ml_dsa_65_pubkey: &[u8],
) -> AggregationMetaVerification {
    let preimage = meta.signing_preimage();
    let sig = BoundHybridSig {
        ed25519: sig_ed25519,
        mldsa65: Some(sig_ml_dsa_65),
    };
    match verify_bound_hybrid(&preimage, &sig, ed25519_pubkey, ml_dsa_65_pubkey) {
        Ok(()) => AggregationMetaVerification::HybridVerified,
        Err(HolonomicError::ClassicalSignatureInvalid)
        | Err(HolonomicError::PqcHalfMissingOrInvalid)
        | Err(HolonomicError::MalformedKeyOrSignature)
        | Err(HolonomicError::Invariant { .. }) => AggregationMetaVerification::Failed,
    }
}

/// §19.7.3: the single tier-aware retirement verdict a verifier exposes and a
/// substrate consumes to gate one step of the §19.7 descent. The canonical
/// superset of v5.9.0's rarity-only [`super::fountain::RetentionDecision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EjectionVerdict {
    /// Above the floor, no pressure step — retain at current fidelity.
    Keep,
    /// One downward step: still recoverable, lower fidelity (an intra-object
    /// layer-drop OR an N→1 aggregation). Persist drives `put_aggregated_tier`.
    EjectToTier,
    /// Forced descent below the floor + purge still-recoverable tiers (§19.3
    /// N5). The fastest descent; **never** tier-shed. Persist drives
    /// `evict_fountain_content_hard_delete`.
    EjectHardDelete,
}

/// §19.7.3 mapping (normative): resolve the descent step for an item from its
/// consent state and whether it is under capacity pressure.
///
/// - a `withdraws` / `consent:state:revoked` item (§19.3 N5) →
///   [`EjectionVerdict::EjectHardDelete`] — the fastest descent, MUST purge,
///   **never** tier-shed (privacy: a revoked item MUST be below the floor at
///   every retained tier);
/// - otherwise, capacity pressure → [`EjectionVerdict::EjectToTier`] (one
///   downward step — still recoverable, lower fidelity);
/// - otherwise → [`EjectionVerdict::Keep`].
///
/// Rarity (the v5.9.0 `RetentionDecision`) is the sub-decision *upstream* of
/// this — it informs whether `under_capacity_pressure` is set for a given item
/// (rare content resists pressure); it never overrides the N5 hard-delete.
#[must_use]
pub fn ejection_verdict(consent: ConsentState, under_capacity_pressure: bool) -> EjectionVerdict {
    match consent {
        // N5: revocation forces immediate descent below the floor, regardless of
        // rarity or pressure. Never a tier-shed.
        ConsentState::Withdrawn => EjectionVerdict::EjectHardDelete,
        ConsentState::Active | ConsentState::Unknown => {
            if under_capacity_pressure {
                EjectionVerdict::EjectToTier
            } else {
                EjectionVerdict::Keep
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};

    fn meta() -> AggregationMetaV1 {
        let members: Vec<String> = ["m3", "m1", "m2"].iter().map(|s| s.to_string()).collect();
        AggregationMetaV1 {
            version: 1,
            content_id: "content-root-1".into(),
            corpus_kind: "trace".into(),
            tier: 2,
            aggregation_algorithm_id: "raptorq-pyramid-v1".into(),
            source_count: members.len() as u32,
            member_commitment: member_commitment(&members),
            noise_floor_descriptor: "mean+stddev".into(),
        }
    }

    #[test]
    fn domain_separator_is_16_bytes() {
        assert_eq!(DOMAIN_AGG_META.len(), 16);
        assert_eq!(DOMAIN_AGG_META, b"AGG-META-v1\0\0\0\0\0");
    }

    #[test]
    fn member_commitment_reuses_ww_merkle_and_is_order_independent() {
        let a = member_commitment(&["m1".into(), "m2".into(), "m3".into()]);
        let b = member_commitment(&["m3".into(), "m1".into(), "m2".into()]);
        assert_eq!(a, b, "lexicographic — order independent");
        // Reuses the §19.1 construction: equals compute_merkle_root over utf8 leaves.
        let leaves: Vec<Vec<u8>> = ["m1", "m2", "m3"]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
        assert_eq!(a, super::super::compute_merkle_root(&leaves));
    }

    #[test]
    fn verify_member_commitment_round_trips() {
        let m = meta();
        assert!(verify_member_commitment(
            &m,
            &["m1".into(), "m2".into(), "m3".into()]
        ));
        // A wrong source set fails the descent-integrity check.
        assert!(!verify_member_commitment(&m, &["m1".into(), "m2".into()]));
        assert!(!verify_member_commitment(
            &m,
            &["m1".into(), "m2".into(), "EVIL".into()]
        ));
    }

    #[test]
    fn descend_order_is_lexicographic_and_re_derives_commitment() {
        let unordered = vec!["m3".into(), "m1".into(), "m2".into()];
        assert_eq!(descend_order(&unordered), vec!["m1", "m2", "m3"]);
        // A descend-ordered list re-derives the committed root.
        let m = meta();
        assert_eq!(
            member_commitment(&descend_order(&unordered)),
            m.member_commitment
        );
    }

    #[test]
    fn aggregation_meta_round_trips_pqc_mandatory() {
        let ed = Ed25519Signer::random().unwrap();
        let mldsa = MlDsa65Signer::new().unwrap();
        let m = meta();
        let pre = m.signing_preimage();
        let ed_sig = ed.sign(&pre).unwrap();
        let mut bound = pre.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa.sign(&bound).unwrap();

        assert_eq!(
            verify_aggregation_meta(
                &m,
                &ed_sig,
                &pqc_sig,
                &ed.public_key().unwrap(),
                &mldsa.public_key().unwrap()
            ),
            AggregationMetaVerification::HybridVerified
        );
        // Tampered tier → fail.
        let mut m2 = m.clone();
        m2.tier = 3;
        assert_eq!(
            verify_aggregation_meta(
                &m2,
                &ed_sig,
                &pqc_sig,
                &ed.public_key().unwrap(),
                &mldsa.public_key().unwrap()
            ),
            AggregationMetaVerification::Failed
        );
    }

    #[test]
    fn ejection_verdict_n5_revoked_is_hard_delete() {
        // N5: revoked → hard delete regardless of pressure (never tier-shed).
        assert_eq!(
            ejection_verdict(ConsentState::Withdrawn, false),
            EjectionVerdict::EjectHardDelete
        );
        assert_eq!(
            ejection_verdict(ConsentState::Withdrawn, true),
            EjectionVerdict::EjectHardDelete
        );
        // Pressure on a live item → one downward step.
        assert_eq!(
            ejection_verdict(ConsentState::Active, true),
            EjectionVerdict::EjectToTier
        );
        // No pressure, live → keep.
        assert_eq!(
            ejection_verdict(ConsentState::Active, false),
            EjectionVerdict::Keep
        );
    }
}
