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
//! **Vector authorship — §19.7 is now 1.0 (CEG 1.0-RC16).** No reference impl
//! defined these bytes, so the *first* conformant implementation generated the
//! §19.6/#57 vectors and a second reproduced them. **CIRISVerify authored them**
//! (`tests/conformance_vectors_v19_7.rs`); **CIRISEdge v4.3.0 reproduced them
//! byte-for-byte on the first attempt with no coordination beyond the spec** —
//! so the §19.7 vector family is **closed and §19.7 is 1.0, not RC** (the §19.0
//! binary discipline makes wire-identity reproducible from the text alone). The
//! `member_commitment` Merkle is the §19.1 WholenessWitness scheme verbatim —
//! one Merkle scheme across §19.1 + §19.7, no fork.

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
    /// §19.7.1.2 (CIRISVerify#167 / CC 6.1.2 noise floor): the **effective**
    /// source count — the weight-adjusted N (inverse-Simpson / participation
    /// ratio, [`effective_source_count`]) a dominance gate checks against the raw
    /// [`Self::source_count`]. A balanced fold of N equal sources has `n_eff == N`;
    /// a fold dominated by a few high-mass sources (the 900/1000 case) collapses
    /// toward `n_eff → 1`, letting [`passes_dominance_gate`] reject it.
    ///
    /// **Signed only when `version >= 2`** — a v1 tier predates the surface and
    /// carries `n_eff == source_count` as a neutral, un-signed placeholder (it
    /// fails `passes_dominance_gate`, which requires a signed n_eff).
    pub n_eff: u32,
    /// §19.7.1.3 (CIRISVerify#191 / CC 6.1.2.1.2 R9): the **content-similarity
    /// multiplicity** — the size of the largest cluster of members whose pairwise
    /// content similarity exceeds the `corpus_kind`-pinned threshold, computed by
    /// the aggregator at fold time (edge, the only point with member payloads in
    /// hand). Closes the R9 residual the mass-based [`Self::n_eff`] cannot see:
    /// 900 near-duplicate contents folded as 900 *distinct members at equal mass*
    /// honestly yield `n_eff == 1000` yet the composite blur IS the data subject
    /// — [`passes_multiplicity_gate`] rejects that.
    ///
    /// **Signed only when `version >= 3`.** A v1/v2 tier lacks this surface and
    /// **fails closed** at the multiplicity gate (flag-day cut, no window).
    pub max_source_multiplicity: u32,
    /// §19.7.1.3 (CIRISVerify#191): Merkle root over the per-member masses (the
    /// §19.1 WholenessWitness construction, [`mass_commitment`]) — makes both
    /// `n_eff` and the clustering **auditable**: an auditor holding the members +
    /// their masses recomputes this root and can *prove* a lying `n_eff` /
    /// multiplicity from held evidence, converting "slashable in principle" into
    /// "mechanically provable". **Signed only when `version >= 3`.**
    pub mass_commitment: [u8; 32],
}

impl AggregationMetaV1 {
    /// Build the §19.7.1 canonical signing preimage (normative byte order):
    /// `AGG-META-v1\0\0\0\0\0 ‖ u32(version) ‖ lp(content_id) ‖ lp(corpus_kind)
    /// ‖ u32(tier) ‖ lp(aggregation_algorithm_id) ‖ u32(source_count) ‖
    /// member_commitment[32] ‖ lp(noise_floor_descriptor) [‖ u32(n_eff) iff
    /// version ≥ 2]`, where `lp(x) = u32_be(len) ‖ utf8(x)` (the §19.0 u32
    /// length-prefix).
    ///
    /// §19.7.1.2 (CIRISVerify#167): a **version-2** tier appends the signed
    /// effective-source-count `u32(n_eff)`. A version-1 tier's preimage is
    /// **byte-identical** to the original layout, so pre-#167 signatures/vectors
    /// still verify unchanged.
    #[must_use]
    pub fn signing_preimage(&self) -> Vec<u8> {
        let p = Preimage::new(DOMAIN_AGG_META)
            .u32_be(self.version)
            .lp(self.content_id.as_bytes())
            .lp(self.corpus_kind.as_bytes())
            .u32_be(self.tier)
            .lp(self.aggregation_algorithm_id.as_bytes())
            .u32_be(self.source_count)
            .fixed(&self.member_commitment)
            .lp(self.noise_floor_descriptor.as_bytes());
        // §19.7.1.2 (#167): v2 appends the signed n_eff. §19.7.1.3 (#191): v3
        // additionally appends the content-similarity multiplicity + the mass
        // commitment. Append-only — a v1/v2 tier's preimage is byte-identical to
        // its original layout, so pre-#191 signatures/vectors still verify.
        let p = if self.version >= 2 {
            p.u32_be(self.n_eff)
        } else {
            p
        };
        if self.version >= 3 {
            p.u32_be(self.max_source_multiplicity)
                .fixed(&self.mass_commitment)
                .finish()
        } else {
            p.finish()
        }
    }
}

/// §19.7.1.2 (CIRISVerify#167 / CC 6.1.2): the **effective source count** of a
/// fold from its per-member content masses — the inverse-Simpson index /
/// participation ratio `n_eff = (Σ mᵢ)² / Σ mᵢ²`, rounded to the nearest
/// integer. Non-positive masses are ignored. A balanced fold of N equal-mass
/// sources gives `n_eff == N`; a fold where one source holds ~90% of the mass
/// (the 900/1000 case) collapses toward `n_eff → 1`.
///
/// Returns `0` for an empty / all-zero-mass fold (fail-closed: a fold with no
/// positive mass has no effective sources).
#[must_use]
pub fn effective_source_count(member_masses: &[f64]) -> u32 {
    let mut sum = 0.0f64;
    let mut sum_sq = 0.0f64;
    for &m in member_masses {
        if m > 0.0 {
            sum += m;
            sum_sq += m * m;
        }
    }
    if sum <= 0.0 || sum_sq <= 0.0 {
        return 0;
    }
    // (Σm)² / Σm² ∈ [1, N]; round to nearest, clamp into u32.
    ((sum * sum) / sum_sq).round().max(1.0) as u32
}

/// §19.7.1.2 dominance gate (CIRISVerify#167 / CC 6.1.2 noise floor). A tier
/// passes iff its **signed** effective source count is at least `min_ratio` of
/// its raw `source_count` — rejecting a composite dominated by a few high-mass
/// sources (the 900/1000 case, `n_eff ≈ 1 ≪ source_count`), where the noise-floor
/// guarantee is violated because a dominated source is effectively recoverable.
///
/// Requires a **version-2** tier (a *signed* `n_eff`, per [`AggregationMetaV1::signing_preimage`]);
/// a version-1 tier has no dominance surface and **fails closed**. Callers that
/// require dominance-checking gate on this after [`verify_aggregation_meta`]
/// (which authenticates the `n_eff` this reads).
#[must_use]
pub fn passes_dominance_gate(meta: &AggregationMetaV1, min_ratio: f64) -> bool {
    if meta.version < 2 || meta.source_count == 0 {
        return false;
    }
    f64::from(meta.n_eff) >= min_ratio * f64::from(meta.source_count)
}

/// Fixed-point scale for committed masses (CIRISVerify#191). A member's content
/// mass (a non-negative `f64`) is committed as `round(mass * MASS_FIXED_POINT_SCALE)`
/// so two conformant implementations commit **byte-identically** — the CC 6.1.2
/// `(R, ε)` falsifiability discipline forbids float non-determinism in the wire
/// commitment.
pub const MASS_FIXED_POINT_SCALE: f64 = 1_000_000.0;

/// Encode a content mass as the pinned fixed-point `u64` (micro-units),
/// saturating at `0` for non-positive mass. The producer commits these via
/// [`mass_commitment`].
#[must_use]
pub fn mass_to_fixed(mass: f64) -> u64 {
    if mass <= 0.0 {
        0
    } else {
        (mass * MASS_FIXED_POINT_SCALE).round() as u64
    }
}

/// §19.7.1.3 (CIRISVerify#191): Merkle root over the per-member masses — the
/// §19.1 WholenessWitness construction ([`member_commitment`]) verbatim, with
/// each leaf binding a member to its fixed-point mass:
/// `leaf = utf8(member_id) ‖ u64_be(mass_fixed)`. Lexicographic order + odd-node
/// duplication (order-independent). An auditor holding `{(member_id, mass)}`
/// recomputes this root and can **prove** a lying `n_eff` / multiplicity from
/// held evidence — converting "slashable in principle" into "mechanically
/// provable".
#[must_use]
pub fn mass_commitment(members: &[(String, u64)]) -> [u8; 32] {
    let leaves: Vec<Vec<u8>> = members
        .iter()
        .map(|(id, mass)| {
            let mut leaf = id.as_bytes().to_vec();
            leaf.extend_from_slice(&mass.to_be_bytes());
            leaf
        })
        .collect();
    super::compute_merkle_root(&leaves)
}

/// §19.7.1.3 audit check: does `members` (member id + fixed-point mass)
/// re-derive the tier's committed [`AggregationMetaV1::mass_commitment`]?
/// Order-independent (the Merkle sorts).
#[must_use]
pub fn verify_mass_commitment(meta: &AggregationMetaV1, members: &[(String, u64)]) -> bool {
    mass_commitment(members) == meta.mass_commitment
}

/// §19.7.1.3 multiplicity gate (CIRISVerify#191 / CC 6.1.2.1.2 R9). A tier passes
/// iff its **signed** largest content-similar cluster is at most `1/n_min` of its
/// raw `source_count` — `max_source_multiplicity · n_min ≤ source_count`.
/// Rejects the 900-near-duplicates-under-distinct-ids fold
/// (`max_source_multiplicity = 900`, `source_count = 1000`, `n_min = 2`:
/// `1800 > 1000` → reject) that the mass-based [`passes_dominance_gate`] honestly
/// admits, because the composite blur IS the data subject.
///
/// `n_min` is the **`corpus_kind`-pinned** floor the caller supplies (two
/// conformant impls MUST agree on it — CC 6.1.2 `(R, ε)`). Requires a
/// **version-3** tier (a *signed* `max_source_multiplicity`); a v1/v2 tier lacks
/// the surface and **fails closed** (the flag-day cut — no deprecation window).
/// `n_min == 0` is rejected. Gate on this AFTER [`verify_aggregation_meta`], which
/// authenticates the value this reads.
#[must_use]
pub fn passes_multiplicity_gate(meta: &AggregationMetaV1, n_min: u32) -> bool {
    if meta.version < 3 || meta.source_count == 0 || n_min == 0 {
        return false;
    }
    u64::from(meta.max_source_multiplicity) * u64::from(n_min) <= u64::from(meta.source_count)
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
    /// Shed **exactly one** pyramid stratum — the tier-`tier` `AggregationMetaV1`
    /// composite — leaving both finer AND coarser tiers intact (§19.7.3, added
    /// 1.0-RC16). The tier-granular form of [`Self::EjectToTier`], applied under
    /// *targeted* pressure. Composes with hard-delete: a `tier` already below
    /// the noise floor is unreachable, so this never resurrects erased content.
    /// Persist drives the tier-tagged evict.
    EjectAggregatedTierOnly {
        /// The pyramid stratum (tier index) to shed.
        tier: u32,
    },
    /// Forced descent below the floor + purge still-recoverable tiers (§19.3
    /// N5). The fastest descent; **never** tier-shed. Persist drives
    /// `evict_fountain_content_hard_delete`.
    EjectHardDelete,
}

/// §19.7.3 targeted variant: shed exactly the tier-`tier` stratum
/// ([`EjectionVerdict::EjectAggregatedTierOnly`]) — for a substrate applying
/// pressure to one intermediate pyramid level rather than the whole item. A
/// pure fabric node MAY compute this mechanically (no agency).
#[must_use]
pub fn eject_aggregated_tier(tier: u32) -> EjectionVerdict {
    EjectionVerdict::EjectAggregatedTierOnly { tier }
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
            n_eff: members.len() as u32,
            // v1 base: the #191 surface is an un-signed placeholder (fails the
            // multiplicity gate, which requires v3). Tests bump `version` + these.
            max_source_multiplicity: 0,
            mass_commitment: [0u8; 32],
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

    // ---- §19.7.1.2 dominance / n_eff surface (#167) --------------------

    #[test]
    fn effective_source_count_matches_inverse_simpson() {
        // A balanced fold of N equal-mass sources → n_eff == N.
        assert_eq!(effective_source_count(&[1.0; 1000]), 1000);
        assert_eq!(effective_source_count(&[5.0; 4]), 4);
        // The 900/1000 dominance case: one source holds 90% of the mass, the
        // other 999 share 10% equally → n_eff collapses toward ~1.
        let mut masses = vec![900.0];
        masses.extend(std::iter::repeat_n(100.0 / 999.0, 999));
        let n_eff = effective_source_count(&masses);
        assert!(
            n_eff <= 2,
            "900/1000-dominated fold must have n_eff ≈ 1, got {n_eff}"
        );
        // Empty / all-zero → 0 (fail-closed).
        assert_eq!(effective_source_count(&[]), 0);
        assert_eq!(effective_source_count(&[0.0, 0.0]), 0);
    }

    #[test]
    fn dominance_gate_rejects_the_900_of_1000_case() {
        // A balanced v2 fold: n_eff == source_count → passes at any sane ratio.
        let mut balanced = meta();
        balanced.version = 2;
        balanced.source_count = 1000;
        balanced.n_eff = 1000;
        assert!(passes_dominance_gate(&balanced, 0.5));

        // The dominated 900/1000 fold: source_count=1000 but n_eff≈1 → rejected.
        let mut dominated = balanced.clone();
        dominated.n_eff = 1;
        assert!(
            !passes_dominance_gate(&dominated, 0.5),
            "a 90%-mass-dominated fold must be rejected"
        );
        // Even a lenient 10% floor rejects n_eff=1 of 1000.
        assert!(!passes_dominance_gate(&dominated, 0.1));

        // A v1 tier has no signed dominance surface → fails closed.
        let mut v1 = balanced.clone();
        v1.version = 1;
        assert!(
            !passes_dominance_gate(&v1, 0.5),
            "a v1 tier (no signed n_eff) must fail the dominance gate"
        );
    }

    #[test]
    fn n_eff_is_covered_by_the_v2_signature() {
        // Sign a v2 tier, then flip n_eff: the signature must no longer verify —
        // proving n_eff is in the signed preimage (not forgeable post-signature).
        let ed = Ed25519Signer::random().unwrap();
        let mldsa = MlDsa65Signer::new().unwrap();
        let mut m = meta();
        m.version = 2;
        m.n_eff = 3;
        let pre = m.signing_preimage();
        let ed_sig = ed.sign(&pre).unwrap();
        let mut bound = pre.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa.sign(&bound).unwrap();
        let (edk, mldk) = (ed.public_key().unwrap(), mldsa.public_key().unwrap());

        assert_eq!(
            verify_aggregation_meta(&m, &ed_sig, &pqc_sig, &edk, &mldk),
            AggregationMetaVerification::HybridVerified
        );
        // Forge a smaller n_eff (make a dominated fold look diverse) → sig fails.
        let mut forged = m.clone();
        forged.n_eff = 1;
        assert_eq!(
            verify_aggregation_meta(&forged, &ed_sig, &pqc_sig, &edk, &mldk),
            AggregationMetaVerification::Failed,
            "n_eff must be bound by the v2 signature"
        );
    }

    #[test]
    fn v1_preimage_is_byte_identical_regardless_of_n_eff() {
        // A v1 tier ignores n_eff in the preimage → pre-#167 signatures unchanged.
        let mut a = meta(); // version 1
        let mut b = a.clone();
        a.n_eff = 7;
        b.n_eff = 999;
        assert_eq!(a.signing_preimage(), b.signing_preimage());
    }

    #[test]
    fn eject_aggregated_tier_only_sheds_one_stratum() {
        // RC16: shed exactly tier N, leaving finer + coarser tiers intact.
        assert_eq!(
            eject_aggregated_tier(3),
            EjectionVerdict::EjectAggregatedTierOnly { tier: 3 }
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

    // ---- §19.7.1.3 multiplicity + mass surface (#191, CC 6.1.2.1.2 R9) ----

    /// The kill-shot: 900 near-duplicate contents folded as 900 DISTINCT members
    /// at equal mass honestly compute n_eff == 1000 (passes the mass dominance
    /// gate) — but the largest content-similar cluster is 900/1000, so the
    /// multiplicity gate rejects the false erasure.
    #[test]
    fn multiplicity_gate_rejects_900_near_duplicates_the_mass_gate_admits() {
        let mut m = meta();
        m.version = 3;
        m.source_count = 1000;
        m.n_eff = 1000; // equal mass → honestly passes the mass dominance gate…
        m.max_source_multiplicity = 900; // …but 900 are near-duplicate content.
        assert!(
            passes_dominance_gate(&m, 0.5),
            "equal-mass fold passes the mass gate"
        );
        assert!(
            !passes_multiplicity_gate(&m, 2),
            "900-of-1000 similar cluster must be rejected (900*2 > 1000)"
        );
    }

    #[test]
    fn multiplicity_gate_accepts_a_diverse_fold_at_the_boundary() {
        let mut m = meta();
        m.version = 3;
        m.source_count = 1000;
        m.max_source_multiplicity = 1;
        assert!(passes_multiplicity_gate(&m, 2));
        m.max_source_multiplicity = 500;
        assert!(
            passes_multiplicity_gate(&m, 2),
            "500*2 == 1000 (boundary passes)"
        );
        m.max_source_multiplicity = 501;
        assert!(!passes_multiplicity_gate(&m, 2), "501*2 > 1000");
    }

    #[test]
    fn multiplicity_gate_fails_closed_below_v3_and_on_zero_nmin() {
        let mut m = meta();
        m.source_count = 1000;
        m.max_source_multiplicity = 1;
        for v in [1u32, 2] {
            m.version = v;
            assert!(
                !passes_multiplicity_gate(&m, 2),
                "v{v} lacks the surface -> fail-closed"
            );
        }
        m.version = 3;
        assert!(!passes_multiplicity_gate(&m, 0), "n_min == 0 -> reject");
    }

    #[test]
    fn v1_and_v2_preimages_are_byte_identical_regardless_of_v3_fields() {
        let base = meta();
        for v in [1u32, 2] {
            let mut a = base.clone();
            a.version = v;
            a.max_source_multiplicity = 0;
            a.mass_commitment = [0u8; 32];
            let mut b = a.clone();
            b.max_source_multiplicity = 42;
            b.mass_commitment = [0xAB; 32];
            assert_eq!(
                a.signing_preimage(),
                b.signing_preimage(),
                "v{v} preimage must ignore the #191 fields (append-only)"
            );
        }
    }

    #[test]
    fn v3_preimage_appends_multiplicity_and_mass_commitment() {
        let mut v3 = meta();
        v3.version = 3;
        v3.max_source_multiplicity = 7;
        v3.mass_commitment = [0x11; 32];
        let mut v2 = v3.clone();
        v2.version = 2;
        assert_eq!(
            v3.signing_preimage().len(),
            v2.signing_preimage().len() + 4 + 32,
            "v3 appends u32(max_source_multiplicity) + mass_commitment[32]"
        );
    }

    #[test]
    fn mass_commitment_binds_masses_and_is_order_independent() {
        let a = mass_commitment(&[("m1".into(), 100), ("m2".into(), 200), ("m3".into(), 300)]);
        let b = mass_commitment(&[("m3".into(), 300), ("m1".into(), 100), ("m2".into(), 200)]);
        assert_eq!(a, b, "order-independent (Merkle sorts)");
        let c = mass_commitment(&[("m1".into(), 100), ("m2".into(), 999), ("m3".into(), 300)]);
        assert_ne!(a, c, "a flipped mass changes the root");
        let mut m = meta();
        m.mass_commitment = a;
        assert!(verify_mass_commitment(
            &m,
            &[("m2".into(), 200), ("m1".into(), 100), ("m3".into(), 300)]
        ));
        assert!(!verify_mass_commitment(
            &m,
            &[("m1".into(), 100), ("m2".into(), 999), ("m3".into(), 300)]
        ));
    }

    #[test]
    fn mass_to_fixed_is_pinned_and_saturates() {
        assert_eq!(mass_to_fixed(1.0), 1_000_000);
        assert_eq!(mass_to_fixed(0.0), 0);
        assert_eq!(mass_to_fixed(-3.0), 0, "non-positive saturates to 0");
        assert_eq!(mass_to_fixed(0.000_001), 1);
    }

    #[test]
    fn v3_bound_hybrid_signature_covers_the_new_surface() {
        let ed = Ed25519Signer::random().unwrap();
        let mldsa = MlDsa65Signer::new().unwrap();
        let mut m = meta();
        m.version = 3;
        m.max_source_multiplicity = 3;
        m.mass_commitment =
            mass_commitment(&[("m1".into(), 100), ("m2".into(), 100), ("m3".into(), 100)]);
        let pre = m.signing_preimage();
        let ed_sig = ed.sign(&pre).unwrap();
        let mut bound = pre.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa.sign(&bound).unwrap();
        let (edk, mldk) = (ed.public_key().unwrap(), mldsa.public_key().unwrap());
        assert_eq!(
            verify_aggregation_meta(&m, &ed_sig, &pqc_sig, &edk, &mldk),
            AggregationMetaVerification::HybridVerified
        );
        // Flipping max_source_multiplicity after signing breaks the signature.
        let mut forged = m.clone();
        forged.max_source_multiplicity = 900;
        assert_eq!(
            verify_aggregation_meta(&forged, &ed_sig, &pqc_sig, &edk, &mldk),
            AggregationMetaVerification::Failed,
            "the signed preimage covers max_source_multiplicity"
        );
    }
}
