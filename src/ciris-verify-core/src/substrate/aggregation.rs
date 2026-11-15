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
//!   and a PQC-mandatory composite ML-DSA-65-Ed25519 signature (CC 2.6.1.7,
//!   [`verify_aggregation_meta`]).
//! - **[`member_commitment`] / [`verify_member_commitment`]** (§19.7.1.1) — the
//!   Merkle root over the tier's source member ids, computed by the **§19.1
//!   WholenessWitness construction reused verbatim** ([`super::compute_merkle_root`]),
//!   so the federation carries one aggregation/witness Merkle scheme, not a third.
//! - **[`EjectionVerdict`] / [`ejection_verdict`]** (§19.7.3) — the tier-aware
//!   retirement surface persist consumes, the canonical superset of v5.9.0's
//!   [`super::durable_storage::RetentionDecision`]. The §19.3 N5 mapping is load-bearing:
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

#[allow(unused_imports)]
use crate::prelude::*;

use super::durable_storage::ConsentState;
use super::preimage::{verify_composite, HolonomicError, Preimage, DOMAIN_AGG_META};

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
    /// §19.7.1.3 (CIRISVerify#191 / CC 6.1.2.3 R9): the **content-similarity
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

/// CC 6.1.2.3 per-fold ceiling: a fold of more than this many sources is
/// refused at the door with the token [`FOLD_SOURCE_COUNT_EXCEEDED`]; a larger
/// population folds hierarchically, as a fold of folds.
///
/// CC 6.1.2.3: "This edition pins a per-fold ceiling of 10⁶ sources, refused at
/// the door above it (`fold_source_count_exceeded`)."
pub const MAX_FOLD_SOURCES: usize = 1_000_000;

/// The CC 6.1.2.3 refusal reason for a fold above [`MAX_FOLD_SOURCES`].
pub const FOLD_SOURCE_COUNT_EXCEEDED: &str = "fold_source_count_exceeded";

/// The CC 6.1.1 refusal reason for a source list that names one member id
/// twice (`federation_malformed_row` / `aggregate_source_duplicate`).
pub const AGGREGATE_SOURCE_DUPLICATE: &str = "aggregate_source_duplicate";

/// CC 6.1.2.3: the **effective source count** of a fold, over the fold's
/// **committed** fixed-point masses (the `m_i` that [`mass_commitment`] binds,
/// produced by [`mass_to_fixed`]). Integer arithmetic only, so aggregator and
/// verifier agree exactly. A balanced fold of N equal committed masses gives
/// `n_eff == N`; a fold where one source holds ~90% of the mass collapses
/// toward `n_eff → 1`.
///
/// CC 6.1.2.3: "`n_eff = floor( (Σ m_i)² / Σ m_i² )` over committed masses
/// `m_i > 0`, `m_i = mass_to_fixed(w_i, W)`. The masses are the fixed-point
/// integers `mass_commitment` commits (`mass_to_fixed`, below), so aggregator
/// and verifier compute over the same integers and no real number enters the
/// computation. … An aggregator MUST sign the `n_eff` it computes over the
/// committed `m_i`, never one computed over `w_i` or any real-valued share."
/// And: "An empty or all-zero-mass fold has `n_eff = 0` (fail-closed: no
/// positive mass, no effective sources)."
///
/// Zero masses are skipped (`m_i > 0`); sums and squares are taken in `u128`.
///
/// # Errors
///
/// [`HolonomicError::Invariant`] with reason [`FOLD_SOURCE_COUNT_EXCEEDED`]
/// when `committed_masses` holds more than [`MAX_FOLD_SOURCES`] entries (the
/// CC 6.1.2.3 per-fold ceiling), and with reason `"n_eff_overflow"` if the
/// squared mass sum does not fit `u128`. That is unreachable for committed
/// masses (shares of 10⁶ micro-units) and is refused rather than approximated.
pub fn effective_source_count(committed_masses: &[u64]) -> Result<u32, HolonomicError> {
    const OVERFLOW: HolonomicError = HolonomicError::Invariant {
        reason: "n_eff_overflow",
    };
    if committed_masses.len() > MAX_FOLD_SOURCES {
        return Err(HolonomicError::Invariant {
            reason: FOLD_SOURCE_COUNT_EXCEEDED,
        });
    }
    let mut sum: u128 = 0;
    let mut sum_sq: u128 = 0;
    for &m in committed_masses.iter().filter(|&&m| m > 0) {
        let m = u128::from(m);
        // ≤ 10⁶ terms of < 2⁶⁴: the sum cannot overflow u128.
        sum += m;
        sum_sq = sum_sq.checked_add(m * m).ok_or(OVERFLOW)?;
    }
    if sum_sq == 0 {
        return Ok(0);
    }
    let sum_squared = sum.checked_mul(sum).ok_or(OVERFLOW)?;
    // floor((Σm)² / Σm²) ∈ [1, number of positive masses] ≤ 10⁶: fits u32.
    Ok(u32::try_from(sum_squared / sum_sq).unwrap_or(u32::MAX))
}

/// CC 6.1.2.3 mass-dominance gate. A tier passes iff `version = 3`,
/// `source_count > 0`, and its **signed** effective source count satisfies
/// `n_eff ≥ min_ratio · source_count` with the CEG-pinned `min_ratio = 0.5`,
/// tested over the committed integers as `n_eff * 2 >= source_count` ("the exact
/// integer form of `min_ratio = 0.5`. No IEEE-754 path is used here"). This rejects
/// a composite dominated by a few high-mass sources (the 900/1000 case,
/// `n_eff ≈ 1 ≪ source_count`).
///
/// `min_ratio` is "a normative constant, not an implementation-tunable knob", so
/// it is not a parameter. `version < 3` is inadmissible and fails closed. Run it
/// after [`verify_aggregation_meta`] (which authenticates the `n_eff` this reads)
/// and before persistence; a failing tier is rejected with
/// [`AGGREGATION_META_DOMINATED`].
#[must_use]
pub fn passes_dominance_gate(meta: &AggregationMetaV1) -> bool {
    if meta.version != 3 || meta.source_count == 0 {
        return false;
    }
    u64::from(meta.n_eff) * 2 >= u64::from(meta.source_count)
}

/// CC 6.1.2.3: the stable rejection token for a tier that fails
/// [`passes_dominance_gate`].
pub const AGGREGATION_META_DOMINATED: &str = "aggregation_meta_dominated";

/// CC 6.1.2.3 fixed-point scale for committed masses: a member's share of the
/// fold's mass is committed in micro-units (10⁶ per whole fold), by
/// [`mass_to_fixed`]'s integer division.
pub const MASS_FIXED_POINT_SCALE: u64 = 1_000_000;

/// CC 6.1.2.3: a member's committed mass — its share of the fold's content
/// mass `total` (`W = Σ w_i`) in micro-units, by integer division, nearest
/// with ties rounded up.
///
/// CC 6.1.2.3: "the committed mass is the member's share of the fold's mass in
/// micro-units, by integer division, nearest with ties rounded up:
/// `mass_to_fixed(w, W) = (2 · w · 10⁶ + W) div (2 · W)` as a `u64`; a member
/// with `w = 0`, or any member of a fold with `W = 0`, commits as `0`."
///
/// `w` and `W` are the integer content masses of CC 6.1.2.3 (`w_i` is the L1
/// norm of the member's resampled payload). The arithmetic is done in `u128`;
/// for `w ≤ W` the result is at most 10⁶. A caller passing `w > W` (not a share)
/// gets the same formula, saturated at `u64::MAX`.
#[must_use]
pub fn mass_to_fixed(w: u64, total: u64) -> u64 {
    if w == 0 || total == 0 {
        return 0;
    }
    let (w, total) = (u128::from(w), u128::from(total));
    let scale = u128::from(MASS_FIXED_POINT_SCALE);
    // 2·w·10⁶ + W < 2⁶⁵·10⁶ + 2⁶⁴ < 2¹²⁸: no overflow.
    let m = (2 * w * scale + total) / (2 * total);
    u64::try_from(m).unwrap_or(u64::MAX)
}

/// Refuse a source list that names one member id twice (CC 6.1.1: "The leaf
/// list MUST be deduplicated as well as sorted … and a list with a repeated
/// leaf is refused before hashing", with a repeated id in `sources` refused as
/// `aggregate_source_duplicate`).
fn refuse_duplicate_ids<'a>(ids: impl Iterator<Item = &'a str>) -> Result<(), HolonomicError> {
    let mut sorted: Vec<&str> = ids.collect();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err(HolonomicError::Invariant {
            reason: AGGREGATE_SOURCE_DUPLICATE,
        });
    }
    Ok(())
}

/// §19.7.1.3 (CIRISVerify#191): Merkle root over the per-member masses — the
/// §19.1 WholenessWitness construction ([`member_commitment`]) verbatim, with
/// each leaf binding a member to its committed mass
/// ([`mass_to_fixed`], CC 6.1.2.3):
/// `leaf = utf8(member_id) ‖ u64_be(mass_fixed)`. Lexicographic order + odd-node
/// duplication (order-independent). An auditor holding `{(member_id, mass)}`
/// recomputes this root and can **prove** a lying `n_eff` / multiplicity from
/// held evidence — converting "slashable in principle" into "mechanically
/// provable".
///
/// # Errors
///
/// [`HolonomicError::Invariant`] with reason [`AGGREGATE_SOURCE_DUPLICATE`]
/// when two entries name the same `member_id` (whatever their masses), per the
/// CC 6.1.1 sorted-AND-unique leaf rule. Refused before hashing.
pub fn mass_commitment(members: &[(String, u64)]) -> Result<[u8; 32], HolonomicError> {
    refuse_duplicate_ids(members.iter().map(|(id, _)| id.as_str()))?;
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
/// Order-independent (the Merkle sorts). `Ok(false)` is a mismatch.
///
/// # Errors
///
/// As [`mass_commitment`]: a repeated `member_id` is refused, never compared.
pub fn verify_mass_commitment(
    meta: &AggregationMetaV1,
    members: &[(String, u64)],
) -> Result<bool, HolonomicError> {
    Ok(mass_commitment(members)? == meta.mass_commitment)
}

/// §19.7.1.3 multiplicity gate (CIRISVerify#191 / CC 6.1.2.3 R9). A tier passes
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
///
/// CC 6.1.2.2: "the odd-node-duplication malleability is moot given the
/// deduplicated-leaf rule of CC 6.1.1 (a repeated `member_id` is refused; the
/// source-id list is sorted AND unique)". Without the refusal `{a,b,c}` and
/// `{a,b,c,c}` share a root (CIRISVerify#314).
///
/// # Errors
///
/// [`HolonomicError::Invariant`] with reason [`AGGREGATE_SOURCE_DUPLICATE`]
/// when a member id repeats. Refused before hashing.
pub fn member_commitment(source_member_ids: &[String]) -> Result<[u8; 32], HolonomicError> {
    refuse_duplicate_ids(source_member_ids.iter().map(String::as_str))?;
    let leaves: Vec<Vec<u8>> = source_member_ids
        .iter()
        .map(|id| id.as_bytes().to_vec())
        .collect();
    super::compute_merkle_root(&leaves)
}

/// §19.7.1.1 descent-integrity check: does `source_member_ids` re-derive the
/// tier's committed `member_commitment` byte-for-byte? Order-independent (the
/// Merkle sorts lexicographically), so the caller need not pre-sort.
/// `Ok(false)` is a mismatch.
///
/// # Errors
///
/// As [`member_commitment`]: a repeated member id is refused, never compared.
pub fn verify_member_commitment(
    meta: &AggregationMetaV1,
    source_member_ids: &[String],
) -> Result<bool, HolonomicError> {
    Ok(member_commitment(source_member_ids)? == meta.member_commitment)
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
    /// The composite signature verified — admissible at ingest.
    Verified,
    /// Verification failed (wrong length, undecodable key, or the composite
    /// signature did not verify; which half failed is not said).
    Failed,
}

/// Verify an `AggregationMetaV1` tier's composite ML-DSA-65-Ed25519 signature
/// (CC 2.6.1.7; `sig` 3373 bytes, `composite_pubkey` 1984 bytes) over its
/// §19.7.1 canonical preimage (PQC-mandatory; neither half verifies alone). The
/// §10.1.5.1.1 store-path rule applies: a substrate MUST reject a tier whose
/// composite signature does not verify **at ingest and before persistence** — pass only [`AggregationMetaVerification::Verified`].
#[must_use]
pub fn verify_aggregation_meta(
    meta: &AggregationMetaV1,
    sig: &[u8],
    composite_pubkey: &[u8],
) -> AggregationMetaVerification {
    match verify_composite(&meta.signing_preimage(), sig, composite_pubkey) {
        Ok(()) => AggregationMetaVerification::Verified,
        Err(_) => AggregationMetaVerification::Failed,
    }
}

/// §19.7.3: the single tier-aware retirement verdict a verifier exposes and a
/// substrate consumes to gate one step of the §19.7 descent. The canonical
/// superset of v5.9.0's rarity-only [`super::durable_storage::RetentionDecision`].
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
    use ciris_crypto::composite::{CompositeSigningKey, MLDSA65_SIG_LEN};

    fn key() -> CompositeSigningKey {
        CompositeSigningKey::from_seeds(&[1; 32], &[2; 32])
    }

    fn meta() -> AggregationMetaV1 {
        let members: Vec<String> = ["m3", "m1", "m2"].iter().map(|s| s.to_string()).collect();
        AggregationMetaV1 {
            version: 1,
            content_id: "content-root-1".into(),
            corpus_kind: "trace".into(),
            tier: 2,
            aggregation_algorithm_id: "raptorq-pyramid-v1".into(),
            source_count: members.len() as u32,
            member_commitment: member_commitment(&members).unwrap(),
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
        let a = member_commitment(&["m1".into(), "m2".into(), "m3".into()]).unwrap();
        let b = member_commitment(&["m3".into(), "m1".into(), "m2".into()]).unwrap();
        assert_eq!(a, b, "lexicographic — order independent");
        // Reuses the §19.1 construction: equals compute_merkle_root over utf8 leaves.
        let leaves: Vec<Vec<u8>> = ["m1", "m2", "m3"]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
        assert_eq!(a, super::super::compute_merkle_root(&leaves).unwrap());
    }

    #[test]
    fn verify_member_commitment_round_trips() {
        let m = meta();
        assert!(verify_member_commitment(&m, &["m1".into(), "m2".into(), "m3".into()]).unwrap());
        // A wrong source set fails the descent-integrity check.
        assert!(!verify_member_commitment(&m, &["m1".into(), "m2".into()]).unwrap());
        assert!(!verify_member_commitment(&m, &["m1".into(), "m2".into(), "EVIL".into()]).unwrap());
    }

    #[test]
    fn descend_order_is_lexicographic_and_re_derives_commitment() {
        let unordered = vec!["m3".into(), "m1".into(), "m2".into()];
        assert_eq!(descend_order(&unordered), vec!["m1", "m2", "m3"]);
        // A descend-ordered list re-derives the committed root.
        let m = meta();
        assert_eq!(
            member_commitment(&descend_order(&unordered)).unwrap(),
            m.member_commitment
        );
    }

    #[test]
    fn aggregation_meta_round_trips_pqc_mandatory() {
        let k = key();
        let other = CompositeSigningKey::from_seeds(&[3; 32], &[4; 32]);
        let m = meta();
        let pre = m.signing_preimage();
        let sig = k.sign(&pre).unwrap();
        let pk = k.public_key().as_bytes();

        assert_eq!(
            verify_aggregation_meta(&m, &sig, pk),
            AggregationMetaVerification::Verified
        );
        // Tampered tier → fail.
        let mut m2 = m.clone();
        m2.tier = 3;
        assert_eq!(
            verify_aggregation_meta(&m2, &sig, pk),
            AggregationMetaVerification::Failed
        );
        // Wrong length: the bare Ed25519 half (the old classical-only shape).
        assert_eq!(
            verify_aggregation_meta(&m, &sig[MLDSA65_SIG_LEN..], pk),
            AggregationMetaVerification::Failed
        );
        // A flipped byte in the ML-DSA region and in the Ed25519 region.
        for i in [0, MLDSA65_SIG_LEN] {
            let mut bad = sig.clone();
            bad[i] ^= 1;
            assert_eq!(
                verify_aggregation_meta(&m, &bad, pk),
                AggregationMetaVerification::Failed,
                "byte {i}"
            );
        }
        // A signature under a different key.
        let foreign = other.sign(&pre).unwrap();
        assert_eq!(
            verify_aggregation_meta(&m, &foreign, pk),
            AggregationMetaVerification::Failed
        );
    }

    // ---- §19.7.1.2 dominance / n_eff surface (#167) --------------------

    #[test]
    fn effective_source_count_matches_inverse_simpson() {
        // A balanced fold of N equal committed masses → n_eff == N.
        assert_eq!(effective_source_count(&[1_000; 1000]).unwrap(), 1000);
        assert_eq!(effective_source_count(&[250_000; 4]).unwrap(), 4);
        // The 900/1000 dominance case: one source holds 90% of the mass, the
        // other 999 share 10% equally → n_eff collapses toward ~1.
        let mut w = vec![900_000u64];
        w.extend(core::iter::repeat_n(100, 999));
        let total: u64 = w.iter().sum();
        let m: Vec<u64> = w.iter().map(|&wi| mass_to_fixed(wi, total)).collect();
        let n_eff = effective_source_count(&m).unwrap();
        assert!(
            n_eff <= 2,
            "900/1000-dominated fold must have n_eff ≈ 1, got {n_eff}"
        );
    }

    #[test]
    fn effective_source_count_is_the_integer_floor() {
        // CC 6.1.2.3 floor, not round-to-nearest: content masses (2, 1) commit
        // as (666667, 333333); (Σm)²/Σm² = 1.7999… → 1 (the f64 round gave 2).
        let m = [mass_to_fixed(2, 3), mass_to_fixed(1, 3)];
        assert_eq!(m, [666_667, 333_333]);
        assert_eq!(effective_source_count(&m).unwrap(), 1);
        // (1.0, 0.5, 0.25)·10⁶: 2.33… → 2.
        assert_eq!(
            effective_source_count(&[1_000_000, 500_000, 250_000]).unwrap(),
            2
        );
    }

    #[test]
    fn effective_source_count_empty_and_zero_folds_are_zero() {
        // CC 6.1.2.3: an empty or all-zero-mass fold has n_eff = 0.
        assert_eq!(effective_source_count(&[]).unwrap(), 0);
        assert_eq!(effective_source_count(&[0, 0, 0]).unwrap(), 0);
        // A W = 0 fold commits every member as 0, hence n_eff = 0.
        let m = [mass_to_fixed(0, 0), mass_to_fixed(0, 0)];
        assert_eq!(effective_source_count(&m).unwrap(), 0);
        // Zero masses are skipped, not counted: (m, 0, 0) → 1.
        assert_eq!(effective_source_count(&[7, 0, 0]).unwrap(), 1);
    }

    #[test]
    fn effective_source_count_refuses_above_the_fold_ceiling() {
        // CC 6.1.2.3: 10⁶ sources is the per-fold ceiling; one more is refused.
        let at_cap = vec![1u64; MAX_FOLD_SOURCES];
        assert_eq!(
            effective_source_count(&at_cap).unwrap(),
            u32::try_from(MAX_FOLD_SOURCES).unwrap()
        );
        let over = vec![1u64; MAX_FOLD_SOURCES + 1];
        assert_eq!(
            effective_source_count(&over).unwrap_err(),
            HolonomicError::Invariant {
                reason: FOLD_SOURCE_COUNT_EXCEEDED
            }
        );
        // The ceiling counts every source, zero-mass ones included.
        assert!(effective_source_count(&vec![0u64; MAX_FOLD_SOURCES + 1]).is_err());
    }

    #[test]
    fn dominance_gate_rejects_the_900_of_1000_case() {
        // A balanced v3 fold: n_eff == source_count → passes.
        let mut balanced = meta();
        balanced.version = 3;
        balanced.source_count = 1000;
        balanced.n_eff = 1000;
        assert!(passes_dominance_gate(&balanced));

        // The dominated 900/1000 fold: source_count=1000 but n_eff≈1 → rejected.
        let mut dominated = balanced.clone();
        dominated.n_eff = 1;
        assert!(
            !passes_dominance_gate(&dominated),
            "a 90%-mass-dominated fold must be rejected"
        );

        // The integer boundary of min_ratio = 0.5: n_eff * 2 >= source_count.
        let mut edge = balanced.clone();
        edge.source_count = 1001;
        edge.n_eff = 500;
        assert!(!passes_dominance_gate(&edge), "500*2 < 1001");
        edge.n_eff = 501;
        assert!(passes_dominance_gate(&edge), "501*2 >= 1001");

        // version < 3 is inadmissible (CC 6.1.2.1) and fails closed, even balanced.
        for v in [1, 2] {
            let mut old = balanced.clone();
            old.version = v;
            assert!(
                !passes_dominance_gate(&old),
                "a v{v} tier must fail the dominance gate"
            );
        }
        let mut empty = balanced.clone();
        empty.source_count = 0;
        empty.n_eff = 0;
        assert!(!passes_dominance_gate(&empty), "source_count = 0 fails");
    }

    #[test]
    fn n_eff_is_covered_by_the_v2_signature() {
        // Sign a v2 tier, then flip n_eff: the signature must no longer verify —
        // proving n_eff is in the signed preimage (not forgeable post-signature).
        let k = key();
        let mut m = meta();
        m.version = 2;
        m.n_eff = 3;
        let pre = m.signing_preimage();
        let sig = k.sign(&pre).unwrap();
        let pk = k.public_key().as_bytes();

        assert_eq!(
            verify_aggregation_meta(&m, &sig, pk),
            AggregationMetaVerification::Verified
        );
        // Forge a smaller n_eff (make a dominated fold look diverse) → sig fails.
        let mut forged = m.clone();
        forged.n_eff = 1;
        assert_eq!(
            verify_aggregation_meta(&forged, &sig, pk),
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

    // ---- §19.7.1.3 multiplicity + mass surface (#191, CC 6.1.2.3 R9) ----

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
            passes_dominance_gate(&m),
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
        let a =
            mass_commitment(&[("m1".into(), 100), ("m2".into(), 200), ("m3".into(), 300)]).unwrap();
        let b =
            mass_commitment(&[("m3".into(), 300), ("m1".into(), 100), ("m2".into(), 200)]).unwrap();
        assert_eq!(a, b, "order-independent (Merkle sorts)");
        let c =
            mass_commitment(&[("m1".into(), 100), ("m2".into(), 999), ("m3".into(), 300)]).unwrap();
        assert_ne!(a, c, "a flipped mass changes the root");
        let mut m = meta();
        m.mass_commitment = a;
        assert!(verify_mass_commitment(
            &m,
            &[("m2".into(), 200), ("m1".into(), 100), ("m3".into(), 300)]
        )
        .unwrap());
        assert!(!verify_mass_commitment(
            &m,
            &[("m1".into(), 100), ("m2".into(), 999), ("m3".into(), 300)]
        )
        .unwrap());
    }

    #[test]
    fn mass_to_fixed_is_the_cc_6_1_2_3_integer_share() {
        // (2·w·10⁶ + W) div (2·W): the share in micro-units, nearest.
        assert_eq!(mass_to_fixed(1, 1), 1_000_000);
        assert_eq!(mass_to_fixed(1, 3), 333_333);
        assert_eq!(mass_to_fixed(2, 3), 666_667);
        // Ties round up: 1/2_000_000 of a fold is exactly 0.5 micro-units.
        assert_eq!(mass_to_fixed(1, 2_000_000), 1);
        assert_eq!(mass_to_fixed(3, 2_000_000), 2, "1.5 → 2");
        // Just below the tie rounds down.
        assert_eq!(mass_to_fixed(1, 2_000_001), 0);
        // w = 0, or W = 0, commits as 0.
        assert_eq!(mass_to_fixed(0, 5), 0);
        assert_eq!(mass_to_fixed(5, 0), 0);
        assert_eq!(mass_to_fixed(0, 0), 0);
        // No overflow at the u64 edge.
        assert_eq!(mass_to_fixed(u64::MAX, u64::MAX), 1_000_000);
    }

    #[test]
    fn repeated_member_id_is_refused() {
        // CIRISVerify#314 / CC 6.1.1: {a,b,c} and {a,b,c,c} shared a root under
        // odd-node duplication. The repeated id is now refused before hashing.
        let dup = ["a", "b", "c", "c"].map(String::from);
        let refused = HolonomicError::Invariant {
            reason: AGGREGATE_SOURCE_DUPLICATE,
        };
        assert_eq!(member_commitment(&dup).unwrap_err(), refused);
        let mut m = meta();
        m.member_commitment = member_commitment(&["a", "b", "c"].map(String::from)).unwrap();
        assert_eq!(verify_member_commitment(&m, &dup).unwrap_err(), refused);
        // mass_commitment refuses a repeated id even when the masses differ
        // (the leaf bytes differ, the member does not).
        let pairs = [("a".to_string(), 1u64), ("b".into(), 2), ("a".into(), 3)];
        assert_eq!(mass_commitment(&pairs).unwrap_err(), refused);
        assert_eq!(verify_mass_commitment(&m, &pairs).unwrap_err(), refused);
    }

    #[test]
    fn v3_composite_signature_covers_the_new_surface() {
        let k = key();
        let mut m = meta();
        m.version = 3;
        m.max_source_multiplicity = 3;
        m.mass_commitment =
            mass_commitment(&[("m1".into(), 100), ("m2".into(), 100), ("m3".into(), 100)]).unwrap();
        let pre = m.signing_preimage();
        let sig = k.sign(&pre).unwrap();
        let pk = k.public_key().as_bytes();
        assert_eq!(
            verify_aggregation_meta(&m, &sig, pk),
            AggregationMetaVerification::Verified
        );
        // Flipping max_source_multiplicity after signing breaks the signature.
        let mut forged = m.clone();
        forged.max_source_multiplicity = 900;
        assert_eq!(
            verify_aggregation_meta(&forged, &sig, pk),
            AggregationMetaVerification::Failed,
            "the signed preimage covers max_source_multiplicity"
        );
    }
}
