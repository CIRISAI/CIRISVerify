//! §19 Holonomic substrate verifiers (CEG 1.0-RC11, CIRISVerify#78).
//!
//! CEG absorbed the CIRISEdge v4.0.0 "holonomic substrate" — ALM relay trees,
//! RaptorQ fountain storage, WholenessWitness divergence detection, recursive
//! trust bootstrap — as additive normative sections **with guardrails** (§19).
//! The adversarial review (→ CIRISEdge#143) found edge v4.0.0 does not enforce
//! the guardrails; **Verify is where they become real.** This module is the
//! cross-impl verifier home for them.
//!
//! ## What's here
//!
//! - `preimage` — §19.0 binary signed-preimage framing + the PQC-mandatory
//!   bound-hybrid gate every §19 object rides (`verify_bound_hybrid`). NOT JCS.
//! - `wholeness_witness` — §19.1 WholenessWitness Merkle (lexicographic leaves,
//!   odd-node duplication, `WW-v1-empty` sentinel — distinct from the §10.3 RFC
//!   6962 log) + N4 equivocation detection.
//! - `bootstrap` — §19.2 recursive trust bootstrap: ≤5-hop, cycle-reject,
//!   §13.3 weight cap, and **N1 trust ≠ membership** (the verdict can't express
//!   admission).
//! - `fountain` — §19.3 holding-claim verify + N5 retention-respects-revocation
//!   + N6 possession-bound + N7 symbol integrity.
//! - `alm` — §19.4 N8 capacity-authenticity gate + the deterministic-topology
//!   input canonicalizer.
//! - `av_chunk` — §10.5.8.3–.5 `SealedAvChunk` header + the inner/outer
//!   double-seal nonce derivations (RC10).
//!
//! ## Conformance status (§19.6 / the #57 freeze gate)
//!
//! The **invariant enforcement** and the **fully-pinned constructions** (the
//! WholenessWitness Merkle, the A/V nonces, the §19.0 framing + PQC gate) ship
//! now and are KAT-locked. The **exact signed-preimage field sets** for the
//! shapes that gain fields under CIRISEdge#143 (`SignedClaim` owner-binding,
//! `SignedRelayCapacity`, the fountain claims) are byte-frozen by the §19.6
//! conformance vectors authored against the **fixed** edge v4.0.x — until a
//! second impl reproduces those vectors byte-for-byte the §19 shapes are
//! **pinned-but-unproven, RC-grade**. This module owns the verifier side of that
//! vector set.

pub mod aggregation;
pub mod alm;
pub mod av_chunk;
pub mod bootstrap;
pub mod fountain;
pub mod preimage;
pub mod wholeness_witness;

// ---- the load-bearing surface, re-exported flat -----------------------

pub use preimage::{
    verify_bound_hybrid, BoundHybridSig, HolonomicError, Preimage, DOMAIN_AGG_META,
    DOMAIN_COMPRESS_REQUEST, DOMAIN_HOLDING_CLAIM, DOMAIN_RELAY_CAPACITY, DOMAIN_SIGNED_CLAIM,
    DOMAIN_WITNESS_PREIMAGE, WW_EMPTY_SENTINEL,
};

pub use aggregation::{
    effective_source_count, eject_aggregated_tier, ejection_verdict, member_commitment,
    passes_dominance_gate, verify_aggregation_meta, verify_member_commitment, AggregationMetaV1,
    AggregationMetaVerification, EjectionVerdict,
};

pub use wholeness_witness::{
    compare_witnesses, compute_merkle_root, verify_witness, Equivocation, WholenessWitness,
    WitnessComparison,
};

pub use bootstrap::{
    membership_blocked_without_owner_binding, recursive_trust_bootstrap, BootstrapHop,
    BootstrapVerdict, OwnerBinding, SignedClaim, TrustRoot, MAX_BOOTSTRAP_HOPS,
};

pub use fountain::{
    holding_claim_counts_toward_rarity, retention_decision, verify_holding_claim, verify_symbol,
    ConsentState, FountainCompressRequest, FountainHoldingClaim, RetentionDecision,
};

pub use alm::{
    bounded_capacity_score, canonicalize_snapshot, verify_relay_capacity, SignedRelayCapacity,
    CAPACITY_SELECTION_CAP_MBPS,
};

pub use av_chunk::{
    inner_nonce, outer_nonce, parse_header, ChunkLayer, SealedAvChunkHeader, AV_NONCE_LEN,
    CHUNK_HEADER_LEN,
};
