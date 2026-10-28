# Substrate Verifiers (CC 6.1)

**Module:** `ciris_verify_core::substrate`. **Wire labels:** the code and the conformance
vectors use the CEG §19 / §19.7 section labels; the constitutional sections are CC 6.1
(the substrate), CC 6.1.1 (wholeness witness), CC 6.1.2 (noise floor) and CC 6.1.5
(replication).

CIRISVerify is the **cross-impl verifier home** for the substrate: the federation's
graceful-degradation / graceful-reconstitution layer. CIRISEdge produces the objects;
this module is where the guardrails are *enforced*, and (for the aggregation pyramid)
where the conformance vectors are *authored*.

## What the substrate provides

- **Graceful degradation** — any subset of RaptorQ fountain symbols decodes at
  proportional fidelity.
- **Graceful reconstitution** — a witnessed, trust-anchored corpus re-establishes
  from any sufficient fragment.

Several enforcement gates live where Verify already sits (hybrid verification,
Merkle, threshold). An edge-produced object that violates a guardrail is *rejected
here*.

## The canonicalization boundary (the shared foundation)

Every substrate object is **transport/substrate framing — NOT an attestation**: it
never instantiates an `attestation_type` and never enters JCS. It signs a **binary,
length-prefixed, big-endian, domain-separated preimage** (`substrate::Preimage`).
**PQC-mandatory at the gate** (`verify_bound_hybrid`): every object carries the bound
hybrid pair — Ed25519 over the preimage, ML-DSA-65 over `preimage ‖ ed25519_sig` — and
a missing/invalid ML-DSA-65 half is rejected **at ingest and before persistence**
(substrate objects are federation-tier). A verdict is recomputed at the gate; a
wire-carried `verified` flag is forgeable and is never trusted.

## Module map

| Module | Surface | Verifier-side invariants enforced |
|--------|---------|-----------------------------------|
| `substrate::preimage` | framing + PQC gate | `verify_bound_hybrid` — **PQC-mandatory**, no classical-only, no in-band `verified` flag |
| `substrate::wholeness_witness` | wholeness witness (CC 6.1.1; CEG §19.1) | lexicographic-leaf Merkle (distinct from the RFC 6962 transparency log; no prefix byte); verify-at-ingest; **equivocation** (two signed roots for the same `(peer, epoch, ns-set)` → non-repudiable, surfaced never reconciled); anonymous/`self` namespace guard; the divergence detector **triggers** quorum-merge and never replaces anti-rollback (it cannot resurrect a revoked key) |
| `substrate::bootstrap` | recursive trust (CEG §19.2) | **trust ≠ membership** (the verdict type cannot express "admitted"); ≤5-hop, cycle-reject, 0.5×root_trust weight cap; `membership_blocked_without_owner_binding` (owner-binding + consensus for non-infra; founder-quorum for infra) |
| `substrate::fountain` | replication (CC 6.1.5; CEG §19.3) | retention respects revocation (revoked → descent below floor regardless of rarity); possession-bound (unverified claims can't force-evict); per-symbol integrity; `symbol_ids` sorted |
| `substrate::alm` | ALM relay tree (CEG §19.4) | capacity authenticity (verify `SignedRelayCapacity` *before* scoring); bounded capacity score (anti-eclipse); deterministic integer-only snapshot canonicalizer; one signing preimage shared with CIRISEdge, pinned by a golden vector |
| `substrate::av_chunk` | realtime A/V framing (CC 5.3.3) | `SealedAvChunk` header parse; the outer nonce; the inner nonce is the CC 5.3.3.1 STREAM nonce (`av_inner_nonce` → `ciris_crypto::stream_seal::stream_nonce`) |
| `substrate::aggregation` | **noise floor / aggregation pyramid** (CC 6.1.2; CEG §19.7) | `AggregationMetaV1` PQC-mandatory ingest gate; `member_commitment` descent integrity (reuses the wholeness-witness Merkle verbatim); signed `n_eff` dominance gate; content-similarity multiplicity gate and `mass_commitment` (v3); `EjectionVerdict` tier-aware retirement (revoked → hard-delete, never tier-shed) |

## The noise floor and the aggregation pyramid (CC 6.1.2)

Revocation, retirement, capacity-eviction and aging are **one pressure-driven
operator**: a monotonic descent of an item's fidelity toward and below the **noise
floor** (the individual-recoverability boundary). The floor is simultaneously the
**privacy boundary** (a revoked item MUST be below it at every retained tier) and the
**durability floor** (the collective blur sits below it, forever). Descent never
terminates at zero: inter-object **N→1 aggregation** builds a mipmap of history, so
remembering *all* of history costs **O(log T)**, not O(T).

Verify verifies the aggregation-tier metadata that tags that pyramid:

- **`verify_aggregation_meta`** — the `AggregationMetaV1` PQC-mandatory ingest gate.
  16-byte `AGG-META-v1\0\0\0\0\0` domain, u32-lp/big-endian framing.
- **`passes_dominance_gate`** — a fold dominated by a few high-mass sources fails on
  its signed effective source count (`n_eff`, inverse-Simpson).
- **`passes_multiplicity_gate`** — a fold of near-duplicate contents under distinct ids
  fails: `max_source_multiplicity · n_min ≤ source_count`, fail-closed below v3.
  `mass_commitment` / `verify_mass_commitment` make `n_eff` and the clustering
  auditable from held evidence.
- **`verify_member_commitment`** — descent integrity: does a source member-id list
  re-derive the tier's committed Merkle root? One Merkle scheme for the wholeness
  witness and the pyramid.
- **`descend_order`** — the lexicographic order `member_commitment` commits to.
- **`EjectionVerdict { Keep | EjectToTier | EjectAggregatedTierOnly { tier } |
  EjectHardDelete }`** — the tier-aware retirement surface persist consumes. A revoked
  item → `EjectHardDelete` (MUST purge, **never** tier-shed); capacity pressure →
  `EjectToTier`; targeted single-stratum pressure → `EjectAggregatedTierOnly` (sheds
  one pyramid level, leaving finer + coarser intact).

## Threat model — what each gate blocks

| Threat | Blocked by |
|--------|-----------|
| Forge a substrate object after a future Ed25519 break | PQC-mandatory `verify_bound_hybrid` |
| Trust a forged "I verified this" flag | verdict recomputed at the gate; in-band `verified` is non-wire |
| Split-view / state divergence between peers | wholeness-witness Merkle + equivocation detection |
| Resurrect a revoked key via "reconstitute from any fragment" | the witness *triggers* quorum-merge, never decides it; anti-rollback preserved |
| Re-attribute deniable/`self` content to a stable peer | anonymous/`self` namespace exclusion |
| Launder trust into membership via a transitive chain | trust≠membership; owner-binding + consensus gate; ≤5-hop + cycle-reject + weight cap |
| Forge a holding claim to force-evict a rival's content | possession-bound rarity |
| Poison a decode with a bad swarm symbol | per-symbol integrity against the signed manifest |
| Eclipse the relay tree with a capacity lie | verify-before-score + bounded capacity term |
| Keep revoked content alive as "rare" | retention-respects-revocation; forced descent below the floor |
| Pass a dominated or near-duplicate fold as a blur | dominance gate + multiplicity gate (CC 6.1.2) |
| Claim a tier was aggregated from sources it wasn't | `member_commitment` recomputation |

## Conformance

The vector family is the cross-impl byte-equality proof for these shapes:

- **Witness / bootstrap / fountain / A/V** — vectors in `tests/vectors/substrate_v19/`,
  checked by `tests/conformance_vectors_v19.rs`, reproduced byte-for-byte by both
  CIRISEdge and CIRISVerify.
- **ALM relay capacity** — `relay_capacity/canonical_bytes.json`, derived from the
  layout independently of the Rust builder.
- **Aggregation pyramid** — authored by CIRISVerify (`tests/vectors/substrate_v19_7/`,
  emit-or-verify in `tests/conformance_vectors_v19_7.rs`), reproduced by CIRISEdge.
  The v3 vector is internally reproducible: `n_eff` and `mass_commitment` recompute
  from its own published fields.

A wire-shape drift in either implementation fails the conformance suite.

## Cross-repo topology

```
CIRISConstitution — CC 6.1 (normative); CEG §19 carries the wire labels
       │
CIRISEdge      — producer: emits the substrate objects (RaptorQ codec, ALM planner,
       │          aggregation operator); reproduces the vectors
CIRISVerify    — verifier: this module. Enforces the guardrails; authors the
       │          aggregation vectors
CIRISPersist   — substrate: calls the verify gates at ingest; consumes
                  EjectionVerdict to drive put_aggregated_tier / evict
```
