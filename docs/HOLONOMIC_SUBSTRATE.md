# Holonomic Substrate Verifiers (CEG §19 / §19.7)

**Status:** `ciris_verify_core::holonomic` — shipped, cross-impl-proven.
**Last updated:** 2026-06-16 (CEG 1.0-RC16: §19 proven vs CIRISEdge v4.1.2; §19.7 **promoted RC→1.0**, proven vs CIRISEdge v4.3.0).

CIRISVerify is the **cross-impl verifier home** for the CEG §19 *holonomic
substrate* — the federation's graceful-degradation / graceful-reconstitution
layer absorbed from CIRISEdge with normative guardrails. This document is the
threat-model + conformance reference for that subsystem. The wire shapes are
CEG's ([`CIRISRegistry/FSD/CEG/19_holonomic.md`]); this module is where the
guardrails become *enforced*, and (for §19.7) where the conformance vectors are
*authored*.

## Why it exists

The holonomic substrate gives the federation two properties:

- **Graceful degradation** — any subset of RaptorQ fountain symbols decodes at
  proportional fidelity.
- **Graceful reconstitution** — a witnessed, trust-anchored corpus re-establishes
  from any sufficient fragment.

The adversarial review of CIRISEdge v4.0.0 (→ CIRISEdge#143) found the *concept*
sound but the *guardrails* unenforced. **Verify is where they become real:**
several §19 enforcement gates live exactly where Verify already sits (hybrid
verification, Merkle, threshold). An edge-produced object that violates a
guardrail is *rejected here*.

## The §19.0 canonicalization boundary (the shared foundation)

Every §19 object is **transport/substrate framing — NOT a §4 attestation**: it
never instantiates an `attestation_type`, never enters §0.9 JCS. It signs a
**binary, length-prefixed, big-endian, domain-separated preimage**
(`holonomic::Preimage`), the same `signing_bytes` carve-out §10.1.5.3 draws for
Verify. **PQC-mandatory at the gate** (`verify_bound_hybrid`): every object
carries the bound hybrid pair — Ed25519 over the preimage, ML-DSA-65 over
`preimage ‖ ed25519_sig` — and a missing/invalid ML-DSA-65 half is rejected
**at ingest and before persistence** (the §10.1.5.1.1 store-path rule; §19
objects are federation-tier). A verdict is recomputed at the gate; a
wire-carried `verified` flag is forgeable and is never trusted (the F-5 rule).

## Module map

| Module | §19 surface | Verifier-side invariants enforced |
|--------|-------------|-----------------------------------|
| `holonomic::preimage` | §19.0 framing + PQC gate | `verify_bound_hybrid` — **PQC-mandatory** (F-2), no classical-only, no in-band `verified` flag (F-5) |
| `holonomic::wholeness_witness` | §19.1 divergence witness | lexicographic-leaf Merkle (distinct from the §10.3 RFC-6962 log; **no prefix, frozen RC15**); N3 verify-at-ingest; **N4 equivocation** (two signed roots, same `(peer,epoch,ns-set)` → non-repudiable, surfaced never reconciled); WW-2 anonymous/`self` namespace guard; **divergence detector that *triggers* §10.1.6 quorum-merge, never replaces anti-rollback** (can't resurrect a revoked key) |
| `holonomic::bootstrap` | §19.2 recursive trust | **N1 trust ≠ membership** (the verdict type is structurally incapable of "admitted"); ≤5-hop, cycle-reject, §13.3 0.5×root_trust weight cap; `membership_blocked_without_owner_binding` (owner-binding + consensus for non-infra; founder-quorum for infra) |
| `holonomic::fountain` | §19.3 fountain storage | **N5** retention respects revocation (revoked → descent below floor regardless of rarity); **N6** possession-bound (unverified claims can't force-evict); **N7** per-symbol integrity; `symbol_ids` sorted |
| `holonomic::alm` | §19.4 ALM relay tree | **N8** capacity authenticity (verify `SignedRelayCapacity` *before* scoring); bounded capacity score (anti-eclipse); deterministic integer-only snapshot canonicalizer |
| `holonomic::av_chunk` | §10.5.8.3–.5 realtime A/V | `SealedAvChunk` header parse + the inner/outer double-seal nonce derivations (KAT-locked) |
| `holonomic::aggregation` | **§19.7 forever-memory** | `AggregationMetaV1` PQC-mandatory ingest gate; `member_commitment` descent integrity (reuses the §19.1 Merkle verbatim); `EjectionVerdict` tier-aware retirement (N5: revoked → hard-delete, never tier-shed) |

## §19.7 — the noise floor / forever-memory model

§19.7 reframes revocation / retirement / capacity-eviction / aging as **one
pressure-driven operator**: a monotonic descent of an item's fidelity toward and
below the **noise floor** (the individual-recoverability boundary). The floor is
load-bearing — it is simultaneously the **privacy boundary** (a revoked item
MUST be below it at every retained tier) and the **durability floor** (the
collective blur sits below it, forever). Descent never terminates at zero:
inter-object **N→1 aggregation** builds a mipmap of history, so remembering *all*
of history costs **O(log T)**, not O(T) — "a million years may be a blur, but it
is remembered, unbroken, to the beginning."

Verify's role is the verifier of the aggregation-tier metadata that tags that
pyramid:

- **`verify_aggregation_meta`** — the `AggregationMetaV1` PQC-mandatory ingest
  gate (the residual Persist#230 named). 16-byte `AGG-META-v1\0\0\0\0\0` domain,
  u32-lp/big-endian §19.0 framing.
- **`verify_member_commitment`** — descent integrity (§19.7.1.1): does a source
  member-id list re-derive the tier's committed Merkle root? Reuses the §19.1
  WholenessWitness Merkle **verbatim** — one Merkle scheme across §19.1 and
  §19.7, no fork.
- **`descend_order`** — the §19.7.2 lexicographic order `member_commitment`
  commits to (the descent-integrity contract).
- **`EjectionVerdict { Keep | EjectToTier | EjectAggregatedTierOnly { tier } |
  EjectHardDelete }`** — the tier-aware retirement surface persist consumes. The
  §19.3 N5 mapping is load-bearing: a revoked item → `EjectHardDelete` (the
  fastest descent, MUST purge, **never** tier-shed); capacity pressure →
  `EjectToTier`; targeted single-stratum pressure → `EjectAggregatedTierOnly`
  (RC16; sheds one pyramid level, leaving finer + coarser intact).

## Threat model — what each gate blocks

| Threat | Blocked by |
|--------|-----------|
| Forge a §19 object after a future Ed25519 break | PQC-mandatory `verify_bound_hybrid` (no classical-only at any §19 gate) |
| Trust a forged "I verified this" flag | F-5: verdict recomputed at the gate; in-band `verified` is non-wire |
| Split-view / state divergence between peers | WholenessWitness Merkle + N4 equivocation detection |
| Resurrect a revoked key via "reconstitute from any fragment" | WW-vs-§10.1.6: witness *triggers* quorum-merge, never decides it; anti-rollback preserved |
| Re-attribute deniable/`self` content to a stable peer | WW-2 anonymous/`self` namespace exclusion |
| Launder trust into membership via a transitive chain | N1 trust≠membership; owner-binding + consensus gate; ≤5-hop + cycle-reject + weight cap |
| Forge a holding claim to force-evict a rival's content | N6 possession-bound rarity |
| Poison a decode with a bad swarm symbol | N7 per-symbol integrity against the signed manifest |
| Eclipse the relay tree with a capacity lie | N8 verify-before-score + bounded (capped) capacity term |
| Keep revoked content alive as "rare" | N5 retention-respects-revocation; §19.7 forced descent below the floor |
| Claim a tier was aggregated from sources it wasn't | `member_commitment` recomputation (descent integrity) |

## Conformance status (§19.6 / #57 freeze gate)

The §19 vector family is the cross-impl byte-equality proof that lifts these
shapes from RC-grade to 1.0:

- **§19 (witness/bootstrap/fountain/AV) — PROVEN.** Vectors authored by
  **CIRISEdge v4.1.2**, reproduced byte-for-byte by **CIRISVerify v5.9.0**
  (`tests/vectors/holonomic_v19/`, `tests/conformance_vectors_v19.rs`). The
  Merkle matched with no change; the preimage encoders reconciled to the v4.1.2
  framing exactly.
- **§19.7 (aggregation pyramid) — 1.0, PROVEN.** Because no reference impl
  predated these bytes, **CIRISVerify v5.10.0 authored the vector family**
  (`tests/vectors/holonomic_v19_7/`, emit-or-verify in
  `tests/conformance_vectors_v19_7.rs`); **CIRISEdge v4.3.0 reproduced them
  byte-for-byte on the first attempt with no coordination beyond the spec.** The
  §19.7 freeze gate is **closed** — §19.7 is 1.0, not RC.

A wire-shape drift in either implementation fails the conformance suite (the
emit-or-verify discipline).

## Cross-repo topology

```
CIRISRegistry  — locks the wire in CEG §19 / §19.7
       │
CIRISEdge      — producer: emits the §19 objects (RaptorQ codec, ALM planner,
       │          aggregation operator); reproduces / co-authors the vectors
CIRISVerify    — verifier: this module. Enforces the guardrails; authored the
       │          §19.7 vectors; reproduced the §19 vectors
CIRISPersist   — substrate: calls the verify gates at ingest (the store-path
                  §10.1.5.1.1 PQC rule); consumes EjectionVerdict to drive
                  put_aggregated_tier / evict (Persist#229 / #230)
```

## References

- CEG spec: `../CIRISRegistry/FSD/CEG/19_holonomic.md` (§19 / §19.7)
- Adoption issues: CIRISPersist#229 / #230 (ingest gate), CIRISEdge#143 / #144 /
  #152 (producer conformance + vectors)
- Tracking: CIRISVerify#78 (§19), CIRISVerify#79 (§19.7)
