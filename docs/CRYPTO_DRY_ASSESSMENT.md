# Crypto DRY Assessment — CIRIS ecosystem vs CIRISVerify (canonical)

**Scope:** CIRISPersist, CIRISEdge, CIRISServer, CIRISAgent audited against CIRISVerify as the canonical crypto authority.
**Method:** 8 finder agents (4 repos × 2 lenses) → per-finding adversarial verification (skeptical-by-default, both codebases read) → this synthesis.
**Date:** 2026-07-15. Verify baseline: v10.3.0.

> Provenance note: 49 raw findings → **35 adversarially confirmed**, **4 rejected**, **10 unverified** (their verifier agents hit a model rate limit — listed separately; several are corroborated by confirmed siblings). Verdicts include category/severity corrections applied by the verifier.

---

## Executive summary

| Category | Confirmed | What it means |
|---|---:|---|
| **re-implementation** | 15 | production code hand-rolls crypto the wheel/rlib already exposes |
| **mis-implementation** | 10 | implements a verify construction but diverges (byte layout, policy, or algorithm) |
| **gap-in-verify** | 8 | the ecosystem needed it; verify doesn't expose it → repo had to hand-roll |
| **mis-attribution** | 2 | claims "verify-authored / same as verify" that verify doesn't back |
| _rejected_ | 4 | survived to a verdict of not-a-finding |
| _unverified_ | 10 | finder-stage only (rate limit) — need a verdict |

**By repo (confirmed):** Agent ~11, Persist ~9, Edge ~9, Server ~6.

### The three things that matter most

1. **🔴 The canonical provenance-chain verifier is broken — and it's in CIRISVerify.** `provenance::verify_provenance_chain` verifies scrub-signatures over the **32-byte `original_content_hash`**, but verify's *own* producers (`federation_self_record::produce_self_key_record` / `produce_scrubbed_key_record`) sign the **JCS-canonicalized `registration_envelope`**. So the canonical verifier rejects every record its own producers emit. This was empirically confirmed against the real baked A1 accord-holder record (CIRISPersist#344) — and it **forced CIRISPersist to fork the entire chain-walk** (`rooting.rs`). Persist's fork is the only correct trust-root verifier in the ecosystem today. **Fix must start in verify** (switch the preimage to JCS envelope + fix the `make_link` test fixture that masks the bug), then persist's fork collapses onto it. _(mis-implementation in verify, high; re-implementation in persist, high.)_

2. **🔴 Kill-switch / accord crypto is fractured and classical-only in the very places the hybrid+quorum invariant exists for.** The Agent runs a *complete parallel* accord protocol (`schemas/accord.py`) — classical-only Ed25519 over a 13-byte `struct.pack(">IB8s")` preimage, no domain separation, no nonce, **1-of-1 hardcoded ROOT key**, 24h (±) replay window, no anti-replay ledger — wired live into message perception and executing `SHUTDOWN_NOW`. Edge's wire-layer accord-carrier gate (`edge.rs:6425`) is **Ed25519-only** (drops verify's `RequireHybrid`) **and counts spares as seats** (`A1+A2` satisfies 2-of-N, violating one-seat-per-human). The Agent additionally carries **four mutually-incompatible emergency-shutdown preimages** (`accord.py` struct-pack, `emergency.py` spaced-`json.dumps`, `control_service` pipe-join, `wise_bus` compact-JSON) — two of which sit on the *same* request path and cannot both pass.

3. **🟠 The hybrid bound-signature rule is re-composed by hand in ~7 places — and one of them is wrong.** `pqc = Sign_PQC(data ‖ ed25519_sig)` is hand-assembled in server lens-core (3 sites), persist `signing/mod.rs`, edge `identity.rs`/`capacity.rs`. The **KMP `FederationSigner.kt` signs ML-DSA over the raw body, not `body‖ed_sig`** → any production signer wired to it produces signatures persist's `HybridPolicy::Strict` rejects. Root cause is a **gap**: the persist Engine PyO3 boundary exposes only the raw halves (`local_sign` / `local_pqc_sign`), and verify has no *async* HybridSignature-producing helper — so every caller re-derives the binding.

---

## Confirmed findings by category

### Re-implementation (production hand-rolls of exposed crypto)

| Sev | Repo | File | Finding | Verify counterpart |
|---|---|---|---|---|
| 🔴 high | Agent | `ciris_engine/schemas/accord.py:335` | Complete parallel accord kill-switch protocol: classical Ed25519 over `struct.pack(">IB8s")`, 1-of-1 hardcoded ROOT key, no quorum/nonce/domain-sep | `humanity_accord` (2/3 hybrid, `ciris.accord_invoke.v1\n` preimage) |
| 🔴 high | Agent | `emergency.py:86` + `control_service/service.py:689` + `wise_bus.py:416` | Four divergent kill-switch signing preimages; two on one request path can't both pass | `jcs` (`jcs_canonicalize`) + humanity_accord discipline |
| 🔴 high | Persist | `federation/rooting.rs:742-816` | Full provenance chain-walk re-implemented; diverges on preimage **and** hybrid policy (see #1 above) | `provenance::verify_provenance_chain_with_policy` |
| 🟠 med | Server | `ciris-lens-core/signing/event.rs:346` | `sign_detection` hand-composes the hybrid bound rule; comment admits "Replicates `sign_hybrid`… rather than calling it" | `ciris_crypto::hybrid::HybridSigner::sign` |
| 🟠 med | Server | `ciris-lens-core/ffi/pyo3.rs:352` | 2nd copy of the binding rule (`process_trace_batch`) | same; fix = one hybrid-sign verb across the Engine boundary |
| 🟠 med | Persist | `signing/mod.rs:447` | `LocalSigner` recomposes bound rule + raw-dalek plaintext path | `hybrid.rs` + `self_at_login::SelfSigner::sign_bound` |
| 🟠 med | Agent | `constants.py:114` | ACCORD manifest integrity: bespoke classical Ed25519, **fail-open** on missing sig/key, no version-binding; bundled `_wheel_locale_merkle` sits unused | `doc_integrity` / `locale_merkle` |
| 🟠 med | Agent | `schemas/accord.py:43-52,153` | Accord invoke: stale 24h window (docstring says 5 min), accepts future-dated, 1-of-1 | `humanity_accord.rs` |
| 🟡 low | Agent | `wise_bus.py:416` | Accord-invocation gate verifies over `json.dumps(sort_keys)` not JCS | `jcs` |
| 🟡 low | Agent | `my_data.py:1480` | DSAR delete signing bytes via `json.dumps`; cross-process contract with Lens | `jcs_canonicalize` |
| 🟡 low | Edge | `holonomic/wholeness_witness.rs` | Local twin of §19.1 WholenessWitness (Merkle+preimage+bound verify) despite depending on verify v10.3.0 | `holonomic::wholeness_witness` (+ `#267` re-export precedent) |
| 🟡 low | Edge | `holonomic/*` (4 sites) | Residual §19 preimage/Merkle twins (WW, fountain, CIRIS-CLAIM, ALM) | `holonomic::preimage` + siblings |
| 🟡 low | Edge | `transport/realtime_av.rs:425` | Re-derives §10.5.8 A/V AEAD nonces (`CIRIS-AV-INNER/OUTER-V1`) | `holonomic::av_chunk::{inner,outer}_nonce` |
| 🟡 low | Edge | `identity.rs:417` | Replay nonce via `Uuid::new_v4` bypassing the RNG facade (but 16B is the pinned wire size — don't widen) | `ciris_crypto::random::fill` |
| 🟡 low | Server | `ciris-lens-core/capture/seal.rs:287` | `verify_trace_signature` on raw `ed25519-dalek` (test-only callers, but pulls a direct dalek dep) | `ciris_crypto::Ed25519Verifier` |

### Mis-implementation (byte-, policy-, or algorithm-level divergence)

| Sev | Repo | File | Divergence | Pinned rule |
|---|---|---|---|---|
| 🔴 high | **Verify** | `provenance.rs:349-406` | Verifies over hash bytes while own producers sign JCS envelope → rejects every real record | own `federation_self_record::sign_bound` |
| 🔴 high | Edge | `transport/realtime_av_alm/capacity.rs:397` | `SignedRelayCapacity` shares domain `CIRISALM-CAPv2\0\0` with verify but **completely incompatible layout** (f32 vs u32 uplink, raw vs lp peer_id) → verify's §19.4 verifier is dead against real traffic; ALM absent from the §19 vector set | `holonomic::alm::signing_preimage` |
| 🔴 high | Edge | `edge.rs:6425`, `messages/mod.rs:829` | Accord-carrier quorum gate is **Ed25519-only** (no ML-DSA field on the wire) — classical-only satisfies a constitutional-traffic threshold | `threshold` `RequireHybrid` |
| 🟠 med | Edge | `edge.rs:6429`, `verify.rs:121` | Accord 2-of-N counted over all `accord_holder` rows distinct by key_id → **A1+A2 (one human) meets threshold** | `accord_roster_from_family` (spares excluded) |
| 🟠 med | Agent | `secrets/encryption.py:200` | AES key = **raw first 32 bytes of an Ed25519 signature** (the public R point), no hash/KDF; the HKDF path is unreachable (binding absent from ctypes client) | `derive_symmetric_key` (HKDF) |
| 🟠 med | Agent | `schemas/services/agent_credits.py:54` + `cirisnode/services.py:662` | `DualSignature` optional/unbound PQC (stripping hole); producer signs only `{interaction_id,timestamp}` — substantive fields uncovered | `hybrid.rs` bound rule + `RequireHybrid` |
| 🟠 med | Server | `src/accord.rs:1144` | Constitutional-halt nonce: `let _ = getrandom::fill(...)` degrades to **all-zero on RNG fault** (comment justifies only for non-binding kinds); same ignored-Result at `api_keys.rs:101` (predictable key), `session.rs:74` (zero salt) | `random`/`rng_health` fail-secure |
| 🟠 med | Agent | `dsar/signature_service.py:149` | Deletion "proofs" signed with **self-minted ephemeral RSA-2048** (off-suite, no custody, no PQC) on a public endpoint | hybrid signer / `doc_integrity` |
| 🟡 low | Agent | `emergency.py:71` | `/emergency/shutdown` verifies over `json.dumps(sort_keys)` (spaces, ensure_ascii) not JCS | `jcs_canonicalize` |
| 🟡 low | Agent | `agent_credits.py:54` (schema) | (dup of above from the drift lens) unbound optional PQC "hybrid-pending" pattern verify retired in #75 | `hybrid.rs` / `RequireHybrid` |

### Gap-in-verify (verify should expose this; repo had to hand-roll)

| Sev | Repo | Need | Fix on verify side |
|---|---|---|---|
| 🟠 med | Agent | EVM tx preimage (RLP + keccak with **3-way keccak fallback** for real-money txs) built agent-side because `sign_evm_transaction` FFI only takes a 32-byte hash | `secp256k1.rs`: FFI that accepts tx fields (RLP+keccak inside the boundary) + expose `keccak256` / checksum-arbitrary-address |
| 🟠 med | Persist | `verify_strict` Ed25519 semantics (reaches for `ed25519-dalek` directly; two acceptance rules in one repo) | add a strict-verify mode to `ciris_crypto::Ed25519Verifier` |
| 🟡 low | Persist | RFC 6962 leaf hash re-implemented because `transparency::hash_leaf`/`hash_node` are `pub(crate)` | **make them `pub`** (one-line) |
| 🟡 low | Agent | Raw Ed25519/P-256 **verify** — wheel exposes `sign_ed25519` but no verify counterpart, so signer can't round-trip | add `ciris_verify_verify_ed25519` / `verify_p256` FFI + wheel |
| 🟡 low | Edge | SAS (Short Authentication String) cross-party derivation — no verify home (and edge's has a byte-sort weakness) | candidate `ciris-crypto::sas` module + FFI/wheel |
| 🟡 low | Edge | Async bound-hybrid sign/verify helper over `ciris-keyring`'s async signers | `self_at_login::SelfSigner::sign_bound` exists but is producer-shaped; a general async HybridSignature composer is missing |
| 🟡 low | Persist | CEG §10.5.2 stream-nonce prefix derivation lives only in persist; encoding unratified and omits verify's u32 length-prefix on `stream_id` | `epoch_key` owns the sibling `(stream_id, epoch)` encoding; add the §10.5.2 GCM-nonce variant |
| 🟡 low | Persist | Python-`json.dumps` canonicalizer (legacy 2.7.x traces) — no verify counterpart; deliberate migration-gated, retires on sunset | acceptable to leave persist-local |

### Mis-attribution

| Sev | Repo | File | Claim vs reality |
|---|---|---|---|
| 🟡 low | Edge | `holonomic/wholeness_witness.rs:59` | Comments cite the odd-layer duplicate-last-node rule as "**RFC 6962 CT convention**" — RFC 6962 does **not** duplicate (splits at largest power of two); only Bitcoin does. Bytes are correct; a 3rd implementer following the citation forks the root for any non-power-of-two leaf count. Verify's own doc pins it as "deliberately NOT RFC 6962." |

> Note: a verify-side self-gap surfaced repeatedly — **`ciris-keyring`'s own seal mints** (`sealed_ed25519.rs:87`, `sealed_mldsa65.rs:125`, `usb_wrapped_mldsa65.rs`, `transport_identity.rs`, `software.rs`) draw raw `OsRng`, bypassing the #74 SP 800-90B latch. The "no weak key is ever produced" invariant only holds for `ciris-crypto`-constructed keys, not keyring-sealed ones. Worth a tracking issue on verify.

---

## Gaps-in-verify roadmap (what to expose so downstreams stop hand-rolling)

Ordered by leverage:

1. **Fix `provenance.rs` preimage** (JCS envelope, not hash bytes) + the masking `make_link` test fixture. **Unblocks persist collapsing its rooting fork** and makes verify's own producers verifiable. _Highest leverage — it's a correctness bug in the canonical verifier._
2. **A single hybrid-sign verb** across the persist Engine PyO3 boundary (`Engine.local_sign_hybrid`) + an **async HybridSignature composer** in verify-core. Kills the ~7 hand-composed binding sites (and the wrong KMP one).
3. **`pub` `transparency::hash_leaf` / `hash_node`.** One line; deletes persist's copy.
4. **Strict-Ed25519 mode** in `ciris_crypto::Ed25519Verifier`. Retires persist's direct-dalek trace path and its two-acceptance-rules hazard.
5. **secp256k1 tx-fields FFI** (RLP+keccak inside the boundary) + `keccak256` / arbitrary-address checksum on the wheel. Removes the agent's 3-way keccak fallback on funds-moving txs.
6. **Raw Ed25519/P-256 verify FFI + wheel** binding. Lets Python consumers round-trip through verify.
7. **ALM §19.4:** pick one authoritative `SignedRelayCapacity` layout (edge's v2 is the producer), regenerate verify's preimage to match or bump to `CAPv3`, and **add the missing ALM entry + golden to the §19 cross-impl vector set** (its absence is why the divergence was never caught).
8. **`doc_integrity` on the wheel** (currently Rust-only) so the agent can produce hybrid verifiable-claim receipts instead of ephemeral RSA.
9. **Ratify the key_grant v2 algorithm string** (`x25519-mlkem768-...` hyphen vs persist's underscore) — CEG cross-confirm; two "pinned" wire identifiers exist for one construction.
10. **Arm `rng_health::run_startup_health_check`** in downstream boots (server/edge never call it, so the fail-secure latch is inert) and route keyring seal mints through `ciris_crypto::random::fill`.
11. (Optional) a **SAS module** if any non-edge surface ever needs to *derive* (not just display) the string — with the key-unit-ordering fix.

---

## Unverified findings (finder-stage only — verifier hit a rate limit)

These need a verdict pass. Several are **corroborated** by a confirmed sibling.

| Repo | File | Claim | Corroboration |
|---|---|---|---|
| Persist | `rooting.rs:805` | `HybridPolicy::Ed25519Fallback` on the trust-root path vs verify's `RequireHybrid` | **confirmed** inside the `rooting.rs:742-816` verdict |
| Agent | `emergency.py:71-86` | `json.dumps` not JCS on `/emergency/shutdown` | **confirmed** by the other lens |
| Server | `FederationSigner.kt:82` | KMP signs ML-DSA over body, not `body‖ed_sig` | standalone — **likely valid, medium**; wire-break to fix |
| Persist | `blobs.rs:223` | `ChunkManifest::to_jcs_bytes` hand-rolls JCS (u64 > 2^53 diverges from RFC 8785) | standalone — likely valid, low |
| Persist | `engine.rs:3327,3344` | partnership/`delegates_to` envelope member shape diverges from verify's pinned 7-member scores shape | standalone — likely valid, medium (#76 lineage) |
| Persist | `conformance_vectors_v19_7.rs:87` | pins only AggregationMeta v1/v2 golden; verify ships v3 (#191) | standalone — likely valid, low |
| Persist | `stream_seal.rs:96` | §10.5.2 stream-nonce info omits u32 length-prefix | standalone — likely valid, low (also a gap) |
| Persist | `media_sharing.rs:533` | key_grant algorithm string underscore vs verify's hyphen | standalone — likely valid, low |
| Server | `qa_runner/common.rs:374` | `invocation_canonical_bytes` re-implements humanity_accord bytes (test/example scope) | standalone — likely valid, low |
| Agent | `stage_runtime.py:77` | `ExemptRules` claims byte-for-byte parity with Rust but adds `exempt_filenames` the Rust walker can't represent | standalone — likely valid, low |

## Rejected (verified → not-a-finding)

- **Server `roles.rs` `verify_root_signature`** — single `ed25519-dalek` compiled in the graph; `Ed25519Verifier` is itself a dalek shim → zero drift risk, style preference only.
- **Edge `swarm_rarity.rs` fountain domains** — Edge **authored** the §19.3 format (`ciris-edge/` namespaced); verify byte-froze to Edge's v4.1.2 vectors. Companion-impl by design, not a dup. (The finding itself mis-attributed direction.)
- **Edge `sas.rs` (re-impl framing)** — exactly one impl exists; every deriving party links it (agent via wheel, server via Cargo dep, KMP fetches rendered). No reproduction obligation.
- **Agent `constants.py:166` (build-manifest attribution)** — ACCORD manifest is WA-root-signed agent-local infra crypto; the claimed producer/counterpart (`verify_build_manifest_contribution`) is a different artifact/trust-root. (The *locale_merkle* framing of the same file was confirmed separately.)
