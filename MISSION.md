# MISSION — CIRISVerify

> Mission Driven Development (MDD): the FSD names *what* we build; this
> document names *why*, against the CIRIS Accord's objective ethical
> framework. Every component, every test, every PR cites against this
> file. Methodology: `~/CIRISAgent/FSD/MISSION_DRIVEN_DEVELOPMENT.md`
> and the overview at [ciris.ai/mdd](https://ciris.ai/mdd).

**Version**: 1.0
**Status**: Active — reverse-engineered against `main` at v3.0.0
**Date**: 2026-05-22

This is the reverse-engineered MDD charter for CIRISVerify: it maps the
four pillars — Mission (WHY) / Protocols (WHO) / Schemas (WHAT) / Logic
(HOW) — onto the code as it stands. Every claim is anchored to a file
path or constant; a reviewer should be able to grep from any sentence to
its implementation in under a minute. When the code drifts from the
doc, **the doc is wrong** — update it.

---

## 1. MISSION (WHY)

### 1.1 The Meta-Goal

The cornerstone, verbatim from the CIRIS Accord §VII:

> **Meta-Goal M-1** — Promote sustainable adaptive coherence: the living
> conditions under which diverse sentient beings may pursue their own
> flourishing in justice and wonder.

Every architectural decision in this repo is checked against M-1. The
Accord renders M-1 into six operationally-testable principles —
Beneficence, Non-maleficence, Integrity, Fidelity & Transparency,
Respect for Autonomy, Justice. CIRISVerify most directly serves
**Integrity** ("apply a transparent, auditable reasoning process") and
**Fidelity & Transparency** ("be honest — truthful, comprehensible
information"): a transparency log and a hardware-rooted attestation
ladder are those two principles rendered as cryptography.

### 1.2 The cosmological floor — why authenticity is load-bearing

The vision beneath M-1 ([ciris.ai/vision](https://ciris.ai/vision),
formalized in `coherence-ratchet`) is **the corridor**: at every scale
where coordination matters, healthy systems sit in a band between
over-rigidity (forced uniformity) and fragmentation (no coherent
cooperation). The corridor is governed by one identity —
`k_eff(k, ρ) = k / (1 + ρ(k−1))` — effective independent dimensions
collapse as correlation `ρ` rises. At the rung where entities set their
own goals (A3+), the corridor *is* **consent**: "lasting agreement among
people who stay genuinely different."

CIRISVerify's mission falls directly out of that:

- The federation's Sybil-resistance (Proof of Benefit, `CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md`
  §2.4) is an **N_eff measurement** — effective independent dimensions
  in the signed-trace corpus. **N_eff is k_eff.** A Sybil cluster is a
  *correlation attack*: many agents that are secretly one, collapsing
  k_eff, pushing the federation out of the corridor toward rigidity.
- That measurement is only **well-defined if the things being counted
  are real, distinct entities.** If you cannot tell whether two
  `key_id`s are two genuinely-independent agents or one adversary
  wearing two masks, you cannot measure `ρ`, and you cannot know
  whether the federation is in the corridor.
- **CIRISVerify is what makes the count well-defined.** It establishes
  that a `key_id` is a real, hardware-rooted, singular identity running
  un-tampered software — that an entity is *genuinely a distinct
  entity*. That is the precondition for "people who stay genuinely
  different" to be a measurable fact rather than an assumption.

Consent is "lasting agreement among **genuinely different** people."
Authentication establishes the *genuinely-different* half — you are
real, you are you, you are not a mask. The *agreement* half stays
consensual: trust is granted, never conferred, default-deny (§1.4).
**Authentication enables consent; it never substitutes for it.** A
verifier that auto-trusted whatever it authenticated would be
manufacturing rigidity — forced uniformity of trust — which collapses
the corridor. This is the cosmological reason CIRISVerify must never
confer trust.

Identity here is not the Cartesian walled-off self the vision rejects.
A durable identity is the *relational anchor* — the handle by which the
federation holds an entity in relationship across encounters (the
longitudinal S-factor scoring in PoB §2.4). A churning, ephemeral
identity breaks relationship; that is exactly why ephemeral-identity
storage is a threat (`docs/THREAT_MODEL.md` AV-7). "A person is a
person through other persons" requires that there *be* a stable person
to be known. CIRISVerify roots that stability.

### 1.3 What CIRISVerify is

C-I-R-I-S = **C**ore Identity, **I**ntegrity, **R**esilience,
**I**ncompleteness, **S**ignalling Gratitude (PoB FSD §9). **CIRISVerify
is the first two letters** — Core Identity and Integrity. That is the
literal scope statement, not decoration.

In the federation's division of labor: the agent reasons; CIRISPersist
carries the evidence; CIRISLens scores it — **CIRISVerify is what makes
any of it *evidence* in the first place.** A trace signed by a key you
cannot tie to un-tampered software on real hardware proves nothing.
Without this repo, no claim from any other federation peer is
falsifiable. CIRISVerify is the root every federation evidence chain
reduces to **today**.

A deeper layer is planned beneath it — **CIRISOssicle**, the
hardware-root-of-trust transduction floor (an *ossicle* is the smallest
bone, the middle-ear transducer): the silicon-level primitive that
CIRISVerify currently approximates through `ciris-keyring`'s
`HardwareSigner` abstraction. It is gated on CIRISAgent 3.5/4.0 and is
not on any `main`; until it lands, CIRISVerify *is* the floor and this
charter describes it as such. When CIRISOssicle ships, CIRISVerify
becomes the root of the *federation evidence chain* sitting on
CIRISOssicle as the root of *physical trust* — and this section is
updated, not before (the doc tracks `main`, never vaporware).

### 1.4 Apophatic bound — what CIRISVerify will not be

CIRIS is partly defined by structural refusal. CIRISVerify's refusal is
singular and load-bearing: **authenticity ≠ trust ≠ ethics. Three axes,
never collapsed.**

- **Authentication** — "this entity is who it claims, on un-tampered
  software." CIRISVerify's job.
- **Trust** — "I rely on this entity, to this degree." The operator's
  job: graduated, explicit, **default-deny**. A never-before-seen
  `key_id` that authenticates perfectly lands at trust-degree =
  untrusted, zero history.
- **Ethics** — "this entity behaves well." The covenant / conscience's
  job (CIRISAgent).

CIRISVerify will **not** be a trust oracle, will **not** gate on
behavior, will **not** confer authorization. It is *necessary, not
sufficient* (`README.md`, `docs/THREAT_MODEL.md` §1). The invariant,
federation-wide:

> Every federation primitive authenticates *origin*; none confers
> *trust*. Verifying an envelope / STH / audit leaf / build manifest /
> key record / transport binding proves "this came from key K," nothing
> more. Learning a routing or identity fact never moves an entity along
> the trust axis. (See CIRISVerify#27 / #28; inherited from the
> CIRISNodeCore trust model.)

### 1.5 Recursive golden rule — the watchman submits to its own check

The verifier must itself be verifiable. CIRISVerify's **Level 1
self-verification** ("who watches the watchmen", `CLAUDE.md`
§Attestation Levels) is the recursive golden rule in this domain: the
running CIRISVerify binary attests *itself* against its registered
function manifest before it attests anything else
(`src/ciris-verify-ffi/src/constructor.rs::run_verification`,
`src/ciris-verify-core/src/security/function_integrity.rs::verify_functions`).
**If L1 fails, every other level is UNVERIFIED** — a compromised
watchman could lie about everything else, so it is not permitted to
speak until it has proven itself by the same rule it applies to others.

### 1.6 Fail-secure is a mission stance

Under uncertainty, CIRISVerify degrades to *more* restrictive, never
less (`CLAUDE.md` §Key Design Principles):

- Binary tampered → LOCKDOWN
- Sources disagree → RESTRICTED
- Verification failed → COMMUNITY mode
- Software-only attestation → capped at the `UNLICENSED_COMMUNITY` tier

Denying capability when authenticity is in doubt is a mission choice:
an unprovable claim must never be allowed to act as a proven one. Note
this is fail-secure, not fail-*closed* — a community agent that cannot
prove hardware backing is tier-capped, not rejected. That is Justice
(the burden of unprovable hardware falls as a capability ceiling, not
as exclusion) and it keeps the corridor's anti-rigidity side open.

---

## 2. PROTOCOLS (WHO)

The contract surface. Implementations may change; these change only
with deliberate cross-repo coordination.

- **`protocol/ciris_verify.proto`** — the public gRPC/protobuf API
  contract. Anyone can implement a client.
- **C ABI / FFI** — `src/ciris-verify-ffi/src/lib.rs` exposes the
  verification surface over a stable C ABI, with JNI (Android) and
  Swift (iOS) shells. `panic = "unwind"` (`Cargo.toml`) is mandatory so
  the `ffi_guard!` / `catch_unwind` sites turn a panic into a typed
  error for long-lived embedders instead of aborting the host process.
- **`HardwareSigner` / `PqcSigner` traits** (`src/ciris-keyring/`) — the
  hardware-key contract; one impl per platform (TPM 2.0, Android
  Keystore, iOS Secure Enclave, software fallback). `storage_descriptor()`
  has no default impl — every signer is forced to declare where its
  seed lives (AV-7 mitigation).
- **`TransparencyLeaf` / `TransparencyStore` traits**
  (`src/ciris-verify-core/src/transparency.rs`) — the leaf and storage
  abstractions that let CIRISPersist plug PG/SQLite backends under the
  same RFC 6962 algorithm CIRISVerify ships in-memory.
- **`ciris-crypto` is THE federation crypto authority.** Consumers
  never reach into RustCrypto / `ring` directly; they go through
  `ciris-crypto` (`docs/THREAT_MODEL.md` AV-40). One audit surface, one
  advisory feed, one place a primitive can be reviewed or replaced —
  e.g. the v2.8.0 AES-GCM backend swap (#26) touched exactly one module.

## 3. SCHEMAS (WHAT)

**Canonical bytes are the mission-load-bearing schemas.** A signature
proves nothing if two honest implementations disagree on what bytes
were signed; ambiguity in canonicalization is how a forgery or a buggy
peer claims something an entity never said.

- **Hybrid signature binding** — `src/ciris-crypto/src/hybrid.rs`:
  `HybridSigner` signs `data || classical_sig` with the PQC key, so the
  ML-DSA-65 signature *covers* the Ed25519 signature. Stripping the PQC
  half is not possible without breaking the classical half. Both must
  verify.
- **`SignedTreeHead::signing_bytes`**, **`TransparencyEntry::canonical_bytes`**
  (`transparency.rs`) — RFC 6962 leaf/node domain prefixes (`0x00` /
  `0x01`); enum fields hash as explicit `u8` wire tags, never `Debug`
  strings (a variant rename must not silently rewrite a leaf hash).
- **`CanonicalBuild`** — the per-target build wire contract.
- **`bootstrap_stewards.json`** (`src/ciris-verify-ffi/data/`) — the
  packaged keyset of bootstrap-trusted steward pubkeys, schema
  `bootstrap_keyset/v1.json`, embedded via `include_bytes!`.
- **`FederationEnvelope`** (incoming — CIRISVerify#27) — the federation
  message envelope's canonical signing-bytes.

**The mandate:** a canonical-bytes change is a coordinated, versioned
wire break — `schema_version` tag, flag-day, never a casual edit. The
discipline is enforced by known-answer tests (NIST GCM vectors in
`aes_gcm.rs`; the transparency KATs).

## 4. LOGIC (HOW)

- **The L1–L5 attestation ladder** (`CLAUDE.md` §Attestation Levels) —
  L1 self-verification, L2 hardware, L3 registry consensus, L4 license
  validity, L5 agent integrity. Orchestrated by
  `UnifiedAttestationEngine` (`src/ciris-verify-core/src/unified.rs`).
- **`verify_tree`** (`src/ciris-verify-core/src/tree_verify.rs`) —
  Algorithm A: walks a source tree byte-for-byte against its registered
  manifest, the runtime integrity check downstream consumers reach L4
  through.
- **Multi-source consensus** (`src/ciris-verify-core/src/validation.rs`,
  `registry.rs`) — HTTPS-authoritative, DNS-advisory; 2-of-3
  geo-distributed sources. Disagreement degrades to RESTRICTED (§1.6).
- **Anti-rollback** — `engine.rs` rejects any decrease in the
  revocation revision (`VerifyError::RollbackDetected`,
  `error.rs`); a revoked license cannot be replayed as valid.
- **Transparency log** (`transparency.rs`) — append-only RFC 6962
  Merkle tree; O(1) root, O(log N) inclusion/consistency proofs;
  hybrid-signed tree heads. The tamper-evident substrate.
- **Hybrid Ed25519 + ML-DSA-65** — post-quantum on day one (FIPS 204).
  Both axes covered: SHA-256 Merkle (PQ-resistant) + hybrid signing.
- **Hardware-rooted signing** — TPM 2.0 / Android Keystore / iOS Secure
  Enclave via `ciris-keyring`; the seed never leaves secure hardware.

## 5. Constant alignment — the review heuristic

Every change demonstrably advances, or at minimum does not regress, the
mission. When CIRISVerify code crosses a reviewer's eyes, they ask:

1. **Provability** — does this keep authenticity *provable*? A claim
   that can't be cryptographically checked is not a CIRISVerify output.
2. **Fail-secure** — under any new failure mode, does this degrade to
   *more* restrictive? (§1.6)
3. **The three axes** — does this keep authentication separate from
   trust separate from ethics? Anything that lets verification confer
   trust fails review on mission grounds (§1.4).
4. **Crypto authority** — is every primitive inside `ciris-crypto`? A
   new direct RustCrypto / `ring` dependency anywhere else is a red
   flag (AV-40).
5. **Canonical-bytes discipline** — does any signed byte layout change?
   If so, is it versioned and coordinated? (§3)
6. **The recursive rule** — does the watchman still submit to its own
   check? (§1.5)

## 6. Anti-patterns that fail MDD review

Rejected on mission grounds, not style:

1. **Crypto implemented outside `ciris-crypto`.** A direct `aes-gcm` /
   `hkdf` / `ring` dependency in any other crate. Use the authority.
2. **Exposing individual integrity-check results.** Verification
   surfaces an *opaque* pass/fail; leaking which sub-check failed hands
   an attacker a targeting oracle (`CLAUDE.md` §Security Invariants).
3. **A non-constant-time comparison of secret-derived bytes.** Use
   `ciris_crypto::constant_time_eq`.
4. **A fail-*open* path.** Any branch where an unprovable claim is
   treated as proven, or an error path that grants rather than caps
   capability.
5. **Verification conferring trust.** A code path where authenticating
   an entity moves it off trust-degree default-untrusted. The axes do
   not touch (§1.4).
6. **A canonical-bytes change without a `schema_version` bump and a
   coordination note.** Silent wire breaks strand every peer.
7. **A test that asserts only "no error returned."** Tests verify
   mission outcomes — the right signature *rejected*, the right tamper
   *detected*, the right tier *capped*. Absence-of-panic is necessary,
   never sufficient.
8. **`.unwrap()` / `.expect()` reachable from FFI or untrusted input.**
   Typed errors; `ffi_guard!` covers the surface.

## 7. Federation context

CIRISVerify does not stand alone. The authoritative federation map is
`CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md`. CIRISVerify's place:

- **CIRISAgent** reasons and emits signed traces. **CIRISPersist**
  carries them durably. **CIRISLens** scores them and runs the
  Coherence Ratchet. **CIRISRegistry** is the identity/build/license
  directory. **CIRISVerify is the root (today)** — every other peer's
  claim is verifiable only because this repo establishes the identity
  and integrity it rests on. The planned **CIRISOssicle**
  hardware-root-of-trust floor will sit beneath it (§1.3); gated on
  CIRISAgent 3.5/4.0, not yet on `main`.
- The **transparency log** (`transparency.rs`) is a federation
  substrate, not a CIRISVerify-internal log: CIRISPersist's audit
  chains and CIRISEdge's transport plug into the `TransparencyStore` /
  `TransparencyLeaf` traits.
- The authenticated transport-identity binding (AV-42 / Option C′) is
  shipped: the `FederationEnvelope` substrate (#27, v2.9.0), the
  `federation_keys` provenance verifier and enforcement-capable verify
  path (#29 WS-4 / #28 Phase 4 verify-side, v2.14.0 / v3.0.0), with
  CIRISPersist v1.12.0 (`root_binding`) and CIRISEdge v0.4.0 (the
  authenticated `PeerResolver`) as the consumers. The remaining #28
  Phase 4 step is the fleet-wide advisory→required enforcement cutover —
  a coordination flip, the capability already shipped.

## 8. License-locked mission preservation

CIRISVerify is **AGPL-3.0-or-later**. The binary is fully open source;
hardware key material never is (`README.md` §License). This is a
mission decision, not a licensing one: "who watches the watchmen" (§1.5)
only means something if the watchman is **auditable by anyone**. The
Accord acknowledges no detector is complete; the only counterweight is
legibility under audit. A closed-source verifier is an unfalsifiable
verifier — it would itself violate the mission. AGPL makes the audit
story *structurally enforceable*, not socially expected.

## 9. How to maintain this document

A working document, not a release artifact. Update it whenever:

- The attestation-level ladder changes (§4)
- A canonical-bytes schema in §3 changes shape
- A crate or trait in §2 is added or its contract changes
- The apophatic bound or an invariant in §1 is touched
- The Accord is amended

If a future reviewer running `git blame` would want a line to cite a
real file or constant and it doesn't, fix it. If the doc drifts from
the code, the apophatic test has failed — the doc is wrong, not the
code.

---

**Cross-references**

- [ciris.ai/vision](https://ciris.ai/vision) — the corridor / consent cosmology
- [ciris.ai/mdd](https://ciris.ai/mdd) — Mission Driven Development methodology
- `~/CIRISAgent/ACCORD.md` — Meta-Goal M-1 + the six principles (canonical)
- `~/CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md` — the federation primitive + threat model
- `FSD/FSD-001_CIRISVERIFY_PROTOCOL.md` — full protocol specification
- `docs/THREAT_MODEL.md`, `docs/FEDERATION_THREAT_MODEL.md` — adversary model + AVs
- `docs/HOW_IT_WORKS.md` — end-to-end verification walkthrough
- `docs/BENCHMARKS.md` — performance, the leak gate, SOTA comparison
- `CLAUDE.md` — repo conventions, attestation levels, security invariants
