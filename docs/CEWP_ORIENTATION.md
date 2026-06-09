# CEWP Orientation — where CIRISVerify sits

*Captured per CIRISVerify#43. This is orientation, not specification —
it keeps the surface this repo maintains aimed at the right platform
targets. The authoritative platform docs live in CIRISNodeCore.*

## The platform premise + bet

> **CEWP's premise: big tech is not necessary.**
> **CEWP's bet: cryptographic substrate + standardized ethical tracing prove it.**

CEWP = **C**IRIS **E**pistemic **W**eb **P**latform (pronounced "soup").
The "cryptographic substrate" half of that sentence is **this repo**.
Without verify-class primitives running at consumer-hardware cost, the
claim that the substrate runs without datacenters is unfounded — so
CIRISVerify's benchmarks *are* the empirical bet, not decoration. See
[`benches/federation_crypto.rs`](../src/ciris-crypto/benches/federation_crypto.rs)
and the liboqs cross-check ([`benches/liboqs_comparison.rs`](../src/ciris-crypto/benches/liboqs_comparison.rs),
CIRISVerify#53) for the measured numbers behind the claim.

## The seven-repo Agent 3.0 substrate

```
                       ┌─────────────────┐
                       │ CIRISAgent/client│  client (Kotlin Multiplatform)
                       │  (CIRISGUI is    │  — CIRISGUI is ORPHANED, do not target
                       │   orphaned)      │
                       └────────┬────────┘
                       ┌────────▼────────┐
                       │   CIRISAgent    │  agent runtime (H3ERE)
                       └────────┬────────┘
        ┌───────────────────────┼───────────────────────┐
 ┌──────▼──────┐        ┌───────▼──────┐         ┌───────▼──────┐
 │ CIRISNodeCore│       │ CIRISLensCore│         │ CIRISRegistry│
 │ (consensus) │        │ (detection)  │         │ (CEG+identity)│
 └──────┬──────┘        └───────┬──────┘         └───────┬──────┘
        └───────────────────────┼───────────────────────┘
        ┌───────────────────────┼───────────────────────┐
 ┌──────▼──────┐        ┌───────▼──────┐         ┌───────▼──────┐
 │  CIRISEdge  │        │ CIRISPersist │         │ CIRISVerify ←│
 │ (transport) │        │  (storage)   │         │  (crypto)    │
 └─────────────┘        └──────────────┘         └──────────────┘
```

## What CIRISVerify owns in that picture

The layer that makes "cryptographic accountability" real rather than a
slogan:

- **Hybrid sign/verify** (Ed25519 + ML-DSA-65) — every wire artifact in
  CEWP is signed and verified here. `ciris-crypto::hybrid`.
- **HardwareSigner trait family** — TPM / Android Keystore / Secure
  Enclave / SoftwareOnly. Identity rooted in cryptography, not a
  corporate database. `ciris-keyring`.
- **Merkle transparency log** — the auditable substrate behind every
  claim. `ciris-verify-core::transparency`.
- **HKDF / HMAC / AES-256-GCM** — encryption at rest (the substrate-floor
  invariant). `ciris-crypto::{kdf,hmac,aes_gcm}`.
- **Build manifest verifier** — supply-chain attestation surface.
- **PQC KEX + key_grant** (X25519 + ML-KEM-768) — harvest-now-decrypt-later
  closure for transport payloads. `ciris-crypto::{hybrid_kex,key_grant}`.
- **Federation trust-root substrate** — `FederationKeyset` (M-of-N
  rotation) + `infrastructure_community` (CEG 0.11 `cohort_subkind:
  infrastructure` trust root, CIRISVerify#31).
- **RNG health-check** — SP 800-90B startup gate, fail-secure
  (CIRISVerify#55). The entropy provenance the rest of the stack
  assumes.
- **Document integrity** — hybrid-signed governance-doc attestation
  (CIRISVerify#54). The substrate's own threat model is in-scope.

## The L0/L1/L2 tier model — how it touches this repo

CEWP runs in three tier postures (set via the agent runtime's
`AgentMode`, surfaced at `/v1/system/agent-mode`). The HardwareSigner
posture is the part that lands here:

| Tier | Posture | HardwareSigner (typical) |
|---|---|---|
| **client** | strict, trust depth 0 | mobile: Android Keystore / iOS Secure Enclave; desktop: `Ed25519SoftwareSigner` |
| **proxy = L0 server** | strict, trust depth 0 | `SoftwareSigner` w/ seed file, optional TPM (user laptop) |
| **server = L1** | trust depth 1 | TPM-backed (`KeyringStorageSigner`) — hosted-operator production posture |
| (future) L2+ | trust depth 2+ | as L1 |

The **authentication ≠ trust** invariant (CIRISVerify#28 / `MISSION.md`
§1.4) is the load-bearing rule across all tiers: verifying a primitive
authenticates *origin* only; trust degree is a separate, explicit,
default-deny axis. A tier is a trust-depth posture, not a verification
shortcut — the crypto checks are identical at every tier.

## Authoritative platform docs (CIRISNodeCore)

- `FSD/CEWP.md` — the platform-identity FSD
- `FSD/FEDERATION_SCALING_MODEL.md` — quantitative model (5 B users at
  v1 on commodity hardware)
- `FSD/ANONYMOUS_TIER.md` — v2 deniability path
- CIRISNodeCore#23 — substrate state matrix / alignment audit

## Maintenance heuristic

When you add or change a primitive here, ask: *does this keep the
"cryptographic substrate runs without datacenters" claim true at
consumer-hardware cost?* If a change regresses a benchmark or moves a
verification cost off commodity hardware, that's a platform-level
regression, not just a local one — the benchmark suite is the gate.
