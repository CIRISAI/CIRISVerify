# CIRISVerify

**The hardware-rooted trust anchor for AI agents.**

v6.0.0 · Rust + Python · AGPL-3.0 · Post-quantum from day one

CIRISVerify answers one question for any agent in the CIRIS ecosystem:
*is this agent who and what it claims to be?* It binds an agent's
identity to secure hardware, verifies its binary and files against a
signed registry manifest, records every verification in a tamper-evident
transparency log, and gates professional capabilities behind a
licensed-human accountability chain. Without it, any agent could
masquerade as any other.

It also **mints federation identities**: a hybrid (Ed25519 + ML-DSA-65)
hardware-rooted key — Ed25519 in a YubiKey / Secure Enclave / StrongBox /
TPM, the ML-DSA-65 seed sealed at rest — plus the signed CEG objects and
shareable identity codes (`fedcode`) the rest of the federation consumes.

It proves an agent is **authentic** — necessary, not sufficient. Ethical
*behavior* is the separate job of the CIRIS covenant system.

## Where we stand vs. the state of the art

| Capability | Industry SOTA | CIRISVerify |
|---|---|---|
| Transparency log | RFC 6962 — Google Trillian, Sigstore Rekor | RFC 6962-compliant Merkle log; O(1) root, O(log N) proofs ([benchmarks](docs/BENCHMARKS.md)) |
| Tree-head signing | Classical (Ed25519/ECDSA) | **Hybrid Ed25519 + ML-DSA-65** signed STHs — ahead of SOTA |
| Signature crypto | Mostly classical; PQ migration underway | **Post-quantum day one** — hybrid, FIPS 204 (ML-DSA-65) |
| Supply-chain integrity | Sigstore cosign, in-toto, SLSA | Signed per-file manifest + runtime tree verification |
| Hardware attestation | TPM remote attestation, App Attest, Play Integrity | TPM 2.0 + Android Keystore + iOS Secure Enclave, unified |
| Agent identity + capability licensing | *no established standard* | Hardware-bound identity + HITL accountability + capability gating |

**Honest read:** on transparency and cryptography CIRISVerify is *at or
ahead* of the state of the art — hybrid-signed tree heads and day-one
post-quantum coverage are both ahead of Trillian/Rekor, which are
classical. On hardware attestation it is at parity. As a *unified*
trust anchor for AI agents it is a new category with no direct peer.
Where it trails Trillian is durability and horizontal scale — Trillian
is a sharded, database-backed service; CIRISVerify is an embeddable
library with a pluggable `TransparencyStore` (CIRISPersist supplies the
PG/SQLite backends). That gap is deployment architecture, not algorithm.

**Response shape:** verify carries **measurements**, never verdicts.
The v3.2.0+ `federation_provenance` surface and v3.6.0+ `AttestBundle`
project the twelve canonical attestation dimensions (FSD-002 §3.2)
as named facts — `self_verification`, `hardware_attestation`,
`registry_consensus`, `license_validity`, `agent_integrity`, plus
`provenance` / `hardware_custody` / `transparency_log` / `cert_validity`
/ `rollback_detected`. Tier / level scoring is sugar the consumer
applies; verify never confers trust (`MISSION.md` §1.4).

## Federation identity (v6.0)

Beyond verifying agents, CIRISVerify is the federation's identity
primitive — it owns the local key ceremony, the rest of the fabric
consumes the result.

- **Hardware-rooted identity creation.** `ciris-verify identity create`
  roots the Ed25519 owner-binding in a YubiKey PIV key (`--provision`
  generates it; firmware ≥ 5.7, touch-required), seals the ML-DSA-65 PQC
  seed at rest (TPM with `--features tpm`, Secure Enclave / StrongBox on
  mobile), and drops a self-signed genesis `KeyRecord` in the CEG outbox
  (`~/ciris/ceg/outbox/`) for CIRISServer to relay. See
  [`docs/FEDERATION_IDENTITY.md`](docs/FEDERATION_IDENTITY.md).
- **`fedcode` — shareable identity codes** ([FSD-003](FSD/FSD-003_FEDERATION_IDENTITY_CODES.md)).
  One kind-tagged codec (user / agent / node / family / community,
  mapping onto the Constitution's `identity_type` + rostered
  `subject_kind`s), `CIRIS-V2-…` QR/text, `label-fingerprint` key_ids
  (collision-free by construction). `ciris-verify fedcode new` works with
  **software** keys (no hardware) — terminal + SVG QR, optional
  password-protected at-rest (PBKDF2 → AES-256-GCM).
- **Self-at-login** (CC §8.1.12.7) — bilateral user↔agent delegation +
  partnership + transport binding, WebAuthn presence the unlock factor;
  "revoke a lost device" via a surviving-key signature.

```bash
ciris-verify fedcode new --kind user --label eric-moore        # software, no token, with a QR
ciris-verify identity create --module libykcs11.so --label eric-moore --provision --pin
```

## Quick start

```bash
pip install ciris-verify        # platform wheel bundles the Rust binary
```

```python
from ciris_verify import CIRISVerify
import os

status = CIRISVerify().get_license_status(challenge_nonce=os.urandom(32))
if status.allows_licensed_operation():
    ...                          # professional capabilities available
else:
    print(status.mandatory_disclosure.text)   # must be shown to users
```

Build from source: `cargo build --release` then `pip install -e bindings/python/`.

## Documentation

| Doc | What |
|---|---|
| [`FSD/FSD-001`](FSD/FSD-001_CIRISVERIFY_PROTOCOL.md) | Full protocol specification (authoritative) |
| [`FSD/FSD-003`](FSD/FSD-003_FEDERATION_IDENTITY_CODES.md) | `fedcode` identity-code taxonomy + key_id format + onboarding (Constitution 0.1.5-grounded) |
| [`docs/FEDERATION_IDENTITY.md`](docs/FEDERATION_IDENTITY.md) | Operator runbook: provision a YubiKey → create your federation ID |
| [`docs/HOW_IT_WORKS.md`](docs/HOW_IT_WORKS.md) | How verification works, end to end |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Threat model + SOTA peer survey |
| [`docs/FEDERATION_THREAT_MODEL.md`](docs/FEDERATION_THREAT_MODEL.md) | Federation-tier threat model (F-AV-*, HNDL/PQC) |
| [`docs/HOLONOMIC_SUBSTRATE.md`](docs/HOLONOMIC_SUBSTRATE.md) | CEG §19 / §19.7 holonomic verifiers (cross-impl-proven) |
| [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) | Benchmark suite, recorded numbers, leak gate |
| [`protocol/ciris_verify.proto`](protocol/ciris_verify.proto) | Public gRPC/protobuf API contract |

## License & contact

AGPL-3.0-or-later — the binary is fully open source; hardware key
material never is. Engineering: `engineering@ciris.ai`.
