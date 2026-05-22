# CIRISVerify

**The hardware-rooted trust anchor for AI agents.**

Protocol 3.0.0 · Rust + Python · AGPL-3.0 · Post-quantum from day one

CIRISVerify answers one question for any agent in the CIRIS ecosystem:
*is this agent who and what it claims to be?* It binds an agent's
identity to secure hardware, verifies its binary and files against a
signed registry manifest, records every verification in a tamper-evident
transparency log, and gates professional capabilities behind a
licensed-human accountability chain. Without it, any agent could
masquerade as any other.

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
| [`docs/HOW_IT_WORKS.md`](docs/HOW_IT_WORKS.md) | How verification works, end to end |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Threat model + SOTA peer survey |
| [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) | Benchmark suite, recorded numbers, leak gate |
| [`protocol/ciris_verify.proto`](protocol/ciris_verify.proto) | Public gRPC/protobuf API contract |

## License & contact

AGPL-3.0-or-later — the binary is fully open source; hardware key
material never is. Engineering: `engineering@ciris.ai`.
