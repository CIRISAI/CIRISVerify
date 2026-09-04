# CIRISVerify

**Decide whether evidence about a machine, a build, or a key is worth
believing — and say exactly how much.**

v14.2.0 · Rust + Python · AGPL-3.0 · Post-quantum from day one

CIRISVerify is an embeddable Rust library (with C FFI and a Python wheel) for
**hardware attestation verification, trust-anchor management, and artifact
integrity**. It walks device-attestation chains to pinned vendor roots, stores
those roots in a constrained IETF-CoTS-shaped anchor store, verifies build and
binary integrity against signed manifests, records verifications in an RFC 6962
transparency log, and signs everything with hybrid Ed25519 + ML-DSA-65.

It is used as the trust anchor for the CIRIS agent ecosystem — but nothing
above is CIRIS-specific, and the four capability areas are usable standalone.

## What it actually does

| | Capability | Concretely |
|---|---|---|
| 1 | **Device attestation** | Android Key Attestation, Apple App Attest, TPM 2.0 EK, YubiKey PIV — each walked to a pinned vendor root, with the attested key bound to the key you hold and the challenge bound to the one you issued |
| 2 | **Constrained trust anchors** | `draft-ietf-rats-concise-ta-stores-02` realized in Rust. Anchors resolve on **(purpose, environment)** together, fail-closed on omission. 44 roots baked, each tagged with how it was sourced |
| 3 | **Artifact integrity** | RFC 6962 Merkle log with hybrid-signed heads, RFC 8785 JCS canonicalization, per-file build manifests, runtime binary self-verification, SD-JWT-style redactable commitments |
| 4 | **Hybrid PQC crypto** | Ed25519 + ML-DSA-65 (FIPS 204) with *bound* signatures, X25519 + ML-KEM-768 KEX, HPKE over X-Wing, SP 800-90B fail-secure RNG |

**The organizing stance: verify emits measurements, never verdicts.** It
reports what a chain proved and what it did not. Turning that into an admission
decision is the consumer's job — and the type system says so: every
classification declares whether you may gate on it and on whose authority.

Three consequences worth internalizing before using it:

- **Absence of an attestation is not failure.** A device with no secure element
  simply produces no hardware evidence. Gating admission on presence makes
  hardware a *requirement* and excludes those devices.
- **A pass is weak evidence; an over-claim is decisive.** Anyone holding a
  genuine chain produces a pass. What carries information is a peer claiming
  *stronger* custody than the chain measures. Weight refutations heavily.
- **Nothing here checks revocation.** No CRL, no OCSP, no vendor revocation
  feed. A valid chain does not mean "not revoked."

## Where it stands vs. peers

| Area | Field | CIRISVerify |
|---|---|---|
| Concise trust-anchor stores | Veraison / `Azure/corim` — CoTS **not modeled** | **First Rust implementation** |
| Signature crypto | Mostly classical; PQ migration underway | **Hybrid day one**, FIPS 204, PQC binds the classical half |
| Device attestation | Per-platform verifiers, hardcoded roots | Four platforms, **one constrained store** |
| Transparency log | RFC 6962 — Trillian, Sigstore Rekor | RFC 6962-correct, **hybrid-signed heads**; not sharded |
| Selective disclosure | SD-JWT, ISO mdoc, BBS+ | SD-JWT salted-digest; **no unlinkability yet** |
| Supply-chain provenance | Sigstore, in-toto, SLSA | Signed manifests + presenter binding; **far smaller ecosystem** |
| Boot-state attestation | Keylime, `go-attestation` (PCR quotes) | **Absent** — device identity only |
| External security audit | — | **None to date** |

Full analysis, including where verify loses and what to use instead:
[`docs/STANDARDS_COMPARISON.md`](docs/STANDARDS_COMPARISON.md).

**Honest read:** ahead on post-quantum posture and CoTS, at parity on device
attestation with an unusually unified store, behind on ecosystem, scale, and
external review. Verify has had internal adversarial audits — one found 1
CRITICAL and 3 HIGH, all in *wiring* rather than primitives — but no
third-party audit.

## Quick start

```bash
pip install ciris-verify        # platform wheel bundles the Rust binary
```

```python
from ciris_verify import CIRISVerify
import os

status = CIRISVerify().get_license_status(challenge_nonce=os.urandom(32))
if status.allows_licensed_operation():
    ...                          # capabilities available
else:
    print(status.mandatory_disclosure.text)
```

```rust
// Verify an Android attestation against the baked Google roots.
use ciris_verify_core::device_attestation::verify_android_key_attestation_with_store;
use ciris_verify_core::trust_anchor_store::baked;

let verdict = verify_android_key_attestation_with_store(
    &baked::default_store(), leaf_der, &intermediates, &expected_pubkey, challenge,
)?;
// `Ok(None)` = no anchor for that class = no hardware evidence. NOT a refusal.
```

Build from source: `cargo build --release`, then `pip install -e bindings/python/`.

## In the CIRIS ecosystem

Within CIRIS, verify answers *is this agent who and what it claims to be?* — it
binds an agent's identity to secure hardware, gates professional capabilities
behind a licensed-human accountability chain, and **mints federation
identities**: a hybrid hardware-rooted key (Ed25519 in a YubiKey / Secure
Enclave / StrongBox / TPM, ML-DSA-65 seed sealed at rest) plus the signed
objects and shareable identity codes (`fedcode`) the rest of the federation
consumes.

It proves an agent is **authentic** — necessary, not sufficient. Ethical
*behavior* is the separate job of the CIRIS covenant system.

```bash
ciris-verify fedcode new --kind user --label eric-moore     # software keys, with a QR
ciris-verify identity create --module libykcs11.so --label eric-moore --provision --pin
```

## Documentation

| Doc | What |
|---|---|
| [`docs/STANDARDS_COMPARISON.md`](docs/STANDARDS_COMPARISON.md) | **Peer analysis** — Veraison, Keylime, Sigstore, in-toto/SLSA, Trillian, SD-JWT, TUF; what verify wins, ties, and loses |
| [`docs/HOW_IT_WORKS.md`](docs/HOW_IT_WORKS.md) | How verification works, end to end |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Threat model (AV-1…AV-51) |
| [`docs/FEDERATION_THREAT_MODEL.md`](docs/FEDERATION_THREAT_MODEL.md) | Federation-tier threat model (F-AV-*, HNDL/PQC) |
| [`docs/TPM_ANCHOR_PROVENANCE.md`](docs/TPM_ANCHOR_PROVENANCE.md) | How the 40 TPM vendor roots were sourced — four attempts, three dead ends |
| [`docs/HARDWARE_ATTESTATION.md`](docs/HARDWARE_ATTESTATION.md) | Platform attestation details |
| [`docs/BINARY_SELF_VERIFICATION.md`](docs/BINARY_SELF_VERIFICATION.md) | "Who watches the watchmen" — runtime self-verification |
| [`docs/CRYPTO_AGILITY.md`](docs/CRYPTO_AGILITY.md) | Algorithm migration posture |
| [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) | Benchmark suite, recorded numbers, leak gate |
| [`docs/HOLONOMIC_SUBSTRATE.md`](docs/HOLONOMIC_SUBSTRATE.md) | CEG §19 / §19.7 verifiers (cross-impl-proven) |
| [`docs/FEDERATION_IDENTITY.md`](docs/FEDERATION_IDENTITY.md) | Operator runbook: YubiKey → federation ID |
| [`FSD/FSD-001`](FSD/FSD-001_CIRISVERIFY_PROTOCOL.md) | Full protocol specification (authoritative) |
| [`protocol/ciris_verify.proto`](protocol/ciris_verify.proto) | Public gRPC/protobuf API contract |

## License & contact

AGPL-3.0-or-later — the binary is fully open source; hardware key material
never is. Engineering: `engineering@ciris.ai`.
