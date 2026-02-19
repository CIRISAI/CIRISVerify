# Similar Projects & Comparative Analysis

This document surveys projects that overlap with CIRISVerify's problem space — hardware-rooted identity, AI agent verification, hybrid post-quantum cryptography, and transparency logging — and compares their approaches.

CIRISVerify occupies a unique intersection: it is a **hardware-rooted, post-quantum-ready license verification system** purpose-built for **AI agent tier enforcement**. No single existing project covers the same combination of concerns. The closest comparisons come from several adjacent categories.

---

## Category 1: AI Agent Identity & Verification

These projects address the question "who is this agent and can it be trusted?" — the same core question CIRISVerify answers, but with different trust models and enforcement mechanisms.

### AgentCred

- **Repository:** [agentcred-ai/AgentCred](https://github.com/agentcred-ai/agentcred)
- **License:** MIT
- **Language:** TypeScript/Node.js

AgentCred gives AI agents a "blue badge" of trust by tying Ed25519 signatures to GitHub identities. Agents sign their output with a JWS structure that includes the developer's GitHub username, agent name, and signed content.

| Aspect | CIRISVerify | AgentCred |
|--------|-------------|-----------|
| **Trust root** | Hardware security module (TPM/SE) | GitHub OAuth identity |
| **Cryptography** | Hybrid Ed25519 + ML-DSA-65 (PQC) | Ed25519 only |
| **Enforcement** | Capability-gated tier system (fail-secure) | Verification badge (advisory) |
| **Scope** | License status, capabilities, autonomy tiers | Authorship attribution |
| **Offline support** | 72-hour grace with cached license | No (requires GitHub) |
| **Hardware binding** | Keys generated in hardware, non-extractable | Software keys |

**Key difference:** AgentCred answers "which human made this agent?" — CIRISVerify answers "what is this agent licensed to do, and can the binary proving it be trusted?"

### HUMAN Verified AI Agent

- **Repository:** [HumanSecurity/human-verified-ai-agent](https://github.com/HumanSecurity/human-verified-ai-agent)
- **License:** Open source
- **Language:** Python

HUMAN Security's open-source demo implements HTTP Message Signatures (RFC 9421) for agent-to-agent authentication. Each agent holds an Ed25519 key pair and signs HTTP requests. Integrates with Google's A2A protocol and OWASP Agent Name Service (ANS).

| Aspect | CIRISVerify | HUMAN Verified AI Agent |
|--------|-------------|------------------------|
| **Trust root** | Hardware + multi-source consensus | Self-asserted key pair |
| **Protocol** | gRPC/protobuf + DNS + HTTPS | HTTP Message Signatures (RFC 9421) |
| **Verification** | License status + capability enforcement | Request authenticity |
| **Transparency** | Merkle tree audit log | None |
| **Anti-rollback** | Monotonic revocation revisions | None |
| **Maturity** | Production binary (v0.3.7, 155+ tests) | Demo/showcase |

**Key difference:** HUMAN Verified AI Agent authenticates agent *requests* on the wire. CIRISVerify authenticates agent *license status and capabilities* at the platform level. These are complementary — an agent could use RFC 9421 for transport authentication while relying on CIRISVerify for license enforcement.

### Sanna

- **Repository:** [nicallen-exd/sanna](https://github.com/nicallen-exd/sanna)
- **License:** Open source
- **Language:** TypeScript

Sanna enforces "constitution-as-code" constraints during AI agent execution. It acts as an MCP gateway proxy that halts on policy violations, escalates risky actions, and generates Ed25519-signed cryptographic receipts.

| Aspect | CIRISVerify | Sanna |
|--------|-------------|-------|
| **Enforcement model** | Hardware-rooted capability gating | Runtime policy proxy |
| **What it controls** | License tier and allowed capabilities | Action-level constitution compliance |
| **Cryptography** | Hybrid classical + PQC | Ed25519 receipts |
| **Architecture** | Embedded verification module | MCP gateway proxy |

**Key difference:** Sanna governs *what an agent does* at runtime via policy. CIRISVerify governs *what an agent is allowed to claim it can do* via cryptographic proof. Sanna operates at the action level; CIRISVerify operates at the identity/license level.

### AIP (Agent Identity Protocol)

- **Repository:** [The-Nexus-Guard/aip](https://github.com/The-Nexus-Guard/aip)
- **License:** Open source
- **Language:** Python

AIP provides cryptographic identity, trust chains, and E2E encrypted messaging for AI agents using Ed25519 key pairs and a vouching/delegation model.

| Aspect | CIRISVerify | AIP |
|--------|-------------|-----|
| **Identity model** | Hardware-bound device key + license JWT | Ed25519 key pair + trust chains |
| **Trust chain** | Steward-signed license via registry | Peer-to-peer vouching |
| **PQC readiness** | Day-1 ML-DSA-65 hybrid | None |
| **Use case** | Professional license enforcement | General agent identity |

### AgentFacts

- **Repository:** [agentfacts/agentfacts-py](https://github.com/agentfacts/agentfacts-py)
- **License:** Open source
- **Language:** Python

AgentFacts creates signed, verifiable agent profiles ("identity cards") capturing metadata like base model, tools, policy, and provenance. Uses Ed25519 + did:key for offline verification.

| Aspect | CIRISVerify | AgentFacts |
|--------|-------------|------------|
| **What is signed** | License status, capabilities, tier | Agent metadata profile |
| **Hardware binding** | Yes (non-extractable keys) | No |
| **Enforcement** | Binary capability gating | Informational/advisory |
| **Dynamic updates** | Real-time license checks with consensus | Static profile cards |

---

## Category 2: Hardware Roots of Trust

These projects provide the hardware security primitives that CIRISVerify builds upon.

### Caliptra (CHIPS Alliance / Linux Foundation)

- **Website:** [opentitan.org](https://opentitan.org) / [chipsalliance.org](https://www.chipsalliance.org/news/chips-alliance-welcomes-the-caliptra-open-source-root-of-trust-project/)
- **Founded by:** AMD, Google, Microsoft, NVIDIA
- **License:** Apache 2.0

Caliptra 2.1 is an open-source silicon Root of Trust (RoT) for integration into SoCs. It provides hardware-rooted identity, measured boot, key management (OCP L.O.C.K.), and quantum-resilient cryptography.

| Aspect | CIRISVerify | Caliptra |
|--------|-------------|----------|
| **Layer** | Application-level verification module | Silicon-level RoT IP block |
| **Scope** | AI agent license enforcement | General-purpose secure boot + attestation |
| **PQC** | ML-DSA-65 (software, bound to classical) | Quantum-resilient crypto (hardware) |
| **Relationship** | Consumer of hardware attestation | Provider of hardware attestation |

**Key difference:** Caliptra is infrastructure *below* CIRISVerify. A future CIRISVerify deployment on Caliptra-equipped hardware could use Caliptra's attestation as an additional trust signal.

### OpenTitan

- **Website:** [opentitan.org](https://opentitan.org/book/doc/security/specs/attestation/)
- **License:** Apache 2.0

OpenTitan is a transparent, open-source silicon root of trust. Its attestation model uses Creator Identity and Owner Identity asymmetric keys provisioned at manufacturing time.

| Aspect | CIRISVerify | OpenTitan |
|--------|-------------|-----------|
| **Layer** | Software verification module | Silicon RoT chip design |
| **Key provisioning** | Runtime (hardware keystore APIs) | Manufacturing-time |
| **Target** | AI agents on commodity devices | Server/enterprise hardware |

**Key difference:** Similar relationship to Caliptra — OpenTitan is a potential hardware substrate, not a competitor. CIRISVerify's cross-platform keyring (`ciris-keyring`) abstracts over the specific hardware available.

### DigiCert TrustCore SDK

- **Website:** [digicert.com/iot/trustcore-sdk](https://www.digicert.com/iot/trustcore-sdk)
- **License:** Free for non-commercial use

TrustCore SDK embeds hardware-rooted identity and attestation readiness into IoT devices, with FIPS-aligned cryptography and PQC readiness (ML-KEM, SLH-DSA, ML-DSA).

| Aspect | CIRISVerify | DigiCert TrustCore |
|--------|-------------|---------------------|
| **Target** | AI agent ecosystems | IoT device manufacturing |
| **Trust model** | Multi-source consensus + registry | DigiCert PKI (centralized CA) |
| **PQC** | ML-DSA-65 hybrid (day-1) | ML-KEM, SLH-DSA, ML-DSA (readiness) |
| **Open source** | AGPL-3.0 (full source) | Source available (non-commercial) |
| **Transparency** | Append-only Merkle log | Certificate Transparency |

---

## Category 3: Transparency Logs & Supply Chain Integrity

### Sigstore (Rekor + Cosign + Fulcio)

- **Repository:** [sigstore/rekor](https://github.com/sigstore/rekor), [sigstore/sigstore-rs](https://docs.sigstore.dev/language_clients/rust/)
- **License:** Apache 2.0
- **Language:** Go (core), Rust client available

Sigstore provides keyless code signing and verification with an immutable transparency log (Rekor). It uses ephemeral signing certificates tied to OIDC identities, eliminating long-lived key management.

| Aspect | CIRISVerify | Sigstore |
|--------|-------------|----------|
| **What is logged** | License verification events | Software artifact signatures |
| **Transparency log** | Local Merkle tree (per-device) | Global Rekor log (public) |
| **Signing model** | Hardware-bound long-lived keys | Ephemeral identity-bound certificates |
| **PQC** | ML-DSA-65 hybrid signatures | Not yet (roadmap) |
| **Use case** | Runtime license enforcement | Build-time artifact provenance |
| **Verification** | Multi-source consensus (2-of-3) | Certificate chain + Rekor inclusion |

**Key difference:** Sigstore verifies *software artifacts* at build/release time. CIRISVerify verifies *license status* at runtime. Both use Merkle trees for tamper evidence, but at different points in the lifecycle. CIRISVerify's transparency log is device-local (audit trail), while Rekor is a global public ledger.

### Sigstore A2A (Agent Signing)

- **Repository:** [sigstore/sigstore-a2a](https://github.com/sigstore/sigstore-a2a)

A newer project applying Sigstore's signing infrastructure to agent-to-agent communication. This bridges the gap between supply chain integrity and agent identity.

**Potential synergy:** CIRISVerify could integrate Sigstore for binary provenance verification while maintaining its own transparency log for license events.

---

## Category 4: Post-Quantum Cryptography Libraries

CIRISVerify's hybrid crypto layer (`ciris-crypto`) uses ML-DSA-65 from the RustCrypto ecosystem. These are the alternative PQC libraries in Rust.

### RustCrypto ml-dsa (used by CIRISVerify)

- **Crate:** `ml-dsa` 0.1.0-rc.3
- **Status:** Release candidate, no independent audit yet

CIRISVerify chose RustCrypto for its pure-Rust implementation, FIPS 204 compliance, and ecosystem compatibility.

### liboqs-rust (Open Quantum Safe)

- **Repository:** [open-quantum-safe/liboqs-rust](https://github.com/open-quantum-safe/liboqs-rust)
- **License:** MIT / Apache-2.0

Rust bindings for the C liboqs library. Supports the full NIST PQC suite. The OQS project explicitly recommends hybrid cryptography — combining PQC with classical algorithms — which aligns with CIRISVerify's approach.

| Aspect | CIRISVerify's ciris-crypto | liboqs-rust |
|--------|---------------------------|-------------|
| **Implementation** | Pure Rust (RustCrypto) | C library with Rust bindings |
| **Hybrid binding** | Built-in (PQC signs data + classical sig) | Manual (user constructs hybrid) |
| **Algorithms** | ML-DSA-65 + Ed25519/ECDSA P-256 | Full NIST PQC suite |
| **Audit status** | Not yet audited | Not yet audited |

### libcrux (Cryspen)

- **Website:** [cryspen.com](https://cryspen.com/post/fospqc/)

Formally verified PQC implementations in Rust using the hax toolchain. Verified to be panic-free, functionally correct, and secret-independent. Used by Mozilla in NSS.

| Aspect | CIRISVerify's ciris-crypto | libcrux |
|--------|---------------------------|---------|
| **Verification** | Test suite (155+ tests) | Formal verification (hax) |
| **Algorithms** | ML-DSA-65 | ML-KEM (Kyber), expanding |
| **Target** | Application-level signing | Library-level primitives |

**Key difference:** libcrux provides the strongest correctness guarantees of any Rust PQC library. CIRISVerify could potentially migrate to libcrux for its ML-DSA implementation once signature schemes are supported and audited.

### aws-lc-rs (AWS)

AWS's Rust cryptography library with ML-DSA support (behind an unstable flag). Pending FIPS review. Backed by AWS's internal security review processes but not yet independently audited for PQC.

---

## Category 5: Veilid (Upstream Compatibility)

- **Website:** [veilid.com](https://veilid.com/how-it-works/cryptography/)
- **License:** MPL-2.0

CIRISVerify's `ciris-keyring` crate extends Veilid's `keyring-manager` pattern. Veilid is a peer-to-peer communication framework created by Cult of the Dead Cow, built in Rust with a focus on privacy and anti-censorship.

| Aspect | CIRISVerify | Veilid |
|--------|-------------|--------|
| **Purpose** | License verification | Private P2P communication |
| **Crypto suite** | Ed25519 + ML-DSA-65 | XChaCha20-Poly1305, Ed25519, x25519, BLAKE3 |
| **PQC** | Day-1 hybrid (ML-DSA-65) | Not yet (crypto-agile design) |
| **Key storage** | Hardware keystore (TPM/SE) via keyring | Encrypted SQLite/IndexedDB via keyring-manager |
| **Crypto agility** | Tagged with CryptoKind (Veilid pattern) | All keys tagged with cryptosystem |
| **Hardware binding** | Non-extractable hardware keys | Software keys with device-key protection |

**Key difference:** Veilid provides the foundational keyring pattern and crypto-agility tagging that CIRISVerify builds upon. CIRISVerify extends this with hardware signing support, PQC hybrid signatures, and license-specific verification logic.

---

## Category 6: Commercial & Emerging Approaches

### Cloudflare Web Bot Auth

Cloudflare's integration of RFC 9421 HTTP Message Signatures into their Verified Bots Program. Bots and AI agents sign requests cryptographically, and Cloudflare validates signatures at the edge.

- [Blog post](https://blog.cloudflare.com/web-bot-auth/)
- **Relevance:** Transport-layer agent authentication, complementary to CIRISVerify's license-layer verification.

### Sumsub Know Your Agent (KYA)

Commercial identity verification for AI agents, linking agents to verified human identities. Focuses on compliance and regulatory requirements.

- **Relevance:** Regulatory compliance layer. CIRISVerify's mandatory disclosure fields serve a similar "know who's responsible" function but via cryptographic proof rather than identity verification workflows.

### Aembit Workload Identity

Secretless authentication for AI agents using workload identity attestation — agents authenticate based on cryptographic proof of their runtime environment rather than static credentials.

- **Relevance:** Similar concept to CIRISVerify's hardware attestation, but focused on cloud workload identity rather than device-level hardware binding.

---

## Summary Comparison Matrix

| Feature | CIRISVerify | AgentCred | HUMAN Verified | Sigstore | Caliptra | Veilid |
|---------|-------------|-----------|----------------|----------|----------|--------|
| **Hardware root of trust** | Yes (TPM/SE) | No | No | No | Yes (silicon) | No |
| **Post-quantum crypto** | ML-DSA-65 hybrid | No | No | No | Roadmap | No |
| **License enforcement** | Yes (tier-gated) | No | No | No | No | No |
| **Transparency log** | Merkle tree | No | No | Rekor (global) | No | No |
| **Multi-source consensus** | 2-of-3 (DNS+HTTPS) | No | No | No | No | No |
| **Anti-rollback** | Monotonic revisions | No | No | No | Secure boot | No |
| **Fail-secure degradation** | Yes (always restrictive) | No | No | N/A | Yes | No |
| **Agent identity** | Device-bound key | GitHub identity | Ed25519 key pair | OIDC identity | N/A | Peer key |
| **Mandatory disclosure** | Yes (cannot suppress) | Badge display | No | No | No | No |
| **Open source** | AGPL-3.0 | MIT | Yes | Apache 2.0 | Apache 2.0 | MPL-2.0 |
| **Language** | Rust | TypeScript | Python | Go/Rust | RTL/C | Rust |

---

## Conclusion

CIRISVerify is differentiated by the **combination** of its features rather than any single capability:

1. **No other AI agent verification project** uses hardware-rooted keys or post-quantum cryptography.
2. **No other PQC project** addresses AI agent license enforcement.
3. **No other hardware attestation project** includes multi-source consensus or agent-specific tier enforcement.
4. **No other transparency log project** combines device-local audit trails with license-specific verification events.

The closest architectural analog is the combination of **Sigstore** (transparency + signing) + **Caliptra** (hardware RoT) + **HUMAN Verified AI Agent** (agent identity) — but that combination does not exist as a unified system. CIRISVerify integrates these concerns into a single, auditable Rust binary with a clear security model: **all failures degrade to more restrictive modes, and software-only deployments are permanently tier-capped**.

Potential integration opportunities exist with several of these projects:
- **Sigstore** for binary provenance verification at build time
- **RFC 9421 / HUMAN Verified AI Agent** for transport-layer request signing
- **libcrux** for formally verified PQC primitives (once ML-DSA support matures)
- **Caliptra/OpenTitan** hardware as additional attestation signals on supported platforms
