# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CIRISVerify is the **hardware-rooted license verification module** for the CIRIS ecosystem. It is an **open-source (AGPL-3.0) Rust binary** that provides cryptographic proof of license status, ensuring that community agents (CIRISCare) cannot masquerade as licensed professional agents (CIRISMedical, CIRISLegal, CIRISFinancial).

**This repository contains the full source code, protocol documentation, and specifications for CIRISVerify.**

## Repository Structure

| Path | Purpose |
|------|---------|
| `FSD/FSD-001_CIRISVERIFY_PROTOCOL.md` | Full technical specification (authoritative) |
| `protocol/ciris_verify.proto` | Public API contract (gRPC/protobuf) |
| `docs/THREAT_MODEL.md` | Formal threat model (6 attack vectors, mitigations) |
| `docs/IMPLEMENTATION_ROADMAP.md` | Implementation phases and timeline |
| `docs/OPEN_ITEMS.md` | Open items and future work tracker |
| `docs/HOW_IT_WORKS.md` | How CIRISVerify works |
| `docs/REGISTRY_INTEGRATION_REQUIREMENTS.md` | CIRISRegistry dependency analysis |
| `docs/REGISTRY_BINARY_MANIFEST.md` | Binary manifest spec for registry team |
| `docs/PORTAL_DEVICE_AUTH_INTEGRATION.md` | Portal device auth integration guide |
| `src/ciris-keyring/` | Cross-platform hardware keyring (extends Veilid pattern) |
| `src/ciris-crypto/` | Hybrid cryptography (ECDSA P-256 + ML-DSA-65) |
| `src/ciris-verify-core/` | Core verification logic (engine, consensus, transparency log) |
| `src/ciris-verify-ffi/` | C FFI and mobile bindings (incl. attestation export) |
| `bindings/python/` | Python SDK (ciris-verify PyPI package) |

## Build Commands

```bash
# Build all crates
cargo build --release

# Run tests
cargo test

# Run tests with PQC support (when ml-dsa stabilizes)
cargo test --features pqc-ml-dsa

# Build for specific target
cargo build --release --target aarch64-linux-android

# Check without building
cargo check

# Lint
cargo clippy -- -W clippy::pedantic

# Format
cargo fmt

# Security audit
cargo deny check
```

## Current Implementation Status

| Crate | Status | Notes |
|-------|--------|-------|
| `ciris-keyring` | Phase 0 | HardwareSigner trait, SoftwareSigner impl, macOS/desktop tracing |
| `ciris-crypto` | Phase 1 Complete | ECDSA P-256, Ed25519, ML-DSA-65 (FIPS 204), hybrid signer with bound signatures |
| `ciris-verify-core` | Phase 3-5 Active | Full verification engine, HTTPS-authoritative consensus, anti-rollback, transparency log (Merkle), Tripwire file integrity, remote attestation export, Level 2 binary self-verification |
| `ciris-verify-ffi` | Phase 4 Active | C FFI with init/status/capability/attestation-export/run-attestation/destroy, JNI bindings |
| `bindings/python` | Released | ciris-verify 0.5.3 on PyPI with platform wheels |

**ML-DSA-65**: Fully implemented using `ml-dsa` 0.1.0-rc.3 (RustCrypto). Bound dual signatures operational.

**155+ tests passing** across all crates (123 lib tests + property tests).

## Development Workflow

### When Modifying the Protocol

1. Update `FSD/FSD-001_CIRISVERIFY_PROTOCOL.md` **first** (source of truth)
2. Update `protocol/ciris_verify.proto` to match
3. Update Rust types in `src/ciris-verify-core/src/types.rs`
4. Coordinate with CIRISRegistry team for API changes

### When Adding Cryptographic Features

1. Add to `src/ciris-crypto/` following the `ClassicalSigner`/`PqcSigner` traits
2. Update `HybridSigner` if signature binding changes
3. Add test vectors from NIST/Wycheproof

### Veilid Upstream Compatibility

This project extends Veilid's `keyring-manager` pattern. To maintain compatibility:
- Follow Veilid's `CryptoKind` tagging pattern
- Use compatible async patterns (tokio)
- Prefer additive changes over modifications
- Document all divergences in `docs/VEILID_DIVERGENCES.md`

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    MULTI-SOURCE VALIDATION (HTTPS-Authoritative)          │
│  HTTPS endpoints (authoritative, multiple independent domains)           │
│  DNS US (us.registry.ciris-services-1.ai) — advisory cross-check        │
│  DNS EU (eu.registry.ciris-services-1.ai) — advisory cross-check        │
│  HTTPS authoritative when reachable; DNS fallback with 2-of-3 consensus │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    CIRISVERIFY MODULE (Open Source - AGPL-3.0)            │
│  Hardware Security (TPM/SE) + License Engine + Binary Integrity         │
│  Hybrid Crypto: Ed25519 (hardware) + ML-DSA-65 (software PQC)           │
│  Anti-Rollback Enforcer + Transparency Log (Merkle Tree)                │
│  Remote Attestation Proof Export + Tripwire File Integrity              │
│  Public interface: FFI/gRPC defined in ciris_verify.proto               │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│              CIRIS AGENT (Open Source - AGPL)                            │
│  DEPENDS on binary. MUST display mandatory_disclosure field.             │
│  WiseBus: PROHIBITED_CAPABILITIES = ALL - license.capabilities          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Key Design Principles

**Hybrid Cryptography (Day-1)**: All signatures use Ed25519 + ML-DSA-65. Both must verify.

**Fail-Secure**: Always degrades to MORE restrictive mode:
- Binary tampered → LOCKDOWN
- Sources disagree → RESTRICTED
- Verification failed → COMMUNITY MODE
- License expired/revoked → COMMUNITY MODE

**SOFTWARE_ONLY Limitation**: Software-only attestation caps at UNLICENSED_COMMUNITY tier.

## Security Invariants (Do Not Violate)

- Never expose individual integrity check results (use opaque failure)
- Always use constant-time cryptographic comparisons
- Certificate pin `verify.ciris.ai` with 90-day rotation
- Nonces must be 32+ bytes from cryptographic RNG
- PQC signature must cover classical signature (binding)
- Revocation revisions must be monotonically non-decreasing (anti-rollback)
- Transparency log entries are append-only (never modify or delete)

## Related Projects

| Project | Integration |
|---------|-------------|
| `../CIRISRegistry` | Source of verification data |
| `../CIRISAgent` | Primary consumer of verification |
| `../CIRISPortal` | License management portal |

## CLI Usage

```bash
# Build CLI
cargo build --release -p ciris-verify-core

# Run full verification
./target/release/ciris_verify run

# Run binary self-check (Level 2)
./target/release/ciris_verify self-check

# Run with custom registry
./target/release/ciris_verify run --registry https://api.registry.ciris-services-1.ai
```

## Attestation Levels

| Level | Name | What it Proves |
|-------|------|----------------|
| 1 | Hardware | TPM/Secure Enclave key valid |
| 2 | Binary Self-Check | THIS binary hash matches registry manifest |
| 3 | Registry Consensus | 2/3 geo-distributed sources agree |
| 4 | License Validity | Signature valid, not expired/revoked |
| 5 | Agent Integrity | Tripwire file hashes match |

**CRITICAL**: If Level 2 fails, Levels 3-5 are UNVERIFIED (yellow). A compromised binary could lie about higher levels.

## Current Registry Gaps (Blocking Production)

See `docs/REGISTRY_INTEGRATION_REQUIREMENTS.md` for details:
- Multi-source DNS publishing: NOT IMPLEMENTED (registry-side)
- Hardware attestation validation: NOT IMPLEMENTED (registry-side)
- Offline package generation: Stub only
- Hybrid signature implementation: DONE in CIRISVerify, NOT IMPLEMENTED in CIRISRegistry
- Binary manifest endpoint: IMPLEMENTED (see `docs/REGISTRY_BINARY_MANIFEST.md`)

## CI/Testing Notes

**Test Runner**: CI uses [cargo-nextest](https://nexte.st/) for reliable parallel test execution:
```bash
# Install nextest
cargo install cargo-nextest

# Run all tests (recommended)
cargo nextest run --all

# Run with reduced proptest cases for faster local iteration
PROPTEST_CASES=16 cargo nextest run --all
```

**Why nextest?** Standard `cargo test` can hang when proptest external test files run in parallel.
nextest handles parallel execution properly and detects/terminates hung tests.

**Test Structure**: External tests are consolidated per crate to avoid compilation overhead:
```
src/ciris-verify-core/tests/
  it/
    main.rs       # mod security; mod validation;
    security.rs   # security property tests
    validation.rs # validation property tests
```
See: https://matklad.github.io/2021/02/27/delete-cargo-integration-tests.html

**Fallback**: If nextest isn't available, use `--lib` to avoid hang:
```bash
cargo test --all --lib  # Fast, lib tests only
```
