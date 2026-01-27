# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CIRISVerify is the **hardware-rooted license verification module** for the CIRIS ecosystem. It is a **closed-source binary** that provides cryptographic proof of license status, ensuring that community agents (CIRISCare) cannot masquerade as licensed professional agents (CIRISMedical, CIRISLegal, CIRISFinancial).

**This repository contains only public protocol documentation and specifications—not the binary source code.**

## Repository Structure

| Path | Purpose |
|------|---------|
| `FSD/FSD-001_CIRISVERIFY_PROTOCOL.md` | Full technical specification (authoritative) |
| `protocol/ciris_verify.proto` | Public API contract (gRPC/protobuf) |
| `docs/IMPLEMENTATION_ROADMAP.md` | Implementation phases and timeline |
| `docs/REGISTRY_INTEGRATION_REQUIREMENTS.md` | CIRISRegistry dependency analysis |
| `src/ciris-keyring/` | Cross-platform hardware keyring (extends Veilid pattern) |
| `src/ciris-crypto/` | Hybrid cryptography (ECDSA P-256 + ML-DSA-65) |
| `src/ciris-verify-core/` | Core verification logic |
| `src/ciris-verify-ffi/` | C FFI and mobile bindings |

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
| `ciris-keyring` | Phase 0 | HardwareSigner trait, SoftwareSigner impl |
| `ciris-crypto` | Phase 1 | ECDSA P-256, Ed25519, hybrid signer |
| `ciris-verify-core` | Scaffold | Types defined, engine stub |
| `ciris-verify-ffi` | Scaffold | C FFI, JNI stubs |

**ML-DSA-65**: Stub ready, awaiting ml-dsa crate stabilization (currently RC)

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
│                    MULTI-SOURCE VALIDATION                               │
│  DNS US (registry-us.ciris.ai) + DNS EU (registry-eu.ciris.ai)          │
│  + HTTPS API (api.registry.ciris.ai)                                    │
│  All 3 must agree (2-of-3 minimum for ACTIVE, any REVOKED = revoked)    │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    CIRISVERIFY MODULE (Closed Binary)                    │
│  Hardware Security (TPM/SE) + License Engine + Binary Integrity         │
│  Hybrid Crypto: Ed25519 (hardware) + ML-DSA-65 (software PQC)           │
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

## Related Projects

| Project | Integration |
|---------|-------------|
| `../CIRISRegistry` | Source of verification data |
| `../CIRISAgent` | Primary consumer of verification |
| `../CIRISPortal` | License management portal |

## Current Registry Gaps (Blocking Production)

See `docs/REGISTRY_INTEGRATION_REQUIREMENTS.md` for details:
- Multi-source DNS publishing: NOT IMPLEMENTED
- Hardware attestation validation: NOT IMPLEMENTED
- Offline package generation: Stub only
- Hybrid signature implementation: NOT IMPLEMENTED
