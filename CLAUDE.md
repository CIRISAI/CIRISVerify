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
| `bindings/swift/` | Swift wrapper + bridging header (iOS Level 5 parity) |

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

# Bump version + refresh Cargo.lock + reclaim stale target/ artifacts
./scripts/bump-version.sh 1.10.3

# Periodic disk hygiene across CIRIS* repos (default 14-day cutoff)
./scripts/clean-stale-targets.sh
```

See [`docs/DEV_HYGIENE.md`](docs/DEV_HYGIENE.md) for the layered self-cleaning policy (dev-profile incremental disabled, bump-time cleanup, periodic sweep) — added 2026-05-04 after a six-bump session blew `target/debug/` to ~180GB.

## Current Implementation Status

| Crate | Status | Notes |
|-------|--------|-------|
| `ciris-keyring` | Phase 2 Complete | HardwareSigner trait, SoftwareSigner impl, Android Keystore, TPM 2.0 (dual-key architecture), **SecureBlobStorage for wallet seeds (v1.4.0+)**, **PqcSigner trait + MlDsa65SoftwareSigner (v1.9.0+, feature `pqc-ml-dsa`)** |
| `ciris-crypto` | Phase 1 Complete | ECDSA P-256, Ed25519, ML-DSA-65 (FIPS 204), hybrid signer with bound signatures, **secp256k1 wallet signing (v1.3.0+)** |
| `ciris-verify-core` | Phase 3-5 Active | Full verification engine, HTTPS-authoritative consensus, anti-rollback, transparency log (Merkle), Tripwire file integrity, remote attestation export, Level 2 binary self-verification, **hardware vulnerability detection (v1.2.0+)**, **offline manifest cache (v1.2.0+)** |
| `ciris-verify-ffi` | Phase 4 Active | C FFI (33 functions), JNI bindings (Android Level 5), Swift wrapper (iOS Level 5), **wallet signing FFI (v1.3.0+)**, **named key storage (v1.5.0+)** |
| `bindings/python` | Released | ciris-verify 1.5.0 on PyPI with platform wheels, **wallet signing support**, **named key storage** |
| `bindings/swift` | Released | CIRISVerify.swift wrapper + bridging header, XCFramework build script |

**ML-DSA-65**: Fully implemented using `ml-dsa` 0.1.0-rc.3 (RustCrypto). Bound dual signatures operational.

**TPM 2.0**: Dual-key architecture with attestation key (restricted, for quotes) and signing key (non-restricted, for arbitrary data). Supports EK certificate reading and external nonce binding. **v1.2.2+**: Signing key blobs are persisted in the `.tpm` file to survive process restart.

**Hardware Vulnerability Detection (v1.2.0+)**: Detects SoC-level vulnerabilities (CVE-2026-20435 MediaTek, CVE-2026-21385 Qualcomm) and caps attestation to SOFTWARE_ONLY for affected devices.

**Offline Manifest Cache (v1.2.0+)**: Hardware-signed cache for L1 self-verification when registry is unreachable. No expiration - valid as long as hardware key exists.

**TPM Key Persistence (v1.2.2+)**: The TPM wrapping module now persists signing key blobs (TPM2B_PRIVATE, TPM2B_PUBLIC) alongside encrypted Ed25519 keys. This prevents identity loss across sessions. File format: `TPM2` magic + version + blobs + signature + AES-GCM ciphertext.

**secp256k1 Wallet Signing (v1.3.0+)**: Deterministic EVM wallet key derivation from Ed25519 root identity using HKDF. Supports EIP-155 transaction signing, EIP-712 typed data, and address recovery. Key hierarchy: `Ed25519 Seed → HKDF-SHA256("CIRIS-wallet-v1", "secp256k1-evm-signing-key") → secp256k1 Private Key → EVM Address (keccak256)`.

**Named Key Storage (v1.5.0+)**: Multi-key support for storing and signing with multiple Ed25519 keys identified by key_id strings. Use cases include WA (Wallet Address) signing, session keys, and backup keys. Keys are stored with hardware protection (TPM/Keystore/SecureEnclave) via SecureBlobStorage. FFI methods: `store_named_key`, `sign_with_named_key`, `has_named_key`, `delete_named_key`, `get_named_key_public`, `list_named_keys`.

**PqcSigner trait + MlDsa65SoftwareSigner (v1.9.0+, feature `pqc-ml-dsa`)**: Async PQC signer trait in `ciris-keyring` parallel to `HardwareSigner` for classical algorithms. Lets downstream consumers (CIRISPersist's cold-path PQC fill-in flow for `federation_keys` / `federation_attestations` / `federation_revocations`) get an ML-DSA-65 signer through the same `get_platform_pqc_signer(key_id, algorithm)` factory pattern that `get_platform_signer` exposes for classical, instead of reaching into the `ml-dsa` crate directly and bypassing the keyring's storage-descriptor and lifecycle abstractions. Today's impl returns a software-only `MlDsa65SoftwareSigner` (file-backed seed via `from_seed_file`, in-memory via `from_seed_bytes`); when post-quantum HSMs ship the factory will probe for hardware first. Constructed signers are byte-equivalent with `dilithium-py` (FIPS 204 final reference), so federation row signatures verify across Rust + Python implementations. See CIRISVerify#5.

**Hardware-Backed Wallet Seed Storage (v1.4.0+)**: `SecureBlobStorage` trait with platform implementations:
- **Android**: `AndroidKeystoreSecureBlobStorage` - AES-256-GCM with hardware-backed key from Android Keystore (TEE/StrongBox)
- **iOS/macOS**: `SecureEnclaveSecureBlobStorage` - ECIES with P-256 key in Secure Enclave (T2/Apple Silicon, keychain fallback on older Macs)
- **Linux/Windows**: `TpmSecureBlobStorage` - TPM 2.0 sealed blobs
- **Fallback**: `SoftwareSecureBlobStorage` - AES-256-GCM with derived master key

**278 tests passing** across all crates.

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

### Feature Completion Checklist

**A feature is NOT done until it is wired end-to-end:**

1. **Rust core implementation** - Types, logic, tests in `ciris-verify-core`
2. **FFI exposure** - Function/struct exposed in `ciris-verify-ffi/src/lib.rs`
3. **JSON serialization** - New fields serialized in FFI response (check `serde` derives)
4. **Python bindings** - Types added to `bindings/python/ciris_verify/types.py`
5. **Platform logging** - Rust `tracing` logs reach platform (Android logcat, iOS console)

**Common mistakes:**
- Adding a field to a Rust struct but not including it in JSON response
- Adding logging with `tracing::warn!()` but not wiring to Android logger
- Testing on desktop but not verifying on mobile targets

**Android logging**: Requires `android_logger` crate initialization in JNI_OnLoad or constructor.
**iOS logging**: Requires `oslog` crate or similar for Console.app visibility.

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
│  DNS EU (eu.registry.ciris-services-eu-1.com) — advisory cross-check    │
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

# Run Level 1 self-check (binary + function integrity)
./target/release/ciris_verify self-check

# Validate sources agreement (Level 3)
./target/release/ciris_verify validate-sources

# Run with custom registry
./target/release/ciris_verify run --registry https://api.registry.ciris-services-1.ai
```

## Attestation Levels

| Level | Name | What it Proves |
|-------|------|----------------|
| 1 | Self-Verification | THIS CIRISVerify binary + functions match registry manifest ("who watches the watchmen") |
| 2 | Hardware | TPM/Secure Enclave key valid |
| 3 | Registry Consensus | 2/3 geo-distributed sources agree |
| 4 | License Validity | Signature valid, not expired/revoked |
| 5 | Agent Integrity | Tripwire file hashes match |

**CRITICAL**: If Level 1 fails, ALL other levels are UNVERIFIED (yellow). A compromised CIRISVerify binary could lie about everything else.

## Registry API Integration

**Working Endpoints** (https://api.registry.ciris-services-1.ai):
- `GET /v1/builds/{version}` - Returns BuildRecordResponse with file manifest
- `GET /v1/builds/hash/{hash}` - Lookup build by binary hash
- `GET /v1/verify/function-manifest/{version}/{target}` - Function-level manifest
- `GET /v1/integrity/nonce` - Play Integrity challenge nonce
- `POST /v1/integrity/verify` - Verify Play Integrity token

**FileManifest Format**: Registry returns both flat (`{"path": "hash"}`) and structured (`{"version": "...", "files": {...}}`) formats. The `FileManifest` enum in `registry.rs` handles both via `#[serde(untagged)]`.

## Play Integrity (Google Android HW Attestation)

**ADVISORY trust layer** - adds confidence but NOT required for verification. Located in `src/ciris-verify-core/src/play_integrity.rs`.

Flow:
1. CIRISVerify calls `get_integrity_nonce()` to get challenge from registry
2. Android app passes nonce to Google Play Integrity API
3. Play Integrity returns encrypted token
4. CIRISVerify calls `verify_integrity_token()` with token + nonce
5. Registry decrypts via Google API and returns verdict

Trust Model: A compromised Google account or Play Integrity service doesn't compromise core verification.

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
