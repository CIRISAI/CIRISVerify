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
| `docs/HOLONOMIC_SUBSTRATE.md` | CEG §19 / §19.7 holonomic verifiers — threat model, module map, conformance status (§19 + §19.7 cross-impl-proven) |
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
| `bindings/swift/` | Swift wrapper + bridging header (iOS full attestation parity) |

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

*(Current release: **v5.10.0** — **CEG 1.0-RC14 §19.7 forever-memory aggregation pyramid (#79)**: `holonomic::aggregation` — `AggregationMetaV1` canonical preimage + PQC-mandatory `verify_aggregation_meta`, `member_commitment`/`verify_member_commitment` (reusing the §19.1 WholenessWitness Merkle), the §19.7.2 descent order, and the `EjectionVerdict{Keep|EjectToTier|EjectHardDelete}` tier-aware retirement surface (N5: revoked → hard-delete, never tier-shed). **Verify is the first conformant impl, so it authors the §19.7 vectors** (`tests/conformance_vectors_v19_7.rs` emit-or-verify; Persist/Edge reproduce). Prior: v5.9.0 §19 holonomic proven cross-impl against CIRISEdge v4.1.2 vectors (`tests/vectors/holonomic_v19/`, `tests/conformance_vectors_v19.rs`) — lifting §19 from RC-grade toward CEG 1.0 GA. Prior: v5.8.0 CEG 1.0-RC11 §19 holonomic substrate verifiers (#78) — §19.0 binary signed-preimage PQC-mandatory gate, §19.1 WholenessWitness Merkle + equivocation, §19.2 recursive-bootstrap (trust≠membership, ≤5-hop, cycle-reject, weight cap), §19.3 fountain holding-claim + revocation-respect, §19.4 ALM capacity authenticity, §10.5.8 A/V chunk nonces. See the v5.8.0 substrate note below. Prior: v5.7.0 CEG 1.0-RC7 conformance + HNDL hardening (#75 hybrid-required at every federation-tier gate, #76 partnership member-set, #77 scope split); v5.6.0 security-audit remediation (#72/#73/#74/#28/#63). The per-crate "Phase" labels below are historical; all crates are production-released.)*

| Crate | Status | Notes |
|-------|--------|-------|
| `ciris-keyring` | Released | HardwareSigner trait, SoftwareSigner impl, Android Keystore, TPM 2.0 (dual-key architecture), SecureBlobStorage for wallet seeds, PqcSigner + MlDsa65SoftwareSigner (feature `pqc-ml-dsa`), **`TransportIdentityKeystore` + `BlobTransportKeystore` — keyring-backed RNS transport identity over the existing SecureBlobStorage tiers (#68, CIRISEdge#99 consumer)**, **`SealedEd25519Signer` + `get_platform_ed25519_signer` — TPM/SE-sealed Ed25519 federation signing key (32-byte pubkey preserved; the Ed25519 counterpart to `get_platform_signer`'s TPM-native ECDSA) (#70, CIRISServer consumer)**, **`SealedMlDsa65Signer` + `get_platform_sealed_mldsa65_signer` — TPM/SE-sealed ML-DSA-65 seed (the PQC half; signing stays software, seed sealed at rest) so the whole hybrid federation key is hardware-backed (#71)**, **`hw_token` generic interface-keyed HW-security-token abstraction + probe→§9.4 `hardware_class` resolver (#62)** |
| `ciris-crypto` | Released | ECDSA P-256, Ed25519, ML-DSA-65 (FIPS 204), hybrid signer with bound signatures, secp256k1 wallet signing, **AES-256-GCM / HKDF / HMAC federation primitives**, **X25519 + ML-KEM-768 hybrid KEX + `key_grant` wrap v1/v2 (X25519+ML-KEM-768, CEG §10.5.3)**, **`random` SP 800-90B RNG health-check + fail-secure (#55)** |
| `ciris-verify-core` | Released | Full verification engine, HTTPS-authoritative consensus, anti-rollback, transparency log (Merkle), file integrity, remote attestation export, binary self-verification, hardware vulnerability detection, offline manifest cache, **`jcs` RFC 8785 canonicalizer + Contribution verify (#59)**, **`doc_integrity` hybrid-signed artifact integrity (#54)**, **`infrastructure_community` CEG 0.11 M-of-N trust root + `threshold` founder-quorum (#31)**, **`boundary_degraded` attestation field (#60)**, **`operational_admit` CEG 1.0-RC2 §5.6.8.13 admit surface — `resolve_role_authority` (§8.1.12.7.1 role-chain) + `verify_partner_record_quorum` (#65)**, **`holonomic` CEG §19 / §19.7 substrate verifiers — §19.0 PQC-mandatory preimage gate, §19.1 WholenessWitness Merkle + equivocation, §19.2 recursive-bootstrap (trust≠membership), §19.3 fountain, §19.4 ALM capacity, §10.5.8 A/V nonces, §19.7 `AggregationMetaV1` + `member_commitment` + `EjectionVerdict` (#78/#79); §19 cross-impl-proven vs Edge v4.1.2, §19.7 **1.0** vs Edge v4.3.0. See [`docs/HOLONOMIC_SUBSTRATE.md`](docs/HOLONOMIC_SUBSTRATE.md)** |
| `ciris-verify-ffi` | Released | C FFI, JNI bindings (Android full attestation), Swift wrapper (iOS full attestation), wallet signing FFI, named key storage, **wheel surfaces for hybrid_kex / key_grant / reconsider_dos / skill_import / locale_merkle / `jcs` (#61)**, **`resolve_role_authority` + `partner_record_quorum` operational-admit JSON surface (#65)** |
| `bindings/python` | Released | **ciris-verify 5.1.0** on PyPI with platform wheels, wallet signing, named key storage, **`jcs_canonicalize` module-level binding (#61)**, **`resolve_role_authority` + `verify_partner_record_quorum` module-level bindings (#65)** |
| `bindings/swift` | Released | CIRISVerify.swift wrapper + bridging header, XCFramework build script |

**ML-DSA-65**: Fully implemented using `ml-dsa` 0.1.0-rc.3 (RustCrypto). Bound dual signatures operational.

**TPM 2.0**: Dual-key architecture with attestation key (restricted, for quotes) and signing key (non-restricted, for arbitrary data). Supports EK certificate reading and external nonce binding. **v1.2.2+**: Signing key blobs are persisted in the `.tpm` file to survive process restart.

**Hardware Vulnerability Detection (v1.2.0+)**: Detects SoC-level vulnerabilities (CVE-2026-20435 MediaTek, CVE-2026-21385 Qualcomm) and caps attestation to SOFTWARE_ONLY for affected devices.

**Offline Manifest Cache (v1.2.0+)**: Hardware-signed cache for self-verification when registry is unreachable. No expiration - valid as long as hardware key exists.

**TPM Key Persistence (v1.2.2+)**: The TPM wrapping module now persists signing key blobs (TPM2B_PRIVATE, TPM2B_PUBLIC) alongside encrypted Ed25519 keys. This prevents identity loss across sessions. File format: `TPM2` magic + version + blobs + signature + AES-GCM ciphertext.

**secp256k1 Wallet Signing (v1.3.0+)**: Deterministic EVM wallet key derivation from Ed25519 root identity using HKDF. Supports EIP-155 transaction signing, EIP-712 typed data, and address recovery. Key hierarchy: `Ed25519 Seed → HKDF-SHA256("CIRIS-wallet-v1", "secp256k1-evm-signing-key") → secp256k1 Private Key → EVM Address (keccak256)`.

**Named Key Storage (v1.5.0+)**: Multi-key support for storing and signing with multiple Ed25519 keys identified by key_id strings. Use cases include WA (Wallet Address) signing, session keys, and backup keys. Keys are stored with hardware protection (TPM/Keystore/SecureEnclave) via SecureBlobStorage. FFI methods: `store_named_key`, `sign_with_named_key`, `has_named_key`, `delete_named_key`, `get_named_key_public`, `list_named_keys`.

**PqcSigner trait + MlDsa65SoftwareSigner (v1.9.0+, feature `pqc-ml-dsa`)**: Async PQC signer trait in `ciris-keyring` parallel to `HardwareSigner` for classical algorithms. Lets downstream consumers (CIRISPersist's cold-path PQC fill-in flow for `federation_keys` / `federation_attestations` / `federation_revocations`) get an ML-DSA-65 signer through the same `get_platform_pqc_signer(key_id, algorithm)` factory pattern that `get_platform_signer` exposes for classical, instead of reaching into the `ml-dsa` crate directly and bypassing the keyring's storage-descriptor and lifecycle abstractions. Today's impl returns a software-only `MlDsa65SoftwareSigner` (file-backed seed via `from_seed_file`, in-memory via `from_seed_bytes`); when post-quantum HSMs ship the factory will probe for hardware first. Constructed signers are byte-equivalent with `dilithium-py` (FIPS 204 final reference), so federation row signatures verify across Rust + Python implementations. See CIRISVerify#5.

**Hardware-Backed Wallet Seed Storage (v1.4.0+)**: `SecureBlobStorage` trait with platform implementations:
- **Android**: `AndroidKeystoreSecureBlobStorage` - AES-256-GCM with hardware-backed key from Android Keystore (TEE/StrongBox)
- **iOS/macOS**: `SecureEnclaveSecureBlobStorage` - ECIES with P-256 key in Secure Enclave (T2/Apple Silicon, keychain fallback on older Macs)
- **Linux/Windows**: `TpmSecureBlobStorage` - TPM 2.0 sealed blobs
- **Fallback**: `SoftwareSecureBlobStorage` - AES-256-GCM with derived master key

**777 lib tests passing** across all crates (default features; +6 more in `ciris-crypto` under the full crypto-feature set exercised by the CI `crypto-features` job — key_grant v1/v2, hybrid_kex, ml_kem). As of v5.1.0.

### v5.0.0 substrate (CEG 1.0 / Agent 3.0) — new modules

- **`ciris_crypto::rng_health` (#55)**: NIST SP 800-90B startup health-check (repetition-count + adaptive-proportion) over a fresh `OsRng` draw; latches a process-global fail-secure flag. On failure `random::fill` returns `RngHealthCheckFailed` *without drawing*. FFI runs it at `ciris_verify_init`. `random` is now a default `ciris-crypto` feature. Closes Fed TM Gap H.
- **`ciris_crypto::key_grant` v2 (#58)**: `wrap_dek_for_recipient_v2` / `unwrap_dek_v2` — X25519 + ML-KEM-768 hybrid DEK wrap (`KEY_GRANT_ALGORITHM_V2 = "x25519-mlkem768-aes256-gcm-hkdf-sha256"`), CEG §10.5.3-mandatory for streaming epoch-DEK. Gated on the `ml-kem` feature. The wire string is pinned but flagged for CEG cross-confirmation before consumers hard-code it as a closed enum.
- **`ciris_verify_core::jcs` (#59) + `jcs_canonicalize` Python binding (#61)**: RFC 8785 JSON Canonicalization (wraps `serde_jcs`/`ryu-js`, KAT-locked) — the one blessed cross-impl signing-bytes encoder for CEG §0.9 Contributions. `verify_jcs_hybrid_signature` for the Conforming-Consumer recompute path. The Python binding does zero canonicalization (transports the value into Rust) → byte-identity by construction. Honors §0.9 omit-vs-materialize (never injects defaults). Gates CIRISPersist#172 OQ-4 + the 2.9.6 JCS cutover.
- **`ciris_verify_core::doc_integrity` (#54)**: hybrid Ed25519 + ML-DSA-65 `DocSignature` over a domain-separated content hash of `(doc_path_label, doc_version_label, content)`; version-bound (no cross-release replay). Phase-1 two-person-rule is `.github/CODEOWNERS` + the CI `threat-model-changelog` gate. Fed TM Gap G Phases 1-2.
- **`ciris_verify_core::infrastructure_community` + `threshold` founder-quorum (#31)**: CEG 0.11 `cohort_subkind: infrastructure` trust root (the `ciris-canonical` shape). `verify_founder_quorum` evaluates M-of-N over the founder subset; `verify_supersedes_preserves_entrenchment` rejects a rotation that weakens `consensus_protocol` or moves `admission_quorum_basis` off `"founders"`. NB: this is the service trust-root **community**; HUMANITY_ACCORD is the separate entrenched-**family** instance (CEG §9.1) whose key material lives in Persist `federation_keys`, verify only doing the 2-of-3 hybrid-sig check.
- **`boundary_degraded` on the attestation result (#60)**: Verify-authored, orthogonal to `hardware_trust_degraded`. `boundary_degraded = (hardware_type == SoftwareOnly)` (no secure element present). Consumers surface it; they MUST NOT derive it from `!hardware_backed`.

### v5.1.0 substrate (CEG 1.0-RC2 §5.6.8.13 operational-data admit) — new module

- **`ciris_verify_core::operational_admit` (#65, Registry#70)**: the admit-verification surface CIRISPersist calls at `put_organization` / `put_org_membership` / `put_partner_record`. RC2 §5.6.8.13 pins the two-quorums split — *signature verification is Verify's, the substrate's merge logic never counts signatures* — so this is the **sole** owner of both operational signature paths (no third bespoke path; §5.6.8.13 forbids it). Two shapes:
  - **`resolve_role_authority` (§8.1.12.7.1 `delegates_to` role-chain resolver)** for `organization` / `org_membership`: a **pure evaluator** (no I/O) over caller-resolved current-state grants. Authorized iff the actor holds the required `OrgRole` via a signature-valid grant whose authority chain is rooted at a recognized steward — bounded, cycle-detected, fail-closed. **NOT** founder-quorum. Identity binding is load-bearing: grant signatures verify against pubkeys **pinned in the caller's `key_directory`** for the claimed `attesting_key_id` (reusing `threshold` bound-sig at threshold 1), never the pubkeys embedded in the grant — a forged grant under a steward's key_id fails the binding.
  - **`verify_partner_record_quorum`** for `partner_record`: canonicalizes via `jcs` and delegates to `verify_founder_quorum` (#31) — the signature *set* over byte-identical JCS bytes, M-of-N stewards. `check_set_semantics_sorted` is the producer-side guard that catches an unsorted capability array (§0.9.2.1 rule 1) *before* M stewards sign divergent bytes and the quorum silently collapses.
  - Exposed through FFI (`ciris_verify_resolve_role_authority` / `ciris_verify_partner_record_quorum`, JSON-in/JSON-out) + Python (`resolve_role_authority` / `verify_partner_record_quorum`). **Role-lattice note:** ships the strict reading (`OrgAdmin` superuser, every other role exact-match) — flagged on #65 for CEG to confirm or enrich (a one-line change in `OrgRole::satisfies`).

### v5.6.0 substrate — adversarial security-audit remediation

A 5-dimension adversarial audit found 1 CRITICAL + 3 HIGH, all confirmed in code, all in **wiring** (sound primitives not invoked on the decisions that matter — not the crypto). v5.6.0 closes them:

- **CRITICAL — license-signature gate (#72)**: `engine.rs` / `jwt.rs` / `validation.rs` / `unified.rs`. `get_license_details` now calls `license_signature_verified` (new `jwt::verify_license_jwt`, hybrid Ed25519 + ML-DSA-65 against the **consensus steward key**, PQC key bound to the consensus fingerprint via constant-time compare) and returns `None` unless it verifies — fail-closed if no consensus key. Removed the expired-license fail-open; a `ValidationError` now degrades instead of admitting. Proven by `test_get_license_details_forged_cache_rejected` + `test_verify_forged_license_rejected` (a forged cache JWT → community, not licensed). Plumbs `steward_key_pqc` / `consensus_key_pqc` through `SourceData` / `ValidationResult`.
- **HIGH — real TPM sealing (#73)**: `storage/tpm.rs`. Master key sealed under the SRK via `TPM2_Create` (persists `out_private` / `out_public` as `{alias}.tpm_seal`, recovered with `TPM2_Unseal`); `is_hardware_backed()` returns `true` **only** when `MasterState::TpmSealed`, and the software fallback reports `false` honestly. Eliminated the plaintext `tpm_sig.bin`.
- **HIGH — fail-secure keygen (#74)**: `ciris-crypto` keygen now honors the SP 800-90B RNG health latch. `Ed25519Signer::random()` / `P256Signer::random()` return `Result` (breaking) and propagate `RngHealthCheckFailed` instead of drawing from a failed CSPRNG — no weak key is ever produced. Proven by the per-primitive `*_fails_secure_when_rng_marked_failed` tests.
- **HIGH — RNS `destination_hash` recompute (#28)**: `transport_binding.rs`. New public `compute_destination_hash` (the §5.6.8.8.1.1 two-stage RNS derivation) is the single producer/consumer derivation; `verify_destination_hash` recomputes + byte-compares, `DestinationHashMismatch` → `authentic=false`. **Producer↔consumer coherence (#63)**: `self_at_login::sign_transport_binding` now *computes* the hash via that same function (no longer accepts an arbitrary one), so a producer can never emit a binding the verifier rejects.
- **#63 producer signing + #71 sealed ML-DSA-65**: `self_at_login.rs` emits the signed delegation / partnership / transport-binding envelopes that the verify-side evaluators consume (round-trip *is* the contract); `sealed_mldsa65.rs` gives the PQC half of the hybrid federation key the same sealed-at-rest custody as #70's Ed25519 half.

### v5.7.0 substrate — CEG 1.0-RC7 conformance + HNDL hardening

RC7 (CIRISRegistry, commit `9535b2a`) pinned three new asks; a deep PQC/HNDL audit against `MISSION.md` + `THREAT_MODEL.md` + `FEDERATION_THREAT_MODEL.md` confirmed the hybrid model was **poppable by a classical-only break** at three federation-tier gates. All closed:

- **CRITICAL — hybrid-required at every federation-tier gate (#75, RC7 §10.1.5.1.1 / F-AV-14)**: the PQC half is now MANDATORY at the federation admission boundary — a classical-only ("hybrid-pending") signature no longer counts. Three surfaces carried the pre-1.0 accommodation and now reject it: (1) `threshold::verify_threshold_signatures` gained `HybridPolicy` (default `RequireHybrid`; inherited by operational_admit role-chain + partner-quorum, transport_binding, founder-quorum, humanity_accord, keyset rotation); (2) `provenance::verify_provenance_chain` (default `RequireHybrid`; new `LinkNotHybrid` error); (3) the license gate — `LicenseVerification::is_licensable()` now requires `HybridVerified` (a `ClassicalVerified` license degrades to community; `classical_gate_held()` is the diagnostic split). Each gate keeps an explicit `AllowClassicalPending` local-tier (§10.1.5.2 self-read) path. Proven by paired `*_rejected_at_federation_tier` / `*_only_at_local_tier` + `submission_stripping_pqc_half_does_not_count` + `test_classical_only_license_degrades_to_community`. doc_integrity / federation_envelope / transparency-STH were already hybrid-mandatory by construction (`ciris_crypto::HybridVerifier`). **Cutover dependency:** the registry must publish each steward/founder `steward_key_pqc` (+ fingerprint) over HTTPS consensus or federation-tier admission/licensing fails closed — the intended fail-secure direction (ties to #69 / Persist#171).
- **HIGH — partnership seven-member set (#76, RC7 §8.1.12.7.1(a))**: `self_at_login::sign_partnership_grant`/`accept` now emit EXACTLY the pinned seven members (`attestation_type:"scores"`, `attesting_key_id`, `dimension`, `score`, `subject_key_ids:[partner]`, `bilateral_pair_id`, `signed_at`; no `valid_until`) — the prior `envelope_type`/scalar-`partner_key_id`/`consented_at` shape diverged from Persist's JCS bytes. The affirmation `score` value (`1`) is flagged for Persist cross-confirmation.
- **HIGH — `infra:*` / `agency:*` delegation scope split (#77, RC7 §8.1.12.7.1 / §5.6.8.10 / §1.3)**: `operational_admit::verify_delegation_scope_split` (pure evaluator + reserved `INFRA_SCOPES`/`AGENCY_SCOPES`) makes "infrastructure must not have agency" wire-checkable — a `node`-only (`identity_type` lacks `agent`) delegate carrying any `agency:*` (or legacy agency kind) is rejected, unknown scope fail-closed. Wired through FFI (`ciris_verify_delegation_scope_split`) + Python (`verify_delegation_scope_split`). Follow-up on #77: the producer `delegates_to` envelope (the verifier obligation — the load-bearing §1.3 half — ships now).

### Reading discipline — CEG family vs community (avoid a recurring mix-up)

`HUMANITY_ACCORD` is a **`family`** (CEG §9.1 / §5.6.8.9 — the canonical entrenched-family instance, `quorum:2/3`, 3 humans, structural-invisibility). `ciris-canonical` is a **`community`** (`cohort_subkind: infrastructure`, §5.6.8.10 — the service trust root for Registry/Lens/Node, founder-quorum, federates publicly). Both are `quorum:M/N` + entrenched and easy to conflate; the `infrastructure_community` module (#31) is the **community** one. The accord hardware-class taxonomy (`YubiKey_5_FIPS` etc.) is CEG §9.4.

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

## Reading discipline — fractal-self framing (v4.0.0+)

Per CEG 0.2 README "How to read this spec without Cartesian default"
(adopted as verify-side discipline in MISSION.md §1.5.1): **self at
every scale is the already-relationally-constituted entity speaking**.
A reviewer trained on PGP / X.509 / DID atomic-principal frames will
look at `witness_relation: self`, attester-supplied `confidence`,
self-signed `federation_keys`, the genesis-case
`WitnessConsistencyProof`, or a deployed steward emitting
`cert_validity:{steward_id}` self-attestation — and want to add
**cross-attestation admission gates**. That is the misread.
Cross-attestations are upstream of the self-attestation, not
downstream gates on it. See MISSION.md §1.5.1 for the full framing
and concrete review-time examples.

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
| `../CIRISRegistry` | Source of verification data; **CEG + identity authority** — owns the identity/admission *API routes* (incl. key registration), policy layer over Persist's tables |
| `../CIRISPersist` | Storage substrate — owns `federation_keys` (the registered-key tables); written *through* Registry's policy layer, not by clients directly |
| `../CIRISAgent` | Primary consumer of verification; embeds the verify wheel; hosts **the client (KMP, `CIRISAgent/client`)** |
| `../CIRISPortal` | License management portal |

**Client / UI topology (corrected 2026-06-09):** The active client is **Kotlin Multiplatform in `CIRISAgent/client`**. **`CIRISGUI` is orphaned** (do not target it). "UI" in project discussion usually means **API routes**, not pixels. Key-registration / identity routes are **CIRISRegistry's** (identity + CEG admission authority); the local key *ceremony* (hardware probe, keygen, touch, hybrid sign) runs client-side via the verify wheel; the resulting pubkey + `hardware_class` + attestations are POSTed to Registry, which validates CEG conformance + admission and writes through to Persist `federation_keys`. See [[reference_client_topology_and_route_ownership]].

## CLI Usage

```bash
# Build CLI
cargo build --release -p ciris-verify-core

# Run full verification
./target/release/ciris_verify run

# Run self-check (binary + function integrity)
./target/release/ciris_verify self-check

# Validate registry consensus across sources
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
