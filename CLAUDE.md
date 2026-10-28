# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CIRISVerify is the **hardware-rooted license verification module** for the CIRIS ecosystem. It is an **open-source (AGPL-3.0) Rust binary** that provides cryptographic proof of license status, ensuring that community agents (CIRISCare) cannot masquerade as licensed professional agents (CIRISMedical, CIRISLegal, CIRISFinancial).

**This repository contains the full source code, protocol documentation, and specifications for CIRISVerify.**

## Repository Structure

| Path | Purpose |
|------|---------|
| `FSD/FSD-001_CIRISVERIFY_PROTOCOL.md` | Full technical specification (authoritative) |
| `FSD/FSD-004_ACCORD_DECIMATION_RECOVERY.md` | Accord **live-quorum** operation & recovery under decimation (quorum floats over who proves life; proof-of-life modifies the quorum + carries a vote; always leans toward firing; adversarial-AGI first-strike threat model). Ratified (CC 0.3 §4.2.6); Phase 1 implemented in `accord_live_quorum` (`tally_live_quorum`, `verify_fire` / `membership_change` / `resume_by_live_quorum`, `verify_recovery_supersede`). Phase 3 (server state) is downstream. |
| `FSD/FSD-005_HUMANITY_ACCORD.md` | **The Humanity Accord — what & why** (descriptive): the constitutional kill-switch rooted in hardware-attested human custody. Recognition root (no-TOFU baked genesis) + custody attestation (YubiKey PIV → pinned Yubico root) + invocation rules (CC 4.2.1). Precise crypto (M-of-N not threshold; PQC at the authority layer, Ed25519-strength custody), boundaries, prior-art delta, verifiable-claim receipts. |
| `FSD/FSD-006_MANIFEST_LIFECYCLE.md` | **The build-manifest lifecycle end to end** — the 15 stages a public blob passes through (bytes → claim → sign → admit → store → holds_bytes → replicate → standing → fetch → size/SHA check → consume → present → retire), each mapped to its owner and CC clause, as the template the encyclopedia / NodeCore blob path inherits. Covers rotation (`supersedes`) and the presenter claim (trust ladder). |
| `protocol/ciris_verify.proto` | Public API contract (gRPC/protobuf) |
| `docs/THREAT_MODEL.md` | Formal threat model (attack vectors, mitigations) |
| `docs/SUBSTRATE.md` | CEG §19 / §19.7 holonomic verifiers — threat model, module map, conformance status (§19 + §19.7 cross-impl-proven) |
| `docs/TPM_ANCHOR_PROVENANCE.md` | How the 40 baked TPM EK vendor roots were sourced, why the tier is `CommunityAggregated` not `VendorOfficial`, what was excluded and why, and what would justify promotion |
| `docs/FEDERATION_IDENTITY.md` | Operator walkthrough: provision a YubiKey PIV Ed25519 key → `identity create` → CEG outbox → CIRISServer relay |
| `docs/HOW_IT_WORKS.md` | How CIRISVerify works |
| `docs/REGISTRY_BINARY_MANIFEST.md` | Binary manifest spec for registry team |
| `src/ciris-keyring/` | Cross-platform hardware keyring (extends Veilid pattern) |
| `src/ciris-crypto/` | Hybrid cryptography (ECDSA P-256 + ML-DSA-65) |
| `src/ciris-verify-core/` | Core verification logic (engine, trust root, transparency log) |
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

See [`docs/DEV_HYGIENE.md`](docs/DEV_HYGIENE.md) for the layered self-cleaning policy (dev-profile incremental disabled, bump-time cleanup, periodic sweep).

## Current Implementation Status

*(Current release: **22.0.0** — see [Release history](#release-history) for this and every prior entry.)*

| Crate | Status | Notes |
|-------|--------|-------|
| `ciris-keyring` | Released | `HardwareSigner` trait, `SoftwareSigner`, Android Keystore, TPM 2.0 via the runtime-loaded plugin (seal/unseal, ECDSA P-256 signer, quote), `SecureBlobStorage` tiers, `PqcSigner` + `MlDsa65SoftwareSigner` (feature `pqc-ml-dsa`), `TransportIdentityKeystore` + `BlobTransportKeystore` (keyring-backed RNS transport identity), `SealedEd25519Signer` + `get_platform_ed25519_signer` (TPM/SE-sealed Ed25519 federation key, 32-byte pubkey), `SealedMlDsa65Signer` + `get_platform_sealed_mldsa65_signer` (sealed ML-DSA-65 seed; signing in software), `self_enc_keys::SelfEncKeys` (content-enc pubkeys and KEX respond from inside custody), `hw_token` interface-keyed token taxonomy + CEG §9.4 `hardware_class` resolver, `pkcs11` PKCS#11 / YubiKey PIV signer, `usb_wrapped_mldsa65::UsbWrappedMlDsa65Signer` (ML-DSA-65 seed AES-256-GCM-wrapped on a USB key under `HKDF(Ed25519_sign("ciris.accord.mldsa-usb-wrap.v1"‖key_id), salt)`; needs the USB, the YubiKey, PIN and touch; YubiKey stays signing-only per CC §9.2; CLI `--portable-usb`), `HardwareType::as_platform()` / `from_platform()` / `ALL_PLATFORMS` (the closed 13-token `hardware_custody:{platform}` vocabulary), storage factory that opens the tier a key already lives in and never falls back, `restore_stranded_software_key`, `storage::HigherTierMint` + `superseded_legacy_keys()`, key-material draws gated by the RNG health latch |
| `ciris-crypto` | Released | ECDSA P-256, Ed25519 (strict verification by default; `verify_permissive` and `verify_strict` named variants), ML-DSA-65 (FIPS 204), hybrid signer with bound signatures, secp256k1 wallet signing, AES-256-GCM (with and without associated data) / HKDF / HMAC, X25519 + ML-KEM-768 hybrid KEX, `key_grant` wrap v1/v2 (CEG §10.5.3), `random` SP 800-90B RNG health check + fail-secure, scope-native privacy (HKDF-SHA3-256, HMAC-SHA3-256, `xchacha` XChaCha20-Poly1305, `hpke` RFC 9180 mode_base over X-Wing, `scope_privacy` record_id / symbol-key / destination / witness-cover-leaf derivations; see [`docs/SCOPE_PRIVACY_NOTES.md`](docs/SCOPE_PRIVACY_NOTES.md)), `self_enc` deterministic X25519 + ML-KEM-768 from the Ed25519 seed, `epoch_key` per-`(stream_id, epoch)` DEK + nonce (CC 5.1), `stream_seal::stream_nonce` (CC 5.3.3.1), `transit_kex` A/V per-hop transit key (CC 5.3.3.5 E1), EVM transaction construction (`keccak256`, EIP-55 `checksum_address`, RLP, `legacy_tx_signing_bytes` / `_hash`, `sign_legacy_transaction` with EIP-155 `v`, `encode_signed_legacy_tx`, `signed_legacy_tx_hash`) |
| `ciris-verify-core` | Released | Verification engine, GenesisBundle trust root (`genesis_bundle`, `validation::TrustRootValidator`, CC 5.3.4), anti-rollback, transparency log (Merkle), file integrity, remote attestation export, binary self-verification, hardware vulnerability detection, offline manifest cache, `jcs` RFC 8785 canonicalizer, `doc_integrity`, `infrastructure_community` + `threshold` founder quorum, `operational_admit`, `boundary_degraded`, `device_attestation` (Android Key Attestation with `AndroidChallengePolicy::{Bound, GenerationOnly}`, TPM EK certificate validation), `app_attest` (Apple App Attest), `trust_anchor_store` (CoTS-shaped constrained anchor store with baked Yubico, Google, Apple and TPM roots), `holonomic` CEG §19 / §19.7 verifiers (see [`docs/SUBSTRATE.md`](docs/SUBSTRATE.md)), `self_at_login` producers + hardware-rooted login ceremony, `ceg_outbox`, `federation_self_record` (self, scrubbed and multi-scrub `KeyRecord` producers, `sign_occurrence_revocation`), `accord_genesis` (HUMANITY_ACCORD genesis producer, baked genesis, `baked_accord_roster`, `accord_holder_bootstrap_anchor`; see [`docs/ACCORD_KEY_GENESIS_RUNBOOK.md`](docs/ACCORD_KEY_GENESIS_RUNBOOK.md)), `humanity_accord` invocations + `accord_halt_latch` (CC 4.2.6: one holder halts, a lone halt lapses unless a majority confirms, a majority resumes), `accord_live_quorum`, `accord_custody_attestation` (YubiKey PIV 9c → f9 → pinned Yubico root, FIPS + touch=always → `YubiKey_5_FIPS`), `manifest_contribution` + `build_attestation_bundle`, `security::wheel` wheel-identity check, `subject_binding`, `canonical_subject` (CC 2.3.2.1), `classification`, `redactable`, `presentation`, `announce_policy`, `fedcode`, the `ciris-verify accord` / `identity` / `token` / `manifest` CLI |
| `ciris-verify-ffi` | Released | C FFI, JNI bindings (Android full attestation), Swift wrapper (iOS full attestation), wallet signing, named key storage, JSON surfaces for hybrid_kex / key_grant / reconsider_dos / skill_import / locale_merkle / `jcs`, `resolve_role_authority` / `partner_record_quorum` / `delegation_scope_split`, `ciris_verify_accord_custody_attestation`, `ciris_verify_accord_invocation_verify` / `_latch_apply` / `_latch_status`, `ciris_verify_rns_destination_hash`, `ciris_verify_scope_privacy_derive`, `ciris_verify_epoch_key_derive`, `ciris_verify_canonical_subject`, `ciris_verify_self_enc_derive` (mint-time only) / `_pubkeys` / `_respond`, `ciris_verify_keccak256` / `ciris_verify_checksum_address` / `ciris_verify_sign_evm_transaction_fields` (amounts as decimal strings), `ciris_verify_verify_ed25519` (strict by default, echoes the `rule`) / `ciris_verify_verify_p256` (`encoding` required), `ciris_verify_test_anchor_compiled_in`, `ciris_verify_ffi_link_anchor` |
| `bindings/python` | Released | ciris-verify on PyPI with platform wheels, wallet signing, named key storage, `jcs_canonicalize`, `resolve_role_authority`, `verify_partner_record_quorum`, `verify_delegation_scope_split`, `verify_accord_custody_attestation`, `verify_accord_invocation` / `accord_latch_apply` / `accord_latch_status`, `rns_destination_hash`, `scope_privacy` namespace, `derive_epoch_key` / `derive_epoch_stream_nonce`, `canonical_subject` / `canonical_subject_from_triple` / `parse_canonical_subject`, `derive_self_enc` / `self_enc_pubkeys` / `self_enc_respond`, `keccak256` / `checksum_address` / `CIRISVerify.sign_evm_transaction_fields`, `verify_ed25519` / `verify_p256`, `test_anchor_compiled_in`; `SourceDetails` carries `sources` / `trust_root` |
| `bindings/swift` | Released | CIRISVerify.swift wrapper + bridging header, XCFramework build script |

**Trust root**: the CC 5.3.4 **GenesisBundle** (charter, accord-holder roster, serve nodes and their transit destinations), fetched over HTTPS from every configured host and verified by `genesis_bundle::verify_genesis_bundle` against the A1/B1/C1 holders baked into this binary (never the bundle's own `holders`). Threshold is `max(carried M, strict majority of the baked roster)`, hybrid on every counted authorization, v4 only. `select_trust_root` takes the highest verified version; two verified bundles at one version with different fingerprints select nothing (CC 3.2 T8(ii)). One verified host suffices. There is no DNS source and no single steward key.

**Licensing**: a licence is a cosigned `licensure:{authority}:v1` row honoured through the reader's own trust set (CC 4.4.3.8). Verify does not yet evaluate those rows, so **every deployment is community**. Revocation is persist's `federation_revocations` quorum rows.

**ML-DSA-65**: Implemented using `ml-dsa` 0.1.1 (RustCrypto, seed zeroize). Bound dual signatures operational.

**TPM 2.0**: Reached only through the runtime-loaded plugin `libciris_tpm_plugin.so` over a versioned C ABI (seal/unseal, ECDSA P-256 signer, quote/attestation); the keyring links no `tss-esapi` on any target. The x86_64-linux wheel bundles the plugin; elsewhere TPM is opportunistic and falls back to software.

**Hardware Vulnerability Detection**: Detects SoC-level vulnerabilities (CVE-2026-20435 MediaTek, CVE-2026-21385 Qualcomm) and caps attestation to SOFTWARE_ONLY for affected devices.

**Offline Manifest Cache**: Hardware-signed cache for self-verification when registry is unreachable. No expiration - valid as long as hardware key exists.

**secp256k1 Wallet Signing**: Deterministic EVM wallet key derivation from Ed25519 root identity using HKDF. Supports EIP-155 transaction signing, EIP-712 typed data, and address recovery. Key hierarchy: `Ed25519 Seed → HKDF-SHA256("CIRIS-wallet-v1", "secp256k1-evm-signing-key") → secp256k1 Private Key → EVM Address (keccak256)`.

**Named Key Storage**: Multi-key support for storing and signing with multiple Ed25519 keys identified by key_id strings. Use cases include WA (Wallet Address) signing, session keys, and backup keys. Keys are stored with hardware protection (TPM/Keystore/SecureEnclave) via SecureBlobStorage. FFI methods: `store_named_key`, `sign_with_named_key`, `has_named_key`, `delete_named_key`, `get_named_key_public`, `list_named_keys`.

**PqcSigner trait + MlDsa65SoftwareSigner (feature `pqc-ml-dsa`)**: Async PQC signer trait in `ciris-keyring` parallel to `HardwareSigner`. `get_platform_pqc_signer(key_id, algorithm)` returns an ML-DSA-65 signer through the same factory pattern as `get_platform_signer`, so consumers (e.g. CIRISPersist's PQC fill-in for `federation_keys` / `federation_attestations` / `federation_revocations`) do not reach into the `ml-dsa` crate directly. The current implementation is software-only `MlDsa65SoftwareSigner` (file-backed seed via `from_seed_file`, in-memory via `from_seed_bytes`). Signers are byte-equivalent with `dilithium-py` (FIPS 204 final reference).

**Hardware-Backed Secure Blob Storage**: `SecureBlobStorage` trait with platform implementations:
- **Android**: `AndroidKeystoreSecureBlobStorage` - AES-256-GCM with hardware-backed key from Android Keystore (TEE/StrongBox)
- **iOS/macOS**: `SecureEnclaveSecureBlobStorage` - ECIES with P-256 key in Secure Enclave (T2/Apple Silicon, keychain fallback on older Macs)
- **Linux/Windows**: `PluginTpmSecureBlobStorage` - 32-byte master sealed through the TPM plugin, per-blob AES-256-GCM under `HKDF("CIRIS-TPM-blob-v2", master)`
- **Fallback**: `SoftwareSecureBlobStorage` - AES-256-GCM with derived master key

Absence of a blob is `KeyNotFound`; a present-but-unreadable blob is `StorageFailed` and is never minted over.

### Modules

- **`ciris_crypto::rng_health`**: NIST SP 800-90B startup health check (repetition-count + adaptive-proportion) over a fresh `OsRng` draw; latches a process-global fail-secure flag. On failure `random::fill` returns `RngHealthCheckFailed` *without drawing*, and keygen (`Ed25519Signer::random()` / `P256Signer::random()` return `Result`) never produces a key. FFI runs it at `ciris_verify_init`. `random` is a default `ciris-crypto` feature.
- **`ciris_crypto::key_grant` v2**: `wrap_dek_for_recipient_v2` / `unwrap_dek_v2` — X25519 + ML-KEM-768 hybrid DEK wrap, `KEY_GRANT_ALGORITHM_V2 = "x25519_mlkem768_aes256_gcm_hkdf_sha256"` (CC 5.1 snake_case; the hyphenated form is accepted only via `key_grant_algorithm_v2_accepts` with the legacy flag, never emitted). Required for streaming epoch-DEK (CEG §10.5.3). Gated on the `ml-kem` feature.
- **`ciris_verify_core::jcs`** + Python `jcs_canonicalize`: RFC 8785 JSON Canonicalization (wraps `serde_jcs`/`ryu-js`, KAT-locked) — the cross-impl signing-bytes encoder for CEG §0.9 Contributions. `verify_jcs_hybrid_signature` for the consumer recompute path. The Python binding transports the value into Rust and does no canonicalization itself. Honors §0.9 omit-vs-materialize (never injects defaults).
- **`ciris_verify_core::doc_integrity`**: hybrid Ed25519 + ML-DSA-65 `DocSignature` over a domain-separated content hash of `(doc_path_label, doc_version_label, content)`; version-bound (no cross-release replay). The two-person rule is `.github/CODEOWNERS` + the CI `threat-model-changelog` gate.
- **`ciris_verify_core::infrastructure_community` + `threshold` founder quorum**: CEG 0.11 `cohort_subkind: infrastructure` trust root (the `ciris-canonical` shape). `verify_founder_quorum` evaluates M-of-N over the founder subset; `verify_supersedes_preserves_entrenchment` rejects a rotation that weakens `consensus_protocol` or moves `admission_quorum_basis` off `"founders"`. This is the service trust-root **community**; HUMANITY_ACCORD is the separate entrenched **family** (CEG §9.1).
- **`boundary_degraded`** on the attestation result: orthogonal to `hardware_trust_degraded`; `boundary_degraded = (hardware_type == SoftwareOnly)`. Consumers surface it and MUST NOT derive it from `!hardware_backed`.
- **`ciris_verify_core::operational_admit`** (CEG 1.0-RC2 §5.6.8.13): the sole owner of operational signature verification for `put_organization` / `put_org_membership` / `put_partner_record`.
  - **`resolve_role_authority`** (§8.1.12.7.1 `delegates_to` role-chain) for `organization` / `org_membership`: a pure evaluator over caller-resolved grants. Authorized iff the actor holds the required `OrgRole` via a signature-valid grant whose chain is rooted at a recognized steward — bounded, cycle-detected, fail-closed; not founder quorum. Grant signatures verify against pubkeys pinned in the caller's `key_directory`, never pubkeys embedded in the grant. Role lattice: `OrgAdmin` is superuser, every other role is exact-match (`OrgRole::satisfies`).
  - **`verify_partner_record_quorum`** for `partner_record`: canonicalizes via `jcs` and delegates to `verify_founder_quorum` (M-of-N stewards over byte-identical JCS bytes). `check_set_semantics_sorted` is the producer-side guard for unsorted capability arrays (§0.9.2.1 rule 1).
  - **`verify_delegation_scope_split`** (§8.1.12.7.1 / §5.6.8.10 / §1.3): a `node`-only delegate carrying any `agency:*` (or legacy agency kind) is rejected; unknown scope fails closed. Reserved `INFRA_SCOPES` / `AGENCY_SCOPES`.
  - Exposed through FFI (`ciris_verify_resolve_role_authority` / `ciris_verify_partner_record_quorum` / `ciris_verify_delegation_scope_split`, JSON-in/JSON-out) + Python.
- **Hybrid required at every federation-tier gate** (§10.1.5.1.1): `threshold::verify_threshold_signatures` takes `HybridPolicy` (default `RequireHybrid`, inherited by role-chain, partner quorum, transport binding, founder quorum, humanity_accord and keyset rotation) and `provenance::verify_provenance_chain` defaults to `RequireHybrid` (`LinkNotHybrid`). Each gate keeps an explicit `AllowClassicalPending` local-tier (§10.1.5.2) path. doc_integrity / federation_envelope / transparency STH are hybrid-mandatory by construction (`ciris_crypto::HybridVerifier`).
- **`transport_binding`**: `compute_destination_hash` (§5.6.8.8.1.1 two-stage RNS derivation) is the single producer/consumer derivation; `verify_destination_hash` recomputes and byte-compares (`DestinationHashMismatch` → `authentic=false`); `self_at_login::sign_transport_binding` computes the hash through the same function.
- **`self_at_login`**: emits the signed delegation, partnership (exactly the seven §8.1.12.7.1(a) members: `attestation_type:"scores"`, `attesting_key_id`, `dimension`, `score` = 1, `subject_key_ids:[partner]`, `bilateral_pair_id`, `signed_at`) and transport-binding envelopes that the verify-side evaluators consume.

### Reading discipline — CEG family vs community (avoid a recurring mix-up)

`HUMANITY_ACCORD` is a **`family`** (CEG §9.1 / §5.6.8.9 — the canonical entrenched-family instance, `quorum:2/3`, 3 humans, structural-invisibility). `ciris-canonical` is a **`community`** (`cohort_subkind: infrastructure`, §5.6.8.10 — the service trust root for Registry/Lens/Node, founder-quorum, federates publicly). Both are `quorum:M/N` + entrenched and easy to conflate; the `infrastructure_community` module is the **community** one. The accord hardware-class taxonomy (`YubiKey_5_FIPS` etc.) is CEG §9.4.

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
- Document all divergences in `docs/UPSTREAM_TRACKING.md`

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│               TRUST ROOT (CC 5.3.4 GenesisBundle over HTTPS)            │
│  HTTPS trust-root hosts (api / us / eu registry, serve nodes) each      │
│  serve the holder-authorized GenesisBundle                              │
│  Every bundle verified against the accord holders baked into the binary │
│  Highest verified version selected; one verified host suffices          │
│  Two verified bundles at one version, different fingerprints → none     │
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
- Licensure rows not yet evaluated (CC 4.4.3.8) → COMMUNITY MODE for every deployment

**SOFTWARE_ONLY Limitation**: Software-only attestation caps at UNLICENSED_COMMUNITY tier.

## Reading discipline — fractal-self framing (v4.0.0+)

Per CEG 0.2 README "How to read this spec without Cartesian default"
(adopted as verify-side discipline in MISSION.md §1.5.1): **self at
every scale is the already-relationally-constituted entity speaking**.
A reviewer trained on PGP / X.509 / DID atomic-principal frames will
look at `witness_relation: self`, attester-supplied `confidence`,
self-signed `federation_keys` (incl. the genesis self-signed `KeyRecord` producer, `federation_self_record.rs`, where `scrub_key_id == key_id`), the genesis-case
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

## Release history

Newest first, **one release per line**, so adding a release is a one-line diff.

- **22.0.0** (BREAKING) — The substrate verifiers move from `ciris_verify_core::holonomic` to `ciris_verify_core::substrate` (CC 6.1); every item and submodule (`wholeness_witness`, `aggregation`, `fountain`, `alm`, `av_chunk`, `preimage`, `storage_contention`, `bootstrap`) is unchanged and there is no alias, so consumers replace the path prefix. The `announce_policy` normative authority string is now `"CC 5.4.6"`. Documentation describes the current state only: superseded design notes and point-in-time reports are removed (they remain in git history).
- **21.0.0** (BREAKING) — Trust root is the CC 5.3.4 GenesisBundle: `genesis_bundle::verify_genesis_bundle` checks holder authorizations against the baked A1/B1/C1 roster, and `TrustRootValidator` selects the highest verified version. Removed: DNS sources, steward key, licence JWTs, revocation list; every deployment is community until licensure rows (CC 4.4.3.8) are evaluated. Wire: `ValidationResults` / `SourceCheckResult` reshaped, `GetStewardKey` → `GetTrustRoot`, `VerifyConfig` loses `dns_*` / `trust_model` / `dns_transport`. Keyring storage opens the tier a key already lives in (#311). `k256` / `p256` 0.14 (RUSTSEC-2026-0387, #316); RUSTSEC-2026-0346–0349, 0367–0369, 0381, 0382, 0385, 0386 fixed by upgrade. (#176, #69)
- **20.2.0** — `ciris_crypto::transit_kex` (feature `transit-kex`): the CC 5.3.3.5 E1 A/V per-hop transit key, hybrid X25519 + ML-KEM-768 against the relay's `transit_kex_pubkeys`, bound to the RNS `link_id` and both `occurrence_key_id`s, one key per direction, keys per handshake, no classical fallback; `TransitHandshake::to_bytes` / `from_bytes` carry the suite identifier `transit_x25519_mlkem768_hkdf_sha256` (`TransitSuite`). No FFI. `quinn-proto` 0.11.19 (RUSTSEC-2026-0338/0339/0340/0341/0342). (#309)
- **20.1.0** — `security::wheel` (`read_wheel_identity`, `check_wheel_matches`, `platform_fits_target`) and `verify_wheel_blob` require a build manifest's `binary_version` and target to match the wheel's own `METADATA` / `WHEEL`; `ciris-build-sign sign --binary *.whl` refuses to sign a mismatch. New dependency `zip` (decompress-only). No FFI. (#306)
- **20.0.0** (BREAKING) — Kill switch per CC 4.2.6: a `constitutional` halt verifies on one holder's hybrid signature and pauses agents; a lone halt lapses `halt_fuse_secs` (86400) after receipt unless a strict majority cosigns `accord:lifecycle:confirmed` (`confirms_halt_id`); a majority `lifecycle:active` ends any halt. Thresholds live in `InvocationKind::required_signatures`; `accord_halt_latch::HaltLatch` + FFI `ciris_verify_accord_invocation_verify` / `_latch_apply` / `_latch_status` + wheel equivalents. Breaking: `InvocationKind::LifecycleConfirmed`, `Invocation.confirms_halt_id`. A/V inner nonce is the CC 5.3.3.1 STREAM nonce (`stream_seal::stream_nonce`, `av_inner_nonce`); `inner_nonce` / `AV_INNER_DOMAIN` deprecated. (#305, #303)
- **19.0.0** (BREAKING) — Every emitted dimension family carries the `:v1` tail (`dim::DIMENSION_VERSION`). `sign_build_manifest_contribution` emits persist's envelope (facts + `row` mirror + `asserted_at` + `build.manifest_size`; no `on_behalf_of` / `delegation_ref`). `verify_build_attestation_bundle` takes a `PipelineBlessing` (`standing`: `Conferred { root, grant, plane }` or `AccordRole`, CC 4.2.1) instead of `(pipeline_record, accord_anchors)`. Presenter bundles ride the trust ladder (`PresentedBuild::{SelfVerify, AgentIntegrity}`) with `references_attestation_id` / `evidence_refs`. FFI/wheel verdict key is `verified`. CI runs CC's namespace matcher. FSD-006 added. (#299)
- **18.0.0** (BREAKING) — `hardware_custody:{platform}:v1` uses CC's closed 13-token vocabulary at every emit site: Android follows the measured KeyMint level, new `KeyAttestationResult.hardware_platform` follows where the key actually lives, unregistered tokens are omitted, resolved claims score PASS; `TpmEkVerdict::to_attestation_entries` takes `Option<TpmProbedPlatform>` (`None` → no custody dimension). `InvocationKind` is lowercase under `ciris.accord_invoke.v2` (#297). `derive_symmetric_key` / `derive_transport_identity` zeroize (#295). Python `HardwareType` lists all 13 tokens with Rust's security levels. (#296)
- **17.1.0** — `compare_sources` → `SourceDivergence::{Agree, ReplicaLag, Conflict}`: equal revision with different keys is a conflict, a revision lag is not; the consensus representative is the group's highest revision; `ConsensusPosture` logs on transitions only. (#223)
- **17.0.0** (BREAKING) — `ClassicalVerifier::verify` (Ed25519) is strict, rejecting small-order `A` / `R`; `verify_permissive` keeps the old rule; FFI `ciris_verify_verify_ed25519` (strict by default, echoes `rule`) and `ciris_verify_verify_p256` (`encoding` required), wheel `verify_ed25519` / `verify_p256` (#207). `archive_superseded_legacy_keys` requires a `HigherTierMint` witness; `superseded_legacy_keys()` accessors (#292). `AndroidChallengePolicy::{Bound, GenerationOnly}` + `verify_android_key_attestation_with_challenge_policy`; the verdict carries `challenge_checked` and is `#[non_exhaustive]` (#293).
- **16.3.0** — EVM field-level signing: `legacy_tx_signing_bytes` / `_hash`, `sign_legacy_transaction` (EIP-155 `v`), `encode_signed_legacy_tx`, `signed_legacy_tx_hash`, `keccak256`, arbitrary-address `checksum_address`; `sign_evm_transaction` is unchanged and documented as returning legacy `v`. FFI `ciris_verify_keccak256` / `ciris_verify_checksum_address` / `ciris_verify_sign_evm_transaction_fields` (amounts as decimal strings); wheel `keccak256`, `checksum_address`, `CIRISVerify.sign_evm_transaction_fields`. (#207)
- **16.2.1** — `SecureBlobStorage::load` contract: absence is `KeyNotFound`, present-but-unreadable is `StorageFailed`; the plugin-TPM and Android backends follow it, so sealed signers mint on a fresh home under the TPM plugin. (#288)
- **16.2.0** — ALM `SignedRelayCapacity` has a §19 golden vector (`relay_capacity/canonical_bytes.json`) and its domain separator is in `domain_separators.json`. (#207)
- **16.1.0** — `create_federation_identity_in(keys_dir, …)` seals the ML-DSA half in a caller-chosen directory (the bare form uses the global `keys_dir()`); FFI config `keys_dir`, CLI `identity create --keys-dir`. (#285)
- **16.0.0** (BREAKING) — Removed the `hw_token::get_token_signer` stub; PKCS#11 signing is `pkcs11::open_pkcs11_signer`. `cryptoki` upgraded (RUSTSEC-2026-0286). (#283)
- **15.2.0** — The manifest Contribution carries `evidence_refs: [manifest_hash]`; the producer requires bare lowercase hex; the verifier rejects `evidence_refs` that omit `build.manifest_hash`; `VerifiedManifest.evidence_refs` is exposed through the FFI. Contributions without `evidence_refs` still verify. `rustls` ≥ 0.23.45 (RUSTSEC-2026-0285). (#281)
- **15.1.0** — `ciris_crypto::aes_gcm::{encrypt_aad, decrypt_aad}` with associated data; the AAD-empty pair is unchanged and the two pairs do not open each other's ciphertexts. (#279)
- **15.0.0** (BREAKING) — `FedCode` and `OwnedNode` are `#[non_exhaustive]` with `FedCode::new` + `with_*` builders and `OwnedNode::new`; `AdmittedHybridKey::admit` is the checked registration input for a code-admitted hybrid key. `bump-version.sh` rewrites intra-workspace sibling pins. (#274, #275)
- **14.2.0** — Fedcode v3 carries an optional `ml_dsa_65_pubkey_sha256` commitment (valid with zero nodes); `verify_pulled_ml_dsa_65_pubkey` checks a pulled ML-DSA key against it (constant-time, fails closed without a commitment); `create_federation_identity` emits v3 codes. FSD-003 §3A.5. (#272)
- **14.1.0** — `verify_manifest_integrity` recognizes both manifest-hash constructions (`ManifestHashCheck::{VerifiedConcatenated, VerifiedJson, Unrecognized}`); `Unrecognized` no longer flips `integrity_valid` and per-file checks run (#224). Fedcode v3 (`CIRIS-V3-`) `user` codes may embed up to 16 `OwnedNode` transport keys; node-free codes stay v2 (#269). All keyring key-material draws go through the RNG health latch (`mint_p256_signing_key`) (#207). The steward-key decode error names the endpoint and schema (#176).
- **14.0.0** (BREAKING) — 31 public error enums are `#[non_exhaustive]`; closed wire vocabularies and `#[repr(C)] CirisVerifyError` stay exhaustive (#257). `valid_until` rides inside the scrub-signed envelope (omitted when `None`) on all key-record producers, `create_federation_identity`, CLI `--valid-until` and FFI, read via `valid_until_in_envelope()`; accord holder records pass `None` (#267). Logging follows the CIRIS Logging Standard; `scripts/check-no-secret-logging.sh` (#265).
- **13.6.1** — Docs: `derive_destination` rotates on the MLS epoch; any multi-hop relaxation of CC 5.4.6 would need a global rotation clock.
- **13.6.0** — `announce_policy::CohortScope` + `wire_may_announce` (CC 5.4.6): below-federation scopes never emit a Reticulum announce, targeted or not; Commons scopes may; an unknown scope fails closed. (#262)
- **13.5.0** — iOS/Android sync use the current EU registry hostname; `scripts/check-no-retired-hostnames.sh` (#11). MLS exporter inputs pinned: `RECORD_EXPORTER_LABEL = "ciris-scope-record-v1"`, `DESTINATION_EXPORTER_LABEL = "ciris-scope-destination-v1"`, `EXPORTER_CONTEXT = b""`, `EXPORTER_LENGTH = 32`; derivations and vectors unchanged (#259).
- **13.4.0** — Scoped RNS destinations (CC 5.4): `k_destination` + `derive_destination(k_destination, member_key_id) -> [u8; 16]` (per-member, `LABEL_DESTINATION`, `u32_be` length prefix); FFI `op: k_destination` / `destination`, wheel `scope_privacy.k_destination` / `derive_destination`; golden vector. (#259)
- **13.3.1** — A rate-limited revocation check is cached for at least `Retry-After`; an unreachable one is capped. The post-release live gate skips on 429.
- **13.3.0** (OPERATIONAL) — Revocation results carry `Determination::{Authoritative, Indeterminate}` (`Indeterminate::{RateLimited, Unreachable}`): a 429 never reads as revoked and honours `Retry-After`, unreachable still fails closed; `is_authoritatively_revoked()`. New `VerifyError::ResponseSchemaMismatch { url, status, detail }`.
- **13.2.0** — `KeyRecord::subject_binding()`, `ProvenanceLink::subject_binding()` and `TransportBinding::subject_binding()` export the projections their checkers enforce; `TransportBindingVerdict::subject_binding_error`; `SubjectBindingError::member()` / `claimed()`. (#254)
- **13.1.0** (SECURITY) — New `subject_binding`: the subject named outside a signed envelope must match the envelope (identity incl. both key legs, fail closed on absence, checked first), enforced on `ProvenanceLink`, `TransportBinding` and the manifest co-scrub blessing. Verifier-only; no wire change. (#252)
- **13.0.0** (BREAKING) — `Frame` + `Arity`: `Arity::testimonial(subject, frame)` refuses an undeclared frame and verify supplies no default. `Gating::Normative { authority }` and `Gating::Structural { breaks }` with `amendable_by()`; `Purpose` is `Structural`; a ruling combined with a mechanism is `Measurement`. `SelfReport` / `LogInfrastructure` / `AbuseResponse` require a frame. (#248)
- **12.6.0** — 40 TPM EK vendor roots (8 vendors, from Microsoft `TrustedTPM.cab`) baked at the `CommunityAggregated` tier; see `docs/TPM_ANCHOR_PROVENANCE.md`. (#199, #227)
- **12.5.0** — `presentation` enforces that identifiers stay separable from presentation format, so an unlinkable presentation is a format addition, never a re-issuance: person-presentation identifiers are classified Global vs narrower, with a drift check.
- **12.4.1** — Docs: `RegistryClient::verify_tpm_attestation` is a remote, advisory registry client; local EK validation is `device_attestation::verify_tpm_ek_certificate` (no local PCR-quote verifier).
- **12.4.0** — `redactable` salted-digest commitments (SD-JWT/mDoc shape): the root binds member count and index; a withheld disclosure reports `MemberState::Redacted`, an altered one `DigestMismatch` (#241). `Gating::combine` / `propagate`: weakest input wins, differing authorities give `Measurement` (#244).
- **12.3.0** — `AnchorProvenance::{CallerSupplied, CommunityAggregated, VendorOfficial, HardwareValidated}` (weakest to strongest) + `resolve_x509_min_provenance`; Yubico is `HardwareValidated`, Google ×2 and Apple `VendorOfficial`; `TrustAnchor::x509` defaults to `CallerSupplied`.
- **12.2.0** — `verify_tpm_ek_certificate{,_with_store}`: EK → intermediates → pinned vendor root with the anti-lift binding, trying every `(KeyAttestation, TPM_EK)` anchor; TPM identity from the TCG SAN OIDs; no nonce and no discrete/firmware split. (#199)
- **12.1.0** — `classification::{Gating, Classification}` (`Normative { authority }`, `Measurement`, `Proposal { tracking }`; `may_gate()` only for `Normative`) on `ConsentDisposition`, CoTS `Purpose`, `AndroidSecurityLevel` and `AppAttestEnvironment`. (#238)
- **12.0.0** (BREAKING) — `ConsentClass` is replaced by `ConsentDisposition` with CC 3.4.5's four categories (SelfReport / ArtifactVerification / LogInfrastructure / AbuseResponse); `is_consent_gated()` is `false` for every verify-owned family. (#238)
- **11.1.0** — `evidence/cc_impl.tsv` + the `tools/check_evidence.py` CI gate (#233); the v3 aggregation golden vector's `n_eff` is derived from its masses (#236); `KEY_GRANT_ALGORITHM_V2` is `x25519_mlkem768_aes256_gcm_hkdf_sha256`, the hyphenated form accept-only via `key_grant_algorithm_v2_accepts` (#234); `canonical_subject` enforces the CC 2.3.2.1 productions (#235).
- **11.0.0** (BREAKING) — Provenance canonical bytes are CC 3.1.2.1 v2 `sha256(JCS({…}))` (`ciris.skill_import.v2` / `ciris.locale_manifest.v2`, return `Result`, omit-vs-materialize, v2 vectors); v1 constants deprecated; `humanity_accord::canonical_bytes` unchanged (#231). Apple App Attest validator `verify_apple_app_attest{,_with_store}` (`ciborium` dependency) (#199). Dimension registry `dim::ALL` / `dim::lookup`. Threat model AV-46…AV-50.
- **10.11.0** — Baked Google Hardware Attestation Root, Google Key Attestation CA1 and Apple App Attestation Root CA, each with a pinned DER digest. (#227)
- **10.10.0** — `trust_anchor_store::baked` / `default_store()` with Yubico Attestation Root 1 (PEM, pinned digest, `BakedRootError::FingerprintMismatch`) scoped to `(KeyAttestation, YUBIKEY_PIV)`; `produce_accord_custody_attestation_validated` self-verifies at mint; `ChainValidationCache` caches only X.509 path validation (bounded, no negative caching, caller clock). (#227)
- **10.9.0** — `trust_anchor_store`, a CoTS model (`draft-ietf-rats-concise-ta-stores-02`): `resolve(purpose, environment)` requires both to match, empty constraint lists match nothing, `environments::*` names; `verify_android_key_attestation_with_store` (a store miss is `Ok(None)`). No CBOR encoding yet. (#227)
- **10.8.0** — `device_attestation::verify_android_key_attestation` (CC 4.2.2.1): chain to a pinned Google root, KeyDescription parse, attested-key and challenge binding; `AndroidAttestationVerdict::refutes(claimed_class)`; no revocation check. (#199)
- **10.7.0** — `build_attestation_bundle`: `produce_build_attestation_bundle` / `verify_build_attestation_bundle` bind a presenter's key to the pipeline-signed manifest it runs (hash-committed, optional RFC 6962 inclusion proof); `BundleVerdict::to_attestation_entries` / `BundleRejection::to_attestation_entry`. Does not prove remote execution. (#181)
- **10.6.3** — `MockAttestedMember` returns `holder: HybridSigningIdentity` with seed-derived Ed25519 and ML-DSA-65; `test-support` enables `pqc`. (#221)
- **10.6.2** — `accord_custody_attestation::test_support` (non-default feature `test-support`): `MockYubicoCa` mints FIPS-attested members chaining to a mock root only. (#219)
- **10.6.1** — `INFRA_SCOPES` replaces `infra:join_communities` with `infra:hold_community_membership` and `infra:hold_family_membership`. (#217)
- **10.6.0** — `canonical_subject` codec (CC 2.3.2.1): `canonical:sha256:<64 lower hex>` over `utf8("{platform}:{entity_kind}:{id}")`, fail-closed parser that rejects bare hex, `classify_subject`; FFI `ciris_verify_canonical_subject`, wheel `canonical_subject` / `canonical_subject_from_triple` / `parse_canonical_subject`. (#201)
- **10.5.1** — Mobile registry calls run on the blocking pool (`mobile_http::{get_json_async, post_json_async, check_status_async}`), so race budget and not-found grace apply on Android/iOS. (#212)
- **10.5.0** — `verify_provenance_chain_with_policy_and_terminus(chain, anchors, policy, accepted_terminus_types)`; the existing functions accept `steward` only. (#208)
- **10.4.0** — `verify_provenance_chain` verifies scrub signatures over `jcs::canonicalize(registration_envelope)` (new `ProvenanceLink.registration_envelope`, `ContentHashMismatch`); `transparency::hash_leaf` / `hash_node` are public; `Ed25519Verifier::verify_strict`.
- **10.3.0** — `ciris_keyring::rt::keyring_block_on` is the sync→async bridge at every keyring site, safe under an ambient Tokio runtime. (#204)
- **10.2.0** — `test_anchor` (feature `test-anchor`): a test-only trust-root anchor and `software_test` custody tier behind `CIRIS_TESTING_MODE`, refused when `ENVIRONMENT` / `CIRIS_ENV` is production/prod/staging; probe `ciris_verify_test_anchor_compiled_in()` / Python `test_anchor_compiled_in()` must return 0 in production. (#202)
- **10.1.1** — No loader callbacks on any platform (Windows `DllMain` and macOS/iOS constructors removed); `early_verify()` runs from `ciris_verify_init()`, so loading the library does no I/O. (#197)
- **10.1.0** — `ciris_crypto::epoch_key` (CC 5.1): `derive_epoch_key` / `derive_epoch_stream_nonce` (HKDF-SHA256, salt `CIRIS-epoch-key-v1`, distinct labels, `u32`-prefixed `stream_id`, `u64` epoch); FFI `ciris_verify_epoch_key_derive`, Python `derive_epoch_key` / `derive_epoch_stream_nonce`. The v3 aggregation functions are re-exported at `holonomic::`. (#193, #194)
- **10.0.0** (BREAKING) — `AggregationMetaV1` v3 adds required `max_source_multiplicity` and `mass_commitment`; `passes_multiplicity_gate` (fails closed below v3), `mass_commitment` / `verify_mass_commitment` / `mass_to_fixed`, `MASS_FIXED_POINT_SCALE = 1e6`; v1/v2 preimages unchanged. (#191, CC 6.1.2.1.2)
- **9.0.2** — `ciris_verify_ffi_link_anchor()` references every exported FFI function so an rlib consumer retains them. (#189)
- **9.0.1** — `ciris-verify-ffi` also emits an `rlib`. (#187)
- **9.0.0** (BREAKING) — `ScrubTarget` gains a required `roles` field, carried inside the signed envelope (empty reproduces the previous bytes); `KeyRecord::roles_in_envelope()`; `verify_build_manifest_via_coscrub` roots a manifest via a pipeline key record carrying `infra:attest` and co-scrubbed by ≥ `MIN_ACCORD_COSCRUBS` (2) accord anchors; `verify_build_manifest_contribution` deprecated. (#185)
- **8.12.0** — Keyring `self_enc_keys::SelfEncKeys` (`open`, `enc_pubkeys`, `kex_respond`) keeps content-encryption private keys in custody; `transport_binding::produce_signed_identity_occurrence`; FFI `ciris_verify_self_enc_pubkeys` / `_respond`, Python `self_enc_pubkeys` / `self_enc_respond`; `ciris_verify_self_enc_derive` is mint-time only. (#183)
- **8.11.0** — `ciris-build-sign pubkey` prints an existing pipeline keypair's public halves as JSON; `Export pipeline pubkeys` workflow.
- **8.10.0** — `ciris-verify manifest sign` CLI wraps `sign_build_manifest_contribution`. (#176)
- **8.9.0** — Multi-scrub key records: `ScrubSig`, `KeyRecord::additional_scrubs` (scrub #1 stays in the base fields), `scrubs()` / `distinct_scrub_count()`, `produce_multiscrub_key_record` and `append_scrub` (re-checks the envelope hash, requires distinct anchors). (#174)
- **8.8.0** — Optional `TransportHint`s inside the signed registration envelope (omitted when empty); `build_registration_envelope`; `KeyRecord::transport_hints()`; CLI `--transport-hint`, FFI `transport_hints`. (#172)
- **8.7.0** — `StorageBudgetV1` + `CorpusWantV1` (CC 6.1.5.2 §Q) in `holonomic`. (#170)
- **8.6.0** — `AggregationMetaV1` v2 signs `n_eff`; `effective_source_count`, `passes_dominance_gate` (v1 fails closed) (#167). `hickory-resolver` 0.25 (#165). Unused dependencies removed (#164).
- **8.5.0** — `produce_scrubbed_key_record(scrubber, ScrubTarget, valid_from)`: an accord holder scrub-signs a node registration with an envelope byte-identical to `produce_self_key_record`. (#162)
- **8.4.0** — `accord_holder_bootstrap_anchor()` returns the seated holders' Ed25519 keys from the baked genesis; provenance anchoring is 1-of-N membership and a `steward,accord_holder` terminus is accepted. (#160)
- **8.3.0** — `ciris_crypto::self_enc`: deterministic X25519 + ML-KEM-768 keypairs from the Ed25519 seed (salt `CIRIS-self-enc-v1`); FFI `ciris_verify_self_enc_derive`, Python `derive_self_enc`; feature `self-enc`. (#151)
- **8.2.0** — `accord_live_quorum` (FSD-004 Phase 1): proposal/participation/decision objects, `tally_live_quorum`, `verify_fire` / `membership_change` / `resume_by_live_quorum`, `verify_recovery_supersede`, `decisions_equivocate`. (#150)
- **8.1.0** — `lifecycle:active` resumptions carry a mandatory `resumes_halt_id` (CC §4.2.1.3) in the preimage; `InvocationError::MalformedResumption`; CLI `--resumes-halt-id`.
- **8.0.0** (BREAKING) — `tss-esapi` removed from `ciris-keyring`: the runtime-loaded TPM plugin (ABI v3: seal/unseal, ECDSA P-256 signer, quote) is the only TPM backend and `tpm-plugin` is a default feature; the `tpm` feature, link-time TPM signer/storage and `.tpm` formats are gone. Prior lower-tier key artifacts are archived as `*.superseded-pre-v8`. (#141)
- **7.6.0** — `ciris-tpm-plugin` crate + C ABI, `ciris_keyring::tpm_plugin` (libloading client) and `PluginTpmSecureBlobStorage`; the x86_64-linux wheel bundles `libciris_tpm_plugin.so` and points `CIRIS_TPM_PLUGIN` at it. (#130)
- **7.5.1** — `SealedEd25519Signer` / `SealedMlDsa65Signer::open_existing()`; `open()` never mints. (#134)
- **7.5.0** — TPM code gated to gnu Linux and Windows, so the keyring builds for musl (#127); the linux wheel builds without `tpm` and loads without libtss2 (#125).
- **7.4.0** — Wheel `ciris_verify.scope_privacy.{k_record_id, k_symbol, derive_record_id, derive_symbol_key, witness_cover_leaf}` via FFI `ciris_verify_scope_privacy_derive`. (#82)
- **7.3.0** — FFI `ciris_verify_rns_destination_hash` + wheel `rns_destination_hash` (§5.6.8.8.1.1). (#28)
- **7.2.0** — `humanity_accord_genesis()` returns the baked 2-of-3 HUMANITY_ACCORD genesis (`genesis/humanity_accord_genesis.json`, founders A1/B1/C1, verified against `genesis/founder_pubkeys.json`). (#107)
- **7.1.0** — `PlatformAttestation::ExternalSecureElement` + `custody_attestation_to_platform_attestation`. (#117)
- **7.0.0** — The custody attestation commits `mldsa65_public_key_sha256` instead of the inline ML-DSA key, bound to the resolved `holder_member`. (#116)
- **6.13.0** — PKCS#11 key lookup by `CKA_ID` (#112); the custody attestation signs a hash commitment to the certificate chain, which rides as hash-bound evidence (#113).
- **6.12.0** — `cryptoki` is a common dependency, so the `pkcs11` feature builds on all targets.
- **6.11.0** — `accord_genesis::humanity_accord_genesis()`: the pinned no-TOFU HUMANITY_ACCORD recognition root. (#107)
- **6.10.0** — `InvocationKind::LifecycleActive` (`lifecycle:active`) under its own domain `ciris.accord_lifecycle.v1`; CLI `--kind reactivate`. (#95)
- **6.9.0** — General `build_membership_change` / `verify_membership_change`; the accord variants are specializations; `roster_from_envelope`. (#104)
- **6.8.1** — `ml-dsa` 0.1.1 seed zeroize. (#87)
- **6.8.0** — Growable accord family (`accord_consensus_protocol` / `strict_majority`), `accord_roster_from_family`, `accord_quorum_from_family`, `build_accord_membership_change` / `verify_accord_membership_change`; key labels A1/B1/C1 (primaries) and A2/B2/C2 (spares). (#95, #96)
- **6.7.1** — `verify_yubikey_piv_attestation` takes a variable-length chain (`yubikey_attestation_chain_hex`); pin `Yubico Attestation Root 1`. (#91)
- **6.7.0** — `accord_custody_attestation`: produce/verify a holder custody bundle whose YubiKey PIV 9c certificate chains to the pinned Yubico root, with attested key == holder Ed25519 and FIPS + touch=always → `YubiKey_5_FIPS`; FFI + Python. (#91)
- **6.6.1** — Seal-alias decoupling. (#89)
- **6.6.0** — Portable USB-wrapped ML-DSA-65 key mode (`UsbWrappedMlDsa65Signer`, `--portable-usb`). (#88)
- **6.5.0** — Accord invocation concurrence (CC 4.2.1). (#86)
- **6.4.1** — Accord genesis quorum is 2/3 of distinct keys.
- **6.4.0** — HUMANITY_ACCORD genesis producer and `ciris-verify accord` CLI.
- **6.1.x** — `delegate` CLI and per-platform CEG manifests.
- **6.0** — `ciris-verify token probe` / `token sign-test` / `identity create`, `ceg_outbox`, `federation_self_record`, `sign_occurrence_revocation`; see [`docs/FEDERATION_IDENTITY.md`](docs/FEDERATION_IDENTITY.md). (#63)
- **v5.14.0** — `SelfSigner`, `HardwareRootedIdentity`, `*_async` producers, `PresencePolicy` / `verify_presence` (WebAuthn unlock), `perform_self_at_login`. (#63)
- **v5.13.0** — cryptoki PKCS#11 / YubiKey backend. (#80)
- **v5.12.0** — WebAuthn passkey assertion verifier (origin exact-match, signCount surfaced).
- **v5.11.0** — `UserIdentityKeyset` OR-of-N hardware keys per identity; federation threat model v1.5.
- **v5.10.0** — CEG §19.7 aggregation: `AggregationMetaV1`, `verify_aggregation_meta`, `member_commitment` / `verify_member_commitment`, descent order, `EjectionVerdict`; §19.7 vectors. (#79)
- **v5.9.0** — §19 holonomic conformance vectors (`tests/vectors/holonomic_v19/`).
- **v5.8.0** — CEG §19 holonomic substrate verifiers. (#78)
- **v5.7.0** — Hybrid required at every federation-tier gate (#75), partnership seven-member set (#76), `infra:*` / `agency:*` scope split (#77).
- **v5.6.0** — License-signature gate (#72), TPM sealing (#73), fail-secure keygen (#74), RNS destination-hash recompute (#28), `self_at_login` producers (#63), sealed ML-DSA-65 (#71).

## Related Projects

| Project | Integration |
|---------|-------------|
| `../CIRISRegistry` | Source of verification data; **CEG + identity authority** — owns the identity/admission *API routes* (incl. key registration), policy layer over Persist's tables |
| `../CIRISPersist` | Storage substrate — owns `federation_keys` (the registered-key tables); written *through* Registry's policy layer, not by clients directly |
| `../CIRISAgent` | Primary consumer of verification; embeds the verify wheel; hosts **the client (KMP, `CIRISAgent/client`)** |
| `../CIRISPortal` | License management portal |

**Client / UI topology:** The active client is **Kotlin Multiplatform in `CIRISAgent/client`**. **`CIRISGUI` is orphaned** (do not target it). "UI" in project discussion usually means **API routes**, not pixels. Key-registration / identity routes are **CIRISRegistry's** (identity + CEG admission authority); the local key *ceremony* (hardware probe, keygen, touch, hybrid sign) runs client-side via the verify wheel; the resulting pubkey + `hardware_class` + attestations are POSTed to Registry, which validates CEG conformance + admission and writes through to Persist `federation_keys`. See [[reference_client_topology_and_route_ownership]].

## CLI Usage

```bash
# Build CLI (token/identity need the pkcs11 feature)
cargo build --release -p ciris-verify-core --features pkcs11

# Full attestation (Levels 1-5)
./target/release/ciris-verify attest --agent-root /path/to/agent --version 1.2.3

# Self-check (binary integrity, Level 1)
./target/release/ciris-verify self-check

# Fetch and verify the trust root from every trust-root host (Level 3, CC 5.3.4)
./target/release/ciris-verify sources

# --- 6.0 federation identity (PKCS#11 / YubiKey) ---
# Discover keys on a YubiKey / PKCS#11 token
./target/release/ciris-verify token probe --module /usr/lib/x86_64-linux-gnu/libykcs11.so --pin
# Prove the token can custody the owner-binding key (on-token sign + verify)
./target/release/ciris-verify token sign-test --module .../libykcs11.so --key-label "..." --pin
# Create the hardware-rooted federation identity → drops a signed object in ~/ciris/ceg/outbox/
./target/release/ciris-verify identity create --module .../libykcs11.so --key-label "..." --identity-type user --pin

# --- 6.4 HUMANITY_ACCORD genesis ceremony (CEG §9.1; docs/ACCORD_KEY_GENESIS_RUNBOOK.md) ---
# Each holder produces their accord_holder genesis record (HW-rooted) → outbox
./target/release/ciris-verify accord holder --key-id A1 --module .../libykcs11.so --key-label "..." --pin
# Coordinator builds the canonical entrenched-family envelope (3 primaries, roster order)
./target/release/ciris-verify accord family-envelope --member A1 --member B1 --member C1 --out family.json
# Each founder co-signs on THEIR token (no human signs another's key)
./target/release/ciris-verify accord co-sign --envelope family.json --key-id A1 --module .../libykcs11.so --key-label "..." --pin --out cosign-a1.json
# Coordinator assembles → verifies the accord's 2/3 quorum of DISTINCT keys, then writes the genesis → outbox
./target/release/ciris-verify accord assemble --envelope family.json --cosign cosign-a1.json --cosign cosign-b1.json --cosign cosign-c1.json

# --- 6.6 portable high-secure key mode: PQC half wrapped on a USB key, both keys + PIN + touch ---
# Add --portable-usb <usb-dir> to any accord command (requires --module/YubiKey). On `accord holder`
# it PROVISIONS the wrapped seed onto the USB; on co-sign/invoke/concur it OPENS it. Portable, not
# machine-bound. The YubiKey stays signing-only (the unwrap key is derived from a signature).
./target/release/ciris-verify accord holder --key-id A1 --module .../libykcs11.so --key-label "..." --pin --portable-usb /media/usb-A1
# --- accord invocations (the kill switch; CC 4.2.1 closed vocab, thresholds per CC 4.2.6) ---
# One holder invokes (constitutional / notify / drill complete on ONE signature; publish it)
./target/release/ciris-verify accord invoke --key-id A1 --roster roster.json --kind constitutional --invocation-id halt-2026-06-19 --payload-sha256 <hex> --module .../libykcs11.so --key-label "..." --pin
# Holder B lists pending objects (flags the ones whose roster they belong to)
./target/release/ciris-verify accord list --mine B1
# lifecycle:confirmed / lifecycle:active need a strict majority of the standing roster: further holders concur
./target/release/ciris-verify accord concur --object <invocation.json> --key-id B1 --module .../libykcs11.so --key-label "..." --pin
```

## Attestation Levels

| Level | Name | What it Proves |
|-------|------|----------------|
| 1 | Self-Verification | THIS CIRISVerify binary + functions match registry manifest ("who watches the watchmen") |
| 2 | Hardware | TPM/Secure Enclave key valid |
| 3 | Trust Root | A verified GenesisBundle (CC 5.3.4) was selected |
| 4 | License Validity | Licensure rows (CC 4.4.3.8); not yet evaluated, so every deployment is community |
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
