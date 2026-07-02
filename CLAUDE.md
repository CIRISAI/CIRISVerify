# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CIRISVerify is the **hardware-rooted license verification module** for the CIRIS ecosystem. It is an **open-source (AGPL-3.0) Rust binary** that provides cryptographic proof of license status, ensuring that community agents (CIRISCare) cannot masquerade as licensed professional agents (CIRISMedical, CIRISLegal, CIRISFinancial).

**This repository contains the full source code, protocol documentation, and specifications for CIRISVerify.**

## Repository Structure

| Path | Purpose |
|------|---------|
| `FSD/FSD-001_CIRISVERIFY_PROTOCOL.md` | Full technical specification (authoritative) |
| `FSD/FSD-004_ACCORD_DECIMATION_RECOVERY.md` | DRAFT design — accord **live-quorum** operation & recovery under decimation (quorum floats over who proves life; proof-of-life modifies the quorum + carries a vote; always leans toward firing; adversarial-AGI first-strike threat model). CIRISVerify#98. Not ratified, not implemented. |
| `FSD/FSD-005_HUMANITY_ACCORD.md` | **The Humanity Accord — what & why** (DESCRIPTIVE, current as of v7.2.0): the constitutional kill-switch rooted in hardware-attested human custody. Recognition root (no-TOFU baked genesis #107) + custody attestation (YubiKey PIV→pinned Yubico root #91) + invocation concurrence (CC 4.2.1). Precise crypto (M-of-N not threshold; PQC at the authority layer, Ed25519-strength custody), honest boundaries, prior-art delta, verifiable-claim receipts. |
| `protocol/ciris_verify.proto` | Public API contract (gRPC/protobuf) |
| `docs/THREAT_MODEL.md` | Formal threat model (6 attack vectors, mitigations) |
| `docs/HOLONOMIC_SUBSTRATE.md` | CEG §19 / §19.7 holonomic verifiers — threat model, module map, conformance status (§19 + §19.7 cross-impl-proven) |
| `docs/FEDERATION_IDENTITY.md` | Operator walkthrough: provision a YubiKey PIV Ed25519 key → `identity create` → CEG outbox → CIRISServer relay |
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

*(Current release: **8.4.0** — **the HUMANITY_ACCORD holders are the genesis-mesh rooting anchor (#160, the "centipede head")**. `accord_genesis::accord_holder_bootstrap_anchor() -> Vec<[u8;32]>` returns the Ed25519 keys of the **seated** accord holders (A1/B1/C1), derived from the baked `humanity_accord_genesis()` roster resolved against the pinned `founder_pubkeys.json` (via `accord_roster_from_family`, one-seat gates applied) — so the mesh rooting anchor and the kill-switch roster share **one source of truth** and can't drift; spares (A2/B2/C2) are excluded, fail-closed to empty if the genesis isn't baked/resolves. **Rooting semantics locked (tests):** `verify_provenance_chain`'s anchor check is set-**membership** (1-of-N), so a canonical node scrubbed by **A1 alone** roots during cold-start bootstrap (the 2/3 quorum governs accord *invocation* — the kill-switch — not rooting); and the terminus `identity_type` is a comma-joined set, so a holder seeded `steward,accord_holder` satisfies the terminus-is-steward gate. **Additive** — `verify_provenance_chain` signature unchanged; consumers are Rust (CIRISPersist seeds the 3 holders as self-signed `steward,accord_holder` rows + roots node keys to them; CIRISEdge wires the anchor into `resolve_announce_cold_start`; CIRISServer seeds the canonical node scrubbed by A1), so no FFI obligation. Prior: **8.3.0** — **deterministic self content-encryption keypairs derived from the Ed25519 base seed (#151)**. `ciris_crypto::self_enc` — `derive_self_enc_x25519` (HKDF-SHA256 → 32-byte X25519 secret/public) + `derive_self_enc_mlkem768` (HKDF-SHA256 → 64-byte `d‖z` → `ml_kem::generate_keypair_deterministic` → 1184-byte ek), mirroring the `secp256k1` wallet pattern. **Distinct salt (`CIRIS-self-enc-v1`) + per-scheme `info`** (`ciris/self-enc/x25519/v1`, `ciris/self-enc/ml-kem-768/v1`) — derived via HKDF, **not** the Ed25519→X25519 birational map (clean scheme separation, no cross-protocol key-reuse). Exposed on the FFI (`ciris_verify_self_enc_derive`, JSON-in `{ed25519_seed}` → base64 JSON envelope with both halves) + Python wheel (`derive_self_enc(seed) -> SelfEncKeys`); the public fields map straight onto `federation_identity_occurrences.pubkey_x25519_base64 / pubkey_ml_kem_768_base64` (Persist V069). Private halves stay in-process. Cross-impl golden pinned (`sha256(x25519_pub‖ek)` for seed `[0x42;32]` = `93a80182…`), verified Rust-core → FFI → wheel. **Scope: self / single-principal only** — every occurrence re-derives the identical keypair so the enc identity travels for free with FedID backup/restore; community DEKs keep independent epoch-rotated keys (do NOT derive there). The `self-enc` feature mirrors the `hybrid-kex` combo (`x25519`+`ml-kem`+`random`); the FFI always enables it. Prior: **8.2.0** — **release-tagged the FSD-004 live-quorum Phase-1 machinery (#150)**: `ciris_verify_core::accord_live_quorum` (proposal/participation/decision objects, `tally_live_quorum`, `verify_fire`/`membership_change`/`resume_by_live_quorum`, `verify_recovery_supersede` [CC-gated], `decisions_equivocate`) — the stateless half of accord decimation-recovery, satisfying every adversarial-review obligation (C1–C3, H1–H3, H5–H7, M1–M3, M5; see `FSD/FSD-004_ADVERSARIAL_REVIEW.md`). v8.1.0 was the docs-only FSD-004/CC-0.5 sync; #150 landed after it untagged, so 8.2.0 ships the code for downstream adoption (CIRISServer#122, CIRISPersist#302, CIRISRegistry#113, CIRISAccord#4). Phase 3 (server state) + the H7 CC cross-confirm are downstream. Prior: **8.1.0** — **`accord:lifecycle:active` resumption carries the CC 0.4-mandated `resumes_halt_id` (§4.2.1.3)**. CC ratified FSD-004's live-quorum into entrenched §4.2.6 (CC 0.3) then expanded the accord surface: CC 0.4 §4.2.1.3 added a **mandatory `resumes_halt_id`** to the resumption preimage — binding a `lifecycle:active` to the *single* `CONSTITUTIONAL` halt it ends, so a stockpiled/replayed resumption can't silently un-halt a *later* kill. `humanity_accord::Invocation` gains `resumes_halt_id: Option<String>` (serde skip-if-none → invoke kinds wire-unchanged); `canonical_bytes` interposes `resumes_halt_id=<id>\n` after `invocation_id` **only** for `lifecycle:active` (the §4.2.1.1 invoke layout is byte-identical); `verify_invocation` **structurally rejects** a `lifecycle:active` missing the field or a non-lifecycle kind carrying one (`InvocationError::MalformedResumption`, before signatures); `ciris-verify accord invoke --kind reactivate` now requires `--resumes-halt-id`. FSD-004 synced to **CC 0.5** (ratified §4.2.6 + the `fire ≤ roster-change ≤ standing` bias gradient + the §4.5.13 reverse-quorum generalization). **NOT in 8.1 (FSD-004 Phases 1-3, ratified-but-unimplemented):** the live-quorum *mechanism* — `accord_proposal`/`accord_participation`/`accord_decision` objects, `tally_live_quorum`, `verify_membership_change_by_live_quorum`, steward backstop, server recompute — gated on FSD-004 Q2 (window calibration) / Q3 (duress) / Q4 (recursion floor) + an adversarial review. Prior: **8.0.0** (BREAKING) — **tss-esapi is GONE from `ciris-keyring` entirely (#141 stage D); the runtime `dlopen` plugin is the keyring's sole TPM backend**. The full native TPM surface — seal/unseal (v7.6.0) **+ signer (ECDSA P-256) + quote/attestation** (#141 stages A-C, plugin ABI **v3**, all hardware-validated on a real `/dev/tpmrm0`: signer roundtrip→p256-verify, persist+re-open reproduces the same key, quote verifies under the AK pubkey) — now runs through `libciris_tpm_plugin.so` over a versioned C ABI, so the keyring link-binds **no** `tss-esapi` on **any** target. Consequences: the keyring + default build carry **zero libtss2 DT_NEEDED** everywhere, `cargo build -p ciris-keyring` cross-builds to **aarch64-musl by DEFAULT** (the #127 goal fully met), and `tpm-plugin` is now a **default** keyring feature (inherited by core/ffi). **Removed:** the `tpm` feature + the `tss-esapi` dep (keyring/core/ffi); `platform/tpm/*` (link `TpmSigner` + `TpmWrappedEd25519Signer` + quote/EK); `storage/tpm.rs` (`TpmSecureBlobStorage`); the 14 `feature="tpm"` `tpm_wrapper` sites in `software.rs`; `examples/tpm_attest.rs`. **Rewired:** `create_hardware_signer` → the plugin signer (`PluginTpmSigner`) is the sole TPM arm; `create_platform_storage` → `PluginTpmSecureBlobStorage` is the sole TPM storage tier; Windows detection probes the plugin's `available()` (not the deleted link-TBS). **Custody-logging clarity (#139/#145):** the macOS Secure Enclave fallback now logs an unambiguous "**UNSIGNED/UNENTITLED BINARY — unable to use the Secure Enclave … FALLING BACK to keychain (software-grade, hw_backed=false)**" at BOTH the signer + storage SE wrapper paths (iOS keeps its hard-error — the signed-bin requirement holds there). **Legacy-key handling — rotate, not migrate:** hardware keys can't be exported and **no FedIDs / signed state exist yet**, so a fresh hardware key *supersedes* the old rather than migrating the secret. `storage::archive_superseded_legacy_keys` (wired into plugin-TPM + SE storage genesis) detects any prior-install lower-tier artifact for an alias and **ARCHIVES it (`*.superseded-pre-v8`, never deletes) with a loud WARN** — never a silent orphaning. When federation turns on later, rotation rides Persist's existing `supersede` (verify re-signs with the new hardware key; Persist supersedes the rows). **BREAKING:** `--features tpm` no longer exists (use `tpm-plugin`, default + ship the plugin `.so`); `.tpm_seal`/`.tpm_blob`/`.tpm` link-format material is unreadable (no real deployments). Prior: **7.6.0** — **runtime-loaded TPM plugin: TPM custody on the wheel + musl WITHOUT linking tss-esapi (#130, the staged #125/#127 follow-up culminated)**. The keyring now reaches TPM purely at runtime by `dlopen`ing a small plugin dylib over a versioned C ABI, instead of link-binding `tss-esapi`. Four merged stages: **(1)** `ciris-tpm-plugin` crate + C ABI (`ciris_tpm_{plugin_abi_version,available,seal,unseal,free}`, ABI v1, caller-allocated out-pointers); **(2)** the real `tss-esapi` seal/unseal backend behind `--features real` (gnu-linux/windows-gated); **(3)** `ciris_keyring::tpm_plugin` — the `libloading` client (`tpm-plugin` feature = `dep:libloading` only, pure-Rust dlopen, builds on EVERY target incl. musl; ABI-version fail-closed; `TpmPlugin::{load,load_from,available,seal,unseal}`); **(4)** `PluginTpmSecureBlobStorage` — the dlopen counterpart to `TpmSecureBlobStorage` (identical at-rest design: a 32-byte master sealed *once*, per-blob AES-256-GCM under `HKDF("CIRIS-TPM-blob-v2", master)`, but the master is sealed through the plugin), wired into `create_platform_storage` **after** the link-time backend (which still wins for existing Linux/Windows-gnu deployments) and **before** software — so TPM custody is opportunistic everywhere the plugin `.so` + a device exist, incl. the published wheel + musl, where `tss-esapi` can't link. Re-open discipline (#134): a present seal file that won't unseal → error, **never** a silent re-mint that orphans sealed seeds. **Packaging:** the FFI/wheel builds with `tpm-plugin` (verified **0 libtss2 DT_NEEDED** in the cdylib — the #125 invariant holds, enforced by a `readelf` guard in CI); the real `libciris_tpm_plugin.so` (3 libtss2 DT_NEEDEDs isolated to IT) is built + bundled into the **x86_64-linux** wheel and attached to the GitHub release; `ciris_verify/__init__.py` points `CIRIS_TPM_PLUGIN` at the bundled path so it `dlopen`s out of the box (operator override respected; absent on macOS/mobile/aarch64 → software fallback). aarch64-linux (cross, no cross-libtss2) + Windows (tss-esapi-on-MSVC) plugin builds + the signer/quote half of `tss-esapi` (`platform/tpm/*`, attestation quotes, still on the link-time `tpm` feature) are documented follow-ups. Prior: **7.5.1** — **sealed signers must not silently mint on re-open (#134)**: `SealedEd25519Signer` / `SealedMlDsa65Signer` grew `open_existing()` (load-only, propagates `KeyNotFound`); `open_or_create` mints only on the explicit adopt path, `open()` ≡ `open_existing()`. Closes the hazard where re-opening a missing seed silently minted fresh key material (orphaning identity); regression-tested `open_fails_loud_on_missing_seed`. Prior: **7.5.0** — **TPM no longer link-binds libtss2: keyring cross-builds to musl (#127) + the wheel loads on bare hosts (#125)** (pragmatic fixes; the runtime-loaded `dlopen` TPM backend that restores TPM on musl/the-wheel is the staged follow-up, #125/#127, NOW landed as 7.6.0 above). **#127:** `tss-esapi-sys` link-binds the system tss2 C libs via pkg-config → hard-failed the *build* cross-compiling to `aarch64-unknown-linux-musl` (Alpine / Home Assistant). Gated `tss-esapi` + every TPM `cfg` site in `ciris-keyring` from `any(linux, windows)` → `any(all(linux, target_env="gnu"), windows)` (~120 sites, consistent global narrow; `factory.rs`'s software-fallback `not(...)` widened so musl falls through to the software signer — matching the keyring's existing runtime `NotSupported`). Verified: `cargo check -p ciris-keyring --features tpm --target {aarch64,x86_64}-unknown-linux-musl` builds (tss-esapi compiled away, no link); gnu host + TPM unchanged (90 +tpm tests green). **#125:** the published linux wheel's cdylib `DT_NEEDED`'d `libtss2-tctildr.so.0` (from `tss-esapi-sys`) → failed to load on any host without the TPM2 runtime, even for pure surfaces (`rns_destination_hash`, `scope_privacy`, jcs, license verify). Dropped the `tpm` feature from the linux-gnu wheel lane in `release.yml`; the cdylib no longer links libtss2 → loads anywhere (the macOS lanes already build the FFI tpm-less — `ciris_verify_tpm_attestation` is gated `not(android|ios)`, not on `feature=tpm`, so it still compiles + degrades to software). Prior: **7.4.0** — **scope-native privacy derivations on the Python wheel — closes #82**. The CEWP `SCOPE_PRIVACY.md` (CC 1.13.3 anonymous-tier) FSD §2.2/§2.4/§3.4 derivation helpers — shipped Rust-side in `ciris_crypto::scope_privacy` (v6.3.0) — are now exposed on the wheel: `ciris_verify.scope_privacy.{k_record_id, k_symbol, derive_record_id, derive_symbol_key, witness_cover_leaf}` (one FFI dispatch `ciris_verify_scope_privacy_derive`, `op`-tagged JSON-in → raw 32-byte out). The canonical bytes (the RFC 8949 §4.2.1 deterministic CBOR `record_id` preimage + the pinned `RecordType` integers self=1/family=2/community=3/federation=4) come from the one Rust impl — no second implementation. Verified end-to-end against the §9 cross-impl golden vectors (`k_record_id([0x42;32]) = 49209926…`, `derive_record_id([0x11;32],"record-0001",community,7) = 5428ddb5…`). The FFI crate enables `ciris-crypto/scope-privacy` so the wheel always carries the symbol. This was the last open box of #82 (the full Rust crypto surface — HKDF/HMAC-SHA3, XChaCha, HPKE/X-Wing, ML-DSA app-tier, all of `scope_privacy.rs` — landed KAT-locked in v6.3.0). Prior: **7.3.0** — **RNS `destination_hash` recompute on the Python wheel — closes the verify-side remainder of the #28 transport-binding waterfall**. The §5.6.8.8.1.1 two-stage RNS destination-hash recompute (`ciris_verify_core::transport_binding::compute_destination_hash`, shipped Rust-side v5.6.0) is now exposed on the FFI (`ciris_verify_rns_destination_hash`, JSON-in `{app_name, aspects, x25519_pubkey, ed25519_pubkey}` → raw 16-byte hash) + Python wheel (`ciris_verify.rns_destination_hash(app_name, aspects, x25519_pub, ed25519_pub) -> bytes`). This lifts CIRISConformance's `test_150_rns_dest_hash.py::test_wheel_recomputes_dest_hash_per_spec` from `xfail` to a real gate — the wheel recompute matches the pinned §5.6.8.8.1.1 golden vector (`98baa5d17abd7d940741d2f7b850577c`) byte-for-byte (verified end-to-end). Producer↔verifier coherence is by construction: the canonical bytes come from the same Rust path the verifiers use, no second impl. NB this resolves the **CIRISConformance-flagged** verify-side piece of #28; the #28 tracker's remaining Phase-4 item is the **fleet-wide enforcement flip** (`Advisory` → `RequireTransportBinding`), a cross-repo coordination event, not verify code. Prior: **7.2.0** — **the accord trio is BAKED (#107)**. The deliberate flip: `accord_genesis::humanity_accord_genesis()` now returns the **real** 2-of-3-cosigned HUMANITY_ACCORD genesis (was `None`/no-TOFU until the ceremony genesis was in hand). The genesis object from the six-key ceremony (#118) is checked in as an auditable file (`src/ciris-verify-core/src/genesis/humanity_accord_genesis.json`, `include_str!`'d into the `HUMANITY_ACCORD_GENESIS_JSON` const) — `key_id "humanity-accord"`, `quorum:2/3` entrenched, founders A1/B1/C1, **3-of-3 cosigned**. The bake is **validated, not pasted**: `humanity_accord_genesis_is_baked_and_quorum_valid` cryptographically re-verifies the full **hybrid (Ed25519 + ML-DSA-65)** founder quorum against the ceremony's published holder pubkeys (`genesis/founder_pubkeys.json`) over the canonical family-envelope bytes (`verify_founder_quorum`, count == 3). **Consequence:** every node on this binary recognizes the HUMANITY_ACCORD kill-switch roster + quorum from this pinned object at cold start, **never from a peer** (no-TOFU). The constitutional off-switch's cold-start recognition root is now live. Prior: **7.1.0** — **custody attestation → persist `attestation_evidence` bridge (#117)**: the last non-interactive bake leg. A verified accord-holder custody attestation can now become CIRISPersist's `accord_holder` admission evidence: new `ciris_keyring::PlatformAttestation::ExternalSecureElement(ExternalSecureElementAttestation)` (the user-held YubiKey-PIV/smartcard secure element, mapping to the existing `HardwareType::ExternalSecureElement`; carries the slot-9c attestation cert + leaf-first chain DERs + FIPS/firmware/touch floor) + `accord_custody_attestation::custody_attestation_to_platform_attestation(obj, verdict)` — the producer-side wrapper that reads the (already hash-bound) cert DERs back out of a verified bundle and packages them with the verdict's hardware floor, so a registrar admits/entrenches a holder with no human/YubiKey in the loop once the ceremony is done. The serde shape of the new variant IS the cross-repo contract persist consumes (Rust-native, no FFI obligation — follows the producer precedent); the consumer re-validates the chain to its own pinned Yubico root. Prior: **7.0.0** — **the accord trio is real**. The milestone cut: a full 6-key **HUMANITY_ACCORD** ceremony ran on physical YubiKey 5 FIPS hardware — 3 human holders, 6 keys (A1/B1/C1 primaries + A2/B2/C2 spares), 6 hardware-rooted holder records, 6 custody attestations chaining to the pinned Yubico root, and the assembled 2-of-3-cosigned `humanity_accord_genesis.json` — the constitutional kill-switch now has its three accountable humans with hardware-unforgeable custody. The release-gating fix that made it produce on real hardware is **#116** (below). Ceremony artifacts staged for baking in PR #118; the #107 pinned-genesis const bake (making `humanity_accord_genesis()` return the real root) is the deliberate next const flip. **#116 — custody attestation: hash-commit the ML-DSA-65 pubkey too (completes #113 on real hardware)**. v6.13.0's #113 hash-committed the attestation *certs* but left the holder's **ML-DSA-65 public key (1952 B → ~2604 base64 chars) inline** in the signed envelope, so the hardware-Ed25519 preimage was still ~3 KB — and the real YubiKey ykcs11 EdDSA single-shot ceiling is *below* that, so `produce_accord_custody_attestation` still hit `CKR_DATA_LEN_RANGE` on the canonical FIPS-YubiKey path. The verifier never reads that field (it resolves the holder's ML-DSA key out-of-band from `holder_member`), so it was dead weight. Fix: commit `mldsa65_public_key_sha256` instead of the inline key — preimage drops ~3 KB → **<1 KB** (now well under the token ceiling; locked by an absolute assert in `signed_preimage_is_independent_of_chain_size`). Hardened beyond the minimal patch: the committed ML-DSA hash is **bound to the resolved `holder_member`** (mirrors the ed25519 binding — load-bearing, not decorative; `committed_mldsa_must_match_resolved_member`). **Validated end-to-end: a full 6-key HUMANITY_ACCORD ceremony produced valid custody attestations with this change** (the artifacts are in PR #118 for baking). No wire-compat concern (#91 not deployed; the ceremony artifacts already use this format). FFI/Python verify surface unchanged. Prior: **6.13.0** — **two real-hardware accord-provisioning blockers, found bringing up the in-hand FIPS keys (#112, #113)**. **#112 — pkcs11 PIV key-lookup by `CKA_ID`, not class-specific label**: `ciris-keyring`'s `open()` looked up the *public* key with the *private* key's `CKA_LABEL`, but ykcs11 labels objects per class (`"Private key for Digital Signature"` ≠ `"Public key for …"`), so a YubiKey PIV slot-9c Ed25519 key failed to open with `KeyNotFound`. Fix: resolve the slot's objects by `CKA_ID` — the portable join key across the `{private, public, certificate}` triple — `open` finds the private key with the caller's config, reads its `CKA_ID`, and resolves the public key by that id (a `key_label` naming the private object still works; tokens with no `CKA_ID` keep the legacy label path). New `read_key_id` / `find_object_by_class_id`; sign-time lookup uses the pinned id too. **#113 — custody attestation signs a hash-COMMITMENT, not the inline cert chain**: the holder's hardware Ed25519 (`CKM_EDDSA`, single-part, bounded input) was handed the full multi-KB PIV attestation chain embedded as hex → `CKR_DATA_LEN_RANGE`. Fix: the signed envelope now carries `sha256` of the 9c cert + each chain cert; the cert DERs ride as **hash-bound evidence** in the (unsigned) outer `SignedCegObject.body`, recomputed + checked by the verifier — so the Ed25519 preimage is small AND independent of cert size (locked by `signed_preimage_is_independent_of_chain_size` + `tampered_evidence_cert_breaks_the_commitment`), binding preserved. `ciris-keyring` also translates `CKR_DATA_LEN_RANGE` into an actionable "preimage N bytes exceeds the token's EdDSA limit" error. No wire-compat concern (#91 not yet deployed — these are exactly the bring-up blockers). FFI/Python verify surface unchanged (JSON pass-through). Prior: **6.12.0** — **pkcs11 (cryptoki) builds on ALL targets — feature parity**: moved `cryptoki` from the Linux/Windows-only target table to the common `[dependencies]` in `ciris-keyring`, so the `pkcs11` feature compiles uniformly on linux/macos/windows/**android/ios** (the backend is simply unavailable at runtime where there is no token — `open_pkcs11` errors honestly). Cross-compile-validated: cryptoki-sys ships pre-generated bindings (no libclang/bindgen by default), and `cargo check --features pkcs11` was confirmed green on `aarch64-apple-ios` and `aarch64-linux-android,android`. TPM (`tss-esapi`) stays Linux/Windows-gated (genuinely platform hardware). This is the CIRISVerify half of the coordinated cut that lets CIRISServer carry a global `default = ["pkcs11"]` without breaking the macos/android/ios builds (#80 follow-up). Prior: **6.11.0** — **pinned HUMANITY_ACCORD genesis recognition root (#107)**: `accord_genesis::humanity_accord_genesis() -> Option<&'static SignedCegObject>` — the **no-TOFU** cold-start kill-switch recognition root. A node not at the ceremony resolves the accord roster + quorum from this **pinned** object (via `accord_roster_from_family` / `accord_quorum_from_family`), never from a peer (fetching = TOFU). A constitutional trust root in the same class as the steward / `ciris-canonical` / Yubico custody roots — and explicitly NOT riding CIRISServer's `CANONICAL_BOOTSTRAP_PEERS`. **Empty (`None`) until the real 2-of-3-cosigned ceremony genesis is baked** (mirrors `CANONICAL_BOOTSTRAP_PEERS = &[]` until 0.6) — the bake is a one-line const update. Fail-closed: a malformed/wrong-kind bake stays `None`. Prior: **6.10.0** — **`accord:lifecycle:active` reactivation scope (#95 "Gap 1")**: the 4th constitutionally-valid HUMANITY_ACCORD signature scope (CC 4.2.1 §69 — the *only* sanctioned **resumption** after a constitutional halt; the CIRISServer `reactivate`). `humanity_accord::InvocationKind` gains `LifecycleActive` (wire `lifecycle:active`), and — because CC §4.2.1.1 closes the `accord:invoke` preimage to exactly {CONSTITUTIONAL, notify, drill} and accord scopes are "wire-isolated AND scope-isolated" — it signs a **distinct** canonical-bytes domain `LIFECYCLE_DOMAIN_PREFIX = "ciris.accord_lifecycle.v1\n"`, never the invoke preimage (no signature crosses the invoke↔lifecycle scope boundary, even with identical id/nonce/payload). It rides the existing 2/3 concurrence flow (`co_sign_invocation`/`concur_accord_invocation`/`accord_invocation_status`/`verify_invocation` are kind-agnostic) and the `ciris-verify accord invoke --kind reactivate` CLI. **⚠ The `accord:lifecycle` canonical-bytes layout is verify-authored (first impl) — CC §4.2.1.1 normatively pins only the `accord:invoke` preimage; flagged for CEG cross-confirmation (CIRISRegistry).** Prior: **6.9.0** — **general (role-agnostic, non-entrenched) `build_membership_change` / `verify_membership_change` (#104)**: the v6.8.0 accord membership-change pair, generalized so a plain `quorum:M/N` community of `role: member` keys can grow/shrink/rotate its roster through the same canonical `supersedes` path. The general pair owns every invariant once — distinct members, strict-majority `2·M>N` (caller may pin a stronger policy; split-brain `1/2` refused), one-human one-seat distinct-pubkey gate, anti-replay `supersedes` binding, entrenchment-not-lifted, and the **prior** roster's quorum counted **role-agnostically** (not founder-only). `build_accord_membership_change` / `verify_accord_membership_change` are now thin **entrenched+founder specializations** (24 accord tests byte-identical). `roster_from_envelope` is the shared roster core. Unblocks CIRISPersist#249's general `supersede_group`. Prior: **6.8.1** ml-dsa 0.1.1 seed-zeroize (#87); **6.8.0** — **growable M-of-N accord family + membership-change `supersedes` + name-free key labels (#95, #96)**: the HUMANITY_ACCORD family is now **growable** — `build_accord_family_envelope` sets `consensus_protocol` to the strict-majority `quorum:M/N` for the member count (`accord_consensus_protocol`/`strict_majority`: 3→2/3, 5→3/5), and `assemble_accord_family_genesis` derives the threshold from the envelope instead of a hardcoded 2. The family object is the single source of truth for both the **roster** (`accord_roster_from_family` — resolves `family.members` against a directory, *ignoring* non-member rows so a person's spare can never become a second seat) and the **threshold** (`accord_quorum_from_family`). **Membership change (#95):** `build_accord_membership_change` + `verify_accord_membership_change` — the entrenched-family `supersedes` for grow / shrink / spare-swap, authorized by the **prior** roster's strict-majority quorum, entrenchment-preserving (rejects lifting the entrenched flag, changing `family_key_id`, dropping below `2·M > N`, or a `supersedes.prior_member_key_ids` that doesn't match the real prior roster — anti-replay). **Name-free labels:** accord key_ids are now `A1`/`B1`/`C1` (primaries) + `A2`/`B2`/`C2`… (spares) — no human names, for the family's structural-invisibility. Runbook §0/§5.1/§10 updated (one-seat-per-human: the kill-switch roster is `family.members`, NOT all accord_holder rows — the CIRISServer#41/#61 gate requirement). NB the §9.2.1 invocation vocabulary stays **closed** (CONSTITUTIONAL/notify/drill); a lifecycle/reactivation kind is deferred pending constitutional grounding (`accord:lifecycle:active` is a self-attestation, not an invocation). Prior: **6.7.1** — **accord custody attestation validated on real hardware + variable-length Yubico chain (#91)**: validated end-to-end against a physical **YubiKey 5 FIPS fw 5.7.4** (`examples/validate_yubikey_attestation`) — `verify_yubikey_piv_attestation` ADMITTED with `fips_certified:true`/`touch_always:true`/`firmware:5.7.4`, confirming the documented Yubico encodings on real hardware (DER-OCTET-STRING-unwrapped `.3`/`.8`, FIPS `.10` on the f9 cert, bare-32-byte Ed25519 SPKI, **SHA256-RSA chain through x509-parser**). The validation revealed Yubico's **2024-12 PKI overhaul**: the chain is now **4 levels** (`9c → f9 → CN=Yubico PIV Attestation B 1 → CN=Yubico Attestation Root 1`), so the verifier + producer were generalized from a fixed 3-cert chain to a **variable-length** path (`verify_yubikey_piv_attestation(9c, &[f9, …intermediates…], pinned_root, expected_ed)`; the bundle now carries `yubikey_attestation_chain_hex`). Pin the **durable root** `Yubico Attestation Root 1` (`developers.yubico.com/PKI/yubico-ca-1.pem`), not the rotating `B 1` intermediate; pre-5.7 keys still verify with `[f9]` under the old root. FFI/Python verify surface unchanged (still one pinned-root arg). Prior: **6.7.0** — **accord-holder custody attestation (#91, the CIRISServer#41 safe-mesh floor)**: `accord_custody_attestation` — the hardware-unforgeable evidence the CIRISServer admission gate verifies before admitting an accord kill-switch key. The **combined 2+3** design: a separate signed CEG object (`accord_holder_custody_attestation`, so the Persist `federation_keys` record stays byte-exact) carrying the YubiKey **PIV slot-9c attestation certificate** — signed inside the YubiKey by its slot-f9 key, chaining to the **pinned Yubico PIV attestation root**. `verify_accord_custody_attestation` proves: (1) the bundle is holder-hybrid-signed (RequireHybrid), (2) the 9c cert chains 9c → f9 → pinned Yubico root, (3) the attested key == the holder's federation Ed25519 key, (4) the Yubico extensions (`1.3.6.1.4.1.41482.3.*`) show FIPS-certified + touch=always → `hardware_class: YubiKey_5_FIPS`. Fail-closed `CustodyError`; the security-critical chain is factored into the directly-testable `verify_yubikey_piv_attestation` helper (rcgen mock-chain tests) and proven producer↔verifier-coherent. Exposed through FFI (`ciris_verify_accord_custody_attestation`, JSON-in/JSON-out) + Python (`verify_accord_custody_attestation`). **⚠ The Yubico extension byte-encodings (touch-policy value, FIPS ext) are pinned from Yubico's published OID table but MUST be cross-confirmed against a real YubiKey 5 FIPS attestation before the gate enforces them** — the rcgen tests validate the chain + extraction *logic*, not the real-device bytes (flagged for #91 validation with the in-hand keys). Prior: **6.6.1** seal-alias decoupling (#89); **6.6.0** portable signature-wrapped ML-DSA-65 USB key mode (#88); **6.5.0** invocation concurrence (CC 4.2.1, #86); **6.4.1** accord genesis 2/3 (not unanimous); **6.4.0** HUMANITY_ACCORD genesis producer; **6.1.x** delegate CLI + per-platform CEG manifests. **6.0** — **operator CLI for hardware-rooted federation identity (#63)**: `ciris-verify token probe` / `token sign-test` discover and prove an owner-binding key on a PKCS#11 / YubiKey PIV token (Ed25519 federation key detection + on-token sign-and-verify), and `ciris-verify identity create` produces a self-signed genesis `KeyRecord` — Ed25519 rooted on a YubiKey PIV key + the software ML-DSA-65 half — written to `~/ciris/ceg/outbox/federation_key_record/<key_id>.json` for CIRISServer to drain and relay via `register_key`. New `ceg_outbox` (universal CEG outbox producer path, `$CIRIS_HOME`-overridable) + `federation_self_record` modules, plus a `sign_occurrence_revocation` "revoke a lost device" producer. Verify only produces + signs the object offline; CIRISServer broadcasts it over CEG. See [`docs/FEDERATION_IDENTITY.md`](docs/FEDERATION_IDENTITY.md). Prior: **v5.14.0** — **self-at-login hardware-rooted identity + WebAuthn presence ceremony (#63)**: `self_at_login` now roots the user key in hardware. New `SelfSigner` async trait unifies the software `HybridSigningIdentity` and a new `HardwareRootedIdentity` (Ed25519 in a `ciris_keyring::HardwareSigner` — Secure Enclave / StrongBox / TPM-sealed / YubiKey-PKCS#11 via the #80 `user_identity` backends — plus the software ML-DSA-65 PQC half; Ed25519-only enforced at construction, fail-closed). Every producer gained an `*_async` path over `SelfSigner` (shared envelope builders → zero JCS drift vs the proven sync producers). `PresencePolicy` + `verify_presence` make a WebAuthn/passkey assertion the **unlock** factor (never the owner-binding signature), and `perform_self_at_login` runs the full bilateral ceremony (presence gate → user-signed delegation + partnership grant → occurrence-signed accept + transport binding → directory members), each piece round-tripped through `operational_admit` / `threshold` / `transport_binding` in-test. Producer surface is Rust-native (no FFI obligation — follows the v5.6.0 producer precedent); FFI exposure is a #63 follow-up when KMP-client wiring lands. Intermediate cuts: v5.13.0 real cryptoki PKCS#11/YubiKey backend (#80, live-test gated on a physical token); v5.12.0 WebAuthn passkey assertion verifier cross-checked vs `webauthn-rs` (origin exact-match + signCount surfaced); v5.11.0 multi-HW-key-per-identity redundancy (`UserIdentityKeyset` OR-of-N) + federation threat model v1.5 (RATCHET corridor-not-ceiling, RC24 moderation-principal walk-up). Prior: v5.10.0 — **CEG 1.0-RC14 §19.7 forever-memory aggregation pyramid (#79)**: `holonomic::aggregation` — `AggregationMetaV1` canonical preimage + PQC-mandatory `verify_aggregation_meta`, `member_commitment`/`verify_member_commitment` (reusing the §19.1 WholenessWitness Merkle), the §19.7.2 descent order, and the `EjectionVerdict{Keep|EjectToTier|EjectHardDelete}` tier-aware retirement surface (N5: revoked → hard-delete, never tier-shed). **Verify is the first conformant impl, so it authors the §19.7 vectors** (`tests/conformance_vectors_v19_7.rs` emit-or-verify; Persist/Edge reproduce). Prior: v5.9.0 §19 holonomic proven cross-impl against CIRISEdge v4.1.2 vectors (`tests/vectors/holonomic_v19/`, `tests/conformance_vectors_v19.rs`) — lifting §19 from RC-grade toward CEG 1.0 GA. Prior: v5.8.0 CEG 1.0-RC11 §19 holonomic substrate verifiers (#78) — §19.0 binary signed-preimage PQC-mandatory gate, §19.1 WholenessWitness Merkle + equivocation, §19.2 recursive-bootstrap (trust≠membership, ≤5-hop, cycle-reject, weight cap), §19.3 fountain holding-claim + revocation-respect, §19.4 ALM capacity authenticity, §10.5.8 A/V chunk nonces. See the v5.8.0 substrate note below. Prior: v5.7.0 CEG 1.0-RC7 conformance + HNDL hardening (#75 hybrid-required at every federation-tier gate, #76 partnership member-set, #77 scope split); v5.6.0 security-audit remediation (#72/#73/#74/#28/#63). The per-crate "Phase" labels below are historical; all crates are production-released.)*

| Crate | Status | Notes |
|-------|--------|-------|
| `ciris-keyring` | Released | HardwareSigner trait, SoftwareSigner impl, Android Keystore, TPM 2.0 (dual-key architecture), SecureBlobStorage for wallet seeds, PqcSigner + MlDsa65SoftwareSigner (feature `pqc-ml-dsa`), **`TransportIdentityKeystore` + `BlobTransportKeystore` — keyring-backed RNS transport identity over the existing SecureBlobStorage tiers (#68, CIRISEdge#99 consumer)**, **`SealedEd25519Signer` + `get_platform_ed25519_signer` — TPM/SE-sealed Ed25519 federation signing key (32-byte pubkey preserved; the Ed25519 counterpart to `get_platform_signer`'s TPM-native ECDSA) (#70, CIRISServer consumer)**, **`SealedMlDsa65Signer` + `get_platform_sealed_mldsa65_signer` — TPM/SE-sealed ML-DSA-65 seed (the PQC half; signing stays software, seed sealed at rest) so the whole hybrid federation key is hardware-backed (#71)**, **`hw_token` generic interface-keyed HW-security-token abstraction + probe→§9.4 `hardware_class` resolver (#62)**, **`usb_wrapped_mldsa65::UsbWrappedMlDsa65Signer` — portable high-secure ML-DSA-65 custody: the PQC seed is AES-256-GCM-wrapped on a USB key under a key derived from the YubiKey's deterministic Ed25519 signature over a domain-separated challenge (`HKDF(Ed25519_sign("ciris.accord.mldsa-usb-wrap.v1"‖key_id), salt)`). Both the USB (ciphertext) and the YubiKey + PIN + touch are required to unwrap; the YubiKey stays signing-only (no decrypt/KEX added — CC §9.2). Portable, not machine-bound. Accord/high-secure-fedID mode; CLI `--portable-usb`** |
| `ciris-crypto` | Released | ECDSA P-256, Ed25519, ML-DSA-65 (FIPS 204), hybrid signer with bound signatures, secp256k1 wallet signing, **AES-256-GCM / HKDF / HMAC federation primitives**, **X25519 + ML-KEM-768 hybrid KEX + `key_grant` wrap v1/v2 (X25519+ML-KEM-768, CEG §10.5.3)**, **`random` SP 800-90B RNG health-check + fail-secure (#55)**, **scope-native privacy surface (#82): HKDF-SHA3-256 + HMAC-SHA3-256, `xchacha` XChaCha20-Poly1305 AEAD, `hpke` RFC 9180 mode_base over the X-Wing hybrid KEM (+ caller-composed ML-DSA-65 sender-auth), `scope_privacy` §2.2/§2.4/§3.4 record_id (canonical RFC 8949 §4.2.1 CBOR + HMAC-SHA3) / symbol-key / witness-cover-leaf derivations — first cut of the cross-cdylib lockstep cascade; see [`docs/SCOPE_PRIVACY_NOTES.md`](docs/SCOPE_PRIVACY_NOTES.md)**, **`self_enc` deterministic self content-encryption keypair derivation (X25519 + ML-KEM-768) from the Ed25519 base seed via domain-separated HKDF, mirroring the wallet pattern (#151)** |
| `ciris-verify-core` | Released | Full verification engine, HTTPS-authoritative consensus, anti-rollback, transparency log (Merkle), file integrity, remote attestation export, binary self-verification, hardware vulnerability detection, offline manifest cache, **`jcs` RFC 8785 canonicalizer + Contribution verify (#59)**, **`doc_integrity` hybrid-signed artifact integrity (#54)**, **`infrastructure_community` CEG 0.11 M-of-N trust root + `threshold` founder-quorum (#31)**, **`boundary_degraded` attestation field (#60)**, **`operational_admit` CEG 1.0-RC2 §5.6.8.13 admit surface — `resolve_role_authority` (§8.1.12.7.1 role-chain) + `verify_partner_record_quorum` (#65)**, **`holonomic` CEG §19 / §19.7 substrate verifiers — §19.0 PQC-mandatory preimage gate, §19.1 WholenessWitness Merkle + equivocation, §19.2 recursive-bootstrap (trust≠membership), §19.3 fountain, §19.4 ALM capacity, §10.5.8 A/V nonces, §19.7 `AggregationMetaV1` + `member_commitment` + `EjectionVerdict` (#78/#79); §19 cross-impl-proven vs Edge v4.1.2, §19.7 **1.0** vs Edge v4.3.0. See [`docs/HOLONOMIC_SUBSTRATE.md`](docs/HOLONOMIC_SUBSTRATE.md)**, **`self_at_login` CEG §8.1.12.7 producer + hardware-rooted login ceremony — `SelfSigner` seam, `HardwareRootedIdentity` (hardware Ed25519 + software ML-DSA), WebAuthn `PresencePolicy`/`verify_presence` unlock, `perform_self_at_login` bilateral bundle (#63)**, **`ceg_outbox` universal `~/ciris/ceg/outbox/<kind>/<id>.json` producer path ($CIRIS_HOME override) + `federation_self_record::produce_self_key_record` self-signed genesis KeyRecord (byte-exact to Persist register_key) + `sign_occurrence_revocation` revoke producer (#63)**, **`accord_genesis` HUMANITY_ACCORD genesis producer (CEG §9.1) — `produce_accord_holder_record` + the entrenched-`family` 2-of-3 genesis (`build_accord_family_envelope` → `co_sign_accord_family` → `assemble_accord_family_genesis`, **2/3 quorum of distinct keys** (not unanimous), round-tripped through `verify_founder_quorum`) **+ the operational invocation concurrence flow — `co_sign_invocation` / `build_accord_invocation_object` / `concur_accord_invocation` / `accord_invocation_status` (one holder invokes a CC 4.2.1 closed-vocab kill/notify/drill, ships it, another concurs to 2/3; distinct-key + identity-bound)** + the `ciris-verify accord` CLI (`holder` / `family-envelope` / `co-sign` / `assemble` / `invoke` / `concur` / `list`) wrapping runbook §5–§7; see [`docs/ACCORD_KEY_GENESIS_RUNBOOK.md`](docs/ACCORD_KEY_GENESIS_RUNBOOK.md)**, **`accord_custody_attestation` hardware-unforgeable accord-holder custody attestation (#91) — `produce_accord_custody_attestation` (holder hybrid-signs a bundle carrying the YubiKey PIV 9c attestation cert) + `verify_accord_custody_attestation` / `verify_yubikey_piv_attestation` (chain 9c → f9 → pinned Yubico root, attested-key == holder Ed25519, FIPS + touch=always floor → `hardware_class: YubiKey_5_FIPS`); fail-closed `CustodyError`. The CIRISServer#41 safe-mesh-floor admission gate**, **`accord_holder_bootstrap_anchor() -> Vec<[u8;32]>` — the genesis-mesh rooting anchor (#160): the seated holders' (A1/B1/C1) Ed25519 keys, derived from the baked genesis roster; a chain terminating at any one roots (set-membership 1-of-N; 2/3 is invocation-only), `steward,accord_holder` terminus satisfies the steward gate** |
| `ciris-verify-ffi` | Released | C FFI, JNI bindings (Android full attestation), Swift wrapper (iOS full attestation), wallet signing FFI, named key storage, **wheel surfaces for hybrid_kex / key_grant / reconsider_dos / skill_import / locale_merkle / `jcs` (#61)**, **`resolve_role_authority` + `partner_record_quorum` operational-admit JSON surface (#65)**, **`ciris_verify_accord_custody_attestation` accord-holder custody-attestation JSON surface (#91)**, **`ciris_verify_rns_destination_hash` §5.6.8.8.1.1 RNS dest-hash recompute surface (#28 lift)**, **`ciris_verify_scope_privacy_derive` scope-native privacy derivation surface (#82)**, **`ciris_verify_self_enc_derive` self content-encryption keypair derivation surface (X25519 + ML-KEM-768 from the Ed25519 seed, #151)** |
| `bindings/python` | Released | **ciris-verify 5.1.0** on PyPI with platform wheels, wallet signing, named key storage, **`jcs_canonicalize` module-level binding (#61)**, **`resolve_role_authority` + `verify_partner_record_quorum` module-level bindings (#65)**, **`verify_accord_custody_attestation` module-level binding (#91)**, **`rns_destination_hash` module-level binding — the §5.6.8.8.1.1 RNS dest-hash recompute on the wheel (#28 lift)**, **`scope_privacy` namespace — the §2.2/§2.4/§3.4 scope-native privacy derivations (#82)**, **`derive_self_enc(seed) -> SelfEncKeys` module-level binding — deterministic self X25519 + ML-KEM-768 content-encryption keypairs (#151)** |
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
self-signed `federation_keys` (incl. the v6.0 genesis self-signed `KeyRecord` producer, `federation_self_record.rs`, where `scrub_key_id == key_id`), the genesis-case
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
# Build CLI (token/identity need the pkcs11 feature)
cargo build --release -p ciris-verify-core --features pkcs11

# Full attestation (Levels 1-5)
./target/release/ciris-verify attest --agent-root /path/to/agent --version 1.2.3

# Self-check (binary integrity, Level 2)
./target/release/ciris-verify self-check

# Cross-check registry sources (Level 3)
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
# --- 6.5 accord invocation concurrence (the operational kill-switch flow; CC 4.2.1 closed vocab) ---
# Holder A invokes (kind ∈ {constitutional, notify, drill}) on their token → 1/2-signed object
./target/release/ciris-verify accord invoke --key-id A1 --roster roster.json --kind constitutional --invocation-id halt-2026-06-19 --payload-sha256 <hex> --module .../libykcs11.so --key-label "..." --pin
# Holder B lists pending objects (flags the ones whose roster they belong to)
./target/release/ciris-verify accord list --mine B1
# Holder B concurs → 2/2, quorum met
./target/release/ciris-verify accord concur --object <invocation.json> --key-id B1 --module .../libykcs11.so --key-label "..." --pin
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
