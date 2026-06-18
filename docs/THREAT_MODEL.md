# CIRISVerify Threat Model

> **Holonomic substrate (CEG §19 / §19.7).** The threat model + verifier
> reference for the `holonomic` module (WholenessWitness, recursive bootstrap,
> fountain, ALM, and the §19.7 forever-memory aggregation pyramid) lives in
> **[`HOLONOMIC_SUBSTRATE.md`](HOLONOMIC_SUBSTRATE.md)** — §19 is cross-impl-proven
> against CIRISEdge v4.1.2, §19.7 is **1.0** (proven against CIRISEdge v4.3.0).

**Last updated:** 2026-06-18 (v6.0 "self-at-login device identity" — AV-43 CEG outbox / AV-44 software-PQC-seed honest-boundary / AV-45 surviving-key revocation; YubiKey PIV §5 row. Prior v5.11.0 "CEG §19 / §19.7 holonomic" — `holonomic` substrate verifiers; §19 cross-impl-proven (Edge v4.1.2), §19.7 promoted to **1.0** (Edge v4.3.0 reproduced Verify-authored vectors), RC16 `EjectAggregatedTierOnly` verdict, RC15 §19.1 Merkle frozen (no RFC-6962 prefix). See [`HOLONOMIC_SUBSTRATE.md`](HOLONOMIC_SUBSTRATE.md). Prior v5.7.0 "CEG 1.0-RC7 / hybrid-required" — **PQC half MANDATORY at every federation-tier admission gate** (#75, RC7 §10.1.5.1.1): `threshold`/`provenance`/license gates reject classical-only ("hybrid-pending") signatures via `HybridPolicy::RequireHybrid`, closing the F-AV-14 "buggy verifier accepts old-classical-only" gap (see §3.2 AV-8 and `FEDERATION_THREAT_MODEL.md` F-AV-14); partnership seven-member set (#76); `infra:*`/`agency:*` delegation scope split makes §1.3 "infrastructure must not have agency" wire-checkable (#77). v5.6.0 "security-audit remediation" — license-signature gate (#72), real TPM sealing (#73), fail-secure keygen (#74), RNS `destination_hash` recompute (#28), producer signing (#63). Prior v5.0.0 "CEG 1.0 / Agent 3.0 substrate" — RNG SP 800-90B startup health-check + fail-secure (AV-39 closed), `boundary_degraded` orthogonal to `hardware_trust_degraded`, JCS/RFC-8785 cross-impl signing bytes, `key_grant` wrap_algorithm v2 (X25519+ML-KEM-768) at-rest PQC, `doc_integrity` hybrid-signed artifact integrity + CODEOWNERS two-person-rule on threat-model docs, `infrastructure_community` M-of-N trust-root substrate)

## 1. Scope

### What CIRISVerify Protects

CIRISVerify is the hardware-rooted license verification module for the CIRIS ecosystem. As of v1.8.3 it also serves as the **build-attestation substrate primitive** for the PoB federation — every CIRIS peer (agent, lens, persist, registry, and CIRISVerify itself) signs and validates its build manifests through one shared code path (`verify_build_manifest`).

It protects against:

- **Identity fraud**: Unlicensed agents (CIRISCare) masquerading as licensed professional agents (CIRISMedical, CIRISLegal, CIRISFinancial)
- **License forgery**: Fabrication of valid-looking license status without registry authority
- **Capability escalation**: Agents claiming capabilities beyond their license tier
- **Silent degradation**: Agents suppressing or modifying mandatory disclosure about their license status
- **Verification tampering**: Modification of the verification binary to return false results
- **Cross-primitive identity confusion**: A compromised primitive's steward key being used to forge other primitives' manifests (v1.8 federation surface)
- **Ephemeral identity churn**: Silent ephemeral storage causing federation peers to lose continuity across restarts (v1.7 storage-descriptor surface)

### What CIRISVerify Does NOT Protect

- **Malicious behavior with valid license**: A properly licensed agent can still act maliciously within its authorized capabilities
- **Compromised steward issuing malicious licenses**: If the license issuing authority is compromised, valid-looking licenses can be issued for malicious agents
- **Network availability**: CIRISVerify degrades gracefully to community mode when offline but cannot guarantee connectivity
- **User device security**: If the user's device is fully compromised (root/admin access), hardware protections may be bypassed
- **Supply chain compromise of hardware**: If the HSM/TEE manufacturer is compromised, hardware attestation is unreliable

---

## 2. Adversary Model

### Adversary Capabilities

The adversary is assumed to have:

- **Full source code access** (AGPL-3.0 licensed, publicly available)
- **Ability to modify and rebuild** the verification binary
- **Network interception** capability (passive and active MITM)
- **Control of one DNS registrar** or one verification source
- **Ability to replay** previously captured valid responses
- **Access to emulators and debuggers** for runtime analysis
- **Unlimited computational resources** for classical cryptography attacks

### Adversary Limitations

The adversary is assumed to NOT have:

- **Simultaneous compromise of all DNS registrars** serving verification data
- **Compromise of the hardware security module** (TPM 2.0, Secure Enclave, StrongBox)
- **Ability to break both Ed25519 AND ML-DSA-65** simultaneously (hybrid crypto defense)
- **Physical access** to the deployment hardware
- **Compromise of the HTTPS certificate infrastructure** (CA compromise)
- **Ability to manipulate system clocks** by more than 5 minutes on the target device

---

## 3. Attack Vectors

Fourteen attack vectors organized by adversary goal. Each lists the attack, primary mitigation, secondary mitigation, and residual risk in-place. Goal-based grouping (mirrors CIRISPersist's structural pattern) makes the surface boundaries explicit:

- **§3.1 License Fraud** — adversary wants to claim a license tier they don't have (AV-1..AV-6)
- **§3.2 Federation Identity** — adversary wants stable misidentification or evasion of longitudinal scoring (AV-7, AV-8)
- **§3.3 Build Provenance** — adversary wants to strip or forge "this primitive's CI signed this binary" attestation (AV-9)
- **§3.4 Supply Chain** — adversary wants to ship malicious code through legitimate signing channels (AV-11, AV-12)
- **§3.5 Hardware Trust Anchor** — adversary wants to extract or counterfeit hardware-bound signing keys (AV-13)
- **§3.6 Operational / Reliability** — non-adversarial failure modes that still cost availability (AV-10)
- **§3.7 Multi-Instance Cohabitation** — multiple CIRISVerify instances on one host racing on shared keyring state (AV-14)

Original six vectors (AV-1..AV-6) from FSD-001; v1.7-v1.8 federation work added AV-7..AV-9; SOTA review (mid-2026) added AV-11..AV-13; v1.6.3 incident response promoted AV-10 to first-class status; v1.8.x cohabitation analysis added AV-14.

---

### 3.1 License Fraud — adversary wants to claim a license tier they don't have

#### AV-1: Code Forking / License Check Removal

**Attack**: Fork the open-source code, remove license checks, deploy as "licensed" agent.

**Primary mitigation**: Hardware-bound signing key. The verification response is signed by a key stored in the device's HSM. A forked binary cannot produce valid signatures because it lacks the hardware key. The key IS the identity — it cannot be copied from the source code.

**Secondary**: Binary integrity check at startup; transparency log records all verification events for after-the-fact audit.

**Residual**: A forked binary running on a SOFTWARE_ONLY device can produce locally-valid-looking output, but it's permanently capped at COMMUNITY tier (§5.1 invariant). Federation peers won't accept its output as professionally-licensed regardless of internal claims.

#### AV-2: Runtime Modification to Fake Licensed Status

**Attack**: Modify the running binary in memory to return fake "licensed" status.

**Primary mitigation**: Binary self-integrity verification at startup (hash comparison against signed manifest). Anti-debugging detection (ptrace, Frida, Xposed). Platform integrity checks (root/jailbreak detection). All checks return opaque pass/fail to prevent targeted bypasses (FSD-001 §"Integrity Check Opacity").

**Secondary**: Hybrid signature on attestation responses — even if the binary is modified to claim higher tier, downstream consumers verifying the response signature against the steward pubkey will reject.

**Residual**: A rooted device with a memory-patched binary can produce locally-correct UX (mandatory disclosure suppressed) but cannot forge valid signatures. The downstream verifier (e.g., another agent in the federation) catches the lie.

#### AV-3: Verification Endpoint Spoofing

**Attack**: Intercept and replace responses from verification endpoints.

**Primary mitigation**: Multi-source validation with consensus. DNS US + DNS EU + HTTPS API must agree (2-of-3 minimum). HTTPS is authoritative when reachable; DNS is advisory cross-check. Multiple HTTPS endpoints at different domains provide redundancy. Certificate pinning on HTTPS connections.

**Secondary**: Hybrid signature on responses ensures the *content* is steward-signed even if the *transport* is spoofed.

**Residual**: Simultaneous compromise of all three sources (US registrar + EU registrar + HTTPS CA) is the bypass. Mitigation is operational — sources are in different jurisdictions with different providers — but a state-level adversary with reach into all three is not defended against.

#### AV-4: Replay of Old Valid License After Revocation

**Attack**: Capture a valid license response before revocation, replay it afterward.

**Primary mitigation**: Anti-rollback monotonic revision enforcement. The system tracks the highest-seen revocation revision and rejects any revision that decreases. Challenge nonce (32+ bytes) prevents simple replay. License expiry timestamps provide time-based bounds.

**Secondary**: Transparency log records all revocation events; federation peers cross-check.

**Residual**: A captured response replayed within its expiry window before any revocation event lands at the consumer's seen-revision counter is acceptable per design — that's the intended grace window. Adversary cannot replay across a revocation event without rolling back the seen-revision counter (which the storage layer prevents).

#### AV-5: Man-in-the-Middle Attestation Responses

**Attack**: Intercept attestation responses and modify them to claim higher trust level.

**Primary mitigation**: Hybrid cryptographic signatures (Ed25519 + ML-DSA-65) over all response data. PQC signature is bound to classical signature (covers `challenge_nonce || classical_sig`), preventing signature stripping. Remote attestation proof export allows third parties to independently verify hardware binding.

**Secondary**: TLS termination + cert pinning at the transport layer.

**Residual**: A complete crypto break of both Ed25519 AND ML-DSA-65 simultaneously. ML-DSA-65 is NIST-standardized post-quantum; Ed25519 is classical. Hybrid means both must fall. **As of v5.7.0 (#75) this "both must fall" property is enforced, not merely intended: federation-tier verification rejects a classical-only signature** (`HybridPolicy::RequireHybrid`), so a break of Ed25519 *alone* no longer suffices to forge an accepted attestation/grant/binding — see §3.2 AV-8 and `FEDERATION_THREAT_MODEL.md` F-AV-14. (Through v5.6.0 several gates accepted a "hybrid-pending" classical-only signature, which reduced the bar to a single-algorithm break at those gates.)

#### AV-6: Emulator/Debugger Interception

**Attack**: Run the agent in an emulator or attach a debugger to intercept and modify verification responses at runtime.

**Primary mitigation**: Platform-specific integrity checks detect emulators (Android: goldfish, qemu; iOS: simulator; Desktop: hypervisor/DMI checks). Debugger detection (ptrace on Linux/Android, sysctl on macOS, IsDebuggerPresent on Windows). Hook detection for Frida/Xposed frameworks. Timing anomaly detection for breakpoint-induced delays.

**Secondary**: Emulator/rooted devices are degraded to COMMUNITY tier rather than blocked outright (open-source principle: never fully stop execution; restrict capability instead).

**Residual**: Sophisticated emulator setups that defeat detection (e.g., hypervisor-level intercepts that hide from in-VM checks). Defense-in-depth via downstream signature verification — even if local checks pass, federation peers verifying the agent's signed output catch fakes.

---

### 3.2 Federation Identity — adversary wants stable misidentification or evasion of longitudinal scoring

#### AV-7: Ephemeral Identity Storage (lens-scrub-key class)

**Attack**: A federation peer's signer silently lands its identity seed in ephemeral storage (container writable layer, `/tmp`, `/var/cache`, user-session keyring). Identity churns every restart. The score function's longitudinal window (PoB §2.4 S-factor 30-day decay) cannot accumulate behind an unstable identity, so anti-Sybil weight stays at zero by construction.

**Primary mitigation**: `HardwareSigner::storage_descriptor()` (v1.7+) declares where the seed lives at runtime. Boot-time logging in `factory.rs::create_hardware_signer` surfaces the descriptor at INFO level for every signer construction. The trait method has no default impl — every signer variant is forced to declare its location.

**Secondary**: Consumers (CIRISAgent, CIRISPersist) gate `--strict-storage` mode that refuses to start if the descriptor matches an ephemeral path heuristic. `disk_path()` and `is_hardware_backed()` helpers let consumers ship their own typed checks.

**Residual**: An operator can override with `CIRIS_PERSIST_KEYRING_PATH_OK=1` (or equivalent) after manual audit. A consumer that ignores the descriptor entirely (doesn't gate boot on it) is back to the pre-v1.7 surface — but that's a consumer-side bug, not a verify-side gap. **Empirical trigger**: 2026-04 lens-scrub key incident (CIRISLens). Persist hit the same class without the descriptor.

#### AV-8: Cross-Primitive Identity Confusion

**Attack**: A compromised primitive's steward key (e.g., lens's) is used to sign a manifest claiming `primitive: agent`, hoping a verifier accepts it as if signed by agent's steward. "Confused deputy" pattern (OWASP Agentic Apps Top-10 in 2026).

**Primary mitigation**: `verify_build_manifest(bytes, expected_primitive, &trusted_pubkey)` validates `manifest.primitive == expected_primitive` BEFORE checking the signature. The primitive discriminant is part of the canonical bytes the hybrid signature covers, so a cross-primitive replay would have to forge a signature valid under a *different* primitive's steward key — equivalent to the original key-compromise problem, not a new attack surface.

**Secondary**: Per-primitive trusted-pubkey lookup means the wrong primitive's signature wouldn't match the expected primitive's pinned key. Lookup mechanism formalized via [`CIRISRegistry/docs/TRUST_CONTRACT.md`](https://github.com/CIRISAI/CIRISRegistry/blob/main/docs/TRUST_CONTRACT.md) §6 — admin-managed `RegisterTrustedPrimitiveKey` admin RPC writes to registry's `trusted_primitive_keys` table (cross-region replicated via Spock per CIRISRegistry#4).

**Long-term mitigation (persist v0.2.x federation directory)**: The trusted-pubkey lookup layer migrates from "registry-local table that the steward writes" to persist's federated `federation_keys` substrate (per [`CIRISPersist/docs/FEDERATION_DIRECTORY.md`](https://github.com/CIRISAI/CIRISPersist/blob/main/docs/FEDERATION_DIRECTORY.md)). Every `federation_keys` row carries scrub-signing four-tuple (recursive cryptographic provenance — every row signed by another row in the same table, terminating at the steward's self-signed bootstrap). Registry becomes a cache+policy layer over persist's substrate (per [`CIRISRegistry/docs/FEDERATION_CLIENT.md`](https://github.com/CIRISAI/CIRISRegistry/blob/main/docs/FEDERATION_CLIENT.md)). This resolves CIRISRegistry#5 §4 not via a new registry endpoint but by repositioning the trust-key-bootstrap layer entirely: persist stores; consumers (registry, verify, agent) compute their own trust verdicts. CIRISVerify verifies the assembled chain in `provenance::verify_provenance_chain` (each link's Ed25519 + ML-DSA-65 scrub-signature against the parent, terminus pinned to a trusted steward bootstrap).

**v5.7.0 strengthening (hybrid-required, #75 / RC7 §10.1.5.1.1)**: `verify_provenance_chain` now **requires the ML-DSA-65 scrub-signature on every link** at federation-tier (default `HybridPolicy::RequireHybrid`; a classical-only / hybrid-pending link is rejected with `LinkNotHybrid`). Previously a link whose cold-path PQC sign hadn't landed was accepted on its Ed25519 scrub-signature alone — meaning a future Ed25519 break could forge a whole provenance chain rooting a counterfeit key at a trusted steward. The permissive behavior is now confined to an explicit `AllowClassicalPending` local-tier (§10.1.5.2) path. A hybrid-pending `federation_keys` row is therefore *local-tier only* until its PQC half lands — the federation-tier identity-confusion surface is closed against a classical-only adversary.

**Residual**: Trusted-pubkey lookup for non-`Verify` primitives currently requires explicit registration via `RegisterTrustedPrimitiveKey` (registry-side, `CIRISVerify` registered today; persist/lens/agent registration coordinated when their CI migrates to `ciris-build-sign`). The persist v0.2.x federation directory is the architecturally-cleaner long-term resolution; until it ships, registry's `trusted_primitive_keys` table is the operational source of truth.

**v3.4.0 strengthening**: `BuildManifest::to_attestation_entries` (v3.4.0) emits a `provenance:build_manifest:{target}` AttestationEntry signed by the per-primitive steward on successful `verify_build_manifest`. The per-primitive discriminant is now a structurally-observable federation_provenance entry (`attester` field carries the steward `key_id`) rather than only an internal verify-side check — a downstream auditor reading the bundle can confirm which primitive's steward attested the build without re-running the manifest verification themselves.

---

### 3.3 Build Provenance — adversary wants to strip or forge "this primitive's CI signed this binary" attestation

#### AV-9: Build Manifest Write-Without-Read (Phase A artifact)

**Attack**: A registered build manifest's original CI signature is silently lost on registry round-trip. Registry's *legacy* POST endpoint flattens `BuildManifest` into the `function_manifests` table and resigns it under the registry's own steward key on GET. Per-primitive steward attribution ("CIRISVerify-steward-2026 signed this") collapses into "registry vouches for this." A federation auditor asking "which primitive's CI actually signed this binary" gets the wrong answer.

**Primary mitigation (post-CIRISRegistry trust-contract docs PR `9f8e1d7`)**: The new POST endpoint preserves the original CI signature in storage. Authoritative reference: [`CIRISRegistry/docs/TRUST_CONTRACT.md`](https://github.com/CIRISAI/CIRISRegistry/blob/main/docs/TRUST_CONTRACT.md) §2.3 documents the two POST cases definitively. Verifiers distinguish which path served a manifest by inspecting `signature.key_id`:

- `signature.key_id == "verify-steward-2026"` (or any per-primitive steward key) → original CI sig preserved → Case (i) per TRUST_CONTRACT.md §2.3 → trust chain to the publishing primitive's steward key. Registry verifies inbound hybrid signature against `trusted_primitive_keys` (their AV-26 closure, v1.3 Phase A, commit `4adc224`) before storing. Operationally validated by registry's own self-publication since `cd95a9f` 2026-05-01 21:02:44Z.
- `signature.key_id` matching the registry's own steward key (`75c29fcc...`) → legacy POST path, registry-resigned → Case (ii) per TRUST_CONTRACT.md §2.3 → trust chain only back to the registry

**Secondary (Path C, always available)**: GitHub release artifact `signed-build-manifests.tar.gz` (added v1.8.3) preserves the original CI-signed `BuildManifest` end-to-end regardless of which POST endpoint was used. Sigstore-signed alongside the binary archives.

**Residual**: Registry adds `GET /v1/verify/build-manifest/{primitive}/{ver}/{target}` returning the original posted `BuildManifest` (CIRISRegistry#5 item 2, queued as Phase B). Until then, federation peers wanting per-primitive steward attribution need to fetch from Path C (release tarball), not Path A (registry GET). Workable but discoverability-asymmetric.

---

### 3.4 Supply Chain — adversary wants to ship malicious code through legitimate signing channels

#### AV-11: Sigstore OIDC Token Theft (federation-poisoning)

**Attack**: An attacker obtains a valid OIDC token for the CIRIS release identity (e.g., compromised GitHub Actions OIDC issuer config, stolen short-lived token from a misconfigured workflow) and signs a malicious binary that is correctly Rekor-logged. Downstream consumers' Sigstore-verify checks pass; the binary is accepted as authentic. Canonical post-XZ Sigstore-era attack pattern.

**Primary mitigation**: Sigstore identity binding via GitHub Actions OIDC (release artifacts are signed under `https://github.com/CIRISAI/CIRISVerify/.github/workflows/release.yml@refs/tags/vX.Y.Z`). Release notes include the expected signer identity for human review.

**Secondary**: Hybrid signature on the BuildManifest provides a second trust path independent of Sigstore. A token-thief who isn't also the steward-key-holder can produce a Sigstore-valid binary but not a steward-signed BuildManifest.

**Residual**: No continuous Rekor-monitor running against the CIRIS signing identity. A rogue signing event under our OIDC identity would not be detected automatically — only by humans noticing an unexpected release. **Action**: integrate `rekor-monitor` against `https://github.com/CIRISAI/CIRISVerify/...` identity, alarm to maintainers on unexpected entries. See §10 SOTA gap #2.

#### AV-12: Maintainer Compromise / XZ-Style Supply Chain

**Attack**: A maintainer with commit access to CIRISVerify (or any of its transitive Rust dependencies) introduces a backdoor that is legitimately signed and released through normal CI. Source review may not catch it (XZ-3094 hid payload in test fixtures and m4 macros, not git source). Downstream Sigstore + hybrid-sig checks pass.

**Primary mitigation**: Open-source under AGPL-3.0 means independent review is possible. Rust ecosystem's `cargo-audit` and `cargo-deny` checks land via `deny.toml` for advisory and license enforcement.

**Secondary**: None against this attack — a compromised maintainer signs both classical + PQC, so hybrid-sig is no defense; they have legitimate access to the steward key, so steward-signed BuildManifest is no defense.

**Residual (open)**: No two-person-rule on **releases** (single-maintainer signoff is the current path). No multi-maintainer signing key. No SBOM published with releases (CISA / EU CRA gap). No reproducible builds means source-vs-binary divergence cannot be independently verified. **Action items**: §10 SOTA gaps #3 (SBOM), #4 (reproducible builds), #5 (two-person-rule on releases).

**Partial closure for governance docs (v5.0.0, CIRISVerify#54)**: distinct from release signing — the **authoritative threat-model + governance documents** (`FEDERATION_THREAT_MODEL.md`, this file, `MISSION.md`, the embedded `bootstrap_stewards.json`) now have (a) a two-person-rule via `.github/CODEOWNERS` requiring reviewer approval on every edit, (b) a CI `threat-model-changelog` gate rejecting an authoritative-doc edit with no changelog delta (a silent F-AV-status downgrade is now diffable-by-construction), and (c) `ciris_verify_core::doc_integrity` — a hybrid Ed25519 + ML-DSA-65 signed content-hash attestation that detects any post-publication tamper. This closes the *document-integrity* half of the meta-class (FEDERATION_THREAT_MODEL.md §6.7 F-AV-MAINT Phases 1-2); the *release-signing* two-person-rule above is a separate, still-open item.

**Related (registry-side, finer-grained)**: [`CIRISRegistry/docs/THREAT_MODEL.md`](https://github.com/CIRISAI/CIRISRegistry/blob/main/docs/THREAT_MODEL.md) AV-34 ("Build-signing key compromise (CI-side, post-Phase-A surface)") catalogues the post-Phase-A surface where per-primitive build-signing keys held in GHA secrets become load-bearing trust anchors for the federation. Their dual-secret-co-requirement defense (publishing requires BOTH the build-signing key AND `REGISTRY_ADMIN_TOKEN`) and per-repo isolation (compromise of one repo's GHA can publish only that primitive's manifests) extend AV-12's mitigation surface across the federation. Their v1.4 hardening proposals (cosign verification on uploaded manifests, M-of-N signing for high-stakes primitives, SLSA attestation in extras) target the same supply-chain class that our SOTA gaps #3-#5 target.

---

### 3.5 Hardware Trust Anchor — adversary wants to extract or counterfeit hardware-bound signing keys

#### AV-13: TEE.fail / Bus-Interposition Attacks on Server-Class TEEs

**Attack**: Physical access to server hardware running a federation validator (e.g., a CIRISRegistry node, a federation peer running CIRISVerify in a confidential VM). DDR5 memory bus interposition (TEE.fail, Oct 2025, Georgia Tech/Purdue, sub-$1k attack) extracts attestation signing keys from fully-updated Intel SGX/TDX or AMD SEV-SNP machines because memory encryption is deterministic. EMFI on ARM TrustZone skips secure-boot checks reliably.

**Primary mitigation**: Threat model assumption §6.4 says adversary doesn't have physical access. Hardware-vulnerability detection (v1.2.0+) covers SoC-level CVEs (MediaTek CVE-2026-20435 boot ROM EMFI, Qualcomm CVE-2026-21385) and caps attestation to `SOFTWARE_ONLY` for affected devices. See §5.1 for the catalogue of detected hardware vulnerabilities.

**Secondary**: HSM-anchored signing keys (FIPS 140-3 Level 3+) for production registry/steward roles. TEE-anchored keys (SGX/TDX/SEV-SNP/CCA) should NOT be used for steward roles in confidential-VM deployments.

**Residual (open)**: Server-class TEE attacks are not modeled in our adversary capability list — physical access is excluded by assumption §6.4. Datacenter deployments of CIRISVerify or CIRISRegistry SHOULD assume hostile co-tenants and deploy steward keys in HSMs, not TEEs. Document this explicitly in registry deployment guidance. See §10 SOTA gap #7.

---

### 3.6 Operational / Reliability — non-adversarial failure modes that still cost availability

#### AV-10: Stale Hardware-Marker Lockup

**Attack surface (operational, not adversarial)**: A `HARDWARE_SECURED:fingerprint` marker file points at a TPM key that has been deleted (`tpm2_evictcontrol` on the wrong handle, OS reinstall, hardware swap). The agent process indefinitely fails its sign() calls because it believes hardware-bound signing is required, but the hardware key is gone. Recovery requires manual marker deletion.

**Primary mitigation**: v1.6.3 (`fix(v1.6.3): Clear stale hardware markers when key becomes inaccessible`) detects the case and surfaces `KeyringError::HardwareNotAvailable` instead of silent stuck-state. v1.6.4 refined the error variant for clearer operator-runbook signaling.

**Secondary**: Operator-runbook for marker file deletion documented in deployment guidance. On next boot, the agent generates a fresh hardware key and a fresh signed manifest.

**Residual**: Identity continuity lost — the agent that comes back after marker recovery has a different signing key than before, so federation longitudinal scoring (PoB §2.4 S-factor) starts over. This is the correct security tradeoff (cannot recover the "real" identity if hardware key is genuinely gone) but operators should be aware. No silent recovery path; identity loss is loud and visible.

---

### 3.7 Multi-Instance Cohabitation — multiple CIRISVerify instances on one host

#### AV-14: Cross-Instance Keyring Contention

**Attack surface (mostly operational, adversarial in worst case)**: Multiple CIRISVerify instances coexist on one host, racing on shared keyring/HSM state. Three deployment shapes produce this:

1. **In-process cohabitation** — two `.so` files loaded into one Python process (e.g., `CIRISPersist` bundles `ciris-verify-core` at compile time; the same process also imports the `ciris-verify` PyPI wheel which carries another copy of the FFI). Each `.so` has its own `static OnceLock<...>` globals — Rust-level state is NOT shared.
2. **Same-host different-process** — agent and persist running as separate daemons on one box, both using the same keyring alias.
3. **Misconfigured deployment** — multiple agent worker pods scaled out against shared persistent storage without an orchestrator.

In all three, the **OS-level backend is the actual serialization point**: TPM via `/dev/tpm0` (single-tab, multiplexed in-kernel or via `tpm2-abrmd`), Apple Keychain via `securityd` daemon, Android Keystore via Binder IPC, Linux Secret Service via D-Bus. Multiple Rust signer instances are clients of those daemons; concurrent reads serialize cleanly. Three race windows remain in our caller code:

- **Key-creation TOCTOU**: process A reads "no key for alias", calls `generate_key()`. Concurrently B does the same. Backend rejects the second create on Android Keystore (`KeyStoreException`), may silently overwrite on macOS Keychain depending on `kSecAttrAccessible`, races on TPM persistent-handle allocation.
- **Stale-marker race**: the `HARDWARE_SECURED:fingerprint` marker file (v1.4.0+ pattern) is process-local. v1.6.3-v1.6.4 fixes the single-process stale-recovery case but doesn't lock against concurrent recovery from another process.
- **Cache consistency**: A creates the key, B's `cached_signing_key: Option<...>` is still `None`. B fails its first `sign()` until something flushes the cache. No invalidation path.

The adversarial worst case: an attacker who controls one of the cohabiting processes attempts a malicious `delete_key()` while another process is mid-attestation. The legitimate process surfaces `HardwareNotAvailable` (AV-10's fix surfaces the symptom) but the operator may not realize the deletion was hostile rather than a hardware failure.

**Primary mitigation (today)**: When CIRISPersist is in the stack, persist's `Engine` holds the verify Engine — there's structurally one verify instance per process and the contention surface vanishes by construction. The dominant production pattern is "persist is the interface to verify" (see `docs/HOW_IT_WORKS.md` "Cohabitation — When Persist Is the Interface"); higher layers go through persist's API rather than instantiating their own verify Engine. AV-14's race windows describe a multi-instance pattern that doesn't occur in a persist-bearing stack.

In verify-only stacks (registry, sovereign-mode dev, simple CLI tooling), there's structurally one consumer — single process, single instance, no race possible.

**Secondary (today)**: OS-daemon-level serialization (TPM via `/dev/tpm0`, Apple `securityd`, Android Binder, Linux Secret Service) closes the **read** path universally — even in the unusual multi-consumer-without-persist case, concurrent reads serialize cleanly through the OS keyring backend. PoB §3.2 single-key-three-roles enforces same-alias semantics: two instances with the same alias are the *same identity*, not competing identities.

**Residual (open, only in verify-only multi-process stacks without an external bootstrap step)**:
- Cold-start key-creation race window in the uncommon multi-consumer-without-persist pattern (e.g., HA replica set running multiple verify-only processes against shared persistent storage). Fix paths: (a) add persist to the stack — surface vanishes; (b) operator-managed pre-bootstrap (`ExecStartPre=flock`); (c) verify v1.9's planned `flock` scope guards around mutating operations (~30 LoC, lower priority since the pattern is uncommon and avoidable).
- v2.0 out-of-process verify daemon was originally tracked as the architecturally clean answer; the persist-as-interface shape makes it unnecessary. Persist's process *is* the singleton when persist is in the stack; for verify-only stacks the "singleton" is just "the one process you have." v2.0 work pivots to formalizing this in docs and possibly adding a runtime warning if a process detects multiple verify Engines on the same alias (a hint that someone is bypassing persist).

#### Cohabitation contract (operator-facing)

Authoritative semantics for "is multiple-CIRISVerify-on-one-host OK":

| Pattern | Same alias | Different alias |
|---|---|---|
| Multiple read-only instances | ✅ Safe — OS serializes; same identity by PoB §3.2 | ⚠️ Conceptually wrong — two identities claiming one role |
| Multiple instances racing on key creation (cold-start) | ⚠️ Race window — backend may reject, may overwrite, may corrupt marker | ✅ No contention but breaks single-key-three-roles |
| Mid-runtime mutation (delete, rotate, recover stale marker) | ❌ Unsafe — caches diverge; surface `HardwareNotAvailable` storms | ⚠️ Same as above; affects only the mutating instance |

**Recommended deployment posture:**
- Cold-start serialization: don't race two processes through a fresh-deployment key-creation phase. Use a deploy-time advisory lock (e.g., systemd `ExecStartPre` with a `flock` against a known path) to ensure the first process completes the create-or-load phase before the second starts.
- Same-alias for same identity: if your host runs both an agent AND a persist daemon, both should use the same alias to consume the same identity (PoB §3.2). Different aliases = different identities = federation confusion.
- Mutation operations only from one process: pick an "owner" process for `generate_key`, `delete_key`, marker recovery. Other instances are read-only consumers.

---

### 3.8 Federation Crypto Authority — adversary wants to bypass or subvert the v2.0 symmetric / KDF / MAC / RNG surface

Threats specific to v2.0's promotion of `ciris-crypto` from "hybrid signing only" to "federation-wide crypto authority." These cover the AES-256-GCM AEAD, KDF (PBKDF2-HMAC-SHA256 + HKDF-SHA256), HMAC-SHA256, and `OsRng`-facade modules introduced in v2.0.0. Signature-side threats (AV-1..AV-34) are unchanged.

Federation policy: every CIRIS primitive that needs symmetric crypto, KDF, MAC, or random bytes routes through `ciris-crypto`. Direct dependencies on RustCrypto crates (`aes-gcm`, `hkdf`, `pbkdf2`, `hmac`, `getrandom`) from downstream consumers are policy violations — the audit point exists so violations are tractable.

#### AV-35: AES-GCM nonce reuse with same key

**Attack surface (catastrophic class)**: GCM is a counter-mode AEAD. Nonce reuse with the same key allows an adversary observing two ciphertexts under the same `(key, nonce)` to: recover the XOR of the two plaintexts (immediate confidentiality break), recover the GCM polynomial-MAC authentication key `H` (full forgery capability for that key going forward).

The library does NOT detect or prevent reuse. The federation's threat model assumes well-behaved callers (the audit point centralizes nonce-management code review at the consumer side, not at the library boundary).

**Primary mitigation**: spec'd policy in `aes_gcm.rs` module docs — caller MUST use random nonces (12 bytes from `ciris_crypto::random::fill`) or strict per-key counter. Random nonces give a ~2³² messages-per-key birthday bound (NIST SP 800-38D §8.3); counter nonces require strict per-key persistent state.

**Secondary**: federation incident channel — observed nonce reuse is reported as a key-compromise event, triggering rotation. Same-host process boundaries should not share AES keys (per AV-14 cohabitation contract: same alias = same identity, so same key — but symmetric keys derived from per-secret salts are different per row, so reuse only matters within a single secret's lifetime).

**Status**: ⚠ Open at the library layer (caller-managed); ✓ Policy documented.

#### AV-36: PBKDF2 iteration count too low

**Attack surface**: A captured PBKDF2 ciphertext + salt allows offline brute-force of the master password. The cost is `iters × hash_ops` per guess; too-low `iters` shifts the cost into adversary-feasible range. OWASP 2026 recommends 600,000 PBKDF2-HMAC-SHA256 rounds.

**Primary mitigation**: spec'd minimum `iters = 100,000` in CIRISPersist#19 (matches CIRISAgent's existing `ciris_engine/logic/secrets/encryption.py` config, established 2025). `iters = 0` rejected with `CryptoError::KdfParameter`. Future bump tracked separately.

**Secondary**: defense-in-depth via hardware-master mode (CIRISPersist#19 `secrets-hw` feature) skips PBKDF2 entirely — symmetric keys derive via HKDF from a hardware-bound master, no password to brute-force. Only software-master mode is exposed to this AV.

**Status**: 🟡 100k iters is the floor; 600k bump scheduled for the v2.x cycle; hardware-master mode not yet wired (deferred from v2.0).

#### AV-37: HKDF context confusion (cross-domain key reuse)

**Attack surface**: Same `(IKM, salt)` used to derive keys for different purposes via colliding `info` strings → key reuse across protocol domains. An adversary who compromises one domain's encryption key can decrypt the other domain's ciphertexts if the keys are identical.

Concrete instance: if persist derives an AES-GCM key with `info = b"ciris-secret"` and an HMAC key with `info = b"ciris-secret"` from the same master, both keys are identical bytes. AES key compromise via cryptanalysis (theoretical) → MAC forgery (immediate).

**Primary mitigation**: federation namespacing convention — `info = b"ciris-<purpose>-v<n>"` where `<purpose>` is unique per cryptographic role and `<n>` is the format version. CIRISPersist documents its info strings in `secrets/encryption.py`. The convention is also the migration knob — bumping `<n>` rotates the derived key family without rotating IKM.

**Secondary**: code review at PR time + cargo-deny lints in downstream consumers banning direct HKDF deps (forces routing through `ciris_crypto::kdf::hkdf_sha256` where the convention is documented).

**Status**: 🟡 Open at the library layer (caller-managed); ✓ Policy documented; ⏳ runtime enforcement (info-string registry validator) tracked as future work.

#### AV-38: HMAC key reused as KDF master (cross-protocol attack)

**Attack surface**: A federation primitive uses one root secret as both an HMAC key (for `EncryptedSecretRecord.edge_hmac`) AND as a PBKDF2 master (for software-master per-secret derivation). The two algorithms make different assumptions about key entropy distribution; combining them creates cross-protocol attacks where partial information from one operation leaks into the security of the other.

**Primary mitigation**: federation policy — derived keys per purpose, never reuse roots across MAC + AEAD + KDF. Two-step derivation: root → HKDF-SHA256(root, salt, b"ciris-mac-v1") → MAC key; root → HKDF-SHA256(root, salt, b"ciris-aead-v1") → AEAD key. Documented in v2.0 release notes; downstream cargo-deny configs flag direct RustCrypto MAC/KDF deps that would bypass policy.

**Status**: ⚠ Open at the library layer (caller-managed); ✓ Policy documented + structurally supported via the existing HKDF surface.

#### AV-39: OsRng entropy degradation

**Attack surface**: `getrandom(2)` on Linux blocks until the kernel CSPRNG is seeded; on first-boot containers and embedded devices the seed pool can be shallow for the first few seconds. Pre-seeded `/dev/urandom` is theoretically nondeterministic but in practice replays predictable patterns until kernel collection catches up.

**Primary mitigation**: `ciris_crypto::random` wraps `OsRng`, which on Linux/Android delegates to `getrandom(2)` (blocking until seeded), on macOS/iOS to `SecRandomCopyBytes`, on Windows to `BCryptGenRandom`. The blocking semantics on Linux are the kernel's mitigation — `getrandom(2)` waits for `random.fasync_init` rather than returning entropy-weak bytes.

**Startup health-check + fail-secure (v5.0.0, CIRISVerify#55)**: `ciris_crypto::rng_health` runs NIST SP 800-90B startup tests over a fresh 4096-byte `OsRng` draw at process init — a repetition-count test (§4.4.1; catches a stuck source emitting the same value) and an adaptive-proportion test (§4.4.2; catches a source biased toward one value) — and latches a process-global verdict. On failure, every subsequent `random::fill` returns `CryptoError::RngHealthCheckFailed` **without drawing**, so a degraded source (vTPM PRNG seeding bug at boot, embedded low-entropy boot, Dual_EC-class compromise) fails closed: nonce / key / KEX generation errors and the attestation degrades through existing crypto error paths instead of silently emitting weak material. The FFI runs the check at `ciris_verify_init` (after logging is wired, so the verdict reaches logcat / Console). This closes Fed TM §3.3 Gap H. It is detection + fail-secure, not prevention — it catches the degradation classes an SP 800-90B startup test can catch, not a subtle in-range bias.

**Secondary**: deployment guidance — containers should include an `ExecStartPre` that reads from `/dev/random` (the blocking variant) or uses `--random-source` mounts to inherit host entropy. Embedded targets get hardware-RNG mixing once we have a concrete embedded consumer (none today; CIRIS deployment targets are server / mobile / desktop).

**Status**: ✓ Mitigated for primary deployment targets (server / mobile / desktop on platforms with a maintained kernel CSPRNG); ✓ startup SP 800-90B health-check + fail-secure latch shipped v5.0.0 (Gap H closed); 🟡 future hardening (independent hardware-entropy mixing, FIPS-mode draw path for FedRAMP/CMMC, per-platform CSPRNG-identity attestation) tracked if/when embedded or compliance targets surface.

#### AV-40: Federation-policy violation (bypassing ciris-crypto)

**Attack surface (process-level)**: A consumer reaches into RustCrypto crates directly (`aes-gcm`, `hkdf`, `pbkdf2`, `hmac`, `getrandom`) for primitives that ciris-crypto already provides. This bypasses the federation's audit point — vuln assessment, KAT vector locking, error-variant standardization, and policy convention all happen at the ciris-crypto boundary; direct deps escape.

**Primary mitigation**: documented in v2.0 release notes — CIRISVerify is the federation crypto authority; consumers MUST go through it. `cargo-deny` config in downstream `Cargo.toml` bans the direct deps:

```toml
[bans]
deny = [
    { name = "aes-gcm", wrappers = ["ciris-crypto"] },
    { name = "hkdf",    wrappers = ["ciris-crypto"] },
    { name = "pbkdf2",  wrappers = ["ciris-crypto"] },
    { name = "hmac",    wrappers = ["ciris-crypto"] },
]
```

**Secondary**: PR-time review — federation primitives' Cargo.toml is reviewed for "does this dep belong here." A new direct RustCrypto dep is a red flag.

**Status**: 🟡 Convention; ⏳ CI-side enforcement tracked as future work once we have a federation-wide cargo-deny baseline (today each repo has its own).

#### AV-41: Hardware-bound master derivation gap

**Attack surface**: Mobile keystores (Android, iOS Secure Enclave) DON'T expose native HKDF as a keystore primitive. v2.0 does NOT ship `HardwareSigner::derive_symmetric_key`. Persist consumers running on mobile fall through to software-master mode — the master sits in process memory long enough to feed HKDF, then is zeroed. The window between "master in memory" and "zero" is a residual surface (heap dump, debugger, OOM core dump) that a hardware-bound derivation method would close.

**Primary mitigation (today)**: persist's software-master mode uses ciris-crypto's `kdf::pbkdf2_hmac_sha256` + `kdf::hkdf_sha256` directly with caller-managed master lifecycle. The master is constructed from a hardware-bound seed (signed challenge from `HardwareSigner::sign`) plus a per-process salt; the derived per-secret key never goes back to disk in cleartext.

**Secondary**: v2.x work — `HardwareSigner::derive_symmetric_key` lands when CIRISPersist#19's `secrets-hw` feature is exercised. Honest design: software-only signers implement it via internal HKDF; mobile signers return `Unsupported`; TPM signers implement it via TPM-side HKDF (TPM 2.0 supports `TPM2_KDFa` for some derivation patterns).

**Status**: 🟡 Software-master mode covered; ⏳ hardware-master derivation deferred to v2.x.

---

### 3.9 Federation Transport-Identity Binding — adversary wants to intercept mesh traffic addressed to another federation key

#### AV-42: Spoofed transport-identity ↔ federation-key binding

**Attack**: Mesh transports (Reticulum) address peers by a *transport identity* — `hash(x25519‖ed25519)` — distinct from the federation Ed25519 `key_id` (AV-17 keeps the federation seed out of the transport process). A sender calling `send(key_id=K, …)` must resolve `K` to a transport identity. An unauthenticated mesh *announce* (`key_id → destination`) is trust-on-first-use: any peer can announce `key_id=K` paired with its own destination, and a sender routes K's envelope to the adversary — interception (the envelope is still sender-signed, so the adversary cannot forge a reply K would accept, but it *receives and decrypts* the bytes, and legitimate delivery is denied).

**Primary mitigation (Option C′)**: the binding is carried as a signature-covered field of the `FederationEnvelope` (`src/ciris-verify-core/src/federation_envelope.rs`). `sender_transport_identities` is inside the canonical bytes the hybrid signature covers, so verifying any envelope from K — which a recipient does anyway — yields an authenticated "K is reachable at T". No separate attestation artifact; no `federation_keys` schema migration. `transport_epoch`, a per-`key_id` monotonic counter enforced by `TransportEpochGuard`, blocks replay of a stale (possibly adversary-controlled) binding — anti-rollback, mirroring revocation-revision monotonicity. The `ENVELOPE_DOMAIN_SEP` prefix separates envelope bytes from every other signed primitive, so a transport-identity-shaped field elsewhere (an STH, a build manifest) can never be harvested as an envelope binding (the AV-8 confused-deputy precedent).

**Secondary**: cold first-contact — before any envelope has been received from K — is rooted against the registry/`federation_keys` directory row for `K`, not trust-on-first-use. One-way broadcast classes (STH gossip, audit broadcasts) route only to already-confirmed transport identities.

**Routing-only / provenance bound (finding G)**: the transport binding is **routing information, not provenance**. It lives in envelopes, deliberately *outside* the `federation_keys` recursive-scrub-signing chain. This is acceptable precisely because it confers nothing — see the invariant below. If a transport identity ever gates a security decision (rather than only addressing), it must first be promoted to a signed `federation_keys`-class row inside the provenance chain.

**Anti-Sybil bound (finding J)**: longitudinal / S-factor anti-Sybil weight keys **only** off `key_id`. A federation key may present, rotate, or multi-home across many transport identities over time; that churn is invisible to scoring. Counting transport identities as identities would let an attacker inflate apparent peer count — `key_id` is the identity, the transport identity is plumbing.

**Authentication ≠ trust invariant** (federation-wide, `MISSION.md` §1.4): *every federation primitive authenticates origin; none confers trust.* Verifying a `FederationEnvelope` proves "this came from key K" and nothing more. A never-before-seen `key_id` delivering a valid envelope lands at trust-degree = default-untrusted, zero history. Confirming a transport binding updates the routing table only — it never moves an entity along the trust axis. Trust is a separate, explicit, operator/policy-controlled, default-deny axis (inherited from the CIRISNodeCore trust model).

**Status**: ✓ Mitigated as of v3.0.0. v2.9.0 shipped the substrate (`FederationEnvelope`, `TransportEpochGuard`); v2.14.0 the `federation_keys` provenance verification (WS-4); v3.0.0 the enforcement-capable verify path (`EnvelopeVerifyPolicy::RequireTransportBinding`, #28 Phase 4 verify-side). The consumers shipped — CIRISPersist v1.12.0 (`root_binding` cold-start rooting), CIRISEdge v0.4.0 (authenticated `PeerResolver`). Residual: the advisory→required enforcement *cutover* is a fleet-coordination flip once every repo meets the floor version (#28 Phase 4 "all repos") — the capability is shipped and switchable; only the dated flip remains.

---

### 3.10 Self-at-Login Device Identity — adversary wants to forge, intercept, or refuse-to-revoke a hardware-rooted login identity (v6.0)

v6.0 ships the hardware-rooted self-at-login surface: a YubiKey-PIV (Ed25519) + software ML-DSA-65 user identity (`self_at_login`), a self-signed genesis `KeyRecord` producer (`federation_self_record`), a filesystem CEG-object outbox (`ceg_outbox`) that CIRISServer drains and relays, and a "revoke the lost/stolen device" producer (`sign_occurrence_revocation`). Three new surfaces; the genesis self-record is covered by the existing self-attestation framing (§3.2 AV-8 + the CLAUDE.md fractal-self reading discipline), not a new AV.

#### AV-43: CEG-outbox tampering / spoofed relay

**Attack surface (local file boundary, mostly adversarial)**: producers (the verify CLI, the KMP client) drop signed CEG objects as files under `~/ciris/ceg/outbox/<kind>/<id>.json`; CIRISServer drains, verifies, and relays them. An attacker with write access to the outbox directory could (a) inject a forged object, (b) overwrite a pending object, or (c) attempt a path-traversal `kind`/`id` to escape the outbox.

**Primary mitigation**: the outbox is a **transport, not a trust root** — by design CIRISServer re-verifies the bound hybrid signature on every drained object before it calls the substrate, and CIRISPersist is signature-blind (the #65 two-quorums split: the substrate's merge logic never counts signatures). An injected or overwritten object without a valid bound hybrid signature (Ed25519 + ML-DSA-65) under a directory-pinned `key_id` is rejected at relay — the file drop confers no authority. A self-signed object (a genesis `KeyRecord`) carries its signature inside `body`; a signed-request object carries it in `signatures` (the `x-ciris-*` header mapping).

**Secondary**: `ceg_outbox::sanitize` reduces every `kind`/`id` to a single path segment (anything outside `[A-Za-z0-9._-]` → `_`), so no `..` or separator survives — a traversal `kind`/`id` cannot escape the outbox (proven by `sanitize_blocks_path_traversal_and_separators`). The same sanitizer guards the CLI's ML-DSA seed-file path.

**Residual**: filesystem ACLs on the `ciris/` root are the local boundary — an attacker with the user's own write permission can still *delete* a pending object (a local availability denial, not a forgery). The outbox is explicitly not a confidentiality or integrity trust anchor; CIRISServer's signature re-check is.

#### AV-44: Software PQC-half seed extraction (honest hardware-boundary disclosure)

**Attack surface (at-rest key material)**: the v6.0 "hardware-rooted" federation identity is **hybrid** — the Ed25519 (classical) half is sealed in the YubiKey / Secure Enclave / StrongBox / TPM, and the ML-DSA-65 (PQC) half is a 32-byte seed whose *signing* is software (no token/TPM/SE can perform ML-DSA-65 signing — no PQC HSM exists as of 2026). The threat is extraction of that PQC seed at rest.

Stated honestly rather than overclaimed: "hardware-rooted" means the *classical* owner-binding half cannot be extracted (AV-1 / AV-13 hold for that half). The PQC half's seed is **sealed at rest** via #71 — `identity create` and the FFI route the ML-DSA-65 half through `get_platform_sealed_mldsa65_signer` (`SealedMlDsa65Signer`): the seed is sealed by the platform secure storage — **TPM-sealed when built `--features tpm` on a TPM host, Secure Enclave / StrongBox on mobile, or a software AES-GCM-sealed blob (derived key) as the fallback — never a plaintext file**. It is fail-secure-CSPRNG-generated (AV-39 latch honored) and unsealed only transiently in memory to sign.

**Primary mitigation**: the hybrid bound-signature property means recovering the PQC seed **alone** does not forge an accepted signature — a forger also needs the hardware Ed25519 half, which is non-extractable. So AV-44 in isolation is a *PQC-downgrade* threat (it removes the post-quantum leg for this identity), not an immediate forgery: it reduces this identity's signatures to classical-only strength until the seed is rotated.

**Secondary**: TPM/SE sealing binds the seed blob to the hardware tier (it cannot be unsealed off-box). On a non-TPM, non-`--features tpm` build the seal is a software AES-GCM blob under a derived master key — weaker than hardware, but still not a plaintext seed.

**Residual (open)**: *signing is software* — the seed is unsealed into process memory to produce each ML-DSA-65 signature, so a privileged attacker who can read the live process memory **at signing time** could capture the seed (a much higher bar than reading a file at rest). This is the irreducible boundary until a PQC-capable HSM/token ships; the seed is otherwise hardware-sealed at rest.

#### AV-45: Lost/stolen-device revocation with the compromised key (surviving-key requirement)

**Attack surface (revocation authorization, not propagation)**: when a device (occurrence) is lost or stolen, the owner revokes it via `sign_occurrence_revocation` (CEG §11.7.1 Option-A forward-secrecy removal). The §11.7.4 vouch is single — "the revoking occurrence OR the `identity_key_id`". If the owner's identity has **only one** enrolled key, that key is the stolen one, and there is no *surviving* key to authorize the revocation.

**Primary mitigation**: revocation must be signed by a **surviving** key — a *different* enrolled occurrence or the identity root, never the compromised key. This is the concrete reason the v5.11.0 OR-of-N multi-hardware-key redundancy (`UserIdentityKeyset`) is a **prerequisite**, not a nicety. The bound hybrid revocation signature verifies at threshold 1 against the *revoker's* directory-pinned pubkeys (the `threshold` primitive), so Registry/Server authenticate that the revocation came from a surviving key before writing the row through to Persist (whose merge logic never counts signatures, §5.6.8.13). The producer permits `revoker == revoked` for a *voluntary* leave, but the stolen-device flow MUST use a different key (proven by `revocation_does_not_bind_to_a_forged_revoker_key_id`).

**Secondary**: once authorized, the revocation propagates under the R1 timeliness contract and "most recent observed revocation wins" merge (the AV-4 anti-rollback discipline). AV-45 is the *authorization* half; R1 (FEDERATION_THREAT_MODEL §3.3 Gap A) is the *propagation* half.

**Residual**: an owner who enrolled exactly one key and lost it has no surviving key to revoke with and must fall back to the steward / out-of-band recovery path — the correct security tradeoff (a single-key identity cannot self-heal), and the standing argument for enrolling ≥2 hardware keys at onboarding.

---

## 4. Mitigation Matrix

| AV | Attack | Primary Mitigation | Secondary | Status | Fix Tracker |
|---|---|---|---|---|---|
| AV-1 | Code fork / license-check removal | Hardware-bound signing key | Binary integrity check | ✓ Mitigated | — |
| AV-2 | Runtime modification | Binary self-integrity + anti-debug | Platform integrity checks | ✓ Mitigated | — |
| AV-3 | Endpoint spoofing | HTTPS authoritative + 2-of-3 consensus | Certificate pinning | ✓ Mitigated | Fix 4 |
| AV-4 | License replay after revocation | Anti-rollback monotonic revision | Challenge nonce + expiry | ✓ Mitigated | Fix 2 |
| AV-5 | MITM attestation | Hybrid Ed25519 + ML-DSA-65 (bound) | Remote attestation proof export | ✓ Mitigated | Fix 3 |
| AV-6 | Emulator/debugger interception | Platform integrity checks | Timing anomaly detection | ✓ Mitigated | — |
| AV-7 | Ephemeral identity storage (lens-scrub class) | `HardwareSigner::storage_descriptor()` v1.7+ + boot-time logging | `--strict-storage` consumer flag, ephemeral-path heuristics | ✓ **Mitigated v1.7.0** | — |
| AV-8 | Cross-primitive identity confusion | Primitive discriminant inside hybrid-sig canonical bytes; per-primitive trusted-pubkey lookup | Registry-mediated trust via `RegisterTrustedPrimitiveKey` | ✓ Mitigated v1.8.0 (verify-side); ⚠ trusted-key bootstrap pending registry support | CIRISRegistry#5 |
| AV-9 | BuildManifest write-without-read (Phase A) | GitHub release artifact `signed-build-manifests.tar.gz` preserves CI signature end-to-end | Symmetric `GET /v1/verify/build-manifest/...` (planned) | 🟡 Mitigated via Path C (release); ⚠ Path B (registry GET) pending | CIRISRegistry#5 item 2 |
| AV-10 | Stale hardware-marker lockup | v1.6.3 detects + clears stale markers; `HardwareNotAvailable` error surfaces recovery path | Operator-runbook for marker file deletion | ✓ Mitigated v1.6.3-v1.6.4 | — |
| AV-11 | Sigstore OIDC token theft | OIDC identity binding via `${workflow}@${ref}`; release notes include expected signer | Hybrid BuildManifest signature is independent of Sigstore — second trust path | 🟡 Partial — no continuous Rekor-monitor on CIRIS identity | §10 SOTA gap #2 |
| AV-12 | Maintainer compromise / XZ-style | AGPL-3.0 source review; `cargo-audit` + `cargo-deny`; hybrid sig | None against this attack — compromised maintainer signs both classical + PQC | ⚠ **Open** — no two-person-rule, no SBOM, no reproducible builds | §10 SOTA gap #3-#5 |
| AV-13 | TEE.fail / DDR5 bus interposition | Threat assumption §6.4 (no physical access); SoC vuln detection v1.2.0+ caps to SOFTWARE_ONLY | Defense-in-depth: HSM-anchored steward keys (FIPS 140-3 L3+) for production roles | 🟡 Mobile/SoC covered; server-class TEE attacks NOT modeled | §10 SOTA gap #7 |
| AV-14 | Cross-instance keyring contention (multi-instance cohabitation) | Persist-as-interface: one verify instance per process by construction in persist-bearing stacks; OS-daemon serialization on read path universally | Documentation contract (HOW_IT_WORKS.md "When Persist Is the Interface"); same-alias = same identity by PoB §3.2 | ✓ Surface vanishes in dominant production pattern (persist-bearing); 🟡 multi-process verify-only stacks need operator-bootstrap or v1.9 flock guards (uncommon pattern) | v1.9 (verify-side `flock` for persist-less stacks) |
| AV-35 | AES-GCM nonce reuse with same key | Caller-managed nonce policy (random 96-bit via `random::fill` OR strict per-key counter); doc'd in `aes_gcm.rs` module | Federation incident channel — observed reuse triggers key rotation | ⚠ Open at library layer (caller-managed); ✓ Policy doc'd in v2.0 | §3.8 AV-35 |
| AV-36 | PBKDF2 iteration count too low | Spec'd minimum 100k iters in CIRISPersist#19 (matches CIRISAgent's existing config); `iters=0` rejected as `KdfParameter` | Hardware-master mode (when shipped) skips PBKDF2 entirely | 🟡 100k is current floor; 600k bump scheduled v2.x | OWASP 2026 |
| AV-37 | HKDF context confusion (cross-domain key reuse) | Federation namespacing convention `info = b"ciris-<purpose>-v<n>"`; doc'd in v2.0 release notes; CIRISPersist documents per-purpose info strings | cargo-deny lints in downstream consumers banning direct hkdf deps | 🟡 Open at library layer (caller-managed); ⏳ runtime info-string registry validator | future |
| AV-38 | HMAC key reused as KDF master (cross-protocol) | Federation policy: derived keys per purpose via HKDF — `root → hkdf(.., b"ciris-mac-v1")`, `root → hkdf(.., b"ciris-aead-v1")` | Documented in v2.0 release notes + cargo-deny direct-hmac/kdf bans | ⚠ Open at library layer (caller-managed); ✓ Policy doc'd | §3.8 AV-38 |
| AV-39 | OsRng entropy degradation | `ciris_crypto::random` wraps `OsRng` (Linux `getrandom(2)` blocks until seeded; macOS `SecRandomCopyBytes`; Windows `BCryptGenRandom`) | Container/embedded deployment guidance — `ExecStartPre` entropy seed; future hardware-entropy mixing | ✓ Server/mobile/desktop covered; 🟡 future FIPS-mode + embedded hardening | v2.x |
| AV-40 | Federation-policy violation (bypassing ciris-crypto direct RustCrypto deps) | v2.0 release notes documenting "ciris-crypto is THE crypto authority"; cargo-deny `[bans]` config in downstream consumers banning `aes-gcm`/`hkdf`/`pbkdf2`/`hmac` direct deps | PR-time review; new direct RustCrypto dep is a red flag | 🟡 Convention; ⏳ federation-wide cargo-deny baseline | future |
| AV-41 | Hardware-bound master derivation gap | Software-master mode uses ciris-crypto KDF directly with caller-managed master lifecycle; master is zeroed after derivation | `HardwareSigner::derive_symmetric_key` lands when CIRISPersist#19's `secrets-hw` is exercised | 🟡 Software-master covered; ⏳ hardware-master deferred to v2.x | CIRISPersist#19 |
| AV-42 | Spoofed transport-identity ↔ federation-key binding | Binding carried as a signature-covered field of the `FederationEnvelope` (Option C′, §3.9); `transport_epoch` anti-rollback via `TransportEpochGuard`; `domain_sep` separation; `federation_keys` provenance verification (`verify_provenance_chain`); enforcement-capable verify path | Cold first-contact rooted against the directory row (CIRISPersist `root_binding`), not TOFU; authenticated `PeerResolver` (CIRISEdge v0.4.0) | ✓ Mitigated v3.0.0 — residual: the fleet enforcement-cutover flip | CIRISVerify#27, #28, #29 |
| AV-43 | CEG-outbox tampering / spoofed relay | Outbox is transport, not trust root — CIRISServer re-verifies the bound hybrid signature on every drained object before calling the substrate; Persist signature-blind (#65) | `ceg_outbox::sanitize` reduces `kind`/`id` to a single path segment (no `..`/separator survives) | ✓ Mitigated v6.0 (forgery); 🟡 local file-ACL is the confidentiality/availability boundary | CIRISVerify#63 |
| AV-44 | PQC-half seed extraction (honest HW-boundary disclosure) | Hybrid bound-signature: the ML-DSA-65 seed alone cannot forge an accepted signature — the hardware Ed25519 half is non-extractable; seed sealed at rest via #71 `get_platform_sealed_mldsa65_signer` (TPM `--features tpm` / SE / StrongBox; software AES-GCM-sealed fallback — never plaintext); CSPRNG-generated (AV-39 latch) | TPM/SE seal binds the seed to the hardware tier | ✓ Sealed-at-rest v6.0 (wired through #71); residual: signing is software (seed in memory at sign time) — no PQC HSM exists | CIRISVerify#71 |
| AV-45 | Lost/stolen-device revocation with the compromised key | Revocation MUST be signed by a **surviving** key (different occurrence or identity root); OR-of-N keyset redundancy is the prerequisite; threshold-1 bound-hybrid verify against the revoker's pinned pubkeys | R1 propagation + "most recent revocation wins" merge (AV-4 anti-rollback) | ✓ Mitigated v6.0 (authorization); residual: single-key identities have no surviving revoker → steward fallback | CIRISVerify#63, #79 |
| Audit | Audit trail tampering | Transparency log with Merkle tree | Append-only persistent storage | ✓ Mitigated | Fix 1 |

**Status legend:** ✓ Mitigated • 🟡 Partial mitigation, residual tracked • ⚠ Open / planned

---

## 5. Security Levels by Hardware Type

| Hardware Type | Security Level | Max License Tier | Attestation Quality | Key Protection |
|---------------|---------------|------------------|--------------------| --------------|
| Android StrongBox | 5 (Dedicated SE) | Professional | Strong (Google hardware attestation) | Hardware-isolated |
| iOS Secure Enclave | 5 (Dedicated SE) | Professional | Strong (Apple App Attest) | Hardware-isolated |
| TPM 2.0 (Discrete) | 5 (Dedicated chip) | Professional | Strong (EK certificate) | Hardware-isolated |
| TPM 2.0 (Firmware) | 4 (fTPM) | Professional | Moderate (no discrete hardware) | Firmware-isolated |
| Intel SGX | 4 (Enclave) | Professional | Moderate (remote attestation) | Enclave-isolated |
| Android Keystore (TEE) | 3 (TEE-backed) | Professional | Moderate (key attestation chain) | TEE-isolated |
| YubiKey PIV / PKCS#11 (external token) | 5 (Dedicated SE) | Professional | Moderate today — PIV attestation cert (slot f9) not yet read, so reported at the honest external-token tier, NOT software | Hardware-isolated (private key never leaves the token; touch-required presence) |
| Software-Only | 1 (No hardware) | Community ONLY | None (key extractable) | None |

**Critical invariant**: `SOFTWARE_ONLY` devices are permanently capped at `UNLICENSED_COMMUNITY` tier. No license upgrade path exists without hardware security.

**YubiKey PIV note (v6.0)**: the canonical hardware backend for the hardware-rooted federation identity is a YubiKey in PIV mode signing **Ed25519** via `CKM_EDDSA` (`ciris_keyring::pkcs11`) — byte-identical to the software Ed25519 signer, so a token-signed binding verifies through the same threshold primitive. **Firmware ≥ 5.7 is required for PIV Ed25519**; older firmware offers only P-256 PIV (also supported, but Ed25519 is the federation default). The PIV signing slot SHOULD be **touch-required** so each federation signature is a physical-presence ceremony. The token's own PIV attestation cert (slot f9) is **not yet read** — until it is, the signer reports `PlatformAttestation::Software` (the honest external-token tier), so the hardware binding is *custody-real but attestation-unproven* to a remote verifier. This is orthogonal to AV-44: the token holds the Ed25519 half; the ML-DSA-65 PQC half is the #71 sealed-at-rest seed (TPM/SE/StrongBox, software-sealed fallback).

---

## 5.1 Known Hardware Vulnerabilities (v1.2.0+)

CIRISVerify detects known hardware vulnerabilities that compromise TEE security. Devices with these vulnerabilities are treated equivalently to emulators—attestation is capped at `SOFTWARE_ONLY` level.

### CVE-2026-20435: MediaTek Boot ROM EMFI Vulnerability

| Property | Value |
|----------|-------|
| Severity | CRITICAL |
| Affected | MediaTek Dimensity 7300, 7200, 1200, 8100, 9000, 9200 (mt6878, mt6886, mt6893, mt6895, mt6983, mt6985) |
| TEE | Trustonic |
| Impact | Physical access can extract Android Keystore keys in <45 seconds |
| Patchable | NO (Boot ROM is burned into silicon) |
| Disclosed | March 12, 2026 by Ledger Donjon |

**Technical Details**: The MediaTek boot ROM contains a flaw in how it handles electromagnetic fault injection (EMFI) during the secure boot process. An attacker with physical access can glitch the chip during TEE initialization to dump the Trustonic TEE's secure world memory, including Android Keystore keys.

**Detection**: CIRISVerify identifies vulnerable chipsets via `Build.HARDWARE` and `Build.BOARD` system properties on Android.

**Mitigation**: Devices with affected chipsets have `hardware_trust_degraded = true` and `HardwareLimitation::VulnerableSoC` in their limitations. Professional license tiers are not available on these devices.

**`boundary_degraded` vs `hardware_trust_degraded` — two orthogonal signals (v5.0.0, CIRISVerify#60)**: a CVE-degraded device like the above is the **forced/involuntary** case — hardware was expected and is compromised → `hardware_trust_degraded = true`. This is distinct from the **software-baseline** case — no secure element is present at all (community / pure-software mode) → `boundary_degraded = true`. The two never both apply to one condition:

| Condition | `boundary_degraded` | `hardware_trust_degraded` |
|---|---|---|
| Hardware present + trusted | false | false |
| Hardware present, CVE/rooted/emulator forced down | **false** | **true** |
| No secure element at all (software-only) | **true** | false |

`boundary_degraded = (detected hardware_type == SoftwareOnly)` is **authored by Verify** on the attestation result, not derived by the consumer from `!hardware_backed` (a lossy proxy that conflates the two cases). Only Verify knows hardware-absent vs hardware-present-but-failed. Consumers surface both fields; they do not compute them. Informational severity (the forced case carries the warning/critical weight via `hardware_trust_degraded`).

### CVE-2026-21385: Qualcomm Security Component Vulnerability

| Property | Value |
|----------|-------|
| Severity | HIGH |
| Status | Under limited, targeted exploitation (CISA KEV catalog) |
| Patchable | YES (March 2026 Android Security Patch) |

**Mitigation**: Devices running Qualcomm chipsets should apply the March 2026 security patch. CIRISVerify tracks `Build.VERSION.SECURITY_PATCH` and can warn about outdated patch levels.

### Other Hardware Limitations

| Limitation | Impact | Caps Attestation? |
|------------|--------|-------------------|
| Emulator detected | No real hardware security | YES |
| Rooted/jailbroken device | HSM protections bypassed | YES |
| Unlocked bootloader | Secure boot chain compromised | YES |
| Outdated security patch | Known vulnerabilities unpatched | NO (warning only) |
| Weak TEE implementation | TEE-specific issues | YES |

---

## 6. Security Assumptions

From FSD-001, the system depends on these assumptions:

1. **HSM integrity**: Hardware security modules (TPM 2.0, Secure Enclave, Android Keystore/StrongBox) are not compromised at the hardware level
2. **DNS diversity**: Multiple DNS registrars are not simultaneously compromised (US and EU registrars are different providers)
3. **TLS infrastructure**: HTTPS certificate infrastructure (Certificate Authorities) is not compromised
4. **Physical security**: Adversary does not have physical access to the deployment hardware (physical access can bypass most HSM protections)
5. **Clock accuracy**: System clocks are reasonably synchronized (within 5 minutes of actual UTC time)
6. **Network path**: Network path to at least one verification source is not fully compromised (offline mode provides 72-hour grace period)

---

## 7. Fail-Secure Degradation

All failures degrade to MORE restrictive modes, never less:

| Failure Condition | Resulting Mode | Rationale |
|-------------------|---------------|-----------|
| Binary integrity check failed | LOCKDOWN | Possible active tampering |
| Sources actively disagree | RESTRICTED | Possible attack on verification |
| Rollback detected | RESTRICTED | Possible replay attack |
| No sources reachable | COMMUNITY (with 72h grace) | Cannot verify current status |
| License expired | COMMUNITY | License no longer valid |
| License revoked | COMMUNITY | License explicitly revoked |
| Signature verification failed | COMMUNITY | Cannot verify authenticity |
| Hardware attestation failed | COMMUNITY | Cannot verify hardware binding |

---

## 8. Cross-Cutting Residual Risks

Per-AV residuals are documented in-place under each attack vector in §3. This section catalogues residuals that aren't tied to a single AV but cross multiple surfaces, plus the index of where in-place residuals live.

### 8.1 In-place residual index

| AV | Surface | Residual summary |
|---|---|---|
| AV-1 | License Fraud | SOFTWARE_ONLY tier cap is the floor — local fakes can't claim Professional through downstream verifiers |
| AV-2 | License Fraud | Memory-patched binary on rooted device fakes UX locally but cannot forge downstream signatures |
| AV-3 | License Fraud | Simultaneous compromise of all 3 sources (US registrar + EU registrar + HTTPS CA) is the bypass |
| AV-4 | License Fraud | Replay within expiry window is design-allowed; cross-revocation replay blocked by anti-rollback |
| AV-5 | License Fraud | Requires breaking Ed25519 AND ML-DSA-65 simultaneously |
| AV-6 | License Fraud | Hypervisor-level intercepts that hide from in-VM checks; defense-in-depth via downstream sig verify |
| AV-7 | Federation Identity | Operator override (`CIRIS_PERSIST_KEYRING_PATH_OK=1`); consumer ignoring the descriptor |
| AV-8 | Federation Identity | Trusted-pubkey lookup for non-`Verify` primitives needs `RegisterTrustedPrimitiveKey` propagation; brief inconsistency window |
| AV-9 | Build Provenance | Per-primitive steward attribution available through Path C (release tarball) until Phase B GET ships |
| AV-10 | Operational | Identity continuity loss after hardware-key recovery; correct security tradeoff |
| AV-11 | Supply Chain | No continuous Rekor-monitor on CIRIS identity (action: §10 gap #2) |
| AV-12 | Supply Chain | No two-person-rule, SBOM, reproducible builds (actions: §10 gaps #3, #4, #5) |
| AV-13 | Hardware | Server-class TEE attacks (TEE.fail) not modeled; HSM-anchored steward keys for prod |
| AV-14 | Operational | Surface vanishes by construction in persist-bearing stacks (persist holds the one verify Engine); uncommon multi-process verify-only pattern needs operator pre-bootstrap or v1.9 flock guards |

### 8.2 Cross-cutting residuals

These don't belong to a single AV because the failure mode crosses surfaces:

1. **Hardware supply chain compromise**: If HSM manufacturers are compromised, attestation data can be forged across all hardware-anchored AVs (1, 5, 13). Mitigation: use hardware from multiple manufacturers; monitor for HSM vulnerability disclosures; defense-in-depth via per-primitive steward separation.

2. **Zero-day in HSM firmware**: Undisclosed vulnerabilities in TPM/SE firmware could allow key extraction. Cross-cuts AV-1, AV-2, AV-13. Mitigation: hybrid crypto means both classical AND PQC must be broken; firmware update monitoring. CIRISVerify v1.2.0+ actively detects known vulnerabilities (e.g., CVE-2026-20435 on MediaTek) and degrades affected devices to `SOFTWARE_ONLY` level.

3. **Clock manipulation**: If system clock is skewed by more than 5 minutes, expiry-based protections (AV-4) and timestamp-based replay defenses weaken. Mitigation: multi-source timestamp cross-checking; NTP hardening guidance for deployments.

4. **All verification sources compromised simultaneously** (AV-3 worst case): if attacker controls all DNS registrars AND HTTPS endpoints, false consensus can be achieved. Mitigation: sources are in different jurisdictions (US/EU) with different registrars; transparency log provides after-the-fact audit capability.

5. **Quantum computer capable of breaking both Ed25519 and ML-DSA-65** (AV-5 + AV-9 + AV-12 worst case): current quantum computers cannot break either. Hybrid approach means BOTH must fall. ML-DSA-65 provides NIST-standardized post-quantum resistance. Mitigation: algorithm agility allows future upgrades — see §10 gap #6 for the formal migration plan.

6. **Insider threat at license issuing authority**: a compromised steward could issue valid licenses to malicious agents. Cross-cuts AV-1, AV-12. Mitigation: transparency log records all issuance events for audit; multi-party authorization for license issuance (registry-side control). Federation-side defense: per-primitive steward separation means a compromised license-issuance steward cannot forge BuildManifest signatures for other primitives.

---

## 9. Federation-Level Security (post-v1.8)

The v1.8 build-manifest substrate (`BuildPrimitive`, `verify_build_manifest`, the `ciris-build-sign` / `ciris-build-verify` CLIs) introduces federation-scale threat surfaces that single-primitive thinking doesn't cover.

### 9.1 Trust topology

| Trust anchor | Held by | Used for |
|---|---|---|
| Registry's steward pubkey | All consumers (pinned at compile time / fetched from `/v1/steward-key`) | Verifying registry-served `FunctionManifest` (Path A reads); future trusted-primitive-key lookups |
| Per-primitive steward pubkey (`verify-steward-2026`, `persist-steward-2026`, etc.) | Each primitive's own publishing CI; registered with registry via `RegisterTrustedPrimitiveKey` | Signing the primitive's own `BuildManifest`; verifying that primitive's manifest in Path B/C |
| Embedded `Verify` steward pubkey | CIRISVerify binary (compile-time constant) | Self-check: validating CIRISVerify's own runtime against its signed manifest (recursive golden rule) |

### 9.2 Trust rotation requirements

Steward keys rotate. The threat model requires:

- **Per-primitive rotation:** old key revocation visible to all consumers within bounded propagation time (target: 24h via cross-region replication per CIRISRegistry#4). Old manifests signed under retired keys remain verifiable via the transparency log; new manifests reject old signatures.
- **Registry steward rotation:** registry signs its own steward-key transitions under the OUTGOING key, so consumers with the old pinned key can verify the new key is legitimate. No rotation should require recompiling consumers.
- **Algorithm rotation (PQC migration):** when ML-DSA-65 successor is needed, hybrid-sig schema admits a third algorithm slot. Old `(Ed25519, ML-DSA-65)` signatures continue to verify; new signatures are `(Ed25519, ML-DSA-65, NEW)` until ML-DSA-65 is fully retired.

The third item is currently **unspecified** — see §10.

### 9.3 Open federation issues

- **AV-9 Phase A artifact** — registry-mediated read path doesn't preserve per-primitive steward attribution. Tracked at CIRISRegistry#5 item 2. Workaround: GitHub release tarball.
- **AV-8 trust-key bootstrap** — non-`Verify` primitives need their pubkeys registered with registry before their manifest POSTs land. Tracked at CIRISRegistry#5 item 3.
- **Confused deputy across primitives** — verify-side defenses are robust (primitive in canonical bytes, separate trusted-pubkey per primitive); registry-side enforcement of "manifest signature must match primitive" is part of the same registration story.

---

## 10. SOTA Gaps and Roadmap

A SOTA review (mid-2026) against current best-practice in software-supply-chain attestation surfaced gaps below. None are exploitable today against CIRISVerify's documented adversary model, but each closes residual risk that the wider industry is moving on.

### Gap 1: SLSA level not declared

**SOTA**: SLSA v1.2 with L3 (hardened build platform, unforgeable provenance signed by the platform) as the credible bar for federation peers; L4 (reproducible builds) increasingly the gating definition.

**CIRISVerify position**: Effective ~SLSA L2 today (signed provenance via Sigstore + GitHub Actions OIDC, build platform is GitHub-hosted runner). L3 requires us to claim the build platform's hardening explicitly and publish provenance attestations (in-toto). L4 requires reproducible builds, which Cargo's release profile (`lto=true`, `codegen-units=1`, `panic="abort"`, `strip=true`) approximates but doesn't guarantee bit-for-bit.

**Action**: declare SLSA L3 target in `docs/IMPLEMENTATION_ROADMAP.md`; publish in-toto attestations alongside release artifacts; reproducible-builds work as separate v2.0 milestone.

### Gap 2: No continuous Rekor identity monitoring

**SOTA**: `rekor-monitor` watches for unexpected signing events under a configured OIDC identity. Canonical post-XZ defense for Sigstore-era supply chain.

**CIRISVerify position**: We sign with Sigstore, log to Rekor, but don't monitor the log for rogue entries under our identity. A stolen OIDC token would produce a correctly-Rekor-logged malicious binary that consumers' verify checks pass.

**Action**: integrate `rekor-monitor` against `https://github.com/CIRISAI/CIRISVerify/...` identity, alarm to maintainers on unexpected entries. Tracked as separate ops item.

### Gap 3: No SBOM in releases

**SOTA**: SPDX 3.0 + CycloneDX 1.6 dual format; CISA minimum elements (component hash, license fields); EU CRA mandate by Dec 2027.

**CIRISVerify position**: No SBOM published. Downstream operators have no machine-readable enumeration of our transitive Rust dependencies — exactly the attack surface a `cargo`-based XZ-equivalent would exploit.

**Action**: `cargo-cyclonedx` integration in release workflow; publish both SPDX + CycloneDX as attached attestations; document in release notes how to verify SBOM signature against steward key.

### Gap 4: No reproducible builds

**SOTA**: Reproducible-builds.org standards; bit-for-bit reproducibility as the only systemic defense against source-vs-binary divergence (XZ-class attacks).

**CIRISVerify position**: Release builds from GitHub-hosted runners with deterministic-ish flags but not verified bit-for-bit. A maintainer with CI access could release a binary that doesn't match the source.

**Action**: not v1.x scope. Targeting reproducibility for v2.0 is the right framing — requires Cargo build-info determinism work + cross-rebuilder verification (e.g., a separate trusted-rebuilder running on independent infrastructure).

### Gap 5: No two-person-rule on releases

**SOTA**: Multi-maintainer signoff for critical projects (OpenSSF Critical Project framework). XZ-3094 demonstrated single-maintainer trust is insufficient.

**CIRISVerify position**: Single-maintainer release path. A compromised maintainer or stolen GitHub token can publish a release that passes all automated checks.

**Action**: GitHub branch protection requiring 2+ approvers on release-tag-creating PRs; key-ceremony procedure for steward-key rotation requiring two operators. Documented in release runbook.

### Gap 6: PQC algorithm-agility plan — ✓ CLOSED (v2.11.0, CIRISVerify#29 WS-5)

**SOTA**: NIST IR 8547 deprecation timeline (quantum-vulnerable algos by 2035); algorithm-agility patterns mandate config-not-code rotation.

**Resolution**: the v2.0 hybrid schema was already algorithm-agile — every signature is self-describing (`crypto_kind` + tagged `ClassicalAlgorithm` + tagged `PqcAlgorithm` + `SignatureMode`), and `PqcAlgorithm` already enumerates ML-DSA-44/65/87 **and SLH-DSA-128s/256s** (FIPS 205 hash-based fallback already nameable). A successor algorithm is an enum variant plus a policy decision, never a wire-format break. v2.11.0 adds the single agility gate, `HybridSignature::meets_federation_policy()`, and `docs/CRYPTO_AGILITY.md` specifies the A/B/C migration protocol (additive accept → emit → retire, with transparency-log history staying verifiable under retired algorithms). Config-not-code rotation: a transition tightens one method, touching no signed structure.

### Gap 7: Server-class TEE attacks not modeled

**SOTA**: TEE.fail (Oct 2025, Georgia Tech / Purdue, sub-$1k) breaks Intel SGX/TDX and AMD SEV-SNP via DDR5 bus interposition. PSA Level-3 RoT IP with SCA + fault-injection resistance is the new bar.

**CIRISVerify position**: Mobile/SoC vulnerability detection (v1.2.0+) caps attestation to SOFTWARE_ONLY for known-bad chips. Server-class TEEs (used by registry-side, by federation peers running confidential VMs) are NOT modeled. A TEE.fail-equivalent against a registry validator could extract steward signing keys.

**Action**: registry-side roadmap item (CIRISRegistry threat model); CIRISVerify's recommendation is HSM-anchored signing keys for production registry/steward roles, not TEE-anchored. Document this explicitly in registry deployment guidance.

---

### Peer comparison (2026-mid SOTA review for v2.0)

The v2.0 cycle promotes ciris-crypto to "federation crypto authority," which makes the question "where do we sit relative to peers in the same shape?" load-bearing. Peers are not direct competitors — most occupy adjacent niches — but each illustrates an axis of the design space we should know our position on.

| Peer | Niche | What we cover that they don't | What they cover that we don't | Our position |
|------|-------|-------------------------------|-------------------------------|--------------|
| **Sigstore + Cosign + Rekor** | Software-supply-chain signed-build attestation via OIDC + transparency log | Hybrid PQC signing, hardware-bound runtime identity, runtime tree-walk verification, license tier enforcement, hardware vuln detection | Continuous Rekor monitoring (Gap 2), keyless OIDC ephemeral signing, federated transparency log peers | Adjacent — we already use Sigstore for the build attestation layer; Rekor monitoring is the residual we know we need to close. |
| **TUF (The Update Framework)** | Hierarchical metadata signing for software updates with role separation (root/targets/snapshot/timestamp) | Hardware-rooted device identity, runtime integrity verification, federation policy enforcement, hybrid-PQC signing | Multi-role signing with key-rotation safety, threshold signatures within roles, freeze-before-publish ordering | Adjacent — TUF's role separation is a model we could borrow if the steward-key model migrates to multi-operator. Today we're a single-role signer. |
| **in-toto + SLSA** | Supply-chain provenance attestation framework | Hybrid-PQC signed provenance, runtime integrity, hardware-rooted identity, license tier integration | Reproducible builds (Gap 4), formal SLSA L3+ attestation (Gap 1), step-by-step build-graph attestation | Adjacent — we partially implement (SLSA L2 effective); SLSA L3 + reproducibility is the v2.0 promise we still owe. |
| **Keylime** | Linux/TPM remote attestation runtime with continuous-attestation policy engine | Mobile attestation (Android Keystore, iOS Secure Enclave), hybrid-PQC signing, license tier integration, runtime tree verifier | IMA boot-time integrity policy, continuous-attestation event stream, OpenStack/Kubernetes integration | Cousin — Keylime is the closest analog for runtime integrity on Linux/TPM. We're broader (mobile) but they're deeper on Linux server-class. |
| **Veilid** | Mesh-network identity + crypto authority + DHT addressing | License tier enforcement, build-manifest provenance, runtime tree-walk verification, hybrid-PQC | DHT-based naming, Veilid-protocol-specific transports, BLAKE3-based identity | Upstream — `keyring-manager` pattern explicitly extends Veilid (see CLAUDE.md). Not competitors; we adopt their patterns where they fit. |
| **Reticulum** | Mesh-transport with native link encryption + identity (X25519 + Ed25519 + AES-256-CBC) | Application-substrate primitives, build attestation, federation policy | Link-layer encryption, mesh routing, addressing-IS-identity at the transport layer | Substrate / transport split — CIRISEdge integrates Reticulum-rs for transport (per `CIRISEdge/FSD/CIRIS_EDGE.md` §AV-15: "edge does not add a third encryption layer"); we're substrate, they're transport. No overlap. |
| **Signal Protocol / libsignal** | E2E messaging with forward secrecy + post-compromise security via Double Ratchet | Federation substrate primitives, hardware identity, build attestation, license tier enforcement | Forward-secret session establishment, Double Ratchet for post-compromise security, X3DH key agreement | Different threat model — Signal is 1:1 + groups with PFS/PCS as the headline; we're substrate-attestation with hybrid signing as the headline. X25519 KEX investigated for v2.0; dropped per edge's transport-encryption delegation. |
| **Matrix Olm/Megolm** | Federation E2E messaging + key transparency | Federation substrate, hardware-bound identity, build attestation | Key-transparency log (different model than build-manifest log), cross-signing for device ownership | Different model — Matrix's KT proves "this device belongs to this user"; ours proves "this binary was signed by this build authority." |
| **FIDO2 / WebAuthn** | Hardware-bound user authentication with attestation | Federation substrate, hybrid-PQC, build attestation, runtime integrity | Browser/WebAuthn integration, Resident Keys, Discoverable Credentials, attestation chain to known root CAs | Adjacent — same hardware identity primitive at a different layer. WebAuthn is user → service; we're agent → federation. Same TPM/SE/StrongBox underneath. |

### What this comparison says about our position

- **Build attestation tier**: we're broadly comparable to Sigstore/in-toto/SLSA but lag on continuous monitoring (Gap 2) and reproducibility (Gap 4). Both are explicit v2.x roadmap items.
- **Runtime integrity tier**: comparable to Keylime on Linux + broader by covering mobile. No peer covers desktop/server/mobile in one substrate the way verify_tree does.
- **Federation crypto authority tier (new in v2.0)**: no direct peer with the same "single audit point for federation primitives" framing. Closest analog is Veilid's `keyring-manager` (which we extend) — but Veilid is a mesh substrate, not a federation crypto authority.
- **Identity tier**: TPM/SE/StrongBox bindings are commodity (FIDO2/Veilid/Keylime/etc all use the same hardware roots); our differentiator is the hybrid-PQC binding on top.
- **Transport tier**: explicitly out of scope — delegated to CIRISEdge + Reticulum-rs. We don't compete with Signal/Matrix/Reticulum on the wire.

The federation crypto authority framing is the v2.0 differentiator. No peer is doing exactly this combination — most do one or two of the tiers; none do all five (build + runtime + identity + symmetric authority + license enforcement) in one substrate.

---

## 11. Federation Role Coverage (v3.6)

The federation expects CIRISVerify to be the **substrate-level crypto authority** — every primitive that needs cryptographic operations routes through this crate. Self-assessment of coverage as of v3.6.0:

### 11.1 Covered

- ✅ **Hybrid signing** (Ed25519 + ML-DSA-65 with bound classical-inside-PQC signatures) — `HybridSigner`/`HybridVerifier` stable since v1.x; PQC binding tested against signature-stripping attacks.
- ✅ **Hardware-bound identity** (TPM 2.0 with EK certificate + dual-key architecture, Android Keystore / StrongBox, iOS Secure Enclave / Apple T2, software fallback) — `HardwareSigner` trait, `StorageDescriptor` for transparency about identity material location.
- ✅ **Build attestation** (BuildManifest validator, function-level integrity, file-tree integrity, multi-target sign + register) — registry round-trip locked by post-release-verify CI; Sigstore + GitHub Actions OIDC for CI signing. v3.4.0 added `BuildManifest::to_attestation_entries` emitting the `provenance:build_manifest:{target}` dimension on successful verify.
- ✅ **Runtime integrity** (`verify_tree`, Algorithm A canonical algorithm shared with `ciris-build-sign sign --tree`, missing/extra/mismatch verdict semantics post-v1.14.0) — Python FFI exposed; live-registry CI gate.
- ✅ **License tier enforcement + mandatory disclosure** — `LicenseEngine`, fail-secure degradation (LOCKDOWN / RESTRICTED / COMMUNITY), capability gating against `PROHIBITED_CAPABILITIES`.
- ✅ **Federation symmetric authority (v2.0)** — AES-256-GCM, PBKDF2, HKDF, HMAC-SHA256, OsRng — single audit point. NIST GCM + RFC 5869 + RFC 4231 vectors locked.
- ✅ **Wallet signing** (secp256k1 EVM, EIP-155, EIP-712, address recovery) — for federation primitives that interact with on-chain attestations.
- ✅ **Hardware vulnerability detection** (CVE-2026-20435 MediaTek, CVE-2026-21385 Qualcomm) — caps attestation to SOFTWARE_ONLY for known-bad chips.
- ✅ **Authenticated transport-identity binding (AV-42)** — v2.9.0 `FederationEnvelope` substrate + v2.14.0 `federation_keys` provenance verifier + v3.0.0 `EnvelopeVerifyPolicy::RequireTransportBinding` enforcement-capable path + v2.10.0 deterministic `derive_transport_identity`. Advisory by default; fleet enforcement cutover is a coordination flip (#28).
- ✅ **M-of-N threshold-signature verifier (v3.1.0)** — `verify_threshold_signatures` over hybrid signatures. Powers federation-keyset bootstrap rotation (#31 Part A) and constitutional emergency shutdown (#32 Ask 3). Mitigates single-steward compromise as a federation-wide primitive.
- ✅ **Scalar-attestation surface (v3.2.0+)** — `federation_provenance` carries the twelve FSD-002 §3.2 dimensions as `AttestationEntry { dimension, score, attester, source_ref }` triples. Verify states what it measured; **the response composes no verdict**, structurally enforcing the §1.4 authentication ≠ trust invariant. v3.6.0 `AttestBundle` projects the same data into named measurement fields for downstream UI / scoring consumers (no ladder structure — tier mapping is consumer policy). v3.7.0 dropped the L1-L5 numbering from the dimension wire strings (`attestation:l1:self_verify` → `attestation:self_verify`, etc.) — the ladder concept lived in `CLAUDE.md` / `HOW_IT_WORKS.md` operator narrative; now it lives only in consumer-side policy, where it belongs.
- ✅ **Transparency-log witness cosigning receiver (v2.12.0)** — `SignedTreeHead::cosign`, `TrustedWitness`, `witness_quorum_met`. Registry-side emitter endpoints tracked at CIRISRegistry#24.
- ✅ **CEG 0.2 §10.0.1 typed error envelope (v4.0.0)** — `ceg_error::CegErrorCode` (13 stable wire codes covering 400/401/403/404/409/422/429/500/503) + `CegError` with `From<VerifyError>` mapping. §0.5/§0.6 violations classify cleanly as `CANONICAL_BYTES_VIOLATION`; signature failures as `SIGNATURE_VERIFICATION_FAILED`; anti-rollback (a wire-shape violation, not crypto) likewise.
- ✅ **CEG 0.2 §10.1.1 full-SHA verification before consumption (v4.0.0)** — `holds_bytes::verify_holds_bytes` enforces §0.6 hex form before hashing (short-prefix attack closed at the wire boundary) and compares digests constant-time. Closes the prefix-collision attack class on the `holds_bytes:sha256:{prefix}` directory dimension.
- ✅ **CEG 0.2 §10.3.1 STH witness consistency-proof requirement (v4.0.0)** — `WitnessConsistencyProof` (genesis / identity / extension shapes) + `count_valid_witnesses` clause 4: cosignatures without a verifying consistency proof MUST NOT count. "Quorum on log consistency, not on a string." Wire-break on `WitnessSignature` (major-version-justifying) — no production consumers wired yet.
- ✅ **CEG 0.2 §10.2 multi-steward response verifier (v4.0.0)** — `steward_key::verify_steward_key_response` enforces canonical_bytes_label parity, signer-in-list, deployed-only signing, and hybrid response signature. `to_attestation_entries` emits `cert_validity:{steward.key_id}` per **deployed steward only** — placeholder pubkeys structurally excluded from trust-root promotion.
- ✅ **CEG 0.2 §0.5/§0.6 canonicalization discipline (v4.0.0)** — `check_canonical_rfc3339` enforces `YYYY-MM-DDTHH:MM:SS.sssZ`; `check_canonical_hex64` enforces lowercase, no `0x`, exactly 64 chars. Applied to `SkillImportManifest` (v3.9.0 carried forward); v4.0 adds `cert_validity_self_attest.valid_until` per §10.2.
- ✅ **CEG 0.2 §5.2 mechanism-only wire strings (v4.0.0)** — `attestation:hardware` → `attestation:hardware_rooted` rename closes the last L-numbering misalignment from CEG 0.1.

### 11.2 Deferred / Roadmap (scheduled work, not blind spots)

- ⏳ **Reproducible builds** (Gap 4) — promised at v2.0, not yet shipped. Targets dropping the "trust the GitHub Actions runner" residual to "trust two independent rebuilders agreeing." Cargo determinism work + cross-rebuilder verification.
- ⏳ **SBOM publishing** (Gap 3) — `cargo-cyclonedx` integration scheduled. SPDX 3.0 + CycloneDX 1.6 dual format per CISA minimum elements + EU CRA Dec 2027 mandate.
- ⏳ **Continuous Rekor monitoring** (Gap 2) — `rekor-monitor` against CIRISVerify's identity, alarm on rogue entries.
- ⏳ **Two-person release rule** (Gap 5) — branch protection requiring 2+ approvers on release-tag-creating PRs; key-ceremony procedure for steward-key rotation.
- ✓ **PQC algorithm-agility** (Gap 6) — **closed v2.11.0** (CIRISVerify#29 WS-5): `HybridSignature::meets_federation_policy()` + `docs/CRYPTO_AGILITY.md`. SLH-DSA-128s/256s already nameable in `PqcAlgorithm`.
- ⏳ **Hardware-master symmetric derivation** (AV-41) — `HardwareSigner::derive_symmetric_key` lands when CIRISPersist#19 exercises the `secrets-hw` path. Software-master mode covers the v2.0 surface.
- ⏳ **PBKDF2 iteration bump** (AV-36) — 100k → 600k+ as compute baselines rise; tracked separately.

### 11.3 Out of scope by design (boundary defense, not omission)

These are NOT gaps. They are deliberate boundary choices respecting adjacent primitives' domains:

- ❌ **Forward-secret session establishment (X25519 KEX)** — investigated for v2.0; dropped after auditing CIRISEdge `FSD/CIRIS_EDGE.md` §AV-15 ("edge does not add a third encryption layer") and CIRISPersist's per-secret encryption shape (one-shot, not session-based). Reticulum / TLS handle transport-layer KEX; we don't duplicate at the substrate layer.
- ❌ **Streaming AEAD** — investigated for v2.0; dropped because persist's encrypted records are tens-to-hundreds of bytes per row, not multi-MB blobs. No concrete consumer.
- ❌ **Aggregate signature schemes** (FROST, BLS aggregation) — not in scope. v3.1.0 shipped a **generic M-of-N over hybrid singletons** (`verify_threshold_signatures` — see §11.1), which satisfies the keyset-rotation (#31) and constitutional-shutdown (#32 Ask 3) demand. True signature aggregation (one short signature standing in for N) requires either pairing-based BLS or schnorr-only FROST; neither maps cleanly onto the hybrid Ed25519 + ML-DSA-65 contract. Deferring matches the demand-driven principle — no consumer needs sub-linear signature size today.
- ❌ **Zero-knowledge proofs / homomorphic encryption** — speculative; no concrete privacy-preserving attestation use case in the federation today. HE is 100-1000× overhead at the state of the art; not federation-ready.
- ❌ **Application-layer transport** — that's CIRISEdge's role with Reticulum-rs (Phase 1) + Leviculum / LoRa / I²P / Serial (Phase 3). We're substrate; they're transport. Different layer, different ownership.
- ❌ **Operator UX for manual verification** — that's CIRISPortal's role. We expose machine-readable attestation; humans interact via portal.

### 11.4 Net assessment

**Federation role is fully covered for v4.0's CEG 0.2 conformance spec.**

The deferred items (§11.2) are scheduled work or dependency-blocked, not blind spots — every one of them is in a roadmap doc with an action item. The out-of-scope items (§11.3) are intentionally bounded to respect adjacent primitives' domains; reaching into them would be over-stepping into CIRISEdge / CIRISPortal / CIRISRegistry territory.

The **largest residual** is reproducible builds (Gap 4). Until two independent rebuilders agree, "the binary matches what GitHub Actions built" is an undeclared trust assumption inherited from CI. This is the single remaining axis where the SOTA peer comparison (§10) shows us trailing — Sigstore's Rekor + reproducibility patterns are mature; we're committed to the target but haven't shipped.

The **second residual** is multi-operator release controls (Gap 5). XZ-3094 demonstrated single-maintainer trust is insufficient for substrate-level dependencies. Branch protection + key ceremony are tractable; just need the operator coordination.

Where the federation could push us further (if the substrate threat model evolves):

- **Aggregate-signature primitive** (BLS / FROST) if some federation operation needs sub-linear signature size at scale — generic M-of-N hybrid singletons cover today's demand (§11.3 #3).
- **Hardware-master symmetric derivation** when persist#19 actually wires `secrets-hw` (§11.2 #6).
- **FIPS-mode RNG draws** if FedRAMP / CMMC compliance becomes a federation requirement (AV-39 secondary).
- **Streaming AEAD** if a federation primitive ever needs multi-MB at-rest blob encryption (currently nobody does — §11.3 #2).
- **Production population of the scalar-attestation surface** depends on three remaining cross-repo emitters: CIRISRegistry#24 (`provenance:slsa:{level}` / `provenance:build_manifest:{target}` / `cert_validity:{authority}` emission + STH witness cosigning endpoint), CIRISAgent#801 (periodic `run_attestation` + bundle UI surfacing + AV-42 cutover commitment), CIRISNodeCore#14 (structurally-independent 3rd `registry_consensus` source post Agent 3.0 fold). The fourth (CIRISPersist#108, `persist_row_hash` surfacing) closed same-day in persist v2.6.0. Verify-side receivers are all shipped — the bundle's measurements populate as each remaining downstream lands.

---

## 12. Update Cadence

This threat model is **updated on every minor version bump** (v1.X → v1.X+1). New attack vectors land here when:

- A new feature exposes a new surface (e.g., v1.7's `StorageDescriptor` introduced AV-7).
- A SOTA review identifies an industry-recognized gap (the v1.8 cycle added AV-11–AV-13 from supply-chain threat literature).
- A real-world incident in our deployment or a sibling primitive's deployment surfaces a class we hadn't catalogued (lens-scrub-key incident motivated AV-7's elevation from "future concern" to "core mitigation").
- A new producer/transport surface lands (v6.0's self-at-login device identity added AV-43 CEG outbox, AV-44 software-PQC-seed-at-rest honest-boundary disclosure, AV-45 surviving-key revocation; the YubiKey PIV external-token row in §5).

Patch releases (v1.X.Y) update only the **Status** column of the mitigation matrix when residuals close. The §10 SOTA roadmap is reviewed at minor-version cadence; a yearly full-text SOTA pass is part of the v2.0 plan.

**Companion documents:**
- [`FSD/FSD-001_CIRISVERIFY_PROTOCOL.md`](../FSD/FSD-001_CIRISVERIFY_PROTOCOL.md) — protocol spec
- [`docs/POB_SUBSTRATE_PRIMITIVES.md`](POB_SUBSTRATE_PRIMITIVES.md) — federation substrate design (closed)
- [`docs/BUILD_MANIFEST.md`](BUILD_MANIFEST.md) — build-manifest schema and CLI usage
- [`docs/BENCHMARKS.md`](BENCHMARKS.md) — performance baselines feeding the regression-gate threat assumption
