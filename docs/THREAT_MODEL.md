# CIRISVerify Threat Model

> **Substrate verifiers (CC 6.1).** The threat model and verifier reference for
> the `substrate` module — wholeness witness (CC 6.1.1), noise floor and the
> aggregation pyramid (CC 6.1.2), replication (CC 6.1.5), recursive bootstrap and
> ALM capacity — lives in **[`SUBSTRATE.md`](SUBSTRATE.md)**.

**Last updated:** 2026-10-28 (v21.0.0). Earlier revisions are in git history.

## 1. Scope

### What CIRISVerify Protects

CIRISVerify is the hardware-rooted license verification module for the CIRIS ecosystem. It also serves as the **build-attestation substrate primitive** for the PoB federation — every CIRIS peer (agent, lens, persist, registry, and CIRISVerify itself) signs and validates its build manifests through one shared code path (`verify_build_manifest`).

It protects against:

- **Identity fraud**: Unlicensed agents (CIRISCare) masquerading as licensed professional agents (CIRISMedical, CIRISLegal, CIRISFinancial)
- **License forgery**: Fabrication of valid-looking license status without licensing authority
- **Trust-root substitution**: Serving a forged, rolled-back or equivocating trust root (GenesisBundle) to a node
- **Capability escalation**: Agents claiming capabilities beyond their license tier
- **Silent degradation**: Agents suppressing or modifying mandatory disclosure about their license status
- **Verification tampering**: Modification of the verification binary to return false results
- **Cross-primitive identity confusion**: A compromised primitive's build-signing key being used to forge other primitives' manifests
- **Ephemeral identity churn**: Silent ephemeral storage causing federation peers to lose continuity across restarts

### What CIRISVerify Does NOT Protect

- **Malicious behavior with valid license**: A properly licensed agent can still act maliciously within its authorized capabilities
- **Compromised licensing authority**: If a licensing authority in a reader's trust set is compromised, it can cosign valid-looking licensure rows for malicious agents
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
- **Control of any trust-root host** (registry endpoint), including serving arbitrary bytes at `/v1/trust-root/bundle`
- **Ability to replay** previously captured valid responses
- **Access to emulators and debuggers** for runtime analysis
- **Unlimited computational resources** for classical cryptography attacks

### Adversary Limitations

The adversary is assumed to NOT have:

- **Keys of a strict majority of the baked accord holders** (the GenesisBundle authorization threshold, CC 5.3.4)
- **Compromise of the hardware security module** (TPM 2.0, Secure Enclave, StrongBox)
- **Ability to break both Ed25519 AND ML-DSA-65** simultaneously (hybrid crypto defense)
- **Physical access** to the deployment hardware
- **Ability to manipulate system clocks** by more than 5 minutes on the target device

---

## 3. Attack Vectors

Attack vectors organized by adversary goal. Each lists the attack, primary mitigation, secondary mitigation, and residual risk in-place. Goal-based grouping (mirrors CIRISPersist's structural pattern) makes the surface boundaries explicit:

- **§3.1 License Fraud** — adversary wants to claim a license tier they don't have (AV-1..AV-6)
- **§3.2 Federation Identity** — adversary wants stable misidentification or evasion of longitudinal scoring (AV-7, AV-8)
- **§3.3 Build Provenance** — adversary wants to strip or forge "this primitive's CI signed this binary" attestation (AV-9)
- **§3.4 Supply Chain** — adversary wants to ship malicious code through legitimate signing channels (AV-11, AV-12)
- **§3.5 Hardware Trust Anchor** — adversary wants to extract or counterfeit hardware-bound signing keys (AV-13)
- **§3.6 Operational / Reliability** — non-adversarial failure modes that still cost availability (AV-10)
- **§3.7 Multi-Instance Cohabitation** — multiple CIRISVerify instances on one host racing on shared keyring state (AV-14)
- **§3.8 Federation Crypto Authority** — symmetric / KDF / MAC / RNG surface (AV-35..AV-41)
- **§3.9 Transport-Identity Binding** (AV-42)
- **§3.10 Self-at-Login Device Identity** (AV-43..AV-45)

AV-46..AV-51 (presenter binding, device attestation, trust anchors, canonical bytes) are catalogued in the §4 matrix.

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

**Secondary**: Hybrid signature on attestation responses — even if the binary is modified to claim higher tier, a downstream consumer verifying the response signature against the deployment's registered key, and the licence against the licensing authority's cosigned row, will reject.

**Residual**: A rooted device with a memory-patched binary can produce locally-correct UX (mandatory disclosure suppressed) but cannot forge valid signatures. The downstream verifier (e.g., another agent in the federation) catches the lie.

#### AV-3: Verification Endpoint Spoofing

**Attack**: Intercept or replace responses from trust-root hosts, or operate a malicious host, to install a forged, rolled-back or split trust root.

**Primary mitigation**: The trust root is a GenesisBundle authorized by the HUMANITY_ACCORD holders whose keys are baked into the binary (CC 5.3.4). Each host's bundle (`GET /v1/trust-root/bundle`; registry alias `/v1/steward-key`) is verified on its own: at least `max(carried M, strict majority of the baked roster)` distinct baked holders must have hybrid-signed the authorization digest (Ed25519 over the digest, ML-DSA-65 over `digest ‖ ed25519_sig`). A host can withhold a bundle but cannot forge one. The highest verified `version` is selected, so an older bundle cannot displace a newer one. Two verified bundles at the same version with different fingerprints are equivocation: nothing is selected and the status is `ERROR_SOURCES_DISAGREE`. One verified host suffices; DNS is not a source, and the unsigned response wrapper carries no authority.

**Secondary**: TLS to each host. TLS is not the trust boundary — it protects availability and confidentiality of the fetch, not the authority of its content.

**Residual**: An adversary controlling every host can deny service (no root → community mode) or withhold a newer bundle so nodes keep the highest version they can verify. Forging a root requires the keys of a strict majority of the baked accord holders.

#### AV-4: Replay After Revocation

**Attack**: Capture a valid response or object before it is revoked, replay it afterward.

**Primary mitigation**: Challenge nonce (32+ bytes) binds each attestation response to the request, preventing simple response replay. Revocation is a quorum-signed `federation_revocations` row; there is no separate signed revocation list to roll back. The trust root cannot be rolled back because the highest verified GenesisBundle version is selected (AV-3). No licence is honoured until the licensure-row gate exists (CC 4.4.3.8), so there is no licence to replay; the local cache is never an authority for a licence.

**Secondary**: Transparency log records verification events; `LicenseCache::check_and_update_revision` provides a monotonic highest-seen-revision guard (`RollbackDetected`).

**Residual**: A revocation row a node has not yet received cannot take effect at that node; propagation timeliness is FEDERATION_THREAT_MODEL §3.3 Gap A (R1).

#### AV-5: Man-in-the-Middle Attestation Responses

**Attack**: Intercept attestation responses and modify them to claim higher trust level.

**Primary mitigation**: Hybrid cryptographic signatures (Ed25519 + ML-DSA-65) over all response data. PQC signature is bound to classical signature (covers `challenge_nonce || classical_sig`), preventing signature stripping. Remote attestation proof export allows third parties to independently verify hardware binding.

**Secondary**: TLS termination + cert pinning at the transport layer.

**Residual**: A complete crypto break of both Ed25519 AND ML-DSA-65 simultaneously. ML-DSA-65 is NIST-standardized post-quantum; Ed25519 is classical. Hybrid means both must fall, and this is enforced: federation-tier verification rejects a classical-only signature (`HybridPolicy::RequireHybrid`), so a break of Ed25519 alone does not forge an accepted attestation, grant or binding — see §3.2 AV-8 and `FEDERATION_THREAT_MODEL.md` F-AV-14. Ed25519 verification is strict (small-order `A`/`R` rejected).

#### AV-6: Emulator/Debugger Interception

**Attack**: Run the agent in an emulator or attach a debugger to intercept and modify verification responses at runtime.

**Primary mitigation**: Platform-specific integrity checks detect emulators (Android: goldfish, qemu; iOS: simulator; Desktop: hypervisor/DMI checks). Debugger detection (ptrace on Linux/Android, sysctl on macOS, IsDebuggerPresent on Windows). Hook detection for Frida/Xposed frameworks. Timing anomaly detection for breakpoint-induced delays.

**Secondary**: Emulator/rooted devices are degraded to COMMUNITY tier rather than blocked outright (open-source principle: never fully stop execution; restrict capability instead).

**Residual**: Sophisticated emulator setups that defeat detection (e.g., hypervisor-level intercepts that hide from in-VM checks). Defense-in-depth via downstream signature verification — even if local checks pass, federation peers verifying the agent's signed output catch fakes.

---

### 3.2 Federation Identity — adversary wants stable misidentification or evasion of longitudinal scoring

#### AV-7: Ephemeral Identity Storage (lens-scrub-key class)

**Attack**: A federation peer's signer silently lands its identity seed in ephemeral storage (container writable layer, `/tmp`, `/var/cache`, user-session keyring). Identity churns every restart. The score function's longitudinal window (PoB §2.4 S-factor 30-day decay) cannot accumulate behind an unstable identity, so anti-Sybil weight stays at zero by construction.

**Primary mitigation**: `HardwareSigner::storage_descriptor()` declares where the seed lives at runtime. Boot-time logging in `factory.rs::create_hardware_signer` surfaces the descriptor at INFO level for every signer construction. The trait method has no default impl — every signer variant is forced to declare its location.

**Secondary**: Consumers (CIRISAgent, CIRISPersist) gate `--strict-storage` mode that refuses to start if the descriptor matches an ephemeral path heuristic. `disk_path()` and `is_hardware_backed()` helpers let consumers ship their own typed checks.

**Residual**: An operator can override with `CIRIS_PERSIST_KEYRING_PATH_OK=1` (or equivalent) after manual audit. A consumer that ignores the descriptor entirely (doesn't gate boot on it) loses the protection — a consumer-side bug, not a verify-side gap.

#### AV-8: Cross-Primitive Identity Confusion

**Attack**: A compromised primitive's build-signing key (e.g., lens's) is used to sign a manifest claiming `primitive: agent`, hoping a verifier accepts it as if signed by agent's key. "Confused deputy" pattern.

**Primary mitigation**: `verify_build_manifest(bytes, expected_primitive, &trusted_pubkey)` validates `manifest.primitive == expected_primitive` BEFORE checking the signature. The primitive discriminant is part of the canonical bytes the hybrid signature covers, so a cross-primitive replay would have to forge a signature valid under a *different* primitive's key — equivalent to the original key-compromise problem, not a new attack surface.

**Secondary**: Per-primitive trusted-pubkey lookup means the wrong primitive's signature does not match the expected primitive's pinned key. For build-manifest Contributions (`provenance:build_manifest:{target}:v1`) the pipeline key's standing is the substrate's: either conferred by delegation from an accord-rooted authority or held as the accord role on its key record (FSD-006); verify checks that the presented blessing names the signing pipeline.

**Key-directory provenance**: every `federation_keys` row carries a scrub-signature (recursive provenance — each row signed by another row, terminating at a self-signed anchor). `provenance::verify_provenance_chain` verifies each link's Ed25519 + ML-DSA-65 scrub-signature over the JCS-canonicalized registration envelope, cross-checks the content hash, binds the link's subject to the envelope it carries, and accepts a terminus whose `identity_type` is in the caller's accepted role set (e.g. `accord_holder`, `canonical`, `steward`). Every link must be hybrid at federation tier (`HybridPolicy::RequireHybrid`; a classical-only link is `LinkNotHybrid`); classical-only acceptance is confined to the explicit `AllowClassicalPending` local-tier path.

**Residual**: A primitive whose pipeline key has no standing in the substrate cannot have its manifests rooted; the consumer sees no standing, never a false pass.

`BuildManifest::to_attestation_entries` emits a `provenance:build_manifest:{target}:v1` AttestationEntry whose `attester` is the signing key, so a downstream auditor can confirm which primitive's key attested the build without re-running verification.

---

### 3.3 Build Provenance — adversary wants to strip or forge "this primitive's CI signed this binary" attestation

#### AV-9: Build Manifest Write-Without-Read

**Attack**: A registered build manifest's original CI signature is lost on registry round-trip. Registry's legacy POST endpoint flattens `BuildManifest` into the `function_manifests` table and re-signs it under the registry's own key on GET. Per-primitive attribution ("CIRISVerify's pipeline signed this") collapses into "registry vouches for this", and an auditor asking which primitive's CI signed a binary gets the wrong answer.

**Primary mitigation**: The registry's current POST endpoint preserves the original CI signature in storage ([`CIRISRegistry/docs/TRUST_CONTRACT.md`](https://github.com/CIRISAI/CIRISRegistry/blob/main/docs/TRUST_CONTRACT.md) §2.3 documents both POST cases). Verifiers distinguish which path served a manifest by `signature.key_id`:

- a per-primitive pipeline key → original CI signature preserved (Case (i)) → trust chain to the publishing primitive's key; the registry verifies the inbound hybrid signature against its `trusted_primitive_keys` before storing;
- the registry's own key → legacy POST path, registry-resigned (Case (ii)) → trust chain only back to the registry.

**Secondary (always available)**: the GitHub release artifact `signed-build-manifests.tar.gz` preserves the original CI-signed `BuildManifest` end to end, Sigstore-signed alongside the binary archives. Build-manifest Contributions (FSD-006) carry the pipeline signature and `evidence_refs: [manifest_hash]` independently of any registry read path.

**Residual**: A registry GET returning the original posted `BuildManifest` (`GET /v1/verify/build-manifest/{primitive}/{ver}/{target}`) is a registry-side item; until it exists, per-primitive attribution is read from the release artifact or the Contribution, not from the legacy registry GET.

---

### 3.4 Supply Chain — adversary wants to ship malicious code through legitimate signing channels

#### AV-11: Sigstore OIDC Token Theft (federation-poisoning)

**Attack**: An attacker obtains a valid OIDC token for the CIRIS release identity (e.g., compromised GitHub Actions OIDC issuer config, stolen short-lived token from a misconfigured workflow) and signs a malicious binary that is correctly Rekor-logged. Downstream consumers' Sigstore-verify checks pass; the binary is accepted as authentic. Canonical post-XZ Sigstore-era attack pattern.

**Primary mitigation**: Sigstore identity binding via GitHub Actions OIDC (release artifacts are signed under `https://github.com/CIRISAI/CIRISVerify/.github/workflows/release.yml@refs/tags/vX.Y.Z`). Release notes include the expected signer identity for human review.

**Secondary**: Hybrid signature on the BuildManifest provides a second trust path independent of Sigstore. A token-thief who does not also hold the pipeline build-signing key can produce a Sigstore-valid binary but not a validly signed BuildManifest.

**Residual**: No continuous Rekor-monitor running against the CIRIS signing identity. A rogue signing event under our OIDC identity would not be detected automatically — only by humans noticing an unexpected release. **Action**: integrate `rekor-monitor` against `https://github.com/CIRISAI/CIRISVerify/...` identity, alarm to maintainers on unexpected entries. See §10 SOTA gap #2.

#### AV-12: Maintainer Compromise / XZ-Style Supply Chain

**Attack**: A maintainer with commit access to CIRISVerify (or any of its transitive Rust dependencies) introduces a backdoor that is legitimately signed and released through normal CI. Source review may not catch it (XZ-3094 hid payload in test fixtures and m4 macros, not git source). Downstream Sigstore + hybrid-sig checks pass.

**Primary mitigation**: Open-source under AGPL-3.0 means independent review is possible. `cargo-audit` and `cargo-deny` (`deny.toml`) enforce advisory and license policy in CI.

**Secondary**: None against this attack — a compromised maintainer signs both classical + PQC, so hybrid-sig is no defense; they have legitimate access to the pipeline signing key, so a signed BuildManifest is no defense.

**Residual (open)**: No two-person-rule on **releases** (single-maintainer signoff is the current path). No multi-maintainer signing key. No SBOM published with releases (CISA / EU CRA gap). No reproducible builds means source-vs-binary divergence cannot be independently verified. **Action items**: §10 SOTA gaps #3 (SBOM), #4 (reproducible builds), #5 (two-person-rule on releases).

**Governance documents**: distinct from release signing — the **authoritative threat-model + governance documents** (`FEDERATION_THREAT_MODEL.md`, this file, `MISSION.md`, the embedded `bootstrap_stewards.json`) have (a) a two-person-rule via `.github/CODEOWNERS` requiring reviewer approval on every edit, (b) a CI `threat-model-changelog` gate rejecting an authoritative-doc edit with no changelog delta (a silent F-AV-status downgrade is diffable by construction), and (c) `ciris_verify_core::doc_integrity` — a hybrid Ed25519 + ML-DSA-65 signed content-hash attestation that detects any post-publication tamper. This closes the *document-integrity* half of the meta-class (FEDERATION_THREAT_MODEL.md §6.7 F-AV-MAINT Phases 1-2); the *release-signing* two-person-rule above is a separate open item.

**Related (registry-side, finer-grained)**: [`CIRISRegistry/docs/THREAT_MODEL.md`](https://github.com/CIRISAI/CIRISRegistry/blob/main/docs/THREAT_MODEL.md) AV-34 ("Build-signing key compromise (CI-side)") catalogues the surface where per-primitive build-signing keys held in GHA secrets are load-bearing trust anchors for the federation. Their dual-secret-co-requirement defense (publishing requires BOTH the build-signing key AND `REGISTRY_ADMIN_TOKEN`) and per-repo isolation (compromise of one repo's GHA can publish only that primitive's manifests) extend AV-12's mitigation surface across the federation. Their hardening proposals (cosign verification on uploaded manifests, M-of-N signing for high-stakes primitives, SLSA attestation in extras) target the same supply-chain class as our SOTA gaps #3-#5.

---

### 3.5 Hardware Trust Anchor — adversary wants to extract or counterfeit hardware-bound signing keys

#### AV-13: TEE.fail / Bus-Interposition Attacks on Server-Class TEEs

**Attack**: Physical access to server hardware running a federation validator (e.g., a CIRISRegistry node, a federation peer running CIRISVerify in a confidential VM). DDR5 memory bus interposition (TEE.fail, Oct 2025, Georgia Tech/Purdue, sub-$1k attack) extracts attestation signing keys from fully-updated Intel SGX/TDX or AMD SEV-SNP machines because memory encryption is deterministic. EMFI on ARM TrustZone skips secure-boot checks reliably.

**Primary mitigation**: Threat model assumption §6.4 says adversary doesn't have physical access. Hardware-vulnerability detection covers SoC-level CVEs (MediaTek CVE-2026-20435 boot ROM EMFI, Qualcomm CVE-2026-21385) and caps attestation to `SOFTWARE_ONLY` for affected devices. See §5.1 for the catalogue of detected hardware vulnerabilities.

**Secondary**: HSM-anchored signing keys (FIPS 140-3 Level 3+) for production registry and pipeline signing roles; the accord holders' keys are on YubiKey 5 FIPS tokens. TEE-anchored keys (SGX/TDX/SEV-SNP/CCA) should NOT be used for signing roles in confidential-VM deployments.

**Residual (open)**: Server-class TEE attacks are not modeled in our adversary capability list — physical access is excluded by assumption §6.4. Datacenter deployments of CIRISVerify or CIRISRegistry SHOULD assume hostile co-tenants and deploy signing keys in HSMs, not TEEs. See §10 SOTA gap #7.

---

### 3.6 Operational / Reliability — non-adversarial failure modes that still cost availability

#### AV-10: Stale Hardware-Marker Lockup

**Attack surface (operational, not adversarial)**: A `HARDWARE_SECURED:fingerprint` marker file points at a TPM key that has been deleted (`tpm2_evictcontrol` on the wrong handle, OS reinstall, hardware swap). The agent process indefinitely fails its sign() calls because it believes hardware-bound signing is required, but the hardware key is gone. Recovery requires manual marker deletion.

**Primary mitigation**: The keyring detects the case, clears the stale marker, and surfaces `KeyringError::HardwareNotAvailable` instead of a silent stuck state. A re-open opens the tier the key actually lives in and never mints a master or supersedes a live key.

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
- **Stale-marker race**: the `HARDWARE_SECURED:fingerprint` marker file is process-local. Single-process stale recovery is handled; concurrent recovery from another process is not locked against.
- **Cache consistency**: A creates the key, B's `cached_signing_key: Option<...>` is still `None`. B fails its first `sign()` until something flushes the cache. No invalidation path.

The adversarial worst case: an attacker who controls one of the cohabiting processes attempts a malicious `delete_key()` while another process is mid-attestation. The legitimate process surfaces `HardwareNotAvailable` (AV-10's fix surfaces the symptom) but the operator may not realize the deletion was hostile rather than a hardware failure.

**Primary mitigation**: When CIRISPersist is in the stack, persist's `Engine` holds the verify Engine — there's structurally one verify instance per process and the contention surface vanishes by construction. The dominant production pattern is "persist is the interface to verify" (see `docs/HOW_IT_WORKS.md` "Cohabitation — When Persist Is the Interface"); higher layers go through persist's API rather than instantiating their own verify Engine. AV-14's race windows describe a multi-instance pattern that doesn't occur in a persist-bearing stack.

In verify-only stacks (registry, sovereign-mode dev, simple CLI tooling), there's structurally one consumer — single process, single instance, no race possible.

**Secondary**: OS-daemon-level serialization (TPM via `/dev/tpm0`, Apple `securityd`, Android Binder, Linux Secret Service) closes the **read** path universally — even in the unusual multi-consumer-without-persist case, concurrent reads serialize cleanly through the OS keyring backend. PoB §3.2 single-key-three-roles enforces same-alias semantics: two instances with the same alias are the *same identity*, not competing identities.

**Residual (open, only in verify-only multi-process stacks without an external bootstrap step)**:
- Cold-start key-creation race window in the uncommon multi-consumer-without-persist pattern (e.g., HA replica set running multiple verify-only processes against shared persistent storage). Fix paths: (a) add persist to the stack — surface vanishes; (b) operator-managed pre-bootstrap (`ExecStartPre=flock`); (c) verify-side `flock` scope guards around mutating operations (not implemented; low priority since the pattern is uncommon and avoidable).
- An out-of-process verify daemon is unnecessary: persist's process is the singleton when persist is in the stack, and a verify-only stack has one process.

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

### 3.8 Federation Crypto Authority — adversary wants to bypass or subvert the symmetric / KDF / MAC / RNG surface

Threats on `ciris-crypto` as the federation-wide crypto authority: the AES-256-GCM AEAD, KDF (PBKDF2-HMAC-SHA256 + HKDF-SHA256), HMAC-SHA256, and `OsRng`-facade modules.

Federation policy: every CIRIS primitive that needs symmetric crypto, KDF, MAC, or random bytes routes through `ciris-crypto`. Direct dependencies on RustCrypto crates (`aes-gcm`, `hkdf`, `pbkdf2`, `hmac`, `getrandom`) from downstream consumers are policy violations — the audit point exists so violations are tractable.

#### AV-35: AES-GCM nonce reuse with same key

**Attack surface (catastrophic class)**: GCM is a counter-mode AEAD. Nonce reuse with the same key allows an adversary observing two ciphertexts under the same `(key, nonce)` to: recover the XOR of the two plaintexts (immediate confidentiality break), recover the GCM polynomial-MAC authentication key `H` (full forgery capability for that key going forward).

The library does NOT detect or prevent reuse. The federation's threat model assumes well-behaved callers (the audit point centralizes nonce-management code review at the consumer side, not at the library boundary).

**Primary mitigation**: spec'd policy in `aes_gcm.rs` module docs — caller MUST use random nonces (12 bytes from `ciris_crypto::random::fill`) or strict per-key counter. Random nonces give a ~2³² messages-per-key birthday bound (NIST SP 800-38D §8.3); counter nonces require strict per-key persistent state.

**Secondary**: federation incident channel — observed nonce reuse is reported as a key-compromise event, triggering rotation. Same-host process boundaries should not share AES keys (per AV-14 cohabitation contract: same alias = same identity, so same key — but symmetric keys derived from per-secret salts are different per row, so reuse only matters within a single secret's lifetime).

**Status**: ⚠ Open at the library layer (caller-managed); ✓ Policy documented.

#### AV-36: PBKDF2 iteration count too low

**Attack surface**: A captured PBKDF2 ciphertext + salt allows offline brute-force of the master password. The cost is `iters × hash_ops` per guess; too-low `iters` shifts the cost into adversary-feasible range. OWASP 2026 recommends 600,000 PBKDF2-HMAC-SHA256 rounds.

**Primary mitigation**: the federation minimum is `iters = 100,000` (CIRISPersist's software-master mode, matching CIRISAgent's `ciris_engine/logic/secrets/encryption.py`). `iters = 0` is rejected with `CryptoError::KdfParameter`.

**Secondary**: a master derived with `derive_symmetric_key` (HKDF from a sealed seed, AV-41) has no password to brute-force; only password-derived software masters are exposed to this AV.

**Status**: 🟡 100k iters is the floor, below OWASP's 600k recommendation.

#### AV-37: HKDF context confusion (cross-domain key reuse)

**Attack surface**: Same `(IKM, salt)` used to derive keys for different purposes via colliding `info` strings → key reuse across protocol domains. An adversary who compromises one domain's encryption key can decrypt the other domain's ciphertexts if the keys are identical.

Concrete instance: if persist derives an AES-GCM key with `info = b"ciris-secret"` and an HMAC key with `info = b"ciris-secret"` from the same master, both keys are identical bytes. AES key compromise via cryptanalysis (theoretical) → MAC forgery (immediate).

**Primary mitigation**: federation namespacing convention — `info = b"ciris-<purpose>-v<n>"` where `<purpose>` is unique per cryptographic role and `<n>` is the format version. CIRISPersist documents its info strings in `secrets/encryption.py`. The convention is also the migration knob — bumping `<n>` rotates the derived key family without rotating IKM.

**Secondary**: code review at PR time + cargo-deny lints in downstream consumers banning direct HKDF deps (forces routing through `ciris_crypto::kdf::hkdf_sha256` where the convention is documented).

**Status**: 🟡 Open at the library layer (caller-managed); ✓ Policy documented; ⏳ runtime enforcement (info-string registry validator) tracked as future work.

#### AV-38: HMAC key reused as KDF master (cross-protocol attack)

**Attack surface**: A federation primitive uses one root secret as both an HMAC key (for `EncryptedSecretRecord.edge_hmac`) AND as a PBKDF2 master (for software-master per-secret derivation). The two algorithms make different assumptions about key entropy distribution; combining them creates cross-protocol attacks where partial information from one operation leaks into the security of the other.

**Primary mitigation**: federation policy — derived keys per purpose, never reuse roots across MAC + AEAD + KDF. Two-step derivation: root → HKDF-SHA256(root, salt, b"ciris-mac-v1") → MAC key; root → HKDF-SHA256(root, salt, b"ciris-aead-v1") → AEAD key. Downstream cargo-deny configs flag direct RustCrypto MAC/KDF deps that would bypass policy.

**Status**: ⚠ Open at the library layer (caller-managed); ✓ Policy documented + structurally supported via the existing HKDF surface.

#### AV-39: OsRng entropy degradation

**Attack surface**: `getrandom(2)` on Linux blocks until the kernel CSPRNG is seeded; on first-boot containers and embedded devices the seed pool can be shallow for the first few seconds. Pre-seeded `/dev/urandom` is theoretically nondeterministic but in practice replays predictable patterns until kernel collection catches up.

**Primary mitigation**: `ciris_crypto::random` wraps `OsRng`, which on Linux/Android delegates to `getrandom(2)` (blocking until seeded), on macOS/iOS to `SecRandomCopyBytes`, on Windows to `BCryptGenRandom`. The blocking semantics on Linux are the kernel's mitigation — `getrandom(2)` waits for `random.fasync_init` rather than returning entropy-weak bytes.

**Startup health-check + fail-secure**: `ciris_crypto::rng_health` runs NIST SP 800-90B startup tests over a fresh 4096-byte `OsRng` draw at process init — a repetition-count test (§4.4.1; catches a stuck source emitting the same value) and an adaptive-proportion test (§4.4.2; catches a source biased toward one value) — and latches a process-global verdict. On failure, every subsequent `random::fill` returns `CryptoError::RngHealthCheckFailed` **without drawing**, so a degraded source (vTPM PRNG seeding bug at boot, embedded low-entropy boot, Dual_EC-class compromise) fails closed: nonce / key / KEX generation errors and the attestation degrades through existing crypto error paths instead of silently emitting weak material. The FFI runs the check at `ciris_verify_init` (after logging is wired, so the verdict reaches logcat / Console). This addresses FEDERATION_THREAT_MODEL §3.3 Gap H. Key generation in `ciris-crypto` and every keyring mint honour the latch. It is detection + fail-secure, not prevention — it catches the degradation classes an SP 800-90B startup test can catch, not a subtle in-range bias.

**Secondary**: deployment guidance — containers should include an `ExecStartPre` that reads from `/dev/random` (the blocking variant) or uses `--random-source` mounts to inherit host entropy. Embedded targets get hardware-RNG mixing once we have a concrete embedded consumer (none today; CIRIS deployment targets are server / mobile / desktop).

**Status**: ✓ Mitigated for primary deployment targets (server / mobile / desktop on platforms with a maintained kernel CSPRNG), with the SP 800-90B startup health-check and fail-secure latch; 🟡 further hardening (independent hardware-entropy mixing, FIPS-mode draw path for FedRAMP/CMMC, per-platform CSPRNG-identity attestation) tracked if/when embedded or compliance targets surface.

#### AV-40: Federation-policy violation (bypassing ciris-crypto)

**Attack surface (process-level)**: A consumer reaches into RustCrypto crates directly (`aes-gcm`, `hkdf`, `pbkdf2`, `hmac`, `getrandom`) for primitives that ciris-crypto already provides. This bypasses the federation's audit point — vuln assessment, KAT vector locking, error-variant standardization, and policy convention all happen at the ciris-crypto boundary; direct deps escape.

**Primary mitigation**: CIRISVerify is the federation crypto authority; consumers MUST go through it. `cargo-deny` config in downstream `Cargo.toml` bans the direct deps:

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

**Attack surface**: Mobile keystores (Android, iOS Secure Enclave) do not expose HKDF as a keystore primitive, so a symmetric master cannot be derived inside the hardware. The seed sits in process memory long enough to feed HKDF, then is zeroed. The window between "seed in memory" and "zero" is a residual surface (heap dump, debugger, OOM core dump).

**Primary mitigation**: `ciris_verify_core::keys::derive_symmetric_key(storage, key_id, context)` derives a 32-byte key by HKDF-SHA256 from a seed held in `SecureBlobStorage` (TPM-sealed, Secure Enclave, Android Keystore, or the software-sealed fallback). The seed is sealed at rest; the loaded seed and the derived key are `Zeroizing` on every exit path. `context` domain-separates derived keys (AV-37).

**Secondary**: persist's password-derived software-master mode uses `kdf::pbkdf2_hmac_sha256` + `kdf::hkdf_sha256` with caller-managed master lifecycle; the derived per-secret key never goes back to disk in cleartext.

**Status**: 🟡 Seed sealed at rest; derivation is in software (seed transiently in memory) on every platform.

---

### 3.9 Federation Transport-Identity Binding — adversary wants to intercept mesh traffic addressed to another federation key

#### AV-42: Spoofed transport-identity ↔ federation-key binding

**Attack**: Mesh transports (Reticulum) address peers by a *transport identity* — `hash(x25519‖ed25519)` — distinct from the federation Ed25519 `key_id` (AV-17 keeps the federation seed out of the transport process). A sender calling `send(key_id=K, …)` must resolve `K` to a transport identity. An unauthenticated mesh *announce* (`key_id → destination`) is trust-on-first-use: any peer can announce `key_id=K` paired with its own destination, and a sender routes K's envelope to the adversary — interception (the envelope is still sender-signed, so the adversary cannot forge a reply K would accept, but it *receives and decrypts* the bytes, and legitimate delivery is denied).

**Primary mitigation (Option C′)**: the binding is carried as a signature-covered field of the `FederationEnvelope` (`src/ciris-verify-core/src/federation_envelope.rs`). `sender_transport_identities` is inside the canonical bytes the hybrid signature covers, so verifying any envelope from K — which a recipient does anyway — yields an authenticated "K is reachable at T". No separate attestation artifact; no `federation_keys` schema migration. `transport_epoch`, a per-`key_id` monotonic counter enforced by `TransportEpochGuard`, blocks replay of a stale (possibly adversary-controlled) binding — anti-rollback, mirroring revocation-revision monotonicity. The `ENVELOPE_DOMAIN_SEP` prefix separates envelope bytes from every other signed primitive, so a transport-identity-shaped field elsewhere (an STH, a build manifest) can never be harvested as an envelope binding (the AV-8 confused-deputy precedent).

**Secondary**: cold first-contact — before any envelope has been received from K — is rooted against the registry/`federation_keys` directory row for `K`, not trust-on-first-use. One-way broadcast classes (STH gossip, audit broadcasts) route only to already-confirmed transport identities.

**Routing-only / provenance bound (finding G)**: the transport binding is **routing information, not provenance**. It lives in envelopes, deliberately *outside* the `federation_keys` recursive-scrub-signing chain. This is acceptable precisely because it confers nothing — see the invariant below. If a transport identity ever gates a security decision (rather than only addressing), it must first be promoted to a signed `federation_keys`-class row inside the provenance chain.

**Anti-Sybil bound (finding J)**: longitudinal / S-factor anti-Sybil weight keys **only** off `key_id`. A federation key may present, rotate, or multi-home across many transport identities over time; that churn is invisible to scoring. Counting transport identities as identities would let an attacker inflate apparent peer count — `key_id` is the identity, the transport identity is plumbing.

**Authentication ≠ trust invariant** (federation-wide, `MISSION.md` §1.4): *every federation primitive authenticates origin; none confers trust.* Verifying a `FederationEnvelope` proves "this came from key K" and nothing more. A never-before-seen `key_id` delivering a valid envelope lands at trust-degree = default-untrusted, zero history. Confirming a transport binding updates the routing table only — it never moves an entity along the trust axis. Trust is a separate, explicit, operator/policy-controlled, default-deny axis (inherited from the CIRISNodeCore trust model).

**Status**: ✓ Mitigated: `FederationEnvelope` + `TransportEpochGuard`, `federation_keys` provenance verification, and the enforcement-capable verify path (`EnvelopeVerifyPolicy::RequireTransportBinding`); consumers are CIRISPersist (`root_binding` cold-start rooting) and CIRISEdge (authenticated `PeerResolver`). `TransportBinding` binds its subject (`attesting_key_id`, `transport_destination`, `encryption_pubkeys`) to the signed occurrence envelope, and the RNS `destination_hash` is recomputed and byte-compared. Residual: enforcement is `Advisory` by default; requiring it is a fleet configuration choice.

---

### 3.10 Self-at-Login Device Identity — adversary wants to forge, intercept, or refuse-to-revoke a hardware-rooted login identity

The hardware-rooted self-at-login surface comprises a YubiKey-PIV (Ed25519) + software ML-DSA-65 user identity (`self_at_login`), a self-signed genesis `KeyRecord` producer (`federation_self_record`), a filesystem CEG-object outbox (`ceg_outbox`) that CIRISServer drains and relays, and a "revoke the lost/stolen device" producer (`sign_occurrence_revocation`). Three surfaces; the genesis self-record is covered by the existing self-attestation framing (§3.2 AV-8 + the CLAUDE.md fractal-self reading discipline), not a new AV.

#### AV-43: CEG-outbox tampering / spoofed relay

**Attack surface (local file boundary, mostly adversarial)**: producers (the verify CLI, the KMP client) drop signed CEG objects as files under `~/ciris/ceg/outbox/<kind>/<id>.json`; CIRISServer drains, verifies, and relays them. An attacker with write access to the outbox directory could (a) inject a forged object, (b) overwrite a pending object, or (c) attempt a path-traversal `kind`/`id` to escape the outbox.

**Primary mitigation**: the outbox is a **transport, not a trust root** — by design CIRISServer re-verifies the bound hybrid signature on every drained object before it calls the substrate, and CIRISPersist is signature-blind (the substrate's merge logic never counts signatures). An injected or overwritten object without a valid bound hybrid signature (Ed25519 + ML-DSA-65) under a directory-pinned `key_id` is rejected at relay — the file drop confers no authority. A self-signed object (a genesis `KeyRecord`) carries its signature inside `body`; a signed-request object carries it in `signatures` (the `x-ciris-*` header mapping).

**Secondary**: `ceg_outbox::sanitize` reduces every `kind`/`id` to a single path segment (anything outside `[A-Za-z0-9._-]` → `_`), so no `..` or separator survives — a traversal `kind`/`id` cannot escape the outbox (proven by `sanitize_blocks_path_traversal_and_separators`). The same sanitizer guards the CLI's ML-DSA seed-file path.

**Residual**: filesystem ACLs on the `ciris/` root are the local boundary — an attacker with the user's own write permission can still *delete* a pending object (a local availability denial, not a forgery). The outbox is explicitly not a confidentiality or integrity trust anchor; CIRISServer's signature re-check is.

#### AV-44: Software PQC-half seed extraction (honest hardware-boundary disclosure)

**Attack surface (at-rest key material)**: the "hardware-rooted" federation identity is **hybrid** — the Ed25519 (classical) half is sealed in the YubiKey / Secure Enclave / StrongBox / TPM, and the ML-DSA-65 (PQC) half is a 32-byte seed whose *signing* is software (no token/TPM/SE can perform ML-DSA-65 signing — no PQC HSM exists as of 2026). The threat is extraction of that PQC seed at rest.

Stated honestly rather than overclaimed: "hardware-rooted" means the *classical* owner-binding half cannot be extracted (AV-1 / AV-13 hold for that half). The PQC half's seed is **sealed at rest** — `identity create` and the FFI route the ML-DSA-65 half through `get_platform_sealed_mldsa65_signer` (`SealedMlDsa65Signer`): the seed is sealed by the platform secure storage — **TPM-sealed through the runtime-loaded TPM plugin on a TPM host, Secure Enclave / StrongBox on mobile, or a software AES-GCM-sealed blob (derived key) as the fallback — never a plaintext file**. It is fail-secure-CSPRNG-generated (AV-39 latch honored) and unsealed only transiently in memory to sign.

**Primary mitigation**: the hybrid bound-signature property means recovering the PQC seed **alone** does not forge an accepted signature — a forger also needs the hardware Ed25519 half, which is non-extractable. So AV-44 in isolation is a *PQC-downgrade* threat (it removes the post-quantum leg for this identity), not an immediate forgery: it reduces this identity's signatures to classical-only strength until the seed is rotated.

**Secondary**: TPM/SE sealing binds the seed blob to the hardware tier (it cannot be unsealed off-box). Without a TPM (or without the TPM plugin) the seal is a software AES-GCM blob under a derived master key — weaker than hardware, but still not a plaintext seed.

**Residual (open)**: *signing is software* — the seed is unsealed into process memory to produce each ML-DSA-65 signature, so a privileged attacker who can read the live process memory **at signing time** could capture the seed (a much higher bar than reading a file at rest). This is the irreducible boundary until a PQC-capable HSM/token ships; the seed is otherwise hardware-sealed at rest.

#### AV-45: Lost/stolen-device revocation with the compromised key (surviving-key requirement)

**Attack surface (revocation authorization, not propagation)**: when a device (occurrence) is lost or stolen, the owner revokes it via `sign_occurrence_revocation` (CEG §11.7.1 Option-A forward-secrecy removal). The §11.7.4 vouch is single — "the revoking occurrence OR the `identity_key_id`". If the owner's identity has **only one** enrolled key, that key is the stolen one, and there is no *surviving* key to authorize the revocation.

**Primary mitigation**: revocation must be signed by a **surviving** key — a *different* enrolled occurrence or the identity root, never the compromised key. This is the concrete reason the OR-of-N multi-hardware-key redundancy (`UserIdentityKeyset`) is a **prerequisite**, not a nicety. The bound hybrid revocation signature verifies at threshold 1 against the *revoker's* directory-pinned pubkeys (the `threshold` primitive), so Registry/Server authenticate that the revocation came from a surviving key before writing the row through to Persist (whose merge logic never counts signatures, §5.6.8.13). The producer permits `revoker == revoked` for a *voluntary* leave, but the stolen-device flow MUST use a different key (proven by `revocation_does_not_bind_to_a_forged_revoker_key_id`).

**Secondary**: once authorized, the revocation propagates under the R1 timeliness contract and "most recent observed revocation wins" merge (the AV-4 anti-rollback discipline). AV-45 is the *authorization* half; R1 (FEDERATION_THREAT_MODEL §3.3 Gap A) is the *propagation* half.

**Residual**: an owner who enrolled exactly one key and lost it has no surviving key to revoke with and must fall back to out-of-band recovery — the correct security tradeoff (a single-key identity cannot self-heal), and the standing argument for enrolling ≥2 hardware keys at onboarding.

---

## 4. Mitigation Matrix

| AV | Attack | Primary Mitigation | Secondary | Status |
|---|---|---|---|---|
| AV-1 | Code fork / license-check removal | Hardware-bound signing key | Binary integrity check | ✓ Mitigated |
| AV-2 | Runtime modification | Binary self-integrity + anti-debug | Platform integrity checks | ✓ Mitigated |
| AV-3 | Endpoint spoofing / trust-root substitution | GenesisBundle verified per host against the baked accord holders, threshold `max(carried M, strict majority)`; highest verified version selected; equal-version split = equivocation (CC 5.3.4) | TLS (availability/confidentiality only) | ✓ Mitigated; residual: all hosts can deny service |
| AV-4 | Replay after revocation | Challenge nonce; quorum-signed `federation_revocations` rows; trust root not rollbackable; no licence honoured until CC 4.4.3.8 gate | Transparency log; monotonic revision guard | ✓ Mitigated; residual: revocation propagation (R1) |
| AV-5 | MITM attestation | Hybrid Ed25519 + ML-DSA-65 (bound), hybrid required at federation tier | Remote attestation proof export | ✓ Mitigated |
| AV-6 | Emulator/debugger interception | Platform integrity checks | Timing anomaly detection | ✓ Mitigated |
| AV-7 | Ephemeral identity storage | `HardwareSigner::storage_descriptor()` + boot-time logging | `--strict-storage` consumer flag, ephemeral-path heuristics | ✓ Mitigated |
| AV-8 | Cross-primitive identity confusion | Primitive discriminant inside hybrid-sig canonical bytes; per-primitive trusted-pubkey lookup; hybrid-required provenance chain | Pipeline standing from the substrate (delegation or accord role, FSD-006) | ✓ Mitigated |
| AV-9 | BuildManifest write-without-read | Original CI signature preserved by the registry's current POST path; release artifact `signed-build-manifests.tar.gz` | Build-manifest Contribution carries the pipeline signature | 🟡 Mitigated via release artifact / Contribution; registry GET of the original manifest is registry-side (CIRISRegistry#5) |
| AV-10 | Stale hardware-marker lockup | Stale markers detected and cleared; `HardwareNotAvailable` surfaces the recovery path | Operator runbook for marker deletion | ✓ Mitigated |
| AV-11 | Sigstore OIDC token theft | OIDC identity binding via `${workflow}@${ref}`; release notes include expected signer | Hybrid BuildManifest signature is a second trust path | 🟡 Partial — no continuous Rekor-monitor (§10 gap #2) |
| AV-12 | Maintainer compromise / XZ-style | AGPL-3.0 source review; `cargo-audit` + `cargo-deny`; hybrid sig | None — a compromised maintainer signs both halves | ⚠ **Open** — no release two-person-rule, no SBOM, no reproducible builds (§10 gaps #3-#5) |
| AV-13 | TEE.fail / DDR5 bus interposition | Assumption §6.4 (no physical access); SoC vuln detection caps to SOFTWARE_ONLY | HSM-anchored signing keys (FIPS 140-3 L3+) for production roles | 🟡 Mobile/SoC covered; server-class TEE attacks not modeled (§10 gap #7) |
| AV-14 | Cross-instance keyring contention | Persist-as-interface: one verify instance per process in persist-bearing stacks; OS-daemon serialization on reads | Cohabitation contract; same alias = same identity (PoB §3.2) | ✓ Surface absent in persist-bearing stacks; 🟡 multi-process verify-only stacks need operator pre-bootstrap |
| AV-35 | AES-GCM nonce reuse with same key | Caller-managed nonce policy (random 96-bit via `random::fill` or strict per-key counter), documented in `aes_gcm.rs` | Observed reuse triggers key rotation | ⚠ Open at library layer (caller-managed); ✓ policy documented |
| AV-36 | PBKDF2 iteration count too low | Minimum 100k iters; `iters=0` rejected as `KdfParameter` | Seed-derived masters (`derive_symmetric_key`) skip PBKDF2 | 🟡 100k floor, below OWASP 600k |
| AV-37 | HKDF context confusion | Namespacing convention `info = b"ciris-<purpose>-v<n>"` | cargo-deny bans on direct hkdf deps downstream | 🟡 Open at library layer (caller-managed); no runtime info-string registry |
| AV-38 | HMAC key reused as KDF master | Derived keys per purpose via HKDF | cargo-deny bans on direct hmac/kdf deps | ⚠ Open at library layer (caller-managed); ✓ policy documented |
| AV-39 | OsRng entropy degradation | `ciris_crypto::random` over `OsRng`; SP 800-90B startup health-check + fail-secure latch honoured by all key generation | Container/embedded entropy guidance | ✓ Server/mobile/desktop covered; 🟡 FIPS-mode + embedded hardening not done |
| AV-40 | Bypassing ciris-crypto with direct RustCrypto deps | ciris-crypto is the crypto authority; cargo-deny `[bans]` downstream | PR-time review | 🟡 Convention; no federation-wide cargo-deny baseline |
| AV-41 | Hardware-bound master derivation gap | `derive_symmetric_key` HKDF from a sealed seed, `Zeroizing` on every path | Password-derived software-master mode | 🟡 Seed sealed at rest; derivation in software |
| AV-42 | Spoofed transport-identity ↔ federation-key binding | Binding signature-covered in `FederationEnvelope`; `transport_epoch` anti-rollback; domain separation; provenance verification; subject binding + RNS dest-hash recompute | Cold first-contact rooted against the directory row, not TOFU | ✓ Mitigated; enforcement `Advisory` by default |
| AV-43 | CEG-outbox tampering / spoofed relay | Outbox is transport, not trust root — CIRISServer re-verifies every drained object; Persist signature-blind | `ceg_outbox::sanitize` single path segment | ✓ Mitigated (forgery); 🟡 local file-ACL is the availability boundary |
| AV-44 | PQC-half seed extraction | Hybrid bound signature: the ML-DSA-65 seed alone cannot forge; seed sealed at rest (TPM plugin / SE / StrongBox; software AES-GCM fallback — never plaintext); CSPRNG latch | TPM/SE seal binds the seed to the hardware tier | ✓ Sealed at rest; residual: signing is software — no PQC HSM exists |
| AV-45 | Lost/stolen-device revocation with the compromised key | Revocation MUST be signed by a surviving key; OR-of-N keyset; threshold-1 bound-hybrid verify against the revoker's pinned pubkeys | R1 propagation + "most recent revocation wins" | ✓ Mitigated (authorization); residual: single-key identities have no surviving revoker |
| AV-46 | Relayed build-attestation bundle | **Presenter binding** — bundle bound-hybrid-signed by the presenter, `attesting_key_id` MUST equal the pinned presenter member, pubkeys from the caller's directory; carried manifest hash-committed and rooted independently | Optional RFC 6962 inclusion proof must carry *this* manifest as its leaf | ✓ Mitigated. **Does NOT prove remote execution** (unprovable) — it proves an attributable, falsifiable assertion over independently-rooted evidence |
| AV-47 | **Lifted device attestation** | The attested key MUST equal the caller-pinned key (`AttestedKeyMismatch` / `KeyIdMismatch`) | Challenge binding — Android `attestationChallenge` (or explicit `GenerationOnly` policy, reported as `challenge_checked`), Apple `nonce = sha256(authData ‖ sha256(challenge))` | ✓ Mitigated (Android, Apple, TPM EK, YubiKey PIV); exercised end to end against mock vendor roots |
| AV-48 | Over-claimed hardware class | `refutes(claimed_class)` fires iff the peer claimed *stronger* custody than the chain measured | Verify emits measurements, consumers gate; absence is never a failure | ✓ Mitigated. Weight refutations heavily, passes lightly, absence not at all |
| AV-49 | Unconstrained trust anchor | **CoTS-shaped store** (`trust_anchor_store`, `draft-ietf-rats-concise-ta-stores`): `resolve(purpose, environment)` requires **both** to match | Fail-closed on omission; baked anchors digest-pinned and checked on load | ✓ Mitigated |
| AV-50 | **Delimiter injection in provenance canonical bytes** | CC 3.1.2.1 v2 canonical bytes are `sha256(JCS({…}))` — structure lives in the encoding, not in delimiters; the line-oriented v1 form (free text with no newline guard) is not emitted | CC 2.6.1.1 omit-vs-materialize; v2 golden vectors pin the JCS form | ✓ Mitigated. The accord-invocation preimage carries no attacker-controlled free text and keeps its line-oriented form |
| AV-51 | **Over-trusted anchor provenance** | `AnchorProvenance` records how each anchor was sourced (`CallerSupplied` < `CommunityAggregated` < `VendorOfficial` < `HardwareValidated`); `resolve_x509_min_provenance(purpose, environment, min)` refuses anything below a caller's bar. The 40 TPM EK roots are `CommunityAggregated` (sourced from Microsoft's `TrustedTPM.cab`, a third party to the TPM vendors) | Sourcing recorded in `docs/TPM_ANCHOR_PROVENANCE.md`; only self-signed roots baked, self-signatures cryptographically verified, expired roots excluded | ✓ Mitigated. A `VendorOfficial` demand yields nothing from the TPM set (asserted by test) |
| Audit | Audit trail tampering | Transparency log with Merkle tree, hybrid-signed heads | Append-only persistent storage | ✓ Mitigated |

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
| YubiKey PIV / PKCS#11 (external token) | 5 (Dedicated SE) | Professional | Strong when a custody attestation is presented (slot-9c attestation cert → f9 → pinned Yubico root, FIPS + touch=always → `YubiKey_5_FIPS`) | Hardware-isolated (private key never leaves the token; touch-required presence) |
| Software-Only | 1 (No hardware) | Community ONLY | None (key extractable) | None |

**Critical invariant**: `SOFTWARE_ONLY` devices are permanently capped at `UNLICENSED_COMMUNITY` tier. No license upgrade path exists without hardware security.

**YubiKey PIV note**: the canonical hardware backend for the hardware-rooted federation identity is a YubiKey in PIV mode signing **Ed25519** via `CKM_EDDSA` (`ciris_keyring::pkcs11`) — byte-identical to the software Ed25519 signer, so a token-signed binding verifies through the same threshold primitive. **Firmware ≥ 5.7 is required for PIV Ed25519**; older firmware offers only P-256 PIV (also supported, but Ed25519 is the federation default). The PIV signing slot SHOULD be **touch-required** so each federation signature is a physical-presence ceremony. Custody is proven to a remote verifier by `accord_custody_attestation`: `verify_yubikey_piv_attestation` walks the slot-9c attestation certificate through f9 and any intermediates to the pinned **Yubico Attestation Root 1**, requires the attested key to equal the holder's federation Ed25519 key, and requires the FIPS and touch=always extensions. A verified attestation converts to `PlatformAttestation::ExternalSecureElement`. This is orthogonal to AV-44: the token holds the Ed25519 half; the ML-DSA-65 PQC half is a sealed-at-rest seed (TPM/SE/StrongBox, software-sealed fallback).

---

## 5.1 Known Hardware Vulnerabilities

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

**`boundary_degraded` vs `hardware_trust_degraded` — two orthogonal signals**: a CVE-degraded device like the above is the **forced/involuntary** case — hardware was expected and is compromised → `hardware_trust_degraded = true`. This is distinct from the **software-baseline** case — no secure element is present at all (community / pure-software mode) → `boundary_degraded = true`. The two never both apply to one condition:

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

1. **HSM integrity**: Hardware security modules (TPM 2.0, Secure Enclave, Android Keystore/StrongBox, YubiKey) are not compromised at the hardware level
2. **Accord-holder keys**: Fewer than a strict majority of the baked HUMANITY_ACCORD holders' keys are compromised (the GenesisBundle authorization threshold)
3. **Trust-root reachability**: At least one trust-root host serving a verifiable GenesisBundle is reachable; otherwise the module stays in community mode
4. **Physical security**: Adversary does not have physical access to the deployment hardware (physical access can bypass most HSM protections)
5. **Clock accuracy**: System clocks are reasonably synchronized (within 5 minutes of actual UTC time)

---

## 7. Fail-Secure Degradation

All failures degrade to MORE restrictive modes, never less:

| Failure Condition | Resulting Mode | Rationale |
|-------------------|---------------|-----------|
| Binary integrity check failed | LOCKDOWN | Possible active tampering |
| Trust-root equivocation (two verified bundles at one version) | RESTRICTED | Possible attack on the trust root |
| Rollback detected | RESTRICTED | Possible replay attack |
| No trust-root host reachable, or none verifies | COMMUNITY | No trust root selected |
| No honoured licensure row (CC 4.4.3.8; the gate is not implemented) | COMMUNITY | No licence |
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
| AV-3 | License Fraud | All hosts can deny service; forging a root needs a strict majority of the baked accord-holder keys |
| AV-4 | License Fraud | A revocation not yet received at a node cannot take effect there (R1 propagation) |
| AV-5 | License Fraud | Requires breaking Ed25519 AND ML-DSA-65 simultaneously |
| AV-6 | License Fraud | Hypervisor-level intercepts that hide from in-VM checks; defense-in-depth via downstream sig verify |
| AV-7 | Federation Identity | Operator override (`CIRIS_PERSIST_KEYRING_PATH_OK=1`); consumer ignoring the descriptor |
| AV-8 | Federation Identity | A pipeline key without substrate standing cannot root its manifests (fails closed) |
| AV-9 | Build Provenance | Per-primitive attribution read from the release artifact or Contribution until the registry serves the original manifest |
| AV-10 | Operational | Identity continuity loss after hardware-key recovery; correct security tradeoff |
| AV-11 | Supply Chain | No continuous Rekor-monitor on CIRIS identity (action: §10 gap #2) |
| AV-12 | Supply Chain | No two-person-rule, SBOM, reproducible builds (actions: §10 gaps #3, #4, #5) |
| AV-13 | Hardware | Server-class TEE attacks (TEE.fail) not modeled; HSM-anchored signing keys for prod |
| AV-14 | Operational | Surface absent in persist-bearing stacks (persist holds the one verify Engine); uncommon multi-process verify-only pattern needs operator pre-bootstrap |
| AV-51 | Trust Anchors | TPM vendor roots are third-party-aggregated (`CommunityAggregated`), not vendor-official; no TPM vendor publishes a machine-fetchable root endpoint |

### 8.2 Cross-cutting residuals

These don't belong to a single AV because the failure mode crosses surfaces:

1. **Hardware supply chain compromise**: If HSM manufacturers are compromised, attestation data can be forged across all hardware-anchored AVs (1, 5, 13). Mitigation: use hardware from multiple manufacturers; monitor for HSM vulnerability disclosures; defense-in-depth via per-primitive signing-key separation.

2. **Zero-day in HSM firmware**: Undisclosed vulnerabilities in TPM/SE firmware could allow key extraction. Cross-cuts AV-1, AV-2, AV-13. Mitigation: hybrid crypto means both classical AND PQC must be broken; firmware update monitoring. CIRISVerify detects known vulnerabilities (e.g., CVE-2026-20435 on MediaTek) and degrades affected devices to `SOFTWARE_ONLY` level.

3. **Clock manipulation**: If system clock is skewed by more than 5 minutes, expiry-based protections (AV-4) and timestamp-based replay defenses weaken. Mitigation: multi-source timestamp cross-checking; NTP hardening guidance for deployments.

4. **Accord-holder key compromise** (AV-3 worst case): an adversary holding the keys of a strict majority of the baked accord holders can authorize a GenesisBundle every node accepts. Mitigation: the holders' Ed25519 keys are on touch-required YubiKey 5 FIPS tokens with custody attestations; the ML-DSA-65 halves are sealed at rest (portable USB-wrapped mode requires the token, its PIN and touch to unwrap); the roster changes only by an entrenched-family `supersedes` the prior roster's majority authorizes (FSD-004, FSD-005).

5. **Quantum computer capable of breaking both Ed25519 and ML-DSA-65** (AV-5 + AV-9 + AV-12 worst case): current quantum computers cannot break either. Hybrid approach means BOTH must fall. ML-DSA-65 provides NIST-standardized post-quantum resistance. Mitigation: algorithm agility allows future upgrades — see §10 gap #6 for the formal migration plan.

6. **Insider threat at a licensing authority**: a compromised authority in a reader's trust set could cosign licensure rows for malicious agents (once the licensure gate exists, CC 4.4.3.8). Cross-cuts AV-1, AV-12. Mitigation: a licence is honoured only through the reader's trust set, so a reader controls which authorities count; licensure rows are cosigned and audit-visible. Per-primitive signing-key separation means a compromised licensing authority cannot forge BuildManifest signatures.

---

## 9. Federation-Level Security

The build-manifest substrate (`BuildPrimitive`, `verify_build_manifest`, the `ciris-build-sign` / `ciris-build-verify` CLIs, build-manifest Contributions) introduces federation-scale threat surfaces that single-primitive thinking doesn't cover.

### 9.1 Trust topology

| Trust anchor | Held by | Used for |
|---|---|---|
| Baked HUMANITY_ACCORD holders (A1/B1/C1) | Every CIRISVerify binary (compile-time genesis) | Authorizing the GenesisBundle trust root (CC 5.3.4); the genesis-mesh rooting anchor for provenance chains |
| GenesisBundle (selected trust root) | Fetched from trust-root hosts, verified against the baked holders | The node's trust root: genesis charter, serve nodes, and the roster the substrate roots to |
| Per-primitive pipeline build-signing key | Each primitive's publishing CI; standing by delegation from an accord-rooted authority or the accord role on its key record | Signing the primitive's own `BuildManifest` / build-manifest Contribution |
| Embedded `Verify` build-manifest pubkey | CIRISVerify binary (compile-time constant) | Self-check: validating CIRISVerify's own runtime against its signed manifest (recursive golden rule) |

### 9.2 Trust rotation requirements

- **Trust-root rotation:** a new GenesisBundle `version` authorized by the accord quorum; every node selects the highest verified version without recompiling.
- **Accord roster change:** an entrenched-family `supersedes` authorized by the prior roster's strict majority (FSD-004, FSD-005). Changing the baked roster itself requires a binary release.
- **Pipeline key rotation:** `supersedes` on the grant (past claims keep standing); compromise is `withdraws` (FSD-006).
- **Algorithm rotation (PQC migration):** a successor algorithm is an enum variant plus a policy change (`HybridSignature::meets_federation_policy()`); the migration protocol is `docs/CRYPTO_AGILITY.md`.

### 9.3 Open federation issues

- **AV-9 registry read path** — the registry-mediated legacy read path does not preserve per-primitive attribution (CIRISRegistry#5). Workaround: release artifact or Contribution.
- **Confused deputy across primitives** — verify-side defenses are the primitive in canonical bytes plus a separate trusted pubkey per primitive; registry-side enforcement of "manifest signature must match primitive" belongs to the same registration path.

---

## 10. SOTA Gaps and Roadmap

Gaps against current best practice in software-supply-chain attestation. None are exploitable today against CIRISVerify's documented adversary model, but each closes residual risk that the wider industry is moving on.

### Gap 1: SLSA level not declared

**SOTA**: SLSA v1.2 with L3 (hardened build platform, unforgeable provenance signed by the platform) as the credible bar for federation peers; L4 (reproducible builds) increasingly the gating definition.

**CIRISVerify position**: Effective ~SLSA L2 today (signed provenance via Sigstore + GitHub Actions OIDC, build platform is GitHub-hosted runner). L3 requires us to claim the build platform's hardening explicitly and publish provenance attestations (in-toto). L4 requires reproducible builds, which Cargo's release profile (`lto=true`, `codegen-units=1`, `panic="abort"`, `strip=true`) approximates but doesn't guarantee bit-for-bit.

**Action**: declare an SLSA L3 target; publish in-toto attestations alongside release artifacts; reproducible builds as separate work (Gap 4).

### Gap 2: No continuous Rekor identity monitoring

**SOTA**: `rekor-monitor` watches for unexpected signing events under a configured OIDC identity. Canonical post-XZ defense for Sigstore-era supply chain.

**CIRISVerify position**: We sign with Sigstore, log to Rekor, but don't monitor the log for rogue entries under our identity. A stolen OIDC token would produce a correctly-Rekor-logged malicious binary that consumers' verify checks pass.

**Action**: integrate `rekor-monitor` against `https://github.com/CIRISAI/CIRISVerify/...` identity, alarm to maintainers on unexpected entries.

### Gap 3: No SBOM in releases

**SOTA**: SPDX 3.0 + CycloneDX 1.6 dual format; CISA minimum elements (component hash, license fields); EU CRA mandate by Dec 2027.

**CIRISVerify position**: No SBOM published. Downstream operators have no machine-readable enumeration of our transitive Rust dependencies — exactly the attack surface a `cargo`-based XZ-equivalent would exploit.

**Action**: `cargo-cyclonedx` integration in release workflow; publish both SPDX + CycloneDX as attached attestations; document how to verify the SBOM signature against the pipeline build-signing key.

### Gap 4: No reproducible builds

**SOTA**: Reproducible-builds.org standards; bit-for-bit reproducibility as the only systemic defense against source-vs-binary divergence (XZ-class attacks).

**CIRISVerify position**: Release builds from GitHub-hosted runners with deterministic-ish flags but not verified bit-for-bit. A maintainer with CI access could release a binary that doesn't match the source.

**Action**: Cargo build-info determinism work + cross-rebuilder verification (e.g., a separate trusted rebuilder on independent infrastructure).

### Gap 5: No two-person-rule on releases

**SOTA**: Multi-maintainer signoff for critical projects (OpenSSF Critical Project framework). XZ-3094 demonstrated single-maintainer trust is insufficient.

**CIRISVerify position**: Single-maintainer release path. A compromised maintainer or stolen GitHub token can publish a release that passes all automated checks.

**Action**: GitHub branch protection requiring 2+ approvers on release-tag-creating PRs; a two-operator key-ceremony procedure for pipeline build-signing key rotation.

### Gap 6: PQC algorithm-agility plan — ✓ closed

**SOTA**: NIST IR 8547 deprecation timeline (quantum-vulnerable algos by 2035); algorithm-agility patterns mandate config-not-code rotation.

**Resolution**: the hybrid schema is algorithm-agile — every signature is self-describing (`crypto_kind` + tagged `ClassicalAlgorithm` + tagged `PqcAlgorithm` + `SignatureMode`), and `PqcAlgorithm` enumerates ML-DSA-44/65/87 **and SLH-DSA-128s/256s** (FIPS 205 hash-based fallback). A successor algorithm is an enum variant plus a policy decision, never a wire-format break. `HybridSignature::meets_federation_policy()` is the single agility gate, and `docs/CRYPTO_AGILITY.md` specifies the migration protocol (additive accept → emit → retire, with transparency-log history staying verifiable under retired algorithms).

### Gap 7: Server-class TEE attacks not modeled

**SOTA**: TEE.fail (Oct 2025, Georgia Tech / Purdue, sub-$1k) breaks Intel SGX/TDX and AMD SEV-SNP via DDR5 bus interposition. PSA Level-3 RoT IP with SCA + fault-injection resistance is the new bar.

**CIRISVerify position**: Mobile/SoC vulnerability detection caps attestation to SOFTWARE_ONLY for known-bad chips. Server-class TEEs (used by registry-side, by federation peers running confidential VMs) are NOT modeled. A TEE.fail-equivalent against a registry validator could extract its signing keys.

**Action**: registry-side item (CIRISRegistry threat model); CIRISVerify's recommendation is HSM-anchored signing keys for production registry and pipeline roles, not TEE-anchored.

---

### Peer comparison

With ciris-crypto as the federation crypto authority, the question "where do we sit relative to peers in the same shape?" is load-bearing. Peers are not direct competitors — most occupy adjacent niches — but each illustrates an axis of the design space we should know our position on.

| Peer | Niche | What we cover that they don't | What they cover that we don't | Our position |
|------|-------|-------------------------------|-------------------------------|--------------|
| **Sigstore + Cosign + Rekor** | Software-supply-chain signed-build attestation via OIDC + transparency log | Hybrid PQC signing, hardware-bound runtime identity, runtime tree-walk verification, license tier enforcement, hardware vuln detection | Continuous Rekor monitoring (Gap 2), keyless OIDC ephemeral signing, federated transparency log peers | Adjacent — we already use Sigstore for the build attestation layer; Rekor monitoring is the residual we know we need to close. |
| **TUF (The Update Framework)** | Hierarchical metadata signing for software updates with role separation (root/targets/snapshot/timestamp) | Hardware-rooted device identity, runtime integrity verification, federation policy enforcement, hybrid-PQC signing | Multi-role signing with key-rotation safety, threshold signatures within roles, freeze-before-publish ordering | Adjacent — the accord's M-of-N GenesisBundle authorization is a root role in TUF's sense; release signing is still a single-role signer. |
| **in-toto + SLSA** | Supply-chain provenance attestation framework | Hybrid-PQC signed provenance, runtime integrity, hardware-rooted identity, license tier integration | Reproducible builds (Gap 4), formal SLSA L3+ attestation (Gap 1), step-by-step build-graph attestation | Adjacent — we partially implement (SLSA L2 effective); SLSA L3 + reproducibility are open (Gaps 1, 4). |
| **Keylime** | Linux/TPM remote attestation runtime with continuous-attestation policy engine | Mobile attestation (Android Keystore, iOS Secure Enclave), hybrid-PQC signing, license tier integration, runtime tree verifier | IMA boot-time integrity policy, continuous-attestation event stream, OpenStack/Kubernetes integration | Cousin — Keylime is the closest analog for runtime integrity on Linux/TPM. We're broader (mobile) but they're deeper on Linux server-class. |
| **Veilid** | Mesh-network identity + crypto authority + DHT addressing | License tier enforcement, build-manifest provenance, runtime tree-walk verification, hybrid-PQC | DHT-based naming, Veilid-protocol-specific transports, BLAKE3-based identity | Upstream — `keyring-manager` pattern explicitly extends Veilid (see CLAUDE.md). Not competitors; we adopt their patterns where they fit. |
| **Reticulum** | Mesh-transport with native link encryption + identity (X25519 + Ed25519 + AES-256-CBC) | Application-substrate primitives, build attestation, federation policy | Link-layer encryption, mesh routing, addressing-IS-identity at the transport layer | Substrate / transport split — CIRISEdge integrates Reticulum-rs for transport (per `CIRISEdge/FSD/CIRIS_EDGE.md` §AV-15: "edge does not add a third encryption layer"); we're substrate, they're transport. No overlap. |
| **Signal Protocol / libsignal** | E2E messaging with forward secrecy + post-compromise security via Double Ratchet | Federation substrate primitives, hardware identity, build attestation, license tier enforcement | Forward-secret session establishment, Double Ratchet for post-compromise security, X3DH key agreement | Different threat model — Signal is 1:1 + groups with PFS/PCS as the headline; we're substrate-attestation with hybrid signing as the headline. We ship hybrid X25519 + ML-KEM-768 KEX primitives (`hybrid_kex`, `transit_kex`, `key_grant`), not a ratchet. |
| **Matrix Olm/Megolm** | Federation E2E messaging + key transparency | Federation substrate, hardware-bound identity, build attestation | Key-transparency log (different model than build-manifest log), cross-signing for device ownership | Different model — Matrix's KT proves "this device belongs to this user"; ours proves "this binary was signed by this build authority." |
| **FIDO2 / WebAuthn** | Hardware-bound user authentication with attestation | Federation substrate, hybrid-PQC, build attestation, runtime integrity | Browser/WebAuthn integration, Resident Keys, Discoverable Credentials, attestation chain to known root CAs | Adjacent — same hardware identity primitive at a different layer. WebAuthn is user → service; we're agent → federation. Same TPM/SE/StrongBox underneath. |

### What this comparison says about our position

- **Build attestation tier**: we're broadly comparable to Sigstore/in-toto/SLSA but lag on continuous monitoring (Gap 2) and reproducibility (Gap 4).
- **Runtime integrity tier**: comparable to Keylime on Linux + broader by covering mobile. No peer covers desktop/server/mobile in one substrate the way verify_tree does.
- **Federation crypto authority tier**: no direct peer with the same "single audit point for federation primitives" framing. Closest analog is Veilid's `keyring-manager` (which we extend) — but Veilid is a mesh substrate, not a federation crypto authority.
- **Identity tier**: TPM/SE/StrongBox bindings are commodity (FIDO2/Veilid/Keylime/etc all use the same hardware roots); our differentiator is the hybrid-PQC binding on top.
- **Transport tier**: explicitly out of scope — delegated to CIRISEdge + Reticulum-rs. We don't compete with Signal/Matrix/Reticulum on the wire.

The federation crypto authority framing is the differentiator. No peer is doing exactly this combination — most do one or two of the tiers; none do all five (build + runtime + identity + symmetric authority + license enforcement) in one substrate.

---

## 11. Federation Role Coverage

The federation expects CIRISVerify to be the **substrate-level crypto authority** — every primitive that needs cryptographic operations routes through this crate.

### 11.1 Covered

- ✅ **Hybrid signing** (Ed25519 + ML-DSA-65 with bound classical-inside-PQC signatures) — `HybridSigner`/`HybridVerifier`; PQC binding tested against signature-stripping attacks; Ed25519 verification strict by default.
- ✅ **Accord-authorized trust root** (CC 5.3.4) — `genesis_bundle::verify_genesis_bundle` against the baked holders, `select_trust_root` (highest version, equivocation detection).
- ✅ **Hardware-bound identity** (TPM 2.0 via the runtime-loaded plugin, Android Keystore / StrongBox, iOS Secure Enclave, YubiKey PIV over PKCS#11, software fallback) — `HardwareSigner` trait, `StorageDescriptor` for transparency about identity material location.
- ✅ **Build attestation** (BuildManifest validator, function-level integrity, file-tree integrity, multi-target sign + register, build-manifest Contributions, wheel identity check) — registry round-trip locked by post-release-verify CI; Sigstore + GitHub Actions OIDC for CI signing; `BuildManifest::to_attestation_entries` emits `provenance:build_manifest:{target}:v1`.
- ✅ **Runtime integrity** (`verify_tree`, Algorithm A shared with `ciris-build-sign sign --tree`, missing/extra/mismatch verdicts) — Python FFI exposed; live-registry CI gate.
- ✅ **License tier enforcement + mandatory disclosure** — `LicenseEngine`, fail-secure degradation (LOCKDOWN / RESTRICTED / COMMUNITY), capability gating against `PROHIBITED_CAPABILITIES`. Every deployment is community until the licensure-row gate (CC 4.4.3.8).
- ✅ **Federation symmetric authority** — AES-256-GCM (with and without AAD), XChaCha20-Poly1305, PBKDF2, HKDF, HMAC, OsRng — single audit point. NIST GCM + RFC 5869 + RFC 4231 vectors locked.
- ✅ **Key exchange** — X25519 + ML-KEM-768 hybrid KEX, `key_grant` DEK wrap, HPKE over X-Wing, the A/V per-hop transit key.
- ✅ **Wallet signing** (secp256k1 EVM, EIP-155 field-level transaction construction, EIP-712, address recovery).
- ✅ **Hardware vulnerability detection** (CVE-2026-20435 MediaTek, CVE-2026-21385 Qualcomm) — caps attestation to SOFTWARE_ONLY for known-bad chips.
- ✅ **Device attestation** — Android Key Attestation, Apple App Attest, TPM 2.0 EK, YubiKey PIV, each to a pinned vendor root in a CoTS-shaped constrained store (AV-47..AV-49, AV-51).
- ✅ **Authenticated transport-identity binding (AV-42)** — `FederationEnvelope`, `federation_keys` provenance verifier, `EnvelopeVerifyPolicy::RequireTransportBinding`, deterministic `derive_transport_identity`.
- ✅ **M-of-N threshold-signature verifier** — `verify_threshold_signatures` over hybrid signatures; used by founder quorum, partner-record quorum, keyset rotation and the accord.
- ✅ **Scalar-attestation surface** — `federation_provenance` carries `AttestationEntry { dimension, score, attester, source_ref }` measurements; the response composes no verdict (the §1.4 authentication ≠ trust invariant). `AttestBundle` projects the same data into named measurement fields; tier mapping is consumer policy.
- ✅ **Transparency-log witness cosigning receiver** — `SignedTreeHead::cosign`, `TrustedWitness`, `witness_quorum_met`; cosignatures count only with a verifying `WitnessConsistencyProof`.
- ✅ **Typed error envelope** — `ceg_error::CegErrorCode` stable wire codes + `CegError` with `From<VerifyError>`.
- ✅ **Full-SHA verification before consumption** — `holds_bytes::verify_holds_bytes` enforces canonical hex before hashing and compares digests constant-time, closing the prefix-collision class.
- ✅ **Canonicalization discipline** — RFC 8785 JCS (`jcs`), `check_canonical_rfc3339`, `check_canonical_hex64`, `canonical_subject` (CC 2.3.2.1).

### 11.2 Deferred / Roadmap (scheduled work, not blind spots)

- ⏳ **Reproducible builds** (Gap 4) — targets dropping the "trust the GitHub Actions runner" residual to "trust two independent rebuilders agreeing." Cargo determinism work + cross-rebuilder verification.
- ⏳ **SBOM publishing** (Gap 3) — `cargo-cyclonedx` integration. SPDX 3.0 + CycloneDX 1.6 dual format per CISA minimum elements + EU CRA Dec 2027 mandate.
- ⏳ **Continuous Rekor monitoring** (Gap 2) — `rekor-monitor` against CIRISVerify's identity, alarm on rogue entries.
- ⏳ **Two-person release rule** (Gap 5) — branch protection requiring 2+ approvers on release-tag-creating PRs; two-operator key ceremony for pipeline key rotation.
- ✓ **PQC algorithm-agility** (Gap 6) — `HybridSignature::meets_federation_policy()` + `docs/CRYPTO_AGILITY.md`.
- ⏳ **In-hardware symmetric derivation** (AV-41) — derivation is HKDF in software from a sealed seed.
- ⏳ **PBKDF2 iteration bump** (AV-36) — 100k → 600k+.
- ⏳ **Licensure-row gate** (CC 4.4.3.8) — until it exists, no deployment is licensed.

### 11.3 Out of scope by design (boundary defense, not omission)

These are NOT gaps. They are deliberate boundary choices respecting adjacent primitives' domains:

- ❌ **Ratcheted session protocols** (Double Ratchet, MLS) — verify supplies KEX and AEAD primitives and the STREAM chunk nonce (`stream_seal`); session and group protocols belong to CIRISEdge and the transport (CIRISEdge `FSD/CIRIS_EDGE.md` §AV-15).
- ❌ **Aggregate signature schemes** (FROST, BLS aggregation) — not in scope. A **generic M-of-N over hybrid singletons** (`verify_threshold_signatures`, §11.1) meets the keyset-rotation and accord demand. True signature aggregation (one short signature standing in for N) requires either pairing-based BLS or schnorr-only FROST; neither maps cleanly onto the hybrid Ed25519 + ML-DSA-65 contract. Deferring matches the demand-driven principle — no consumer needs sub-linear signature size today.
- ❌ **Zero-knowledge proofs / homomorphic encryption** — speculative; no concrete privacy-preserving attestation use case in the federation today. HE is 100-1000× overhead at the state of the art; not federation-ready.
- ❌ **Application-layer transport** — that's CIRISEdge's role over Reticulum (leviculum) and its other transports. We're substrate; they're transport. Different layer, different ownership.
- ❌ **Operator UX for manual verification** — the client (KMP, `CIRISAgent/client`) and CIRISServer's routes. We expose machine-readable attestation.

### 11.4 Net assessment

**Federation crypto-authority role is covered.**

The deferred items (§11.2) are scheduled work or dependency-blocked, not blind spots — each carries an action item here. The out-of-scope items (§11.3) are intentionally bounded to respect adjacent primitives' domains; reaching into them would over-step into CIRISEdge / CIRISServer / CIRISRegistry territory.

The **largest residual** is reproducible builds (Gap 4). Until two independent rebuilders agree, "the binary matches what GitHub Actions built" is an undeclared trust assumption inherited from CI. This is the single remaining axis where the SOTA peer comparison (§10) shows us trailing — Sigstore's Rekor + reproducibility patterns are mature; we're committed to the target but haven't shipped.

The **second residual** is multi-operator release controls (Gap 5). XZ-3094 demonstrated single-maintainer trust is insufficient for substrate-level dependencies. Branch protection + key ceremony are tractable; just need the operator coordination.

Where the federation could push us further (if the substrate threat model evolves):

- **Aggregate-signature primitive** (BLS / FROST) if some federation operation needs sub-linear signature size at scale — generic M-of-N hybrid singletons cover today's demand (§11.3 #3).
- **In-hardware symmetric derivation** where a platform offers it (§11.2).
- **FIPS-mode RNG draws** if FedRAMP / CMMC compliance becomes a federation requirement (AV-39 secondary).
- **Production population of the scalar-attestation surface** depends on downstream emitters: CIRISRegistry (`provenance:slsa:{level}` / `cert_validity:{authority}` emission + STH witness cosigning endpoint) and CIRISAgent (periodic `run_attestation` + bundle surfacing). The verify-side receivers exist.

---

## 12. Update Cadence

This threat model is updated whenever:

- A new feature exposes a new surface.
- A SOTA review identifies an industry-recognized gap.
- A real-world incident in a CIRIS deployment surfaces a class not yet catalogued.
- A new producer or transport surface is added.

Every edit records a changelog line (the `Last updated` stamp) and passes the CODEOWNERS two-person rule.

**Companion documents:**
- [`FSD/FSD-001_CIRISVERIFY_PROTOCOL.md`](../FSD/FSD-001_CIRISVERIFY_PROTOCOL.md) — protocol spec
- [`docs/BUILD_MANIFEST.md`](BUILD_MANIFEST.md) — build-manifest schema and CLI usage
- [`docs/BENCHMARKS.md`](BENCHMARKS.md) — performance baselines feeding the regression-gate threat assumption
