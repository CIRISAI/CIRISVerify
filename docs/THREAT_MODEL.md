# CIRISVerify Threat Model

## 1. Scope

### What CIRISVerify Protects

CIRISVerify is the hardware-rooted license verification module for the CIRIS ecosystem. It protects against:

- **Identity fraud**: Unlicensed agents (CIRISCare) masquerading as licensed professional agents (CIRISMedical, CIRISLegal, CIRISFinancial)
- **License forgery**: Fabrication of valid-looking license status without registry authority
- **Capability escalation**: Agents claiming capabilities beyond their license tier
- **Silent degradation**: Agents suppressing or modifying mandatory disclosure about their license status
- **Verification tampering**: Modification of the verification binary to return false results

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

Six primary attack vectors identified in FSD-001:

### AV-1: Code Forking / License Check Removal

**Attack**: Fork the open-source code, remove license checks, deploy as "licensed" agent.

**Mitigation**: Hardware-bound signing key. The verification response is signed by a key stored in the device's HSM. A forked binary cannot produce valid signatures because it lacks the hardware key. The key IS the identity — it cannot be copied from the source code.

### AV-2: Runtime Modification to Fake Licensed Status

**Attack**: Modify the running binary in memory to return fake "licensed" status.

**Mitigation**: Binary self-integrity verification at startup (hash comparison). Anti-debugging detection (ptrace, Frida, Xposed). Platform integrity checks (root/jailbreak detection). All checks return opaque pass/fail to prevent targeted bypasses.

### AV-3: Verification Endpoint Spoofing

**Attack**: Intercept and replace responses from verification endpoints.

**Mitigation**: Multi-source validation with consensus. DNS US + DNS EU + HTTPS API must agree (2-of-3 minimum). HTTPS is authoritative when reachable; DNS is advisory cross-check. Multiple HTTPS endpoints at different domains provide redundancy. Certificate pinning on HTTPS connections.

### AV-4: Replay of Old Valid License After Revocation

**Attack**: Capture a valid license response before revocation, replay it afterward.

**Mitigation**: Anti-rollback monotonic revision enforcement. The system tracks the highest-seen revocation revision and rejects any revision that decreases. Challenge nonce (32+ bytes) prevents simple replay. License expiry timestamps provide time-based bounds.

### AV-5: Man-in-the-Middle Attestation Responses

**Attack**: Intercept attestation responses and modify them to claim higher trust level.

**Mitigation**: Hybrid cryptographic signatures (Ed25519 + ML-DSA-65) over all response data. PQC signature is bound to classical signature (covers `challenge_nonce || classical_sig`), preventing signature stripping. Remote attestation proof export allows third parties to independently verify hardware binding.

### AV-6: Emulator/Debugger Interception

**Attack**: Run the agent in an emulator or attach a debugger to intercept and modify verification responses at runtime.

**Mitigation**: Platform-specific integrity checks detect emulators (Android: goldfish, qemu; iOS: simulator; Desktop: hypervisor/DMI checks). Debugger detection (ptrace on Linux/Android, sysctl on macOS, IsDebuggerPresent on Windows). Hook detection for Frida/Xposed frameworks. Timing anomaly detection for breakpoint-induced delays.

---

## 4. Mitigation Matrix

| Attack Vector | Primary Mitigation | Secondary Mitigation | Fix Reference |
|---------------|-------------------|---------------------|---------------|
| AV-1: Code fork | Hardware-bound signing key | Binary integrity check | Existing |
| AV-2: Runtime modification | Binary self-integrity + anti-debug | Platform integrity checks | Existing |
| AV-3: Endpoint spoofing | HTTPS authoritative + multi-source consensus | Certificate pinning | Fix 4 |
| AV-4: License replay | Anti-rollback monotonic revision | Challenge nonce + expiry | Fix 2 |
| AV-5: MITM attestation | Hybrid crypto (Ed25519 + ML-DSA-65) | Remote attestation proof export | Fix 3 |
| AV-6: Emulator/debugger | Platform integrity checks | Timing anomaly detection | Existing |
| Audit trail tampering | Transparency log with Merkle tree | Append-only persistent storage | Fix 1 |

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
| Software-Only | 1 (No hardware) | Community ONLY | None (key extractable) | None |

**Critical invariant**: `SOFTWARE_ONLY` devices are permanently capped at `UNLICENSED_COMMUNITY` tier. No license upgrade path exists without hardware security.

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

## 8. Residual Risks

Risks that CIRISVerify mitigates but cannot fully eliminate:

1. **Hardware supply chain compromise**: If HSM manufacturers are compromised, attestation data can be forged. Mitigation: use hardware from multiple manufacturers; monitor for HSM vulnerability disclosures.

2. **Zero-day in HSM firmware**: Undisclosed vulnerabilities in TPM/SE firmware could allow key extraction. Mitigation: hybrid crypto means both classical AND PQC must be broken; firmware update monitoring. **Note**: CIRISVerify v1.2.0+ actively detects known vulnerabilities (e.g., CVE-2026-20435 on MediaTek) and degrades affected devices to `SOFTWARE_ONLY` level.

3. **Physical access attacks on vulnerable SoCs**: Some chipsets (e.g., MediaTek Dimensity with CVE-2026-20435) have boot ROM flaws that allow key extraction via electromagnetic fault injection in under 45 seconds. Mitigation: CIRISVerify detects affected chipsets and caps attestation. Users should avoid these devices for high-security deployments.

4. **Clock manipulation**: If system clock is skewed by more than 5 minutes, expiry-based protections weaken. Mitigation: multi-source timestamp cross-checking; NTP hardening guidance for deployments.

5. **All verification sources compromised simultaneously**: If attacker controls all DNS registrars AND HTTPS endpoints, false consensus can be achieved. Mitigation: sources are in different jurisdictions (US/EU) with different registrars; transparency log provides after-the-fact audit capability.

6. **Quantum computer capable of breaking both Ed25519 and ML-DSA-65**: Current quantum computers cannot break either. Hybrid approach means BOTH must fall. ML-DSA-65 provides NIST-standardized post-quantum resistance. Mitigation: algorithm agility allows future upgrades.

7. **Insider threat at license issuing authority**: A compromised steward could issue valid licenses to malicious agents. Mitigation: transparency log records all issuance events for audit; multi-party authorization for license issuance (registry-side control).
