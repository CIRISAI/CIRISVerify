# CIRISVerify: Standards Comparison and PQC Implementation

**Version**: 2.0
**Date**: 2026-01-25
**Author**: CIRIS L3C
**Cryptographic Baseline**: Ed25519 + ML-DSA-65 (Hybrid Mode)

## Executive Summary

This document compares CIRISVerify's design against existing industry standards for hardware attestation, license verification, and remote integrity verification. **CIRISVerify launches with hybrid cryptography (Ed25519 + ML-DSA) as its day-1 standard**, implementing NIST FIPS 204 and meeting NSA CNSA 2.0 requirements for quantum-resistant software signing.

---

## Part I: Comparison Against Existing Standards

### 1. Remote Attestation Standards

#### IETF RFC 9683/9684 (December 2024)

The IETF published [RFC 9683](https://datatracker.ietf.org/doc/rfc9683/) and [RFC 9684](https://www.rfc-editor.org/rfc/rfc9684.html) in December 2024, establishing standards for TPM-based remote attestation of network devices.

| Aspect | RFC 9683/9684 | CIRISVerify |
|--------|---------------|-------------|
| **Scope** | Network device firmware integrity | Software license + integrity |
| **Hardware** | TPM 1.2/2.0 only | TPM + Secure Enclave + Keystore |
| **Protocol** | YANG/NETCONF | Protobuf/gRPC + FFI |
| **Challenge-Response** | Yes (CHARRA) | Yes (nonce-based) |
| **Quote Mechanism** | TPM Quote primitive | Platform-specific attestation |

**CIRISVerify Alignment**:
- ✅ Uses challenge-response model (nonce prevents replay)
- ✅ Supports TPM 2.0 attestation
- ⚠️ Extends beyond TPM to mobile platforms (necessary for Android/iOS)
- ✅ Could expose YANG interface for enterprise integration

**Gap**: CIRISVerify should consider adding RFC 9684-compliant YANG interface for enterprise network integration.

#### Trusted Computing Group (TCG) Standards

The [TCG TPM 2.0 Library Specification](https://trustedcomputinggroup.org/remote-platform-integrity-attestation/) is ISO/IEC standardized and forms the foundation for hardware-rooted trust.

| Aspect | TCG TPM 2.0 | CIRISVerify |
|--------|-------------|-------------|
| **Key Storage** | Sealed to PCRs | Hardware-bound (platform-specific) |
| **Remote Attestation** | AIK-based quotes | Platform attestation + multi-source |
| **Revocation** | CRL-based | Multi-source consensus + CRL |
| **Certification** | FIPS 140-3 | Depends on platform HSM |

**CIRISVerify Alignment**:
- ✅ TPM implementation follows TCG spec
- ✅ Uses hardware-bound keys that cannot be extracted
- ➕ Adds multi-source validation (not in TCG spec)
- ➕ Adds application-layer license semantics

### 2. Mobile Attestation Standards

#### Google Play Integrity API

The [Play Integrity API](https://developer.android.com/google/play/integrity/overview) replaced SafetyNet in 2021 and provides app attestation for Android.

| Aspect | Play Integrity | CIRISVerify |
|--------|---------------|-------------|
| **Verdicts** | App, Device, Account, Play Protect | License status + integrity |
| **Hardware Binding** | Optional (MEETS_STRONG_INTEGRITY) | Required |
| **Server Dependency** | Google servers | Multi-source (no single dependency) |
| **Spoofing Resistance** | [Known bypasses exist](https://www.guardsquare.com/blog/google-play-integrity-api-app-attestation) | Multi-source + hardware binding |

**CIRISVerify Advantages**:
- ✅ No single-vendor dependency (Google)
- ✅ Multi-source validation prevents MITM
- ✅ Hardware attestation mandatory, not optional
- ✅ Works on non-Google Android (GrapheneOS, etc.)

**CIRISVerify Uses Play Integrity As**:
- Secondary signal for Android integrity
- Not primary trust anchor (too easily spoofed)

#### Apple App Attest

[App Attest](https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity) (iOS 14+) provides cryptographic attestation for iOS apps.

| Aspect | App Attest | CIRISVerify |
|--------|-----------|-------------|
| **Key Generation** | Secure Enclave | Secure Enclave |
| **Attestation** | Apple servers | Multi-source + Apple |
| **Device Binding** | Yes | Yes |
| **Offline Support** | Limited | Graceful degradation |

**CIRISVerify Alignment**:
- ✅ Uses Secure Enclave for iOS
- ✅ Incorporates App Attest assertion
- ➕ Adds multi-source validation
- ➕ Adds offline grace period

### 3. Software License Verification Standards

#### Traditional Approaches

| Approach | Strengths | Weaknesses |
|----------|-----------|------------|
| **License Keys** | Simple, offline | Easily shared/cracked |
| **Online Activation** | Revocable | Single point of failure |
| **Hardware Dongles** | Strong binding | Physical distribution |
| **Node-Locked** | Hardware bound | Inflexible |

**CIRISVerify Innovation**:
- Combines hardware binding (like dongles) with online verification
- Multi-source validation eliminates single point of failure
- Graceful degradation enables offline operation
- Cryptographic proof enables third-party verification

#### Comparison Matrix

| Feature | License Keys | Online Activation | Hardware Dongle | CIRISVerify |
|---------|-------------|-------------------|-----------------|-------------|
| **Forgery Resistance** | Low | Medium | High | High |
| **Offline Support** | Full | None | Full | Graceful |
| **Revocation** | None | Immediate | Difficult | Multi-source |
| **Third-Party Verifiable** | No | No | No | **Yes** |
| **Open Protocol** | N/A | No | No | **Yes** |

### 4. Code Signing and Attestation

#### CSR Attestation (IETF Draft)

The [IETF CSR Attestation draft](https://www.ietf.org/archive/id/draft-ietf-lamps-csr-attestation-08.html) defines how to include attestation evidence in certificate signing requests.

**Relevance to CIRISVerify**:
- CIRISVerify could issue attestation that integrates with PKI
- License status could be embedded in X.509 extensions
- Third parties could verify license status via certificate

**Future Enhancement**: Consider adding X.509 certificate issuance for licensed deployments.

### 5. Confidential Computing

#### Intel TDX / AMD SEV-SNP

Modern confidential computing relies on hardware-controlled Roots of Trust inherently bound to specific CPU vendors.

| Aspect | Intel TDX/AMD SEV | CIRISVerify |
|--------|-------------------|-------------|
| **Trust Root** | CPU vendor | Multi-source + hardware |
| **Attestation** | Vendor-specific | Platform-agnostic |
| **Memory Protection** | Encrypted enclaves | N/A (different scope) |

**CIRISVerify Position**:
- Not competing with confidential computing
- Could run *inside* confidential computing environment
- Adds application-layer license semantics on top

---

## Part II: Post-Quantum Cryptography Implementation

### NIST PQC Standards (Finalized August 2024)

NIST published three finalized PQC standards:

| Standard | Algorithm | Purpose | CIRISVerify Status |
|----------|-----------|---------|-------------------|
| [FIPS 203](https://csrc.nist.gov/news/2024/postquantum-cryptography-fips-approved) | ML-KEM (Kyber) | Key Encapsulation | Future (TLS 1.4) |
| [FIPS 204](https://csrc.nist.gov/news/2024/postquantum-cryptography-fips-approved) | ML-DSA (Dilithium) | Digital Signatures | **IMPLEMENTED (Day 1)** |
| [FIPS 205](https://csrc.nist.gov/news/2024/postquantum-cryptography-fips-approved) | SLH-DSA (SPHINCS+) | Hash-Based Signatures | Supported Alternative |

Additional standards in development:
- **FIPS 206**: FALCON (in development)
- **HQC**: Selected March 2025 for standardization

### CIRISVerify Cryptographic Implementation (Day-1 Standard)

**CIRISVerify 2.0 launches with HYBRID_REQUIRED mode.** All operations require both classical and PQC signatures.

| Component | Classical | Post-Quantum | Signature Mode |
|-----------|-----------|--------------|----------------|
| **License Signing** | Ed25519 | ML-DSA-65 | **HYBRID_REQUIRED** |
| **Hardware Attestation** | Ed25519/ECDSA | ML-DSA-65 (software) | **HYBRID_REQUIRED** |
| **Steward Key** | Ed25519 | ML-DSA-65 | **HYBRID_REQUIRED** |
| **Response Signatures** | Ed25519 | ML-DSA-65 | **HYBRID_REQUIRED** |
| **Binary Checksums** | Ed25519 | ML-DSA-65 | **HYBRID_REQUIRED** |

**Verification requires BOTH signatures to pass. Failure of either signature rejects the operation.**

### Why Hybrid Mode at Launch?

| Reason | Explanation |
|--------|-------------|
| **CNSA 2.0 Compliance** | NSA guidance requires PQC support for software signing "immediately" |
| **Defense-in-Depth** | If ML-DSA has unknown weaknesses, Ed25519 provides backup |
| **Quantum Resistance** | If quantum computers advance faster than expected, PQC provides protection |
| **Hardware Binding** | Classical signature from HSM provides hardware root of trust |
| **No Migration Debt** | Starting with hybrid avoids painful mid-lifecycle transitions |

### NSA CNSA 2.0 Compliance

Per [NSA guidance](https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/):

| Capability | Support By | Prefer By | Exclusive By | CIRISVerify |
|------------|-----------|-----------|--------------|-------------|
| Software/Firmware Signing | Immediately | 2025 | 2030 | **Compliant (Day 1)** |
| Web/Cloud Services | 2025 | 2026 | 2033 | Tracking |
| Traditional Networking | 2026 | 2028 | 2033 | N/A |

### Threat Assessment

| Threat | Timeline | CIRISVerify Mitigation |
|--------|----------|----------------------|
| **Harvest Now, Decrypt Later** | Now | **Mitigated** - ML-DSA signatures from day 1 |
| **CRQC (Cryptographically Relevant Quantum Computer)** | 2030-2040 | **Mitigated** - PQC already deployed |
| **Classical Algorithm Compromise** | Ongoing | **Mitigated** - Hybrid requires both to pass |
| **PQC Algorithm Weakness** | Unknown | **Mitigated** - Classical backup still validates |

### Implementation Details

```protobuf
// ciris_verify.proto v2.0
message HardwareAttestation {
  // Classical signature (hardware-bound)
  bytes hardware_public_key = 2;       // Ed25519
  bytes hardware_signature = 3;        // Hardware HSM

  // PQC signature (software, required)
  bytes pqc_public_key = 10;           // ML-DSA-65
  bytes pqc_signature = 11;            // Software-generated
  PQCAlgorithm pqc_algorithm = 12;     // Must be ML_DSA_65+
  SignatureMode signature_mode = 13;   // Must be HYBRID_REQUIRED
}

enum SignatureMode {
  SIGNATURE_MODE_UNSPECIFIED = 0;
  CLASSICAL_ONLY = 1;       // REJECTED by CIRISVerify 2.0
  HYBRID_REQUIRED = 2;      // Day-1 standard
  PQC_ONLY = 3;             // Future (post-hardware PQC)
}
```

### Future Roadmap

#### Phase 1: Current (2026) - Hybrid Launch

**Status: ACTIVE**

- Hybrid mode (Ed25519 + ML-DSA-65) required for all operations
- Hardware provides classical signature; software adds PQC
- Both signatures must verify

#### Phase 2: Hardware PQC (2027-2029)

**Status: Planned**

When TPM/Secure Enclave/Keystore add ML-DSA support:
1. Hardware generates both classical and PQC signatures
2. Software PQC signature becomes optional backup
3. Higher security assurance for PQC binding

#### Phase 3: Classical Deprecation (2030+)

**Status: Long-term**

Per CNSA 2.0 "Exclusive By" dates:
1. Classical signatures become optional
2. PQC-only mode available for compliant hardware
3. Legacy compatibility maintained for non-upgraded devices

### PQC Implementation Considerations

#### Key Sizes

| Algorithm | Public Key | Signature | vs Ed25519 |
|-----------|-----------|-----------|------------|
| Ed25519 | 32 bytes | 64 bytes | Baseline |
| ML-DSA-65 | 1,952 bytes | 3,293 bytes | ~50x larger |
| ML-DSA-87 | 2,592 bytes | 4,595 bytes | ~70x larger |
| SLH-DSA-SHA2-256s | 64 bytes | 29,792 bytes | Huge signature |

**Impact**:
- License JWTs will grow significantly (~5-10KB vs ~500B)
- DNS TXT records cannot hold full PQC keys (need alternative)
- Mobile bandwidth considerations for offline caching

#### Performance

| Algorithm | Sign (ops/s) | Verify (ops/s) |
|-----------|-------------|----------------|
| Ed25519 | ~50,000 | ~20,000 |
| ML-DSA-65 | ~5,000 | ~10,000 |
| ML-DSA-87 | ~3,000 | ~6,000 |

**Impact**:
- 10x slower signing (acceptable for license issuance)
- 2-3x slower verification (acceptable for startup)

#### DNS Challenge

Current design uses DNS TXT records for multi-source validation:
```
_ciris-verify.ciris-services-1.ai TXT "v=ciris1 key=ed25519:MCow... rev=..."
```

**PQC Problem**: ML-DSA public keys are ~2KB, exceeding DNS TXT limits (255 bytes per string, 65KB total but impractical).

**Solutions**:

1. **Key Fingerprint in DNS**:
```
_ciris-verify.ciris-services-1.ai TXT "v=ciris2 fp=sha256:abc123... rev=..."
```
Full key fetched from HTTPS endpoint; DNS provides fingerprint for integrity.

2. **DNS-over-HTTPS with Large Records**:
Use DoH providers that support larger responses.

3. **Multiple TXT Records**:
Split key across multiple TXT records (fragile, not recommended).

**Recommendation**: Option 1 (fingerprint in DNS) maintains multi-source validation while accommodating PQC key sizes.

### Updated Protocol for PQC

```protobuf
// ciris_verify_v2.proto additions

message StewardKeyResponse {
  // Classical key (Ed25519)
  bytes steward_key_classical = 1;
  string key_id_classical = 2;

  // PQC key (ML-DSA)
  bytes steward_key_pqc = 10;
  string key_id_pqc = 11;
  PQCAlgorithm pqc_algorithm = 12;

  // Transition mode
  KeyTransitionMode transition_mode = 20;
}

enum KeyTransitionMode {
  KEY_TRANSITION_UNSPECIFIED = 0;
  CLASSICAL_ONLY = 1;      // Pre-PQC
  HYBRID_REQUIRED = 2;     // Both signatures required
  PQC_PREFERRED = 3;       // PQC primary, classical fallback
  PQC_ONLY = 4;            // Post-transition
}

message HardwareAttestation {
  // Existing fields...

  // PQC signature from hardware
  bytes hardware_signature_pqc = 20;
  PQCAlgorithm hardware_pqc_algorithm = 21;
}
```

### Hardware PQC Support

| Platform | PQC Status | Notes |
|----------|-----------|-------|
| **TPM 2.0** | [TCG working on PQC](https://trustedcomputinggroup.org/) | Expected 2026-2027 |
| **Android Keystore** | Not yet | Dependent on Google |
| **iOS Secure Enclave** | Not yet | Dependent on Apple |
| **Intel SGX** | Research phase | SDK updates needed |

**Mitigation**: Use software PQC with hardware-protected classical signature until hardware PQC available.

```
Hybrid Attestation:
1. Hardware signs with classical Ed25519 (hardware-bound)
2. Software adds PQC signature (ML-DSA) over combined payload
3. Verifier checks both
```

This provides:
- Hardware binding (via classical signature)
- Quantum resistance (via PQC signature)
- Defense-in-depth

---

## Part III: Implementation Status and Next Steps

### Completed (Day 1 - January 2026)

1. **Hybrid Cryptography**: Ed25519 + ML-DSA-65 required for all operations
2. **Protocol Version 2.0**: Includes `signature_mode`, `pqc_algorithm` fields
3. **Algorithm Agility**: `PQCAlgorithm` enum supports ML-DSA-44/65/87 and SLH-DSA
4. **DNS Fingerprint Strategy**: PQC keys via fingerprint in DNS, full key via HTTPS
5. **Dual Signature Verification**: Both classical and PQC must pass

### In Progress (Q1 2026)

1. **PQC Library Selection**: Evaluating liboqs, pqcrypto, BoringSSL PQC
2. **Performance Benchmarking**: ML-DSA-65 on mobile/server platforms
3. **Binary Distribution**: Dual-signed checksums for all platforms
4. **Integration Testing**: CIRISAgent integration with v2.0 protocol

### Planned (2026-2027)

1. **Key Rotation Infrastructure**: Support multiple active key pairs
2. **Monitoring Dashboard**: PQC signature verification metrics
3. **Integrator Documentation**: Client library examples for hybrid verification
4. **Compliance Audit**: Third-party verification of CNSA 2.0 compliance

### Future (2027-2030+)

1. **Hardware PQC Support**: Track TPM/Keystore/Enclave ML-DSA support
2. **Hardware-Bound PQC**: When available, require hardware PQC signatures
3. **Classical Deprecation**: Per CNSA 2.0 "Exclusive By 2030" timeline
4. **FIPS 206 (FALCON)**: Evaluate for smaller signature sizes when standardized

---

## Sources

- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/news/2024/postquantum-cryptography-fips-approved)
- [NIST FIPS 203, 204, 205 Overview](https://cloudsecurityalliance.org/blog/2024/08/15/nist-fips-203-204-and-205-finalized-an-important-step-towards-a-quantum-safe-future)
- [RFC 9683 - TPM Remote Attestation](https://datatracker.ietf.org/doc/rfc9683/)
- [RFC 9684 - YANG Model for CHARRA](https://www.rfc-editor.org/rfc/rfc9684.html)
- [Google Play Integrity API](https://developer.android.com/google/play/integrity/overview)
- [Play Integrity Limitations](https://www.guardsquare.com/blog/google-play-integrity-api-app-attestation)
- [iOS App Attest Security Analysis](https://www.guardsquare.com/blog/android-and-ios-app-attestation)
- [Trusted Computing Group](https://trustedcomputinggroup.org/remote-platform-integrity-attestation/)
- [DigiCert PQC Progress Tracking](https://www.digicert.com/blog/the-progress-toward-post-quantum-cryptography)
- [Palo Alto PQC Standards Guide](https://www.paloaltonetworks.com/cyberpedia/pqc-standards)

---

**Document Status**: Complete
**Protocol Version**: 2.0.0 (Hybrid Cryptography)
**Cryptographic Baseline**: Ed25519 + ML-DSA-65 (FIPS 204)
**CNSA 2.0 Compliance**: Software Signing - **Compliant**
**Next Review**: Q3 2026 (post FIPS 206 publication)
