# FSD-001: CIRISVerify Protocol Specification

**Status**: Draft
**Author**: Eric Moore, CIRIS L3C
**Created**: 2026-01-25
**Updated**: 2026-01-25
**Scope**: Hardware-rooted license verification for CIRIS ecosystem
**Risk Level**: CRITICAL (Life-Safety Systems Dependent)

## Executive Summary

CIRISVerify is a closed-source binary module that provides hardware-rooted license verification for the CIRIS ecosystem. It enables CIRISAgent deployments to cryptographically prove their license status, ensuring that community agents (CIRISCare) cannot masquerade as licensed professional agents (CIRISMedical, CIRISLegal, CIRISFinancial) even if the open-source code is modified.

**The core guarantee**: An agent cannot claim to be licensed without cryptographic proof from a hardware-bound verification module that validates against multiple independent sources.

## Mission Alignment

### Meta-Goal M-1 Connection
> "Promote sustainable adaptive coherence—the living conditions under which diverse sentient beings may pursue their own flourishing in justice and wonder."

CIRISVerify serves M-1 by:
1. **Preventing harm**: Ensuring unlicensed systems cannot perform high-risk medical/legal/financial actions
2. **Maintaining trust**: Creating verifiable accountability for licensed professional deployments
3. **Preserving openness**: Keeping the ecosystem fully open-source while adding accountability where stakes are high
4. **Enabling flourishing**: Allowing the commons to grow while protecting life-critical use cases

### Foundational Principle Alignment

| Principle | CIRISVerify Alignment |
|-----------|----------------------|
| **Beneficence** | Enables licensed medical AI to serve patients with steward accountability |
| **Non-maleficence** | Prevents unlicensed systems from performing dangerous actions |
| **Integrity** | Hardware-rooted proof cannot be forged or modified |
| **Fidelity & Transparency** | Public protocol, auditable behavior, mandatory disclosure |
| **Autonomy** | Users always informed of license status before trusting agent |
| **Justice** | Same ethical floor for all; accountability layer for high-stakes domains |

## Problem Statement

### The Threat Model

The CIRIS ecosystem is fully open-source (AGPL). This creates a specific threat:

**Adversary Goal**: Trick users into believing an unlicensed CIRISCare deployment is actually a licensed CIRISMedical deployment, then perform high-risk medical actions without steward accountability.

**Attack Vectors**:
1. Fork the code, remove license checks, claim to be licensed
2. Modify runtime to return fake "licensed" status
3. Spoof verification endpoints
4. Replay old valid license after revocation
5. Man-in-the-middle attestation responses
6. Run in emulator/debugger to intercept and modify responses

### Why Open-Source Self-Reporting Fails

```python
# This can be trivially modified by an adversary:
class LicenseChecker:
    def is_licensed(self):
        return True  # Adversary changes this
```

**The code cannot be trusted to honestly report its own status if an adversary controls the code.**

### The Stakes

- **Medical**: Unlicensed agent performs triage, misses critical symptoms → patient harm
- **Legal**: Unlicensed agent provides legal advice, user relies on it → legal harm
- **Financial**: Unlicensed agent provides investment advice → financial harm

In licensed deployments, there is steward accountability and recourse. In unlicensed deployments claiming to be licensed, there is neither—but the user doesn't know.

## Solution Design

### Implementation Language: Rust

CIRISVerify is implemented in **Rust** for the following reasons:

| Requirement | Rust Advantage |
|-------------|---------------|
| Memory safety | No buffer overflows, use-after-free, or data races without `unsafe` |
| Cross-platform | Single codebase compiles to Android, iOS, Linux, Windows, macOS, WASM |
| Performance | Zero-cost abstractions, no GC pauses during cryptographic operations |
| Cryptography ecosystem | Mature libraries (RustCrypto, ring, aws-lc-rs, ed25519-dalek) |
| FFI compatibility | Native C ABI for integration with any language |
| Auditability | Ownership model makes security review more tractable |
| Binary size | Minimal runtime, suitable for embedded/mobile |

**Key Dependencies** (reference implementation):

| Component | Crate | Purpose |
|-----------|-------|---------|
| Classical crypto | `p256`, `ed25519-dalek` | ECDSA P-256, Ed25519 signatures |
| Post-quantum | `ml-dsa` or `aws-lc-rs` | ML-DSA-65 (FIPS 204) |
| Hardware keystore | `keyring-manager` (Veilid fork) | Cross-platform secure storage |
| TPM | `tss-esapi` | TPM 2.0 integration |
| gRPC | `tonic` | Protocol implementation |
| Protobuf | `prost` | Message serialization |
| Async runtime | `tokio` | Async I/O |

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    VERIFICATION INFRASTRUCTURE                           │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                    Multi-Source Validation                          │ │
│  │                                                                     │ │
│  │  DNS (US)                 DNS (EU)                HTTPS Endpoint   │ │
│  │  ciris-services-1.ai      ciris-services-2.ai     verify.ciris.ai  │ │
│  │  (Registrar A)            (Registrar B)           (Cloudflare)     │ │
│  │                                                                     │ │
│  │  All three MUST agree on steward public key and revocation status  │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                 CIRIS VERIFY MODULE (Closed Binary)                      │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │  Hardware   │  │  Multi-DNS  │  │  Binary     │  │  License    │   │
│  │  Security   │  │  Validator  │  │  Integrity  │  │  Engine     │   │
│  │  Module     │  │             │  │  Checker    │  │             │   │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘   │
│         │                │                │                │          │
│         └────────────────┴────────────────┴────────────────┘          │
│                                    │                                   │
│                                    ▼                                   │
│  ┌────────────────────────────────────────────────────────────────────┐│
│  │              Public Protocol Interface (FFI/gRPC)                  ││
│  │              Protocol defined in ciris_verify.proto                ││
│  └────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│              CIRIS AGENT (Open Source - AGPL)                            │
│                                                                          │
│  DEPENDS on ciris-verify binary. CANNOT function in professional mode   │
│  without valid response. MUST display mandatory_disclosure field.        │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  WiseBus: PROHIBITED_CAPABILITIES = ALL - license.capabilities     │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### Design Principles

#### 1. Hybrid Cryptography (Day-1 Requirement)

**CIRISVerify requires dual cryptographic signatures from launch.** Given that NIST finalized FIPS 203/204/205 in August 2024 and NSA CNSA 2.0 guidance recommends PQC support for software signing "immediately," hybrid mode is not a future migration—it is the day-1 standard.

| Component | Classical Algorithm | Post-Quantum Algorithm | Status |
|-----------|--------------------|-----------------------|--------|
| **License Signing** | Ed25519 | ML-DSA-65 (FIPS 204) | **Required** |
| **Hardware Attestation** | Platform-preferred (see below) | ML-DSA-65 (software) | **Required** |
| **Steward Key** | Ed25519 | ML-DSA-65 | **Required** |
| **Response Signatures** | Ed25519 (software) | ML-DSA-65 | **Required** |

**Verification requires BOTH signatures to pass.** This provides:
- **Quantum resistance**: Protected against future quantum attacks via ML-DSA
- **Hardware binding**: Classical signature from secure hardware
- **Defense-in-depth**: If either algorithm has unknown weaknesses, the other provides backup

##### Hardware Classical Algorithm Selection

**Critical constraint**: Mobile hardware security modules have limited algorithm support:

| Platform | Hardware Module | Supported Algorithms | CIRISVerify Selection |
|----------|----------------|---------------------|----------------------|
| Android | Keystore/StrongBox | ECDSA P-256, RSA | **ECDSA P-256** |
| iOS | Secure Enclave | ECDSA P-256 only | **ECDSA P-256** |
| Server/Desktop | TPM 2.0 | ECDSA P-256, RSA, (some) Ed25519 | **ECDSA P-256** (compatibility) |
| Server | Intel SGX | Software choice | **Ed25519** |
| Fallback | Software-only | Any | **Ed25519** |

**Design Decision**: CIRISVerify uses **ECDSA P-256 (secp256r1)** as the primary hardware-bound classical algorithm for cross-platform consistency. This ensures:
1. All hardware platforms can generate and use keys
2. Verification logic is uniform across platforms
3. No platform-specific algorithm negotiation required

**Exception**: SGX and software-only deployments MAY use Ed25519 for the hardware attestation signature since they are not constrained by hardware HSM limitations.

The `HardwareAttestation.classical_algorithm` field indicates which algorithm was used, enabling verifiers to select the correct verification path.

**Hardware PQC Gap Mitigation**: Since TPM/Secure Enclave/Keystore do not yet support PQC:
1. Hardware generates and signs with classical ECDSA P-256 (hardware-bound)
2. Software adds ML-DSA-65 signature over the combined payload (including hardware signature)
3. Verifier checks both signatures

This provides hardware binding via classical + quantum resistance via PQC.

#### 2. Hardware Root of Trust
The verification response is signed by a key that is:
- Generated inside secure hardware (TPM/Secure Enclave/Keystore)
- Never extractable
- Unique per device

An adversary who modifies the code cannot forge this signature.

#### 2. Multi-Source Validation
No single point of compromise:
- DNS record at `ciris-services-1.ai` (US registrar)
- DNS record at `ciris-services-2.ai` (EU registrar)
- HTTPS endpoint at `verify.ciris.ai`

All three must agree. Compromising one triggers `SOURCES_DISAGREE` status.

#### 3. Fail-Safe to Community Mode
Any error condition degrades to CIRISCare (unlicensed) behavior:
- Binary tampered → LOCKDOWN
- Sources disagree → RESTRICTED
- Verification failed → COMMUNITY MODE
- License expired → COMMUNITY MODE
- License revoked → COMMUNITY MODE

**The failure mode is always MORE restrictive, never less.**

#### 4. Mandatory Disclosure
The binary returns a `mandatory_disclosure` string that:
- Is baked into the binary (cannot be modified without detection)
- MUST be displayed to users
- Accurately reflects the actual license status

#### 5. Public Protocol, Private Implementation
- **Public**: Protocol spec (this document), interface definition (protobuf)
- **Private**: Implementation source code
- **Verifiable**: Behavior is deterministic and auditable

## Protocol Specification

### 1. Service Definition

```protobuf
// ciris_verify.proto
// Version: 1.0.0
//
// This protocol is PUBLIC. Anyone can implement a client.
// The server implementation is closed-source.

syntax = "proto3";

package ciris.verify.v1;

option go_package = "github.com/cirisai/ciris-verify/proto/v1";

// CIRISVerify provides hardware-rooted license verification
service CIRISVerify {
  // Get the current license status for this deployment
  rpc GetLicenseStatus(LicenseStatusRequest) returns (LicenseStatusResponse);

  // Check if a specific capability is allowed
  rpc CheckCapability(CapabilityCheckRequest) returns (CapabilityCheckResponse);

  // Get the current steward public key (for external verification)
  rpc GetStewardKey(StewardKeyRequest) returns (StewardKeyResponse);

  // Health check
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
}
```

### 2. License Status

```protobuf
message LicenseStatusRequest {
  // Unique deployment identifier (hardware-derived if available)
  string deployment_id = 1;

  // Random nonce to prevent replay attacks
  bytes challenge_nonce = 2;

  // Optional: force refresh from remote sources
  bool force_refresh = 3;
}

message LicenseStatusResponse {
  // Overall status
  LicenseStatus status = 1;

  // License details (if licensed)
  LicenseDetails license = 2;

  // CRITICAL: Must be displayed to users
  string mandatory_disclosure = 3;

  // Hardware attestation
  HardwareAttestation attestation = 4;

  // Multi-source validation results
  SourceValidation validation = 5;

  // Response metadata
  ResponseMetadata metadata = 6;
}

enum LicenseStatus {
  LICENSE_STATUS_UNSPECIFIED = 0;

  // Licensed statuses
  LICENSED_PROFESSIONAL = 1;      // Full steward-backed license
  LICENSED_COMMUNITY_PLUS = 2;    // Enhanced community (some features)

  // Unlicensed statuses
  UNLICENSED_COMMUNITY = 3;       // Standard CIRISCare
  UNLICENSED_UNVERIFIED = 4;      // Could not verify (offline grace)

  // Error statuses
  ERROR_BINARY_TAMPERED = 10;     // Integrity check failed
  ERROR_SOURCES_DISAGREE = 11;    // Multi-source mismatch (attack?)
  ERROR_VERIFICATION_FAILED = 12; // Could not reach any source
  ERROR_LICENSE_REVOKED = 13;     // Explicitly revoked by steward
  ERROR_LICENSE_EXPIRED = 14;     // Past expiration date
}
```

### 3. License Details

```protobuf
message LicenseDetails {
  // Unique license identifier
  string license_id = 1;

  // License type
  LicenseType license_type = 2;

  // Licensee information
  string organization_name = 3;
  string organization_id = 4;

  // Validity period
  int64 issued_at = 5;          // Unix timestamp
  int64 expires_at = 6;         // Unix timestamp
  int64 not_before = 7;         // Unix timestamp

  // Capability grants
  repeated string capabilities = 8;
  repeated string capabilities_denied = 9;

  // Autonomy tier limit
  AutonomyTier max_autonomy_tier = 10;

  // Deployment constraints
  DeploymentConstraints constraints = 11;

  // Original signed license JWT (for external verification)
  string license_jwt = 12;
}

enum LicenseType {
  LICENSE_TYPE_UNSPECIFIED = 0;
  COMMUNITY = 1;                  // CIRISCare
  PROFESSIONAL_MEDICAL = 2;       // CIRISMedical
  PROFESSIONAL_LEGAL = 3;         // CIRISLegal
  PROFESSIONAL_FINANCIAL = 4;     // CIRISFinancial
  PROFESSIONAL_FULL = 5;          // All professional modules
}

enum AutonomyTier {
  AUTONOMY_TIER_UNSPECIFIED = 0;
  A0_ADVISORY = 1;                // Grammar, formatting
  A1_LIMITED = 2;                 // Static Q&A
  A2_MODERATE = 3;                // Recommendations with oversight
  A3_HIGH = 4;                    // Triage, diagnosis support
  A4_CRITICAL = 5;                // Treatment decisions (requires hardware interlock)
}

message DeploymentConstraints {
  // Requires human supervisor present
  bool requires_supervisor = 1;

  // Required supervisor credentials
  repeated string supervisor_credentials = 2;

  // Maximum hours offline before degradation
  int32 offline_grace_hours = 3;

  // Requires hardware attestation for A4 actions
  bool requires_hardware_attestation = 4;

  // Geographic restrictions (ISO 3166-1 alpha-2)
  repeated string allowed_regions = 5;

  // Facility type restrictions
  repeated string allowed_facility_types = 6;
}
```

### 4. Hardware Attestation (Hybrid Cryptography)

```protobuf
message HardwareAttestation {
  // Hardware security module type
  HardwareType hardware_type = 1;

  // === CLASSICAL SIGNATURE (Hardware-Bound) ===
  // Classical algorithm used for hardware signature
  // ECDSA_P256 for mobile/TPM, ED25519 for SGX/software
  ClassicalAlgorithm classical_algorithm = 9;

  // Hardware-bound public key (algorithm indicated by classical_algorithm)
  bytes hardware_public_key = 2;

  // Classical signature over response using hardware key
  bytes hardware_signature = 3;

  // === POST-QUANTUM SIGNATURE (Software, Required) ===
  // ML-DSA public key (software-generated, stored securely)
  bytes pqc_public_key = 10;

  // ML-DSA signature over response (includes hardware signature in payload)
  bytes pqc_signature = 11;

  // PQC algorithm used (must be ML_DSA_65 or higher)
  PQCAlgorithm pqc_algorithm = 12;

  // Signature mode (must be HYBRID_REQUIRED for v2.0)
  SignatureMode signature_mode = 13;

  // Platform-specific attestation
  oneof platform_attestation {
    AndroidAttestation android = 4;
    IOSAttestation ios = 5;
    TPMAttestation tpm = 6;
    SoftwareAttestation software = 7;
  }

  // Integrity check results
  IntegrityStatus integrity = 8;
}

// Classical algorithm for hardware-bound signatures
enum ClassicalAlgorithm {
  CLASSICAL_ALGORITHM_UNSPECIFIED = 0;
  ECDSA_P256 = 1;    // secp256r1/prime256v1 - Required for mobile HSMs
  ED25519 = 2;       // Edwards curve - Used for SGX/software
  ECDSA_P384 = 3;    // secp384r1 - Optional higher security
}

// Post-Quantum Cryptography Algorithm Selection
// Based on NIST FIPS 204 (ML-DSA) finalized August 2024
enum PQCAlgorithm {
  PQC_ALGORITHM_UNSPECIFIED = 0;

  // ML-DSA (Dilithium) - FIPS 204
  ML_DSA_44 = 1;   // Security level 2 (~128-bit classical)
  ML_DSA_65 = 2;   // Security level 3 (~192-bit classical) - MINIMUM REQUIRED
  ML_DSA_87 = 3;   // Security level 5 (~256-bit classical)

  // SLH-DSA (SPHINCS+) - FIPS 205 - Stateless hash-based (conservative choice)
  SLH_DSA_SHA2_128S = 10;  // Small signature, 128-bit security
  SLH_DSA_SHA2_256S = 11;  // Small signature, 256-bit security
}

enum HardwareType {
  HARDWARE_TYPE_UNSPECIFIED = 0;
  ANDROID_KEYSTORE = 1;           // Android Hardware Keystore
  ANDROID_STRONGBOX = 2;          // Android StrongBox (higher security)
  IOS_SECURE_ENCLAVE = 3;         // Apple Secure Enclave
  TPM_2_0 = 4;                    // Trusted Platform Module 2.0
  INTEL_SGX = 5;                  // Intel Software Guard Extensions
  SOFTWARE_ONLY = 6;              // Software-based (lowest security)
}

message IntegrityStatus {
  // Binary self-hash verification
  bool binary_integrity_valid = 1;

  // Debugger detection
  bool debugger_detected = 2;

  // Hook detection (Frida, Xposed, etc.)
  bool hooks_detected = 3;

  // Root/jailbreak detection
  bool device_compromised = 4;

  // Emulator detection
  bool emulator_detected = 5;

  // Timestamp of last integrity check
  int64 last_check_timestamp = 6;
}

message AndroidAttestation {
  // Play Integrity API verdict
  bytes play_integrity_token = 1;

  // SafetyNet attestation (legacy)
  bytes safetynet_response = 2;

  // Key attestation certificate chain
  repeated bytes key_attestation_chain = 3;
}

message IOSAttestation {
  // App Attest assertion
  bytes app_attest_assertion = 1;

  // DeviceCheck token
  bytes device_check_token = 2;
}

message TPMAttestation {
  // TPM quote
  bytes tpm_quote = 1;

  // PCR values
  repeated bytes pcr_values = 2;

  // AIK certificate
  bytes aik_certificate = 3;
}

message SoftwareAttestation {
  // Self-computed integrity hash
  bytes self_hash = 1;

  // Obfuscated integrity checks passed
  int32 integrity_checks_passed = 2;

  // Warning: Software-only provides weaker guarantees
  string security_warning = 3;
}
```

### 5. Multi-Source Validation

```protobuf
message SourceValidation {
  // DNS source 1 (US)
  SourceResult dns_us = 1;

  // DNS source 2 (EU)
  SourceResult dns_eu = 2;

  // HTTPS endpoint
  SourceResult https_endpoint = 3;

  // Overall validation status
  ValidationStatus overall_status = 4;

  // Consensus steward key (if all sources agree)
  bytes consensus_steward_key = 5;

  // Consensus revocation revision
  int64 consensus_revocation_revision = 6;
}

message SourceResult {
  // Source identifier
  string source = 1;

  // Was the source reachable?
  bool reachable = 2;

  // Did it return valid data?
  bool valid = 3;

  // Steward key from this source
  bytes steward_key = 4;

  // Revocation list revision
  int64 revocation_revision = 5;

  // Timestamp of check
  int64 checked_at = 6;

  // Error message (if any)
  string error = 7;
}

enum ValidationStatus {
  VALIDATION_STATUS_UNSPECIFIED = 0;
  ALL_SOURCES_AGREE = 1;          // All 3 sources match
  PARTIAL_AGREEMENT = 2;          // 2 of 3 sources match (degraded)
  SOURCES_DISAGREE = 3;           // Sources return different keys (attack?)
  NO_SOURCES_REACHABLE = 4;       // Offline - use cached
  VALIDATION_ERROR = 5;           // Unexpected error
}
```

### 6. Capability Check

```protobuf
message CapabilityCheckRequest {
  // Capability to check (e.g., "domain:medical:triage")
  string capability = 1;

  // Action requiring this capability
  string action = 2;

  // Autonomy tier required
  AutonomyTier required_tier = 3;
}

message CapabilityCheckResponse {
  // Is this capability allowed?
  bool allowed = 1;

  // Reason (if denied)
  string denial_reason = 2;

  // Required conditions (if conditionally allowed)
  repeated string required_conditions = 3;

  // Suggested alternative (if capability denied)
  string suggested_alternative = 4;
}
```

### 7. Response Metadata

```protobuf
message ResponseMetadata {
  // Protocol version
  string protocol_version = 1;

  // Binary version
  string binary_version = 2;

  // Response timestamp
  int64 timestamp = 3;

  // Cache TTL (seconds)
  int32 cache_ttl = 4;

  // Next recommended check time
  int64 next_check_at = 5;

  // Request ID for debugging
  string request_id = 6;
}
```

## Mandatory Disclosure Strings

The following disclosure strings are baked into the binary and cannot be modified:

```
LICENSED_PROFESSIONAL:
"Licensed {license_type} deployment. License: {license_id}.
Organization: {organization_name}. Steward-backed by CIRIS L3C.
Verify at: ciris.ai/verify/{license_id}"

LICENSED_COMMUNITY_PLUS:
"Enhanced CIRISCare community deployment with additional features.
License: {license_id}. Some capabilities steward-backed.
Full professional features require professional license."

UNLICENSED_COMMUNITY:
"CIRISCare community deployment. NOT a licensed professional provider.
Cannot provide official certifications or steward-backed advice.
For professional medical/legal/financial needs, seek licensed providers.
This agent defers to human judgment for significant decisions."

UNLICENSED_UNVERIFIED:
"License verification unavailable. Operating in restricted community mode.
This agent should NOT be relied upon for professional advice until
verification succeeds. Limited functionality enabled."

ERROR_BINARY_TAMPERED:
"⚠️ CRITICAL SECURITY WARNING ⚠️
Verification module integrity check FAILED.
This installation may have been tampered with.
DO NOT trust this agent for ANY professional purposes.
DO NOT enter sensitive information.
Contact: security@ciris.ai"

ERROR_SOURCES_DISAGREE:
"⚠️ SECURITY WARNING ⚠️
Verification sources returned conflicting information.
Possible security incident or network attack detected.
Operating in restricted mode. Contact: security@ciris.ai"

ERROR_LICENSE_REVOKED:
"License {license_id} has been REVOKED by the steward.
Reason: {revocation_reason}
This deployment is no longer authorized for professional use.
Operating in community mode only."

ERROR_LICENSE_EXPIRED:
"License {license_id} expired on {expiry_date}.
Operating in community mode until license is renewed.
Contact your administrator or licensing@ciris.ai"
```

## DNS Record Format (Hybrid Keys)

### TXT Record Schema

ML-DSA public keys are ~2KB, exceeding practical DNS TXT limits. The solution: store the Ed25519 key directly and the ML-DSA key fingerprint, with full PQC key available via HTTPS.

```
_ciris-verify.ciris-services-1.ai TXT "v=ciris2 key=ed25519:{base64_pubkey} pqc_fp=sha256:{hex_fingerprint} rev={revision} ts={timestamp}"
_ciris-verify.ciris-services-2.ai TXT "v=ciris2 key=ed25519:{base64_pubkey} pqc_fp=sha256:{hex_fingerprint} rev={revision} ts={timestamp}"
```

**Fields**:
- `v`: Protocol version (**ciris2** - indicates hybrid mode)
- `key`: Steward Ed25519 public key (base64, ~44 chars)
- `pqc_fp`: SHA-256 fingerprint of ML-DSA public key (hex, 64 chars)
- `rev`: Revocation list revision number
- `ts`: Last update timestamp (Unix)

### Example

```
_ciris-verify.ciris-services-1.ai TXT "v=ciris2 key=ed25519:MCowBQYDK2VwAyEAb3X9... pqc_fp=sha256:a1b2c3d4e5f6... rev=2026012501 ts=1737763200"
```

### PQC Key Retrieval

The full ML-DSA public key is retrieved via HTTPS:

1. Fetch `GET https://verify.ciris.ai/v1/steward-key`
2. Compute `SHA-256(response.steward_key_pqc)`
3. Compare with `pqc_fp` from DNS records
4. All three sources (DNS US, DNS EU, HTTPS) must have matching fingerprint

This maintains multi-source validation while accommodating PQC key sizes.

## HTTPS Endpoint Specification

### GET /v1/steward-key

Returns current steward signing keys (both classical and PQC).

**Response**:
```json
{
  "classical": {
    "algorithm": "Ed25519",
    "key": "MCowBQYDK2VwAyEA...",
    "key_id": "steward-2026-01"
  },
  "pqc": {
    "algorithm": "ML-DSA-65",
    "key": "MIIFxjALBglg...",
    "key_id": "steward-pqc-2026-01",
    "fingerprint": "sha256:a1b2c3d4e5f6..."
  },
  "signature_mode": "HYBRID_REQUIRED",
  "revision": 2026012501,
  "timestamp": 1737763200,
  "next_rotation": 1745625600,
  "response_signature_classical": "base64...",
  "response_signature_pqc": "base64..."
}
```

**Note**: The response itself is signed with both keys to prevent MITM on the key exchange.

### GET /v1/revocation/{license_id}

Check if a specific license is revoked.

**Response**:
```json
{
  "license_id": "CML-2026-0001",
  "revoked": false,
  "checked_at": 1737763200
}
```

Or if revoked:
```json
{
  "license_id": "CML-2026-0001",
  "revoked": true,
  "revoked_at": 1737500000,
  "reason": "License holder request",
  "checked_at": 1737763200
}
```

### POST /v1/validate-license

Validate a license JWT.

**Request**:
```json
{
  "license_jwt": "eyJ..."
}
```

**Response**:
```json
{
  "valid": true,
  "license_id": "CML-2026-0001",
  "license_type": "PROFESSIONAL_MEDICAL",
  "organization": "Metro Hospital Network",
  "expires_at": 1745625600,
  "capabilities": ["domain:medical:triage", "domain:medical:diagnosis_support"]
}
```

## License JWT Format (Hybrid Signatures)

Licenses are issued with **dual signatures** (Ed25519 + ML-DSA). This is a day-1 requirement per CNSA 2.0 guidance.

### Header
```json
{
  "alg": "EdDSA+ML-DSA-65",
  "typ": "CIRIS-LICENSE-HYBRID",
  "kid": "steward-2026-01",
  "pqc_kid": "steward-pqc-2026-01"
}
```

### Payload
```json
{
  "iss": "verify.ciris.ai",
  "sub": "org:metro-hospital-network",
  "aud": "ciris-verify",
  "iat": 1737763200,
  "exp": 1745625600,
  "nbf": 1737763200,
  "jti": "CML-2026-0001",

  "ciris": {
    "license_type": "PROFESSIONAL_MEDICAL",
    "organization_name": "Metro Hospital Network",
    "organization_id": "org-mhn-001",

    "capabilities": [
      "domain:medical:triage",
      "domain:medical:diagnosis_support",
      "domain:medical:prescription_verify",
      "domain:medical:imaging"
    ],

    "capabilities_denied": [
      "domain:medical:surgery",
      "domain:medical:autonomous_treatment"
    ],

    "max_autonomy_tier": "A3",

    "constraints": {
      "requires_supervisor": true,
      "supervisor_credentials": ["PMDC", "GMC", "USMLE"],
      "offline_grace_hours": 72,
      "requires_hardware_attestation": false
    },

    "crypto": {
      "classical_alg": "Ed25519",
      "pqc_alg": "ML-DSA-65",
      "signature_mode": "HYBRID_REQUIRED"
    }
  }
}
```

### Dual Signatures

The license includes **two signatures**, both of which MUST validate:

```
License = Base64URL(Header) + "." + Base64URL(Payload) + "." + Base64URL(ClassicalSig) + "." + Base64URL(PQCSig)
```

| Signature | Algorithm | Key ID | Size |
|-----------|-----------|--------|------|
| **Classical** | Ed25519 | `steward-2026-01` | 64 bytes |
| **Post-Quantum** | ML-DSA-65 | `steward-pqc-2026-01` | ~3,293 bytes |

**Verification Process**:
1. Parse the license JWT (4 parts instead of standard 3)
2. Verify Ed25519 signature against `steward_key_classical`
3. Verify ML-DSA-65 signature against `steward_key_pqc`
4. **Both must pass** - failure of either rejects the license

**Note**: The total license size increases from ~500 bytes to ~5KB due to the ML-DSA signature. This is acceptable for license issuance operations.

## Integration Requirements

### CIRISAgent Integration

```python
# Required integration in ciris_engine/core/runtime.py

class CIRISRuntime:
    async def initialize(self):
        # MUST verify license before enabling capabilities
        self.verify_client = CIRISVerifyClient()
        license_status = await self.verify_client.get_license_status()

        # Configure WiseBus based on license
        self.wise_bus.configure_from_license(license_status)

        # Store mandatory disclosure for all responses
        self.mandatory_disclosure = license_status.mandatory_disclosure

    async def handle_action(self, action):
        # MUST include disclosure in every response
        action.metadata["license_disclosure"] = self.mandatory_disclosure
        action.metadata["license_status"] = self.license_status.status.name

        # Capability check
        if not await self.verify_client.check_capability(action.capability):
            raise CapabilityDeniedError(...)
```

### WiseBus Integration

```python
# Required integration in ciris_engine/logic/buses/wise_bus.py

class WiseBus:
    def configure_from_license(self, license_status):
        if license_status.status in [ERROR_BINARY_TAMPERED, ERROR_SOURCES_DISAGREE]:
            # COMPLETE LOCKDOWN
            self.PROHIBITED_CAPABILITIES = ALL_CAPABILITIES

        elif license_status.status in [ERROR_VERIFICATION_FAILED, UNLICENSED_UNVERIFIED]:
            # RESTRICTED MODE
            self.PROHIBITED_CAPABILITIES = ALL_PROFESSIONAL_CAPABILITIES

        elif license_status.status == UNLICENSED_COMMUNITY:
            # COMMUNITY MODE
            self.PROHIBITED_CAPABILITIES = LICENSED_ONLY_CAPABILITIES

        else:
            # LICENSED - enable based on specific grants
            self.PROHIBITED_CAPABILITIES = (
                ALL_PROFESSIONAL_CAPABILITIES -
                set(license_status.license.capabilities)
            )
```

## Security Considerations

### Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Code modification to skip verification | Hardware signature cannot be forged without hardware key |
| Fake license file | Signature verification against multi-source steward key |
| MITM of verify.ciris.ai | DNS sources won't match HTTPS |
| DNS poisoning of one source | Other sources won't match |
| Replay of old valid license | Revocation check, expiry validation |
| Emulator/debugger interception | Platform integrity checks |
| Binary modification | Self-integrity verification |
| Key extraction from binary | Keys stored in hardware, never in binary |

### Security Assumptions

1. Hardware security modules (TPM/Secure Enclave/Keystore) are not compromised
2. Multiple DNS registrars are not simultaneously compromised
3. HTTPS certificate infrastructure is not compromised
4. Adversary does not have physical access to hardware
5. System clocks are reasonably synchronized (within 5 minutes of actual time)
6. Network path to at least one verification source is not fully compromised

### Mandatory Security Requirements

The following requirements MUST be implemented in the CIRISVerify binary:

#### 1. SOFTWARE_ONLY Tier Restriction (CRITICAL)

**SOFTWARE_ONLY attestation (HardwareType = 6) is limited to UNLICENSED_COMMUNITY tier maximum.**

Rationale: Software-only attestation can be bypassed through reverse engineering. An adversary who modifies the binary can forge software attestation. Therefore, software-only deployments MUST NOT receive professional capabilities.

```
IF hardware_type == SOFTWARE_ONLY:
    max_license_status = UNLICENSED_COMMUNITY
    PROHIBITED: LICENSED_PROFESSIONAL, LICENSED_COMMUNITY_PLUS
```

| Hardware Type | Maximum License Status | Professional Capabilities |
|---------------|----------------------|---------------------------|
| ANDROID_STRONGBOX | LICENSED_PROFESSIONAL | Yes |
| IOS_SECURE_ENCLAVE | LICENSED_PROFESSIONAL | Yes |
| TPM_2_0 | LICENSED_PROFESSIONAL | Yes |
| ANDROID_KEYSTORE | LICENSED_PROFESSIONAL | Yes |
| INTEL_SGX | LICENSED_PROFESSIONAL | Yes |
| **SOFTWARE_ONLY** | **UNLICENSED_COMMUNITY** | **NO** |

#### 2. PQC Signature Binding (CRITICAL)

The PQC signature MUST cover the classical signature to prevent signature stripping attacks:

```
signed_payload = Header || Payload || Classical_Signature
PQC_Signature = Sign_ML-DSA(steward_pqc_key, signed_payload)
```

Verification order:
1. Verify classical signature over (Header || Payload)
2. Verify PQC signature over (Header || Payload || Classical_Signature)
3. **Both MUST pass** - failure of either rejects the license

This binding ensures an attacker cannot strip one signature while preserving the other.

#### 3. Certificate Pinning

CIRISVerify MUST implement certificate pinning for `verify.ciris.ai`:

```
Primary Pin: SHA-256 fingerprint of verify.ciris.ai leaf certificate
Backup Pin: SHA-256 fingerprint of issuing CA certificate
Pin Expiry: Pins valid for 90 days, updated via binary releases
```

If certificate does not match pinned values:
- Log security event
- Fall back to DNS-only validation (2 sources)
- Return `PARTIAL_AGREEMENT` status with security warning

#### 4. Constant-Time Cryptographic Operations

All signature verification MUST use constant-time comparison to prevent timing attacks:

- Ed25519 signature comparison: constant-time
- ML-DSA signature comparison: constant-time
- Nonce comparison: constant-time
- Key comparison: constant-time

Implementation MUST use platform-provided constant-time primitives or verified implementations.

#### 5. Nonce Requirements

Challenge nonces MUST meet the following requirements:

| Requirement | Value |
|-------------|-------|
| Minimum length | 32 bytes |
| Source | Cryptographically secure RNG |
| Uniqueness window | 24 hours |
| Binding | Nonce bound to deployment_id in signature |

Nonce handling:
- Server MUST reject nonces shorter than 32 bytes
- Server MUST track used nonces for 24 hours minimum
- Response signature MUST include nonce in signed payload
- Client MUST verify returned nonce matches submitted nonce

#### 6. Integrity Check Opacity

The binary MUST NOT expose which specific integrity checks failed:

```protobuf
// WRONG - Exposes attack surface
message IntegrityStatus {
  bool debugger_detected = 2;    // Don't expose individually
  bool hooks_detected = 3;       // Don't expose individually
  bool device_compromised = 4;   // Don't expose individually
}

// CORRECT - Single opaque failure
message IntegrityStatus {
  bool integrity_valid = 1;                    // Single pass/fail
  int64 last_check_timestamp = 6;              // When checked
  string failure_category = 10;                // Generic: "environment", "binary", "runtime"
}
```

Rationale: Exposing individual check results allows attackers to enumerate and bypass each check systematically.

#### 7. PARTIAL_AGREEMENT Capability Restrictions

When validation status is `PARTIAL_AGREEMENT` (2 of 3 sources agree):

| Capability | Allowed |
|------------|---------|
| A0_ADVISORY | Yes |
| A1_LIMITED | Yes |
| A2_MODERATE | Yes |
| A3_HIGH | **Reduced** - requires supervisor confirmation |
| A4_CRITICAL | **NO** |

Rationale: Partial agreement may indicate an ongoing attack. High-autonomy actions should require additional confirmation.

### Known Limitations

1. **Software-only mode**: Limited to community tier only (see requirement above)
2. **Offline operation**: Cached licenses may become stale; grace period configurable
3. **Novel attacks**: New hardware vulnerabilities may emerge; binary updates required
4. **Social engineering**: Cannot prevent users from ignoring warnings
5. **Hardware PQC gap**: PQC signatures are software-based until HSMs support ML-DSA
6. **Clock dependency**: Significant clock skew can cause false positives/negatives

## Testing Requirements

### Unit Tests
- License JWT parsing and validation
- Multi-source consensus algorithm
- Capability grant/deny logic
- Mandatory disclosure selection

### Integration Tests
- End-to-end license verification flow
- Offline degradation behavior
- Source disagreement handling
- Cache TTL and refresh

### Security Tests
- Binary integrity verification
- Debugger detection
- Hook detection
- Replay attack prevention
- Invalid signature rejection

### Compliance Tests
- Mandatory disclosure always present
- Correct status for each license type
- Proper degradation on errors

## Deployment

### Binary Distribution

```
ciris-verify/
├── binaries/
│   ├── android/
│   │   ├── arm64-v8a/libciris_verify.so
│   │   ├── armeabi-v7a/libciris_verify.so
│   │   └── x86_64/libciris_verify.so
│   ├── ios/
│   │   └── CIRISVerify.xcframework/
│   ├── linux/
│   │   ├── x86_64/libciris_verify.so
│   │   └── aarch64/libciris_verify.so
│   ├── windows/
│   │   └── x64/ciris_verify.dll
│   └── macos/
│       └── universal/libciris_verify.dylib
├── checksums/
│   └── SHA256SUMS.sig
└── protocol/
    └── ciris_verify.proto
```

### Checksum Verification (Hybrid Signatures)

All binaries are accompanied by steward-signed checksums using **both** Ed25519 and ML-DSA:

```
SHA256SUMS:
abc123...  android/arm64-v8a/libciris_verify.so
def456...  android/armeabi-v7a/libciris_verify.so
...

SHA256SUMS.sig.ed25519: Ed25519 signature of SHA256SUMS
SHA256SUMS.sig.mldsa65: ML-DSA-65 signature of SHA256SUMS
```

**Verification Process**:
1. Download `SHA256SUMS`, `SHA256SUMS.sig.ed25519`, and `SHA256SUMS.sig.mldsa65`
2. Fetch steward keys from `verify.ciris.ai/v1/steward-key`
3. Verify Ed25519 signature against `steward_key_classical`
4. Verify ML-DSA-65 signature against `steward_key_pqc`
5. **Both signatures must pass** before trusting binary checksums
6. Verify binary SHA-256 matches the signed checksum

Clients MUST verify both signatures before loading binaries.

## Versioning

### Protocol Versioning
- Major: Breaking changes to protocol
- Minor: Backward-compatible additions
- Patch: Bug fixes

Current version: **2.0.0** (Hybrid Cryptography)

Version history:
- 2.0.0 (2026-01-25): Hybrid cryptography as day-1 standard
- 1.0.0 (never released): Classical-only draft

### Binary Versioning
Binaries are versioned independently but must support current protocol version.

### Cryptographic Agility
The protocol supports algorithm agility via the `PQCAlgorithm` enum. Future NIST standards (FIPS 206/FALCON, HQC) can be added without breaking changes.

## Governance

### Key Rotation
- Steward signing keys rotate annually
- 30-day overlap period for transition
- Emergency rotation procedure for compromise

### Revocation
- Steward may revoke licenses for cause
- 7-day cure period for minor violations
- Immediate revocation for safety-critical violations
- Published revocation policy

### Disputes
- Arbitration process defined in license agreement
- Steward accountable under L3C structure

### Humanitarian and Extended Deployment Options

The following license options MAY be configured by the steward for specific deployment contexts:

#### Extended Offline Grace Period

Standard licenses include 72-hour offline grace. For humanitarian deployments (remote clinics, disaster response, conflict zones), extended grace periods are available:

| Deployment Type | Recommended Grace Period |
|-----------------|-------------------------|
| Urban healthcare | 72 hours (standard) |
| Rural/remote clinic | 168 hours (7 days) |
| Humanitarian field mission | 336 hours (14 days) |
| Disaster response | 504 hours (21 days) |

Configuration via license JWT:
```json
"constraints": {
  "offline_grace_hours": 336,
  "deployment_context": "humanitarian_field"
}
```

#### Low-Bandwidth Mode

For deployments with limited connectivity (satellite, 2G), licenses MAY be configured to:
- Accept 2-of-3 source validation without degradation
- Use fingerprint-only PQC validation (skip full key fetch)
- Extend cache TTL to reduce verification frequency

#### Multi-Language Disclosure

Mandatory disclosures are available in localized versions. The binary includes disclosure strings for:
- English (en) - Default
- Additional languages configured at build time

Future versions will support runtime locale selection via `Accept-Language` header equivalent.

#### Emergency Override (Future)

**Status: Under consideration for v2.1**

For mass casualty events and declared emergencies, a steward-activated emergency mode MAY:
- Extend all active licenses by 72 hours
- Issue temporary emergency tokens to registered humanitarian organizations
- Enable geographic emergency zones with relaxed verification

This feature requires careful design to prevent abuse while enabling disaster response.

## Appendix A: FFI Interface

For non-gRPC integration, the binary exposes C-compatible FFI:

```c
// ciris_verify.h

typedef struct CIRISVerifyHandle* CIRISVerify;

// Initialize the verification module
CIRISVerify ciris_verify_init(void);

// Get license status (returns serialized protobuf)
int ciris_verify_get_status(
    CIRISVerify handle,
    const uint8_t* request_data,
    size_t request_len,
    uint8_t** response_data,
    size_t* response_len
);

// Check capability
int ciris_verify_check_capability(
    CIRISVerify handle,
    const char* capability,
    const char* action,
    int required_tier,
    int* allowed
);

// Free allocated memory
void ciris_verify_free(uint8_t* data);

// Cleanup
void ciris_verify_destroy(CIRISVerify handle);
```

## Appendix B: Example Integration

```python
# Python integration example
import ctypes
from ciris_verify_pb2 import LicenseStatusRequest, LicenseStatusResponse

class CIRISVerifyClient:
    def __init__(self):
        # Load platform-specific binary
        self._lib = ctypes.CDLL("libciris_verify.so")
        self._handle = self._lib.ciris_verify_init()

    def get_license_status(self, deployment_id: str) -> LicenseStatusResponse:
        request = LicenseStatusRequest(
            deployment_id=deployment_id,
            challenge_nonce=os.urandom(32)
        )

        request_data = request.SerializeToString()
        response_data = ctypes.POINTER(ctypes.c_uint8)()
        response_len = ctypes.c_size_t()

        result = self._lib.ciris_verify_get_status(
            self._handle,
            request_data,
            len(request_data),
            ctypes.byref(response_data),
            ctypes.byref(response_len)
        )

        if result != 0:
            raise RuntimeError(f"Verification failed: {result}")

        response = LicenseStatusResponse()
        response.ParseFromString(
            ctypes.string_at(response_data, response_len.value)
        )

        self._lib.ciris_verify_free(response_data)
        return response

    def __del__(self):
        if hasattr(self, '_handle'):
            self._lib.ciris_verify_destroy(self._handle)
```

---

**Document Status**: Draft - Pending Review
**Protocol Version**: 2.0.0 (Hybrid Cryptography)
**Cryptographic Baseline**: Ed25519 + ML-DSA-65 (FIPS 204)

**Compliance Notes**:
- Meets NSA CNSA 2.0 "Support By Immediately" requirement for software signing
- Implements NIST FIPS 204 (ML-DSA) finalized August 2024
- Hybrid mode provides defense-in-depth against quantum and classical attacks

**Next Steps**:
1. Security review of protocol (including PQC implementation)
2. Selection of PQC library (liboqs, pqcrypto, or BoringSSL PQC)
3. Implementation of reference binary with hybrid signatures
4. Integration testing with CIRISAgent
5. Legal review of mandatory disclosures
6. Performance benchmarking of ML-DSA on mobile platforms
