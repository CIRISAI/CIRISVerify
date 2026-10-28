# FSD-001: CIRISVerify Protocol Specification

**Status**: Draft
**Author**: Eric Moore, CIRIS L3C
**Created**: 2026-01-25
**Updated**: 2026-10-28
**Scope**: Hardware-rooted license verification for CIRIS ecosystem
**Risk Level**: CRITICAL (Life-Safety Systems Dependent)

## Executive Summary

CIRISVerify is an open-source (AGPL-3.0) binary module that provides hardware-rooted license verification for the CIRIS ecosystem. It enables CIRISAgent deployments to cryptographically prove their license status, ensuring that community agents (CIRISCare) cannot masquerade as licensed professional agents (CIRISMedical, CIRISLegal, CIRISFinancial) even if the open-source code is modified.

**The core guarantee**: An agent cannot claim to be licensed without cryptographic proof from a hardware-bound verification module whose trust root is authorized by the accord holders baked into the binary (CC 5.3.4).

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
| Post-quantum | `ml-dsa` | ML-DSA-65 (FIPS 204) |
| Hardware keystore | `ciris-keyring` (extends Veilid's `keyring-manager` pattern) | Cross-platform secure storage |
| TPM | runtime-loaded `libciris_tpm_plugin` (C ABI over `tss-esapi`) | TPM 2.0 integration without link-time `libtss2` |
| Canonicalization | `serde_jcs` | RFC 8785 JCS for signed bytes |
| Async runtime | `tokio` | Async I/O |

The protocol is defined in `protocol/ciris_verify.proto`; the shipped interface is the C FFI (Appendix A) and the Python/Swift bindings over it.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    VERIFICATION INFRASTRUCTURE                           │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                    Trust-Root Hosts (HTTPS)                         │ │
│  │                                                                     │ │
│  │  api.registry.        us.registry.          eu.registry.           │ │
│  │  ciris-services-1.ai  ciris-services-1.ai   ciris-services-1.ai    │ │
│  │                                                                     │ │
│  │  Each serves a GenesisBundle; each is verified on its own against  │ │
│  │  the baked accord holders. Highest verified version is the root.   │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                 CIRIS VERIFY MODULE (Open Source - AGPL-3.0)             │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │  Hardware   │  │  Trust-Root │  │  Binary     │  │  License    │   │
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
| **Trust-root authorization** (accord holders) | Ed25519 | ML-DSA-65 (FIPS 204) | **Required** |
| **Federation rows** (licensure, revocation, key records) | Ed25519 | ML-DSA-65 | **Required** |
| **Hardware Attestation** | Platform-preferred (see below) | ML-DSA-65 (software) | **Required** |
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

#### 3. Accord-Authorized Trust Root
The trust root is a GenesisBundle authorized by a strict majority of the accord
holders whose keys are baked into the binary (CC 5.3.4, §5). No host, registrar or
single key can substitute it:
- a host can withhold a bundle but cannot forge one;
- one verified host is enough to select a root;
- two verified bundles at the same version with different fingerprints are
  equivocation, select nothing, and report `ERROR_SOURCES_DISAGREE`.

#### 4. Fail-Safe to Community Mode
Any error condition degrades to CIRISCare (unlicensed) behavior:
- Binary tampered → LOCKDOWN
- Trust-root equivocation → RESTRICTED
- No trust root verified → COMMUNITY MODE
- No honoured licensure row → COMMUNITY MODE

**The failure mode is always MORE restrictive, never less.**

#### 5. Mandatory Disclosure
The binary returns a `mandatory_disclosure` string that:
- Is baked into the binary (cannot be modified without detection)
- MUST be displayed to users
- Accurately reflects the actual license status

#### 6. Public Protocol, Open Implementation
- **Public**: Protocol spec (this document), interface definition (protobuf)
- **Open Source**: Implementation source code (AGPL-3.0)
- **Verifiable**: Behavior is deterministic and auditable

## Protocol Specification

### 1. Service Definition

```protobuf
// ciris_verify.proto
// Version: 2.0.0
//
// This protocol is PUBLIC. Anyone can implement a client.
// The server implementation is open-source (AGPL-3.0).

syntax = "proto3";

package ciris.verify.v2;

option go_package = "github.com/cirisai/ciris-verify/proto/v2";

// CIRISVerify provides hardware-rooted license verification
service CIRISVerify {
  // Get the current license status for this deployment
  rpc GetLicenseStatus(LicenseStatusRequest) returns (LicenseStatusResponse);

  // Check if a specific capability is allowed
  rpc CheckCapability(CapabilityCheckRequest) returns (CapabilityCheckResponse);

  // The trust root this module selected (CC 5.3.4)
  rpc GetTrustRoot(TrustRootRequest) returns (TrustRoot);

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

  // Licensed statuses (reserved for the licensure gate, CC 4.4.3.8)
  LICENSED_PROFESSIONAL = 1;      // Professional licence
  LICENSED_COMMUNITY_PLUS = 2;    // Enhanced community (some features)

  // Unlicensed statuses
  UNLICENSED_COMMUNITY = 3;       // Standard CIRISCare
  UNLICENSED_UNVERIFIED = 4;      // Could not verify (offline grace)

  // Error statuses
  ERROR_BINARY_TAMPERED = 10;     // Integrity check failed
  ERROR_SOURCES_DISAGREE = 11;    // Trust-root equivocation
  ERROR_VERIFICATION_FAILED = 12; // No trust root verified
  ERROR_LICENSE_REVOKED = 13;     // Reserved for the licensure gate
  ERROR_LICENSE_EXPIRED = 14;     // Reserved for the licensure gate
}
```

### 3. License Details

`LicenseDetails` is populated only by the licensure gate (see Licensure below), which
is not implemented; it is absent from every response today.

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

  // Never populated (no licence JWT exists)
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

### 5. Trust-Root Validation (CC 5.3.4)

Each configured trust-root host serves a GenesisBundle at `GET /v1/trust-root/bundle`
(registries also serve it at `/v1/steward-key`). The response wrapper is unsigned;
only `bundle` is read. Each bundle is verified independently:

1. it parses under the wire shape (each `attestations` element is exactly one of a
   delegation row, a `family` record or a `community` record, rows first);
2. `version` is 4 (the only accepted root version);
3. `family_key_id` is the baked accord family;
4. `consensus_protocol` is `quorum:M/N` (anything else is refused, never guessed);
5. at least `max(M, strict_majority(baked roster))` distinct baked holders authorized
   it with a hybrid signature (Ed25519 over the 32-byte authorization digest,
   ML-DSA-65 over `digest ‖ ed25519_sig`); a duplicate holder is refused, a holder
   outside the baked roster never counts;
6. it carries a `genesis-charter` row.

The authorization digest is SHA-256 over the JCS canonicalization of the projection
in `ciris_verify_core::genesis_bundle`.

Selection: the highest verified `version` is the root; two verified bundles at that
version with different fingerprints are equivocation and select nothing
(`produced_at` breaks no tie, CC 3.2 T8(ii)). One verified host is enough.

```protobuf
message SourceValidation {
  ValidationStatus overall_status = 4;
  repeated SourceResult sources = 12;  // one per trust-root host
  TrustRoot trust_root = 13;           // the selected root, if any
}

message SourceResult {
  string source = 1;              // host base URL
  bool reachable = 2;
  bool valid = 3;                 // served a bundle that verifies
  int64 checked_at = 6;
  string error = 7;
  string bundle_fingerprint = 12; // sha256:<hex> over JCS(bundle)
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

The following disclosure strings are baked into the binary and cannot be modified. The licensed, revoked and expired strings apply only once the licensure gate (CC 4.4.3.8) exists:

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
Trust-root hosts served two different verified bundles at the same version.
Possible security incident or network attack detected.
Operating in restricted mode. Contact: security@ciris.ai"

ERROR_LICENSE_REVOKED:
"License {license_id} has been REVOKED.
Reason: {revocation_reason}
This deployment is no longer authorized for professional use.
Operating in community mode only."

ERROR_LICENSE_EXPIRED:
"License {license_id} expired on {expiry_date}.
Operating in community mode until license is renewed.
Contact your administrator or licensing@ciris.ai"
```

## HTTPS Endpoint

### GET /v1/trust-root/bundle

Each trust-root host serves its GenesisBundle here (registries also serve it at
`/v1/steward-key`). The response is a JSON wrapper whose only field read is
`bundle`; the wrapper is unsigned and carries no authority. Verification and
selection are specified in §5. Defaults: `https://api.registry.ciris-services-1.ai`,
`https://us.registry.ciris-services-1.ai`, `https://eu.registry.ciris-services-1.ai`.
Hosts add availability, not trust: a host can withhold a bundle but cannot forge
one, because only the baked accord holders can authorize it. DNS is not a source.

## Licensure (CC 4.4.3.8)

A licence is a cosigned `licensure:{authority}:v1` row about the deployment's key,
honoured when its authority is in the reader's trust set. This module does not yet
evaluate licensure rows, so the licence gate returns no licence and every deployment
reports `UNLICENSED_COMMUNITY` or a more restrictive status. The local cache is never
an authority for a licence. `LICENSED_PROFESSIONAL`, `LICENSED_COMMUNITY_PLUS`,
`ERROR_LICENSE_EXPIRED`, `ERROR_LICENSE_REVOKED` and the `LicenseDetails` message are
reserved for the licensure gate and are not produced today; `LicenseDetails.license_jwt`
and the `license_pqc_*` / `signature_mode` fields are never populated.

## Revocation

Revocation is a quorum-signed `federation_revocations` row. There is no separate
signed revocation list and no revocation endpoint.

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
| Fake license file | A licence is a cosigned licensure row honoured only through the reader's trust set; no file or cache is an authority |
| Substituted or MITM trust-root host | Bundle must verify against the baked accord holders; a host can withhold, not forge |
| Equivocating hosts | Two verified bundles at one version select nothing (`ERROR_SOURCES_DISAGREE`) |
| Rollback to an older trust root | Highest verified version is selected |
| Replay of a revoked object | Quorum-signed `federation_revocations` rows |
| Emulator/debugger interception | Platform integrity checks |
| Binary modification | Self-integrity verification |
| Key extraction from binary | Keys stored in hardware, never in binary |

### Security Assumptions

1. Hardware security modules (TPM/Secure Enclave/Keystore) are not compromised
2. Fewer than a strict majority of the baked accord holders' keys are compromised
3. At least one trust-root host is reachable (otherwise the module stays in community mode)
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
ed25519_sig = Sign_Ed25519(key, message)
mldsa_sig   = Sign_ML-DSA-65(pqc_key, message || ed25519_sig)
```

Verification order:
1. Verify the Ed25519 signature over `message`
2. Verify the ML-DSA-65 signature over `message || ed25519_sig`
3. **Both MUST pass** - failure of either rejects the object

For a GenesisBundle authorization, `message` is the 32-byte authorization digest (§5).

This binding ensures an attacker cannot strip one signature while preserving the other.

#### 3. Transport Security

TLS protects availability and privacy of the bundle fetch, not its authority: a
bundle is accepted only if it verifies against the baked accord holders, so a host
presenting a different certificate can at most withhold a root. `VerifyConfig.cert_pin`
accepts a `sha256:` certificate fingerprint for a host.

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

When validation status is `PARTIAL_AGREEMENT` (a root was selected, but some hosts failed or served a lower version):

| Capability | Allowed |
|------------|---------|
| A0_ADVISORY | Yes |
| A1_LIMITED | Yes |
| A2_MODERATE | Yes |
| A3_HIGH | **Reduced** - requires supervisor confirmation |
| A4_CRITICAL | **NO** |

Rationale: Partial agreement may indicate a host under attack. High-autonomy actions should require additional confirmation.

### Known Limitations

1. **Software-only mode**: Limited to community tier only (see requirement above)
2. **Offline operation**: With no reachable trust-root host the module stays in community mode
3. **Novel attacks**: New hardware vulnerabilities may emerge; binary updates required
4. **Social engineering**: Cannot prevent users from ignoring warnings
5. **Hardware PQC gap**: PQC signatures are software-based until HSMs support ML-DSA
6. **Clock dependency**: Significant clock skew can cause false positives/negatives

## Testing Requirements

### Unit Tests
- GenesisBundle verification against the baked roster
- Trust-root selection (highest version, equivocation)
- Capability grant/deny logic
- Mandatory disclosure selection

### Integration Tests
- End-to-end trust-root fetch and verification
- Offline degradation behavior
- Equivocation handling
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

### Release Verification (Hybrid Signatures)

Each release artifact is described by a build-manifest Contribution
(`provenance:build_manifest:{target}:v1`) signed with a bound hybrid signature
(Ed25519 + ML-DSA-65) by the CI pipeline key. The manifest names the artifact's
`binary_hash`, `binary_version` and target; a wheel's own `Version` and platform tag
must match the manifest (`verify_wheel_blob`). The pipeline key has standing either
by delegation from an accord-rooted authority or by the accord role on its key record.
The full lifecycle is FSD-006; the manifest shape is `docs/BUILD_MANIFEST.md`.

Clients MUST verify the manifest signature and the artifact hash before loading a binary.

## Versioning

### Protocol Versioning
- Major: Breaking changes to protocol
- Minor: Backward-compatible additions
- Patch: Bug fixes

Current version: **2.0.0** (Hybrid Cryptography, package `ciris.verify.v2`).

### Binary Versioning
Binaries are versioned independently but must support current protocol version.

### Cryptographic Agility
The protocol supports algorithm agility via the `PQCAlgorithm` enum. Future NIST standards (FIPS 206/FALCON, HQC) can be added without breaking changes.

## Governance

### Trust-Root Rotation
- The trust root rotates by a new GenesisBundle `version` authorized by the accord quorum (§5); the highest verified version is selected.
- The accord roster itself changes by an entrenched-family `supersedes` authorized by the prior roster's strict majority (FSD-004, FSD-005).

### Revocation
- Revocation is a quorum-signed `federation_revocations` row.
- Revocation policy for licences is the licensing authority's, expressed through its licensure rows (CC 4.4.3.8).

### Disputes
- Arbitration process defined in license agreement
- Steward accountable under L3C structure

### Humanitarian and Extended Deployment Options

The following licence options MAY be configured by the licensing authority for specific deployment contexts:

#### Extended Offline Grace Period

Standard licenses include 72-hour offline grace. For humanitarian deployments (remote clinics, disaster response, conflict zones), extended grace periods are available:

| Deployment Type | Recommended Grace Period |
|-----------------|-------------------------|
| Urban healthcare | 72 hours (standard) |
| Rural/remote clinic | 168 hours (7 days) |
| Humanitarian field mission | 336 hours (14 days) |
| Disaster response | 504 hours (21 days) |

The grace period is `DeploymentConstraints.offline_grace_hours`.

#### Low-Bandwidth Mode

For deployments with limited connectivity (satellite, 2G), a licence MAY extend the
cache TTL to reduce verification frequency. One verified trust-root host is already
sufficient to select a root.

#### Multi-Language Disclosure

Mandatory disclosures are available in localized versions. The binary includes disclosure strings for:
- English (en) - Default
- Additional languages configured at build time

Future versions will support runtime locale selection via `Accept-Language` header equivalent.

#### Emergency Override (Not Specified)

For mass casualty events and declared emergencies, an emergency mode MAY:
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
