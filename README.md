# CIRISVerify

**Hardware-Rooted License Verification for the CIRIS Ecosystem**

**Protocol Version**: 2.0.0 | **Cryptographic Baseline**: Ed25519 + ML-DSA-65 (Hybrid)

CIRISVerify is an open-source binary module that provides cryptographic proof of license status for CIRIS deployments. It ensures that community agents (CIRISCare) cannot masquerade as licensed professional agents (CIRISMedical, CIRISLegal, CIRISFinancial).

**Post-Quantum Ready**: CIRISVerify launches with hybrid cryptography (classical + ML-DSA) as its day-1 standard, implementing NIST FIPS 204 and meeting NSA CNSA 2.0 requirements.

## The Problem

The CIRIS ecosystem is fully open-source (AGPL). This is intentional—we believe in radical openness. But it creates a specific challenge:

**How do you prove license status when anyone can modify the code?**

An adversary could fork CIRISCare, modify it to claim "I am licensed CIRISMedical," and perform high-risk medical actions without steward accountability.

## The Solution

CIRISVerify provides a **hardware-rooted trust anchor** that:

1. **Cannot be forged** - Responses are signed by keys stored in secure hardware (TPM, Secure Enclave, Android Keystore)
2. **Cannot be spoofed** - Validates against multiple independent sources (DNS + HTTPS)
3. **Fails safe** - Any error condition degrades to community mode, never less restrictive
4. **Is always transparent** - Returns mandatory disclosure strings that MUST be shown to users

## Architecture

```
Multi-Source Validation          CIRISVerify Binary (AGPL-3.0)        CIRISAgent (Open)
┌────────────────────┐          ┌──────────────────────────┐          ┌─────────────────┐
│ DNS (US registrar) │─────────▶│ Hardware Security Module │          │                 │
│ DNS (EU registrar) │─────────▶│ Multi-Source Validator   │─────────▶│ WiseBus         │
│ HTTPS endpoint     │─────────▶│ License Engine           │          │ Capability Gate │
└────────────────────┘          │ Hybrid Crypto (Ed25519 + │          │                 │
All 3 MUST agree                │   ML-DSA-65)             │          └─────────────────┘
(Ed25519 key + PQC              └──────────────────────────┘          DEPENDS on binary
 fingerprint)                   Signs with BOTH classical             MUST show disclosure
                                and post-quantum signatures
```

## What's Public vs Private

| Component | Visibility | Reason |
|-----------|-----------|--------|
| Protocol specification | **Public** | Anyone can implement a client |
| Protobuf definitions | **Public** | Interoperability |
| Integration examples | **Public** | Ease of adoption |
| Binary source code | **Public (AGPL-3.0)** | Open-source transparency |
| Hardware key material | **Private** | Security |

## Repository Structure

```
CIRISVerify/
├── FSD/
│   └── FSD-001_CIRISVERIFY_PROTOCOL.md    # Full specification
├── protocol/
│   └── ciris_verify.proto                  # Public protocol definition
├── docs/
│   ├── integration-guide.md               # How to integrate (TODO)
│   └── security-model.md                  # Threat model details (TODO)
└── README.md                              # This file
```

## License Status Types

| Status | Meaning | Agent Behavior |
|--------|---------|----------------|
| `LICENSED_PROFESSIONAL` | Full steward-backed license | All licensed capabilities enabled |
| `LICENSED_COMMUNITY_PLUS` | Enhanced community | Some additional features |
| `UNLICENSED_COMMUNITY` | Standard CIRISCare | Community capabilities only |
| `UNLICENSED_UNVERIFIED` | Could not verify | Restricted community mode |
| `ERROR_BINARY_TAMPERED` | Integrity check failed | **LOCKDOWN** - minimal functionality |
| `ERROR_SOURCES_DISAGREE` | Possible attack | **RESTRICTED** - investigation required |

## Mandatory Disclosure

Every response includes a `mandatory_disclosure` field that:

- Is baked into the binary (cannot be modified)
- MUST be displayed to end users
- Accurately describes the license status

Example for unlicensed community deployment:

> "CIRISCare community deployment. NOT a licensed professional provider. Cannot provide official certifications or steward-backed advice. For professional medical/legal/financial needs, seek licensed providers. This agent defers to human judgment for significant decisions."

## Multi-Source Validation

To prevent single points of compromise, CIRISVerify validates the steward's public key against three independent sources:

1. **DNS TXT record** at `_ciris-verify.ciris-services-1.ai` (US registrar)
2. **DNS TXT record** at `_ciris-verify.ciris-services-2.ai` (EU registrar)
3. **HTTPS endpoint** at `verify.ciris.ai`

All three must return the same steward public key. If they disagree, `ERROR_SOURCES_DISAGREE` is returned—this may indicate an attack.

## Hardware Security & Hybrid Cryptography

CIRISVerify uses platform-specific secure hardware with **hybrid cryptography**:

| Platform | Hardware Module | Classical Sig | PQC Sig | Security Level |
|----------|----------------|---------------|---------|----------------|
| Android | Hardware Keystore / StrongBox | Hardware | Software | High |
| iOS | Secure Enclave | Hardware | Software | High |
| Server | TPM 2.0 | Hardware | Software | High |
| Desktop | TPM 2.0 or SGX | Hardware | Software | Medium-High |
| Fallback | Software-only | Software | Software | Lower (with warnings) |

**Dual Signature Requirement**: Every response includes:
1. **Ed25519 signature** from hardware (provides hardware binding)
2. **ML-DSA-65 signature** from software (provides quantum resistance)

Both signatures **must verify**. This provides defense-in-depth against both classical and quantum attacks.

## Integration

CIRISAgent depends on CIRISVerify. Without a valid response from the binary:

```python
# In CIRISAgent
license_status = await verify_client.get_license_status()

if license_status.status in LOCKDOWN_STATUSES:
    # Complete lockdown - minimal functionality
    self.PROHIBITED_CAPABILITIES = ALL_CAPABILITIES

elif license_status.status in COMMUNITY_STATUSES:
    # Community mode - no professional capabilities
    self.PROHIBITED_CAPABILITIES = ALL_PROFESSIONAL_CAPABILITIES

else:
    # Licensed - enable granted capabilities only
    self.PROHIBITED_CAPABILITIES = (
        ALL_CAPABILITIES - set(license_status.capabilities)
    )

# ALWAYS include disclosure
response.metadata["license_disclosure"] = license_status.mandatory_disclosure
```

## License

CIRISVerify is licensed under **AGPL-3.0-or-later**, consistent with the rest of the CIRIS ecosystem. See the [LICENSE](LICENSE) file for full terms.

## Verification

You can verify a license independently using **hybrid verification**:

1. Get the license JWT from the response (format: `header.payload.ed25519_sig.mldsa_sig`)
2. Fetch the steward public keys from `verify.ciris.ai/v1/steward-key`
3. Verify the Ed25519 signature against `steward_key_classical`
4. Verify the ML-DSA-65 signature against `steward_key_pqc`
5. **Both signatures must pass** - failure of either rejects the license
6. Check the claims match the response

```bash
# Example verification
curl https://verify.ciris.ai/v1/validate-license \
  -H "Content-Type: application/json" \
  -d '{"license_jwt": "eyJ..."}'

# Response includes both verification results
{
  "valid": true,
  "classical_signature_valid": true,
  "pqc_signature_valid": true,
  "signature_mode": "HYBRID_REQUIRED",
  ...
}
```

## Contributing

The protocol specification is open for review and feedback:

1. Read `FSD/FSD-001_CIRISVERIFY_PROTOCOL.md`
2. Open issues for questions or concerns
3. Security researchers: Please report vulnerabilities to `security@ciris.ai`

## Contact

- **General**: info@ciris.ai
- **Security**: security@ciris.ai
- **Licensing**: licensing@ciris.ai

---

**CIRISVerify is infrastructure for trust, not control.**

The capability is the same whether licensed or not. The difference is accountability—and with CIRISVerify, that accountability is cryptographically provable.
