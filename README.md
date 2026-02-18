# CIRISVerify

**The DMV for AI Agents — Identity, Integrity, and Accountability**

**Protocol Version**: 2.0.0 | **Cryptographic Baseline**: Ed25519 + ML-DSA-65 (Hybrid)

CIRISVerify is the trust anchor for the CIRIS ecosystem. Think of it like the DMV system for AI agents: it issues the driver's license (identity), performs the vehicle inspection (software/hardware integrity), and tracks insurance (who is responsible and under what authority). Without it, any agent could claim to be anything.

**Post-Quantum Ready**: Hybrid cryptography (Ed25519 + ML-DSA-65) as day-1 standard, implementing NIST FIPS 204.

## What CIRISVerify Does (The Driving Analogy)

Every car on the road needs three things to operate legally. Every CIRIS agent needs the same three things:

### 1. Driver's License — Identity & Signing Key

Just like a driver's license proves *who you are*, CIRISVerify holds a hardware-bound Ed25519 signing key that **is** the agent's identity. The key doesn't represent the identity — it *is* the identity. Stored in secure hardware (TPM, Secure Enclave, Android Keystore), it cannot be forged or transferred.

### 2. Registration & Inspection — Software and Hardware Integrity

Just like vehicle registration proves your car is roadworthy and the VIN matches the title, CIRISVerify performs two integrity checks:

- **Software integrity** (Tripwire): Every file in the CIRISAgent distribution is SHA-256 hashed at build time and stored in a signed manifest in CIRISRegistry. At runtime, CIRISVerify validates files against this manifest. Any modification — even one byte — triggers forced shutdown.
- **Hardware attestation**: Validates the execution environment via TPM/Secure Enclave/Keystore. Software-only environments are capped at community tier (like driving with a learner's permit).

### 3. Insurance — Accountability and Licensing (HITL)

Just like insurance proves *who is liable* if something goes wrong, CIRISVerify tracks the human-in-the-loop accountability chain:

- **Which organization** deployed this agent
- **Which licensed human** is responsible for its actions
- **What capabilities** they are authorized to use (medical, legal, financial)
- **Mandatory disclosure** that must be shown to every user, accurately describing the agent's license status

An unlicensed community agent is like an uninsured driver — it can still drive (operate), but it cannot perform professional services that require accountability.

### The DMV Itself — Multi-Source Validation

CIRISVerify doesn't trust a single source. It queries three independent infrastructure endpoints (DNS US, DNS EU, HTTPS API) and requires consensus — like checking a license against both the state database and the federal system. If sources disagree, that's a red flag (possible attack), and the agent is restricted.

**Is CIRISVerify sufficient to trust an agent?** No — it proves the agent is *authentic* (necessary). The CIRIS covenant system proves the agent *behaves ethically* (sufficient together). CIRISVerify is the DMV; the covenant is the rules of the road.

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

## Quick Start

### Build from Source

```bash
# Build the Rust shared library
cargo build --release

# Copy binary into Python package
cp target/release/libciris_verify_ffi.dylib bindings/python/ciris_verify/  # macOS
# cp target/release/libciris_verify_ffi.so bindings/python/ciris_verify/   # Linux

# Install Python bindings
pip install -e bindings/python/

# Verify
python -c "from ciris_verify import CIRISVerify, MockCIRISVerify, LicenseStatus; print('OK')"
```

Or use the build script:
```bash
./scripts/build_and_install.sh
```

### Install from PyPI (Coming Soon)

```bash
pip install ciris-verify
# Platform-specific wheel will include the correct Rust binary automatically
# Supports: Linux x86_64, macOS ARM64, macOS x86_64, Windows x86_64
```

## Python SDK

```python
from ciris_verify import CIRISVerify, MockCIRISVerify, LicenseStatus
import os

# For testing/community mode (no binary needed):
mock = MockCIRISVerify()
status = await mock.get_license_status(challenge_nonce=os.urandom(32))
print(status.status)                    # LicenseStatus.UNLICENSED_COMMUNITY
print(status.mandatory_disclosure.text) # Required disclosure text

# Check capabilities:
result = await mock.check_capability("medical:diagnosis")
print(result.allowed)  # False in community mode

result = await mock.check_capability("standard:telemetry")
print(result.allowed)  # True — standard ops always allowed

# For production (with Rust binary):
verifier = CIRISVerify()
status = await verifier.get_license_status(challenge_nonce=os.urandom(32))
```

See [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md) for full integration details.

## Repository Structure

```
CIRISVerify/
├── FSD/
│   └── FSD-001_CIRISVERIFY_PROTOCOL.md    # Full specification
├── protocol/
│   └── ciris_verify.proto                  # Public protocol definition
├── src/
│   ├── ciris-keyring/                     # Hardware keyring (TPM/SE/Keystore)
│   ├── ciris-crypto/                      # Hybrid crypto (Ed25519 + ML-DSA-65)
│   ├── ciris-verify-core/                 # Core verification engine
│   └── ciris-verify-ffi/                  # C FFI layer
├── bindings/
│   └── python/ciris_verify/               # Python SDK (ciris-verify package)
├── docs/
│   ├── HOW_IT_WORKS.md                    # How CIRISVerify works
│   ├── IMPLEMENTATION_ROADMAP.md          # Development roadmap
│   └── REGISTRY_INTEGRATION_REQUIREMENTS.md # Registry dependencies
├── scripts/
│   └── build_and_install.sh               # Build + install helper
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

1. **DNS** at `us.registry.ciris-services-1.ai` (US)
2. **DNS** at `eu.registry.ciris-services-1.ai` (EU)
3. **HTTPS** at `api.registry.ciris-services-1.ai`

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
