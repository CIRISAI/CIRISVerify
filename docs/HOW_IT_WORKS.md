# How CIRISVerify Works

**Last Updated**: 2026-02-17

CIRISVerify is a Rust shared library (`libciris_verify_ffi`) with Python bindings (`ciris-verify`) that provides hardware-rooted license verification for the CIRIS ecosystem. Every CIRISAgent installation includes CIRISVerify to cryptographically verify its license status.

---

## What It Does

CIRISVerify does **four things** (think: driver's license, registration, insurance, driving record):

1. **Identity & Signing Key** (Driver's License) — Stores a hardware-bound Ed25519 signing key that IS the agent's identity. Proves "I am who I claim to be." The key is the identity; they are the same mechanism.

2. **Agent File Integrity** (Vehicle Registration) — Tripwire-style checking of all CIRISAgent Python files against a signed manifest from CIRISRegistry. Every file in the distribution is hashed at build time; CIRISVerify validates at runtime (full check or spot check). **Any file change whatsoever** — except `.env`, log, or audit files — triggers immediate forced shutdown.

3. **Hardware Attestation + License Accountability** (Insurance) — Validates the execution environment via TPM/Secure Enclave/Keystore AND, if this is a licensed install, identifies **who is responsible**: the organization ID that deployed this agent, the responsible licensed party, and their contact information. Just like insurance proves both that you're covered and who is liable if something goes wrong. Software-only attestation caps at COMMUNITY tier.

4. **Binary Self-Integrity + Multi-Source Validation** (Driving Record) — Validates its own Rust binary hasn't been tampered with, checks revocation status against 3 independent sources, and verifies the license JWT with dual signatures (Ed25519 + ML-DSA-65).

**Is CIRISVerify sufficient to trust an agent?** No — it proves the agent is *authentic* (necessary). The CIRIS covenant system proves the agent *behaves ethically* (sufficient together). CIRISVerify is the DMV; the covenant is the rules of the road.

It returns a `LicenseStatusResponse` containing:
- **Status code** — What mode the agent should operate in
- **Mandatory disclosure** — Text that MUST be displayed to users
- **Capability grants** — What the license allows (if licensed)
- **Hardware attestation** — Proof of hardware-rooted verification
- **Source validation** — Multi-source consensus results
- **File integrity** — Result of Tripwire agent file check

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Multi-Source Validation                    │
│                                                              │
│  DNS US                    DNS EU                  HTTPS     │
│  us.registry.              eu.registry.            api.      │
│  ciris-services-1.ai       ciris-services-1.ai     registry. │
│                                                    ciris-    │
│                                                    services- │
│                                                    1.ai      │
│                                                              │
│  All 3 queried in parallel. 2-of-3 must agree.              │
│  Any source reporting REVOKED → immediate action.            │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              CIRISVerify Binary (Rust cdylib)                 │
│                                                              │
│  1. Binary integrity self-check                              │
│  2. Multi-source validation (DNS US + DNS EU + HTTPS)        │
│  3. License JWT verification (Ed25519 + ML-DSA-65)           │
│  4. Hardware attestation (TPM/SE/Keystore/Software)          │
│  5. Build LicenseStatusResponse with mandatory disclosure    │
│                                                              │
│  Exposed via C FFI → consumed by Python ctypes bindings      │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              CIRISAgent (Python)                              │
│                                                              │
│  ciris_adapters/ciris_verify/adapter.py                      │
│    → CIRISVerifyService (service.py)                         │
│      → CIRISVerify or MockCIRISVerify (ciris-verify package) │
│        → libciris_verify_ffi.{so,dylib,dll} (Rust FFI)       │
│                                                              │
│  Result feeds into:                                          │
│  - WiseBus.PROHIBITED_CAPABILITIES                           │
│  - Mandatory disclosure display                              │
│  - Agent tier determination                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Status Codes

The `LicenseStatus` enum determines agent operating mode:

| Code | Name | Meaning | Agent Mode |
|------|------|---------|------------|
| 100 | `LICENSED_PROFESSIONAL` | Valid professional license | Full licensed capabilities |
| 101 | `LICENSED_PROFESSIONAL_GRACE` | License valid, in offline grace period | Licensed (time-limited) |
| 200 | `UNLICENSED_COMMUNITY` | No license, verification succeeded | Community mode |
| 201 | `UNLICENSED_COMMUNITY_OFFLINE` | No license, offline | Community mode |
| 300 | `RESTRICTED_VERIFICATION_FAILED` | Verification failed | Restricted |
| 301 | `RESTRICTED_SOURCES_DISAGREE` | Multi-source disagreement | Restricted |
| 302 | `RESTRICTED_PARTIAL_AGREEMENT` | Only 2-of-3 sources agree | Restricted |
| 400 | `ERROR_BINARY_TAMPERED` | Binary integrity check failed | Error/degraded |
| 401 | `ERROR_REVOKED` | License revoked | Error/degraded |
| 402 | `ERROR_EXPIRED` | License expired | Error/degraded |
| 403 | `ERROR_HARDWARE_MISMATCH` | Hardware changed since license | Error/degraded |
| 404 | `ERROR_VERIFICATION_FAILED` | General verification failure | Error/degraded |
| 405 | `ERROR_SOURCES_DISAGREE` | Sources conflict (possible attack) | Error/degraded |
| 500 | `LOCKDOWN_INTEGRITY_FAILURE` | Critical integrity failure | Lockdown |
| 501 | `LOCKDOWN_ATTACK_DETECTED` | Attack pattern detected | Lockdown |

**Fail-secure rule**: Status always degrades to MORE restrictive, never less.

---

## How Agents Consume It

### 1. Via the CIRISVerify Adapter

CIRISAgent loads CIRISVerify as an adapter:

```python
# In CIRISAgent's adapter configuration
adapter = CIRISVerifyAdapter(runtime=runtime, adapter_config={
    "use_mock": False,        # Use real binary
    "cache_ttl_seconds": 300, # Cache results for 5 minutes
    "timeout_seconds": 10.0,  # Verification timeout
})
await adapter.start()

# Check license status
status = await adapter.get_license_status()
if status.allows_licensed_operation():
    # Professional mode
    pass
else:
    # Community mode — display mandatory disclosure
    print(status.mandatory_disclosure.text)
```

### 2. Via the Python SDK Directly

```python
from ciris_verify import CIRISVerify, LicenseStatus
import os

verifier = CIRISVerify()
status = await verifier.get_license_status(challenge_nonce=os.urandom(32))

print(f"Status: {status.status}")           # e.g., LicenseStatus.UNLICENSED_COMMUNITY
print(f"Licensed: {status.allows_licensed_operation()}")
print(f"Hardware: {status.hardware_type}")   # e.g., HardwareType.SOFTWARE_ONLY
print(f"Disclosure: {status.mandatory_disclosure.text}")

# Check specific capability
result = await verifier.check_capability("medical:diagnosis")
print(f"Medical allowed: {result.allowed}")  # False in community mode
```

### 3. Mock Mode for Testing

```python
from ciris_verify import MockCIRISVerify

mock = MockCIRISVerify()
status = await mock.get_license_status(challenge_nonce=b'\x00' * 32)
# Returns UNLICENSED_COMMUNITY with proper disclosure
```

---

## Capability Taxonomy Integration

CIRISVerify status maps to CIRISAgent's WiseBus prohibition system:

### WiseBus Prohibition Levels

| Level | Description | Example Domains |
|-------|-------------|-----------------|
| `REQUIRES_SEPARATE_MODULE` | Needs a licensed module (CIRISMedical, etc.) | medical, financial, legal, home_security, identity_verification, content_moderation, research, infrastructure_control |
| `NEVER_ALLOWED` | Absolutely prohibited regardless of license | weapons, illegal_activity, child_exploitation, critical_infrastructure_attack |
| `TIER_RESTRICTED` | Requires minimum tier level | community_moderation (tier 3+) |

### How License Status Affects Prohibitions

```
LICENSED_PROFESSIONAL (100):
  → Licensed module (e.g., CIRISMedical) checks CIRISVerify
  → If licensed with "medical:*" capability, lifts medical prohibitions
  → WiseBus.PROHIBITED_CAPABILITIES.discard("medical")
  → NEVER_ALLOWED categories remain prohibited regardless

UNLICENSED_COMMUNITY (200):
  → All REQUIRES_SEPARATE_MODULE categories stay prohibited
  → standard:* and tool:* operations are allowed
  → Agent operates in community mode

LOCKDOWN (500+):
  → ALL capabilities prohibited
  → Minimal functionality only
```

### Standard Operations (Always Allowed)

These capability prefixes are allowed in ANY mode (community, licensed, restricted):
- `standard:*` — data collection, surveys, focus groups, A/B testing
- `tool:*` — search, calculator, file operations

---

## Multi-Source Validation

CIRISVerify queries three independent sources:

| Source | Endpoint | Purpose |
|--------|----------|---------|
| DNS US | `us.registry.ciris-services-1.ai` | US-hosted DNS TXT records |
| DNS EU | `eu.registry.ciris-services-1.ai` | EU-hosted DNS TXT records |
| HTTPS | `api.registry.ciris-services-1.ai` | HTTPS API endpoint |

**Consensus rules:**
- 3-of-3 agree → `ALL_SOURCES_AGREE` → Full confidence
- 2-of-3 agree → `PARTIAL_AGREEMENT` → Proceed with caution
- Sources disagree → `SOURCES_DISAGREE` → Security alert, restricted mode
- 0 reachable → `NO_SOURCES_REACHABLE` → Use cache or degrade

---

## Agent File Integrity (Tripwire)

CIRISVerify validates that the CIRISAgent's Python files have not been tampered with since the distribution was built. This is similar to how [Tripwire](https://en.wikipedia.org/wiki/Open_Source_Tripwire) works for server security.

### How It Works

1. **At build time**: A manifest is generated containing the SHA-256 hash of every file in the distribution (version 2.0.0+). CIRISRegistry stores these manifests per version.
2. **At runtime**: CIRISVerify hashes files on disk and compares against the signed manifest.
3. **Any mismatch = forced shutdown**: Modified files, missing files, or unexpected `.py` files all trigger immediate shutdown.

### Check Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Full check** | Hash every file in the manifest + scan for unexpected files | Startup, periodic deep scan |
| **Spot check** | Hash a random subset of files | Runtime monitoring (e.g., every 5 minutes) |

### Exempt Files

These files are **not checked** because they change during normal operation:

| Pattern | Reason |
|---------|--------|
| `.env` | Environment configuration |
| `*.log` | Log output |
| `*.audit` | Audit trail |
| `*.db`, `*.sqlite` | Runtime databases |
| `*.pyc`, `__pycache__/` | Python bytecode cache |
| `.git/`, `.venv/` | Development artifacts |
| `data/`, `logs/`, `dist/`, `build/` | Runtime/build directories |

### Python API

```python
from ciris_verify import CIRISVerify

verifier = CIRISVerify()
result = await verifier.check_agent_integrity(
    manifest_path="/path/to/manifest.json",
    agent_root="/path/to/ciris_agent/",
    spot_check_count=0,  # 0 = full check
)

if not result.integrity_valid:
    # FORCED SHUTDOWN — agent files have been tampered with
    print(f"Integrity failure: {result.failure_reason}")
    # failure_reason is one of: "modified", "missing", "unexpected", "manifest"
```

---

## Mandatory Disclosure

Every `LicenseStatusResponse` includes a `MandatoryDisclosure`:

```python
class MandatoryDisclosure:
    text: str                          # Display text (MUST show to users)
    severity: DisclosureSeverity       # info, warning, critical
    locale: str                        # Language code (default: "en")
    legal_jurisdiction: Optional[str]  # Applicable jurisdiction
```

**Agents MUST display this text.** It is baked into the binary and accurately describes the license status. Failure to display is a violation of the CIRIS ecosystem rules.

Example for community mode:
> "NOTICE: This is a CIRISCare community deployment. NOT a licensed professional provider. For medical, legal, or financial needs, seek licensed providers."

---

## Building and Installing

### Build the Rust Binary
```bash
cd /path/to/CIRISVerify
cargo build --release
# Produces: target/release/libciris_verify_ffi.{so,dylib}
```

### Install the Python Package
```bash
# Copy binary into Python package
cp target/release/libciris_verify_ffi.dylib bindings/python/ciris_verify/

# Install (editable mode for development)
pip install -e bindings/python/

# Verify
python -c "from ciris_verify import CIRISVerify, MockCIRISVerify, LicenseStatus; print('OK')"
```

### Or Use the Build Script
```bash
./scripts/build_and_install.sh
```

### Production: Install from PyPI
```bash
pip install ciris-verify
# Platform-specific wheel includes the correct Rust binary
```

---

## File Layout

```
CIRISVerify/
├── src/
│   ├── ciris-keyring/          # Hardware keyring (TPM/SE/Keystore)
│   ├── ciris-crypto/           # Hybrid crypto (Ed25519 + ML-DSA-65)
│   ├── ciris-verify-core/      # Core verification engine
│   │   └── src/
│   │       ├── engine.rs       # License engine + multi-source validation
│   │       ├── config.rs       # Infrastructure endpoints
│   │       ├── types.rs        # Rust types
│   │       └── security/       # Binary integrity checks
│   └── ciris-verify-ffi/       # C FFI layer
│       └── src/lib.rs          # FFI functions called by Python
├── bindings/
│   └── python/
│       └── ciris_verify/
│           ├── __init__.py     # Package exports
│           ├── client.py       # CIRISVerify + MockCIRISVerify (ctypes FFI)
│           ├── types.py        # Pydantic models (LicenseStatus, etc.)
│           └── exceptions.py   # Error types
├── protocol/
│   └── ciris_verify.proto      # Public API contract (gRPC/protobuf)
├── FSD/
│   └── FSD-001_CIRISVERIFY_PROTOCOL.md  # Full specification
└── scripts/
    └── build_and_install.sh    # Build + install helper
```
