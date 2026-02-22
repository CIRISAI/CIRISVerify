# How CIRISVerify Works

**Last Updated**: 2026-02-22 (v0.6.17)

CIRISVerify is a Rust shared library (`libciris_verify_ffi`) with Python bindings (`ciris-verify`) that serves as the trust anchor for the CIRIS ecosystem. Think of it as the **DMV for AI agents** — it handles identity, integrity, and accountability.

---

## The Driving Analogy

Every car on the road needs three things. Every CIRIS agent needs the same three:

| Road Requirement | CIRISVerify Equivalent | What It Proves |
|-----------------|----------------------|----------------|
| **Driver's License** | Hardware-bound Ed25519 signing key | **Who the agent is** — identity cannot be forged or transferred |
| **Registration & Inspection** | Tripwire file integrity + hardware attestation | **The vehicle is sound** — software hasn't been tampered with, hardware environment is genuine |
| **Insurance** | License JWT with org ID, responsible human, capability grants | **Who is liable** — which human/organization is accountable, what they're authorized to do |

The DMV itself? That's the multi-source validation — CIRISVerify doesn't trust any single source, querying 3 independent endpoints and requiring consensus.

---

## What It Does (In Detail)

### 1. Driver's License — Identity & Signing Key

CIRISVerify holds a hardware-bound Ed25519 signing key that **is** the agent's identity. The key doesn't represent the identity — it *is* the identity, the same mechanism. Stored in secure hardware (TPM, Secure Enclave, Android Keystore), it cannot be forged, copied, or transferred. Every response the agent produces is signed with this key, proving authenticity.

### 2. Registration & Inspection — Software and Hardware Integrity

**Software integrity (Tripwire):** Every file in the CIRISAgent distribution is SHA-256 hashed at build time and registered in CIRISRegistry as a signed manifest. At runtime, CIRISVerify hashes files on disk and compares. **Any modification whatsoever** — except `.env`, logs, and runtime data — triggers immediate forced shutdown.

**Hardware attestation:** Validates the execution environment via platform-specific secure hardware. Software-only environments are capped at COMMUNITY tier — like driving with a learner's permit.

### 3. Insurance — Accountability and Licensing (HITL)

If this is a licensed install, CIRISVerify identifies **who is responsible**:
- The **organization ID** that deployed this agent
- The **responsible licensed human** (the human-in-the-loop)
- Their **contact information** and **capability grants** (medical, legal, financial)
- A **mandatory disclosure** that MUST be shown to every user

An unlicensed community agent is like an uninsured driver — it can still operate, but it cannot perform professional services requiring steward accountability.

### 4. The DMV — Multi-Source Validation

CIRISVerify validates against 3 independent sources (DNS US, DNS EU, HTTPS API). All 3 must agree. If they disagree, that's a security alert (possible attack) and the agent enters restricted mode. The license JWT is verified with dual signatures (Ed25519 + ML-DSA-65) — both must pass.

---

## The Response

Every verification returns a `LicenseStatusResponse` containing:
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

## Command-Line Interface

CIRISVerify includes a standalone CLI (`ciris-verify`) for diagnostics and verification:

### Available Commands

| Command | Description | Attestation Level |
|---------|-------------|-------------------|
| `ciris-verify` | Show help and explanation | — |
| `ciris-verify info` | Show system capabilities | — |
| `ciris-verify sources` | Check DNS/HTTPS validation | Level 3 |
| `ciris-verify self-check` | Verify binary integrity | Level 2 |
| `ciris-verify function-check` | Verify FFI function integrity | Runtime |
| `ciris-verify agent-files` | Verify agent file integrity | Level 4 |
| `ciris-verify audit-trail` | Verify audit log integrity | Level 5 |
| `ciris-verify list-manifests` | List available registry manifests | — |

### Attestation Levels

CIRISVerify implements progressive trust verification across 5 levels:

| Level | Name | Verification | CLI Command |
|-------|------|--------------|-------------|
| 1 | Library Loaded | Binary executes successfully | (implicit) |
| 2 | Binary Self-Verification | SHA-256 of THIS binary vs registry | `self-check` |
| 3 | Registry Cross-Validation | 2/3 consensus from DNS US/EU + HTTPS | `sources` |
| 4 | Agent File Integrity | SHA-256 of agent files vs manifest | `agent-files` |
| 5 | Portal Key + Audit Trail | Ed25519 signatures + hash chain | `audit-trail` |

**Critical**: If ANY level fails, ALL higher levels are UNVERIFIED. A compromised Level 2 binary could report "all green" regardless of actual state.

### Example Usage

```bash
# Show system info and capabilities
ciris-verify info

# Check multi-source validation (Level 3)
ciris-verify sources --timeout 15

# Verify binary integrity (Level 2)
ciris-verify self-check

# List available manifests for this version
ciris-verify list-manifests

# Verify FFI function integrity
ciris-verify function-check --show-details

# Verify agent files (Level 4)
ciris-verify agent-files --version 2.0.0 --agent-root /path/to/agent

# Verify audit trail (Level 5)
ciris-verify audit-trail --db-path /path/to/ciris_audit.db

# JSON output for automation
ciris-verify sources --format json
```

---

## Registry Manifests

CIRISRegistry hosts three types of manifests used for verification:

### 1. Binary Manifest (Level 2)

SHA-256 hashes of CIRISVerify binaries for each platform target.

**Route**: `GET /v1/verify/binary-manifest/{version}`

```json
{
  "version": "0.6.17",
  "binaries": {
    "x86_64-unknown-linux-gnu": "sha256:abc123...",
    "aarch64-apple-darwin": "sha256:def456...",
    "x86_64-pc-windows-msvc": "sha256:ghi789...",
    "aarch64-linux-android": "sha256:jkl012..."
  },
  "generated_at": "2026-02-22T00:00:00Z"
}
```

### 2. File Manifest (Level 4)

SHA-256 hashes of all CIRISAgent files for Tripwire-style verification.

**Route**: `GET /v1/builds/{version}`

```json
{
  "build_id": "uuid-here",
  "version": "2.0.0",
  "file_manifest_json": {
    "version": "2.0.0",
    "files": {
      "ciris_engine/__init__.py": "sha256:...",
      "ciris_engine/main.py": "sha256:..."
    }
  },
  "file_manifest_count": 150,
  "file_manifest_hash": "sha256:..."
}
```

### 3. Function Manifest (Runtime)

SHA-256 hashes of FFI export functions at the bytecode level, with hybrid signatures.

**Route**: `GET /v1/verify/function-manifest/{version}/{target}`

```json
{
  "version": "1.0.0",
  "target": "x86_64-unknown-linux-gnu",
  "binary_hash": "sha256:...",
  "binary_version": "0.6.17",
  "generated_at": "2026-02-22T00:00:00Z",
  "functions": {
    "ciris_verify_init": {
      "name": "ciris_verify_init",
      "offset": 12345,
      "size": 256,
      "hash": "sha256:..."
    }
  },
  "manifest_hash": "sha256:...",
  "signature": {
    "classical": "base64-ed25519-sig",
    "classical_algorithm": "Ed25519",
    "pqc": "base64-mldsa65-sig",
    "pqc_algorithm": "ML-DSA-65",
    "key_id": "steward-key-1"
  }
}
```

**Security Properties**:
- Hybrid signatures (Ed25519 + ML-DSA-65) for post-quantum security
- PQC signature covers (manifest || classical_sig) - bound signature pattern
- Opaque failure reporting (never reveals WHICH function failed)
- Constant-time hash comparison

---

## Audit Trail Verification

CIRISVerify validates the cryptographic integrity of an agent's audit log (Level 5).

### Hash Chain Structure

Each audit entry contains:
- `sequence_number` — Monotonically increasing
- `previous_hash` — SHA-256 of previous entry (or "genesis" for first)
- `entry_hash` — SHA-256 of this entry's canonical form
- `signature` — Ed25519 signature over entry_hash
- `signing_key_id` — Key identifier (should be Portal key)

### Verification Checks

| Check | Description |
|-------|-------------|
| Genesis validity | First entry has `previous_hash = "genesis"` |
| Hash chain | Each entry's `previous_hash` matches prior `entry_hash` |
| Entry hashes | Computed hash matches stored `entry_hash` |
| Signatures | Ed25519 signature verifies (if present) |
| Portal key | Signing key is the expected Portal-issued key |

### Supported Formats

| Format | Path | Command |
|--------|------|---------|
| SQLite | `ciris_audit.db` | `--db-path` |
| JSONL | `audit_logs.jsonl` | `--jsonl-path` |

### Verification Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| Full | Verify entire chain | Startup, audits |
| Spot check | Random sample | Runtime monitoring |

```bash
# Full verification from SQLite
ciris-verify audit-trail --db-path ./ciris_audit.db

# Spot check from JSONL
ciris-verify audit-trail --jsonl-path ./audit_logs.jsonl --spot-check --sample-size 100

# With Portal key verification
ciris-verify audit-trail --db-path ./ciris_audit.db --portal-key-id "portal-key-abc123"
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
│   │       ├── bin/
│   │       │   └── ciris_verify.rs  # CLI binary
│   │       ├── engine.rs       # License engine + multi-source validation
│   │       ├── registry.rs     # Registry client for manifests
│   │       ├── audit.rs        # Audit trail verification
│   │       ├── config.rs       # Infrastructure endpoints
│   │       ├── types.rs        # Rust types
│   │       └── security/
│   │           ├── mod.rs           # Security module
│   │           ├── file_integrity.rs    # Tripwire file checks
│   │           ├── function_integrity.rs # FFI function verification
│   │           ├── anti_tamper.rs       # Anti-tamper detection
│   │           └── platform.rs          # Platform detection
│   ├── ciris-verify-ffi/       # C FFI layer
│   │   └── src/
│   │       ├── lib.rs          # FFI functions called by Python
│   │       ├── android_sync.rs # Android-specific sync I/O
│   │       └── constructor.rs  # Library constructors
│   └── ciris-manifest-tool/    # Manifest generation tool
│       └── src/
│           ├── main.rs         # CLI for generating manifests
│           └── parser/         # Binary parsers (ELF, Mach-O, PE)
├── bindings/
│   └── python/
│       └── ciris_verify/
│           ├── __init__.py     # Package exports
│           ├── client.py       # CIRISVerify + MockCIRISVerify (ctypes FFI)
│           ├── types.py        # Pydantic models (LicenseStatus, etc.)
│           └── exceptions.py   # Error types
├── protocol/
│   └── ciris_verify.proto      # Public API contract (gRPC/protobuf)
├── docs/
│   ├── HOW_IT_WORKS.md         # This document
│   ├── THREAT_MODEL.md         # Security threat analysis
│   ├── REGISTRY_BINARY_MANIFEST.md    # Binary manifest spec
│   └── REGISTRY_FUNCTION_MANIFEST_API.md  # Function manifest spec
├── FSD/
│   └── FSD-001_CIRISVERIFY_PROTOCOL.md  # Full specification
└── scripts/
    └── build_and_install.sh    # Build + install helper
```

### CLI Binary

After building, the CLI is available at:
```bash
# Linux/macOS
./target/release/ciris-verify

# Or install globally
cargo install --path src/ciris-verify-core
ciris-verify --help
```
