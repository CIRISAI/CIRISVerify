# How CIRISVerify Works

**Last Updated**: 2026-03-28 (v1.3.1)

> **Disclaimer**: This is research software exploring approaches to AI agent verification and accountability. It is not a complete security solution. No software can provide absolute protection against determined adversaries. This documentation is provided for educational and research purposes to inform the broader AI alignment community. We make no warranties and accept no liability.

CIRISVerify is a Rust shared library (`libciris_verify_ffi`) with Python bindings (`ciris-verify`) that attempts to provide a trust anchor for the CIRIS ecosystem. Think of it as a **DMV for AI agents** — it tries to verify identity, integrity, and accountability.

**Technical Deep Dives**: For implementation details, see:
- [Binary Self-Verification](./BINARY_SELF_VERIFICATION.md) - How the library verifies itself across platforms
- [Threat Model](./THREAT_MODEL.md) - Security analysis and attack vectors
- [Registry Binary Manifest](./REGISTRY_BINARY_MANIFEST.md) - API specification

---

## The DMV Analogy

Every car on the road needs three things to legally operate. Every CIRIS agent needs the same three:

| What Your Car Needs | What CIRIS Agents Need | What It Proves |
|---------------------|------------------------|----------------|
| **Driver's License** | Hardware-bound Ed25519 signing key | **Who you are** — identity that can't be forged or transferred |
| **Vehicle Inspection** | Binary integrity + file hash verification | **Your vehicle is safe** — software hasn't been modified or tampered with |
| **Insurance** | License certificate with org ID & human contact | **Who's responsible** — which organization and human are accountable |

And just like a DMV doesn't trust a single piece of ID, CIRISVerify queries **3 independent sources** and requires them to agree.

---

## Who Inspects the Inspection Station?

Before verifying anything else, CIRISVerify must prove **it hasn't been tampered with itself**. Just like an inspection station needs its own certification before it can certify cars.

### How Binary Self-Verification Works

1. **Hash Yourself**: CIRISVerify computes a SHA-256 fingerprint of its own binary
2. **Check the Registry**: Fetches the official fingerprint from CIRISRegistry
3. **Compare**: If they match, the binary is authentic

The tricky part? Finding "yourself" when you're a library loaded inside another program.

### Platform-Specific Detection

| Platform | How We Find Ourselves |
|----------|----------------------|
| **Linux** | Parse `/proc/self/maps` to find `libciris_verify_ffi.so` in memory |
| **Android** | Same as Linux — Android is Linux under the hood |
| **macOS** | Iterate Apple's `dyld` image list to find our loaded `.dylib` |
| **iOS** | Same as macOS, plus special handling for code-signed binaries |
| **Windows** | Standard executable path lookup |

*For the full technical details, see [Binary Self-Verification Deep Dive](./BINARY_SELF_VERIFICATION.md).*

---

## What It Does (In Detail)

### 1. Driver's License — Identity & Signing Key

CIRISVerify holds a hardware-bound Ed25519 signing key that **is** the agent's identity. The key doesn't represent the identity — it *is* the identity, the same mechanism. Stored in secure hardware (TPM, Secure Enclave, Android Keystore), it cannot be forged, copied, or transferred. Every response the agent produces is signed with this key, proving authenticity.

**Storage descriptor (v1.7+):** Every signer declares where its identity material lives via `HardwareSigner::storage_descriptor()`. Surfaced through the FFI as `ciris_verify_signer_storage_descriptor()` and through the Python/Swift bindings. Four variants:

- `Hardware { hardware_type, blob_path }` — HSM-protected. `blob_path`, when present (Android Keystore-wrapped seed, Linux TPM `.tpm` envelope), is informational; the file is useless without the HSM.
- `SoftwareFile { path }` — software seed on disk. **This is the path ephemeral-storage heuristics must check.** A path under `/tmp`, `/var/cache`, or a container writable layer without a mounted volume means the identity churns every restart and the federation's longitudinal score (PoB §2.4 S-factor, 30-day decay window) cannot accumulate.
- `SoftwareOsKeyring { backend, scope }` — secret-service / Keychain / DPAPI. `scope` distinguishes user-session-bound (disappears at logout) from system-scoped (survives reboot).
- `InMemory` — RAM-only by design. The signer has no persistent storage of its own; a higher-level wrapper provides persistence.

Every CIRIS primitive that participates in PoB-style longitudinal scoring (agent, lens, persist, registry) should consult its signer's descriptor at boot and refuse to start if the storage looks ephemeral. Pattern (Python):

```python
from ciris_verify import CIRISVerify, StorageKind

v = CIRISVerify()
desc = v.storage_descriptor()
if desc.kind == StorageKind.SOFTWARE_FILE:
    path = desc.disk_path()
    if path and any(path.startswith(p) for p in ("/tmp/", "/var/cache/")):
        raise RuntimeError(f"identity in ephemeral storage: {path}")
```

### 2. Registration & Inspection — Software and Hardware Integrity

**Software integrity (Tripwire):** Every file in the CIRISAgent distribution is SHA-256 hashed at build time and registered in CIRISRegistry as a signed manifest. At runtime, CIRISVerify hashes files on disk and compares. **Any modification whatsoever** — except `.env`, logs, and runtime data — triggers immediate forced shutdown.

**Hardware attestation:** Validates the execution environment via platform-specific secure hardware. Software-only environments are capped at COMMUNITY tier — like driving with a learner's permit.

**Hardware vulnerability detection (v1.2.0+):** Even with hardware security, some SoCs have known vulnerabilities that compromise the trust chain. CIRISVerify detects these and caps attestation accordingly — like a recall notice on your car's brakes.

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

CIRISVerify includes a standalone CLI (`ciris-verify`) for running inspections manually:

### Available Commands

| Command | What It Does | Car Analogy |
|---------|--------------|-------------|
| `ciris-verify` | Show help | Read the DMV handbook |
| `ciris-verify info` | Show system capabilities | Check what your car supports |
| `ciris-verify self-check` | Verify binary integrity (Level 2) | Is this inspection station certified? |
| `ciris-verify sources` | Check registry consensus (Level 3) | Cross-check 3 DMV databases |
| `ciris-verify function-check` | Verify FFI functions | Check individual inspection equipment |
| `ciris-verify agent-files` | Verify agent file integrity (Level 4) | Full vehicle inspection |
| `ciris-verify audit-trail` | Verify audit log integrity (Level 5) | Review complete service history |
| `ciris-verify list-manifests` | List available manifests | Check what records exist |

### Attestation Levels — The 5-Point Inspection

Like a car inspection has multiple checkpoints (brakes, lights, emissions), CIRISVerify has 5 progressive trust levels:

| Level | The Check | Car Analogy | CLI Command |
|-------|-----------|-------------|-------------|
| **1** | Library Loaded | The car starts | (implicit) |
| **2** | Binary Self-Verification | Is this a real inspection station? | `self-check` |
| **3** | Registry Cross-Validation | Check 3 independent DMV databases | `sources` |
| **4** | Agent File Integrity | Vehicle hasn't been modified since manufacture | `agent-files` |
| **5** | Audit Trail Verification | Complete service history, no gaps | `audit-trail` |

**Critical**: If ANY level fails, ALL higher levels are UNVERIFIED (shown in yellow). A compromised inspection station (Level 2 fail) could lie about everything else.

*Technical detail: See [Binary Self-Verification](./BINARY_SELF_VERIFICATION.md) for how Level 2 works on each platform.*

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

CIRISRegistry hosts three types of manifests — think of them as official DMV records:

### 1. Binary Manifest (Level 2) — "Is This a Real Inspection Station?"

SHA-256 fingerprints of CIRISVerify binaries for each platform. Used to verify the verifier itself.

**Route**: `GET /v1/verify/binary-manifest/{version}`

```json
{
  "version": "1.0.8",
  "binaries": {
    "x86_64-unknown-linux-gnu": "sha256:63d2d68b...",
    "aarch64-apple-darwin": "sha256:9b457096...",
    "android-arm64-v8a": "sha256:b0b104a8...",
    "aarch64-apple-ios": "sha256:bcf0bfc0..."
  },
  "generated_at": "2026-02-28T00:00:00Z"
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

**Fail-secure intent**: The system is designed to degrade to MORE restrictive modes on failure—though bugs may exist.

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
| DNS EU | `eu.registry.ciris-services-eu-1.com` | EU-hosted DNS TXT records |
| HTTPS | `api.registry.ciris-services-1.ai` | HTTPS API endpoint |

**Consensus rules:**
- 3-of-3 agree → `ALL_SOURCES_AGREE` → Full confidence
- 2-of-3 agree → `PARTIAL_AGREEMENT` → Proceed with caution
- Sources disagree → `SOURCES_DISAGREE` → Security alert, restricted mode
- 0 reachable → `NO_SOURCES_REACHABLE` → Use cache or degrade

---

## Hardware Vulnerability Detection (v1.2.0+)

Even with hardware-backed security, some devices have known silicon-level vulnerabilities that compromise the trust chain. CIRISVerify actively detects these and caps attestation to `SOFTWARE_ONLY` level — the same treatment as emulators.

### Known Vulnerabilities Tracked

| CVE | Vendor | Impact | Patchable? | Detection Method |
|-----|--------|--------|------------|------------------|
| **CVE-2026-20435** | MediaTek | Boot ROM EMFI - key extraction in <45s | ❌ NO (silicon) | `Build.HARDWARE` chip ID |
| **CVE-2026-21385** | Qualcomm | Security component under active exploitation | ✅ YES | `Build.VERSION.SECURITY_PATCH` |

### How Detection Works

1. **On Android**: JNI provides `Build.HARDWARE`, `Build.BOARD`, `Build.VERSION.SECURITY_PATCH`
2. **CIRISVerify parses** these properties to identify SoC manufacturer and model
3. **Vulnerable chips** are matched against a known-bad list
4. **Patchable CVEs** check the security patch level against the fix date

### Affected MediaTek Chips (CVE-2026-20435)

These Dimensity SoCs have Trustonic TEE with exploitable boot ROM:

| Chip ID | Marketing Name | Vulnerable? |
|---------|----------------|-------------|
| mt6878 | Dimensity 7300 | ✅ YES |
| mt6886 | Dimensity 7200 | ✅ YES |
| mt6893 | Dimensity 1200 | ✅ YES |
| mt6895 | Dimensity 8100 | ✅ YES |
| mt6983 | Dimensity 9000 | ✅ YES |
| mt6985 | Dimensity 9200 | ✅ YES |

**Why it matters**: An attacker with ~45 seconds of physical access can extract Android Keystore keys. This defeats hardware-rooted attestation.

### Qualcomm Patch Detection (CVE-2026-21385)

Unlike MediaTek's unfixable boot ROM issue, Qualcomm's CVE-2026-21385 was patched in the **March 2026 Android Security Bulletin**.

```
Security Patch Level >= 2026-03-01  →  SAFE
Security Patch Level < 2026-03-01   →  VULNERABLE (caps attestation)
```

### API Usage

```python
from ciris_verify import CIRISVerify

verifier = CIRISVerify()

# Basic detection (desktop/iOS)
info = verifier.get_hardware_info_sync()

# Enhanced Android detection with JNI properties
info = verifier.get_hardware_info_android_sync(
    hardware="mt6878",
    board="dimensity7300",
    manufacturer="Xiaomi",
    model="Redmi Note 13",
    security_patch="2026-03-01",
    fingerprint="Xiaomi/redmi/device:14/fingerprint",
)

if info.hardware_trust_degraded:
    print(f"⚠️ Hardware trust degraded: {info.trust_degradation_reason}")
    for lim in info.limitations:
        print(f"  - {lim.description()}")
```

### Trust Degradation Chain

```
Vulnerable SoC detected
    ↓
hardware_trust_degraded = true
    ↓
HardwareLimitation::VulnerableSoC added
    ↓
Attestation capped to SOFTWARE_ONLY
    ↓
Maximum tier = COMMUNITY (no professional license)
```

---

## EVM Wallet Signing (v1.3.0+)

CIRISVerify can derive an EVM-compatible secp256k1 wallet from the agent's identity key. This enables agents to sign blockchain transactions, proving their identity on-chain without exposing the root Ed25519 key.

### Key Derivation Hierarchy

The wallet key is derived deterministically from the Ed25519 seed using HKDF:

```
Ed25519 Seed (32 bytes)
    │
    └── HKDF-SHA256(salt="CIRIS-wallet-v1", info="secp256k1-evm-signing-key")
            │
            └── secp256k1 Private Key (32 bytes)
                    │
                    └── secp256k1 Public Key (65 bytes uncompressed)
                            │
                            └── EVM Address (20 bytes via keccak256)
```

**Security property**: The same Ed25519 seed always produces the same EVM wallet. The wallet cannot exist without the identity key, and vice versa — they are cryptographically bound.

### Supported Operations

| Operation | Description | Use Case |
|-----------|-------------|----------|
| **Address derivation** | Get checksummed EVM address | Display to users, receive funds |
| **Message signing** | Sign arbitrary 32-byte hash | Off-chain attestations |
| **Transaction signing** | Sign with EIP-155 replay protection | On-chain transactions |
| **Typed data signing** | EIP-712 structured data | DeFi interactions, permits |
| **Address recovery** | Verify signature → recover signer | On-chain verification |

### Python API

```python
from ciris_verify import CIRISVerify

verifier = CIRISVerify()

# Get wallet info (address, public key)
wallet = verifier.get_wallet_info_sync()
print(f"EVM Address: {wallet['evm_address']}")
# Output: 0x1234...abcd (checksummed)

# Sign a message hash
message_hash = bytes.fromhex("a1b2c3..." * 8)  # 32 bytes
signature = verifier.sign_secp256k1_sync(message_hash)
# Returns 65-byte signature (r || s || v)

# Sign an EVM transaction
tx_hash = bytes.fromhex("d4e5f6..." * 8)  # 32 bytes
chain_id = 8453  # Base mainnet
signature = verifier.sign_evm_transaction_sync(tx_hash, chain_id)
# Returns signature with v = 27 or 28 (legacy format)

# Sign EIP-712 typed data
domain_hash = bytes.fromhex("...")  # 32 bytes
struct_hash = bytes.fromhex("...")  # 32 bytes
signature = verifier.sign_typed_data_sync(domain_hash, struct_hash)

# Recover address from signature
recovered = verifier.recover_evm_address_sync(message_hash, signature)
assert recovered == wallet['evm_address']
```

### Hardware Binding

When running on hardware-backed platforms (TPM, Secure Enclave, Android Keystore):
- The Ed25519 seed is protected by hardware
- Wallet derivation requires hardware unlock
- Software-only mode still works but lacks hardware protection

**Note**: The secp256k1 key itself is derived in software (HKDF), not stored in hardware. The hardware protection is at the Ed25519 seed level. This is intentional — hardware secure elements rarely support secp256k1 directly.

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

## Cohabitation Contract — Inverted-Pyramid Doctrine

CIRISVerify is the lowest layer of the CIRIS stack: pure cryptographic primitives, HSM access, no persistent state of its own beyond what the OS keyring backend holds. Above verify, **CIRISPersist is the lowest *stateful* library** — its `Engine::__init__` (v0.1.14+) holds a filesystem `flock` during keyring bootstrap, making cold-start safe across N concurrent consumers by construction.

The doctrinal rule:

> **If CIRISPersist is in your dependency stack, persist owns keyring bootstrap. Verify is a happy passenger that reads the OS keyring after persist has populated it.**
>
> If persist is NOT in your stack (registry-only, sovereign-mode dev, lens before the §3.1 collapse), verify's bootstrap path or an operator-managed alternative serializes cold-start.

This is an inverted pyramid: higher-stack-but-stateful libraries take precedence over lower-stack libraries for shared concerns. Verify provides the primitives; persist provides the bootstrap authority when present.

### Why this works without explicit deferral code

Verify's `factory::create_hardware_signer` doesn't introspect for persist. It doesn't have to. The deferral happens implicitly through the OS keyring backend:

1. Persist's `Engine::__init__` acquires the flock, calls `get_platform_signer(alias)`, generates-or-loads the key, releases the flock.
2. Any subsequent verify call (in the same process or a different one on the same host) hits `get_platform_signer(alias)` against an already-populated keyring backend → loads existing key, no creation race.

The deferral is structural: persist runs first because it's the higher-stateful layer that consumers depend on for evidence persistence. By the time anything else needs to sign, the key is there.

### Cohabitation patterns and which case applies

| Stack composition | Bootstrap authority | Cold-start posture |
|---|---|---|
| **Persist + Verify** (e.g., agent + persist co-located, lens consuming persist) | Persist's `Engine::__init__` flock | All consumers race the flock; first wins, others wait, all converge on the same identity |
| **Verify-only, single process** (registry, simple sovereign agent) | Verify's first `get_platform_signer()` call | No race possible — single process, single bootstrap |
| **Verify-only, multi-process** (registry HA replica set without persist) | Operator-managed (`flock` in `ExecStartPre` or pre-bootstrap step) | Verify v1.9's planned `flock` guards close the race when shipped; until then, operator runbook |
| **Multiple aliases on one host** | N/A — this is wrong | Same identity = same alias by PoB §3.2; different aliases = different identities = federation confused-deputy |

### What's safe under the inverted pyramid

- **Persist + N consumers** all racing through the flock — persist's contract handles this end-to-end. Each `Engine::__init__` is safe to call concurrently from any number of workers/pods/processes.
- **Multiple READ-only verify instances** under the same alias — OS-daemon-level serialization (TPM via `/dev/tpm0`, Apple `securityd`, Android Binder, Linux Secret Service) handles concurrent access. PoB §3.2 single-key-three-roles makes "same alias = same identity" correct.
- **Cross-`.so` in-process loading** — each `.so` carries its own Rust globals (`OnceLock`, etc.) but they reach through the FFI to the same OS keyring. Caches diverge transiently but converge on next read.

### What's still unsafe (verify-only stacks without an external bootstrap step)

These are cases where neither persist's flock nor an operator-managed serialization step exists:

- **Cold-start key creation race in a verify-only multi-process deployment.** Two processes starting simultaneously against a fresh deployment may both hit `key_exists()` → `false` → `generate_key()`. Backend behavior:
  - Android Keystore: rejects the second create with `KeyStoreException`.
  - macOS Keychain: depends on `kSecAttrAccessible`; may silently overwrite.
  - TPM persistent handles: races on `TPM2_EvictControl`.
  - Software seed file: last-writer-wins, prior caller's cached signing key now points at deleted material.
- **Concurrent mutation** (generate, delete, stale-marker recovery) without coordination.

For verify-only multi-process stacks, use one of:
- A pre-bootstrap step (CI-time or systemd `ExecStartPre`) that creates the key once before workload processes start.
- Verify v1.9's planned filesystem `flock` guards around mutation ops (forthcoming; ~30 LoC).
- Add persist to your stack — it solves this for free.

### Same-alias rule (unchanged regardless of stack composition)

If your host runs **multiple primitives** that need to sign (agent, persist, lens, registry, etc.), they should use the **same alias** to share one identity. Different aliases = different identities = each primitive's federation reputation tracked separately, breaking PoB §3.2's single-key-three-roles guarantee.

The default alias is `ciris_verify_key` (per `KeyGenConfig::default()`). Override only if you have a deliberate reason — and then override consistently across all co-resident primitives.

### v1.9 / v2.0 roadmap (verify-side)

The inverted pyramid means verify-side cohabitation work is **secondary**, not primary. Persist already solves the dominant case. Remaining work:

- **v1.9** — filesystem `flock`-based scope guards around verify's mutation ops (`generate_key`, `delete_key`, stale-marker recovery). Closes the verify-only multi-process race window for stacks that don't include persist. Lower priority since most production stacks have persist.
- **v2.0** — out-of-process verify daemon would be the architecturally pure singleton, but the inverted pyramid makes a daemon less compelling: persist already provides the singleton-bootstrap guarantee at a higher layer where it's more naturally located. Likely v2.0 work is "formalize the persist-as-bootstrap-authority pattern in docs and runtime checks" rather than ship a separate daemon.

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
│   ├── ciris-crypto/           # Hybrid crypto (Ed25519 + ML-DSA-65 + secp256k1)
│   ├── ciris-verify-core/      # Core verification engine
│   │   └── src/
│   │       ├── bin/
│   │       │   └── ciris_verify.rs  # CLI binary
│   │       ├── engine.rs       # License engine + multi-source validation
│   │       ├── registry.rs     # Registry client for manifests
│   │       ├── audit.rs        # Audit trail verification
│   │       ├── config.rs       # Infrastructure endpoints
│   │       ├── hardware_info.rs # Hardware vulnerability detection (v1.2.0+)
│   │       ├── manifest_cache.rs # Offline L1 verification cache (v1.2.0+)
│   │       ├── types.rs        # Rust types
│   │       └── security/
│   │           ├── mod.rs           # Security module
│   │           ├── file_integrity.rs    # Tripwire file checks
│   │           ├── function_integrity.rs # FFI function verification
│   │           ├── anti_tamper.rs       # Anti-tamper detection
│   │           └── platform.rs          # Platform detection (emulator/root)
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
