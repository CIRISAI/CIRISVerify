# CIRISVerify Python Bindings

Python bindings for CIRISVerify, the hardware-rooted license verification module for the CIRIS ecosystem.

## Installation

```bash
pip install ciris-verify
```

**Note:** The CIRISVerify binary must be installed separately. See the [CIRISVerify documentation](https://github.com/CIRISAI/CIRISVerify) for installation instructions.

## Quick Start

```python
import os
from ciris_verify import CIRISVerify, LicenseStatus

# Initialize the verifier
verifier = CIRISVerify()

# Get license status with a fresh nonce
status = await verifier.get_license_status(
    challenge_nonce=os.urandom(32)
)

# Check if professional capabilities are available
if status.allows_licensed_operation():
    print("Professional license verified!")
    print(f"Tier: {status.license.tier}")
    print(f"Capabilities: {status.license.capabilities}")
else:
    print("Running in community mode")

# IMPORTANT: Always display the mandatory disclosure
print(status.mandatory_disclosure.text)
```

## Mandatory Disclosure

Per the CIRIS ecosystem rules, agents **MUST** display the `mandatory_disclosure.text` to users. This ensures transparency about the agent's capabilities and licensing status.

```python
# The disclosure MUST be shown to users
disclosure = status.mandatory_disclosure
print(f"[{disclosure.severity.upper()}] {disclosure.text}")
```

## Capability Checking

For frequent capability checks, use the fast path:

```python
result = await verifier.check_capability("medical:diagnosis")
if result.allowed:
    # Capability is available
    pass
else:
    print(f"Capability denied: {result.reason}")
```

## Testing

For testing without the actual binary, use `MockCIRISVerify`:

```python
from ciris_verify import MockCIRISVerify, LicenseStatus

# Create a mock that returns community mode
verifier = MockCIRISVerify(
    mock_status=LicenseStatus.UNLICENSED_COMMUNITY
)

# Use exactly like the real client
status = await verifier.get_license_status(os.urandom(32))
assert status.status == LicenseStatus.UNLICENSED_COMMUNITY
```

## Error Handling

```python
from ciris_verify import (
    CIRISVerifyError,
    BinaryNotFoundError,
    BinaryTamperedError,
    VerificationFailedError,
)

try:
    verifier = CIRISVerify()
    status = await verifier.get_license_status(os.urandom(32))
except BinaryNotFoundError as e:
    # Binary not installed
    print(f"CIRISVerify not found: {e.path}")
except BinaryTamperedError:
    # CRITICAL: Binary has been modified
    # Halt all operations immediately
    raise SystemExit("SECURITY ALERT: Binary integrity compromised")
except VerificationFailedError as e:
    # Verification failed - operate in restricted mode
    print(f"Verification failed: {e}")
```

## License Status Codes

| Status | Code | Description |
|--------|------|-------------|
| `LICENSED_PROFESSIONAL` | 100 | Full professional license active |
| `LICENSED_PROFESSIONAL_GRACE` | 101 | License valid, in offline grace period |
| `UNLICENSED_COMMUNITY` | 200 | Community mode, no professional capabilities |
| `RESTRICTED_*` | 300-399 | Restricted mode due to verification issues |
| `ERROR_*` | 400-499 | Error states (revoked, expired, etc.) |
| `LOCKDOWN_*` | 500+ | Critical security failure, halt operations |

## Thread Safety

The client is thread-safe and can be used from multiple threads or async tasks concurrently.

## License

Proprietary - See LICENSE file in the CIRISVerify repository.
