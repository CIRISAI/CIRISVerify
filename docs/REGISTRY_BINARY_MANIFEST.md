# Registry Binary Manifest Implementation

## Overview

CIRISVerify v0.5.2 introduces **Level 2 Binary Self-Verification** - the ability for the CIRISVerify binary to verify its own integrity against a registry-hosted manifest. This closes the "who watches the watchmen" attack vector where a compromised verifier could report false results.

## Required Registry Route

### Endpoint

```
GET /v1/verify/binary-manifest/{version}
```

### Example Request

```
GET https://api.registry.ciris-services-1.ai/v1/verify/binary-manifest/0.5.2
```

### Response Format

```json
{
  "version": "0.5.2",
  "binaries": {
    "x86_64-unknown-linux-gnu": "sha256:abc123def456...",
    "aarch64-unknown-linux-gnu": "sha256:789ghi012jkl...",
    "x86_64-apple-darwin": "sha256:mno345pqr678...",
    "aarch64-apple-darwin": "sha256:stu901vwx234...",
    "x86_64-pc-windows-msvc": "sha256:yza567bcd890..."
  },
  "generated_at": "2026-02-20T12:00:00Z"
}
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | Semantic version of CIRISVerify |
| `binaries` | object | Map of Rust target triple → SHA-256 hash |
| `generated_at` | string | ISO 8601 timestamp when manifest was generated |

### Target Triples

The following targets are built in CI and need hashes:

| Target | Platform | Notes |
|--------|----------|-------|
| `x86_64-unknown-linux-gnu` | Linux x86_64 | Primary server platform |
| `aarch64-unknown-linux-gnu` | Linux ARM64 | Raspberry Pi, AWS Graviton |
| `x86_64-apple-darwin` | macOS Intel | Legacy Mac support |
| `aarch64-apple-darwin` | macOS Apple Silicon | M1/M2/M3 Macs |
| `x86_64-pc-windows-msvc` | Windows x64 | Windows desktop |
| `aarch64-linux-android` | Android ARM64 | Primary mobile |
| `armv7-linux-androideabi` | Android ARMv7 | Legacy Android |
| `x86_64-linux-android` | Android x86_64 | Emulators |

## Hash Format

Hashes should be lowercase hex-encoded SHA-256, optionally prefixed with `sha256:`:

```
"sha256:7d36f92ca90116c184024a0f03af7cec12551c609f78de62ced5e3cffd238de3"
```

or:

```
"7d36f92ca90116c184024a0f03af7cec12551c609f78de62ced5e3cffd238de3"
```

Both formats are accepted by the client.

## Data Source Options

### Option 1: GitHub Release Integration (Recommended)

The CIRISVerify release workflow uploads a `CHECKSUMS.txt` file as a release asset:

```
https://github.com/CIRISAI/CIRISVerify/releases/download/v0.5.2/CHECKSUMS.txt
```

Format:
```
7d36f92ca90116c184024a0f03af7cec12551c609f78de62ced5e3cffd238de3  libciris_verify_ffi-x86_64-unknown-linux-gnu.so
abc123def456789...  libciris_verify_ffi-aarch64-apple-darwin.dylib
...
```

The registry can:
1. Fetch this file on release webhook
2. Parse and store in database
3. Serve via the `/v1/verify/binary-manifest/{version}` endpoint

### Option 2: CI Push

The release workflow can POST hashes directly to the registry:

```bash
curl -X POST https://api.registry.ciris-services-1.ai/v1/verify/binary-manifest \
  -H "Authorization: Bearer $REGISTRY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "version": "0.5.2",
    "binaries": { ... },
    "generated_at": "2026-02-20T12:00:00Z"
  }'
```

## Trust Model

### Recursive Dependency

Binary self-verification has a circular trust dependency:

```
Level 2 (Self-Check) → needs manifest from → Level 3 (Registry)
Level 3 (Registry)   → validated by       → Level 2 (This Binary)
```

### Resolution

1. **Initial Provisioning**: The first install MUST come from a trusted source:
   - Android: Google Play Store
   - iOS: Apple App Store
   - Python: PyPI (`pip install ciris-verify`)
   - Linux: Official package repositories

2. **Subsequent Updates**: Once a trusted binary is installed, it can verify updates against the registry manifest.

3. **Multi-Source Validation**: Level 3 uses 2-of-3 consensus across geographically distributed sources (US DNS, EU DNS, HTTPS) to prevent registry MITM.

### What Self-Verification Does NOT Protect Against

- **Fully compromised registry**: An attacker controlling the registry could update both the binary distribution and the manifest simultaneously.
- **Compromised initial provisioning**: A malicious app store listing.

### Mitigations

- Level 3 multi-source cross-validation
- Trusted app store provisioning
- (Future) Manifest signing key pinning with rotation detection

## Error Responses

### 404 Not Found

Version not found or route not implemented:

```json
{
  "error": "not_found",
  "message": "Binary manifest not found for version 0.5.2"
}
```

### 400 Bad Request

Invalid version format:

```json
{
  "error": "bad_request",
  "message": "Invalid version format"
}
```

## Testing

Once implemented, test with:

```bash
# Run self-check against registry
ciris-verify self-check

# Or with custom registry URL
ciris-verify self-check --registry https://api.registry.ciris-services-1.ai
```

Expected output on success:
```
[PASS] Binary hash matches registry manifest
Level 2 verification PASSED. This binary is authentic.
```

Expected output when route not implemented:
```
[WARN] Could not fetch binary manifest: HTTPS error: 404 Not Found
The registry may not have implemented the binary manifest route yet.
```

## Implementation Checklist

- [ ] Add database table for binary manifests
- [ ] Implement `GET /v1/verify/binary-manifest/{version}` endpoint
- [ ] Set up GitHub release webhook OR CI push integration
- [ ] Populate manifest for v0.5.2 release
- [ ] Test with `ciris-verify self-check`

## Questions?

Contact the CIRISVerify team or open an issue at:
https://github.com/CIRISAI/CIRISVerify/issues
