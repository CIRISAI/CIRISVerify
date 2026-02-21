# CIRISPortal Device Auth — Agent Integration Guide

This document describes how agents integrate with CIRISPortal's device authorization flow, including the CIRISVerify attestation challenge that proves an untampered CIRIS agent installation is submitting the request.

**Audience**: CIRISAgent team, third-party agent developers, QA engineers.

---

## Overview

When an agent needs a signing key (identity activation), it initiates an RFC 8628 device auth flow with CIRISPortal. The portal issues a challenge nonce. **CIRIS agents** must sign this challenge using CIRISVerify's hardware-bound keys and submit the attestation proof before their key will be provisioned. **Non-CIRIS agents** skip attestation and receive a basic identity.

```
┌──────────────────────────────────────────────────────────────┐
│                    CIRIS Agent Flow                           │
│                                                              │
│  Agent → Portal: initiate (get challenge_nonce)              │
│  Agent → CIRISVerify: export_attestation(challenge_nonce)    │
│  Agent → CIRISVerify: check_agent_integrity(manifest)        │
│  Agent → Portal: attest (submit proof)                       │
│  User  → Portal: OAuth → select template → pay $1.50        │
│  Agent → Portal: poll for key (provisioned after payment)    │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│                  Non-CIRIS Agent Flow                         │
│                                                              │
│  Agent → Portal: initiate (challenge_nonce returned but      │
│                             attestation is optional)         │
│  User  → Portal: OAuth → select "Non-CIRIS Agent" → pay     │
│  Agent → Portal: poll for key (no attestation required)      │
└──────────────────────────────────────────────────────────────┘
```

---

## API Reference

All endpoints are on the CIRISPortal host (e.g., `https://portal.ciris.ai`).

### Step 1: Initiate Device Auth

```
POST /api/device/authorize
Content-Type: application/json

{
  "portal_url": "https://portal.ciris.ai",
  "agent_info": {
    "agentHash": "<SHA-256 hex of agent build, 64 chars>",
    "currentPublicKey": "<base64 if agent already has a key>",
    "requestedAdapters": ["home_assistant", "mcp_client"]
  }
}
```

**Response (200):**
```json
{
  "device_code": "a1b2c3...64-char-hex...",
  "user_code": "ABCD-1234",
  "verification_uri": "https://portal.ciris.ai/device",
  "verification_uri_complete": "https://portal.ciris.ai/device?code=ABCD-1234",
  "expires_in": 900,
  "interval": 5,
  "challenge_nonce": "e4f5a6...64-char-hex..."
}
```

**Key fields:**
- `device_code` — opaque secret, used for polling and attestation (keep private)
- `user_code` — human-readable, display to user so they can authenticate in browser
- `challenge_nonce` — 32-byte hex nonce for CIRISVerify attestation
- `expires_in` — 900 seconds (15 minutes) before the session expires

---

### Step 2: Submit Attestation (CIRIS agents only)

After receiving `challenge_nonce`, the agent must:

1. Call `CIRISVerify.export_attestation(challenge_nonce_bytes)` to get an `AttestationProof`
2. Call `CIRISVerify.check_agent_integrity(manifest)` to verify file integrity
3. Submit both to Portal

```
POST /api/device/attest
Content-Type: application/json

{
  "device_code": "a1b2c3...the device_code from step 1...",
  "attestation_proof": {
    "platform_attestation": "<base64 TPM quote / SE assertion>",
    "hardware_public_key": "<base64 ECDSA P-256 or Ed25519 public key>",
    "hardware_algorithm": "Ed25519",
    "pqc_public_key": "<base64 ML-DSA-65 public key>",
    "pqc_algorithm": "ML-DSA-65",
    "challenge": "e4f5a6...the challenge_nonce hex...",
    "classical_signature": "<base64 HW-bound sig over challenge bytes>",
    "pqc_signature": "<base64 ML-DSA sig over (challenge || classical_sig)>",
    "merkle_root": "<hex 32-byte Merkle root of transparency log>",
    "log_entry_count": 42,
    "generated_at": "2026-02-18T12:00:00Z",
    "binary_version": "0.5.3",
    "hardware_type": "TPM_2_0"
  },
  "agent_hash": "a1b2c3d4...64-char SHA-256 hex of agent build...",
  "integrity_passed": true
}
```

**Response (200) — Verified:**
```json
{
  "verified": true,
  "hardware_type": "TPM_2_0",
  "agent_known": true,
  "build_attested": true,
  "warnings": []
}
```

**Response (403) — Verification failed:**
```json
{
  "verified": false,
  "errors": ["Ed25519 signature verification failed"],
  "warnings": ["No build attestation found"],
  "hardware_type": "SOFTWARE_ONLY"
}
```

**This endpoint is unauthenticated** — the `device_code` is the secret. Do not expose the device code to users or logs.

---

### Step 3: User Authenticates in Browser

Display to the user:
```
To activate this agent, open:
  https://portal.ciris.ai/device?code=ABCD-1234

Or visit https://portal.ciris.ai/device and enter code: ABCD-1234
```

In the browser, the user will:
1. Sign in via OAuth (Google)
2. Choose "CIRIS Agent" or "Non-CIRIS Agent"
3. Confirm identity template (auto-selected based on agent type)
4. Complete Stripe payment ($1.50 per identity)

---

### Step 4: Poll for Key

```
POST /api/device/token
Content-Type: application/json

{
  "device_code": "a1b2c3...the device_code from step 1..."
}
```

**Responses:**

| Status | Body `error` | Meaning | Action |
|--------|-------------|---------|--------|
| 428 | `authorization_pending` | User hasn't completed yet | Keep polling every `interval` seconds |
| 200 | *(key payload)* | Key provisioned | Store key, stop polling |
| 400 | `expired_token` | Session expired or key already consumed | Start over |
| 403 | `access_denied` | User denied the request | Abort |

**Success response (200):**
```json
{
  "status": "provisioned",
  "signing_key": {
    "ed25519_private_key": "<base64>",
    "ed25519_public_key": "<base64>",
    "key_id": "abc123...",
    "org_id": "org_456..."
  },
  "agent_record": {
    "identity_template": "default",
    "stewardship_tier": 4,
    "permitted_actions": ["SPEAK", "OBSERVE", "MEMORIZE", ...],
    "approved_adapters": ["ciris_hosted_tools"]
  },
  "portal_url": "https://portal.ciris.ai",
  "licensed_package": null
}
```

**The signing key is delivered exactly once.** After consumption, the device record is deleted. If you lose the key, you must start a new device auth session.

---

## CIRIS Agent Integration (Python)

### Full Example

```python
import httpx
import asyncio
from ciris_verify import CIRISVerify  # ciris-verify PyPI package

PORTAL_URL = "https://portal.ciris.ai"
AGENT_HASH = "your-agent-build-sha256-hex-64-chars"
MANIFEST_PATH = "/path/to/agent/file_manifest.json"

async def acquire_license():
    verify = CIRISVerify()

    # Step 1: Initiate device auth
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{PORTAL_URL}/api/device/authorize", json={
            "portal_url": PORTAL_URL,
            "agent_info": {
                "agentHash": AGENT_HASH,
            }
        })
        resp.raise_for_status()
        data = resp.json()

    device_code = data["device_code"]
    user_code = data["user_code"]
    challenge_nonce = data["challenge_nonce"]
    verification_url = data["verification_uri_complete"]

    print(f"\n  To activate, open: {verification_url}\n")

    # Step 2: Generate attestation proof
    challenge_bytes = bytes.fromhex(challenge_nonce)
    attestation_proof = await verify.export_attestation(challenge_bytes)

    # Step 3: Check agent integrity
    with open(MANIFEST_PATH) as f:
        manifest = f.read()
    integrity_result = await verify.check_agent_integrity(manifest)

    # Step 4: Submit attestation to Portal
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{PORTAL_URL}/api/device/attest", json={
            "device_code": device_code,
            "attestation_proof": attestation_proof.to_dict(),
            "agent_hash": AGENT_HASH,
            "integrity_passed": integrity_result.passed,
        })
        attest_data = resp.json()

    if not attest_data.get("verified"):
        raise RuntimeError(
            f"Attestation failed: {attest_data.get('errors', [])}"
        )

    print(f"  Attestation verified (hardware: {attest_data['hardware_type']})")
    print(f"  Waiting for user to complete payment...")

    # Step 5: Poll for key
    async with httpx.AsyncClient() as client:
        while True:
            resp = await client.post(f"{PORTAL_URL}/api/device/token", json={
                "device_code": device_code,
            })

            if resp.status_code == 200:
                key_data = resp.json()
                print(f"  Key received: {key_data['signing_key']['key_id']}")
                return key_data

            body = resp.json()
            if body.get("error") == "authorization_pending":
                await asyncio.sleep(5)
                continue

            raise RuntimeError(f"Device auth failed: {body}")
```

### CIRISVerify FFI Reference

```python
from ciris_verify import CIRISVerify

verify = CIRISVerify()

# Export attestation proof (signs challenge with HW-bound key)
proof = await verify.export_attestation(challenge_bytes)  # bytes, 32+
# proof.platform_attestation  -> bytes (TPM quote / SE assertion)
# proof.hardware_public_key   -> bytes (ECDSA P-256 or Ed25519)
# proof.hardware_algorithm    -> str   ("ECDSA_P256" or "Ed25519")
# proof.pqc_public_key        -> bytes (ML-DSA-65, ~1952 bytes)
# proof.classical_signature   -> bytes (HW sig over challenge)
# proof.pqc_signature         -> bytes (ML-DSA over challenge||classical)
# proof.hardware_type         -> str   ("TPM_2_0", "SOFTWARE_ONLY", etc.)
# proof.merkle_root           -> bytes (32 bytes)
# proof.to_dict()             -> dict  (JSON-serializable for API)

# Check agent file integrity
result = await verify.check_agent_integrity(manifest_json)
# result.passed    -> bool
# result.details   -> opaque (do not inspect individual files)

# Get license status (for runtime gating, not device auth)
status = await verify.get_license_status()
```

---

## Non-CIRIS Agent Integration

Non-CIRIS agents do **not** need CIRISVerify. The flow is simpler:

```python
import httpx
import asyncio

PORTAL_URL = "https://portal.ciris.ai"

async def acquire_identity():
    # Step 1: Initiate (challenge_nonce returned but not needed)
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{PORTAL_URL}/api/device/authorize", json={
            "portal_url": PORTAL_URL,
            "agent_info": {}
        })
        resp.raise_for_status()
        data = resp.json()

    device_code = data["device_code"]
    verification_url = data["verification_uri_complete"]

    # Step 2: Skip attestation — not required for non-CIRIS agents
    print(f"\n  To activate, open: {verification_url}\n")
    print(f"  Select 'Non-CIRIS Agent' in the portal.\n")

    # Step 3: Poll for key
    async with httpx.AsyncClient() as client:
        while True:
            resp = await client.post(f"{PORTAL_URL}/api/device/token", json={
                "device_code": device_code,
            })

            if resp.status_code == 200:
                return resp.json()

            body = resp.json()
            if body.get("error") == "authorization_pending":
                await asyncio.sleep(5)
                continue

            raise RuntimeError(f"Failed: {body}")
```

### What Non-CIRIS Agents Get

- Ed25519 signing key pair (same as CIRIS agents)
- Registry listing with `AGENT_TYPE_CUSTOM` and `non_ciris` template
- Basic verification (key-based identity, no hardware attestation)
- Community tier only (max 5 identities per org)

### What Non-CIRIS Agents Do NOT Get

- No hardware root of trust
- No stewardship tier enforcement
- No WBD routing via node.ciris.ai
- No accord compliance verification
- No file integrity guarantees
- Registry listing shows `attestation_verified: false`

---

## Attestation Verification — What Portal Checks

When a CIRIS agent submits `POST /api/device/attest`, Portal verifies:

| Check | How | Fail Behavior |
|-------|-----|---------------|
| **Challenge nonce** | `proof.challenge == record.challengeNonce` | Reject (replay attack) |
| **Classical signature** | `crypto.verify(Ed25519/P-256, challenge, pubkey, sig)` | Reject |
| **PQC signature presence** | `proof.pqc_signature.length > 0` | Warning (logged, not blocking) |
| **Agent hash in Registry** | `LookupAgent(agentHash)` via gRPC | Warning (may be first reg) |
| **Agent not revoked** | `agentRecord.status != REVOKED` | Reject |
| **Build attestation** | `GetBuildAttestation(agentHash)` via gRPC | Warning (logged) |
| **File integrity** | `integrity_passed == true` | Reject |
| **Hardware type** | `proof.hardware_type` stored for audit | `SOFTWARE_ONLY` → warning |

**Verdict**: Attestation passes if there are **zero errors** and the **classical signature is valid**. Warnings are logged but do not block provisioning.

**PQC verification**: ML-DSA-65 signature verification will be delegated to CIRISRegistry via a future `VerifyAttestation` RPC (the Rust crypto stack already has `HybridCrypto::verify()`). Currently, Portal verifies the classical signature locally and logs the PQC signature for audit.

---

## Sequence Diagram

```
Agent                CIRISVerify          Portal              Registry         User (Browser)
  │                      │                  │                    │                    │
  │ POST /device/authorize                  │                    │                    │
  │ {portal_url, agent_info}                │                    │                    │
  │────────────────────────────────────────>│                    │                    │
  │                      │                  │                    │                    │
  │ {device_code, user_code,                │                    │                    │
  │  challenge_nonce}    │                  │                    │                    │
  │<────────────────────────────────────────│                    │                    │
  │                      │                  │                    │                    │
  │ export_attestation   │                  │                    │                    │
  │ (challenge_nonce)    │                  │                    │                    │
  │─────────────────────>│                  │                    │                    │
  │                      │                  │                    │                    │
  │ AttestationProof     │                  │                    │                    │
  │ (HW sig + PQC sig)   │                  │                    │                    │
  │<─────────────────────│                  │                    │                    │
  │                      │                  │                    │                    │
  │ check_agent_integrity│                  │                    │                    │
  │─────────────────────>│                  │                    │                    │
  │ {passed: true}       │                  │                    │                    │
  │<─────────────────────│                  │                    │                    │
  │                      │                  │                    │                    │
  │ POST /device/attest  │                  │                    │                    │
  │ {device_code, proof, │                  │                    │                    │
  │  agent_hash, integrity_passed}          │                    │                    │
  │────────────────────────────────────────>│                    │                    │
  │                      │                  │ LookupAgent        │                    │
  │                      │                  │───────────────────>│                    │
  │                      │                  │ AgentRecord        │                    │
  │                      │                  │<───────────────────│                    │
  │                      │                  │ GetBuildAttestation│                    │
  │                      │                  │───────────────────>│                    │
  │                      │                  │ BuildProvenance    │                    │
  │                      │                  │<───────────────────│                    │
  │                      │                  │                    │                    │
  │ {verified: true}     │                  │                    │                    │
  │<────────────────────────────────────────│                    │                    │
  │                      │                  │                    │                    │
  │ (Display to user: "Open portal.ciris.ai/device?code=ABCD-1234")                 │
  │                      │                  │                    │           OAuth login
  │                      │                  │                    │     Select agent type
  │                      │                  │                    │     Confirm template
  │                      │                  │                    │     Stripe payment
  │                      │                  │<───────────────────────────────────────│
  │                      │                  │ (checkout + complete)                   │
  │                      │                  │                    │                    │
  │ POST /device/token   │                  │                    │                    │
  │ {device_code}        │                  │                    │                    │
  │────────────────────────────────────────>│                    │                    │
  │                      │                  │                    │                    │
  │ {signing_key, agent_record}             │                    │                    │
  │<────────────────────────────────────────│                    │                    │
```

---

## QA Test Plan

### CIRIS Agent — Happy Path

1. **Initiate**: `POST /api/device/authorize` with valid `agent_info.agentHash`
2. **Verify response** includes `challenge_nonce` (64-char hex)
3. **Generate attestation**: Call `CIRISVerify.export_attestation(nonce_bytes)`
4. **Check integrity**: Call `CIRISVerify.check_agent_integrity(manifest)`
5. **Submit attestation**: `POST /api/device/attest` with proof + `integrity_passed: true`
6. **Verify**: Response has `verified: true`
7. **Open browser**: Navigate to `verification_uri_complete`, sign in, select "CIRIS Agent"
8. **Pay**: Complete Stripe checkout ($1.50)
9. **Poll**: `POST /api/device/token` returns key on next poll
10. **Verify key**: Ed25519 key pair is valid, `key_id` is non-empty

### CIRIS Agent — Attestation Failures

| Test | Input | Expected |
|------|-------|----------|
| Wrong nonce | `challenge: "0000..."` (not the issued nonce) | 403, error: "Challenge nonce mismatch" |
| Invalid signature | Corrupt `classical_signature` | 403, error: "signature verification failed" |
| Integrity failed | `integrity_passed: false` | 403, error: "integrity check failed" |
| Skip attestation | Call `/device/complete` without `/device/attest` | 428, error: "Attestation required" |
| Revoked agent | Use hash of revoked agent in Registry | 403, error: "Agent has been revoked" |
| Expired session | Wait > 15 min, then attest | 404, error: "Invalid or expired device code" |
| Double attestation | Call attest twice | 200 second time (idempotent) |

### Non-CIRIS Agent — Happy Path

1. **Initiate**: `POST /api/device/authorize` with minimal `agent_info`
2. **Skip attestation** (do NOT call `/api/device/attest`)
3. **Open browser**: Navigate to `verification_uri_complete`, sign in, select "Non-CIRIS Agent"
4. **Pay**: Complete Stripe checkout ($1.50)
5. **Poll**: `POST /api/device/token` returns key
6. **Verify**: Template is `non_ciris`, agent type is `AGENT_TYPE_CUSTOM`

### Non-CIRIS Agent — Edge Cases

| Test | Input | Expected |
|------|-------|----------|
| Non-CIRIS completes without attest | Normal flow, skip attest | Key provisioned (attest not required) |
| Non-CIRIS submits attest anyway | Submit attestation proof | 200 (accepted but not required) |
| Non-CIRIS selects CIRIS template | User selects "CIRIS Agent" in browser | Only `non_ciris` template shown |

### Payment Gating

| Test | Scenario | Expected |
|------|----------|----------|
| Complete without payment | Call `/device/complete` before Stripe | 402, "Payment required" |
| Canceled checkout | User cancels Stripe | Portal shows "canceled" banner, can retry |
| Webhook race | Complete immediately after Stripe redirect | Portal polls Stripe API as fallback |

### Security Tests

| Test | Scenario | Expected |
|------|----------|----------|
| Replay attack | Reuse same attestation proof on new session | Fails (nonce doesn't match) |
| Device code brute force | Random device codes to `/device/attest` | 404 for all |
| Cross-session attack | Attest with device_code A, proof from session B | Nonce mismatch → 403 |
| Expired session | Attest after 15 min | 404 expired |

---

## Error Codes Reference

| Endpoint | Status | Error | Meaning |
|----------|--------|-------|---------|
| `/device/authorize` | 400 | `portal_url is required` | Missing required field |
| `/device/attest` | 400 | `device_code is required` | Missing device code |
| `/device/attest` | 400 | `attestation_proof is required` | Missing proof |
| `/device/attest` | 404 | `Invalid or expired device code` | Session gone |
| `/device/attest` | 403 | `Challenge nonce mismatch` | Replay / wrong nonce |
| `/device/attest` | 403 | `signature verification failed` | Bad signature |
| `/device/attest` | 403 | `integrity check failed` | Tampered files |
| `/device/attest` | 403 | `Agent has been revoked` | Revoked in Registry |
| `/device/complete` | 428 | `Attestation required for CIRIS agents` | Must attest first |
| `/device/complete` | 402 | `Payment required` | Must pay first |
| `/device/token` | 428 | `authorization_pending` | User hasn't finished |
| `/device/token` | 400 | `expired_token` | Session expired |
| `/device/token` | 403 | `access_denied` | User denied |

---

## Architecture Notes

### Why Portal verifies (not Registry directly)

Portal is the coordination point for the device auth flow — it issued the challenge, holds the device record, and manages the payment + user OAuth. Having Portal verify the attestation keeps the flow simple: one place manages the session lifecycle.

Registry is consulted for data (agent lookup, build attestation) but doesn't need to know about device auth sessions.

### PQC verification roadmap

Currently, Portal verifies the Ed25519 classical signature locally (Node.js `crypto` module supports Ed25519 natively). The ML-DSA-65 PQC signature is logged for audit but not verified server-side until Registry exposes a `VerifyAttestation` RPC.

When that RPC ships, Portal will send the full proof to Registry for hybrid verification. The `HybridCrypto::verify()` function already exists in the Registry Rust codebase — it just needs a gRPC wrapper.

### SOFTWARE_ONLY hardware type

Agents running without TPM/Secure Enclave fall back to software signing. The attestation still works (Ed25519 signature is valid), but there's no hardware root of trust. These agents:
- Show `hardware_type: SOFTWARE_ONLY` in attestation result
- Are flagged with a warning in the audit trail
- Are limited to community tier (enforced by both CIRISVerify and Portal)
- Still get a valid signing key — the software-only status is recorded, not blocked

### Manifest regeneration

The file integrity check (`check_agent_integrity`) compares runtime files against a SHA-256 manifest stored in CIRISRegistry via `RegisterBuild`. If the manifest is stale (doesn't match the current build), integrity checks will fail for legitimate agents.

**Before QA**: Regenerate the manifest from a clean build and register it via `RegisterBuild` / `RegisterBuildAttestation`. The current 2.0.0 manifest is dated.
