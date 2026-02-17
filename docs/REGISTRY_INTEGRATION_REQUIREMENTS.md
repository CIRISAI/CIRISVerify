# CIRISVerify Integration Requirements

**Version:** 1.1.0
**Date:** 2026-02-17
**Status:** Active — Infrastructure endpoints configured, multi-source engine implemented

This document analyzes the requirements for CIRISVerify integration with CIRISRegistry, identifying what's implemented, what's missing, and what needs to be prioritized.

---

## Executive Summary

CIRISVerify is the hardware-rooted license verification component that enables CIRIS agents to verify their authorization status. It requires specific Registry capabilities to function correctly in both online and offline modes.

**Key Findings:**
- 54 gRPC endpoints specified in protocol
- Core lookup endpoints implemented (stub level in Registry, functional in CIRISVerify engine)
- Multi-source validation engine implemented in Rust with real infrastructure endpoints
- DNS endpoints configured: `us.registry.ciris-services-1.ai`, `eu.registry.ciris-services-1.ai`
- HTTPS endpoint configured: `api.registry.ciris-services-1.ai`
- Python SDK (`ciris-verify`) implemented and installed in CIRISAgent
- Hardware attestation validation: software fallback operational, hardware pending

---

## 1. CIRISVerify Core Requirements

### 1.1 Read-Only Verification Endpoints (Required)

| Endpoint | Purpose | CIRISVerify Usage | Status |
|----------|---------|-------------------|--------|
| `LookupAgent` | Verify agent build hash | Every agent startup | Stub |
| `LookupPartner` | Verify partner license | Every agent startup | Stub |
| `VerifyDeployment` | Combined agent+partner check | Primary verification call | Stub |
| `GetRevocationList` | Check revocation status | Periodic check (every 5min) | Stub |
| `GetPublicKeys` | Get partner public keys | Signature verification | Stub |
| `GetOfflinePackage` | Full offline verification data | Network-limited environments | Stub |
| `GetOfflineDelta` | Incremental updates | Bandwidth-constrained updates | Stub |
| `HealthCheck` | Check registry availability | Before queries | Stub |
| `GetEmergencyStatus` | Check circuit breaker | Fail-fast on lockdown | Stub |
| `GetCapabilities` | Feature discovery | Client version compat | Stub |

### 1.2 Multi-Source Validation (Engine Implemented — DNS Publishing Pending)

Per FSD-001, CIRISVerify MUST query multiple sources:

```
┌─────────────────────────────────────────────────────────┐
│                    CIRISVerify                          │
│                                                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐       │
│  │  DNS US     │ │  DNS EU     │ │  HTTPS API  │       │
│  │ registry-us │ │ registry-eu │ │ api.registry│       │
│  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘       │
│         │               │               │               │
│         └───────────────┼───────────────┘               │
│                         │                               │
│                    2-of-3 Agreement                     │
│                         │                               │
│                ┌────────┴────────┐                      │
│                │ ACTIVE / REVOKED│                      │
│                └─────────────────┘                      │
└─────────────────────────────────────────────────────────┘
```

**Component Status:**

1. **DNS TXT Record Publishing** — Pending (Registry side)
   ```
   <hash_prefix>._agent.registry.ciris.ai TXT "v=1;s=ACTIVE;t=CIRISMEDICAL;sig=..."
   <partner_id>._partner.registry.ciris.ai TXT "v=1;s=ACTIVE;l=PROF_MED;sig=..."
   ```

2. **Multi-Region HTTPS Endpoints** — ✅ Configured in CIRISVerify
   - `us.registry.ciris-services-1.ai` (US region)
   - `eu.registry.ciris-services-1.ai` (EU region)
   - `api.registry.ciris-services-1.ai` (Primary API)

3. **Validation Logic** — ✅ Implemented in Rust (`engine.rs`)
   - Minimum 2-of-3 sources must agree for ACTIVE
   - ANY source reporting REVOKED triggers immediate action
   - Disagreement on critical fields triggers SECURITY_ALERT
   - Consensus algorithm with `build_validation_results()` and `compute_overall_validation()`

### 1.3 Hardware Attestation (NOT Implemented)

CIRISVerify uses hardware-rooted attestation to prove deployment integrity:

```protobuf
message LookupPartnerRequest {
  string partner_id = 1;
  bytes request_nonce = 2;
  bytes hardware_attestation = 3;  // Required for professional lookups
}
```

**Required Implementation:**
- TPM 2.0 attestation validation
- Apple Secure Enclave validation (macOS/iOS)
- Android Hardware Keystore validation
- Fallback to software attestation with logging

### 1.4 Offline Verification (Stub Only)

Medical devices and network-limited environments require 72+ hour offline capability:

**Required Components:**
1. `OfflineVerificationPackage` generation
2. Merkle tree construction for agents/partners/revocations
3. `MerkleProofWithChain` for complete chain of custody
4. Delta generation for bandwidth-constrained updates
5. Package expiration enforcement (configurable per partner)

---

## 2. Gap Analysis

### 2.1 Protocol Implementation Status

| Service | Total Methods | Implemented | Stub | Missing |
|---------|---------------|-------------|------|---------|
| RegistryService | 13 | 0 | 13 | 0 |
| RegistryAdminService | 18 | 0 | 18 | 0 |
| PortalService | 23 | 0 | 23 | 0 |
| **Total** | **54** | **0** | **54** | **0** |

All methods are stub implementations returning placeholder data. Business logic needs implementation.

### 2.2 Critical Missing Features

#### Priority 1: Verification Core (Required for CIRISVerify)

| Feature | Description | Complexity |
|---------|-------------|------------|
| **Agent/Partner Lookup** | Database queries with Merkle proofs | Medium |
| **Hybrid Signature Verification** | Ed25519 + ML-DSA-65 validation | High |
| **Revocation List** | Delta updates with version tracking | Medium |
| **Capability Intersection** | `effective = agent ∩ partner.granted - partner.denied` | Low |

#### Priority 2: Multi-Source Validation (Required for Production)

| Feature | Description | Complexity |
|---------|-------------|------------|
| **DNS TXT Publishing** | Route 53 TXT record generation | Medium |
| **DNS Query Support** | TXT record format for compact responses | Medium |
| **Cross-Region Sync** | US↔EU database replication | High |
| **Consensus Logic** | 2-of-3 agreement algorithm | Medium |

#### Priority 3: Offline Support (Required for Medical)

| Feature | Description | Complexity |
|---------|-------------|------------|
| **Snapshot Generation** | Full registry export with Merkle roots | High |
| **Delta Generation** | Incremental updates since timestamp | High |
| **Package Signing** | Hybrid signature on compressed data | Medium |
| **Chain of Custody** | MerkleProofWithChain construction | High |

#### Priority 4: Security Hardening (Required for Compliance)

| Feature | Description | Complexity |
|---------|-------------|------------|
| **Hardware Attestation** | TPM/Secure Enclave validation | Very High |
| **HSM Integration** | Vault/CloudKMS/HSM key storage | High |
| **Rate Limiting** | Per-endpoint rate limits | Low |
| **Audit Logging** | Cryptographic audit trail | Medium |

### 2.3 Database Schema Gaps

Current schema needs additions for:

```sql
-- Multi-source validation tracking
CREATE TABLE dns_sync_status (
    region TEXT PRIMARY KEY,  -- 'us', 'eu'
    last_sync_at TIMESTAMPTZ,
    record_count INTEGER,
    sync_status TEXT  -- 'SYNCED', 'BEHIND', 'ERROR'
);

-- Hardware attestation records
CREATE TABLE hardware_attestations (
    attestation_id UUID PRIMARY KEY,
    partner_id UUID REFERENCES partners(id),
    attestation_type TEXT,  -- 'TPM', 'SECURE_ENCLAVE', 'SOFTWARE'
    attestation_data BYTEA,
    verified_at TIMESTAMPTZ,
    valid_until TIMESTAMPTZ
);

-- Offline package tracking
CREATE TABLE offline_packages (
    package_id UUID PRIMARY KEY,
    snapshot_version BIGINT,
    generated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    agents_root BYTEA,
    partners_root BYTEA,
    revocations_root BYTEA,
    package_signature BYTEA,
    compression TEXT
);
```

---

## 3. CIRISVerify Client SDK Requirements

### 3.1 Recommended SDK Interface

```rust
/// CIRISVerify client for agent verification
pub struct CirisVerifyClient {
    registry_url: String,
    dns_us_resolver: DnsResolver,
    dns_eu_resolver: DnsResolver,
    offline_cache: OfflinePackageCache,
    hardware_attestor: HardwareAttestor,
}

impl CirisVerifyClient {
    /// Verify agent deployment with multi-source validation
    pub async fn verify_deployment(
        &self,
        agent_hash: &[u8; 32],
        partner_id: &str,
    ) -> Result<VerificationResult, VerifyError> {
        // 1. Query all sources in parallel
        let (dns_us, dns_eu, https) = tokio::join!(
            self.query_dns_us(agent_hash, partner_id),
            self.query_dns_eu(agent_hash, partner_id),
            self.query_https(agent_hash, partner_id),
        );

        // 2. Check for any revocation
        if dns_us.is_revoked() || dns_eu.is_revoked() || https.is_revoked() {
            return Ok(VerificationResult::Revoked {
                source: first_revoked_source
            });
        }

        // 3. Require 2-of-3 agreement for ACTIVE
        let agreement = count_active_sources(&[dns_us, dns_eu, https]);
        if agreement < 2 {
            return Err(VerifyError::InsufficientAgreement);
        }

        // 4. Return effective capabilities
        Ok(VerificationResult::Verified {
            effective_capabilities: calculate_intersection(...),
            effective_autonomy: min_autonomy(...),
        })
    }

    /// Verify using offline cache (for network-limited environments)
    pub fn verify_offline(
        &self,
        agent_hash: &[u8; 32],
        partner_id: &str,
    ) -> Result<VerificationResult, VerifyError> {
        // Check cache freshness (72-hour default)
        let package = self.offline_cache.get_current()?;
        if package.is_expired() {
            return Err(VerifyError::OfflineCacheExpired);
        }

        // Verify Merkle proof chain
        let agent = package.lookup_agent_with_proof(agent_hash)?;
        let partner = package.lookup_partner_with_proof(partner_id)?;

        // Verify package signature
        if !self.verify_package_signature(&package)? {
            return Err(VerifyError::InvalidPackageSignature);
        }

        Ok(VerificationResult::VerifiedOffline {
            effective_capabilities: calculate_intersection(...),
            cache_expires_at: package.expires_at,
        })
    }
}
```

### 3.2 DNS Query Format

For compact DNS TXT responses:

```
Query: a1b2c3d4e5f6._agent.registry-us.ciris.ai TXT

Response: "v=1;s=A;t=MED;a=A2;c=3;sig=<base64>"

Fields:
  v=1     - Protocol version
  s=A     - Status: A=Active, D=Deprecated, R=Revoked
  t=MED   - Type: MED=Medical, LEG=Legal, FIN=Financial
  a=A2    - Max autonomy tier
  c=3     - Capability count (full list via HTTPS)
  sig=... - Truncated hybrid signature (full via HTTPS)
```

---

## 4. Implementation Roadmap

### Phase 1: Core Verification (Blocks CIRISVerify Alpha)

1. Implement `LookupAgent` with database query
2. Implement `LookupPartner` with database query
3. Implement `VerifyDeployment` with capability intersection
4. Implement `GetRevocationList` with delta support
5. Add Merkle proof generation

**Deliverable:** CIRISVerify can perform basic online verification

### Phase 2: Cryptographic Security (Blocks CIRISVerify Beta)

1. Implement hybrid signature generation (Ed25519 + ML-DSA-65)
2. Implement signature verification
3. Add signing key management
4. Add response signing for all lookups

**Deliverable:** All responses are cryptographically signed

### Phase 3: Multi-Source Validation (Blocks Production)

1. Implement DNS TXT record generation
2. Set up Route 53 automation for record publishing
3. Deploy EU region instance
4. Implement cross-region replication
5. Add 2-of-3 consensus validation

**Deliverable:** Multi-source validation operational

### Phase 4: Offline Verification (Blocks Medical Deployment)

1. Implement `OfflineVerificationPackage` generation
2. Implement Merkle tree construction
3. Implement `MerkleProofWithChain`
4. Implement delta generation
5. Add package compression (gzip/zstd)

**Deliverable:** 72+ hour offline verification capability

### Phase 5: Hardware Attestation (Blocks Enterprise Deployment)

1. TPM 2.0 attestation validation
2. Apple Secure Enclave validation
3. Android Keystore validation
4. Attestation logging and auditing

**Deliverable:** Hardware-rooted verification

---

## 5. Testing Requirements

### 5.1 Verification Test Cases

| Test | Description | Pass Criteria |
|------|-------------|---------------|
| VER-001 | Valid agent lookup | Returns ACTIVE with capabilities |
| VER-002 | Unknown agent lookup | Returns NOT_FOUND, community mode |
| VER-003 | Revoked agent lookup | Returns REVOKED with reason |
| VER-004 | Valid partner lookup | Returns ACTIVE with grants |
| VER-005 | Expired partner lookup | Returns EXPIRED, community mode |
| VER-006 | Capability intersection | `agent ∩ partner.granted - denied` |
| VER-007 | Autonomy tier calculation | `min(agent.tier, partner.tier)` |
| VER-008 | Multi-source agreement | 2-of-3 required for ACTIVE |
| VER-009 | Any revoked = revoked | Single REVOKED source triggers |
| VER-010 | Offline verification | Works with valid package |
| VER-011 | Offline cache expired | Degrades to community mode |
| VER-012 | Hardware attestation | TPM validation passes |

### 5.2 Performance Requirements

| Metric | Target | Critical |
|--------|--------|----------|
| Lookup latency (P99) | < 100ms | < 500ms |
| Multi-source latency (P99) | < 300ms | < 1000ms |
| Revocation list download | < 5s | < 30s |
| Offline package size | < 10MB | < 50MB |
| Offline package generation | < 60s | < 300s |

---

## 6. Security Considerations

### 6.1 Threat Mitigations

| Threat | Mitigation | Status |
|--------|------------|--------|
| Registry compromise | Multi-source validation | NOT IMPLEMENTED |
| Replay attacks | Nonce in requests, timestamp in responses | Protocol defined |
| Enumeration | Rate limiting, API key for bulk | NOT IMPLEMENTED |
| Stale data attacks | Short TTL, revocation priority | Protocol defined |
| Key compromise | Hybrid crypto, key rotation, HSM | NOT IMPLEMENTED |
| DNS hijacking | DNSSEC + signature verification | NOT IMPLEMENTED |

### 6.2 Fail-Secure Defaults

CIRISVerify MUST implement these fail-secure behaviors:

1. **Unknown agent** → Community tier only
2. **Unknown partner** → No capability grants
3. **Network failure** → Use cached data (if fresh) OR degrade
4. **Cache expired** → Community tier only
5. **Signature invalid** → Reject completely
6. **Any revocation** → Immediate enforcement

---

## 7. Dependencies

### 7.1 External Dependencies

| Dependency | Purpose | Alternative |
|------------|---------|-------------|
| Route 53 | DNS TXT publishing | CloudFlare DNS |
| AWS KMS | Key storage | HashiCorp Vault |
| CloudWatch | Metrics | Prometheus |
| PostgreSQL | Primary database | None |

### 7.2 Library Dependencies

```toml
# Required for CIRISVerify integration
ed25519-dalek = "2"           # Ed25519 signatures
pqcrypto-dilithium = "0.5"    # ML-DSA-65 (Dilithium)
sha2 = "0.10"                 # SHA-256 hashing
merkle-tree = "0.1"           # Merkle proof generation
zstd = "0.13"                 # Package compression
trust-dns-client = "0.23"     # DNS queries
```

---

## 8. Open Questions

1. **DNS TTL Strategy**: What TTL for DNS TXT records? (Current thinking: 300s for agent, 60s for revocations)

2. **Offline Grace Period**: Should this be configurable per-partner? (FSD says 72h default, but medical may need longer)

3. **Hardware Attestation Fallback**: What happens on devices without TPM/Secure Enclave? (Current thinking: software attestation with logging)

4. **Revocation Propagation SLA**: What's the maximum time from revocation to enforcement? (Target: < 60 seconds)

5. **Multi-Region Consistency**: Eventually consistent or strongly consistent? (Recommendation: Eventually consistent with revocation priority)

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-26 | Initial analysis |
