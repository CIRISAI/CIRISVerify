# CIRISVerify: Open Items and Future Work

**Generated**: 2026-01-25 | **Updated**: 2026-02-17
**Source**: Multi-stakeholder evaluation (Security, Compliance, Partner, Humanitarian)

This document tracks items identified during evaluation that require business decisions, significant development effort, or external engagement beyond specification updates.

---

## Items Added to FSD (Completed)

The following items have been incorporated into the protocol specification:

| Item | Location | Status |
|------|----------|--------|
| SOFTWARE_ONLY tier restriction | FSD Section "Mandatory Security Requirements" | **Done** |
| PQC signature binding | FSD Section "Mandatory Security Requirements" | **Done** |
| Certificate pinning requirement | FSD Section "Mandatory Security Requirements" | **Done** |
| Constant-time verification | FSD Section "Mandatory Security Requirements" | **Done** |
| Nonce handling specification | FSD Section "Mandatory Security Requirements" | **Done** |
| Integrity check opacity | FSD + Proto `IntegrityStatus` | **Done** |
| PARTIAL_AGREEMENT restrictions | FSD Section "Mandatory Security Requirements" | **Done** |
| Extended offline grace options | FSD Section "Humanitarian Deployment Options" | **Done** |
| Low-bandwidth mode | FSD Section "Humanitarian Deployment Options" | **Done** |
| Emergency override (placeholder) | FSD Section "Humanitarian Deployment Options" | **Noted for v2.1** |

---

## Business/Legal Items (Requires Steward Decision)

### 1. Source Code Escrow
**Priority**: HIGH
**Stakeholders**: Partners, Enterprise Customers

**Issue**: Partners expressed concern about vendor lock-in and business continuity if CIRIS L3C ceases operations.

**Recommendation**: Establish source code escrow agreement with release triggers:
- CIRIS L3C bankruptcy or dissolution
- Failure to maintain verification infrastructure for 30+ days
- Material breach of SLA commitments

**Action Owner**: CIRIS L3C Legal/Executive

---

### 2. Steward Key Succession Plan
**Priority**: HIGH
**Stakeholders**: All

**Issue**: No documented succession plan for steward signing keys if CIRIS L3C leadership changes or organization fails.

**Recommendation**: Document key succession including:
- Multi-party key ceremony requirements
- Emergency key rotation procedures
- Succession entity identification
- Key recovery from escrow procedures

**Action Owner**: CIRIS L3C Executive

---

### 3. Pricing Structure
**Priority**: HIGH
**Stakeholders**: Partners, NGOs

**Issue**: No pricing information available. Partners cannot evaluate cost-benefit. NGOs need humanitarian pricing tier.

**Recommendation**: Publish or provide on request:
- Per-organization licensing tiers
- Capability-based pricing (medical, legal, financial)
- Volume discounts for multi-site deployments
- Humanitarian/NGO subsidized tier
- Academic/research pricing

**Action Owner**: CIRIS L3C Business Development

---

### 4. SLA Definitions
**Priority**: HIGH
**Stakeholders**: Partners, Enterprise Customers

**Issue**: No SLA commitments for verification infrastructure uptime.

**Recommendation**: Define and publish:
- Uptime commitment (recommend 99.95%+)
- Response time for critical issues (<4 hours)
- Planned maintenance windows
- Incident communication procedures
- Credits/remedies for SLA breach

**Action Owner**: CIRIS L3C Operations

---

### 5. HIPAA Business Associate Agreement
**Priority**: MEDIUM
**Stakeholders**: Healthcare Partners (US)

**Issue**: If verification flow touches any PHI, HIPAA BAA required.

**Recommendation**:
- Analyze whether verification flow involves PHI (likely no)
- If yes, prepare standard BAA template
- If no, document data flow to confirm no PHI involvement

**Action Owner**: CIRIS L3C Legal/Compliance

---

## Development Items (Requires Engineering)

### 6. Official SDKs
**Priority**: MEDIUM
**Stakeholders**: Partners

**Issue**: No official client libraries. Partners must implement from protobuf.

**Recommendation**: Develop official SDKs for:
- Python (highest priority - CIRISAgent integration)
- Java/Kotlin (Android applications)
- Swift (iOS applications)
- TypeScript (web applications)
- Go (server applications)

**Estimated Effort**: 2-4 weeks per SDK
**Action Owner**: CIRIS Engineering

---

### 7. REST API Gateway
**Priority**: LOW
**Stakeholders**: Partners

**Issue**: Some partners prefer REST over gRPC for simpler integration.

**Recommendation**: Add REST/JSON gateway for:
- GET /v1/license-status
- GET /v1/capability-check
- GET /v1/health

gRPC remains primary; REST is convenience layer.

**Estimated Effort**: 1-2 weeks
**Action Owner**: CIRIS Engineering

---

### 8. Monitoring/Metrics Endpoint
**Priority**: MEDIUM
**Stakeholders**: Partners, Operations

**Issue**: No Prometheus/StatsD metrics export for operational monitoring.

**Recommendation**: Add metrics endpoint exposing:
- Verification success/failure rates
- Latency percentiles
- Cache hit rates
- Source reachability
- Hardware type distribution

**Estimated Effort**: 1 week
**Action Owner**: CIRIS Engineering

---

### 9. Multi-Language Disclosures
**Priority**: MEDIUM
**Stakeholders**: NGOs, International Partners

**Issue**: Mandatory disclosures currently English-only.

**Recommendation**:
- Phase 1: Build-time localization for top 10 languages
- Phase 2: Runtime locale selection
- Provide translation guide for community contributions

**Estimated Effort**: 2-3 weeks (Phase 1)
**Action Owner**: CIRIS Engineering + Localization

---

### 10. Emergency Override Mechanism
**Priority**: LOW (v2.1)
**Stakeholders**: NGOs, Humanitarian Organizations

**Issue**: No mechanism to extend licenses during declared emergencies.

**Recommendation**: Design emergency override with:
- Steward-activated emergency tokens
- Geographic emergency zones
- Time-limited extensions
- Full audit logging
- Abuse prevention controls

**Estimated Effort**: 4-6 weeks (complex feature)
**Action Owner**: CIRIS Engineering + Policy

---

## Compliance/Certification Items

### 11. Incident Response Plan
**Priority**: HIGH
**Stakeholders**: Assessors, Enterprise Customers

**Issue**: No formal incident response plan documented.

**Recommendation**: Develop and publish:
- Incident classification scheme
- Escalation procedures
- Forensic data collection requirements
- Communication templates
- Post-incident review process

**Action Owner**: CIRIS Operations/Security

---

### 12. Audit Log Specification
**Priority**: HIGH
**Stakeholders**: Assessors, Compliance

**Issue**: No standardized audit log format specified.

**Status**: **PARTIALLY ADDRESSED** — The `TransparencyLog` module (Fix 1) provides:
- Append-only, chain-linked verification event logging
- SHA-256 Merkle tree with tamper-evident inclusion proofs
- Structured `TransparencyEntry` records (index, timestamp, license_id, status, consensus_status, revocation_revision, previous_hash, merkle_root)
- Persistent file output for durable audit trails
- Proof chain export for third-party audit

**Remaining work**: Define additional structured events for capability checks, administrative actions, and security events. Standardize JSON schema and retention policy.

**Action Owner**: CIRIS Engineering/Security

---

### 13. FIPS 140-3 Certification Path
**Priority**: MEDIUM
**Stakeholders**: Government, Healthcare Enterprise

**Issue**: No FIPS 140-3 certification for cryptographic module.

**Recommendation**:
- Phase 1: Use FIPS 140-3 validated libraries (OpenSSL, BoringSSL)
- Phase 2: Pursue module certification (12-18 months, significant cost)
- Document cryptographic boundary and NIST SP 800-57 compliance

**Estimated Cost**: $150-300K for certification
**Action Owner**: CIRIS Executive (funding decision)

---

### 14. SOC 2 Type II
**Priority**: MEDIUM
**Stakeholders**: Enterprise Partners

**Issue**: No SOC 2 compliance for verification infrastructure.

**Recommendation**:
- Map controls to Trust Service Criteria
- Engage auditor for Type I (point-in-time)
- Progress to Type II (period of time)

**Estimated Cost**: $50-100K annually
**Timeline**: 6-12 months for Type II
**Action Owner**: CIRIS Operations/Compliance

---

### 15. Third-Party Security Audit
**Priority**: HIGH
**Stakeholders**: All

**Issue**: Security-critical binary requires independent security validation.

**Recommendation**: Engage security firm for:
- Binary reverse engineering assessment
- Cryptographic implementation review
- Penetration testing of verification infrastructure
- Protocol specification review

**Estimated Cost**: $75-150K
**Frequency**: Pre-release + annually
**Action Owner**: CIRIS Security

---

## Operational Items

### 16. Device Fleet Management
**Priority**: MEDIUM
**Stakeholders**: Enterprise Partners

**Issue**: No documented process for managing multiple devices under one license.

**Recommendation**: Clarify and document:
- Organization vs. device licensing model
- Device registration/deregistration procedures
- License transfer between devices
- Fleet status dashboard (future feature)

**Action Owner**: CIRIS Product/Engineering

---

### 17. Field Troubleshooting Guide
**Priority**: MEDIUM
**Stakeholders**: NGOs, Field Operations

**Issue**: No troubleshooting documentation for non-technical field staff.

**Recommendation**: Create:
- Decision tree for common errors
- Visual status indicator guide
- Escalation contact procedures
- Offline recovery procedures

**Action Owner**: CIRIS Documentation/Support

---

### 18. Binary Update Process
**Priority**: MEDIUM
**Stakeholders**: Partners, Medical Device Manufacturers

**Issue**: Update frequency and notification process not documented.

**Recommendation**: Define and publish:
- Release cadence (recommend quarterly + security patches)
- Change notification lead time (recommend 30 days for non-security)
- Backwards compatibility guarantees
- Rollback procedures

**Action Owner**: CIRIS Engineering/Product

---

## Summary by Priority

### Critical (Before GA)
- Source code escrow (#1)
- Steward key succession (#2)
- Pricing structure (#3)
- SLA definitions (#4)
- Incident response plan (#11)
- Third-party security audit (#15)

### High (Within 6 months)
- Audit log specification (#12) — **partially addressed** (transparency log with Merkle tree implemented; remaining: event schema standardization)
- Official Python SDK (#6) — **partially addressed** (ciris-verify 0.2.0 published on PyPI)
- Field troubleshooting guide (#17)

### Medium (Within 12 months)
- Additional SDKs (#6)
- Monitoring endpoint (#8)
- Multi-language disclosures (#9)
- FIPS 140-3 path (#13)
- SOC 2 Type II (#14)
- Device fleet management (#16)
- Binary update process (#18)

### Low/Future (v2.1+)
- REST API gateway (#7)
- Emergency override mechanism (#10)

---

**Document Owner**: CIRIS L3C Product/Engineering
**Review Cycle**: Monthly until GA, quarterly thereafter
