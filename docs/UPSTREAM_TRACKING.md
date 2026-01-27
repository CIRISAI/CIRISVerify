# Veilid Upstream Tracking

This document tracks our relationship with the Veilid project and documents divergences for future reconciliation.

## Upstream Reference

| Component | Upstream | Version | Status |
|-----------|----------|---------|--------|
| `keyring` crate | [crates.io/keyring](https://crates.io/crates/keyring) | 3.6 | In use |
| CryptoKind pattern | veilid-core/src/crypto | TBD | Pattern adopted |
| async patterns (tokio) | veilid-core | TBD | Compatible |

**Note**: We use the standard `keyring` crate from crates.io for OS keychain integration instead of
Veilid's keyring-manager. This provides cross-platform key storage (macOS Keychain, Windows
Credential Manager, Linux Secret Service) with a stable, public API.

## Design Patterns Adopted from Veilid

### 1. CryptoKind Algorithm Tagging

Veilid uses a 4-byte tag to identify cryptographic algorithms:

```rust
// Veilid pattern
pub type CryptoKind = [u8; 4];
pub const CRYPTO_KIND_VLD0: CryptoKind = *b"VLD0";

// CIRISVerify adoption
pub const CRYPTO_KIND_CIRIS_V1: CryptoKind = *b"CIR1";
```

**Rationale**: Enables crypto agility and clear algorithm identification in serialized data.

### 2. Async Runtime (Tokio)

Using tokio as the async runtime for Veilid compatibility:

```toml
tokio = { version = "1.35", features = ["full"] }
async-trait = "0.1"
```

### 3. Error Handling Pattern

Following Veilid's thiserror-based error types:

```rust
#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    #[error("No platform support available")]
    NoPlatformSupport,
    // ...
}
```

## Divergences from Veilid

### 1. HardwareSigner Trait (Extension)

**Status**: New functionality, not in upstream

Veilid's keyring-manager handles key storage but not signing. We extend with:

```rust
#[async_trait]
pub trait HardwareSigner: Send + Sync {
    fn algorithm(&self) -> ClassicalAlgorithm;
    fn hardware_type(&self) -> HardwareType;
    async fn public_key(&self) -> Result<Vec<u8>, KeyringError>;
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError>;
    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError>;
}
```

**Upstream contribution potential**: High - useful for any Veilid app needing hardware-bound signatures.

### 2. ECDSA P-256 Support

**Status**: Not in Veilid (uses Ed25519/X25519)

Required for mobile HSM compatibility (Android Keystore, iOS Secure Enclave).

**Upstream contribution potential**: Medium - Veilid prioritizes Ed25519, but P-256 enables hardware security.

### 3. Post-Quantum Cryptography

**Status**: Not in Veilid

ML-DSA-65 (FIPS 204) for quantum resistance.

**Upstream contribution potential**: High - future-proofing for Veilid.

### 4. Platform Attestation

**Status**: Not in Veilid

Hardware attestation for Android, iOS, TPM.

**Upstream contribution potential**: Medium - specific to verification use cases.

## Sync Process

### Checking for Upstream Changes

```bash
# Clone/update Veilid reference
git clone https://gitlab.com/veilid/veilid.git ../veilid-upstream
cd ../veilid-upstream
git pull

# Compare keyring-manager changes
git log --oneline --since="LAST_SYNC_DATE" -- veilid-core/src/*/keyring*
```

### Sync Checklist

1. [ ] Review upstream changes to keyring-manager
2. [ ] Review changes to CryptoKind definitions
3. [ ] Review async runtime updates
4. [ ] Test compatibility with our extensions
5. [ ] Update this document with new commit hash
6. [ ] Document any new divergences

## Contribution Guidelines

When preparing changes for upstream contribution:

1. **Isolate CIRIS-specific code**: Keep license verification separate from generic functionality
2. **Use feature flags**: New features should be opt-in
3. **Maintain API compatibility**: Don't break existing Veilid interfaces
4. **Add comprehensive tests**: Upstream requires good test coverage
5. **Document thoroughly**: Veilid has high documentation standards

### Candidate Contributions

| Feature | Priority | Status | Notes |
|---------|----------|--------|-------|
| HardwareSigner trait | High | Planning | Abstract away CIRIS-specific parts first |
| ECDSA P-256 support | Medium | Planning | Discuss with Veilid maintainers |
| TPM integration | Medium | Planning | Server-side hardware binding |
| Mobile attestation | Low | Planning | Very specific to verification |

## Contact

- **Veilid Project**: https://veilid.com
- **Veilid GitLab**: https://gitlab.com/veilid/veilid
- **Veilid Discord**: For contribution discussions

---

**Last Updated**: 2026-01-26
**Document Owner**: CIRIS Engineering
