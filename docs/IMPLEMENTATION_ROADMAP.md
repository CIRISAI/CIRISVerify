# CIRISVerify Implementation Roadmap

**Status**: Active Development (Phase 0-1 Complete, Phase 3-4 In Progress)
**Target**: Production-ready v2.0.0
**Language**: Rust
**Upstream Alignment**: Veilid patterns for potential contribution
**Last Updated**: 2026-02-17

---

## Guiding Principles

### 1. Veilid Compatibility
- Follow Veilid's `CryptoKind` pattern for algorithm tagging
- Use compatible error types and async patterns (tokio)
- Structure crates similarly for potential upstream contribution
- Use `cfg` feature flags consistently with Veilid conventions

### 2. Minimal Divergence
When extending Veilid components:
- Prefer **additive changes** over modifications
- Use **trait extension** rather than forking structs
- Keep **API surface compatible** where possible
- Document all divergences for future reconciliation

### 3. Security First
- No `unsafe` outside FFI boundaries
- All crypto operations via audited crates
- Constant-time comparisons throughout
- Fail-secure by default

---

## Phase 0: Foundation ✅ COMPLETE

### 0.1 Project Setup
- [x] Initialize Cargo workspace (4 crates: ciris-keyring, ciris-crypto, ciris-verify-core, ciris-verify-ffi)
- [x] Configure CI/CD (GitHub Actions — cargo test, cargo deny, rustfmt, clippy)
- [x] Set up cross-compilation targets
- [x] Configure clippy/rustfmt with strict settings
- [x] Set up security audit workflow (cargo-deny)

### 0.2 Upstream Alignment
- [x] Fork `keyring-manager` to `ciris-keyring`
- [x] Document Veilid commit hash for tracking
- [x] Set up upstream sync workflow
- [x] Identify minimal changes needed

### Deliverables
- ✅ Compiling workspace with all crate stubs
- ✅ CI passing (124 tests)
- ✅ Documented upstream tracking

---

## Phase 1: Core Cryptography

### 1.1 Classical Algorithms (`ciris-crypto`)

#### ECDSA P-256 (Hardware-compatible)
```rust
// Primary algorithm for hardware HSMs
pub trait EcdsaP256Signer {
    fn public_key(&self) -> P256PublicKey;
    fn sign(&self, msg: &[u8]) -> Result<P256Signature, CryptoError>;
}

pub trait EcdsaP256Verifier {
    fn verify(&self, msg: &[u8], sig: &P256Signature) -> Result<bool, CryptoError>;
}
```

**Crate**: `p256` (RustCrypto)
**Why**: Audited, pure Rust, FIPS 186-4 compliant

#### Ed25519 (Software/SGX)
```rust
// For steward signatures and SGX deployments
pub trait Ed25519Signer {
    fn public_key(&self) -> Ed25519PublicKey;
    fn sign(&self, msg: &[u8]) -> Result<Ed25519Signature, CryptoError>;
}
```

**Crate**: `ed25519-dalek`
**Why**: Mature, audited, used by Veilid

### 1.2 Post-Quantum Algorithms

#### ML-DSA-65 (FIPS 204)
```rust
pub trait MlDsaSigner {
    fn public_key(&self) -> MlDsaPublicKey;  // ~1,952 bytes
    fn sign(&self, msg: &[u8]) -> Result<MlDsaSignature, CryptoError>;  // ~3,293 bytes
}
```

**Crate Options** (evaluate in order):
1. `aws-lc-rs` - Best audit path, FIPS trajectory
2. `ml-dsa` (RustCrypto) - Pure Rust, unaudited
3. `pqcrypto` - FFI to liboqs, audited upstream

**Decision Criteria**:
- [ ] Benchmark on mobile (ARM64)
- [ ] Evaluate FIPS certification path
- [ ] Check no_std compatibility for embedded

### 1.3 Hybrid Signature System

Following Veilid's `CryptoKind` pattern:

```rust
/// Four-character code identifying crypto system (Veilid pattern)
pub type CryptoKind = [u8; 4];

pub const CRYPTO_KIND_CIRIS_V1: CryptoKind = *b"CIR1";

/// Tagged signature that includes algorithm info
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    pub crypto_kind: CryptoKind,
    pub classical: TaggedClassicalSignature,
    pub pqc: TaggedPqcSignature,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TaggedClassicalSignature {
    pub algorithm: ClassicalAlgorithm,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TaggedPqcSignature {
    pub algorithm: PqcAlgorithm,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}
```

### 1.4 Signature Binding (Critical Security)

```rust
impl HybridSigner {
    /// Create bound hybrid signature
    /// PQC signature covers classical signature to prevent stripping
    pub fn sign_hybrid(
        &self,
        data: &[u8],
        classical_signer: &dyn ClassicalSigner,
        pqc_signer: &dyn PqcSigner,
    ) -> Result<HybridSignature, CryptoError> {
        // 1. Classical signature over data
        let classical_sig = classical_signer.sign(data)?;

        // 2. Build bound payload: data || classical_sig
        let bound_payload = [data, &classical_sig.signature].concat();

        // 3. PQC signature over bound payload
        let pqc_sig = pqc_signer.sign(&bound_payload)?;

        Ok(HybridSignature {
            crypto_kind: CRYPTO_KIND_CIRIS_V1,
            classical: classical_sig,
            pqc: pqc_sig,
        })
    }

    /// Verify bound hybrid signature
    /// Both signatures must pass; order matters
    pub fn verify_hybrid(
        &self,
        data: &[u8],
        signature: &HybridSignature,
    ) -> Result<bool, CryptoError> {
        // 1. Verify classical signature
        let classical_valid = self.verify_classical(data, &signature.classical)?;
        if !classical_valid {
            return Ok(false);
        }

        // 2. Rebuild bound payload
        let bound_payload = [data, &signature.classical.signature].concat();

        // 3. Verify PQC signature over bound payload
        self.verify_pqc(&bound_payload, &signature.pqc)
    }
}
```

### Deliverables
- `ciris-crypto` crate with all algorithms
- Comprehensive test vectors (NIST, Wycheproof)
- Benchmark suite for mobile targets
- Algorithm selection documentation

---

## Phase 2: Hardware Integration

### 2.1 HardwareSigner Trait (`ciris-keyring`)

Extend `keyring-manager` with signing capability:

```rust
/// Extension trait for hardware-bound signing
/// Compatible with Veilid's async patterns
#[async_trait]
pub trait HardwareSigner: Send + Sync {
    /// Algorithm this signer uses (hardware-constrained)
    fn algorithm(&self) -> ClassicalAlgorithm;

    /// Hardware type for attestation context
    fn hardware_type(&self) -> HardwareType;

    /// Public key (exportable)
    async fn public_key(&self) -> Result<Vec<u8>, KeyringError>;

    /// Sign data - private key never leaves hardware
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError>;

    /// Platform attestation proving hardware binding
    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError>;

    /// Key generation (if not already present)
    async fn generate_key(&self, config: &KeyGenConfig) -> Result<(), KeyringError>;
}

/// Configuration for key generation
pub struct KeyGenConfig {
    pub alias: String,
    pub require_hardware: bool,
    pub require_user_auth: bool,
    pub auth_timeout_seconds: Option<u32>,
}
```

### 2.2 Android Keystore Implementation

```rust
#[cfg(target_os = "android")]
pub struct AndroidKeystoreSigner {
    alias: String,
    jvm: JavaVM,
}

#[cfg(target_os = "android")]
#[async_trait]
impl HardwareSigner for AndroidKeystoreSigner {
    fn algorithm(&self) -> ClassicalAlgorithm {
        ClassicalAlgorithm::EcdsaP256  // Hardware constraint
    }

    fn hardware_type(&self) -> HardwareType {
        // Detect StrongBox vs standard Keystore
        if self.has_strongbox() {
            HardwareType::AndroidStrongbox
        } else {
            HardwareType::AndroidKeystore
        }
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        // JNI call to Keystore
        let env = self.jvm.attach_current_thread()?;

        // Get key from Keystore
        let keystore = env.call_static_method(
            "java/security/KeyStore",
            "getInstance",
            "(Ljava/lang/String;)Ljava/security/KeyStore;",
            &[JValue::from(env.new_string("AndroidKeyStore")?)],
        )?;

        // ... sign with Signature.getInstance("SHA256withECDSA")
    }

    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
        Ok(PlatformAttestation::Android(AndroidAttestation {
            key_attestation_chain: self.get_attestation_chain().await?,
            play_integrity_token: self.get_play_integrity().await.ok(),
        }))
    }
}
```

### 2.3 iOS Secure Enclave Implementation

```rust
#[cfg(target_os = "ios")]
pub struct SecureEnclaveSigner {
    key_tag: String,
}

#[cfg(target_os = "ios")]
#[async_trait]
impl HardwareSigner for SecureEnclaveSigner {
    fn algorithm(&self) -> ClassicalAlgorithm {
        ClassicalAlgorithm::EcdsaP256  // Only option for SE
    }

    fn hardware_type(&self) -> HardwareType {
        HardwareType::IosSecureEnclave
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        // Use Security.framework via objc crate
        // SecKeyCreateSignature with kSecKeyAlgorithmECDSASignatureMessageX962SHA256
    }

    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
        Ok(PlatformAttestation::Ios(IosAttestation {
            app_attest_assertion: self.get_app_attest().await?,
            device_check_token: self.get_device_check().await.ok(),
        }))
    }
}
```

### 2.4 TPM 2.0 Implementation

```rust
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub struct TpmSigner {
    context: tss_esapi::Context,
    key_handle: KeyHandle,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[async_trait]
impl HardwareSigner for TpmSigner {
    fn algorithm(&self) -> ClassicalAlgorithm {
        ClassicalAlgorithm::EcdsaP256  // Cross-platform consistency
    }

    fn hardware_type(&self) -> HardwareType {
        HardwareType::Tpm20
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        // Use tss-esapi
        let digest = Digest::try_from(sha256(data))?;
        let signature = self.context.sign(
            self.key_handle,
            digest,
            SignatureScheme::EcDsa { hash_scheme: HashScheme::Sha256 },
            HashcheckTicket::default(),
        )?;
        Ok(signature.marshal()?)
    }

    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
        let quote = self.context.quote(...)?;
        Ok(PlatformAttestation::Tpm(TpmAttestation {
            quote: quote.marshal()?,
            pcr_values: self.read_pcrs()?,
            aik_certificate: self.get_aik_cert()?,
        }))
    }
}
```

### 2.5 Software Fallback

```rust
/// Software-only signer for development/testing
/// WARNING: Limited to UNLICENSED_COMMUNITY tier
pub struct SoftwareSigner {
    keypair: p256::SecretKey,
}

#[async_trait]
impl HardwareSigner for SoftwareSigner {
    fn algorithm(&self) -> ClassicalAlgorithm {
        ClassicalAlgorithm::EcdsaP256
    }

    fn hardware_type(&self) -> HardwareType {
        HardwareType::SoftwareOnly  // Triggers tier restriction
    }

    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
        Ok(PlatformAttestation::Software(SoftwareAttestation {
            security_warning: "SOFTWARE_ONLY: No hardware binding. \
                              Limited to UNLICENSED_COMMUNITY tier.".into(),
        }))
    }
}
```

### Deliverables
- `ciris-keyring` crate with all platform implementations
- Integration tests on real hardware (CI with device farm)
- Attestation verification test suite
- Platform capability detection

---

## Phase 3: Verification Engine

### 3.1 Multi-Source DNS Validator

```rust
pub struct DnsValidator {
    resolvers: Vec<DnsResolver>,
    timeout: Duration,
}

impl DnsValidator {
    /// Query multiple DNS sources for steward key
    pub async fn validate(&self) -> Result<DnsValidation, ValidationError> {
        let futures: Vec<_> = self.resolvers
            .iter()
            .map(|r| self.query_source(r))
            .collect();

        let results = futures::future::join_all(futures).await;

        self.compute_consensus(results)
    }

    fn compute_consensus(&self, results: Vec<SourceResult>) -> Result<DnsValidation, ValidationError> {
        let valid_results: Vec<_> = results.iter()
            .filter(|r| r.reachable && r.valid)
            .collect();

        match valid_results.len() {
            3 => {
                // All agree?
                if self.all_keys_match(&valid_results) {
                    Ok(DnsValidation::AllSourcesAgree { ... })
                } else {
                    Err(ValidationError::SourcesDisagree)  // Possible attack
                }
            }
            2 => {
                // 2-of-3 agreement
                if self.two_keys_match(&valid_results) {
                    Ok(DnsValidation::PartialAgreement { ... })
                } else {
                    Err(ValidationError::SourcesDisagree)
                }
            }
            1 => Ok(DnsValidation::SingleSource { ... }),  // Degraded
            0 => Err(ValidationError::NoSourcesReachable),
        }
    }
}
```

### 3.2 License JWT Parser

```rust
/// Parse 4-part hybrid JWT: header.payload.classical_sig.pqc_sig
pub struct HybridJwt {
    pub header: JwtHeader,
    pub payload: LicensePayload,
    pub classical_signature: Vec<u8>,
    pub pqc_signature: Vec<u8>,
}

impl HybridJwt {
    pub fn parse(token: &str) -> Result<Self, JwtError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 4 {
            return Err(JwtError::InvalidFormat(
                "Expected 4 parts for hybrid JWT".into()
            ));
        }

        Ok(Self {
            header: serde_json::from_slice(&base64url_decode(parts[0])?)?,
            payload: serde_json::from_slice(&base64url_decode(parts[1])?)?,
            classical_signature: base64url_decode(parts[2])?,
            pqc_signature: base64url_decode(parts[3])?,
        })
    }

    pub fn verify(&self, steward_keys: &StewardKeys) -> Result<bool, JwtError> {
        let signing_input = format!("{}.{}",
            base64url_encode(&self.header),
            base64url_encode(&self.payload)
        );

        // 1. Verify classical signature
        let classical_valid = steward_keys.classical.verify(
            signing_input.as_bytes(),
            &self.classical_signature
        )?;

        if !classical_valid {
            return Ok(false);
        }

        // 2. Verify PQC signature (over signing_input + classical_sig)
        let bound_input = [signing_input.as_bytes(), &self.classical_signature].concat();
        steward_keys.pqc.verify(&bound_input, &self.pqc_signature)
    }
}
```

### 3.3 License Status Engine

```rust
pub struct LicenseEngine {
    dns_validator: DnsValidator,
    https_client: HttpsClient,
    cache: ProtectedStore,
    hw_signer: Box<dyn HardwareSigner>,
}

impl LicenseEngine {
    pub async fn get_license_status(
        &self,
        request: LicenseStatusRequest,
    ) -> LicenseStatusResponse {
        // 1. Binary integrity check
        if !self.verify_integrity() {
            return self.error_response(LicenseStatus::ErrorBinaryTampered);
        }

        // 2. Multi-source validation
        let validation = match self.validate_sources().await {
            Ok(v) => v,
            Err(ValidationError::SourcesDisagree) => {
                return self.error_response(LicenseStatus::ErrorSourcesDisagree);
            }
            Err(_) => {
                // Try cache
                if let Some(cached) = self.cache.get_license().await {
                    if cached.is_fresh() {
                        return self.from_cache(cached);
                    }
                }
                return self.error_response(LicenseStatus::ErrorVerificationFailed);
            }
        };

        // 3. License verification
        let license = self.verify_license(&validation).await;

        // 4. Apply hardware tier restriction
        let status = self.apply_hardware_restriction(license);

        // 5. Generate attestation
        let attestation = self.generate_attestation(&request).await;

        // 6. Build response
        self.build_response(status, attestation, validation)
    }

    fn apply_hardware_restriction(&self, license: LicenseDetails) -> LicenseStatus {
        // SOFTWARE_ONLY caps at UNLICENSED_COMMUNITY
        if self.hw_signer.hardware_type() == HardwareType::SoftwareOnly {
            return LicenseStatus::UnlicensedCommunity;
        }
        license.status
    }
}
```

### Deliverables
- `ciris-verify-core` with full verification logic
- Mock servers for testing
- Integration tests with real DNS/HTTPS
- Cache persistence tests

---

## Phase 4: Interface Layer

### 4.1 gRPC Service (`tonic`)

```rust
#[tonic::async_trait]
impl CirisVerify for CirisVerifyService {
    async fn get_license_status(
        &self,
        request: Request<LicenseStatusRequest>,
    ) -> Result<Response<LicenseStatusResponse>, Status> {
        let req = request.into_inner();

        // Validate nonce
        if req.challenge_nonce.len() < 32 {
            return Err(Status::invalid_argument("Nonce must be >= 32 bytes"));
        }

        let response = self.engine.get_license_status(req).await;
        Ok(Response::new(response))
    }

    async fn check_capability(
        &self,
        request: Request<CapabilityCheckRequest>,
    ) -> Result<Response<CapabilityCheckResponse>, Status> {
        // ...
    }
}
```

### 4.2 C FFI

```rust
// ciris-verify-ffi/src/lib.rs

#[repr(C)]
pub struct CirisVerifyHandle {
    runtime: tokio::runtime::Runtime,
    engine: Arc<LicenseEngine>,
}

#[no_mangle]
pub extern "C" fn ciris_verify_init() -> *mut CirisVerifyHandle {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let engine = runtime.block_on(LicenseEngine::new());

    Box::into_raw(Box::new(CirisVerifyHandle {
        runtime,
        engine: Arc::new(engine),
    }))
}

#[no_mangle]
pub extern "C" fn ciris_verify_get_status(
    handle: *mut CirisVerifyHandle,
    request_data: *const u8,
    request_len: usize,
    response_data: *mut *mut u8,
    response_len: *mut usize,
) -> i32 {
    let handle = unsafe { &*handle };
    let request_bytes = unsafe { std::slice::from_raw_parts(request_data, request_len) };

    let request: LicenseStatusRequest = match prost::Message::decode(request_bytes) {
        Ok(r) => r,
        Err(_) => return -1,
    };

    let response = handle.runtime.block_on(
        handle.engine.get_license_status(request)
    );

    let response_bytes = response.encode_to_vec();

    unsafe {
        *response_len = response_bytes.len();
        *response_data = libc::malloc(response_bytes.len()) as *mut u8;
        std::ptr::copy_nonoverlapping(
            response_bytes.as_ptr(),
            *response_data,
            response_bytes.len()
        );
    }

    0
}

#[no_mangle]
pub extern "C" fn ciris_verify_free(data: *mut u8) {
    unsafe { libc::free(data as *mut libc::c_void) };
}

#[no_mangle]
pub extern "C" fn ciris_verify_destroy(handle: *mut CirisVerifyHandle) {
    unsafe { drop(Box::from_raw(handle)) };
}
```

### 4.3 Generated Bindings

Use `cbindgen` to generate C header:

```toml
# cbindgen.toml
language = "C"
header = "/* CIRISVerify FFI - Auto-generated */"
include_guard = "CIRIS_VERIFY_H"
```

### Deliverables
- gRPC server binary
- C FFI library + header
- Python bindings (PyO3)
- Swift/Kotlin wrapper stubs

---

## Phase 5: Security Hardening

### 5.1 Binary Integrity

```rust
/// Self-verification at startup
pub fn verify_binary_integrity() -> bool {
    // 1. Check embedded hash
    let expected_hash = include_bytes!("../build/hash.bin");
    let actual_hash = compute_self_hash();

    if !constant_time_eq(expected_hash, &actual_hash) {
        return false;
    }

    // 2. Check for debugger
    #[cfg(target_os = "linux")]
    if is_ptrace_attached() {
        return false;
    }

    // 3. Check for hooks (platform-specific)
    if detect_common_hooks() {
        return false;
    }

    true
}
```

### 5.2 Anti-Tamper (Platform-Specific)

- **Android**: Root detection, Frida detection, Magisk detection
- **iOS**: Jailbreak detection, Cydia detection, code signing validation
- **Desktop**: Debugger detection, VM detection (optional)

### 5.3 Constant-Time Operations

```rust
/// Constant-time byte comparison
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
```

### Deliverables
- Security test suite
- Fuzzing harness (cargo-fuzz)
- Third-party audit preparation docs

---

## Phase 6: Platform Builds

### 6.1 Build Matrix

| Target | Toolchain | Notes |
|--------|-----------|-------|
| `aarch64-linux-android` | NDK r26 | Primary Android |
| `armv7-linux-androideabi` | NDK r26 | Legacy Android |
| `x86_64-linux-android` | NDK r26 | Emulator |
| `aarch64-apple-ios` | Xcode 15 | iPhone |
| `aarch64-apple-ios-sim` | Xcode 15 | Simulator |
| `x86_64-unknown-linux-gnu` | GCC 11 | Server |
| `aarch64-unknown-linux-gnu` | GCC 11 | ARM Server |
| `x86_64-pc-windows-msvc` | VS 2022 | Windows |
| `x86_64-apple-darwin` | Xcode 15 | macOS Intel |
| `aarch64-apple-darwin` | Xcode 15 | macOS ARM |

### 6.2 CI/CD Pipeline

```yaml
# .github/workflows/build.yml
jobs:
  build-matrix:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
          - os: ubuntu-latest
            target: aarch64-linux-android
            ndk: r26
          - os: macos-latest
            target: aarch64-apple-ios
          - os: windows-latest
            target: x86_64-pc-windows-msvc

    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      - run: cargo build --release --target ${{ matrix.target }}
```

### 6.3 Binary Signing

All release binaries signed with both Ed25519 and ML-DSA-65:

```bash
# Sign checksums with both algorithms
sha256sum binaries/* > SHA256SUMS
sign-ed25519 SHA256SUMS > SHA256SUMS.sig.ed25519
sign-ml-dsa-65 SHA256SUMS > SHA256SUMS.sig.mldsa65
```

### Deliverables
- Reproducible builds
- Signed release artifacts
- Platform-specific packages (AAR, XCFramework, deb/rpm)

---

## Phase 7: Integration & Testing

### 7.1 CIRISAgent Integration
- [ ] Python FFI wrapper
- [ ] Integration with WiseBus
- [ ] Mandatory disclosure enforcement
- [ ] End-to-end tests

### 7.2 Load Testing
- [ ] 10,000 concurrent verifications
- [ ] Cache performance under load
- [ ] Network failure scenarios

### 7.3 Security Audit Prep
- [ ] Threat model document
- [ ] Code review checklist
- [ ] Audit scope definition

### Deliverables
- Integration test suite
- Performance benchmarks
- Audit-ready documentation

---

## Milestone Summary

| Phase | Key Deliverable |
|-------|-----------------|
| 0: Foundation | Compiling workspace, CI |
| 1: Cryptography | Hybrid signature system |
| 2: Hardware | Platform signers + attestation |
| 3: Verification | License engine |
| 4: Interface | gRPC + FFI |
| 5: Security | Hardened binary |
| 6: Builds | Cross-platform releases |
| 7: Integration | CIRISAgent integration |
| **Final** | Production v2.0.0 |

---

## Upstream Contribution Strategy

### Candidates for Veilid Upstream

1. **`HardwareSigner` trait** - Useful for any Veilid app needing hardware-bound keys
2. **ECDSA P-256 support** - Enables mobile hardware integration
3. **TPM integration** - Server-side hardware binding

### Contribution Process

1. Develop in `ciris-keyring` fork
2. Abstract away CIRIS-specific parts
3. Open Veilid issue discussing addition
4. Submit MR with minimal changes
5. Maintain compatibility layer if divergence required

### Tracking Upstream

```toml
# Cargo.toml
[dependencies]
# Track specific Veilid commit for reproducibility
keyring-manager = { git = "https://gitlab.com/veilid/veilid", rev = "abc123" }
```

Periodic sync with upstream:
1. Rebase fork on latest Veilid main
2. Resolve conflicts
3. Run full test suite
4. Document any new divergences

---

## Open Decisions

| Decision | Options | Recommendation | Status |
|----------|---------|----------------|--------|
| PQC library | aws-lc-rs vs ml-dsa vs pqcrypto | aws-lc-rs (audit path) | **Pending benchmark** |
| Async runtime | tokio vs async-std | tokio (Veilid compat) | **Decided** |
| Protobuf | prost vs protobuf-rs | prost (Veilid compat) | **Decided** |
| Android JNI | jni vs ndk-glue | jni (keyring-manager compat) | **Decided** |

---

**Document Owner**: CIRIS Engineering
**Last Updated**: 2026-01-26
**Review Cycle**: During active development
