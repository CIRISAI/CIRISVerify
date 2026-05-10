# CIRISVerify v2.0.0 — Federation Crypto Authority

**Closes:** [#7](https://github.com/CIRISAI/CIRISVerify/issues/7) (federation crypto primitives prerequisite for CIRISPersist#19).

v2.0.0 promotes `ciris-crypto` to the federation's crypto authority. Every CIRIS primitive that needs symmetric encryption, key derivation, MAC, or random bytes routes through this crate — no more reaching into RustCrypto crates directly. Single audit point, federation-wide RNG/KDF policy, single set of error variants for callers to match on.

## What's new — `ciris-crypto`

Four new feature-gated modules. Each is opt-in (default-features unchanged) so consumers pull in only what they need.

### `aes-gcm` feature → `ciris_crypto::aes_gcm`

```rust
pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
```

AES-256-GCM only. 32-byte key, 12-byte nonce, 16-byte appended tag. Tested against NIST GCM test vectors. **No nonce reuse detection at this layer** — caller-managed (random or counter); reuse is a key-compromise event.

### `kdf` feature → `ciris_crypto::kdf`

```rust
pub fn pbkdf2_hmac_sha256(master: &[u8], salt: &[u8], iters: u32, out_len: usize) -> Result<Vec<u8>, CryptoError>;
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, CryptoError>;
```

Two KDFs: PBKDF2-HMAC-SHA256 for password-shaped derivation (CIRISPersist#19 uses `iters = 100_000`), HKDF-SHA256 for hardware-master derivation. HKDF tested against RFC 5869 vectors. PBKDF2 zero-iterations and HKDF over-length-output rejected with `CryptoError::KdfParameter`.

### `hmac` feature → `ciris_crypto::hmac`

```rust
pub fn sha256(key: &[u8], msg: &[u8]) -> [u8; 32];

pub mod util {
    pub fn ct_eq(a: &[u8], b: &[u8]) -> bool;
}
```

HMAC-SHA256 for `EncryptedSecretRecord.edge_hmac` integrity check. Tested against RFC 4231 vectors. `util::ct_eq` is the spec'd export name; backed by the existing crate-level `constant_time_eq` (subtle::ConstantTimeEq).

### `random` feature → `ciris_crypto::random`

```rust
pub fn fill(buf: &mut [u8]) -> Result<(), CryptoError>;
pub fn bytes(n: usize) -> Result<Vec<u8>, CryptoError>;
```

OsRng facade. Linux/Android: `getrandom(2)`. macOS/iOS: `SecRandomCopyBytes`. Windows: `BCryptGenRandom`. Centralized so future entropy hardening (FIPS, hardware mixing) lands in one place.

## Migration

### Existing callers

**No breaking changes.** All v1.x exports unchanged:

- `Ed25519Signer`/`Verifier`, `P256Signer`/`Verifier`, `MlDsa65Signer`/`Verifier`
- `HybridSigner`/`Verifier`, `ClassicalSigner`/`Verifier`, `PqcSigner`/`Verifier`
- `secp256k1` wallet signing, `constant_time_eq`
- All existing feature flags (`default = ["ecdsa-p256", "ed25519", "secp256k1"]`, `pqc-ml-dsa`, `pqc-aws-lc`)

`verify_tree()`, `TreeVerifyResult`, the entire CIRISVerify Python API: unchanged.

### Downstream consumers (CIRISPersist#19, CIRISEdge#3, etc.)

Add the features you need to your `Cargo.toml`:

```toml
ciris-crypto = { git = "https://github.com/CIRISAI/CIRISVerify", tag = "v2.0.0", version = "2", features = [
    "ed25519", "pqc-ml-dsa",
    "aes-gcm", "kdf", "hmac", "random",   # NEW — pick what you need
] }
```

Match the new `CryptoError` variants where you handle errors:

```rust
match err {
    CryptoError::AesGcm { operation: "decrypt", .. } => /* tampered ciphertext */,
    CryptoError::KdfParameter(reason) => /* invalid params */,
    // existing variants unchanged
    other => /* … */,
}
```

## Why "2.0"?

Additive surface, no breaking API changes — semver-pure, this could've been 1.15. The major bump signals the **federation crypto authority** framing: from v2.0 forward, downstream consumers MUST go through `ciris-crypto` for symmetric/KDF/MAC/RNG ops. Reaching into `aes-gcm`/`hkdf`/`pbkdf2`/`hmac`/`getrandom` directly is a federation-policy violation that future audits will flag.

## What's NOT in v2.0

- **`HardwareSigner::derive_symmetric_key`** — deferred. Mobile keystores (Android, iOS) don't expose native HKDF; a hardware-master derivation method has to be honest about per-platform availability. Lands in a focused minor when CIRISPersist#19 actually exercises hardware-backed symmetric paths.
- **X25519 KEX, streaming AEAD** — investigated and dropped from scope after auditing CIRISEdge (delegates transport encryption to Reticulum/TLS) and CIRISPersist (per-secret encryption is one-shot AES-GCM, not streaming).
- **L278 cognitive-complexity refactor + L1970 anyio timeout-context refactor** in `client.py` (deferred from CIRISVerify#14 to v2.0). Pushed to a follow-up minor — kept out of v2.0 to keep the release tightly scoped to the crypto authority work.

## Pipeline receipts

(filled in after pipeline lands)

## Cross-links

- [`ciris-crypto v1.10.0` issue spec](https://github.com/CIRISAI/CIRISVerify/issues/7) — original spec; closed by this release at v2.0.0.
- CIRISPersist#19 — federated SecretsService; primary consumer of v2.0's surface.
- CIRISEdge#3 — federated secrets at edge; secondary consumer.
- CIRISAgent#741 (merged 2026-05-09) — verify_tree() adopted; sequencing prereq for v2.0 satisfied.
