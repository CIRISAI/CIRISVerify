# Hardware Attestation — Consumer Guide

What evidence CIRISVerify exposes about a signer's hardware backing, and
how a consumer (CIRISPersist, CIRISAgent, anyone applying a policy)
drives the "truly hardware-attested" distinction itself.

## Principle — verify exposes evidence, the consumer decides

Per [`MISSION.md`](../MISSION.md) §1.4, every CIRIS federation primitive
authenticates *origin*; none confers *trust*. The same rule applies to
hardware attestation: **CIRISVerify ships the full attestation
evidence; the consumer applies its own policy** ("HUMANITY_ACCORD
requires HSM FIPS 140-3 L3+", "CIRIS Medical requires Apple Secure
Enclave OR YubiKey OR HSM", etc.). There is no single boolean
`is_truly_hardware_attested` flag in verify — a flag would be verify
making the policy decision, which it must not.

This is the same shape as [`ProvenanceChain`](./THREAT_MODEL.md#av-8)
verification: verify *exposes* the chain, the consumer pins which
trust root is trusted.

## The two methods to ask about, on the trait

```rust
pub trait HardwareSigner: Send + Sync {
    /// Broad hardware-class taxonomy — the answer to "what kind of
    /// hardware backs this key?"
    fn hardware_type(&self) -> HardwareType;

    /// Full attestation evidence object — the answer to "prove it."
    async fn attestation_with_nonce(
        &self,
        nonce: Option<&[u8]>,
    ) -> Result<PlatformAttestation, KeyringError>;
    // (`attestation()` is a no-nonce convenience that wraps this.)
}
```

A consumer that wants to make a "truly hardware-attested" decision
combines them: `hardware_type()` declares the *class*,
`attestation_with_nonce(challenge)` produces the *evidence chain* that
proves the class claim. Policy = `(hardware_type matches my requirement)
AND (attestation chain validates per my requirement)`.

## The hardware-class taxonomy

[`HardwareType`](../src/ciris-keyring/src/types.rs) — twelve variants,
ordered roughly by security tier:

| Variant | What |
|---|---|
| `AndroidKeystore` | TEE-backed Android Keystore |
| `AndroidStrongbox` | Dedicated secure element (higher than Keystore) |
| `IosSecureEnclave` | iOS / iPadOS Secure Enclave |
| `MacOsSecureEnclave` | macOS Secure Enclave (T2 / Apple Silicon) |
| `TpmDiscrete` | Discrete TPM 2.0 chip |
| `TpmFirmware` | fTPM (CPU firmware / TEE) |
| `IntelSgx` | Intel SGX enclave |
| `AwsCloudHsm` | AWS CloudHSM (FIPS 140-2 L3) |
| `AzureHsm` | Azure Dedicated / Managed HSM |
| `GcpCloudHsm` | Google Cloud HSM |
| `YubiHsm` | Yubico YubiHSM 2 |
| `SoftwareOnly` | No hardware — capped at UNLICENSED_COMMUNITY |

`HardwareType::supports_professional_license()` returns `true` for
every variant *except* `SoftwareOnly` — the one place verify *does*
draw a structural line, because a software-only key cannot bind to
hardware by definition. Beyond that single floor, any "tier" or
"granularity" is the consumer's policy.

## The evidence enum — what each variant carries

[`PlatformAttestation`](../src/ciris-keyring/src/types.rs) — one
variant per hardware family, carrying everything a downstream verifier
needs to independently validate the chain.

### `PlatformAttestation::Android(AndroidAttestation)`

```rust
pub struct AndroidAttestation {
    /// Android Key Attestation cert chain (DER-encoded), leaf to
    /// Google root. Parse and verify against Google's hardware
    /// attestation root keys.
    pub key_attestation_chain: Vec<Vec<u8>>,

    /// Google Play Integrity API token (JWT). Carries the
    /// DeviceIntegrity / AppIntegrity / AccountDetails verdict —
    /// verify the JWT signature against Google's public keys, then
    /// inspect the verdict fields.
    pub play_integrity_token: Option<String>,

    /// StrongBox-backed (dedicated secure element vs. TEE Keystore).
    pub strongbox_backed: bool,
}
```

Consumer policy example: *"Android signer accepted iff
`key_attestation_chain` verifies to Google's root AND
`play_integrity_token` decodes to `MEETS_DEVICE_INTEGRITY` AND
`strongbox_backed == true`."*

### `PlatformAttestation::Ios(IosAttestation)`

```rust
pub struct IosAttestation {
    pub secure_enclave: bool,
    /// Apple App Attest assertion (CBOR). Verify against Apple's
    /// App Attest root cert; binds app identity + Secure Enclave key.
    pub app_attest: Option<Vec<u8>>,
    /// DeviceCheck token (Apple device-level fraud signal).
    pub device_check_token: Option<Vec<u8>>,
}
```

### `PlatformAttestation::Tpm(TpmAttestation)`

```rust
pub struct TpmAttestation {
    pub tpm_version: String,
    pub manufacturer: String,
    pub discrete: bool,  // discrete chip vs. firmware TPM
    /// TPM quote — TPMS_ATTEST + signature + PCR selection +
    /// qualifying_data (the challenge nonce) + PCR values. A verifier
    /// reconstructs the quote, checks the signature against
    /// `ak_public_key`, and inspects the PCR digests.
    pub quote: Option<TpmQuoteData>,
    /// EK certificate (X.509 DER) — chain to the TPM manufacturer's
    /// CA to prove genuine hardware.
    pub ek_cert: Option<Vec<u8>>,
    pub ak_public_key: Option<Vec<u8>>,
}
```

Consumer policy example: *"TPM signer accepted iff `discrete == true`
AND `ek_cert` chains to a recognized manufacturer CA AND the quote's
PCR digests match a known-good measurement set."*

### `PlatformAttestation::Software(SoftwareAttestation)`

The honest variant — no hardware evidence to verify. A consumer that
requires hardware MUST reject any `Software` variant.

## How to consume it

### From Rust

```rust
use ciris_keyring::{HardwareSigner, PlatformAttestation};

let attestation = signer.attestation_with_nonce(Some(&challenge)).await?;
let class = signer.hardware_type();

match attestation {
    PlatformAttestation::Android(a) => {
        // a.key_attestation_chain, a.play_integrity_token, a.strongbox_backed
        // Apply your policy.
    }
    PlatformAttestation::Ios(i) => { /* … */ }
    PlatformAttestation::Tpm(t) => { /* … */ }
    PlatformAttestation::Software(_) => {
        // Reject if policy requires hardware.
    }
}
```

### From any other language (FFI)

```c
int32_t ciris_verify_export_attestation(
    CirisVerifyHandle *handle,
    const uint8_t *challenge,
    size_t challenge_len,
    uint8_t **proof_data,
    size_t *proof_len);
```

Returns an [`AttestationProof`](../src/ciris-verify-core/src/types.rs)
serialized as JSON. The proof embeds `.platform_attestation` — the
exact `PlatformAttestation` enum above, JSON-tagged by variant — plus
the hybrid signature over the challenge, the merkle root and entry
count from the transparency log at proof-time, the binary version, and
the hardware-type string.

## "Truly hardware-attested" — driven by the consumer

There is **no single CIRISVerify-side flag** for this — by design.
Consumers compose the distinction from the surface above:

1. **Class check** — `hardware_type` is one of the variants the policy
   accepts.
2. **Evidence presence** — the matching `PlatformAttestation` variant
   carries the required fields (e.g. `play_integrity_token: Some(_)`,
   or `ek_cert: Some(_)`).
3. **Chain verification** — the evidence validates against the
   appropriate external root (Google for Android, Apple for iOS,
   manufacturer CA for TPM).
4. **Nonce binding** — the attestation was generated with the consumer's
   challenge (see `attestation_with_nonce`). Replay defense.

Steps 1–2 are pure structural matching on what verify exposes. Step 4
is supplied by the caller. **Step 3 — chain validation — is local** in
`ciris_verify_core::device_attestation`, each walk ending at an anchor
resolved from the constrained trust-anchor store
(`trust_anchor_store::baked::default_store()`, resolved on purpose +
environment together):

| Class | Local validator | Binds |
|-------|-----------------|-------|
| Android Key Attestation | `verify_android_key_attestation{,_with_store}` (+ `_with_challenge_policy`) | attested key = expected key; `attestationChallenge` (or `GenerationOnly`, reported as `challenge_checked`) |
| Apple App Attest | `verify_apple_app_attest{,_with_store}` | credential key id; nonce; `rpIdHash`; `signCount == 0` |
| TPM 2.0 EK | `verify_tpm_ek_certificate{,_with_store}` | certified key = pinned EK (device identity only — no PCR-quote verifier, no nonce) |
| YubiKey PIV | `accord_custody_attestation::verify_yubikey_piv_attestation` | attested key = holder Ed25519; FIPS + touch policy |

A store miss returns `Ok(None)` — no hardware evidence, never a refusal.
No validator checks revocation. The `play_integrity` / `tpm_attest` /
`app_attest` modules are request/response types for the registry's
attestation endpoints; their verdicts are an online third party's and are
advisory, not an admission gate.

## Refs

- [`MISSION.md`](../MISSION.md) §1.4 — auth ≠ trust ≠ ethics
- [`docs/THREAT_MODEL.md`](./THREAT_MODEL.md) §3.2 — AV-8 / cross-primitive identity
- [`src/ciris-keyring/src/types.rs`](../src/ciris-keyring/src/types.rs) — `PlatformAttestation`, `HardwareType`
- [`src/ciris-keyring/src/signer.rs`](../src/ciris-keyring/src/signer.rs) — `HardwareSigner`
- [`src/ciris-verify-core/src/types.rs`](../src/ciris-verify-core/src/types.rs) — `AttestationProof`
- [`src/ciris-verify-core/src/device_attestation.rs`](../src/ciris-verify-core/src/device_attestation.rs) — local chain validators
- [`src/ciris-verify-core/src/play_integrity.rs`](../src/ciris-verify-core/src/play_integrity.rs), [`tpm_attest.rs`](../src/ciris-verify-core/src/tpm_attest.rs), [`app_attest.rs`](../src/ciris-verify-core/src/app_attest.rs) — registry-side verify request/response types
