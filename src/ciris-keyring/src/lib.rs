//! # ciris-keyring
//!
//! Cross-platform hardware keyring with signing support for CIRISVerify.
//!
//! This crate extends the Veilid keyring-manager pattern to support:
//! - Hardware-bound cryptographic signing (not just storage)
//! - Platform attestation for remote verification
//! - ECDSA P-256 (mobile HSM compatible) and Ed25519 algorithms
//!
//! ## Platform Support
//!
//! | Platform | Backend | Signing Algorithm | Attestation |
//! |----------|---------|-------------------|-------------|
//! | Android | Keystore/StrongBox | ECDSA P-256 | Key attestation + Play Integrity |
//! | iOS | Secure Enclave | ECDSA P-256 | App Attest + DeviceCheck |
//! | Linux/Windows | TPM 2.0 | ECDSA P-256 | TPM Quote |
//! | macOS | Keychain | ECDSA P-256 | (limited) |
//! | Fallback | Software | ECDSA P-256 / Ed25519 | None (tier-limited) |
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ciris_keyring::{HardwareSigner, KeyGenConfig, get_platform_signer};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Get platform-appropriate signer
//!     let signer = get_platform_signer().await?;
//!
//!     // Generate key if needed
//!     signer.generate_key(&KeyGenConfig::default()).await?;
//!
//!     // Sign data
//!     let signature = signer.sign(b"data to sign").await?;
//!
//!     // Get attestation for remote verification
//!     let attestation = signer.attestation().await?;
//!
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]
#![allow(clippy::pedantic)] // Too strict for production code
#![allow(clippy::doc_markdown)] // Allow product names without backticks
#![allow(clippy::missing_errors_doc)] // Error documentation not required
#![allow(clippy::missing_panics_doc)] // Panic documentation not required
#![allow(clippy::module_name_repetitions)] // Allow Type in module::Type
#![allow(clippy::must_use_candidate)] // Not all functions need must_use

mod error;
// Reentrancy-safe block_on bridge (CIRISVerify#204). Its only real callers are
// the android hardware paths (the sole place `tokio` is a dependency), so it is
// android-gated — plus `test` so its unit tests still compile+run under the host
// CI job (where tokio is a dev-dependency).
#[cfg(any(target_os = "android", test))]
mod rt;
mod signer;
mod types;

/// Generic, interface-keyed external hardware-security-token abstraction
/// (CIRISVerify#62). Probe → CEG §9.4 `hardware_class` resolver (real, tested)
/// + an honestly-stubbed PC/SC token-signer entry point.
pub mod hw_token;

#[cfg(feature = "software")]
mod software;

/// Post-quantum signer trait + ML-DSA-65 software implementation.
///
/// Parallel to `HardwareSigner` for classical algorithms. Gated behind the
/// `pqc-ml-dsa` feature so the default build doesn't pull in the ml-dsa crate.
#[cfg(feature = "pqc-ml-dsa")]
pub mod pqc;

/// Single-call steward seed loader (v2.1.0+, CIRISVerify#20).
///
/// Cross-crate convenience for federation consumers: load both classical
/// (Ed25519) and optional PQC (ML-DSA-65) local signing identities from
/// filesystem seeds and get back `Arc<dyn HardwareSigner>` +
/// `Option<Arc<dyn PqcSigner>>`. Eliminates the duplicated seed-loading
/// glue that CIRISEdge, CIRISPersist, and CIRISLensCore each wrote
/// separately before this lands.
///
/// **v2.4.0 rename:** previously named `steward_seed` /
/// `load_steward_seed` / `StewardSeedConfig`. "Steward" in CIRIS means a
/// bootstrap-trusted root identity (`bootstrap_stewards.json`); this
/// loader actually loads a deployment's *local* signing identity.
/// v2.4.0 corrects the vocabulary — hard rename, no shim. Downstream
/// imports update from `ciris_keyring::{load_steward_seed,
/// StewardSeedConfig}` to `ciris_keyring::{load_local_seed,
/// LocalSeedConfig}`.
#[cfg(all(feature = "software", feature = "pqc-ml-dsa"))]
pub mod local_seed;

/// Generic secure blob storage abstraction.
pub mod storage;

/// Keyring-backed RNS transport-identity storage (CIRISVerify#68).
pub mod transport_identity;

/// TPM/SE-sealed Ed25519 federation signing key (CIRISVerify#70).
pub mod sealed_ed25519;

/// User-identity hardware custody — the responsible owner's federation key,
/// multi-factor (YubiKey/PKCS#11 + TPM-SE signing, WebAuthn/passkey presence)
/// and multi-key-per-identity for redundancy (CIRISVerify#80).
pub mod user_identity;

/// YubiKey / PKCS#11 hardware-token signer — real `C_Sign` over a physical
/// token behind the `pkcs11` feature (CIRISVerify#80).
pub mod pkcs11;

/// TPM/SE-sealed ML-DSA-65 federation signing key — the PQC half of
/// hardware-backed federation custody (CIRISVerify#70 PQC analog).
#[cfg(feature = "pqc-ml-dsa")]
pub mod sealed_mldsa65;

/// Self content-encryption as a **custody capability** (CIRISVerify#183):
/// hand out enc pubkeys + perform the KEX respond from inside the seal, by
/// alias, with no private key material crossing any API boundary. Opens over
/// the same sealed Ed25519 seed the federation signer uses.
#[cfg(feature = "pqc-ml-dsa")]
pub mod self_enc_keys;

/// Portable signature-wrapped ML-DSA-65 custody — the ML-DSA seed on a USB key,
/// AEAD-wrapped under a YubiKey-Ed25519-signature-derived key (both keys + PIN +
/// touch required; YubiKey stays signing-only). Accord/high-secure portable mode.
#[cfg(feature = "pqc-ml-dsa")]
pub mod usb_wrapped_mldsa65;

/// Runtime-loaded TPM backend — `dlopen`s `libciris_tpm_plugin.so` over a small
/// C ABI (CIRISVerify#130) so the keyring uses TPM without link-binding
/// `tss-esapi`. Builds on every target (incl. musl); TPM is opportunistic where
/// the plugin .so + libtss2 exist at runtime, else the software fallback.
#[cfg(feature = "tpm-plugin")]
pub mod tpm_plugin;

/// Platform-specific hardware signer implementations.
pub mod platform;

/// OS keyring integration for cross-platform key storage.
#[cfg(feature = "keyring-storage")]
pub mod keyring_storage;

pub use error::KeyringError;

/// Run the SP 800-90B startup health check if nothing has yet
/// (CIRISVerify#207 item 6).
///
/// `ciris_crypto::random::fill` only READS the latch, and an uninitialized
/// latch reads as healthy. The only production caller of
/// `run_startup_health_check` is `ciris-verify-ffi` — so a direct
/// `ciris-keyring` consumer (the documented standalone API, or a downstream
/// service that links the keyring without the FFI) could reach a mint having
/// never run the check, and the routing added for #207 would buy nothing.
///
/// `run_startup_health_check` latches through a `OnceLock`, so calling it here
/// is idempotent and costs one atomic load after the first mint.
///
/// # Errors
/// [`KeyringError::KeyGenerationFailed`] if the startup test fails — refusing
/// to mint is the fail-secure answer, and the whole point of #74.
pub(crate) fn ensure_rng_health_checked() -> Result<(), KeyringError> {
    // An ALREADY-FAILED latch is decisive — do not re-run.
    //
    // `run_startup_health_check` is `get_or_init` + `store_state`, so calling
    // it when the latch is already `Failed` re-runs the test and OVERWRITES
    // the verdict. That would let a mint proceed off a fresh pass after the
    // process had already latched a failure, which is exactly the latch's
    // reason for existing: the verdict is sticky by design.
    if ciris_crypto::rng_health::is_rng_failed() {
        return Err(KeyringError::KeyGenerationFailed {
            reason: "RNG health latch is FAILED; refusing to mint key material".to_string(),
        });
    }
    match ciris_crypto::rng_health::run_startup_health_check() {
        ciris_crypto::rng_health::RngHealth::Healthy => Ok(()),
        ciris_crypto::rng_health::RngHealth::Failed { test, detail } => {
            Err(KeyringError::KeyGenerationFailed {
                reason: format!(
                    "SP 800-90B startup health check FAILED ({test}: {detail}); \
                     refusing to mint key material"
                ),
            })
        },
    }
}

/// Mint a P-256 signing key from **latch-checked** randomness
/// (CIRISVerify#207 item 6 / #74).
///
/// `SigningKey::random(&mut OsRng)` draws straight from the OS RNG, bypassing
/// the SP 800-90B startup health latch that #74 added so *"no weak key is ever
/// produced"*. That invariant therefore held for `ciris-crypto`-constructed
/// keys and **not** for keyring-minted ones — which are the federation
/// identity keys, i.e. the ones that matter.
///
/// The bytes themselves go through [`ciris_crypto::random::fill`], rather than
/// merely probing the latch and then drawing unchecked, so the key material is
/// literally what the checked path produced.
///
/// # Errors
/// [`KeyringError::KeyGenerationFailed`] if the RNG health latch has tripped,
/// or (with probability under 2⁻³²) if the draw is not a valid P-256 scalar.
/// Refusing is the fail-secure answer in both cases: a retry loop around a
/// possibly-broken RNG is not an improvement.
pub fn mint_p256_signing_key() -> Result<p256::ecdsa::SigningKey, KeyringError> {
    ensure_rng_health_checked()?;
    let mut bytes = [0u8; 32];
    ciris_crypto::random::fill(&mut bytes).map_err(|e| KeyringError::KeyGenerationFailed {
        reason: format!("RNG health check failed; refusing to mint a P-256 key: {e}"),
    })?;
    let key = p256::ecdsa::SigningKey::from_slice(&bytes).map_err(|e| {
        KeyringError::KeyGenerationFailed {
            reason: format!("random draw was not a valid P-256 scalar: {e}"),
        }
    })?;
    Ok(key)
}

pub use hw_token::{
    get_token_signer, hardware_class_table, resolve_hardware_class, HardwareClassRule, ProbedToken,
    TokenInterface, GENERIC_EXTERNAL_TOKEN_CLASS,
};
pub use signer::{HardwareSigner, KeyGenConfig};
pub use types::{
    AndroidAttestation, ClassicalAlgorithm, ExternalSecureElementAttestation, HardwareType,
    IosAttestation, KeyringScope, PlatformAttestation, SoftwareAttestation, StorageDescriptor,
    TpmAttestation,
};

pub use platform::{
    create_hardware_signer, create_software_signer, detect_hardware_type, MaxTier,
    PlatformCapabilities,
};

pub use storage::{create_platform_storage, SecureBlobStorage, StorageBackend};

pub use transport_identity::{
    BlobTransportKeystore, TransportIdentityKeystore, TRANSPORT_IDENTITY_LEN,
};

pub use sealed_ed25519::{get_platform_ed25519_signer, SealedEd25519Signer};

#[cfg(feature = "keyring-storage")]
pub use keyring_storage::{create_keyring_signer, KeyringStorageSigner};

#[cfg(feature = "software")]
pub use software::{
    Ed25519SoftwareSigner, MutableEd25519Signer, MutableSoftwareSigner, SoftwareSigner,
};

#[cfg(feature = "pqc-ml-dsa")]
pub use pqc::{get_platform_pqc_signer, MlDsa65SoftwareSigner, PqcAlgorithm, PqcSigner};

#[cfg(feature = "pqc-ml-dsa")]
pub use sealed_mldsa65::{get_platform_sealed_mldsa65_signer, SealedMlDsa65Signer};

#[cfg(all(feature = "software", feature = "pqc-ml-dsa"))]
pub use local_seed::{load_local_seed, LocalSeedConfig};

/// Get the best available hardware signer for the current platform.
///
/// Platform selection priority:
/// 1. Android StrongBox (if available)
/// 2. Android Keystore
/// 3. iOS Secure Enclave
/// 4. TPM 2.0
/// 5. Software fallback (WARNING: tier-limited)
///
/// # Arguments
///
/// * `alias` - Key alias/identifier to use
///
/// # Errors
///
/// Returns error if no signer can be initialized.
pub fn get_platform_signer(alias: &str) -> Result<Box<dyn HardwareSigner>, KeyringError> {
    let caps = detect_hardware_type();

    tracing::info!(
        hardware_type = ?caps.hardware_type,
        has_hardware = caps.has_hardware,
        max_tier = ?caps.max_tier,
        "Platform signer: detected capabilities"
    );

    if caps.has_hardware {
        tracing::info!(
            "Platform signer: attempting hardware signer (alias={})",
            alias
        );
        create_hardware_signer(alias, false)
    } else {
        tracing::warn!(
            "Platform signer: no hardware available, using software signer. \
             Deployment limited to UNLICENSED_COMMUNITY tier."
        );
        create_software_signer(alias)
    }
}

/// Check if hardware-backed signing is available on this platform.
pub fn is_hardware_available() -> bool {
    detect_hardware_type().has_hardware
}

#[cfg(test)]
mod rng_latch {
    /// **CIRISVerify#207 item 6 / #74.** The keyring mints the federation
    /// identity keys, and its mints drew raw `OsRng` — so "no weak key is
    /// ever produced" held for `ciris-crypto` keys and not for these.
    ///
    /// #74 proved that invariant with a per-primitive fail-secure test. This
    /// is the one the keyring was missing.
    #[test]
    fn minting_refuses_on_a_tripped_rng_latch() {
        use ciris_crypto::rng_health::{__force_health_for_test, RngHealth};

        // `ciris-crypto`'s thread-local override is `#[cfg(test)]`, which is
        // NOT active when it is compiled as this crate's dependency — so
        // `__force_health_for_test` writes the PROCESS-GLOBAL latch.
        //
        // CI runs `cargo nextest`, which gives every test its own PROCESS, so
        // the global is not shared and there is no race to serialize. An
        // earlier revision added a module-local mutex for this; it protected
        // nothing under nextest and implied a guarantee it did not provide, so
        // it is gone. The `Restore` guard stays: under a plain `cargo test`
        // this thread must not leave the latch tripped.
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                __force_health_for_test(RngHealth::Healthy);
            }
        }
        let _restore = Restore;

        __force_health_for_test(RngHealth::Failed {
            test: ciris_crypto::rng_health::TEST_REPETITION_COUNT,
            detail: "forced for the keyring fail-secure test".to_string(),
        });
        assert!(
            matches!(
                super::mint_p256_signing_key(),
                Err(crate::KeyringError::KeyGenerationFailed { .. })
            ),
            "a keyring mint MUST refuse when the RNG health latch has tripped"
        );

        __force_health_for_test(RngHealth::Healthy);
        assert!(super::mint_p256_signing_key().is_ok());
    }
}
