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
mod signer;
mod types;

#[cfg(feature = "software")]
mod software;

/// Platform-specific hardware signer implementations.
pub mod platform;

/// OS keyring integration for cross-platform key storage.
#[cfg(feature = "keyring-storage")]
pub mod keyring_storage;

pub use error::KeyringError;
pub use signer::{HardwareSigner, KeyGenConfig};
pub use types::{
    AndroidAttestation, ClassicalAlgorithm, HardwareType, IosAttestation, PlatformAttestation,
    SoftwareAttestation, TpmAttestation,
};

pub use platform::{
    create_hardware_signer, create_software_signer, detect_hardware_type, MaxTier,
    PlatformCapabilities,
};

#[cfg(feature = "keyring-storage")]
pub use keyring_storage::{create_keyring_signer, KeyringStorageSigner};

#[cfg(feature = "software")]
pub use software::{
    Ed25519SoftwareSigner, MutableEd25519Signer, MutableSoftwareSigner, SoftwareSigner,
};

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
