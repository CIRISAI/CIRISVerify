//! Platform-specific hardware signer implementations.
//!
//! Each platform has its own hardware security module:
//! - Android: Keystore/StrongBox
//! - iOS: Secure Enclave
//! - Desktop/Server: TPM 2.0
//! - Fallback: Software-only (restricted tier)

#[cfg(target_os = "android")]
pub mod android;

#[cfg(target_os = "ios")]
pub mod ios;

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
pub mod tpm;

// Windows-native TPM via Platform Crypto Provider (experimental)
#[cfg(all(feature = "tpm-windows", target_os = "windows"))]
pub mod tpm_windows;

mod factory;

pub use factory::{
    create_hardware_signer, create_software_signer, detect_hardware_type, MaxTier,
    PlatformCapabilities,
};

#[cfg(target_os = "android")]
pub use android::AndroidKeystoreSigner;

#[cfg(target_os = "ios")]
pub use ios::SecureEnclaveSigner;

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
pub use tpm::TpmSigner;

// Windows-native TPM signer (experimental)
#[cfg(all(feature = "tpm-windows", target_os = "windows"))]
pub use tpm_windows::WindowsTpmSigner;
