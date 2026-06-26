//! Platform-specific hardware signer implementations.
//!
//! Each platform has its own hardware security module:
//! - Android: Keystore/StrongBox
//! - iOS/macOS: Secure Enclave (Apple Silicon / T2)
//! - Linux/Windows: TPM 2.0
//! - Fallback: Software-only (restricted tier)

#[cfg(target_os = "android")]
pub mod android;

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub mod ios;

// TPM backend — gated to glibc-linux + windows; tss-esapi link-binds the tss2 C
// libs, which won't cross-link on musl (the keyring builds without TPM there,
// CIRISVerify#127).
#[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "windows"))]
pub mod tpm;

// Windows-native TPM via Platform Crypto Provider (experimental)
#[cfg(all(feature = "tpm-windows", target_os = "windows"))]
pub mod tpm_windows;

// Runtime-loaded TPM signer (CIRISVerify#141) — the ECDSA P-256 `HardwareSigner`
// over the `dlopen` plugin, so the native TPM signing path works on every target
// that can load the plugin (incl. the wheel + musl), with no tss-esapi link.
#[cfg(feature = "tpm-plugin")]
pub mod tpm_plugin_signer;

mod factory;

pub use factory::{
    create_hardware_signer, create_software_signer, detect_hardware_type, MaxTier,
    PlatformCapabilities,
};

#[cfg(target_os = "android")]
pub use android::{AndroidKeystoreSigner, HardwareWrappedEd25519Signer};

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub use ios::{SecureEnclaveSigner, SecureEnclaveWrappedEd25519Signer};

#[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "windows"))]
pub use tpm::TpmSigner;

#[cfg(feature = "tpm-plugin")]
pub use tpm_plugin_signer::PluginTpmSigner;

// Windows-native TPM signer (experimental)
#[cfg(all(feature = "tpm-windows", target_os = "windows"))]
pub use tpm_windows::WindowsTpmSigner;
