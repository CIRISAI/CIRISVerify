//! Platform-specific hardware signer implementations.
//!
//! Each platform has its own hardware security module:
//! - Android: Keystore/StrongBox
//! - iOS/macOS: Secure Enclave (Apple Silicon / T2)
//! - Linux/Windows: TPM 2.0
//! - Fallback: Software-only (restricted tier)
//!
//! The hardware backends and the signer factory keep key envelopes on disk, so
//! they need the `fs` feature. Without it only [`detect_hardware_type`] and the
//! capability types remain (the slim WASM profile, which reports
//! `SoftwareOnly`).

#[cfg(all(feature = "fs", target_os = "android"))]
pub mod android;

#[cfg(all(feature = "fs", any(target_os = "ios", target_os = "macos")))]
pub mod ios;

// Windows-native TPM via Platform Crypto Provider (experimental)
#[cfg(all(feature = "tpm-windows", target_os = "windows"))]
pub mod tpm_windows;

// Runtime-loaded TPM signer (CIRISVerify#141) — the ECDSA P-256 `HardwareSigner`
// over the `dlopen` plugin, so the native TPM signing path works on every target
// that can load the plugin (incl. the wheel + musl), with no tss-esapi link.
#[cfg(feature = "tpm-plugin")]
pub mod tpm_plugin_signer;

mod factory;

#[cfg(feature = "fs")]
pub use factory::{create_hardware_signer, create_software_signer};
pub use factory::{detect_hardware_type, MaxTier, PlatformCapabilities};

#[cfg(all(feature = "fs", target_os = "android"))]
pub use android::{AndroidKeystoreSigner, HardwareWrappedEd25519Signer};

#[cfg(all(feature = "fs", any(target_os = "ios", target_os = "macos")))]
pub use ios::{SecureEnclaveSigner, SecureEnclaveWrappedEd25519Signer};

#[cfg(feature = "tpm-plugin")]
pub use tpm_plugin_signer::PluginTpmSigner;

// Windows-native TPM signer (experimental)
#[cfg(all(feature = "tpm-windows", target_os = "windows"))]
pub use tpm_windows::WindowsTpmSigner;
