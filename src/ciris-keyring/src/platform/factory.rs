//! Platform detection and signer factory.
//!
//! Automatically detects the best available hardware security module
//! and creates an appropriate signer. Falls back gracefully to software
//! signing when hardware is unavailable.

use crate::error::KeyringError;
use crate::signer::HardwareSigner;
use crate::software::SoftwareSigner;
use crate::types::HardwareType;

/// Platform capabilities detected at runtime.
#[derive(Debug, Clone)]
pub struct PlatformCapabilities {
    /// Best available hardware type
    pub hardware_type: HardwareType,
    /// Whether hardware-backed keys are available
    pub has_hardware: bool,
    /// Whether user authentication is supported
    pub supports_user_auth: bool,
    /// Whether attestation is available
    pub supports_attestation: bool,
    /// Maximum supported tier based on hardware
    pub max_tier: MaxTier,
}

/// Maximum license tier supported by this platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxTier {
    /// Full professional tier (discrete TPM, StrongBox)
    Professional,
    /// Standard tier (fTPM, Keystore, Secure Enclave)
    Standard,
    /// Community tier only (software)
    CommunityOnly,
}

impl PlatformCapabilities {
    /// Check if this platform can support professional tier.
    #[must_use]
    pub fn supports_professional(&self) -> bool {
        self.max_tier == MaxTier::Professional
    }

    /// Check if this platform can support licensed operations.
    #[must_use]
    pub fn supports_licensed(&self) -> bool {
        matches!(self.max_tier, MaxTier::Professional | MaxTier::Standard)
    }
}

/// Detect hardware capabilities of the current platform.
pub fn detect_hardware_type() -> PlatformCapabilities {
    #[cfg(target_os = "android")]
    {
        detect_android_capabilities()
    }

    #[cfg(target_os = "ios")]
    {
        detect_ios_capabilities()
    }

    #[cfg(target_os = "linux")]
    {
        detect_linux_capabilities()
    }

    #[cfg(target_os = "windows")]
    {
        detect_windows_capabilities()
    }

    #[cfg(target_os = "macos")]
    {
        detect_macos_capabilities()
    }

    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "windows",
        target_os = "macos"
    )))]
    {
        PlatformCapabilities {
            hardware_type: HardwareType::SoftwareOnly,
            has_hardware: false,
            supports_user_auth: false,
            supports_attestation: false,
            max_tier: MaxTier::CommunityOnly,
        }
    }
}

#[cfg(target_os = "android")]
fn detect_android_capabilities() -> PlatformCapabilities {
    // Would use JNI to check PackageManager.hasSystemFeature
    // For now, conservative defaults
    PlatformCapabilities {
        hardware_type: HardwareType::AndroidKeystore,
        has_hardware: true,
        supports_user_auth: true,
        supports_attestation: true,
        max_tier: MaxTier::Standard, // StrongBox would be Professional
    }
}

#[cfg(target_os = "ios")]
fn detect_ios_capabilities() -> PlatformCapabilities {
    // Simulator builds have target_abi = "sim" (Rust 1.78+)
    #[cfg(target_abi = "sim")]
    {
        return PlatformCapabilities {
            hardware_type: HardwareType::SoftwareOnly,
            has_hardware: false,
            supports_user_auth: false,
            supports_attestation: false,
            max_tier: MaxTier::CommunityOnly,
        };
    }

    #[cfg(not(target_abi = "sim"))]
    {
        PlatformCapabilities {
            hardware_type: HardwareType::IosSecureEnclave,
            has_hardware: true,
            supports_user_auth: true,
            supports_attestation: true,
            max_tier: MaxTier::Standard,
        }
    }
}

#[cfg(target_os = "linux")]
fn detect_linux_capabilities() -> PlatformCapabilities {
    use std::path::Path;

    let has_tpm = Path::new("/dev/tpm0").exists() || Path::new("/dev/tpmrm0").exists();

    if has_tpm {
        PlatformCapabilities {
            hardware_type: HardwareType::TpmFirmware, // Assume fTPM, detect discrete at runtime
            has_hardware: true,
            supports_user_auth: false, // TPM doesn't have biometrics
            supports_attestation: true,
            max_tier: MaxTier::Standard, // Discrete TPM would be Professional
        }
    } else {
        PlatformCapabilities {
            hardware_type: HardwareType::SoftwareOnly,
            has_hardware: false,
            supports_user_auth: false,
            supports_attestation: false,
            max_tier: MaxTier::CommunityOnly,
        }
    }
}

#[cfg(target_os = "windows")]
fn detect_windows_capabilities() -> PlatformCapabilities {
    // Probe TBS (user-mode, no admin needed). If TBS is missing or no TPM
    // is present, fall back to software-only with the same posture as Linux
    // without a TPM device node.
    let has_tpm = crate::platform::tpm::probe_tbs_device_info().is_some();
    if has_tpm {
        PlatformCapabilities {
            hardware_type: HardwareType::TpmFirmware,
            has_hardware: true,
            supports_user_auth: true, // Windows Hello
            supports_attestation: true,
            max_tier: MaxTier::Standard,
        }
    } else {
        PlatformCapabilities {
            hardware_type: HardwareType::SoftwareOnly,
            has_hardware: false,
            supports_user_auth: false,
            supports_attestation: false,
            max_tier: MaxTier::CommunityOnly,
        }
    }
}

#[cfg(target_os = "macos")]
fn detect_macos_capabilities() -> PlatformCapabilities {
    // macOS with Apple Silicon has Secure Enclave
    // T2 Macs also have it
    PlatformCapabilities {
        hardware_type: HardwareType::MacOsSecureEnclave,
        has_hardware: true,
        supports_user_auth: true, // Touch ID / Face ID
        supports_attestation: true,
        max_tier: MaxTier::Standard,
    }
}

/// Create the best available hardware signer for this platform.
///
/// # Arguments
///
/// * `alias` - Key alias/tag to use
/// * `require_hardware` - If true, fails if no hardware is available
///
/// # Errors
///
/// Returns error if hardware is required but unavailable.
pub fn create_hardware_signer(
    alias: &str,
    require_hardware: bool,
) -> Result<Box<dyn HardwareSigner>, KeyringError> {
    let capabilities = detect_hardware_type();

    tracing::info!(
        hardware_type = ?capabilities.hardware_type,
        has_hardware = capabilities.has_hardware,
        require_hardware = require_hardware,
        "create_hardware_signer: starting"
    );

    if require_hardware && !capabilities.has_hardware {
        return Err(KeyringError::HardwareNotAvailable {
            reason: "Hardware security module required but not available".into(),
        });
    }

    #[cfg(target_os = "android")]
    {
        use super::AndroidKeystoreSigner;
        let prefer_strongbox = true; // Always prefer if available
        return Ok(Box::new(AndroidKeystoreSigner::new(
            alias,
            prefer_strongbox,
        )?));
    }

    #[cfg(target_os = "ios")]
    {
        // Simulator: no Secure Enclave, fall through to software signer
        #[cfg(not(target_abi = "sim"))]
        {
            use super::SecureEnclaveSigner;
            return Ok(Box::new(SecureEnclaveSigner::new(alias)?));
        }
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        if capabilities.has_hardware {
            use super::TpmSigner;
            match TpmSigner::new(alias, None) {
                Ok(signer) => {
                    tracing::info!("Using TPM signer for hardware security");
                    return Ok(Box::new(signer));
                },
                Err(e) => {
                    tracing::warn!(
                        "TPM initialization failed ({}), falling back to software signer",
                        e
                    );
                    // Fall through to software signer below
                },
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if capabilities.has_hardware {
            use super::SecureEnclaveSigner;
            match SecureEnclaveSigner::new(alias) {
                Ok(signer) => {
                    tracing::info!("Using Secure Enclave signer on macOS");
                    return Ok(Box::new(signer));
                },
                Err(e) => {
                    tracing::warn!(
                        "macOS: Secure Enclave not available ({}), falling back to software signer",
                        e
                    );
                    // Fall through to software signer below
                },
            }
        }
    }

    // Fallback to software signer
    if require_hardware {
        return Err(KeyringError::HardwareNotAvailable {
            reason: "No hardware security module available on this platform".into(),
        });
    }

    let key_dir = default_key_dir();
    tracing::info!(
        key_dir = ?key_dir,
        "Using software signer (no hardware security module)"
    );
    Ok(Box::new(SoftwareSigner::new(alias, key_dir)?))
}

/// Create a software-only signer (for testing or community tier).
///
/// # Arguments
///
/// * `alias` - Key alias to use
///
/// # Errors
///
/// Returns error if key generation fails.
pub fn create_software_signer(alias: &str) -> Result<Box<dyn HardwareSigner>, KeyringError> {
    let key_dir = default_key_dir();
    Ok(Box::new(SoftwareSigner::new(alias, key_dir)?))
}

/// Get the default key storage directory.
///
/// Tries in order:
/// 1. `$CIRIS_DATA_DIR` environment variable
/// 2. Platform-specific data directory (XDG, AppSupport, LocalAppData)
/// 3. Current directory as fallback
fn default_key_dir() -> std::path::PathBuf {
    // Check environment variable first
    if let Ok(dir) = std::env::var("CIRIS_DATA_DIR") {
        return std::path::PathBuf::from(dir);
    }

    // Platform-specific defaults
    #[cfg(target_os = "linux")]
    {
        if let Some(dir) = dirs::data_local_dir() {
            return dir.join("ciris-verify");
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(dir) = dirs::data_local_dir() {
            return dir.join("ai.ciris.verify");
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(dir) = dirs::data_local_dir() {
            return dir.join("ciris-verify");
        }
    }

    // Fallback to current directory
    std::path::PathBuf::from(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_capabilities() {
        let caps = detect_hardware_type();
        // Just verify it doesn't panic
        assert!(matches!(
            caps.hardware_type,
            HardwareType::SoftwareOnly
                | HardwareType::AndroidKeystore
                | HardwareType::AndroidStrongbox
                | HardwareType::IosSecureEnclave
                | HardwareType::MacOsSecureEnclave
                | HardwareType::TpmFirmware
                | HardwareType::TpmDiscrete
        ));
    }

    #[test]
    fn test_software_signer_creation() {
        let signer = create_software_signer("test_factory_key");
        assert!(signer.is_ok());
        // Cleanup: delete persisted key file
        let key_path = default_key_dir().join("test_factory_key.p256.key");
        let _ = std::fs::remove_file(&key_path);
    }

    #[test]
    fn test_max_tier_checks() {
        let caps = PlatformCapabilities {
            hardware_type: HardwareType::TpmDiscrete,
            has_hardware: true,
            supports_user_auth: false,
            supports_attestation: true,
            max_tier: MaxTier::Professional,
        };

        assert!(caps.supports_professional());
        assert!(caps.supports_licensed());

        let community_caps = PlatformCapabilities {
            hardware_type: HardwareType::SoftwareOnly,
            has_hardware: false,
            supports_user_auth: false,
            supports_attestation: false,
            max_tier: MaxTier::CommunityOnly,
        };

        assert!(!community_caps.supports_professional());
        assert!(!community_caps.supports_licensed());
    }
}
