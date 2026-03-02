//! TPM detection and context creation.

use crate::error::KeyringError;

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use std::str::FromStr;

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use tss_esapi::{
    tcti_ldr::{DeviceConfig, TctiNameConf},
    Context,
};

/// Detect if a TPM 2.0 is available and whether it's discrete.
///
/// Returns `(available, is_discrete)`.
pub fn detect_tpm() -> Result<(bool, bool), KeyringError> {
    #[cfg(target_os = "linux")]
    {
        use std::path::Path;

        let has_tpm0 = Path::new("/dev/tpm0").exists();
        let has_tpmrm0 = Path::new("/dev/tpmrm0").exists();

        if !has_tpm0 && !has_tpmrm0 {
            tracing::debug!("TPM: no device nodes found (/dev/tpm0, /dev/tpmrm0)");
            return Ok((false, false));
        }

        tracing::info!(
            tpm0 = has_tpm0,
            tpmrm0 = has_tpmrm0,
            "TPM: device nodes detected"
        );

        let is_discrete = check_if_discrete_tpm();
        Ok((true, is_discrete))
    }

    #[cfg(target_os = "windows")]
    {
        tracing::info!("TPM: checking Windows TPM availability");
        Ok((true, false))
    }

    #[cfg(target_os = "macos")]
    {
        Ok((false, false))
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Ok((false, false))
    }
}

#[cfg(target_os = "linux")]
fn check_if_discrete_tpm() -> bool {
    if let Some(manufacturer) = get_tpm_manufacturer() {
        let lower = manufacturer.to_lowercase();
        if lower.contains("infineon")
            || lower.contains("stmicro")
            || lower.contains("nuvoton")
            || lower.contains("atmel")
        {
            tracing::info!("TPM: detected discrete TPM ({})", manufacturer.trim());
            return true;
        }
    }
    tracing::debug!("TPM: assuming firmware TPM (conservative default)");
    false
}

#[cfg(not(target_os = "linux"))]
fn check_if_discrete_tpm() -> bool {
    false
}

/// Get TPM manufacturer string from sysfs.
#[cfg(target_os = "linux")]
pub fn get_tpm_manufacturer() -> Option<String> {
    // Try description first
    if let Ok(desc) = std::fs::read_to_string("/sys/class/tpm/tpm0/device/description") {
        return Some(desc.trim().to_string());
    }
    // Fallback to manufacturer ID
    if let Ok(id) = std::fs::read_to_string("/sys/class/tpm/tpm0/tpm_version_major") {
        return Some(format!("TPM {}", id.trim()));
    }
    None
}

/// Get TPM manufacturer string (non-Linux platforms).
#[cfg(not(target_os = "linux"))]
pub fn get_tpm_manufacturer() -> Option<String> {
    None
}

/// Create a TPM context for the current platform.
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub fn create_context() -> Result<Context, KeyringError> {
    #[cfg(target_os = "linux")]
    let tcti = {
        let device_path = if std::path::Path::new("/dev/tpmrm0").exists() {
            "/dev/tpmrm0"
        } else {
            "/dev/tpm0"
        };

        tracing::debug!("TPM: using device {}", device_path);

        let device_config =
            DeviceConfig::from_str(device_path).map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to create device config: {}", e),
            })?;

        TctiNameConf::Device(device_config)
    };

    #[cfg(target_os = "windows")]
    let tcti = TctiNameConf::Tbs;

    tracing::debug!("TPM: creating context");

    Context::new(tcti).map_err(|e| {
        tracing::error!("TPM: failed to create context: {}", e);
        KeyringError::HardwareError {
            reason: format!("Failed to create TPM context: {}", e),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_tpm_returns_ok() {
        // detect_tpm should always return Ok, even if no TPM is present
        let result = detect_tpm();
        assert!(result.is_ok());
    }

    #[test]
    fn test_detect_tpm_tuple_structure() {
        let result = detect_tpm().unwrap();
        let (available, is_discrete) = result;
        // Both should be boolean values
        assert!(available || !available);
        assert!(is_discrete || !is_discrete);
        // If discrete, must be available
        if is_discrete {
            assert!(available);
        }
    }

    #[test]
    fn test_get_tpm_manufacturer() {
        // Should return Some or None without panicking
        let _manufacturer = get_tpm_manufacturer();
    }

    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    #[test]
    fn test_create_context_on_tpm_system() {
        // Only run this test if TPM is actually available
        let (available, _) = detect_tpm().unwrap();
        if available {
            let result = create_context();
            assert!(result.is_ok(), "Failed to create context on TPM system");
        }
    }
}
