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
        let info = probe_tbs_device_info();
        match info {
            Some(version) => {
                tracing::info!("TPM: TBS reports TPM {}", version);
                Ok((true, false))
            },
            None => {
                tracing::info!("TPM: TBS reports no TPM available");
                Ok((false, false))
            },
        }
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

/// Probe Windows TBS (TPM Base Services) for TPM presence and version.
///
/// TBS is a user-mode API exposed by `tbs.dll` and is reachable without
/// administrator privileges on Windows 10/11. Returns `Some("2.0")`,
/// `Some("1.2")`, or `None` if no TPM is present (or TBS itself is missing,
/// e.g. on stripped-down SKUs).
///
/// We resolve the entry point dynamically with `LoadLibraryA`/`GetProcAddress`
/// so that the binary still loads on hosts where `tbs.dll` is absent.
#[cfg(target_os = "windows")]
pub fn probe_tbs_device_info() -> Option<&'static str> {
    use std::ffi::CString;

    // TBS_DEVICE_INFO struct layout per <tbs.h>. `structVersion` is set by the
    // caller; everything else is filled by TBS.
    #[repr(C)]
    #[derive(Default)]
    struct TbsDeviceInfo {
        struct_version: u32,
        tpm_version: u32,    // 1 = TPM 1.2, 2 = TPM 2.0
        tpm_interface_type: u32,
        tpm_impl_revision: u32,
    }

    type TbsiGetDeviceInfo =
        unsafe extern "system" fn(size: u32, info: *mut TbsDeviceInfo) -> u32;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryA(name: *const i8) -> *mut std::ffi::c_void;
        fn GetProcAddress(
            module: *mut std::ffi::c_void,
            name: *const i8,
        ) -> *mut std::ffi::c_void;
        fn FreeLibrary(module: *mut std::ffi::c_void) -> i32;
    }

    let dll_name = CString::new("tbs.dll").ok()?;
    let proc_name = CString::new("Tbsi_GetDeviceInfo").ok()?;

    unsafe {
        let module = LoadLibraryA(dll_name.as_ptr());
        if module.is_null() {
            tracing::debug!("TPM: tbs.dll not loadable");
            return None;
        }

        let proc_addr = GetProcAddress(module, proc_name.as_ptr());
        if proc_addr.is_null() {
            FreeLibrary(module);
            tracing::debug!("TPM: Tbsi_GetDeviceInfo not exported by tbs.dll");
            return None;
        }

        let get_info: TbsiGetDeviceInfo = std::mem::transmute(proc_addr);
        let mut info = TbsDeviceInfo {
            struct_version: 1,
            ..Default::default()
        };
        let result = get_info(
            std::mem::size_of::<TbsDeviceInfo>() as u32,
            &mut info,
        );
        FreeLibrary(module);

        // TBS_SUCCESS == 0. Anything else (including TBS_E_TPM_NOT_FOUND
        // 0x8028400F) means we should treat the TPM as unavailable.
        if result != 0 {
            tracing::debug!("TPM: Tbsi_GetDeviceInfo returned 0x{:08x}", result);
            return None;
        }

        match info.tpm_version {
            2 => Some("2.0"),
            1 => Some("1.2"),
            other => {
                tracing::debug!("TPM: TBS reported unknown tpm_version={}", other);
                None
            },
        }
    }
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
        // Verify the tuple structure returned correctly
        // A discrete TPM must also be available
        if is_discrete {
            assert!(available, "discrete TPM should also be marked as available");
        }
        // available can be true or false regardless of is_discrete
        // (fTPM is available but not discrete)
        let _ = (available, is_discrete); // Use values to satisfy compiler
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

    /// On Windows, TBS is reachable without admin. We can't assert that a TPM
    /// is present (CI Windows runners often lack one), but the probe must
    /// return without panicking and either Some("2.0"|"1.2") or None — never
    /// some unexpected value.
    #[cfg(target_os = "windows")]
    #[test]
    fn test_probe_tbs_device_info_returns_known_value() {
        match probe_tbs_device_info() {
            None => {} // No TPM, or stripped-down SKU — acceptable.
            Some(version) => {
                assert!(
                    version == "2.0" || version == "1.2",
                    "TBS reported unexpected TPM version: {}",
                    version
                );
            }
        }
    }

    /// detect_tpm and probe_tbs_device_info must agree on Windows. If TBS
    /// reports a TPM, detect_tpm must mark it available; if TBS doesn't,
    /// detect_tpm must mark it unavailable. A drift between these two would
    /// give us a false-positive PlatformCapabilities and silently mis-tier
    /// the agent.
    #[cfg(target_os = "windows")]
    #[test]
    fn test_detect_tpm_agrees_with_tbs_probe() {
        let from_tbs = probe_tbs_device_info().is_some();
        let (from_detect, _) = detect_tpm().unwrap();
        assert_eq!(
            from_tbs, from_detect,
            "detect_tpm and probe_tbs_device_info disagree: \
             tbs={}, detect={}",
            from_tbs, from_detect
        );
    }
}
