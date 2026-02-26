//! Platform-specific security checks.
//!
//! Detects compromised execution environments:
//! - Rooted Android devices
//! - Jailbroken iOS devices
//! - Emulators and virtual machines
//!
//! ## Design Philosophy
//!
//! These checks are defense-in-depth. A compromised device doesn't
//! automatically mean malicious intent, but it does mean we can't
//! trust hardware-based security guarantees.
//!
//! When a compromised device is detected:
//! - License verification still works
//! - But attestation reflects compromised status
//! - Highest autonomy tiers may be restricted

/// Check if the device is compromised (rooted/jailbroken).
///
/// Returns `true` if compromise indicators are found.
pub fn is_device_compromised() -> bool {
    #[cfg(target_os = "android")]
    {
        return is_android_rooted();
    }

    #[cfg(target_os = "ios")]
    {
        return is_ios_jailbroken();
    }

    // Desktop platforms are assumed "compromised" in the sense that
    // the user has full control. This is expected and not a problem.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    {
        false
    }

    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "windows",
        target_os = "macos"
    )))]
    {
        false
    }
}

/// Check if running in an emulator or virtual machine.
///
/// Returns `true` if emulator/VM indicators are found.
/// This is used for attestation reporting, not for blocking.
pub fn is_emulator() -> bool {
    #[cfg(target_os = "android")]
    {
        return is_android_emulator();
    }

    #[cfg(target_os = "ios")]
    {
        return is_ios_simulator();
    }

    // On desktop, detect VMs for attestation reporting
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    {
        is_virtual_machine()
    }

    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "windows",
        target_os = "macos"
    )))]
    {
        false
    }
}

/// Check if running in a SUSPICIOUS emulator that should block execution.
///
/// This distinguishes between:
/// - Mobile emulators (Android emulator, iOS simulator) → BLOCK (suspicious)
/// - Desktop VMs (KVM, VMware, cloud instances) → ALLOW (legitimate use)
///
/// Desktop VMs are legitimate deployment targets (cloud servers, dev environments).
/// Mobile emulators are suspicious because real mobile apps run on physical devices.
pub fn is_suspicious_emulator() -> bool {
    #[cfg(target_os = "android")]
    {
        return is_android_emulator();
    }

    #[cfg(target_os = "ios")]
    {
        return is_ios_simulator();
    }

    // Desktop VMs are NOT suspicious - they're legitimate deployment targets.
    // Cloud servers, dev environments, CI/CD all run in VMs.
    // The user already has full control on desktop anyway.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    {
        false
    }

    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "windows",
        target_os = "macos"
    )))]
    {
        false
    }
}

// =============================================================================
// Android Root Detection
// =============================================================================

/// Check if Android device is rooted.
#[cfg(target_os = "android")]
fn is_android_rooted() -> bool {
    // Method 1: Check for common root binaries
    let root_binaries = [
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/local/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
    ];

    for path in root_binaries {
        if std::path::Path::new(path).exists() {
            return true;
        }
    }

    // Method 2: Check for Magisk
    let magisk_paths = [
        "/data/adb/magisk",
        "/sbin/.magisk",
        "/cache/.disable_magisk",
        "/dev/.magisk.unblock",
    ];

    for path in magisk_paths {
        if std::path::Path::new(path).exists() {
            return true;
        }
    }

    // Method 3: Check for root management apps
    let root_apps = [
        "/data/data/com.topjohnwu.magisk",
        "/data/data/eu.chainfire.supersu",
        "/data/data/com.noshufou.android.su",
        "/data/data/com.koushikdutta.superuser",
        "/data/data/com.zachspong.temprootremovejb",
        "/data/data/com.ramdroid.appquarantine",
    ];

    for path in root_apps {
        if std::path::Path::new(path).exists() {
            return true;
        }
    }

    // Method 4: Check build tags
    if let Ok(tags) = std::env::var("ro.build.tags") {
        if tags.contains("test-keys") {
            return true;
        }
    }

    // Method 5: Check if we can execute su
    if std::process::Command::new("su")
        .arg("-c")
        .arg("id")
        .output()
        .is_ok()
    {
        return true;
    }

    false
}

/// Check if running on Android emulator.
#[cfg(target_os = "android")]
fn is_android_emulator() -> bool {
    use android_system_properties::AndroidSystemProperties;

    let props = AndroidSystemProperties::new();

    // Method 1: Direct emulator indicator (most reliable)
    // ro.build.characteristics=emulator is set on all official Android emulators
    if let Some(chars) = props.get("ro.build.characteristics") {
        if chars.contains("emulator") {
            return true;
        }
    }

    // Method 2: QEMU indicator (boot property)
    // ro.boot.qemu=1 is set when running under QEMU
    if let Some(qemu) = props.get("ro.boot.qemu") {
        if qemu == "1" {
            return true;
        }
    }
    if let Some(qemu) = props.get("ro.kernel.qemu") {
        if qemu == "1" {
            return true;
        }
    }

    // Method 3: Check hardware property
    if let Some(hw) = props.get("ro.hardware") {
        let hw_lower = hw.to_lowercase();
        if hw_lower.contains("goldfish")
            || hw_lower.contains("ranchu")
            || hw_lower.contains("vbox86")
        {
            return true;
        }
    }

    // Method 4: Check product device for emulator patterns
    if let Some(device) = props.get("ro.product.device") {
        let device_lower = device.to_lowercase();
        if device_lower.contains("generic")
            || device_lower.contains("sdk_gphone")
            || device_lower.contains("emu64")
            || device_lower.contains("emulator")
            || device_lower.contains("vbox86")
        {
            return true;
        }
    }

    // Method 5: Check product model
    if let Some(model) = props.get("ro.product.model") {
        let model_lower = model.to_lowercase();
        if model_lower.contains("sdk")
            || model_lower.contains("emulator")
            || model_lower.contains("android sdk")
        {
            return true;
        }
    }

    // Method 6: Check build fingerprint
    if let Some(fp) = props.get("ro.build.fingerprint") {
        let fp_lower = fp.to_lowercase();
        if fp_lower.contains("sdk_gphone")
            || fp_lower.contains("generic")
            || fp_lower.contains("emulator")
        {
            return true;
        }
    }

    // Method 7: Check for emulator-specific files (fallback)
    let emulator_files = [
        "/dev/socket/qemud",
        "/dev/qemu_pipe",
        "/dev/goldfish_pipe",
        "/system/bin/qemu-props",
    ];

    for path in emulator_files {
        if std::path::Path::new(path).exists() {
            return true;
        }
    }

    false
}

// =============================================================================
// iOS Jailbreak Detection
// =============================================================================

/// Check if iOS device is jailbroken.
#[cfg(target_os = "ios")]
fn is_ios_jailbroken() -> bool {
    // Method 1: Check for jailbreak files
    let jailbreak_paths = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/var/cache/apt",
        "/var/lib/apt",
        "/var/lib/cydia",
        "/var/tmp/cydia.log",
        "/bin/bash",
        "/bin/sh",
        "/usr/sbin/sshd",
        "/usr/bin/sshd",
        "/usr/libexec/ssh-keysign",
        "/etc/apt",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/var/mobile/Library/SBSettings/Themes",
        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        "/private/var/stash",
    ];

    for path in jailbreak_paths {
        if std::path::Path::new(path).exists() {
            return true;
        }
    }

    // Method 2: Check if we can write outside sandbox
    let test_path = "/private/jailbreak_test";
    if std::fs::write(test_path, "test").is_ok() {
        let _ = std::fs::remove_file(test_path);
        return true;
    }

    // Method 3: Check for symbolic links (jailbreaks often use them)
    let symlink_checks = ["/Applications", "/Library/Ringtones", "/Library/Wallpaper"];

    for path in symlink_checks {
        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            if metadata.file_type().is_symlink() {
                return true;
            }
        }
    }

    // Method 4: Check URL schemes
    // Would need UIApplication access via objc crate

    false
}

/// Check if running on iOS Simulator.
#[cfg(target_os = "ios")]
fn is_ios_simulator() -> bool {
    // Check TARGET_OS_SIMULATOR via compile-time
    cfg!(target_os = "ios") && cfg!(target_arch = "x86_64")
}

// =============================================================================
// Desktop VM Detection
// =============================================================================

/// Check if running in a virtual machine.
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
fn is_virtual_machine() -> bool {
    #[cfg(target_os = "linux")]
    {
        return is_linux_vm();
    }

    #[cfg(target_os = "windows")]
    {
        return is_windows_vm();
    }

    #[cfg(target_os = "macos")]
    {
        return is_macos_vm();
    }

    #[allow(unreachable_code)]
    false
}

/// Check for VM on Linux.
#[cfg(target_os = "linux")]
fn is_linux_vm() -> bool {
    use std::io::Read;

    // Method 1: Check DMI information
    let dmi_paths = [
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
    ];

    let vm_indicators = [
        "VMware",
        "VirtualBox",
        "QEMU",
        "KVM",
        "Xen",
        "Microsoft Corporation", // Hyper-V
        "Parallels",
        "innotek GmbH",
    ];

    for path in dmi_paths {
        if let Ok(mut file) = std::fs::File::open(path) {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_ok() {
                for indicator in vm_indicators {
                    if contents.contains(indicator) {
                        return true;
                    }
                }
            }
        }
    }

    // Method 2: Check CPU info for hypervisor flag
    if let Ok(mut file) = std::fs::File::open("/proc/cpuinfo") {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() && contents.contains("hypervisor") {
            return true;
        }
    }

    false
}

/// Check for VM on Windows.
#[cfg(target_os = "windows")]
fn is_windows_vm() -> bool {
    // Check for VM-specific registry keys or WMI queries
    // This would require windows-rs bindings

    // Basic check: look for VM tools processes
    // Would need psapi or similar to enumerate processes

    false
}

/// Check for VM on macOS.
#[cfg(target_os = "macos")]
fn is_macos_vm() -> bool {
    // Check sysctl for VM indicators
    if let Ok(output) = std::process::Command::new("sysctl")
        .arg("-n")
        .arg("machdep.cpu.features")
        .output()
    {
        let features = String::from_utf8_lossy(&output.stdout);
        if features.contains("VMM") {
            return true;
        }
    }

    // Check for VM-specific hardware model
    if let Ok(output) = std::process::Command::new("sysctl")
        .arg("-n")
        .arg("hw.model")
        .output()
    {
        let model = String::from_utf8_lossy(&output.stdout);
        let vm_models = ["VMware", "VirtualBox", "Parallels"];
        for vm in vm_models {
            if model.contains(vm) {
                return true;
            }
        }
    }

    false
}

// =============================================================================
// Fallback implementations for non-mobile platforms
// =============================================================================

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
fn is_android_rooted() -> bool {
    false
}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
fn is_android_emulator() -> bool {
    false
}

#[cfg(not(target_os = "ios"))]
#[allow(dead_code)]
fn is_ios_jailbroken() -> bool {
    false
}

#[cfg(not(target_os = "ios"))]
#[allow(dead_code)]
fn is_ios_simulator() -> bool {
    false
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
#[allow(dead_code)]
fn is_virtual_machine() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_compromise_check() {
        // This test just ensures the function runs without panicking
        let _result = is_device_compromised();
    }

    #[test]
    fn test_emulator_check() {
        // This test just ensures the function runs without panicking
        let _result = is_emulator();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_vm_detection() {
        // This will correctly detect if we're in a VM
        let result = is_linux_vm();
        // We don't assert the result since tests may run in VMs
        let _ = result;
    }
}
