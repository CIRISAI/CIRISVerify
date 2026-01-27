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

/// Check if running in an emulator.
///
/// Returns `true` if emulator indicators are found.
pub fn is_emulator() -> bool {
    #[cfg(target_os = "android")]
    {
        return is_android_emulator();
    }

    #[cfg(target_os = "ios")]
    {
        return is_ios_simulator();
    }

    // On desktop, we optionally detect VMs but don't fail on them
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
    use std::io::Read;

    // Method 1: Check build properties
    let emulator_props = [
        ("ro.hardware", &["goldfish", "ranchu", "vbox86"]),
        (
            "ro.product.model",
            &["sdk", "google_sdk", "Emulator", "Android SDK"],
        ),
        ("ro.product.manufacturer", &["Genymotion", "unknown"]),
        ("ro.product.device", &["generic", "generic_x86", "vbox86p"]),
    ];

    // Read from /system/build.prop
    if let Ok(mut file) = std::fs::File::open("/system/build.prop") {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            for (prop, values) in emulator_props {
                for line in contents.lines() {
                    if line.starts_with(prop) {
                        for val in *values {
                            if line.contains(val) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    // Method 2: Check for emulator-specific files
    let emulator_files = [
        "/dev/socket/qemud",
        "/dev/qemu_pipe",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props",
    ];

    for path in emulator_files {
        if std::path::Path::new(path).exists() {
            return true;
        }
    }

    // Method 3: Check CPU info for emulator signatures
    if let Ok(mut file) = std::fs::File::open("/proc/cpuinfo") {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            let emulator_cpu = ["goldfish", "vbox86", "Android Virtual"];
            for pattern in emulator_cpu {
                if contents.contains(pattern) {
                    return true;
                }
            }
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
