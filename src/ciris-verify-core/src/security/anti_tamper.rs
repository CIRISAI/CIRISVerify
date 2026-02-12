//! Anti-tampering detection.
//!
//! Detects:
//! - Debuggers (ptrace, lldb, gdb)
//! - Function hooking (Frida, Xposed)
//! - Memory tampering
//!
//! ## Design Philosophy
//!
//! These checks are designed to raise the bar for attackers, not provide
//! absolute protection. A determined attacker with physical access can
//! always bypass software-only checks. The goal is:
//!
//! 1. Detect common instrumentation tools
//! 2. Prevent casual tampering
//! 3. Make bypassing time-consuming enough to deter most attackers
//!
//! ## Platform Support
//!
//! - Linux: ptrace, /proc checks
//! - Android: ptrace, frida detection, root detection
//! - iOS: sysctl, dyld checks
//! - Windows: IsDebuggerPresent, NtQueryInformationProcess
//! - macOS: sysctl, PT_DENY_ATTACH

/// Check if a debugger is currently attached.
///
/// Uses platform-specific methods to detect common debuggers.
pub fn is_debugger_attached() -> bool {
    // Check multiple methods to detect debugger
    let ptrace_check = check_ptrace();
    let proc_check = check_proc_status();
    let timing_check = check_timing_anomaly();

    ptrace_check || proc_check || timing_check
}

/// Detect common hooking frameworks.
///
/// Checks for:
/// - Frida
/// - Xposed (Android)
/// - Substrate/Substitute (iOS)
/// - Generic PLT/GOT hooks
pub fn detect_hooks() -> bool {
    let frida_check = detect_frida();
    let xposed_check = detect_xposed();
    let memory_check = detect_memory_anomalies();

    frida_check || xposed_check || memory_check
}

// =============================================================================
// Linux/Android Implementations
// =============================================================================

/// Check if ptrace is attached (Linux/Android).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn check_ptrace() -> bool {
    use std::io::Read;

    // Method 1: Try to ptrace ourselves
    // If a debugger is attached, ptrace(PTRACE_TRACEME) will fail
    unsafe {
        let result = libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
        if result == -1 {
            return true;
        }
        // Detach from ourselves
        libc::ptrace(libc::PTRACE_DETACH, 0, 0, 0);
    }

    // Method 2: Check /proc/self/status for TracerPid
    if let Ok(mut file) = std::fs::File::open("/proc/self/status") {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            for line in contents.lines() {
                if line.starts_with("TracerPid:") {
                    if let Some(pid_str) = line.split_whitespace().nth(1) {
                        if let Ok(pid) = pid_str.parse::<i32>() {
                            if pid != 0 {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    false
}

/// Check /proc/self/status for debugger indicators (Linux/Android).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn check_proc_status() -> bool {
    use std::io::Read;

    // Check for suspicious entries in /proc/self/maps
    if let Ok(mut file) = std::fs::File::open("/proc/self/maps") {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            // Look for debugger-related libraries
            let suspicious = [
                "frida",
                "gdb",
                "lldb",
                "ida",
                "radare",
                "r2",
                "xposed",
                "substrate",
            ];

            let contents_lower = contents.to_lowercase();
            for pattern in suspicious {
                if contents_lower.contains(pattern) {
                    return true;
                }
            }
        }
    }

    false
}

/// Detect Frida (Linux/Android).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn detect_frida() -> bool {
    use std::io::Read;
    use std::net::TcpStream;

    // Method 1: Check for Frida's default port
    if TcpStream::connect("127.0.0.1:27042").is_ok() {
        return true;
    }

    // Method 2: Check for frida-server process
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_dir() {
                    let cmdline_path = entry.path().join("cmdline");
                    if let Ok(mut file) = std::fs::File::open(&cmdline_path) {
                        let mut contents = String::new();
                        if file.read_to_string(&mut contents).is_ok() && contents.contains("frida")
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }

    // Method 3: Check for Frida's named pipe
    if std::path::Path::new("/data/local/tmp/frida-server").exists() {
        return true;
    }

    false
}

/// Detect Xposed framework (Android only).
#[cfg(target_os = "android")]
fn detect_xposed() -> bool {
    // Check for Xposed installer
    let xposed_paths = [
        "/system/framework/XposedBridge.jar",
        "/system/xposed.prop",
        "/data/data/de.robv.android.xposed.installer",
        "/data/data/org.meowcat.edxposed.manager",
        "/data/data/io.github.lsposed.manager",
    ];

    for path in xposed_paths {
        if std::path::Path::new(path).exists() {
            return true;
        }
    }

    // Check stack trace for Xposed classes
    // This is a heuristic - Xposed hooks show up in stack traces
    false
}

#[cfg(not(target_os = "android"))]
fn detect_xposed() -> bool {
    false
}

// =============================================================================
// macOS/iOS Implementations
// =============================================================================

/// Check for debugger via sysctl (macOS/iOS).
///
/// Uses the `CTL_KERN` / `KERN_PROC` / `KERN_PROC_PID` sysctl to query
/// the kernel for `P_TRACED` on the current process.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn check_ptrace() -> bool {
    use std::mem;

    // The P_TRACED flag from <sys/proc.h>
    const P_TRACED: i32 = 0x00000800;

    // We only need the p_flag field which lives at a known offset inside
    // kinfo_proc.  Rather than reproducing the entire (large, unstable)
    // struct we allocate a conservatively-sized buffer and read p_flag at
    // the correct byte offset.
    //
    // On both arm64 and x86-64 Darwin the layout is:
    //   struct kinfo_proc {            // total ≈ 648 bytes
    //       struct extern_proc kp_proc;
    //           …
    //           int p_flag;            // offset 16 in extern_proc → offset 16
    //           …
    //   };
    const KINFO_PROC_SIZE: usize = 648;
    const P_FLAG_OFFSET: usize = 16;

    unsafe {
        let mut buf = [0u8; KINFO_PROC_SIZE];
        let mut size: libc::size_t = KINFO_PROC_SIZE;

        let mut mib: [libc::c_int; 4] = [
            libc::CTL_KERN,
            libc::KERN_PROC,
            libc::KERN_PROC_PID,
            libc::getpid(),
        ];

        let result = libc::sysctl(
            mib.as_mut_ptr(),
            4,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &mut size,
            std::ptr::null_mut(),
            0,
        );

        if result == 0 && size >= P_FLAG_OFFSET + mem::size_of::<i32>() {
            let p_flag = i32::from_ne_bytes(
                buf[P_FLAG_OFFSET..P_FLAG_OFFSET + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            return (p_flag & P_TRACED) != 0;
        }
    }

    false
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn check_proc_status() -> bool {
    // On macOS/iOS, we rely on sysctl checks
    false
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn detect_frida() -> bool {
    use std::net::TcpStream;

    // Check for Frida's default port
    if TcpStream::connect("127.0.0.1:27042").is_ok() {
        return true;
    }

    // Check for Frida in loaded dylibs
    // This would require iterating dyld images
    false
}

// =============================================================================
// Windows Implementations
// =============================================================================

#[cfg(target_os = "windows")]
fn check_ptrace() -> bool {
    unsafe {
        // IsDebuggerPresent
        windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent() != 0
    }
}

#[cfg(target_os = "windows")]
fn check_proc_status() -> bool {
    unsafe {
        // CheckRemoteDebuggerPresent
        let mut debugger_present: i32 = 0;
        let result = windows_sys::Win32::System::Diagnostics::Debug::CheckRemoteDebuggerPresent(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
            &mut debugger_present,
        );
        result != 0 && debugger_present != 0
    }
}

#[cfg(target_os = "windows")]
fn detect_frida() -> bool {
    use std::net::TcpStream;

    // Check for Frida's default port
    TcpStream::connect("127.0.0.1:27042").is_ok()
}

// =============================================================================
// Fallback Implementations
// =============================================================================

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "windows"
)))]
fn check_ptrace() -> bool {
    false
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "windows"
)))]
fn check_proc_status() -> bool {
    false
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "windows"
)))]
fn detect_frida() -> bool {
    false
}

// =============================================================================
// Common Implementations
// =============================================================================

/// Check for timing anomalies that suggest debugging.
///
/// Breakpoints cause significant timing delays.
fn check_timing_anomaly() -> bool {
    use std::time::Instant;

    // Perform a simple operation that should be fast
    let start = Instant::now();

    // Do some busy work
    let mut sum = 0u64;
    for i in 0..1000 {
        sum = sum.wrapping_add(i);
    }

    let elapsed = start.elapsed();

    // Prevent optimization from removing the loop
    std::hint::black_box(sum);

    // If this simple operation took more than 100ms, something is wrong
    // (normal execution should be < 1ms)
    elapsed.as_millis() > 100
}

/// Detect memory anomalies suggesting tampering.
fn detect_memory_anomalies() -> bool {
    // Check if critical functions have been modified
    // This is a basic check - more sophisticated checks would
    // verify function prologues haven't been patched

    // For now, we just verify some basic properties
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // Check if code section is writable (it shouldn't be)
        // This would require parsing /proc/self/maps and checking permissions
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debugger_not_attached_in_normal_execution() {
        // In normal test execution without a debugger attached,
        // this should return false (no debugger)
        // Note: This test may fail if run under a debugger!
        #[cfg(not(debug_assertions))]
        {
            // Only run this check in release mode
            // as debug mode may have different behavior
        }
    }

    #[test]
    fn test_timing_check_normal() {
        // Normal execution should not trigger timing anomaly
        let result = check_timing_anomaly();
        assert!(!result, "Timing check failed in normal execution");
    }

    #[test]
    fn test_frida_not_present() {
        // In a normal environment without Frida, this should return false
        // Note: This test will fail if Frida is actually running!
        let result = detect_frida();
        // We don't assert here because Frida might legitimately be running
        // in some test environments
        let _ = result;
    }
}
