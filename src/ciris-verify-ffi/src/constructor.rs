//! Early function integrity verification via platform constructors.
//!
//! This module runs before `main()` to verify that the FFI functions have not
//! been tampered with since build time. The result is stored in a global
//! `FunctionIntegrityStatus` that clients can query via `ciris_verify_get_status()`.
//!
//! ## Platform Mechanisms
//!
//! - **Linux/Android**: `.init_array` section with priority 101
//! - **macOS/iOS**: `#[ctor::ctor]` attribute
//! - **Windows**: `DllMain` with `DLL_PROCESS_ATTACH`
//!
//! ## Fail-Secure Degradation
//!
//! Per threat model Section 7, all failures degrade to MORE restrictive modes.
//! The constructor sets the status; the client decides the action.
//!
//! | Status | Client Action |
//! |--------|---------------|
//! | Verified | Normal operation |
//! | Unavailable | Warn user, may retry |
//! | SignatureInvalid | Refuse to operate |
//! | Tampered | Refuse to operate |
//! | NotFound | First release? Client decides |

use std::sync::OnceLock;
use std::time::Duration;

use ciris_verify_core::registry::{RegistryClient, DEFAULT_REGISTRY_URL};
use ciris_verify_core::security::function_integrity::{
    verify_functions, verify_manifest_signature, FunctionIntegrityStatus, StewardPublicKey,
};

/// Global function integrity status, set by constructor, read by `ciris_verify_get_status()`.
pub static FUNCTION_INTEGRITY_STATUS: OnceLock<FunctionIntegrityStatus> = OnceLock::new();

/// Steward public key for manifest verification.
///
/// This key is embedded at compile time and used to verify function manifests.
/// To rotate the key, a new version of CIRISVerify must be released.
///
/// TODO: Replace with actual steward public key bytes before v0.6.0 release.
static STEWARD_ED25519_PUBKEY: [u8; 32] = [0u8; 32]; // Placeholder
static STEWARD_MLDSA65_PUBKEY: [u8; 0] = []; // Placeholder (1952 bytes when populated)

static STEWARD_PUBKEY: StewardPublicKey = StewardPublicKey {
    ed25519: &STEWARD_ED25519_PUBKEY,
    ml_dsa_65: &STEWARD_MLDSA65_PUBKEY,
};

/// Run early function integrity verification.
///
/// This function:
/// 1. Creates a minimal tokio runtime
/// 2. Fetches the function manifest from the registry
/// 3. Verifies the manifest signature
/// 4. Hashes each function in memory
/// 5. Stores the result in `FUNCTION_INTEGRITY_STATUS`
///
/// The function never fails - all errors result in a status being set.
fn early_verify() {
    use std::sync::Once;
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        let status = run_verification();
        let _ = FUNCTION_INTEGRITY_STATUS.set(status);
    });
}

/// Perform the actual verification.
fn run_verification() -> FunctionIntegrityStatus {
    // Check if we have a valid steward key
    if *STEWARD_PUBKEY.ed25519 == [0u8; 32] || STEWARD_PUBKEY.ml_dsa_65.is_empty() {
        // Steward key not configured - skip verification
        // This is expected during development/testing
        return FunctionIntegrityStatus::Unavailable {
            reason: "steward_key_not_configured".to_string(),
        };
    }

    // Create minimal runtime for network fetch
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            return FunctionIntegrityStatus::Unavailable {
                reason: format!("runtime:{}", e),
            }
        },
    };

    rt.block_on(async {
        let target = detect_target();
        let version = env!("CARGO_PKG_VERSION");

        // Fetch manifest (5 second timeout)
        let registry = match RegistryClient::new(DEFAULT_REGISTRY_URL, Duration::from_secs(5)) {
            Ok(r) => r,
            Err(e) => {
                return FunctionIntegrityStatus::Unavailable {
                    reason: format!("client:{}", e),
                }
            },
        };

        let manifest = match registry.get_function_manifest(version, &target).await {
            Ok(m) => m,
            Err(ciris_verify_core::error::VerifyError::HttpsError { message }) => {
                // Could be network timeout, 404, etc.
                if message.contains("404") || message.contains("not found") {
                    return FunctionIntegrityStatus::NotFound;
                }
                return FunctionIntegrityStatus::Unavailable {
                    reason: format!("network:{}", message),
                };
            },
            Err(e) => {
                return FunctionIntegrityStatus::Unavailable {
                    reason: format!("fetch:{}", e),
                }
            },
        };

        // Verify signature
        match verify_manifest_signature(&manifest, &STEWARD_PUBKEY) {
            Ok(true) => {},
            Ok(false) => return FunctionIntegrityStatus::SignatureInvalid,
            Err(_) => return FunctionIntegrityStatus::SignatureInvalid,
        }

        // Verify function hashes
        let result = verify_functions(&manifest);
        if result.integrity_valid {
            FunctionIntegrityStatus::Verified
        } else {
            FunctionIntegrityStatus::Tampered
        }
    })
}

/// Detect the current target triple.
///
/// Returns the Rust target triple based on compile-time configuration.
fn detect_target() -> &'static str {
    // Detect at compile time using cfg attributes
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
    return "x86_64-unknown-linux-gnu";

    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"))]
    return "aarch64-unknown-linux-gnu";

    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    return "x86_64-apple-darwin";

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    return "aarch64-apple-darwin";

    #[cfg(all(target_arch = "x86_64", target_os = "windows", target_env = "msvc"))]
    return "x86_64-pc-windows-msvc";

    #[cfg(all(target_arch = "aarch64", target_os = "android"))]
    return "aarch64-linux-android";

    #[cfg(all(target_arch = "arm", target_os = "android"))]
    return "armv7-linux-androideabi";

    #[cfg(all(target_arch = "x86_64", target_os = "android"))]
    return "x86_64-linux-android";

    #[cfg(all(target_arch = "aarch64", target_os = "ios"))]
    return "aarch64-apple-ios";

    // Fallback for unknown targets
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"),
        all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "windows", target_env = "msvc"),
        all(target_arch = "aarch64", target_os = "android"),
        all(target_arch = "arm", target_os = "android"),
        all(target_arch = "x86_64", target_os = "android"),
        all(target_arch = "aarch64", target_os = "ios"),
    )))]
    return "unknown";
}

/// Get the current function integrity status.
///
/// Returns the status set by the constructor, or `Pending` if not yet verified.
pub fn get_function_integrity_status() -> FunctionIntegrityStatus {
    FUNCTION_INTEGRITY_STATUS
        .get()
        .cloned()
        .unwrap_or(FunctionIntegrityStatus::Pending)
}

// =============================================================================
// Platform-Specific Constructors
// =============================================================================

// Linux/Android: .init_array constructor
#[cfg(any(target_os = "linux", target_os = "android"))]
#[cfg(not(any(test, debug_assertions)))]
mod ctor_impl {
    use super::early_verify;

    #[link_section = ".init_array"]
    #[used]
    static CTOR: extern "C" fn() = early_verify_ctor;

    extern "C" fn early_verify_ctor() {
        early_verify();
    }
}

// macOS/iOS: ctor crate
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[cfg(not(any(test, debug_assertions)))]
#[ctor::ctor]
fn early_verify_ctor() {
    early_verify();
}

// Windows: DllMain
#[cfg(target_os = "windows")]
#[cfg(not(any(test, debug_assertions)))]
mod ctor_impl {
    use super::early_verify;
    use std::ffi::c_void;

    const DLL_PROCESS_ATTACH: u32 = 1;

    #[no_mangle]
    unsafe extern "system" fn DllMain(
        _hinst: *mut c_void,
        reason: u32,
        _reserved: *mut c_void,
    ) -> i32 {
        if reason == DLL_PROCESS_ATTACH {
            early_verify();
        }
        1 // TRUE - always succeed, status available via get_status()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_integrity_status_display() {
        assert_eq!(FunctionIntegrityStatus::Verified.to_string(), "verified");
        assert_eq!(FunctionIntegrityStatus::Tampered.to_string(), "tampered");
        assert_eq!(
            FunctionIntegrityStatus::Unavailable {
                reason: "test".to_string()
            }
            .to_string(),
            "unavailable:test"
        );
        assert_eq!(
            FunctionIntegrityStatus::SignatureInvalid.to_string(),
            "signature_invalid"
        );
        assert_eq!(FunctionIntegrityStatus::NotFound.to_string(), "not_found");
        assert_eq!(FunctionIntegrityStatus::Pending.to_string(), "pending");
    }

    #[test]
    fn test_get_status_defaults_to_pending() {
        // In tests, constructor doesn't run (guarded by #[cfg(not(test))])
        // So we can test the default behavior
        // Note: OnceLock might already be set from other tests, so we check either case
        let status = get_function_integrity_status();
        // Either pending (not set) or some other status (from previous test runs)
        assert!(
            matches!(
                status,
                FunctionIntegrityStatus::Pending | FunctionIntegrityStatus::Unavailable { .. }
            ),
            "Unexpected status: {:?}",
            status
        );
    }

    #[test]
    fn test_detect_target() {
        let target = detect_target();
        assert!(!target.is_empty());
        // Should be a known target or "unknown"
        assert!(
            target.contains("linux")
                || target.contains("darwin")
                || target.contains("windows")
                || target.contains("android")
                || target.contains("ios")
                || target == "unknown"
        );
    }

    #[test]
    fn test_run_verification_without_steward_key() {
        // With placeholder steward key, should return Unavailable
        let status = run_verification();
        assert!(
            matches!(status, FunctionIntegrityStatus::Unavailable { ref reason } if reason.contains("steward_key")),
            "Expected Unavailable with steward_key reason, got: {:?}",
            status
        );
    }
}
