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

// Placeholder code - constructors will be enabled in a future release
#![allow(dead_code)]

use std::sync::OnceLock;
use std::time::Duration;

use ciris_verify_core::registry::{RegistryClient, DEFAULT_REGISTRY_URL};
use ciris_verify_core::security::function_integrity::{
    verify_functions, verify_manifest_signature, FunctionIntegrityStatus, StewardPublicKey,
};

/// Global function integrity status, set by constructor, read by `ciris_verify_get_status()`.
pub static FUNCTION_INTEGRITY_STATUS: OnceLock<FunctionIntegrityStatus> = OnceLock::new();

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
///
/// Idempotent via `Once::call_once`. Made `pub(crate)` in v4.7.1 so
/// `ciris_verify_init` can lazy-trigger it after the FFI library has
/// finished loading - see [`CIRISVerify#51`] for the dlopen-vs-Tokio
/// loader-lock deadlock this defers around.
///
/// [`CIRISVerify#51`]: https://github.com/CIRISAI/CIRISVerify/issues/51
pub(crate) fn early_verify() {
    use std::sync::Once;
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        let status = run_verification();
        let _ = FUNCTION_INTEGRITY_STATUS.set(status);
    });
}

/// Resolve the bootstrap-trusted steward set from the packaged keyset.
/// Cached for the process lifetime — load+decode cost is paid once.
///
/// v3.0.1: the v2.1.x hardcoded-steward fallback was removed (it was
/// scheduled for v2.3.0; #29 deferral). The embedded keyset is
/// `include_bytes!`-baked and CI-verified parseable on every release
/// (`bootstrap_keyset::tests::embedded_keyset_parses`), so a load
/// failure is a build-broke-itself condition, not a field one. If it
/// nonetheless fails, this returns an **empty set** — fail-secure:
/// `run_verification` then reports `Unavailable { no_trusted_stewards }`
/// rather than silently trusting a stale hardcoded key.
fn get_trusted_stewards() -> &'static [crate::bootstrap_keyset::LoadedSteward] {
    static CACHE: OnceLock<Vec<crate::bootstrap_keyset::LoadedSteward>> = OnceLock::new();
    CACHE.get_or_init(|| match crate::bootstrap_keyset::load_keyset() {
        Ok(keys) => {
            tracing::info!(
                "Bootstrap keyset loaded: {} steward(s) — primary key_id={}",
                keys.len(),
                keys[0].key_id
            );
            keys
        },
        Err(e) => {
            tracing::error!(
                "Bootstrap keyset load failed ({e}) — no trusted stewards; \
                 function-integrity verification will report Unavailable (fail-secure)"
            );
            Vec::new()
        },
    })
}

/// Perform the actual verification.
fn run_verification() -> FunctionIntegrityStatus {
    // Check for skip flag - useful for Python/FFI contexts where blocking
    // during dlopen() can deadlock with the import lock
    if std::env::var("CIRIS_SKIP_EARLY_VERIFY").is_ok() {
        return FunctionIntegrityStatus::Unavailable {
            reason: "skipped_by_env".to_string(),
        };
    }

    // Resolve trusted stewards from the packaged keyset. v3.0.1 removed
    // the v2.1.x hardcoded-constant fallback — a keyset load failure
    // yields an empty set, handled fail-secure just below.
    let stewards = get_trusted_stewards();
    if stewards.is_empty() {
        return FunctionIntegrityStatus::Unavailable {
            reason: "no_trusted_stewards".to_string(),
        };
    }
    if stewards[0].ed25519 == [0u8; 32] {
        // Dev/test build with zeroed steward — skip verification.
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

        // Fetch manifest (5 second timeout). The early-verify ctor is part of
        // the ciris-verify-ffi shared library itself — its job is to verify
        // the running .so/.dll/.dylib against the registry. The project is
        // statically `"ciris-verify"` regardless of which downstream primitive
        // dlopen()s us, so we pass it explicitly per-call (v1.12.0+).
        // (Pre-v1.11.0 this defaulted to ciris-agent server-side, which
        // silently misverified verify against agent's namespace for years.)
        let registry = match RegistryClient::new(DEFAULT_REGISTRY_URL, Duration::from_secs(5)) {
            Ok(r) => r,
            Err(e) => {
                return FunctionIntegrityStatus::Unavailable {
                    reason: format!("client:{}", e),
                }
            },
        };

        let manifest = match registry
            .get_function_manifest("ciris-verify", version, target)
            .await
        {
            Ok(m) => m,
            // v2.2.0+ #21: NotFound is a structured variant now, so we no
            // longer have to string-match HttpsError messages for "404".
            Err(ciris_verify_core::error::VerifyError::NotFound { .. }) => {
                return FunctionIntegrityStatus::NotFound;
            },
            Err(e) => {
                return FunctionIntegrityStatus::Unavailable {
                    reason: format!("fetch:{}", e),
                }
            },
        };

        // v2.2.0+ #22: try each trusted steward — manifest is accepted if
        // ANY listed steward's hybrid signature verifies. With one entry
        // (v2.2.0 baseline) this is equivalent to the v2.1.x single-key
        // check; the multi-entry case is the 2.9.1 decentralization path.
        let signature_ok = stewards.iter().any(|s| {
            let key = StewardPublicKey {
                ed25519: &s.ed25519,
                ml_dsa_65: &s.mldsa65,
            };
            matches!(verify_manifest_signature(&manifest, &key), Ok(true))
        });
        if !signature_ok {
            return FunctionIntegrityStatus::SignatureInvalid;
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

/// Detect the current target platform name.
///
/// Returns names that match the registry manifest naming convention.
/// - Desktop: Uses Rust target triples (e.g., `x86_64-unknown-linux-gnu`)
/// - Android: Uses Android ABI names (e.g., `android-arm64-v8a`)
/// - iOS: Uses Rust target triples (e.g., `aarch64-apple-ios`, `aarch64-apple-ios-sim`)
fn detect_target() -> &'static str {
    // Detect at compile time using cfg attributes

    // Desktop Linux
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
    return "x86_64-unknown-linux-gnu";

    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"))]
    return "aarch64-unknown-linux-gnu";

    // macOS
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    return "x86_64-apple-darwin";

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    return "aarch64-apple-darwin";

    // Windows
    #[cfg(all(target_arch = "x86_64", target_os = "windows", target_env = "msvc"))]
    return "x86_64-pc-windows-msvc";

    // Android - use ABI names to match registry manifest
    #[cfg(all(target_arch = "aarch64", target_os = "android"))]
    return "android-arm64-v8a";

    #[cfg(all(target_arch = "arm", target_os = "android"))]
    return "android-armeabi-v7a";

    #[cfg(all(target_arch = "x86_64", target_os = "android"))]
    return "android-x86_64";

    // iOS - use Rust target triples to match registry manifest and build.rs TARGET env
    #[cfg(all(target_arch = "aarch64", target_os = "ios", not(target_abi = "sim")))]
    return "aarch64-apple-ios";

    #[cfg(all(target_arch = "aarch64", target_os = "ios", target_abi = "sim"))]
    return "aarch64-apple-ios-sim";

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
        all(target_arch = "aarch64", target_os = "ios", not(target_abi = "sim")),
        all(target_arch = "aarch64", target_os = "ios", target_abi = "sim"),
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

// Linux/Android: DISABLED in v4.7.1 (CIRISVerify#51).
//
// Starting (and `block_on`-waiting on) a Tokio runtime from DT_INIT /
// .init_array deadlocks against the glibc dynamic loader lock.
// Sequence:
//   1. `dlopen(libciris_verify_ffi.so)` acquires `_rtld_global`
//      (the loader lock) and calls our constructors.
//   2. Our ctor enters `early_verify()` → builds a Tokio current-
//      thread runtime with `enable_io()` and calls `block_on` on a
//      reqwest HTTPS fetch.
//   3. Tokio's IO driver / reqwest's connection pool spawns a worker
//      thread for DNS + TLS setup. That worker calls
//      `__cxa_thread_atexit_impl` to register a TLS destructor,
//      which itself needs `_rtld_global` to walk the loaded-DSO list.
//   4. Main ctor thread parks waiting for the runtime to come up
//      while holding the loader lock; worker parks waiting for the
//      loader lock to register its TLS dtor. Permanent deadlock,
//      `CIRISVerify()` never returns.
//
// Fix: defer early-verify to the first FFI call (`ciris_verify_init`
// in `lib.rs`). By then `dlopen` has long since released the loader
// lock and starting a runtime + worker threads is safe. The
// `Once::call_once` inside `early_verify` keeps it single-shot.
//
// macOS/iOS still use `#[ctor::ctor]` below — dyld + Apple's TLS
// model don't share glibc's `_rtld_global` cycle. Windows
// `DllMain` is likewise left in place (its loader lock is held but
// returns before any Tokio worker can register a TLS dtor).

// macOS/iOS: ctor crate
// Wrapped in catch_unwind because the constructor runs before main() and
// before the iOS/macOS runtime is fully initialized. A panic here would
// abort the entire process (SIGILL under panic=abort). Verification is
// advisory, so a caught panic just results in Unavailable status.
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[cfg(not(any(test, debug_assertions)))]
#[ctor::ctor]
fn early_verify_ctor() {
    let _ = std::panic::catch_unwind(|| {
        early_verify();
    });
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
        // Should be a known platform name or "unknown"
        // Desktop: Rust triples (linux, darwin, windows)
        // Mobile: Platform names (android-*, ios-*)
        assert!(
            target.contains("linux")
                || target.contains("darwin")
                || target.contains("windows")
                || target.starts_with("android-")
                || target.contains("apple-ios")
                || target == "unknown",
            "Unexpected target: {}",
            target
        );
    }

    /// Lock: the packaged keyset's first (primary) steward entry has
    /// not drifted.
    ///
    /// Pre-v3.0.1 this compared the entry to the v2.1.x hardcoded
    /// `[u8; 32]` / `[u8; 1952]` constants (the "zero behavior change"
    /// guarantee for the v2.2.0 keyset cutover). Those constants were
    /// removed with the hardcoded-steward fallback (#29 deferral), so
    /// the lock is now a known-answer test: `key_id`, the Ed25519
    /// public key (hex), and the ML-DSA-65 key length. Swapping the
    /// primary steward changes `key_id` and the Ed25519 key — either is
    /// caught. If this fails, `bootstrap_stewards.json` changed; don't
    /// ship until the change is intended.
    #[test]
    fn test_keyset_primary_steward_is_stable() {
        let stewards = crate::bootstrap_keyset::load_keyset().expect("packaged keyset must parse");
        let first = &stewards[0];
        assert_eq!(
            first.key_id, "ciris-registry-main-v1",
            "primary steward key_id drifted"
        );
        assert_eq!(
            hex::encode(first.ed25519),
            "1d9e82f69f31af62fdbfa61960968a40bd4ff35034484736cead0c3811723e44",
            "primary steward Ed25519 public key drifted"
        );
        assert_eq!(
            first.mldsa65.len(),
            1952,
            "primary steward ML-DSA-65 key must be 1952 bytes (FIPS 204)"
        );
    }

    #[test]
    fn test_run_verification_with_real_keys() {
        // With real steward keys embedded, verification should proceed.
        // The result depends on network availability and whether a manifest exists:
        // - NotFound: No manifest published for this version yet
        // - Unavailable: Network timeout or error
        // - SignatureInvalid: Manifest exists but signature doesn't match
        // - Verified: Manifest exists and matches
        // - Tampered: Manifest exists, signature valid, but hashes don't match
        let status = run_verification();
        assert!(
            matches!(
                status,
                FunctionIntegrityStatus::Verified
                    | FunctionIntegrityStatus::NotFound
                    | FunctionIntegrityStatus::Unavailable { .. }
                    | FunctionIntegrityStatus::SignatureInvalid
                    | FunctionIntegrityStatus::Tampered
            ),
            "Unexpected status: {:?}",
            status
        );
    }
}
