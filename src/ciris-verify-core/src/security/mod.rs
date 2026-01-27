//! Security hardening and integrity verification.
//!
//! This module provides comprehensive security checks for CIRISVerify:
//!
//! - Binary self-integrity verification
//! - Debugger and hook detection
//! - Platform-specific tampering detection
//! - Constant-time cryptographic operations
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ciris_verify_core::security::{IntegrityChecker, IntegrityStatus};
//!
//! let checker = IntegrityChecker::new();
//! let status = checker.check_all();
//!
//! if !status.integrity_valid {
//!     // Fail secure - restrict to lockdown mode
//! }
//! ```

mod anti_tamper;
mod platform;

// Re-export from the main security module
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Digest, Sha256};

pub use anti_tamper::{detect_hooks, is_debugger_attached};
pub use platform::{is_device_compromised, is_emulator};

/// Opaque integrity status.
///
/// Per FSD-001 Section "Integrity Check Opacity", we MUST NOT expose
/// which specific checks failed. Only a single pass/fail and generic
/// failure category are provided.
#[derive(Debug, Clone)]
pub struct IntegrityStatus {
    /// Single pass/fail result.
    pub integrity_valid: bool,
    /// Timestamp of last check (Unix seconds).
    pub last_check_timestamp: i64,
    /// Generic failure category (if failed).
    /// One of: "environment", "binary", "runtime", or empty if valid.
    pub failure_category: String,
}

impl Default for IntegrityStatus {
    fn default() -> Self {
        Self {
            integrity_valid: false,
            last_check_timestamp: 0,
            failure_category: String::new(),
        }
    }
}

/// Comprehensive integrity checker.
///
/// Performs all security checks and returns an opaque result.
pub struct IntegrityChecker {
    /// Expected binary hash (embedded at build time).
    expected_hash: Option<[u8; 32]>,
    /// Whether to skip checks in debug builds.
    #[cfg(debug_assertions)]
    skip_in_debug: bool,
}

impl IntegrityChecker {
    /// Create a new integrity checker.
    ///
    /// In production builds, the expected hash should be embedded
    /// at build time using `include_bytes!`.
    pub fn new() -> Self {
        Self {
            expected_hash: None,
            #[cfg(debug_assertions)]
            skip_in_debug: true,
        }
    }

    /// Create an integrity checker with embedded hash.
    pub fn with_expected_hash(hash: [u8; 32]) -> Self {
        Self {
            expected_hash: Some(hash),
            #[cfg(debug_assertions)]
            skip_in_debug: false,
        }
    }

    /// Perform all integrity checks.
    ///
    /// Returns an opaque status that does NOT reveal which specific
    /// check failed.
    pub fn check_all(&self) -> IntegrityStatus {
        let timestamp = current_timestamp();

        // In debug builds, optionally skip checks
        #[cfg(debug_assertions)]
        if self.skip_in_debug {
            return IntegrityStatus {
                integrity_valid: true,
                last_check_timestamp: timestamp,
                failure_category: String::new(),
            };
        }

        // Collect all check results
        // We check ALL even if one fails to prevent timing attacks
        let binary_ok = self.check_binary_integrity();
        let debugger_ok = !is_debugger_attached();
        let hooks_ok = !detect_hooks();
        let environment_ok = self.check_environment();

        // Combine results - all must pass
        let all_valid = binary_ok && debugger_ok && hooks_ok && environment_ok;

        // Determine generic failure category (for logging only)
        let failure_category = if all_valid {
            String::new()
        } else if !binary_ok {
            "binary".to_string()
        } else if !environment_ok {
            "environment".to_string()
        } else {
            "runtime".to_string()
        };

        IntegrityStatus {
            integrity_valid: all_valid,
            last_check_timestamp: timestamp,
            failure_category,
        }
    }

    /// Check binary self-integrity.
    fn check_binary_integrity(&self) -> bool {
        let expected = match &self.expected_hash {
            Some(h) => h,
            None => {
                // No hash embedded - skip check in development
                #[cfg(debug_assertions)]
                return true;
                #[cfg(not(debug_assertions))]
                return false;
            }
        };

        match compute_self_hash() {
            Some(actual) => constant_time_eq(expected, &actual),
            None => false,
        }
    }

    /// Check execution environment.
    fn check_environment(&self) -> bool {
        // Platform-specific environment checks
        let device_ok = !is_device_compromised();
        let emulator_ok = !is_emulator();

        device_ok && emulator_ok
    }
}

impl Default for IntegrityChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute SHA-256 hash of the current binary.
///
/// Returns `None` if the binary cannot be read (which is itself
/// an integrity failure).
fn compute_self_hash() -> Option<[u8; 32]> {
    // Get path to current executable
    let exe_path = std::env::current_exe().ok()?;

    // Read binary contents
    let binary_data = std::fs::read(&exe_path).ok()?;

    // Compute SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&binary_data);
    let hash = hasher.finalize();

    Some(hash.into())
}

/// Constant-time byte comparison.
///
/// Prevents timing attacks by always comparing all bytes regardless
/// of where a mismatch occurs.
///
/// # Security
///
/// This function is critical for security. It MUST:
/// - Take the same amount of time regardless of input
/// - Not short-circuit on first mismatch
/// - Not leak information through timing
#[inline(never)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // XOR all bytes together - any difference sets bits
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    // Compare against zero in constant time
    // This prevents branch prediction attacks
    result == 0
}

/// Constant-time selection.
///
/// Returns `a` if `condition` is true, `b` otherwise.
/// Takes constant time regardless of condition.
#[inline(never)]
pub fn constant_time_select(condition: bool, a: u8, b: u8) -> u8 {
    let mask = if condition { 0xFF } else { 0x00 };
    (a & mask) | (b & !mask)
}

/// Get current Unix timestamp.
fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_equal() {
        let a = [1u8, 2, 3, 4, 5];
        let b = [1u8, 2, 3, 4, 5];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_different() {
        let a = [1u8, 2, 3, 4, 5];
        let b = [1u8, 2, 3, 4, 6];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        let a = [1u8, 2, 3, 4, 5];
        let b = [1u8, 2, 3, 4];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        let a: [u8; 0] = [];
        let b: [u8; 0] = [];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_select() {
        assert_eq!(constant_time_select(true, 10, 20), 10);
        assert_eq!(constant_time_select(false, 10, 20), 20);
    }

    #[test]
    fn test_integrity_checker_debug_mode() {
        let checker = IntegrityChecker::new();
        let status = checker.check_all();

        // In debug mode with skip_in_debug=true, should pass
        #[cfg(debug_assertions)]
        assert!(status.integrity_valid);
    }

    #[test]
    fn test_integrity_status_default() {
        let status = IntegrityStatus::default();
        assert!(!status.integrity_valid);
        assert_eq!(status.last_check_timestamp, 0);
        assert!(status.failure_category.is_empty());
    }
}
