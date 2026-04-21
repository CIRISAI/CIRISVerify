//! Platform Conformance Test Harness
//!
//! Provides a single FFI entry point to run all platform conformance tests
//! and log results to platform logging (logcat, oslog, stdout, etc.).
//!
//! ## Usage
//!
//! ```c
//! CirisVerifyHandle handle = ciris_verify_init();
//! int32_t failures = ciris_verify_run_conformance_tests(handle);
//! if (failures == 0) {
//!     printf("All tests passed!\n");
//! } else {
//!     printf("%d test(s) failed\n", failures);
//! }
//! ciris_verify_destroy(handle);
//! ```

use std::time::Instant;

/// Hardware diagnostics info
#[derive(Debug, Clone)]
pub struct Diagnostics {
    pub hardware_type: String,
    pub attestation_level: String,
    pub raw: String,
}

/// Result of a single conformance test
#[derive(Debug)]
pub struct TestResult {
    pub name: &'static str,
    pub passed: bool,
    pub message: String,
    pub duration_ms: u64,
}

/// Summary of all conformance tests
#[derive(Debug, Default)]
pub struct ConformanceReport {
    pub tests: Vec<TestResult>,
    pub platform: String,
    pub hardware_backend: String,
    pub library_version: String,
}

impl ConformanceReport {
    pub fn passed(&self) -> usize {
        self.tests.iter().filter(|t| t.passed).count()
    }

    pub fn failed(&self) -> usize {
        self.tests.iter().filter(|t| !t.passed).count()
    }

    pub fn total(&self) -> usize {
        self.tests.len()
    }

    /// Log the full report to platform logging
    pub fn log_report(&self) {
        tracing::info!("╔══════════════════════════════════════════════════════════════╗");
        tracing::info!("║        CIRISVERIFY PLATFORM CONFORMANCE TEST REPORT          ║");
        tracing::info!("╠══════════════════════════════════════════════════════════════╣");
        tracing::info!("║ Version:  {:<50} ║", self.library_version);
        tracing::info!("║ Platform: {:<50} ║", self.platform);
        tracing::info!("║ Backend:  {:<50} ║", self.hardware_backend);
        tracing::info!("╠══════════════════════════════════════════════════════════════╣");

        for test in &self.tests {
            let status = if test.passed { "✓ PASS" } else { "✗ FAIL" };
            let name_truncated = if test.name.len() > 35 {
                &test.name[..35]
            } else {
                test.name
            };
            tracing::info!(
                "║ {} {:35} {:>6}ms ║",
                status,
                name_truncated,
                test.duration_ms
            );
            if !test.passed {
                // Log failure message on next line
                let msg_truncated = if test.message.len() > 56 {
                    format!("{}...", &test.message[..53])
                } else {
                    test.message.clone()
                };
                tracing::warn!("║   └─ {:<56} ║", msg_truncated);
            }
        }

        tracing::info!("╠══════════════════════════════════════════════════════════════╣");
        tracing::info!(
            "║ TOTAL: {} passed, {} failed, {} total{:<21}║",
            self.passed(),
            self.failed(),
            self.total(),
            ""
        );

        if self.failed() == 0 {
            tracing::info!("║                    ✓ ALL TESTS PASSED                        ║");
        } else {
            tracing::error!("║                    ✗ SOME TESTS FAILED                       ║");
        }
        tracing::info!("╚══════════════════════════════════════════════════════════════╝");
    }
}

/// Run a single test and capture the result
fn run_test<F>(name: &'static str, test_fn: F) -> TestResult
where
    F: FnOnce() -> Result<String, String>,
{
    let start = Instant::now();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test_fn));
    let duration_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(Ok(msg)) => TestResult {
            name,
            passed: true,
            message: msg,
            duration_ms,
        },
        Ok(Err(msg)) => TestResult {
            name,
            passed: false,
            message: msg,
            duration_ms,
        },
        Err(_) => TestResult {
            name,
            passed: false,
            message: "Test panicked".to_string(),
            duration_ms,
        },
    }
}

// =============================================================================
// Individual Conformance Tests
// =============================================================================

use crate::CirisVerifyHandle;

/// Test 1: Hardware backend detection
pub fn test_hardware_detection(handle: &CirisVerifyHandle) -> TestResult {
    run_test("hardware_detection", || {
        let diagnostics = handle.get_diagnostics();

        // Check that we got valid diagnostics
        if diagnostics.hardware_type.is_empty() {
            return Err("No hardware type reported".to_string());
        }

        Ok(format!(
            "type={}, level={}",
            diagnostics.hardware_type, diagnostics.attestation_level
        ))
    })
}

/// Test 2: Named key storage - store
pub fn test_named_key_store(handle: &CirisVerifyHandle) -> TestResult {
    run_test("named_key_store", || {
        // Use a test-specific key ID
        let key_id = "conformance:test_key_v1";

        // Generate deterministic test seed
        let test_seed: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        match handle.store_named_key(key_id, &test_seed) {
            Ok(()) => Ok("Key stored successfully".to_string()),
            Err(e) => Err(format!("Failed to store key: {:?}", e)),
        }
    })
}

/// Test 3: Named key storage - has_key
pub fn test_named_key_has(handle: &CirisVerifyHandle) -> TestResult {
    run_test("named_key_has", || {
        let key_id = "conformance:test_key_v1";

        match handle.has_named_key(key_id) {
            Ok(true) => Ok("Key exists".to_string()),
            Ok(false) => Err("Key should exist but doesn't".to_string()),
            Err(e) => Err(format!("has_named_key failed: {:?}", e)),
        }
    })
}

/// Test 4: Named key storage - get public key
pub fn test_named_key_get_public(handle: &CirisVerifyHandle) -> TestResult {
    run_test("named_key_get_public", || {
        let key_id = "conformance:test_key_v1";

        match handle.get_named_key_public(key_id) {
            Ok(pubkey) => {
                if pubkey.len() != 32 {
                    return Err(format!("Expected 32-byte pubkey, got {}", pubkey.len()));
                }
                Ok(format!(
                    "pubkey[0..4]={:02x}{:02x}{:02x}{:02x}",
                    pubkey[0], pubkey[1], pubkey[2], pubkey[3]
                ))
            },
            Err(e) => Err(format!("get_named_key_public failed: {:?}", e)),
        }
    })
}

/// Test 5: Ed25519 signing with named key
pub fn test_named_key_sign(handle: &CirisVerifyHandle) -> TestResult {
    run_test("named_key_sign", || {
        let key_id = "conformance:test_key_v1";
        let test_data = b"CIRISVerify conformance test data";

        match handle.sign_with_named_key(key_id, test_data) {
            Ok(signature) => {
                if signature.len() != 64 {
                    return Err(format!(
                        "Expected 64-byte signature, got {}",
                        signature.len()
                    ));
                }
                Ok(format!(
                    "sig[0..4]={:02x}{:02x}{:02x}{:02x}",
                    signature[0], signature[1], signature[2], signature[3]
                ))
            },
            Err(e) => Err(format!("sign_with_named_key failed: {:?}", e)),
        }
    })
}

/// Test 6: v1.6.0 Encryption roundtrip
pub fn test_encryption_roundtrip(handle: &CirisVerifyHandle) -> TestResult {
    run_test("encryption_roundtrip_v1.6", || {
        let key_id = "conformance:test_key_v1";
        let plaintext = b"Secret message for conformance testing!";
        let aad = b"additional-authenticated-data";

        // Encrypt
        let ciphertext = match handle.encrypt_with_named_key(key_id, plaintext, aad) {
            Ok(ct) => ct,
            Err(e) => return Err(format!("Encryption failed: {:?}", e)),
        };

        // Verify ciphertext format: nonce (12) + ciphertext + tag (16)
        if ciphertext.len() < 12 + 16 + 1 {
            return Err(format!("Ciphertext too short: {} bytes", ciphertext.len()));
        }

        // Decrypt
        let decrypted = match handle.decrypt_with_named_key(key_id, &ciphertext, aad) {
            Ok(pt) => pt,
            Err(e) => return Err(format!("Decryption failed: {:?}", e)),
        };

        // Verify roundtrip
        if decrypted != plaintext {
            return Err("Decrypted text doesn't match original".to_string());
        }

        Ok(format!(
            "{}B → {}B → {}B",
            plaintext.len(),
            ciphertext.len(),
            decrypted.len()
        ))
    })
}

/// Test 7: v1.6.0 Encryption with wrong AAD (should fail)
pub fn test_encryption_aad_mismatch(handle: &CirisVerifyHandle) -> TestResult {
    run_test("encryption_aad_mismatch", || {
        let key_id = "conformance:test_key_v1";
        let plaintext = b"Secret message";
        let aad_encrypt = b"correct-aad";
        let aad_decrypt = b"wrong-aad";

        // Encrypt with correct AAD
        let ciphertext = match handle.encrypt_with_named_key(key_id, plaintext, aad_encrypt) {
            Ok(ct) => ct,
            Err(e) => return Err(format!("Encryption failed: {:?}", e)),
        };

        // Decrypt with wrong AAD - should fail
        match handle.decrypt_with_named_key(key_id, &ciphertext, aad_decrypt) {
            Ok(_) => Err("Decryption should have failed with wrong AAD".to_string()),
            Err(_) => Ok("Correctly rejected wrong AAD".to_string()),
        }
    })
}

/// Test 8: v1.6.0 Key derivation
pub fn test_key_derivation(handle: &CirisVerifyHandle) -> TestResult {
    run_test("key_derivation_v1.6", || {
        let key_id = "conformance:test_key_v1";
        let context = "conformance-test-context";

        match handle.derive_symmetric_key(key_id, context) {
            Ok(derived_key) => {
                if derived_key.len() != 32 {
                    return Err(format!("Expected 32-byte key, got {}", derived_key.len()));
                }

                // Derive again - should be deterministic
                let derived_key2 = handle
                    .derive_symmetric_key(key_id, context)
                    .map_err(|e| format!("Second derivation failed: {:?}", e))?;

                if derived_key != derived_key2 {
                    return Err("Key derivation not deterministic".to_string());
                }

                Ok(format!(
                    "key[0..4]={:02x}{:02x}{:02x}{:02x}",
                    derived_key[0], derived_key[1], derived_key[2], derived_key[3]
                ))
            },
            Err(e) => Err(format!("derive_symmetric_key failed: {:?}", e)),
        }
    })
}

/// Test 9: Key derivation with different context produces different keys
pub fn test_key_derivation_context_separation(handle: &CirisVerifyHandle) -> TestResult {
    run_test("key_derivation_context_sep", || {
        let key_id = "conformance:test_key_v1";

        let key1 = handle
            .derive_symmetric_key(key_id, "context-1")
            .map_err(|e| format!("Derivation 1 failed: {:?}", e))?;
        let key2 = handle
            .derive_symmetric_key(key_id, "context-2")
            .map_err(|e| format!("Derivation 2 failed: {:?}", e))?;

        if key1 == key2 {
            Err("Different contexts should produce different keys".to_string())
        } else {
            Ok("Context separation verified".to_string())
        }
    })
}

/// Test 10: Cleanup - delete test key
pub fn test_named_key_delete(handle: &CirisVerifyHandle) -> TestResult {
    run_test("named_key_delete", || {
        let key_id = "conformance:test_key_v1";

        // Delete the key
        match handle.delete_named_key(key_id) {
            Ok(()) => {},
            Err(e) => return Err(format!("delete_named_key failed: {:?}", e)),
        }

        // Verify it's gone
        match handle.has_named_key(key_id) {
            Ok(false) => Ok("Key deleted successfully".to_string()),
            Ok(true) => Err("Key still exists after deletion".to_string()),
            Err(e) => Err(format!("has_named_key failed after delete: {:?}", e)),
        }
    })
}

/// Test 11: Operations on non-existent key should fail gracefully
pub fn test_nonexistent_key_handling(handle: &CirisVerifyHandle) -> TestResult {
    run_test("nonexistent_key_handling", || {
        let key_id = "conformance:nonexistent_key_xyz";

        // has_named_key should return false, not error
        match handle.has_named_key(key_id) {
            Ok(false) => {},
            Ok(true) => return Err("Nonexistent key reported as existing".to_string()),
            Err(e) => return Err(format!("has_named_key should not error: {:?}", e)),
        }

        // sign_with_named_key should error
        match handle.sign_with_named_key(key_id, b"test") {
            Ok(_) => Err("Signing with nonexistent key should fail".to_string()),
            Err(_) => Ok("Correctly handles nonexistent key".to_string()),
        }
    })
}

// =============================================================================
// Main Runner
// =============================================================================

/// Run all conformance tests and return a report
pub fn run_all_tests(handle: &CirisVerifyHandle) -> ConformanceReport {
    let diag = handle.get_diagnostics();

    let mut report = ConformanceReport {
        tests: Vec::new(),
        platform: detect_platform(),
        hardware_backend: format!("{} (level {})", diag.hardware_type, diag.attestation_level),
        library_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    tracing::info!("Starting CIRISVerify conformance tests...");

    // Run tests in order (some depend on previous tests)
    report.tests.push(test_hardware_detection(handle));
    report.tests.push(test_named_key_store(handle));
    report.tests.push(test_named_key_has(handle));
    report.tests.push(test_named_key_get_public(handle));
    report.tests.push(test_named_key_sign(handle));
    report.tests.push(test_encryption_roundtrip(handle));
    report.tests.push(test_encryption_aad_mismatch(handle));
    report.tests.push(test_key_derivation(handle));
    report
        .tests
        .push(test_key_derivation_context_separation(handle));
    report.tests.push(test_named_key_delete(handle));
    report.tests.push(test_nonexistent_key_handling(handle));

    // Log the full report
    report.log_report();

    report
}

/// Detect the current platform for reporting
fn detect_platform() -> String {
    #[cfg(target_os = "android")]
    {
        "Android".to_string()
    }
    #[cfg(target_os = "ios")]
    {
        "iOS".to_string()
    }
    #[cfg(target_os = "macos")]
    {
        #[cfg(target_arch = "aarch64")]
        {
            "macOS (Apple Silicon)".to_string()
        }
        #[cfg(target_arch = "x86_64")]
        {
            "macOS (Intel)".to_string()
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            "macOS".to_string()
        }
    }
    #[cfg(target_os = "windows")]
    {
        "Windows".to_string()
    }
    #[cfg(target_os = "linux")]
    {
        #[cfg(target_env = "musl")]
        {
            "Linux (musl)".to_string()
        }
        #[cfg(not(target_env = "musl"))]
        {
            "Linux (glibc)".to_string()
        }
    }
    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "macos",
        target_os = "windows",
        target_os = "linux"
    )))]
    {
        "Unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_detection() {
        let platform = detect_platform();
        assert!(!platform.is_empty());
        println!("Detected platform: {}", platform);
    }
}
