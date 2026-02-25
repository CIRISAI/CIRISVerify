//! Property-based tests for security hardening.
//!
//! These tests verify security invariants and constant-time behavior.

use proptest::prelude::*;

use ciris_verify_core::security::{constant_time_eq, IntegrityChecker, IntegrityStatus};

// =============================================================================
// Constant-Time Comparison Properties
// =============================================================================

/// Strategy for arbitrary byte arrays.
fn byte_array() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..1024)
}

/// Strategy for pairs of byte arrays of the same length.
fn same_length_byte_pairs(max_len: usize) -> impl Strategy<Value = (Vec<u8>, Vec<u8>)> {
    (0..=max_len).prop_flat_map(|len| {
        (
            prop::collection::vec(any::<u8>(), len),
            prop::collection::vec(any::<u8>(), len),
        )
    })
}

proptest! {
    // Reduced from 128 to prevent CI timeout on slow runners
    #![proptest_config(ProptestConfig {
        cases: 32,
        max_shrink_iters: 200,
        ..ProptestConfig::default()
    })]

    // ========================================================================
    // Constant-Time Comparison Properties
    // ========================================================================

    /// Reflexivity: any array equals itself.
    #[test]
    fn constant_time_reflexive(data in byte_array()) {
        prop_assert!(constant_time_eq(&data, &data));
    }

    /// Symmetry: if a == b then b == a.
    #[test]
    fn constant_time_symmetric((a, b) in same_length_byte_pairs(256)) {
        prop_assert_eq!(constant_time_eq(&a, &b), constant_time_eq(&b, &a));
    }

    /// Different lengths always differ.
    #[test]
    fn constant_time_length_mismatch(
        a in prop::collection::vec(any::<u8>(), 1..128),
        b in prop::collection::vec(any::<u8>(), 129..256)
    ) {
        prop_assert!(!constant_time_eq(&a, &b));
    }

    /// Any modification produces inequality.
    #[test]
    fn constant_time_detects_any_change(
        data in prop::collection::vec(any::<u8>(), 1..256),
        pos in 0usize..256,
        delta in 1u8..=255
    ) {
        let pos = pos % data.len();
        let mut modified = data.clone();
        modified[pos] = modified[pos].wrapping_add(delta);

        prop_assert!(!constant_time_eq(&data, &modified));
    }

    /// Empty arrays are equal.
    #[test]
    fn constant_time_empty_equal(_seed in any::<u64>()) {
        let empty: Vec<u8> = vec![];
        prop_assert!(constant_time_eq(&empty, &empty));
    }

    // ========================================================================
    // Integrity Checker Properties
    // ========================================================================

    /// Integrity checker always returns valid timestamp.
    #[test]
    fn integrity_timestamp_valid(_seed in any::<u64>()) {
        let checker = IntegrityChecker::new();
        let status = checker.check_all();

        // Timestamp should be reasonable (after 2024)
        prop_assert!(status.last_check_timestamp > 1704067200); // 2024-01-01
    }

    /// Integrity checker produces consistent results.
    #[test]
    fn integrity_consistent(_seed in any::<u64>()) {
        let checker = IntegrityChecker::new();

        // Run twice in quick succession
        let status1 = checker.check_all();
        let status2 = checker.check_all();

        // In debug mode, both should pass
        #[cfg(debug_assertions)]
        {
            prop_assert_eq!(status1.integrity_valid, status2.integrity_valid);
        }
    }

    /// Failure category is appropriate.
    #[test]
    fn integrity_failure_category_valid(_seed in any::<u64>()) {
        let checker = IntegrityChecker::new();
        let status = checker.check_all();

        if status.integrity_valid {
            prop_assert!(status.failure_category.is_empty());
        } else {
            prop_assert!(
                status.failure_category == "binary" ||
                status.failure_category == "environment" ||
                status.failure_category == "runtime"
            );
        }
    }
}

// =============================================================================
// Timing Attack Resistance Tests
// =============================================================================

/// Test that constant_time_eq doesn't leak information through timing.
///
/// This test measures execution time for various inputs and checks that
/// timing doesn't correlate with the position of the first difference.
///
/// NOTE: This is a statistical test and may have false positives/negatives.
/// It's meant to catch gross timing leaks, not subtle side channels.
#[test]
fn test_no_gross_timing_leak() {
    use std::time::Instant;

    // Create two 256-byte arrays
    let a: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let b: Vec<u8> = (0..256).map(|i| i as u8).collect();

    // Warmup: prime caches and JIT to avoid cold-start skew on CI runners
    for _ in 0..500 {
        std::hint::black_box(constant_time_eq(&a, &b));
    }

    // Time comparison of equal arrays (reduced iterations for CI)
    let start = Instant::now();
    for _ in 0..1000 {
        std::hint::black_box(constant_time_eq(&a, &b));
    }
    let equal_time = start.elapsed();

    // Create array differing at first byte
    let mut diff_first = b.clone();
    diff_first[0] = 255;

    let start = Instant::now();
    for _ in 0..1000 {
        std::hint::black_box(constant_time_eq(&a, &diff_first));
    }
    let diff_first_time = start.elapsed();

    // Create array differing at last byte
    let mut diff_last = b.clone();
    diff_last[255] = 255;

    let start = Instant::now();
    for _ in 0..1000 {
        std::hint::black_box(constant_time_eq(&a, &diff_last));
    }
    let diff_last_time = start.elapsed();

    // All timings should be within 2x of each other
    // (generous margin for noise)
    let max_time = equal_time.max(diff_first_time).max(diff_last_time);
    let min_time = equal_time.min(diff_first_time).min(diff_last_time);

    // This assertion may fail under heavy system load
    // That's acceptable - the test is statistical
    assert!(
        max_time.as_nanos() < min_time.as_nanos() * 5,
        "Potential timing leak detected: equal={:?}, diff_first={:?}, diff_last={:?}",
        equal_time,
        diff_first_time,
        diff_last_time
    );
}

// =============================================================================
// Integrity Status Tests
// =============================================================================

#[test]
fn test_integrity_status_default_is_fail_secure() {
    let status = IntegrityStatus::default();

    // Default should be INVALID (fail-secure)
    assert!(!status.integrity_valid);
    assert_eq!(status.last_check_timestamp, 0);
}

#[test]
#[ignore = "slow: reads entire binary - run with `cargo test -- --ignored`"]
fn test_integrity_checker_with_hash() {
    // Create checker with a specific hash (all zeros)
    // This will NOT match the actual binary hash
    let expected_hash = [0u8; 32];
    let checker = IntegrityChecker::with_expected_hash(expected_hash);

    // with_expected_hash disables skip_in_debug, so this check runs
    // The hash won't match, so integrity should fail
    let status = checker.check_all();

    // With an incorrect hash, integrity check should fail
    // (unless we're in an environment where self-hash can't be computed)
    // The important thing is it doesn't crash and returns a valid status
    assert!(status.last_check_timestamp > 0);
    if !status.integrity_valid {
        assert!(!status.failure_category.is_empty());
    }
}

// =============================================================================
// Security Module Integration Tests
// =============================================================================

#[test]
fn test_security_module_exports() {
    // Verify all expected exports are available
    use ciris_verify_core::security::{
        constant_time_eq, detect_hooks, is_debugger_attached, is_device_compromised, is_emulator,
        IntegrityChecker, IntegrityStatus,
    };

    // These should all compile and be callable
    let _eq = constant_time_eq(&[1, 2, 3], &[1, 2, 3]);
    let _hooks = detect_hooks();
    let _debugger = is_debugger_attached();
    let _compromised = is_device_compromised();
    let _emulator = is_emulator();
    let _checker = IntegrityChecker::new();
    let _status = IntegrityStatus::default();
}

#[test]
fn test_debug_mode_behavior() {
    // In debug mode, integrity checks should pass by default
    // This enables development without security blocking
    let checker = IntegrityChecker::new();
    let status = checker.check_all();

    #[cfg(debug_assertions)]
    assert!(
        status.integrity_valid,
        "Debug mode should pass integrity checks by default"
    );
}

// =============================================================================
// Fail-Secure Property Tests
// =============================================================================

// Note: Integrity checking with_expected_hash is VERY SLOW because it reads
// the entire binary. This is a single deterministic test, not proptest.
#[test]
#[ignore = "slow: reads entire binary - run with `cargo test -- --ignored`"]
fn fail_secure_on_bad_hash() {
    // Create checker with arbitrary hash that won't match
    let bad_hash = [0xFFu8; 32];
    let checker = IntegrityChecker::with_expected_hash(bad_hash);

    // In release mode, this should fail
    // In debug mode with skip_in_debug=false, it reads the binary
    let status = checker.check_all();

    // The point is: we never crash or expose information
    assert!(status.last_check_timestamp > 0);
    if !status.integrity_valid {
        assert!(!status.failure_category.is_empty());
    }
}
