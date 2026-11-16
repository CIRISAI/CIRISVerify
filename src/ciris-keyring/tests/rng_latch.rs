//! The keyring's mints refuse on a tripped RNG health latch (CIRISVerify#207
//! item 6 / #74).
//!
//! This test writes the PROCESS-GLOBAL latch (`ciris-crypto`'s thread-local
//! override is `#[cfg(test)]` and is not active in a dependency). It lives in
//! its own integration-test binary so it never shares a process with the
//! keyring's unit tests: under a plain `cargo test --lib` (the pre-commit
//! hook) a tripped latch would otherwise race with every other mint. `cargo
//! nextest` already isolates each test; this makes `cargo test` safe too.
#![cfg(feature = "software")]

use ciris_crypto::rng_health::{__force_health_for_test, RngHealth, TEST_REPETITION_COUNT};

#[test]
fn minting_refuses_on_a_tripped_rng_latch() {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            __force_health_for_test(RngHealth::Healthy);
        }
    }
    let _restore = Restore;

    __force_health_for_test(RngHealth::Failed {
        test: TEST_REPETITION_COUNT,
        detail: "forced for the keyring fail-secure test".to_string(),
    });
    assert!(
        matches!(
            ciris_keyring::mint_p256_signing_key(),
            Err(ciris_keyring::KeyringError::KeyGenerationFailed { .. })
        ),
        "a keyring mint MUST refuse when the RNG health latch has tripped"
    );

    __force_health_for_test(RngHealth::Healthy);
    assert!(ciris_keyring::mint_p256_signing_key().is_ok());
}
