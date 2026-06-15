//! Cryptographically secure RNG facade (CIRISVerify#7, v2.0.0+).
//!
//! Centralizes the federation's RNG policy in `ciris-crypto`. Consumers
//! that need raw random bytes (nonces, salts, software-mode master-key
//! generation, etc.) go through this module rather than reaching into
//! `rand_core`/`getrandom` directly. That keeps a single audit point for
//! entropy provenance and lets future hardening (FIPS draws,
//! hardware-entropy mixing) land here once and propagate federation-wide.
//!
//! ## RNG-health coverage of key generation (CIRISVerify#74)
//!
//! The fail-secure latch this module gates on (see [`fill`]) is the SAME
//! latch every keygen path now consults before drawing — but not every
//! keygen routes its draw *through* [`fill`]. Two shapes exist:
//!
//! - **Seed-then-construct** (`Ed25519Signer::random`,
//!   `MlDsa65Signer::new`): the 32-byte seed IS drawn via [`fill`], so
//!   the gate is inherited directly.
//! - **Latch-checked backend draw** (`P256Signer::random`, the
//!   `x25519` ephemerals, `ml_kem::{generate_keypair, encapsulate}`):
//!   the underlying crate must draw its own scalar/randomness with
//!   rejection sampling (a raw [`fill`] of 32 bytes is not a valid
//!   uniform scalar), so those call sites read
//!   [`crate::rng_health::is_rng_failed`] and fail closed BEFORE letting
//!   the backend draw.
//!
//! Either way, on a `Failed` latch no long-term key is produced. (Before
//! #74 the keygen paths drew `OsRng` directly and bypassed the latch
//! entirely — the audit-point claim here was aspirational for keygen and
//! is now load-bearing.)
//!
//! Backed by [`rand_core::OsRng`], which on Linux/Android sources
//! `getrandom(2)` (kernel CSPRNG), on macOS/iOS uses
//! `SecRandomCopyBytes` (Apple's CSPRNG), on Windows uses
//! `BCryptGenRandom`. All blocking paths.

use rand_core::{OsRng, RngCore};

use crate::error::CryptoError;
use crate::rng_health;

/// Fill `buf` with cryptographically-secure random bytes.
///
/// # Fail-secure gate (CIRISVerify#55 Gap H)
///
/// Before drawing, this reads the latched startup RNG health verdict
/// via [`rng_health::is_rng_failed`]. If the SP 800-90B startup
/// health-check has run AND failed (the OS entropy source is producing
/// detectably non-random output), `fill` returns
/// `CryptoError::RngHealthCheckFailed` WITHOUT drawing — degrading
/// closed rather than emitting potentially-predictable bytes. The gate
/// only READS the latch; it never runs the check itself (the check
/// draws, which would risk recursion). Callers invoke
/// [`rng_health::run_startup_health_check`] once at process init.
///
/// # Errors
///
/// - `CryptoError::RngHealthCheckFailed` if the startup health-check
///   failed (fail-secure; no bytes drawn).
/// - `CryptoError::SerializationError` (re-purposed for "couldn't fill
///   from OS entropy source") on the rare platforms where `OsRng` can
///   fail. On Linux/macOS/Windows this is effectively infallible.
pub fn fill(buf: &mut [u8]) -> Result<(), CryptoError> {
    if rng_health::is_rng_failed() {
        return Err(CryptoError::RngHealthCheckFailed(
            "OS RNG failed the SP 800-90B startup health-check; refusing to draw".to_string(),
        ));
    }
    let mut rng = OsRng;
    rng.try_fill_bytes(buf)
        .map_err(|e| CryptoError::SerializationError(format!("OsRng fill: {e}")))
}

/// Allocate and fill `n` bytes from the OS entropy source.
///
/// Convenience wrapper around [`fill`]. Returns `Vec<u8>` of length `n`.
///
/// # Errors
///
/// Same as [`fill`].
pub fn bytes(n: usize) -> Result<Vec<u8>, CryptoError> {
    let mut out = vec![0u8; n];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Output is the requested length and clearly random (two draws
    /// don't match — birthday probability for 32 bytes is ~2⁻¹²⁸ per draw).
    #[test]
    fn bytes_returns_requested_length_and_is_random() {
        let a = bytes(32).unwrap();
        let b = bytes(32).unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
        assert_ne!(a, b);
        // Not all zeros (this is an extremely loose check; the real
        // randomness assertion is that two draws differ above).
        assert!(a.iter().any(|&x| x != 0));
    }

    /// `fill` writes into a caller-provided slice without allocating.
    #[test]
    fn fill_into_caller_buffer() {
        let mut buf = [0u8; 16];
        fill(&mut buf).unwrap();
        // Same loose nonzero check.
        assert!(buf.iter().any(|&x| x != 0));
    }

    /// Empty buffer is a no-op, not an error.
    #[test]
    fn fill_empty_is_ok() {
        let mut empty: [u8; 0] = [];
        fill(&mut empty).unwrap();
        let zero_bytes = bytes(0).unwrap();
        assert!(zero_bytes.is_empty());
    }

    /// When the health latch is forced to `Failed`, `fill` fail-secures
    /// with `RngHealthCheckFailed` and draws nothing; forcing it back to
    /// `Healthy` restores normal operation.
    ///
    /// The health latch is a process-global shared by every test in the
    /// crate, so this test holds a static serialization mutex for the
    /// duration of its forced-`Failed` window and ALWAYS restores the
    /// latch to `Healthy` before releasing it. That keeps the global in
    /// a benign (Healthy) state for any test that races afterward and
    /// makes this test deterministic rather than flaky.
    #[test]
    fn fill_fails_secure_when_rng_marked_failed() {
        use crate::rng_health::{self, RngHealth};
        use std::sync::Mutex;

        // Serialize against any other test that pokes the global latch.
        static GATE: Mutex<()> = Mutex::new(());
        let _guard = GATE.lock().unwrap_or_else(|p| p.into_inner());

        rng_health::__force_health_for_test(RngHealth::Failed {
            test: "test-injected",
            detail: "forced for fail-secure path".to_string(),
        });

        let mut buf = [0u8; 16];
        let err = fill(&mut buf).unwrap_err();
        assert!(
            matches!(err, CryptoError::RngHealthCheckFailed(_)),
            "expected RngHealthCheckFailed, got {err:?}"
        );
        // Fail-secure means no bytes were emitted into the buffer.
        assert!(buf.iter().all(|&b| b == 0));
        // bytes() inherits the gate through fill().
        assert!(matches!(
            bytes(16).unwrap_err(),
            CryptoError::RngHealthCheckFailed(_)
        ));

        // Restore and confirm normal operation resumes.
        rng_health::__force_health_for_test(RngHealth::Healthy);
        fill(&mut buf).unwrap();
        assert!(buf.iter().any(|&b| b != 0));
    }
}
