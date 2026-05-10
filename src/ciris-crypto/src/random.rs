//! Cryptographically secure RNG facade (CIRISVerify#7, v2.0.0+).
//!
//! Centralizes the federation's RNG policy in `ciris-crypto`. Every
//! consumer that needs random bytes (nonces, salts, software-mode
//! master-key generation, etc.) goes through this module rather than
//! reaching into `rand_core`/`getrandom` directly. That keeps a single
//! audit point for entropy provenance and lets future hardening (FIPS
//! draws, hardware-entropy mixing) land here once and propagate
//! federation-wide.
//!
//! Backed by [`rand_core::OsRng`], which on Linux/Android sources
//! `getrandom(2)` (kernel CSPRNG), on macOS/iOS uses
//! `SecRandomCopyBytes` (Apple's CSPRNG), on Windows uses
//! `BCryptGenRandom`. All blocking paths.

use rand_core::{OsRng, RngCore};

use crate::error::CryptoError;

/// Fill `buf` with cryptographically-secure random bytes.
///
/// # Errors
///
/// `CryptoError::SerializationError` (re-purposed for "couldn't fill
/// from OS entropy source") on the rare platforms where `OsRng` can
/// fail. On Linux/macOS/Windows this is effectively infallible.
pub fn fill(buf: &mut [u8]) -> Result<(), CryptoError> {
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
}
