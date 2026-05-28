//! CEG 0.2 §10.1.1 full-SHA verification before consumption
//! (v4.0.0-rc2+).
//!
//! Per CIRISRegistry CEG 0.2 §10.1.1 (normative): a CEG-Conforming
//! Consumer (CCC) MUST verify the full SHA-256 of received bytes
//! against the value in `evidence_refs[]` BEFORE handing the bytes
//! to any consumer (Agent loader, Portal renderer, etc.).
//!
//! The `holds_bytes:sha256:{prefix}` directory dimension (§5.6.7)
//! carries only a short prefix for index efficiency; consumers MUST
//! NOT short-circuit verification to the prefix. The full-SHA check
//! is what closes the prefix-collision attack class.
//!
//! ## What this module ships
//!
//! - [`verify_holds_bytes`] — full SHA-256 verification with §0.6
//!   canonical-hex discipline. Constant-time comparison of digests.
//! - [`HoldsBytesError`] — typed failure modes mapping to
//!   [`crate::ceg_error::CegErrorCode`] when crossed to the §10.0.1
//!   wire envelope.
//!
//! ## What this module does NOT ship (consumer-side concerns)
//!
//! - Re-fetch / try-next-holder logic — that's the caller's
//!   `PeerResolver` strategy (CIRISEdge).
//! - `withdraws` emission on ContentMiss per §10.1.2 — the caller
//!   has authority to emit; verify only provides the rejection
//!   primitive.
//! - 24-hour TTL on `holds_bytes` directory entries (§10.1.2) —
//!   the caller checks `signed_at` against the freshness window.

use sha2::{Digest, Sha256};

use crate::ceg_error::{CegError, CegErrorCode};
use crate::security::constant_time_eq;

/// Typed failure modes for [`verify_holds_bytes`]. All map cleanly
/// into the §10.0.1 wire envelope via [`From`].
#[derive(Debug, Clone)]
pub enum HoldsBytesError {
    /// Expected hex string doesn't pass §0.6 canonicalization
    /// (wrong length, uppercase, `0x` prefix, non-hex char).
    Section06Violation(String),
    /// Computed SHA-256 of received bytes doesn't match the expected
    /// digest. The bytes MUST be discarded.
    DigestMismatch {
        /// Hex of what we computed.
        computed: String,
        /// Hex of what was expected.
        expected: String,
    },
}

impl std::fmt::Display for HoldsBytesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Section06Violation(msg) => write!(f, "§0.6 violation: {msg}"),
            Self::DigestMismatch { computed, expected } => {
                write!(
                    f,
                    "§10.1.1 violation: computed sha256={} != expected sha256={}",
                    truncate(computed, 16),
                    truncate(expected, 16)
                )
            },
        }
    }
}

impl std::error::Error for HoldsBytesError {}

impl From<HoldsBytesError> for CegError {
    fn from(e: HoldsBytesError) -> Self {
        match &e {
            HoldsBytesError::Section06Violation(_) => {
                CegError::new(CegErrorCode::CanonicalBytesViolation, e.to_string())
            },
            HoldsBytesError::DigestMismatch { .. } => {
                CegError::new(CegErrorCode::SignatureVerificationFailed, e.to_string())
            },
        }
    }
}

/// §10.1.1: verify the full SHA-256 of `received_bytes` against
/// `expected_sha256_hex`.
///
/// `expected_sha256_hex` MUST satisfy CEG §0.6 (lowercase, exactly
/// 64 hex chars, no `0x` prefix, no separators); a non-canonical
/// expected value is itself a wire violation and yields
/// [`HoldsBytesError::Section06Violation`] without even hashing the
/// bytes. The constant-time comparison runs only on canonical input.
///
/// Returns `Ok(())` iff the full SHA-256 matches; on any error the
/// caller MUST discard `received_bytes` and MAY emit a `withdraws`
/// against the `holds_bytes:sha256:{prefix}` attestation per §10.1.2.
///
/// # Safety against short-circuit attacks
///
/// The function ignores any short-prefix optimization (no
/// `starts_with` checks). All 32 bytes are compared in constant time.
/// A prefix collision in the directory `holds_bytes:sha256:{prefix}`
/// MUST NOT propagate into a falsely-accepted full SHA — that is the
/// gap §10.1.1 closes.
pub fn verify_holds_bytes(
    received_bytes: &[u8],
    expected_sha256_hex: &str,
) -> Result<(), HoldsBytesError> {
    check_section_06_hex(expected_sha256_hex)?;

    let mut hasher = Sha256::new();
    hasher.update(received_bytes);
    let computed: [u8; 32] = hasher.finalize().into();
    let computed_hex = hex_encode_lowercase(&computed);

    // Compare in constant time on the raw 32 bytes — the lowercase
    // hex we computed and the lowercase hex we accepted are
    // already canonicalized, so byte-equal iff hash-equal.
    let expected_bytes =
        decode_hex32_lowercase(expected_sha256_hex).map_err(HoldsBytesError::Section06Violation)?;
    if constant_time_eq(&computed, &expected_bytes) {
        Ok(())
    } else {
        Err(HoldsBytesError::DigestMismatch {
            computed: computed_hex,
            expected: expected_sha256_hex.to_string(),
        })
    }
}

/// Strict §0.6 hex form check: lowercase, exactly 64 chars, no `0x`,
/// no separators.
fn check_section_06_hex(s: &str) -> Result<(), HoldsBytesError> {
    if s.len() != 64 {
        return Err(HoldsBytesError::Section06Violation(format!(
            "expected 64 hex chars, got {}",
            s.len()
        )));
    }
    if s.starts_with("0x") || s.starts_with("0X") {
        return Err(HoldsBytesError::Section06Violation(
            "`0x` prefix not allowed in canonical hex".to_string(),
        ));
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(HoldsBytesError::Section06Violation(
            "non-lowercase-hex character".to_string(),
        ));
    }
    Ok(())
}

fn decode_hex32_lowercase(s: &str) -> Result<[u8; 32], String> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err(format!("expected 64 chars, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble_lowercase(bytes[i * 2])?;
        let lo = hex_nibble_lowercase(bytes[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble_lowercase(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(format!("non-lowercase-hex char {:?}", c as char)),
    }
}

fn hex_encode_lowercase(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn truncate(s: &str, n: usize) -> &str {
    s.get(..n.min(s.len())).unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer round-trip: SHA-256 of the empty string is
    /// `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
    #[test]
    fn verify_holds_bytes_accepts_canonical_match() {
        let empty: &[u8] = &[];
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(verify_holds_bytes(empty, expected).is_ok());
    }

    #[test]
    fn verify_holds_bytes_rejects_digest_mismatch() {
        let bytes: &[u8] = b"not the empty string";
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let result = verify_holds_bytes(bytes, expected);
        assert!(matches!(
            result,
            Err(HoldsBytesError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn verify_holds_bytes_rejects_short_circuit_to_prefix_attack() {
        // The directory entry would carry only a short prefix, but
        // §10.1.1 says callers MUST NOT short-circuit. Here we
        // verify the full-hex rejection: a prefix-only expected
        // value is rejected as §0.6 violation, not silently
        // accepted because the prefix matches.
        let bytes: &[u8] = &[];
        let prefix_only = "e3b0c44298fc1c14"; // 16 chars — would match prefix of empty-string SHA
        let result = verify_holds_bytes(bytes, prefix_only);
        assert!(matches!(
            result,
            Err(HoldsBytesError::Section06Violation(_))
        ));
    }

    #[test]
    fn verify_holds_bytes_rejects_uppercase_hex() {
        let bytes: &[u8] = &[];
        let upper = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        let result = verify_holds_bytes(bytes, upper);
        assert!(matches!(
            result,
            Err(HoldsBytesError::Section06Violation(_))
        ));
    }

    #[test]
    fn verify_holds_bytes_rejects_0x_prefix() {
        let bytes: &[u8] = &[];
        let prefixed = "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85";
        let result = verify_holds_bytes(bytes, prefixed);
        assert!(matches!(
            result,
            Err(HoldsBytesError::Section06Violation(_))
        ));
    }

    #[test]
    fn verify_holds_bytes_rejects_wrong_length() {
        let bytes: &[u8] = &[];
        // 63 chars (one short)
        let short = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85";
        let result = verify_holds_bytes(bytes, short);
        assert!(matches!(
            result,
            Err(HoldsBytesError::Section06Violation(_))
        ));
    }

    /// CEG §10.1.1 promise: the digest comparison is constant-time.
    /// We don't measure timing here — we just confirm the path goes
    /// through `constant_time_eq` (the security primitive) rather
    /// than `==` on `[u8; 32]`. Behavioral test:
    /// digest-mismatch from a 1-byte-different blob fails, digest-
    /// match from the original blob succeeds, both via the same path.
    #[test]
    fn verify_holds_bytes_runs_constant_time_path_on_both_outcomes() {
        let bytes_a: &[u8] = b"the quick brown fox";
        let mut hasher = Sha256::new();
        hasher.update(bytes_a);
        let digest_a: [u8; 32] = hasher.finalize().into();
        let expected_a = hex_encode_lowercase(&digest_a);

        assert!(verify_holds_bytes(bytes_a, &expected_a).is_ok());
        // One-byte change → reject.
        let bytes_b: &[u8] = b"the quick brown foy";
        assert!(matches!(
            verify_holds_bytes(bytes_b, &expected_a),
            Err(HoldsBytesError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn holds_bytes_error_converts_to_ceg_canonical_bytes_violation() {
        let e = HoldsBytesError::Section06Violation("test".into());
        let c: CegError = e.into();
        assert_eq!(c.code, CegErrorCode::CanonicalBytesViolation);
        assert_eq!(c.http_status, 400);
    }

    #[test]
    fn holds_bytes_error_converts_to_ceg_signature_verification_failed_on_digest_mismatch() {
        let e = HoldsBytesError::DigestMismatch {
            computed: "a".repeat(64),
            expected: "b".repeat(64),
        };
        let c: CegError = e.into();
        assert_eq!(c.code, CegErrorCode::SignatureVerificationFailed);
        assert_eq!(c.http_status, 422);
    }

    /// CEG §0.6 byte-layout stability: this is the canonical hex
    /// encoding contract. A change to the lowercase-only / no-prefix
    /// / exact-length discipline ripples to every consumer.
    #[test]
    fn section_06_hex_check_locks_all_three_invariants() {
        // Lowercase 64-char accepted.
        assert!(check_section_06_hex(&"a".repeat(64)).is_ok());
        // Uppercase rejected.
        assert!(check_section_06_hex(&"A".repeat(64)).is_err());
        // 0x prefix rejected even at correct total length.
        assert!(check_section_06_hex(&format!("0x{}", "a".repeat(62))).is_err());
        // Short rejected.
        assert!(check_section_06_hex(&"a".repeat(63)).is_err());
        // Long rejected.
        assert!(check_section_06_hex(&"a".repeat(65)).is_err());
    }
}
