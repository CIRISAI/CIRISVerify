//! CEG 0.2 §10.0.1 typed error envelope (v4.0.0-rc2+).
//!
//! Per CIRISRegistry CEG 0.2 §10.0.1, all CEG-conformant error
//! responses use a single canonical envelope shape:
//!
//! ```json
//! {
//!   "error": {
//!     "code": "<ENUM_VALUE>",
//!     "http_status": <int>,
//!     "message": "<human-readable>",
//!     "request_id": "<server-assigned>",
//!     "details": {<error-specific fields>}
//!   }
//! }
//! ```
//!
//! This module ships the verify-side mirror of that envelope. Verify
//! functions still return `Result<_, VerifyError>` for ergonomic
//! internal use; the HTTP / FFI / Python boundary translates via
//! [`CegError::from`].
//!
//! The discrimination matters because §0.5 / §0.6 / §0.7
//! canonicalization violations are wire-shape violations that must
//! be tagged distinctly from cryptographic-verification failures —
//! the consumer's recovery posture differs (resign vs renegotiate
//! transport vs reject + ban).

use serde::{Deserialize, Serialize};

use crate::error::VerifyError;

/// CEG 0.2 §10.0.1 error code enum. Stable wire constants — a
/// change is a federation-wide coordination event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CegErrorCode {
    /// 400 — Invalid JSON, missing required field, bad field type.
    #[serde(rename = "MALFORMED_REQUEST")]
    MalformedRequest,
    /// 400 — Date-time / hex / encoding doesn't match §0.5 / §0.6.
    /// THIS is the code v4.0.0-rc1's canonicalization checks
    /// (`check_canonical_rfc3339`, `check_canonical_hex64`) map to.
    #[serde(rename = "CANONICAL_BYTES_VIOLATION")]
    CanonicalBytesViolation,
    /// 401 — Bearer token missing or invalid.
    #[serde(rename = "UNAUTHENTICATED")]
    Unauthenticated,
    /// 403 — Producer attempted to emit under a reserved prefix
    /// without authority per §7.
    #[serde(rename = "RESERVED_PREFIX_VIOLATION")]
    ReservedPrefixViolation,
    /// 404 — Witness `key_id` not registered in directory (§10.3).
    #[serde(rename = "UNKNOWN_WITNESS")]
    UnknownWitness,
    /// 404 — Generic resource not found.
    #[serde(rename = "NOT_FOUND")]
    NotFound,
    /// 409 — Replay detected (e.g. duplicate
    /// `(tree_size, witness_key_id)` cosignature with different
    /// signatures).
    #[serde(rename = "IDEMPOTENT_CONFLICT")]
    IdempotentConflict,
    /// 422 — Ed25519 or ML-DSA-65 failed to verify;
    /// `details.algorithm` names which.
    #[serde(rename = "SIGNATURE_VERIFICATION_FAILED")]
    SignatureVerificationFailed,
    /// 422 — `signed_at` exceeds §0.7 ±5 minute tolerance.
    #[serde(rename = "CLOCK_SKEW_VIOLATION")]
    ClockSkewViolation,
    /// 422 — Insufficient cosignatures to validate (§10.3.1).
    #[serde(rename = "WITNESS_QUORUM_NOT_MET")]
    WitnessQuorumNotMet,
    /// 429 — `X-RateLimit-*` headers set; `Retry-After` honored.
    #[serde(rename = "RATE_LIMITED")]
    RateLimited,
    /// 500 — Server-side fault; `request_id` usable for support.
    #[serde(rename = "INTERNAL_ERROR")]
    InternalError,
    /// 503 — Substrate replication lag exceeds liveness bound.
    #[serde(rename = "WITNESS_DIRECTORY_UNAVAILABLE")]
    WitnessDirectoryUnavailable,
    /// 429 — Per-event reconsideration rate limit exceeded
    /// (CIRISVerify#46 F-AV-RECONSIDER-DOS defense; v4.5.0+).
    #[serde(rename = "RECONSIDERATION_RATE_LIMITED")]
    ReconsiderationRateLimited,
    /// 429 — Per-actor cumulative filing budget exhausted
    /// (CIRISVerify#46 F-AV-RECONSIDER-DOS defense; v4.5.0+).
    #[serde(rename = "ACTOR_BUDGET_EXHAUSTED")]
    ActorBudgetExhausted,
    /// 429 — Cross-event harassment cluster detected
    /// (CIRISVerify#46 F-AV-RECONSIDER-DOS defense; v4.5.0+).
    #[serde(rename = "HARASSMENT_CLUSTER_DETECTED")]
    HarassmentClusterDetected,
}

impl CegErrorCode {
    /// HTTP status code paired with this error per §10.0.1 table.
    #[must_use]
    pub fn http_status(self) -> u16 {
        match self {
            Self::MalformedRequest | Self::CanonicalBytesViolation => 400,
            Self::Unauthenticated => 401,
            Self::ReservedPrefixViolation => 403,
            Self::UnknownWitness | Self::NotFound => 404,
            Self::IdempotentConflict => 409,
            Self::SignatureVerificationFailed
            | Self::ClockSkewViolation
            | Self::WitnessQuorumNotMet => 422,
            Self::RateLimited
            | Self::ReconsiderationRateLimited
            | Self::ActorBudgetExhausted
            | Self::HarassmentClusterDetected => 429,
            Self::InternalError => 500,
            Self::WitnessDirectoryUnavailable => 503,
        }
    }

    /// Stable wire-string representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedRequest => "MALFORMED_REQUEST",
            Self::CanonicalBytesViolation => "CANONICAL_BYTES_VIOLATION",
            Self::Unauthenticated => "UNAUTHENTICATED",
            Self::ReservedPrefixViolation => "RESERVED_PREFIX_VIOLATION",
            Self::UnknownWitness => "UNKNOWN_WITNESS",
            Self::NotFound => "NOT_FOUND",
            Self::IdempotentConflict => "IDEMPOTENT_CONFLICT",
            Self::SignatureVerificationFailed => "SIGNATURE_VERIFICATION_FAILED",
            Self::ClockSkewViolation => "CLOCK_SKEW_VIOLATION",
            Self::WitnessQuorumNotMet => "WITNESS_QUORUM_NOT_MET",
            Self::RateLimited => "RATE_LIMITED",
            Self::InternalError => "INTERNAL_ERROR",
            Self::WitnessDirectoryUnavailable => "WITNESS_DIRECTORY_UNAVAILABLE",
            Self::ReconsiderationRateLimited => "RECONSIDERATION_RATE_LIMITED",
            Self::ActorBudgetExhausted => "ACTOR_BUDGET_EXHAUSTED",
            Self::HarassmentClusterDetected => "HARASSMENT_CLUSTER_DETECTED",
        }
    }
}

/// One CEG §10.0.1 error envelope.
///
/// Field shape mirrors the JSON wire form. `request_id` and `details`
/// are optional in struct form (`None` / empty), but the JSON
/// representation per §10.0.1 always includes them — `request_id`
/// MAY be a server-assigned empty string when not yet known, and
/// `details` MAY be an empty object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CegError {
    /// Stable error code from [`CegErrorCode`].
    pub code: CegErrorCode,
    /// HTTP status (mirrors `code.http_status()`).
    pub http_status: u16,
    /// Human-readable message; safe to log + display.
    pub message: String,
    /// Server-assigned request id for support correlation. Optional
    /// (omitted from JSON when None).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Error-specific details. Defaults to an empty JSON object when
    /// no fields are provided.
    #[serde(default)]
    pub details: serde_json::Value,
}

impl CegError {
    /// Construct a CegError with the canonical `http_status` for `code`.
    #[must_use]
    pub fn new(code: CegErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            http_status: code.http_status(),
            message: message.into(),
            request_id: None,
            details: serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    /// Attach a server-assigned `request_id`.
    #[must_use]
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Attach error-specific details (must be a JSON object).
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}

impl std::fmt::Display for CegError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}): {}",
            self.code.as_str(),
            self.http_status,
            self.message
        )
    }
}

impl std::error::Error for CegError {}

/// Map a verify-internal [`VerifyError`] into the [`CegError`] wire
/// envelope. The mapping recognizes the §0.5 / §0.6 marker substrings
/// produced by v4.0.0-rc1's canonicalization checks and tags them
/// as [`CegErrorCode::CanonicalBytesViolation`]; everything else
/// defaults to [`CegErrorCode::SignatureVerificationFailed`] (the
/// existing path through `verify_hybrid_signature`) or
/// [`CegErrorCode::InternalError`] for IO / parse failures.
impl From<VerifyError> for CegError {
    fn from(e: VerifyError) -> Self {
        let msg = e.to_string();
        let code = if msg.contains("§0.5") || msg.contains("§0.6") {
            CegErrorCode::CanonicalBytesViolation
        } else if msg.contains("signature") || msg.contains("Signature") || msg.contains("verif") {
            CegErrorCode::SignatureVerificationFailed
        } else if msg.contains("not found") || msg.contains("Not Found") {
            CegErrorCode::NotFound
        } else if msg.contains("rollback") || msg.contains("Rollback") {
            // Anti-rollback is structurally a §10.0.1 wire-shape
            // violation: the producer asserted a revision older than
            // a previously-seen one, which is not a legitimate
            // canonical state.
            CegErrorCode::CanonicalBytesViolation
        } else {
            CegErrorCode::InternalError
        };
        Self::new(code, msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CEG §10.0.1 wire-string stability: the code strings + HTTP
    /// status table are federation-wide constants.
    #[test]
    fn error_code_wire_strings_are_stable() {
        assert_eq!(CegErrorCode::MalformedRequest.as_str(), "MALFORMED_REQUEST");
        assert_eq!(
            CegErrorCode::CanonicalBytesViolation.as_str(),
            "CANONICAL_BYTES_VIOLATION"
        );
        assert_eq!(
            CegErrorCode::SignatureVerificationFailed.as_str(),
            "SIGNATURE_VERIFICATION_FAILED"
        );
        assert_eq!(
            CegErrorCode::ClockSkewViolation.as_str(),
            "CLOCK_SKEW_VIOLATION"
        );
        assert_eq!(
            CegErrorCode::WitnessQuorumNotMet.as_str(),
            "WITNESS_QUORUM_NOT_MET"
        );
        assert_eq!(
            CegErrorCode::WitnessDirectoryUnavailable.as_str(),
            "WITNESS_DIRECTORY_UNAVAILABLE"
        );
    }

    /// CEG §10.0.1 HTTP-status table is normative.
    #[test]
    fn http_status_table_matches_spec() {
        assert_eq!(CegErrorCode::MalformedRequest.http_status(), 400);
        assert_eq!(CegErrorCode::CanonicalBytesViolation.http_status(), 400);
        assert_eq!(CegErrorCode::Unauthenticated.http_status(), 401);
        assert_eq!(CegErrorCode::ReservedPrefixViolation.http_status(), 403);
        assert_eq!(CegErrorCode::UnknownWitness.http_status(), 404);
        assert_eq!(CegErrorCode::NotFound.http_status(), 404);
        assert_eq!(CegErrorCode::IdempotentConflict.http_status(), 409);
        assert_eq!(CegErrorCode::SignatureVerificationFailed.http_status(), 422);
        assert_eq!(CegErrorCode::ClockSkewViolation.http_status(), 422);
        assert_eq!(CegErrorCode::WitnessQuorumNotMet.http_status(), 422);
        assert_eq!(CegErrorCode::RateLimited.http_status(), 429);
        assert_eq!(CegErrorCode::InternalError.http_status(), 500);
        assert_eq!(CegErrorCode::WitnessDirectoryUnavailable.http_status(), 503);
    }

    #[test]
    fn ceg_error_json_shape_matches_spec() {
        let e = CegError::new(
            CegErrorCode::CanonicalBytesViolation,
            "skill_manifest_sha256: §0.6 violation",
        )
        .with_request_id("req-abc-123")
        .with_details(serde_json::json!({"field": "skill_manifest_sha256"}));
        let j = serde_json::to_value(&e).unwrap();
        assert_eq!(j["code"], "CANONICAL_BYTES_VIOLATION");
        assert_eq!(j["http_status"], 400);
        assert_eq!(j["request_id"], "req-abc-123");
        assert_eq!(j["details"]["field"], "skill_manifest_sha256");
    }

    #[test]
    fn verify_error_section_0_6_maps_to_canonical_bytes_violation() {
        let v = VerifyError::IntegrityError {
            message: "skill_manifest_sha256: §0.6 violation — 0x prefix not allowed".into(),
        };
        let c: CegError = v.into();
        assert_eq!(c.code, CegErrorCode::CanonicalBytesViolation);
        assert_eq!(c.http_status, 400);
    }

    #[test]
    fn verify_error_section_0_5_maps_to_canonical_bytes_violation() {
        let v = VerifyError::IntegrityError {
            message: "import_timestamp: §0.5 violation — `Z` (UTC suffix) expected".into(),
        };
        let c: CegError = v.into();
        assert_eq!(c.code, CegErrorCode::CanonicalBytesViolation);
    }

    #[test]
    fn verify_error_signature_failure_maps_to_signature_verification_failed() {
        let v = VerifyError::IntegrityError {
            message: "SkillImportManifest hybrid signature verification failed".into(),
        };
        let c: CegError = v.into();
        assert_eq!(c.code, CegErrorCode::SignatureVerificationFailed);
        assert_eq!(c.http_status, 422);
    }

    #[test]
    fn verify_error_rollback_maps_to_canonical_bytes_violation() {
        // Anti-rollback is structurally a wire-shape violation — a
        // producer asserted a revision older than previously seen.
        let v = VerifyError::IntegrityError {
            message: "rollback_detected on license_revocation_revision".into(),
        };
        let c: CegError = v.into();
        assert_eq!(c.code, CegErrorCode::CanonicalBytesViolation);
    }

    #[test]
    fn display_includes_code_status_and_message() {
        let e = CegError::new(CegErrorCode::WitnessQuorumNotMet, "got 1, want 2");
        let s = e.to_string();
        assert!(s.contains("WITNESS_QUORUM_NOT_MET"));
        assert!(s.contains("422"));
        assert!(s.contains("got 1, want 2"));
    }

    #[test]
    fn json_round_trip() {
        let e = CegError::new(CegErrorCode::ClockSkewViolation, "skew 6m > 5m tolerance")
            .with_request_id("req-1")
            .with_details(serde_json::json!({"observed_skew_seconds": 360}));
        let s = serde_json::to_string(&e).unwrap();
        let back: CegError = serde_json::from_str(&s).unwrap();
        assert_eq!(back.code, CegErrorCode::ClockSkewViolation);
        assert_eq!(back.http_status, 422);
        assert_eq!(back.request_id.as_deref(), Some("req-1"));
        assert_eq!(back.details["observed_skew_seconds"], 360);
    }
}
