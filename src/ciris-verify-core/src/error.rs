//! Error types for verification operations.

use thiserror::Error;

/// Errors that can occur during verification.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Binary integrity check failed - possible tampering.
    #[error("Binary integrity check failed")]
    BinaryTampered,

    /// Multi-source validation sources disagree - possible attack.
    #[error("Verification sources disagree")]
    SourcesDisagree,

    /// Could not reach any verification source.
    #[error("No verification sources reachable")]
    NoSourcesReachable,

    /// License has been revoked.
    #[error("License revoked: {reason}")]
    LicenseRevoked {
        /// Reason for revocation.
        reason: String,
    },

    /// License has expired.
    #[error("License expired at {expiry}")]
    LicenseExpired {
        /// Expiration timestamp.
        expiry: i64,
    },

    /// Invalid license format or signature.
    #[error("Invalid license: {reason}")]
    InvalidLicense {
        /// Reason the license is invalid.
        reason: String,
    },

    /// Signature verification failed.
    #[error("Signature verification failed: {reason}")]
    SignatureVerificationFailed {
        /// Reason for failure.
        reason: String,
    },

    /// Hardware attestation failed.
    #[error("Hardware attestation failed: {reason}")]
    AttestationFailed {
        /// Reason for failure.
        reason: String,
    },

    /// DNS resolution error.
    #[error("DNS error: {message}")]
    DnsError {
        /// Error message.
        message: String,
    },

    /// HTTPS error.
    #[error("HTTPS error: {message}")]
    HttpsError {
        /// Error message.
        message: String,
    },

    /// Registry resource not found (HTTP 404).
    ///
    /// Distinct from `HttpsError` so callers can short-circuit dependent
    /// probes (no point fetching a binary-manifest for a version that
    /// doesn't exist) and cache the negative result for the run.
    /// Introduced v2.2.0 for issue #21.
    #[error("Registry resource not found: {url}")]
    NotFound {
        /// URL that returned 404.
        url: String,
    },

    /// Registry rate-limited the request (HTTP 429).
    ///
    /// `retry_after_secs` is the parsed `Retry-After` header per RFC 7231
    /// §7.1.3 — `None` if absent. The `MultiSourceRegistry` honors this
    /// before issuing fallback probes and writes it into a shared cooldown
    /// gate so concurrent probes in the same flow also back off.
    /// Introduced v2.2.0 for issue #21.
    #[error("Registry rate-limited at {url} (retry after {retry_after_secs:?}s)")]
    RateLimited {
        /// URL that returned 429.
        url: String,
        /// `Retry-After` seconds if the registry sent the header.
        retry_after_secs: Option<u64>,
    },

    /// Cache error.
    #[error("Cache error: {message}")]
    CacheError {
        /// Error message.
        message: String,
    },

    /// Rollback attack detected - revocation revision went backward.
    #[error("Rollback detected: saw revision {current} but previously saw {last_seen}")]
    RollbackDetected {
        /// The revision in the current response.
        current: u64,
        /// The highest revision previously seen.
        last_seen: u64,
    },

    /// Transport-epoch rollback (CIRISVerify#27, AV-42) — a federation
    /// envelope carried a `transport_epoch` lower than one already seen
    /// for the same `key_id`. A replayed older envelope must not be able
    /// to revert a peer's transport-identity binding to a stale (and
    /// possibly adversary-controlled) one. Mirrors `RollbackDetected`
    /// for the transport-binding axis.
    #[error(
        "Transport-epoch rollback for key_id {key_id}: \
         envelope epoch {attempted} is below highest seen {highest_seen}"
    )]
    TransportEpochRollback {
        /// The federation key_id the envelope claimed to be from.
        key_id: String,
        /// The epoch the rejected envelope carried.
        attempted: u64,
        /// The highest epoch previously admitted for this key_id.
        highest_seen: u64,
    },

    /// Configuration error.
    #[error("Configuration error: {message}")]
    ConfigError {
        /// Error message.
        message: String,
    },

    /// Integrity check error (for binary self-verification).
    #[error("Integrity check error: {message}")]
    IntegrityError {
        /// Error message.
        message: String,
    },

    /// Cryptographic error.
    #[error("Crypto error: {0}")]
    CryptoError(#[from] ciris_crypto::CryptoError),

    /// Keyring error.
    #[error("Keyring error: {0}")]
    KeyringError(#[from] ciris_keyring::KeyringError),
}

impl VerifyError {
    /// Check if this error should trigger LOCKDOWN mode.
    #[must_use]
    pub fn is_lockdown(&self) -> bool {
        matches!(self, Self::BinaryTampered)
    }

    /// Check if this error should trigger RESTRICTED mode.
    #[must_use]
    pub fn is_restricted(&self) -> bool {
        matches!(self, Self::SourcesDisagree | Self::RollbackDetected { .. })
    }

    /// Check if this error should degrade to COMMUNITY mode.
    #[must_use]
    pub fn is_community_degradation(&self) -> bool {
        matches!(
            self,
            Self::NoSourcesReachable
                | Self::LicenseRevoked { .. }
                | Self::LicenseExpired { .. }
                | Self::InvalidLicense { .. }
                | Self::SignatureVerificationFailed { .. }
        )
    }
}
