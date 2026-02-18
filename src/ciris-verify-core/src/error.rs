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

    /// Configuration error.
    #[error("Configuration error: {message}")]
    ConfigError {
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
