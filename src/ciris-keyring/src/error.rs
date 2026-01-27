//! Error types for keyring operations.

use thiserror::Error;

/// Errors that can occur during keyring operations.
#[derive(Debug, Error)]
pub enum KeyringError {
    /// No hardware security module available on this platform.
    #[error("No hardware security module available on this platform")]
    NoPlatformSupport,

    /// Hardware security module not available.
    #[error("Hardware not available: {reason}")]
    HardwareNotAvailable {
        /// Reason hardware is not available.
        reason: String,
    },

    /// Key with the specified alias not found.
    #[error("Key not found: {alias}")]
    KeyNotFound {
        /// The key alias that was not found.
        alias: String,
    },

    /// Key already exists with this alias.
    #[error("Key already exists: {alias}")]
    KeyAlreadyExists {
        /// The key alias that already exists.
        alias: String,
    },

    /// Key generation failed.
    #[error("Key generation failed: {reason}")]
    KeyGenerationFailed {
        /// Reason for the failure.
        reason: String,
    },

    /// Signing operation failed.
    #[error("Signing failed: {reason}")]
    SigningFailed {
        /// Reason for the failure.
        reason: String,
    },

    /// Attestation retrieval failed.
    #[error("Attestation failed: {reason}")]
    AttestationFailed {
        /// Reason for the failure.
        reason: String,
    },

    /// User authentication required but not provided.
    #[error("User authentication required")]
    AuthenticationRequired,

    /// User authentication failed.
    #[error("User authentication failed")]
    AuthenticationFailed,

    /// Hardware security module error.
    #[error("Hardware security error: {reason}")]
    HardwareError {
        /// Reason for the failure.
        reason: String,
    },

    /// Platform-specific error.
    #[error("Platform error: {message}")]
    PlatformError {
        /// Error message from the platform.
        message: String,
    },

    /// Serialization/deserialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid key configuration.
    #[error("Invalid configuration: {reason}")]
    InvalidConfiguration {
        /// Reason the configuration is invalid.
        reason: String,
    },

    /// Operation not supported on this platform.
    #[error("Operation not supported: {operation}")]
    NotSupported {
        /// The unsupported operation.
        operation: String,
    },

    /// Keyring/storage initialization failed.
    #[error("Initialization failed: {reason}")]
    InitializationFailed {
        /// Reason for the failure.
        reason: String,
    },

    /// Invalid key data.
    #[error("Invalid key: {reason}")]
    InvalidKey {
        /// Reason the key is invalid.
        reason: String,
    },

    /// Storage operation failed.
    #[error("Storage failed: {reason}")]
    StorageFailed {
        /// Reason for the failure.
        reason: String,
    },

    /// Generic operation failed.
    #[error("Operation failed: {reason}")]
    OperationFailed {
        /// Reason for the failure.
        reason: String,
    },
}

impl KeyringError {
    /// Create a platform error from a message.
    #[must_use]
    pub fn platform(message: impl Into<String>) -> Self {
        Self::PlatformError {
            message: message.into(),
        }
    }

    /// Create a hardware error from a reason.
    #[must_use]
    pub fn hardware(reason: impl Into<String>) -> Self {
        Self::HardwareError {
            reason: reason.into(),
        }
    }

    /// Create a signing error from a reason.
    #[must_use]
    pub fn signing(reason: impl Into<String>) -> Self {
        Self::SigningFailed {
            reason: reason.into(),
        }
    }
}

#[cfg(all(target_os = "android", feature = "android"))]
impl From<jni::errors::Error> for KeyringError {
    fn from(err: jni::errors::Error) -> Self {
        Self::PlatformError {
            message: err.to_string(),
        }
    }
}
