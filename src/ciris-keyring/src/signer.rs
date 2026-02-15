//! Hardware signer trait and configuration.
//!
//! This module defines the core [`HardwareSigner`] trait that all platform
//! implementations must provide. The trait is designed to be compatible with
//! Veilid's async patterns while adding signing capabilities.

use async_trait::async_trait;

use crate::error::KeyringError;
use crate::types::{ClassicalAlgorithm, HardwareType, PlatformAttestation};

/// Configuration for key generation.
#[derive(Debug, Clone)]
pub struct KeyGenConfig {
    /// Unique alias/identifier for the key.
    pub alias: String,

    /// Require hardware-backed key storage.
    /// If true and hardware is unavailable, key generation will fail.
    pub require_hardware: bool,

    /// Require user authentication before key use.
    /// Uses biometrics or device PIN/password.
    pub require_user_auth: bool,

    /// Timeout for user authentication in seconds.
    /// Only relevant if `require_user_auth` is true.
    pub auth_timeout_seconds: Option<u32>,

    /// Invalidate key if biometrics are updated.
    /// Provides protection against biometric enrollment attacks.
    pub invalidate_on_biometric_change: bool,

    /// Preferred algorithm (may be overridden by hardware constraints).
    pub preferred_algorithm: ClassicalAlgorithm,
}

impl Default for KeyGenConfig {
    fn default() -> Self {
        Self {
            alias: "ciris_verify_key".to_string(),
            require_hardware: true,
            require_user_auth: false,
            auth_timeout_seconds: None,
            invalidate_on_biometric_change: false,
            preferred_algorithm: ClassicalAlgorithm::EcdsaP256,
        }
    }
}

impl KeyGenConfig {
    /// Create a new configuration with the given alias.
    #[must_use]
    pub fn new(alias: impl Into<String>) -> Self {
        Self {
            alias: alias.into(),
            ..Default::default()
        }
    }

    /// Set whether hardware backing is required.
    #[must_use]
    pub fn require_hardware(mut self, require: bool) -> Self {
        self.require_hardware = require;
        self
    }

    /// Set whether user authentication is required.
    #[must_use]
    pub fn require_user_auth(mut self, require: bool, timeout_seconds: Option<u32>) -> Self {
        self.require_user_auth = require;
        self.auth_timeout_seconds = timeout_seconds;
        self
    }

    /// Set the preferred algorithm.
    #[must_use]
    pub fn algorithm(mut self, algorithm: ClassicalAlgorithm) -> Self {
        self.preferred_algorithm = algorithm;
        self
    }
}

/// Trait for hardware-bound cryptographic signing.
///
/// This trait extends the Veilid keyring-manager pattern to support:
/// - Signing operations (not just storage)
/// - Platform attestation for remote verification
/// - Hardware type detection for tier restrictions
///
/// ## Security Properties
///
/// - Private keys never leave the hardware security module
/// - Signing operations are performed entirely within secure hardware
/// - Attestation provides cryptographic proof of hardware binding
///
/// ## Platform Implementations
///
/// - Android: `AndroidKeystoreSigner` (feature: `android`)
/// - iOS: `SecureEnclaveSigner` (feature: `ios`)
/// - TPM: `TpmSigner` (feature: `tpm`)
/// - Fallback: `SoftwareSigner` (feature: `software`)
///
/// ## Example
///
/// ```rust,ignore
/// use ciris_keyring::{HardwareSigner, KeyGenConfig};
///
/// async fn sign_verification_response(
///     signer: &dyn HardwareSigner,
///     data: &[u8],
/// ) -> Result<Vec<u8>, KeyringError> {
///     // Check hardware type for tier restrictions
///     if !signer.hardware_type().supports_professional_license() {
///         tracing::warn!("Software-only signer: limited to community tier");
///     }
///
///     // Sign the data
///     let signature = signer.sign(data).await?;
///
///     Ok(signature)
/// }
/// ```
#[async_trait]
pub trait HardwareSigner: Send + Sync {
    /// Get the classical algorithm used by this signer.
    ///
    /// This is determined by hardware constraints:
    /// - Mobile HSMs: ECDSA P-256 only
    /// - TPM: ECDSA P-256 (for compatibility)
    /// - SGX/Software: Ed25519 or ECDSA P-256
    fn algorithm(&self) -> ClassicalAlgorithm;

    /// Get the hardware type for this signer.
    ///
    /// Used for:
    /// - License tier restrictions (SOFTWARE_ONLY is limited)
    /// - Attestation type selection
    /// - Security level reporting
    fn hardware_type(&self) -> HardwareType;

    /// Get the public key.
    ///
    /// The public key can be exported and shared.
    /// Format depends on [`HardwareSigner::algorithm()`]:
    /// - ECDSA P-256: 65 bytes (uncompressed SEC1)
    /// - Ed25519: 32 bytes
    ///
    /// # Errors
    ///
    /// Returns error if the key doesn't exist or cannot be accessed.
    async fn public_key(&self) -> Result<Vec<u8>, KeyringError>;

    /// Sign data with the hardware-bound private key.
    ///
    /// The private key never leaves the secure hardware.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to sign (will be hashed internally for ECDSA)
    ///
    /// # Returns
    ///
    /// Signature bytes:
    /// - ECDSA P-256: 64 bytes (R || S, fixed-size)
    /// - Ed25519: 64 bytes
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Key doesn't exist
    /// - User authentication required but not provided
    /// - Hardware error during signing
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError>;

    /// Get platform attestation proving hardware binding.
    ///
    /// Attestation allows remote verifiers to confirm that:
    /// - The key was generated in secure hardware
    /// - The key cannot be extracted
    /// - The device meets security requirements
    ///
    /// # Errors
    ///
    /// Returns error if attestation cannot be generated.
    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError>;

    /// Generate a new key with the given configuration.
    ///
    /// If a key with the same alias already exists, this returns
    /// [`KeyringError::KeyAlreadyExists`].
    ///
    /// # Arguments
    ///
    /// * `config` - Key generation configuration
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Key already exists
    /// - Hardware requirements cannot be met
    /// - Key generation fails
    async fn generate_key(&self, config: &KeyGenConfig) -> Result<(), KeyringError>;

    /// Check if a key with the given alias exists.
    async fn key_exists(&self, alias: &str) -> Result<bool, KeyringError>;

    /// Delete a key with the given alias.
    ///
    /// # Errors
    ///
    /// Returns error if the key doesn't exist or cannot be deleted.
    async fn delete_key(&self, alias: &str) -> Result<(), KeyringError>;

    /// Get the key alias currently in use.
    fn current_alias(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_gen_config_builder() {
        let config = KeyGenConfig::new("test_key")
            .require_hardware(true)
            .require_user_auth(true, Some(30))
            .algorithm(ClassicalAlgorithm::EcdsaP256);

        assert_eq!(config.alias, "test_key");
        assert!(config.require_hardware);
        assert!(config.require_user_auth);
        assert_eq!(config.auth_timeout_seconds, Some(30));
        assert_eq!(config.preferred_algorithm, ClassicalAlgorithm::EcdsaP256);
    }
}
