//! Software-only signer implementation.
//!
//! WARNING: This implementation provides NO hardware binding.
//! Deployments using this signer are LIMITED to UNLICENSED_COMMUNITY tier.
//!
//! Use only for:
//! - Development and testing
//! - Platforms without hardware security (some VMs, containers)
//! - Community deployments that don't require professional features
//!
//! ## Supported Algorithms
//!
//! - `SoftwareSigner` - ECDSA P-256 (generated locally)
//! - `Ed25519SoftwareSigner` - Ed25519 (for Portal-issued keys)

use async_trait::async_trait;
use ed25519_dalek::{Signature as Ed25519Signature, Signer as Ed25519SignerTrait, SigningKey as Ed25519SigningKey};
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;

use crate::error::KeyringError;
use crate::signer::{HardwareSigner, KeyGenConfig};
use crate::types::{ClassicalAlgorithm, HardwareType, PlatformAttestation, SoftwareAttestation};

/// Software-only signer for development and fallback scenarios.
///
/// # Security Warning
///
/// This signer stores keys in memory (or encrypted on disk) without
/// hardware protection. The private key CAN be extracted by an attacker
/// with system access. Deployments using this signer are automatically
/// limited to UNLICENSED_COMMUNITY tier.
///
/// # Use Cases
///
/// - Development and testing
/// - CI/CD environments
/// - Containers without TPM passthrough
/// - Community deployments
pub struct SoftwareSigner {
    signing_key: Option<SigningKey>,
    alias: String,
}

impl SoftwareSigner {
    /// Create a new software signer.
    ///
    /// # Arguments
    ///
    /// * `alias` - Key alias/identifier
    ///
    /// # Errors
    ///
    /// Currently infallible, but returns Result for API consistency.
    pub fn new(alias: impl Into<String>) -> Result<Self, KeyringError> {
        let alias = alias.into();
        tracing::info!(
            alias = %alias,
            "SoftwareSigner: generating ephemeral ECDSA P-256 key (no hardware binding)"
        );

        let signing_key = SigningKey::random(&mut OsRng);

        tracing::warn!(
            "SoftwareSigner: NO HARDWARE BINDING — limited to UNLICENSED_COMMUNITY tier"
        );

        Ok(Self {
            signing_key: Some(signing_key),
            alias,
        })
    }

    /// Create a software signer with an existing key.
    ///
    /// # Arguments
    ///
    /// * `signing_key` - Existing ECDSA P-256 signing key
    /// * `alias` - Key alias
    #[must_use]
    pub fn with_key(signing_key: SigningKey, alias: String) -> Self {
        Self {
            signing_key: Some(signing_key),
            alias,
        }
    }

    /// Generate a new random key.
    pub fn generate_random_key(&mut self) {
        self.signing_key = Some(SigningKey::random(&mut OsRng));
    }
}

#[async_trait]
impl HardwareSigner for SoftwareSigner {
    fn algorithm(&self) -> ClassicalAlgorithm {
        ClassicalAlgorithm::EcdsaP256
    }

    fn hardware_type(&self) -> HardwareType {
        HardwareType::SoftwareOnly
    }

    async fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
        let key = self.signing_key.as_ref().ok_or(KeyringError::KeyNotFound {
            alias: self.alias.clone(),
        })?;

        let verifying_key = key.verifying_key();
        let encoded = verifying_key.to_encoded_point(false);

        Ok(encoded.as_bytes().to_vec())
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        let key = self.signing_key.as_ref().ok_or(KeyringError::KeyNotFound {
            alias: self.alias.clone(),
        })?;

        // P-256 uses SHA-256 internally for message hashing
        let signature: Signature = key.sign(data);

        // Return fixed-size signature (R || S)
        Ok(signature.to_bytes().to_vec())
    }

    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
        Ok(PlatformAttestation::Software(SoftwareAttestation {
            key_derivation: "random".to_string(),
            storage: "memory".to_string(),
            security_warning: "SOFTWARE_ONLY: No hardware binding available. \
                               Private key can be extracted by attacker with system access. \
                               This deployment is LIMITED to UNLICENSED_COMMUNITY tier."
                .to_string(),
        }))
    }

    async fn generate_key(&self, config: &KeyGenConfig) -> Result<(), KeyringError> {
        if config.require_hardware {
            return Err(KeyringError::HardwareError {
                reason: "Hardware required but SoftwareSigner has no hardware support".into(),
            });
        }

        // Note: This is a bit awkward with &self, but we maintain the trait signature
        // In practice, you'd use interior mutability or a different pattern
        // For now, we just validate that it would work
        tracing::info!(
            alias = %config.alias,
            "Software key generation requested (actual generation deferred)"
        );

        Ok(())
    }

    async fn key_exists(&self, alias: &str) -> Result<bool, KeyringError> {
        Ok(self.signing_key.is_some() && self.alias == alias)
    }

    async fn delete_key(&self, alias: &str) -> Result<(), KeyringError> {
        if self.alias != alias {
            return Err(KeyringError::KeyNotFound {
                alias: alias.to_string(),
            });
        }

        // Note: With &self we can't actually delete. See note in generate_key.
        tracing::info!(alias = %alias, "Software key deletion requested");

        Ok(())
    }

    fn current_alias(&self) -> &str {
        &self.alias
    }
}

/// Mutable software signer for testing and development.
///
/// This version allows actual key generation and deletion.
pub struct MutableSoftwareSigner {
    inner: std::sync::RwLock<SoftwareSigner>,
}

impl MutableSoftwareSigner {
    /// Create a new mutable software signer.
    pub fn new(alias: impl Into<String>) -> Result<Self, KeyringError> {
        Ok(Self {
            inner: std::sync::RwLock::new(SoftwareSigner::new(alias)?),
        })
    }

    /// Generate a key, actually mutating the internal state.
    pub fn generate_key_mut(&self, config: &KeyGenConfig) -> Result<(), KeyringError> {
        if config.require_hardware {
            return Err(KeyringError::HardwareError {
                reason: "Hardware required but SoftwareSigner has no hardware support".into(),
            });
        }

        let mut inner = self
            .inner
            .write()
            .map_err(|_| KeyringError::PlatformError {
                message: "Lock poisoned".into(),
            })?;

        if inner.signing_key.is_some() && inner.alias == config.alias {
            return Err(KeyringError::KeyAlreadyExists {
                alias: config.alias.clone(),
            });
        }

        inner.alias = config.alias.clone();
        inner.generate_random_key();

        tracing::info!(alias = %config.alias, "Software key generated");

        Ok(())
    }
}

/// Ed25519 software signer for Portal-issued keys.
///
/// This signer is used for keys issued by CIRISPortal, which uses Ed25519.
/// Unlike `SoftwareSigner` (ECDSA P-256), this signer is specifically for
/// importing externally-issued Ed25519 keys.
///
/// # Security Warning
///
/// Like `SoftwareSigner`, this provides NO hardware binding. The private key
/// CAN be extracted by an attacker with system access.
///
/// # Use Cases
///
/// - Importing Portal-issued device authentication keys
/// - Agent identity keys from `agent_signing.key`
/// - Software-only deployments with Ed25519
pub struct Ed25519SoftwareSigner {
    signing_key: Option<Ed25519SigningKey>,
    alias: String,
}

impl Ed25519SoftwareSigner {
    /// Create a new Ed25519 software signer without a key.
    ///
    /// Use `import_key` to load a key.
    pub fn new(alias: impl Into<String>) -> Self {
        let alias = alias.into();
        tracing::info!(
            alias = %alias,
            "Ed25519SoftwareSigner: created (no key loaded)"
        );

        Self {
            signing_key: None,
            alias,
        }
    }

    /// Create a signer from raw Ed25519 seed bytes (32 bytes).
    ///
    /// This is the format Portal uses for device authentication keys.
    ///
    /// # Arguments
    ///
    /// * `key_bytes` - 32-byte Ed25519 seed/private key
    /// * `alias` - Key alias
    ///
    /// # Errors
    ///
    /// Returns error if key_bytes is not exactly 32 bytes.
    pub fn from_bytes(key_bytes: &[u8], alias: impl Into<String>) -> Result<Self, KeyringError> {
        let alias = alias.into();

        if key_bytes.len() != 32 {
            tracing::error!(
                alias = %alias,
                key_len = key_bytes.len(),
                "Ed25519SoftwareSigner: invalid key length (expected 32 bytes)"
            );
            return Err(KeyringError::InvalidKey {
                reason: format!(
                    "Ed25519 key must be 32 bytes, got {} bytes",
                    key_bytes.len()
                ),
            });
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(key_bytes);

        let signing_key = Ed25519SigningKey::from_bytes(&seed);

        tracing::info!(
            alias = %alias,
            "Ed25519SoftwareSigner: key imported from bytes"
        );
        tracing::warn!(
            "Ed25519SoftwareSigner: NO HARDWARE BINDING — limited to UNLICENSED_COMMUNITY tier"
        );

        Ok(Self {
            signing_key: Some(signing_key),
            alias,
        })
    }

    /// Import a key from bytes, replacing any existing key.
    ///
    /// # Arguments
    ///
    /// * `key_bytes` - 32-byte Ed25519 seed
    ///
    /// # Errors
    ///
    /// Returns error if key_bytes is not exactly 32 bytes.
    pub fn import_key(&mut self, key_bytes: &[u8]) -> Result<(), KeyringError> {
        if key_bytes.len() != 32 {
            tracing::error!(
                alias = %self.alias,
                key_len = key_bytes.len(),
                "import_key: invalid key length"
            );
            return Err(KeyringError::InvalidKey {
                reason: format!(
                    "Ed25519 key must be 32 bytes, got {} bytes",
                    key_bytes.len()
                ),
            });
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(key_bytes);

        self.signing_key = Some(Ed25519SigningKey::from_bytes(&seed));

        tracing::info!(alias = %self.alias, "Ed25519 key imported successfully");
        Ok(())
    }

    /// Check if a key is loaded.
    #[must_use]
    pub fn has_key(&self) -> bool {
        self.signing_key.is_some()
    }

    /// Delete the loaded key.
    pub fn clear_key(&mut self) {
        if self.signing_key.is_some() {
            tracing::info!(alias = %self.alias, "Ed25519 key cleared");
        }
        self.signing_key = None;
    }

    /// Get the public key bytes if a key is loaded.
    pub fn get_public_key(&self) -> Option<Vec<u8>> {
        self.signing_key
            .as_ref()
            .map(|k| k.verifying_key().to_bytes().to_vec())
    }
}

#[async_trait]
impl HardwareSigner for Ed25519SoftwareSigner {
    fn algorithm(&self) -> ClassicalAlgorithm {
        ClassicalAlgorithm::Ed25519
    }

    fn hardware_type(&self) -> HardwareType {
        HardwareType::SoftwareOnly
    }

    async fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
        let key = self.signing_key.as_ref().ok_or(KeyringError::KeyNotFound {
            alias: self.alias.clone(),
        })?;

        Ok(key.verifying_key().to_bytes().to_vec())
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        let key = self.signing_key.as_ref().ok_or(KeyringError::KeyNotFound {
            alias: self.alias.clone(),
        })?;

        let signature: Ed25519Signature = key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
        Ok(PlatformAttestation::Software(SoftwareAttestation {
            key_derivation: "portal-issued".to_string(),
            storage: "memory".to_string(),
            security_warning: "SOFTWARE_ONLY: No hardware binding available. \
                               Private key can be extracted by attacker with system access. \
                               This deployment is LIMITED to UNLICENSED_COMMUNITY tier."
                .to_string(),
        }))
    }

    async fn generate_key(&self, config: &KeyGenConfig) -> Result<(), KeyringError> {
        if config.require_hardware {
            return Err(KeyringError::HardwareError {
                reason: "Hardware required but Ed25519SoftwareSigner has no hardware support"
                    .into(),
            });
        }

        tracing::warn!(
            alias = %config.alias,
            "Ed25519SoftwareSigner::generate_key called - use import_key instead for Portal keys"
        );

        Ok(())
    }

    async fn key_exists(&self, alias: &str) -> Result<bool, KeyringError> {
        Ok(self.signing_key.is_some() && self.alias == alias)
    }

    async fn delete_key(&self, alias: &str) -> Result<(), KeyringError> {
        if self.alias != alias {
            return Err(KeyringError::KeyNotFound {
                alias: alias.to_string(),
            });
        }

        tracing::info!(alias = %alias, "Ed25519 key deletion requested");
        Ok(())
    }

    fn current_alias(&self) -> &str {
        &self.alias
    }
}

/// Thread-safe mutable Ed25519 software signer.
///
/// Wraps `Ed25519SoftwareSigner` with interior mutability for use in
/// concurrent contexts.
pub struct MutableEd25519Signer {
    inner: std::sync::RwLock<Ed25519SoftwareSigner>,
}

impl MutableEd25519Signer {
    /// Create a new mutable Ed25519 signer without a key.
    pub fn new(alias: impl Into<String>) -> Self {
        Self {
            inner: std::sync::RwLock::new(Ed25519SoftwareSigner::new(alias)),
        }
    }

    /// Import a key from bytes.
    pub fn import_key(&self, key_bytes: &[u8]) -> Result<(), KeyringError> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| KeyringError::PlatformError {
                message: "Lock poisoned".into(),
            })?;

        inner.import_key(key_bytes)
    }

    /// Check if a key is loaded.
    pub fn has_key(&self) -> bool {
        self.inner
            .read()
            .map(|inner| inner.has_key())
            .unwrap_or(false)
    }

    /// Clear the loaded key.
    pub fn clear_key(&self) -> Result<(), KeyringError> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| KeyringError::PlatformError {
                message: "Lock poisoned".into(),
            })?;

        inner.clear_key();
        Ok(())
    }

    /// Get the public key if loaded.
    pub fn get_public_key(&self) -> Option<Vec<u8>> {
        self.inner.read().ok().and_then(|inner| inner.get_public_key())
    }

    /// Sign data with the loaded key.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        let inner = self.inner.read().map_err(|_| KeyringError::PlatformError {
            message: "Lock poisoned".into(),
        })?;

        let key = inner.signing_key.as_ref().ok_or(KeyringError::KeyNotFound {
            alias: inner.alias.clone(),
        })?;

        let signature: Ed25519Signature = key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Get the current alias.
    pub fn alias(&self) -> String {
        self.inner
            .read()
            .map(|inner| inner.alias.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_software_signer_hardware_type() {
        let signer = SoftwareSigner::new("test_key").unwrap();
        assert_eq!(signer.hardware_type(), HardwareType::SoftwareOnly);
        assert!(!signer.hardware_type().supports_professional_license());
    }

    #[tokio::test]
    async fn test_software_signer_algorithm() {
        let signer = SoftwareSigner::new("test_key").unwrap();
        assert_eq!(signer.algorithm(), ClassicalAlgorithm::EcdsaP256);
    }

    #[tokio::test]
    async fn test_software_signer_sign_and_verify() {
        use p256::ecdsa::signature::Verifier;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();

        let signer = SoftwareSigner::with_key(signing_key, "test".into());

        let data = b"test data to sign";
        let signature_bytes = signer.sign(data).await.unwrap();

        // Verify signature
        let signature = Signature::from_slice(&signature_bytes).unwrap();
        assert!(verifying_key.verify(data, &signature).is_ok());
    }

    #[tokio::test]
    async fn test_software_signer_attestation() {
        let signer = SoftwareSigner::new("test_key").unwrap();
        let attestation = signer.attestation().await.unwrap();

        match attestation {
            PlatformAttestation::Software(sa) => {
                assert!(sa.security_warning.contains("SOFTWARE_ONLY"));
            },
            _ => panic!("Expected SoftwareAttestation"),
        }
    }

    #[tokio::test]
    async fn test_software_signer_rejects_hardware_requirement() {
        let signer = SoftwareSigner::new("test_key").unwrap();
        let config = KeyGenConfig::new("test").require_hardware(true);

        let result = signer.generate_key(&config).await;
        assert!(matches!(result, Err(KeyringError::HardwareError { .. })));
    }

    #[tokio::test]
    async fn test_mutable_software_signer() {
        let signer = MutableSoftwareSigner::new("test_key").unwrap();

        // Key is auto-generated by new(), so generating with the same alias should fail
        let config = KeyGenConfig::new("test_key").require_hardware(false);
        let result = signer.generate_key_mut(&config);
        assert!(matches!(result, Err(KeyringError::KeyAlreadyExists { .. })));

        // Generating with a different alias should succeed (replaces the key)
        let config2 = KeyGenConfig::new("other_key").require_hardware(false);
        signer.generate_key_mut(&config2).unwrap();
    }

    #[tokio::test]
    async fn test_ed25519_software_signer_from_bytes() {
        // Generate a random 32-byte seed
        let seed: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];

        let signer = Ed25519SoftwareSigner::from_bytes(&seed, "test_ed25519").unwrap();

        // Check algorithm
        assert_eq!(signer.algorithm(), ClassicalAlgorithm::Ed25519);
        assert_eq!(signer.hardware_type(), HardwareType::SoftwareOnly);

        // Check has_key
        assert!(signer.has_key());

        // Get public key
        let pubkey = signer.public_key().await.unwrap();
        assert_eq!(pubkey.len(), 32);

        // Sign and verify
        let data = b"test data to sign";
        let signature = signer.sign(data).await.unwrap();
        assert_eq!(signature.len(), 64);

        // Verify signature using ed25519-dalek
        use ed25519_dalek::{Verifier, VerifyingKey, Signature as DalekSignature};
        let verifying_key = VerifyingKey::from_bytes(&pubkey.try_into().unwrap()).unwrap();
        let dalek_sig = DalekSignature::from_slice(&signature).unwrap();
        assert!(verifying_key.verify(data, &dalek_sig).is_ok());
    }

    #[tokio::test]
    async fn test_ed25519_invalid_key_length() {
        // Test with wrong key length
        let short_seed = [0u8; 16];
        let result = Ed25519SoftwareSigner::from_bytes(&short_seed, "test");
        assert!(matches!(result, Err(KeyringError::InvalidKey { .. })));

        let long_seed = [0u8; 64];
        let result = Ed25519SoftwareSigner::from_bytes(&long_seed, "test");
        assert!(matches!(result, Err(KeyringError::InvalidKey { .. })));
    }

    #[tokio::test]
    async fn test_mutable_ed25519_signer() {
        let signer = MutableEd25519Signer::new("test_ed25519");

        // No key initially
        assert!(!signer.has_key());

        // Import key
        let seed: [u8; 32] = [0x42; 32];
        signer.import_key(&seed).unwrap();
        assert!(signer.has_key());

        // Get public key
        let pubkey = signer.get_public_key().unwrap();
        assert_eq!(pubkey.len(), 32);

        // Sign
        let data = b"test data";
        let sig = signer.sign(data).unwrap();
        assert_eq!(sig.len(), 64);

        // Clear key
        signer.clear_key().unwrap();
        assert!(!signer.has_key());
    }
}
