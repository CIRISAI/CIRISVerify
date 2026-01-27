//! Software-only signer implementation.
//!
//! WARNING: This implementation provides NO hardware binding.
//! Deployments using this signer are LIMITED to UNLICENSED_COMMUNITY tier.
//!
//! Use only for:
//! - Development and testing
//! - Platforms without hardware security (some VMs, containers)
//! - Community deployments that don't require professional features

use async_trait::async_trait;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
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
        tracing::warn!(
            "SoftwareSigner initialized. NO HARDWARE BINDING. \
             Limited to UNLICENSED_COMMUNITY tier."
        );

        Ok(Self {
            signing_key: None,
            alias: alias.into(),
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

        let config = KeyGenConfig::new("test_key").require_hardware(false);
        signer.generate_key_mut(&config).unwrap();

        // Try to generate again - should fail
        let result = signer.generate_key_mut(&config);
        assert!(matches!(result, Err(KeyringError::KeyAlreadyExists { .. })));
    }
}
