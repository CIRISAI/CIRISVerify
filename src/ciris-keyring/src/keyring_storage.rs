//! Integration with the `keyring` crate for cross-platform key storage.
//!
//! This module bridges the standard keyring crate (OS keychains) with
//! our HardwareSigner trait (signing operations).
//!
//! The keyring crate provides:
//! - macOS Keychain
//! - Windows Credential Manager
//! - Linux Secret Service (via D-Bus)
//!
//! We extend it with:
//! - Software-based signing using stored keys
//! - Platform attestation (minimal, software-only)

#[cfg(feature = "keyring-storage")]
use keyring::Entry;

use async_trait::async_trait;

use crate::error::KeyringError;
use crate::signer::{HardwareSigner, KeyGenConfig};
use crate::types::{ClassicalAlgorithm, HardwareType, PlatformAttestation};

/// Keyring-backed signer that uses OS keychains for key storage
/// and provides software-based signing.
///
/// # Security Note
///
/// While keys are stored in OS keychains (which may have hardware-backed storage),
/// signing operations are performed in software. This means:
/// - Keys are protected at rest by OS keychain security
/// - Signing does NOT use hardware security modules
/// - This is classified as SOFTWARE_ONLY for tier restrictions
#[cfg(feature = "keyring-storage")]
pub struct KeyringStorageSigner {
    /// Keyring entry for key storage
    entry: Entry,
    /// Service name
    service: String,
    /// Key identifier/alias
    alias: String,
    /// Cached signing key (loaded from keyring)
    signing_key: Option<p256::ecdsa::SigningKey>,
}

#[cfg(feature = "keyring-storage")]
impl KeyringStorageSigner {
    /// Create a new signer backed by OS keychain.
    ///
    /// # Arguments
    ///
    /// * `service` - Service name for the keyring entry (e.g., "ciris-verify")
    /// * `alias` - Key alias/username for the keyring entry
    ///
    /// # Errors
    ///
    /// Returns error if keyring initialization fails.
    pub fn new(service: &str, alias: impl Into<String>) -> Result<Self, KeyringError> {
        let alias = alias.into();

        let entry = Entry::new(service, &alias)
            .map_err(|e| KeyringError::InitializationFailed {
                reason: format!("Keyring init failed: {e}"),
            })?;

        Ok(Self {
            entry,
            service: service.to_string(),
            alias,
            signing_key: None,
        })
    }

    /// Load an existing key from the keyring.
    pub fn load_key(&mut self) -> Result<(), KeyringError> {
        let key_bytes = self.entry.get_secret()
            .map_err(|e| match e {
                keyring::Error::NoEntry => KeyringError::KeyNotFound {
                    alias: self.alias.clone(),
                },
                _ => KeyringError::OperationFailed {
                    reason: format!("Failed to get key: {e}"),
                },
            })?;

        let signing_key = p256::ecdsa::SigningKey::from_bytes((&key_bytes[..]).into())
            .map_err(|e| KeyringError::InvalidKey {
                reason: format!("Failed to parse key: {e}"),
            })?;

        self.signing_key = Some(signing_key);
        Ok(())
    }

    /// Store a key in the keyring.
    pub fn store_key(&self, key_bytes: &[u8]) -> Result<(), KeyringError> {
        self.entry.set_secret(key_bytes)
            .map_err(|e| KeyringError::StorageFailed {
                reason: format!("Failed to store key: {e}"),
            })?;
        Ok(())
    }

    /// Generate a new key and store it in the keyring.
    pub fn generate_and_store(&mut self) -> Result<(), KeyringError> {
        use p256::ecdsa::SigningKey;
        use rand_core::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let key_bytes = signing_key.to_bytes();

        self.store_key(&key_bytes)?;
        self.signing_key = Some(signing_key);

        Ok(())
    }

    /// Delete the key from the keyring.
    pub fn delete_stored_key(&self) -> Result<(), KeyringError> {
        self.entry.delete_credential()
            .map_err(|e| KeyringError::OperationFailed {
                reason: format!("Failed to delete key: {e}"),
            })?;
        Ok(())
    }
}

#[cfg(feature = "keyring-storage")]
#[async_trait]
impl HardwareSigner for KeyringStorageSigner {
    fn algorithm(&self) -> ClassicalAlgorithm {
        ClassicalAlgorithm::EcdsaP256
    }

    fn hardware_type(&self) -> HardwareType {
        // Keyring storage uses OS-level storage but software signing
        HardwareType::SoftwareOnly
    }

    async fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
        let signing_key = self.signing_key.as_ref()
            .ok_or_else(|| KeyringError::KeyNotFound {
                alias: self.alias.clone(),
            })?;

        let verifying_key = signing_key.verifying_key();
        let encoded = verifying_key.to_encoded_point(false);
        Ok(encoded.as_bytes().to_vec())
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        use p256::ecdsa::{signature::Signer, Signature};

        let signing_key = self.signing_key.as_ref()
            .ok_or_else(|| KeyringError::KeyNotFound {
                alias: self.alias.clone(),
            })?;

        let signature: Signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
        // Keyring storage is software-only, so minimal attestation
        Ok(PlatformAttestation::Software(crate::types::SoftwareAttestation {
            key_derivation: "random".into(),
            storage: format!("keyring:{}", self.service),
            security_warning: "SOFTWARE_ONLY: OS keyring provides storage-at-rest protection but \
                              signing is software-based. Limited to UNLICENSED_COMMUNITY tier."
                .into(),
        }))
    }

    async fn generate_key(&self, _config: &KeyGenConfig) -> Result<(), KeyringError> {
        // Use generate_and_store instead (needs &mut self)
        Err(KeyringError::OperationFailed {
            reason: "Use generate_and_store() for KeyringStorageSigner".into(),
        })
    }

    async fn key_exists(&self, _alias: &str) -> Result<bool, KeyringError> {
        match self.entry.get_secret() {
            Ok(_) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(KeyringError::OperationFailed {
                reason: format!("Failed to check key: {e}"),
            }),
        }
    }

    async fn delete_key(&self, _alias: &str) -> Result<(), KeyringError> {
        self.delete_stored_key()
    }

    fn current_alias(&self) -> &str {
        &self.alias
    }
}

/// Create a signer that uses OS keychain for storage.
///
/// This provides OS-level secure storage (Keychain, Credential Manager, Secret Service)
/// but uses software-based signing (not hardware-bound).
#[cfg(feature = "keyring-storage")]
pub fn create_keyring_signer(
    service: &str,
    alias: &str,
) -> Result<KeyringStorageSigner, KeyringError> {
    KeyringStorageSigner::new(service, alias)
}

#[cfg(not(feature = "keyring-storage"))]
pub fn create_keyring_signer(
    _service: &str,
    _alias: &str,
) -> Result<(), KeyringError> {
    Err(KeyringError::NoPlatformSupport)
}

#[cfg(all(test, feature = "keyring-storage"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_keyring_signer_creation() {
        // This test requires keyring access which may not be available in CI
        let result = KeyringStorageSigner::new("ciris-test", "test-key");
        // Don't assert success - keyring may not be available
        if let Ok(signer) = result {
            assert_eq!(signer.algorithm(), ClassicalAlgorithm::EcdsaP256);
            assert_eq!(signer.hardware_type(), HardwareType::SoftwareOnly);
        }
    }
}
