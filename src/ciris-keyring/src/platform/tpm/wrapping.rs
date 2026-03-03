//! TPM-wrapped Ed25519 key storage.
//!
//! Uses TPM-derived AES-256-GCM encryption to protect Ed25519 keys at rest.
//! The encryption key is derived from a TPM-held secret, providing hardware
//! binding while allowing import of Portal keys.

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use crate::error::KeyringError;

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use tracing::{debug, error, info, warn};

/// Size of Ed25519 private key
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
const ED25519_PRIVATE_KEY_SIZE: usize = 32;
/// AES-256-GCM nonce size
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
const AES_GCM_NONCE_SIZE: usize = 12;
/// AES-256-GCM tag size
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
const AES_GCM_TAG_SIZE: usize = 16;

/// TPM-wrapped Ed25519 signer for Linux/Windows.
///
/// Uses a TPM-derived AES-256-GCM key to protect the Ed25519 private key.
/// The AES key is derived by signing a fixed challenge with a TPM key,
/// providing binding to the specific TPM while allowing key import.
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub struct TpmWrappedEd25519Signer {
    /// Path to the encrypted Ed25519 key file
    encrypted_key_path: std::path::PathBuf,
    /// Cached Ed25519 signing key (decrypted in memory when needed)
    cached_signing_key: std::sync::Mutex<Option<ed25519_dalek::SigningKey>>,
    /// Alias for logging
    alias: String,
}

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
impl TpmWrappedEd25519Signer {
    /// Create a new TPM-wrapped Ed25519 signer.
    ///
    /// # Arguments
    /// * `alias` - Alias for the key (used in file name and logging)
    /// * `key_dir` - Directory to store the encrypted key
    pub fn new(
        alias: impl Into<String>,
        key_dir: impl Into<std::path::PathBuf>,
    ) -> Result<Self, KeyringError> {
        let alias = alias.into();
        let key_dir = key_dir.into();
        let encrypted_key_path = key_dir.join(format!("{}.ed25519.tpm", alias));

        info!(
            alias = %alias,
            key_path = ?encrypted_key_path,
            "TpmWrappedEd25519Signer::new"
        );

        // Ensure key directory exists
        if let Some(parent) = encrypted_key_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                error!("Failed to create key directory: {}", e);
                KeyringError::StorageFailed {
                    reason: format!("Failed to create key directory: {}", e),
                }
            })?;
        }

        Ok(Self {
            encrypted_key_path,
            cached_signing_key: std::sync::Mutex::new(None),
            alias,
        })
    }

    /// Check if a TPM-wrapped key exists.
    pub fn key_exists(&self) -> bool {
        self.encrypted_key_path.exists()
    }

    /// Import an Ed25519 key and encrypt it with TPM-derived key.
    pub fn import_key(&self, key_bytes: &[u8]) -> Result<(), KeyringError> {
        info!(
            alias = %self.alias,
            key_len = key_bytes.len(),
            "Importing Ed25519 key with TPM wrapping"
        );

        if key_bytes.len() != ED25519_PRIVATE_KEY_SIZE {
            return Err(KeyringError::InvalidKey {
                reason: format!(
                    "Ed25519 key must be {} bytes, got {}",
                    ED25519_PRIVATE_KEY_SIZE,
                    key_bytes.len()
                ),
            });
        }

        // Derive AES key from TPM
        let aes_key = self.derive_aes_key()?;

        // Encrypt the Ed25519 key
        let encrypted = self.aes_encrypt(&aes_key, key_bytes)?;

        // Write encrypted key to disk
        std::fs::write(&self.encrypted_key_path, &encrypted).map_err(|e| {
            error!("Failed to write encrypted key: {}", e);
            KeyringError::StorageFailed {
                reason: format!("Failed to write encrypted key: {}", e),
            }
        })?;

        // Parse and cache the signing key
        let mut key_array = [0u8; ED25519_PRIVATE_KEY_SIZE];
        key_array.copy_from_slice(key_bytes);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);

        {
            let mut cache = self.cached_signing_key.lock().unwrap();
            *cache = Some(signing_key);
        }

        info!(
            alias = %self.alias,
            encrypted_size = encrypted.len(),
            "Ed25519 key encrypted with TPM-derived key"
        );

        Ok(())
    }

    /// Get the Ed25519 public key.
    pub fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
        let signing_key = self.get_or_load_signing_key()?;
        let verifying_key = signing_key.verifying_key();
        Ok(verifying_key.to_bytes().to_vec())
    }

    /// Sign data with the Ed25519 key.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        use ed25519_dalek::Signer;
        let signing_key = self.get_or_load_signing_key()?;
        let signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Delete the TPM-wrapped key.
    pub fn delete_key(&self) -> Result<(), KeyringError> {
        info!(alias = %self.alias, "Deleting TPM-wrapped Ed25519 key");

        // Clear cached key
        {
            let mut cache = self.cached_signing_key.lock().unwrap();
            *cache = None;
        }

        // Delete encrypted key file
        if self.encrypted_key_path.exists() {
            std::fs::remove_file(&self.encrypted_key_path).map_err(|e| {
                warn!("Failed to delete encrypted key file: {}", e);
                KeyringError::StorageFailed {
                    reason: format!("Failed to delete encrypted key file: {}", e),
                }
            })?;
        }

        info!(alias = %self.alias, "TPM-wrapped Ed25519 key deleted");
        Ok(())
    }

    /// Returns true because key is protected by TPM-derived encryption.
    pub fn is_hardware_backed(&self) -> bool {
        true
    }

    /// Get diagnostics information.
    pub fn diagnostics(&self) -> String {
        format!(
            "TpmWrappedEd25519Signer:\n\
             - Alias: {}\n\
             - Encrypted key path: {:?}\n\
             - Key exists: {}\n\
             - Key cached: {}\n\
             - Hardware backed: true (TPM-derived AES)",
            self.alias,
            self.encrypted_key_path,
            self.encrypted_key_path.exists(),
            self.cached_signing_key.lock().unwrap().is_some()
        )
    }

    fn get_or_load_signing_key(&self) -> Result<ed25519_dalek::SigningKey, KeyringError> {
        // Check cache first
        {
            let cache = self.cached_signing_key.lock().unwrap();
            if let Some(ref key) = *cache {
                return Ok(key.clone());
            }
        }

        // Load and decrypt from disk
        let encrypted = std::fs::read(&self.encrypted_key_path).map_err(|e| {
            error!("Failed to read encrypted key: {}", e);
            KeyringError::StorageFailed {
                reason: format!("Failed to read encrypted key: {}", e),
            }
        })?;

        // Derive AES key from TPM
        let aes_key = self.derive_aes_key()?;

        // Decrypt
        let decrypted = self.aes_decrypt(&aes_key, &encrypted)?;

        if decrypted.len() != ED25519_PRIVATE_KEY_SIZE {
            return Err(KeyringError::StorageFailed {
                reason: format!(
                    "Invalid decrypted key size: expected {}, got {}",
                    ED25519_PRIVATE_KEY_SIZE,
                    decrypted.len()
                ),
            });
        }

        let mut key_bytes = [0u8; ED25519_PRIVATE_KEY_SIZE];
        key_bytes.copy_from_slice(&decrypted);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);

        // Cache it
        {
            let mut cache = self.cached_signing_key.lock().unwrap();
            *cache = Some(signing_key.clone());
        }

        Ok(signing_key)
    }

    /// Derive an AES-256 key from TPM.
    ///
    /// Uses the TPM to sign a fixed challenge, then derives an AES key
    /// from the signature using HKDF. This binds the encryption to this
    /// specific TPM - a different TPM will produce a different signature.
    fn derive_aes_key(&self) -> Result<[u8; 32], KeyringError> {
        use sha2::{Digest, Sha256};

        debug!(alias = %self.alias, "Deriving AES key from TPM");

        // Fixed challenge for key derivation
        // This is public knowledge - security comes from TPM signature
        let challenge = b"CIRISVerify-TPM-KeyWrap-v1";

        // Create TPM context
        let mut context = super::detection::create_context()?;

        // Get or create primary storage key
        let primary_handle = super::keys::get_or_create_primary(&mut context)?;

        // Create a signing key under the primary
        let signing_key_handle = super::keys::create_signing_key(&mut context, primary_handle)?;

        // Hash the challenge
        let digest_bytes = Sha256::digest(challenge);

        // Sign with TPM
        let digest = tss_esapi::structures::Digest::try_from(&digest_bytes[..]).map_err(|e| {
            KeyringError::HardwareError {
                reason: format!("Failed to create digest: {}", e),
            }
        })?;

        // Create null validation ticket for external data
        let validation = super::signing::create_null_validation_ticket()?;

        let signature = context
            .execute_with_nullauth_session(|ctx| {
                ctx.sign(
                    signing_key_handle,
                    digest.clone(),
                    tss_esapi::structures::SignatureScheme::EcDsa {
                        hash_scheme: tss_esapi::structures::HashScheme::new(
                            tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
                        ),
                    },
                    validation.clone(),
                )
            })
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("TPM signing for key derivation failed: {}", e),
            })?;

        // Extract signature bytes
        let sig_bytes = super::signing::extract_ecdsa_signature(&signature)?;

        // Derive AES key using HKDF
        use hkdf::Hkdf;
        let hk = Hkdf::<Sha256>::new(None, &sig_bytes);
        let mut aes_key = [0u8; 32];
        hk.expand(b"aes-256-gcm-key", &mut aes_key)
            .map_err(|_| KeyringError::HardwareError {
                reason: "HKDF expansion failed".into(),
            })?;

        // Cleanup
        let _ = context.flush_context(signing_key_handle.into());
        let _ = context.flush_context(primary_handle.into());

        debug!(alias = %self.alias, "AES key derived from TPM signature");
        Ok(aes_key)
    }

    /// Encrypt data using AES-256-GCM.
    fn aes_encrypt(&self, key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, KeyringError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use rand_core::{OsRng, RngCore};

        // Generate random nonce
        let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Create cipher
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to create AES cipher: {}", e),
        })?;

        // Encrypt
        let ciphertext =
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|e| KeyringError::HardwareError {
                    reason: format!("AES encryption failed: {}", e),
                })?;

        // Format: nonce || ciphertext (includes tag)
        let mut result = Vec::with_capacity(AES_GCM_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data using AES-256-GCM.
    fn aes_decrypt(&self, key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, KeyringError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        if encrypted.len() < AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE {
            return Err(KeyringError::StorageFailed {
                reason: format!(
                    "Encrypted data too short: {} bytes (min {})",
                    encrypted.len(),
                    AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE
                ),
            });
        }

        // Split nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted.split_at(AES_GCM_NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Create cipher
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to create AES cipher: {}", e),
        })?;

        // Decrypt
        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
            error!(alias = %self.alias, "AES decryption failed (wrong TPM?): {}", e);
            KeyringError::HardwareError {
                reason: format!(
                    "AES decryption failed (key may be bound to different TPM): {}",
                    e
                ),
            }
        })?;

        Ok(plaintext)
    }
}

/// Stub implementation for non-TPM platforms
#[cfg(not(all(feature = "tpm", any(target_os = "linux", target_os = "windows"))))]
pub struct TpmWrappedEd25519Signer {
    _private: (),
}

#[cfg(not(all(feature = "tpm", any(target_os = "linux", target_os = "windows"))))]
impl TpmWrappedEd25519Signer {
    /// Create a new TPM-wrapped Ed25519 signer (stub - returns error).
    pub fn new(
        _alias: impl Into<String>,
        _key_dir: impl Into<std::path::PathBuf>,
    ) -> Result<Self, crate::error::KeyringError> {
        Err(crate::error::KeyringError::NoPlatformSupport)
    }

    /// Check if a TPM-wrapped key exists (stub - always false).
    pub fn key_exists(&self) -> bool {
        false
    }

    /// Import an Ed25519 key (stub - returns error).
    pub fn import_key(&self, _key_bytes: &[u8]) -> Result<(), crate::error::KeyringError> {
        Err(crate::error::KeyringError::NoPlatformSupport)
    }

    /// Get the Ed25519 public key (stub - returns error).
    pub fn public_key(&self) -> Result<Vec<u8>, crate::error::KeyringError> {
        Err(crate::error::KeyringError::NoPlatformSupport)
    }

    /// Sign data with the Ed25519 key (stub - returns error).
    pub fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, crate::error::KeyringError> {
        Err(crate::error::KeyringError::NoPlatformSupport)
    }

    /// Delete the TPM-wrapped key (stub - returns error).
    pub fn delete_key(&self) -> Result<(), crate::error::KeyringError> {
        Err(crate::error::KeyringError::NoPlatformSupport)
    }

    /// Check if hardware-backed (stub - always false).
    pub fn is_hardware_backed(&self) -> bool {
        false
    }

    /// Get diagnostics information (stub).
    pub fn diagnostics(&self) -> String {
        "TpmWrappedEd25519Signer: TPM not available on this platform".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpm_wrapped_signer_stub() {
        // On non-TPM platforms, creation should fail gracefully
        #[cfg(not(all(feature = "tpm", any(target_os = "linux", target_os = "windows"))))]
        {
            let result = TpmWrappedEd25519Signer::new("test", "/tmp");
            assert!(result.is_err());
        }
    }

    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    #[test]
    fn test_tpm_wrapped_signer_creation() {
        // This test just verifies the struct can be created
        // Actual TPM operations require hardware
        let result = TpmWrappedEd25519Signer::new("test_key", "/tmp/ciris_test_tpm");
        assert!(result.is_ok());
        let signer = result.unwrap();
        assert!(!signer.key_exists());
        assert!(signer.is_hardware_backed());
    }
}
