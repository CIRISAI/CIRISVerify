//! TPM 2.0 secure blob storage implementation.
//!
//! Uses TPM-derived AES-256-GCM encryption to protect arbitrary secrets at rest.
//! The encryption key is derived from a TPM-held ECDSA signing key, providing
//! hardware binding.

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use crate::error::KeyringError;

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use crate::storage::SecureBlobStorage;

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use std::path::PathBuf;

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use std::sync::Mutex;

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use tracing::{debug, error, info, warn};

/// AES-256-GCM nonce size
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
const AES_GCM_NONCE_SIZE: usize = 12;

/// TPM-backed secure blob storage.
///
/// Uses a TPM ECDSA signing key to derive per-blob AES encryption keys.
/// The signing key signature is created once and reused for all blobs.
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub struct TpmSecureBlobStorage {
    /// Base directory for storing encrypted blobs
    storage_dir: PathBuf,
    /// Alias prefix for file naming
    alias: String,
    /// Cached signature for AES key derivation
    cached_signature: Mutex<Option<Vec<u8>>>,
}

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
impl TpmSecureBlobStorage {
    /// Create new TPM-backed storage.
    pub fn new(
        alias: impl Into<String>,
        storage_dir: impl Into<PathBuf>,
    ) -> Result<Self, KeyringError> {
        let alias = alias.into();
        let storage_dir = storage_dir.into();

        // Ensure storage directory exists
        std::fs::create_dir_all(&storage_dir).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to create storage directory: {}", e),
        })?;

        info!(
            alias = %alias,
            storage_dir = ?storage_dir,
            "TpmSecureBlobStorage initialized"
        );

        Ok(Self {
            storage_dir,
            alias,
            cached_signature: Mutex::new(None),
        })
    }

    /// Get the file path for a blob.
    fn blob_path(&self, key_id: &str) -> PathBuf {
        let safe_id = key_id.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
        self.storage_dir
            .join(format!("{}.{}.tpm_blob", self.alias, safe_id))
    }

    /// Get the file path for the cached signature.
    fn signature_path(&self) -> PathBuf {
        self.storage_dir.join(format!("{}.tpm_sig.bin", self.alias))
    }

    /// Get or create the TPM-derived signature for AES key derivation.
    fn get_or_create_signature(&self) -> Result<Vec<u8>, KeyringError> {
        // Check cache first
        {
            let guard = self
                .cached_signature
                .lock()
                .map_err(|_| KeyringError::StorageFailed {
                    reason: "Failed to acquire signature lock".into(),
                })?;
            if let Some(sig) = guard.as_ref() {
                return Ok(sig.clone());
            }
        }

        // Try to load from file
        let sig_path = self.signature_path();
        if sig_path.exists() {
            match std::fs::read(&sig_path) {
                Ok(sig) if sig.len() >= 64 => {
                    debug!("Loaded cached TPM signature from disk");
                    let mut guard =
                        self.cached_signature
                            .lock()
                            .map_err(|_| KeyringError::StorageFailed {
                                reason: "Failed to acquire signature lock".into(),
                            })?;
                    *guard = Some(sig.clone());
                    return Ok(sig);
                },
                _ => {
                    warn!("Invalid cached signature, regenerating");
                },
            }
        }

        // Create new signature using TPM
        let signature = self.create_tpm_signature()?;

        // Cache to disk
        if let Err(e) = std::fs::write(&sig_path, &signature) {
            warn!("Failed to cache TPM signature: {}", e);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&sig_path, perms);
        }

        // Cache in memory
        {
            let mut guard =
                self.cached_signature
                    .lock()
                    .map_err(|_| KeyringError::StorageFailed {
                        reason: "Failed to acquire signature lock".into(),
                    })?;
            *guard = Some(signature.clone());
        }

        info!("Created and cached new TPM signature for blob storage");
        Ok(signature)
    }

    /// Create a TPM signature for AES key derivation.
    fn create_tpm_signature(&self) -> Result<Vec<u8>, KeyringError> {
        use crate::platform::tpm::{create_context, create_null_validation_ticket};
        use tss_esapi::{
            attributes::ObjectAttributesBuilder,
            interface_types::{
                algorithm::{HashingAlgorithm, PublicAlgorithm},
                ecc::EccCurve,
                resource_handles::Hierarchy,
            },
            structures::{
                Digest as TpmDigest, EccScheme, HashScheme, KeyDerivationFunctionScheme,
                PublicBuilder, PublicEccParametersBuilder, SignatureScheme,
                SymmetricDefinitionObject,
            },
        };

        // Open TPM context
        let mut context = create_context()?;

        // Create primary key under owner hierarchy
        let primary_key_template = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(
                ObjectAttributesBuilder::new()
                    .with_fixed_tpm(true)
                    .with_fixed_parent(true)
                    .with_sensitive_data_origin(true)
                    .with_user_with_auth(true)
                    .with_decrypt(true)
                    .with_restricted(true)
                    .build()
                    .map_err(|e| KeyringError::HardwareError {
                        reason: format!("Failed to build key attributes: {}", e),
                    })?,
            )
            .with_ecc_parameters(
                PublicEccParametersBuilder::new_restricted_decryption_key(
                    SymmetricDefinitionObject::AES_256_CFB,
                    EccCurve::NistP256,
                )
                .build()
                .map_err(|e| KeyringError::HardwareError {
                    reason: format!("Failed to build ECC params: {}", e),
                })?,
            )
            .with_ecc_unique_identifier(Default::default())
            .build()
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to build key template: {}", e),
            })?;

        let primary_key = context
            .create_primary(
                Hierarchy::Owner,
                primary_key_template,
                None,
                None,
                None,
                None,
            )
            .map_err(|e| {
                error!("Failed to create TPM primary key: {}", e);
                KeyringError::HardwareError {
                    reason: format!("Failed to create primary key: {}", e),
                }
            })?;

        // Create signing key under primary
        let signing_key_template = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(
                ObjectAttributesBuilder::new()
                    .with_fixed_tpm(true)
                    .with_fixed_parent(true)
                    .with_sensitive_data_origin(true)
                    .with_user_with_auth(true)
                    .with_sign_encrypt(true)
                    .build()
                    .map_err(|e| KeyringError::HardwareError {
                        reason: format!("Failed to build signing key attributes: {}", e),
                    })?,
            )
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
                    .with_curve(EccCurve::NistP256)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .with_symmetric(SymmetricDefinitionObject::Null)
                    .build()
                    .map_err(|e| KeyringError::HardwareError {
                        reason: format!("Failed to build signing key ECC params: {}", e),
                    })?,
            )
            .with_ecc_unique_identifier(Default::default())
            .build()
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to build signing key template: {}", e),
            })?;

        let signing_key_result = context
            .create(
                primary_key.key_handle,
                signing_key_template,
                None,
                None,
                None,
                None,
            )
            .map_err(|e| {
                error!("Failed to create TPM signing key: {}", e);
                KeyringError::HardwareError {
                    reason: format!("Failed to create signing key: {}", e),
                }
            })?;

        // Load the signing key
        let signing_key_handle = context
            .load(
                primary_key.key_handle,
                signing_key_result.out_private,
                signing_key_result.out_public,
            )
            .map_err(|e| {
                error!("Failed to load TPM signing key: {}", e);
                KeyringError::HardwareError {
                    reason: format!("Failed to load signing key: {}", e),
                }
            })?;

        // Sign a fixed challenge to derive AES key
        let challenge = b"CIRIS-TpmSecureBlobStorage-AES-Key-Derivation-v1";
        let challenge_hash = {
            use sha2::{Digest, Sha256};
            Sha256::digest(challenge)
        };

        let digest = TpmDigest::try_from(challenge_hash.as_slice()).map_err(|e| {
            KeyringError::HardwareError {
                reason: format!("Failed to create TPM digest: {}", e),
            }
        })?;

        let validation_ticket = create_null_validation_ticket()?;

        let signature = context
            .sign(
                signing_key_handle.into(),
                digest,
                SignatureScheme::Null,
                validation_ticket,
            )
            .map_err(|e| {
                error!("Failed to sign with TPM key: {}", e);
                KeyringError::HardwareError {
                    reason: format!("Failed to sign challenge: {}", e),
                }
            })?;

        // Extract signature bytes using the helper
        let signature_bytes = crate::platform::tpm::extract_ecdsa_signature(&signature)?;

        // Flush handles
        let _ = context.flush_context(signing_key_handle.into());
        let _ = context.flush_context(primary_key.key_handle.into());

        Ok(signature_bytes)
    }

    /// Derive AES key from signature and key_id.
    fn derive_aes_key(&self, signature: &[u8], key_id: &str) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(Some(b"CIRIS-TPM-blob-v1"), signature);
        let mut key = [0u8; 32];
        hkdf.expand(key_id.as_bytes(), &mut key)
            .expect("HKDF expansion should not fail");
        key
    }

    /// Encrypt data with AES-256-GCM.
    #[allow(deprecated)]
    fn encrypt(&self, key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, KeyringError> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use rand::RngCore;

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to create cipher: {}", e),
        })?;

        let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext =
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|e| KeyringError::StorageFailed {
                    reason: format!("Encryption failed: {}", e),
                })?;

        let mut result = Vec::with_capacity(AES_GCM_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data with AES-256-GCM.
    #[allow(deprecated)]
    fn decrypt(&self, key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, KeyringError> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

        if encrypted.len() < AES_GCM_NONCE_SIZE {
            return Err(KeyringError::StorageFailed {
                reason: "Encrypted data too short".into(),
            });
        }

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to create cipher: {}", e),
        })?;

        let nonce = Nonce::from_slice(&encrypted[..AES_GCM_NONCE_SIZE]);
        let ciphertext = &encrypted[AES_GCM_NONCE_SIZE..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| KeyringError::StorageFailed {
                reason: format!("Decryption failed: {}", e),
            })
    }
}

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
impl SecureBlobStorage for TpmSecureBlobStorage {
    fn store(&self, key_id: &str, data: &[u8]) -> Result<(), KeyringError> {
        let signature = self.get_or_create_signature()?;
        let aes_key = self.derive_aes_key(&signature, key_id);
        let encrypted = self.encrypt(&aes_key, data)?;

        let path = self.blob_path(key_id);

        // Write atomically
        let temp_path = path.with_extension("tpm_blob.tmp");
        std::fs::write(&temp_path, &encrypted).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to write blob: {}", e),
        })?;
        std::fs::rename(&temp_path, &path).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to rename blob: {}", e),
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&path, perms);
        }

        debug!(key_id = %key_id, "Stored TPM-protected blob");
        Ok(())
    }

    fn load(&self, key_id: &str) -> Result<Vec<u8>, KeyringError> {
        let path = self.blob_path(key_id);
        if !path.exists() {
            return Err(KeyringError::KeyNotFound {
                alias: key_id.to_string(),
            });
        }

        let encrypted = std::fs::read(&path).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to read blob: {}", e),
        })?;

        let signature = self.get_or_create_signature()?;
        let aes_key = self.derive_aes_key(&signature, key_id);
        self.decrypt(&aes_key, &encrypted)
    }

    fn exists(&self, key_id: &str) -> bool {
        self.blob_path(key_id).exists()
    }

    fn delete(&self, key_id: &str) -> Result<(), KeyringError> {
        let path = self.blob_path(key_id);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| KeyringError::StorageFailed {
                reason: format!("Failed to delete blob: {}", e),
            })?;
            info!(key_id = %key_id, "Deleted TPM-protected blob");
        }
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<String>, KeyringError> {
        let prefix = format!("{}.", self.alias);
        let suffix = ".tpm_blob";

        let mut keys = Vec::new();

        let entries =
            std::fs::read_dir(&self.storage_dir).map_err(|e| KeyringError::StorageFailed {
                reason: format!("Failed to read storage directory: {}", e),
            })?;

        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with(&prefix) && name.ends_with(suffix) {
                    let key_id = &name[prefix.len()..name.len() - suffix.len()];
                    keys.push(key_id.to_string());
                }
            }
        }

        Ok(keys)
    }

    fn is_hardware_backed(&self) -> bool {
        true
    }

    fn diagnostics(&self) -> String {
        let keys = self.list_keys().unwrap_or_default();
        let has_sig = self.signature_path().exists();

        format!(
            "TpmSecureBlobStorage:\n\
             - Alias: {}\n\
             - Storage dir: {:?}\n\
             - Hardware backed: true (TPM 2.0)\n\
             - Signature cached: {}\n\
             - Stored keys: {:?}",
            self.alias, self.storage_dir, has_sig, keys
        )
    }
}

// Stub for non-TPM platforms
#[cfg(not(all(feature = "tpm", any(target_os = "linux", target_os = "windows"))))]
pub struct TpmSecureBlobStorage;

#[cfg(not(all(feature = "tpm", any(target_os = "linux", target_os = "windows"))))]
impl TpmSecureBlobStorage {
    pub fn new(
        _alias: impl Into<String>,
        _storage_dir: impl Into<std::path::PathBuf>,
    ) -> Result<Self, crate::error::KeyringError> {
        Err(crate::error::KeyringError::HardwareNotAvailable {
            reason: "TPM not available on this platform".into(),
        })
    }
}
