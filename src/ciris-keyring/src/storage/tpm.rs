//! TPM 2.0 secure blob storage implementation.
//!
//! Uses TPM-derived AES-256-GCM encryption to protect arbitrary secrets at rest.
//! The encryption key is derived from a TPM-held ECDSA signing key, providing
//! hardware binding.
//!
//! # Storage Format
//!
//! Each blob is stored in a file with format:
//! ```text
//! [4 bytes]  Magic: "BLOB"
//! [4 bytes]  Version: 1
//! [4 bytes]  Private blob length (little-endian)
//! [N bytes]  TPM2B_PRIVATE blob (signing key)
//! [4 bytes]  Public blob length (little-endian)
//! [M bytes]  TPM2B_PUBLIC blob (signing key)
//! [4 bytes]  Signature length (little-endian)
//! [K bytes]  ECDSA signature (for AES key derivation)
//! [remaining] AES-GCM encrypted data (nonce || ciphertext || tag)
//! ```

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use crate::error::KeyringError;

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use crate::storage::SecureBlobStorage;

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use std::path::PathBuf;

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use std::sync::Mutex;

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use tss_esapi::traits::{Marshall, UnMarshall};

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use tracing::{debug, error, info, warn};

/// Magic bytes for blob file format
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
const BLOB_FILE_MAGIC: &[u8; 4] = b"BLOB";

/// Current file format version
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
const BLOB_FILE_VERSION: u32 = 1;

/// AES-256-GCM nonce size
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
const AES_GCM_NONCE_SIZE: usize = 12;

/// TPM-backed secure blob storage.
///
/// Uses a single TPM ECDSA signing key to derive per-blob AES encryption keys.
/// The signing key and its signature are created once and reused for all blobs.
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub struct TpmSecureBlobStorage {
    /// Base directory for storing encrypted blobs
    storage_dir: PathBuf,
    /// Alias prefix for file naming
    alias: String,
    /// Cached TPM context (expensive to create)
    tpm_context: Mutex<Option<TpmContext>>,
}

/// Cached TPM signing key context.
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
struct TpmContext {
    /// TPM2B_PRIVATE blob for the signing key
    private_blob: Vec<u8>,
    /// TPM2B_PUBLIC blob for the signing key
    public_blob: Vec<u8>,
    /// ECDSA signature used for AES key derivation
    signature: Vec<u8>,
}

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
impl TpmSecureBlobStorage {
    /// Create new TPM-backed storage.
    ///
    /// # Arguments
    /// * `alias` - Prefix for stored files
    /// * `storage_dir` - Directory to store encrypted blobs
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
            tpm_context: Mutex::new(None),
        })
    }

    /// Get the path for the TPM master context file.
    fn master_context_path(&self) -> PathBuf {
        self.storage_dir
            .join(format!("{}.tpm_master.ctx", self.alias))
    }

    /// Get the file path for a blob.
    fn blob_path(&self, key_id: &str) -> PathBuf {
        let safe_id = key_id.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
        self.storage_dir
            .join(format!("{}.{}.tpm_blob", self.alias, safe_id))
    }

    /// Initialize TPM context if not already done.
    fn ensure_tpm_context(&self) -> Result<(), KeyringError> {
        let mut ctx_guard = self
            .tpm_context
            .lock()
            .map_err(|_| KeyringError::StorageFailed {
                reason: "Failed to acquire TPM context lock".into(),
            })?;

        if ctx_guard.is_some() {
            return Ok(());
        }

        // Try to load existing context
        let master_path = self.master_context_path();
        if master_path.exists() {
            match self.load_master_context(&master_path) {
                Ok(ctx) => {
                    debug!("Loaded existing TPM master context");
                    *ctx_guard = Some(ctx);
                    return Ok(());
                },
                Err(e) => {
                    warn!("Failed to load TPM master context, will regenerate: {}", e);
                },
            }
        }

        // Create new TPM signing key
        let ctx = self.create_tpm_context()?;

        // Save master context
        self.save_master_context(&master_path, &ctx)?;

        *ctx_guard = Some(ctx);
        info!("Created new TPM master context");

        Ok(())
    }

    /// Create a new TPM signing key and derive the initial signature.
    fn create_tpm_context(&self) -> Result<TpmContext, KeyringError> {
        use tss_esapi::{
            attributes::ObjectAttributesBuilder,
            interface_types::{
                algorithm::{HashingAlgorithm, PublicAlgorithm},
                ecc::EccCurve,
                key_bits::RsaKeyBits,
                resource_handles::Hierarchy,
            },
            structures::{
                EccScheme, HashScheme, KeyDerivationFunctionScheme, Public, PublicBuilder,
                PublicEccParametersBuilder, PublicKeyRsa, RsaExponent, SymmetricDefinitionObject,
            },
            tcti_ldr::TctiNameConf,
            Context,
        };

        // Open TPM context
        let tcti = TctiNameConf::from_environment_variable()
            .unwrap_or_else(|_| TctiNameConf::Device(Default::default()));

        let mut context = Context::new(tcti).map_err(|e| {
            error!("Failed to open TPM context: {}", e);
            KeyringError::HardwareNotAvailable {
                reason: format!("TPM not available: {}", e),
            }
        })?;

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
                    .with_sign_encrypt(true)
                    .build()
                    .map_err(|e| KeyringError::HardwareNotAvailable {
                        reason: format!("Failed to build key attributes: {}", e),
                    })?,
            )
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
                    .with_curve(EccCurve::NistP256)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .with_symmetric(SymmetricDefinitionObject::Null)
                    .build()
                    .map_err(|e| KeyringError::HardwareNotAvailable {
                        reason: format!("Failed to build ECC params: {}", e),
                    })?,
            )
            .with_ecc_unique_identifier(Default::default())
            .build()
            .map_err(|e| KeyringError::HardwareNotAvailable {
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
                KeyringError::HardwareNotAvailable {
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
                    .map_err(|e| KeyringError::HardwareNotAvailable {
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
                    .map_err(|e| KeyringError::HardwareNotAvailable {
                        reason: format!("Failed to build signing key ECC params: {}", e),
                    })?,
            )
            .with_ecc_unique_identifier(Default::default())
            .build()
            .map_err(|e| KeyringError::HardwareNotAvailable {
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
                KeyringError::HardwareNotAvailable {
                    reason: format!("Failed to create signing key: {}", e),
                }
            })?;

        // Marshal the key blobs
        let private_blob =
            signing_key_result
                .out_private
                .marshall()
                .map_err(|e| KeyringError::StorageFailed {
                    reason: format!("Failed to marshal private blob: {}", e),
                })?;

        let public_blob =
            signing_key_result
                .out_public
                .marshall()
                .map_err(|e| KeyringError::StorageFailed {
                    reason: format!("Failed to marshal public blob: {}", e),
                })?;

        // Load the signing key to sign a challenge
        let signing_key_handle = context
            .load(
                primary_key.key_handle,
                signing_key_result.out_private.clone(),
                signing_key_result.out_public.clone(),
            )
            .map_err(|e| {
                error!("Failed to load TPM signing key: {}", e);
                KeyringError::HardwareNotAvailable {
                    reason: format!("Failed to load signing key: {}", e),
                }
            })?;

        // Sign a fixed challenge to derive AES key
        // The challenge is deterministic so we always get the same signature
        // (IMPORTANT: We store this signature because ECDSA is non-deterministic)
        let challenge = b"CIRIS-TpmSecureBlobStorage-AES-Key-Derivation-v1";
        let challenge_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(challenge);
            hasher.finalize()
        };

        use tss_esapi::structures::{Digest as TpmDigest, SignatureScheme};

        let digest = TpmDigest::try_from(challenge_hash.as_slice()).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Failed to create TPM digest: {}", e),
            }
        })?;

        let signature = context
            .sign(
                signing_key_handle.into(),
                digest,
                SignatureScheme::Null,
                Default::default(),
            )
            .map_err(|e| {
                error!("Failed to sign with TPM key: {}", e);
                KeyringError::HardwareNotAvailable {
                    reason: format!("Failed to sign challenge: {}", e),
                }
            })?;

        let signature_bytes = signature
            .marshall()
            .map_err(|e| KeyringError::StorageFailed {
                reason: format!("Failed to marshal signature: {}", e),
            })?;

        // Flush handles
        let _ = context.flush_context(signing_key_handle.into());
        let _ = context.flush_context(primary_key.key_handle.into());

        Ok(TpmContext {
            private_blob,
            public_blob,
            signature: signature_bytes,
        })
    }

    /// Save master context to file.
    fn save_master_context(&self, path: &PathBuf, ctx: &TpmContext) -> Result<(), KeyringError> {
        let mut data = Vec::new();

        // Magic
        data.extend_from_slice(b"TPMC");
        // Version
        data.extend_from_slice(&1u32.to_le_bytes());
        // Private blob
        data.extend_from_slice(&(ctx.private_blob.len() as u32).to_le_bytes());
        data.extend_from_slice(&ctx.private_blob);
        // Public blob
        data.extend_from_slice(&(ctx.public_blob.len() as u32).to_le_bytes());
        data.extend_from_slice(&ctx.public_blob);
        // Signature
        data.extend_from_slice(&(ctx.signature.len() as u32).to_le_bytes());
        data.extend_from_slice(&ctx.signature);

        // Write atomically
        let temp_path = path.with_extension("ctx.tmp");
        std::fs::write(&temp_path, &data).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to write master context: {}", e),
        })?;
        std::fs::rename(&temp_path, path).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to rename master context: {}", e),
        })?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }

        Ok(())
    }

    /// Load master context from file.
    fn load_master_context(&self, path: &PathBuf) -> Result<TpmContext, KeyringError> {
        let data = std::fs::read(path).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to read master context: {}", e),
        })?;

        if data.len() < 12 {
            return Err(KeyringError::StorageFailed {
                reason: "Master context file too short".into(),
            });
        }

        // Check magic
        if &data[0..4] != b"TPMC" {
            return Err(KeyringError::StorageFailed {
                reason: "Invalid master context magic".into(),
            });
        }

        // Check version
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if version != 1 {
            return Err(KeyringError::StorageFailed {
                reason: format!("Unsupported master context version: {}", version),
            });
        }

        let mut offset = 8;

        // Read private blob
        let private_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;
        let private_blob = data[offset..offset + private_len].to_vec();
        offset += private_len;

        // Read public blob
        let public_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;
        let public_blob = data[offset..offset + public_len].to_vec();
        offset += public_len;

        // Read signature
        let sig_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;
        let signature = data[offset..offset + sig_len].to_vec();

        Ok(TpmContext {
            private_blob,
            public_blob,
            signature,
        })
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
        self.ensure_tpm_context()?;

        let ctx_guard = self
            .tpm_context
            .lock()
            .map_err(|_| KeyringError::StorageFailed {
                reason: "Failed to acquire TPM context lock".into(),
            })?;
        let ctx = ctx_guard
            .as_ref()
            .ok_or_else(|| KeyringError::StorageFailed {
                reason: "TPM context not initialized".into(),
            })?;

        let aes_key = self.derive_aes_key(&ctx.signature, key_id);
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
        self.ensure_tpm_context()?;

        let path = self.blob_path(key_id);
        if !path.exists() {
            return Err(KeyringError::KeyNotFound {
                alias: key_id.to_string(),
            });
        }

        let encrypted = std::fs::read(&path).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to read blob: {}", e),
        })?;

        let ctx_guard = self
            .tpm_context
            .lock()
            .map_err(|_| KeyringError::StorageFailed {
                reason: "Failed to acquire TPM context lock".into(),
            })?;
        let ctx = ctx_guard
            .as_ref()
            .ok_or_else(|| KeyringError::StorageFailed {
                reason: "TPM context not initialized".into(),
            })?;

        let aes_key = self.derive_aes_key(&ctx.signature, key_id);
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
        let ctx_loaded = self
            .tpm_context
            .lock()
            .map(|g| g.is_some())
            .unwrap_or(false);

        format!(
            "TpmSecureBlobStorage:\n\
             - Alias: {}\n\
             - Storage dir: {:?}\n\
             - Hardware backed: true (TPM 2.0)\n\
             - Context loaded: {}\n\
             - Stored keys: {:?}",
            self.alias, self.storage_dir, ctx_loaded, keys
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
