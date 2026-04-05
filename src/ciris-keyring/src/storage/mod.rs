//! Generic secure blob storage abstraction.
//!
//! Platform-specific implementations:
//! - `TpmSecureBlobStorage` - TPM 2.0 (Linux/Windows, requires `tpm` feature)
//! - `AndroidKeystoreStorage` - Android Keystore (requires `android` feature)
//! - `SecureEnclaveStorage` - iOS Secure Enclave (requires `ios` feature)
//!
//! This module provides a platform-agnostic interface for storing arbitrary
//! secret material (keys, seeds, etc.) with hardware-backed protection where
//! available.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    SecureBlobStorage Trait                       │
//! │  store(key_id, data) -> Result<()>                              │
//! │  load(key_id) -> Result<Vec<u8>>                                │
//! │  exists(key_id) -> bool                                         │
//! │  delete(key_id) -> Result<()>                                   │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!          ┌──────────────────┼──────────────────┐
//!          ▼                  ▼                  ▼
//!    ┌──────────┐      ┌──────────┐      ┌──────────┐
//!    │   TPM    │      │ Android  │      │   iOS    │
//!    │ Storage  │      │ Keystore │      │   SE     │
//!    └──────────┘      └──────────┘      └──────────┘
//! ```
//!
//! # Key IDs
//!
//! Key IDs are namespaced strings that identify stored secrets:
//! - `identity.ed25519` - Ed25519 signing key seed
//! - `identity.wallet_seed` - secp256k1 wallet derivation seed
//! - `identity.pqc_seed` - Post-quantum key seed (future)
//!
//! # Example
//!
//! ```rust,ignore
//! use ciris_keyring::storage::{SecureBlobStorage, create_platform_storage};
//!
//! let storage = create_platform_storage("my-agent", "/path/to/keys")?;
//!
//! // Store a secret
//! storage.store("identity.wallet_seed", &seed_bytes)?;
//!
//! // Load it back
//! let loaded = storage.load("identity.wallet_seed")?;
//!
//! // Check existence
//! if storage.exists("identity.wallet_seed") {
//!     storage.delete("identity.wallet_seed")?;
//! }
//! ```

// Platform-specific implementations
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub mod tpm;

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub use tpm::TpmSecureBlobStorage;

// TODO: Enable when JNI issues are resolved
// #[cfg(target_os = "android")]
// pub mod android;
//
// #[cfg(target_os = "android")]
// pub use android::AndroidKeystoreSecureBlobStorage;

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub mod ios;

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub use ios::SecureEnclaveSecureBlobStorage;

use crate::error::KeyringError;
use std::path::PathBuf;

/// Trait for platform-agnostic secure blob storage.
///
/// Implementations provide hardware-backed protection where available
/// (TPM, Secure Enclave, Android Keystore) with software fallback.
pub trait SecureBlobStorage: Send + Sync {
    /// Store a secret blob with the given key ID.
    ///
    /// Overwrites any existing data for this key ID.
    ///
    /// # Arguments
    /// * `key_id` - Unique identifier for this secret (e.g., "identity.wallet_seed")
    /// * `data` - Raw secret bytes to store
    ///
    /// # Errors
    /// Returns error if storage fails (hardware unavailable, I/O error, etc.)
    fn store(&self, key_id: &str, data: &[u8]) -> Result<(), KeyringError>;

    /// Load a secret blob by key ID.
    ///
    /// # Arguments
    /// * `key_id` - Unique identifier for the secret
    ///
    /// # Returns
    /// The raw secret bytes, or error if not found or decryption fails.
    fn load(&self, key_id: &str) -> Result<Vec<u8>, KeyringError>;

    /// Check if a secret exists for the given key ID.
    fn exists(&self, key_id: &str) -> bool;

    /// Delete a secret by key ID.
    ///
    /// # Errors
    /// Returns error if deletion fails. Returns Ok(()) if key doesn't exist.
    fn delete(&self, key_id: &str) -> Result<(), KeyringError>;

    /// List all stored key IDs.
    fn list_keys(&self) -> Result<Vec<String>, KeyringError>;

    /// Returns true if this storage is hardware-backed.
    fn is_hardware_backed(&self) -> bool;

    /// Get diagnostics information about this storage.
    fn diagnostics(&self) -> String;
}

/// Storage backend type, determined at runtime based on platform capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackend {
    /// TPM 2.0 (Linux/Windows)
    Tpm,
    /// Android Keystore / StrongBox
    AndroidKeystore,
    /// iOS/macOS Secure Enclave
    SecureEnclave,
    /// Software-only (encrypted with derived key)
    Software,
}

impl std::fmt::Display for StorageBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageBackend::Tpm => write!(f, "TPM 2.0"),
            StorageBackend::AndroidKeystore => write!(f, "Android Keystore"),
            StorageBackend::SecureEnclave => write!(f, "Secure Enclave"),
            StorageBackend::Software => write!(f, "Software"),
        }
    }
}

// =============================================================================
// Software Storage Implementation
// =============================================================================

/// Software-only secure storage using AES-256-GCM.
///
/// Keys are encrypted with a password-derived key (Argon2id) and stored
/// in individual files. This is the fallback when hardware is unavailable.
pub struct SoftwareSecureBlobStorage {
    /// Base directory for storing encrypted blobs
    storage_dir: PathBuf,
    /// Alias prefix for file naming
    alias: String,
    /// Cached encryption key (derived from password or generated)
    encryption_key: std::sync::RwLock<Option<[u8; 32]>>,
}

impl SoftwareSecureBlobStorage {
    /// Create new software storage.
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

        tracing::info!(
            alias = %alias,
            storage_dir = ?storage_dir,
            "SoftwareSecureBlobStorage initialized"
        );

        Ok(Self {
            storage_dir,
            alias,
            encryption_key: std::sync::RwLock::new(None),
        })
    }

    /// Initialize with a master key (32 bytes).
    ///
    /// All blobs will be encrypted with keys derived from this master key.
    pub fn init_with_master_key(&self, master_key: &[u8; 32]) -> Result<(), KeyringError> {
        let mut key = self
            .encryption_key
            .write()
            .map_err(|_| KeyringError::StorageFailed {
                reason: "Failed to acquire encryption key lock".into(),
            })?;
        *key = Some(*master_key);
        Ok(())
    }

    /// Generate and store a random master key.
    ///
    /// The master key is stored in a special file and used to derive
    /// per-blob encryption keys.
    pub fn init_with_random_key(&self) -> Result<(), KeyringError> {
        use rand::RngCore;

        let mut master_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut master_key);

        // Store the master key (this is the weak point for software-only mode)
        let master_key_path = self.storage_dir.join(format!("{}.master.key", self.alias));
        std::fs::write(&master_key_path, master_key).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to write master key: {}", e),
        })?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&master_key_path, perms);
        }

        self.init_with_master_key(&master_key)?;

        // Zero the local copy
        master_key.iter_mut().for_each(|b| *b = 0);

        tracing::info!("Generated and stored random master key");
        Ok(())
    }

    /// Load master key from storage if it exists.
    pub fn try_load_master_key(&self) -> Result<bool, KeyringError> {
        let master_key_path = self.storage_dir.join(format!("{}.master.key", self.alias));

        if !master_key_path.exists() {
            return Ok(false);
        }

        let mut master_key_bytes =
            std::fs::read(&master_key_path).map_err(|e| KeyringError::StorageFailed {
                reason: format!("Failed to read master key: {}", e),
            })?;

        if master_key_bytes.len() != 32 {
            return Err(KeyringError::StorageFailed {
                reason: format!("Invalid master key length: {}", master_key_bytes.len()),
            });
        }

        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&master_key_bytes);

        // Zero the read bytes
        master_key_bytes.iter_mut().for_each(|b| *b = 0);

        self.init_with_master_key(&master_key)?;

        // Zero local copy
        master_key.iter_mut().for_each(|b| *b = 0);

        tracing::debug!("Loaded existing master key");
        Ok(true)
    }

    /// Get or initialize the master key.
    fn ensure_master_key(&self) -> Result<[u8; 32], KeyringError> {
        // Check if already initialized
        {
            let key = self
                .encryption_key
                .read()
                .map_err(|_| KeyringError::StorageFailed {
                    reason: "Failed to acquire encryption key lock".into(),
                })?;
            if let Some(k) = *key {
                return Ok(k);
            }
        }

        // Try to load existing key
        if self.try_load_master_key()? {
            let key = self
                .encryption_key
                .read()
                .map_err(|_| KeyringError::StorageFailed {
                    reason: "Failed to acquire encryption key lock".into(),
                })?;
            return key.ok_or_else(|| KeyringError::StorageFailed {
                reason: "Master key not initialized after load".into(),
            });
        }

        // Generate new key
        self.init_with_random_key()?;

        let key = self
            .encryption_key
            .read()
            .map_err(|_| KeyringError::StorageFailed {
                reason: "Failed to acquire encryption key lock".into(),
            })?;
        key.ok_or_else(|| KeyringError::StorageFailed {
            reason: "Master key not initialized after generation".into(),
        })
    }

    /// Derive a per-blob encryption key from the master key and key_id.
    fn derive_blob_key(&self, master_key: &[u8; 32], key_id: &str) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(Some(b"CIRIS-blob-storage-v1"), master_key);
        let mut derived = [0u8; 32];
        hkdf.expand(key_id.as_bytes(), &mut derived)
            .expect("HKDF expansion should not fail for 32 bytes");
        derived
    }

    /// Get the file path for a key ID.
    fn blob_path(&self, key_id: &str) -> PathBuf {
        // Sanitize key_id for filesystem
        let safe_id = key_id.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
        self.storage_dir
            .join(format!("{}.{}.blob", self.alias, safe_id))
    }

    /// Encrypt data with AES-256-GCM.
    #[allow(deprecated)] // from_slice deprecation warning from aes-gcm
    fn encrypt(&self, key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, KeyringError> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use rand::RngCore;

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to create cipher: {}", e),
        })?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext =
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|e| KeyringError::StorageFailed {
                    reason: format!("Encryption failed: {}", e),
                })?;

        // Format: nonce (12) || ciphertext (includes tag)
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data with AES-256-GCM.
    /// Decrypt data with AES-256-GCM.
    #[allow(deprecated)] // from_slice deprecation warning from aes-gcm
    fn decrypt(&self, key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, KeyringError> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

        if encrypted.len() < 12 {
            return Err(KeyringError::StorageFailed {
                reason: "Encrypted data too short".into(),
            });
        }

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to create cipher: {}", e),
        })?;

        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext = &encrypted[12..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| KeyringError::StorageFailed {
                reason: format!("Decryption failed: {}", e),
            })
    }
}

impl SecureBlobStorage for SoftwareSecureBlobStorage {
    fn store(&self, key_id: &str, data: &[u8]) -> Result<(), KeyringError> {
        let master_key = self.ensure_master_key()?;
        let blob_key = self.derive_blob_key(&master_key, key_id);
        let encrypted = self.encrypt(&blob_key, data)?;

        let path = self.blob_path(key_id);

        // Write atomically
        let temp_path = path.with_extension("blob.tmp");
        std::fs::write(&temp_path, &encrypted).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to write blob: {}", e),
        })?;
        std::fs::rename(&temp_path, &path).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to rename blob: {}", e),
        })?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&path, perms);
        }

        tracing::debug!(key_id = %key_id, path = ?path, "Stored encrypted blob");
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

        let master_key = self.ensure_master_key()?;
        let blob_key = self.derive_blob_key(&master_key, key_id);
        let decrypted = self.decrypt(&blob_key, &encrypted)?;

        tracing::debug!(key_id = %key_id, "Loaded encrypted blob");
        Ok(decrypted)
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
            tracing::info!(key_id = %key_id, "Deleted blob");
        }

        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<String>, KeyringError> {
        let prefix = format!("{}.", self.alias);
        let suffix = ".blob";

        let mut keys = Vec::new();

        let entries =
            std::fs::read_dir(&self.storage_dir).map_err(|e| KeyringError::StorageFailed {
                reason: format!("Failed to read storage directory: {}", e),
            })?;

        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with(&prefix) && name.ends_with(suffix) {
                    // Extract key_id from filename
                    let key_id = &name[prefix.len()..name.len() - suffix.len()];
                    keys.push(key_id.to_string());
                }
            }
        }

        Ok(keys)
    }

    fn is_hardware_backed(&self) -> bool {
        false
    }

    fn diagnostics(&self) -> String {
        let keys = self.list_keys().unwrap_or_default();
        format!(
            "SoftwareSecureBlobStorage:\n\
             - Alias: {}\n\
             - Storage dir: {:?}\n\
             - Hardware backed: false\n\
             - Stored keys: {:?}",
            self.alias, self.storage_dir, keys
        )
    }
}

// =============================================================================
// Factory Function
// =============================================================================

/// Create the best available secure storage for the current platform.
///
/// Tries hardware-backed storage first (TPM on Linux/Windows), falls back to software.
///
/// # Arguments
/// * `alias` - Prefix for stored secrets
/// * `storage_dir` - Directory for file-based storage
///
/// # Returns
/// A boxed `SecureBlobStorage` implementation.
pub fn create_platform_storage(
    alias: impl Into<String>,
    storage_dir: impl Into<PathBuf>,
) -> Result<Box<dyn SecureBlobStorage>, KeyringError> {
    let alias = alias.into();
    let storage_dir = storage_dir.into();

    // Try TPM on Linux/Windows
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    {
        // Check if TPM is available using detection module
        let tpm_available = crate::platform::tpm::detect_tpm()
            .map(|(avail, _)| avail)
            .unwrap_or(false);

        if tpm_available {
            match TpmSecureBlobStorage::new(&alias, &storage_dir) {
                Ok(storage) => {
                    tracing::info!(
                        alias = %alias,
                        "Using TPM-backed secure storage for wallet seeds"
                    );
                    return Ok(Box::new(storage));
                },
                Err(e) => {
                    tracing::warn!(
                        alias = %alias,
                        error = %e,
                        "TPM storage initialization failed, falling back to software"
                    );
                },
            }
        }
    }

    // Android Keystore (hardware-backed on supported devices)
    // TODO: Enable when JNI issues are resolved
    // The AndroidKeystoreSecureBlobStorage implementation needs JNI API fixes
    #[cfg(target_os = "android")]
    {
        tracing::info!(
            alias = %alias,
            "Android detected - using software storage (Keystore blob storage pending JNI fixes)"
        );
    }

    // iOS/macOS Secure Enclave
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        match SecureEnclaveSecureBlobStorage::new(&alias, &storage_dir) {
            Ok(storage) => {
                tracing::info!(
                    alias = %alias,
                    hw_backed = storage.is_hardware_backed(),
                    "Using Secure Enclave-backed secure storage for wallet seeds"
                );
                return Ok(Box::new(storage));
            },
            Err(e) => {
                tracing::warn!(
                    alias = %alias,
                    error = %e,
                    "Secure Enclave storage initialization failed, falling back to software"
                );
            },
        }
    }

    // Fall back to software storage
    tracing::info!(
        alias = %alias,
        "Using software-only secure storage for wallet seeds"
    );

    Ok(Box::new(SoftwareSecureBlobStorage::new(
        alias,
        storage_dir,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_software_storage_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SoftwareSecureBlobStorage::new("test", temp_dir.path()).unwrap();

        let secret = b"my secret data";
        storage.store("test.key", secret).unwrap();

        assert!(storage.exists("test.key"));

        let loaded = storage.load("test.key").unwrap();
        assert_eq!(loaded, secret);
    }

    #[test]
    fn test_software_storage_multiple_keys() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SoftwareSecureBlobStorage::new("test", temp_dir.path()).unwrap();

        storage.store("identity.ed25519", b"ed25519 seed").unwrap();
        storage
            .store("identity.wallet_seed", b"wallet seed")
            .unwrap();

        assert!(storage.exists("identity.ed25519"));
        assert!(storage.exists("identity.wallet_seed"));

        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"identity.ed25519".to_string()));
        assert!(keys.contains(&"identity.wallet_seed".to_string()));
    }

    #[test]
    fn test_software_storage_delete() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SoftwareSecureBlobStorage::new("test", temp_dir.path()).unwrap();

        storage.store("test.key", b"data").unwrap();
        assert!(storage.exists("test.key"));

        storage.delete("test.key").unwrap();
        assert!(!storage.exists("test.key"));
    }

    #[test]
    fn test_software_storage_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SoftwareSecureBlobStorage::new("test", temp_dir.path()).unwrap();

        storage.store("test.key", b"original").unwrap();
        storage.store("test.key", b"updated").unwrap();

        let loaded = storage.load("test.key").unwrap();
        assert_eq!(loaded, b"updated");
    }

    #[test]
    fn test_software_storage_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SoftwareSecureBlobStorage::new("test", temp_dir.path()).unwrap();

        let result = storage.load("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_different_key_ids_different_ciphertexts() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SoftwareSecureBlobStorage::new("test", temp_dir.path()).unwrap();

        // Same data, different key IDs should produce different ciphertexts
        let data = b"same data";
        storage.store("key1", data).unwrap();
        storage.store("key2", data).unwrap();

        // Read raw files to verify they're different (due to different derived keys + random nonces)
        let path1 = storage.blob_path("key1");
        let path2 = storage.blob_path("key2");
        let raw1 = std::fs::read(path1).unwrap();
        let raw2 = std::fs::read(path2).unwrap();

        assert_ne!(
            raw1, raw2,
            "Different key IDs should produce different ciphertexts"
        );
    }

    #[test]
    fn test_persistence_across_instances() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        // First instance
        {
            let storage = SoftwareSecureBlobStorage::new("test", &path).unwrap();
            storage.store("persistent.key", b"persistent data").unwrap();
        }

        // New instance should be able to read the data
        {
            let storage = SoftwareSecureBlobStorage::new("test", &path).unwrap();
            let loaded = storage.load("persistent.key").unwrap();
            assert_eq!(loaded, b"persistent data");
        }
    }
}
