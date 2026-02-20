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
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519SignerTrait, SigningKey as Ed25519SigningKey,
};
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

/// Thread-safe mutable Ed25519 software signer with optional persistence.
///
/// Wraps `Ed25519SoftwareSigner` with interior mutability for use in
/// concurrent contexts. Supports persisting keys to filesystem storage.
///
/// # Storage Locations (tried in order)
///
/// 1. `$CIRIS_KEY_PATH` environment variable (if set)
/// 2. Android: `$CIRIS_DATA_DIR/{alias}.key` (set by app to Context.getFilesDir())
/// 3. Linux/macOS: `$XDG_DATA_HOME/ciris-verify/{alias}.key` or `~/.local/share/ciris-verify/{alias}.key`
/// 4. Windows: `%LOCALAPPDATA%\ciris-verify\{alias}.key`
/// 5. Fallback: `./{alias}.key` in current directory
///
/// # Security Note
///
/// Keys are stored in plaintext. On Android, app-private storage provides
/// isolation. On desktop, consider encrypting the storage directory.
pub struct MutableEd25519Signer {
    inner: std::sync::RwLock<Ed25519SoftwareSigner>,
    /// Path to key storage file (set after first persistence attempt)
    storage_path: std::sync::RwLock<Option<std::path::PathBuf>>,
}

impl MutableEd25519Signer {
    /// Create a new mutable Ed25519 signer, attempting to load persisted key.
    ///
    /// If a persisted key exists at the storage location, it will be loaded.
    /// Otherwise, the signer starts with no key loaded.
    pub fn new(alias: impl Into<String>) -> Self {
        let alias = alias.into();
        tracing::info!(alias = %alias, "MutableEd25519Signer::new - initializing");

        let signer = Self {
            inner: std::sync::RwLock::new(Ed25519SoftwareSigner::new(alias.clone())),
            storage_path: std::sync::RwLock::new(None),
        };

        // Try to load persisted key
        match signer.try_load_persisted_key() {
            Ok(true) => {
                tracing::info!(
                    alias = %alias,
                    "Loaded persisted Ed25519 key from storage"
                );
            },
            Ok(false) => {
                tracing::debug!(
                    alias = %alias,
                    "No persisted Ed25519 key found"
                );
            },
            Err(e) => {
                tracing::warn!(
                    alias = %alias,
                    error = %e,
                    "Failed to load persisted key (will start fresh)"
                );
            },
        }

        signer
    }

    /// Get the storage path for this signer's key.
    fn get_storage_path(&self) -> Option<std::path::PathBuf> {
        let alias = self.alias();
        let filename = format!("{}.key", alias);

        // 1. Check explicit environment variable
        if let Ok(path) = std::env::var("CIRIS_KEY_PATH") {
            let path = std::path::PathBuf::from(path);
            tracing::debug!(path = %path.display(), "Using CIRIS_KEY_PATH for key storage");
            return Some(path);
        }

        // 2. Check CIRIS_DATA_DIR (set by Android app)
        if let Ok(data_dir) = std::env::var("CIRIS_DATA_DIR") {
            let path = std::path::PathBuf::from(data_dir).join(&filename);
            tracing::debug!(path = %path.display(), "Using CIRIS_DATA_DIR for key storage");
            return Some(path);
        }

        // 3. Platform-specific data directory
        #[cfg(target_os = "android")]
        {
            // On Android, fall back to current directory if CIRIS_DATA_DIR not set
            tracing::warn!(
                "CIRIS_DATA_DIR not set on Android - key persistence may not work. \
                 Set CIRIS_DATA_DIR to Context.getFilesDir().getAbsolutePath()"
            );
            return Some(std::path::PathBuf::from(".").join(&filename));
        }

        #[cfg(not(target_os = "android"))]
        {
            // Desktop platforms: use XDG/AppData directories
            if let Some(data_dir) = dirs::data_local_dir() {
                let ciris_dir = data_dir.join("ciris-verify");
                if let Err(e) = std::fs::create_dir_all(&ciris_dir) {
                    tracing::warn!(
                        error = %e,
                        path = %ciris_dir.display(),
                        "Failed to create ciris-verify data directory"
                    );
                }
                let path = ciris_dir.join(&filename);
                tracing::debug!(path = %path.display(), "Using platform data dir for key storage");
                return Some(path);
            }

            // Fallback to current directory
            tracing::warn!("No suitable data directory found - using current directory");
            Some(std::path::PathBuf::from(".").join(&filename))
        }
    }

    /// Try to load a persisted key from storage.
    ///
    /// Returns Ok(true) if key was loaded, Ok(false) if no key exists,
    /// or Err if loading failed.
    pub fn try_load_persisted_key(&self) -> Result<bool, KeyringError> {
        let path = match self.get_storage_path() {
            Some(p) => p,
            None => {
                tracing::debug!("No storage path available for key persistence");
                return Ok(false);
            },
        };

        // Update cached storage path
        if let Ok(mut sp) = self.storage_path.write() {
            *sp = Some(path.clone());
        }

        if !path.exists() {
            tracing::debug!(path = %path.display(), "No persisted key file found");
            return Ok(false);
        }

        tracing::info!(path = %path.display(), "Found persisted key file, loading...");

        let key_bytes = std::fs::read(&path).map_err(|e| {
            tracing::error!(path = %path.display(), error = %e, "Failed to read key file");
            KeyringError::StorageFailed {
                reason: format!("Failed to read key file: {}", e),
            }
        })?;

        if key_bytes.len() != 32 {
            tracing::error!(
                path = %path.display(),
                len = key_bytes.len(),
                "Invalid key file size (expected 32 bytes)"
            );
            return Err(KeyringError::InvalidKey {
                reason: format!(
                    "Key file has invalid size: {} (expected 32)",
                    key_bytes.len()
                ),
            });
        }

        // Import the key
        let mut inner = self
            .inner
            .write()
            .map_err(|_| KeyringError::PlatformError {
                message: "Lock poisoned".into(),
            })?;

        inner.import_key(&key_bytes)?;

        tracing::info!(
            path = %path.display(),
            "Successfully loaded persisted Ed25519 key"
        );

        Ok(true)
    }

    /// Persist the current key to storage.
    ///
    /// Returns Ok(true) if persisted, Ok(false) if no key to persist,
    /// or Err if persistence failed.
    pub fn persist_key(&self) -> Result<bool, KeyringError> {
        let path = match self.get_storage_path() {
            Some(p) => p,
            None => {
                tracing::warn!("No storage path available - key will not be persisted");
                return Ok(false);
            },
        };

        // Update cached storage path
        if let Ok(mut sp) = self.storage_path.write() {
            *sp = Some(path.clone());
        }

        let inner = self.inner.read().map_err(|_| KeyringError::PlatformError {
            message: "Lock poisoned".into(),
        })?;

        let key = match &inner.signing_key {
            Some(k) => k,
            None => {
                tracing::debug!("No key loaded to persist");
                return Ok(false);
            },
        };

        // Get the seed bytes (private key)
        let key_bytes = key.to_bytes();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    tracing::error!(
                        path = %parent.display(),
                        error = %e,
                        "Failed to create key storage directory"
                    );
                    KeyringError::StorageFailed {
                        reason: format!("Failed to create directory: {}", e),
                    }
                })?;
            }
        }

        // Write key file with restricted permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600) // rw------- (owner only)
                .open(&path)
                .map_err(|e| {
                    tracing::error!(path = %path.display(), error = %e, "Failed to create key file");
                    KeyringError::StorageFailed {
                        reason: format!("Failed to create key file: {}", e),
                    }
                })?;

            use std::io::Write;
            file.write_all(&key_bytes).map_err(|e| {
                tracing::error!(path = %path.display(), error = %e, "Failed to write key file");
                KeyringError::StorageFailed {
                    reason: format!("Failed to write key file: {}", e),
                }
            })?;
        }

        #[cfg(not(unix))]
        {
            std::fs::write(&path, &key_bytes).map_err(|e| {
                tracing::error!(path = %path.display(), error = %e, "Failed to write key file");
                KeyringError::StorageFailed {
                    reason: format!("Failed to write key file: {}", e),
                }
            })?;
        }

        tracing::info!(
            path = %path.display(),
            "Persisted Ed25519 key to storage"
        );

        Ok(true)
    }

    /// Delete the persisted key from storage.
    pub fn delete_persisted_key(&self) -> Result<bool, KeyringError> {
        let path = self
            .storage_path
            .read()
            .ok()
            .and_then(|p| p.clone())
            .or_else(|| self.get_storage_path());

        let path = match path {
            Some(p) => p,
            None => return Ok(false),
        };

        if !path.exists() {
            tracing::debug!(path = %path.display(), "No persisted key file to delete");
            return Ok(false);
        }

        std::fs::remove_file(&path).map_err(|e| {
            tracing::error!(path = %path.display(), error = %e, "Failed to delete key file");
            KeyringError::StorageFailed {
                reason: format!("Failed to delete key file: {}", e),
            }
        })?;

        tracing::info!(path = %path.display(), "Deleted persisted key file");
        Ok(true)
    }

    /// Get the current storage path (if any).
    pub fn current_storage_path(&self) -> Option<std::path::PathBuf> {
        self.storage_path.read().ok().and_then(|p| p.clone())
    }

    /// Import a key from bytes and persist to storage.
    ///
    /// This is the primary method for importing Portal-issued keys.
    /// The key is stored both in memory and persisted to disk.
    pub fn import_key(&self, key_bytes: &[u8]) -> Result<(), KeyringError> {
        tracing::info!(
            key_len = key_bytes.len(),
            "MutableEd25519Signer::import_key - importing key"
        );

        // First import to memory
        {
            let mut inner = self
                .inner
                .write()
                .map_err(|_| KeyringError::PlatformError {
                    message: "Lock poisoned".into(),
                })?;

            inner.import_key(key_bytes)?;
        }

        tracing::info!("Key imported to memory, attempting to persist...");

        // Then persist to storage
        match self.persist_key() {
            Ok(true) => {
                tracing::info!("Key successfully persisted to storage");
            },
            Ok(false) => {
                tracing::warn!(
                    "Key imported to memory but NOT persisted (no storage path). \
                     Key will be lost when process exits!"
                );
            },
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Key imported to memory but persistence FAILED. \
                     Key will be lost when process exits!"
                );
                // Don't fail the import - key is still in memory
            },
        }

        Ok(())
    }

    /// Check if a key is loaded (in memory).
    pub fn has_key(&self) -> bool {
        let has = self
            .inner
            .read()
            .map(|inner| inner.has_key())
            .unwrap_or(false);

        tracing::debug!(has_key = has, "MutableEd25519Signer::has_key check");
        has
    }

    /// Clear the loaded key from memory and optionally delete from storage.
    pub fn clear_key(&self) -> Result<(), KeyringError> {
        tracing::info!("MutableEd25519Signer::clear_key - clearing key");

        // Clear from memory
        {
            let mut inner = self
                .inner
                .write()
                .map_err(|_| KeyringError::PlatformError {
                    message: "Lock poisoned".into(),
                })?;

            inner.clear_key();
        }

        // Delete from storage
        match self.delete_persisted_key() {
            Ok(true) => {
                tracing::info!("Key cleared from memory and deleted from storage");
            },
            Ok(false) => {
                tracing::debug!("Key cleared from memory (no persisted key to delete)");
            },
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Key cleared from memory but failed to delete from storage"
                );
            },
        }

        Ok(())
    }

    /// Get the public key if loaded.
    pub fn get_public_key(&self) -> Option<Vec<u8>> {
        self.inner
            .read()
            .ok()
            .and_then(|inner| inner.get_public_key())
    }

    /// Sign data with the loaded key.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        let inner = self.inner.read().map_err(|_| KeyringError::PlatformError {
            message: "Lock poisoned".into(),
        })?;

        let key = inner
            .signing_key
            .as_ref()
            .ok_or(KeyringError::KeyNotFound {
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

    /// Get diagnostic information about the signer state.
    pub fn diagnostics(&self) -> String {
        let has_key = self.has_key();
        let storage_path = self.current_storage_path();
        let alias = self.alias();

        format!(
            "MutableEd25519Signer diagnostics:\n\
             - alias: {}\n\
             - has_key (memory): {}\n\
             - storage_path: {:?}\n\
             - CIRIS_KEY_PATH: {:?}\n\
             - CIRIS_DATA_DIR: {:?}",
            alias,
            has_key,
            storage_path,
            std::env::var("CIRIS_KEY_PATH").ok(),
            std::env::var("CIRIS_DATA_DIR").ok(),
        )
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
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
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
        use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
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
