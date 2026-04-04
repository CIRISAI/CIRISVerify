//! Secure Enclave-backed secure blob storage (iOS/macOS).
//!
//! Uses ECIES (Elliptic Curve Integrated Encryption Scheme) with a
//! Secure Enclave P-256 key to encrypt arbitrary blobs before storing
//! them on disk.
//!
//! # Platform Support
//!
//! - **iOS**: Uses Secure Enclave (iPhone 5s+, iPad Air+)
//! - **macOS**: Uses Secure Enclave on T2/Apple Silicon Macs
//!   - Falls back to keychain P-256 key on older Macs (still protected)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │  Secure Enclave (P-256)             │
//! │  Tag: {alias}_blob_ecies_wrapper    │
//! │  ECIES encrypt (public) / decrypt   │
//! └──────────────┬──────────────────────┘
//!                │ SecKeyCreateDecryptedData
//!                ▼
//! ┌─────────────────────────────────────┐
//! │  Disk: {alias}.{key_id}.blob        │
//! │  ECIES ciphertext of secret data    │
//! └─────────────────────────────────────┘
//! ```

use crate::error::KeyringError;
use crate::storage::SecureBlobStorage;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};

#[cfg(any(target_os = "ios", target_os = "macos"))]
use core_foundation::base::TCFType;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use core_foundation::boolean::CFBoolean;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use core_foundation::data::CFData;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use core_foundation::dictionary::CFMutableDictionary;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use core_foundation::number::CFNumber;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use core_foundation::string::CFString;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use security_framework::access_control::{ProtectionMode, SecAccessControl};
#[cfg(any(target_os = "ios", target_os = "macos"))]
use security_framework::key::{Algorithm, SecKey};

// Declare Security framework symbols not exported by security-framework-sys
#[cfg(any(target_os = "ios", target_os = "macos"))]
extern "C" {
    static kSecAttrApplicationTag: core_foundation_sys::string::CFStringRef;
    static kSecMatchLimitOne: core_foundation_sys::string::CFStringRef;
}

/// Secure Enclave-backed secure blob storage for iOS/macOS.
///
/// Uses ECIES with a P-256 key stored in the Secure Enclave (or keychain
/// on older Macs) to encrypt blobs before writing them to disk.
///
/// # Security
///
/// - The P-256 private key never leaves the Secure Enclave
/// - Encrypted blobs can only be decrypted on the same device
/// - Provides hardware-level protection for wallet seeds and other secrets
pub struct SecureEnclaveSecureBlobStorage {
    /// Alias prefix for this storage instance
    alias: String,
    /// Directory where encrypted blobs are stored
    storage_dir: PathBuf,
    /// Tag for the ECIES wrapper key in keychain/SE
    wrapper_key_tag: String,
    /// Whether the wrapper key is in Secure Enclave (true) or keychain (false)
    is_secure_enclave: bool,
}

impl SecureEnclaveSecureBlobStorage {
    /// Create a new Secure Enclave-backed storage.
    ///
    /// # Arguments
    /// * `alias` - Prefix for key naming (e.g., "agent_signing")
    /// * `storage_dir` - Directory to store encrypted blobs
    ///
    /// # Returns
    /// A new storage instance, or error if initialization fails.
    pub fn new(
        alias: impl Into<String>,
        storage_dir: impl Into<PathBuf>,
    ) -> Result<Self, KeyringError> {
        let alias = alias.into();
        let storage_dir = storage_dir.into();
        let wrapper_key_tag = format!("{}_blob_ecies_wrapper", alias);

        info!(
            alias = %alias,
            storage_dir = ?storage_dir,
            wrapper_key_tag = %wrapper_key_tag,
            "Creating SecureEnclaveSecureBlobStorage"
        );

        // Ensure storage directory exists
        std::fs::create_dir_all(&storage_dir).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to create storage directory: {}", e),
        })?;

        let mut storage = Self {
            alias,
            storage_dir,
            wrapper_key_tag,
            is_secure_enclave: false, // Will be updated after key generation
        };

        // Ensure wrapper key exists
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            storage.ensure_wrapper_key()?;
        }

        Ok(storage)
    }

    /// Get the file path for a blob.
    fn blob_path(&self, key_id: &str) -> PathBuf {
        // Sanitize key_id for filesystem
        let safe_id = key_id.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
        self.storage_dir
            .join(format!("{}.{}.blob", self.alias, safe_id))
    }

    /// Check if Secure Enclave is available.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    fn is_se_available() -> bool {
        // iOS always has SE on supported devices (iPhone 5s+)
        #[cfg(target_os = "ios")]
        {
            true
        }

        // macOS: T2 chip or Apple Silicon
        #[cfg(target_os = "macos")]
        {
            // Try to detect SE availability by checking system info
            // For now, assume SE is available and let key generation fail if not
            true
        }
    }

    /// Ensure the ECIES wrapper key exists, creating it if needed.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    fn ensure_wrapper_key(&mut self) -> Result<(), KeyringError> {
        match self.query_wrapper_private_key() {
            Ok(_) => {
                debug!(
                    tag = %self.wrapper_key_tag,
                    "SE ECIES wrapper key already exists"
                );
                // Check if it's actually in SE by trying SE-specific operations
                self.is_secure_enclave = self.check_key_in_se();
                Ok(())
            },
            Err(KeyringError::KeyNotFound { .. }) => {
                info!(
                    tag = %self.wrapper_key_tag,
                    "Generating ECIES wrapper key for blob storage"
                );
                self.generate_wrapper_key()
            },
            Err(e) => Err(e),
        }
    }

    /// Check if the wrapper key is in Secure Enclave.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    fn check_key_in_se(&self) -> bool {
        // For now, assume SE on iOS, check on macOS
        #[cfg(target_os = "ios")]
        {
            true
        }

        #[cfg(target_os = "macos")]
        {
            // macOS: If we successfully generated with SE, it's in SE
            // This is set during key generation
            false
        }
    }

    /// Build a keychain query dictionary for the wrapper key.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    fn build_wrapper_key_query(&self) -> CFMutableDictionary {
        use security_framework_sys::item::*;

        let tag = CFData::from_buffer(self.wrapper_key_tag.as_bytes());

        unsafe {
            let mut query = CFMutableDictionary::new();
            query.set(
                CFString::wrap_under_get_rule(kSecClass).as_CFTypeRef(),
                CFString::wrap_under_get_rule(kSecClassKey).as_CFTypeRef(),
            );
            query.set(
                CFString::wrap_under_get_rule(kSecAttrKeyType).as_CFTypeRef(),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFTypeRef(),
            );
            query.set(
                CFString::wrap_under_get_rule(kSecAttrKeyClass).as_CFTypeRef(),
                CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate).as_CFTypeRef(),
            );
            query.set(
                CFString::wrap_under_get_rule(kSecAttrApplicationTag).as_CFTypeRef(),
                tag.as_CFTypeRef(),
            );
            query
        }
    }

    /// Query the keychain for the wrapper private key.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    fn query_wrapper_private_key(&self) -> Result<SecKey, KeyringError> {
        use security_framework_sys::item::*;
        use security_framework_sys::keychain_item::SecItemCopyMatching;

        unsafe {
            let mut query = self.build_wrapper_key_query();
            query.set(
                CFString::wrap_under_get_rule(kSecReturnRef).as_CFTypeRef(),
                CFBoolean::true_value().as_CFTypeRef(),
            );
            query.set(
                CFString::wrap_under_get_rule(kSecMatchLimit).as_CFTypeRef(),
                CFString::wrap_under_get_rule(kSecMatchLimitOne).as_CFTypeRef(),
            );

            let mut result: core_foundation::base::CFTypeRef = std::ptr::null();
            let status = SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result);

            if status != 0 || result.is_null() {
                return Err(KeyringError::KeyNotFound {
                    alias: self.wrapper_key_tag.clone(),
                });
            }

            Ok(SecKey::wrap_under_create_rule(result as _))
        }
    }

    /// Generate a new P-256 key for ECIES wrapping.
    ///
    /// On iOS, always uses Secure Enclave.
    /// On macOS, tries SE first; if unavailable, falls back to keychain P-256.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    fn generate_wrapper_key(&mut self) -> Result<(), KeyringError> {
        // Try SE first
        match self.generate_wrapper_key_inner(true) {
            Ok(()) => {
                self.is_secure_enclave = true;
                Ok(())
            },
            #[cfg(target_os = "macos")]
            Err(ref e)
                if e.to_string().contains("-34018")
                    || e.to_string().contains("MissingEntitlement") =>
            {
                warn!(
                    tag = %self.wrapper_key_tag,
                    "SE key generation failed (errSecMissingEntitlement) — \
                     macOS CLI process lacks entitlements. Falling back to keychain P-256 key."
                );
                self.is_secure_enclave = false;
                self.generate_wrapper_key_inner(false)
            },
            Err(e) => Err(e),
        }
    }

    /// Inner key generation: `use_se=true` for Secure Enclave, `false` for regular keychain.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    fn generate_wrapper_key_inner(&self, use_se: bool) -> Result<(), KeyringError> {
        use security_framework_sys::item::*;

        let tag = CFData::from_buffer(self.wrapper_key_tag.as_bytes());

        unsafe {
            let mut private_attrs = CFMutableDictionary::new();
            private_attrs.set(
                CFString::wrap_under_get_rule(kSecAttrIsPermanent).as_CFTypeRef(),
                CFBoolean::true_value().as_CFTypeRef(),
            );
            private_attrs.set(
                CFString::wrap_under_get_rule(kSecAttrApplicationTag).as_CFTypeRef(),
                tag.as_CFTypeRef(),
            );

            if use_se {
                // SE keys require access control with private key usage
                use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;
                let access_control = SecAccessControl::create_with_protection(
                    Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
                    kSecAccessControlPrivateKeyUsage,
                )
                .map_err(|e| KeyringError::KeyGenerationFailed {
                    reason: format!("Failed to create access control: {e}"),
                })?;
                private_attrs.set(
                    CFString::wrap_under_get_rule(kSecAttrAccessControl).as_CFTypeRef(),
                    access_control.as_CFTypeRef(),
                );
            }
            // Non-SE keychain keys: no access control policy (avoids entitlement requirement)

            let mut params = CFMutableDictionary::new();
            params.set(
                CFString::wrap_under_get_rule(kSecAttrKeyType).as_CFTypeRef(),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFTypeRef(),
            );
            params.set(
                CFString::wrap_under_get_rule(kSecAttrKeySizeInBits).as_CFTypeRef(),
                CFNumber::from(256_i32).as_CFTypeRef(),
            );
            if use_se {
                params.set(
                    CFString::wrap_under_get_rule(kSecAttrTokenID).as_CFTypeRef(),
                    CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).as_CFTypeRef(),
                );
            }
            params.set(
                CFString::wrap_under_get_rule(kSecPrivateKeyAttrs).as_CFTypeRef(),
                private_attrs.as_CFTypeRef(),
            );

            let mut cf_error: core_foundation_sys::error::CFErrorRef = std::ptr::null_mut();
            let key = security_framework_sys::key::SecKeyCreateRandomKey(
                params.as_concrete_TypeRef(),
                &mut cf_error,
            );

            if key.is_null() {
                let err_msg = if !cf_error.is_null() {
                    let cf_err = core_foundation::error::CFError::wrap_under_create_rule(cf_error);
                    format!(
                        "{} wrapper key generation failed: {cf_err}",
                        if use_se { "SE" } else { "Keychain" }
                    )
                } else {
                    format!(
                        "{} wrapper key generation failed",
                        if use_se { "SE" } else { "Keychain" }
                    )
                };
                return Err(KeyringError::KeyGenerationFailed { reason: err_msg });
            }

            core_foundation::base::CFRelease(key as _);
        }

        info!(
            tag = %self.wrapper_key_tag,
            mode = if use_se { "Secure Enclave" } else { "Keychain" },
            "ECIES wrapper key generated for blob storage"
        );

        Ok(())
    }

    /// Encrypt data using ECIES with the wrapper key.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, KeyringError> {
        use security_framework_sys::key::SecKeyCreateEncryptedData;

        let private_key = self.query_wrapper_private_key()?;
        let public_key = private_key
            .public_key()
            .ok_or_else(|| KeyringError::HardwareError {
                reason: "Failed to get public key from wrapper key".into(),
            })?;

        let plaintext_cf = CFData::from_buffer(plaintext);
        let mut cf_error: core_foundation_sys::error::CFErrorRef = std::ptr::null_mut();

        let ciphertext = unsafe {
            SecKeyCreateEncryptedData(
                public_key.as_concrete_TypeRef(),
                Algorithm::ECIESEncryptionStandardX963SHA256AESGCM.into(),
                plaintext_cf.as_concrete_TypeRef(),
                &mut cf_error,
            )
        };

        if ciphertext.is_null() {
            let err_msg = if !cf_error.is_null() {
                let cf_err =
                    unsafe { core_foundation::error::CFError::wrap_under_create_rule(cf_error) };
                format!("ECIES encryption failed: {cf_err}")
            } else {
                "ECIES encryption failed".to_string()
            };
            return Err(KeyringError::HardwareError { reason: err_msg });
        }

        let cf_data = unsafe { CFData::wrap_under_create_rule(ciphertext) };
        Ok(cf_data.to_vec())
    }

    /// Decrypt data using ECIES with the wrapper key.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, KeyringError> {
        use security_framework_sys::key::SecKeyCreateDecryptedData;

        let private_key = self.query_wrapper_private_key()?;
        let ciphertext_cf = CFData::from_buffer(ciphertext);
        let mut cf_error: core_foundation_sys::error::CFErrorRef = std::ptr::null_mut();

        let plaintext = unsafe {
            SecKeyCreateDecryptedData(
                private_key.as_concrete_TypeRef(),
                Algorithm::ECIESEncryptionStandardX963SHA256AESGCM.into(),
                ciphertext_cf.as_concrete_TypeRef(),
                &mut cf_error,
            )
        };

        if plaintext.is_null() {
            let err_msg = if !cf_error.is_null() {
                let cf_err =
                    unsafe { core_foundation::error::CFError::wrap_under_create_rule(cf_error) };
                format!("ECIES decryption failed: {cf_err}")
            } else {
                "ECIES decryption failed".to_string()
            };
            return Err(KeyringError::HardwareError { reason: err_msg });
        }

        let cf_data = unsafe { CFData::wrap_under_create_rule(plaintext) };
        Ok(cf_data.to_vec())
    }

    /// Delete the wrapper key from keychain.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    fn delete_wrapper_key(&self) -> Result<(), KeyringError> {
        use security_framework_sys::keychain_item::SecItemDelete;

        unsafe {
            let query = self.build_wrapper_key_query();
            let status = SecItemDelete(query.as_concrete_TypeRef());
            if status != 0 && status != -25300
            /* errSecItemNotFound */
            {
                return Err(KeyringError::StorageFailed {
                    reason: format!("Failed to delete wrapper key: OSStatus {status}"),
                });
            }
        }

        info!(tag = %self.wrapper_key_tag, "Wrapper key deleted");
        Ok(())
    }
}

impl SecureBlobStorage for SecureEnclaveSecureBlobStorage {
    fn store(&self, key_id: &str, data: &[u8]) -> Result<(), KeyringError> {
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            let encrypted = self.encrypt(data)?;

            let path = self.blob_path(key_id);

            // Write atomically
            let temp_path = path.with_extension("blob.tmp");

            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&temp_path)
                    .map_err(|e| KeyringError::StorageFailed {
                        reason: format!("Failed to create blob file: {e}"),
                    })?;
                file.write_all(&encrypted)
                    .map_err(|e| KeyringError::StorageFailed {
                        reason: format!("Failed to write blob: {e}"),
                    })?;
            }

            #[cfg(not(unix))]
            {
                std::fs::write(&temp_path, &encrypted).map_err(|e| {
                    KeyringError::StorageFailed {
                        reason: format!("Failed to write blob: {e}"),
                    }
                })?;
            }

            std::fs::rename(&temp_path, &path).map_err(|e| KeyringError::StorageFailed {
                reason: format!("Failed to rename blob: {e}"),
            })?;

            debug!(
                key_id = %key_id,
                path = ?path,
                hw_backed = self.is_secure_enclave,
                "Stored ECIES-encrypted blob"
            );

            Ok(())
        }

        #[cfg(not(any(target_os = "ios", target_os = "macos")))]
        {
            let _ = (key_id, data);
            Err(KeyringError::NoPlatformSupport)
        }
    }

    fn load(&self, key_id: &str) -> Result<Vec<u8>, KeyringError> {
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            let path = self.blob_path(key_id);

            if !path.exists() {
                return Err(KeyringError::KeyNotFound {
                    alias: key_id.to_string(),
                });
            }

            let encrypted = std::fs::read(&path).map_err(|e| KeyringError::StorageFailed {
                reason: format!("Failed to read blob: {e}"),
            })?;

            let plaintext = self.decrypt(&encrypted)?;

            debug!(key_id = %key_id, "Loaded ECIES-encrypted blob");
            Ok(plaintext)
        }

        #[cfg(not(any(target_os = "ios", target_os = "macos")))]
        {
            let _ = key_id;
            Err(KeyringError::NoPlatformSupport)
        }
    }

    fn exists(&self, key_id: &str) -> bool {
        self.blob_path(key_id).exists()
    }

    fn delete(&self, key_id: &str) -> Result<(), KeyringError> {
        let path = self.blob_path(key_id);

        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| KeyringError::StorageFailed {
                reason: format!("Failed to delete blob: {e}"),
            })?;
            info!(key_id = %key_id, "Deleted blob");
        }

        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<String>, KeyringError> {
        let prefix = format!("{}.", self.alias);
        let suffix = ".blob";

        let mut keys = Vec::new();

        let entries =
            std::fs::read_dir(&self.storage_dir).map_err(|e| KeyringError::StorageFailed {
                reason: format!("Failed to read storage directory: {e}"),
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
        self.is_secure_enclave
    }

    fn diagnostics(&self) -> String {
        let keys = self.list_keys().unwrap_or_default();
        format!(
            "SecureEnclaveSecureBlobStorage:\n\
             - Alias: {}\n\
             - Storage dir: {:?}\n\
             - Wrapper key tag: {}\n\
             - Hardware backed (SE): {}\n\
             - Stored keys: {:?}",
            self.alias, self.storage_dir, self.wrapper_key_tag, self.is_secure_enclave, keys
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_path_sanitization() {
        let storage = SecureEnclaveSecureBlobStorage {
            alias: "test".to_string(),
            storage_dir: PathBuf::from("/tmp/test"),
            wrapper_key_tag: "test_blob_ecies_wrapper".to_string(),
            is_secure_enclave: false,
        };

        // Normal key
        let path = storage.blob_path("identity.wallet_seed");
        assert!(path
            .to_string_lossy()
            .ends_with("test.identity.wallet_seed.blob"));

        // Key with special characters
        let path = storage.blob_path("weird/key:name");
        assert!(path.to_string_lossy().ends_with("test.weird_key_name.blob"));
    }

    #[cfg(any(target_os = "ios", target_os = "macos"))]
    #[test]
    #[ignore = "Requires keychain entitlements (run from signed app)"]
    fn test_se_blob_storage_roundtrip() {
        let dir = std::env::temp_dir().join("ciris_test_se_blob");
        let _ = std::fs::create_dir_all(&dir);

        let storage = SecureEnclaveSecureBlobStorage::new("test_blob", dir.clone())
            .expect("Storage should initialize");

        // Store a secret
        let secret = b"my wallet seed bytes here";
        storage
            .store("identity.wallet_seed", secret)
            .expect("store should succeed");

        // Verify it exists
        assert!(storage.exists("identity.wallet_seed"));

        // Load it back
        let loaded = storage
            .load("identity.wallet_seed")
            .expect("load should succeed");
        assert_eq!(loaded, secret);

        // List keys
        let keys = storage.list_keys().expect("list_keys should succeed");
        assert!(keys.contains(&"identity.wallet_seed".to_string()));

        // Delete
        storage
            .delete("identity.wallet_seed")
            .expect("delete should succeed");
        assert!(!storage.exists("identity.wallet_seed"));

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }
}
