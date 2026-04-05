//! Android Keystore-backed secure blob storage.
//!
//! Uses AES-256-GCM with a hardware-backed key from Android Keystore
//! to encrypt arbitrary blobs. The encrypted blobs are stored on disk.

use crate::error::KeyringError;
use crate::storage::SecureBlobStorage;
use std::path::PathBuf;
use tracing::{debug, error, info};

#[cfg(target_os = "android")]
use jni::objects::{JByteArray, JObject, JValue};

#[cfg(target_os = "android")]
use crate::platform::android::{get_java_vm, AndroidKeystoreSigner};

/// AES-GCM nonce size (96 bits = 12 bytes)
const AES_GCM_NONCE_SIZE: usize = 12;

/// AES-GCM tag size (128 bits = 16 bytes)
#[allow(dead_code)]
const AES_GCM_TAG_SIZE: usize = 16;

/// Android Keystore-backed secure blob storage.
///
/// Uses an AES-256-GCM key stored in Android Keystore (hardware-backed
/// on devices with TEE or StrongBox) to encrypt blobs before writing
/// them to disk.
///
/// # Security
///
/// - The AES key never leaves the hardware security module
/// - Encrypted blobs can only be decrypted on the same device
/// - Provides protection against offline attacks on the filesystem
pub struct AndroidKeystoreSecureBlobStorage {
    /// Alias prefix for this storage instance
    alias: String,
    /// Directory where encrypted blobs are stored
    storage_dir: PathBuf,
    /// Alias for the AES wrapper key in Android Keystore
    wrapper_key_alias: String,
    /// Whether the wrapper key uses StrongBox (if available)
    use_strongbox: bool,
}

impl AndroidKeystoreSecureBlobStorage {
    /// Create a new Android Keystore-backed storage.
    ///
    /// # Arguments
    /// * `alias` - Prefix for key naming (e.g., "agent_signing")
    /// * `storage_dir` - Directory to store encrypted blobs
    ///
    /// # Returns
    /// A new storage instance, or error if Android Keystore is unavailable.
    pub fn new(
        alias: impl Into<String>,
        storage_dir: impl Into<PathBuf>,
    ) -> Result<Self, KeyringError> {
        let alias = alias.into();
        let storage_dir = storage_dir.into();
        let wrapper_key_alias = format!("{}_blob_aes_wrapper", alias);

        info!(
            alias = %alias,
            storage_dir = ?storage_dir,
            wrapper_key_alias = %wrapper_key_alias,
            "Creating AndroidKeystoreSecureBlobStorage"
        );

        // Ensure storage directory exists
        if let Some(parent) = storage_dir.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| KeyringError::StorageFailed {
                    reason: format!("Failed to create storage directory: {}", e),
                })?;
            }
        }
        if !storage_dir.exists() {
            std::fs::create_dir_all(&storage_dir).map_err(|e| KeyringError::StorageFailed {
                reason: format!("Failed to create storage directory: {}", e),
            })?;
        }

        // Check if StrongBox is available
        let use_strongbox = Self::check_strongbox_available();

        let storage = Self {
            alias,
            storage_dir,
            wrapper_key_alias,
            use_strongbox,
        };

        // Ensure wrapper key exists
        #[cfg(target_os = "android")]
        {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| KeyringError::PlatformError {
                    message: format!("Failed to create runtime: {}", e),
                })?;

            if !rt.block_on(storage.wrapper_key_exists())? {
                info!(
                    wrapper_key_alias = %storage.wrapper_key_alias,
                    use_strongbox = storage.use_strongbox,
                    "Creating AES wrapper key for blob storage"
                );
                rt.block_on(storage.create_wrapper_key())?;
            }
        }

        Ok(storage)
    }

    /// Check if StrongBox is available on this device.
    ///
    /// Uses PackageManager.hasSystemFeature(FEATURE_STRONGBOX_KEYSTORE) to detect
    /// StrongBox support. Requires Android 9.0 (API 28) or higher.
    fn check_strongbox_available() -> bool {
        #[cfg(target_os = "android")]
        {
            use jni::objects::JString;

            let vm = match get_java_vm() {
                Some(vm) => vm,
                None => {
                    debug!("StrongBox check: JNI not initialized");
                    return false;
                },
            };

            let mut env = match vm.attach_current_thread() {
                Ok(env) => env,
                Err(e) => {
                    debug!("StrongBox check: JNI attach failed: {}", e);
                    return false;
                },
            };

            // Get the ActivityThread to access the application context
            let activity_thread_class = match env.find_class("android/app/ActivityThread") {
                Ok(c) => c,
                Err(_) => {
                    debug!("StrongBox check: ActivityThread class not found");
                    return false;
                },
            };

            let current_app = match env.call_static_method(
                activity_thread_class,
                "currentApplication",
                "()Landroid/app/Application;",
                &[],
            ) {
                Ok(app) => app,
                Err(_) => {
                    debug!("StrongBox check: currentApplication failed");
                    return false;
                },
            };

            let context = match current_app.l() {
                Ok(c) => c,
                Err(_) => {
                    debug!("StrongBox check: context conversion failed");
                    return false;
                },
            };

            if context.is_null() {
                debug!("StrongBox check: context is null");
                return false;
            }

            // Get PackageManager from context
            let package_manager = match env.call_method(
                &context,
                "getPackageManager",
                "()Landroid/content/pm/PackageManager;",
                &[],
            ) {
                Ok(pm) => pm,
                Err(_) => {
                    debug!("StrongBox check: getPackageManager failed");
                    return false;
                },
            };

            let pm = match package_manager.l() {
                Ok(p) => p,
                Err(_) => {
                    debug!("StrongBox check: PackageManager conversion failed");
                    return false;
                },
            };

            if pm.is_null() {
                debug!("StrongBox check: PackageManager is null");
                return false;
            }

            // Check for FEATURE_STRONGBOX_KEYSTORE
            let feature_name: JString = match env.new_string("android.hardware.strongbox_keystore")
            {
                Ok(s) => s,
                Err(_) => {
                    debug!("StrongBox check: string creation failed");
                    return false;
                },
            };

            let has_feature = match env.call_method(
                &pm,
                "hasSystemFeature",
                "(Ljava/lang/String;)Z",
                &[JValue::Object(&feature_name.into())],
            ) {
                Ok(result) => result,
                Err(_) => {
                    debug!("StrongBox check: hasSystemFeature failed");
                    return false;
                },
            };

            match has_feature.z() {
                Ok(has) => {
                    info!(
                        strongbox_available = has,
                        "StrongBox availability check complete"
                    );
                    has
                },
                Err(_) => {
                    debug!("StrongBox check: boolean conversion failed");
                    false
                },
            }
        }
        #[cfg(not(target_os = "android"))]
        {
            false
        }
    }

    /// Get the file path for a given key ID.
    fn blob_path(&self, key_id: &str) -> PathBuf {
        // Sanitize key_id for filesystem
        let safe_id = key_id.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
        self.storage_dir
            .join(format!("{}.{}.enc", self.alias, safe_id))
    }

    /// Check if wrapper key exists in Android Keystore.
    #[cfg(target_os = "android")]
    async fn wrapper_key_exists(&self) -> Result<bool, KeyringError> {
        let vm = get_java_vm().ok_or_else(|| KeyringError::HardwareNotAvailable {
            reason: "JNI not initialized".into(),
        })?;

        let mut env =
            vm.attach_current_thread()
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("JNI attach failed: {}", e),
                })?;

        let keystore = AndroidKeystoreSigner::get_keystore(&mut env)?;

        let alias_str = env.new_string(&self.wrapper_key_alias).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI string creation failed: {}", e),
            }
        })?;

        let contains = env
            .call_method(
                &keystore,
                "containsAlias",
                "(Ljava/lang/String;)Z",
                &[JValue::Object(&alias_str.into())],
            )
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("containsAlias failed: {}", e),
            })?;

        contains
            .z()
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Boolean conversion failed: {}", e),
            })
    }

    /// Create the AES wrapper key in Android Keystore.
    #[cfg(target_os = "android")]
    async fn create_wrapper_key(&self) -> Result<(), KeyringError> {
        let vm = get_java_vm().ok_or_else(|| KeyringError::HardwareNotAvailable {
            reason: "JNI not initialized".into(),
        })?;

        let mut env =
            vm.attach_current_thread()
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("JNI attach failed: {}", e),
                })?;

        // Get KeyGenerator for AES
        let algorithm = env
            .new_string("AES")
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("JNI string failed: {}", e),
            })?;

        let provider =
            env.new_string("AndroidKeyStore")
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("JNI string failed: {}", e),
                })?;

        let key_gen_class = env.find_class("javax/crypto/KeyGenerator").map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("KeyGenerator class not found: {}", e),
            }
        })?;

        let key_gen = env
            .call_static_method(
                &key_gen_class,
                "getInstance",
                "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
                &[
                    JValue::Object(&algorithm.into()),
                    JValue::Object(&provider.into()),
                ],
            )
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("KeyGenerator.getInstance failed: {}", e),
            })?;

        let key_gen = key_gen
            .l()
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("KeyGenerator conversion failed: {}", e),
            })?;

        // Build KeyGenParameterSpec
        let alias_str = env.new_string(&self.wrapper_key_alias).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI string failed: {}", e),
            }
        })?;

        let purposes = 3; // PURPOSE_ENCRYPT | PURPOSE_DECRYPT

        let builder_class = env
            .find_class("android/security/keystore/KeyGenParameterSpec$Builder")
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Builder class not found: {}", e),
            })?;

        let builder = env
            .new_object(
                &builder_class,
                "(Ljava/lang/String;I)V",
                &[JValue::Object(&alias_str.into()), JValue::Int(purposes)],
            )
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Builder constructor failed: {}", e),
            })?;

        // Set key size (256 bits)
        env.call_method(
            &builder,
            "setKeySize",
            "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Int(256)],
        )
        .map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("setKeySize failed: {}", e),
        })?;

        // Set block modes (GCM)
        let gcm_mode = env
            .new_string("GCM")
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("JNI string failed: {}", e),
            })?;

        let string_class =
            env.find_class("java/lang/String")
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("String class not found: {}", e),
                })?;

        let modes_array = env
            .new_object_array(1, &string_class, &gcm_mode)
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Array creation failed: {}", e),
            })?;

        env.call_method(
            &builder,
            "setBlockModes",
            "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Object(&modes_array.into())],
        )
        .map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("setBlockModes failed: {}", e),
        })?;

        // Set encryption paddings (NoPadding for GCM)
        let no_padding =
            env.new_string("NoPadding")
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("JNI string failed: {}", e),
                })?;

        let paddings_array = env
            .new_object_array(1, &string_class, &no_padding)
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Array creation failed: {}", e),
            })?;

        env.call_method(
            &builder,
            "setEncryptionPaddings",
            "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Object(&paddings_array.into())],
        )
        .map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("setEncryptionPaddings failed: {}", e),
        })?;

        // Try to use StrongBox if available
        if self.use_strongbox {
            let _ = env.call_method(
                &builder,
                "setIsStrongBoxBacked",
                "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[JValue::Bool(1)],
            );
        }

        // Build the spec
        let spec = env
            .call_method(
                &builder,
                "build",
                "()Landroid/security/keystore/KeyGenParameterSpec;",
                &[],
            )
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("build failed: {}", e),
            })?;

        let spec = spec.l().map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("Spec conversion failed: {}", e),
        })?;

        // Initialize and generate key
        env.call_method(
            &key_gen,
            "init",
            "(Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[JValue::Object(&spec)],
        )
        .map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("init failed: {}", e),
        })?;

        env.call_method(&key_gen, "generateKey", "()Ljavax/crypto/SecretKey;", &[])
            .map_err(|e| {
                error!(alias = %self.wrapper_key_alias, "generateKey failed: {}", e);
                KeyringError::HardwareNotAvailable {
                    reason: format!("generateKey failed: {}", e),
                }
            })?;

        info!(
            wrapper_alias = %self.wrapper_key_alias,
            use_strongbox = self.use_strongbox,
            "AES-256-GCM wrapper key generated for blob storage"
        );

        Ok(())
    }

    /// Encrypt data using the AES wrapper key.
    #[cfg(target_os = "android")]
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, KeyringError> {
        let vm = get_java_vm().ok_or_else(|| KeyringError::HardwareNotAvailable {
            reason: "JNI not initialized".into(),
        })?;

        let mut env =
            vm.attach_current_thread()
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("JNI attach failed: {}", e),
                })?;

        // Get the AES key from Keystore
        let keystore = AndroidKeystoreSigner::get_keystore(&mut env)?;

        let alias_str = env.new_string(&self.wrapper_key_alias).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI string creation failed: {}", e),
            }
        })?;

        let entry = env
            .call_method(
                &keystore,
                "getEntry",
                "(Ljava/lang/String;Ljava/security/KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;",
                &[JValue::Object(&alias_str.into()), JValue::Object(&JObject::null())],
            )
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("getEntry failed: {}", e),
            })?;

        let entry = entry.l().map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("Entry conversion failed: {}", e),
        })?;

        if entry.is_null() {
            return Err(KeyringError::HardwareNotAvailable {
                reason: format!("AES wrapper key '{}' not found", self.wrapper_key_alias),
            });
        }

        let secret_key = env
            .call_method(&entry, "getSecretKey", "()Ljavax/crypto/SecretKey;", &[])
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("getSecretKey failed: {}", e),
            })?;

        let secret_key = secret_key
            .l()
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("SecretKey conversion failed: {}", e),
            })?;

        // Get Cipher instance
        let transformation = env.new_string("AES/GCM/NoPadding").map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI string failed: {}", e),
            }
        })?;

        let cipher_class = env.find_class("javax/crypto/Cipher").map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Cipher class not found: {}", e),
            }
        })?;

        let cipher = env
            .call_static_method(
                &cipher_class,
                "getInstance",
                "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
                &[JValue::Object(&transformation.into())],
            )
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Cipher.getInstance failed: {}", e),
            })?;

        let cipher = cipher.l().map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("Cipher conversion failed: {}", e),
        })?;

        // Initialize for encryption (ENCRYPT_MODE = 1)
        env.call_method(
            &cipher,
            "init",
            "(ILjava/security/Key;)V",
            &[JValue::Int(1), JValue::Object(&secret_key)],
        )
        .map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("Cipher.init failed: {}", e),
        })?;

        // Get the IV (nonce)
        let iv = env
            .call_method(&cipher, "getIV", "()[B", &[])
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("getIV failed: {}", e),
            })?;

        let iv = iv.l().map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("IV conversion failed: {}", e),
        })?;

        // Safety: getIV returns a byte[], which is a JByteArray in JNI
        let iv_array = unsafe { JByteArray::from_raw(iv.into_raw()) };
        let iv_bytes =
            env.convert_byte_array(&iv_array)
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("IV byte array conversion failed: {}", e),
                })?;

        // Convert plaintext to Java byte array
        let plaintext_array = env.byte_array_from_slice(plaintext).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Plaintext array creation failed: {}", e),
            }
        })?;

        // Encrypt
        let ciphertext = env
            .call_method(
                &cipher,
                "doFinal",
                "([B)[B",
                &[JValue::Object(&plaintext_array.into())],
            )
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("doFinal failed: {}", e),
            })?;

        let ciphertext = ciphertext
            .l()
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Ciphertext conversion failed: {}", e),
            })?;

        // Safety: doFinal returns a byte[], which is a JByteArray in JNI
        let ciphertext_array = unsafe { JByteArray::from_raw(ciphertext.into_raw()) };
        let ciphertext_bytes = env.convert_byte_array(&ciphertext_array).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Ciphertext byte array conversion failed: {}", e),
            }
        })?;

        // Combine IV + ciphertext
        let mut result = Vec::with_capacity(iv_bytes.len() + ciphertext_bytes.len());
        result.extend_from_slice(&iv_bytes);
        result.extend_from_slice(&ciphertext_bytes);

        debug!(
            iv_len = iv_bytes.len(),
            ciphertext_len = ciphertext_bytes.len(),
            total_len = result.len(),
            "Blob encrypted"
        );

        Ok(result)
    }

    /// Decrypt data using the AES wrapper key.
    #[cfg(target_os = "android")]
    async fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, KeyringError> {
        if encrypted.len() < AES_GCM_NONCE_SIZE {
            return Err(KeyringError::StorageFailed {
                reason: "Encrypted data too short".into(),
            });
        }

        let (iv, ciphertext) = encrypted.split_at(AES_GCM_NONCE_SIZE);

        let vm = get_java_vm().ok_or_else(|| KeyringError::HardwareNotAvailable {
            reason: "JNI not initialized".into(),
        })?;

        let mut env =
            vm.attach_current_thread()
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("JNI attach failed: {}", e),
                })?;

        // Get the AES key from Keystore
        let keystore = AndroidKeystoreSigner::get_keystore(&mut env)?;

        let alias_str = env.new_string(&self.wrapper_key_alias).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI string creation failed: {}", e),
            }
        })?;

        let entry = env
            .call_method(
                &keystore,
                "getEntry",
                "(Ljava/lang/String;Ljava/security/KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;",
                &[JValue::Object(&alias_str.into()), JValue::Object(&JObject::null())],
            )
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("getEntry failed: {}", e),
            })?;

        let entry = entry.l().map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("Entry conversion failed: {}", e),
        })?;

        if entry.is_null() {
            return Err(KeyringError::HardwareNotAvailable {
                reason: format!("AES wrapper key '{}' not found", self.wrapper_key_alias),
            });
        }

        let secret_key = env
            .call_method(&entry, "getSecretKey", "()Ljavax/crypto/SecretKey;", &[])
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("getSecretKey failed: {}", e),
            })?;

        let secret_key = secret_key
            .l()
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("SecretKey conversion failed: {}", e),
            })?;

        // Get Cipher instance
        let transformation = env.new_string("AES/GCM/NoPadding").map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI string failed: {}", e),
            }
        })?;

        let cipher_class = env.find_class("javax/crypto/Cipher").map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Cipher class not found: {}", e),
            }
        })?;

        let cipher = env
            .call_static_method(
                &cipher_class,
                "getInstance",
                "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
                &[JValue::Object(&transformation.into())],
            )
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Cipher.getInstance failed: {}", e),
            })?;

        let cipher = cipher.l().map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("Cipher conversion failed: {}", e),
        })?;

        // Create GCMParameterSpec with IV
        let iv_array =
            env.byte_array_from_slice(iv)
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("IV array creation failed: {}", e),
                })?;

        let gcm_spec_class = env
            .find_class("javax/crypto/spec/GCMParameterSpec")
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("GCMParameterSpec class not found: {}", e),
            })?;

        let gcm_spec = env
            .new_object(
                &gcm_spec_class,
                "(I[B)V",
                &[JValue::Int(128), JValue::Object(&iv_array.into())], // 128-bit tag
            )
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("GCMParameterSpec constructor failed: {}", e),
            })?;

        // Initialize for decryption (DECRYPT_MODE = 2)
        env.call_method(
            &cipher,
            "init",
            "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[
                JValue::Int(2),
                JValue::Object(&secret_key),
                JValue::Object(&gcm_spec),
            ],
        )
        .map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("Cipher.init failed: {}", e),
        })?;

        // Convert ciphertext to Java byte array
        let ciphertext_array = env.byte_array_from_slice(ciphertext).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Ciphertext array creation failed: {}", e),
            }
        })?;

        // Decrypt
        let plaintext = env
            .call_method(
                &cipher,
                "doFinal",
                "([B)[B",
                &[JValue::Object(&ciphertext_array.into())],
            )
            .map_err(|e| KeyringError::StorageFailed {
                reason: format!("Decryption failed (wrong key or corrupted data): {}", e),
            })?;

        let plaintext = plaintext.l().map_err(|e| KeyringError::StorageFailed {
            reason: format!("Plaintext conversion failed: {}", e),
        })?;

        // Safety: doFinal returns a byte[], which is a JByteArray in JNI
        let plaintext_array = unsafe { JByteArray::from_raw(plaintext.into_raw()) };
        let plaintext_bytes =
            env.convert_byte_array(&plaintext_array)
                .map_err(|e| KeyringError::StorageFailed {
                    reason: format!("Plaintext byte array conversion failed: {}", e),
                })?;

        debug!(plaintext_len = plaintext_bytes.len(), "Blob decrypted");

        Ok(plaintext_bytes)
    }
}

impl SecureBlobStorage for AndroidKeystoreSecureBlobStorage {
    fn store(&self, key_id: &str, data: &[u8]) -> Result<(), KeyringError> {
        debug!(key_id = %key_id, data_len = data.len(), "Storing blob");

        #[cfg(target_os = "android")]
        {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| KeyringError::PlatformError {
                    message: format!("Failed to create runtime: {}", e),
                })?;

            let encrypted = rt.block_on(self.encrypt(data))?;
            let path = self.blob_path(key_id);

            std::fs::write(&path, &encrypted).map_err(|e| KeyringError::StorageFailed {
                reason: format!("Failed to write encrypted blob: {}", e),
            })?;

            info!(
                key_id = %key_id,
                path = ?path,
                encrypted_len = encrypted.len(),
                "Blob stored with hardware-backed encryption"
            );

            Ok(())
        }

        #[cfg(not(target_os = "android"))]
        {
            let _ = (key_id, data);
            Err(KeyringError::NoPlatformSupport)
        }
    }

    fn load(&self, key_id: &str) -> Result<Vec<u8>, KeyringError> {
        debug!(key_id = %key_id, "Loading blob");

        #[cfg(target_os = "android")]
        {
            let path = self.blob_path(key_id);

            let encrypted = std::fs::read(&path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    KeyringError::StorageFailed {
                        reason: format!("Blob not found: {}", key_id),
                    }
                } else {
                    KeyringError::StorageFailed {
                        reason: format!("Failed to read blob: {}", e),
                    }
                }
            })?;

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| KeyringError::PlatformError {
                    message: format!("Failed to create runtime: {}", e),
                })?;

            let decrypted = rt.block_on(self.decrypt(&encrypted))?;

            debug!(
                key_id = %key_id,
                decrypted_len = decrypted.len(),
                "Blob loaded and decrypted"
            );

            Ok(decrypted)
        }

        #[cfg(not(target_os = "android"))]
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
                reason: format!("Failed to delete blob: {}", e),
            })?;
            info!(key_id = %key_id, "Blob deleted");
        }
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<String>, KeyringError> {
        let prefix = format!("{}.", self.alias);
        let suffix = ".enc";

        let mut keys = Vec::new();

        let entries =
            std::fs::read_dir(&self.storage_dir).map_err(|e| KeyringError::StorageFailed {
                reason: format!("Failed to list storage directory: {}", e),
            })?;

        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with(&prefix) && name.ends_with(suffix) {
                    // Extract key_id from "{alias}.{key_id}.enc"
                    let key_id = &name[prefix.len()..name.len() - suffix.len()];
                    keys.push(key_id.to_string());
                }
            }
        }

        Ok(keys)
    }

    fn is_hardware_backed(&self) -> bool {
        true // Android Keystore is hardware-backed (TEE or StrongBox)
    }

    fn diagnostics(&self) -> String {
        let keys = self.list_keys().unwrap_or_default();
        format!(
            "AndroidKeystoreSecureBlobStorage:\n\
             - Alias: {}\n\
             - Storage dir: {:?}\n\
             - Wrapper key: {}\n\
             - Hardware backed: true\n\
             - StrongBox: {}\n\
             - Stored keys: {:?}",
            self.alias, self.storage_dir, self.wrapper_key_alias, self.use_strongbox, keys
        )
    }
}
