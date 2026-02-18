//! Android Keystore/StrongBox hardware signer implementation.
//!
//! Uses JNI to access Android's hardware-backed keystore.
//! Supports both standard Keystore (TEE) and StrongBox (dedicated HSM).

use async_trait::async_trait;
use tracing::{debug, error, info, warn};

use crate::error::KeyringError;
use crate::signer::{HardwareSigner, KeyGenConfig};
use crate::types::{AndroidAttestation, ClassicalAlgorithm, HardwareType, PlatformAttestation};

#[cfg(target_os = "android")]
use std::sync::OnceLock;

#[cfg(target_os = "android")]
use jni::{
    objects::{JByteArray, JObject, JObjectArray, JValue},
    JNIEnv, JavaVM,
};

/// Global JavaVM reference, set during JNI_OnLoad or explicit initialization.
#[cfg(target_os = "android")]
static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();

/// Initialize the JNI subsystem with a JavaVM reference.
///
/// This must be called before any Android Keystore operations.
/// Typically called from JNI_OnLoad or from the Android app's initialization.
#[cfg(target_os = "android")]
pub fn init_jni(vm: JavaVM) -> Result<(), KeyringError> {
    info!("init_jni: initializing JavaVM reference");
    JAVA_VM.set(vm).map_err(|_| {
        error!("init_jni: JavaVM already initialized");
        KeyringError::HardwareNotAvailable {
            reason: "JavaVM already initialized".into(),
        }
    })
}

/// Get the cached JavaVM reference.
#[cfg(target_os = "android")]
fn get_java_vm() -> Option<&'static JavaVM> {
    JAVA_VM.get()
}

/// JNI_OnLoad - called automatically when the library is loaded by Android.
#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "system" fn JNI_OnLoad(
    vm: *mut jni::sys::JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> jni::sys::jint {
    info!("JNI_OnLoad: CIRISVerify native library loaded");

    // Safety: vm pointer is provided by the JVM and is valid
    let vm = match JavaVM::from_raw(vm) {
        Ok(vm) => vm,
        Err(e) => {
            error!("JNI_OnLoad: failed to create JavaVM wrapper: {}", e);
            return jni::sys::JNI_ERR;
        }
    };

    if let Err(e) = init_jni(vm) {
        error!("JNI_OnLoad: failed to initialize JNI: {}", e);
        return jni::sys::JNI_ERR;
    }

    info!("JNI_OnLoad: JNI initialization complete");
    jni::sys::JNI_VERSION_1_6
}

/// Android Keystore signer using hardware-backed keys.
///
/// This implementation requires JNI access to the Android Keystore API.
/// Keys are generated in and never leave the hardware security module.
pub struct AndroidKeystoreSigner {
    /// Key alias in the Android Keystore
    alias: String,
    /// Whether StrongBox is available and being used
    use_strongbox: bool,
    /// Cached public key (exported from hardware)
    public_key: Option<Vec<u8>>,
}

impl AndroidKeystoreSigner {
    /// Create a new Android Keystore signer.
    pub fn new(alias: impl Into<String>, prefer_strongbox: bool) -> Result<Self, KeyringError> {
        let alias = alias.into();
        info!(
            alias = %alias,
            prefer_strongbox = prefer_strongbox,
            "AndroidKeystoreSigner::new - initializing"
        );

        #[cfg(target_os = "android")]
        {
            if get_java_vm().is_none() {
                warn!(
                    alias = %alias,
                    "JNI not initialized - call init_jni() or ensure library is loaded via System.loadLibrary()"
                );
            }
        }

        let use_strongbox = prefer_strongbox && Self::detect_strongbox().unwrap_or(false);

        info!(
            alias = %alias,
            use_strongbox = use_strongbox,
            "AndroidKeystoreSigner created"
        );

        Ok(Self {
            alias,
            use_strongbox,
            public_key: None,
        })
    }

    fn detect_strongbox() -> Result<bool, KeyringError> {
        #[cfg(target_os = "android")]
        {
            debug!("detect_strongbox: checking for StrongBox support");
            // StrongBox detection requires Context, default to false
            Ok(false)
        }

        #[cfg(not(target_os = "android"))]
        {
            debug!("detect_strongbox: not on Android platform");
            Err(KeyringError::NoPlatformSupport)
        }
    }

    #[cfg(target_os = "android")]
    fn get_keystore<'a>(env: &mut JNIEnv<'a>) -> Result<JObject<'a>, KeyringError> {
        debug!("get_keystore: loading AndroidKeyStore");

        let keystore_type = env.new_string("AndroidKeyStore").map_err(|e| {
            error!("get_keystore: failed to create string: {}", e);
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI string creation failed: {}", e),
            }
        })?;

        let keystore_class = env.find_class("java/security/KeyStore").map_err(|e| {
            error!("get_keystore: failed to find KeyStore class: {}", e);
            KeyringError::HardwareNotAvailable {
                reason: format!("KeyStore class not found: {}", e),
            }
        })?;

        let keystore = env
            .call_static_method(
                keystore_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyStore;",
                &[JValue::Object(&keystore_type.into())],
            )
            .map_err(|e| {
                error!("get_keystore: getInstance failed: {}", e);
                KeyringError::HardwareNotAvailable {
                    reason: format!("KeyStore.getInstance failed: {}", e),
                }
            })?;

        let keystore = keystore.l().map_err(|e| {
            error!("get_keystore: failed to convert result: {}", e);
            KeyringError::HardwareNotAvailable {
                reason: format!("KeyStore conversion failed: {}", e),
            }
        })?;

        env.call_method(
            &keystore,
            "load",
            "(Ljava/security/KeyStore$LoadStoreParameter;)V",
            &[JValue::Object(&JObject::null())],
        )
        .map_err(|e| {
            error!("get_keystore: load failed: {}", e);
            KeyringError::HardwareNotAvailable {
                reason: format!("KeyStore.load failed: {}", e),
            }
        })?;

        debug!("get_keystore: AndroidKeyStore loaded successfully");
        Ok(keystore)
    }

    pub async fn get_attestation_chain(&self) -> Result<Vec<Vec<u8>>, KeyringError> {
        info!(alias = %self.alias, "get_attestation_chain called");

        #[cfg(target_os = "android")]
        {
            let vm = get_java_vm().ok_or_else(|| {
                warn!(alias = %self.alias, "get_attestation_chain: JNI not available");
                KeyringError::HardwareNotAvailable {
                    reason: "JNI not initialized".into(),
                }
            })?;

            let mut env = vm.attach_current_thread().map_err(|e| {
                error!("get_attestation_chain: failed to attach thread: {}", e);
                KeyringError::HardwareNotAvailable {
                    reason: format!("JNI attach failed: {}", e),
                }
            })?;

            let keystore = Self::get_keystore(&mut env)?;

            let alias_str = env.new_string(&self.alias).map_err(|e| {
                KeyringError::HardwareNotAvailable {
                    reason: format!("JNI string creation failed: {}", e),
                }
            })?;

            let chain = env
                .call_method(
                    &keystore,
                    "getCertificateChain",
                    "(Ljava/lang/String;)[Ljava/security/cert/Certificate;",
                    &[JValue::Object(&alias_str.into())],
                )
                .map_err(|e| {
                    warn!(alias = %self.alias, "getCertificateChain failed: {}", e);
                    KeyringError::HardwareNotAvailable {
                        reason: format!("getCertificateChain failed: {}", e),
                    }
                })?;

            let chain_obj = chain.l().map_err(|e| {
                KeyringError::HardwareNotAvailable {
                    reason: format!("Certificate chain conversion failed: {}", e),
                }
            })?;

            if chain_obj.is_null() {
                debug!(alias = %self.alias, "No certificate chain found for alias");
                return Ok(vec![]);
            }

            // Convert JObject to JObjectArray
            let chain_array: JObjectArray = chain_obj.into();
            let length = env.get_array_length(&chain_array).map_err(|e| {
                KeyringError::HardwareNotAvailable {
                    reason: format!("Failed to get array length: {}", e),
                }
            })? as usize;

            let mut result = Vec::with_capacity(length);
            for i in 0..length {
                let cert = env.get_object_array_element(&chain_array, i as i32).map_err(|e| {
                    KeyringError::HardwareNotAvailable {
                        reason: format!("Failed to get certificate at index {}: {}", i, e),
                    }
                })?;

                let encoded = env
                    .call_method(&cert, "getEncoded", "()[B", &[])
                    .map_err(|e| {
                        KeyringError::HardwareNotAvailable {
                            reason: format!("getEncoded failed: {}", e),
                        }
                    })?;

                let encoded_obj = encoded.l().map_err(|e| {
                    KeyringError::HardwareNotAvailable {
                        reason: format!("Encoded conversion failed: {}", e),
                    }
                })?;

                let encoded_array: JByteArray = encoded_obj.into();
                let bytes = env.convert_byte_array(encoded_array).map_err(|e| {
                    KeyringError::HardwareNotAvailable {
                        reason: format!("Byte array conversion failed: {}", e),
                    }
                })?;

                result.push(bytes);
            }

            info!(alias = %self.alias, chain_len = result.len(), "Attestation chain retrieved");
            Ok(result)
        }

        #[cfg(not(target_os = "android"))]
        {
            error!("get_attestation_chain: not on Android platform");
            Err(KeyringError::NoPlatformSupport)
        }
    }

    pub async fn get_play_integrity_token(&self) -> Result<String, KeyringError> {
        info!(alias = %self.alias, "get_play_integrity_token called");

        #[cfg(target_os = "android")]
        {
            warn!(
                alias = %self.alias,
                "Play Integrity should be called from app layer with proper Context"
            );
            Err(KeyringError::HardwareNotAvailable {
                reason: "Play Integrity API requires app-layer integration".into(),
            })
        }

        #[cfg(not(target_os = "android"))]
        {
            error!("get_play_integrity_token: not on Android platform");
            Err(KeyringError::NoPlatformSupport)
        }
    }

    #[cfg(target_os = "android")]
    async fn jni_sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        info!(
            alias = %self.alias,
            data_len = data.len(),
            "jni_sign called"
        );

        let vm = get_java_vm().ok_or_else(|| {
            warn!(alias = %self.alias, "jni_sign: JNI not available");
            KeyringError::HardwareNotAvailable {
                reason: "JNI not initialized".into(),
            }
        })?;

        let mut env = vm.attach_current_thread().map_err(|e| {
            error!("jni_sign: failed to attach thread: {}", e);
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI attach failed: {}", e),
            }
        })?;

        let keystore = Self::get_keystore(&mut env)?;

        let alias_str = env.new_string(&self.alias).map_err(|e| {
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
            .map_err(|e| {
                error!(alias = %self.alias, "getEntry failed: {}", e);
                KeyringError::HardwareNotAvailable {
                    reason: format!("getEntry failed: {}", e),
                }
            })?;

        let entry = entry.l().map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Entry conversion failed: {}", e),
            }
        })?;

        if entry.is_null() {
            error!(alias = %self.alias, "Key not found in keystore");
            return Err(KeyringError::HardwareNotAvailable {
                reason: format!("Key '{}' not found in Android Keystore", self.alias),
            });
        }

        let private_key = env
            .call_method(&entry, "getPrivateKey", "()Ljava/security/PrivateKey;", &[])
            .map_err(|e| {
                error!(alias = %self.alias, "getPrivateKey failed: {}", e);
                KeyringError::HardwareNotAvailable {
                    reason: format!("getPrivateKey failed: {}", e),
                }
            })?;

        let private_key = private_key.l().map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("PrivateKey conversion failed: {}", e),
            }
        })?;

        let algo_str = env.new_string("SHA256withECDSA").map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI string creation failed: {}", e),
            }
        })?;

        let sig_class = env.find_class("java/security/Signature").map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Signature class not found: {}", e),
            }
        })?;

        let signature = env
            .call_static_method(
                sig_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/Signature;",
                &[JValue::Object(&algo_str.into())],
            )
            .map_err(|e| {
                KeyringError::HardwareNotAvailable {
                    reason: format!("Signature.getInstance failed: {}", e),
                }
            })?;

        let signature = signature.l().map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Signature conversion failed: {}", e),
            }
        })?;

        env.call_method(
            &signature,
            "initSign",
            "(Ljava/security/PrivateKey;)V",
            &[JValue::Object(&private_key)],
        )
        .map_err(|e| {
            error!(alias = %self.alias, "initSign failed: {}", e);
            KeyringError::HardwareNotAvailable {
                reason: format!("initSign failed: {}", e),
            }
        })?;

        let data_array = env.byte_array_from_slice(data).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Failed to create byte array: {}", e),
            }
        })?;

        env.call_method(&signature, "update", "([B)V", &[JValue::Object(&data_array)])
            .map_err(|e| {
                KeyringError::HardwareNotAvailable {
                    reason: format!("update failed: {}", e),
                }
            })?;

        let sig_bytes = env
            .call_method(&signature, "sign", "()[B", &[])
            .map_err(|e| {
                error!(alias = %self.alias, "sign failed: {}", e);
                KeyringError::HardwareNotAvailable {
                    reason: format!("sign failed: {}", e),
                }
            })?;

        let sig_obj = sig_bytes.l().map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Signature bytes conversion failed: {}", e),
            }
        })?;

        let sig_array: JByteArray = sig_obj.into();
        let result = env.convert_byte_array(sig_array).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Byte array conversion failed: {}", e),
            }
        })?;

        info!(alias = %self.alias, sig_len = result.len(), "Signature created successfully");
        Ok(result)
    }

    #[cfg(target_os = "android")]
    async fn jni_get_public_key(&self) -> Result<Vec<u8>, KeyringError> {
        info!(alias = %self.alias, "jni_get_public_key called");

        let vm = get_java_vm().ok_or_else(|| {
            warn!(alias = %self.alias, "jni_get_public_key: JNI not available");
            KeyringError::HardwareNotAvailable {
                reason: "JNI not initialized".into(),
            }
        })?;

        let mut env = vm.attach_current_thread().map_err(|e| {
            error!("jni_get_public_key: failed to attach thread: {}", e);
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI attach failed: {}", e),
            }
        })?;

        let keystore = Self::get_keystore(&mut env)?;

        let alias_str = env.new_string(&self.alias).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI string creation failed: {}", e),
            }
        })?;

        let cert = env
            .call_method(
                &keystore,
                "getCertificate",
                "(Ljava/lang/String;)Ljava/security/cert/Certificate;",
                &[JValue::Object(&alias_str.into())],
            )
            .map_err(|e| {
                error!(alias = %self.alias, "getCertificate failed: {}", e);
                KeyringError::HardwareNotAvailable {
                    reason: format!("getCertificate failed: {}", e),
                }
            })?;

        let cert = cert.l().map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Certificate conversion failed: {}", e),
            }
        })?;

        if cert.is_null() {
            error!(alias = %self.alias, "Certificate not found");
            return Err(KeyringError::HardwareNotAvailable {
                reason: format!("Certificate for '{}' not found", self.alias),
            });
        }

        let public_key = env
            .call_method(&cert, "getPublicKey", "()Ljava/security/PublicKey;", &[])
            .map_err(|e| {
                KeyringError::HardwareNotAvailable {
                    reason: format!("getPublicKey failed: {}", e),
                }
            })?;

        let public_key = public_key.l().map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("PublicKey conversion failed: {}", e),
            }
        })?;

        let encoded = env
            .call_method(&public_key, "getEncoded", "()[B", &[])
            .map_err(|e| {
                KeyringError::HardwareNotAvailable {
                    reason: format!("getEncoded failed: {}", e),
                }
            })?;

        let encoded_obj = encoded.l().map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Encoded conversion failed: {}", e),
            }
        })?;

        let encoded_array: JByteArray = encoded_obj.into();
        let result = env.convert_byte_array(encoded_array).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Byte array conversion failed: {}", e),
            }
        })?;

        info!(alias = %self.alias, key_len = result.len(), "Public key retrieved");
        Ok(result)
    }

    #[cfg(target_os = "android")]
    async fn jni_generate_key(&self, config: &KeyGenConfig) -> Result<(), KeyringError> {
        info!(
            alias = %self.alias,
            config = ?config,
            "jni_generate_key called"
        );

        let vm = get_java_vm().ok_or_else(|| {
            warn!(alias = %self.alias, "jni_generate_key: JNI not available");
            KeyringError::HardwareNotAvailable {
                reason: "JNI not initialized".into(),
            }
        })?;

        let mut env = vm.attach_current_thread().map_err(|e| {
            error!("jni_generate_key: failed to attach thread: {}", e);
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI attach failed: {}", e),
            }
        })?;

        // Create KeyPairGenerator for EC
        let algo_str = env.new_string("EC").map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI string creation failed: {}", e),
            }
        })?;

        let provider_str = env.new_string("AndroidKeyStore").map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI string creation failed: {}", e),
            }
        })?;

        let kpg_class = env.find_class("java/security/KeyPairGenerator").map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("KeyPairGenerator class not found: {}", e),
            }
        })?;

        let key_pair_gen = env
            .call_static_method(
                kpg_class,
                "getInstance",
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
                &[JValue::Object(&algo_str.into()), JValue::Object(&provider_str.into())],
            )
            .map_err(|e| {
                KeyringError::HardwareNotAvailable {
                    reason: format!("KeyPairGenerator.getInstance failed: {}", e),
                }
            })?;

        let key_pair_gen = key_pair_gen.l().map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("KeyPairGenerator conversion failed: {}", e),
            }
        })?;

        // Build KeyGenParameterSpec
        let alias_str = env.new_string(&self.alias).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI string creation failed: {}", e),
            }
        })?;

        // PURPOSE_SIGN = 4
        let purposes = 4i32;

        let builder_class = env
            .find_class("android/security/keystore/KeyGenParameterSpec$Builder")
            .map_err(|e| {
                KeyringError::HardwareNotAvailable {
                    reason: format!("KeyGenParameterSpec.Builder class not found: {}", e),
                }
            })?;

        let builder = env
            .new_object(
                builder_class,
                "(Ljava/lang/String;I)V",
                &[JValue::Object(&alias_str.into()), JValue::Int(purposes)],
            )
            .map_err(|e| {
                KeyringError::HardwareNotAvailable {
                    reason: format!("Builder construction failed: {}", e),
                }
            })?;

        // Set key size to 256 (P-256)
        env.call_method(
            &builder,
            "setKeySize",
            "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Int(256)],
        )
        .map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("setKeySize failed: {}", e),
            }
        })?;

        // Set digests - need to create array separately to avoid borrow issues
        let sha256_str = env.new_string("SHA-256").map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("String creation failed: {}", e),
            }
        })?;

        let string_class = env.find_class("java/lang/String").map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("String class not found: {}", e),
            }
        })?;

        let digests_array = env
            .new_object_array(1, string_class, &sha256_str)
            .map_err(|e| {
                KeyringError::HardwareNotAvailable {
                    reason: format!("Digests array creation failed: {}", e),
                }
            })?;

        env.call_method(
            &builder,
            "setDigests",
            "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Object(&digests_array)],
        )
        .map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("setDigests failed: {}", e),
            }
        })?;

        // Set StrongBox if requested
        if self.use_strongbox {
            let _ = env.call_method(
                &builder,
                "setIsStrongBoxBacked",
                "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[JValue::Bool(1)],
            ); // Ignore error if StrongBox not available
        }

        // Build the spec
        let spec = env
            .call_method(
                &builder,
                "build",
                "()Landroid/security/keystore/KeyGenParameterSpec;",
                &[],
            )
            .map_err(|e| {
                KeyringError::HardwareNotAvailable {
                    reason: format!("build failed: {}", e),
                }
            })?;

        let spec = spec.l().map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Spec conversion failed: {}", e),
            }
        })?;

        // Initialize generator
        env.call_method(
            &key_pair_gen,
            "initialize",
            "(Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[JValue::Object(&spec)],
        )
        .map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("initialize failed: {}", e),
            }
        })?;

        // Generate key pair
        env.call_method(&key_pair_gen, "generateKeyPair", "()Ljava/security/KeyPair;", &[])
            .map_err(|e| {
                error!(alias = %self.alias, "generateKeyPair failed: {}", e);
                KeyringError::HardwareNotAvailable {
                    reason: format!("generateKeyPair failed: {}", e),
                }
            })?;

        info!(alias = %self.alias, "Key generated successfully in Android Keystore");
        Ok(())
    }

    #[cfg(target_os = "android")]
    async fn jni_key_exists(&self, alias: &str) -> Result<bool, KeyringError> {
        debug!(alias = %alias, "jni_key_exists called");

        let vm = get_java_vm().ok_or_else(|| {
            KeyringError::HardwareNotAvailable {
                reason: "JNI not initialized".into(),
            }
        })?;

        let mut env = vm.attach_current_thread().map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI attach failed: {}", e),
            }
        })?;

        let keystore = Self::get_keystore(&mut env)?;

        let alias_str = env.new_string(alias).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI string creation failed: {}", e),
            }
        })?;

        let exists = env
            .call_method(
                &keystore,
                "containsAlias",
                "(Ljava/lang/String;)Z",
                &[JValue::Object(&alias_str.into())],
            )
            .map_err(|e| {
                KeyringError::HardwareNotAvailable {
                    reason: format!("containsAlias failed: {}", e),
                }
            })?;

        let result = exists.z().map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Boolean conversion failed: {}", e),
            }
        })?;

        debug!(alias = %alias, exists = result, "Key existence check complete");
        Ok(result)
    }

    #[cfg(target_os = "android")]
    async fn jni_delete_key(&self, alias: &str) -> Result<(), KeyringError> {
        info!(alias = %alias, "jni_delete_key called");

        let vm = get_java_vm().ok_or_else(|| {
            KeyringError::HardwareNotAvailable {
                reason: "JNI not initialized".into(),
            }
        })?;

        let mut env = vm.attach_current_thread().map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI attach failed: {}", e),
            }
        })?;

        let keystore = Self::get_keystore(&mut env)?;

        let alias_str = env.new_string(alias).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI string creation failed: {}", e),
            }
        })?;

        env.call_method(
            &keystore,
            "deleteEntry",
            "(Ljava/lang/String;)V",
            &[JValue::Object(&alias_str.into())],
        )
        .map_err(|e| {
            error!(alias = %alias, "deleteEntry failed: {}", e);
            KeyringError::HardwareNotAvailable {
                reason: format!("deleteEntry failed: {}", e),
            }
        })?;

        info!(alias = %alias, "Key deleted from Android Keystore");
        Ok(())
    }
}

#[async_trait]
impl HardwareSigner for AndroidKeystoreSigner {
    fn algorithm(&self) -> ClassicalAlgorithm {
        ClassicalAlgorithm::EcdsaP256
    }

    fn hardware_type(&self) -> HardwareType {
        if self.use_strongbox {
            HardwareType::AndroidStrongbox
        } else {
            HardwareType::AndroidKeystore
        }
    }

    async fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
        debug!(alias = %self.alias, "public_key() called");

        #[cfg(target_os = "android")]
        {
            if let Some(ref pk) = self.public_key {
                debug!(alias = %self.alias, "returning cached public key");
                return Ok(pk.clone());
            }
            self.jni_get_public_key().await
        }

        #[cfg(not(target_os = "android"))]
        {
            error!(alias = %self.alias, "public_key: not on Android platform");
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        debug!(alias = %self.alias, data_len = data.len(), "sign() called");

        #[cfg(target_os = "android")]
        {
            self.jni_sign(data).await
        }

        #[cfg(not(target_os = "android"))]
        {
            let _ = data;
            error!(alias = %self.alias, "sign: not on Android platform");
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
        info!(alias = %self.alias, "attestation() called");

        #[cfg(target_os = "android")]
        {
            let attestation_chain = match self.get_attestation_chain().await {
                Ok(chain) => chain,
                Err(e) => {
                    warn!(alias = %self.alias, error = %e, "Could not get attestation chain");
                    vec![]
                }
            };

            let play_integrity_token = match self.get_play_integrity_token().await {
                Ok(token) => Some(token),
                Err(e) => {
                    debug!(alias = %self.alias, error = %e, "Play Integrity token not available");
                    None
                }
            };

            info!(
                alias = %self.alias,
                chain_len = attestation_chain.len(),
                has_play_integrity = play_integrity_token.is_some(),
                strongbox = self.use_strongbox,
                "Returning Android attestation"
            );

            Ok(PlatformAttestation::Android(AndroidAttestation {
                key_attestation_chain: attestation_chain,
                play_integrity_token,
                strongbox_backed: self.use_strongbox,
            }))
        }

        #[cfg(not(target_os = "android"))]
        {
            error!(alias = %self.alias, "attestation: not on Android platform");
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn generate_key(&self, config: &KeyGenConfig) -> Result<(), KeyringError> {
        info!(alias = %self.alias, "generate_key() called");

        #[cfg(target_os = "android")]
        {
            self.jni_generate_key(config).await
        }

        #[cfg(not(target_os = "android"))]
        {
            let _ = config;
            error!(alias = %self.alias, "generate_key: not on Android platform");
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn key_exists(&self, alias: &str) -> Result<bool, KeyringError> {
        debug!(alias = %alias, "key_exists() called");

        #[cfg(target_os = "android")]
        {
            self.jni_key_exists(alias).await
        }

        #[cfg(not(target_os = "android"))]
        {
            let _ = alias;
            error!("key_exists: not on Android platform");
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn delete_key(&self, alias: &str) -> Result<(), KeyringError> {
        info!(alias = %alias, "delete_key() called");

        #[cfg(target_os = "android")]
        {
            self.jni_delete_key(alias).await
        }

        #[cfg(not(target_os = "android"))]
        {
            let _ = alias;
            error!("delete_key: not on Android platform");
            Err(KeyringError::NoPlatformSupport)
        }
    }

    fn current_alias(&self) -> &str {
        &self.alias
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_android_signer_creation() {
        #[cfg(target_os = "android")]
        {
            let signer = AndroidKeystoreSigner::new("test_key", false);
            assert!(signer.is_ok());
            assert_eq!(signer.unwrap().algorithm(), ClassicalAlgorithm::EcdsaP256);
        }
    }
}
