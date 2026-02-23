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
        },
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

            let alias_str =
                env.new_string(&self.alias)
                    .map_err(|e| KeyringError::HardwareNotAvailable {
                        reason: format!("JNI string creation failed: {}", e),
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

            let chain_obj = chain.l().map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Certificate chain conversion failed: {}", e),
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
                let cert = env
                    .get_object_array_element(&chain_array, i as i32)
                    .map_err(|e| KeyringError::HardwareNotAvailable {
                        reason: format!("Failed to get certificate at index {}: {}", i, e),
                    })?;

                let encoded = env
                    .call_method(&cert, "getEncoded", "()[B", &[])
                    .map_err(|e| KeyringError::HardwareNotAvailable {
                        reason: format!("getEncoded failed: {}", e),
                    })?;

                let encoded_obj = encoded
                    .l()
                    .map_err(|e| KeyringError::HardwareNotAvailable {
                        reason: format!("Encoded conversion failed: {}", e),
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

        let alias_str =
            env.new_string(&self.alias)
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("JNI string creation failed: {}", e),
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

        let entry = entry.l().map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("Entry conversion failed: {}", e),
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

        let private_key = private_key
            .l()
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("PrivateKey conversion failed: {}", e),
            })?;

        let algo_str =
            env.new_string("SHA256withECDSA")
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("JNI string creation failed: {}", e),
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
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Signature.getInstance failed: {}", e),
            })?;

        let signature = signature
            .l()
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Signature conversion failed: {}", e),
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

        let data_array =
            env.byte_array_from_slice(data)
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("Failed to create byte array: {}", e),
                })?;

        env.call_method(
            &signature,
            "update",
            "([B)V",
            &[JValue::Object(&data_array)],
        )
        .map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("update failed: {}", e),
        })?;

        let sig_bytes = env
            .call_method(&signature, "sign", "()[B", &[])
            .map_err(|e| {
                error!(alias = %self.alias, "sign failed: {}", e);
                KeyringError::HardwareNotAvailable {
                    reason: format!("sign failed: {}", e),
                }
            })?;

        let sig_obj = sig_bytes
            .l()
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Signature bytes conversion failed: {}", e),
            })?;

        let sig_array: JByteArray = sig_obj.into();
        let result =
            env.convert_byte_array(sig_array)
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("Byte array conversion failed: {}", e),
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

        let alias_str =
            env.new_string(&self.alias)
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("JNI string creation failed: {}", e),
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

        let cert = cert.l().map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("Certificate conversion failed: {}", e),
        })?;

        if cert.is_null() {
            error!(alias = %self.alias, "Certificate not found");
            return Err(KeyringError::HardwareNotAvailable {
                reason: format!("Certificate for '{}' not found", self.alias),
            });
        }

        let public_key = env
            .call_method(&cert, "getPublicKey", "()Ljava/security/PublicKey;", &[])
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("getPublicKey failed: {}", e),
            })?;

        let public_key = public_key
            .l()
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("PublicKey conversion failed: {}", e),
            })?;

        let encoded = env
            .call_method(&public_key, "getEncoded", "()[B", &[])
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("getEncoded failed: {}", e),
            })?;

        let encoded_obj = encoded
            .l()
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Encoded conversion failed: {}", e),
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
        let algo_str = env
            .new_string("EC")
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("JNI string creation failed: {}", e),
            })?;

        let provider_str =
            env.new_string("AndroidKeyStore")
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("JNI string creation failed: {}", e),
                })?;

        let kpg_class = env
            .find_class("java/security/KeyPairGenerator")
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("KeyPairGenerator class not found: {}", e),
            })?;

        let key_pair_gen = env
            .call_static_method(
                kpg_class,
                "getInstance",
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
                &[
                    JValue::Object(&algo_str.into()),
                    JValue::Object(&provider_str.into()),
                ],
            )
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("KeyPairGenerator.getInstance failed: {}", e),
            })?;

        let key_pair_gen = key_pair_gen
            .l()
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("KeyPairGenerator conversion failed: {}", e),
            })?;

        // Build KeyGenParameterSpec
        let alias_str =
            env.new_string(&self.alias)
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("JNI string creation failed: {}", e),
                })?;

        // PURPOSE_SIGN = 4
        let purposes = 4i32;

        let builder_class = env
            .find_class("android/security/keystore/KeyGenParameterSpec$Builder")
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("KeyGenParameterSpec.Builder class not found: {}", e),
            })?;

        let builder = env
            .new_object(
                builder_class,
                "(Ljava/lang/String;I)V",
                &[JValue::Object(&alias_str.into()), JValue::Int(purposes)],
            )
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Builder construction failed: {}", e),
            })?;

        // Set key size to 256 (P-256)
        env.call_method(
            &builder,
            "setKeySize",
            "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Int(256)],
        )
        .map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("setKeySize failed: {}", e),
        })?;

        // Set digests - need to create array separately to avoid borrow issues
        let sha256_str =
            env.new_string("SHA-256")
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("String creation failed: {}", e),
                })?;

        let string_class =
            env.find_class("java/lang/String")
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("String class not found: {}", e),
                })?;

        let digests_array = env
            .new_object_array(1, string_class, &sha256_str)
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Digests array creation failed: {}", e),
            })?;

        env.call_method(
            &builder,
            "setDigests",
            "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Object(&digests_array)],
        )
        .map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("setDigests failed: {}", e),
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
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("build failed: {}", e),
            })?;

        let spec = spec.l().map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("Spec conversion failed: {}", e),
        })?;

        // Initialize generator
        env.call_method(
            &key_pair_gen,
            "initialize",
            "(Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[JValue::Object(&spec)],
        )
        .map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("initialize failed: {}", e),
        })?;

        // Generate key pair
        env.call_method(
            &key_pair_gen,
            "generateKeyPair",
            "()Ljava/security/KeyPair;",
            &[],
        )
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

        let vm = get_java_vm().ok_or_else(|| KeyringError::HardwareNotAvailable {
            reason: "JNI not initialized".into(),
        })?;

        let mut env =
            vm.attach_current_thread()
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("JNI attach failed: {}", e),
                })?;

        let keystore = Self::get_keystore(&mut env)?;

        let alias_str = env
            .new_string(alias)
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("JNI string creation failed: {}", e),
            })?;

        let exists = env
            .call_method(
                &keystore,
                "containsAlias",
                "(Ljava/lang/String;)Z",
                &[JValue::Object(&alias_str.into())],
            )
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("containsAlias failed: {}", e),
            })?;

        let result = exists.z().map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("Boolean conversion failed: {}", e),
        })?;

        debug!(alias = %alias, exists = result, "Key existence check complete");
        Ok(result)
    }

    #[cfg(target_os = "android")]
    async fn jni_delete_key(&self, alias: &str) -> Result<(), KeyringError> {
        info!(alias = %alias, "jni_delete_key called");

        let vm = get_java_vm().ok_or_else(|| KeyringError::HardwareNotAvailable {
            reason: "JNI not initialized".into(),
        })?;

        let mut env =
            vm.attach_current_thread()
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("JNI attach failed: {}", e),
                })?;

        let keystore = Self::get_keystore(&mut env)?;

        let alias_str = env
            .new_string(alias)
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("JNI string creation failed: {}", e),
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
                },
            };

            let play_integrity_token = match self.get_play_integrity_token().await {
                Ok(token) => Some(token),
                Err(e) => {
                    debug!(alias = %self.alias, error = %e, "Play Integrity token not available");
                    None
                },
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

// ============================================================================
// Hardware-Wrapped Ed25519 Signer
// ============================================================================
//
// Android Keystore doesn't support Ed25519 directly, so we use a hybrid approach:
// 1. Generate an AES-256-GCM key in Android Keystore (hardware-backed)
// 2. Use that AES key to encrypt the Ed25519 private key
// 3. Store the encrypted Ed25519 key on disk
//
// This provides hardware-backed protection for Ed25519 keys.

/// Hardware-wrapped Ed25519 signer for Android.
///
/// Uses an AES-256-GCM key stored in Android Keystore to protect the Ed25519
/// private key. The Ed25519 key is encrypted and stored on disk, but can only
/// be decrypted using the hardware-backed AES key.
pub struct HardwareWrappedEd25519Signer {
    /// Alias for the AES wrapper key in Android Keystore
    wrapper_key_alias: String,
    /// Path to the encrypted Ed25519 key file
    encrypted_key_path: std::path::PathBuf,
    /// Cached Ed25519 signing key (decrypted in memory when needed)
    #[cfg(target_os = "android")]
    cached_signing_key: std::sync::Mutex<Option<ed25519_dalek::SigningKey>>,
    /// Whether StrongBox is used for the wrapper key
    use_strongbox: bool,
}

/// Format of encrypted Ed25519 key on disk:
/// [12 bytes nonce][encrypted_key + 16 byte GCM tag]
const AES_GCM_NONCE_SIZE: usize = 12;
const AES_GCM_TAG_SIZE: usize = 16;
const ED25519_PRIVATE_KEY_SIZE: usize = 32;

impl HardwareWrappedEd25519Signer {
    /// Create a new hardware-wrapped Ed25519 signer.
    ///
    /// # Arguments
    /// * `alias` - Base alias for keys (wrapper key will be `{alias}_aes_wrapper`)
    /// * `key_dir` - Directory to store the encrypted Ed25519 key
    /// * `prefer_strongbox` - Whether to prefer StrongBox for the AES wrapper key
    pub fn new(
        alias: impl Into<String>,
        key_dir: impl Into<std::path::PathBuf>,
        prefer_strongbox: bool,
    ) -> Result<Self, KeyringError> {
        let alias = alias.into();
        let key_dir = key_dir.into();
        let wrapper_key_alias = format!("{}_aes_wrapper", alias);
        let encrypted_key_path = key_dir.join(format!("{}.ed25519.enc", alias));

        info!(
            alias = %alias,
            wrapper_alias = %wrapper_key_alias,
            key_path = ?encrypted_key_path,
            prefer_strongbox = prefer_strongbox,
            "HardwareWrappedEd25519Signer::new"
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
            wrapper_key_alias,
            encrypted_key_path,
            #[cfg(target_os = "android")]
            cached_signing_key: std::sync::Mutex::new(None),
            use_strongbox: prefer_strongbox,
        })
    }

    /// Check if an Ed25519 key exists (both wrapper key and encrypted key file).
    pub async fn key_exists(&self) -> Result<bool, KeyringError> {
        #[cfg(target_os = "android")]
        {
            // Check if wrapper key exists in Keystore
            let wrapper_exists = self.jni_aes_key_exists().await?;
            // Check if encrypted key file exists
            let file_exists = self.encrypted_key_path.exists();

            debug!(
                wrapper_alias = %self.wrapper_key_alias,
                wrapper_exists = wrapper_exists,
                file_exists = file_exists,
                "key_exists check"
            );

            Ok(wrapper_exists && file_exists)
        }

        #[cfg(not(target_os = "android"))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    /// Generate a new Ed25519 key protected by hardware-backed AES encryption.
    pub async fn generate_key(&self) -> Result<(), KeyringError> {
        info!(
            wrapper_alias = %self.wrapper_key_alias,
            "Generating hardware-wrapped Ed25519 key"
        );

        #[cfg(target_os = "android")]
        {
            // 1. Generate AES-256-GCM wrapper key in Android Keystore
            self.jni_generate_aes_wrapper_key().await?;

            // 2. Generate Ed25519 key pair in software
            use rand_core::OsRng;
            let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
            let private_key_bytes = signing_key.to_bytes();

            // 3. Encrypt the Ed25519 private key with the hardware-backed AES key
            let encrypted = self.jni_aes_encrypt(&private_key_bytes).await?;

            // 4. Write encrypted key to disk
            std::fs::write(&self.encrypted_key_path, &encrypted).map_err(|e| {
                error!("Failed to write encrypted key: {}", e);
                KeyringError::StorageFailed {
                    reason: format!("Failed to write encrypted key: {}", e),
                }
            })?;

            // 5. Cache the signing key
            {
                let mut cache = self.cached_signing_key.lock().unwrap();
                *cache = Some(signing_key);
            }

            info!(
                wrapper_alias = %self.wrapper_key_alias,
                encrypted_size = encrypted.len(),
                "Hardware-wrapped Ed25519 key generated successfully"
            );

            Ok(())
        }

        #[cfg(not(target_os = "android"))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    /// Import an existing Ed25519 key protected by hardware-backed AES encryption.
    ///
    /// This is used for Portal-issued keys that need to be stored with hardware protection.
    pub async fn import_key(&self, key_bytes: &[u8]) -> Result<(), KeyringError> {
        info!(
            wrapper_alias = %self.wrapper_key_alias,
            key_len = key_bytes.len(),
            "Importing hardware-wrapped Ed25519 key"
        );

        #[cfg(target_os = "android")]
        {
            if key_bytes.len() != ED25519_PRIVATE_KEY_SIZE {
                return Err(KeyringError::InvalidKey {
                    reason: format!(
                        "Ed25519 key must be {} bytes, got {}",
                        ED25519_PRIVATE_KEY_SIZE,
                        key_bytes.len()
                    ),
                });
            }

            // 1. Check if AES wrapper key exists, create if not
            if !self.jni_aes_key_exists().await? {
                info!(
                    wrapper_alias = %self.wrapper_key_alias,
                    "Creating new AES wrapper key for import"
                );
                self.jni_generate_aes_wrapper_key().await?;
            }

            // 2. Parse the Ed25519 key
            let mut key_array = [0u8; ED25519_PRIVATE_KEY_SIZE];
            key_array.copy_from_slice(key_bytes);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);

            // 3. Encrypt the Ed25519 private key with the hardware-backed AES key
            let encrypted = self.jni_aes_encrypt(key_bytes).await?;

            // 4. Write encrypted key to disk
            std::fs::write(&self.encrypted_key_path, &encrypted).map_err(|e| {
                error!("Failed to write encrypted key: {}", e);
                KeyringError::StorageFailed {
                    reason: format!("Failed to write encrypted key: {}", e),
                }
            })?;

            // 5. Cache the signing key
            {
                let mut cache = self.cached_signing_key.lock().unwrap();
                *cache = Some(signing_key);
            }

            info!(
                wrapper_alias = %self.wrapper_key_alias,
                encrypted_size = encrypted.len(),
                "Hardware-wrapped Ed25519 key imported successfully"
            );

            Ok(())
        }

        #[cfg(not(target_os = "android"))]
        {
            let _ = key_bytes;
            Err(KeyringError::NoPlatformSupport)
        }
    }

    /// Get the Ed25519 public key.
    pub async fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
        #[cfg(target_os = "android")]
        {
            let signing_key = self.get_or_load_signing_key().await?;
            let verifying_key = signing_key.verifying_key();
            Ok(verifying_key.to_bytes().to_vec())
        }

        #[cfg(not(target_os = "android"))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    /// Sign data with the Ed25519 key.
    pub async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        #[cfg(target_os = "android")]
        {
            use ed25519_dalek::Signer;
            let signing_key = self.get_or_load_signing_key().await?;
            let signature = signing_key.sign(data);
            Ok(signature.to_bytes().to_vec())
        }

        #[cfg(not(target_os = "android"))]
        {
            let _ = data;
            Err(KeyringError::NoPlatformSupport)
        }
    }

    /// Delete the Ed25519 key (both wrapper key and encrypted file).
    pub async fn delete_key(&self) -> Result<(), KeyringError> {
        info!(
            wrapper_alias = %self.wrapper_key_alias,
            "Deleting hardware-wrapped Ed25519 key"
        );

        #[cfg(target_os = "android")]
        {
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

            // Delete AES wrapper key from Keystore
            self.jni_delete_aes_wrapper_key().await?;

            info!(
                wrapper_alias = %self.wrapper_key_alias,
                "Hardware-wrapped Ed25519 key deleted"
            );

            Ok(())
        }

        #[cfg(not(target_os = "android"))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    #[cfg(target_os = "android")]
    async fn get_or_load_signing_key(&self) -> Result<ed25519_dalek::SigningKey, KeyringError> {
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

        let decrypted = self.jni_aes_decrypt(&encrypted).await?;

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

    // ========================================================================
    // JNI Methods for AES-256-GCM operations
    // ========================================================================

    #[cfg(target_os = "android")]
    async fn jni_aes_key_exists(&self) -> Result<bool, KeyringError> {
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

        let exists = env
            .call_method(
                &keystore,
                "containsAlias",
                "(Ljava/lang/String;)Z",
                &[JValue::Object(&alias_str.into())],
            )
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("containsAlias failed: {}", e),
            })?;

        exists.z().map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("Boolean conversion failed: {}", e),
        })
    }

    #[cfg(target_os = "android")]
    async fn jni_generate_aes_wrapper_key(&self) -> Result<(), KeyringError> {
        info!(
            wrapper_alias = %self.wrapper_key_alias,
            strongbox = self.use_strongbox,
            "Generating AES-256-GCM wrapper key in Android Keystore"
        );

        let vm = get_java_vm().ok_or_else(|| KeyringError::HardwareNotAvailable {
            reason: "JNI not initialized".into(),
        })?;

        let mut env =
            vm.attach_current_thread()
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("JNI attach failed: {}", e),
                })?;

        // Create KeyGenerator for AES
        let algo_str = env
            .new_string("AES")
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("JNI string creation failed: {}", e),
            })?;

        let provider_str =
            env.new_string("AndroidKeyStore")
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("JNI string creation failed: {}", e),
                })?;

        let kg_class = env.find_class("javax/crypto/KeyGenerator").map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("KeyGenerator class not found: {}", e),
            }
        })?;

        let key_gen = env
            .call_static_method(
                kg_class,
                "getInstance",
                "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
                &[
                    JValue::Object(&algo_str.into()),
                    JValue::Object(&provider_str.into()),
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
        // PURPOSE_ENCRYPT | PURPOSE_DECRYPT = 1 | 2 = 3
        let purposes = 3i32;

        let alias_str = env.new_string(&self.wrapper_key_alias).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("JNI string creation failed: {}", e),
            }
        })?;

        let builder_class = env
            .find_class("android/security/keystore/KeyGenParameterSpec$Builder")
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("KeyGenParameterSpec.Builder class not found: {}", e),
            })?;

        let builder = env
            .new_object(
                builder_class,
                "(Ljava/lang/String;I)V",
                &[JValue::Object(&alias_str.into()), JValue::Int(purposes)],
            )
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Builder construction failed: {}", e),
            })?;

        // Set key size to 256 bits
        env.call_method(
            &builder,
            "setKeySize",
            "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Int(256)],
        )
        .map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("setKeySize failed: {}", e),
        })?;

        // Set block modes - GCM
        let gcm_str = env
            .new_string("GCM")
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("String creation failed: {}", e),
            })?;

        let string_class =
            env.find_class("java/lang/String")
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("String class not found: {}", e),
                })?;

        let block_modes_array = env
            .new_object_array(1, string_class, &gcm_str)
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Block modes array creation failed: {}", e),
            })?;

        env.call_method(
            &builder,
            "setBlockModes",
            "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Object(&block_modes_array)],
        )
        .map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("setBlockModes failed: {}", e),
        })?;

        // Set encryption paddings - NONE for GCM
        let none_str =
            env.new_string("NoPadding")
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("String creation failed: {}", e),
                })?;

        // Need to find String class again since previous was moved
        let string_class2 =
            env.find_class("java/lang/String")
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("String class not found: {}", e),
                })?;

        let paddings_array = env
            .new_object_array(1, string_class2, &none_str)
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Paddings array creation failed: {}", e),
            })?;

        env.call_method(
            &builder,
            "setEncryptionPaddings",
            "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Object(&paddings_array)],
        )
        .map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("setEncryptionPaddings failed: {}", e),
        })?;

        // Set StrongBox if requested
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
            "AES-256-GCM wrapper key generated in Android Keystore"
        );

        Ok(())
    }

    #[cfg(target_os = "android")]
    async fn jni_aes_encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, KeyringError> {
        debug!(
            wrapper_alias = %self.wrapper_key_alias,
            plaintext_len = plaintext.len(),
            "AES-GCM encrypting"
        );

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

        // Create Cipher instance
        let transformation = env.new_string("AES/GCM/NoPadding").map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("String creation failed: {}", e),
            }
        })?;

        let cipher_class = env.find_class("javax/crypto/Cipher").map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Cipher class not found: {}", e),
            }
        })?;

        let cipher = env
            .call_static_method(
                cipher_class,
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

        // Init cipher for encryption (ENCRYPT_MODE = 1)
        env.call_method(
            &cipher,
            "init",
            "(ILjava/security/Key;)V",
            &[JValue::Int(1), JValue::Object(&secret_key)],
        )
        .map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("Cipher.init failed: {}", e),
        })?;

        // Get the IV (nonce) that was automatically generated
        let iv = env
            .call_method(&cipher, "getIV", "()[B", &[])
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("getIV failed: {}", e),
            })?;

        let iv_obj = iv.l().map_err(|e| KeyringError::HardwareNotAvailable {
            reason: format!("IV conversion failed: {}", e),
        })?;

        let iv_array: JByteArray = iv_obj.into();
        let iv_bytes =
            env.convert_byte_array(iv_array)
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("IV byte array conversion failed: {}", e),
                })?;

        // Encrypt the plaintext
        let plaintext_array = env.byte_array_from_slice(plaintext).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Failed to create plaintext array: {}", e),
            }
        })?;

        let ciphertext = env
            .call_method(
                &cipher,
                "doFinal",
                "([B)[B",
                &[JValue::Object(&plaintext_array)],
            )
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("doFinal failed: {}", e),
            })?;

        let ciphertext_obj = ciphertext
            .l()
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Ciphertext conversion failed: {}", e),
            })?;

        let ciphertext_array: JByteArray = ciphertext_obj.into();
        let ciphertext_bytes = env.convert_byte_array(ciphertext_array).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Ciphertext byte array conversion failed: {}", e),
            }
        })?;

        // Combine IV + ciphertext
        let mut result = Vec::with_capacity(iv_bytes.len() + ciphertext_bytes.len());
        result.extend_from_slice(&iv_bytes);
        result.extend_from_slice(&ciphertext_bytes);

        debug!(
            wrapper_alias = %self.wrapper_key_alias,
            iv_len = iv_bytes.len(),
            ciphertext_len = ciphertext_bytes.len(),
            total_len = result.len(),
            "AES-GCM encryption complete"
        );

        Ok(result)
    }

    #[cfg(target_os = "android")]
    async fn jni_aes_decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, KeyringError> {
        debug!(
            wrapper_alias = %self.wrapper_key_alias,
            encrypted_len = encrypted.len(),
            "AES-GCM decrypting"
        );

        if encrypted.len() < AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE {
            return Err(KeyringError::StorageFailed {
                reason: format!(
                    "Encrypted data too short: {} bytes (min {})",
                    encrypted.len(),
                    AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE
                ),
            });
        }

        let vm = get_java_vm().ok_or_else(|| KeyringError::HardwareNotAvailable {
            reason: "JNI not initialized".into(),
        })?;

        let mut env =
            vm.attach_current_thread()
                .map_err(|e| KeyringError::HardwareNotAvailable {
                    reason: format!("JNI attach failed: {}", e),
                })?;

        // Split IV and ciphertext
        let (iv_bytes, ciphertext_bytes) = encrypted.split_at(AES_GCM_NONCE_SIZE);

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

        // Create GCMParameterSpec with the IV
        let gcm_spec_class = env
            .find_class("javax/crypto/spec/GCMParameterSpec")
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("GCMParameterSpec class not found: {}", e),
            })?;

        let iv_array = env.byte_array_from_slice(iv_bytes).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Failed to create IV array: {}", e),
            }
        })?;

        // GCM tag length in bits (128 bits = 16 bytes)
        let gcm_spec = env
            .new_object(
                gcm_spec_class,
                "(I[B)V",
                &[JValue::Int(128), JValue::Object(&iv_array)],
            )
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("GCMParameterSpec construction failed: {}", e),
            })?;

        // Create Cipher instance
        let transformation = env.new_string("AES/GCM/NoPadding").map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("String creation failed: {}", e),
            }
        })?;

        let cipher_class = env.find_class("javax/crypto/Cipher").map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Cipher class not found: {}", e),
            }
        })?;

        let cipher = env
            .call_static_method(
                cipher_class,
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

        // Init cipher for decryption (DECRYPT_MODE = 2)
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

        // Decrypt the ciphertext
        let ciphertext_array = env.byte_array_from_slice(ciphertext_bytes).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Failed to create ciphertext array: {}", e),
            }
        })?;

        let plaintext = env
            .call_method(
                &cipher,
                "doFinal",
                "([B)[B",
                &[JValue::Object(&ciphertext_array)],
            )
            .map_err(|e| {
                error!(
                    wrapper_alias = %self.wrapper_key_alias,
                    "AES-GCM decryption failed (authentication failure?): {}", e
                );
                KeyringError::HardwareNotAvailable {
                    reason: format!("Decryption failed: {}", e),
                }
            })?;

        let plaintext_obj = plaintext
            .l()
            .map_err(|e| KeyringError::HardwareNotAvailable {
                reason: format!("Plaintext conversion failed: {}", e),
            })?;

        let plaintext_array: JByteArray = plaintext_obj.into();
        let result = env.convert_byte_array(plaintext_array).map_err(|e| {
            KeyringError::HardwareNotAvailable {
                reason: format!("Plaintext byte array conversion failed: {}", e),
            }
        })?;

        debug!(
            wrapper_alias = %self.wrapper_key_alias,
            plaintext_len = result.len(),
            "AES-GCM decryption complete"
        );

        Ok(result)
    }

    #[cfg(target_os = "android")]
    async fn jni_delete_aes_wrapper_key(&self) -> Result<(), KeyringError> {
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

        env.call_method(
            &keystore,
            "deleteEntry",
            "(Ljava/lang/String;)V",
            &[JValue::Object(&alias_str.into())],
        )
        .map_err(|e| {
            warn!(
                wrapper_alias = %self.wrapper_key_alias,
                "deleteEntry failed: {}", e
            );
            KeyringError::HardwareNotAvailable {
                reason: format!("deleteEntry failed: {}", e),
            }
        })?;

        Ok(())
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

    #[test]
    fn test_hardware_wrapped_ed25519_creation() {
        #[cfg(target_os = "android")]
        {
            let signer =
                HardwareWrappedEd25519Signer::new("test_ed25519", "/tmp/ciris_test", false);
            assert!(signer.is_ok());
        }
    }
}
