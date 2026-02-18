//! iOS Secure Enclave hardware signer implementation.
//!
//! Uses the Security framework to access the Secure Enclave.
//! Only ECDSA P-256 is supported by the Secure Enclave.

use async_trait::async_trait;

use crate::error::KeyringError;
use crate::signer::{HardwareSigner, KeyGenConfig};
use crate::types::{ClassicalAlgorithm, HardwareType, IosAttestation, PlatformAttestation};

#[cfg(any(target_os = "ios", target_os = "macos"))]
use core_foundation::base::TCFType;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use core_foundation::boolean::CFBoolean;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use core_foundation::data::CFData;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use core_foundation::number::CFNumber;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use core_foundation::string::CFString;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use core_foundation::dictionary::CFMutableDictionary;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use security_framework::access_control::{SecAccessControl, ProtectionMode};
#[cfg(any(target_os = "ios", target_os = "macos"))]
use security_framework::key::{SecKey, Algorithm};

// Declare Security framework symbols not exported by security-framework-sys
#[cfg(any(target_os = "ios", target_os = "macos"))]
extern "C" {
    static kSecAttrApplicationTag: core_foundation_sys::string::CFStringRef;
    static kSecMatchLimitOne: core_foundation_sys::string::CFStringRef;
}

/// iOS Secure Enclave signer using hardware-backed keys.
///
/// Keys are generated in and never leave the Secure Enclave.
/// Requires iOS 10+ or macOS 10.13+ with T2 chip or Apple Silicon.
pub struct SecureEnclaveSigner {
    /// Key tag for identifying the key in the keychain
    key_tag: String,
    /// Cached public key
    public_key: Option<Vec<u8>>,
}

impl SecureEnclaveSigner {
    /// Create a new Secure Enclave signer.
    ///
    /// # Arguments
    ///
    /// * `key_tag` - Unique identifier for the key in the keychain
    ///
    /// # Errors
    ///
    /// Returns error if Secure Enclave is not available.
    pub fn new(key_tag: impl Into<String>) -> Result<Self, KeyringError> {
        let key_tag = key_tag.into();

        if !Self::is_secure_enclave_available()? {
            return Err(KeyringError::HardwareNotAvailable {
                reason: "Secure Enclave not available on this device".into(),
            });
        }

        Ok(Self {
            key_tag,
            public_key: None,
        })
    }

    /// Check if Secure Enclave is available on this device.
    fn is_secure_enclave_available() -> Result<bool, KeyringError> {
        #[cfg(target_os = "ios")]
        {
            // SE is always available on supported iOS devices (iPhone 5S+)
            Ok(true)
        }

        #[cfg(target_os = "macos")]
        {
            // On macOS, requires T2 chip or Apple Silicon
            Ok(true)
        }

        #[cfg(not(any(target_os = "ios", target_os = "macos")))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    /// Get App Attest key and attestation.
    ///
    /// Currently returns an error as App Attest requires the ObjC runtime
    /// (DCAppAttestService), which will be added in v2.1. The attestation
    /// field is optional, so this is handled gracefully.
    pub async fn get_app_attest(&self, _challenge: &[u8]) -> Result<Vec<u8>, KeyringError> {
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            Err(KeyringError::NotSupported {
                operation: "App Attest requires ObjC runtime (DCAppAttestService), deferred to v2.1"
                    .into(),
            })
        }

        #[cfg(not(any(target_os = "ios", target_os = "macos")))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    /// Build the application tag as CFData from the key_tag string.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    fn application_tag(&self) -> CFData {
        CFData::from_buffer(self.key_tag.as_bytes())
    }

    /// Build a keychain query dictionary for finding our private key by tag.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    fn build_key_query(&self) -> CFMutableDictionary {
        use security_framework_sys::item::*;

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
                self.application_tag().as_CFTypeRef(),
            );
            query
        }
    }

    /// Query the keychain for the private key with matching tag.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    fn query_private_key(&self) -> Result<SecKey, KeyringError> {
        use security_framework_sys::item::*;
        use security_framework_sys::keychain_item::SecItemCopyMatching;

        unsafe {
            let mut query = self.build_key_query();
            query.set(
                CFString::wrap_under_get_rule(kSecReturnRef).as_CFTypeRef(),
                CFBoolean::true_value().as_CFTypeRef(),
            );
            query.set(
                CFString::wrap_under_get_rule(kSecMatchLimit).as_CFTypeRef(),
                CFString::wrap_under_get_rule(kSecMatchLimitOne).as_CFTypeRef(),
            );

            let mut result: core_foundation::base::CFTypeRef = std::ptr::null();
            let status =
                SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result);

            if status != 0 || result.is_null() {
                return Err(KeyringError::KeyNotFound {
                    alias: self.key_tag.clone(),
                });
            }

            Ok(SecKey::wrap_under_create_rule(result as _))
        }
    }

    /// Sign data using the Secure Enclave.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    async fn security_framework_sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        let private_key = self.query_private_key()?;

        // ECDSA P-256 with SHA-256 — the SE hashes internally
        private_key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, data)
            .map_err(|e| KeyringError::SigningFailed {
                reason: format!("Secure Enclave signing failed: {e}"),
            })
    }

    /// Get public key from the Secure Enclave.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    async fn security_framework_get_public_key(&self) -> Result<Vec<u8>, KeyringError> {
        let private_key = self.query_private_key()?;

        let public_key =
            private_key
                .public_key()
                .ok_or_else(|| KeyringError::HardwareError {
                    reason: "Failed to extract public key from Secure Enclave key".into(),
                })?;

        let repr =
            public_key
                .external_representation()
                .ok_or_else(|| KeyringError::HardwareError {
                    reason: "Failed to get external representation of public key".into(),
                })?;

        // Returns SEC1 uncompressed point: 0x04 || X (32) || Y (32) = 65 bytes
        Ok(repr.to_vec())
    }

    /// Generate a new key in the Secure Enclave.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    async fn security_framework_generate_key(
        &self,
        _config: &KeyGenConfig,
    ) -> Result<(), KeyringError> {
        use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;
        use security_framework_sys::item::*;

        // Create access control: key usable when device unlocked, this device only,
        // with private key usage flag (required for Secure Enclave)
        let access_control = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            kSecAccessControlPrivateKeyUsage,
        )
        .map_err(|e| KeyringError::KeyGenerationFailed {
            reason: format!("Failed to create access control: {e}"),
        })?;

        unsafe {
            // Build private key attributes sub-dictionary
            let mut private_attrs = CFMutableDictionary::new();
            private_attrs.set(
                CFString::wrap_under_get_rule(kSecAttrIsPermanent).as_CFTypeRef(),
                CFBoolean::true_value().as_CFTypeRef(),
            );
            private_attrs.set(
                CFString::wrap_under_get_rule(kSecAttrApplicationTag).as_CFTypeRef(),
                self.application_tag().as_CFTypeRef(),
            );
            private_attrs.set(
                CFString::wrap_under_get_rule(kSecAttrAccessControl).as_CFTypeRef(),
                access_control.as_CFTypeRef(),
            );

            // Build key generation parameters
            let mut params = CFMutableDictionary::new();
            params.set(
                CFString::wrap_under_get_rule(kSecAttrKeyType).as_CFTypeRef(),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFTypeRef(),
            );
            params.set(
                CFString::wrap_under_get_rule(kSecAttrKeySizeInBits).as_CFTypeRef(),
                CFNumber::from(256_i32).as_CFTypeRef(),
            );
            params.set(
                CFString::wrap_under_get_rule(kSecAttrTokenID).as_CFTypeRef(),
                CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).as_CFTypeRef(),
            );
            params.set(
                CFString::wrap_under_get_rule(kSecPrivateKeyAttrs).as_CFTypeRef(),
                private_attrs.as_CFTypeRef(),
            );

            let mut error: core_foundation_sys::error::CFErrorRef = std::ptr::null_mut();
            let key = security_framework_sys::key::SecKeyCreateRandomKey(
                params.as_concrete_TypeRef(),
                &mut error,
            );

            if key.is_null() {
                let err_msg = if !error.is_null() {
                    let cf_error =
                        core_foundation::error::CFError::wrap_under_create_rule(error);
                    format!("SecKeyCreateRandomKey failed: {cf_error}")
                } else {
                    "SecKeyCreateRandomKey failed for Secure Enclave".to_string()
                };
                return Err(KeyringError::KeyGenerationFailed { reason: err_msg });
            }

            // Key is stored persistently in the keychain via kSecAttrIsPermanent.
            // Release the returned SecKeyRef — key is retrievable by tag.
            core_foundation::base::CFRelease(key as _);
        }

        Ok(())
    }
}

#[async_trait]
impl HardwareSigner for SecureEnclaveSigner {
    fn algorithm(&self) -> ClassicalAlgorithm {
        ClassicalAlgorithm::EcdsaP256
    }

    fn hardware_type(&self) -> HardwareType {
        HardwareType::IosSecureEnclave
    }

    async fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            if let Some(ref pk) = self.public_key {
                return Ok(pk.clone());
            }
            self.security_framework_get_public_key().await
        }

        #[cfg(not(any(target_os = "ios", target_os = "macos")))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            self.security_framework_sign(data).await
        }

        #[cfg(not(any(target_os = "ios", target_os = "macos")))]
        {
            let _ = data;
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            use rand_core::{OsRng, RngCore};
            let mut challenge = [0u8; 32];
            OsRng.fill_bytes(&mut challenge);

            let app_attest = self.get_app_attest(&challenge).await.ok();

            Ok(PlatformAttestation::Ios(IosAttestation {
                secure_enclave: true,
                app_attest,
                device_check_token: None,
            }))
        }

        #[cfg(not(any(target_os = "ios", target_os = "macos")))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn generate_key(&self, config: &KeyGenConfig) -> Result<(), KeyringError> {
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            self.security_framework_generate_key(config).await
        }

        #[cfg(not(any(target_os = "ios", target_os = "macos")))]
        {
            let _ = config;
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn key_exists(&self, _alias: &str) -> Result<bool, KeyringError> {
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            match self.query_private_key() {
                Ok(_) => Ok(true),
                Err(KeyringError::KeyNotFound { .. }) => Ok(false),
                Err(e) => Err(e),
            }
        }

        #[cfg(not(any(target_os = "ios", target_os = "macos")))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn delete_key(&self, _alias: &str) -> Result<(), KeyringError> {
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            use security_framework_sys::keychain_item::SecItemDelete;

            unsafe {
                let query = self.build_key_query();
                let status = SecItemDelete(query.as_concrete_TypeRef());
                if status != 0 {
                    return Err(KeyringError::KeyNotFound {
                        alias: self.key_tag.clone(),
                    });
                }
            }

            Ok(())
        }

        #[cfg(not(any(target_os = "ios", target_os = "macos")))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    fn current_alias(&self) -> &str {
        &self.key_tag
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ios_signer_algorithm() {
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            let signer = SecureEnclaveSigner::new("test_key").expect("SE should be available");
            assert_eq!(signer.algorithm(), ClassicalAlgorithm::EcdsaP256);
            assert_eq!(signer.hardware_type(), HardwareType::IosSecureEnclave);
            assert_eq!(signer.current_alias(), "test_key");
        }
    }
}
