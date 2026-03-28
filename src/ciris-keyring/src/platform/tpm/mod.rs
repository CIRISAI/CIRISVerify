//! TPM 2.0 hardware signer implementation.
//!
//! Uses tss-esapi for TPM 2.0 access on Linux and Windows.
//! Supports ECDSA P-256 for cross-platform compatibility.
//!
//! ## Module Structure
//!
//! - `detection`: TPM detection and context creation
//! - `keys`: Key creation (primary, signing, attestation)
//! - `signing`: Signing helpers (signature extraction)
//! - `quote`: Quote generation and EK certificate reading

mod detection;
mod keys;
mod quote;
mod signing;
mod wrapping;

// Re-export public items
// Detection functions work on all platforms
pub use detection::{detect_tpm, get_tpm_manufacturer};

// TPM-specific functions require the tpm feature
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub use detection::create_context;
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub use keys::{
    create_attestation_key, create_signing_key, extract_public_key_from_public,
    get_or_create_primary,
};
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub use quote::{read_ek_certificate, read_pcr_values};
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub use signing::{create_null_validation_ticket, extract_ecdsa_signature};

// TpmQuote is always available (just a data struct)
pub use quote::TpmQuote;

// TPM-wrapped Ed25519 signer for hardware-backed key storage
pub use wrapping::TpmWrappedEd25519Signer;

use async_trait::async_trait;
use std::sync::Mutex;

use crate::error::KeyringError;
use crate::signer::{HardwareSigner, KeyGenConfig};
use crate::types::{ClassicalAlgorithm, HardwareType, PlatformAttestation};

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use crate::types::{TpmAttestation, TpmQuoteData};

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use tss_esapi::{
    handles::KeyHandle,
    interface_types::algorithm::HashingAlgorithm,
    structures::{Digest, HashScheme, SignatureScheme},
    Context,
};

/// TPM 2.0 signer for desktop and server platforms.
///
/// Supports both discrete TPMs and firmware TPMs (fTPM).
/// Uses ECDSA P-256 for compatibility with mobile platforms.
///
/// ## Dual-Key Architecture
///
/// The TPM signer maintains two keys:
/// - **Signing Key** (non-restricted): For signing arbitrary external data
/// - **Attestation Key** (restricted): For TPM quotes (PCR attestation)
///
/// This is necessary because TPM2_Quote requires a restricted key, which
/// can only sign TPM-generated data (not arbitrary challenges).
pub struct TpmSigner {
    /// Key alias for identification
    alias: String,
    /// Whether this is a discrete TPM (vs firmware TPM)
    is_discrete: bool,
    /// Persistent handle for the signing key (0x81000000 - 0x81FFFFFF)
    #[allow(dead_code)]
    persistent_handle: Option<u32>,
    /// TPM context (wrapped in Mutex for interior mutability)
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    context: Mutex<Option<Context>>,
    /// Cached public key bytes
    #[allow(dead_code)]
    cached_public_key: Mutex<Option<Vec<u8>>>,
    /// Signing key handle (non-restricted, for external data)
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    key_handle: Mutex<Option<KeyHandle>>,
    /// Attestation key handle (restricted, for quotes)
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    attestation_key_handle: Mutex<Option<KeyHandle>>,
    /// Cached attestation key public key
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    ak_public_key: Mutex<Option<Vec<u8>>>,
}

impl TpmSigner {
    /// Create a new TPM signer.
    pub fn new(
        alias: impl Into<String>,
        persistent_handle: Option<u32>,
    ) -> Result<Self, KeyringError> {
        let alias = alias.into();

        let (available, is_discrete) = detect_tpm()?;
        if !available {
            return Err(KeyringError::HardwareNotAvailable {
                reason: "No TPM 2.0 found".into(),
            });
        }

        tracing::info!(
            alias = %alias,
            is_discrete = is_discrete,
            persistent_handle = ?persistent_handle,
            "TpmSigner: creating new TPM signer"
        );

        #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
        {
            let context = create_context()?;
            tracing::info!("TPM context created successfully");

            Ok(Self {
                alias,
                is_discrete,
                persistent_handle,
                context: Mutex::new(Some(context)),
                cached_public_key: Mutex::new(None),
                key_handle: Mutex::new(None),
                attestation_key_handle: Mutex::new(None),
                ak_public_key: Mutex::new(None),
            })
        }

        #[cfg(not(all(feature = "tpm", any(target_os = "linux", target_os = "windows"))))]
        {
            Err(KeyringError::HardwareNotAvailable {
                reason: "TPM support not compiled in (enable 'tpm' feature)".into(),
            })
        }
    }

    /// Ensure the signing key is available.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    fn ensure_key(&self) -> Result<KeyHandle, KeyringError> {
        {
            let handle_guard = self
                .key_handle
                .lock()
                .map_err(|_| KeyringError::HardwareError {
                    reason: "Key handle lock poisoned".into(),
                })?;
            if let Some(handle) = *handle_guard {
                tracing::trace!("TPM: using cached key handle");
                return Ok(handle);
            }
        }

        tracing::debug!("TPM: no cached key handle, creating new key");

        let mut context_guard = self
            .context
            .lock()
            .map_err(|_| KeyringError::HardwareError {
                reason: "Context lock poisoned".into(),
            })?;

        let context = context_guard
            .as_mut()
            .ok_or_else(|| KeyringError::HardwareError {
                reason: "TPM context not initialized".into(),
            })?;

        let primary_handle = get_or_create_primary(context)?;
        let signing_key = create_signing_key(context, primary_handle)?;

        let mut handle_guard = self
            .key_handle
            .lock()
            .map_err(|_| KeyringError::HardwareError {
                reason: "Key handle lock poisoned".into(),
            })?;
        *handle_guard = Some(signing_key);

        if let Err(e) = context.flush_context(primary_handle.into()) {
            tracing::warn!("TPM: failed to flush primary handle: {}", e);
        }

        Ok(signing_key)
    }

    /// Ensure the attestation key (AK) is available for quote operations.
    ///
    /// Returns both the key handle and the public key bytes.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    fn ensure_attestation_key(&self) -> Result<(KeyHandle, Vec<u8>), KeyringError> {
        // Check if we have a cached attestation key
        {
            let handle_guard =
                self.attestation_key_handle
                    .lock()
                    .map_err(|_| KeyringError::HardwareError {
                        reason: "AK handle lock poisoned".into(),
                    })?;
            let pubkey_guard =
                self.ak_public_key
                    .lock()
                    .map_err(|_| KeyringError::HardwareError {
                        reason: "AK pubkey lock poisoned".into(),
                    })?;
            if let (Some(handle), Some(pubkey)) = (*handle_guard, pubkey_guard.as_ref()) {
                tracing::trace!("TPM: using cached attestation key handle");
                return Ok((handle, pubkey.clone()));
            }
        }

        tracing::debug!("TPM: no cached attestation key, creating new AK");

        let mut context_guard = self
            .context
            .lock()
            .map_err(|_| KeyringError::HardwareError {
                reason: "Context lock poisoned".into(),
            })?;

        let context = context_guard
            .as_mut()
            .ok_or_else(|| KeyringError::HardwareError {
                reason: "TPM context not initialized".into(),
            })?;

        let primary_handle = get_or_create_primary(context)?;
        let (ak_handle, ak_pubkey) = create_attestation_key(context, primary_handle)?;

        // Cache the attestation key handle and public key
        {
            let mut handle_guard =
                self.attestation_key_handle
                    .lock()
                    .map_err(|_| KeyringError::HardwareError {
                        reason: "AK handle lock poisoned".into(),
                    })?;
            *handle_guard = Some(ak_handle);
        }
        {
            let mut pubkey_guard =
                self.ak_public_key
                    .lock()
                    .map_err(|_| KeyringError::HardwareError {
                        reason: "AK pubkey lock poisoned".into(),
                    })?;
            *pubkey_guard = Some(ak_pubkey.clone());
        }

        if let Err(e) = context.flush_context(primary_handle.into()) {
            tracing::warn!("TPM: failed to flush primary handle: {}", e);
        }

        Ok((ak_handle, ak_pubkey))
    }

    /// Sign data using the TPM signing key.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    async fn tpm_sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        use sha2::{Digest as Sha2Digest, Sha256};

        tracing::debug!(data_len = data.len(), "TPM: signing data");

        let key_handle = self.ensure_key()?;

        let mut context_guard = self
            .context
            .lock()
            .map_err(|_| KeyringError::HardwareError {
                reason: "Context lock poisoned".into(),
            })?;

        let context = context_guard
            .as_mut()
            .ok_or_else(|| KeyringError::HardwareError {
                reason: "TPM context not initialized".into(),
            })?;

        // Hash the data (TPM signs hashes, not raw data)
        let hash = Sha256::digest(data);

        let digest = Digest::try_from(&hash[..]).map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to create digest: {}", e),
        })?;

        // Create a null validation ticket for external data
        let validation = signing::create_null_validation_ticket()?;

        let signature = context
            .execute_with_nullauth_session(|ctx| {
                ctx.sign(
                    key_handle,
                    digest.clone(),
                    SignatureScheme::EcDsa {
                        hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                    },
                    validation.clone(),
                )
            })
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("TPM signing failed: {}", e),
            })?;

        let sig_bytes = extract_ecdsa_signature(&signature)?;
        tracing::debug!(sig_len = sig_bytes.len(), "TPM: signature generated");
        Ok(sig_bytes)
    }

    /// Get the public key from the TPM signing key.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    async fn tpm_get_public_key(&self) -> Result<Vec<u8>, KeyringError> {
        {
            let cache = self
                .cached_public_key
                .lock()
                .map_err(|_| KeyringError::HardwareError {
                    reason: "Public key cache lock poisoned".into(),
                })?;
            if let Some(ref pk) = *cache {
                tracing::trace!(len = pk.len(), "TPM: returning cached public key");
                return Ok(pk.clone());
            }
        }

        tracing::debug!("TPM: reading public key from TPM");

        let key_handle = self.ensure_key()?;

        let mut context_guard = self
            .context
            .lock()
            .map_err(|_| KeyringError::HardwareError {
                reason: "Context lock poisoned".into(),
            })?;

        let context = context_guard
            .as_mut()
            .ok_or_else(|| KeyringError::HardwareError {
                reason: "TPM context not initialized".into(),
            })?;

        let (public, _, _) = context
            .execute_without_session(|ctx| ctx.read_public(key_handle))
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to read public key: {}", e),
            })?;

        let pubkey = extract_public_key_from_public(&public)?;

        tracing::debug!(pubkey_len = pubkey.len(), "TPM: public key retrieved");

        // Cache the result
        {
            let mut cache =
                self.cached_public_key
                    .lock()
                    .map_err(|_| KeyringError::HardwareError {
                        reason: "Public key cache lock poisoned".into(),
                    })?;
            *cache = Some(pubkey.clone());
        }

        Ok(pubkey)
    }

    /// Generate a new key in the TPM.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    async fn tpm_generate_key(&self, config: &KeyGenConfig) -> Result<(), KeyringError> {
        tracing::info!(alias = %config.alias, "TPM: generating new key");

        // Clear any existing key handle
        {
            let mut handle_guard =
                self.key_handle
                    .lock()
                    .map_err(|_| KeyringError::HardwareError {
                        reason: "Key handle lock poisoned".into(),
                    })?;

            if let Some(handle) = handle_guard.take() {
                let mut context_guard =
                    self.context
                        .lock()
                        .map_err(|_| KeyringError::HardwareError {
                            reason: "Context lock poisoned".into(),
                        })?;

                if let Some(context) = context_guard.as_mut() {
                    if let Err(e) = context.flush_context(handle.into()) {
                        tracing::warn!("TPM: failed to flush old key handle: {}", e);
                    }
                }
            }
        }

        // Clear cached public key
        {
            let mut cache =
                self.cached_public_key
                    .lock()
                    .map_err(|_| KeyringError::HardwareError {
                        reason: "Public key cache lock poisoned".into(),
                    })?;
            *cache = None;
        }

        let _handle = self.ensure_key()?;
        tracing::info!("TPM: key generated successfully");
        Ok(())
    }

    /// Delete the key from the TPM.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    async fn tpm_delete_key(&self) -> Result<(), KeyringError> {
        tracing::info!("TPM: deleting key");

        {
            let mut handle_guard =
                self.key_handle
                    .lock()
                    .map_err(|_| KeyringError::HardwareError {
                        reason: "Key handle lock poisoned".into(),
                    })?;

            if let Some(handle) = handle_guard.take() {
                let mut context_guard =
                    self.context
                        .lock()
                        .map_err(|_| KeyringError::HardwareError {
                            reason: "Context lock poisoned".into(),
                        })?;

                if let Some(context) = context_guard.as_mut() {
                    if let Err(e) = context.flush_context(handle.into()) {
                        tracing::warn!("TPM: failed to flush key handle: {}", e);
                    }
                }
            }
        }

        {
            let mut cache =
                self.cached_public_key
                    .lock()
                    .map_err(|_| KeyringError::HardwareError {
                        reason: "Public key cache lock poisoned".into(),
                    })?;
            *cache = None;
        }

        tracing::info!("TPM: key deleted successfully");
        Ok(())
    }

    /// Generate a TPM quote using the attestation key.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    fn generate_quote(
        &self,
        external_nonce: Option<&[u8]>,
    ) -> Result<(TpmQuote, Vec<u8>), KeyringError> {
        // Use the restricted attestation key for quotes
        let (ak_handle, ak_pubkey) = self.ensure_attestation_key()?;

        let mut context_guard = self
            .context
            .lock()
            .map_err(|_| KeyringError::HardwareError {
                reason: "Context lock poisoned".into(),
            })?;

        let context = context_guard
            .as_mut()
            .ok_or_else(|| KeyringError::HardwareError {
                reason: "TPM context not initialized".into(),
            })?;

        let quote_data = quote::generate_quote(context, ak_handle, external_nonce)?;

        tracing::info!(
            ak_pubkey_len = ak_pubkey.len(),
            "TPM: quote generated with attestation key"
        );

        Ok((quote_data, ak_pubkey))
    }

    /// Read the EK certificate from TPM NV storage.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    fn read_ek_cert(&self) -> Result<Vec<u8>, KeyringError> {
        let mut context_guard = self
            .context
            .lock()
            .map_err(|_| KeyringError::HardwareError {
                reason: "Context lock poisoned".into(),
            })?;

        let context = context_guard
            .as_mut()
            .ok_or_else(|| KeyringError::HardwareError {
                reason: "TPM context not initialized".into(),
            })?;

        read_ek_certificate(context)
    }
}

#[async_trait]
impl HardwareSigner for TpmSigner {
    fn algorithm(&self) -> ClassicalAlgorithm {
        ClassicalAlgorithm::EcdsaP256
    }

    fn hardware_type(&self) -> HardwareType {
        if self.is_discrete {
            HardwareType::TpmDiscrete
        } else {
            HardwareType::TpmFirmware
        }
    }

    async fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
        #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
        {
            self.tpm_get_public_key().await
        }

        #[cfg(not(all(feature = "tpm", any(target_os = "linux", target_os = "windows"))))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
        {
            self.tpm_sign(data).await
        }

        #[cfg(not(all(feature = "tpm", any(target_os = "linux", target_os = "windows"))))]
        {
            let _ = data;
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
        // Default attestation uses no external nonce
        self.attestation_with_nonce(None).await
    }

    async fn attestation_with_nonce(
        &self,
        nonce: Option<&[u8]>,
    ) -> Result<PlatformAttestation, KeyringError> {
        #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
        {
            tracing::debug!(
                external_nonce = nonce.is_some(),
                "TPM: generating full attestation with quote and EK cert"
            );

            // Get manufacturer from sysfs if available
            let manufacturer = get_tpm_manufacturer().unwrap_or_else(|| "Unknown".into());

            // Generate TPM quote over PCRs 0-7, with optional external nonce
            let (quote_data, ak_public_key) = match self.generate_quote(nonce) {
                Ok((q, ak_pubkey)) => {
                    tracing::info!(
                        quoted_len = q.quoted.len(),
                        sig_len = q.signature.len(),
                        ak_pubkey_len = ak_pubkey.len(),
                        "TPM: quote generated successfully with attestation key"
                    );
                    // Read actual PCR values and convert to PcrValue structs
                    let pcr_values = match create_context() {
                        Ok(mut tpm_ctx) => match quote::read_pcr_values(&mut tpm_ctx) {
                            Ok(values) => {
                                tracing::debug!(pcr_count = values.len(), "Read PCR values");
                                let pcr_vec: Vec<crate::types::PcrValue> = values
                                    .into_iter()
                                    .map(|(index, digest)| crate::types::PcrValue { index, digest })
                                    .collect();
                                Some(pcr_vec)
                            },
                            Err(e) => {
                                tracing::warn!("Failed to read PCR values (non-fatal): {}", e);
                                None
                            },
                        },
                        Err(e) => {
                            tracing::warn!("Failed to create TPM context for PCR read: {}", e);
                            None
                        },
                    };

                    // Convert TpmQuote to TpmQuoteData for the public API
                    let quote_data = TpmQuoteData {
                        quoted: q.quoted,
                        signature: q.signature,
                        pcr_selection: q.pcr_selection,
                        qualifying_data: q.nonce,
                        pcr_values,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    };
                    (Some(quote_data), Some(ak_pubkey))
                },
                Err(e) => {
                    tracing::warn!("TPM: quote generation failed (non-fatal): {}", e);
                    (None, None)
                },
            };

            // Read EK certificate from NV storage
            let ek_cert = match self.read_ek_cert() {
                Ok(cert) => {
                    tracing::info!(cert_len = cert.len(), "TPM: EK cert retrieved");
                    Some(cert)
                },
                Err(e) => {
                    tracing::warn!("TPM: EK cert read failed (non-fatal): {}", e);
                    None
                },
            };

            Ok(PlatformAttestation::Tpm(TpmAttestation {
                tpm_version: "2.0".into(),
                manufacturer,
                discrete: self.is_discrete,
                quote: quote_data,
                ek_cert,
                ak_public_key,
            }))
        }

        #[cfg(not(all(feature = "tpm", any(target_os = "linux", target_os = "windows"))))]
        {
            let _ = nonce;
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn generate_key(&self, config: &KeyGenConfig) -> Result<(), KeyringError> {
        #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
        {
            self.tpm_generate_key(config).await
        }

        #[cfg(not(all(feature = "tpm", any(target_os = "linux", target_os = "windows"))))]
        {
            let _ = config;
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn key_exists(&self, _alias: &str) -> Result<bool, KeyringError> {
        #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
        {
            let handle_guard = self
                .key_handle
                .lock()
                .map_err(|_| KeyringError::HardwareError {
                    reason: "Key handle lock poisoned".into(),
                })?;

            let exists = handle_guard.is_some() || self.persistent_handle.is_some();
            tracing::trace!(exists = exists, "TPM: key_exists check");
            Ok(exists)
        }

        #[cfg(not(all(feature = "tpm", any(target_os = "linux", target_os = "windows"))))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn delete_key(&self, _alias: &str) -> Result<(), KeyringError> {
        #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
        {
            self.tpm_delete_key().await
        }

        #[cfg(not(all(feature = "tpm", any(target_os = "linux", target_os = "windows"))))]
        {
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
    fn test_tpm_detection() {
        let result = detect_tpm();
        assert!(result.is_ok());
        let (available, _is_discrete) = result.unwrap();
        println!("TPM available: {}", available);
    }

    #[test]
    fn test_tpm_signer_requires_tpm() {
        // TpmSigner::new should fail gracefully if no TPM
        let result = TpmSigner::new("test_key", None);
        // Either succeeds (TPM present) or fails with appropriate error
        match result {
            Ok(signer) => {
                assert_eq!(signer.current_alias(), "test_key");
                assert!(matches!(
                    signer.hardware_type(),
                    HardwareType::TpmDiscrete | HardwareType::TpmFirmware
                ));
                assert_eq!(signer.algorithm(), ClassicalAlgorithm::EcdsaP256);
            },
            Err(KeyringError::HardwareNotAvailable { .. }) => {
                // Expected on systems without TPM
            },
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_tpm_quote_struct() {
        let quote = TpmQuote {
            quoted: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            pcr_selection: vec![0xFF],
            nonce: vec![7, 8, 9],
        };

        assert_eq!(quote.quoted.len(), 3);
        assert_eq!(quote.signature.len(), 3);
        assert_eq!(quote.pcr_selection, vec![0xFF]);
        assert_eq!(quote.nonce.len(), 3);
    }

    #[test]
    fn test_module_exports() {
        // Verify all expected items are exported
        let _ = detect_tpm;
        let _ = get_tpm_manufacturer;

        #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
        {
            let _ = create_context;
            let _ = get_or_create_primary;
            let _ = create_signing_key;
            let _ = create_attestation_key;
            let _ = extract_public_key_from_public;
            let _ = extract_ecdsa_signature;
            let _ = read_ek_certificate;
        }
    }
}
