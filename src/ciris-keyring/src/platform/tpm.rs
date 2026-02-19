//! TPM 2.0 hardware signer implementation.
//!
//! Uses tss-esapi for TPM 2.0 access on Linux and Windows.
//! Supports ECDSA P-256 for cross-platform compatibility.

use async_trait::async_trait;
use std::sync::Mutex;

use crate::error::KeyringError;
use crate::signer::{HardwareSigner, KeyGenConfig};
use crate::types::{ClassicalAlgorithm, HardwareType, PlatformAttestation};

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use crate::types::TpmAttestation;

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use std::str::FromStr;

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        resource_handles::Hierarchy,
    },
    structures::{
        Data, Digest, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme,
        PcrSelectionListBuilder, PcrSlot, Public, PublicBuilder, PublicEccParametersBuilder,
        SignatureScheme, SymmetricDefinitionObject,
    },
    tcti_ldr::{DeviceConfig, TctiNameConf},
    traits::Marshall,
    Context,
};

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use tss_esapi::handles::{NvIndexHandle, TpmHandle};

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use tss_esapi::interface_types::resource_handles::NvAuth;

/// TPM 2.0 signer for desktop and server platforms.
///
/// Supports both discrete TPMs and firmware TPMs (fTPM).
/// Uses ECDSA P-256 for compatibility with mobile platforms.
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
    /// Key handle for the current session
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    key_handle: Mutex<Option<KeyHandle>>,
}

impl TpmSigner {
    /// Create a new TPM signer.
    pub fn new(
        alias: impl Into<String>,
        persistent_handle: Option<u32>,
    ) -> Result<Self, KeyringError> {
        let alias = alias.into();

        let (available, is_discrete) = Self::detect_tpm()?;
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
            let context = Self::create_context()?;
            tracing::info!("TPM context created successfully");

            Ok(Self {
                alias,
                is_discrete,
                persistent_handle,
                context: Mutex::new(Some(context)),
                cached_public_key: Mutex::new(None),
                key_handle: Mutex::new(None),
            })
        }

        #[cfg(not(all(feature = "tpm", any(target_os = "linux", target_os = "windows"))))]
        {
            Err(KeyringError::HardwareNotAvailable {
                reason: "TPM support not compiled in (enable 'tpm' feature)".into(),
            })
        }
    }

    fn detect_tpm() -> Result<(bool, bool), KeyringError> {
        #[cfg(target_os = "linux")]
        {
            use std::path::Path;

            let has_tpm0 = Path::new("/dev/tpm0").exists();
            let has_tpmrm0 = Path::new("/dev/tpmrm0").exists();

            if !has_tpm0 && !has_tpmrm0 {
                tracing::debug!("TPM: no device nodes found (/dev/tpm0, /dev/tpmrm0)");
                return Ok((false, false));
            }

            tracing::info!(
                tpm0 = has_tpm0,
                tpmrm0 = has_tpmrm0,
                "TPM: device nodes detected"
            );

            let is_discrete = Self::check_if_discrete_tpm();
            Ok((true, is_discrete))
        }

        #[cfg(target_os = "windows")]
        {
            tracing::info!("TPM: checking Windows TPM availability");
            Ok((true, false))
        }

        #[cfg(target_os = "macos")]
        {
            Ok((false, false))
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            Ok((false, false))
        }
    }

    #[cfg(target_os = "linux")]
    fn check_if_discrete_tpm() -> bool {
        if let Some(manufacturer) = Self::get_tpm_manufacturer() {
            let lower = manufacturer.to_lowercase();
            if lower.contains("infineon")
                || lower.contains("stmicro")
                || lower.contains("nuvoton")
                || lower.contains("atmel")
            {
                tracing::info!("TPM: detected discrete TPM ({})", manufacturer.trim());
                return true;
            }
        }
        tracing::debug!("TPM: assuming firmware TPM (conservative default)");
        false
    }

    #[cfg(not(target_os = "linux"))]
    fn check_if_discrete_tpm() -> bool {
        false
    }

    /// Get TPM manufacturer string from sysfs.
    #[cfg(target_os = "linux")]
    fn get_tpm_manufacturer() -> Option<String> {
        // Try description first
        if let Ok(desc) = std::fs::read_to_string("/sys/class/tpm/tpm0/device/description") {
            return Some(desc.trim().to_string());
        }
        // Fallback to manufacturer ID
        if let Ok(id) = std::fs::read_to_string("/sys/class/tpm/tpm0/tpm_version_major") {
            return Some(format!("TPM {}", id.trim()));
        }
        None
    }

    /// Get TPM manufacturer string (non-Linux platforms).
    #[cfg(not(target_os = "linux"))]
    fn get_tpm_manufacturer() -> Option<String> {
        None
    }

    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    fn create_context() -> Result<Context, KeyringError> {
        #[cfg(target_os = "linux")]
        let tcti = {
            let device_path = if std::path::Path::new("/dev/tpmrm0").exists() {
                "/dev/tpmrm0"
            } else {
                "/dev/tpm0"
            };

            tracing::debug!("TPM: using device {}", device_path);

            let device_config =
                DeviceConfig::from_str(device_path).map_err(|e| KeyringError::HardwareError {
                    reason: format!("Failed to create device config: {}", e),
                })?;

            TctiNameConf::Device(device_config)
        };

        #[cfg(target_os = "windows")]
        let tcti = TctiNameConf::Tbs;

        tracing::debug!("TPM: creating context");

        Context::new(tcti).map_err(|e| {
            tracing::error!("TPM: failed to create context: {}", e);
            KeyringError::HardwareError {
                reason: format!("Failed to create TPM context: {}", e),
            }
        })
    }

    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    fn get_or_create_primary(context: &mut Context) -> Result<KeyHandle, KeyringError> {
        tracing::debug!("TPM: creating primary key under owner hierarchy");

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to build object attributes: {}", e),
            })?;

        let ecc_params = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::Null)
            .with_curve(EccCurve::NistP256)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
            .build()
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to build ECC parameters: {}", e),
            })?;

        let primary_public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(ecc_params)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to build primary public: {}", e),
            })?;

        let result = context
            .create_primary(Hierarchy::Owner, primary_public, None, None, None, None)
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to create primary key: {}", e),
            })?;

        tracing::info!("TPM: created primary key");
        Ok(result.key_handle)
    }

    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    fn create_signing_key(
        context: &mut Context,
        primary_handle: KeyHandle,
    ) -> Result<KeyHandle, KeyringError> {
        tracing::debug!("TPM: creating signing key under primary");

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .build()
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to build signing key attributes: {}", e),
            })?;

        let ecc_params = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
            .with_curve(EccCurve::NistP256)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .with_symmetric(SymmetricDefinitionObject::Null)
            .build()
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to build signing key ECC parameters: {}", e),
            })?;

        let signing_public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(ecc_params)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to build signing key public: {}", e),
            })?;

        let result = context
            .create(primary_handle, signing_public, None, None, None, None)
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to create signing key: {}", e),
            })?;

        let key_handle = context
            .load(primary_handle, result.out_private, result.out_public)
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to load signing key: {}", e),
            })?;

        tracing::info!("TPM: created and loaded signing key");
        Ok(key_handle)
    }

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

        let primary_handle = Self::get_or_create_primary(context)?;
        let signing_key = Self::create_signing_key(context, primary_handle)?;

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
        let validation = tss_esapi::structures::HashcheckTicket::try_from(
            tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
                tag: tss_esapi::constants::tss::TPM2_ST_HASHCHECK,
                hierarchy: tss_esapi::constants::tss::TPM2_RH_NULL,
                digest: tss_esapi::tss2_esys::TPM2B_DIGEST {
                    size: 0,
                    buffer: [0; 64],
                },
            },
        )
        .map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to create validation ticket: {}", e),
        })?;

        let signature = context
            .sign(
                key_handle,
                digest,
                SignatureScheme::EcDsa {
                    hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                },
                validation,
            )
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("TPM signing failed: {}", e),
            })?;

        let sig_bytes = Self::extract_ecdsa_signature(&signature)?;
        tracing::debug!(sig_len = sig_bytes.len(), "TPM: signature generated");
        Ok(sig_bytes)
    }

    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    fn extract_ecdsa_signature(
        signature: &tss_esapi::structures::Signature,
    ) -> Result<Vec<u8>, KeyringError> {
        match signature {
            tss_esapi::structures::Signature::EcDsa(ecdsa_sig) => {
                // Get raw bytes from EccParameter using value() method
                let r_bytes: Vec<u8> = ecdsa_sig.signature_r().value().to_vec();
                let s_bytes: Vec<u8> = ecdsa_sig.signature_s().value().to_vec();

                let mut sig = Vec::with_capacity(64);
                // Pad r to 32 bytes
                if r_bytes.len() < 32 {
                    sig.extend(std::iter::repeat(0u8).take(32 - r_bytes.len()));
                }
                sig.extend(&r_bytes[r_bytes.len().saturating_sub(32)..]);

                // Pad s to 32 bytes
                if s_bytes.len() < 32 {
                    sig.extend(std::iter::repeat(0u8).take(32 - s_bytes.len()));
                }
                sig.extend(&s_bytes[s_bytes.len().saturating_sub(32)..]);

                Ok(sig)
            },
            _ => Err(KeyringError::HardwareError {
                reason: "Unexpected signature type from TPM".into(),
            }),
        }
    }

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

        let (public, _, _) =
            context
                .read_public(key_handle)
                .map_err(|e| KeyringError::HardwareError {
                    reason: format!("Failed to read public key: {}", e),
                })?;

        // Extract ECC point
        let ecc_point = match public {
            Public::Ecc { unique, .. } => unique,
            _ => {
                return Err(KeyringError::HardwareError {
                    reason: "Key is not ECC".into(),
                })
            },
        };

        // Format as uncompressed point (0x04 || x || y)
        let x_bytes: Vec<u8> = ecc_point.x().value().to_vec();
        let y_bytes: Vec<u8> = ecc_point.y().value().to_vec();

        let mut pubkey = Vec::with_capacity(65);
        pubkey.push(0x04); // Uncompressed point indicator

        // Pad x to 32 bytes
        if x_bytes.len() < 32 {
            pubkey.extend(std::iter::repeat(0u8).take(32 - x_bytes.len()));
        }
        pubkey.extend(&x_bytes[x_bytes.len().saturating_sub(32)..]);

        // Pad y to 32 bytes
        if y_bytes.len() < 32 {
            pubkey.extend(std::iter::repeat(0u8).take(32 - y_bytes.len()));
        }
        pubkey.extend(&y_bytes[y_bytes.len().saturating_sub(32)..]);

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

    /// Generate a TPM quote over selected PCRs.
    ///
    /// This quotes PCRs 0-7 (platform configuration registers) which contain
    /// measurements of the boot process, firmware, and system configuration.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    fn generate_quote(&self) -> Result<TpmQuote, KeyringError> {
        use rand_core::{OsRng, RngCore};

        tracing::info!("TPM: generating PCR quote");

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

        // Generate a fresh nonce for anti-replay
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        let qualifying_data =
            Data::try_from(nonce.to_vec()).map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to create qualifying data: {}", e),
            })?;

        // Select PCRs 0-7 (boot measurements) with SHA-256
        let pcr_selection = PcrSelectionListBuilder::new()
            .with_selection(
                HashingAlgorithm::Sha256,
                &[
                    PcrSlot::Slot0,
                    PcrSlot::Slot1,
                    PcrSlot::Slot2,
                    PcrSlot::Slot3,
                    PcrSlot::Slot4,
                    PcrSlot::Slot5,
                    PcrSlot::Slot6,
                    PcrSlot::Slot7,
                ],
            )
            .build()
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to build PCR selection: {}", e),
            })?;

        // Generate quote using ECDSA with SHA-256
        let signing_scheme = SignatureScheme::EcDsa {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        };

        tracing::debug!(
            pcr_slots = "0-7",
            hash_alg = "SHA-256",
            "TPM: requesting quote"
        );

        let (attest, signature) = context
            .quote(key_handle, qualifying_data, signing_scheme, pcr_selection)
            .map_err(|e| {
                tracing::error!("TPM: quote generation failed: {}", e);
                KeyringError::HardwareError {
                    reason: format!("TPM quote failed: {}", e),
                }
            })?;

        // Serialize the attestation structure using TPM marshalling
        let quoted_bytes: Vec<u8> = attest.marshall().map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to marshall attestation: {}", e),
        })?;

        // Extract signature bytes
        let sig_bytes = Self::extract_ecdsa_signature(&signature)?;

        // PCR selection as bytes (bitmap representation)
        let pcr_selection_bytes: Vec<u8> = vec![0xFF]; // PCRs 0-7 selected

        tracing::info!(
            quoted_len = quoted_bytes.len(),
            sig_len = sig_bytes.len(),
            "TPM: quote generated successfully"
        );

        Ok(TpmQuote {
            quoted: quoted_bytes,
            signature: sig_bytes,
            pcr_selection: pcr_selection_bytes,
            nonce: nonce.to_vec(),
        })
    }

    /// Read the Endorsement Key (EK) certificate from TPM NV storage.
    ///
    /// EK certificates are provisioned by TPM manufacturers and can be used
    /// to verify the TPM is genuine. ECC EK cert is at NV index 0x01C0000A.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    fn read_ek_certificate(&self) -> Result<Vec<u8>, KeyringError> {
        tracing::info!("TPM: reading EK certificate from NV storage");

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

        // ECC EK certificate NV index (TCG spec)
        // RSA would be 0x01C00002, but we use ECC P-256
        const ECC_EK_CERT_NV_INDEX: u32 = 0x01C0_000A;

        // Create TPM handle for NV index
        let tpm_handle = TpmHandle::NvIndex(ECC_EK_CERT_NV_INDEX.try_into().map_err(|e| {
            KeyringError::HardwareError {
                reason: format!("Invalid NV index: {:?}", e),
            }
        })?);

        // Convert TPM handle to ESYS resource handle
        let object_handle = context.tr_from_tpm_public(tpm_handle).map_err(|e| {
            tracing::warn!(
                "TPM: EK cert NV index not found (may not be provisioned): {}",
                e
            );
            KeyringError::HardwareError {
                reason: format!("EK cert NV index not accessible: {}", e),
            }
        })?;

        let nv_index_handle = NvIndexHandle::from(object_handle);

        // Read the NV public to get the size
        let (nv_public, _name) = context.nv_read_public(nv_index_handle).map_err(|e| {
            tracing::warn!("TPM: EK cert NV read public failed: {}", e);
            KeyringError::HardwareError {
                reason: format!("EK cert NV read public failed: {}", e),
            }
        })?;

        let cert_size = nv_public.data_size() as u16;
        tracing::debug!(cert_size = cert_size, "TPM: EK cert NV size");

        if cert_size == 0 {
            return Err(KeyringError::HardwareError {
                reason: "EK certificate NV area is empty".into(),
            });
        }

        // Read the certificate data in chunks (max 1024 bytes per read)
        let mut cert_data = Vec::with_capacity(cert_size as usize);
        let mut offset = 0u16;
        const MAX_NV_READ: u16 = 1024;

        while offset < cert_size {
            let read_size = std::cmp::min(MAX_NV_READ, cert_size.saturating_sub(offset));

            let chunk = context
                .nv_read(NvAuth::Owner, nv_index_handle, read_size, offset)
                .map_err(|e| {
                    tracing::error!("TPM: NV read failed at offset {}: {}", offset, e);
                    KeyringError::HardwareError {
                        reason: format!("NV read failed: {}", e),
                    }
                })?;

            cert_data.extend_from_slice(&chunk);
            offset += read_size;
        }

        tracing::info!(
            cert_len = cert_data.len(),
            "TPM: EK certificate read successfully"
        );

        Ok(cert_data)
    }
}

/// TPM quote structure containing PCR attestation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TpmQuote {
    /// The quoted data (TPMS_ATTEST serialized)
    pub quoted: Vec<u8>,
    /// Signature over the quote (ECDSA P-256)
    pub signature: Vec<u8>,
    /// PCR selection bitmap (which PCRs were quoted)
    pub pcr_selection: Vec<u8>,
    /// Nonce used in the quote (for freshness)
    pub nonce: Vec<u8>,
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
        #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
        {
            tracing::debug!("TPM: generating full attestation with quote and EK cert");

            // Get manufacturer from sysfs if available
            let manufacturer = Self::get_tpm_manufacturer().unwrap_or_else(|| "Unknown".into());

            // Generate TPM quote over PCRs 0-7
            let quote = match self.generate_quote() {
                Ok(q) => {
                    tracing::info!("TPM: quote generated successfully");
                    Some(serde_json::to_vec(&q).unwrap_or_default())
                },
                Err(e) => {
                    tracing::warn!("TPM: quote generation failed (non-fatal): {}", e);
                    None
                },
            };

            // Read EK certificate from NV storage
            let ek_cert = match self.read_ek_certificate() {
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
                quote,
                ek_cert,
            }))
        }

        #[cfg(not(all(feature = "tpm", any(target_os = "linux", target_os = "windows"))))]
        {
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
        let result = TpmSigner::detect_tpm();
        assert!(result.is_ok());
        let (available, _is_discrete) = result.unwrap();
        println!("TPM available: {}", available);
    }
}
