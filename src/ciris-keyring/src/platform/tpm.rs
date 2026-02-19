//! TPM 2.0 hardware signer implementation.
//!
//! Uses tss-esapi for TPM 2.0 access on Linux and Windows.
//! Supports ECDSA P-256 for cross-platform compatibility.

use async_trait::async_trait;
use std::sync::Mutex;

use crate::error::KeyringError;
use crate::signer::{HardwareSigner, KeyGenConfig};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use crate::types::TpmAttestation;
use crate::types::{ClassicalAlgorithm, HardwareType, PlatformAttestation};

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    handles::{KeyHandle, PersistentTpmHandle, TpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        Digest, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, Public,
        PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa, RsaExponent, RsaScheme,
        SignatureScheme, SymmetricDefinitionObject,
    },
    tcti_ldr::TctiNameConf,
    Context,
};

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
    persistent_handle: Option<u32>,
    /// TPM context (wrapped in Mutex for interior mutability)
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    context: Mutex<Option<Context>>,
    /// Cached public key bytes
    cached_public_key: Mutex<Option<Vec<u8>>>,
    /// Key handle for the current session
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    key_handle: Mutex<Option<KeyHandle>>,
}

impl TpmSigner {
    /// Create a new TPM signer.
    ///
    /// # Arguments
    ///
    /// * `alias` - Identifier for the key
    /// * `persistent_handle` - Optional persistent handle (if key already exists)
    ///
    /// # Errors
    ///
    /// Returns error if TPM is not available.
    pub fn new(
        alias: impl Into<String>,
        persistent_handle: Option<u32>,
    ) -> Result<Self, KeyringError> {
        let alias = alias.into();

        // Check TPM availability
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
            // Try to create TPM context
            let context = Self::create_context()?;

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
            Ok(Self {
                alias,
                is_discrete,
                persistent_handle,
                cached_public_key: Mutex::new(None),
            })
        }
    }

    /// Detect TPM availability and type.
    fn detect_tpm() -> Result<(bool, bool), KeyringError> {
        #[cfg(target_os = "linux")]
        {
            use std::path::Path;

            // Check for TPM device nodes
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

            // Try to determine if discrete TPM by reading manufacturer info
            // For now, assume fTPM (conservative) - can be refined later
            let is_discrete = Self::check_if_discrete_tpm();

            Ok((true, is_discrete))
        }

        #[cfg(target_os = "windows")]
        {
            // Windows has built-in TPM support via TPM Base Services (TBS)
            // The presence of TPM can be checked via WMI or by trying to open TBS
            tracing::info!("TPM: checking Windows TPM availability");
            Ok((true, false)) // Assume available, actual check happens on context creation
        }

        #[cfg(target_os = "macos")]
        {
            // macOS with T2/Apple Silicon doesn't expose TPM traditionally
            // but has Secure Enclave (handled by separate implementation)
            Ok((false, false))
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            Ok((false, false))
        }
    }

    /// Check if TPM is discrete (vs firmware/integrated)
    #[cfg(target_os = "linux")]
    fn check_if_discrete_tpm() -> bool {
        // Read manufacturer from sysfs if available
        if let Ok(manufacturer) = std::fs::read_to_string("/sys/class/tpm/tpm0/device/description")
        {
            let lower = manufacturer.to_lowercase();
            // Discrete TPM manufacturers
            if lower.contains("infineon")
                || lower.contains("stmicro")
                || lower.contains("nuvoton")
                || lower.contains("atmel")
            {
                tracing::info!("TPM: detected discrete TPM ({})", manufacturer.trim());
                return true;
            }
        }

        // Check capabilities file for firmware TPM indicators
        if let Ok(caps) = std::fs::read_to_string("/sys/class/tpm/tpm0/caps") {
            if caps.contains("firmware") || caps.contains("fTPM") {
                tracing::info!("TPM: detected firmware TPM");
                return false;
            }
        }

        tracing::debug!("TPM: assuming firmware TPM (conservative default)");
        false
    }

    #[cfg(not(target_os = "linux"))]
    fn check_if_discrete_tpm() -> bool {
        false
    }

    /// Create a TPM context.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    fn create_context() -> Result<Context, KeyringError> {
        #[cfg(target_os = "linux")]
        let tcti = {
            // Prefer tabrmd (resource manager) if available, fall back to device
            if std::path::Path::new("/dev/tpmrm0").exists() {
                TctiNameConf::Device(std::path::PathBuf::from("/dev/tpmrm0"))
            } else {
                TctiNameConf::Device(std::path::PathBuf::from("/dev/tpm0"))
            }
        };

        #[cfg(target_os = "windows")]
        let tcti = TctiNameConf::Tbs;

        tracing::debug!("TPM: creating context with TCTI: {:?}", tcti);

        Context::new(tcti).map_err(|e| {
            tracing::error!("TPM: failed to create context: {}", e);
            KeyringError::HardwareError {
                reason: format!("Failed to create TPM context: {}", e),
            }
        })
    }

    /// Get or create the primary key under the owner hierarchy.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    fn get_or_create_primary(context: &mut Context) -> Result<KeyHandle, KeyringError> {
        tracing::debug!("TPM: creating primary key under owner hierarchy");

        // Define primary key template (ECC P-256)
        let primary_public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(
                ObjectAttributesBuilder::new()
                    .with_fixed_tpm(true)
                    .with_fixed_parent(true)
                    .with_sensitive_data_origin(true)
                    .with_user_with_auth(true)
                    .with_decrypt(true)
                    .with_restricted(true)
                    .build()
                    .map_err(|e| KeyringError::HardwareError {
                        reason: format!("Failed to build object attributes: {}", e),
                    })?,
            )
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_ecc_scheme(EccScheme::Null)
                    .with_curve(EccCurve::NistP256)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                    .build()
                    .map_err(|e| KeyringError::HardwareError {
                        reason: format!("Failed to build ECC parameters: {}", e),
                    })?,
            )
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to build primary public: {}", e),
            })?;

        let primary_handle = context
            .create_primary(Hierarchy::Owner, primary_public, None, None, None, None)
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to create primary key: {}", e),
            })?
            .key_handle;

        tracing::info!("TPM: created primary key handle");
        Ok(primary_handle)
    }

    /// Create a signing key under the primary.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    fn create_signing_key(
        context: &mut Context,
        primary_handle: KeyHandle,
    ) -> Result<KeyHandle, KeyringError> {
        tracing::debug!("TPM: creating signing key under primary");

        // Define signing key template (ECC P-256, ECDSA)
        let signing_public = PublicBuilder::new()
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
                    .map_err(|e| KeyringError::HardwareError {
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
                    .map_err(|e| KeyringError::HardwareError {
                        reason: format!("Failed to build signing key ECC parameters: {}", e),
                    })?,
            )
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

        // Load the key
        let key_handle = context
            .load(primary_handle, result.out_private, result.out_public)
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to load signing key: {}", e),
            })?;

        tracing::info!("TPM: created and loaded signing key");
        Ok(key_handle)
    }

    /// Ensure we have a usable signing key.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    fn ensure_key(&self) -> Result<KeyHandle, KeyringError> {
        // Check if we already have a key handle
        {
            let handle_guard = self.key_handle.lock().map_err(|_| KeyringError::HardwareError {
                reason: "Key handle lock poisoned".into(),
            })?;
            if let Some(handle) = *handle_guard {
                return Ok(handle);
            }
        }

        // Need to create or load key
        let mut context_guard = self.context.lock().map_err(|_| KeyringError::HardwareError {
            reason: "Context lock poisoned".into(),
        })?;

        let context = context_guard.as_mut().ok_or_else(|| KeyringError::HardwareError {
            reason: "TPM context not initialized".into(),
        })?;

        // Check for persistent handle first
        if let Some(persistent) = self.persistent_handle {
            tracing::debug!("TPM: loading key from persistent handle 0x{:08x}", persistent);

            let handle = PersistentTpmHandle::new(persistent).map_err(|e| {
                KeyringError::HardwareError {
                    reason: format!("Invalid persistent handle: {}", e),
                }
            })?;

            let key_handle = context
                .tr_from_tpm_public(TpmHandle::Persistent(handle))
                .map_err(|e| KeyringError::HardwareError {
                    reason: format!("Failed to load persistent key: {}", e),
                })?
                .into();

            let mut handle_guard = self.key_handle.lock().map_err(|_| KeyringError::HardwareError {
                reason: "Key handle lock poisoned".into(),
            })?;
            *handle_guard = Some(key_handle);

            return Ok(key_handle);
        }

        // Create new key hierarchy
        let primary_handle = Self::get_or_create_primary(context)?;
        let signing_key = Self::create_signing_key(context, primary_handle)?;

        // Cache the handle
        let mut handle_guard = self.key_handle.lock().map_err(|_| KeyringError::HardwareError {
            reason: "Key handle lock poisoned".into(),
        })?;
        *handle_guard = Some(signing_key);

        // Flush the primary (we only need the signing key)
        let _ = context.flush_context(primary_handle.into());

        Ok(signing_key)
    }

    /// Get TPM quote for attestation.
    ///
    /// Creates a signed quote over PCRs and external data.
    #[allow(unused_variables)]
    pub async fn get_quote(
        &self,
        nonce: &[u8],
        pcr_selection: &[u8],
    ) -> Result<TpmQuote, KeyringError> {
        #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
        {
            use tss_esapi::{
                interface_types::algorithm::HashingAlgorithm,
                structures::{PcrSelectionListBuilder, PcrSlot},
            };

            tracing::debug!("TPM: generating quote with {} byte nonce", nonce.len());

            let key_handle = self.ensure_key()?;

            let mut context_guard =
                self.context.lock().map_err(|_| KeyringError::HardwareError {
                    reason: "Context lock poisoned".into(),
                })?;

            let context = context_guard
                .as_mut()
                .ok_or_else(|| KeyringError::HardwareError {
                    reason: "TPM context not initialized".into(),
                })?;

            // Build PCR selection (use SHA-256 bank, PCRs 0,1,2,3,7)
            let pcr_selection_list = PcrSelectionListBuilder::new()
                .with_selection(
                    HashingAlgorithm::Sha256,
                    &[
                        PcrSlot::Slot0,
                        PcrSlot::Slot1,
                        PcrSlot::Slot2,
                        PcrSlot::Slot3,
                        PcrSlot::Slot7,
                    ],
                )
                .build()
                .map_err(|e| KeyringError::HardwareError {
                    reason: format!("Failed to build PCR selection: {}", e),
                })?;

            // Create qualifying data from nonce
            let qualifying_data = Digest::try_from(nonce.to_vec()).map_err(|e| {
                KeyringError::HardwareError {
                    reason: format!("Invalid nonce for quote: {}", e),
                }
            })?;

            // Get the quote
            let (attest, signature) = context
                .quote(
                    key_handle,
                    qualifying_data,
                    SignatureScheme::EcDsa {
                        hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                    },
                    pcr_selection_list.clone(),
                )
                .map_err(|e| KeyringError::HardwareError {
                    reason: format!("TPM quote failed: {}", e),
                })?;

            // Read PCR values
            let (_, _, pcr_data) = context
                .pcr_read(pcr_selection_list)
                .map_err(|e| KeyringError::HardwareError {
                    reason: format!("Failed to read PCRs: {}", e),
                })?;

            // Serialize the results
            let quoted = attest.marshall().map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to marshal attest: {}", e),
            })?;

            let sig_bytes = match signature {
                tss_esapi::structures::Signature::EcDsa(ecdsa_sig) => {
                    let r = ecdsa_sig.signature_r().as_bytes();
                    let s = ecdsa_sig.signature_s().as_bytes();
                    let mut sig = Vec::with_capacity(64);
                    // Pad to 32 bytes each
                    sig.extend(std::iter::repeat(0).take(32 - r.len()));
                    sig.extend(r);
                    sig.extend(std::iter::repeat(0).take(32 - s.len()));
                    sig.extend(s);
                    sig
                }
                _ => {
                    return Err(KeyringError::HardwareError {
                        reason: "Unexpected signature type from TPM".into(),
                    })
                }
            };

            // Serialize PCR values
            let pcr_bytes = pcr_data
                .pcr_bank(HashingAlgorithm::Sha256)
                .map(|bank| {
                    bank.into_iter()
                        .flat_map(|(_, digest)| digest.as_bytes().to_vec())
                        .collect()
                })
                .unwrap_or_default();

            tracing::info!("TPM: quote generated successfully");

            Ok(TpmQuote {
                quoted,
                signature: sig_bytes,
                pcr_values: pcr_bytes,
            })
        }

        #[cfg(not(all(feature = "tpm", any(target_os = "linux", target_os = "windows"))))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    /// Get Endorsement Key certificate chain.
    #[allow(unused_variables)]
    pub async fn get_ek_cert(&self) -> Result<Vec<u8>, KeyringError> {
        #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
        {
            use tss_esapi::handles::NvIndexTpmHandle;

            tracing::debug!("TPM: retrieving EK certificate");

            let mut context_guard =
                self.context.lock().map_err(|_| KeyringError::HardwareError {
                    reason: "Context lock poisoned".into(),
                })?;

            let context = context_guard
                .as_mut()
                .ok_or_else(|| KeyringError::HardwareError {
                    reason: "TPM context not initialized".into(),
                })?;

            // EK cert is typically at NV index 0x01C00002 (RSA) or 0x01C0000A (ECC)
            // Try ECC first since we use ECC keys
            let nv_indices = [0x01C0000Au32, 0x01C00002u32];

            for nv_index in nv_indices {
                let nv_handle = match NvIndexTpmHandle::new(nv_index) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                // Try to read the NV index
                match context.nv_read_public(nv_handle.into()) {
                    Ok((public, _)) => {
                        let size = public.data_size();
                        match context.nv_read(nv_handle.into(), size, 0.into()) {
                            Ok(data) => {
                                tracing::info!(
                                    "TPM: retrieved EK cert from NV index 0x{:08x} ({} bytes)",
                                    nv_index,
                                    data.len()
                                );
                                return Ok(data.to_vec());
                            }
                            Err(e) => {
                                tracing::debug!(
                                    "TPM: failed to read NV index 0x{:08x}: {}",
                                    nv_index,
                                    e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            "TPM: NV index 0x{:08x} not found: {}",
                            nv_index,
                            e
                        );
                    }
                }
            }

            Err(KeyringError::HardwareError {
                reason: "EK certificate not found in TPM NV storage".into(),
            })
        }

        #[cfg(not(all(feature = "tpm", any(target_os = "linux", target_os = "windows"))))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    /// Sign data using the TPM.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    async fn tpm_sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        use sha2::{Digest as Sha2Digest, Sha256};

        tracing::debug!("TPM: signing {} bytes of data", data.len());

        let key_handle = self.ensure_key()?;

        let mut context_guard = self.context.lock().map_err(|_| KeyringError::HardwareError {
            reason: "Context lock poisoned".into(),
        })?;

        let context = context_guard.as_mut().ok_or_else(|| KeyringError::HardwareError {
            reason: "TPM context not initialized".into(),
        })?;

        // Hash the data (TPM signs hashes, not raw data)
        let hash = Sha256::digest(data);
        let digest = Digest::try_from(hash.as_slice()).map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to create digest: {}", e),
        })?;

        // Sign the hash
        let signature = context
            .sign(
                key_handle,
                digest,
                SignatureScheme::EcDsa {
                    hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                },
                tss_esapi::structures::HashcheckTicket::default(),
            )
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("TPM signing failed: {}", e),
            })?;

        // Extract signature bytes
        let sig_bytes = match signature {
            tss_esapi::structures::Signature::EcDsa(ecdsa_sig) => {
                let r = ecdsa_sig.signature_r().as_bytes();
                let s = ecdsa_sig.signature_s().as_bytes();
                let mut sig = Vec::with_capacity(64);
                // Pad to 32 bytes each (P-256 uses 32-byte coordinates)
                sig.extend(std::iter::repeat(0).take(32 - r.len()));
                sig.extend(r);
                sig.extend(std::iter::repeat(0).take(32 - s.len()));
                sig.extend(s);
                sig
            }
            _ => {
                return Err(KeyringError::HardwareError {
                    reason: "Unexpected signature type from TPM".into(),
                })
            }
        };

        tracing::debug!("TPM: signature generated ({} bytes)", sig_bytes.len());
        Ok(sig_bytes)
    }

    /// Get public key from TPM.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    async fn tpm_get_public_key(&self) -> Result<Vec<u8>, KeyringError> {
        // Check cache first
        {
            let cache = self
                .cached_public_key
                .lock()
                .map_err(|_| KeyringError::HardwareError {
                    reason: "Public key cache lock poisoned".into(),
                })?;
            if let Some(ref pk) = *cache {
                return Ok(pk.clone());
            }
        }

        tracing::debug!("TPM: reading public key");

        let key_handle = self.ensure_key()?;

        let mut context_guard = self.context.lock().map_err(|_| KeyringError::HardwareError {
            reason: "Context lock poisoned".into(),
        })?;

        let context = context_guard.as_mut().ok_or_else(|| KeyringError::HardwareError {
            reason: "TPM context not initialized".into(),
        })?;

        // Read the public key
        let (public, _, _) = context
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
            }
        };

        // Format as uncompressed point (0x04 || x || y)
        let x = ecc_point.x().as_bytes();
        let y = ecc_point.y().as_bytes();

        let mut pubkey = Vec::with_capacity(65);
        pubkey.push(0x04); // Uncompressed point indicator
        // Pad x to 32 bytes
        pubkey.extend(std::iter::repeat(0).take(32 - x.len()));
        pubkey.extend(x);
        // Pad y to 32 bytes
        pubkey.extend(std::iter::repeat(0).take(32 - y.len()));
        pubkey.extend(y);

        tracing::debug!("TPM: public key retrieved ({} bytes)", pubkey.len());

        // Cache the result
        {
            let mut cache = self
                .cached_public_key
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
            *handle_guard = None;
        }

        // Clear cached public key
        {
            let mut cache = self
                .cached_public_key
                .lock()
                .map_err(|_| KeyringError::HardwareError {
                    reason: "Public key cache lock poisoned".into(),
                })?;
            *cache = None;
        }

        // ensure_key will create a new key
        let _handle = self.ensure_key()?;

        tracing::info!("TPM: key generated successfully");
        Ok(())
    }

    /// Delete a key from the TPM.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    async fn tpm_delete_key(&self) -> Result<(), KeyringError> {
        tracing::info!("TPM: deleting key");

        // If we have a persistent handle, evict it
        if let Some(persistent) = self.persistent_handle {
            let mut context_guard =
                self.context.lock().map_err(|_| KeyringError::HardwareError {
                    reason: "Context lock poisoned".into(),
                })?;

            let context = context_guard
                .as_mut()
                .ok_or_else(|| KeyringError::HardwareError {
                    reason: "TPM context not initialized".into(),
                })?;

            let handle = PersistentTpmHandle::new(persistent).map_err(|e| {
                KeyringError::HardwareError {
                    reason: format!("Invalid persistent handle: {}", e),
                }
            })?;

            let key_handle: KeyHandle = context
                .tr_from_tpm_public(TpmHandle::Persistent(handle))
                .map_err(|e| KeyringError::HardwareError {
                    reason: format!("Failed to get persistent key handle: {}", e),
                })?
                .into();

            // Evict the persistent key
            context
                .evict_control(
                    tss_esapi::interface_types::resource_handles::Provision::Owner,
                    key_handle.into(),
                    handle,
                )
                .map_err(|e| KeyringError::HardwareError {
                    reason: format!("Failed to evict persistent key: {}", e),
                })?;

            tracing::info!(
                "TPM: evicted persistent key at handle 0x{:08x}",
                persistent
            );
        }

        // Clear the key handle
        {
            let mut handle_guard =
                self.key_handle
                    .lock()
                    .map_err(|_| KeyringError::HardwareError {
                        reason: "Key handle lock poisoned".into(),
                    })?;

            if let Some(handle) = handle_guard.take() {
                // Flush the transient handle
                let mut context_guard =
                    self.context.lock().map_err(|_| KeyringError::HardwareError {
                        reason: "Context lock poisoned".into(),
                    })?;

                if let Some(context) = context_guard.as_mut() {
                    let _ = context.flush_context(handle.into());
                }
            }
        }

        // Clear cached public key
        {
            let mut cache = self
                .cached_public_key
                .lock()
                .map_err(|_| KeyringError::HardwareError {
                    reason: "Public key cache lock poisoned".into(),
                })?;
            *cache = None;
        }

        tracing::info!("TPM: key deleted successfully");
        Ok(())
    }
}

/// TPM quote structure.
#[derive(Debug, Clone)]
pub struct TpmQuote {
    /// The quoted data (TPMS_ATTEST)
    pub quoted: Vec<u8>,
    /// Signature over the quote
    pub signature: Vec<u8>,
    /// PCR values included in the quote
    pub pcr_values: Vec<u8>,
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
            // Generate nonce for freshness
            use rand_core::{OsRng, RngCore};
            let mut nonce = [0u8; 32];
            OsRng.fill_bytes(&mut nonce);

            // Get quote over standard PCRs (boot chain)
            let pcr_selection = [0u8, 1, 2, 3, 7];
            let quote = self.get_quote(&nonce, &pcr_selection).await.ok();

            // Get EK cert if available
            let ek_cert = self.get_ek_cert().await.ok();

            Ok(PlatformAttestation::Tpm(TpmAttestation {
                tpm_version: "2.0".into(),
                manufacturer: "Unknown".into(),
                discrete: self.is_discrete,
                quote: quote.map(|q| q.quoted),
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
            // Check if we have a key handle or can load from persistent
            let handle_guard =
                self.key_handle
                    .lock()
                    .map_err(|_| KeyringError::HardwareError {
                        reason: "Key handle lock poisoned".into(),
                    })?;

            if handle_guard.is_some() {
                return Ok(true);
            }

            // Check for persistent handle
            Ok(self.persistent_handle.is_some())
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
        // This would only work on systems with TPM
        let result = TpmSigner::detect_tpm();
        // Don't assert success - TPM may not be present
        assert!(result.is_ok());
    }
}
