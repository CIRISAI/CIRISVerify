//! Windows TPM signer using Platform Crypto Provider (PCP).
//!
//! This is an EXPERIMENTAL implementation that uses Windows NCrypt API
//! with the Microsoft Platform Crypto Provider to access TPM-backed keys.
//!
//! **WARNING**: This feature is experimental. Use `--features tpm-windows` to enable.
//!
//! Reference: https://github.com/ElMostafaIdrassi/pcpcrypto (Apache-2.0)

use async_trait::async_trait;
use std::sync::Mutex;

use crate::error::KeyringError;
use crate::signer::{HardwareSigner, KeyGenConfig};
use crate::types::{ClassicalAlgorithm, HardwareType, PlatformAttestation, TpmAttestation};

#[cfg(all(feature = "tpm-windows", target_os = "windows"))]
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::Foundation::NTSTATUS,
    Win32::Security::Cryptography::{
        BCryptCloseAlgorithmProvider, BCryptOpenAlgorithmProvider, NCryptCreatePersistedKey,
        NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptGetProperty,
        NCryptOpenKey, NCryptOpenStorageProvider, NCryptSignHash, BCRYPT_ECCPUBLIC_BLOB,
        BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, CERT_KEY_SPEC,
        NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
    },
};

/// Microsoft Platform Crypto Provider name.
/// This provider uses the TPM for hardware-backed key operations.
#[cfg(all(feature = "tpm-windows", target_os = "windows"))]
const MS_PLATFORM_CRYPTO_PROVIDER: &str = "Microsoft Platform Crypto Provider";

/// Windows TPM signer using Platform Crypto Provider.
///
/// This implementation uses NCrypt API with the Microsoft Platform Crypto Provider
/// which automatically leverages the TPM for key storage and cryptographic operations.
pub struct WindowsTpmSigner {
    /// Key alias for identification
    alias: String,
    /// NCrypt provider handle
    #[cfg(all(feature = "tpm-windows", target_os = "windows"))]
    provider: Mutex<Option<NCRYPT_PROV_HANDLE>>,
    /// NCrypt key handle
    #[cfg(all(feature = "tpm-windows", target_os = "windows"))]
    key_handle: Mutex<Option<NCRYPT_KEY_HANDLE>>,
    /// Cached public key bytes
    cached_public_key: Mutex<Option<Vec<u8>>>,
    /// Whether experimental warning has been shown
    warning_shown: std::sync::atomic::AtomicBool,
}

impl WindowsTpmSigner {
    /// Create a new Windows TPM signer.
    ///
    /// **WARNING**: This is an experimental feature.
    pub fn new(alias: impl Into<String>) -> Result<Self, KeyringError> {
        let alias = alias.into();

        // Log experimental warning
        tracing::warn!("=== EXPERIMENTAL FEATURE: Windows TPM via Platform Crypto Provider ===");
        tracing::warn!("This feature is experimental and may not work correctly on all systems.");
        tracing::warn!("Please report issues at https://github.com/CIRISAI/CIRISVerify/issues");

        #[cfg(all(feature = "tpm-windows", target_os = "windows"))]
        {
            // Check if TPM is available
            if !Self::is_tpm_available() {
                return Err(KeyringError::HardwareNotAvailable {
                    reason: "TPM not available or Platform Crypto Provider not supported".into(),
                });
            }

            // Open the Platform Crypto Provider
            let provider = Self::open_provider()?;

            tracing::info!(
                alias = %alias,
                "WindowsTpmSigner: created with Platform Crypto Provider (EXPERIMENTAL)"
            );

            Ok(Self {
                alias,
                provider: Mutex::new(Some(provider)),
                key_handle: Mutex::new(None),
                cached_public_key: Mutex::new(None),
                warning_shown: std::sync::atomic::AtomicBool::new(true),
            })
        }

        #[cfg(not(all(feature = "tpm-windows", target_os = "windows")))]
        {
            Err(KeyringError::HardwareNotAvailable {
                reason: "Windows TPM support not compiled in (enable 'tpm-windows' feature)".into(),
            })
        }
    }

    /// Check if TPM is available via Platform Crypto Provider.
    #[cfg(all(feature = "tpm-windows", target_os = "windows"))]
    fn is_tpm_available() -> bool {
        // Try to open the Platform Crypto Provider
        // If it succeeds, TPM is available
        let provider_name: Vec<u16> = MS_PLATFORM_CRYPTO_PROVIDER
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut provider_handle = NCRYPT_PROV_HANDLE::default();

        let status = unsafe {
            NCryptOpenStorageProvider(&mut provider_handle, PCWSTR(provider_name.as_ptr()), 0)
        };

        if status.is_ok() {
            // Clean up
            unsafe {
                let _ = NCryptFreeObject(provider_handle);
            }
            tracing::debug!("Windows TPM: Platform Crypto Provider available");
            true
        } else {
            tracing::debug!(
                "Windows TPM: Platform Crypto Provider not available: {:?}",
                status
            );
            false
        }
    }

    #[cfg(not(all(feature = "tpm-windows", target_os = "windows")))]
    fn is_tpm_available() -> bool {
        false
    }

    /// Open the Platform Crypto Provider.
    #[cfg(all(feature = "tpm-windows", target_os = "windows"))]
    fn open_provider() -> Result<NCRYPT_PROV_HANDLE, KeyringError> {
        let provider_name: Vec<u16> = MS_PLATFORM_CRYPTO_PROVIDER
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut provider_handle = NCRYPT_PROV_HANDLE::default();

        let status = unsafe {
            NCryptOpenStorageProvider(&mut provider_handle, PCWSTR(provider_name.as_ptr()), 0)
        };

        if status.is_err() {
            return Err(KeyringError::HardwareError {
                reason: format!("Failed to open Platform Crypto Provider: {:?}", status),
            });
        }

        Ok(provider_handle)
    }

    /// Create an ECDSA P-256 key in the TPM.
    #[cfg(all(feature = "tpm-windows", target_os = "windows"))]
    fn create_key(&self, key_name: &str) -> Result<NCRYPT_KEY_HANDLE, KeyringError> {
        let provider_guard = self
            .provider
            .lock()
            .map_err(|_| KeyringError::HardwareError {
                reason: "Provider lock poisoned".into(),
            })?;

        let provider = provider_guard
            .as_ref()
            .ok_or_else(|| KeyringError::HardwareError {
                reason: "Provider not initialized".into(),
            })?;

        // Key name as wide string
        let key_name_wide: Vec<u16> = key_name.encode_utf16().chain(std::iter::once(0)).collect();

        // Algorithm: ECDSA P-256
        let algo_name: Vec<u16> = "ECDSA_P256"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut key_handle = NCRYPT_KEY_HANDLE::default();

        tracing::debug!("Windows TPM: Creating ECDSA P-256 key '{}'", key_name);

        let status = unsafe {
            NCryptCreatePersistedKey(
                *provider,
                &mut key_handle,
                PCWSTR(algo_name.as_ptr()),
                PCWSTR(key_name_wide.as_ptr()),
                CERT_KEY_SPEC(0), // dwLegacyKeySpec
                NCRYPT_FLAGS(0),  // dwFlags
            )
        };

        if status.is_err() {
            return Err(KeyringError::HardwareError {
                reason: format!("Failed to create TPM key: {:?}", status),
            });
        }

        // Finalize the key (persist it)
        let status = unsafe { NCryptFinalizeKey(key_handle, NCRYPT_FLAGS(0)) };

        if status.is_err() {
            // Clean up on failure
            unsafe {
                let _ = NCryptFreeObject(key_handle);
            }
            return Err(KeyringError::HardwareError {
                reason: format!("Failed to finalize TPM key: {:?}", status),
            });
        }

        tracing::info!(
            "Windows TPM: ECDSA P-256 key '{}' created successfully",
            key_name
        );
        Ok(key_handle)
    }

    /// Open an existing key by name.
    #[cfg(all(feature = "tpm-windows", target_os = "windows"))]
    fn open_key(&self, key_name: &str) -> Result<NCRYPT_KEY_HANDLE, KeyringError> {
        let provider_guard = self
            .provider
            .lock()
            .map_err(|_| KeyringError::HardwareError {
                reason: "Provider lock poisoned".into(),
            })?;

        let provider = provider_guard
            .as_ref()
            .ok_or_else(|| KeyringError::HardwareError {
                reason: "Provider not initialized".into(),
            })?;

        let key_name_wide: Vec<u16> = key_name.encode_utf16().chain(std::iter::once(0)).collect();

        let mut key_handle = NCRYPT_KEY_HANDLE::default();

        let status = unsafe {
            NCryptOpenKey(
                *provider,
                &mut key_handle,
                PCWSTR(key_name_wide.as_ptr()),
                CERT_KEY_SPEC(0), // dwLegacyKeySpec
                NCRYPT_FLAGS(0),  // dwFlags
            )
        };

        if status.is_err() {
            return Err(KeyringError::HardwareError {
                reason: format!("Failed to open TPM key '{}': {:?}", key_name, status),
            });
        }

        Ok(key_handle)
    }

    /// Get or create the signing key.
    #[cfg(all(feature = "tpm-windows", target_os = "windows"))]
    fn ensure_key(&self) -> Result<NCRYPT_KEY_HANDLE, KeyringError> {
        // Check if we already have a key handle
        {
            let handle_guard = self
                .key_handle
                .lock()
                .map_err(|_| KeyringError::HardwareError {
                    reason: "Key handle lock poisoned".into(),
                })?;
            if let Some(handle) = *handle_guard {
                return Ok(handle);
            }
        }

        let key_name = format!("CIRISVerify_{}", self.alias);

        // Try to open existing key first
        match self.open_key(&key_name) {
            Ok(handle) => {
                tracing::debug!("Windows TPM: Opened existing key '{}'", key_name);
                let mut handle_guard =
                    self.key_handle
                        .lock()
                        .map_err(|_| KeyringError::HardwareError {
                            reason: "Key handle lock poisoned".into(),
                        })?;
                *handle_guard = Some(handle);
                return Ok(handle);
            },
            Err(_) => {
                tracing::debug!(
                    "Windows TPM: Key '{}' not found, creating new key",
                    key_name
                );
            },
        }

        // Create new key
        let handle = self.create_key(&key_name)?;
        let mut handle_guard = self
            .key_handle
            .lock()
            .map_err(|_| KeyringError::HardwareError {
                reason: "Key handle lock poisoned".into(),
            })?;
        *handle_guard = Some(handle);
        Ok(handle)
    }

    /// Export the public key.
    #[cfg(all(feature = "tpm-windows", target_os = "windows"))]
    fn export_public_key(&self, key_handle: NCRYPT_KEY_HANDLE) -> Result<Vec<u8>, KeyringError> {
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

        let blob_type: Vec<u16> = "ECCPUBLICBLOB"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // First call to get size
        let mut size: u32 = 0;
        let status = unsafe {
            NCryptExportKey(
                key_handle,
                NCRYPT_KEY_HANDLE::default(),
                PCWSTR(blob_type.as_ptr()),
                None,
                None,
                &mut size,
                NCRYPT_FLAGS(0),
            )
        };

        if status.is_err() {
            return Err(KeyringError::HardwareError {
                reason: format!("Failed to get public key size: {:?}", status),
            });
        }

        // Second call to get data
        let mut buffer = vec![0u8; size as usize];
        let status = unsafe {
            NCryptExportKey(
                key_handle,
                NCRYPT_KEY_HANDLE::default(),
                PCWSTR(blob_type.as_ptr()),
                None,
                Some(&mut buffer),
                &mut size,
                NCRYPT_FLAGS(0),
            )
        };

        if status.is_err() {
            return Err(KeyringError::HardwareError {
                reason: format!("Failed to export public key: {:?}", status),
            });
        }

        buffer.truncate(size as usize);

        // The ECCPUBLICBLOB format is:
        // - BCRYPT_ECCKEY_BLOB header (8 bytes: magic + cbKey)
        // - X coordinate (cbKey bytes)
        // - Y coordinate (cbKey bytes)
        //
        // We need to convert to uncompressed point format (0x04 || X || Y)
        if buffer.len() < 8 {
            return Err(KeyringError::HardwareError {
                reason: "Public key blob too small".into(),
            });
        }

        // Read cbKey from header (offset 4, little-endian u32)
        let cb_key = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]) as usize;

        if buffer.len() < 8 + cb_key * 2 {
            return Err(KeyringError::HardwareError {
                reason: format!(
                    "Public key blob too small: expected {}, got {}",
                    8 + cb_key * 2,
                    buffer.len()
                ),
            });
        }

        // Extract X and Y coordinates
        let x = &buffer[8..8 + cb_key];
        let y = &buffer[8 + cb_key..8 + cb_key * 2];

        // Format as uncompressed point: 0x04 || X || Y
        let mut pubkey = Vec::with_capacity(1 + cb_key * 2);
        pubkey.push(0x04);
        pubkey.extend_from_slice(x);
        pubkey.extend_from_slice(y);

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

        tracing::debug!(
            pubkey_len = pubkey.len(),
            "Windows TPM: public key exported"
        );
        Ok(pubkey)
    }

    /// Sign data using the TPM key.
    #[cfg(all(feature = "tpm-windows", target_os = "windows"))]
    fn sign_hash(
        &self,
        key_handle: NCRYPT_KEY_HANDLE,
        hash: &[u8],
    ) -> Result<Vec<u8>, KeyringError> {
        // For ECDSA P-256, signature is 64 bytes (r || s, each 32 bytes)
        let mut signature = vec![0u8; 64];
        let mut sig_len: u32 = 64;

        let status = unsafe {
            NCryptSignHash(
                key_handle,
                None, // pPaddingInfo (not used for ECDSA)
                hash,
                Some(&mut signature),
                &mut sig_len,
                NCRYPT_FLAGS(0),
            )
        };

        if status.is_err() {
            return Err(KeyringError::HardwareError {
                reason: format!("TPM signing failed: {:?}", status),
            });
        }

        signature.truncate(sig_len as usize);
        tracing::debug!(sig_len = sig_len, "Windows TPM: signature generated");
        Ok(signature)
    }
}

impl Drop for WindowsTpmSigner {
    fn drop(&mut self) {
        #[cfg(all(feature = "tpm-windows", target_os = "windows"))]
        {
            // Clean up key handle
            if let Ok(mut handle_guard) = self.key_handle.lock() {
                if let Some(handle) = handle_guard.take() {
                    unsafe {
                        let _ = NCryptFreeObject(handle);
                    }
                }
            }

            // Clean up provider handle
            if let Ok(mut provider_guard) = self.provider.lock() {
                if let Some(provider) = provider_guard.take() {
                    unsafe {
                        let _ = NCryptFreeObject(provider);
                    }
                }
            }
        }
    }
}

#[async_trait]
impl HardwareSigner for WindowsTpmSigner {
    fn algorithm(&self) -> ClassicalAlgorithm {
        ClassicalAlgorithm::EcdsaP256
    }

    fn hardware_type(&self) -> HardwareType {
        // PCP uses firmware TPM on most systems
        HardwareType::TpmFirmware
    }

    async fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
        #[cfg(all(feature = "tpm-windows", target_os = "windows"))]
        {
            let key_handle = self.ensure_key()?;
            self.export_public_key(key_handle)
        }

        #[cfg(not(all(feature = "tpm-windows", target_os = "windows")))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        #[cfg(all(feature = "tpm-windows", target_os = "windows"))]
        {
            use sha2::{Digest, Sha256};

            let key_handle = self.ensure_key()?;

            // Hash the data (TPM signs hashes, not raw data)
            let hash = Sha256::digest(data);

            self.sign_hash(key_handle, &hash)
        }

        #[cfg(not(all(feature = "tpm-windows", target_os = "windows")))]
        {
            let _ = data;
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
        // Windows PCP doesn't provide the same attestation as tss-esapi
        // Return basic TPM attestation info
        Ok(PlatformAttestation::Tpm(TpmAttestation {
            tpm_version: "2.0".into(),
            manufacturer: "Windows Platform Crypto Provider (EXPERIMENTAL)".into(),
            discrete: false, // PCP typically uses fTPM
            quote: None,     // PCP doesn't expose quote directly
            ek_cert: None,   // PCP doesn't expose EK cert directly
        }))
    }

    async fn generate_key(&self, config: &KeyGenConfig) -> Result<(), KeyringError> {
        #[cfg(all(feature = "tpm-windows", target_os = "windows"))]
        {
            tracing::info!(alias = %config.alias, "Windows TPM: generating new key");

            // Clear existing key handle
            {
                let mut handle_guard =
                    self.key_handle
                        .lock()
                        .map_err(|_| KeyringError::HardwareError {
                            reason: "Key handle lock poisoned".into(),
                        })?;
                if let Some(handle) = handle_guard.take() {
                    unsafe {
                        let _ = NCryptFreeObject(handle);
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

            // Create new key
            let _handle = self.ensure_key()?;
            tracing::info!("Windows TPM: key generated successfully");
            Ok(())
        }

        #[cfg(not(all(feature = "tpm-windows", target_os = "windows")))]
        {
            let _ = config;
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn key_exists(&self, _alias: &str) -> Result<bool, KeyringError> {
        #[cfg(all(feature = "tpm-windows", target_os = "windows"))]
        {
            let handle_guard = self
                .key_handle
                .lock()
                .map_err(|_| KeyringError::HardwareError {
                    reason: "Key handle lock poisoned".into(),
                })?;
            Ok(handle_guard.is_some())
        }

        #[cfg(not(all(feature = "tpm-windows", target_os = "windows")))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn delete_key(&self, _alias: &str) -> Result<(), KeyringError> {
        #[cfg(all(feature = "tpm-windows", target_os = "windows"))]
        {
            let mut handle_guard =
                self.key_handle
                    .lock()
                    .map_err(|_| KeyringError::HardwareError {
                        reason: "Key handle lock poisoned".into(),
                    })?;

            if let Some(handle) = handle_guard.take() {
                let status = unsafe { NCryptDeleteKey(handle, 0) };
                if status.is_err() {
                    return Err(KeyringError::HardwareError {
                        reason: format!("Failed to delete TPM key: {:?}", status),
                    });
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

            tracing::info!("Windows TPM: key deleted successfully");
            Ok(())
        }

        #[cfg(not(all(feature = "tpm-windows", target_os = "windows")))]
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
    fn test_tpm_availability_check() {
        let available = WindowsTpmSigner::is_tpm_available();
        println!("Windows TPM available: {}", available);
    }
}
