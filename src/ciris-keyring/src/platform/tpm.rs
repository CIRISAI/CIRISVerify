//! TPM 2.0 hardware signer implementation.
//!
//! Uses tss-esapi for TPM 2.0 access on Linux, Windows, and macOS.
//! Supports ECDSA P-256 for cross-platform compatibility.

use async_trait::async_trait;

use crate::error::KeyringError;
use crate::signer::{HardwareSigner, KeyGenConfig};
use crate::types::{ClassicalAlgorithm, HardwareType, PlatformAttestation, TpmAttestation};

/// TPM 2.0 signer for desktop and server platforms.
///
/// Supports both discrete TPMs and firmware TPMs (fTPM).
/// Uses ECDSA P-256 for compatibility with mobile platforms.
pub struct TpmSigner {
    /// Key handle or persistent handle
    key_handle: u32,
    /// Key alias for identification
    alias: String,
    /// Whether this is a discrete TPM (vs firmware TPM)
    is_discrete: bool,
    /// Cached public key
    public_key: Option<Vec<u8>>,
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
    pub fn new(alias: impl Into<String>, persistent_handle: Option<u32>) -> Result<Self, KeyringError> {
        let alias = alias.into();

        // Check TPM availability
        let (available, is_discrete) = Self::detect_tpm()?;
        if !available {
            return Err(KeyringError::HardwareNotAvailable {
                reason: "No TPM 2.0 found".into(),
            });
        }

        Ok(Self {
            key_handle: persistent_handle.unwrap_or(0),
            alias,
            is_discrete,
            public_key: None,
        })
    }

    /// Detect TPM availability and type.
    fn detect_tpm() -> Result<(bool, bool), KeyringError> {
        #[cfg(target_os = "linux")]
        {
            // Check for /dev/tpm0 or /dev/tpmrm0
            use std::path::Path;
            let tpm_available = Path::new("/dev/tpm0").exists()
                || Path::new("/dev/tpmrm0").exists();

            if !tpm_available {
                return Ok((false, false));
            }

            // Check if discrete by reading TPM manufacturer
            // For now, assume fTPM (conservative)
            Ok((true, false))
        }

        #[cfg(target_os = "windows")]
        {
            // Windows has built-in TPM support via TPM Base Services (TBS)
            // Check using tss-esapi with Windows TCTI
            Ok((true, false)) // Assume available, check at runtime
        }

        #[cfg(target_os = "macos")]
        {
            // macOS with T2/Apple Silicon doesn't expose TPM traditionally
            // but has Secure Enclave (use that instead)
            Ok((false, false))
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    /// Get TPM quote for attestation.
    ///
    /// Creates a signed quote over PCRs and external data.
    pub async fn get_quote(&self, nonce: &[u8], pcr_selection: &[u8]) -> Result<TpmQuote, KeyringError> {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            // Real implementation would:
            // 1. Create ESYS context
            // 2. Select PCRs (typically 0,1,2,3,7 for boot chain)
            // 3. Call Esys_Quote with signing key and nonce
            // 4. Return quote and signature
            let _ = (nonce, pcr_selection);
            todo!("Implement TPM quote")
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = (nonce, pcr_selection);
            Err(KeyringError::NoPlatformSupport)
        }
    }

    /// Get Endorsement Key certificate chain.
    pub async fn get_ek_cert(&self) -> Result<Vec<u8>, KeyringError> {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            // Real implementation would:
            // 1. Read EK cert from NV index 0x01C00002 (RSA) or 0x01C0000A (ECC)
            // 2. Or retrieve from manufacturer's CA
            todo!("Implement EK cert retrieval")
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    /// Sign data using the TPM.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    async fn tpm_sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        // Real implementation would:
        // 1. Create ESYS context
        // 2. Load key if not persistent
        // 3. Hash data (TPM signs hashes, not raw data)
        // 4. Esys_Sign with ECDSA scheme
        // 5. Return signature
        let _ = data;
        todo!("Implement TPM signing")
    }

    /// Get public key from TPM.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    async fn tpm_get_public_key(&self) -> Result<Vec<u8>, KeyringError> {
        // Real implementation would:
        // 1. Create ESYS context
        // 2. Esys_ReadPublic to get TPM2B_PUBLIC
        // 3. Extract ECC point (x, y)
        // 4. Return as uncompressed point (0x04 || x || y)
        todo!("Implement TPM public key export")
    }

    /// Generate a new key in the TPM.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    async fn tpm_generate_key(&self, config: &KeyGenConfig) -> Result<u32, KeyringError> {
        // Real implementation would:
        // 1. Create ESYS context
        // 2. Create primary key under owner hierarchy (or use SRK)
        // 3. Create child key with:
        //    - TPM2_ALG_ECDSA + TPM2_ALG_SHA256
        //    - TPM2_ECC_NIST_P256
        //    - sign + decrypt attributes
        // 4. Optionally make persistent with Esys_EvictControl
        // 5. Return handle
        let _ = config;
        todo!("Implement TPM key generation")
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
        // Use P-256 for cross-platform compatibility
        // TPM also supports P-384, RSA, but P-256 is universal
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
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            if let Some(ref pk) = self.public_key {
                return Ok(pk.clone());
            }
            self.tpm_get_public_key().await
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            self.tpm_sign(data).await
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = data;
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            // Generate nonce for freshness
            use rand_core::{OsRng, RngCore};
            let mut nonce = [0u8; 32];
            OsRng.fill_bytes(&mut nonce);

            // Get quote over standard PCRs (boot chain)
            let pcr_selection = [0u8, 1, 2, 3, 7]; // Boot PCRs
            let quote = self.get_quote(&nonce, &pcr_selection).await.ok();

            // Get EK cert if available
            let ek_cert = self.get_ek_cert().await.ok();

            Ok(PlatformAttestation::Tpm(TpmAttestation {
                tpm_version: "2.0".into(),
                manufacturer: "Unknown".into(), // Would be detected from TPM
                discrete: self.is_discrete,
                quote: quote.map(|q| q.quoted),
                ek_cert,
            }))
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn generate_key(&self, config: &KeyGenConfig) -> Result<(), KeyringError> {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            let _handle = self.tpm_generate_key(config).await?;
            Ok(())
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = config;
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn key_exists(&self, _alias: &str) -> Result<bool, KeyringError> {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            // Check if persistent handle exists
            Ok(self.key_handle != 0)
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Err(KeyringError::NoPlatformSupport)
        }
    }

    async fn delete_key(&self, _alias: &str) -> Result<(), KeyringError> {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            // Would use Esys_EvictControl to remove persistent key
            todo!("Implement TPM key deletion")
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
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
