//! Core types for hardware keyring operations.
//!
//! These types are designed to be compatible with Veilid's CryptoKind pattern,
//! using tagged enums for algorithm identification.

use serde::{Deserialize, Serialize};

/// Classical cryptographic algorithm for hardware-bound signatures.
///
/// Mobile HSMs (Android Keystore, iOS Secure Enclave) only support ECDSA P-256.
/// TPM 2.0 supports ECDSA P-256, RSA, and some implementations support Ed25519.
/// For cross-platform consistency, ECDSA P-256 is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum ClassicalAlgorithm {
    /// ECDSA with NIST P-256 curve (secp256r1/prime256v1)
    /// Required for mobile HSMs. Default for cross-platform compatibility.
    #[default]
    EcdsaP256 = 1,

    /// Ed25519 Edwards curve signatures
    /// Used for SGX and software-only deployments.
    Ed25519 = 2,

    /// ECDSA with NIST P-384 curve (secp384r1)
    /// Optional higher security, supported by TPM 2.0.
    EcdsaP384 = 3,
}

impl ClassicalAlgorithm {
    /// Get the signature size in bytes for this algorithm.
    #[must_use]
    pub const fn signature_size(&self) -> usize {
        match self {
            Self::EcdsaP256 => 64, // R (32) + S (32)
            Self::Ed25519 => 64,
            Self::EcdsaP384 => 96, // R (48) + S (48)
        }
    }

    /// Get the public key size in bytes for this algorithm.
    #[must_use]
    pub const fn public_key_size(&self) -> usize {
        match self {
            Self::EcdsaP256 => 65, // Uncompressed: 0x04 || X (32) || Y (32)
            Self::Ed25519 => 32,
            Self::EcdsaP384 => 97, // Uncompressed: 0x04 || X (48) || Y (48)
        }
    }
}

/// Type of hardware security module.
///
/// This determines the security guarantees and maximum license tier available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum HardwareType {
    /// Android Hardware Keystore (TEE-backed)
    AndroidKeystore = 1,

    /// Android StrongBox (dedicated secure element)
    /// Higher security than standard Keystore.
    AndroidStrongbox = 2,

    /// Apple Secure Enclave
    IosSecureEnclave = 3,

    /// Discrete TPM 2.0 (dedicated chip)
    /// Higher security than firmware TPM.
    TpmDiscrete = 4,

    /// Firmware TPM 2.0 (fTPM)
    /// Runs in CPU firmware/trusted execution environment.
    TpmFirmware = 5,

    /// Intel Software Guard Extensions
    IntelSgx = 6,

    /// Software-only implementation
    /// WARNING: Limited to UNLICENSED_COMMUNITY tier maximum.
    SoftwareOnly = 7,
}

impl HardwareType {
    /// Check if this hardware type supports professional licensing.
    ///
    /// SOFTWARE_ONLY is limited to community tier due to lack of hardware binding.
    #[must_use]
    pub const fn supports_professional_license(&self) -> bool {
        !matches!(self, Self::SoftwareOnly)
    }

    /// Get the security level (1-5, higher is better).
    #[must_use]
    pub const fn security_level(&self) -> u8 {
        match self {
            Self::AndroidStrongbox => 5,
            Self::TpmDiscrete => 5,
            Self::IosSecureEnclave => 5,
            Self::TpmFirmware => 4,
            Self::IntelSgx => 4,
            Self::AndroidKeystore => 3,
            Self::SoftwareOnly => 1,
        }
    }
}

/// Platform-specific attestation data.
///
/// This proves to remote verifiers that the key is hardware-bound.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlatformAttestation {
    /// Android attestation data
    Android(AndroidAttestation),

    /// iOS attestation data
    Ios(IosAttestation),

    /// TPM attestation data
    Tpm(TpmAttestation),

    /// Software-only (no attestation)
    Software(SoftwareAttestation),
}

/// Android-specific attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidAttestation {
    /// Key attestation certificate chain (DER-encoded).
    /// Chain: key cert -> intermediate(s) -> Google root.
    pub key_attestation_chain: Vec<Vec<u8>>,

    /// Google Play Integrity API token (optional).
    /// Provides device integrity verdict.
    pub play_integrity_token: Option<String>,

    /// Whether StrongBox was used.
    pub strongbox_backed: bool,
}

/// iOS-specific attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosAttestation {
    /// Whether Secure Enclave was used.
    pub secure_enclave: bool,

    /// App Attest data (optional).
    /// Proves app integrity and Secure Enclave key binding.
    pub app_attest: Option<Vec<u8>>,

    /// DeviceCheck token (optional).
    /// Provides device-level fraud detection.
    pub device_check_token: Option<Vec<u8>>,
}

/// TPM 2.0 attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmAttestation {
    /// TPM version string.
    pub tpm_version: String,

    /// TPM manufacturer information.
    pub manufacturer: String,

    /// Whether this is a discrete TPM (vs firmware TPM).
    pub discrete: bool,

    /// TPM quote (signed PCR values), if available.
    pub quote: Option<Vec<u8>>,

    /// Endorsement Key certificate, if available.
    pub ek_cert: Option<Vec<u8>>,
}

/// Software-only attestation (minimal).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareAttestation {
    /// Key derivation method.
    pub key_derivation: String,

    /// Storage backend used.
    pub storage: String,

    /// Security warning for software-only deployments.
    pub security_warning: String,
}

impl Default for SoftwareAttestation {
    fn default() -> Self {
        Self {
            key_derivation: "random".to_string(),
            storage: "memory".to_string(),
            security_warning: "SOFTWARE_ONLY: No hardware binding available. \
                               This deployment is limited to UNLICENSED_COMMUNITY tier. \
                               Keys can be extracted by an attacker with system access."
                .to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_sizes() {
        assert_eq!(ClassicalAlgorithm::EcdsaP256.signature_size(), 64);
        assert_eq!(ClassicalAlgorithm::EcdsaP256.public_key_size(), 65);
        assert_eq!(ClassicalAlgorithm::Ed25519.signature_size(), 64);
        assert_eq!(ClassicalAlgorithm::Ed25519.public_key_size(), 32);
    }

    #[test]
    fn test_hardware_type_professional_support() {
        assert!(HardwareType::AndroidStrongbox.supports_professional_license());
        assert!(HardwareType::IosSecureEnclave.supports_professional_license());
        assert!(HardwareType::TpmDiscrete.supports_professional_license());
        assert!(HardwareType::TpmFirmware.supports_professional_license());
        assert!(!HardwareType::SoftwareOnly.supports_professional_license());
    }
}
