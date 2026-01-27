//! Cryptographic types following Veilid's CryptoKind pattern.

use serde::{Deserialize, Serialize};

/// Four-character code identifying a cryptographic system.
///
/// This follows Veilid's pattern for crypto agility, allowing multiple
/// crypto systems to coexist and enabling smooth migrations.
pub type CryptoKind = [u8; 4];

/// CIRISVerify hybrid cryptosystem v1.
///
/// Uses ECDSA P-256 + ML-DSA-65 for hardware compatibility with PQC protection.
pub const CRYPTO_KIND_CIRIS_V1: CryptoKind = *b"CIR1";

/// Classical signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ClassicalAlgorithm {
    /// ECDSA with NIST P-256 (secp256r1)
    /// Hardware-compatible: Android Keystore, iOS Secure Enclave, TPM 2.0
    EcdsaP256 = 1,

    /// Ed25519 Edwards curve
    /// Used for steward signatures and software-only deployments
    Ed25519 = 2,

    /// ECDSA with NIST P-384 (secp384r1)
    /// Higher security, TPM 2.0 compatible
    EcdsaP384 = 3,
}

impl ClassicalAlgorithm {
    /// OID for this algorithm (for X.509/PKCS)
    #[must_use]
    pub const fn oid(&self) -> &'static str {
        match self {
            Self::EcdsaP256 => "1.2.840.10045.4.3.2", // ecdsa-with-SHA256
            Self::Ed25519 => "1.3.101.112",           // id-Ed25519
            Self::EcdsaP384 => "1.2.840.10045.4.3.3", // ecdsa-with-SHA384
        }
    }
}

/// Post-quantum signature algorithm.
///
/// Based on NIST FIPS 204 (ML-DSA), finalized August 2024.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PqcAlgorithm {
    /// ML-DSA-44 (Dilithium2)
    /// Security level 2 (~128-bit classical)
    /// NOT SUFFICIENT for CIRISVerify - use ML-DSA-65+
    MlDsa44 = 1,

    /// ML-DSA-65 (Dilithium3)
    /// Security level 3 (~192-bit classical)
    /// MINIMUM REQUIRED for CIRISVerify
    MlDsa65 = 2,

    /// ML-DSA-87 (Dilithium5)
    /// Security level 5 (~256-bit classical)
    MlDsa87 = 3,

    /// SLH-DSA-SHA2-128s (SPHINCS+)
    /// Stateless hash-based, conservative choice
    SlhDsaSha2_128s = 10,

    /// SLH-DSA-SHA2-256s (SPHINCS+)
    /// Maximum security stateless hash-based
    SlhDsaSha2_256s = 11,
}

impl PqcAlgorithm {
    /// Check if this algorithm meets CIRISVerify minimum requirements.
    #[must_use]
    pub const fn meets_minimum_requirement(&self) -> bool {
        !matches!(self, Self::MlDsa44)
    }

    /// Get signature size in bytes.
    #[must_use]
    pub const fn signature_size(&self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3293,
            Self::MlDsa87 => 4595,
            Self::SlhDsaSha2_128s => 7856,
            Self::SlhDsaSha2_256s => 29792,
        }
    }

    /// Get public key size in bytes.
    #[must_use]
    pub const fn public_key_size(&self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
            Self::SlhDsaSha2_128s => 32,
            Self::SlhDsaSha2_256s => 64,
        }
    }
}

/// Signature mode for hybrid cryptography.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum SignatureMode {
    /// Classical signature only (DEPRECATED - not accepted by CIRISVerify 2.0)
    ClassicalOnly = 1,

    /// Both classical and PQC signatures required (DEFAULT)
    #[default]
    HybridRequired = 2,

    /// PQC signature only (reserved for future post-transition)
    PqcOnly = 3,
}

/// Tagged classical signature with algorithm identification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaggedClassicalSignature {
    /// Algorithm used for this signature
    pub algorithm: ClassicalAlgorithm,

    /// Raw signature bytes
    pub signature: Vec<u8>,

    /// Public key that can verify this signature
    pub public_key: Vec<u8>,
}

/// Tagged PQC signature with algorithm identification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaggedPqcSignature {
    /// Algorithm used for this signature
    pub algorithm: PqcAlgorithm,

    /// Raw signature bytes
    pub signature: Vec<u8>,

    /// Public key that can verify this signature
    pub public_key: Vec<u8>,
}

/// Combined hybrid signature (classical + PQC).
///
/// The PQC signature covers the classical signature to prevent stripping attacks.
///
/// Verification requires:
/// 1. Verify classical signature over original data
/// 2. Verify PQC signature over (data || classical_signature)
/// 3. Both must pass for the hybrid signature to be valid
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Crypto system identifier (e.g., CRYPTO_KIND_CIRIS_V1)
    pub crypto_kind: CryptoKind,

    /// Classical signature component
    pub classical: TaggedClassicalSignature,

    /// Post-quantum signature component
    pub pqc: TaggedPqcSignature,

    /// Signature mode
    pub mode: SignatureMode,
}

impl HybridSignature {
    /// Get the total size of this hybrid signature in bytes.
    #[must_use]
    pub fn total_size(&self) -> usize {
        4 // crypto_kind
            + 1 // classical algorithm tag
            + self.classical.signature.len()
            + self.classical.public_key.len()
            + 1 // pqc algorithm tag
            + self.pqc.signature.len()
            + self.pqc.public_key.len()
            + 1 // mode
    }

    /// Serialize to bytes for transmission.
    ///
    /// Format: crypto_kind || classical || pqc || mode
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // Use CBOR or similar for actual implementation
        // This is a placeholder showing the concept
        let mut bytes = Vec::with_capacity(self.total_size());
        bytes.extend_from_slice(&self.crypto_kind);
        bytes.push(self.classical.algorithm as u8);
        bytes.extend_from_slice(&self.classical.signature);
        bytes.extend_from_slice(&self.classical.public_key);
        bytes.push(self.pqc.algorithm as u8);
        bytes.extend_from_slice(&self.pqc.signature);
        bytes.extend_from_slice(&self.pqc.public_key);
        bytes.push(self.mode as u8);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_kind() {
        assert_eq!(&CRYPTO_KIND_CIRIS_V1, b"CIR1");
    }

    #[test]
    fn test_pqc_minimum_requirement() {
        assert!(!PqcAlgorithm::MlDsa44.meets_minimum_requirement());
        assert!(PqcAlgorithm::MlDsa65.meets_minimum_requirement());
        assert!(PqcAlgorithm::MlDsa87.meets_minimum_requirement());
    }

    #[test]
    fn test_pqc_signature_sizes() {
        assert_eq!(PqcAlgorithm::MlDsa65.signature_size(), 3293);
        assert_eq!(PqcAlgorithm::MlDsa65.public_key_size(), 1952);
    }

    #[test]
    fn test_signature_mode_default() {
        assert_eq!(SignatureMode::default(), SignatureMode::HybridRequired);
    }
}
