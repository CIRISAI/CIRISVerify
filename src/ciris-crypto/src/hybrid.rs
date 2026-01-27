//! Hybrid signature system combining classical and post-quantum cryptography.
//!
//! This module implements the dual-signature scheme required by CIRISVerify:
//!
//! 1. Sign data with classical algorithm (hardware-bound if available)
//! 2. Sign (data || classical_signature) with PQC algorithm
//! 3. Verification requires BOTH signatures to pass

use crate::error::CryptoError;
use crate::types::{
    ClassicalAlgorithm, CryptoKind, HybridSignature, PqcAlgorithm, SignatureMode,
    TaggedClassicalSignature, TaggedPqcSignature, CRYPTO_KIND_CIRIS_V1,
};

/// Trait for classical signature operations.
pub trait ClassicalSigner {
    /// Get the algorithm used by this signer.
    fn algorithm(&self) -> ClassicalAlgorithm;

    /// Get the public key.
    fn public_key(&self) -> Result<Vec<u8>, CryptoError>;

    /// Sign data and return the signature.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// Trait for classical signature verification.
pub trait ClassicalVerifier {
    /// Verify a signature against a public key.
    fn verify(&self, public_key: &[u8], data: &[u8], signature: &[u8])
        -> Result<bool, CryptoError>;
}

/// Trait for PQC signature operations.
pub trait PqcSigner {
    /// Get the algorithm used by this signer.
    fn algorithm(&self) -> PqcAlgorithm;

    /// Get the public key.
    fn public_key(&self) -> Result<Vec<u8>, CryptoError>;

    /// Sign data and return the signature.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// Trait for PQC signature verification.
pub trait PqcVerifier {
    /// Verify a signature against a public key.
    fn verify(&self, public_key: &[u8], data: &[u8], signature: &[u8])
        -> Result<bool, CryptoError>;
}

/// Creates hybrid signatures combining classical and PQC.
pub struct HybridSigner<C, P>
where
    C: ClassicalSigner,
    P: PqcSigner,
{
    classical: C,
    pqc: P,
    crypto_kind: CryptoKind,
}

impl<C, P> HybridSigner<C, P>
where
    C: ClassicalSigner,
    P: PqcSigner,
{
    /// Create a new hybrid signer with the default crypto kind.
    pub fn new(classical: C, pqc: P) -> Result<Self, CryptoError> {
        // Validate PQC algorithm meets requirements
        if !pqc.algorithm().meets_minimum_requirement() {
            return Err(CryptoError::InsufficientPqcSecurity {
                algorithm: pqc.algorithm(),
            });
        }

        Ok(Self {
            classical,
            pqc,
            crypto_kind: CRYPTO_KIND_CIRIS_V1,
        })
    }

    /// Create a hybrid signer with a custom crypto kind.
    pub fn with_crypto_kind(
        classical: C,
        pqc: P,
        crypto_kind: CryptoKind,
    ) -> Result<Self, CryptoError> {
        if !pqc.algorithm().meets_minimum_requirement() {
            return Err(CryptoError::InsufficientPqcSecurity {
                algorithm: pqc.algorithm(),
            });
        }

        Ok(Self {
            classical,
            pqc,
            crypto_kind,
        })
    }

    /// Sign data with both classical and PQC algorithms.
    ///
    /// The PQC signature covers the classical signature to prevent stripping:
    /// ```text
    /// classical_sig = Sign_Classical(data)
    /// pqc_sig = Sign_PQC(data || classical_sig)
    /// ```
    pub fn sign(&self, data: &[u8]) -> Result<HybridSignature, CryptoError> {
        // Step 1: Classical signature over data
        let classical_sig = self.classical.sign(data)?;
        let classical_pk = self.classical.public_key()?;

        // Step 2: Build bound payload (data || classical_signature)
        // This binds the PQC signature to the classical signature
        let mut bound_payload = Vec::with_capacity(data.len() + classical_sig.len());
        bound_payload.extend_from_slice(data);
        bound_payload.extend_from_slice(&classical_sig);

        // Step 3: PQC signature over bound payload
        let pqc_sig = self.pqc.sign(&bound_payload)?;
        let pqc_pk = self.pqc.public_key()?;

        Ok(HybridSignature {
            crypto_kind: self.crypto_kind,
            classical: TaggedClassicalSignature {
                algorithm: self.classical.algorithm(),
                signature: classical_sig,
                public_key: classical_pk,
            },
            pqc: TaggedPqcSignature {
                algorithm: self.pqc.algorithm(),
                signature: pqc_sig,
                public_key: pqc_pk,
            },
            mode: SignatureMode::HybridRequired,
        })
    }

    /// Get the crypto kind used by this signer.
    #[must_use]
    pub fn crypto_kind(&self) -> CryptoKind {
        self.crypto_kind
    }
}

/// Verifies hybrid signatures.
pub struct HybridVerifier<C, P>
where
    C: ClassicalVerifier,
    P: PqcVerifier,
{
    classical: C,
    pqc: P,
    expected_crypto_kind: Option<CryptoKind>,
}

impl<C, P> HybridVerifier<C, P>
where
    C: ClassicalVerifier,
    P: PqcVerifier,
{
    /// Create a new hybrid verifier.
    pub fn new(classical: C, pqc: P) -> Self {
        Self {
            classical,
            pqc,
            expected_crypto_kind: None,
        }
    }

    /// Create a verifier that enforces a specific crypto kind.
    pub fn with_expected_crypto_kind(classical: C, pqc: P, crypto_kind: CryptoKind) -> Self {
        Self {
            classical,
            pqc,
            expected_crypto_kind: Some(crypto_kind),
        }
    }

    /// Verify a hybrid signature.
    ///
    /// Verification steps:
    /// 1. Check crypto kind (if enforced)
    /// 2. Verify classical signature over data
    /// 3. Rebuild bound payload (data || classical_sig)
    /// 4. Verify PQC signature over bound payload
    /// 5. BOTH must pass
    pub fn verify(&self, data: &[u8], signature: &HybridSignature) -> Result<bool, CryptoError> {
        // Step 0: Check crypto kind if enforced
        if let Some(expected) = self.expected_crypto_kind {
            if signature.crypto_kind != expected {
                return Err(CryptoError::CryptoKindMismatch {
                    expected,
                    actual: signature.crypto_kind,
                });
            }
        }

        // Step 1: Verify classical signature over original data
        let classical_valid = self.classical.verify(
            &signature.classical.public_key,
            data,
            &signature.classical.signature,
        )?;

        if !classical_valid {
            return Err(CryptoError::ClassicalVerificationFailed {
                algorithm: signature.classical.algorithm,
            });
        }

        // Step 2: Rebuild bound payload (data || classical_signature)
        let mut bound_payload =
            Vec::with_capacity(data.len() + signature.classical.signature.len());
        bound_payload.extend_from_slice(data);
        bound_payload.extend_from_slice(&signature.classical.signature);

        // Step 3: Verify PQC signature over bound payload
        let pqc_valid = self.pqc.verify(
            &signature.pqc.public_key,
            &bound_payload,
            &signature.pqc.signature,
        )?;

        if !pqc_valid {
            return Err(CryptoError::PqcVerificationFailed {
                algorithm: signature.pqc.algorithm,
            });
        }

        // Both signatures verified
        Ok(true)
    }

    /// Verify only the classical component (for partial verification).
    ///
    /// WARNING: This should only be used for debugging or when PQC is unavailable.
    /// Production verification MUST use [`verify`].
    pub fn verify_classical_only(
        &self,
        data: &[u8],
        signature: &HybridSignature,
    ) -> Result<bool, CryptoError> {
        self.classical.verify(
            &signature.classical.public_key,
            data,
            &signature.classical.signature,
        )
    }

    /// Verify only the PQC component (for testing).
    ///
    /// Note: This verifies the PQC signature over the bound payload,
    /// which requires the classical signature to be present.
    pub fn verify_pqc_only(
        &self,
        data: &[u8],
        signature: &HybridSignature,
    ) -> Result<bool, CryptoError> {
        // Rebuild bound payload
        let mut bound_payload =
            Vec::with_capacity(data.len() + signature.classical.signature.len());
        bound_payload.extend_from_slice(data);
        bound_payload.extend_from_slice(&signature.classical.signature);

        self.pqc.verify(
            &signature.pqc.public_key,
            &bound_payload,
            &signature.pqc.signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock implementations for testing
    struct MockClassicalSigner {
        algorithm: ClassicalAlgorithm,
        public_key: Vec<u8>,
        signature: Vec<u8>,
    }

    impl ClassicalSigner for MockClassicalSigner {
        fn algorithm(&self) -> ClassicalAlgorithm {
            self.algorithm
        }

        fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
            Ok(self.public_key.clone())
        }

        fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
            Ok(self.signature.clone())
        }
    }

    struct MockClassicalVerifier;

    impl ClassicalVerifier for MockClassicalVerifier {
        fn verify(&self, _pk: &[u8], _data: &[u8], _sig: &[u8]) -> Result<bool, CryptoError> {
            Ok(true) // Always pass for testing
        }
    }

    struct MockPqcSigner {
        algorithm: PqcAlgorithm,
        public_key: Vec<u8>,
        signature: Vec<u8>,
    }

    impl PqcSigner for MockPqcSigner {
        fn algorithm(&self) -> PqcAlgorithm {
            self.algorithm
        }

        fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
            Ok(self.public_key.clone())
        }

        fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
            Ok(self.signature.clone())
        }
    }

    struct MockPqcVerifier;

    impl PqcVerifier for MockPqcVerifier {
        fn verify(&self, _pk: &[u8], _data: &[u8], _sig: &[u8]) -> Result<bool, CryptoError> {
            Ok(true) // Always pass for testing
        }
    }

    #[test]
    fn test_hybrid_signer_rejects_insufficient_pqc() {
        let classical = MockClassicalSigner {
            algorithm: ClassicalAlgorithm::EcdsaP256,
            public_key: vec![0; 65],
            signature: vec![0; 64],
        };

        let pqc = MockPqcSigner {
            algorithm: PqcAlgorithm::MlDsa44, // Insufficient
            public_key: vec![0; 1312],
            signature: vec![0; 2420],
        };

        let result = HybridSigner::new(classical, pqc);
        assert!(matches!(
            result,
            Err(CryptoError::InsufficientPqcSecurity { .. })
        ));
    }

    #[test]
    fn test_hybrid_sign_and_verify() {
        let classical_signer = MockClassicalSigner {
            algorithm: ClassicalAlgorithm::EcdsaP256,
            public_key: vec![0x04; 65],
            signature: vec![0xAA; 64],
        };

        let pqc_signer = MockPqcSigner {
            algorithm: PqcAlgorithm::MlDsa65,
            public_key: vec![0xBB; 1952],
            signature: vec![0xCC; 3293],
        };

        let signer = HybridSigner::new(classical_signer, pqc_signer).unwrap();
        let signature = signer.sign(b"test data").unwrap();

        assert_eq!(signature.crypto_kind, CRYPTO_KIND_CIRIS_V1);
        assert_eq!(signature.classical.algorithm, ClassicalAlgorithm::EcdsaP256);
        assert_eq!(signature.pqc.algorithm, PqcAlgorithm::MlDsa65);
        assert_eq!(signature.mode, SignatureMode::HybridRequired);

        // Verify
        let verifier = HybridVerifier::new(MockClassicalVerifier, MockPqcVerifier);
        let result = verifier.verify(b"test data", &signature);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
