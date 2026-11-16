//! The CC 2.6.1.7 composite (ML-DSA-65 with Ed25519) over two opaque keyring
//! signers (v23.1.2).
//!
//! A caller that holds the halves behind the keyring's traits, an Ed25519
//! [`HardwareSigner`] and an ML-DSA-65 [`PqcSigner`] (often sealed:
//! `SealedMlDsa65Signer`, `UsbWrappedMlDsa65Signer`), never reads either seed.
//! [`composite_sign`](crate::composite::composite_sign) computes the message
//! representative `M'`, has the ML-DSA-65 signer sign it under the composite
//! label as its FIPS 204 context
//! ([`PqcSigner::sign_with_context`]), has the Ed25519 signer sign the same
//! `M'`, and assembles `mldsaSig || ed25519Sig` with
//! [`ciris_crypto::composite::assemble_composite`], which checks both halves
//! under the stated composite public key before returning. For the same seeds
//! the bytes equal `CompositeSigningKey::from_seeds(..).sign(msg)`.
//!
//! ## Which `HardwareSigner`s are usable (PureEdDSA)
//!
//! The Ed25519 half must sign the 127-byte `M'` as given (RFC 8032 PureEdDSA),
//! not a prehash of it. In this crate the signers whose
//! [`HardwareSigner::algorithm`] is `Ed25519` all do: `Ed25519SoftwareSigner`
//! (`ed25519_dalek` over the bytes), `SealedEd25519Signer` (delegates to it)
//! and the PKCS#11 / YubiKey PIV `Pkcs11Signer` with an Ed25519 key
//! (`CKM_EDDSA` over the bytes; `M'` is far below the token's single-shot
//! input cap, #113). Every other keyring signer (`SoftwareSigner`, the TPM
//! plugin and Windows TPM signers, Android Keystore, Secure Enclave,
//! `KeyringStorageSigner`) is ECDSA P-256, prehashes with SHA-256, and is
//! refused here by algorithm before anything is signed. An external Ed25519
//! signer that prehashes (Ed25519ph) would produce a signature that fails the
//! strict check in `assemble_composite`, so it is refused at mint either way.

use ciris_crypto::composite::{assemble_composite, message_representative, LABEL};
pub use ciris_crypto::composite::{CompositePublicKey, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use ciris_crypto::CryptoError;

use crate::error::KeyringError;
use crate::pqc::{PqcAlgorithm, PqcSigner};
use crate::signer::HardwareSigner;
use crate::types::ClassicalAlgorithm;

fn check_algorithms(
    ed25519: &dyn HardwareSigner,
    mldsa: &dyn PqcSigner,
) -> Result<(), KeyringError> {
    if ed25519.algorithm() != ClassicalAlgorithm::Ed25519 {
        return Err(KeyringError::InvalidKey {
            reason: format!(
                "composite classical half must be an Ed25519 signer, got {:?}",
                ed25519.algorithm()
            ),
        });
    }
    if mldsa.algorithm() != PqcAlgorithm::MlDsa65 {
        return Err(KeyringError::InvalidKey {
            reason: format!(
                "composite PQC half must be an ML-DSA-65 signer, got {:?}",
                mldsa.algorithm()
            ),
        });
    }
    Ok(())
}

fn crypto_err(e: CryptoError) -> KeyringError {
    match e {
        CryptoError::VerificationFailed => KeyringError::SigningFailed {
            reason: "composite: a half does not verify under the composite public key \
                     (wrong key, a prehashing Ed25519 signer, or a missing ML-DSA context)"
                .into(),
        },
        CryptoError::InvalidPublicKey { reason } => KeyringError::InvalidKey {
            reason: format!("composite public key: {reason}"),
        },
        other => KeyringError::SigningFailed {
            reason: format!("composite: {other}"),
        },
    }
}

/// The composite public key `mldsaPK || ed25519PK` of the two signers.
///
/// # Errors
///
/// [`KeyringError::InvalidKey`] if `ed25519` is not an Ed25519 signer,
/// `mldsa` is not ML-DSA-65, or a public key does not decode; otherwise the
/// signers' own `public_key` errors.
pub async fn composite_public_key(
    ed25519: &dyn HardwareSigner,
    mldsa: &dyn PqcSigner,
) -> Result<CompositePublicKey, KeyringError> {
    check_algorithms(ed25519, mldsa)?;
    let ml_pk = mldsa.public_key().await?;
    let ed_pk = ed25519.public_key().await?;
    CompositePublicKey::from_halves(&ml_pk, &ed_pk).map_err(crypto_err)
}

/// Sign `msg` as the CC 2.6.1.7 composite: 3373 bytes, `mldsaSig || ed25519Sig`.
///
/// Computes `M' = message_representative(msg)`, calls
/// `mldsa.sign_with_context(LABEL, M')` and `ed25519.sign(M')`, then
/// [`assemble_composite`] checks both halves under `composite_public` (ML-DSA
/// with ctx = `LABEL`, Ed25519 strictly). Deterministic when both signers are
/// (every keyring ML-DSA-65 signer and Ed25519 is).
///
/// # Errors
///
/// - [`KeyringError::InvalidKey`] if `ed25519` is not an Ed25519 signer or
///   `mldsa` is not ML-DSA-65 (checked before either signs);
/// - the signers' own errors, including [`KeyringError::NotSupported`] from a
///   `PqcSigner` that does not implement `sign_with_context`;
/// - [`KeyringError::SigningFailed`] if the Ed25519 signature is not 64 bytes
///   or either half does not verify under `composite_public` (a signer whose
///   key is not the one in `composite_public` is refused here).
pub async fn composite_sign(
    ed25519: &dyn HardwareSigner,
    mldsa: &dyn PqcSigner,
    composite_public: &CompositePublicKey,
    msg: &[u8],
) -> Result<Vec<u8>, KeyringError> {
    check_algorithms(ed25519, mldsa)?;
    let mp = message_representative(msg);
    let ml_sig = mldsa.sign_with_context(LABEL, &mp).await?;
    let ed_sig = ed25519.sign(&mp).await?;
    let ed_sig: [u8; 64] =
        ed_sig
            .as_slice()
            .try_into()
            .map_err(|_| KeyringError::SigningFailed {
                reason: format!("Ed25519 signature is 64 bytes, got {}", ed_sig.len()),
            })?;
    assemble_composite(composite_public, msg, &ml_sig, &ed_sig).map_err(crypto_err)
}

#[cfg(all(test, feature = "software"))]
mod tests {
    use async_trait::async_trait;
    use ciris_crypto::composite::CompositeSigningKey;

    use super::*;
    use crate::pqc::MlDsa65SoftwareSigner;
    use crate::software::{Ed25519SoftwareSigner, SoftwareSigner};
    use crate::types::{HardwareType, PlatformAttestation, StorageDescriptor};

    const ML_SEED: [u8; 32] = [3; 32];
    const ED_SEED: [u8; 32] = [4; 32];

    fn signers() -> (Ed25519SoftwareSigner, MlDsa65SoftwareSigner) {
        (
            Ed25519SoftwareSigner::from_bytes(&ED_SEED, "ed").unwrap(),
            MlDsa65SoftwareSigner::from_seed_bytes(&ML_SEED, "ml").unwrap(),
        )
    }

    #[tokio::test]
    async fn matches_the_whole_key() {
        let (ed, ml) = signers();
        let whole = CompositeSigningKey::from_seeds(&ML_SEED, &ED_SEED);
        let public = composite_public_key(&ed, &ml).await.unwrap();
        assert_eq!(public.as_bytes(), whole.public_key().as_bytes());
        for msg in [&b""[..], b"row", &[0x5a; 4096]] {
            let sig = composite_sign(&ed, &ml, &public, msg).await.unwrap();
            assert_eq!(sig.len(), SIGNATURE_LEN);
            assert_eq!(sig, whole.sign(msg).unwrap());
            public.verify(msg, &sig).unwrap();
        }
    }

    #[tokio::test]
    async fn direct_crypto_signer_matches_too() {
        let ed = Ed25519SoftwareSigner::from_bytes(&ED_SEED, "ed").unwrap();
        let ml = ciris_crypto::MlDsa65Signer::from_seed(&ML_SEED).unwrap();
        let public = composite_public_key(&ed, &ml).await.unwrap();
        let sig = composite_sign(&ed, &ml, &public, b"row").await.unwrap();
        assert_eq!(
            sig,
            CompositeSigningKey::from_seeds(&ML_SEED, &ED_SEED)
                .sign(b"row")
                .unwrap()
        );
    }

    #[tokio::test]
    async fn mismatched_ed25519_is_refused_at_assemble() {
        let (_, ml) = signers();
        let public = CompositeSigningKey::from_seeds(&ML_SEED, &ED_SEED)
            .public_key()
            .clone();
        let wrong = Ed25519SoftwareSigner::from_bytes(&[5; 32], "wrong").unwrap();
        let err = composite_sign(&wrong, &ml, &public, b"row")
            .await
            .unwrap_err();
        assert!(matches!(err, KeyringError::SigningFailed { .. }), "{err:?}");
        // And an ML-DSA half from another seed.
        let (ed, _) = signers();
        let other_ml = MlDsa65SoftwareSigner::from_seed_bytes(&[6; 32], "other").unwrap();
        let err = composite_sign(&ed, &other_ml, &public, b"row")
            .await
            .unwrap_err();
        assert!(matches!(err, KeyringError::SigningFailed { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn p256_signer_is_refused_by_algorithm() {
        let (_, ml) = signers();
        let p256 = SoftwareSigner::generate_in_memory("p256").unwrap();
        let public = CompositeSigningKey::from_seeds(&ML_SEED, &ED_SEED)
            .public_key()
            .clone();
        assert!(matches!(
            composite_sign(&p256, &ml, &public, b"row").await,
            Err(KeyringError::InvalidKey { .. })
        ));
    }

    /// A `PqcSigner` that leaves `sign_with_context` at its default.
    struct NoContext;

    #[async_trait]
    impl PqcSigner for NoContext {
        fn algorithm(&self) -> PqcAlgorithm {
            PqcAlgorithm::MlDsa65
        }
        fn hardware_type(&self) -> HardwareType {
            HardwareType::SoftwareOnly
        }
        async fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
            Ok(vec![0; 1952])
        }
        async fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, KeyringError> {
            Ok(vec![0; 3309])
        }
        async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
            Err(KeyringError::NoPlatformSupport)
        }
        fn current_alias(&self) -> &str {
            "no-context"
        }
        fn storage_descriptor(&self) -> StorageDescriptor {
            StorageDescriptor::InMemory
        }
    }

    #[tokio::test]
    async fn default_sign_with_context_is_unsupported() {
        assert!(matches!(
            NoContext.sign_with_context(LABEL, b"m").await,
            Err(KeyringError::NotSupported { .. })
        ));
        let (ed, _) = signers();
        let public = CompositeSigningKey::from_seeds(&ML_SEED, &ED_SEED)
            .public_key()
            .clone();
        assert!(matches!(
            composite_sign(&ed, &NoContext, &public, b"row").await,
            Err(KeyringError::NotSupported { .. })
        ));
    }

    #[tokio::test]
    async fn over_long_context_is_refused() {
        let (_, ml) = signers();
        let direct = ciris_crypto::MlDsa65Signer::from_seed(&ML_SEED).unwrap();
        let signers: [&dyn PqcSigner; 2] = [&ml, &direct];
        for s in signers {
            assert!(s.sign_with_context(&[0; 255], b"m").await.is_ok());
            assert!(matches!(
                s.sign_with_context(&[0; 256], b"m").await,
                Err(KeyringError::SigningFailed { .. })
            ));
            // The empty context is `sign`.
            assert_eq!(
                s.sign_with_context(b"", b"m").await.unwrap(),
                s.sign(b"m").await.unwrap()
            );
        }
        // A keyless signer reports the over-long context first.
        let keyless = MlDsa65SoftwareSigner::new("keyless");
        assert!(matches!(
            keyless.sign_with_context(&[0; 256], b"m").await,
            Err(KeyringError::SigningFailed { .. })
        ));
    }
}
