//! Composite ML-DSA-65 with Ed25519 (CC 2.6.1.7, CIRISVerify#326).
//!
//! The construction of draft-ietf-lamps-pq-composite-sigs-19 §3, as
//! draft-ietf-jose-pq-composite-sigs-06 profiles it for COSE: the
//! application context is always empty, so the message representative is
//!
//! ```text
//! M' = "CompositeAlgorithmSignatures2025" || "COMPSIG-MLDSA65-Ed25519-SHA512"
//!      || 0x00 || SHA-512(M)
//! ```
//!
//! ML-DSA-65 signs `M'` with the label bytes as its FIPS 204 context string
//! (never the empty one) and Ed25519 signs `M'` as it is. The signature is
//! `mldsaSig || ed25519Sig` (3309 + 64 = 3373 bytes) and the public key
//! `mldsaPK || ed25519PK` (1952 + 32 = 1984 bytes). Both halves must verify;
//! neither verifies alone, because each signs a representative bound to the
//! composite label.
//!
//! Ed25519 is verified strictly (small-order and non-canonical points
//! refused), as everywhere else in verify.
//!
//! Signing is deterministic (FIPS 204 §3.4 permits it) so the pure tier
//! draws no randomness; the private key is the two 32-byte seeds,
//! `mldsaSeed || ed25519Seed`, as LAMPS -19 serializes it.
//!
//! The COSE algorithm identifier is `-70100` (private use) until IANA
//! assigns one; JOSE -06 lists the value as TBD.

use alloc::vec::Vec;

use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use ml_dsa::signature::Keypair as _;
use ml_dsa::{
    EncodedVerifyingKey, MlDsa65, Seed, Signature as MlSignature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use crate::CryptoError;

/// The LAMPS -19 domain prefix, the ASCII bytes of `CompositeAlgorithmSignatures2025`.
pub const PREFIX: &[u8; 32] = b"CompositeAlgorithmSignatures2025";
/// The signature label of ML-DSA-65 with Ed25519 (LAMPS -19 §6).
pub const LABEL: &[u8; 30] = b"COMPSIG-MLDSA65-Ed25519-SHA512";
/// The private-use COSE algorithm identifier carried until IANA assigns one.
pub const COSE_ALG: i64 = -70100;
/// ML-DSA-65 public key length.
pub const MLDSA65_PK_LEN: usize = 1952;
/// ML-DSA-65 signature length.
pub const MLDSA65_SIG_LEN: usize = 3309;
/// Composite public key length.
pub const PUBLIC_KEY_LEN: usize = MLDSA65_PK_LEN + 32;
/// Composite signature length.
pub const SIGNATURE_LEN: usize = MLDSA65_SIG_LEN + 64;
/// Composite private key length (the two seeds).
pub const SECRET_KEY_LEN: usize = 64;
/// Message representative length: prefix, label, the context length byte, SHA-512.
pub const REPRESENTATIVE_LEN: usize = 32 + 30 + 1 + 64;

/// `M'` for `msg` under the empty application context.
#[must_use]
pub fn message_representative(msg: &[u8]) -> [u8; REPRESENTATIVE_LEN] {
    let mut out = [0u8; REPRESENTATIVE_LEN];
    out[..32].copy_from_slice(PREFIX);
    out[32..62].copy_from_slice(LABEL);
    out[62] = 0x00;
    out[63..].copy_from_slice(&Sha512::digest(msg));
    out
}

/// A composite signing key held as its two seeds.
pub struct CompositeSigningKey {
    mldsa: SigningKey<MlDsa65>,
    ed25519: EdSigningKey,
    public: CompositePublicKey,
}

impl CompositeSigningKey {
    /// Build from the ML-DSA-65 seed (FIPS 204 `ξ`) and the Ed25519 seed.
    #[must_use]
    pub fn from_seeds(mldsa_seed: &[u8; 32], ed25519_seed: &[u8; 32]) -> Self {
        let seed = Zeroizing::new(Seed::from(*mldsa_seed));
        let mldsa = SigningKey::<MlDsa65>::from_seed(&seed);
        let ed25519 = EdSigningKey::from_bytes(ed25519_seed);
        let mut pk = [0u8; PUBLIC_KEY_LEN];
        pk[..MLDSA65_PK_LEN].copy_from_slice(&mldsa.verifying_key().encode());
        pk[MLDSA65_PK_LEN..].copy_from_slice(ed25519.verifying_key().as_bytes());
        let public = CompositePublicKey::from_bytes(&pk)
            .expect("a freshly derived composite public key decodes");
        Self {
            mldsa,
            ed25519,
            public,
        }
    }

    /// Build from the LAMPS -19 private key serialization, `mldsaSeed || ed25519Seed`.
    ///
    /// # Errors
    /// [`CryptoError::InvalidPrivateKey`] unless `sk` is 64 bytes.
    pub fn from_bytes(sk: &[u8]) -> Result<Self, CryptoError> {
        if sk.len() != SECRET_KEY_LEN {
            return Err(CryptoError::InvalidPrivateKey {
                reason: alloc::format!(
                    "composite private key is {SECRET_KEY_LEN} bytes, got {}",
                    sk.len()
                ),
            });
        }
        let mut a = Zeroizing::new([0u8; 32]);
        let mut b = Zeroizing::new([0u8; 32]);
        a.copy_from_slice(&sk[..32]);
        b.copy_from_slice(&sk[32..]);
        Ok(Self::from_seeds(&a, &b))
    }

    /// The composite public key.
    #[must_use]
    pub fn public_key(&self) -> &CompositePublicKey {
        &self.public
    }

    /// Sign `msg`: both halves over `M'`, deterministically.
    ///
    /// # Errors
    /// [`CryptoError::SigningFailed`] if ML-DSA signing fails.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mp = message_representative(msg);
        let ml = self
            .mldsa
            .expanded_key()
            .sign_deterministic(&mp, LABEL)
            .map_err(|_| CryptoError::SigningFailed {
                reason: "ML-DSA-65 composite half".into(),
            })?;
        let ed = self.ed25519.sign(&mp);
        let mut out = Vec::with_capacity(SIGNATURE_LEN);
        out.extend_from_slice(&ml.encode());
        out.extend_from_slice(&ed.to_bytes());
        debug_assert_eq!(out.len(), SIGNATURE_LEN);
        Ok(out)
    }
}

/// The ML-DSA-65 half of a composite key, held here, with the Ed25519 half
/// held elsewhere: a PIV token (YubiKey 9c), a platform keystore, or any
/// external Ed25519 signer. CC 4.2.2 lets a composite key's halves be held
/// apart; an accord holder keeps Ed25519 on a YubiKey and ML-DSA-65 on a
/// separate offline USB key (`pq_custody: removable_offline`).
///
/// [`SplitCompositeSigner::sign`] computes `M'`, signs it with ML-DSA-65
/// locally (the label as FIPS 204 context), hands the same 127-byte `M'` to
/// the external Ed25519 signer, and assembles `mldsaSig || ed25519Sig`: the
/// same bytes [`CompositeSigningKey`] produces for the same keys. The
/// external signature is verified against the stated Ed25519 public key
/// before it is returned, so a token that signs with the wrong key is caught
/// at mint, not by a verifier later.
pub struct SplitCompositeSigner {
    mldsa: SigningKey<MlDsa65>,
    public: CompositePublicKey,
}

impl SplitCompositeSigner {
    /// From the ML-DSA-65 seed and the external half's Ed25519 public key.
    ///
    /// # Errors
    /// [`CryptoError::InvalidPublicKey`] if `ed25519_public` is not a valid point.
    pub fn new(mldsa_seed: &[u8; 32], ed25519_public: &[u8; 32]) -> Result<Self, CryptoError> {
        let seed = Zeroizing::new(Seed::from(*mldsa_seed));
        let mldsa = SigningKey::<MlDsa65>::from_seed(&seed);
        let mut pk = [0u8; PUBLIC_KEY_LEN];
        pk[..MLDSA65_PK_LEN].copy_from_slice(&mldsa.verifying_key().encode());
        pk[MLDSA65_PK_LEN..].copy_from_slice(ed25519_public);
        let public = CompositePublicKey::from_bytes(&pk)?;
        Ok(Self { mldsa, public })
    }

    /// The composite public key.
    #[must_use]
    pub fn public_key(&self) -> &CompositePublicKey {
        &self.public
    }

    /// The message representative the external Ed25519 signer must sign
    /// for `msg` (exposed for asynchronous signers, which compute it first).
    #[must_use]
    pub fn representative(msg: &[u8]) -> [u8; REPRESENTATIVE_LEN] {
        message_representative(msg)
    }

    /// Sign `msg`, calling `ed25519_sign` with `M'` for the classical half.
    ///
    /// # Errors
    /// The external signer's error, [`CryptoError::SigningFailed`] if ML-DSA
    /// signing fails, or [`CryptoError::VerificationFailed`] if the external
    /// signature does not verify under the stated Ed25519 public key.
    pub fn sign(
        &self,
        msg: &[u8],
        ed25519_sign: impl FnOnce(&[u8]) -> Result<[u8; 64], CryptoError>,
    ) -> Result<Vec<u8>, CryptoError> {
        let mp = message_representative(msg);
        let ed = ed25519_sign(&mp)?;
        self.assemble(msg, &ed)
    }

    /// Assemble the composite from an Ed25519 signature over
    /// [`Self::representative`]`(msg)` obtained by the caller (for example
    /// asynchronously from a token), signing the ML-DSA-65 half here.
    ///
    /// # Errors
    /// As [`Self::sign`].
    pub fn assemble(&self, msg: &[u8], ed25519_sig: &[u8; 64]) -> Result<Vec<u8>, CryptoError> {
        let mp = message_representative(msg);
        let ed_sig = ed25519_dalek::Signature::from_bytes(ed25519_sig);
        if self.public.ed25519.verify_strict(&mp, &ed_sig).is_err() {
            return Err(CryptoError::VerificationFailed);
        }
        let ml = self
            .mldsa
            .expanded_key()
            .sign_deterministic(&mp, LABEL)
            .map_err(|_| CryptoError::SigningFailed {
                reason: "ML-DSA-65 composite half".into(),
            })?;
        let mut out = Vec::with_capacity(SIGNATURE_LEN);
        out.extend_from_slice(&ml.encode());
        out.extend_from_slice(ed25519_sig);
        Ok(out)
    }
}

/// A composite public key, `mldsaPK || ed25519PK`.
#[derive(Clone)]
pub struct CompositePublicKey {
    bytes: [u8; PUBLIC_KEY_LEN],
    mldsa: VerifyingKey<MlDsa65>,
    ed25519: EdVerifyingKey,
}

impl core::fmt::Debug for CompositePublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CompositePublicKey").finish_non_exhaustive()
    }
}

impl CompositePublicKey {
    /// Decode the 1984-byte composite public key.
    ///
    /// # Errors
    /// [`CryptoError::InvalidPublicKey`] on a wrong length or an Ed25519 half
    /// that is not a valid point.
    pub fn from_bytes(pk: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; PUBLIC_KEY_LEN] =
            pk.try_into().map_err(|_| CryptoError::InvalidPublicKey {
                reason: alloc::format!(
                    "composite public key is {PUBLIC_KEY_LEN} bytes, got {}",
                    pk.len()
                ),
            })?;
        let enc =
            EncodedVerifyingKey::<MlDsa65>::try_from(&bytes[..MLDSA65_PK_LEN]).map_err(|_| {
                CryptoError::InvalidPublicKey {
                    reason: "ML-DSA-65 half".into(),
                }
            })?;
        let mldsa = VerifyingKey::<MlDsa65>::decode(&enc);
        let ed: [u8; 32] = bytes[MLDSA65_PK_LEN..].try_into().expect("32 bytes");
        let ed25519 =
            EdVerifyingKey::from_bytes(&ed).map_err(|_| CryptoError::InvalidPublicKey {
                reason: "Ed25519 half".into(),
            })?;
        Ok(Self {
            bytes,
            mldsa,
            ed25519,
        })
    }

    /// The 1984-byte encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.bytes
    }

    /// Verify a composite signature over `msg`. Both halves must verify; the
    /// result does not say which one failed.
    ///
    /// # Errors
    /// [`CryptoError::InvalidSignature`] on a wrong length,
    /// [`CryptoError::VerificationFailed`] otherwise.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        if sig.len() != SIGNATURE_LEN {
            return Err(CryptoError::InvalidSignature {
                reason: alloc::format!(
                    "composite signature is {SIGNATURE_LEN} bytes, got {}",
                    sig.len()
                ),
            });
        }
        let mp = message_representative(msg);
        let ml_ok = MlSignature::<MlDsa65>::try_from(&sig[..MLDSA65_SIG_LEN])
            .map(|s| self.mldsa.verify_with_context(&mp, LABEL, &s))
            .unwrap_or(false);
        let ed_sig = ed25519_dalek::Signature::from_bytes(
            sig[MLDSA65_SIG_LEN..].try_into().expect("64 bytes"),
        );
        let ed_ok = self.ed25519.verify_strict(&mp, &ed_sig).is_ok();
        // Evaluate both before deciding, so the failure is one outcome.
        if ml_ok & ed_ok {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn representative_layout() {
        let mp = message_representative(b"");
        assert_eq!(&mp[..32], PREFIX);
        assert_eq!(&mp[32..62], LABEL);
        assert_eq!(mp[62], 0);
        assert_eq!(&mp[63..], Sha512::digest(b"").as_slice());
    }

    #[test]
    fn round_trip_and_tamper() {
        let k = CompositeSigningKey::from_seeds(&[7; 32], &[9; 32]);
        let sig = k.sign(b"row").unwrap();
        assert_eq!(sig.len(), SIGNATURE_LEN);
        let pk = CompositePublicKey::from_bytes(k.public_key().as_bytes()).unwrap();
        pk.verify(b"row", &sig).unwrap();
        assert!(pk.verify(b"rov", &sig).is_err());
        for i in [0, MLDSA65_SIG_LEN - 1, MLDSA65_SIG_LEN, SIGNATURE_LEN - 1] {
            let mut bad = sig.clone();
            bad[i] ^= 1;
            assert!(pk.verify(b"row", &bad).is_err(), "byte {i}");
        }
        assert!(pk.verify(b"row", &sig[..SIGNATURE_LEN - 1]).is_err());
    }

    #[test]
    fn split_signer_matches_the_whole_key() {
        let whole = CompositeSigningKey::from_seeds(&[3; 32], &[4; 32]);
        let token = EdSigningKey::from_bytes(&[4; 32]);
        let split = SplitCompositeSigner::new(&[3; 32], token.verifying_key().as_bytes()).unwrap();
        assert_eq!(split.public_key().as_bytes(), whole.public_key().as_bytes());
        let sig = split
            .sign(b"row", |mp| {
                assert_eq!(mp.len(), REPRESENTATIVE_LEN);
                Ok(token.sign(mp).to_bytes())
            })
            .unwrap();
        assert_eq!(sig, whole.sign(b"row").unwrap());
        whole.public_key().verify(b"row", &sig).unwrap();
        // A token signing with another key is caught at mint.
        let wrong = EdSigningKey::from_bytes(&[5; 32]);
        assert!(matches!(
            split.sign(b"row", |mp| Ok(wrong.sign(mp).to_bytes())),
            Err(CryptoError::VerificationFailed)
        ));
        // The asynchronous path: representative first, assemble later.
        let mp = SplitCompositeSigner::representative(b"row");
        let ed = token.sign(&mp).to_bytes();
        assert_eq!(split.assemble(b"row", &ed).unwrap(), sig);
    }

    #[test]
    fn deterministic() {
        let k = CompositeSigningKey::from_seeds(&[1; 32], &[2; 32]);
        assert_eq!(k.sign(b"m").unwrap(), k.sign(b"m").unwrap());
    }
}
