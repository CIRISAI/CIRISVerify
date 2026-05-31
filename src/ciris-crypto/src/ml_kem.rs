//! ML-KEM-768 (FIPS 203 final) primitive — bytes-only public API
//! (CIRISVerify#47, v4.6.0+).
//!
//! Backend: `ml-kem` crate (RustCrypto, FIPS 203 final). This module
//! wraps it in a bytes-only public surface — consumers handle
//! `Vec<u8>` keys and ciphertexts without depending on `ml-kem` types
//! directly.
//!
//! ## Sizes (FIPS 203 Table 3)
//!
//! - public key (encapsulation key):   1184 B
//! - private key (decapsulation key):  2400 B (expanded form)
//! - ciphertext:                       1088 B
//! - shared secret:                      32 B

use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem, KeyExport, KeyInit},
    MlKem768,
};

use crate::error::CryptoError;

/// ML-KEM-768 encapsulation-key (public-key) length in bytes.
pub const ML_KEM_768_PUBKEY_LEN: usize = 1184;

/// ML-KEM-768 decapsulation-key (private-key) length in bytes.
/// This is the SEED-form encoding (64 bytes) — the wire-canonical
/// form per FIPS 203 + the form `to_bytes()` produces. The expanded
/// 2400-byte form is reconstructed deterministically on decap.
pub const ML_KEM_768_PRIVKEY_LEN: usize = 64;

/// ML-KEM-768 ciphertext length in bytes.
pub const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;

/// ML-KEM-768 shared-secret length in bytes.
pub const ML_KEM_768_SHARED_SECRET_LEN: usize = 32;

/// Generate a fresh ML-KEM-768 keypair using the system CSPRNG.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let (dk, ek) = MlKem768::generate_keypair();
    Ok((dk.to_bytes().to_vec(), ek.to_bytes().to_vec()))
}

/// Encapsulate a fresh shared secret under `recipient_public_key`.
pub fn encapsulate(recipient_public_key: &[u8]) -> Result<(Vec<u8>, [u8; 32]), CryptoError> {
    if recipient_public_key.len() != ML_KEM_768_PUBKEY_LEN {
        return Err(CryptoError::InvalidPublicKey {
            reason: format!(
                "ML-KEM-768 pubkey wrong length (expected {}, got {})",
                ML_KEM_768_PUBKEY_LEN,
                recipient_public_key.len()
            ),
        });
    }
    let ek_array: &ml_kem::Key<ml_kem::ml_kem_768::EncapsulationKey> = recipient_public_key
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKey {
            reason: "ML-KEM-768 pubkey array conversion failed".into(),
        })?;
    let ek = ml_kem::ml_kem_768::EncapsulationKey::new(ek_array).map_err(|_| {
        CryptoError::InvalidPublicKey {
            reason: "ML-KEM-768 pubkey invalid".into(),
        }
    })?;
    let (ct, ss) = ek.encapsulate();
    let mut ss_out = [0u8; 32];
    ss_out.copy_from_slice(&ss);
    Ok((ct.to_vec(), ss_out))
}

/// Decapsulate a ciphertext using `recipient_private_key`.
pub fn decapsulate(
    recipient_private_key: &[u8],
    ciphertext: &[u8],
) -> Result<[u8; 32], CryptoError> {
    if recipient_private_key.len() != ML_KEM_768_PRIVKEY_LEN {
        return Err(CryptoError::InvalidPrivateKey {
            reason: format!(
                "ML-KEM-768 privkey wrong length (expected {}, got {})",
                ML_KEM_768_PRIVKEY_LEN,
                recipient_private_key.len()
            ),
        });
    }
    if ciphertext.len() != ML_KEM_768_CIPHERTEXT_LEN {
        return Err(CryptoError::SerializationError(format!(
            "ML-KEM-768 ciphertext wrong length (expected {}, got {})",
            ML_KEM_768_CIPHERTEXT_LEN,
            ciphertext.len()
        )));
    }
    let dk_array: &ml_kem::Key<ml_kem::ml_kem_768::DecapsulationKey> = recipient_private_key
        .try_into()
        .map_err(|_| CryptoError::InvalidPrivateKey {
            reason: "ML-KEM-768 privkey array conversion failed".into(),
        })?;
    let dk = ml_kem::ml_kem_768::DecapsulationKey::new(dk_array);
    let ct_array: &ml_kem::kem::Ciphertext<MlKem768> = ciphertext.try_into().map_err(|_| {
        CryptoError::SerializationError("ML-KEM-768 ciphertext array conversion failed".into())
    })?;
    let ss = dk.decapsulate(ct_array);
    let mut ss_out = [0u8; 32];
    ss_out.copy_from_slice(&ss);
    Ok(ss_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_lengths_match_fips_203_spec() {
        let (sk, pk) = generate_keypair().unwrap();
        assert_eq!(pk.len(), ML_KEM_768_PUBKEY_LEN);
        assert_eq!(sk.len(), ML_KEM_768_PRIVKEY_LEN);
    }

    #[test]
    fn encap_decap_round_trip() {
        let (sk, pk) = generate_keypair().unwrap();
        let (ct, ss_send) = encapsulate(&pk).unwrap();
        assert_eq!(ct.len(), ML_KEM_768_CIPHERTEXT_LEN);
        let ss_recv = decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_send, ss_recv);
    }

    #[test]
    fn fresh_keypairs_produce_distinct_publics() {
        let (_, pk_a) = generate_keypair().unwrap();
        let (_, pk_b) = generate_keypair().unwrap();
        assert_ne!(pk_a, pk_b);
    }

    #[test]
    fn fresh_encaps_produce_distinct_ciphertexts() {
        let (_, pk) = generate_keypair().unwrap();
        let (ct_a, ss_a) = encapsulate(&pk).unwrap();
        let (ct_b, ss_b) = encapsulate(&pk).unwrap();
        assert_ne!(ct_a, ct_b);
        assert_ne!(ss_a, ss_b);
    }

    #[test]
    fn decap_with_wrong_privkey_yields_different_secret() {
        let (sk_a, pk_a) = generate_keypair().unwrap();
        let (sk_b, _) = generate_keypair().unwrap();
        let (ct, ss_legit) = encapsulate(&pk_a).unwrap();
        assert_eq!(ss_legit, decapsulate(&sk_a, &ct).unwrap());
        let ss_wrong = decapsulate(&sk_b, &ct).unwrap();
        assert_ne!(ss_legit, ss_wrong);
    }

    #[test]
    fn encap_rejects_wrong_length_pubkey() {
        assert!(encapsulate(&[0u8; 100]).is_err());
    }

    #[test]
    fn decap_rejects_wrong_length_inputs() {
        let (sk, pk) = generate_keypair().unwrap();
        let (ct, _) = encapsulate(&pk).unwrap();
        assert!(decapsulate(&[0u8; 100], &ct).is_err());
        assert!(decapsulate(&sk, &[0u8; 100]).is_err());
    }
}
