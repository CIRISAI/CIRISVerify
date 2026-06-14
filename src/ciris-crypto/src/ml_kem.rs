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

/// Deterministically derive an ML-KEM-768 keypair from a 64-byte seed
/// (`d || z` per FIPS 203 §7 keygen). Returns `(dk_seed_bytes, ek_bytes)`
/// matching the byte layout of [`generate_keypair`].
///
/// This is the FIPS 203 deterministic keygen path. It is the basis for
/// Known-Answer-Test (KAT) verification against the reference vectors;
/// production callers should use [`generate_keypair`] (system CSPRNG).
pub fn generate_keypair_deterministic(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    if seed.len() != ML_KEM_768_PRIVKEY_LEN {
        return Err(CryptoError::InvalidPrivateKey {
            reason: format!(
                "ML-KEM-768 keygen seed wrong length (expected {}, got {})",
                ML_KEM_768_PRIVKEY_LEN,
                seed.len()
            ),
        });
    }
    let seed_arr: &ml_kem::Seed = seed
        .try_into()
        .map_err(|_| CryptoError::InvalidPrivateKey {
            reason: "ML-KEM-768 keygen seed array conversion failed".into(),
        })?;
    let dk = ml_kem::ml_kem_768::DecapsulationKey::from_seed(*seed_arr);
    let dk_seed = dk.to_seed().ok_or_else(|| CryptoError::InvalidPrivateKey {
        reason: "ML-KEM-768 dk not seed-backed".into(),
    })?;
    let ek = dk.encapsulation_key();
    Ok((dk_seed.to_vec(), ek.to_bytes().to_vec()))
}

/// Deterministically encapsulate under `recipient_public_key` using a fixed
/// 32-byte message `m` (FIPS 203 §7 encaps randomness). Returns
/// `(ciphertext, shared_secret)`.
///
/// FIPS 203 KAT-only path. Production callers MUST use [`encapsulate`]
/// (fresh CSPRNG `m`) — reusing `m` across encapsulations is catastrophic.
pub fn encapsulate_deterministic(
    recipient_public_key: &[u8],
    m: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), CryptoError> {
    if recipient_public_key.len() != ML_KEM_768_PUBKEY_LEN {
        return Err(CryptoError::InvalidPublicKey {
            reason: format!(
                "ML-KEM-768 pubkey wrong length (expected {}, got {})",
                ML_KEM_768_PUBKEY_LEN,
                recipient_public_key.len()
            ),
        });
    }
    if m.len() != ML_KEM_768_SHARED_SECRET_LEN {
        return Err(CryptoError::SerializationError(format!(
            "ML-KEM-768 encaps m wrong length (expected {}, got {})",
            ML_KEM_768_SHARED_SECRET_LEN,
            m.len()
        )));
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
    let m_arr: &ml_kem::B32 = m.try_into().map_err(|_| {
        CryptoError::SerializationError("ML-KEM-768 m array conversion failed".into())
    })?;
    let (ct, ss) = ek.encapsulate_deterministic(m_arr);
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

    // ---- FIPS 203 deterministic Known-Answer-Test (KAT) ----
    //
    // These vectors PIN the exact byte output of the shipped `ml-kem`
    // (RustCrypto) ML-KEM-768 backend through this module's deterministic
    // surface, so a backend bump that silently changes the encoding (or a
    // build mis-link) is caught at test time.
    //
    // Inputs are the FIPS 203 §7 deterministic-keygen/encaps randomness:
    //   keygen seed = d || z, with d = bytes 0x00..0x1f, z = bytes 0x20..0x3f
    //   encaps m    = bytes 0x80..0x9f
    //
    // Expected values are SHA-256 digests of the full 1184 B ek / 64 B dk
    // seed / 1088 B ciphertext (too large to inline) plus the full 32 B
    // shared secret. They were captured from this backend and are stable
    // across runs and machines because every step is deterministic.
    //
    // PROVENANCE NOTE: this is an exact-output KAT pinned to the RustCrypto
    // `ml-kem` 0.3.x backend's encoding. It is NOT independently cross-
    // checked against the NIST ACVP ML-KEM-768 response file in THIS module
    // — the backend crate carries its own ACVP/Wycheproof vector tests
    // (see `ml-kem`'s `tests/wycheproof.rs`), which our dependency on it
    // transitively exercises. To upgrade this to a NIST-sourced KAT, drop an
    // ACVP `dk`/`ek`/`c`/`k` triple here and compare bytes directly.
    const KAT_EK_SHA256: &str = "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9";
    const KAT_DK_SEED_SHA256: &str =
        "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108";
    const KAT_CT_SHA256: &str = "1f16e217ad23771f7f72522c602dcf10cd1e2eea2648e72d29c1255a3949c33e";
    const KAT_SS_HEX: &str = "ef91db44b6cd5b2c50f483481a3d6e2a08cc149764fcb8dc568851332da45ed9";

    fn sha256_hex(b: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut s = Sha256::new();
        s.update(b);
        hex::encode(s.finalize())
    }

    fn kat_keygen_seed() -> [u8; 64] {
        let mut seed = [0u8; 64];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        seed
    }

    fn kat_encaps_m() -> [u8; 32] {
        let mut m = [0u8; 32];
        for (i, b) in m.iter_mut().enumerate() {
            *b = (0x80 + i) as u8;
        }
        m
    }

    #[test]
    fn fips203_deterministic_kat_pins_exact_bytes() {
        let seed = kat_keygen_seed();
        let (dk_seed, ek) = generate_keypair_deterministic(&seed).unwrap();

        // Length invariants (FIPS 203 Table 3, seed-form dk).
        assert_eq!(ek.len(), ML_KEM_768_PUBKEY_LEN, "ek len");
        assert_eq!(dk_seed.len(), ML_KEM_768_PRIVKEY_LEN, "dk seed len");

        // `to_seed()` must round-trip the input d||z exactly.
        assert_eq!(dk_seed, seed, "dk seed must equal input d||z");

        // Pinned key bytes.
        assert_eq!(sha256_hex(&ek), KAT_EK_SHA256, "ek bytes drifted");
        assert_eq!(
            sha256_hex(&dk_seed),
            KAT_DK_SEED_SHA256,
            "dk seed bytes drifted"
        );

        let m = kat_encaps_m();
        let (ct, ss_send) = encapsulate_deterministic(&ek, &m).unwrap();
        assert_eq!(ct.len(), ML_KEM_768_CIPHERTEXT_LEN, "ct len");
        assert_eq!(ss_send.len(), ML_KEM_768_SHARED_SECRET_LEN, "ss len");

        // Pinned ciphertext + shared secret.
        assert_eq!(sha256_hex(&ct), KAT_CT_SHA256, "ciphertext bytes drifted");
        assert_eq!(hex::encode(ss_send), KAT_SS_HEX, "shared secret drifted");

        // Decaps with the matching dk recovers the SAME shared secret.
        let ss_recv = decapsulate(&dk_seed, &ct).unwrap();
        assert_eq!(ss_send, ss_recv, "decaps ss != encaps ss");
        assert_eq!(hex::encode(ss_recv), KAT_SS_HEX, "decaps ss drifted");
    }

    #[test]
    fn deterministic_keygen_is_byte_stable_across_runs() {
        let seed = kat_keygen_seed();
        let (dk1, ek1) = generate_keypair_deterministic(&seed).unwrap();
        let (dk2, ek2) = generate_keypair_deterministic(&seed).unwrap();
        assert_eq!(ek1, ek2);
        assert_eq!(dk1, dk2);
    }

    #[test]
    fn deterministic_encaps_is_byte_stable_across_runs() {
        let (_, ek) = generate_keypair_deterministic(&kat_keygen_seed()).unwrap();
        let m = kat_encaps_m();
        let (ct1, ss1) = encapsulate_deterministic(&ek, &m).unwrap();
        let (ct2, ss2) = encapsulate_deterministic(&ek, &m).unwrap();
        assert_eq!(ct1, ct2);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn deterministic_keygen_then_random_encaps_round_trips() {
        // The deterministic dk interoperates with the production
        // (CSPRNG) encapsulate path.
        let (dk_seed, ek) = generate_keypair_deterministic(&kat_keygen_seed()).unwrap();
        let (ct, ss_send) = encapsulate(&ek).unwrap();
        let ss_recv = decapsulate(&dk_seed, &ct).unwrap();
        assert_eq!(ss_send, ss_recv);
    }

    #[test]
    fn deterministic_keygen_rejects_wrong_length_seed() {
        assert!(generate_keypair_deterministic(&[0u8; 32]).is_err());
        assert!(generate_keypair_deterministic(&[0u8; 65]).is_err());
    }

    #[test]
    fn deterministic_encaps_rejects_wrong_length_m() {
        let (_, ek) = generate_keypair_deterministic(&kat_keygen_seed()).unwrap();
        assert!(encapsulate_deterministic(&ek, &[0u8; 16]).is_err());
        assert!(encapsulate_deterministic(&ek, &[0u8; 33]).is_err());
    }

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
