//! X-Wing, the hybrid post-quantum KEM of draft-connolly-cfrg-xwing-kem-11
//! (CIRISVerify#324, CC 5.1 / 5.4.4 / 5.4.6).
//!
//! X-Wing combines ML-KEM-768 and X25519 with the draft's SHA3-256 combiner:
//!
//! ```text
//! ss = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ "\.//^\")      (§5.3, label 5c2e2f2f5e5c)
//! pk = pk_M ‖ pk_X   (1184 + 32 = 1216 bytes)                (§5.1)
//! ct = ct_M ‖ ct_X   (1088 + 32 = 1120 bytes)                (§5.4)
//! sk = the 32-byte seed, expanded by SHAKE256 to 96 bytes    (§5.2)
//! ```
//!
//! It is the KEM of the MLS Welcome wrap ([`crate::hpke`], KEM id `0x647a`)
//! and of the onion hop (CC 5.4.6, `outfox-xwing-v1`). The construction is
//! RustCrypto's `x-wing` crate (draft-06, whose output bytes CC compared with
//! -11 and found identical). This module locks it to the -11 Appendix C known
//! answers and to verify's own vectors (`tests/vectors/xwing/`): the draft
//! still calls its vectors provisional, and a later revision that changes any
//! byte is a different construction under a different identifier (CC 5.4.6).
//!
//! **Keys.** The private key is the 32-byte seed and nothing else (§5.2,
//! CC 5.4.6 (i)). A static key is generated from its seed by X-Wing's own
//! expansion, never by HPKE `DeriveKeyPair`, which applies a labelled SHAKE256
//! and would derive a different key from the same input (CC ruling on #324).
//!
//! **Public keys** are refused at the boundary: a wrong length, or an ML-KEM
//! half that fails the FIPS 203 §7.2 encapsulation-key check (type and modulus),
//! never becomes an [`XWingPublicKey`]. The two halves are exposed as the
//! the CC 3.3.6.2 bindings carry the whole 1216-byte key as one member (`transit_xwing_pubkey`, `onion_hop_xwing_pubkey`; Eric's ruling), in this same `pk_M ‖ pk_X` order
//!
//! **Randomness** is injected ([`XWingPublicKey::encapsulate_with_rng`]), so the
//! KEM works without `std`. With the `random` feature
//! [`XWingPublicKey::encapsulate`] draws through the health-latched RNG facade
//! instead. Decapsulation needs no randomness. It never fails on a well-formed
//! ciphertext: a wrong key or tampered ciphertext yields an unrelated secret
//! (implicit rejection), which the AEAD above it refuses.

#[allow(unused_imports)]
use crate::prelude::*;

use rand_core::CryptoRngCore;
use x_wing::{Decapsulate, KeyExport, TryKeyInit};
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// Length of an X-Wing public key, `pk_M ‖ pk_X` (`Npk`).
pub const XWING_PUBLIC_KEY_LEN: usize = 1216;
/// Length of the ML-KEM-768 half of a public key.
pub const XWING_ML_KEM_768_PUBLIC_KEY_LEN: usize = 1184;
/// Length of the X25519 half of a public key.
pub const XWING_X25519_PUBLIC_KEY_LEN: usize = 32;
/// Length of an X-Wing private key, the seed (`Nsk`).
pub const XWING_SEED_LEN: usize = 32;
/// Length of an X-Wing ciphertext, `ct_M ‖ ct_X` (`Nenc`).
pub const XWING_CIPHERTEXT_LEN: usize = 1120;
/// Length of the shared secret (`Nsecret`).
pub const XWING_SHARED_SECRET_LEN: usize = 32;
/// Bytes of randomness one encapsulation consumes (`eseed`).
pub const XWING_ENCAPSULATION_RANDOMNESS_LEN: usize = 64;

fn invalid(reason: impl Into<String>) -> CryptoError {
    CryptoError::invalid_public_key(reason)
}

/// An X-Wing private key: the 32-byte seed (§5.2). Zeroized on drop.
#[derive(Clone)]
pub struct XWingSecretKey {
    seed: Zeroizing<[u8; XWING_SEED_LEN]>,
}

impl core::fmt::Debug for XWingSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XWingSecretKey").finish_non_exhaustive()
    }
}

impl XWingSecretKey {
    /// The key whose seed is `seed`.
    #[must_use]
    pub fn from_seed(seed: [u8; XWING_SEED_LEN]) -> Self {
        Self {
            seed: Zeroizing::new(seed),
        }
    }

    /// A fresh key from `rng`.
    pub fn generate_with_rng(rng: &mut impl CryptoRngCore) -> Self {
        let mut seed = Zeroizing::new([0u8; XWING_SEED_LEN]);
        rng.fill_bytes(seed.as_mut());
        Self { seed }
    }

    /// A fresh key from the health-latched RNG facade.
    ///
    /// # Errors
    /// [`CryptoError::RngHealthCheckFailed`] if the RNG latch has failed.
    #[cfg(feature = "random")]
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = Zeroizing::new([0u8; XWING_SEED_LEN]);
        crate::random::fill(seed.as_mut())?;
        Ok(Self { seed })
    }

    /// The seed.
    #[must_use]
    pub fn seed(&self) -> &[u8; XWING_SEED_LEN] {
        &self.seed
    }

    fn inner(&self) -> x_wing::DecapsulationKey {
        x_wing::DecapsulationKey::from(*self.seed)
    }

    /// The matching public key (§5.2).
    #[must_use]
    pub fn public_key(&self) -> XWingPublicKey {
        use x_wing::Decapsulator;
        let ek = self.inner().encapsulation_key().clone();
        let mut bytes = [0u8; XWING_PUBLIC_KEY_LEN];
        bytes.copy_from_slice(&ek.to_bytes());
        XWingPublicKey { bytes, ek }
    }

    /// `Decapsulate(ct, sk)` (§5.5).
    ///
    /// # Errors
    /// [`CryptoError::InvalidCiphertext`] if `ciphertext` is not 1120 bytes.
    /// A well-formed ciphertext always decapsulates (implicit rejection).
    pub fn decapsulate(
        &self,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<[u8; XWING_SHARED_SECRET_LEN]>, CryptoError> {
        let ct = x_wing::Ciphertext::try_from(ciphertext).map_err(|_| {
            CryptoError::InvalidCiphertext {
                reason: format!(
                    "X-Wing ciphertext must be {XWING_CIPHERTEXT_LEN} bytes, got {}",
                    ciphertext.len()
                ),
            }
        })?;
        let ss = self.inner().decapsulate(&ct);
        let mut out = Zeroizing::new([0u8; XWING_SHARED_SECRET_LEN]);
        out.copy_from_slice(&ss);
        Ok(out)
    }
}

/// An X-Wing public key, `pk_M ‖ pk_X`, checked on construction.
#[derive(Clone, PartialEq, Eq)]
pub struct XWingPublicKey {
    bytes: [u8; XWING_PUBLIC_KEY_LEN],
    ek: x_wing::EncapsulationKey,
}

impl core::fmt::Debug for XWingPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XWingPublicKey")
            .field("x25519", &hex::encode(self.x25519()))
            .finish_non_exhaustive()
    }
}

impl XWingPublicKey {
    /// Parse the 1216-byte `pk_M ‖ pk_X`.
    ///
    /// # Errors
    /// [`CryptoError::InvalidPublicKey`] on a wrong length or an ML-KEM half
    /// that fails the FIPS 203 §7.2 encapsulation-key check.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != XWING_PUBLIC_KEY_LEN {
            return Err(invalid(format!(
                "X-Wing public key must be {XWING_PUBLIC_KEY_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let ek = x_wing::EncapsulationKey::new_from_slice(bytes).map_err(|_| {
            invalid("X-Wing ML-KEM-768 half fails the FIPS 203 §7.2 encapsulation-key check")
        })?;
        let mut arr = [0u8; XWING_PUBLIC_KEY_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr, ek })
    }

    /// Assemble from the two halves (ML-KEM-768 then X25519) of a 1216-byte binding member
    /// (CC 3.3.6.2): `ml_kem_768` (1184 bytes) and `x25519` (32 bytes).
    ///
    /// # Errors
    /// As [`Self::from_bytes`], naming the half whose length is wrong.
    pub fn from_halves(ml_kem_768: &[u8], x25519: &[u8]) -> Result<Self, CryptoError> {
        if ml_kem_768.len() != XWING_ML_KEM_768_PUBLIC_KEY_LEN {
            return Err(invalid(format!(
                "X-Wing ml_kem_768 half must be {XWING_ML_KEM_768_PUBLIC_KEY_LEN} bytes, got {}",
                ml_kem_768.len()
            )));
        }
        if x25519.len() != XWING_X25519_PUBLIC_KEY_LEN {
            return Err(invalid(format!(
                "X-Wing x25519 half must be {XWING_X25519_PUBLIC_KEY_LEN} bytes, got {}",
                x25519.len()
            )));
        }
        let mut arr = [0u8; XWING_PUBLIC_KEY_LEN];
        arr[..XWING_ML_KEM_768_PUBLIC_KEY_LEN].copy_from_slice(ml_kem_768);
        arr[XWING_ML_KEM_768_PUBLIC_KEY_LEN..].copy_from_slice(x25519);
        Self::from_bytes(&arr)
    }

    /// The 1216-byte encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; XWING_PUBLIC_KEY_LEN] {
        &self.bytes
    }

    /// The ML-KEM-768 half (`pk_M`, 1184 bytes).
    #[must_use]
    pub fn ml_kem_768(&self) -> &[u8] {
        &self.bytes[..XWING_ML_KEM_768_PUBLIC_KEY_LEN]
    }

    /// The X25519 half (`pk_X`, 32 bytes).
    #[must_use]
    pub fn x25519(&self) -> &[u8] {
        &self.bytes[XWING_ML_KEM_768_PUBLIC_KEY_LEN..]
    }

    /// `Encapsulate(pk)` (§5.4) with randomness from `rng`. Returns the
    /// 1120-byte ciphertext and the shared secret.
    pub fn encapsulate_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> (
        [u8; XWING_CIPHERTEXT_LEN],
        Zeroizing<[u8; XWING_SHARED_SECRET_LEN]>,
    ) {
        let mut eseed = Zeroizing::new([0u8; XWING_ENCAPSULATION_RANDOMNESS_LEN]);
        rng.fill_bytes(eseed.as_mut());
        self.encapsulate_derand(&eseed)
    }

    /// `Encapsulate(pk)` with randomness from the health-latched RNG facade.
    ///
    /// # Errors
    /// [`CryptoError::RngHealthCheckFailed`] if the RNG latch has failed.
    #[cfg(feature = "random")]
    #[allow(clippy::type_complexity)]
    pub fn encapsulate(
        &self,
    ) -> Result<
        (
            [u8; XWING_CIPHERTEXT_LEN],
            Zeroizing<[u8; XWING_SHARED_SECRET_LEN]>,
        ),
        CryptoError,
    > {
        let mut eseed = Zeroizing::new([0u8; XWING_ENCAPSULATION_RANDOMNESS_LEN]);
        crate::random::fill(eseed.as_mut())?;
        Ok(self.encapsulate_derand(&eseed))
    }

    /// `EncapsulateDerand(pk, eseed)`: the known-answer form. Crate-internal,
    /// so no caller can reuse randomness (CC ruling on #324: derand only for
    /// known answers).
    pub(crate) fn encapsulate_derand(
        &self,
        eseed: &[u8; XWING_ENCAPSULATION_RANDOMNESS_LEN],
    ) -> (
        [u8; XWING_CIPHERTEXT_LEN],
        Zeroizing<[u8; XWING_SHARED_SECRET_LEN]>,
    ) {
        let randomness = x_wing::kem::common::array::Array::from(*eseed);
        let (ct, ss) = self.ek.encapsulate_deterministic(&randomness);
        let mut ct_out = [0u8; XWING_CIPHERTEXT_LEN];
        ct_out.copy_from_slice(&ct);
        let mut ss_out = Zeroizing::new([0u8; XWING_SHARED_SECRET_LEN]);
        ss_out.copy_from_slice(&ss);
        (ct_out, ss_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// draft-connolly-cfrg-xwing-kem-11 Appendix C, all three vectors, copied
    /// from the draft text (byte-identical to the draft-06 vectors).
    const DRAFT_11_VECTORS: &str =
        include_str!("../tests/vectors/xwing/draft-connolly-cfrg-xwing-kem-11.json");

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn draft_11_appendix_c_known_answers() {
        let vectors: Vec<serde_json::Value> = serde_json::from_str(DRAFT_11_VECTORS).unwrap();
        assert_eq!(vectors.len(), 3);
        for v in &vectors {
            let seed: [u8; 32] = h(v["seed"].as_str().unwrap()).try_into().unwrap();
            assert_eq!(h(v["sk"].as_str().unwrap()), seed, "sk is the seed");
            let sk = XWingSecretKey::from_seed(seed);
            let pk = sk.public_key();
            assert_eq!(pk.as_bytes().to_vec(), h(v["pk"].as_str().unwrap()), "pk");
            let eseed: [u8; 64] = h(v["eseed"].as_str().unwrap()).try_into().unwrap();
            let (ct, ss) = pk.encapsulate_derand(&eseed);
            assert_eq!(ct.to_vec(), h(v["ct"].as_str().unwrap()), "ct");
            assert_eq!(ss.to_vec(), h(v["ss"].as_str().unwrap()), "ss");
            assert_eq!(sk.decapsulate(&ct).unwrap().to_vec(), ss.to_vec(), "decaps");
            // The halves reassemble to the same key.
            let again = XWingPublicKey::from_halves(pk.ml_kem_768(), pk.x25519()).unwrap();
            assert_eq!(again, pk);
            assert_eq!(XWingPublicKey::from_bytes(pk.as_bytes()).unwrap(), pk);
        }
    }

    #[test]
    fn wrong_lengths_are_refused() {
        let pk = XWingSecretKey::from_seed([7; 32]).public_key();
        assert!(XWingPublicKey::from_bytes(&pk.as_bytes()[..1215]).is_err());
        let mut long = pk.as_bytes().to_vec();
        long.push(0);
        assert!(XWingPublicKey::from_bytes(&long).is_err());
        assert!(XWingPublicKey::from_halves(&pk.ml_kem_768()[1..], pk.x25519()).is_err());
        assert!(XWingPublicKey::from_halves(pk.ml_kem_768(), &pk.x25519()[1..]).is_err());
        let sk = XWingSecretKey::from_seed([7; 32]);
        assert!(sk.decapsulate(&[0u8; 1119]).is_err());
        assert!(sk.decapsulate(&[0u8; 1121]).is_err());
    }

    /// FIPS 203 §7.2 modulus check: a coefficient ≥ q = 3329 in `pk_M`'s
    /// encoded `t_hat` is refused. The first 12-bit coefficient is bytes 0 and
    /// the low nibble of byte 1; 0xFFF = 4095 > 3328.
    #[test]
    fn ml_kem_modulus_check_is_enforced() {
        let pk = XWingSecretKey::from_seed([9; 32]).public_key();
        let mut bad = *pk.as_bytes();
        bad[0] = 0xFF;
        bad[1] |= 0x0F;
        assert!(XWingPublicKey::from_bytes(&bad).is_err());
        assert!(XWingPublicKey::from_halves(&bad[..1184], &bad[1184..]).is_err());
    }

    #[test]
    fn injected_rng_round_trips_and_wrong_key_diverges() {
        use rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([3; 32]);
        let sk = XWingSecretKey::generate_with_rng(&mut rng);
        let pk = sk.public_key();
        let (ct, ss) = pk.encapsulate_with_rng(&mut rng);
        assert_eq!(sk.decapsulate(&ct).unwrap().to_vec(), ss.to_vec());
        let other = XWingSecretKey::from_seed([4; 32]);
        assert_ne!(other.decapsulate(&ct).unwrap().to_vec(), ss.to_vec());
        let mut tampered = ct;
        tampered[1119] ^= 1;
        assert_ne!(sk.decapsulate(&tampered).unwrap().to_vec(), ss.to_vec());
    }
}
