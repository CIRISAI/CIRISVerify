//! Deterministic **self content-encryption** keypair derivation (CIRISVerify#151).
//!
//! Derives the two content-encryption keypairs — X25519 (classical ECDH) and
//! ML-KEM-768 (FIPS 203 PQC KEM) — **deterministically from the Ed25519 base
//! seed**, mirroring the wallet derivation in [`crate::secp256k1::derive_wallet_keypair`].
//!
//! ## Why derive (not generate)
//!
//! For the **self / single-principal** case, deriving the encryption identity
//! from the one canonical Ed25519 seed means it:
//!
//! - **travels for free** with the FedID backup/restore — every occurrence
//!   (Mac Secure Enclave / USB-restore / laptop TPM) re-derives the *identical*
//!   keypair, so there is no separate enc-key custody and no per-occurrence
//!   re-key on restore;
//! - is **mathematically bound** to the single identity instead of being an
//!   independent artifact that can drift.
//!
//! **Scope:** this shared-across-occurrences model is for **self** only.
//! Community DEKs keep independent keys + epoch rotation for forward secrecy on
//! member removal — do **not** derive there.
//!
//! ## Construction
//!
//! `HKDF-SHA256(salt = SELF_ENC_HKDF_SALT, ikm = ed25519_seed)` expanded under a
//! **distinct `info` per scheme**, never the Ed25519→X25519 birational map (keeps
//! clean scheme separation and avoids any cross-protocol key-reuse concern; the
//! ML-DSA→ML-KEM direction has no conversion map anyway).
//!
//! - X25519: expand 32 bytes → the StaticSecret scalar bytes; public via
//!   [`crate::x25519::public_from_secret`].
//! - ML-KEM-768: expand 64 bytes (`d || z`, FIPS 203 §7) →
//!   [`crate::ml_kem::generate_keypair_deterministic`].
//!
//! Only the **public** halves cross the wire (x25519 32 B, ML-KEM-768 1184 B) —
//! exactly what `federation_identity_occurrences.pubkey_x25519_base64 /
//! pubkey_ml_kem_768_base64` expect (CIRISPersist V069). The private halves
//! never leave the enclave.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CryptoError;
use crate::ml_kem::{self, ML_KEM_768_PRIVKEY_LEN};
use crate::x25519;

/// HKDF salt shared by the whole self-enc family. Distinct from the wallet's
/// `CIRIS-wallet-v1` salt, so a self-enc key can never collide with a wallet key
/// even before the per-scheme `info` separation.
const SELF_ENC_HKDF_SALT: &[u8] = b"CIRIS-self-enc-v1";

/// Per-scheme HKDF `info` — X25519 content-encryption keypair.
const X25519_HKDF_INFO: &[u8] = b"ciris/self-enc/x25519/v1";

/// Per-scheme HKDF `info` — ML-KEM-768 content-encryption keypair.
const ML_KEM_768_HKDF_INFO: &[u8] = b"ciris/self-enc/ml-kem-768/v1";

/// Length of the derived X25519 secret scalar bytes (pre-clamp StaticSecret input).
pub const SELF_ENC_X25519_SECRET_LEN: usize = 32;

/// Derive the **self X25519 content-encryption keypair** from the Ed25519 base seed.
///
/// Returns `(secret_bytes, public_bytes)`, each 32 bytes. `secret_bytes` is the
/// StaticSecret scalar input (x25519-dalek clamps on use); `public_bytes` is the
/// wire-shared half. Re-deriving the public from `secret_bytes` via
/// [`crate::x25519::public_from_secret`] reproduces `public_bytes` exactly.
#[must_use]
pub fn derive_self_enc_x25519(ed25519_seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hkdf = Hkdf::<Sha256>::new(Some(SELF_ENC_HKDF_SALT), ed25519_seed);
    let mut secret = [0u8; SELF_ENC_X25519_SECRET_LEN];
    hkdf.expand(X25519_HKDF_INFO, &mut secret)
        .expect("HKDF-SHA256 expand of 32 bytes never fails");

    let public = x25519::public_from_secret(&secret);
    // Return the secret to the caller (enclave-held); the local copy is zeroed.
    let out_secret = secret;
    secret.iter_mut().for_each(|b| *b = 0);
    (out_secret, public)
}

/// Derive the **self ML-KEM-768 content-encryption keypair** from the Ed25519 base seed.
///
/// Returns `(dk_seed, ek_public)` — the 64-byte `d || z` decapsulation-key seed
/// (FIPS 203 §7 seed form) and the 1184-byte encapsulation (public) key. The seed
/// form is the wire-canonical private encoding used elsewhere in `ciris-crypto`.
///
/// # Errors
///
/// Propagates [`CryptoError`] only on the structurally-unreachable ML-KEM keygen
/// failure paths (wrong seed length / array conversion) — the 64-byte HKDF output
/// always satisfies them.
pub fn derive_self_enc_mlkem768(
    ed25519_seed: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(SELF_ENC_HKDF_SALT), ed25519_seed);
    let mut dz_seed = [0u8; ML_KEM_768_PRIVKEY_LEN]; // d || z, 64 bytes
    hkdf.expand(ML_KEM_768_HKDF_INFO, &mut dz_seed)
        .expect("HKDF-SHA256 expand of 64 bytes never fails");

    let result = ml_kem::generate_keypair_deterministic(&dz_seed);
    dz_seed.iter_mut().for_each(|b| *b = 0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_kem::{ML_KEM_768_PRIVKEY_LEN, ML_KEM_768_PUBKEY_LEN};
    use sha2::Digest;

    const SEED_A: [u8; 32] = [0x42; 32];
    const SEED_B: [u8; 32] = [0x11; 32];

    #[test]
    fn x25519_is_deterministic_and_correctly_shaped() {
        let (s1, p1) = derive_self_enc_x25519(&SEED_A);
        let (s2, p2) = derive_self_enc_x25519(&SEED_A);
        assert_eq!(s1, s2, "same seed → same secret");
        assert_eq!(p1, p2, "same seed → same public");
        assert_eq!(s1.len(), 32);
        assert_eq!(p1.len(), 32);
        // Public re-derives from the secret.
        assert_eq!(x25519::public_from_secret(&s1), p1);
    }

    #[test]
    fn mlkem_is_deterministic_and_correctly_shaped() {
        let (dk1, ek1) = derive_self_enc_mlkem768(&SEED_A).unwrap();
        let (dk2, ek2) = derive_self_enc_mlkem768(&SEED_A).unwrap();
        assert_eq!(dk1, dk2, "same seed → same dk seed");
        assert_eq!(ek1, ek2, "same seed → same ek public");
        assert_eq!(dk1.len(), ML_KEM_768_PRIVKEY_LEN, "dk seed is 64 B (d||z)");
        assert_eq!(ek1.len(), ML_KEM_768_PUBKEY_LEN, "ek public is 1184 B");
    }

    #[test]
    fn distinct_seeds_yield_distinct_keys() {
        let (sa, pa) = derive_self_enc_x25519(&SEED_A);
        let (sb, pb) = derive_self_enc_x25519(&SEED_B);
        assert_ne!(sa, sb);
        assert_ne!(pa, pb);
        let (dka, eka) = derive_self_enc_mlkem768(&SEED_A).unwrap();
        let (dkb, ekb) = derive_self_enc_mlkem768(&SEED_B).unwrap();
        assert_ne!(dka, dkb);
        assert_ne!(eka, ekb);
    }

    #[test]
    fn schemes_are_domain_separated() {
        // The X25519 secret must not be a prefix of the ML-KEM d||z seed
        // (distinct HKDF `info` guarantees independence).
        let (x_secret, _) = derive_self_enc_x25519(&SEED_A);
        let (dk_seed, _) = derive_self_enc_mlkem768(&SEED_A).unwrap();
        assert_ne!(
            &dk_seed[..32],
            &x_secret[..],
            "schemes must not share key material"
        );
    }

    #[cfg(feature = "secp256k1")]
    #[test]
    fn separated_from_wallet_derivation() {
        // Distinct salt + info from the secp256k1 wallet path: the X25519 secret
        // must not equal the wallet's HKDF-derived secp256k1 seed for the same
        // base seed. (Different scheme, but the IKM is identical — prove the KDF
        // domain separation holds.)
        let (x_secret, _) = derive_self_enc_x25519(&SEED_A);
        let (wallet_sk, _) = crate::secp256k1::derive_wallet_keypair(&SEED_A);
        assert_ne!(x_secret.as_slice(), wallet_sk.to_bytes().as_slice());
    }

    /// Cross-impl golden: the KMP client + server mint path MUST reproduce these
    /// byte-for-byte for `seed = [0x42; 32]`. Pinned as a SHA-256 over the two
    /// public halves (x25519 ‖ ml-kem ek) so a derivation drift fails loudly.
    #[test]
    fn pinned_golden_vector_seed_0x42() {
        let (_, x_pub) = derive_self_enc_x25519(&SEED_A);
        let (_, ek_pub) = derive_self_enc_mlkem768(&SEED_A).unwrap();
        let mut h = Sha256::new();
        h.update(x_pub);
        h.update(&ek_pub);
        let digest = hex::encode(h.finalize());
        assert_eq!(
            digest, GOLDEN_PUBKEYS_SHA256_SEED_0X42,
            "self-enc derivation drifted from the pinned cross-impl golden"
        );
    }

    const GOLDEN_PUBKEYS_SHA256_SEED_0X42: &str =
        "93a8018292b9b71cdda0fb93803567007aa316000245fbd0fb64dba053526789";
}
