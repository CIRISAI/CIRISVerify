//! Ed25519 signature operations.
//!
//! Used for steward signatures and software-only deployments.
//! Note: Most mobile hardware HSMs do NOT support Ed25519.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
#[cfg(not(feature = "random"))]
use rand_core::OsRng;

use crate::error::CryptoError;
use crate::hybrid::{ClassicalSigner, ClassicalVerifier};
use crate::types::ClassicalAlgorithm;

/// Ed25519 signer.
pub struct Ed25519Signer {
    signing_key: SigningKey,
}

impl Ed25519Signer {
    /// Create a new signer with a freshly generated random key.
    ///
    /// # Fail-secure (CIRISVerify#74)
    ///
    /// The 32-byte seed is drawn through [`crate::random::fill`], which
    /// reads the latched SP 800-90B startup RNG health verdict
    /// ([`crate::rng_health::is_rng_failed`]) before drawing. If the OS
    /// entropy source failed that check, the draw is refused and this
    /// returns `CryptoError::RngHealthCheckFailed` WITHOUT generating a
    /// key — so a broken-entropy environment cannot mint a predictable
    /// long-term identity key. (Previously this drew `OsRng` directly,
    /// bypassing the latch — the bug fixed here.)
    ///
    /// When the `random` feature is disabled the facade is not compiled;
    /// in that build the seed is drawn directly from `OsRng` (no latch
    /// exists to consult).
    ///
    /// # Errors
    ///
    /// `CryptoError::RngHealthCheckFailed` if the RNG health latch is
    /// `Failed` (fail-secure; no key generated). Other variants only on
    /// the rare platforms where the OS entropy source itself errors.
    pub fn random() -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        #[cfg(feature = "random")]
        {
            crate::random::fill(&mut seed)?;
        }
        #[cfg(not(feature = "random"))]
        {
            use rand_core::RngCore;
            OsRng
                .try_fill_bytes(&mut seed)
                .map_err(|e| CryptoError::invalid_private_key(format!("OsRng seed draw: {e}")))?;
        }
        Self::from_seed(&seed)
    }

    /// Create a signer from seed bytes (32 bytes).
    ///
    /// # Errors
    ///
    /// Returns error if the seed is not exactly 32 bytes.
    pub fn from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        if seed.len() != 32 {
            return Err(CryptoError::invalid_private_key(format!(
                "Ed25519 seed must be 32 bytes, got {}",
                seed.len()
            )));
        }

        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(seed);

        Ok(Self {
            signing_key: SigningKey::from_bytes(&seed_array),
        })
    }

    /// Get the verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl ClassicalSigner for Ed25519Signer {
    fn algorithm(&self) -> ClassicalAlgorithm {
        ClassicalAlgorithm::Ed25519
    }

    fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.signing_key.verifying_key().to_bytes().to_vec())
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signature = self.signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
}

/// Ed25519 verifier.
pub struct Ed25519Verifier;

impl Ed25519Verifier {
    /// Create a new verifier.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for Ed25519Verifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a 32-byte pubkey + 64-byte signature into dalek types (shared by the
/// permissive and strict verify paths).
fn parse_key_and_sig(
    public_key: &[u8],
    signature: &[u8],
) -> Result<(VerifyingKey, Signature), CryptoError> {
    if public_key.len() != 32 {
        return Err(CryptoError::invalid_public_key(format!(
            "Ed25519 public key must be 32 bytes, got {}",
            public_key.len()
        )));
    }
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(public_key);
    let vk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| CryptoError::invalid_public_key(e.to_string()))?;

    if signature.len() != 64 {
        return Err(CryptoError::invalid_signature(format!(
            "Ed25519 signature must be 64 bytes, got {}",
            signature.len()
        )));
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    Ok((vk, Signature::from_bytes(&sig_bytes)))
}

impl Ed25519Verifier {
    /// **Strict** RFC 8032 verification — identical to
    /// [`ClassicalVerifier::verify`], which has been strict since 17.0.0.
    ///
    /// Retained as a named entry point because CIRISPersist's trace-verify
    /// floor calls it explicitly (it was added in v10.4.0 so that path could
    /// stop reaching for `ed25519-dalek` directly). Keeping the name also lets
    /// a caller *state* that strictness is load-bearing at the call site
    /// rather than inheriting it.
    ///
    /// # Errors
    /// [`CryptoError`] if the public key or signature is malformed; `Ok(false)`
    /// if well-formed but not a valid (strict) signature.
    pub fn verify_strict(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let (vk, sig) = parse_key_and_sig(public_key, signature)?;
        Ok(vk.verify_strict(data, &sig).is_ok())
    }

    /// **Permissive** (cofactorless, ed25519-dalek `verify`) verification — the
    /// pre-17.0.0 behaviour of [`ClassicalVerifier::verify`], kept reachable
    /// only under a name that says what it is.
    ///
    /// # This accepts a universal forgery, and that is not hypothetical
    ///
    /// Permissive verification does not reject a small-order `A` or `R`. With
    /// `A` = the identity point, the cofactorless equation `[s]B = R + [k]A`
    /// collapses to `[s]B = R`, so the single 64-byte signature
    /// `(R = identity, s = 0)` verifies against **any message whatsoever** —
    /// with no private key in existence. A test in this module exhibits it.
    ///
    /// Callers therefore MUST NOT use this to decide anything. It exists so
    /// that a caller who must reproduce another implementation's acceptance
    /// set — e.g. to explain why a peer accepted a signature this crate
    /// refuses — can do so deliberately and say so in the code.
    ///
    /// Ed25519 verifiers genuinely disagree here: cofactored vs cofactorless
    /// verification and small-order key handling are per-implementation
    /// choices (Chalkias, Garillot & Nikolaenko, *Taming the Many EdDSAs*,
    /// SSR 2020; ZIP-215 exists to pin one). "RFC 8032 verify has no drift
    /// risk" is a comfortable assumption and a false one.
    ///
    /// # Errors
    /// [`CryptoError`] if the public key or signature is malformed; `Ok(false)`
    /// if well-formed but not a valid (permissive) signature.
    pub fn verify_permissive(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let (vk, sig) = parse_key_and_sig(public_key, signature)?;
        match vk.verify(data, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl ClassicalVerifier for Ed25519Verifier {
    /// Verify strictly (CIRISVerify#207 item 1).
    ///
    /// **This was permissive before 17.0.0**, and every authority gate in this
    /// workspace reaches Ed25519 through this trait method: the M-of-N
    /// threshold verifier and everything that inherits it, the provenance
    /// chain walk, the license JWT gate, binary self-verification, and
    /// `HybridVerifier`'s classical half (so doc_integrity, jcs,
    /// federation_envelope and the transparency STH too). `verify_strict`
    /// shipped in v10.4.0 for a *downstream's* trace floor and was called by
    /// nothing inside this workspace — the stricter primitive existed and was
    /// not invoked on the decisions that matter.
    ///
    /// Strictness is the default here rather than a flag at ~8 call sites
    /// because a flag is something a **new** call site forgets; see
    /// [`Self::verify_permissive`] for what the old default accepted.
    ///
    /// No honest signer is affected: an honest key is not small-order and an
    /// honest signature's `R` carries no torsion component, so nothing this
    /// workspace or its peers legitimately produce changes verdict.
    fn verify(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let (vk, sig) = parse_key_and_sig(public_key, signature)?;
        Ok(vk.verify_strict(data, &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Ed25519 identity point (`y = 1`, sign bit clear) — one of the
    /// eight small-order points.
    fn identity_point() -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = 1;
        a
    }

    /// `(R = identity, s = 0)`. Under cofactorless verification with
    /// `A` = identity the equation `[s]B = R + [k]A` becomes
    /// `identity = identity`, independent of the message.
    fn universal_forgery() -> [u8; 64] {
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&identity_point());
        sig
    }

    /// The reason strictness is the default, stated as an executable fact
    /// rather than a doc comment (CIRISVerify#207 item 1).
    #[test]
    fn permissive_accepts_a_universal_forgery_that_strict_refuses() {
        let v = Ed25519Verifier::new();
        let (pk, sig) = (identity_point(), universal_forgery());

        // ONE signature, no private key anywhere, two unrelated messages.
        for msg in [
            b"transfer 1 token".as_slice(),
            b"HALT THE ACCORD".as_slice(),
            b"".as_slice(),
        ] {
            assert!(
                v.verify_permissive(&pk, msg, &sig).unwrap(),
                "permissive must be SHOWN to accept the forgery, or this test \
                 asserts nothing about why the default changed"
            );
            assert!(
                !v.verify_strict(&pk, msg, &sig).unwrap(),
                "strict must refuse the forgery"
            );
        }
    }

    /// The default acceptance rule IS the strict one. Guards against a future
    /// edit quietly restoring the permissive default at the one place every
    /// authority gate in the workspace reaches Ed25519 through.
    #[test]
    fn default_verify_is_strict_not_permissive() {
        let v = Ed25519Verifier::new();
        assert!(
            !v.verify(&identity_point(), b"anything", &universal_forgery())
                .unwrap(),
            "ClassicalVerifier::verify must be strict"
        );
    }

    /// Strictness must not cost an honest signature: the default and both
    /// named entry points agree on every real signature.
    #[test]
    fn honest_signatures_verify_under_every_entry_point() {
        let signer = Ed25519Signer::random().unwrap();
        let pk = signer.public_key().unwrap();
        for data in [b"".as_slice(), b"x".as_slice(), &[0u8; 1024][..]] {
            let sig = signer.sign(data).unwrap();
            assert_eq!(
                v_all(&pk, data, &sig),
                (true, true, true),
                "data len {}",
                data.len()
            );
        }
    }

    fn v_all(pk: &[u8], data: &[u8], sig: &[u8]) -> (bool, bool, bool) {
        let v = Ed25519Verifier::new();
        (
            v.verify(pk, data, sig).unwrap(),
            v.verify_strict(pk, data, sig).unwrap(),
            v.verify_permissive(pk, data, sig).unwrap(),
        )
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let signer = Ed25519Signer::random().unwrap();
        let verifier = Ed25519Verifier::new();

        let data = b"test message";
        let signature = signer.sign(data).unwrap();
        let public_key = signer.public_key().unwrap();

        assert_eq!(signature.len(), 64);
        assert_eq!(public_key.len(), 32);

        let valid = verifier.verify(&public_key, data, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_ed25519_verify_strict_accepts_honest_signature() {
        // An honestly-produced signature verifies under both the permissive and
        // strict paths; a tampered one fails both. (Small/mixed-order forgeries
        // that distinguish the two can't be produced from a normal signer.)
        let signer = Ed25519Signer::random().unwrap();
        let verifier = Ed25519Verifier::new();
        let data = b"strict path message";
        let sig = signer.sign(data).unwrap();
        let pk = signer.public_key().unwrap();

        assert!(verifier.verify_strict(&pk, data, &sig).unwrap());
        assert!(verifier.verify(&pk, data, &sig).unwrap());

        let mut bad = sig.clone();
        bad[0] ^= 0x01;
        assert!(!verifier.verify_strict(&pk, data, &bad).unwrap());
        // Malformed inputs are Err on both paths.
        assert!(verifier.verify_strict(&pk[..31], data, &sig).is_err());
    }

    #[test]
    fn test_ed25519_from_seed() {
        let seed = [42u8; 32];
        let signer1 = Ed25519Signer::from_seed(&seed).unwrap();
        let signer2 = Ed25519Signer::from_seed(&seed).unwrap();

        // Same seed should produce same key
        assert_eq!(signer1.public_key().unwrap(), signer2.public_key().unwrap());
    }

    /// CIRISVerify#74 fail-secure proof: when the SP 800-90B RNG health
    /// latch is forced `Failed`, keygen refuses to draw and returns
    /// `RngHealthCheckFailed` rather than minting a (potentially
    /// predictable) identity key.
    #[cfg(feature = "random")]
    #[test]
    fn random_fails_secure_when_rng_marked_failed() {
        crate::rng_health::test_support::with_forced_failed(|| {
            // Signer holds key material and is intentionally not `Debug`,
            // so assert on the variant directly rather than `unwrap_err`.
            assert!(
                matches!(
                    Ed25519Signer::random(),
                    Err(CryptoError::RngHealthCheckFailed(_))
                ),
                "keygen must fail-secure on failed RNG latch"
            );
        });
        // Latch restored: keygen works again.
        assert!(Ed25519Signer::random().is_ok());
    }
}
