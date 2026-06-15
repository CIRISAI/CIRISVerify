//! X25519 (Curve25519) ECDH primitive (CIRISVerify#44, v4.4.0+).
//!
//! Bytes-only public surface — consumers handle `[u8; 32]` keys
//! without depending on the `x25519-dalek` types. That keeps the
//! AV-40 "ciris-crypto is THE federation crypto authority"
//! invariant intact and lets downstream consumers (CIRISNodeCore's
//! key-grant flow, future ML-KEM hybrid migration) ratchet the
//! backend without changing the call sites.
//!
//! ## What this module ships
//!
//! - [`generate_ephemeral_keypair`] — fresh 32-byte
//!   (secret, public) pair for the sender side of a wrap.
//! - [`public_from_secret`] — derive a 32-byte public key from a
//!   32-byte secret (e.g. for the recipient side to reconstruct
//!   its own public for HKDF salt binding).
//! - [`dh`] — Diffie-Hellman shared secret: a 32-byte value
//!   suitable as HKDF input keying material.
//!
//! ## What this module does NOT ship
//!
//! - Long-term identity key storage (use `ciris-keyring` for
//!   that).
//! - X-coordinate validation gymnastics — `x25519-dalek` follows
//!   RFC 7748 + the small-subgroup-safe practice of clamping the
//!   secret before scalar multiplication and accepting all-zero
//!   public-key contributions (which the consumer's AEAD step
//!   detects as a tag-mismatch failure on unwrap).

use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::error::CryptoError;

/// X25519 key length in bytes (RFC 7748).
pub const X25519_KEY_LEN: usize = 32;

/// Fail-secure gate (CIRISVerify#74): refuse to draw fresh X25519 key
/// material when the SP 800-90B startup RNG health latch is `Failed`.
///
/// `x25519-dalek` draws its secret scalar from `OsRng` internally, so we
/// cannot route the draw through `random::fill`; instead we consult the
/// latch BEFORE letting dalek draw. When the `random` feature is not
/// compiled (X25519 can be enabled standalone) there is no latch and the
/// gate is a no-op.
#[inline]
fn rng_health_gate() -> Result<(), CryptoError> {
    #[cfg(feature = "random")]
    {
        if crate::rng_health::is_rng_failed() {
            return Err(CryptoError::RngHealthCheckFailed(
                "OS RNG failed the SP 800-90B startup health-check; refusing X25519 keygen"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

/// Generate an ephemeral (secret, public) keypair from a CSPRNG.
///
/// The secret is `StaticSecret`-shaped (clamped per RFC 7748) so the
/// caller can persist it if needed. The public is the corresponding
/// montgomery-u-coordinate.
///
/// # Errors
///
/// `CryptoError::RngHealthCheckFailed` if the SP 800-90B startup RNG
/// health latch is `Failed` (fail-secure; no key drawn — CIRISVerify#74).
/// `CryptoError::Other` if the OS CSPRNG is unavailable (extremely
/// rare on a healthy system; mirrors what `random::fill` reports).
pub fn generate_ephemeral_keypair() -> Result<([u8; 32], [u8; 32]), CryptoError> {
    rng_health_gate()?;
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    Ok((secret.to_bytes(), public.to_bytes()))
}

/// Derive the X25519 public key from a 32-byte secret.
///
/// Used by the unwrap path to reconstruct the recipient's own public
/// key for HKDF salt binding (the salt is
/// `ephemeral_pub || recipient_pub`; both sides need it).
pub fn public_from_secret(secret_bytes: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*secret_bytes);
    PublicKey::from(&secret).to_bytes()
}

/// Diffie-Hellman shared secret between a local secret and a peer
/// public key. Returns the 32-byte shared secret.
///
/// **Suitable only as HKDF input keying material** — never as a
/// symmetric key directly. The shared secret has uniform-random
/// distribution under the standard X25519 assumption but is NOT
/// uniformly distributed as bytes; always run it through a KDF.
///
/// # Errors
///
/// This function is structurally infallible (RFC 7748 scalarmult
/// never errors on well-formed inputs), but returns `Result` for
/// API parity with the rest of ciris-crypto's signer surfaces.
pub fn dh(secret_bytes: &[u8; 32], peer_public_bytes: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let secret = StaticSecret::from(*secret_bytes);
    let peer = PublicKey::from(*peer_public_bytes);
    let shared = secret.diffie_hellman(&peer);
    Ok(shared.to_bytes())
}

/// One-shot ephemeral DH suitable for HPKE-base-mode-style wraps:
/// generates a fresh keypair, runs DH against `recipient_public`,
/// and returns `(ephemeral_public, shared_secret)`. The ephemeral
/// secret is discarded after the DH step — the caller never sees it.
///
/// # Errors
///
/// `CryptoError::RngHealthCheckFailed` if the SP 800-90B startup RNG
/// health latch is `Failed` (fail-secure; no ephemeral drawn —
/// CIRISVerify#74). Otherwise propagates as [`generate_ephemeral_keypair`].
pub fn ephemeral_dh(
    recipient_public_bytes: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    rng_health_gate()?;
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&secret).to_bytes();
    let recipient = PublicKey::from(*recipient_public_bytes);
    let shared = secret.diffie_hellman(&recipient).to_bytes();
    Ok((ephemeral_public, shared))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_round_trip_via_public_from_secret() {
        let (secret, public) = generate_ephemeral_keypair().unwrap();
        // Reconstructing the public from the secret yields the same
        // bytes — RFC 7748 + the dalek implementation are deterministic.
        let reconstructed = public_from_secret(&secret);
        assert_eq!(public, reconstructed);
    }

    #[test]
    fn dh_is_symmetric() {
        // Alice's keypair.
        let (alice_secret, alice_public) = generate_ephemeral_keypair().unwrap();
        // Bob's keypair.
        let (bob_secret, bob_public) = generate_ephemeral_keypair().unwrap();
        // ECDH: alice computes shared via her secret and bob's public;
        // bob computes shared via his secret and alice's public. They
        // must match.
        let shared_a = dh(&alice_secret, &bob_public).unwrap();
        let shared_b = dh(&bob_secret, &alice_public).unwrap();
        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 32);
    }

    #[test]
    fn ephemeral_dh_produces_distinct_keypairs_per_call() {
        // Multiple ephemeral_dh calls against the same recipient
        // produce distinct ephemeral publics + shared secrets.
        let (_, recipient_pub) = generate_ephemeral_keypair().unwrap();
        let (eph_pub_a, shared_a) = ephemeral_dh(&recipient_pub).unwrap();
        let (eph_pub_b, shared_b) = ephemeral_dh(&recipient_pub).unwrap();
        assert_ne!(eph_pub_a, eph_pub_b, "ephemeral pubs must differ");
        assert_ne!(shared_a, shared_b, "shared secrets must differ");
    }

    #[test]
    fn different_recipients_produce_different_shared_secrets() {
        let (alice_secret, _) = generate_ephemeral_keypair().unwrap();
        let (_, bob_public) = generate_ephemeral_keypair().unwrap();
        let (_, charlie_public) = generate_ephemeral_keypair().unwrap();
        let shared_to_bob = dh(&alice_secret, &bob_public).unwrap();
        let shared_to_charlie = dh(&alice_secret, &charlie_public).unwrap();
        assert_ne!(shared_to_bob, shared_to_charlie);
    }

    /// RFC 7748 §6.1 test vector — well-known fixed input/output.
    /// Locks the X25519 implementation against any backend drift.
    #[test]
    fn rfc_7748_section_6_1_test_vector() {
        // Alice's secret + Bob's public from RFC 7748 §6.1.
        let alice_secret: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_public: [u8; 32] = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];
        let expected_shared: [u8; 32] = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];
        let computed = dh(&alice_secret, &bob_public).unwrap();
        assert_eq!(computed, expected_shared, "RFC 7748 §6.1 vector must match");
    }

    /// CIRISVerify#74 fail-secure proof: with the RNG health latch forced
    /// `Failed`, both fresh-keypair draws refuse rather than producing
    /// ephemeral key material from the suspect entropy source.
    #[cfg(feature = "random")]
    #[test]
    fn keygen_fails_secure_when_rng_marked_failed() {
        let (_, recipient_pub) = generate_ephemeral_keypair().unwrap();
        crate::rng_health::test_support::with_forced_failed(|| {
            assert!(matches!(
                generate_ephemeral_keypair().unwrap_err(),
                CryptoError::RngHealthCheckFailed(_)
            ));
            assert!(matches!(
                ephemeral_dh(&recipient_pub).unwrap_err(),
                CryptoError::RngHealthCheckFailed(_)
            ));
        });
        assert!(generate_ephemeral_keypair().is_ok());
    }
}
