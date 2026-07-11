//! Self content-encryption as a **custody capability** (CIRISVerify#183).
//!
//! A hybrid identity must be able to (a) hand out its content-encryption
//! **pubkeys** and (b) perform the KEX **respond** — both from inside custody,
//! by alias, with **no private key material crossing any API boundary in
//! either direction**. The raw-bytes surface (`ciris_crypto::self_enc` /
//! `ciris_verify_self_enc_derive`) is unusable on a sealed identity (there is
//! no plaintext seed to hand it) and defeats sealing on a software one.
//!
//! [`SelfEncKeys`](crate::self_enc_keys::SelfEncKeys) opens over the **same sealed Ed25519 seed the federation
//! signer uses** ([`crate::sealed_ed25519::SealedEd25519Signer`], the shared
//! `ed25519.seed` blob under the same alias/`seed_dir`) and performs the
//! content-enc ops with the exact retrieve → use → scrub motion the sealed
//! signers already use: the durable seed stays sealed at rest, is opened
//! in-process per op, HKDF-derives the enc keypairs deterministically
//! (`ciris_crypto::self_enc` — same seed ⇒ same enc keypair on every open and
//! every restore, preserving the #151 restore/portability property and
//! self-DEK coherence), performs the op, and scrubs. Nothing new is stored;
//! nothing private is exported.
//!
//! Fail-loud [`KeyringError::KeyNotFound`] on a missing seed (#134 discipline —
//! never mint here).

use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine};

use crate::error::KeyringError;
use crate::storage::{create_platform_storage, SecureBlobStorage};

/// SecureBlobStorage key the sealed Ed25519 seed lives under — the SAME key
/// [`crate::sealed_ed25519::SealedEd25519Signer`] uses, so the content-enc
/// capability opens over the identity's existing federation seed (no new
/// stored material, no second seed to keep coherent).
const SEED_KEY_ID: &str = "ed25519.seed";
/// Ed25519 seed length.
const SEED_LEN: usize = 32;

/// The PUBLIC content-encryption halves, base64 — shaped to drop straight into
/// an occurrence's `encryption_pubkeys` (persist field names).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionPubkeysOut {
    /// X25519 public key (32 raw bytes), base64.
    pub x25519_base64: String,
    /// ML-KEM-768 encapsulation (public) key (1184 raw bytes), base64.
    pub ml_kem_768_base64: String,
}

/// Content-encryption custody handle over a sealed Ed25519 identity seed.
///
/// Holds only the storage handle — never a derived secret. Every op re-opens
/// the sealed seed, derives in-process, and scrubs before returning.
pub struct SelfEncKeys {
    storage: Box<dyn SecureBlobStorage>,
    alias: String,
    seed_dir: PathBuf,
}

impl std::fmt::Debug for SelfEncKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material — only the (public) resolution identity.
        f.debug_struct("SelfEncKeys")
            .field("alias", &self.alias)
            .field("seed_dir", &self.seed_dir)
            .finish_non_exhaustive()
    }
}

impl SelfEncKeys {
    /// Open the content-enc capability over the sealed Ed25519 seed at
    /// `seed_dir` under `alias` (the SAME resolution as
    /// [`crate::sealed_ed25519::SealedEd25519Signer::open`]).
    ///
    /// Fails [`KeyringError::KeyNotFound`] if no sealed seed is present —
    /// re-opening NEVER fabricates a seed (#134).
    pub fn open(
        alias: impl Into<String>,
        seed_dir: impl Into<PathBuf>,
    ) -> Result<Self, KeyringError> {
        let alias = alias.into();
        let seed_dir = seed_dir.into();
        let storage = create_platform_storage(&alias, &seed_dir)?;
        // Probe now so a missing seed fails at `open`, not on first use.
        // `KeyNotFound` propagates (never mint here).
        let mut probe = storage.load(SEED_KEY_ID)?;
        probe.iter_mut().for_each(|b| *b = 0);
        Ok(Self {
            storage,
            alias,
            seed_dir,
        })
    }

    /// The alias this capability is bound to.
    #[must_use]
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// The `seed_dir` this capability resolves against.
    #[must_use]
    pub fn seed_dir(&self) -> &PathBuf {
        &self.seed_dir
    }

    /// Retrieve the sealed seed, hand it to `f`, and scrub every in-process
    /// copy afterward (the sealed durable copy stays in `storage`). Mirrors
    /// the sealed signers' per-op retrieve → use → scrub posture.
    fn with_seed<T>(
        &self,
        f: impl FnOnce(&[u8; SEED_LEN]) -> Result<T, KeyringError>,
    ) -> Result<T, KeyringError> {
        let mut raw = self.storage.load(SEED_KEY_ID)?;
        if raw.len() != SEED_LEN {
            raw.iter_mut().for_each(|b| *b = 0);
            return Err(KeyringError::InvalidKey {
                reason: format!(
                    "sealed Ed25519 seed is {} bytes, expected {SEED_LEN}",
                    raw.len()
                ),
            });
        }
        let mut seed = [0u8; SEED_LEN];
        seed.copy_from_slice(&raw);
        raw.iter_mut().for_each(|b| *b = 0);

        let out = f(&seed);

        seed.iter_mut().for_each(|b| *b = 0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        out
    }

    /// Derive + return the PUBLIC content-enc halves (X25519 32 B + ML-KEM-768
    /// ek 1184 B, base64). Secrets are derived in-process and scrubbed before
    /// return — no private byte leaves.
    pub fn enc_pubkeys(&self) -> Result<EncryptionPubkeysOut, KeyringError> {
        self.with_seed(|seed| {
            let (mut x_secret, x_public) = ciris_crypto::self_enc::derive_self_enc_x25519(seed);
            // We only need the public half here — scrub the secret immediately.
            x_secret.iter_mut().for_each(|b| *b = 0);
            let (mut dk_seed, ek) = ciris_crypto::self_enc::derive_self_enc_mlkem768(seed)
                .map_err(|e| KeyringError::InvalidKey {
                    reason: format!("ML-KEM-768 derive: {e}"),
                })?;
            dk_seed.iter_mut().for_each(|b| *b = 0);
            Ok(EncryptionPubkeysOut {
                x25519_base64: STANDARD.encode(x_public),
                ml_kem_768_base64: STANDARD.encode(ek),
            })
        })
    }

    /// Perform the KEX **respond** INSIDE custody: derive the private halves
    /// in-process from the sealed seed, run the algorithm-dispatched respond
    /// ([`ciris_crypto::hybrid_kex`]), scrub the privs, and return ONLY the
    /// 32-byte session key. `handshake_json` is the wire handshake message the
    /// initiator sent (its `algorithm` field selects hybrid vs classical, same
    /// negotiation rule as the responder crypto enforces).
    pub fn kex_respond(&self, handshake_json: &[u8]) -> Result<[u8; 32], KeyringError> {
        use ciris_crypto::hybrid_kex::{
            respond_classical, respond_hybrid_with_public, ClassicalHandshakeMsg,
            HybridHandshakeMsg, KEX_ALGORITHM_CLASSICAL_V1, KEX_ALGORITHM_HYBRID_V1,
        };

        // Peek the algorithm to dispatch without committing to a message shape.
        let peek: serde_json::Value =
            serde_json::from_slice(handshake_json).map_err(|e| KeyringError::InvalidKey {
                reason: format!("handshake JSON: {e}"),
            })?;
        let algorithm = peek
            .get("algorithm")
            .and_then(|a| a.as_str())
            .ok_or_else(|| KeyringError::InvalidKey {
                reason: "handshake missing `algorithm`".to_string(),
            })?
            .to_string();

        self.with_seed(|seed| {
            let (mut x_secret, _x_public) = ciris_crypto::self_enc::derive_self_enc_x25519(seed);

            let result =
                if algorithm == KEX_ALGORITHM_HYBRID_V1 {
                    let msg: HybridHandshakeMsg =
                        serde_json::from_slice(handshake_json).map_err(|e| {
                            KeyringError::InvalidKey {
                                reason: format!("hybrid handshake: {e}"),
                            }
                        })?;
                    let (mut dk_seed, ek) = ciris_crypto::self_enc::derive_self_enc_mlkem768(seed)
                        .map_err(|e| KeyringError::InvalidKey {
                            reason: format!("ML-KEM-768 derive: {e}"),
                        })?;
                    let r = respond_hybrid_with_public(&x_secret, &dk_seed, &ek, &msg);
                    dk_seed.iter_mut().for_each(|b| *b = 0);
                    r
                } else if algorithm == KEX_ALGORITHM_CLASSICAL_V1 {
                    let msg: ClassicalHandshakeMsg = serde_json::from_slice(handshake_json)
                        .map_err(|e| KeyringError::InvalidKey {
                            reason: format!("classical handshake: {e}"),
                        })?;
                    respond_classical(&x_secret, &msg)
                } else {
                    x_secret.iter_mut().for_each(|b| *b = 0);
                    return Err(KeyringError::InvalidKey {
                        reason: format!("unsupported KEX algorithm `{algorithm}`"),
                    });
                };

            x_secret.iter_mut().for_each(|b| *b = 0);
            result.map_err(|e| KeyringError::InvalidKey {
                reason: format!("KEX respond: {e}"),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// Seal a known Ed25519 seed under `alias` so `SelfEncKeys::open` has a
    /// seed to derive from (mirrors a provisioned federation identity).
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    fn seal_seed(alias: &str, dir: &std::path::Path, seed: &[u8; 32]) {
        crate::sealed_ed25519::SealedEd25519Signer::open_or_create(
            alias,
            dir.to_path_buf(),
            Some(seed),
        )
        .unwrap();
    }

    #[test]
    fn open_fails_loud_when_no_seed_is_sealed() {
        let dir = seed_dir();
        let err = SelfEncKeys::open("absent", dir.path().to_path_buf()).unwrap_err();
        assert!(
            matches!(err, KeyringError::KeyNotFound { .. }),
            "missing seed must be KeyNotFound, got {err:?}"
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[test]
    fn enc_pubkeys_match_the_raw_self_enc_derivation() {
        let dir = seed_dir();
        let seed = [0x42u8; 32];
        seal_seed("id", dir.path(), &seed);

        let keys = SelfEncKeys::open("id", dir.path().to_path_buf()).unwrap();
        let out = keys.enc_pubkeys().unwrap();

        let (_s, x_pub) = ciris_crypto::self_enc::derive_self_enc_x25519(&seed);
        let (_d, ek) = ciris_crypto::self_enc::derive_self_enc_mlkem768(&seed).unwrap();
        assert_eq!(out.x25519_base64, STANDARD.encode(x_pub), "x25519 pub");
        assert_eq!(out.ml_kem_768_base64, STANDARD.encode(ek), "ml-kem ek");
        assert_eq!(STANDARD.decode(&out.x25519_base64).unwrap().len(), 32);
        assert_eq!(STANDARD.decode(&out.ml_kem_768_base64).unwrap().len(), 1184);
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[test]
    fn enc_pubkeys_are_restore_stable() {
        // Re-sealing the same seed under a fresh dir yields identical pubkeys
        // (determinism / restore-stability, the #151 property).
        let (d1, d2) = (seed_dir(), seed_dir());
        let seed = [0x11u8; 32];
        seal_seed("a", d1.path(), &seed);
        seal_seed("a", d2.path(), &seed);
        let p1 = SelfEncKeys::open("a", d1.path().to_path_buf())
            .unwrap()
            .enc_pubkeys()
            .unwrap();
        let p2 = SelfEncKeys::open("a", d2.path().to_path_buf())
            .unwrap()
            .enc_pubkeys()
            .unwrap();
        assert_eq!(p1, p2);
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[test]
    fn hybrid_roundtrip_initiate_outside_respond_in_custody() {
        use ciris_crypto::hybrid_kex::initiate_hybrid;

        let dir = seed_dir();
        let seed = [0x7u8; 32];
        seal_seed("node", dir.path(), &seed);
        let keys = SelfEncKeys::open("node", dir.path().to_path_buf()).unwrap();

        // Peer initiates against ONLY the public halves this capability exposes.
        let pubs = keys.enc_pubkeys().unwrap();
        let x_pub: [u8; 32] = STANDARD
            .decode(&pubs.x25519_base64)
            .unwrap()
            .try_into()
            .unwrap();
        let ek = STANDARD.decode(&pubs.ml_kem_768_base64).unwrap();
        let (msg, initiator_key) = initiate_hybrid(&x_pub, &ek).unwrap();

        // Responder derives privs inside custody and returns only the session key.
        let handshake = serde_json::to_vec(&msg).unwrap();
        let responder_key = keys.kex_respond(&handshake).unwrap();

        assert_eq!(
            initiator_key, responder_key,
            "both sides must agree on the session key"
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[test]
    fn classical_roundtrip_in_custody() {
        use ciris_crypto::hybrid_kex::initiate_classical;

        let dir = seed_dir();
        let seed = [0x9u8; 32];
        seal_seed("node", dir.path(), &seed);
        let keys = SelfEncKeys::open("node", dir.path().to_path_buf()).unwrap();

        let pubs = keys.enc_pubkeys().unwrap();
        let x_pub: [u8; 32] = STANDARD
            .decode(&pubs.x25519_base64)
            .unwrap()
            .try_into()
            .unwrap();
        let (msg, initiator_key) = initiate_classical(&x_pub).unwrap();
        let responder_key = keys
            .kex_respond(&serde_json::to_vec(&msg).unwrap())
            .unwrap();
        assert_eq!(initiator_key, responder_key);
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[test]
    fn unknown_algorithm_is_rejected() {
        let dir = seed_dir();
        seal_seed("node", dir.path(), &[0x1u8; 32]);
        let keys = SelfEncKeys::open("node", dir.path().to_path_buf()).unwrap();
        let err = keys
            .kex_respond(br#"{"algorithm":"totally-made-up"}"#)
            .unwrap_err();
        assert!(matches!(err, KeyringError::InvalidKey { .. }));
    }
}
