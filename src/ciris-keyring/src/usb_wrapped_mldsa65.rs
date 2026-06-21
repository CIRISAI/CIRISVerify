//! Portable **signature-wrapped** ML-DSA-65 signer — the high-secure portable
//! custody for the post-quantum half (CIRISVerify, accord portable key mode).
//!
//! The accord/high-secure variant where the ML-DSA-65 seed lives on a **USB
//! key**, AEAD-encrypted under a key derived from the **YubiKey's deterministic
//! Ed25519 signature** over a fixed, domain-separated challenge. To unwrap, the
//! YubiKey must sign that challenge (**touch + PIN**) — so **both** the USB
//! (which holds the ciphertext) **and** the YubiKey (the only producer of the
//! wrap key) are required, plus the PIN and touch.
//!
//! ## Why signature-derived (not ECDH)
//!
//! The wrap key = `HKDF-SHA256(ikm = Ed25519_sign(challenge), salt, info)`.
//! Ed25519 is deterministic (RFC 8032), so the same challenge always yields the
//! same signature → the same wrap key. Crucially the YubiKey only ever **signs**
//! — it gains **no decrypt / key-exchange capability**, so an accord key stays
//! strictly signing-only (CC §9.2 scope-isolation preserved). The wrap challenge
//! (`ciris.accord.mldsa-usb-wrap.v1`) is domain-separated from the accord
//! invocation preimage (`ciris.accord_invoke.v1`), so the two never collide.
//!
//! ## What this protects (and what it does not)
//!
//! ML-DSA-65 signing is still **software** (no PQC token ships in 2026) — once
//! unwrapped, the seed is a transient in-process buffer, same AV-17 carve-out as
//! [`crate::sealed_mldsa65`]. What this mode closes is **at-rest exfil +
//! portability**: the USB seed is useless without the YubiKey, and the identity
//! is no longer machine-bound (it travels on the two keys). The *in-memory*
//! residual that used to leave ml-dsa's outer `SigningKey` seed un-zeroized for
//! its lifetime is orthogonal to this at-rest mode and was closed codebase-wide
//! by the ml-dsa 0.1.1 bump (`SigningKey<P>: ZeroizeOnDrop`, CIRISVerify#87).
//! When a FIPS ML-DSA token ships, this whole layer swaps for a hardware
//! `PqcSigner` with no change above the trait.
//!
//! ## Operational notes
//!
//! - The wrap-challenge **signature is as sensitive as the seed**: anyone who
//!   captures it (for a given `key_id` + the cleartext `salt` on the USB) can
//!   re-derive the wrap key forever. It is never logged or transmitted — only
//!   `ed_pub` and the ciphertext land in the blob — and the YubiKey gates its
//!   production (touch + PIN). Treat the unwrap touch as a privileged operation.
//! - **Recovery / brick-survival:** the seed lives *only* on the USB (wrapped).
//!   A lost/destroyed USB, or a token that stops re-deriving, means this identity
//!   can no longer sign — recover via the §10 entrenched-family spare-swap (the
//!   spare is a distinct pre-attested identity). `provision` runs a
//!   verify-by-open so a non-deterministic token fails at provisioning, never
//!   leaving a silently-bricked accord half.

use std::path::{Path, PathBuf};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use async_trait::async_trait;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::KeyringError;
use crate::pqc::{MlDsa65SoftwareSigner, PqcAlgorithm, PqcSigner};
use crate::signer::HardwareSigner;
use crate::types::{HardwareType, PlatformAttestation, StorageDescriptor};

/// ML-DSA-65 seed length (FIPS 204 ξ).
const SEED_LEN: usize = 32;
/// Domain-separated prefix the YubiKey signs to derive the wrap key. Distinct
/// from the `ciris.accord_invoke.v1` invocation preimage — no cross-use.
const WRAP_DOMAIN: &[u8] = b"ciris.accord.mldsa-usb-wrap.v1\n";
/// HKDF `info` for the wrap-key expansion.
const WRAP_HKDF_INFO: &[u8] = b"ciris-mldsa-usb-wrap-key-v1";
/// On-USB blob schema tag.
const BLOB_SCHEMA: &str = "ciris.mldsa-usb-wrap.v1";

/// The fixed challenge the YubiKey signs to produce the wrap-key IKM — bound to
/// `key_id` so distinct identities derive distinct wrap keys.
fn wrap_challenge(key_id: &str) -> Vec<u8> {
    let mut c = Vec::with_capacity(WRAP_DOMAIN.len() + key_id.len());
    c.extend_from_slice(WRAP_DOMAIN);
    c.extend_from_slice(key_id.as_bytes());
    c
}

/// Derive the 32-byte AEAD wrap key from the Ed25519 signature + salt.
fn derive_wrap_key(ed_sig: &[u8], salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ed_sig);
    let mut key = [0u8; 32];
    hk.expand(WRAP_HKDF_INFO, &mut key)
        .expect("32 bytes is within HKDF-SHA256 output bound");
    key
}

/// The blob written to the USB key (JSON, base64 fields). Pubkeys are public, so
/// stored in the clear; only the seed is encrypted.
#[derive(Serialize, Deserialize)]
struct WrappedBlob {
    schema: String,
    key_id: String,
    /// The YubiKey Ed25519 pubkey this blob is bound to — wrong-token early-out.
    ed25519_pubkey_b64: String,
    /// The ML-DSA-65 pubkey (public; lets `public_key()` answer without unwrap).
    mldsa65_pubkey_b64: String,
    salt_b64: String,
    nonce_b64: String,
    /// `AES-256-GCM(wrap_key, nonce, seed)` ‖ tag.
    ciphertext_b64: String,
}

fn blob_path(usb_dir: &Path, key_id: &str) -> PathBuf {
    let safe: String = key_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    usb_dir.join(format!("{safe}.ciris-mldsa-usb.json"))
}

fn invalid(reason: impl Into<String>) -> KeyringError {
    KeyringError::InvalidKey {
        reason: reason.into(),
    }
}

/// A [`PqcSigner`] whose ML-DSA-65 seed is signature-wrapped on a USB key,
/// unwrappable only with the YubiKey it was provisioned to (touch + PIN). Signs
/// ML-DSA-65 in software over the unwrapped seed.
#[derive(Debug)]
pub struct UsbWrappedMlDsa65Signer {
    inner: MlDsa65SoftwareSigner,
    key_id: String,
    usb_dir: PathBuf,
}

impl UsbWrappedMlDsa65Signer {
    /// **Provision**: generate (or adopt) the ML-DSA-65 seed, derive the wrap key
    /// from `ed`'s signature over the challenge, AEAD-encrypt the seed, and write
    /// the blob to `usb_dir`. The YubiKey is touched twice here (a determinism
    /// self-check, fail-closed if the signer is non-deterministic).
    ///
    /// # Errors
    ///
    /// [`KeyringError`] on a signer fault, a non-deterministic Ed25519 signer, or
    /// a USB write failure.
    pub async fn provision(
        ed: &dyn HardwareSigner,
        key_id: impl Into<String>,
        usb_dir: impl Into<PathBuf>,
        adopt_seed: Option<&[u8; SEED_LEN]>,
    ) -> Result<Self, KeyringError> {
        let key_id = key_id.into();
        let usb_dir = usb_dir.into();

        let mut seed = [0u8; SEED_LEN];
        match adopt_seed {
            Some(s) => seed.copy_from_slice(s),
            None => OsRng.fill_bytes(&mut seed),
        }

        // The wrap key is derived from a deterministic Ed25519 signature. Prove
        // the signer is actually deterministic before we depend on it — a
        // non-deterministic signer would make the seed permanently unrecoverable.
        let challenge = wrap_challenge(&key_id);
        let sig1 = ed.sign(&challenge).await?;
        let sig2 = ed.sign(&challenge).await?;
        if sig1 != sig2 {
            seed.iter_mut().for_each(|b| *b = 0);
            return Err(invalid(
                "Ed25519 signer is non-deterministic — cannot derive a stable wrap key \
                 (Ed25519 MUST be RFC 8032 deterministic)",
            ));
        }

        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let wrap_key = derive_wrap_key(&sig1, &salt);
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let cipher =
            Aes256Gcm::new_from_slice(&wrap_key).map_err(|e| invalid(format!("AEAD init: {e}")))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), seed.as_ref())
            .map_err(|e| invalid(format!("AEAD seal: {e}")))?;

        let inner = MlDsa65SoftwareSigner::from_seed_bytes(&seed, key_id.clone())?;
        let mldsa_pub = inner.public_key().await?;
        let ed_pub = ed.public_key().await?;

        let blob = WrappedBlob {
            schema: BLOB_SCHEMA.to_string(),
            key_id: key_id.clone(),
            ed25519_pubkey_b64: hex::encode(&ed_pub),
            mldsa65_pubkey_b64: hex::encode(&mldsa_pub),
            salt_b64: hex::encode(salt),
            nonce_b64: hex::encode(nonce),
            ciphertext_b64: hex::encode(&ciphertext),
        };
        write_blob(&usb_dir, &key_id, &blob)?;

        seed.iter_mut().for_each(|b| *b = 0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        // **Verify-by-open** — the determinism double-check above only proves the
        // signer is stable across two back-to-back signs. It cannot prove `open()`
        // will re-derive *later*. So immediately re-open the just-written blob: a
        // third sign that diverges from the encrypting signature makes the AEAD
        // open fail HERE, at provision, rather than silently bricking the accord
        // half at first restore. On failure the bad blob is removed so a broken
        // token can never leave a half-written, unrecoverable seed behind.
        if let Err(e) = Self::open(ed, &key_id, &usb_dir).await {
            let _ = std::fs::remove_file(blob_path(&usb_dir, &key_id));
            return Err(invalid(format!(
                "verify-by-open failed — the token did not reproduce the wrap key, so the seed \
                 would not be recoverable (non-deterministic Ed25519 signer?). The USB blob was \
                 removed; re-provision with a conformant token, or recover via the genesis seed / \
                 §10 spare-swap: {e}"
            )));
        }
        Ok(Self {
            inner,
            key_id,
            usb_dir,
        })
    }

    /// **Open**: read the blob from `usb_dir`, confirm it is bound to `ed`'s
    /// YubiKey, derive the wrap key from `ed`'s signature over the challenge
    /// (touch + PIN), decrypt the seed, and load the software signer. The seed
    /// buffer is scrubbed after load.
    ///
    /// # Errors
    ///
    /// [`KeyringError::InvalidKey`] if the blob is missing/malformed, the YubiKey
    /// doesn't match the one it was provisioned to, or the AEAD open fails (wrong
    /// key / tampered ciphertext).
    pub async fn open(
        ed: &dyn HardwareSigner,
        key_id: &str,
        usb_dir: impl Into<PathBuf>,
    ) -> Result<Self, KeyringError> {
        let usb_dir = usb_dir.into();
        let blob = read_blob(&usb_dir, key_id)?;

        // Bind to the provisioning YubiKey — a wrong token fails here with a clear
        // message, before we waste a touch on a doomed unwrap.
        let ed_pub = ed.public_key().await?;
        if hex::encode(&ed_pub) != blob.ed25519_pubkey_b64 {
            return Err(invalid(
                "this USB blob is bound to a different YubiKey (Ed25519 pubkey mismatch)",
            ));
        }

        let salt = hex::decode(&blob.salt_b64).map_err(|e| invalid(format!("salt: {e}")))?;
        let nonce = hex::decode(&blob.nonce_b64).map_err(|e| invalid(format!("nonce: {e}")))?;
        let ciphertext =
            hex::decode(&blob.ciphertext_b64).map_err(|e| invalid(format!("ciphertext: {e}")))?;

        let sig = ed.sign(&wrap_challenge(&blob.key_id)).await?; // touch + PIN
        let wrap_key = derive_wrap_key(&sig, &salt);
        let cipher =
            Aes256Gcm::new_from_slice(&wrap_key).map_err(|e| invalid(format!("AEAD init: {e}")))?;
        let mut seed_vec = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| {
                invalid(
                    "AEAD open failed — wrong YubiKey, wrong PIN-gated key, or tampered USB blob",
                )
            })?;
        if seed_vec.len() != SEED_LEN {
            seed_vec.iter_mut().for_each(|b| *b = 0);
            return Err(invalid("decrypted seed has wrong length"));
        }
        let mut seed = [0u8; SEED_LEN];
        seed.copy_from_slice(&seed_vec);
        seed_vec.iter_mut().for_each(|b| *b = 0);

        let inner = MlDsa65SoftwareSigner::from_seed_bytes(&seed, blob.key_id.clone())?;
        seed.iter_mut().for_each(|b| *b = 0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        // Corruption check: the reconstructed pubkey must match the blob's.
        if hex::encode(inner.public_key().await?) != blob.mldsa65_pubkey_b64 {
            return Err(invalid(
                "unwrapped seed does not reproduce the recorded ML-DSA-65 pubkey (corrupt blob)",
            ));
        }

        Ok(Self {
            inner,
            key_id: blob.key_id,
            usb_dir,
        })
    }
}

fn write_blob(usb_dir: &Path, key_id: &str, blob: &WrappedBlob) -> Result<(), KeyringError> {
    std::fs::create_dir_all(usb_dir)
        .map_err(|e| invalid(format!("create USB dir {}: {e}", usb_dir.display())))?;
    let path = blob_path(usb_dir, key_id);
    let json =
        serde_json::to_string_pretty(blob).map_err(|e| invalid(format!("serialize blob: {e}")))?;
    std::fs::write(&path, json).map_err(|e| invalid(format!("write {}: {e}", path.display())))?;
    Ok(())
}

fn read_blob(usb_dir: &Path, key_id: &str) -> Result<WrappedBlob, KeyringError> {
    let path = blob_path(usb_dir, key_id);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| invalid(format!("read USB blob {}: {e}", path.display())))?;
    let blob: WrappedBlob =
        serde_json::from_str(&text).map_err(|e| invalid(format!("parse blob: {e}")))?;
    if blob.schema != BLOB_SCHEMA {
        return Err(invalid(format!("unexpected blob schema {:?}", blob.schema)));
    }
    if blob.key_id != key_id {
        return Err(invalid(format!(
            "blob key_id {:?} != requested {key_id:?}",
            blob.key_id
        )));
    }
    Ok(blob)
}

#[async_trait]
impl PqcSigner for UsbWrappedMlDsa65Signer {
    fn algorithm(&self) -> PqcAlgorithm {
        self.inner.algorithm()
    }

    fn hardware_type(&self) -> HardwareType {
        // Honest: ML-DSA signing is software and the seed at rest is a file (on
        // USB). The YubiKey gates the *unwrap*, but the signing tier is software.
        HardwareType::SoftwareOnly
    }

    async fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
        self.inner.public_key().await
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        self.inner.sign(data).await
    }

    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
        self.inner.attestation().await
    }

    fn current_alias(&self) -> &str {
        &self.key_id
    }

    fn storage_descriptor(&self) -> StorageDescriptor {
        StorageDescriptor::SoftwareFile {
            path: blob_path(&self.usb_dir, &self.key_id),
        }
    }
}

#[cfg(all(test, feature = "software"))]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::sealed_ed25519::SealedEd25519Signer;
    use crate::signer::KeyGenConfig;
    use crate::types::ClassicalAlgorithm;

    /// A signer that is deterministic for the first `flip_on - 1` signs, then
    /// diverges on the `flip_on`-th — the out-of-spec non-deterministic token the
    /// determinism check defends against. Delegates everything else to a real
    /// Ed25519 signer.
    struct FlakySigner {
        inner: SealedEd25519Signer,
        n: AtomicUsize,
        flip_on: usize,
    }

    #[async_trait]
    impl HardwareSigner for FlakySigner {
        fn algorithm(&self) -> ClassicalAlgorithm {
            self.inner.algorithm()
        }
        fn hardware_type(&self) -> HardwareType {
            self.inner.hardware_type()
        }
        async fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
            self.inner.public_key().await
        }
        async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
            let i = self.n.fetch_add(1, Ordering::Relaxed) + 1;
            let mut sig = self.inner.sign(data).await?;
            if i == self.flip_on {
                sig[0] ^= 1; // diverge on the flip_on-th sign
            }
            Ok(sig)
        }
        async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
            self.inner.attestation().await
        }
        async fn attestation_with_nonce(
            &self,
            nonce: Option<&[u8]>,
        ) -> Result<PlatformAttestation, KeyringError> {
            self.inner.attestation_with_nonce(nonce).await
        }
        async fn generate_key(&self, config: &KeyGenConfig) -> Result<(), KeyringError> {
            self.inner.generate_key(config).await
        }
        async fn key_exists(&self, alias: &str) -> Result<bool, KeyringError> {
            self.inner.key_exists(alias).await
        }
        async fn delete_key(&self, alias: &str) -> Result<(), KeyringError> {
            self.inner.delete_key(alias).await
        }
        fn current_alias(&self) -> &str {
            self.inner.current_alias()
        }
        fn storage_descriptor(&self) -> StorageDescriptor {
            self.inner.storage_descriptor()
        }
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut s = [0u8; 8];
        OsRng.fill_bytes(&mut s);
        let hex: String = s.iter().map(|b| format!("{b:02x}")).collect();
        std::env::temp_dir().join(format!("ciris-usb-{tag}-{hex}"))
    }

    fn tmp_usb() -> PathBuf {
        tmp_dir("mldsa")
    }

    // A deterministic Ed25519 HardwareSigner standing in for the YubiKey
    // (Ed25519 is RFC-8032 deterministic — exactly the property the wrap needs).
    fn yubikey(alias: &str) -> SealedEd25519Signer {
        SealedEd25519Signer::open(alias, tmp_dir("ed")).unwrap()
    }

    #[tokio::test]
    async fn provision_then_open_round_trips_and_signs() {
        let usb = tmp_usb();
        let yk = yubikey("accord-eric-moore-primary-ed");
        let prov = UsbWrappedMlDsa65Signer::provision(&yk, "accord-eric-moore-primary", &usb, None)
            .await
            .unwrap();
        let pub_at_provision = prov.public_key().await.unwrap();

        // Re-open from the USB with the same YubiKey → same identity.
        let opened = UsbWrappedMlDsa65Signer::open(&yk, "accord-eric-moore-primary", &usb)
            .await
            .unwrap();
        assert_eq!(opened.public_key().await.unwrap(), pub_at_provision);

        // It actually signs ML-DSA-65.
        let sig = opened.sign(b"accord-invocation-bytes").await.unwrap();
        assert_eq!(sig.len(), 3309); // FIPS 204 ML-DSA-65 signature length
    }

    #[tokio::test]
    async fn wrong_yubikey_cannot_open() {
        let usb = tmp_usb();
        let yk = yubikey("real-yk");
        UsbWrappedMlDsa65Signer::provision(&yk, "k1", &usb, None)
            .await
            .unwrap();
        let attacker = yubikey("attacker-yk");
        let err = UsbWrappedMlDsa65Signer::open(&attacker, "k1", &usb)
            .await
            .unwrap_err();
        // Caught at the pubkey-binding check.
        assert!(matches!(err, KeyringError::InvalidKey { .. }));
    }

    #[tokio::test]
    async fn tampered_blob_fails_open() {
        let usb = tmp_usb();
        let yk = yubikey("yk");
        UsbWrappedMlDsa65Signer::provision(&yk, "k1", &usb, None)
            .await
            .unwrap();
        // Flip a byte in the ciphertext.
        let path = blob_path(&usb, "k1");
        let mut blob: WrappedBlob =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let mut ct = hex::decode(&blob.ciphertext_b64).unwrap();
        ct[0] ^= 1;
        blob.ciphertext_b64 = hex::encode(&ct);
        std::fs::write(&path, serde_json::to_string(&blob).unwrap()).unwrap();

        let err = UsbWrappedMlDsa65Signer::open(&yk, "k1", &usb)
            .await
            .unwrap_err();
        assert!(matches!(err, KeyringError::InvalidKey { .. }));
    }

    #[tokio::test]
    async fn non_deterministic_token_caught_at_provision_not_bricked() {
        // CRITICAL regression (adversarial review): a token deterministic for the
        // two self-check signs but diverging on the third (the verify-by-open
        // sign) MUST fail provisioning and leave NO blob behind — never a
        // silently-bricked HUMANITY_ACCORD PQC half.
        let usb = tmp_usb();
        let flaky = FlakySigner {
            inner: yubikey("flaky"),
            n: AtomicUsize::new(0),
            flip_on: 3, // signs 1,2 (self-check) stable; sign 3 (verify-by-open) diverges
        };
        let err = UsbWrappedMlDsa65Signer::provision(&flaky, "k1", &usb, None)
            .await
            .unwrap_err();
        assert!(matches!(err, KeyringError::InvalidKey { .. }));
        // The half-written blob was removed — no unrecoverable seed left behind.
        assert!(!blob_path(&usb, "k1").exists());
    }

    #[tokio::test]
    async fn adopt_seed_preserves_pubkey() {
        // Provisioning a known seed must reproduce the same ML-DSA pubkey (the
        // software→portable migration path).
        let usb = tmp_usb();
        let yk = yubikey("yk");
        let seed = [7u8; SEED_LEN];
        let a = UsbWrappedMlDsa65Signer::provision(&yk, "k1", &usb, Some(&seed))
            .await
            .unwrap();
        let direct = MlDsa65SoftwareSigner::from_seed_bytes(&seed, "k1".to_string()).unwrap();
        assert_eq!(
            a.public_key().await.unwrap(),
            direct.public_key().await.unwrap()
        );
    }

    #[tokio::test]
    async fn both_required_usb_alone_is_useless() {
        // Without the YubiKey, the USB blob can't be opened (no wrap key).
        let usb = tmp_usb();
        let yk = yubikey("yk");
        UsbWrappedMlDsa65Signer::provision(&yk, "k1", &usb, None)
            .await
            .unwrap();
        // A different (attacker) token can't derive the wrap key.
        let other = yubikey("other");
        assert!(UsbWrappedMlDsa65Signer::open(&other, "k1", &usb)
            .await
            .is_err());
        // And with no blob on the USB at all, open fails (USB alone / YubiKey
        // alone both insufficient).
        let empty = tmp_usb();
        assert!(UsbWrappedMlDsa65Signer::open(&yk, "k1", &empty)
            .await
            .is_err());
    }
}
