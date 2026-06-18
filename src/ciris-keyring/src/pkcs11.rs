//! YubiKey / PKCS#11 hardware-token signer — real `C_Sign` over a physical
//! token (CIRISVerify#80, the "with my YubiKey" path).
//!
//! `Pkcs11Config` is always available (it is just data — CIRISServer builds it
//! from env/config). The real signing path (`Pkcs11Signer`) is behind the
//! **`pkcs11`** feature, which pulls in `cryptoki` (the parsec PKCS#11
//! wrapper). Without the feature, `open_pkcs11_signer` honestly returns
//! `KeyringError::NotSupported` — there is no token on a CI box.
//!
//! ## Algorithms
//!
//! The federation user identity is **Ed25519** (the owner-binding's classical
//! half), signed via `CKM_EDDSA` over the preimage directly — byte-identical to
//! the software `crate::software::Ed25519SoftwareSigner`. A P-256 PIV key is
//! also supported (`CKM_ECDSA` over `SHA-256(preimage)`, returning the raw
//! `r ‖ s` the `ciris_crypto` P-256 verifier expects) for tokens provisioned
//! that way, but Ed25519 is the federation default.
//!
//! ## How a YubiKey is reached
//!
//! Point `Pkcs11Config::module_path` at the token's PKCS#11 module — Yubico's
//! `libykcs11` (PIV) or OpenSC's `opensc-pkcs11.so` — set the user PIN and the
//! key's `CKA_LABEL` / `CKA_ID` (the PIV slot, e.g. `9c` digital-signature), and
//! `open_pkcs11_signer` logs in, locates the key, and reads its public key.
//! Each `HardwareSigner::sign` opens a session, logs in, and runs `C_Sign` on
//! the token — **the private key never leaves the hardware**.

use std::path::PathBuf;

use crate::error::KeyringError;
#[cfg(not(feature = "pkcs11"))]
use crate::signer::HardwareSigner;
use crate::types::ClassicalAlgorithm;

/// How to reach a user-identity signing key on a PKCS#11 hardware token.
/// Always available (data only); the signer is `pkcs11`-feature-gated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs11Config {
    /// Filesystem path to the token's PKCS#11 module (`.so`/`.dll`/`.dylib`),
    /// e.g. `libykcs11.so` (Yubico PIV) or `opensc-pkcs11.so`.
    pub module_path: PathBuf,
    /// The token's user PIN. Held in memory for the signer's lifetime (a token
    /// requires login per session); supply a per-use PIN if that is too broad.
    pub user_pin: Option<String>,
    /// `CKA_LABEL` of the key object to use (e.g. the PIV slot's label).
    pub key_label: Option<String>,
    /// `CKA_ID` of the key object (an alternative to `key_label`).
    pub key_id: Option<Vec<u8>>,
    /// Which token slot to use (index into `get_slots_with_token()`); default 0.
    pub slot_index: usize,
}

impl Pkcs11Config {
    /// A minimal config: module + PIN + key label, first slot.
    #[must_use]
    pub fn new(
        module_path: impl Into<PathBuf>,
        user_pin: impl Into<String>,
        key_label: impl Into<String>,
    ) -> Self {
        Self {
            module_path: module_path.into(),
            user_pin: Some(user_pin.into()),
            key_label: Some(key_label.into()),
            key_id: None,
            slot_index: 0,
        }
    }
}

/// A read-only inventory of a PKCS#11 token — its identity plus the key
/// objects on it — so an operator can discover the `CKA_LABEL` / `CKA_ID` to
/// sign with (the `ciris-verify token probe` CLI surface). Data only; the
/// probe *function* is `pkcs11`-feature-gated.
#[derive(Debug, Clone)]
pub struct Pkcs11Probe {
    /// Every slot that currently has a token present.
    pub tokens: Vec<Pkcs11TokenInfo>,
    /// Key objects found in the selected slot (`Pkcs11Config::slot_index`).
    pub keys: Vec<Pkcs11KeyInfo>,
}

/// Identity of one present token (from `CK_TOKEN_INFO`).
#[derive(Debug, Clone)]
pub struct Pkcs11TokenInfo {
    /// Index into `get_slots_with_token()` (what `slot_index` selects).
    pub slot_index: usize,
    /// `manufacturerID` (e.g. `"Yubico (www.yubico.com)"`).
    pub manufacturer: String,
    /// `model` (e.g. `"YubiKey YK5"`).
    pub model: String,
    /// `serialNumber`.
    pub serial: String,
    /// Token `label`.
    pub label: String,
}

/// One key object on the token.
#[derive(Debug, Clone)]
pub struct Pkcs11KeyInfo {
    /// `"public"` or `"private"`.
    pub class: &'static str,
    /// `CKA_LABEL`, if set — what `Pkcs11Config::key_label` matches.
    pub label: Option<String>,
    /// `CKA_ID` as lowercase hex, if set — what `Pkcs11Config::key_id` matches.
    pub id_hex: Option<String>,
    /// `CKA_KEY_TYPE` rendered for humans (e.g. `"EC_EDWARDS"`, `"EC"`, `"RSA"`).
    pub key_type: String,
    /// The CIRIS federation algorithm this key type maps to, if any. `None`
    /// means the key is unusable as a federation owner-binding (e.g. RSA).
    pub ciris_algorithm: Option<ClassicalAlgorithm>,
}

/// Probe a PKCS#11 token: list present tokens and the key objects in the
/// selected slot. Read-only — it never writes to the device. Logs in only if
/// `Pkcs11Config::user_pin` is set (private-key objects are otherwise hidden).
///
/// # Errors
///
/// Module/token failures, or `NotSupported` without the `pkcs11` feature.
#[cfg(not(feature = "pkcs11"))]
pub fn probe_pkcs11(_config: &Pkcs11Config) -> Result<Pkcs11Probe, KeyringError> {
    Err(KeyringError::NotSupported {
        operation: "PKCS#11 probe: build with `--features pkcs11` and attach a token".into(),
    })
}

/// Open a [`HardwareSigner`] backed by a PKCS#11 token for the user identity
/// `alias`. With the `pkcs11` feature: real `cryptoki`. Without it: honest
/// [`KeyringError::NotSupported`].
///
/// # Errors
///
/// Token / module / login / key-lookup failures, or `NotSupported` when the
/// `pkcs11` feature is not compiled in.
#[cfg(not(feature = "pkcs11"))]
pub fn open_pkcs11_signer(
    alias: &str,
    _config: &Pkcs11Config,
) -> Result<Box<dyn HardwareSigner>, KeyringError> {
    Err(KeyringError::NotSupported {
        operation: format!(
            "PKCS#11 token signing (alias={alias}): build with `--features pkcs11` \
             (cryptoki) and a physical token (CIRISVerify#80)"
        ),
    })
}

#[cfg(feature = "pkcs11")]
pub use real::{open_pkcs11_signer, probe_pkcs11, Pkcs11Signer};

#[cfg(feature = "pkcs11")]
mod real {
    use super::{KeyringError, Pkcs11Config};
    use crate::signer::{HardwareSigner, KeyGenConfig};
    use crate::types::{
        ClassicalAlgorithm, HardwareType, PlatformAttestation, SoftwareAttestation,
        StorageDescriptor,
    };

    use async_trait::async_trait;
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
    use cryptoki::session::{Session, UserType};
    use cryptoki::slot::Slot;
    use cryptoki::types::AuthPin;
    use sha2::{Digest, Sha256};

    fn err(reason: impl std::fmt::Display) -> KeyringError {
        KeyringError::HardwareError {
            reason: reason.to_string(),
        }
    }

    /// A signer whose private key lives on a PKCS#11 token (YubiKey PIV).
    pub struct Pkcs11Signer {
        ctx: Pkcs11,
        slot: Slot,
        config: Pkcs11Config,
        alias: String,
        algorithm: ClassicalAlgorithm,
        public_key: Vec<u8>,
    }

    impl Pkcs11Signer {
        /// Initialize the module, log in, locate the key, read its public key.
        fn open(alias: &str, config: &Pkcs11Config) -> Result<Self, KeyringError> {
            let ctx = Pkcs11::new(&config.module_path)
                .map_err(|e| err(format!("load PKCS#11 module: {e}")))?;
            ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
                .map_err(|e| err(format!("C_Initialize: {e}")))?;
            let slots = ctx
                .get_slots_with_token()
                .map_err(|e| err(format!("get_slots_with_token: {e}")))?;
            let slot = *slots
                .get(config.slot_index)
                .ok_or_else(|| err(format!("no token in slot index {}", config.slot_index)))?;

            // Read the public key + key type in a logged-in session, then drop it.
            let (algorithm, public_key) = {
                let session = ctx
                    .open_ro_session(slot)
                    .map_err(|e| err(format!("open session: {e}")))?;
                login(&session, config)?;
                let pub_handle = find_key(&session, config, ObjectClass::PUBLIC_KEY)?;
                let key_type = read_key_type(&session, pub_handle)?;
                let algorithm = algorithm_for(key_type)?;
                let public_key = read_public_key(&session, pub_handle, algorithm)?;
                (algorithm, public_key)
            };

            Ok(Self {
                ctx,
                slot,
                config: config.clone(),
                alias: alias.to_string(),
                algorithm,
                public_key,
            })
        }

        fn sign_on_token(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
            let session = self
                .ctx
                .open_ro_session(self.slot)
                .map_err(|e| err(format!("open session: {e}")))?;
            login(&session, &self.config)?;
            let priv_handle = find_key(&session, &self.config, ObjectClass::PRIVATE_KEY)?;
            match self.algorithm {
                // Ed25519: CKM_EDDSA signs the message directly (Ed25519 hashes
                // internally) — byte-identical to the software Ed25519 signer.
                ClassicalAlgorithm::Ed25519 => session
                    .sign(
                        &Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519)),
                        priv_handle,
                        data,
                    )
                    .map_err(|e| err(format!("C_Sign (EdDSA): {e}"))),
                // ECDSA P-256: CKM_ECDSA signs a pre-computed hash and returns
                // raw r‖s — prehash with SHA-256 to match the P-256 verifier.
                ClassicalAlgorithm::EcdsaP256 => {
                    let digest: [u8; 32] = Sha256::digest(data).into();
                    session
                        .sign(&Mechanism::Ecdsa, priv_handle, &digest)
                        .map_err(|e| err(format!("C_Sign (ECDSA): {e}")))
                },
                ClassicalAlgorithm::EcdsaP384 => Err(KeyringError::NotSupported {
                    operation: "PKCS#11 P-384 signing (federation key is Ed25519/P-256)".into(),
                }),
            }
        }
    }

    fn login(session: &Session, config: &Pkcs11Config) -> Result<(), KeyringError> {
        if let Some(pin) = &config.user_pin {
            session
                .login(UserType::User, Some(&AuthPin::new(pin.clone().into())))
                .map_err(|e| err(format!("C_Login: {e}")))?;
        }
        Ok(())
    }

    fn find_key(
        session: &Session,
        config: &Pkcs11Config,
        class: ObjectClass,
    ) -> Result<ObjectHandle, KeyringError> {
        let mut template = vec![Attribute::Class(class)];
        if let Some(label) = &config.key_label {
            template.push(Attribute::Label(label.as_bytes().to_vec()));
        }
        if let Some(id) = &config.key_id {
            template.push(Attribute::Id(id.clone()));
        }
        let handles = session
            .find_objects(&template)
            .map_err(|e| err(format!("find_objects: {e}")))?;
        handles
            .into_iter()
            .next()
            .ok_or_else(|| KeyringError::KeyNotFound {
                alias: config
                    .key_label
                    .clone()
                    .unwrap_or_else(|| "<by id>".to_string()),
            })
    }

    fn read_key_type(session: &Session, handle: ObjectHandle) -> Result<KeyType, KeyringError> {
        let attrs = session
            .get_attributes(handle, &[AttributeType::KeyType])
            .map_err(|e| err(format!("get_attributes(KeyType): {e}")))?;
        for a in attrs {
            if let Attribute::KeyType(kt) = a {
                return Ok(kt);
            }
        }
        Err(err("token did not return CKA_KEY_TYPE"))
    }

    fn algorithm_for(key_type: KeyType) -> Result<ClassicalAlgorithm, KeyringError> {
        if key_type == KeyType::EC_EDWARDS {
            Ok(ClassicalAlgorithm::Ed25519)
        } else if key_type == KeyType::EC {
            Ok(ClassicalAlgorithm::EcdsaP256)
        } else {
            Err(KeyringError::NotSupported {
                operation: format!(
                    "PKCS#11 key type {key_type:?} (federation user identity is Ed25519 or P-256)"
                ),
            })
        }
    }

    /// Read the public key, decoding `CKA_EC_POINT` (a DER `OCTET STRING`):
    /// Ed25519 → the raw 32-byte key; P-256 → the 65-byte SEC1 point.
    fn read_public_key(
        session: &Session,
        handle: ObjectHandle,
        algorithm: ClassicalAlgorithm,
    ) -> Result<Vec<u8>, KeyringError> {
        let attrs = session
            .get_attributes(handle, &[AttributeType::EcPoint])
            .map_err(|e| err(format!("get_attributes(EcPoint): {e}")))?;
        let ec_point = attrs
            .into_iter()
            .find_map(|a| match a {
                Attribute::EcPoint(p) => Some(p),
                _ => None,
            })
            .ok_or_else(|| err("token did not return CKA_EC_POINT"))?;
        let point = unwrap_der_octet_string(&ec_point)?;
        let expected = match algorithm {
            ClassicalAlgorithm::Ed25519 => 32,
            ClassicalAlgorithm::EcdsaP256 => 65,
            ClassicalAlgorithm::EcdsaP384 => 0,
        };
        if expected != 0 && point.len() != expected {
            return Err(err(format!(
                "Ec_POINT decoded to {} bytes, expected {expected}",
                point.len()
            )));
        }
        Ok(point)
    }

    /// Unwrap a DER `OCTET STRING` (`0x04 len value`) — short form and `0x81`
    /// long form. PKCS#11 wraps the EC point this way.
    fn unwrap_der_octet_string(der: &[u8]) -> Result<Vec<u8>, KeyringError> {
        if der.len() < 2 || der[0] != 0x04 {
            return Err(err("CKA_EC_POINT is not a DER OCTET STRING"));
        }
        let (len, offset) = if der[1] < 0x80 {
            (der[1] as usize, 2)
        } else if der[1] == 0x81 && der.len() >= 3 {
            (der[2] as usize, 3)
        } else {
            return Err(err("CKA_EC_POINT has an unsupported DER length form"));
        };
        der.get(offset..offset + len)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| err("CKA_EC_POINT length exceeds the attribute value"))
    }

    /// Open a token-backed signer. See the module docs.
    ///
    /// # Errors
    /// Token/module/login/key-lookup failures.
    pub fn open_pkcs11_signer(
        alias: &str,
        config: &Pkcs11Config,
    ) -> Result<Box<dyn HardwareSigner>, KeyringError> {
        Ok(Box::new(Pkcs11Signer::open(alias, config)?))
    }

    /// Read-only token inventory. See [`super::probe_pkcs11`].
    ///
    /// # Errors
    /// Module/token enumeration failures.
    pub fn probe_pkcs11(config: &Pkcs11Config) -> Result<super::Pkcs11Probe, KeyringError> {
        let ctx = Pkcs11::new(&config.module_path)
            .map_err(|e| err(format!("load PKCS#11 module: {e}")))?;
        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| err(format!("C_Initialize: {e}")))?;
        let slots = ctx
            .get_slots_with_token()
            .map_err(|e| err(format!("get_slots_with_token: {e}")))?;

        let mut tokens = Vec::new();
        for (i, slot) in slots.iter().enumerate() {
            let info = ctx
                .get_token_info(*slot)
                .map_err(|e| err(format!("get_token_info: {e}")))?;
            tokens.push(super::Pkcs11TokenInfo {
                slot_index: i,
                manufacturer: info.manufacturer_id().trim().to_string(),
                model: info.model().trim().to_string(),
                serial: info.serial_number().trim().to_string(),
                label: info.label().trim().to_string(),
            });
        }

        let mut keys = Vec::new();
        if let Some(slot) = slots.get(config.slot_index).copied() {
            let session = ctx
                .open_ro_session(slot)
                .map_err(|e| err(format!("open session: {e}")))?;
            // Private-key objects are only listable after C_Login; do it if a PIN
            // was supplied (best-effort — a probe with no PIN still lists pubkeys).
            let _ = login(&session, config);
            for (class, name) in [
                (ObjectClass::PUBLIC_KEY, "public"),
                (ObjectClass::PRIVATE_KEY, "private"),
            ] {
                let handles = session
                    .find_objects(&[Attribute::Class(class)])
                    .map_err(|e| err(format!("find_objects({name}): {e}")))?;
                for h in handles {
                    keys.push(read_key_info(&session, h, name));
                }
            }
        }

        Ok(super::Pkcs11Probe { tokens, keys })
    }

    /// Read a key object's label / id / type for the probe (tolerant — missing
    /// attributes just render as `None` / `"unknown"`).
    fn read_key_info(
        session: &Session,
        handle: ObjectHandle,
        class: &'static str,
    ) -> super::Pkcs11KeyInfo {
        let attrs = session
            .get_attributes(
                handle,
                &[
                    AttributeType::Label,
                    AttributeType::Id,
                    AttributeType::KeyType,
                ],
            )
            .unwrap_or_default();
        let mut label = None;
        let mut id_hex = None;
        let mut key_type = "unknown".to_string();
        let mut ciris_algorithm = None;
        for a in attrs {
            match a {
                Attribute::Label(bytes) => {
                    label = Some(String::from_utf8_lossy(&bytes).trim().to_string());
                },
                Attribute::Id(bytes) => {
                    id_hex = Some(bytes.iter().map(|b| format!("{b:02x}")).collect());
                },
                Attribute::KeyType(kt) => {
                    key_type = format!("{kt:?}");
                    ciris_algorithm = algorithm_for(kt).ok();
                },
                _ => {},
            }
        }
        super::Pkcs11KeyInfo {
            class,
            label,
            id_hex,
            key_type,
            ciris_algorithm,
        }
    }

    #[async_trait]
    impl HardwareSigner for Pkcs11Signer {
        fn algorithm(&self) -> ClassicalAlgorithm {
            self.algorithm
        }

        fn hardware_type(&self) -> HardwareType {
            HardwareType::ExternalSecureElement
        }

        async fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
            Ok(self.public_key.clone())
        }

        async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
            self.sign_on_token(data)
        }

        async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
            // A YubiKey PIV can produce an attestation cert (slot f9); not yet
            // wired — report the honest external-token tier (NOT software).
            Ok(PlatformAttestation::Software(SoftwareAttestation {
                key_derivation: "pkcs11-external-token".into(),
                storage: "external-secure-element".into(),
                security_warning: "PKCS#11 attestation cert (PIV slot f9) not yet read".into(),
            }))
        }

        async fn generate_key(&self, _config: &KeyGenConfig) -> Result<(), KeyringError> {
            // Keys are provisioned on the token out-of-band (ykman/piv-tool); the
            // signer never generates the private key (it can't leave the token).
            Err(KeyringError::NotSupported {
                operation: "PKCS#11 in-band keygen — provision the key on the token (ykman)".into(),
            })
        }

        async fn key_exists(&self, alias: &str) -> Result<bool, KeyringError> {
            Ok(alias == self.alias)
        }

        async fn delete_key(&self, _alias: &str) -> Result<(), KeyringError> {
            Err(KeyringError::NotSupported {
                operation: "PKCS#11 key deletion — manage token objects with ykman".into(),
            })
        }

        fn current_alias(&self) -> &str {
            &self.alias
        }

        fn storage_descriptor(&self) -> StorageDescriptor {
            StorageDescriptor::Hardware {
                hardware_type: HardwareType::ExternalSecureElement,
                blob_path: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_builder() {
        let c = Pkcs11Config::new("/usr/lib/libykcs11.so", "123456", "PIV AUTH key");
        assert_eq!(c.slot_index, 0);
        assert_eq!(c.user_pin.as_deref(), Some("123456"));
        assert!(c.key_label.is_some());
    }

    #[cfg(not(feature = "pkcs11"))]
    #[test]
    fn without_feature_is_not_supported() {
        let c = Pkcs11Config::new("/x.so", "0", "k");
        assert!(matches!(
            open_pkcs11_signer("user-1", &c),
            Err(KeyringError::NotSupported { .. })
        ));
    }

    /// **Live token test.** Requires a physical PKCS#11 token (YubiKey). Set:
    /// - `CIRIS_PKCS11_MODULE` — path to the module (`libykcs11.so` / `opensc-pkcs11.so`)
    /// - `CIRIS_PKCS11_PIN` — the user PIN
    /// - `CIRIS_PKCS11_KEY_LABEL` — the key object's `CKA_LABEL` (e.g. the PIV slot)
    /// - `CIRIS_PKCS11_SLOT` (optional) — slot index, default 0
    ///
    /// Run: `cargo test -p ciris-keyring --features pkcs11 -- --ignored pkcs11_live`.
    /// It opens the token, reads the public key, signs a test preimage on the
    /// device, and **verifies the signature** — the real end-to-end proof that
    /// the federation owner-binding can be custodied by the YubiKey.
    #[cfg(feature = "pkcs11")]
    #[tokio::test]
    #[ignore = "requires a physical PKCS#11 token; set CIRIS_PKCS11_* and pass --ignored"]
    async fn pkcs11_live_sign_and_verify() {
        use crate::types::ClassicalAlgorithm;

        let Ok(module) = std::env::var("CIRIS_PKCS11_MODULE") else {
            eprintln!("skip: set CIRIS_PKCS11_MODULE (+ _PIN, _KEY_LABEL)");
            return;
        };
        let cfg = Pkcs11Config {
            module_path: module.into(),
            user_pin: std::env::var("CIRIS_PKCS11_PIN").ok(),
            key_label: std::env::var("CIRIS_PKCS11_KEY_LABEL").ok(),
            key_id: None,
            slot_index: std::env::var("CIRIS_PKCS11_SLOT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
        };

        let signer = open_pkcs11_signer("user-live", &cfg).expect("open token signer");
        let pubkey = signer.public_key().await.expect("read public key");
        let msg = b"ciris owner-binding test preimage";
        let sig = signer.sign(msg).await.expect("C_Sign on token");

        match signer.algorithm() {
            ClassicalAlgorithm::Ed25519 => {
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                let vk = VerifyingKey::from_bytes(pubkey.as_slice().try_into().unwrap())
                    .expect("pubkey");
                vk.verify(msg, &Signature::from_slice(&sig).unwrap())
                    .expect("Ed25519 token signature MUST verify");
                println!(
                    "✓ YubiKey Ed25519 sign+verify OK ({}-byte pubkey)",
                    pubkey.len()
                );
            },
            ClassicalAlgorithm::EcdsaP256 => {
                use p256::ecdsa::signature::Verifier;
                use p256::ecdsa::{Signature, VerifyingKey};
                let vk = VerifyingKey::from_sec1_bytes(&pubkey).expect("pubkey");
                vk.verify(msg, &Signature::from_slice(&sig).unwrap())
                    .expect("P-256 token signature MUST verify");
                println!("✓ YubiKey P-256 sign+verify OK");
            },
            other => panic!("unexpected token algorithm: {other:?}"),
        }
    }
}
