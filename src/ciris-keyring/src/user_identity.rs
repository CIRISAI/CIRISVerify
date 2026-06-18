//! User-identity hardware custody — the responsible owner's federation key
//! (CIRISVerify#80).
//!
//! The CC fabric-ownership model (CIRISServer v0.4.4) has the owner-binding
//! `delegates_to(user → node, infra:*)` **user-signed** — the responsible human
//! cryptographically asserts ownership. Persist's `Engine` holds exactly one
//! steward `LocalSigner` (the *node* key); this module is the **distinct
//! user-identity** accessor so the human's owner-binding signature is custodied
//! by the human's own hardware, never co-resident with the node steward key.
//!
//! ## Two kinds of factor (the honest crypto)
//!
//! A federation owner-binding is an **Ed25519 (+ ML-DSA-65) signature over a
//! binary preimage**. Not every "authenticator" can produce one:
//!
//! - **Signing factors** (`FactorKind::Signing`) — a YubiKey PIV slot
//!   (PKCS#11), a TPM/Secure-Enclave-sealed key, or a software seed. These hold
//!   an Ed25519 key and *directly sign* the owner-binding. `get_user_identity_signer`
//!   returns one as a `HardwareSigner`.
//! - **Presence factors** (`FactorKind::Presence`) — a **WebAuthn/FIDO2
//!   passkey** (Google Authenticator, Microsoft Authenticator, Apple/Android
//!   passkeys, a platform authenticator). A passkey signs WebAuthn's assertion
//!   format over a challenge — it **authenticates presence and gates/unlocks**
//!   the signing key, but does **not** itself produce the federation owner-binding
//!   signature. Its assertion is verified by `ciris_crypto::webauthn`.
//!
//! ## Multiple hardware keys per identity (redundancy)
//!
//! `UserIdentityKeyset` associates **N** factors with one logical identity. A
//! private signing key cannot be copied onto several tokens (that is the point
//! of hardware custody), so redundancy is **OR-of-N over signing keys**: any
//! associated signing key validly authorizes the owner-binding (lose one
//! YubiKey, the backup still works). This is exactly the HUMANITY_ACCORD
//! pattern — each holder carries two YubiKey 5 FIPS for redundancy (CEG §9.4).
//! A verifier accepts a binding signed by **any** associated signing key
//! (`ciris_verify_core::threshold` at threshold 1 over
//! `UserIdentityKeyset::signing_public_keys`).

use std::path::PathBuf;

use crate::error::KeyringError;
use crate::hw_token::TokenInterface;
use crate::signer::HardwareSigner;

/// What a federation identity factor can cryptographically do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactorKind {
    /// Holds an Ed25519 key and **directly signs** the owner-binding (YubiKey
    /// PIV / TPM-SE-sealed / software seed).
    Signing,
    /// **Authenticates presence + unlocks** the signing key but does NOT itself
    /// sign the federation preimage (a WebAuthn/FIDO2 passkey — Google /
    /// Microsoft Authenticator, Apple/Android, platform authenticator).
    Presence,
}

/// Where a factor's key material is custodied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactorBackend {
    /// TPM 2.0 / Secure Enclave-sealed Ed25519 ([`crate::sealed_ed25519`]).
    PlatformSealed,
    /// External hardware token over PKCS#11 / PIV (YubiKey). Real signing behind
    /// the token; resolved by [`crate::hw_token`].
    Pkcs11 {
        /// The token interface the key is reached over.
        interface: TokenInterface,
    },
    /// Software seed — explicit dev/test custody (no hardware guarantee).
    Software,
    /// A WebAuthn/FIDO2 passkey held by an authenticator app or platform.
    /// Always a [`FactorKind::Presence`] factor.
    WebauthnPasskey {
        /// Provider label, e.g. `"google-authenticator"`, `"microsoft-authenticator"`,
        /// `"apple-passkey"`, `"android-passkey"`, `"platform"`.
        provider: String,
    },
}

/// One factor associated with a user identity — a signing key or a presence
/// credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityFactor {
    /// Human label, e.g. `"yubikey-primary"`, `"yubikey-backup"`, `"phone-passkey"`.
    pub label: String,
    /// Whether this factor signs the owner-binding or only authenticates presence.
    pub kind: FactorKind,
    /// Where the key material lives.
    pub backend: FactorBackend,
    /// For a [`FactorKind::Signing`] factor: the Ed25519 public key (32 bytes) a
    /// verifier pins. For a [`FactorKind::Presence`] factor: the WebAuthn
    /// credential public key (COSE) the passkey assertion verifies against.
    pub public_key: Vec<u8>,
    /// CEG §9.4 `hardware_class`, e.g. `"YubiKey_5_FIPS"`, `"TPM_2_0"`,
    /// `"Passkey_Synced"`.
    pub hardware_class: String,
}

impl IdentityFactor {
    /// Whether this factor can directly authorize the owner-binding signature.
    #[must_use]
    pub fn is_signing(&self) -> bool {
        self.kind == FactorKind::Signing
    }
}

/// A logical user identity backed by **N** factors (the redundancy / multi-key
/// model). Holds no private material — only the *association* of public keys /
/// credentials a verifier trusts for this identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserIdentityKeyset {
    /// The logical identity id (e.g. `key_id = sha256(primary_ed25519_pubkey)`).
    pub identity_id: String,
    factors: Vec<IdentityFactor>,
}

impl UserIdentityKeyset {
    /// Create a keyset for `identity_id` with its first factor.
    #[must_use]
    pub fn new(identity_id: impl Into<String>, primary: IdentityFactor) -> Self {
        Self {
            identity_id: identity_id.into(),
            factors: vec![primary],
        }
    }

    /// Associate another factor (a backup YubiKey, an authenticator-app passkey).
    /// Idempotent: a factor whose `public_key` is already present is not
    /// duplicated. Returns `true` if it was newly added.
    pub fn register(&mut self, factor: IdentityFactor) -> bool {
        if self
            .factors
            .iter()
            .any(|f| f.public_key == factor.public_key)
        {
            return false;
        }
        self.factors.push(factor);
        true
    }

    /// All associated factors.
    #[must_use]
    pub fn factors(&self) -> &[IdentityFactor] {
        &self.factors
    }

    /// The Ed25519 public keys that may **sign** the owner-binding (the OR-of-N
    /// redundancy set). A verifier accepts a binding signed by any of these.
    #[must_use]
    pub fn signing_public_keys(&self) -> Vec<&[u8]> {
        self.factors
            .iter()
            .filter(|f| f.is_signing())
            .map(|f| f.public_key.as_slice())
            .collect()
    }

    /// The presence factors (authenticator-app passkeys) — the unlock/presence
    /// gate, not owner-binding signers.
    #[must_use]
    pub fn presence_factors(&self) -> Vec<&IdentityFactor> {
        self.factors.iter().filter(|f| !f.is_signing()).collect()
    }

    /// Does `ed25519_pubkey` belong to one of this identity's **signing** keys?
    /// This is the redundancy check: an owner-binding from any associated
    /// signing key is authorized for the identity.
    #[must_use]
    pub fn authorizes_signing_key(&self, ed25519_pubkey: &[u8]) -> bool {
        self.factors
            .iter()
            .any(|f| f.is_signing() && f.public_key == ed25519_pubkey)
    }

    /// Number of distinct signing keys — the redundancy degree (1 = no backup).
    #[must_use]
    pub fn redundancy(&self) -> usize {
        self.factors.iter().filter(|f| f.is_signing()).count()
    }
}

/// Which custody backend to resolve a user-identity **signing** key from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningBackend {
    /// Best platform hardware: TPM 2.0 / Secure Enclave-sealed Ed25519, with an
    /// encrypted software fallback. Testable on any box.
    PlatformSealed,
    /// External hardware token (YubiKey) over the given interface (PIV/PKCS#11).
    /// Requires a physical token; resolved via [`crate::hw_token`].
    Pkcs11 {
        /// The token interface (`TokenInterface::Pkcs11` for YubiKey PIV/PKCS#11).
        interface: TokenInterface,
    },
    /// Software seed — explicit dev/test custody.
    Software,
}

/// How to locate the user identity's signing key. **Distinct namespace from the
/// node steward** (`key_id` + `seed_dir` MUST NOT collide with the node's) — the
/// whole point is that the human's key is not co-resident with the node key.
#[derive(Debug, Clone)]
pub struct UserIdentityConfig {
    /// The user-identity alias (e.g. `CIRIS_USER_KEY_ID`).
    pub key_id: String,
    /// Where the sealed/software seed lives (separate from the node steward's).
    pub seed_dir: PathBuf,
    /// The custody backend.
    pub backend: SigningBackend,
}

/// Resolve the user identity's **signing** key as a [`HardwareSigner`] — the
/// substrate side of "set up my federation ID with my YubiKey / passkey and
/// establish ownership." CIRISServer's `/v1/setup/claim-remote` calls this to
/// sign the `infra:*` owner-binding with the *user's* key (not the node's).
///
/// - [`SigningBackend::PlatformSealed`] → a TPM/SE-sealed Ed25519 signer (or
///   encrypted software fallback) under `key_id` / `seed_dir`.
/// - [`SigningBackend::Pkcs11`] → an external-token signer (YubiKey). Requires a
///   physical token; returns [`KeyringError::NotSupported`] when no PKCS#11
///   backend is compiled in (the `hw_token` path, CIRISVerify#62).
/// - [`SigningBackend::Software`] → a software signer (dev/test).
///
/// # Errors
///
/// Propagates the backend's construction error.
pub fn get_user_identity_signer(
    config: &UserIdentityConfig,
) -> Result<Box<dyn HardwareSigner>, KeyringError> {
    match &config.backend {
        SigningBackend::PlatformSealed => {
            crate::sealed_ed25519::get_platform_ed25519_signer(&config.key_id, &config.seed_dir)
        },
        SigningBackend::Pkcs11 { interface } => {
            crate::hw_token::get_token_signer(*interface, &config.key_id)
        },
        SigningBackend::Software => crate::platform::create_software_signer(&config.key_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_factor(label: &str, pubkey: &[u8]) -> IdentityFactor {
        IdentityFactor {
            label: label.to_string(),
            kind: FactorKind::Signing,
            backend: FactorBackend::PlatformSealed,
            public_key: pubkey.to_vec(),
            hardware_class: "TPM_2_0".to_string(),
        }
    }

    fn passkey_factor(label: &str, provider: &str, cred: &[u8]) -> IdentityFactor {
        IdentityFactor {
            label: label.to_string(),
            kind: FactorKind::Presence,
            backend: FactorBackend::WebauthnPasskey {
                provider: provider.to_string(),
            },
            public_key: cred.to_vec(),
            hardware_class: "Passkey_Synced".to_string(),
        }
    }

    #[test]
    fn redundant_signing_keys_all_authorize() {
        // The accord-holder model: two YubiKeys, one identity.
        let mut ks =
            UserIdentityKeyset::new("user-1", signing_factor("yubikey-primary", &[1u8; 32]));
        assert!(ks.register(signing_factor("yubikey-backup", &[2u8; 32])));
        assert_eq!(ks.redundancy(), 2);
        // A binding signed by EITHER key is authorized (OR-of-N).
        assert!(ks.authorizes_signing_key(&[1u8; 32]));
        assert!(ks.authorizes_signing_key(&[2u8; 32]));
        // An unassociated key is not.
        assert!(!ks.authorizes_signing_key(&[3u8; 32]));
        assert_eq!(ks.signing_public_keys().len(), 2);
    }

    #[test]
    fn duplicate_registration_is_idempotent() {
        let mut ks = UserIdentityKeyset::new("user-1", signing_factor("a", &[1u8; 32]));
        assert!(!ks.register(signing_factor("a-again", &[1u8; 32])));
        assert_eq!(ks.factors().len(), 1);
    }

    #[test]
    fn presence_factors_do_not_authorize_signing() {
        // A passkey (Google/MS authenticator) authenticates presence but is NOT
        // a signing key — it can't authorize the owner-binding by itself.
        let mut ks = UserIdentityKeyset::new("user-1", signing_factor("yubikey", &[1u8; 32]));
        ks.register(passkey_factor("phone", "google-authenticator", &[9u8; 65]));
        assert_eq!(ks.redundancy(), 1, "passkey is not a signing key");
        assert!(!ks.authorizes_signing_key(&[9u8; 65]));
        assert_eq!(ks.presence_factors().len(), 1);
        assert_eq!(
            ks.presence_factors()[0].backend,
            FactorBackend::WebauthnPasskey {
                provider: "google-authenticator".to_string()
            }
        );
    }

    #[test]
    fn software_user_identity_signer_resolves_and_is_distinct() {
        // A user identity under its own namespace (not the node steward's).
        let dir = std::env::temp_dir().join(format!("ciris-user-id-{}", std::process::id()));
        let cfg = UserIdentityConfig {
            key_id: "user-owner-1".to_string(),
            seed_dir: dir.clone(),
            backend: SigningBackend::Software,
        };
        let signer = get_user_identity_signer(&cfg).unwrap();
        assert_eq!(signer.current_alias(), "user-owner-1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pkcs11_backend_reports_unsupported_without_token() {
        // Honest: no PKCS#11 backend compiled in / no token on this box.
        let cfg = UserIdentityConfig {
            key_id: "user-yk-1".to_string(),
            seed_dir: std::env::temp_dir(),
            backend: SigningBackend::Pkcs11 {
                interface: TokenInterface::Pkcs11,
            },
        };
        assert!(matches!(
            get_user_identity_signer(&cfg),
            Err(KeyringError::NotSupported { .. })
        ));
    }
}
