//! Backend-agnostic federation-identity creation — the one core both the
//! `ciris-verify identity create` CLI and the FFI (`ciris_verify_create_
//! federation_identity`, for the KMP client's mobile/desktop UI) call.
//!
//! The caller opens a hardware Ed25519 [`HardwareSigner`] for whatever backend
//! fits the platform — a YubiKey PIV token (desktop), a Secure Enclave /
//! StrongBox / TPM-sealed key (mobile/desktop, auto-provisioned by
//! `get_platform_ed25519_signer`), or a software key (test). This module then
//! does the platform-independent rest: derive the federation `key_id`, attach
//! the ML-DSA-65 PQC half whose seed is **sealed at rest** by the platform
//! secure storage (#71 `get_platform_sealed_mldsa65_signer` — TPM with
//! `--features tpm`, SE / StrongBox on mobile, software AES-GCM-sealed
//! fallback), and emit the self-signed genesis [`SignedCegObject`] for the
//! [`crate::ceg_outbox`].
//!
//! **Provisioning split.** *Generating* the hardware key is backend-specific
//! and stays with the caller: `get_platform_ed25519_signer` creates the sealed
//! key on first open (mobile/desktop SE), while a YubiKey PIV slot is
//! provisioned out-of-band with `ykman` (the CLI's `--provision`) because PIV
//! slot policy + the slot certificate are PIV-applet operations, not PKCS#11.
//! By the time a signer reaches this module the key exists.

use std::sync::Arc;

use base64::Engine;
use ciris_keyring::{HardwareSigner, KeyringError};

use crate::ceg_outbox::{keys_dir, SignedCegObject};
use crate::error::VerifyError;
use crate::federation_self_record::{produce_self_key_record, TransportHint};
use crate::self_at_login::HardwareRootedIdentity;

/// The CEG `kind` of a genesis federation key record.
pub const FEDERATION_KEY_RECORD_KIND: &str = "federation_key_record";

fn keyring_err(e: KeyringError) -> VerifyError {
    VerifyError::IntegrityError {
        message: format!("hardware signer fault: {e}"),
    }
}

/// The outcome of creating a federation identity.
pub struct CreatedIdentity {
    /// The federation `key_id` (caller-chosen, else `sha256(ed_pubkey)` hex).
    pub key_id: String,
    /// The signed CEG object to relay (a self-signed genesis `KeyRecord`).
    pub object: SignedCegObject,
    /// The entity's shareable **fedcode** (FSD-003) — a `usercode` for a `user`
    /// identity, `agentcode` for `agent`, etc. Drop a usercode into a node's
    /// config to claim ownership (FSD-003 §5).
    pub code: String,
}
/// A key's validity window (CIRISVerify#268).
///
/// This exists to make a specific mis-call **impossible rather than
/// discouraged**. `valid_until` and `seal_alias` are both `Option<&str>` and
/// were adjacent, so a caller migrating from the pre-14.0 signature who added
/// the new argument in the wrong slot would compile cleanly and **sign their
/// seal alias as the key's expiry**, while the alias silently became `None`.
///
/// A previous revision of this file asserted the opposite — that "every pair
/// is type-distinguished, so a mis-ordered call does not compile" — and used
/// that claim to silence `clippy::too_many_arguments`. The claim was false for
/// exactly the pair that mattered, and the lint was pointing at the real
/// problem. Bundling the window into one type makes the assertion true and
/// drops the argument count honestly, so the allow is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validity<'a> {
    from: &'a str,
    /// Owned because it is CANONICALIZED at construction, not borrowed from
    /// the caller's text — see [`Validity::checked`].
    until: Option<String>,
}

impl<'a> Validity<'a> {
    /// Build a window, **refusing an instant nothing can compare against**
    /// (CIRISVerify#268).
    ///
    /// This is the **only** way to construct a `Validity`. The fields are
    /// private and there is no unchecked constructor, because a previous
    /// revision offered `new`/`starting` alongside this and a caller doing the
    /// natural thing got no validation at all — an optional check is skippable
    /// by omission, which is the same lesson #252 rule 3 records and the third
    /// time this pull request has had to learn it.
    ///
    /// It is also the single validation rule for every entry point — the CLI's
    /// `--valid-until`, the FFI's `valid_until`, and any Rust caller. They
    /// previously disagreed: the FFI refused `soon` while the CLI accepted it,
    /// opened or minted the sealed PQC key, and emitted a **signed** record
    /// carrying an expiry no consumer could evaluate. Two checks for one rule
    /// is how they drift, so there is one.
    ///
    /// # Errors
    /// [`VerifyError::IntegrityError`] if either instant is not RFC-3339, or
    /// if the window ends before it starts.
    pub fn checked(from: &'a str, until: Option<&'a str>) -> Result<Self, VerifyError> {
        let bad = |what: &str, v: &str| VerifyError::IntegrityError {
            message: format!("{what} must be an RFC-3339 instant, got {v:?}"),
        };
        let start =
            chrono::DateTime::parse_from_rfc3339(from).map_err(|_| bad("valid_from", from))?;
        if let Some(u) = until {
            let end = chrono::DateTime::parse_from_rfc3339(u).map_err(|_| bad("valid_until", u))?;
            if end <= start {
                return Err(VerifyError::IntegrityError {
                    message: format!(
                        "valid_until ({u}) must be after valid_from ({from}) — a window \
                         that closes before it opens is not an expiry"
                    ),
                });
            }
            // ONE canonical text form for the signed member (#268).
            //
            // `2027-08-19T00:00:00+02:00` and `2027-08-18T22:00:00Z` are the
            // same instant and different bytes. The subject binding compares
            // the top-level field against the signed envelope copy as TEXT,
            // and a consumer that round-trips the record through a typed
            // timestamp column — which CIRISPersist has — re-serializes the
            // column while the envelope stays opaque. The two then disagree
            // about a record nobody tampered with.
            //
            // A caller may pass any RFC-3339 form; what is PINNED is what gets
            // signed: UTC, `Z`, second precision.
            //
            // Deliberately NOT applied to `valid_from`: it is an existing
            // signed member, so rewriting it would change the canonical bytes
            // of every record already produced. That asymmetry is a
            // compatibility fact rather than a preference.
            return Ok(Self {
                from,
                until: Some(
                    end.with_timezone(&chrono::Utc)
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                ),
            });
        }
        Ok(Self { from, until: None })
    }

    /// The instant the key becomes valid (RFC-3339, validated).
    #[must_use]
    pub const fn from(&self) -> &'a str {
        self.from
    }

    /// The instant the key stops being valid, if it expires (RFC-3339,
    /// validated). `None` omits the member from the signed envelope entirely,
    /// reproducing the pre-14.0 canonical bytes.
    #[must_use]
    pub fn until(&self) -> Option<&str> {
        self.until.as_deref()
    }
}

/// Create a self-signed genesis federation identity from an already-opened
/// hardware Ed25519 signer.
///
/// `hw_signer` MUST be Ed25519 (the federation classical half) and its key MUST
/// already exist (the caller provisioned it). The ML-DSA-65 PQC half is a
/// TPM/SE-sealed seed (#71). `valid_from` is caller-supplied RFC-3339.
///
/// The `key_id` is, in order of precedence: `fed_key_id` if given; else
/// `derive_key_id(label, ed_pubkey)` (the FSD-003 `label-fingerprint` form) if
/// `label` is given; else `derive_key_id("id", …)`. The returned
/// [`CreatedIdentity::code`] is the shareable fedcode for `identity_type`.
///
/// `seal_alias` keys the **ML-DSA-65 seal storage** independently of the
/// recorded/encoded `key_id` (CIRISVerify#89). Pass `None` for the back-compat
/// default — the seal is keyed by `key_id`, exactly as before. Pass `Some(alias)`
/// to record under the derived `key_id` while sealing (and re-opening) the PQC
/// half under a **stable keystore alias** — so a switch to derived key_ids needs
/// no custody re-open / lockout for already-sealed seeds. The ML-DSA *pubkey* is
/// a function of the sealed *seed* (under `seal_alias`), not the alias string,
/// so the recorded record stays self-consistent and re-open by `seal_alias`
/// reproduces it. (CIRISServer's USER path: record under
/// `derive_key_id("<alias>-user", ed_pub)`, seal under the stable `<alias>-user`.)
///
/// `transport_hints` (CIRISVerify#172) are embedded inside the signed
/// `registration_envelope` so a baked/replicated record is self-describing
/// (WHO + HOW-TO-REACH). Pass `&[]` for an ordinary identity — the envelope is
/// then byte-identical to the pre-#172 shape.
///
/// # Errors
///
/// [`VerifyError`] if the signer is not Ed25519, the pubkey/seed cannot be
/// read, or signing fails.
pub async fn create_federation_identity(
    hw_signer: Arc<dyn HardwareSigner>,
    identity_type: &str,
    fed_key_id: Option<String>,
    label: Option<&str>,
    validity: Validity<'_>,
    seal_alias: Option<&str>,
    transport_hints: &[TransportHint],
) -> Result<CreatedIdentity, VerifyError> {
    let ed_pub = hw_signer.public_key().await.map_err(keyring_err)?;
    let key_id =
        fed_key_id.unwrap_or_else(|| crate::fedcode::derive_key_id(label.unwrap_or("id"), &ed_pub));

    // The ML-DSA-65 PQC half: TPM/SE-sealed at rest (#71). The 32-byte seed is
    // sealed under the platform secure storage (TPM with `--features tpm`,
    // Secure Enclave / StrongBox on mobile; software-sealed AES-GCM fallback
    // otherwise — never a plaintext file) and unsealed only transiently to
    // sign. Auto-generates + seals on first call, adopts the sealed seed after.
    //
    // #89: the seal is keyed by `seal_alias` when given (a stable keystore
    // alias), else by the recorded `key_id` (back-compat). Decoupling lets the
    // recorded key_id move to the derived form without re-sealing every seed.
    let seal_id = seal_alias.unwrap_or(&key_id);
    // CREATE is a deliberate mint-or-adopt: `open_or_create(None)` re-opens a
    // sealed seed if present, else mints + seals a fresh one. The bare factory
    // `get_platform_sealed_mldsa65_signer` is now **re-open-only** and fails
    // loud (CIRISVerify#134), so identity *creation* must use this explicit path.
    let mldsa: Box<dyn ciris_keyring::PqcSigner> = Box::new(
        ciris_keyring::SealedMlDsa65Signer::open_or_create(seal_id, keys_dir(), None)
            .map_err(keyring_err)?,
    );

    let identity = HardwareRootedIdentity::new(key_id.clone(), hw_signer, Arc::from(mldsa))?;
    let record = produce_self_key_record(
        &identity,
        identity_type,
        validity.from(),
        validity.until(),
        transport_hints,
    )
    .await?;
    let body = serde_json::to_value(&record).map_err(|e| VerifyError::IntegrityError {
        message: format!("serialize key record: {e}"),
    })?;

    let object = SignedCegObject::new(FEDERATION_KEY_RECORD_KIND, &key_id, validity.from(), body);

    // The shareable fedcode for this entity (FSD-003).
    let kind = match identity_type {
        "agent" => crate::fedcode::FedKind::Agent,
        "node" => crate::fedcode::FedKind::Node,
        _ => crate::fedcode::FedKind::User,
    };
    let code = crate::fedcode::encode(&crate::fedcode::FedCode {
        kind,
        key_id: key_id.clone(),
        pubkey_ed25519_base64: base64::engine::general_purpose::STANDARD.encode(&ed_pub),
        transport_hint: None,
        alias_hint: label.map(str::to_string),
        group_key_id: None,
    })
    .map_err(|e| VerifyError::IntegrityError {
        message: format!("encode fedcode: {e}"),
    })?;

    Ok(CreatedIdentity {
        key_id,
        object,
        code,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("ciris-fedid-{tag}-{}", std::process::id()))
    }

    #[tokio::test]
    // The env-serialization guard is intentionally held across the await — the
    // CIRIS_HOME env must stay set through the async create, and this is a
    // single-threaded test runtime (no deadlock risk).
    #[allow(clippy::await_holding_lock)]
    async fn create_identity_from_software_ed25519_signer() {
        // A software Ed25519 HardwareSigner stands in for a YubiKey / SE — the
        // core is backend-agnostic, so this exercises the whole flow.
        let _g = crate::ceg_outbox::CIRIS_HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tmp("create");
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var(crate::ceg_outbox::CIRIS_HOME_ENV, &dir);

        let hw: Arc<dyn HardwareSigner> =
            Arc::new(ciris_keyring::Ed25519SoftwareSigner::from_bytes(&[9u8; 32], "fed").unwrap());
        let created = create_federation_identity(
            hw,
            "user",
            None,
            Some("Eric Moore"),
            Validity::checked("2026-06-18T00:00:00Z", None).unwrap(),
            None,
            &[],
        )
        .await
        .unwrap();

        assert_eq!(created.object.kind, FEDERATION_KEY_RECORD_KIND);
        assert_eq!(created.object.key_id, created.key_id);
        // label-fingerprint key_id + a usercode fell out.
        assert!(
            created.key_id.starts_with("eric-moore-"),
            "got {}",
            created.key_id
        );
        assert!(created.code.starts_with("CIRIS-V2-"));
        assert_eq!(
            crate::fedcode::decode(&created.code).unwrap().kind,
            crate::fedcode::FedKind::User
        );
        // The body is the SignedKeyRecord wrapper { record: {...} } — the exact
        // `peer_key_record` shape CIRISServer accepts; signature inside `body`.
        let rec = &created.object.body["record"];
        assert_eq!(rec["scrub_key_id"], rec["key_id"], "self-signed genesis");
        assert_eq!(rec["identity_type"], "user");
        assert_eq!(rec["algorithm"], "hybrid");
        assert!(created.object.signatures.is_none());

        std::env::remove_var(crate::ceg_outbox::CIRIS_HOME_ENV);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn seal_alias_decouples_recorded_key_id_from_seal_storage() {
        // #89: record under the derived key_id, seal the ML-DSA half under a
        // stable keystore alias — and re-opening the seal by that alias must
        // reproduce the recorded ML-DSA pubkey (no custody migration).
        let _g = crate::ceg_outbox::CIRIS_HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tmp("seal-alias");
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var(crate::ceg_outbox::CIRIS_HOME_ENV, &dir);

        let hw: Arc<dyn HardwareSigner> =
            Arc::new(ciris_keyring::Ed25519SoftwareSigner::from_bytes(&[5u8; 32], "fed").unwrap());
        let recorded = "eric-moore-derivedfp00".to_string();
        let seal_alias = "stable-keystore-alias-user";
        let created = create_federation_identity(
            hw,
            "user",
            Some(recorded.clone()),
            Some("Eric Moore"),
            Validity::checked("2026-06-18T00:00:00Z", None).unwrap(),
            Some(seal_alias),
            &[],
        )
        .await
        .unwrap();

        // Recorded/encoded under the derived key_id, NOT the seal alias.
        assert_eq!(created.key_id, recorded);
        assert_eq!(created.object.key_id, recorded);
        assert_eq!(created.object.body["record"]["key_id"], recorded);
        assert_ne!(created.key_id, seal_alias);

        // The recorded ML-DSA pubkey == the seed sealed under `seal_alias`, so a
        // re-open by the alias (resolve_user_signer) reproduces it — no lockout.
        let recorded_mldsa_pub = created.object.body["record"]["pubkey_ml_dsa_65_base64"]
            .as_str()
            .unwrap();
        let reopened =
            ciris_keyring::get_platform_sealed_mldsa65_signer(seal_alias, keys_dir()).unwrap();
        let reopened_pub =
            base64::engine::general_purpose::STANDARD.encode(reopened.public_key().await.unwrap());
        assert_eq!(recorded_mldsa_pub, reopened_pub);

        std::env::remove_var(crate::ceg_outbox::CIRIS_HOME_ENV);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn transport_hints_land_in_the_signed_ceg_object() {
        // #172: a hint passed here rides inside the signed registration_envelope
        // in the emitted CEG object body — self-describing WHO + HOW-TO-REACH.
        let _g = crate::ceg_outbox::CIRIS_HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tmp("hints");
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var(crate::ceg_outbox::CIRIS_HOME_ENV, &dir);

        let hw: Arc<dyn HardwareSigner> =
            Arc::new(ciris_keyring::Ed25519SoftwareSigner::from_bytes(&[7u8; 32], "fed").unwrap());
        let created = create_federation_identity(
            hw,
            "node",
            Some("canonical-server-1".to_string()),
            None,
            Validity::checked("2026-07-02T00:00:00Z", None).unwrap(),
            None,
            &[TransportHint {
                kind: "ip".to_string(),
                destination: "108.61.242.236:4242".to_string(),
            }],
        )
        .await
        .unwrap();

        let env = &created.object.body["record"]["registration_envelope"];
        assert_eq!(env["transport_hints"][0]["kind"], "ip");
        assert_eq!(
            env["transport_hints"][0]["destination"],
            "108.61.242.236:4242"
        );

        std::env::remove_var(crate::ceg_outbox::CIRIS_HOME_ENV);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
