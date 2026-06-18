//! "Self at login" producer surface (CEG 0.15 §8.1.12.7, CIRISRegistry#65).
//!
//! CEG pins the canonical user-identity composition: a hybrid
//! hardware-rooted **user** key plus an **agent** occurrence form one Self,
//! and the app is *partnered + delegated* at login. CIRISVerify owns the
//! crypto + ceremony half. This module is the **producer** half — it
//! *emits* the signed claims that the existing verify-side evaluators
//! ([`crate::operational_admit`], [`crate::transport_binding`],
//! [`crate::threshold`]) consume. Producer and consumer are deliberately
//! coherent: every shape this module signs round-trips through the matching
//! verifier (see the module tests — that round-trip *is* the contract).
//!
//! ## Scope (CIRISVerify#63 — now hardware-rooted end-to-end)
//!
//! This module produces the federation-tier-promotable signed envelopes AND
//! roots the user key in hardware:
//!
//! - **The signing seam is [`SelfSigner`]** — every producer has a sync
//!   software path (over [`HybridSigningIdentity`]) and an `*_async` path over
//!   any [`SelfSigner`], so the user key may be software *or* hardware-rooted
//!   ([`HardwareRootedIdentity`]: Ed25519 in a Secure Enclave / Android
//!   StrongBox / TPM-sealed / YubiKey-PKCS#11 signer via the
//!   `ciris_keyring::user_identity` backends, CIRISVerify#80; ML-DSA-65 PQC
//!   half in software). The bound-hybrid wire bytes are identical either way.
//! - **WebAuthn/passkey is the [`PresencePolicy`] unlock factor** — a verified
//!   passkey assertion ([`verify_presence`]) gates the [`perform_self_at_login`]
//!   ceremony. Presence is an unlock, never the owner-binding signature.
//! - **[`perform_self_at_login`]** runs the whole bilateral ceremony (presence
//!   gate → user-signed delegation + partnership grant → occurrence-signed
//!   accept + transport binding → directory members), each piece round-tripped
//!   through its verifier in the module tests.
//!
//! The federation-tier-promotable signed envelopes:
//!
//! 1. [`sign_delegation`] — the `delegates_to(user → agent occurrence)`
//!    `org_membership` grant. Verifies through
//!    [`crate::operational_admit::resolve_role_authority`] (the §8.1.12.7.1
//!    role-chain path) / [`crate::threshold::verify_threshold_signatures`].
//! 2. [`sign_partnership_grant`] / [`sign_partnership_accept`] — the
//!    bilateral `consent:partnership_grant:v1` / `:accept:v1` envelopes
//!    (§8.1.11.x / §8.1.12.7). Hybrid-signed over `JCS(envelope)`; each
//!    half verifies as a threshold-1 bound signature, and the pair is
//!    cross-checked by `bilateral_pair_id`.
//! 3. [`sign_transport_binding`] — the `transport_destination`
//!    `identity_occurrence` binding (§5.6.8.8.1, AV-17). Produces a
//!    [`crate::transport_binding::TransportBinding`] that
//!    [`crate::transport_binding::verify_transport_binding`] accepts.
//!
//! ## The one signature format (matches every verifier byte-for-byte)
//!
//! Every signed unit here uses the federation **bound hybrid signature**:
//! Ed25519 over `JCS(envelope)`, then ML-DSA-65 over
//! `JCS(envelope) ‖ ed25519_sig` (the PQC half binds the classical half).
//! Canonicalization is [`crate::jcs::canonicalize`] (RFC 8785). The signed
//! output is the `{ signed_envelope, ed25519_signature_base64,
//! mldsa65_signature_base64 }` shape the verifiers consume. This is exactly
//! [`crate::threshold::verify_threshold_signatures`]'s rule at threshold 1,
//! which `resolve_role_authority` and `verify_transport_binding` both reuse
//! — so a signature produced here verifies there by construction.
//!
//! ## Fail-closed
//!
//! Signing can fail only on a genuine crypto-layer fault (canonicalization
//! of a structurally-impossible envelope, or a signer error); those surface
//! as [`VerifyError`]. There is no "soft" partial output — a function either
//! returns a fully-signed envelope or an error.

use std::sync::Arc;

use base64::Engine;
use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};
use ciris_keyring::{ClassicalAlgorithm, HardwareSigner};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::VerifyError;
use crate::jcs;
use crate::threshold::ThresholdMember;
use crate::transport_binding::{
    compute_destination_hash, EncryptionPubkeys, TransportBinding, TransportBindingSignature,
    TransportDestination,
};
use crate::webauthn::{verify_assertion, Assertion, AssertionOutcome, WebauthnError};

/// Standard base64 engine — the one the verifiers decode with.
fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// The positive `score` member of a `consent:partnership_*:v1` envelope (CEG
/// §8.1.12.7.1(a) — "score: positive (the affirmation)"). The seven-member set
/// pins the member *presence*; the affirmation value is `1` on both halves.
/// Producer and substrate MUST agree on this exact JSON number (it is part of
/// the JCS signing bytes) — flagged for Persist cross-confirmation on #76.
const PARTNERSHIP_AFFIRMATION_SCORE: i64 = 1;

/// A hybrid signing identity: a federation `key_id` plus its Ed25519 +
/// ML-DSA-65 keypair. This is the producer-side counterpart of a
/// [`ThresholdMember`] (which holds only the *public* halves).
///
/// Today this wraps software signers ([`Ed25519Signer`] / [`MlDsa65Signer`]).
/// When the hardware-rooting work (CIRISVerify#62/#65) lands, a hardware
/// signer can satisfy the same `sign(bytes) -> bound hybrid signature`
/// contract — the byte format produced here does not change, so downstream
/// verification is untouched. The hardware seam is therefore here, in the
/// identity, not in any of the `sign_*` functions below.
pub struct HybridSigningIdentity {
    key_id: String,
    ed: Ed25519Signer,
    mldsa: MlDsa65Signer,
}

/// The output of every `sign_*` function: an envelope plus its detached
/// bound hybrid signature, in the exact `{signed_envelope,
/// ed25519_signature_base64, mldsa65_signature_base64}` shape the verifiers
/// consume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEnvelope {
    /// The exact object whose `JCS` bytes were signed. Pass this, unmodified,
    /// to the verifier — re-defaulting or reserializing through a typed
    /// struct would change the bytes and break verification (§0.9).
    pub signed_envelope: Value,
    /// Ed25519 signature over `JCS(signed_envelope)`, base64 standard.
    pub ed25519_signature_base64: String,
    /// ML-DSA-65 signature over `JCS(signed_envelope) ‖ ed25519_sig`
    /// (bound), base64 standard.
    pub mldsa65_signature_base64: String,
}

impl HybridSigningIdentity {
    /// Construct from existing signers (the hardware seam — a hardware
    /// signer can be adapted to the same keypair here in future).
    #[must_use]
    pub fn new(key_id: impl Into<String>, ed: Ed25519Signer, mldsa: MlDsa65Signer) -> Self {
        Self {
            key_id: key_id.into(),
            ed,
            mldsa,
        }
    }

    /// Generate a fresh software hybrid identity (test / software-only use).
    ///
    /// # Errors
    ///
    /// [`VerifyError::IntegrityError`] if the ML-DSA-65 signer cannot be
    /// constructed (e.g. the `pqc-ml-dsa` feature is disabled).
    pub fn generate(key_id: impl Into<String>) -> Result<Self, VerifyError> {
        let mldsa = MlDsa65Signer::new().map_err(|e| VerifyError::IntegrityError {
            message: format!("ML-DSA-65 signer construction failed: {e}"),
        })?;
        Ok(Self::new(key_id, Ed25519Signer::random()?, mldsa))
    }

    /// This identity's federation `key_id`.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The [`ThresholdMember`] pinning this identity's public keys — the
    /// directory entry a verifier needs to bind a signature from this
    /// identity to its `key_id`. `role` is `None` (set it on the returned
    /// value for a founder/steward roster).
    ///
    /// # Errors
    ///
    /// [`VerifyError::IntegrityError`] if either public key cannot be read.
    pub fn directory_member(&self) -> Result<ThresholdMember, VerifyError> {
        let ed_pub = self.ed.public_key().map_err(crypto_err)?;
        let mldsa_pub = self.mldsa.public_key().map_err(crypto_err)?;
        Ok(ThresholdMember {
            member_id: self.key_id.clone(),
            ed25519_public_key_base64: b64().encode(ed_pub),
            mldsa65_public_key_base64: Some(b64().encode(mldsa_pub)),
            role: None,
        })
    }

    /// Hybrid-sign raw bytes with the bound-signature discipline: Ed25519
    /// over `bytes`, then ML-DSA-65 over `bytes ‖ ed25519_sig`. Returns the
    /// two base64 halves. This is the single primitive every `sign_*`
    /// function routes through, and it is byte-identical to the construction
    /// in [`crate::threshold`] / [`crate::transport_binding`].
    fn sign_bytes(&self, bytes: &[u8]) -> Result<(String, String), VerifyError> {
        let ed_sig = self.ed.sign(bytes).map_err(crypto_err)?;
        let mut bound = bytes.to_vec();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = self.mldsa.sign(&bound).map_err(crypto_err)?;
        Ok((b64().encode(&ed_sig), b64().encode(&pqc_sig)))
    }

    /// Canonicalize `envelope` with JCS and produce a [`SignedEnvelope`].
    fn sign_envelope(&self, envelope: Value) -> Result<SignedEnvelope, VerifyError> {
        let bytes = jcs::canonicalize(&envelope)?;
        let (ed, mldsa) = self.sign_bytes(&bytes)?;
        Ok(SignedEnvelope {
            signed_envelope: envelope,
            ed25519_signature_base64: ed,
            mldsa65_signature_base64: mldsa,
        })
    }
}

fn crypto_err(e: ciris_crypto::CryptoError) -> VerifyError {
    VerifyError::IntegrityError {
        message: format!("hybrid signing failed: {e}"),
    }
}

fn keyring_err(e: ciris_keyring::KeyringError) -> VerifyError {
    VerifyError::IntegrityError {
        message: format!("hardware signer fault: {e}"),
    }
}

// ===========================================================================
// The producer-side signing seam (CIRISVerify#63 hardware-rooting)
// ===========================================================================

/// The one signing seam every ceremony producer routes through.
///
/// `sign_delegation_async` / `sign_partnership_*_async` /
/// `sign_transport_binding_async` are written against this trait, so the same
/// CEG-pinned envelope shapes are bound-hybrid-signed *identically* whether
/// the federation key lives in software ([`HybridSigningIdentity`]) or is
/// hardware-rooted ([`HardwareRootedIdentity`] — Secure Enclave / Android
/// StrongBox / TPM-sealed / YubiKey-PKCS#11 via the
/// `ciris_keyring::user_identity` backends, CIRISVerify#80). The bound-hybrid
/// byte format is fixed by [`SelfSigner::sign_bound`]; downstream verification
/// is untouched by *where* the Ed25519 half is sealed.
///
/// The async signature is load-bearing: a hardware signer's `sign` is async
/// (it may touch a secure element / await a YubiKey touch). The software
/// identity satisfies it trivially (its inner sign is sync).
#[async_trait::async_trait]
pub trait SelfSigner: Send + Sync {
    /// This identity's federation `key_id`.
    fn key_id(&self) -> &str;

    /// The Ed25519 (classical) public key — 32 raw bytes.
    ///
    /// # Errors
    /// [`VerifyError::IntegrityError`] if the key cannot be read.
    async fn ed25519_public_key(&self) -> Result<Vec<u8>, VerifyError>;

    /// The ML-DSA-65 (PQC) public key — raw bytes.
    ///
    /// # Errors
    /// [`VerifyError::IntegrityError`] if the key cannot be read.
    async fn mldsa65_public_key(&self) -> Result<Vec<u8>, VerifyError>;

    /// Bound hybrid sign: Ed25519 over `bytes`, then ML-DSA-65 over
    /// `bytes ‖ ed25519_sig` (the PQC half binds the classical half). Returns
    /// `(ed25519_sig_base64, mldsa65_sig_base64)` — byte-identical to the
    /// software primitive `HybridSigningIdentity::sign_bytes`.
    ///
    /// # Errors
    /// [`VerifyError`] on a hardware-signer or crypto-layer fault.
    async fn sign_bound(&self, bytes: &[u8]) -> Result<(String, String), VerifyError>;

    /// The [`ThresholdMember`] pinning this identity's public keys — the
    /// directory entry a verifier binds a signature from this identity to.
    /// `role` is `None`.
    ///
    /// # Errors
    /// [`VerifyError::IntegrityError`] if either public key cannot be read.
    async fn directory_member(&self) -> Result<ThresholdMember, VerifyError> {
        let ed = self.ed25519_public_key().await?;
        let mldsa = self.mldsa65_public_key().await?;
        Ok(ThresholdMember {
            member_id: self.key_id().to_string(),
            ed25519_public_key_base64: b64().encode(ed),
            mldsa65_public_key_base64: Some(b64().encode(mldsa)),
            role: None,
        })
    }

    /// Canonicalize `envelope` (JCS, RFC 8785) and bound-hybrid-sign it into a
    /// [`SignedEnvelope`].
    ///
    /// # Errors
    /// [`VerifyError`] on a canonicalization or signer fault.
    async fn sign_envelope_async(&self, envelope: Value) -> Result<SignedEnvelope, VerifyError> {
        let bytes = jcs::canonicalize(&envelope)?;
        let (ed, mldsa) = self.sign_bound(&bytes).await?;
        Ok(SignedEnvelope {
            signed_envelope: envelope,
            ed25519_signature_base64: ed,
            mldsa65_signature_base64: mldsa,
        })
    }
}

#[async_trait::async_trait]
impl SelfSigner for HybridSigningIdentity {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    async fn ed25519_public_key(&self) -> Result<Vec<u8>, VerifyError> {
        self.ed.public_key().map_err(crypto_err)
    }

    async fn mldsa65_public_key(&self) -> Result<Vec<u8>, VerifyError> {
        self.mldsa.public_key().map_err(crypto_err)
    }

    async fn sign_bound(&self, bytes: &[u8]) -> Result<(String, String), VerifyError> {
        // Reuse the sync primitive — byte-identical to the hardware path below.
        self.sign_bytes(bytes)
    }
}

/// A **hardware-rooted** hybrid user identity (CIRISVerify#63).
///
/// The Ed25519 federation-signing half lives in a hardware
/// [`HardwareSigner`] — Secure Enclave / Android StrongBox / TPM-sealed
/// (CIRISVerify#70) / YubiKey-PKCS#11 (CIRISVerify#80), selected through the
/// `ciris_keyring::user_identity` backends. The ML-DSA-65 PQC half is software
/// (its seed sealed-at-rest by CIRISVerify#71 when constructed from a sealed
/// seed). **The signing seed never leaves the secure element** — only the
/// bound hybrid signature is exported.
///
/// Satisfies the same [`SelfSigner`] contract as the software
/// [`HybridSigningIdentity`], so every ceremony producer is
/// hardware/software-agnostic and the wire bytes are identical — a binding
/// signed here verifies through [`crate::threshold`] /
/// [`crate::operational_admit`] / [`crate::transport_binding`] exactly as a
/// software-signed one does.
///
/// The hardware signer MUST be Ed25519 ([`ClassicalAlgorithm::Ed25519`]) — the
/// federation signing algorithm. A P-256-only token is rejected at
/// [`HardwareRootedIdentity::new`] (fail-closed, not silently downgraded).
pub struct HardwareRootedIdentity {
    key_id: String,
    ed: Arc<dyn HardwareSigner>,
    mldsa: MlDsa65Signer,
}

impl HardwareRootedIdentity {
    /// Construct from a hardware Ed25519 signer plus the software ML-DSA-65
    /// PQC half.
    ///
    /// # Errors
    /// [`VerifyError::IntegrityError`] if `ed` is not an Ed25519 signer — the
    /// federation tier requires Ed25519 + ML-DSA-65, and a P-256 hardware key
    /// cannot stand in for the classical half.
    pub fn new(
        key_id: impl Into<String>,
        ed: Arc<dyn HardwareSigner>,
        mldsa: MlDsa65Signer,
    ) -> Result<Self, VerifyError> {
        if ed.algorithm() != ClassicalAlgorithm::Ed25519 {
            return Err(VerifyError::IntegrityError {
                message: format!(
                    "hardware-rooted federation key must be Ed25519, got {:?}",
                    ed.algorithm()
                ),
            });
        }
        Ok(Self {
            key_id: key_id.into(),
            ed,
            mldsa,
        })
    }

    /// This identity's federation `key_id`.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The hardware custody class of the Ed25519 signing half — what feeds the
    /// CEG §9.4 `hardware_class` / attestation surface a consumer reports.
    #[must_use]
    pub fn hardware_type(&self) -> ciris_keyring::HardwareType {
        self.ed.hardware_type()
    }
}

#[async_trait::async_trait]
impl SelfSigner for HardwareRootedIdentity {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    async fn ed25519_public_key(&self) -> Result<Vec<u8>, VerifyError> {
        self.ed.public_key().await.map_err(keyring_err)
    }

    async fn mldsa65_public_key(&self) -> Result<Vec<u8>, VerifyError> {
        self.mldsa.public_key().map_err(crypto_err)
    }

    async fn sign_bound(&self, bytes: &[u8]) -> Result<(String, String), VerifyError> {
        // Ed25519 in hardware (async — may await a secure-element / touch), then
        // ML-DSA-65 in software over `bytes ‖ ed_sig`. Byte-identical bound
        // construction to HybridSigningIdentity::sign_bytes.
        let ed_sig = self.ed.sign(bytes).await.map_err(keyring_err)?;
        let mut bound = bytes.to_vec();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = self.mldsa.sign(&bound).map_err(crypto_err)?;
        Ok((b64().encode(&ed_sig), b64().encode(&pqc_sig)))
    }
}

// ===========================================================================
// 1. delegates_to(user -> agent occurrence) — org_membership grant
// ===========================================================================

/// Hybrid-sign a `delegates_to(user → agent occurrence)` `org_membership`
/// grant (CEG §8.1.12.7.1). `granter` (a user / steward / org admin key)
/// asserts that `subject_key_id` (the agent occurrence) holds `role` in
/// `org_id`, with `status: "active"`.
///
/// The produced [`SignedEnvelope`] maps directly onto
/// [`crate::operational_admit::MembershipGrant`]: its `signed_envelope`
/// carries the `user_id` / `org_id` / `role` / `status` /
/// `attesting_key_id` members `resolve_role_authority` reads, and its two
/// signature halves are the bound hybrid signature that
/// [`crate::threshold::verify_threshold_signatures`] checks at threshold 1.
/// So a grant signed here, with `granter` pinned as a `root_steward` (or via
/// an `OrgAdmin` chain), is authorized by `resolve_role_authority`.
///
/// `role` is the wire string (`"org_admin"` / `"key_manager"` / `"operator"`
/// / `"viewer"`) — the same `OrgRole` wire form the verifier parses.
///
/// # Errors
///
/// [`VerifyError`] only on a canonicalization or signer fault.
pub fn sign_delegation(
    granter: &HybridSigningIdentity,
    subject_key_id: &str,
    org_id: &str,
    role: &str,
    status: &str,
) -> Result<SignedEnvelope, VerifyError> {
    granter.sign_envelope(delegation_envelope(
        &granter.key_id,
        subject_key_id,
        org_id,
        role,
        status,
    ))
}

/// Hardware-rooted async variant of [`sign_delegation`] — same envelope, signed
/// through any [`SelfSigner`] (software or hardware-rooted).
///
/// # Errors
///
/// [`VerifyError`] only on a canonicalization or signer fault.
pub async fn sign_delegation_async(
    granter: &dyn SelfSigner,
    subject_key_id: &str,
    org_id: &str,
    role: &str,
    status: &str,
) -> Result<SignedEnvelope, VerifyError> {
    granter
        .sign_envelope_async(delegation_envelope(
            granter.key_id(),
            subject_key_id,
            org_id,
            role,
            status,
        ))
        .await
}

/// The canonical `delegates_to` `org_membership` envelope (§8.1.12.7.1) —
/// shared by the sync and async producers so the signed bytes can never drift.
fn delegation_envelope(
    attesting_key_id: &str,
    subject_key_id: &str,
    org_id: &str,
    role: &str,
    status: &str,
) -> Value {
    json!({
        "user_id": subject_key_id,
        "org_id": org_id,
        "role": role,
        "status": status,
        "attesting_key_id": attesting_key_id,
    })
}

// ===========================================================================
// 2. Bilateral partnership: consent:partnership_grant:v1 / :accept:v1
// ===========================================================================

/// Hybrid-sign the `consent:partnership_grant:v1` envelope (CEG §8.1.11.x /
/// §8.1.12.7). `granter` (the **user** key) initiates a bilateral
/// partnership with `partner_key_id` (the **agent** occurrence), scoped to
/// `bilateral_pair_id` — the stable join key that ties the grant to its
/// matching accept.
///
/// **Member set pinned by CEG 1.0-RC7 §8.1.12.7.1(a)** (CIRISRegistry#81):
/// the bare-`scores` shape with EXACTLY seven REQUIRED members —
/// `attestation_type:"scores"`, `attesting_key_id` (the signer = granter),
/// `dimension:"consent:partnership_grant:v1"`, `score` (positive affirmation),
/// `subject_key_ids:[partner_key_id]` (the OTHER party, single-element array),
/// `bilateral_pair_id`, `signed_at`. **No `valid_until`** — a PARTNERED pair
/// has no expiry (omitted, not null). Both impls MUST canonicalize exactly
/// this set or the JCS bytes — and the hybrid signatures — diverge.
///
/// The output verifies as a threshold-1 bound hybrid signature against the
/// granter's pinned pubkeys (the [`crate::threshold`] rule), exactly like a
/// `MembershipGrant` signature.
///
/// # Errors
///
/// [`VerifyError`] only on a canonicalization or signer fault.
pub fn sign_partnership_grant(
    granter: &HybridSigningIdentity,
    partner_key_id: &str,
    bilateral_pair_id: &str,
    signed_at: &str,
) -> Result<SignedEnvelope, VerifyError> {
    granter.sign_envelope(partnership_envelope(
        "consent:partnership_grant:v1",
        &granter.key_id,
        partner_key_id,
        bilateral_pair_id,
        signed_at,
    ))
}

/// Hardware-rooted async variant of [`sign_partnership_grant`].
///
/// # Errors
///
/// [`VerifyError`] only on a canonicalization or signer fault.
pub async fn sign_partnership_grant_async(
    granter: &dyn SelfSigner,
    partner_key_id: &str,
    bilateral_pair_id: &str,
    signed_at: &str,
) -> Result<SignedEnvelope, VerifyError> {
    granter
        .sign_envelope_async(partnership_envelope(
            "consent:partnership_grant:v1",
            granter.key_id(),
            partner_key_id,
            bilateral_pair_id,
            signed_at,
        ))
        .await
}

/// The canonical bilateral-partnership envelope (CEG 1.0-RC7 §8.1.12.7.1(a)):
/// EXACTLY the seven REQUIRED members, bare-`scores` shape. `attesting_key_id`
/// is the signer; `subject_key_ids` is the single-element array of the OTHER
/// party (set-sorted trivially); NO `valid_until` (a PARTNERED pair has no
/// expiry — omitted, not null). `dimension` selects grant vs accept. JCS sorts
/// keys, so member order here is irrelevant to the signed bytes. Shared by the
/// sync and async producers so the JCS signing bytes can never drift.
fn partnership_envelope(
    dimension: &str,
    attesting_key_id: &str,
    other_party_key_id: &str,
    bilateral_pair_id: &str,
    signed_at: &str,
) -> Value {
    json!({
        "attestation_type": "scores",
        "attesting_key_id": attesting_key_id,
        "dimension": dimension,
        "score": PARTNERSHIP_AFFIRMATION_SCORE,
        "subject_key_ids": [other_party_key_id],
        "bilateral_pair_id": bilateral_pair_id,
        "signed_at": signed_at,
    })
}

/// Hybrid-sign the `consent:partnership_accept:v1` envelope — the matching
/// half of [`sign_partnership_grant`]. `accepter` (the **agent** occurrence
/// key, i.e. the `partner_key_id` of the grant) accepts the partnership
/// identified by the same `bilateral_pair_id`.
///
/// The `bilateral_pair_id` MUST equal the grant's, and `granter_key_id` MUST
/// name the original granter — that is what ties the two unilateral signed
/// envelopes into one bilateral partnership. Both envelopes are independently
/// bound-hybrid-signed by their respective signers, each verifiable at
/// threshold 1 against that signer's pinned pubkeys.
///
/// # Errors
///
/// [`VerifyError`] only on a canonicalization or signer fault.
pub fn sign_partnership_accept(
    accepter: &HybridSigningIdentity,
    granter_key_id: &str,
    bilateral_pair_id: &str,
    signed_at: &str,
) -> Result<SignedEnvelope, VerifyError> {
    accepter.sign_envelope(partnership_envelope(
        "consent:partnership_accept:v1",
        &accepter.key_id,
        granter_key_id,
        bilateral_pair_id,
        signed_at,
    ))
}

/// Hardware-rooted async variant of [`sign_partnership_accept`].
///
/// # Errors
///
/// [`VerifyError`] only on a canonicalization or signer fault.
pub async fn sign_partnership_accept_async(
    accepter: &dyn SelfSigner,
    granter_key_id: &str,
    bilateral_pair_id: &str,
    signed_at: &str,
) -> Result<SignedEnvelope, VerifyError> {
    accepter
        .sign_envelope_async(partnership_envelope(
            "consent:partnership_accept:v1",
            accepter.key_id(),
            granter_key_id,
            bilateral_pair_id,
            signed_at,
        ))
        .await
}

// ===========================================================================
// 3. transport_destination binding (§5.6.8.8.1, AV-17)
// ===========================================================================

/// The transport-identity material to bind to an occurrence — produced
/// out-of-band (a fresh dual-key RNS identity + content-KEM keys), kept
/// **separate** from the federation signing key (AV-17: the signing seed
/// never enters Reticulum). All byte payloads are raw (pre-base64); the
/// signer base64-encodes them into the signed envelope.
pub struct TransportIdentityMaterial<'a> {
    /// Transport RNS X25519 (encryption) pubkey, 32 raw bytes.
    pub reticulum_x25519_pubkey: &'a [u8],
    /// Transport RNS Ed25519 (signing) pubkey, 32 raw bytes. MUST NOT equal
    /// the federation signing key (AV-17) — the verifier rejects equality.
    pub reticulum_ed25519_pubkey: &'a [u8],
    /// RNS app name (e.g. `"ciris.federation"`).
    pub app_name: &'a str,
    /// RNS aspects (ordered — part of the hash preimage, NOT sorted).
    pub aspects: &'a [String],
    /// Optional content-KEM keys (§5.6.8.8.2). When present, the X25519 half
    /// MUST differ from the transport X25519 (C4 — the verifier rejects
    /// reuse). `(x25519_32_bytes, ml_kem_768_1184_bytes)`.
    pub encryption: Option<(&'a [u8], &'a [u8])>,
}

/// Hybrid-sign a `transport_destination` `identity_occurrence` binding (CEG
/// §5.6.8.8.1, AV-17). `signer` is the occurrence's **federation signing
/// key**; it authorizes the bound dual-key RNS transport identity in `mat`.
///
/// Returns a fully-assembled [`TransportBinding`] — `signed_envelope` is the
/// `identity_occurrence` object (with the `transport_destination` and,
/// if present, `encryption_pubkeys` members), bound-hybrid-signed over its
/// `JCS` bytes. Feed it straight to
/// [`crate::transport_binding::verify_transport_binding`] with a directory
/// pinning `signer`'s pubkeys; it returns `authentic: true`.
///
/// The producer is responsible for the key-separation invariants the
/// verifier enforces: `mat.reticulum_ed25519_pubkey` must differ from
/// `signer`'s Ed25519 key (AV-17), and any content-KEM X25519 must differ
/// from the transport X25519 (§5.6.8.8.2 C4). This function does not
/// silently "fix" a violation — it signs what it is given, and a violating
/// binding is then *rejected* by the verifier (proving the producer cannot
/// smuggle a reused key past verification).
///
/// # Errors
///
/// [`VerifyError`] on a canonicalization or signer fault. (Malformed key
/// lengths are a *verifier* concern, surfaced as a fail-closed verdict, not
/// a producer error — mirroring the verify-side contract.)
pub fn sign_transport_binding(
    signer: &HybridSigningIdentity,
    occurrence_key_id: &str,
    device_class: &str,
    mat: &TransportIdentityMaterial<'_>,
    signed_at: &str,
) -> Result<TransportBinding, VerifyError> {
    let (envelope, td, enc) = transport_envelope(
        &signer.key_id,
        occurrence_key_id,
        device_class,
        mat,
        signed_at,
    )?;
    let bytes = jcs::canonicalize(&envelope)?;
    let (ed_sig, mldsa_sig) = signer.sign_bytes(&bytes)?;
    Ok(assemble_transport_binding(
        signer.key_id.clone(),
        envelope,
        td,
        enc,
        ed_sig,
        mldsa_sig,
    ))
}

/// Hardware-rooted async variant of [`sign_transport_binding`] — same
/// occurrence envelope, signed through any [`SelfSigner`].
///
/// # Errors
///
/// [`VerifyError`] on a canonicalization or signer fault.
pub async fn sign_transport_binding_async(
    signer: &dyn SelfSigner,
    occurrence_key_id: &str,
    device_class: &str,
    mat: &TransportIdentityMaterial<'_>,
    signed_at: &str,
) -> Result<TransportBinding, VerifyError> {
    let (envelope, td, enc) = transport_envelope(
        signer.key_id(),
        occurrence_key_id,
        device_class,
        mat,
        signed_at,
    )?;
    let bytes = jcs::canonicalize(&envelope)?;
    let (ed_sig, mldsa_sig) = signer.sign_bound(&bytes).await?;
    Ok(assemble_transport_binding(
        signer.key_id().to_string(),
        envelope,
        td,
        enc,
        ed_sig,
        mldsa_sig,
    ))
}

/// Build the `transport_destination` occurrence envelope (§5.6.8.8.1, AV-17)
/// plus its parsed [`TransportDestination`] / [`EncryptionPubkeys`]. Shared by
/// the sync and async producers; the only difference between them is which
/// signer produces the two bound-hybrid halves.
fn transport_envelope(
    signer_key_id: &str,
    occurrence_key_id: &str,
    device_class: &str,
    mat: &TransportIdentityMaterial<'_>,
    signed_at: &str,
) -> Result<(Value, TransportDestination, Option<EncryptionPubkeys>), VerifyError> {
    // Derive the destination_hash from the same §5.6.8.8.1.1 algorithm the
    // verifier recomputes — a producer never carries an arbitrary hash, or it
    // fails the consumer's recompute. `None` iff an aspect carries an illegal
    // `.` (producer-side input error).
    let dest_hash = compute_destination_hash(
        mat.app_name,
        mat.aspects,
        mat.reticulum_x25519_pubkey,
        mat.reticulum_ed25519_pubkey,
    )
    .ok_or_else(|| VerifyError::IntegrityError {
        message: "transport aspect contains an illegal '.' (§5.6.8.8.1.1)".to_string(),
    })?;
    let td = TransportDestination {
        reticulum_x25519_pubkey_base64: b64().encode(mat.reticulum_x25519_pubkey),
        reticulum_ed25519_pubkey_base64: b64().encode(mat.reticulum_ed25519_pubkey),
        destination_hash_base64: b64().encode(dest_hash),
        app_name: mat.app_name.to_string(),
        aspects: mat.aspects.to_vec(),
    };
    let enc = mat.encryption.map(|(x, ml_kem)| EncryptionPubkeys {
        x25519_base64: b64().encode(x),
        ml_kem_768_base64: b64().encode(ml_kem),
    });

    // The signed occurrence envelope (§8.1.12.7.1(c)). It embeds the
    // transport_destination (and encryption_pubkeys, if present) as members
    // so the hybrid signature covers them + the destination_hash. Mirror the
    // member shape verify_transport_binding's fixtures parse from.
    let mut envelope = json!({
        "attestation_type": "scores",
        "subject_kind": "identity_occurrence",
        "attesting_key_id": signer_key_id,
        "identity_key_id": signer_key_id,
        "occurrence_key_id": occurrence_key_id,
        "device_class": device_class,
        "transport_destination": {
            "reticulum_x25519_pubkey": td.reticulum_x25519_pubkey_base64,
            "reticulum_ed25519_pubkey": td.reticulum_ed25519_pubkey_base64,
            "destination_hash": td.destination_hash_base64,
            "app_name": td.app_name,
            "aspects": td.aspects,
        },
        "signed_at": signed_at,
    });
    if let Some(enc) = &enc {
        envelope["encryption_pubkeys"] = json!({
            "x25519_base64": enc.x25519_base64,
            "ml_kem_768_base64": enc.ml_kem_768_base64,
        });
    }
    Ok((envelope, td, enc))
}

fn assemble_transport_binding(
    attesting_key_id: String,
    envelope: Value,
    td: TransportDestination,
    enc: Option<EncryptionPubkeys>,
    ed_sig: String,
    mldsa_sig: String,
) -> TransportBinding {
    TransportBinding {
        attesting_key_id,
        signed_envelope: envelope,
        transport_destination: td,
        encryption_pubkeys: enc,
        signature: TransportBindingSignature {
            ed25519_signature_base64: ed_sig,
            mldsa65_signature_base64: Some(mldsa_sig),
        },
    }
}

/// Convert a [`SignedEnvelope`] into an
/// [`crate::operational_admit::MembershipGrant`] — the verify-side type the
/// role-chain resolver consumes. Convenience for the delegation path.
#[must_use]
pub fn as_membership_grant(signed: &SignedEnvelope) -> crate::operational_admit::MembershipGrant {
    crate::operational_admit::MembershipGrant {
        signed_envelope: signed.signed_envelope.clone(),
        ed25519_signature_base64: signed.ed25519_signature_base64.clone(),
        mldsa65_signature_base64: Some(signed.mldsa65_signature_base64.clone()),
    }
}

// ===========================================================================
// 3b. occurrence revocation — "revoke the lost / stolen device" (CEG §11.7)
// ===========================================================================

/// Hybrid-sign an `identity_occurrence` **revocation** — the cryptographic
/// authorization to remove a device (occurrence) from your identity (CEG
/// §11.7.1 Option-A forward-secrecy removal). This is the producer half of
/// "revoke the lost one": `revoker` is a **surviving** key, and it signs a
/// revocation of `revoked_occurrence_key_id` under `identity_key_id`.
///
/// **Use a surviving key.** Per §11.7.4 the vouch (`witness_set`) is single —
/// "the revoking occurrence OR the `identity_key_id`". For a *stolen* device
/// you must revoke with a **different** key you still control (another enrolled
/// occurrence, or the identity root) — never the compromised key. This is the
/// concrete reason the OR-of-N redundancy ([`crate::self_at_login`] multi-key
/// enrollment) matters: with only one key you cannot authorize its own
/// removal. The producer does not forbid `revoker == revoked` (a *voluntary*
/// leave may self-revoke), but the stolen-device flow MUST NOT.
///
/// The signed envelope's members map onto CIRISPersist's
/// `IdentityOccurrenceRevocation` row (minus the server-computed
/// `persist_row_hash`): `identity_key_id`, `occurrence_key_id`, `revoked_at`,
/// `effective_at`, optional `reason`, and `witness_set: [revoker_key_id]`.
/// `revoked_at` / `effective_at` are caller-supplied RFC-3339 (this module is
/// clock-free so the signed bytes are reproducible); `effective_at` may be
/// future-dated. The bound hybrid signature verifies at threshold 1 against the
/// revoker's pinned pubkeys — the same primitive
/// ([`crate::threshold::verify_threshold_signatures`]) the admission boundary
/// reuses — so Registry/Server can verify the authorization before writing the
/// row through to Persist (whose merge logic never counts signatures, §5.6.8.13).
///
/// **Cross-impl flag:** the member set is pinned to the Persist row shape but
/// the *signed-envelope framing* (member names + the `witness_set` single-vouch)
/// is flagged for CIRISServer/Registry cross-confirmation — like the #76
/// partnership seven-member set was.
///
/// # Errors
///
/// [`VerifyError`] only on a canonicalization or signer fault.
pub async fn sign_occurrence_revocation(
    revoker: &dyn SelfSigner,
    identity_key_id: &str,
    revoked_occurrence_key_id: &str,
    reason: Option<&str>,
    revoked_at: &str,
    effective_at: &str,
) -> Result<SignedEnvelope, VerifyError> {
    revoker
        .sign_envelope_async(occurrence_revocation_envelope(
            identity_key_id,
            revoked_occurrence_key_id,
            reason,
            revoked_at,
            effective_at,
            revoker.key_id(),
        ))
        .await
}

/// The canonical occurrence-revocation envelope (CEG §11.7) — members map to
/// the Persist `IdentityOccurrenceRevocation` row. `reason` is omitted (not
/// null) when absent (§0.9 omit-vs-materialize). `witness_set` is the single
/// vouch `[revoker_key_id]` (§11.7.4).
fn occurrence_revocation_envelope(
    identity_key_id: &str,
    revoked_occurrence_key_id: &str,
    reason: Option<&str>,
    revoked_at: &str,
    effective_at: &str,
    revoker_key_id: &str,
) -> Value {
    let mut env = json!({
        "identity_key_id": identity_key_id,
        "occurrence_key_id": revoked_occurrence_key_id,
        "revoked_at": revoked_at,
        "effective_at": effective_at,
        "witness_set": [revoker_key_id],
    });
    if let Some(reason) = reason {
        env["reason"] = json!(reason);
    }
    env
}

// ===========================================================================
// 4. The unified login ceremony (CIRISVerify#63): WebAuthn presence + bundle
// ===========================================================================

/// The WebAuthn/passkey **presence** policy that gates the login ceremony
/// (CIRISVerify#63). Presence is an *unlock* factor — proof a human is at the
/// device — NOT the owner-binding signature. The hardware-rooted
/// [`SelfSigner`] still produces every federation signature; a verified
/// passkey only authorizes the ceremony to run.
///
/// `rp_id` / `origins` are the anti-phishing binding (exact-match — a passkey
/// minted for another origin cannot unlock here). Set `require_user_verified`
/// for high-assurance presence (the authenticator did a biometric/PIN, not a
/// bare tap) — recommended for a federation-key ceremony.
pub struct PresencePolicy<'a> {
    /// The relying-party id the passkey is scoped to (e.g. `"ciris.ai"`).
    pub rp_id: &'a str,
    /// The exact allowed `origin`(s) of the `clientDataJSON`.
    pub origins: &'a [&'a str],
    /// Require the User-Verified flag (biometric/PIN), not just User-Present.
    pub require_user_verified: bool,
}

/// Verify the passkey **presence** assertion that unlocks the ceremony.
///
/// A thin, intent-named wrapper over [`verify_assertion`]: it makes the
/// "presence, not owner-binding" contract explicit at the call site. Returns
/// the [`AssertionOutcome`] (the `sign_count` for the caller's stateful
/// clone-detection, and whether UV was set).
///
/// # Errors
///
/// [`WebauthnError`] if any checkable step fails — the single fail-closed
/// presence signal.
pub fn verify_presence(
    assertion: &Assertion<'_>,
    expected_challenge: &[u8],
    policy: &PresencePolicy<'_>,
) -> Result<AssertionOutcome, WebauthnError> {
    verify_assertion(
        assertion,
        expected_challenge,
        policy.rp_id,
        policy.origins,
        policy.require_user_verified,
    )
}

/// The fixed inputs for one self-at-login ceremony.
pub struct LoginInputs<'a> {
    /// The org the occurrence is delegated into.
    pub org_id: &'a str,
    /// The `OrgRole` wire string granted to the occurrence (e.g. `"operator"`).
    pub role: &'a str,
    /// The agent-occurrence federation `key_id` (the partner / delegate).
    pub occurrence_key_id: &'a str,
    /// The stable join key tying the partnership grant to its accept.
    pub bilateral_pair_id: &'a str,
    /// The occurrence's device class (for the transport binding / §9.4).
    pub device_class: &'a str,
    /// The occurrence's transport-identity material (kept separate from the
    /// federation signing key — AV-17).
    pub transport: &'a TransportIdentityMaterial<'a>,
    /// RFC 3339 ceremony timestamp (the caller supplies it — this module is
    /// clock-free so the signed bytes are reproducible).
    pub signed_at: &'a str,
}

/// The complete bilateral self-at-login output — every signed claim a
/// downstream verifier needs to admit the (user + occurrence) Self.
pub struct SelfAtLoginBundle {
    /// The verified passkey presence outcome (sign_count, user_verified).
    pub presence: AssertionOutcome,
    /// The user key's directory entry (pin its pubkeys to verify the grants).
    pub user_directory_member: ThresholdMember,
    /// The occurrence key's directory entry.
    pub occurrence_directory_member: ThresholdMember,
    /// `delegates_to(user → occurrence)` `org_membership` grant — user-signed.
    pub delegation: SignedEnvelope,
    /// `consent:partnership_grant:v1` — user-signed.
    pub partnership_grant: SignedEnvelope,
    /// `consent:partnership_accept:v1` — occurrence-signed.
    pub partnership_accept: SignedEnvelope,
    /// `transport_destination` occurrence binding — occurrence-signed.
    pub transport_binding: TransportBinding,
}

/// Run the full self-at-login ceremony (CIRISVerify#63).
///
/// 1. **Gate on presence** — the passkey assertion must verify under `policy`
///    (fail-closed: a [`WebauthnError`] aborts the ceremony, nothing is
///    signed).
/// 2. The hardware-rooted **`user`** identity signs the
///    `delegates_to(user → occurrence)` grant and the partnership grant.
/// 3. The **`occurrence`** identity signs the matching partnership accept and
///    its own transport binding.
///
/// Every produced envelope round-trips through its verifier
/// ([`crate::operational_admit`] / [`crate::threshold`] /
/// [`crate::transport_binding`]) against the directory members returned here —
/// that round-trip is the contract (see the ceremony test).
///
/// `user` and `occurrence` are both [`SelfSigner`]s, so either may be
/// hardware-rooted ([`HardwareRootedIdentity`]) or software
/// ([`HybridSigningIdentity`]) — the wire bytes are identical.
///
/// # Errors
///
/// [`VerifyError::IntegrityError`] if presence fails to verify, or any
/// [`VerifyError`] from a canonicalization / signer fault.
#[allow(clippy::too_many_arguments)]
pub async fn perform_self_at_login(
    user: &dyn SelfSigner,
    occurrence: &dyn SelfSigner,
    presence_assertion: &Assertion<'_>,
    presence_challenge: &[u8],
    policy: &PresencePolicy<'_>,
    inputs: &LoginInputs<'_>,
) -> Result<SelfAtLoginBundle, VerifyError> {
    // 1. Presence gate — fail-closed before any federation signature is made.
    let presence =
        verify_presence(presence_assertion, presence_challenge, policy).map_err(|e| {
            VerifyError::IntegrityError {
                message: format!("self-at-login presence verification failed: {e:?}"),
            }
        })?;

    // 2. User-signed: delegation + partnership grant.
    let delegation = sign_delegation_async(
        user,
        inputs.occurrence_key_id,
        inputs.org_id,
        inputs.role,
        "active",
    )
    .await?;
    let partnership_grant = sign_partnership_grant_async(
        user,
        inputs.occurrence_key_id,
        inputs.bilateral_pair_id,
        inputs.signed_at,
    )
    .await?;

    // 3. Occurrence-signed: partnership accept + transport binding.
    let partnership_accept = sign_partnership_accept_async(
        occurrence,
        user.key_id(),
        inputs.bilateral_pair_id,
        inputs.signed_at,
    )
    .await?;
    let transport_binding = sign_transport_binding_async(
        occurrence,
        inputs.occurrence_key_id,
        inputs.device_class,
        inputs.transport,
        inputs.signed_at,
    )
    .await?;

    Ok(SelfAtLoginBundle {
        presence,
        user_directory_member: user.directory_member().await?,
        occurrence_directory_member: occurrence.directory_member().await?,
        delegation,
        partnership_grant,
        partnership_accept,
        transport_binding,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operational_admit::{resolve_role_authority, AuthorizationReason, OrgRole};
    use crate::threshold::{verify_threshold_signatures, ThresholdSignature};
    use crate::transport_binding::{verify_transport_binding, TransportBindingReason};

    fn pubkey_bytes(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    /// Build the threshold-1 signature view of a SignedEnvelope, the way a
    /// verifier reconstructs it.
    fn threshold_sig(key_id: &str, signed: &SignedEnvelope) -> ThresholdSignature {
        ThresholdSignature {
            member_id: key_id.to_string(),
            ed25519_signature_base64: signed.ed25519_signature_base64.clone(),
            mldsa65_signature_base64: Some(signed.mldsa65_signature_base64.clone()),
        }
    }

    // ---- 1. delegation round-trips through resolve_role_authority --------

    #[test]
    fn delegation_verifies_through_resolve_role_authority() {
        // A user (steward root) delegates Operator authority to an agent
        // occurrence. resolve_role_authority must authorize the occurrence.
        let user = HybridSigningIdentity::generate("user-steward-1").unwrap();
        let agent_occ = "agent-occ-1";

        let signed = sign_delegation(&user, agent_occ, "org-x", "operator", "active").unwrap();
        let grant = as_membership_grant(&signed);

        let dir = vec![user.directory_member().unwrap()];
        let roots = vec!["user-steward-1".to_string()];

        let v = resolve_role_authority(
            agent_occ,
            "org-x",
            OrgRole::Operator,
            &[grant],
            &dir,
            &roots,
        );
        assert!(
            v.authorized,
            "a delegation signed by sign_delegation, granter pinned as a root \
             steward, must authorize the occurrence via resolve_role_authority"
        );
        assert!(v.root_anchored);
        assert_eq!(v.established_by.as_deref(), Some("user-steward-1"));
        assert_eq!(v.reason, AuthorizationReason::Authorized);
    }

    #[test]
    fn delegation_signature_verifies_at_threshold_one() {
        // The lower-level proof: the raw bound hybrid signature verifies via
        // verify_threshold_signatures (the primitive resolve_role_authority
        // and verify_transport_binding both reuse).
        let user = HybridSigningIdentity::generate("user-1").unwrap();
        let signed = sign_delegation(&user, "agent-1", "org-x", "org_admin", "active").unwrap();

        let bytes = jcs::canonicalize(&signed.signed_envelope).unwrap();
        let member = user.directory_member().unwrap();
        let sig = threshold_sig("user-1", &signed);

        assert_eq!(
            verify_threshold_signatures(&bytes, &[member], &[sig], 1),
            Ok(1),
            "the produced bound hybrid signature must verify at threshold 1"
        );
    }

    #[test]
    fn tampered_delegation_envelope_is_rejected() {
        // Negative: tamper the signed envelope after signing → JCS bytes
        // change → resolve_role_authority denies (chain not anchored, because
        // the grant signature no longer binds).
        let user = HybridSigningIdentity::generate("user-steward-1").unwrap();
        let mut signed =
            sign_delegation(&user, "agent-occ-1", "org-x", "viewer", "active").unwrap();
        // Privilege-escalate the role after signing.
        signed.signed_envelope["role"] = json!("org_admin");
        let grant = as_membership_grant(&signed);

        let dir = vec![user.directory_member().unwrap()];
        let roots = vec!["user-steward-1".to_string()];

        let v = resolve_role_authority(
            "agent-occ-1",
            "org-x",
            OrgRole::OrgAdmin,
            &[grant],
            &dir,
            &roots,
        );
        assert!(
            !v.authorized,
            "tampering the role after signing must break the binding and deny"
        );
        assert_eq!(v.reason, AuthorizationReason::ChainNotAnchored);
    }

    #[test]
    fn delegation_signed_by_wrong_key_does_not_bind() {
        // Negative: an attacker signs a grant CLAIMING to be from the user
        // steward, but the directory pins the steward to the REAL keys.
        let real_user = HybridSigningIdentity::generate("user-steward-1").unwrap();
        let attacker = HybridSigningIdentity::new(
            "user-steward-1", // claims the steward's key_id
            Ed25519Signer::random().unwrap(),
            MlDsa65Signer::new().unwrap(),
        );

        let forged = sign_delegation(&attacker, "agent-1", "org-x", "org_admin", "active").unwrap();
        let grant = as_membership_grant(&forged);

        // Directory pins the steward key_id to the REAL user's pubkeys.
        let dir = vec![real_user.directory_member().unwrap()];
        let roots = vec!["user-steward-1".to_string()];

        let v = resolve_role_authority(
            "agent-1",
            "org-x",
            OrgRole::OrgAdmin,
            &[grant],
            &dir,
            &roots,
        );
        assert!(
            !v.authorized,
            "a forged grant must not bind to the steward key_id"
        );
    }

    // ---- 2. partnership grant / accept ----------------------------------

    #[test]
    fn partnership_grant_and_accept_verify_at_threshold_one() {
        let user = HybridSigningIdentity::generate("user-1").unwrap();
        let agent = HybridSigningIdentity::generate("agent-occ-1").unwrap();
        let pair_id = "pair-abc-123";

        let grant =
            sign_partnership_grant(&user, "agent-occ-1", pair_id, "2026-06-14T00:00:00.000Z")
                .unwrap();
        let accept =
            sign_partnership_accept(&agent, "user-1", pair_id, "2026-06-14T00:00:01.000Z").unwrap();

        // Each half verifies as a threshold-1 bound hybrid signature against
        // its own signer's pinned pubkeys.
        let grant_bytes = jcs::canonicalize(&grant.signed_envelope).unwrap();
        assert_eq!(
            verify_threshold_signatures(
                &grant_bytes,
                &[user.directory_member().unwrap()],
                &[threshold_sig("user-1", &grant)],
                1,
            ),
            Ok(1),
            "partnership_grant must verify under the user key"
        );

        let accept_bytes = jcs::canonicalize(&accept.signed_envelope).unwrap();
        assert_eq!(
            verify_threshold_signatures(
                &accept_bytes,
                &[agent.directory_member().unwrap()],
                &[threshold_sig("agent-occ-1", &accept)],
                1,
            ),
            Ok(1),
            "partnership_accept must verify under the agent occurrence key"
        );

        // RC7 §8.1.12.7.1(a): exactly the seven REQUIRED members, no more.
        for env in [&grant.signed_envelope, &accept.signed_envelope] {
            let obj = env.as_object().unwrap();
            let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                vec![
                    "attestation_type",
                    "attesting_key_id",
                    "bilateral_pair_id",
                    "dimension",
                    "score",
                    "signed_at",
                    "subject_key_ids",
                ],
                "partnership envelope must carry EXACTLY the seven RC7 members"
            );
            assert_eq!(env["attestation_type"], json!("scores"));
            assert!(env["score"].as_i64().unwrap() > 0, "score must be positive");
            assert!(env.get("valid_until").is_none(), "no valid_until (omitted)");
            assert!(env["subject_key_ids"].is_array());
        }
        // The bilateral join + cross-naming via subject_key_ids / attesting_key_id.
        assert_eq!(
            grant.signed_envelope["bilateral_pair_id"],
            accept.signed_envelope["bilateral_pair_id"]
        );
        assert_eq!(
            grant.signed_envelope["dimension"],
            json!("consent:partnership_grant:v1")
        );
        assert_eq!(
            accept.signed_envelope["dimension"],
            json!("consent:partnership_accept:v1")
        );
        // grant: signer = user, subject = agent occurrence.
        assert_eq!(grant.signed_envelope["attesting_key_id"], json!("user-1"));
        assert_eq!(
            grant.signed_envelope["subject_key_ids"],
            json!(["agent-occ-1"])
        );
        // accept: signer = agent occurrence, subject = the original granter.
        assert_eq!(
            accept.signed_envelope["attesting_key_id"],
            json!("agent-occ-1")
        );
        assert_eq!(accept.signed_envelope["subject_key_ids"], json!(["user-1"]));
    }

    #[test]
    fn tampered_partnership_grant_fails_verification() {
        let user = HybridSigningIdentity::generate("user-1").unwrap();
        let mut grant =
            sign_partnership_grant(&user, "agent-occ-1", "pair-1", "2026-06-14T00:00:00.000Z")
                .unwrap();
        // Repoint the partnership at a different agent after signing.
        grant.signed_envelope["subject_key_ids"] = json!(["agent-evil"]);

        let bytes = jcs::canonicalize(&grant.signed_envelope).unwrap();
        assert!(
            verify_threshold_signatures(
                &bytes,
                &[user.directory_member().unwrap()],
                &[threshold_sig("user-1", &grant)],
                1,
            )
            .is_err(),
            "tampering partner_key_id after signing must fail verification"
        );
    }

    // ---- 3. transport binding round-trips through the verifier ----------

    #[test]
    fn transport_binding_verifies_through_verify_transport_binding() {
        let signer = HybridSigningIdentity::generate("occ-signing-key").unwrap();
        let aspects = vec!["announce".to_string(), "v1".to_string()];
        // Transport ed key distinct from the signing key (AV-17); content-KEM
        // x25519 distinct from transport x25519 (C4).
        let kem = vec![0x11u8; 1184];
        let mat = TransportIdentityMaterial {
            reticulum_x25519_pubkey: &pubkey_bytes(0x02),
            reticulum_ed25519_pubkey: &pubkey_bytes(0x01),
            app_name: "ciris.federation",
            aspects: &aspects,
            encryption: Some((&pubkey_bytes(0x03), &kem)),
        };

        let binding =
            sign_transport_binding(&signer, "occ-1", "agent", &mat, "2026-06-14T00:00:00.000Z")
                .unwrap();

        let dir = vec![signer.directory_member().unwrap()];
        let v = verify_transport_binding(&binding, &dir).unwrap();
        assert!(
            v.authentic,
            "a transport binding signed by sign_transport_binding must verify"
        );
        assert_eq!(v.reason, TransportBindingReason::Verified);
    }

    #[test]
    fn transport_binding_without_encryption_verifies() {
        let signer = HybridSigningIdentity::generate("occ-signing-key").unwrap();
        let aspects = vec!["announce".to_string()];
        let mat = TransportIdentityMaterial {
            reticulum_x25519_pubkey: &pubkey_bytes(0x02),
            reticulum_ed25519_pubkey: &pubkey_bytes(0x01),
            app_name: "ciris.federation",
            aspects: &aspects,
            encryption: None,
        };
        let binding =
            sign_transport_binding(&signer, "occ-1", "agent", &mat, "2026-06-14T00:00:00.000Z")
                .unwrap();
        let dir = vec![signer.directory_member().unwrap()];
        let v = verify_transport_binding(&binding, &dir).unwrap();
        assert!(v.authentic);
        assert_eq!(v.reason, TransportBindingReason::Verified);
    }

    #[test]
    fn tampered_transport_binding_is_rejected() {
        // Negative: tamper a signed member after signing → JCS bytes change
        // → verify_transport_binding reports SignatureInvalid.
        let signer = HybridSigningIdentity::generate("occ-signing-key").unwrap();
        let aspects = vec!["announce".to_string()];
        let mat = TransportIdentityMaterial {
            reticulum_x25519_pubkey: &pubkey_bytes(0x02),
            reticulum_ed25519_pubkey: &pubkey_bytes(0x01),
            app_name: "ciris.federation",
            aspects: &aspects,
            encryption: None,
        };
        let mut binding =
            sign_transport_binding(&signer, "occ-1", "agent", &mat, "2026-06-14T00:00:00.000Z")
                .unwrap();
        binding.signed_envelope["device_class"] = json!("laptop");

        let dir = vec![signer.directory_member().unwrap()];
        let v = verify_transport_binding(&binding, &dir).unwrap();
        assert!(!v.authentic);
        assert_eq!(v.reason, TransportBindingReason::SignatureInvalid);
    }

    #[test]
    fn transport_binding_reusing_signing_key_is_rejected_by_verifier() {
        // The producer signs what it is given; a producer that (wrongly)
        // reuses the federation signing key as the transport ed key cannot
        // sneak it past the verifier (AV-17).
        let signer = HybridSigningIdentity::generate("occ-signing-key").unwrap();
        let signing_ed = signer.directory_member().unwrap().ed25519_public_key_base64;
        let signing_ed_raw = b64().decode(&signing_ed).unwrap();
        let aspects = vec!["announce".to_string()];
        let mat = TransportIdentityMaterial {
            reticulum_x25519_pubkey: &pubkey_bytes(0x02),
            reticulum_ed25519_pubkey: &signing_ed_raw, // <-- AV-17 violation
            app_name: "ciris.federation",
            aspects: &aspects,
            encryption: None,
        };
        let binding =
            sign_transport_binding(&signer, "occ-1", "agent", &mat, "2026-06-14T00:00:00.000Z")
                .unwrap();
        let dir = vec![signer.directory_member().unwrap()];
        let v = verify_transport_binding(&binding, &dir).unwrap();
        assert!(!v.authentic);
        assert_eq!(v.reason, TransportBindingReason::KeySeparationViolation);
    }

    // ---- 4. hardware-rooted identity + the self-at-login ceremony --------

    /// A software Ed25519 [`HardwareSigner`] standing in for a real secure
    /// element (Secure Enclave / StrongBox / YubiKey) — the byte contract is
    /// identical, so the ceremony is fully exercisable without a physical key.
    fn software_hw_ed25519(seed: u8, alias: &str) -> Arc<dyn HardwareSigner> {
        Arc::new(ciris_keyring::Ed25519SoftwareSigner::from_bytes(&[seed; 32], alias).unwrap())
    }

    fn hardware_rooted(seed: u8, key_id: &str) -> HardwareRootedIdentity {
        HardwareRootedIdentity::new(
            key_id,
            software_hw_ed25519(seed, key_id),
            MlDsa65Signer::new().unwrap(),
        )
        .unwrap()
    }

    /// Build a valid EdDSA passkey **presence** assertion (the credential key is
    /// the passkey, distinct from the federation signing key).
    fn make_passkey(
        cred: &Ed25519Signer,
        challenge: &[u8],
        rp_id: &str,
        origin: &str,
        uv: bool,
        sign_count: u32,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use sha2::{Digest, Sha256};
        let client = json!({
            "type": "webauthn.get",
            "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
            "origin": origin,
        });
        let cdj = serde_json::to_vec(&client).unwrap();
        let mut auth = Vec::new();
        auth.extend_from_slice(&<[u8; 32]>::from(Sha256::digest(rp_id.as_bytes())));
        auth.push(0x01 | if uv { 0x04 } else { 0 }); // UP | UV
        auth.extend_from_slice(&sign_count.to_be_bytes());
        let client_hash: [u8; 32] = Sha256::digest(&cdj).into();
        let mut signed = auth.clone();
        signed.extend_from_slice(&client_hash);
        let sig = signer_sign(cred, &signed);
        (cdj, auth, sig)
    }

    fn signer_sign(s: &Ed25519Signer, msg: &[u8]) -> Vec<u8> {
        s.sign(msg).unwrap()
    }

    #[tokio::test]
    async fn hardware_rooted_identity_produces_verifiable_delegation() {
        // The hardware seam: a HardwareRootedIdentity (Ed25519 in a hardware
        // signer + software ML-DSA) produces bytes byte-identical to the
        // software path — a delegation it signs verifies through the same
        // resolve_role_authority.
        let user = hardware_rooted(0x07, "user-steward-1");
        assert_eq!(
            user.hardware_type(),
            ciris_keyring::HardwareType::SoftwareOnly
        );

        let signed = sign_delegation_async(&user, "agent-occ-1", "org-x", "operator", "active")
            .await
            .unwrap();
        let grant = as_membership_grant(&signed);
        let dir = vec![user.directory_member().await.unwrap()];
        let roots = vec!["user-steward-1".to_string()];

        let v = resolve_role_authority(
            "agent-occ-1",
            "org-x",
            OrgRole::Operator,
            &[grant],
            &dir,
            &roots,
        );
        assert!(
            v.authorized,
            "a hardware-rooted delegation must verify through resolve_role_authority"
        );
        assert_eq!(v.reason, AuthorizationReason::Authorized);
    }

    #[tokio::test]
    async fn hardware_rooted_rejects_non_ed25519_signer() {
        // The federation classical half MUST be Ed25519 — a P-256-only token is
        // refused at construction (fail-closed, not silently downgraded).
        let p256 = Arc::from(ciris_keyring::create_software_signer("p256-token").unwrap());
        let err = HardwareRootedIdentity::new("user-1", p256, MlDsa65Signer::new().unwrap());
        assert!(err.is_err(), "a P-256 hardware key must be rejected");
    }

    fn presence_policy() -> PresencePolicy<'static> {
        PresencePolicy {
            rp_id: "ciris.ai",
            origins: &["https://ciris.ai"],
            require_user_verified: true,
        }
    }

    #[tokio::test]
    async fn full_self_at_login_ceremony_round_trips() {
        // The end-to-end #63 contract: a hardware-rooted user, a software
        // occurrence, a WebAuthn presence unlock, and every produced envelope
        // verifies through its matching verifier.
        let user = hardware_rooted(0x07, "user-steward-1");
        let occurrence = HybridSigningIdentity::generate("agent-occ-1").unwrap();

        // Presence: a passkey assertion (credential key ≠ federation key).
        let passkey = Ed25519Signer::random().unwrap();
        let passkey_pub = passkey.public_key().unwrap();
        let challenge = b"server-issued-login-challenge";
        let (cdj, auth, sig) = make_passkey(
            &passkey,
            challenge,
            "ciris.ai",
            "https://ciris.ai",
            true,
            42,
        );
        let assertion = Assertion {
            alg: crate::webauthn::WebauthnAlg::EdDsa,
            credential_public_key: &passkey_pub,
            authenticator_data: &auth,
            client_data_json: &cdj,
            signature: &sig,
        };

        let aspects = vec!["announce".to_string(), "v1".to_string()];
        let transport = TransportIdentityMaterial {
            reticulum_x25519_pubkey: &pubkey_bytes(0x02),
            reticulum_ed25519_pubkey: &pubkey_bytes(0x01),
            app_name: "ciris.federation",
            aspects: &aspects,
            encryption: None,
        };
        let inputs = LoginInputs {
            org_id: "org-x",
            role: "operator",
            occurrence_key_id: "agent-occ-1",
            bilateral_pair_id: "pair-xyz",
            device_class: "agent",
            transport: &transport,
            signed_at: "2026-06-17T00:00:00.000Z",
        };

        let bundle = perform_self_at_login(
            &user,
            &occurrence,
            &assertion,
            challenge,
            &presence_policy(),
            &inputs,
        )
        .await
        .unwrap();

        // Presence outcome surfaced (sign_count for clone-detection).
        assert_eq!(bundle.presence.sign_count, 42);
        assert!(bundle.presence.user_verified);

        // (a) delegation verifies through resolve_role_authority.
        let v = resolve_role_authority(
            "agent-occ-1",
            "org-x",
            OrgRole::Operator,
            &[as_membership_grant(&bundle.delegation)],
            std::slice::from_ref(&bundle.user_directory_member),
            &["user-steward-1".to_string()],
        );
        assert!(
            v.authorized,
            "ceremony delegation must authorize the occurrence"
        );

        // (b) partnership grant (user) + accept (occurrence) each verify at
        //     threshold 1 against their own signer, joined by bilateral_pair_id.
        let g_bytes = jcs::canonicalize(&bundle.partnership_grant.signed_envelope).unwrap();
        assert_eq!(
            verify_threshold_signatures(
                &g_bytes,
                std::slice::from_ref(&bundle.user_directory_member),
                &[threshold_sig("user-steward-1", &bundle.partnership_grant)],
                1,
            ),
            Ok(1),
        );
        let a_bytes = jcs::canonicalize(&bundle.partnership_accept.signed_envelope).unwrap();
        assert_eq!(
            verify_threshold_signatures(
                &a_bytes,
                std::slice::from_ref(&bundle.occurrence_directory_member),
                &[threshold_sig("agent-occ-1", &bundle.partnership_accept)],
                1,
            ),
            Ok(1),
        );
        assert_eq!(
            bundle.partnership_grant.signed_envelope["bilateral_pair_id"],
            bundle.partnership_accept.signed_envelope["bilateral_pair_id"],
        );

        // (c) transport binding verifies through verify_transport_binding.
        let tv = verify_transport_binding(
            &bundle.transport_binding,
            std::slice::from_ref(&bundle.occurrence_directory_member),
        )
        .unwrap();
        assert!(tv.authentic, "ceremony transport binding must verify");
        assert_eq!(tv.reason, TransportBindingReason::Verified);
    }

    #[tokio::test]
    async fn self_at_login_fails_closed_on_bad_presence() {
        // A wrong-challenge passkey aborts the ceremony — nothing is signed.
        let user = hardware_rooted(0x07, "user-steward-1");
        let occurrence = HybridSigningIdentity::generate("agent-occ-1").unwrap();

        let passkey = Ed25519Signer::random().unwrap();
        let passkey_pub = passkey.public_key().unwrap();
        let (cdj, auth, sig) = make_passkey(
            &passkey,
            b"real-challenge",
            "ciris.ai",
            "https://ciris.ai",
            true,
            1,
        );
        let assertion = Assertion {
            alg: crate::webauthn::WebauthnAlg::EdDsa,
            credential_public_key: &passkey_pub,
            authenticator_data: &auth,
            client_data_json: &cdj,
            signature: &sig,
        };

        let aspects = vec!["announce".to_string()];
        let transport = TransportIdentityMaterial {
            reticulum_x25519_pubkey: &pubkey_bytes(0x02),
            reticulum_ed25519_pubkey: &pubkey_bytes(0x01),
            app_name: "ciris.federation",
            aspects: &aspects,
            encryption: None,
        };
        let inputs = LoginInputs {
            org_id: "org-x",
            role: "operator",
            occurrence_key_id: "agent-occ-1",
            bilateral_pair_id: "pair-xyz",
            device_class: "agent",
            transport: &transport,
            signed_at: "2026-06-17T00:00:00.000Z",
        };

        // Verifier is handed a DIFFERENT challenge than the passkey signed.
        let r = perform_self_at_login(
            &user,
            &occurrence,
            &assertion,
            b"attacker-substituted-challenge",
            &presence_policy(),
            &inputs,
        )
        .await;
        assert!(
            r.is_err(),
            "ceremony must fail closed when presence does not verify"
        );
    }

    // ---- 5. occurrence revocation — "revoke the lost device" -------------

    #[tokio::test]
    async fn occurrence_revocation_verifies_with_a_surviving_key() {
        // Device A (a SURVIVING hardware-rooted key) revokes device B. The
        // signed revocation verifies at threshold 1 against A's pinned pubkeys
        // — exactly what Registry/Server checks before writing the row through
        // to Persist. (You cannot trust the stolen key to revoke itself; the
        // OR-of-N redundancy is what makes A available to sign this.)
        let device_a = hardware_rooted(0x07, "device-a-key");
        let revocation = sign_occurrence_revocation(
            &device_a,
            "my-identity-key",
            "device-b-stolen-key",
            Some("device lost"),
            "2026-06-18T00:00:00.000Z",
            "2026-06-18T00:00:00.000Z",
        )
        .await
        .unwrap();

        // Members map to the Persist IdentityOccurrenceRevocation row.
        let env = &revocation.signed_envelope;
        assert_eq!(env["identity_key_id"], json!("my-identity-key"));
        assert_eq!(env["occurrence_key_id"], json!("device-b-stolen-key"));
        assert_eq!(
            env["witness_set"],
            json!(["device-a-key"]),
            "single vouch = the revoker (§11.7.4)"
        );
        assert_eq!(env["reason"], json!("device lost"));

        // The authorization verifies at threshold 1 under the revoker's key.
        let bytes = jcs::canonicalize(env).unwrap();
        assert_eq!(
            verify_threshold_signatures(
                &bytes,
                &[device_a.directory_member().await.unwrap()],
                &[threshold_sig("device-a-key", &revocation)],
                1,
            ),
            Ok(1),
            "a revocation signed by a surviving key must verify at threshold 1"
        );
    }

    #[tokio::test]
    async fn tampered_revocation_target_fails_verification() {
        // Repoint the revocation at a different occurrence after signing → the
        // JCS bytes change → the authorization no longer verifies (an attacker
        // cannot retarget a signed revocation).
        let device_a = hardware_rooted(0x07, "device-a-key");
        let mut revocation = sign_occurrence_revocation(
            &device_a,
            "my-identity-key",
            "device-b-key",
            None,
            "2026-06-18T00:00:00.000Z",
            "2026-06-18T00:00:00.000Z",
        )
        .await
        .unwrap();
        // No reason supplied → omitted, not null (§0.9).
        assert!(revocation.signed_envelope.get("reason").is_none());

        revocation.signed_envelope["occurrence_key_id"] = json!("device-c-key");
        let bytes = jcs::canonicalize(&revocation.signed_envelope).unwrap();
        assert!(
            verify_threshold_signatures(
                &bytes,
                &[device_a.directory_member().await.unwrap()],
                &[threshold_sig("device-a-key", &revocation)],
                1,
            )
            .is_err(),
            "retargeting a signed revocation must break verification"
        );
    }

    #[tokio::test]
    async fn revocation_does_not_bind_to_a_forged_revoker_key_id() {
        // A revocation is authorized only if it verifies against the revoker's
        // DIRECTORY-pinned pubkeys. An attacker who signs a revocation while
        // CLAIMING a surviving key's key_id (but using their own keypair) is
        // rejected, because the directory pins that key_id to the real pubkeys.
        let real_device_a = hardware_rooted(0x07, "device-a-key");
        let attacker = HybridSigningIdentity::new(
            "device-a-key", // claims the surviving key's id
            Ed25519Signer::random().unwrap(),
            MlDsa65Signer::new().unwrap(),
        );

        let forged = sign_occurrence_revocation(
            &attacker,
            "my-identity-key",
            "device-b-key",
            None,
            "2026-06-18T00:00:00.000Z",
            "2026-06-18T00:00:00.000Z",
        )
        .await
        .unwrap();

        let bytes = jcs::canonicalize(&forged.signed_envelope).unwrap();
        assert!(
            verify_threshold_signatures(
                &bytes,
                // directory pins device-a-key to the REAL surviving key's pubkeys
                &[real_device_a.directory_member().await.unwrap()],
                &[threshold_sig("device-a-key", &forged)],
                1,
            )
            .is_err(),
            "a revocation forged under a surviving key's id must not authorize"
        );
    }

    #[tokio::test]
    async fn voluntary_self_revoke_carries_self_as_sole_vouch() {
        // §11.7.4 permits the revoking occurrence to be the subject (a voluntary
        // leave). Pin that behavior: witness_set == [self], and it verifies
        // under the signer's own key. (The STOLEN-device flow must instead use a
        // surviving key — that is the producer's documented caller contract.)
        let device = hardware_rooted(0x07, "device-self");
        let rev = sign_occurrence_revocation(
            &device,
            "my-identity-key",
            "device-self", // revoking itself
            Some("voluntary leave"),
            "2026-06-18T00:00:00.000Z",
            "2026-06-18T00:00:00.000Z",
        )
        .await
        .unwrap();
        assert_eq!(rev.signed_envelope["witness_set"], json!(["device-self"]));
        let bytes = jcs::canonicalize(&rev.signed_envelope).unwrap();
        assert_eq!(
            verify_threshold_signatures(
                &bytes,
                &[device.directory_member().await.unwrap()],
                &[threshold_sig("device-self", &rev)],
                1,
            ),
            Ok(1),
        );
    }
}
