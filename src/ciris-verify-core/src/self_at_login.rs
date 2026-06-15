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
//! ## Scope (the buildable signing pieces of CIRISVerify#63)
//!
//! The full #63 deliverable also covers the *hardware-rooting* of the user
//! key (Secure Enclave / StrongBox / YubiKey, `hardware_class` §9.4) and the
//! WebAuthn/passkey **presence** unlock factor — those need the hardware
//! signer work tracked in CIRISVerify#62/#65 and are **out of scope here**.
//! This module takes an already-constructed hybrid signing identity (today
//! a software [`Ed25519Signer`] + [`MlDsa65Signer`] pair; tomorrow a
//! hardware-backed one behind the same byte contract) and produces the
//! federation-tier-promotable signed envelopes:
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

use base64::Engine;
use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::VerifyError;
use crate::jcs;
use crate::threshold::ThresholdMember;
use crate::transport_binding::{
    compute_destination_hash, EncryptionPubkeys, TransportBinding, TransportBindingSignature,
    TransportDestination,
};

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
    let envelope = json!({
        "user_id": subject_key_id,
        "org_id": org_id,
        "role": role,
        "status": status,
        "attesting_key_id": granter.key_id,
    });
    granter.sign_envelope(envelope)
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
    // CEG 1.0-RC7 §8.1.12.7.1(a): EXACTLY these seven members, bare-`scores`
    // shape. `attesting_key_id` is the signer (granter); `subject_key_ids` is
    // the single-element array `[partner]` (set-sorted trivially); NO
    // `valid_until` (a PARTNERED pair has no expiry — omitted, not null). JCS
    // sorts keys, so member order here is irrelevant to the signed bytes.
    let envelope = json!({
        "attestation_type": "scores",
        "attesting_key_id": granter.key_id,
        "dimension": "consent:partnership_grant:v1",
        "score": PARTNERSHIP_AFFIRMATION_SCORE,
        "subject_key_ids": [partner_key_id],
        "bilateral_pair_id": bilateral_pair_id,
        "signed_at": signed_at,
    });
    granter.sign_envelope(envelope)
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
    // CEG 1.0-RC7 §8.1.12.7.1(a) accept half: same seven-member set, mirrored.
    // `attesting_key_id` is the accepter (the signer); `subject_key_ids` is the
    // OTHER party — here the original granter (`[granter_key_id]`). Tied to the
    // grant by the shared `bilateral_pair_id`.
    let envelope = json!({
        "attestation_type": "scores",
        "attesting_key_id": accepter.key_id,
        "dimension": "consent:partnership_accept:v1",
        "score": PARTNERSHIP_AFFIRMATION_SCORE,
        "subject_key_ids": [granter_key_id],
        "bilateral_pair_id": bilateral_pair_id,
        "signed_at": signed_at,
    });
    accepter.sign_envelope(envelope)
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
        "attesting_key_id": signer.key_id,
        "identity_key_id": signer.key_id,
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

    let bytes = jcs::canonicalize(&envelope)?;
    let (ed_sig, mldsa_sig) = signer.sign_bytes(&bytes)?;

    Ok(TransportBinding {
        attesting_key_id: signer.key_id.clone(),
        signed_envelope: envelope,
        transport_destination: td,
        encryption_pubkeys: enc,
        signature: TransportBindingSignature {
            ed25519_signature_base64: ed_sig,
            mldsa65_signature_base64: Some(mldsa_sig),
        },
    })
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
}
