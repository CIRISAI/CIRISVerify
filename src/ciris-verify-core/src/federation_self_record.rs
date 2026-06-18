//! Self-signed federation key record — the **genesis federation identity**
//! object (CIRISServer 6.0 `identity create`).
//!
//! A brand-new federation identity is a *self-signed* `KeyRecord`: the
//! identity's hybrid key (Ed25519 + ML-DSA-65) signs its own
//! `registration_envelope` as proof-of-possession. CIRISServer drains it from
//! the [`crate::ceg_outbox`] and relays it; CIRISPersist's `register_key`
//! verifies the bound hybrid signature over
//! `ceg_produce_canonicalize(registration_envelope)` — which **is** verify's
//! own JCS ([`crate::jcs`]) — before storing.
//!
//! ## Producer ↔ consumer (byte-exact)
//!
//! `register_key` recomputes `hex(SHA-256(JCS(registration_envelope)))`,
//! cross-checks it against [`KeyRecord::original_content_hash`], then runs a
//! **Strict** hybrid verify (both halves REQUIRED) of
//! [`KeyRecord::scrub_signature_classical`] /
//! [`KeyRecord::scrub_signature_pqc`] over those bytes. A self-attested row
//! (`scrub_key_id == key_id`) reads the verifying pubkeys straight off the
//! submitted record. This module produces exactly that shape: the signature is
//! the same bound-hybrid construction
//! ([`crate::self_at_login::SelfSigner::sign_bound`]) — `Ed25519.sign(JCS)`
//! then `ML-DSA-65.sign(JCS ‖ ed_sig)` — so a record produced here passes
//! `register_key` by construction.
//!
//! `register_key` does **not** inspect the envelope's *contents* beyond
//! canonicalize → hash → verify, so the envelope shape is the producer's; the
//! `purpose` string is flagged for CIRISServer/Persist cross-confirmation.

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::VerifyError;
use crate::jcs;
use crate::self_at_login::SelfSigner;

/// `algorithm` string CIRISPersist requires for a hybrid row (`algorithm::HYBRID`).
pub const ALGORITHM_HYBRID: &str = "hybrid";
/// `identity_type` for a responsible-owner / human identity.
pub const IDENTITY_TYPE_USER: &str = "user";
/// `identity_type` for an agent occurrence.
pub const IDENTITY_TYPE_AGENT: &str = "agent";

/// The `purpose` member of the genesis registration envelope. **Flagged for
/// CIRISServer/Persist cross-confirmation** (mirrors the known-good value in
/// Persist's `register_key` round-trip test).
pub const REGISTRATION_PURPOSE: &str = "federation-peering";

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// A self-signed federation key record. Serializes to CIRISPersist's
/// `KeyRecord` wire shape — wrap it in [`SignedKeyRecord`] for submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRecord {
    /// Canonical key identifier.
    pub key_id: String,
    /// Ed25519 32-byte raw public key, base64 standard.
    pub pubkey_ed25519_base64: String,
    /// ML-DSA-65 raw public key, base64 standard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey_ml_dsa_65_base64: Option<String>,
    /// Always [`ALGORITHM_HYBRID`].
    pub algorithm: String,
    /// Identity classification ([`IDENTITY_TYPE_USER`] / [`IDENTITY_TYPE_AGENT`]).
    pub identity_type: String,
    /// Logical identity reference (here: the `key_id` itself, for genesis).
    pub identity_ref: String,
    /// RFC-3339 — when the key became valid.
    pub valid_from: String,
    /// RFC-3339 — expiry (`None` = no expiry).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    /// The object whose `JCS` bytes were signed (verbatim).
    pub registration_envelope: Value,
    /// Hex `SHA-256(JCS(registration_envelope))`.
    pub original_content_hash: String,
    /// Base64 `Ed25519.sign(JCS(registration_envelope))`.
    pub scrub_signature_classical: String,
    /// Base64 `ML-DSA-65.sign(JCS(registration_envelope) ‖ ed25519_sig)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
    /// The key that signed THIS row. Genesis is self-signed: `== key_id`.
    pub scrub_key_id: String,
    /// RFC-3339 — when the scrub-signature was issued.
    pub scrub_timestamp: String,
    /// RFC-3339 — when the PQC half was attached (here: at genesis).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pqc_completed_at: Option<String>,
    /// **Server-computed** — emitted empty; CIRISPersist recomputes + ignores.
    pub persist_row_hash: String,
    /// Per-row role tags (empty for a fresh identity).
    #[serde(default)]
    pub roles: Vec<String>,
}

/// The submission wrapper CIRISPersist's `register_key` / CIRISServer peering
/// accept (`peer_key_record`). `persist_row_hash` inside is ignored on write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedKeyRecord {
    /// The self-signed record.
    pub record: KeyRecord,
}

/// Produce a self-signed genesis [`SignedKeyRecord`] for `signer`'s identity.
///
/// `signer` is the hybrid identity (typically a
/// [`crate::self_at_login::HardwareRootedIdentity`] rooted in a YubiKey).
/// `valid_from` is caller-supplied RFC-3339 (this module is clock-free so the
/// signed bytes are reproducible). The Ed25519 half signs on the hardware
/// token (a touch-required key blocks here until tapped); the ML-DSA-65 half
/// signs in software over the bound input.
///
/// # Errors
///
/// [`VerifyError`] on a canonicalization or signer fault.
pub async fn produce_self_key_record(
    signer: &dyn SelfSigner,
    identity_type: &str,
    valid_from: &str,
) -> Result<SignedKeyRecord, VerifyError> {
    let key_id = signer.key_id().to_string();
    let ed_pub = signer.ed25519_public_key().await?;
    let mldsa_pub = signer.mldsa65_public_key().await?;
    let pubkey_ed25519_base64 = b64().encode(&ed_pub);
    let pubkey_ml_dsa_65_base64 = b64().encode(&mldsa_pub);

    // The signed envelope binds EVERY security-bearing field the substrate
    // later trusts off the row — not just {key_id, purpose}. A self-attested
    // proof-of-possession that omits `identity_type` / the pubkeys / validity
    // would let a captured genesis record be replayed with those fields flipped
    // and still verify (the signature would not cover them). `register_key`
    // recanonicalizes this exact object; a consumer SHOULD additionally assert
    // each row field equals its signed value here (flagged for Persist on #63).
    let registration_envelope = json!({
        "key_id": key_id,
        "purpose": REGISTRATION_PURPOSE,
        "algorithm": ALGORITHM_HYBRID,
        "identity_type": identity_type,
        "pubkey_ed25519_base64": pubkey_ed25519_base64,
        "pubkey_ml_dsa_65_base64": pubkey_ml_dsa_65_base64,
        "valid_from": valid_from,
    });
    let canonical = jcs::canonicalize(&registration_envelope)?;
    let original_content_hash = hex::encode(Sha256::digest(&canonical));

    // The bound hybrid signature over the exact bytes register_key recomputes.
    let (ed_sig_b64, pqc_sig_b64) = signer.sign_bound(&canonical).await?;

    let record = KeyRecord {
        key_id: key_id.clone(),
        pubkey_ed25519_base64,
        pubkey_ml_dsa_65_base64: Some(pubkey_ml_dsa_65_base64),
        algorithm: ALGORITHM_HYBRID.to_string(),
        identity_type: identity_type.to_string(),
        identity_ref: key_id.clone(),
        valid_from: valid_from.to_string(),
        valid_until: None,
        registration_envelope,
        original_content_hash,
        scrub_signature_classical: ed_sig_b64,
        scrub_signature_pqc: Some(pqc_sig_b64),
        scrub_key_id: key_id, // self-signed genesis: scrub_key_id == key_id
        scrub_timestamp: valid_from.to_string(),
        pqc_completed_at: Some(valid_from.to_string()),
        persist_row_hash: String::new(),
        roles: Vec::new(),
    };
    Ok(SignedKeyRecord { record })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_at_login::HybridSigningIdentity;
    use crate::threshold::{verify_threshold_signatures, ThresholdMember, ThresholdSignature};

    #[tokio::test]
    async fn self_key_record_self_verifies_like_register_key() {
        // Reproduce CIRISPersist register_key's check: recompute
        // hex(SHA-256(JCS(envelope))) == original_content_hash, then Strict
        // hybrid-verify the scrub signatures over those bytes against the
        // pubkeys carried in the record (self-attested path).
        let identity = HybridSigningIdentity::generate("my-identity-key").unwrap();
        let signed = produce_self_key_record(&identity, IDENTITY_TYPE_USER, "2026-06-18T00:00:00Z")
            .await
            .unwrap();
        let r = &signed.record;

        assert_eq!(r.algorithm, ALGORITHM_HYBRID);
        assert_eq!(r.scrub_key_id, r.key_id, "genesis row is self-signed");
        assert_eq!(r.identity_type, IDENTITY_TYPE_USER);

        // (1) hash cross-check.
        let canonical = jcs::canonicalize(&r.registration_envelope).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&canonical)),
            r.original_content_hash
        );

        // (2) Strict bound-hybrid verify against the record's own pubkeys —
        //     the same primitive register_key reaches through verify_hybrid.
        let member = ThresholdMember {
            member_id: r.key_id.clone(),
            ed25519_public_key_base64: r.pubkey_ed25519_base64.clone(),
            mldsa65_public_key_base64: r.pubkey_ml_dsa_65_base64.clone(),
            role: None,
        };
        let sig = ThresholdSignature {
            member_id: r.key_id.clone(),
            ed25519_signature_base64: r.scrub_signature_classical.clone(),
            mldsa65_signature_base64: r.scrub_signature_pqc.clone(),
        };
        assert_eq!(
            verify_threshold_signatures(&canonical, &[member], &[sig], 1),
            Ok(1),
            "the self-signed record must hybrid-verify (Strict) by construction"
        );
    }

    /// Cross-impl drift guard: verify emits the RFC-3339 timestamp fields as
    /// `String`, but CIRISPersist's `KeyRecord` deserializes them into
    /// `chrono::DateTime<Utc>`. A same-impl round-trip can't catch a value that
    /// verify emits but Persist's stricter types reject — so deserialize the
    /// produced JSON into a Persist-shaped struct here.
    #[tokio::test]
    async fn produced_json_deserializes_into_persist_datetime_shape() {
        use chrono::{DateTime, Utc};

        // Mirrors CIRISPersist `federation::types::KeyRecord`'s typed fields
        // (the security-bearing subset) — same field names, `DateTime<Utc>`
        // where Persist is strict, matching serde defaults / skips.
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct PersistShapedKeyRecord {
            key_id: String,
            pubkey_ed25519_base64: String,
            #[serde(default)]
            pubkey_ml_dsa_65_base64: Option<String>,
            algorithm: String,
            identity_type: String,
            identity_ref: String,
            valid_from: DateTime<Utc>,
            #[serde(default)]
            valid_until: Option<DateTime<Utc>>,
            registration_envelope: Value,
            original_content_hash: String,
            scrub_signature_classical: String,
            #[serde(default)]
            scrub_signature_pqc: Option<String>,
            scrub_key_id: String,
            scrub_timestamp: DateTime<Utc>,
            #[serde(default)]
            pqc_completed_at: Option<DateTime<Utc>>,
            persist_row_hash: String,
            #[serde(default)]
            roles: Vec<String>,
        }

        let identity = HybridSigningIdentity::generate("my-identity-key").unwrap();
        let signed = produce_self_key_record(&identity, IDENTITY_TYPE_USER, "2026-06-18T00:00:00Z")
            .await
            .unwrap();
        let json = serde_json::to_value(&signed.record).unwrap();

        let parsed: PersistShapedKeyRecord = serde_json::from_value(json)
            .expect("verify's KeyRecord JSON must deserialize into Persist's DateTime<Utc> shape");
        assert_eq!(parsed.key_id, "my-identity-key");
        assert_eq!(parsed.algorithm, ALGORITHM_HYBRID);
        // valid_from parsed as a real timestamp (not a bare/offsetless string).
        assert_eq!(
            parsed.valid_from,
            "2026-06-18T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[tokio::test]
    async fn tampered_record_fails_the_hash_crosscheck() {
        let identity = HybridSigningIdentity::generate("k").unwrap();
        let mut signed =
            produce_self_key_record(&identity, IDENTITY_TYPE_USER, "2026-06-18T00:00:00Z")
                .await
                .unwrap();
        // Mutate the envelope after signing → recomputed hash diverges.
        signed.record.registration_envelope = json!({"key_id": "k", "purpose": "TAMPERED"});
        let canonical = jcs::canonicalize(&signed.record.registration_envelope).unwrap();
        assert_ne!(
            hex::encode(Sha256::digest(&canonical)),
            signed.record.original_content_hash,
            "register_key catches the envelope/hash divergence fail-secure"
        );
    }
}
