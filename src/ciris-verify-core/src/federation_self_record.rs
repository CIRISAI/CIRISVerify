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

/// A node's transport reachability hint — **WHO** (the key record's identity) plus
/// **HOW-TO-REACH** (this hint), both covered by the same accord scrub-signature so a
/// baked/replicated canonical record is self-describing and unspoofable post-hoc
/// (CIRISVerify#172 producer half; CIRISPersist#381 read contract).
///
/// `kind` is an **open vocabulary** (`ip` | `reticulum` | `https` | …); consumers
/// dial by `kind` and ignore ones they don't understand. This is CIRISPersist's exact
/// read shape — `registration_envelope["transport_hints"][*].{kind,destination}` — so
/// its `serde_json` read + `KeyRecord::transport_hints()` see these verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportHint {
    /// Transport family (`ip`, `reticulum`, `https`, …) — open vocabulary.
    pub kind: String,
    /// Where to reach the node on that transport (e.g. `108.61.242.236:4242`).
    pub destination: String,
}

/// Build the genesis `registration_envelope` — the **single source of truth** shared by
/// [`produce_self_key_record`] and [`produce_scrubbed_key_record`] so the two can never
/// drift (a genesis record would fail to root on a producer-vs-verifier mismatch;
/// CIRISPersist#345).
///
/// `transport_hints` is **materialize-when-present** (CEG §0.9 omit-vs-materialize): an
/// empty list omits the key entirely, reproducing the pre-#172 envelope **byte-for-byte**
/// so existing records / signatures / golden vectors stay valid. JCS
/// ([`crate::jcs`]) sorts keys lexicographically, so the *insertion order here is
/// irrelevant* to the canonical bytes / `original_content_hash`.
fn build_registration_envelope(
    key_id: &str,
    identity_type: &str,
    pubkey_ed25519_base64: &str,
    pubkey_ml_dsa_65_base64: &str,
    valid_from: &str,
    transport_hints: &[TransportHint],
) -> Value {
    let mut envelope = json!({
        "key_id": key_id,
        "purpose": REGISTRATION_PURPOSE,
        "algorithm": ALGORITHM_HYBRID,
        "identity_type": identity_type,
        "pubkey_ed25519_base64": pubkey_ed25519_base64,
        "pubkey_ml_dsa_65_base64": pubkey_ml_dsa_65_base64,
        "valid_from": valid_from,
    });
    // Only materialize `transport_hints` when there is at least one — absent hints
    // MUST leave the envelope bytes identical to the pre-#172 shape (see doc above).
    if !transport_hints.is_empty() {
        envelope
            .as_object_mut()
            .expect("json! built an object")
            .insert(
                "transport_hints".to_string(),
                serde_json::to_value(transport_hints).expect("TransportHint serializes"),
            );
    }
    envelope
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

impl KeyRecord {
    /// Read the [`TransportHint`]s carried in the signed `registration_envelope`
    /// (CIRISVerify#172). Mirrors CIRISPersist's `KeyRecord::transport_hints()`
    /// read contract: a record with no hint (or a malformed/absent field) reads
    /// as an empty list — never an error, never a default injected on write.
    #[must_use]
    pub fn transport_hints(&self) -> Vec<TransportHint> {
        self.registration_envelope
            .get("transport_hints")
            .and_then(|v| serde_json::from_value::<Vec<TransportHint>>(v.clone()).ok())
            .unwrap_or_default()
    }
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
/// `transport_hints` (CIRISVerify#172) are embedded **inside** the signed
/// `registration_envelope` — so the reachability hint is covered by
/// `original_content_hash` and the hybrid scrub-signature, accord-attested by
/// construction. Pass `&[]` for an ordinary hintless record; an empty list
/// reproduces the pre-#172 envelope bytes exactly (see
/// `build_registration_envelope`).
///
/// # Errors
///
/// [`VerifyError`] on a canonicalization or signer fault.
pub async fn produce_self_key_record(
    signer: &dyn SelfSigner,
    identity_type: &str,
    valid_from: &str,
    transport_hints: &[TransportHint],
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
    // #172: `transport_hints` ride inside this same signed envelope.
    let registration_envelope = build_registration_envelope(
        &key_id,
        identity_type,
        &pubkey_ed25519_base64,
        &pubkey_ml_dsa_65_base64,
        valid_from,
        transport_hints,
    );
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

/// The node an accord holder is admitting to the trust root — the identity
/// fields the scrubbed record carries (the *target*, not the signer). The
/// pubkeys are the node's already-minted hybrid keys (base64 standard); the
/// holder never derives them.
#[derive(Debug, Clone)]
pub struct ScrubTarget {
    /// The target node's `key_id` (e.g. `canonical-server-1`).
    pub key_id: String,
    /// The target's Ed25519 public key, base64 standard.
    pub pubkey_ed25519_base64: String,
    /// The target's ML-DSA-65 public key, base64 standard.
    pub pubkey_ml_dsa_65_base64: String,
    /// The target's `identity_type` (e.g. `node`).
    pub identity_type: String,
}

/// Produce an **accord-scrubbed** key record — the scrub twin of
/// [`produce_self_key_record`] (CIRISVerify#160/#162, the genesis-mesh
/// "centipede tail").
///
/// An accord holder (`scrubber`, e.g. A1) admits a node to the trust root by
/// scrub-signing that node's registration with the accord key. The produced
/// record is **byte-identical in envelope + JCS canonicalization** to a
/// self-signed record for the same target fields — the *only* difference is that
/// the scrub-signature and `scrub_key_id` are the **scrubber's**, not the
/// target's. So the node's provenance chain is `node → A1 (self-signed
/// steward,accord_holder anchor)` and **roots** at the [`accord_holder_bootstrap_anchor`](crate::accord_genesis::accord_holder_bootstrap_anchor).
///
/// **Single source of truth (why this lives in verify):** the envelope shape and
/// canonicalization are shared with [`produce_self_key_record`], which is exactly
/// what CIRISPersist's `register_key` / `root_binding` recanonicalize and verify.
/// A hand-rolled producer in a consumer would silently drift from that
/// canonicalization (CIRISPersist#345) and every genesis record would fail to
/// root.
///
/// `transport_hints` (CIRISVerify#172) are embedded inside the signed envelope
/// exactly as in [`produce_self_key_record`] — so the accord holder attests the
/// admitted node's reachability along with its identity, in one scrub-signature.
/// This is the canonical-node admission path the operator ceremony uses to bake
/// a hint-carrying canonical record. Pass `&[]` to omit (byte-identical to the
/// pre-#172 shape).
///
/// # Errors
///
/// [`VerifyError`] if the scrubber's signer fails or the envelope can't be
/// canonicalized.
pub async fn produce_scrubbed_key_record(
    scrubber: &dyn SelfSigner,
    target: ScrubTarget,
    valid_from: &str,
    transport_hints: &[TransportHint],
) -> Result<SignedKeyRecord, VerifyError> {
    // Same rich envelope as `produce_self_key_record`, but over the TARGET's
    // fields — so persist recanonicalizes byte-identical bytes and the
    // scrub-signature (below) verifies against `scrub_key_id`'s pinned pubkey.
    // #172: `transport_hints` ride inside the same signed envelope; the shared
    // builder guarantees byte-identity with the self-record for the same fields.
    let registration_envelope = build_registration_envelope(
        &target.key_id,
        &target.identity_type,
        &target.pubkey_ed25519_base64,
        &target.pubkey_ml_dsa_65_base64,
        valid_from,
        transport_hints,
    );
    let canonical = jcs::canonicalize(&registration_envelope)?;
    let original_content_hash = hex::encode(Sha256::digest(&canonical));

    // The SCRUBBER (A1) signs the TARGET's canonical envelope — the bound
    // hybrid signature over the exact bytes register_key recomputes.
    let (ed_sig_b64, pqc_sig_b64) = scrubber.sign_bound(&canonical).await?;

    let record = KeyRecord {
        // Identity fields are the TARGET's …
        key_id: target.key_id.clone(),
        pubkey_ed25519_base64: target.pubkey_ed25519_base64,
        pubkey_ml_dsa_65_base64: Some(target.pubkey_ml_dsa_65_base64),
        algorithm: ALGORITHM_HYBRID.to_string(),
        identity_type: target.identity_type,
        identity_ref: target.key_id.clone(),
        valid_from: valid_from.to_string(),
        valid_until: None,
        registration_envelope,
        original_content_hash,
        // … the signature + scrub_key_id are the SCRUBBER's (the whole point:
        // scrub_key_id != key_id ⇒ the chain roots at the accord holder).
        scrub_signature_classical: ed_sig_b64,
        scrub_signature_pqc: Some(pqc_sig_b64),
        scrub_key_id: scrubber.key_id().to_string(),
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
        let signed =
            produce_self_key_record(&identity, IDENTITY_TYPE_USER, "2026-06-18T00:00:00Z", &[])
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

    /// #162: an accord holder (A1) scrub-signs a node's registration. The record
    /// carries the TARGET's identity but the SCRUBBER's signature + scrub_key_id,
    /// and verifies through persist's `register_key` / `root_binding` path
    /// (recanonicalize → hash cross-check → Strict hybrid-verify against
    /// `scrub_key_id`'s — A1's — pinned pubkey). That is what makes the node's
    /// chain `node → A1` root at the accord anchor.
    #[tokio::test]
    async fn scrubbed_record_carries_target_identity_and_verifies_against_the_scrubber() {
        let a1 = HybridSigningIdentity::generate("A1").unwrap();
        let node = HybridSigningIdentity::generate("canonical-server-1").unwrap();
        let node_ed = b64().encode(node.ed25519_public_key().await.unwrap());
        let node_mldsa = b64().encode(node.mldsa65_public_key().await.unwrap());

        let signed = produce_scrubbed_key_record(
            &a1,
            ScrubTarget {
                key_id: "canonical-server-1".to_string(),
                pubkey_ed25519_base64: node_ed.clone(),
                pubkey_ml_dsa_65_base64: node_mldsa.clone(),
                identity_type: "node".to_string(),
            },
            "2026-07-02T00:00:00Z",
            &[],
        )
        .await
        .unwrap();
        let r = &signed.record;

        // Identity fields are the TARGET's; the scrub is the SCRUBBER's.
        assert_eq!(r.key_id, "canonical-server-1");
        assert_eq!(r.identity_type, "node");
        assert_eq!(r.pubkey_ed25519_base64, node_ed);
        assert_eq!(r.scrub_key_id, "A1", "admitted-by is the accord holder");
        assert_ne!(
            r.scrub_key_id, r.key_id,
            "a scrub record is NOT self-signed"
        );

        let canonical = jcs::canonicalize(&r.registration_envelope).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&canonical)),
            r.original_content_hash
        );

        // Verifies against A1 (the scrubber) …
        let scrubber = ThresholdMember {
            member_id: "A1".to_string(),
            ed25519_public_key_base64: b64().encode(a1.ed25519_public_key().await.unwrap()),
            mldsa65_public_key_base64: Some(b64().encode(a1.mldsa65_public_key().await.unwrap())),
            role: None,
        };
        let sig = ThresholdSignature {
            member_id: "A1".to_string(),
            ed25519_signature_base64: r.scrub_signature_classical.clone(),
            mldsa65_signature_base64: r.scrub_signature_pqc.clone(),
        };
        assert_eq!(
            verify_threshold_signatures(&canonical, &[scrubber], std::slice::from_ref(&sig), 1),
            Ok(1),
            "must hybrid-verify against the SCRUBBER's key (root_binding path)"
        );
        // … and NOT against the target's own key (it isn't self-signed).
        let node_member = ThresholdMember {
            member_id: "A1".to_string(),
            ed25519_public_key_base64: node_ed,
            mldsa65_public_key_base64: Some(node_mldsa),
            role: None,
        };
        assert_ne!(
            verify_threshold_signatures(&canonical, &[node_member], &[sig], 1),
            Ok(1),
            "the scrub signature is A1's, not the node's"
        );
    }

    /// #162 no-drift guard: the scrubbed record's canonical registration envelope
    /// is BYTE-IDENTICAL to what `produce_self_key_record` emits for the same
    /// identity fields — so persist verifies both through one canonicalization and
    /// a genesis record can never fail to root on a producer-vs-verifier drift.
    #[tokio::test]
    async fn scrubbed_envelope_is_byte_identical_to_the_self_envelope() {
        let a1 = HybridSigningIdentity::generate("A1").unwrap();
        let node = HybridSigningIdentity::generate("canonical-server-1").unwrap();
        let node_ed = b64().encode(node.ed25519_public_key().await.unwrap());
        let node_mldsa = b64().encode(node.mldsa65_public_key().await.unwrap());

        // Node signs itself as a "node" …
        let self_rec = produce_self_key_record(&node, "node", "2026-07-02T00:00:00Z", &[])
            .await
            .unwrap();
        // … A1 scrub-signs the SAME node's registration.
        let scrubbed = produce_scrubbed_key_record(
            &a1,
            ScrubTarget {
                key_id: "canonical-server-1".to_string(),
                pubkey_ed25519_base64: node_ed,
                pubkey_ml_dsa_65_base64: node_mldsa,
                identity_type: "node".to_string(),
            },
            "2026-07-02T00:00:00Z",
            &[],
        )
        .await
        .unwrap();

        let self_canon = jcs::canonicalize(&self_rec.record.registration_envelope).unwrap();
        let scrub_canon = jcs::canonicalize(&scrubbed.record.registration_envelope).unwrap();
        assert_eq!(
            self_canon, scrub_canon,
            "envelopes must canonicalize identically (no drift)"
        );
        assert_eq!(
            self_rec.record.original_content_hash,
            scrubbed.record.original_content_hash
        );
        // Only the scrub identity differs.
        assert_eq!(self_rec.record.scrub_key_id, "canonical-server-1");
        assert_eq!(scrubbed.record.scrub_key_id, "A1");
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
        let signed =
            produce_self_key_record(&identity, IDENTITY_TYPE_USER, "2026-06-18T00:00:00Z", &[])
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
            produce_self_key_record(&identity, IDENTITY_TYPE_USER, "2026-06-18T00:00:00Z", &[])
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

    fn hints() -> Vec<TransportHint> {
        vec![
            TransportHint {
                kind: "ip".to_string(),
                destination: "108.61.242.236:4242".to_string(),
            },
            TransportHint {
                kind: "reticulum".to_string(),
                destination: "a1b2c3d4e5f6".to_string(),
            },
        ]
    }

    /// #172: an empty `transport_hints` list MUST leave the signed envelope
    /// byte-identical to the pre-#172 shape — no `transport_hints` key at all —
    /// so already-baked records / signatures / golden vectors stay valid.
    #[tokio::test]
    async fn absent_hints_omit_the_key_and_preserve_pre_172_bytes() {
        let identity = HybridSigningIdentity::generate("k").unwrap();
        let signed =
            produce_self_key_record(&identity, IDENTITY_TYPE_USER, "2026-06-18T00:00:00Z", &[])
                .await
                .unwrap();
        let env = &signed.record.registration_envelope;
        assert!(
            env.get("transport_hints").is_none(),
            "an empty hint list must NOT materialize the key"
        );
        assert!(signed.record.transport_hints().is_empty());

        // The canonical bytes equal a hand-built 7-field pre-#172 envelope for
        // the same fields — the byte-identity that keeps old signatures valid.
        let ed = signed.record.pubkey_ed25519_base64.clone();
        let pqc = signed.record.pubkey_ml_dsa_65_base64.clone().unwrap();
        let pre_172 = json!({
            "key_id": "k",
            "purpose": REGISTRATION_PURPOSE,
            "algorithm": ALGORITHM_HYBRID,
            "identity_type": IDENTITY_TYPE_USER,
            "pubkey_ed25519_base64": ed,
            "pubkey_ml_dsa_65_base64": pqc,
            "valid_from": "2026-06-18T00:00:00Z",
        });
        assert_eq!(
            jcs::canonicalize(env).unwrap(),
            jcs::canonicalize(&pre_172).unwrap(),
            "absent-hint envelope must canonicalize identically to the pre-#172 shape"
        );
    }

    /// #172: hints ride INSIDE the signed envelope — they are covered by
    /// `original_content_hash` and hybrid-verify, and read back via
    /// `transport_hints()`.
    #[tokio::test]
    async fn hints_are_signed_and_read_back() {
        let identity = HybridSigningIdentity::generate("node-1").unwrap();
        let signed = produce_self_key_record(&identity, "node", "2026-07-02T00:00:00Z", &hints())
            .await
            .unwrap();
        let r = &signed.record;

        // Read contract (persist's `KeyRecord::transport_hints()` shape).
        assert_eq!(r.transport_hints(), hints());
        assert_eq!(
            r.registration_envelope["transport_hints"][0]["destination"],
            "108.61.242.236:4242"
        );

        // The hints are inside the hash + signature: recompute + Strict verify.
        let canonical = jcs::canonicalize(&r.registration_envelope).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&canonical)),
            r.original_content_hash
        );
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
            "hint-carrying record must hybrid-verify (hints are inside the signature)"
        );

        // A hint tampered after signing breaks the hash cross-check fail-secure.
        let mut tampered = r.registration_envelope.clone();
        tampered["transport_hints"][0]["destination"] = json!("10.0.0.1:4242");
        assert_ne!(
            hex::encode(Sha256::digest(jcs::canonicalize(&tampered).unwrap())),
            r.original_content_hash,
            "mutating a hint after signing must diverge from original_content_hash"
        );
    }

    /// #172 no-drift with hints present: the scrubbed record's canonical envelope
    /// is byte-identical to the self-record's for the SAME identity fields AND
    /// hints — so persist verifies both through one canonicalization even when a
    /// canonical node is admitted-by-A1 with a reachability hint.
    #[tokio::test]
    async fn scrubbed_and_self_envelopes_match_with_hints() {
        let a1 = HybridSigningIdentity::generate("A1").unwrap();
        let node = HybridSigningIdentity::generate("canonical-server-1").unwrap();
        let node_ed = b64().encode(node.ed25519_public_key().await.unwrap());
        let node_mldsa = b64().encode(node.mldsa65_public_key().await.unwrap());

        let self_rec = produce_self_key_record(&node, "node", "2026-07-02T00:00:00Z", &hints())
            .await
            .unwrap();
        let scrubbed = produce_scrubbed_key_record(
            &a1,
            ScrubTarget {
                key_id: "canonical-server-1".to_string(),
                pubkey_ed25519_base64: node_ed,
                pubkey_ml_dsa_65_base64: node_mldsa,
                identity_type: "node".to_string(),
            },
            "2026-07-02T00:00:00Z",
            &hints(),
        )
        .await
        .unwrap();

        assert_eq!(
            jcs::canonicalize(&self_rec.record.registration_envelope).unwrap(),
            jcs::canonicalize(&scrubbed.record.registration_envelope).unwrap(),
            "hint-carrying envelopes must canonicalize identically (no drift)"
        );
        assert_eq!(
            self_rec.record.original_content_hash,
            scrubbed.record.original_content_hash
        );
        assert_eq!(scrubbed.record.transport_hints(), hints());
        // Admitted-by the accord holder, reachability attested in the same scrub.
        assert_eq!(scrubbed.record.scrub_key_id, "A1");
    }
}
