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

/// A single anchor-holder scrub signature over a canonical `registration_envelope`
/// (CIRISVerify#174 multi-scrub — CIRISPersist#383's 2-of-3 canonical add).
///
/// The 2nd..Nth scrubs of a multi-scrub canonical record ride in
/// [`KeyRecord::additional_scrubs`]; **scrub #1 stays in the base
/// `scrub_key_id` / `scrub_signature_classical` / `scrub_signature_pqc` fields**, so
/// a single-scrub record is byte-identical to the pre-#174 shape. Every scrub is
/// over the **same** canonical bytes (byte-identical `registration_envelope` /
/// `original_content_hash`) — the scrub *set* lives OUTSIDE the signed envelope, so a
/// 1-scrub and a 2-scrub record of the same target canonicalize identically (§3 of
/// CIRISPersist#383). `root_binding` roots via **any one** scrub; persist confers the
/// `canonical` role only on **≥2 distinct** anchor scrubs.
///
/// This is persist's exact wire shape for an entry of the additive `additional_scrubs`
/// set — pinned against `CIRISPersist/src/federation/types.rs::KeyRecord` field naming.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrubSig {
    /// The anchor holder (A1/B1/C1) whose key produced this scrub — FKs to a
    /// registered `federation_keys` row; the scrub verifies against its pubkey.
    pub scrub_key_id: String,
    /// Base64 `Ed25519.sign(JCS(registration_envelope))` — same canonical bytes
    /// as every other scrub on the record.
    pub scrub_signature_classical: String,
    /// Base64 `ML-DSA-65.sign(JCS(registration_envelope) ‖ ed25519_sig)`. `None`
    /// only for a hybrid-pending scrub (producers here always fill it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
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
    /// CIRISVerify#174 — the **2nd..Nth** anchor scrub signatures over the SAME
    /// canonical `registration_envelope` (scrub #1 is the base `scrub_*` fields
    /// above). Empty for an ordinary / single-scrub record → serializes away
    /// entirely, so the record stays **byte-identical** to the pre-#174 shape
    /// (persist recomputes `persist_row_hash`; an absent field can't perturb it).
    /// CIRISPersist admits the `canonical` role on **≥2 distinct** anchor scrubs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_scrubs: Vec<ScrubSig>,
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

    /// The **full ordered scrub set** (CIRISVerify#174): scrub #1 reconstructed
    /// from the base `scrub_*` fields, followed by every [`Self::additional_scrubs`]
    /// entry. Each is a signature over the *same* canonical `registration_envelope`
    /// bytes. This is the set persist roots (any one) / admits `canonical` on (≥2
    /// distinct).
    #[must_use]
    pub fn scrubs(&self) -> Vec<ScrubSig> {
        let mut out = Vec::with_capacity(1 + self.additional_scrubs.len());
        out.push(ScrubSig {
            scrub_key_id: self.scrub_key_id.clone(),
            scrub_signature_classical: self.scrub_signature_classical.clone(),
            scrub_signature_pqc: self.scrub_signature_pqc.clone(),
        });
        out.extend(self.additional_scrubs.iter().cloned());
        out
    }

    /// Count of **distinct** anchor `scrub_key_id`s across the whole scrub set
    /// ([`Self::scrubs`]). CIRISPersist#383 confers the `canonical` role only at
    /// `>= 2`; this is the producer-side pre-check that a ceremony reached quorum
    /// before the bytes are handed to persist.
    #[must_use]
    pub fn distinct_scrub_count(&self) -> usize {
        let mut ids = std::collections::BTreeSet::new();
        ids.insert(self.scrub_key_id.as_str());
        for s in &self.additional_scrubs {
            ids.insert(s.scrub_key_id.as_str());
        }
        ids.len()
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
        additional_scrubs: Vec::new(),
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
        additional_scrubs: Vec::new(),
    };
    Ok(SignedKeyRecord { record })
}

/// Produce a **multi-scrub** canonical key record — N anchor holders (A1/B1/C1)
/// each scrub-sign one node's registration, so the record roots at the accord
/// anchor with **≥2 distinct** scrubs and persist can confer the `canonical` role
/// (CIRISVerify#174 — CIRISPersist#383's 2-of-3 canonical add).
///
/// The envelope + canonical bytes are produced **once** (via
/// [`produce_scrubbed_key_record`] for scrub #1), then each remaining anchor's scrub
/// is [`append_scrub`]ed over those *same* bytes — so the record is byte-identical to
/// a single-scrub record of the same target, differing only by the scrub *set*
/// (§3 of #383). `scrubbers[0]` becomes scrub #1 (the base `scrub_*` fields); the
/// rest populate [`KeyRecord::additional_scrubs`].
///
/// Distinct-anchor is enforced ([`append_scrub`] rejects a duplicate `scrub_key_id`),
/// so a real 2-of-3 needs two *different* holders. Order of `scrubbers` only sets
/// which holder is scrub #1; the resulting canonical bytes are order-independent.
///
/// # Errors
///
/// [`VerifyError`] if `scrubbers` is empty, a signer faults, the envelope can't be
/// canonicalized, or two scrubbers share a `scrub_key_id`.
pub async fn produce_multiscrub_key_record(
    scrubbers: &[&dyn SelfSigner],
    target: ScrubTarget,
    valid_from: &str,
    transport_hints: &[TransportHint],
) -> Result<SignedKeyRecord, VerifyError> {
    let (first, rest) = scrubbers
        .split_first()
        .ok_or_else(|| VerifyError::IntegrityError {
            message: "produce_multiscrub_key_record requires at least one scrubber".to_string(),
        })?;
    // Scrub #1 mints the shared envelope + canonical bytes (base scrub_* fields).
    let mut record =
        produce_scrubbed_key_record(*first, target, valid_from, transport_hints).await?;
    // Each remaining anchor appends a scrub over those SAME bytes.
    for scrubber in rest {
        record = append_scrub(record, *scrubber).await?;
    }
    Ok(record)
}

/// Append a second (or Nth) anchor scrub to a **partial** canonical record over its
/// **byte-identical** canonical envelope (CIRISVerify#174) — the load-bearing
/// cross-device ceremony op: A1 scrubs on device 1 → a 1-scrub partial → B1
/// `append_scrub`s on device 2 → a ≥2-scrub record persist admits as `canonical`.
///
/// The appended scrub is over the record's **existing** `registration_envelope`,
/// recanonicalized here and **hash-checked against `original_content_hash` first**
/// (fail-secure: a partial whose envelope was tampered in transit can't get a fresh
/// valid scrub laid over the bad bytes). Distinct-anchor is enforced — appending a
/// `scrub_key_id` already in the scrub set is rejected (no double-count toward the
/// ≥2 quorum). The envelope, `original_content_hash`, and scrub #1 are untouched, so
/// the result canonicalizes identically to the input (only the scrub set grows).
///
/// # Errors
///
/// [`VerifyError`] if the envelope can't be canonicalized, its recomputed hash
/// doesn't match `original_content_hash`, `scrubber`'s `scrub_key_id` is already
/// present, or the signer faults.
pub async fn append_scrub(
    mut record: SignedKeyRecord,
    scrubber: &dyn SelfSigner,
) -> Result<SignedKeyRecord, VerifyError> {
    // Recanonicalize the EXISTING envelope — the appended scrub is over the same
    // canonical bytes as every scrub already on the record.
    let canonical = jcs::canonicalize(&record.record.registration_envelope)?;
    let recomputed = hex::encode(Sha256::digest(&canonical));
    if recomputed != record.record.original_content_hash {
        return Err(VerifyError::IntegrityError {
            message: format!(
                "append_scrub: recomputed envelope hash {recomputed} != original_content_hash {} \
                 — refusing to scrub a tampered partial",
                record.record.original_content_hash
            ),
        });
    }

    // Distinct-anchor guard: one holder cannot double-count toward the ≥2 quorum.
    let new_id = scrubber.key_id().to_string();
    if record
        .record
        .scrubs()
        .iter()
        .any(|s| s.scrub_key_id == new_id)
    {
        return Err(VerifyError::IntegrityError {
            message: format!("append_scrub: anchor {new_id} has already scrubbed this record"),
        });
    }

    let (ed_sig_b64, pqc_sig_b64) = scrubber.sign_bound(&canonical).await?;
    record.record.additional_scrubs.push(ScrubSig {
        scrub_key_id: new_id,
        scrub_signature_classical: ed_sig_b64,
        scrub_signature_pqc: Some(pqc_sig_b64),
    });
    Ok(record)
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
            // #174: the additive multi-scrub set persist will read (serde-default
            // empty on pre-#174 records) — same field name + entry shape.
            #[serde(default)]
            additional_scrubs: Vec<PersistShapedScrub>,
        }
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct PersistShapedScrub {
            scrub_key_id: String,
            scrub_signature_classical: String,
            #[serde(default)]
            scrub_signature_pqc: Option<String>,
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
        // A single-scrub record carries NO additional_scrubs (byte-compat).
        assert!(parsed.additional_scrubs.is_empty());
        // valid_from parsed as a real timestamp (not a bare/offsetless string).
        assert_eq!(
            parsed.valid_from,
            "2026-06-18T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );

        // #174: a 2-scrub canonical record round-trips too — the extra anchor
        // shows up in `additional_scrubs` with persist's field names.
        let a1 = HybridSigningIdentity::generate("A1").unwrap();
        let b1 = HybridSigningIdentity::generate("B1").unwrap();
        let node = HybridSigningIdentity::generate("canonical-server-1").unwrap();
        let node_ed = b64().encode(node.ed25519_public_key().await.unwrap());
        let node_mldsa = b64().encode(node.mldsa65_public_key().await.unwrap());
        let multi = produce_multiscrub_key_record(
            &[&a1, &b1],
            ScrubTarget {
                key_id: "canonical-server-1".to_string(),
                pubkey_ed25519_base64: node_ed,
                pubkey_ml_dsa_65_base64: node_mldsa,
                identity_type: "node".to_string(),
            },
            "2026-07-05T00:00:00Z",
            &[],
        )
        .await
        .unwrap();
        let multi_parsed: PersistShapedKeyRecord =
            serde_json::from_value(serde_json::to_value(&multi.record).unwrap())
                .expect("multi-scrub record must deserialize into Persist's shape");
        assert_eq!(multi_parsed.scrub_key_id, "A1", "scrub #1 in base fields");
        assert_eq!(
            multi_parsed.additional_scrubs.len(),
            1,
            "B1 is the 2nd scrub"
        );
        assert_eq!(multi_parsed.additional_scrubs[0].scrub_key_id, "B1");
        assert!(multi_parsed.additional_scrubs[0]
            .scrub_signature_pqc
            .is_some());
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

    // ---- #174 multi-scrub / append-a-scrub -------------------------------

    /// Hybrid-verify one [`ScrubSig`] against its signer's pubkeys over the shared
    /// canonical bytes — the `root_binding` check persist runs per scrub.
    async fn scrub_hybrid_verifies(
        canonical: &[u8],
        signer: &dyn SelfSigner,
        scrub: &ScrubSig,
    ) -> bool {
        let member = ThresholdMember {
            member_id: scrub.scrub_key_id.clone(),
            ed25519_public_key_base64: b64().encode(signer.ed25519_public_key().await.unwrap()),
            mldsa65_public_key_base64: Some(
                b64().encode(signer.mldsa65_public_key().await.unwrap()),
            ),
            role: None,
        };
        let sig = ThresholdSignature {
            member_id: scrub.scrub_key_id.clone(),
            ed25519_signature_base64: scrub.scrub_signature_classical.clone(),
            mldsa65_signature_base64: scrub.scrub_signature_pqc.clone(),
        };
        verify_threshold_signatures(canonical, &[member], &[sig], 1) == Ok(1)
    }

    async fn node_target() -> (HybridSigningIdentity, ScrubTarget) {
        let node = HybridSigningIdentity::generate("canonical-server-1").unwrap();
        let target = ScrubTarget {
            key_id: "canonical-server-1".to_string(),
            pubkey_ed25519_base64: b64().encode(node.ed25519_public_key().await.unwrap()),
            pubkey_ml_dsa_65_base64: b64().encode(node.mldsa65_public_key().await.unwrap()),
            identity_type: "node".to_string(),
        };
        (node, target)
    }

    /// #174: a 2-scrub record canonicalizes IDENTICALLY to a 1-scrub record of the
    /// same target (only the scrub set differs), reaches the 2-distinct quorum, and
    /// each anchor's scrub hybrid-verifies against its own key over the shared bytes.
    #[tokio::test]
    async fn multiscrub_matches_single_scrub_bytes_and_both_anchors_verify() {
        let a1 = HybridSigningIdentity::generate("A1").unwrap();
        let b1 = HybridSigningIdentity::generate("B1").unwrap();
        let (_node, target) = node_target().await;

        let single = produce_scrubbed_key_record(&a1, target.clone(), "2026-07-05T00:00:00Z", &[])
            .await
            .unwrap();
        let multi = produce_multiscrub_key_record(&[&a1, &b1], target, "2026-07-05T00:00:00Z", &[])
            .await
            .unwrap();

        // §3 of #383: same canonical envelope + hash — scrubs live OUTSIDE it.
        assert_eq!(
            jcs::canonicalize(&single.record.registration_envelope).unwrap(),
            jcs::canonicalize(&multi.record.registration_envelope).unwrap(),
        );
        assert_eq!(
            single.record.original_content_hash,
            multi.record.original_content_hash
        );

        // Quorum: A1 (base fields) + B1 (additional_scrubs) = 2 distinct.
        assert_eq!(multi.record.scrub_key_id, "A1", "scrub #1 in base fields");
        assert_eq!(multi.record.additional_scrubs.len(), 1);
        assert_eq!(multi.record.additional_scrubs[0].scrub_key_id, "B1");
        assert_eq!(multi.record.distinct_scrub_count(), 2);

        // Each scrub verifies over the SAME canonical bytes against its own key.
        let canonical = jcs::canonicalize(&multi.record.registration_envelope).unwrap();
        let scrubs = multi.record.scrubs();
        assert!(scrub_hybrid_verifies(&canonical, &a1, &scrubs[0]).await);
        assert!(scrub_hybrid_verifies(&canonical, &b1, &scrubs[1]).await);
        // …and cross-checks fail (A1's scrub is not valid under B1's key).
        assert!(!scrub_hybrid_verifies(&canonical, &b1, &scrubs[0]).await);
    }

    /// #174 cross-device ceremony: A1 scrubs on device 1 → a 1-scrub partial that
    /// travels as JSON → B1 `append_scrub`s on device 2 → a ≥2 record persist
    /// admits. The append is over byte-identical bytes; scrub #1 is untouched.
    #[tokio::test]
    async fn append_scrub_completes_the_2_of_3_over_identical_bytes() {
        let a1 = HybridSigningIdentity::generate("A1").unwrap();
        let b1 = HybridSigningIdentity::generate("B1").unwrap();
        let (_node, target) = node_target().await;

        // Device 1: A1 mints the partial.
        let partial = produce_scrubbed_key_record(&a1, target, "2026-07-05T00:00:00Z", &[])
            .await
            .unwrap();
        // Serialize → deserialize to simulate the accord-gossip hop.
        let wire = serde_json::to_value(&partial).unwrap();
        let received: SignedKeyRecord = serde_json::from_value(wire).unwrap();
        assert!(received.record.additional_scrubs.is_empty());

        // Device 2: B1 appends. Envelope + hash + scrub #1 unchanged.
        let completed = append_scrub(received, &b1).await.unwrap();
        assert_eq!(
            completed.record.original_content_hash,
            partial.record.original_content_hash
        );
        assert_eq!(completed.record.scrub_key_id, "A1");
        assert_eq!(
            completed.record.scrub_signature_classical,
            partial.record.scrub_signature_classical
        );
        assert_eq!(completed.record.distinct_scrub_count(), 2);

        let canonical = jcs::canonicalize(&completed.record.registration_envelope).unwrap();
        let scrubs = completed.record.scrubs();
        assert!(scrub_hybrid_verifies(&canonical, &a1, &scrubs[0]).await);
        assert!(scrub_hybrid_verifies(&canonical, &b1, &scrubs[1]).await);
    }

    /// #174: one holder cannot double-count toward the quorum — appending an anchor
    /// already in the scrub set is rejected.
    #[tokio::test]
    async fn append_scrub_rejects_a_duplicate_anchor() {
        let a1 = HybridSigningIdentity::generate("A1").unwrap();
        let (_node, target) = node_target().await;
        let partial = produce_scrubbed_key_record(&a1, target, "2026-07-05T00:00:00Z", &[])
            .await
            .unwrap();
        // A1 tries to append again → refused (still just 1 distinct anchor).
        assert!(append_scrub(partial, &a1).await.is_err());
    }

    /// #174 fail-secure: a partial whose envelope was tampered in transit must not
    /// receive a fresh valid scrub over the bad bytes — the hash cross-check refuses.
    #[tokio::test]
    async fn append_scrub_refuses_a_tampered_partial() {
        let a1 = HybridSigningIdentity::generate("A1").unwrap();
        let b1 = HybridSigningIdentity::generate("B1").unwrap();
        let (_node, target) = node_target().await;
        let mut partial = produce_scrubbed_key_record(&a1, target, "2026-07-05T00:00:00Z", &[])
            .await
            .unwrap();
        // Mutate the envelope after A1 signed → recomputed hash != original_content_hash.
        partial.record.registration_envelope["identity_type"] = json!("agent");
        assert!(append_scrub(partial, &b1).await.is_err());
    }

    /// #174 byte-identity / row-hash parity: a single-scrub record serializes with
    /// NO `additional_scrubs` key, so it is wire-identical to a pre-#174 record.
    #[tokio::test]
    async fn single_scrub_record_omits_additional_scrubs_in_json() {
        let a1 = HybridSigningIdentity::generate("A1").unwrap();
        let (_node, target) = node_target().await;
        let single = produce_scrubbed_key_record(&a1, target, "2026-07-05T00:00:00Z", &[])
            .await
            .unwrap();
        let json = serde_json::to_value(&single.record).unwrap();
        assert!(
            json.get("additional_scrubs").is_none(),
            "an empty scrub set must not materialize the key (row-hash parity)"
        );
        assert_eq!(single.record.distinct_scrub_count(), 1);
    }

    /// #174: `produce_multiscrub_key_record` requires at least one scrubber.
    #[tokio::test]
    async fn multiscrub_empty_scrubbers_is_an_error() {
        let (_node, target) = node_target().await;
        assert!(
            produce_multiscrub_key_record(&[], target, "2026-07-05T00:00:00Z", &[])
                .await
                .is_err()
        );
    }
}
