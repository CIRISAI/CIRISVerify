//! CC 5.3.4 — the **GenesisBundle**: the portable trust root a registry or
//! canonical node serves at `/v1/trust-root/bundle` (alias `/v1/steward-key`),
//! hybrid-authorized by the accord holders (CIRISVerify#176, #69,
//! CIRISPersist#1141).
//!
//! # One preimage, owned here
//!
//! The holders sign [`authorization_digest`]: SHA-256 over the JCS
//! canonicalization of a **projection** of the bundle. Until this module that
//! projection lived in CIRISPersist (`federation/genesis/bundle.rs`), mirrored
//! by CIRISServer. Persist depends on verify, so a verify-side reader had either
//! to copy it — a third signing preimage, the drift class behind v10.4.0 and
//! v13.2.0 — or to own it. It is owned here, and persist and server delegate
//! (CIRISPersist#1141), gated by a byte-identity test against the vectors in
//! `tests/vectors/genesis_bundle/`, which were produced by **persist's own
//! function** at `ee30310f`, not by this code.
//!
//! The projection, exactly:
//!
//! ```text
//! JCS({
//!   version, family_key_id, consensus_protocol, produced_at,
//!   holders:     [record minus {persist_row_hash, pqc_completed_at,
//!                               scrub_key_id, scrub_signature_classical,
//!                               scrub_signature_pqc, scrub_timestamp,
//!                               additional_scrubs}],
//!   serve_nodes: [same projection],
//!   attestations: [rows → {attestation_id, attesting_key_id, attested_key_id,
//!                          attestation_type, attestation_envelope}]
//!                 ++ [roster records → {family: envelope} | {community: envelope}],
//!   serve_transport_destinations: [{attesting_key_id, signed_envelope}]  // version ≥ 4 only
//! })
//! ```
//!
//! **Records are projected through typed serde, never from raw wire JSON**,
//! because that is what persist does and the two are not the same bytes: a
//! record's instants re-render through `chrono` (`+00:00` becomes `Z`, trailing
//! zero fractions drop), an `Option` written as `null` is omitted, an empty
//! `roles` is materialized as `[]`, an unknown member is dropped. Each mirror
//! type below carries persist's serde attributes member for member, and the
//! vectors cover the cases where raw and typed differ.
//!
//! # Verifying
//!
//! [`verify_genesis_bundle`] is the CC 5.3.4 floor: *"a consumer MUST verify
//! the bundle's quorum against its own records before promoting any field to a
//! trust root."* Its own records are the holders baked into this binary from
//! the genesis ceremony (#107) — never `bundle.holders`, which is carried as a
//! cross-check and has no authority. The threshold is
//! `max(carried M, strict majority of the baked roster)`, so a bundle cannot
//! talk its own threshold down and one that asks for more still gets it.
//! Every counted authorization is hybrid (Ed25519 over the digest, ML-DSA-65
//! over `digest ‖ ed25519_sig`); a duplicate holder is refused, not merged.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::threshold::{
    verify_threshold_signatures_with_policy, HybridPolicy, ThresholdMember, ThresholdSignature,
};

/// The first bundle version that carries the roster records (family /
/// community) inside `attestations`.
pub const ROSTER_RECORDS_VERSION: u32 = 3;

/// The first bundle version whose digest binds `serve_transport_destinations`.
pub const SERVE_TRANSPORT_DESTINATIONS_VERSION: u32 = 4;

/// The only bundle version [`verify_genesis_bundle`] accepts as a trust root.
/// The registry and canonical nodes serve v4 only (hard cut, registry 4.1.0);
/// [`authorization_digest`] still computes v2 and v3 so the digest is one
/// implementation for every reader, including persist's stored history.
pub const ACCEPTED_BUNDLE_VERSION: u32 = 4;

/// The `attestation_id` of the root charter row; its `attested_key_id` names
/// the charter root.
pub const GENESIS_CHARTER_ATTESTATION_ID: &str = "genesis-charter";

/// Why a bundle could not be parsed or verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GenesisBundleError {
    /// The bundle does not parse under the wire shape.
    #[error("genesis bundle malformed: {0}")]
    Malformed(String),
    /// The bundle is a version this verifier does not accept as a root.
    #[error("genesis bundle version {got} is not accepted (accepts {accepted})")]
    UnacceptedVersion {
        /// The version the bundle carries.
        got: u32,
        /// The version this verifier accepts.
        accepted: u32,
    },
    /// The bundle names a different family from the baked accord.
    #[error("genesis bundle is for family {got:?}, not {expected:?}")]
    WrongFamily {
        /// The bundle's `family_key_id`.
        got: String,
        /// The baked accord family.
        expected: String,
    },
    /// `consensus_protocol` is not `quorum:M/N`. A verifier must not guess a
    /// threshold.
    #[error("genesis bundle consensus_protocol {0:?} is not quorum:M/N")]
    UnparseableProtocol(String),
    /// Two authorizations name the same holder.
    #[error("genesis bundle carries two authorizations from {0}")]
    DuplicateAuthorization(String),
    /// No baked accord roster is available to verify against.
    #[error("no baked accord roster to verify the genesis bundle against")]
    NoBakedRoster,
    /// Fewer distinct baked holders authorized the bundle than its threshold.
    #[error("genesis bundle quorum not met: {have} of {needed} required authorizations")]
    QuorumNotMet {
        /// Verified authorizations from baked holders.
        have: usize,
        /// Required.
        needed: usize,
    },
    /// The bundle carries no `genesis-charter` row.
    #[error("genesis bundle has no genesis-charter row")]
    NoCharter,
}

/// One holder's hybrid authorization over [`authorization_digest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisAuthorization {
    /// The authorizing holder's key id.
    pub holder_key_id: String,
    /// Ed25519 over the 32-byte digest, base64.
    pub signature_classical: String,
    /// ML-DSA-65 over `digest ‖ ed25519_sig`, base64.
    pub signature_pqc: String,
}

// ─── persist mirror types (projection only) ────────────────────────────────
//
// Member for member, attribute for attribute, persist's `federation::types`
// at ee30310f. Only what the digest serializes is mirrored; a field persist
// adds to `KeyRecord` is bound by persist's digest by default and will show
// up here as a vector mismatch, which is the intended failure.

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScrubSig {
    scrub_key_id: String,
    scrub_signature_classical: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scrub_signature_pqc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cosigned_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyRecord {
    key_id: String,
    pubkey_ed25519_base64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pubkey_ml_dsa_65_base64: Option<String>,
    algorithm: String,
    identity_type: String,
    identity_ref: String,
    valid_from: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    valid_until: Option<DateTime<Utc>>,
    registration_envelope: Value,
    original_content_hash: String,
    scrub_signature_classical: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scrub_signature_pqc: Option<String>,
    scrub_key_id: String,
    scrub_timestamp: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pqc_completed_at: Option<DateTime<Utc>>,
    persist_row_hash: String,
    #[serde(default, rename = "roles")]
    capability_roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attestation_evidence: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consent_role: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    additional_scrubs: Vec<ScrubSig>,
}

/// The record members the digest never binds: two node-local (persist
/// computes them) and five the ceremony itself mutates after a holder signs
/// (the accumulating scrub set; binding them makes a 2-of-3 ceremony
/// impossible to complete, CIRISPersist#683).
const UNBOUND_RECORD_MEMBERS: [&str; 7] = [
    "persist_row_hash",
    "pqc_completed_at",
    "scrub_key_id",
    "scrub_signature_classical",
    "scrub_signature_pqc",
    "scrub_timestamp",
    "additional_scrubs",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedKeyRecord {
    record: KeyRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RosterMember {
    key_id: String,
    joined_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Family {
    family_key_id: String,
    family_name: String,
    members: Vec<RosterMember>,
    founded_at: DateTime<Utc>,
    consensus_protocol: String,
    #[serde(default)]
    consensus_protocol_entrenched: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dissolved_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    prev_head_digest: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    charter_digest: String,
    persist_row_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Community {
    community_key_id: String,
    community_name: String,
    members: Vec<RosterMember>,
    founded_at: DateTime<Utc>,
    consensus_protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_blob: Option<Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    prev_head_digest: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    charter_digest: String,
    persist_row_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AttestationRow {
    attestation_id: String,
    attesting_key_id: String,
    attested_key_id: String,
    attestation_type: String,
    attestation_envelope: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct SignedAttestationRow {
    attestation: AttestationRow,
}

#[derive(Debug, Clone, Deserialize)]
struct SignedFamily {
    family: Family,
}

#[derive(Debug, Clone, Deserialize)]
struct SignedCommunity {
    community: Community,
}

#[derive(Debug, Clone, Deserialize)]
struct TransportRow {
    attesting_key_id: String,
    signed_envelope: Value,
}

#[derive(Debug, Clone)]
enum RosterRecord {
    Family(Family),
    Community(Community),
}

impl RosterRecord {
    /// The record's own signing envelope (its serde form minus
    /// `persist_row_hash`) under its kind.
    fn digest_projection(&self) -> Result<Value, GenesisBundleError> {
        let (kind, mut v) = match self {
            Self::Family(f) => ("family", to_value(f)?),
            Self::Community(c) => ("community", to_value(c)?),
        };
        if let Some(obj) = v.as_object_mut() {
            obj.remove("persist_row_hash");
        }
        Ok(serde_json::json!({ kind: v }))
    }
}

#[derive(Debug, Clone, Deserialize)]
struct WireIn {
    version: u32,
    family_key_id: String,
    holders: Vec<SignedKeyRecord>,
    serve_nodes: Vec<SignedKeyRecord>,
    consensus_protocol: String,
    attestations: Vec<Value>,
    authorizations: Vec<GenesisAuthorization>,
    produced_at: String,
    #[serde(default)]
    serve_transport_destinations: Vec<TransportRow>,
}

/// A parsed GenesisBundle: what the digest is computed over, plus the
/// authorizations. Construct with [`GenesisBundle::from_value`].
#[derive(Debug, Clone)]
pub struct GenesisBundle {
    version: u32,
    family_key_id: String,
    consensus_protocol: String,
    produced_at: String,
    holders: Vec<KeyRecord>,
    serve_nodes: Vec<KeyRecord>,
    rows: Vec<AttestationRow>,
    roster_records: Vec<RosterRecord>,
    serve_transport_destinations: Vec<TransportRow>,
    authorizations: Vec<GenesisAuthorization>,
}

impl GenesisBundle {
    /// Parse the `bundle` member of a `/v1/trust-root/bundle` response (pass
    /// the inner object, not the wrapper). Each `attestations` element is
    /// exactly one of a delegation row (`attestation`), a family record
    /// (`family`) or a community record (`community`), and every row precedes
    /// every roster record — one spelling, so a parse and a re-serialization
    /// are the same bytes.
    pub fn from_value(bundle: &Value) -> Result<Self, GenesisBundleError> {
        let w: WireIn = serde_json::from_value(bundle.clone())
            .map_err(|e| GenesisBundleError::Malformed(e.to_string()))?;
        let mut rows = Vec::new();
        let mut roster_records = Vec::new();
        for (n, member) in w.attestations.into_iter().enumerate() {
            let has = |k: &str| member.get(k).is_some();
            let err = |e: serde_json::Error| {
                GenesisBundleError::Malformed(format!("attestations[{n}]: {e}"))
            };
            match [has("attestation"), has("family"), has("community")] {
                [true, false, false] => {
                    if !roster_records.is_empty() {
                        return Err(GenesisBundleError::Malformed(format!(
                            "attestations[{n}]: a delegation row follows a roster record"
                        )));
                    }
                    let row: SignedAttestationRow = serde_json::from_value(member).map_err(err)?;
                    rows.push(row.attestation);
                },
                [false, true, false] => {
                    let f: SignedFamily = serde_json::from_value(member).map_err(err)?;
                    roster_records.push(RosterRecord::Family(f.family));
                },
                [false, false, true] => {
                    let c: SignedCommunity = serde_json::from_value(member).map_err(err)?;
                    roster_records.push(RosterRecord::Community(c.community));
                },
                _ => {
                    return Err(GenesisBundleError::Malformed(format!(
                        "attestations[{n}]: an element is exactly one of `attestation`, \
                         `family` or `community`"
                    )))
                },
            }
        }
        Ok(Self {
            version: w.version,
            family_key_id: w.family_key_id,
            consensus_protocol: w.consensus_protocol,
            produced_at: w.produced_at,
            holders: w.holders.into_iter().map(|h| h.record).collect(),
            serve_nodes: w.serve_nodes.into_iter().map(|n| n.record).collect(),
            rows,
            roster_records,
            serve_transport_destinations: w.serve_transport_destinations,
            authorizations: w.authorizations,
        })
    }

    /// The bundle's schema version.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The accord family this bundle seeds.
    #[must_use]
    pub fn family_key_id(&self) -> &str {
        &self.family_key_id
    }

    /// The carried authorizations.
    #[must_use]
    pub fn authorizations(&self) -> &[GenesisAuthorization] {
        &self.authorizations
    }
}

fn to_value<T: Serialize>(t: &T) -> Result<Value, GenesisBundleError> {
    serde_json::to_value(t).map_err(|e| GenesisBundleError::Malformed(e.to_string()))
}

fn project_record(record: &KeyRecord) -> Result<Value, GenesisBundleError> {
    let mut v = to_value(record)?;
    let map = v.as_object_mut().ok_or_else(|| {
        GenesisBundleError::Malformed(format!("record {} is not an object", record.key_id))
    })?;
    for member in UNBOUND_RECORD_MEMBERS {
        map.remove(member);
    }
    Ok(v)
}

/// The 32 bytes every holder authorization signs. See the module docs for
/// the projection; it is byte-identical to CIRISPersist's
/// `authorization_digest` at `ee30310f`, asserted by vectors that persist's
/// function produced.
pub fn authorization_digest(bundle: &GenesisBundle) -> Result<[u8; 32], GenesisBundleError> {
    let mut attestations = bundle
        .rows
        .iter()
        .map(|a| {
            serde_json::json!({
                "attestation_id": a.attestation_id,
                "attesting_key_id": a.attesting_key_id,
                "attested_key_id": a.attested_key_id,
                "attestation_type": a.attestation_type,
                "attestation_envelope": a.attestation_envelope,
            })
        })
        .collect::<Vec<_>>();
    for r in &bundle.roster_records {
        attestations.push(r.digest_projection()?);
    }
    let mut preimage = serde_json::json!({
        "version": bundle.version,
        "family_key_id": bundle.family_key_id,
        "consensus_protocol": bundle.consensus_protocol,
        "produced_at": bundle.produced_at,
        "holders": bundle.holders.iter().map(project_record).collect::<Result<Vec<_>, _>>()?,
        "serve_nodes": bundle.serve_nodes.iter().map(project_record).collect::<Result<Vec<_>, _>>()?,
        "attestations": attestations,
    });
    if bundle.version >= SERVE_TRANSPORT_DESTINATIONS_VERSION {
        if let Some(map) = preimage.as_object_mut() {
            map.insert(
                "serve_transport_destinations".to_owned(),
                bundle
                    .serve_transport_destinations
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "attesting_key_id": r.attesting_key_id,
                            "signed_envelope": r.signed_envelope,
                        })
                    })
                    .collect::<Vec<_>>()
                    .into(),
            );
        }
    }
    let canonical = crate::jcs::canonicalize(&preimage)
        .map_err(|e| GenesisBundleError::Malformed(e.to_string()))?;
    Ok(Sha256::digest(&canonical).into())
}

/// `sha256:<64 lowercase hex>` over `JCS(bundle)`: the CC 5.3.4
/// `bundle_fingerprint`, recomputed from the bundle as served rather than
/// read off the unsigned wrapper.
pub fn bundle_fingerprint(bundle: &Value) -> Result<String, GenesisBundleError> {
    let canonical = crate::jcs::canonicalize(bundle)
        .map_err(|e| GenesisBundleError::Malformed(e.to_string()))?;
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(&canonical))
    ))
}

/// `M` of a `quorum:M/N` protocol string; `None` for anything else.
#[must_use]
pub fn quorum_m(protocol: &str) -> Option<usize> {
    let rest = protocol.strip_prefix("quorum:")?;
    let (m, n) = rest.split_once('/')?;
    let m: usize = m.parse().ok()?;
    let n: usize = n.parse().ok()?;
    (m > 0 && m <= n).then_some(m)
}

/// One serve node the verified bundle confers, as the bundle carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServeNode {
    /// The node's key id.
    pub key_id: String,
    /// Ed25519 public key, base64.
    pub pubkey_ed25519_base64: String,
    /// ML-DSA-65 public key, base64, if carried.
    pub pubkey_ml_dsa_65_base64: Option<String>,
    /// The record's capability roles.
    pub roles: Vec<String>,
}

/// What a verified bundle establishes. Only built by [`verify_genesis_bundle`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedGenesisBundle {
    /// The bundle version (always [`ACCEPTED_BUNDLE_VERSION`]).
    pub version: u32,
    /// The accord family.
    pub family_key_id: String,
    /// `attested_key_id` of the `genesis-charter` row.
    pub charter_root_key_id: String,
    /// The baked holders whose authorization verified, sorted.
    pub authorized_by: Vec<String>,
    /// The threshold that was applied.
    pub threshold: usize,
    /// The hex [`authorization_digest`].
    pub authorization_digest: String,
    /// The recomputed `bundle_fingerprint`.
    pub bundle_fingerprint: String,
    /// The serve nodes the bundle confers.
    pub serve_nodes: Vec<ServeNode>,
    /// The ceremony instant.
    pub produced_at: String,
}

/// Verify a GenesisBundle against the holders baked into this binary
/// ([`crate::accord_genesis::baked_accord_roster`]). See
/// [`verify_genesis_bundle_against`].
pub fn verify_genesis_bundle(bundle: &Value) -> Result<VerifiedGenesisBundle, GenesisBundleError> {
    let roster = crate::accord_genesis::baked_accord_roster();
    verify_genesis_bundle_against(
        bundle,
        &roster,
        crate::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID,
    )
}

/// Verify a GenesisBundle (the inner `bundle` object) against a caller-pinned
/// holder `roster` and family.
///
/// Refuses: an unparseable bundle; any version but [`ACCEPTED_BUNDLE_VERSION`];
/// another family; a `consensus_protocol` that is not `quorum:M/N`; two
/// authorizations from one holder; fewer than
/// `max(M, strict_majority(roster))` hybrid authorizations from roster
/// holders; a bundle with no `genesis-charter` row. An authorization from a key
/// outside `roster` is ignored, never counted.
pub fn verify_genesis_bundle_against(
    bundle: &Value,
    roster: &[ThresholdMember],
    family_key_id: &str,
) -> Result<VerifiedGenesisBundle, GenesisBundleError> {
    if roster.is_empty() {
        return Err(GenesisBundleError::NoBakedRoster);
    }
    let parsed = GenesisBundle::from_value(bundle)?;
    if parsed.version != ACCEPTED_BUNDLE_VERSION {
        return Err(GenesisBundleError::UnacceptedVersion {
            got: parsed.version,
            accepted: ACCEPTED_BUNDLE_VERSION,
        });
    }
    if parsed.family_key_id != family_key_id {
        return Err(GenesisBundleError::WrongFamily {
            got: parsed.family_key_id,
            expected: family_key_id.to_owned(),
        });
    }
    let carried_m = quorum_m(&parsed.consensus_protocol).ok_or_else(|| {
        GenesisBundleError::UnparseableProtocol(parsed.consensus_protocol.clone())
    })?;
    let needed = carried_m.max(crate::accord_genesis::strict_majority(roster.len()));

    let mut seen = BTreeSet::new();
    for a in &parsed.authorizations {
        if !seen.insert(a.holder_key_id.as_str()) {
            return Err(GenesisBundleError::DuplicateAuthorization(
                a.holder_key_id.clone(),
            ));
        }
    }

    let digest = authorization_digest(&parsed)?;
    let in_roster: BTreeSet<&str> = roster.iter().map(|m| m.member_id.as_str()).collect();
    let signatures: Vec<ThresholdSignature> = parsed
        .authorizations
        .iter()
        .filter(|a| in_roster.contains(a.holder_key_id.as_str()))
        .map(|a| ThresholdSignature {
            member_id: a.holder_key_id.clone(),
            ed25519_signature_base64: a.signature_classical.clone(),
            mldsa65_signature_base64: Some(a.signature_pqc.clone()),
        })
        .collect();

    let mut authorized_by = Vec::new();
    for sig in &signatures {
        if verify_threshold_signatures_with_policy(
            &digest,
            roster,
            std::slice::from_ref(sig),
            1,
            HybridPolicy::RequireHybrid,
        )
        .is_ok()
        {
            authorized_by.push(sig.member_id.clone());
        }
    }
    authorized_by.sort();
    if authorized_by.len() < needed {
        return Err(GenesisBundleError::QuorumNotMet {
            have: authorized_by.len(),
            needed,
        });
    }

    let charter_root_key_id = parsed
        .rows
        .iter()
        .find(|r| r.attestation_id == GENESIS_CHARTER_ATTESTATION_ID)
        .map(|r| r.attested_key_id.clone())
        .ok_or(GenesisBundleError::NoCharter)?;

    Ok(VerifiedGenesisBundle {
        version: parsed.version,
        family_key_id: parsed.family_key_id.clone(),
        charter_root_key_id,
        authorized_by,
        threshold: needed,
        authorization_digest: hex::encode(digest),
        bundle_fingerprint: bundle_fingerprint(bundle)?,
        serve_nodes: parsed
            .serve_nodes
            .iter()
            .map(|n| ServeNode {
                key_id: n.key_id.clone(),
                pubkey_ed25519_base64: n.pubkey_ed25519_base64.clone(),
                pubkey_ml_dsa_65_base64: n.pubkey_ml_dsa_65_base64.clone(),
                roles: n.capability_roles.clone(),
            })
            .collect(),
        produced_at: parsed.produced_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const V2: &str = include_str!("../tests/vectors/genesis_bundle/v2_registry_live.json");
    const V4: &str = include_str!("../tests/vectors/genesis_bundle/v4_persist_v59_1_0.json");

    /// Produced by CIRISPersist's own `authorization_digest` at `ee30310f`
    /// (scratch example over these exact files), not by this module.
    const V2_DIGEST: &str = "787d0632ae8a645d2c52c6f65909724d8cb370399b14b4c7077786229dabe952";
    const V4_DIGEST: &str = "8e5f5a7c5af3ecad7f4e370b6b53b624683bd69729e39bcf4ee41b39077a198a";

    fn v(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn digest_matches_persist_on_the_live_v2_and_v4_bundles() {
        for (src, want) in [(V2, V2_DIGEST), (V4, V4_DIGEST)] {
            let b = GenesisBundle::from_value(&v(src)).unwrap();
            assert_eq!(hex::encode(authorization_digest(&b).unwrap()), want);
        }
    }

    /// Every vector's digest as CIRISPersist's own `authorization_digest`
    /// computed it at `ee30310f`. The `v4_variant_*` files edit holder 0's
    /// record where a raw-JSON projection and persist's typed one would
    /// differ: an `Option` written as `null`, `roles` absent, an instant with
    /// a `+00:00` offset, and an unknown member.
    #[test]
    fn digest_matches_persist_on_every_vector() {
        let cases: [(&str, &str); 7] = [
            (V2, V2_DIGEST),
            (
                include_str!("../tests/vectors/genesis_bundle/v3_persist_c45a1519.json"),
                "4ccbed38990cb4b6127ff13c2444126fe5e8ca168f5d4e69832b5b9a399eaf0f",
            ),
            (V4, V4_DIGEST),
            (
                include_str!("../tests/vectors/genesis_bundle/v4_variant_valid_until_null.json"),
                V4_DIGEST,
            ),
            (
                include_str!("../tests/vectors/genesis_bundle/v4_variant_roles_absent.json"),
                V4_DIGEST,
            ),
            (
                include_str!("../tests/vectors/genesis_bundle/v4_variant_offset_instant.json"),
                V4_DIGEST,
            ),
            (
                include_str!("../tests/vectors/genesis_bundle/v4_variant_null_and_unknown.json"),
                "ee49f07c7e32cecfd26250c13e278876c20174219259089b7f607c0cf51222e1",
            ),
        ];
        for (n, (src, want)) in cases.iter().enumerate() {
            let b = GenesisBundle::from_value(&v(src)).unwrap();
            assert_eq!(
                hex::encode(authorization_digest(&b).unwrap()),
                *want,
                "vector {n}"
            );
        }
    }

    #[test]
    fn the_live_v4_bundle_verifies_against_the_baked_roster() {
        let out = verify_genesis_bundle(&v(V4)).unwrap();
        assert_eq!(out.version, 4);
        assert_eq!(out.family_key_id, "humanity-accord");
        assert_eq!(out.charter_root_key_id, "humanity-accord");
        assert_eq!(out.authorized_by, vec!["A1".to_string(), "B1".to_string()]);
        assert_eq!(out.threshold, 2);
        assert_eq!(out.authorization_digest, V4_DIGEST);
        assert_eq!(out.serve_nodes.len(), 1);
    }

    #[test]
    fn a_v2_bundle_is_not_accepted_as_a_root_even_though_it_is_authorized() {
        assert!(matches!(
            verify_genesis_bundle(&v(V2)),
            Err(GenesisBundleError::UnacceptedVersion { got: 2, .. })
        ));
    }

    /// Any change to a bound member breaks every authorization.
    #[test]
    fn a_substituted_serve_node_key_breaks_the_quorum() {
        let mut b = v(V4);
        b["serve_nodes"][0]["record"]["pubkey_ed25519_base64"] =
            Value::String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into());
        assert!(matches!(
            verify_genesis_bundle(&b),
            Err(GenesisBundleError::QuorumNotMet { have: 0, needed: 2 })
        ));
    }

    #[test]
    fn a_substituted_transit_destination_breaks_the_quorum() {
        let mut b = v(V4);
        b["serve_transport_destinations"][0]["signed_envelope"]["destination"] =
            Value::String("00000000000000000000000000000000".into());
        assert!(matches!(
            verify_genesis_bundle(&b),
            Err(GenesisBundleError::QuorumNotMet { .. })
        ));
    }

    /// The scrub set is evidence the ceremony accumulates, so it is not
    /// bound; changing it must not break an honest authorization.
    #[test]
    fn the_scrub_set_is_not_bound() {
        let mut b = v(V4);
        b["serve_nodes"][0]["record"]["additional_scrubs"] = Value::Array(vec![]);
        b["serve_nodes"][0]["record"]["persist_row_hash"] = Value::String("x".into());
        assert_eq!(verify_genesis_bundle(&b).unwrap().authorized_by.len(), 2);
    }

    /// The bundle cannot talk its threshold down; one holder is not enough.
    #[test]
    fn one_authorization_does_not_meet_quorum_whatever_the_bundle_claims() {
        let mut b = v(V4);
        b["consensus_protocol"] = Value::String("quorum:1/3".into());
        b["authorizations"].as_array_mut().unwrap().truncate(1);
        // Changing consensus_protocol also changes the digest, so re-sign is
        // impossible here; what matters is the threshold the verifier asks.
        match verify_genesis_bundle(&b) {
            Err(GenesisBundleError::QuorumNotMet { needed, .. }) => assert_eq!(needed, 2),
            other => panic!("expected QuorumNotMet, got {other:?}"),
        }
    }

    #[test]
    fn a_duplicate_authorization_is_refused_not_merged() {
        let mut b = v(V4);
        let first = b["authorizations"][0].clone();
        b["authorizations"].as_array_mut().unwrap().push(first);
        assert!(matches!(
            verify_genesis_bundle(&b),
            Err(GenesisBundleError::DuplicateAuthorization(_))
        ));
    }

    #[test]
    fn an_unparseable_protocol_is_refused_not_guessed() {
        let mut b = v(V4);
        b["consensus_protocol"] = Value::String("majority".into());
        assert!(matches!(
            verify_genesis_bundle(&b),
            Err(GenesisBundleError::UnparseableProtocol(_))
        ));
    }

    /// An authorization from a key outside the baked roster never counts,
    /// even if the bundle lists that key as a holder.
    #[test]
    fn only_baked_holders_count() {
        let roster: Vec<ThresholdMember> = crate::accord_genesis::baked_accord_roster()
            .into_iter()
            .filter(|m| m.member_id != "B1")
            .collect();
        match verify_genesis_bundle_against(&v(V4), &roster, "humanity-accord") {
            Err(GenesisBundleError::QuorumNotMet { have, needed }) => {
                assert_eq!((have, needed), (1, 2));
            },
            other => panic!("expected QuorumNotMet, got {other:?}"),
        }
    }

    #[test]
    fn a_row_after_a_roster_record_is_refused() {
        let mut b = v(V4);
        let atts = b["attestations"].as_array_mut().unwrap();
        let row = atts.remove(0);
        atts.push(row);
        assert!(matches!(
            GenesisBundle::from_value(&b),
            Err(GenesisBundleError::Malformed(_))
        ));
    }

    #[test]
    fn quorum_m_parses_only_quorum_m_of_n() {
        assert_eq!(quorum_m("quorum:2/3"), Some(2));
        assert_eq!(quorum_m("quorum:0/3"), None);
        assert_eq!(quorum_m("quorum:4/3"), None);
        assert_eq!(quorum_m("majority"), None);
    }
}
