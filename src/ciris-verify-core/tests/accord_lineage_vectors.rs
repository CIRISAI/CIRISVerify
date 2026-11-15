//! The accord lineage vector — **authored by CIRISPersist** (CC 3.2 T6, annex
//! 8.11; CC 4.2.6).
//!
//! `tests/vectors/accord_lineage/accord_lineage_v1.json` is persist's own,
//! vendored byte for byte (persist commit `e943482e`, branch
//! `vec-accord-lineage`; see the README beside it). Persist's doors produced
//! every version, so this harness holds verify to persist:
//!
//! - every `canonical_bytes` (utf8 and hex) is reproduced byte for byte by
//!   [`persist_canonical`] from the stored and the offered record, and hashes
//!   to the version's `persist_row_hash`;
//! - every canonicalizer probe, instant and omitted-Option rule reproduces;
//! - v2's change envelope, offered record and signing bytes are rebuilt from v1
//!   plus the vector's inputs by `accord_genesis::build_membership_change`, and
//!   the roster-change verifier accepts v2 under the vector's signatures;
//! - v3's recovery statement, offered record and signing bytes are rebuilt from
//!   v2 by `build_holder_recovery`, and `verify_holder_recovery` accepts v3;
//! - tampering with a link, a commitment, a key or a member is refused.

use chrono::{DateTime, Utc};
use ciris_verify_core::accord_genesis::{
    accord_family_signing_bytes, build_membership_change, verify_membership_change,
    AccordGenesisError,
};
use ciris_verify_core::accord_live_quorum::{
    build_holder_recovery, recovery_commitment_in_force, roster_version_digest, seat_change_digest,
    verify_holder_recovery, AccordAction, AccordDecision, AccordProposal, DecidedSeatChange,
    FamilyRecord, FamilyRecordMember, HolderRecoveryRequest, LiveQuorumError, RecoveryKeyRecord,
    RosterVersion, SeatAdd, SeatChange, CHARTER_RECOVERY_COMMITMENTS_FIELD,
};
use ciris_verify_core::persist_canonical;
use ciris_verify_core::threshold::{ThresholdMember, ThresholdSignature};
use serde_json::{json, Value};

const VECTOR: &str = include_str!("vectors/accord_lineage/accord_lineage_v1.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

/// The bytes a `{utf8, hex}` pair names, checking the two agree.
fn bytes_of(v: &Value) -> Vec<u8> {
    let utf8 = v["utf8"].as_str().unwrap().as_bytes().to_vec();
    let hex = hex::decode(v["hex"].as_str().unwrap()).unwrap();
    assert_eq!(utf8, hex, "utf8 and hex name the same bytes");
    hex
}

fn family(v: &Value) -> FamilyRecord {
    serde_json::from_value(v.clone()).unwrap()
}

fn version(v: &Value, n: usize) -> &Value {
    &v["versions"][n - 1]
}

fn stored(v: &Value, n: usize) -> FamilyRecord {
    family(&version(v, n)["stored_family"])
}

fn offered(v: &Value, n: usize) -> FamilyRecord {
    family(&version(v, n)["offered_family"])
}

fn at(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

/// Every listed key as a directory member.
fn directory(v: &Value) -> Vec<ThresholdMember> {
    v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| ThresholdMember {
            member_id: k["key_id"].as_str().unwrap().to_string(),
            ed25519_public_key_base64: k["ed25519_public_key_base64"].as_str().unwrap().to_string(),
            mldsa65_public_key_base64: Some(
                k["ml_dsa_65_public_key_base64"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            ),
            role: None,
        })
        .collect()
}

fn key_record(v: &Value, key_id: &str) -> RecoveryKeyRecord {
    let k = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["key_id"] == key_id)
        .unwrap();
    RecoveryKeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: k["ed25519_public_key_base64"].as_str().unwrap().to_string(),
        pubkey_ml_dsa_65_base64: k["ml_dsa_65_public_key_base64"]
            .as_str()
            .unwrap()
            .to_string(),
    }
}

fn signatures(v: &Value, n: usize) -> Vec<ThresholdSignature> {
    serde_json::from_value(version(v, n)["quorum_signatures"].clone()).unwrap()
}

// --- persist_row_hash -------------------------------------------------------------

#[test]
fn every_canonical_byte_string_and_row_hash_reproduces() {
    let v = vector();
    let mut prev = String::new();
    for n in 1..=3 {
        let r = version(&v, n);
        let canonical = bytes_of(&r["canonical_bytes"]);
        let hash = r["persist_row_hash"].as_str().unwrap();
        for form in ["offered_family", "stored_family"] {
            // The typed record and the raw JSON value give the same bytes.
            let typed = family(&r[form]);
            assert_eq!(
                persist_row_hash_preimage_utf8(&typed),
                String::from_utf8(canonical.clone()).unwrap(),
                "v{n} {form}: canonical bytes (typed)"
            );
            assert_eq!(
                persist_canonical::persist_row_hash_preimage(&r[form]).unwrap(),
                canonical,
                "v{n} {form}: canonical bytes (raw value)"
            );
            assert_eq!(typed.row_hash().unwrap(), hash, "v{n} {form}: hash");
            assert_eq!(
                roster_version_digest(&typed).unwrap(),
                hash,
                "v{n} {form}: the roster version digest is the persist_row_hash"
            );
            assert_eq!(typed.prev_head_digest, prev, "v{n} {form}: link");
            // The typed record serializes as persist serializes it.
            assert_eq!(
                serde_json::to_value(&typed).unwrap(),
                r[form],
                "v{n} {form}: serde shape"
            );
        }
        assert_eq!(r["prev_head_digest"], prev.as_str(), "v{n}: prev");
        assert_eq!(stored(&v, n).persist_row_hash, hash, "v{n}: stored hash");
        prev = hash.to_string();
    }
}

fn persist_row_hash_preimage_utf8(f: &FamilyRecord) -> String {
    String::from_utf8(persist_canonical::persist_row_hash_preimage(f).unwrap()).unwrap()
}

#[test]
fn every_canonicalizer_probe_reproduces() {
    let v = vector();
    let probes = v["canonicalizer_rules"]["probes"].as_array().unwrap();
    assert_eq!(probes.len(), 24);
    for p in probes {
        let rule = p["rule"].as_str().unwrap();
        assert_eq!(
            persist_canonical::python_json_dumps(&p["input"]),
            bytes_of(&p["output"]),
            "probe {rule}"
        );
    }
    // The rules the vector names, each probed.
    let rules: Vec<&str> = probes.iter().map(|p| p["rule"].as_str().unwrap()).collect();
    for r in [
        "non_ascii_bmp_latin",
        "non_bmp_emoji",
        "non_bmp_object_key_order",
        "control_and_escapes",
        "float_small",
        "float_1e_minus_5",
        "float_1e16",
        "float_negative_zero",
        "int_u64_max",
        "int_i64_min",
    ] {
        assert!(rules.contains(&r), "{r} is probed");
    }
}

#[test]
fn every_instant_truncation_reproduces() {
    let v = vector();
    let instants = v["canonicalizer_rules"]["instants"].as_array().unwrap();
    assert_eq!(instants.len(), 7);
    for i in instants {
        let raw = i["raw"].as_str().unwrap();
        let t: DateTime<Utc> = raw.parse().unwrap();
        let serde = serde_json::to_value(t).unwrap();
        assert_eq!(serde, i["serde"], "{raw}: serde rendering");
        let mut truncated = serde.clone();
        persist_canonical::truncate_instants_to_microseconds(&mut truncated);
        assert_eq!(truncated, i["truncated"], "{raw}: truncated");
    }
}

#[test]
fn absent_options_are_omitted() {
    let v = vector();
    let m = FamilyRecordMember {
        key_id: "k".to_string(),
        joined_at: at("2026-01-01T00:00:00Z"),
        role: None,
    };
    assert_eq!(
        serde_json::to_value(&m).unwrap(),
        v["canonicalizer_rules"]["absent_option"]["member_role_none"]
    );
    // Genesis: no prev_head_digest member, no dissolved_at, in the bytes.
    let g = persist_row_hash_preimage_utf8(&stored(&v, 1));
    assert!(!g.contains("prev_head_digest") && !g.contains("dissolved_at"));
    assert!(!g.contains("null"));
    let mut no_charter = stored(&v, 1);
    no_charter.charter_digest = String::new();
    assert!(!persist_row_hash_preimage_utf8(&no_charter).contains("charter_digest"));
}

// --- rebuilding v2 and v3 ------------------------------------------------------------

/// v2's seat change, as the vector's change envelope names it.
fn v2_change(v: &Value) -> SeatChange {
    let added = &version(v, 2)["change_envelope"]["changes"][0]["add"][0];
    SeatChange {
        remove: vec![],
        add: vec![SeatAdd {
            key_id: added["key_id"].as_str().unwrap().to_string(),
            role: Some(added["role"].as_str().unwrap().to_string()),
        }],
    }
}

/// v2's decision, rebuilt from the vector's inputs over v1's hash.
fn v2_decision(v: &Value) -> AccordDecision {
    let d = &version(v, 2)["decision"];
    let family_key_id = v["family_key_id"].as_str().unwrap();
    let proposal = AccordProposal {
        family_key_id: family_key_id.to_string(),
        action: AccordAction::RosterChange,
        nonce: d["nonce"].as_str().unwrap().to_string(),
        window_until: d["window_until"].as_str().unwrap().to_string(),
        prior_family_digest: stored(v, 1).row_hash().unwrap(),
        payload_sha256: seat_change_digest(family_key_id, &v2_change(v)).unwrap(),
    };
    AccordDecision {
        proposal,
        live_set: vec!["vec-holder-a".into(), "vec-holder-b".into()],
        yes: 2,
        no: 0,
        abstain: 0,
        authorized: true,
    }
}

fn v2_joined_at(v: &Value) -> DateTime<Utc> {
    let added = offered(v, 2);
    added.seat("vec-holder-d").unwrap().1.joined_at
}

#[test]
fn v2_is_rebuilt_byte_for_byte() {
    let v = vector();
    let r = version(&v, 2);
    let decision = v2_decision(&v);
    assert_eq!(
        decision.proposal.payload_sha256, r["decision"]["seat_change_digest"],
        "seat_change_digest"
    );
    assert_eq!(
        decision.proposal.digest(),
        r["decision"]["digest"],
        "decision digest"
    );
    let draft = build_membership_change(
        &stored(&v, 1),
        &[DecidedSeatChange {
            change: v2_change(&v),
            decision: decision.proposal.digest(),
        }],
        r["charter_digest"].as_str().unwrap(),
        v2_joined_at(&v),
    )
    .unwrap();
    assert_eq!(
        draft.change_envelope, r["change_envelope"],
        "change envelope"
    );
    assert_eq!(
        serde_json::to_value(&draft.next).unwrap(),
        r["offered_family"],
        "offered family"
    );
    assert_eq!(draft.next, offered(&v, 2));
    assert_eq!(
        draft.signing_bytes,
        bytes_of(&r["signing_bytes"]),
        "signing bytes"
    );
    assert_eq!(
        accord_family_signing_bytes(&r["change_envelope"]).unwrap(),
        bytes_of(&r["signing_bytes"])
    );
    assert_eq!(
        persist_canonical::persist_row_hash_preimage(&draft.next).unwrap(),
        bytes_of(&r["canonical_bytes"]),
        "canonical bytes"
    );
}

fn verify_v2(
    v: &Value,
    offered2: &FamilyRecord,
    env: &Value,
    sigs: &[ThresholdSignature],
    decisions: &[AccordDecision],
) -> Result<Vec<String>, AccordGenesisError> {
    verify_membership_change(
        &stored(v, 1),
        offered2,
        env,
        sigs,
        decisions,
        &directory(v),
        Utc::now(),
    )
}

#[test]
fn the_roster_change_verifier_accepts_v2() {
    let v = vector();
    let r = version(&v, 2);
    for form in [offered(&v, 2), stored(&v, 2)] {
        assert_eq!(
            verify_v2(
                &v,
                &form,
                &r["change_envelope"],
                &signatures(&v, 2),
                &[v2_decision(&v)]
            )
            .unwrap(),
            vec!["vec-holder-d".to_string()]
        );
    }
}

fn v3_request(v: &Value) -> HolderRecoveryRequest {
    let st = &version(v, 3)["change_envelope"];
    let s = |k: &str| st[k].as_str().unwrap().to_string();
    HolderRecoveryRequest {
        old_holder_key_id: s("old_holder_key_id"),
        new_holder_key_id: s("new_holder_key_id"),
        recovery_key_id: s("recovery_key_id"),
        next_recovery_commitment: s("next_recovery_commitment"),
        joined_at: offered(v, 3).seat("vec-holder-a2").unwrap().1.joined_at,
    }
}

#[test]
fn v3_is_rebuilt_byte_for_byte() {
    let v = vector();
    let r = version(&v, 3);
    let draft = build_holder_recovery(&stored(&v, 2), &v3_request(&v)).unwrap();
    assert_eq!(draft.statement, r["change_envelope"], "recovery statement");
    assert_eq!(
        serde_json::to_value(&draft.next).unwrap(),
        r["offered_family"],
        "offered family"
    );
    assert_eq!(draft.next, offered(&v, 3));
    assert_eq!(
        draft.statement_bytes,
        bytes_of(&r["signing_bytes"]),
        "signing bytes"
    );
    // The recovery door signs ceg_produce_canonicalize(statement): the same bytes.
    assert_eq!(
        draft.statement_bytes,
        bytes_of(&r["door_statement_bytes"]),
        "door statement bytes"
    );
    assert_eq!(
        persist_canonical::persist_row_hash_preimage(&draft.next).unwrap(),
        bytes_of(&r["canonical_bytes"]),
        "canonical bytes"
    );
}

/// The charter commitment the vector's charter rows carry for `vec-holder-a`:
/// the commitment to `vec-holder-a-recovery`'s listed keys.
fn charter(v: &Value) -> Value {
    json!({
        CHARTER_RECOVERY_COMMITMENTS_FIELD: {
            "vec-holder-a": key_record(v, "vec-holder-a-recovery").commitment().unwrap(),
        }
    })
}

fn lineage(v: &Value, through: usize) -> Vec<RosterVersion> {
    (1..=through)
        .map(|n| RosterVersion {
            family: stored(v, n),
            change_envelope: (n > 1).then(|| version(v, n)["change_envelope"].clone()),
        })
        .collect()
}

fn verify_v3(
    v: &Value,
    charter: &Value,
    lineage: &[RosterVersion],
    offered3: &FamilyRecord,
    statement: &Value,
    key: &RecoveryKeyRecord,
) -> Result<String, LiveQuorumError> {
    verify_holder_recovery(
        charter,
        lineage,
        offered3,
        statement,
        key,
        &signatures(v, 3),
        &directory(v),
    )
    .map(|verdict| verdict.new_signing_key_id)
}

fn statement(v: &Value) -> Value {
    version(v, 3)["change_envelope"].clone()
}

fn recovery_key(v: &Value) -> RecoveryKeyRecord {
    key_record(v, "vec-holder-a-recovery")
}

#[test]
fn verify_holder_recovery_accepts_v3() {
    let v = vector();
    let next = statement(&v)["next_recovery_commitment"]
        .as_str()
        .unwrap()
        .to_string();
    for form in [offered(&v, 3), stored(&v, 3)] {
        assert_eq!(
            verify_v3(
                &v,
                &charter(&v),
                &lineage(&v, 2),
                &form,
                &statement(&v),
                &recovery_key(&v)
            )
            .unwrap(),
            "vec-holder-a2"
        );
    }
    // Once v3 is stored, its statement's commitment is the one in force for a2.
    assert_eq!(
        recovery_commitment_in_force(&charter(&v), &lineage(&v, 3), "vec-holder-a2").unwrap(),
        Some(next)
    );
    // vec-holder-d, seated by the ordinary change, reads the charter.
    let c = json!({ CHARTER_RECOVERY_COMMITMENTS_FIELD: { "vec-holder-d": "d".repeat(64) } });
    assert_eq!(
        recovery_commitment_in_force(&c, &lineage(&v, 3), "vec-holder-d").unwrap(),
        Some("d".repeat(64))
    );
}

// --- tamper ---------------------------------------------------------------------------

fn lineage_err(r: Result<impl std::fmt::Debug, LiveQuorumError>) {
    assert!(
        matches!(r, Err(LiveQuorumError::LineageIncomplete { .. })),
        "expected LineageIncomplete, got {r:?}"
    );
}

#[test]
fn a_tampered_link_is_refused() {
    let v = vector();
    let (c, o, st, k) = (charter(&v), offered(&v, 3), statement(&v), recovery_key(&v));

    // v2's head link names something other than v1's persist_row_hash. Its
    // stored hash and its envelope's next_persist_row_hash are recomputed too,
    // so only the link itself is wrong.
    let relink = |prev: String| {
        let mut l = lineage(&v, 2);
        l[1].family.prev_head_digest = prev;
        l[1].family.persist_row_hash = l[1].family.row_hash().unwrap();
        l[1].change_envelope.as_mut().unwrap()["next_persist_row_hash"] =
            json!(l[1].family.persist_row_hash);
        l
    };
    lineage_err(recovery_commitment_in_force(
        &c,
        &relink("0".repeat(64)),
        "vec-holder-a",
    ));

    // The old (wrong) link: the SHA-256 of v1's JCS signing bytes.
    let jcs_digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
        stored(&v, 1).record_signing_bytes().unwrap(),
    ));
    lineage_err(recovery_commitment_in_force(
        &c,
        &relink(jcs_digest),
        "vec-holder-a",
    ));

    // v2's change envelope binds another predecessor.
    let mut l = lineage(&v, 2);
    l[1].change_envelope.as_mut().unwrap()["prior_persist_row_hash"] = json!("1".repeat(64));
    lineage_err(verify_v3(&v, &c, &l, &o, &st, &k));

    // A stored hash that does not recompute.
    let mut l = lineage(&v, 2);
    l[0].family.persist_row_hash = "2".repeat(64);
    lineage_err(recovery_commitment_in_force(&c, &l, "vec-holder-a"));

    // A version missing (v1 dropped): the lineage does not start at genesis.
    lineage_err(verify_v3(&v, &c, &lineage(&v, 2)[1..], &o, &st, &k));

    // The roster change: the offered record names another predecessor.
    let r = version(&v, 2);
    let mut o2 = offered(&v, 2);
    o2.prev_head_digest = "3".repeat(64);
    assert!(matches!(
        verify_v2(
            &v,
            &o2,
            &r["change_envelope"],
            &signatures(&v, 2),
            &[v2_decision(&v)]
        ),
        Err(AccordGenesisError::RosterChangeUnbound { .. })
    ));
    // And the recovery: the statement names another standing version.
    let mut st2 = st.clone();
    st2["prior_persist_row_hash"] = json!("4".repeat(64));
    assert!(matches!(
        verify_v3(&v, &c, &lineage(&v, 2), &o, &st2, &k),
        Err(LiveQuorumError::RecoveryStatementUnbound { .. })
    ));
}

#[test]
fn a_tampered_commitment_is_refused() {
    let v = vector();
    let (o, st, k, l) = (
        offered(&v, 3),
        statement(&v),
        recovery_key(&v),
        lineage(&v, 2),
    );

    // The statement's next commitment: not what the recovery key signed.
    let mut st2 = st.clone();
    st2["next_recovery_commitment"] = json!("e".repeat(64));
    assert!(matches!(
        verify_v3(&v, &charter(&v), &l, &o, &st2, &k),
        Err(LiveQuorumError::Signature(_))
    ));
    // The charter's commitment for vec-holder-a: the key no longer matches it.
    let c2 = json!({ CHARTER_RECOVERY_COMMITMENTS_FIELD: { "vec-holder-a": "f".repeat(64) } });
    assert_eq!(
        verify_v3(&v, &c2, &l, &o, &st, &k),
        Err(LiveQuorumError::RecoveryCommitmentMismatch)
    );
    // No commitment at all.
    assert!(matches!(
        verify_v3(&v, &json!({}), &l, &o, &st, &k),
        Err(LiveQuorumError::NoCommitmentInForce { .. })
    ));
    // A next commitment repeating the one it spends.
    let spent = k.commitment().unwrap();
    let mut req = v3_request(&v);
    req.next_recovery_commitment.clone_from(&spent);
    let draft = build_holder_recovery(&stored(&v, 2), &req).unwrap();
    assert_eq!(
        verify_v3(&v, &charter(&v), &l, &draft.next, &draft.statement, &k),
        Err(LiveQuorumError::RecoveryReusesCommitment)
    );
}

#[test]
fn a_tampered_key_is_refused() {
    let v = vector();
    let (c, o, st, l) = (charter(&v), offered(&v, 3), statement(&v), lineage(&v, 2));

    // The recovery key's id with another key's material.
    let mut k = recovery_key(&v);
    k.pubkey_ed25519_base64 = key_record(&v, "vec-holder-b").pubkey_ed25519_base64;
    assert_eq!(
        verify_v3(&v, &c, &l, &o, &st, &k),
        Err(LiveQuorumError::RecoveryCommitmentMismatch)
    );
    // Another holder's key presented as the recovery key.
    assert_eq!(
        verify_v3(&v, &c, &l, &o, &st, &key_record(&v, "vec-holder-b")),
        Err(LiveQuorumError::RecoveryCommitmentMismatch)
    );
    // The statement seats another new key than the version does.
    let mut st2 = st.clone();
    st2["new_holder_key_id"] = json!("vec-holder-d");
    assert!(verify_v3(&v, &c, &l, &o, &st2, &recovery_key(&v)).is_err());
    // A recovery key spent by an earlier recovery: the charter commits the
    // same key for vec-holder-b, and v3 already rotated a seat under it.
    let mut req = v3_request(&v);
    req.old_holder_key_id = "vec-holder-b".to_string();
    req.new_holder_key_id = "vec-holder-a".to_string();
    req.joined_at = at("2026-07-01T00:00:00Z");
    let draft = build_holder_recovery(&stored(&v, 3), &req).unwrap();
    let shared = recovery_key(&v).commitment().unwrap();
    let c3 = json!({ CHARTER_RECOVERY_COMMITMENTS_FIELD: { "vec-holder-b": shared } });
    let r = verify_holder_recovery(
        &c3,
        &lineage(&v, 3),
        &draft.next,
        &draft.statement,
        &recovery_key(&v),
        &signatures(&v, 3),
        &directory(&v),
    );
    assert_eq!(
        r,
        Err(LiveQuorumError::RecoveryKeySpent {
            key_id: "vec-holder-a-recovery".to_string()
        })
    );
    // The signature: forged under another holder's key.
    let mut sigs = signatures(&v, 3);
    sigs[0].ed25519_signature_base64 = signatures(&v, 2)[0].ed25519_signature_base64.clone();
    assert!(matches!(
        verify_holder_recovery(&c, &l, &o, &st, &recovery_key(&v), &sigs, &directory(&v)),
        Err(LiveQuorumError::Signature(_))
    ));
    // The roster change, cosigned by one standing holder only.
    let r2 = version(&v, 2);
    assert!(matches!(
        verify_v2(
            &v,
            &offered(&v, 2),
            &r2["change_envelope"],
            &signatures(&v, 2)[..1],
            &[v2_decision(&v)]
        ),
        Err(AccordGenesisError::QuorumNotMet {
            valid: 1,
            required: 2
        })
    ));
    // A cosign under a key that is not the signer's.
    let mut forged = signatures(&v, 2);
    forged[1].mldsa65_signature_base64 = forged[0].mldsa65_signature_base64.clone();
    assert!(verify_v2(
        &v,
        &offered(&v, 2),
        &r2["change_envelope"],
        &forged,
        &[v2_decision(&v)]
    )
    .is_err());
}

#[test]
fn a_tampered_member_is_refused() {
    let v = vector();
    let (c, st, k, l) = (charter(&v), statement(&v), recovery_key(&v), lineage(&v, 2));

    // A member's role changed in the recovery version: no longer the version
    // the statement names.
    let mut o = offered(&v, 3);
    o.members[1].role = Some("member".to_string());
    assert!(matches!(
        verify_v3(&v, &c, &l, &o, &st, &k),
        Err(LiveQuorumError::RecoveryStatementUnbound { .. })
    ));
    // The same change made consistently (statement rebuilt to name it) is
    // still not only the holder's own seat.
    let mut st2 = st.clone();
    st2["next_persist_row_hash"] = json!(o.row_hash().unwrap());
    assert!(matches!(
        verify_v3(&v, &c, &l, &o, &st2, &k),
        Err(LiveQuorumError::RecoveryOutsideOwnSeat { .. })
    ));
    // A member's joined_at moved by a microsecond changes the row hash.
    let mut o = offered(&v, 3);
    o.members[2].joined_at += chrono::Duration::microseconds(1);
    assert_ne!(o.row_hash().unwrap(), offered(&v, 3).row_hash().unwrap());
    // ...but a nanosecond below the microsecond does not (persist truncates).
    let mut o = offered(&v, 3);
    o.members[3].joined_at += chrono::Duration::nanoseconds(1);
    assert_eq!(o.row_hash().unwrap(), offered(&v, 3).row_hash().unwrap());

    // The roster change: a member added beyond the decided change.
    let r = version(&v, 2);
    let mut o2 = offered(&v, 2);
    o2.members.push(FamilyRecordMember {
        key_id: "vec-holder-a2".to_string(),
        joined_at: at("2026-03-14T00:00:00Z"),
        role: None,
    });
    let mut env = r["change_envelope"].clone();
    env["next_persist_row_hash"] = json!(o2.row_hash().unwrap());
    assert!(matches!(
        verify_v2(&v, &o2, &env, &signatures(&v, 2), &[v2_decision(&v)]),
        Err(AccordGenesisError::RosterChangeUncovered { .. })
    ));
    // A member changed in the stored v2 (so v3 does not link it).
    let mut l = lineage(&v, 3);
    l[1].family.members[3].role = None;
    l[1].family.persist_row_hash = String::new();
    lineage_err(recovery_commitment_in_force(&c, &l, "vec-holder-a2"));
    // A roster change with no recorded decision.
    assert!(matches!(
        verify_v2(
            &v,
            &offered(&v, 2),
            &r["change_envelope"],
            &signatures(&v, 2),
            &[]
        ),
        Err(AccordGenesisError::RosterChangeUncovered { .. })
    ));
}
