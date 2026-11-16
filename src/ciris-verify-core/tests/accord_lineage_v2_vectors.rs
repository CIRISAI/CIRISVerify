//! The accord lineage vector **v2** — authored by CIRISPersist (CC 3.2 T6,
//! annex 8.11; CC 4.2.6 rc20).
//!
//! `tests/vectors/accord_lineage/accord_lineage_v2.json` is persist's own,
//! vendored byte for byte (persist commit `864b038`, to ship in persist v62;
//! see the README beside it). It extends v1 with persist's stored **charter
//! rows** and a fourth version that adopts a new charter re-listing a
//! commitment the v3 recovery spent. This harness holds verify to it:
//!
//! - the file's SHA-256 (LF-normalised) is pinned;
//! - every version's `canonical_bytes` and `persist_row_hash` reproduce, each
//!   links its predecessor, and v1–v3 are v1's versions unchanged;
//! - every charter row is named by its own recomputed `persist_row_hash`, and
//!   each version's `charter_digest` names one of them;
//! - v4's roster change is rebuilt byte for byte and accepted; v3's recovery
//!   is accepted over the charter rows;
//! - the `expected` section replays through
//!   `recovery_commitment_in_force_with_charters`: the commitment in force at
//!   the head for each holder, and every spent commitment in force for none.

use chrono::{DateTime, Utc};
use ciris_verify_core::accord_genesis::{
    accord_family_signing_bytes, build_membership_change, verify_membership_change,
};
use ciris_verify_core::accord_live_quorum::{
    build_holder_recovery, recovery_commitment_in_force_with_charters, seat_change_digest,
    verify_holder_recovery_with_charters, AccordAction, AccordDecision, AccordProposal,
    DecidedSeatChange, FamilyRecord, HolderRecoveryRequest, RecoveryKeyRecord, RosterVersion,
    SeatAdd, SeatChange,
};
use ciris_verify_core::persist_canonical;
use ciris_verify_core::threshold::{ThresholdMember, ThresholdSignature};
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/accord_lineage/accord_lineage_v2.json");
const VECTOR_V1: &str = include_str!("vectors/accord_lineage/accord_lineage_v1.json");

/// SHA-256 of persist's file (LF line endings), commit `864b038`.
const VECTOR_SHA256: &str = "d3ace82cbf7fe3749e51601125efa0012f2af46a27ef542166fa127dec607191";

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

fn bytes_of(v: &Value) -> Vec<u8> {
    let utf8 = v["utf8"].as_str().unwrap().as_bytes().to_vec();
    let hex = hex::decode(v["hex"].as_str().unwrap()).unwrap();
    assert_eq!(utf8, hex, "utf8 and hex name the same bytes");
    hex
}

fn version(v: &Value, n: usize) -> &Value {
    &v["versions"][n - 1]
}

fn family(v: &Value) -> FamilyRecord {
    serde_json::from_value(v.clone()).unwrap()
}

fn stored(v: &Value, n: usize) -> FamilyRecord {
    family(&version(v, n)["stored_family"])
}

fn offered(v: &Value, n: usize) -> FamilyRecord {
    family(&version(v, n)["offered_family"])
}

fn charters(v: &Value) -> Vec<Value> {
    v["charters"].as_array().unwrap().clone()
}

fn lineage(v: &Value, through: usize) -> Vec<RosterVersion> {
    (1..=through)
        .map(|n| RosterVersion {
            family: stored(v, n),
            change_envelope: (n > 1).then(|| version(v, n)["change_envelope"].clone()),
        })
        .collect()
}

fn directory(v: &Value) -> Vec<ThresholdMember> {
    v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| ThresholdMember {
            member_id: k["key_id"].as_str().unwrap().into(),
            ed25519_public_key_base64: k["ed25519_public_key_base64"].as_str().unwrap().into(),
            mldsa65_public_key_base64: Some(
                k["ml_dsa_65_public_key_base64"].as_str().unwrap().into(),
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
        pubkey_ed25519_base64: k["ed25519_public_key_base64"].as_str().unwrap().into(),
        pubkey_ml_dsa_65_base64: k["ml_dsa_65_public_key_base64"].as_str().unwrap().into(),
    }
}

fn signatures(v: &Value, n: usize) -> Vec<ThresholdSignature> {
    serde_json::from_value(version(v, n)["quorum_signatures"].clone()).unwrap()
}

#[test]
fn the_vendored_file_is_persists() {
    // A Windows checkout may carry CRLF (no .gitattributes); hash the LF form.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/accord_lineage/accord_lineage_v2.json");
    let text = std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
    let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(text.as_bytes()));
    assert_eq!(
        digest, VECTOR_SHA256,
        "accord_lineage_v2.json is not persist's file"
    );
    let v = vector();
    assert_eq!(v["vector"], "ciris.accord_lineage.v2");
    assert_eq!(v["versions"].as_array().unwrap().len(), 4);
    assert_eq!(v["charters"].as_array().unwrap().len(), 3);
    assert_eq!(v["keys"].as_array().unwrap().len(), 6);
}

#[test]
fn every_version_reproduces_and_links() {
    let v = vector();
    let mut prev = String::new();
    for n in 1..=4 {
        let r = version(&v, n);
        let canonical = bytes_of(&r["canonical_bytes"]);
        let hash = r["persist_row_hash"].as_str().unwrap();
        for form in ["offered_family", "stored_family"] {
            assert_eq!(
                persist_canonical::persist_row_hash_preimage(&r[form]).unwrap(),
                canonical,
                "v{n} {form}: canonical bytes"
            );
            let typed = family(&r[form]);
            assert_eq!(
                persist_canonical::persist_row_hash_preimage(&typed).unwrap(),
                canonical,
                "v{n} {form}: canonical bytes (typed)"
            );
            assert_eq!(typed.row_hash().unwrap(), hash, "v{n} {form}: hash");
            assert_eq!(typed.prev_head_digest, prev, "v{n} {form}: link");
            assert_eq!(
                typed.charter_digest, r["charter_digest"],
                "v{n} {form}: charter"
            );
        }
        assert_eq!(stored(&v, n).persist_row_hash, hash, "v{n}: stored hash");
        prev = hash.to_string();
    }
    // v1–v3 are persist's v1 vector's versions, unchanged.
    let v1: Value = serde_json::from_str(VECTOR_V1).unwrap();
    for n in 1..=3 {
        assert_eq!(version(&v, n), version(&v1, n), "v{n} differs from v1's");
    }
}

#[test]
fn every_charter_row_is_named_by_its_persist_row_hash() {
    let v = vector();
    let rows = charters(&v);
    let digests: Vec<String> = rows
        .iter()
        .map(|c| {
            let d = persist_canonical::persist_row_hash(c).unwrap();
            assert_eq!(c["persist_row_hash"], d.as_str(), "stored charter hash");
            d
        })
        .collect();
    // v1 adopts the first, v2 the second (kept by v3), v4 the third.
    for (n, i) in [(1, 0), (2, 1), (3, 1), (4, 2)] {
        assert_eq!(stored(&v, n).charter_digest, digests[i], "v{n} charter");
    }
    // v4's charter re-lists, for vec-holder-a2, the commitment v3 spent.
    let spent = v["expected"]["spent"][0].as_str().unwrap();
    assert_eq!(
        rows[2]["attestation_envelope"]["recovery_commitments"]["vec-holder-a2"],
        spent
    );
    assert_eq!(
        key_record(&v, "vec-holder-a-recovery")
            .commitment()
            .unwrap(),
        spent
    );
}

fn v4_change() -> SeatChange {
    SeatChange {
        remove: vec!["vec-holder-d".to_string()],
        add: Vec::<SeatAdd>::new(),
    }
}

fn v4_decision(v: &Value) -> AccordDecision {
    let d = &version(v, 4)["decision"];
    let family_key_id = v["family_key_id"].as_str().unwrap();
    AccordDecision {
        proposal: AccordProposal {
            family_key_id: family_key_id.to_string(),
            action: AccordAction::RosterChange,
            nonce: d["nonce"].as_str().unwrap().to_string(),
            window_until: d["window_until"].as_str().unwrap().to_string(),
            prior_family_digest: stored(v, 3).row_hash().unwrap(),
            payload_sha256: seat_change_digest(family_key_id, &v4_change()).unwrap(),
        },
        live_set: vec![
            "vec-holder-a2".into(),
            "vec-holder-b".into(),
            "vec-holder-c".into(),
        ],
        yes: 3,
        no: 0,
        abstain: 0,
        authorized: true,
    }
}

#[test]
fn v4_is_rebuilt_byte_for_byte_and_accepted() {
    let v = vector();
    let r = version(&v, 4);
    let decision = v4_decision(&v);
    assert_eq!(
        decision.proposal.payload_sha256,
        r["decision"]["seat_change_digest"]
    );
    assert_eq!(decision.proposal.digest(), r["decision"]["digest"]);
    let draft = build_membership_change(
        &stored(&v, 3),
        &[DecidedSeatChange {
            change: v4_change(),
            decision: decision.proposal.digest(),
        }],
        r["charter_digest"].as_str().unwrap(),
        DateTime::<Utc>::UNIX_EPOCH,
    )
    .unwrap();
    assert_eq!(draft.change_envelope, r["change_envelope"]);
    assert_eq!(draft.next, offered(&v, 4));
    assert_eq!(draft.signing_bytes, bytes_of(&r["signing_bytes"]));
    assert_eq!(
        accord_family_signing_bytes(&r["change_envelope"]).unwrap(),
        bytes_of(&r["signing_bytes"])
    );
    for form in [offered(&v, 4), stored(&v, 4)] {
        assert_eq!(
            verify_membership_change(
                &stored(&v, 3),
                &form,
                &r["change_envelope"],
                &signatures(&v, 4),
                std::slice::from_ref(&decision),
                &directory(&v),
                Utc::now(),
            )
            .unwrap(),
            Vec::<String>::new()
        );
    }
}

#[test]
fn v3_recovery_is_accepted_over_the_charter_rows() {
    let v = vector();
    let st = &version(&v, 3)["change_envelope"];
    let s = |k: &str| st[k].as_str().unwrap().to_string();
    let req = HolderRecoveryRequest {
        old_holder_key_id: s("old_holder_key_id"),
        new_holder_key_id: s("new_holder_key_id"),
        recovery_key_id: s("recovery_key_id"),
        next_recovery_commitment: s("next_recovery_commitment"),
        joined_at: offered(&v, 3).seat("vec-holder-a2").unwrap().1.joined_at,
    };
    let draft = build_holder_recovery(&stored(&v, 2), &req).unwrap();
    assert_eq!(&draft.statement, st);
    assert_eq!(draft.next, offered(&v, 3));
    let verdict = verify_holder_recovery_with_charters(
        &charters(&v),
        &lineage(&v, 2),
        &stored(&v, 3),
        st,
        &key_record(&v, "vec-holder-a-recovery"),
        &signatures(&v, 3),
        &directory(&v),
    )
    .unwrap();
    assert_eq!(verdict.new_signing_key_id, "vec-holder-a2");
    assert_eq!(verdict.next_commitment, s("next_recovery_commitment"));
}

#[test]
fn the_expected_section_replays() {
    let v = vector();
    let rows = charters(&v);
    let l = lineage(&v, 4);
    let expected = v["expected"]["in_force_at_head"].as_object().unwrap();
    for (holder, c) in expected {
        assert_eq!(
            recovery_commitment_in_force_with_charters(&rows, &l, holder).unwrap(),
            Some(c.as_str().unwrap().to_string()),
            "in force at head for {holder}"
        );
    }
    // Every seat at the head is listed, and keys without a seat have none.
    let head = stored(&v, 4);
    let mut seated = head.member_key_ids();
    seated.sort();
    let mut listed: Vec<String> = expected.keys().cloned().collect();
    listed.sort();
    assert_eq!(seated, listed);
    for k in ["vec-holder-a", "vec-holder-d", "vec-holder-a-recovery"] {
        assert_eq!(
            recovery_commitment_in_force_with_charters(&rows, &l, k).unwrap(),
            None,
            "{k}"
        );
    }
    // A spent commitment is in force for nobody, at any version of the lineage
    // after the recovery that spent it, even after v4's charter re-lists it.
    for spent in v["expected"]["spent"].as_array().unwrap() {
        for through in 3..=4 {
            let l = lineage(&v, through);
            for holder in stored(&v, through).member_key_ids() {
                assert_ne!(
                    recovery_commitment_in_force_with_charters(&rows, &l, &holder)
                        .unwrap()
                        .as_deref(),
                    spent.as_str(),
                    "{holder} at v{through}"
                );
            }
        }
    }
    // Before the recovery, the spent commitment was vec-holder-a's.
    assert_eq!(
        recovery_commitment_in_force_with_charters(&rows, &lineage(&v, 2), "vec-holder-a")
            .unwrap()
            .as_deref(),
        v["expected"]["spent"][0].as_str()
    );
}
