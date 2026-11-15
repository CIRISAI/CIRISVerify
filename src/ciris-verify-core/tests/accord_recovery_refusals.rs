//! Accord holder-recovery **refusal** known answers (CC 4.2.6, rc20), for
//! CIRISPersist (CIRISVerify#302 follow-up).
//!
//! `tests/vectors/accord_lineage/accord_recovery_refusals_v1.json` is authored
//! by verify on top of persist's own `accord_lineage_v1.json` (vendored beside
//! it). Every case starts from that lineage, standing at persist's v2, and
//! offers a recovery of `vec-holder-a` under `vec-holder-a-recovery` that the
//! rule refuses. Signatures come from persist's deterministic test signers
//! (seed = the key id's bytes over a `[0x11; 32]` overlay, checked here
//! against the lineage's listed public keys), so persist can feed each case to
//! its own door and expect the same refusal.
//!
//! The test rebuilds the file from scratch and fails on any difference, then
//! runs `verify_holder_recovery` on every case and checks the named refusal.
//! `CIRIS_ACCORD_REFUSALS_REGENERATE=1` rewrites the file.

use base64::Engine;
use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};
use ciris_verify_core::accord_live_quorum::{
    build_holder_recovery, verify_holder_recovery, FamilyRecord, HolderRecoveryRequest,
    LiveQuorumError, RecoveryKeyRecord, RosterVersion, CHARTER_RECOVERY_COMMITMENTS_FIELD,
};
use ciris_verify_core::threshold::{ThresholdMember, ThresholdSignature};
use serde_json::{json, Value};

const LINEAGE: &str = include_str!("vectors/accord_lineage/accord_lineage_v1.json");
const FILE: &str = "tests/vectors/accord_lineage/accord_recovery_refusals_v1.json";

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn lineage_vector() -> Value {
    serde_json::from_str(LINEAGE).unwrap()
}

fn version(v: &Value, n: usize) -> &Value {
    &v["versions"][n - 1]
}

fn stored(v: &Value, n: usize) -> FamilyRecord {
    serde_json::from_value(version(v, n)["stored_family"].clone()).unwrap()
}

fn key<'a>(v: &'a Value, key_id: &str) -> &'a Value {
    v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["key_id"] == key_id)
        .unwrap()
}

fn key_record(v: &Value, key_id: &str) -> RecoveryKeyRecord {
    let k = key(v, key_id);
    RecoveryKeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: k["ed25519_public_key_base64"].as_str().unwrap().into(),
        pubkey_ml_dsa_65_base64: k["ml_dsa_65_public_key_base64"].as_str().unwrap().into(),
    }
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

/// persist's deterministic test signer: the key id's bytes over `[0x11; 32]`.
fn signer(key_id: &str) -> (Ed25519Signer, MlDsa65Signer) {
    let mut seed = [0x11u8; 32];
    for (i, b) in key_id.bytes().take(32).enumerate() {
        seed[i] = b;
    }
    (
        Ed25519Signer::from_seed(&seed).unwrap(),
        MlDsa65Signer::from_seed(&seed).unwrap(),
    )
}

/// The bound hybrid signature (ML-DSA-65 over `bytes ‖ ed25519_sig`).
fn sign(key_id: &str, bytes: &[u8]) -> ThresholdSignature {
    let (ed, ml) = signer(key_id);
    let ed_sig = ed.sign(bytes).unwrap();
    let mut bound = bytes.to_vec();
    bound.extend_from_slice(&ed_sig);
    ThresholdSignature {
        member_id: key_id.to_string(),
        ed25519_signature_base64: b64().encode(&ed_sig),
        mldsa65_signature_base64: Some(b64().encode(ml.sign(&bound).unwrap())),
    }
}

fn charter(v: &Value) -> Value {
    json!({
        CHARTER_RECOVERY_COMMITMENTS_FIELD: {
            "vec-holder-a": key_record(v, "vec-holder-a-recovery").commitment().unwrap(),
        }
    })
}

fn lineage(v: &Value, versions: &[usize]) -> Vec<RosterVersion> {
    versions
        .iter()
        .map(|&n| RosterVersion {
            family: stored(v, n),
            change_envelope: (n > 1).then(|| version(v, n)["change_envelope"].clone()),
        })
        .collect()
}

/// persist's v3 request (vec-holder-a → vec-holder-a2), as the base each case edits.
fn v3_request(v: &Value) -> HolderRecoveryRequest {
    let st = &version(v, 3)["change_envelope"];
    let s = |k: &str| st[k].as_str().unwrap().to_string();
    let offered: FamilyRecord =
        serde_json::from_value(version(v, 3)["offered_family"].clone()).unwrap();
    HolderRecoveryRequest {
        old_holder_key_id: s("old_holder_key_id"),
        new_holder_key_id: s("new_holder_key_id"),
        recovery_key_id: s("recovery_key_id"),
        next_recovery_commitment: s("next_recovery_commitment"),
        joined_at: offered.seat("vec-holder-a2").unwrap().1.joined_at,
    }
}

/// Re-point the statement's `next_persist_row_hash` at `next`'s row hash.
fn rebind(statement: &mut Value, next: &FamilyRecord) {
    statement["next_persist_row_hash"] =
        json!(ciris_verify_core::persist_canonical::persist_row_hash(next).unwrap());
}

struct Case {
    id: &'static str,
    rule: &'static str,
    description: &'static str,
    expect: &'static str,
    persist_today: &'static str,
    lineage: Vec<usize>,
    offered: FamilyRecord,
    statement: Value,
}

fn cases(v: &Value) -> Vec<Case> {
    let standing = stored(v, 2);
    let spent = key_record(v, "vec-holder-a-recovery").commitment().unwrap();
    let mut out = Vec::new();

    // Point 1: the next commitment repeats the one it spends.
    let mut req = v3_request(v);
    req.next_recovery_commitment.clone_from(&spent);
    let d = build_holder_recovery(&standing, &req).unwrap();
    out.push(Case {
        id: "next_commitment_reused",
        rule: "CC 4.2.6 (rc20) point 1: the next recovery commitment must differ from the one spent",
        description: "vec-holder-a recovers to vec-holder-a2 naming, as its next commitment, the commitment of vec-holder-a-recovery: the one this recovery spends.",
        expect: "RecoveryReusesCommitment",
        persist_today: "accord_recovery_next_commitment_not_fresh",
        lineage: vec![1, 2],
        offered: d.next,
        statement: d.statement,
    });

    // Point 2: the recovery names the signing key already seated.
    let mut d = build_holder_recovery(&standing, &v3_request(v)).unwrap();
    d.statement["new_holder_key_id"] = json!("vec-holder-a");
    let seat = d
        .next
        .members
        .iter_mut()
        .find(|m| m.key_id == "vec-holder-a2")
        .unwrap();
    seat.key_id = "vec-holder-a".into();
    rebind(&mut d.statement, &d.next);
    out.push(Case {
        id: "same_signing_key",
        rule: "CC 4.2.6 (rc20) point 2: a recovery naming the same signing key concludes nothing",
        description: "The statement and the offered record keep vec-holder-a in its own seat.",
        expect: "RecoveryReusesSigningKey",
        persist_today: "accord_recovery_seat_taken (as a side effect; no dedicated token)",
        lineage: vec![1, 2],
        offered: d.next,
        statement: d.statement,
    });

    // Point 2: the recovery seats its own recovery key.
    let mut d = build_holder_recovery(&standing, &v3_request(v)).unwrap();
    d.statement["new_holder_key_id"] = json!("vec-holder-a-recovery");
    let seat = d
        .next
        .members
        .iter_mut()
        .find(|m| m.key_id == "vec-holder-a2")
        .unwrap();
    seat.key_id = "vec-holder-a-recovery".into();
    rebind(&mut d.statement, &d.next);
    out.push(Case {
        id: "recovery_key_as_signing_key",
        rule: "CC 4.2.6 (rc20) point 2: the recovery key is spent by the recovery and never becomes the seat",
        description: "vec-holder-a recovers to vec-holder-a-recovery, its own recovery key.",
        expect: "RecoveryKeyAsSigningKey",
        persist_today: "not refused (gap 2b)",
        lineage: vec![1, 2],
        offered: d.next,
        statement: d.statement,
    });

    // The lineage: the chain must start at genesis and have no gap.
    let d = build_holder_recovery(&standing, &v3_request(v)).unwrap();
    out.push(Case {
        id: "lineage_not_from_genesis",
        rule: "CC 3.2 T6 / annex 8.11: the commitment walk starts at genesis; it never falls back across a gap",
        description: "persist's valid v3 recovery, offered over a lineage holding only v2.",
        expect: "LineageIncomplete",
        persist_today: "n/a (persist reads by charter)",
        lineage: vec![2],
        offered: d.next.clone(),
        statement: d.statement.clone(),
    });
    out.push(Case {
        id: "lineage_gap",
        rule: "CC 3.2 T6 / annex 8.11: each version names its predecessor's persist_row_hash",
        description: "persist's valid v3 recovery, offered over a lineage v1, v1, v2: the second row does not link to the first.",
        expect: "LineageIncomplete",
        persist_today: "n/a (persist reads by charter)",
        lineage: vec![1, 1, 2],
        offered: d.next,
        statement: d.statement,
    });
    out
}

fn render(v: &Value) -> Value {
    let charter = charter(v);
    let cases: Vec<Value> = cases(v)
        .into_iter()
        .map(|c| {
            let bytes = ciris_verify_core::jcs::canonicalize(&c.statement).unwrap();
            json!({
                "id": c.id,
                "rule": c.rule,
                "description": c.description,
                "expect_verify": c.expect,
                "persist_today": c.persist_today,
                "lineage_versions": c.lineage,
                "offered_family": c.offered,
                "statement": c.statement,
                "signing_bytes": {"hex": hex::encode(&bytes), "utf8": String::from_utf8(bytes.clone()).unwrap()},
                "recovery_key_id": "vec-holder-a-recovery",
                "recovery_signatures": [sign("vec-holder-a-recovery", &bytes)],
            })
        })
        .collect();
    json!({
        "vector": "ciris.accord_recovery_refusals.v1",
        "produced_by": "CIRISVerify (src/ciris-verify-core/tests/accord_recovery_refusals.rs)",
        "builds_on": "accord_lineage_v1.json (CIRISPersist commit e943482e), vendored beside this file: lineage_versions index its versions (1 = genesis)",
        "synthetic": "deterministic test signers (seed = the key id's bytes over a [0x11;32] overlay), the same as accord_lineage_v1.json",
        "charter": charter,
        "charter_note": "The single charter verify_holder_recovery reads as the genesis charter: vec-holder-a's commitment is the commitment of vec-holder-a-recovery's listed keys. Cases that follow charter versions (a spent commitment re-listed by a later charter; a missing charter row) need persist's charter rows and are not in v1.",
        "signing": "recovery_signatures sign signing_bytes = JCS(statement) (what persist's draft_accord_recovery hands the recovery key); ML-DSA-65 covers signing_bytes ‖ ed25519_sig",
        "cases": cases,
    })
}

#[test]
fn the_signer_rule_reproduces_the_lineage_keys() {
    let v = lineage_vector();
    for k in v["keys"].as_array().unwrap() {
        let id = k["key_id"].as_str().unwrap();
        let (ed, ml) = signer(id);
        assert_eq!(
            b64().encode(ed.public_key().unwrap()),
            k["ed25519_public_key_base64"],
            "{id}"
        );
        assert_eq!(
            b64().encode(ml.public_key().unwrap()),
            k["ml_dsa_65_public_key_base64"],
            "{id}"
        );
    }
}

#[test]
fn the_file_is_current_and_every_case_is_refused() {
    let v = lineage_vector();
    let rendered = render(&v);
    let text = serde_json::to_string_pretty(&rendered).unwrap() + "\n";
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(FILE);
    if std::env::var_os("CIRIS_ACCORD_REFUSALS_REGENERATE").is_some() {
        std::fs::write(&path, &text).unwrap();
    }
    let on_disk = std::fs::read_to_string(&path).expect("refusal vector file present");
    assert_eq!(
        on_disk, text,
        "{FILE} has drifted; regenerate with CIRIS_ACCORD_REFUSALS_REGENERATE=1"
    );

    let file: Value = serde_json::from_str(&on_disk).unwrap();
    let dir = directory(&v);
    let recovery_key = key_record(&v, "vec-holder-a-recovery");
    for c in file["cases"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let versions: Vec<usize> = serde_json::from_value(c["lineage_versions"].clone()).unwrap();
        let offered: FamilyRecord = serde_json::from_value(c["offered_family"].clone()).unwrap();
        let sigs: Vec<ThresholdSignature> =
            serde_json::from_value(c["recovery_signatures"].clone()).unwrap();
        let got = verify_holder_recovery(
            &file["charter"],
            &lineage(&v, &versions),
            &offered,
            &c["statement"],
            &recovery_key,
            &sigs,
            &dir,
        );
        let name = match &got {
            Err(e) => {
                let dbg = format!("{e:?}");
                dbg.split([' ', '{', '(']).next().unwrap().to_string()
            },
            Ok(_) => "accepted".to_string(),
        };
        assert_eq!(name, c["expect_verify"].as_str().unwrap(), "{id}: {got:?}");
        assert!(got.is_err(), "{id}");
        // The signatures are genuine, so a door that checks them first still
        // reaches the refusal under test.
        let bytes = ciris_verify_core::jcs::canonicalize(&c["statement"]).unwrap();
        assert_eq!(hex::encode(&bytes), c["signing_bytes"]["hex"], "{id}");
        let member = ThresholdMember {
            member_id: recovery_key.key_id.clone(),
            ed25519_public_key_base64: recovery_key.pubkey_ed25519_base64.clone(),
            mldsa65_public_key_base64: Some(recovery_key.pubkey_ml_dsa_65_base64.clone()),
            role: None,
        };
        ciris_verify_core::threshold::verify_threshold_signatures(&bytes, &[member], &sigs, 1)
            .unwrap_or_else(|e| panic!("{id}: recovery signature does not verify: {e:?}"));
    }
    // Every expected refusal is a real variant name (guard against a typo).
    let _ = LiveQuorumError::RecoveryKeyAsSigningKey {
        key_id: String::new(),
    };
}
