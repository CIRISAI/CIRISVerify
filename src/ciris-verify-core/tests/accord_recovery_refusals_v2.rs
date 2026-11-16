//! Accord holder-recovery **refusal** known answers, v2 (CC 4.2.6, rc20): the
//! two cases that follow charter versions, built on CIRISPersist's real
//! charter rows.
//!
//! `tests/vectors/accord_lineage/accord_recovery_refusals_v2.json` is authored
//! by verify on top of persist's `accord_lineage_v2.json` (vendored beside it,
//! persist commit `864b038`). Both cases stand at persist's v4: v3's recovery
//! spent `vec-holder-a-recovery`'s commitment, and v4 adopted a charter that
//! re-lists that commitment for `vec-holder-a2`. Each offers a recovery of
//! `vec-holder-a2` to `vec-holder-a3` over that lineage and persist's stored
//! charter rows, and the rule refuses it:
//!
//! - `spent_commitment_relisted`: the recovery is made under the spent
//!   commitment the v4 charter re-lists. A commitment once spent never returns
//!   (CC 4.2.6): `RecoveryKeySpent`.
//! - `charter_missing`: a valid recovery (under the commitment v3 named for
//!   `vec-holder-a2`), offered with v4's charter row withheld:
//!   `CharterMissing`. With every row it is accepted.
//!
//! Signatures come from persist's deterministic test signers (seed = the key
//! id's bytes over a `[0x11; 32]` overlay). The keys the cases add beyond
//! persist's six are listed in the file under `added_keys`, from the same rule.
//!
//! The test rebuilds the file from scratch and fails on any difference, then
//! runs `verify_holder_recovery_with_charters` on every case and checks the
//! named refusal. `CIRIS_ACCORD_REFUSALS_REGENERATE=1` rewrites the file.

use base64::Engine;
use chrono::{DateTime, Utc};
use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};
use ciris_verify_core::accord_live_quorum::{
    build_holder_recovery, verify_holder_recovery_with_charters, FamilyRecord,
    HolderRecoveryRequest, LiveQuorumError, RecoveryKeyRecord, RosterVersion,
};
use ciris_verify_core::threshold::{ThresholdMember, ThresholdSignature};
use serde_json::{json, Value};

const LINEAGE: &str = include_str!("vectors/accord_lineage/accord_lineage_v2.json");
const FILE: &str = "tests/vectors/accord_lineage/accord_recovery_refusals_v2.json";

/// The keys the cases add, beyond the six persist's file lists.
const ADDED_KEYS: [&str; 3] = [
    "vec-holder-a2-recovery",
    "vec-holder-a3",
    "vec-holder-a3-recovery",
];

/// The seat the cases recover, its new key and the instant it joins.
const OLD: &str = "vec-holder-a2";
const NEW: &str = "vec-holder-a3";
const JOINED_AT: &str = "2026-09-01T00:00:00Z";

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

fn lineage(v: &Value, through: usize) -> Vec<RosterVersion> {
    (1..=through)
        .map(|n| RosterVersion {
            family: stored(v, n),
            change_envelope: (n > 1).then(|| version(v, n)["change_envelope"].clone()),
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

/// A key in the shape of persist's `keys` entries.
fn key_entry(key_id: &str) -> Value {
    let (ed, ml) = signer(key_id);
    json!({
        "key_id": key_id,
        "ed25519_public_key_base64": b64().encode(ed.public_key().unwrap()),
        "ml_dsa_65_public_key_base64": b64().encode(ml.public_key().unwrap()),
    })
}

/// persist's keys, then the added ones.
fn all_keys(v: &Value) -> Vec<Value> {
    let mut keys = v["keys"].as_array().unwrap().clone();
    keys.extend(ADDED_KEYS.iter().map(|k| key_entry(k)));
    keys
}

fn key_record(keys: &[Value], key_id: &str) -> RecoveryKeyRecord {
    let k = keys.iter().find(|k| k["key_id"] == key_id).unwrap();
    RecoveryKeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: k["ed25519_public_key_base64"].as_str().unwrap().into(),
        pubkey_ml_dsa_65_base64: k["ml_dsa_65_public_key_base64"].as_str().unwrap().into(),
    }
}

fn directory(keys: &[Value]) -> Vec<ThresholdMember> {
    keys.iter()
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

struct Case {
    id: &'static str,
    rule: &'static str,
    description: &'static str,
    expect: &'static str,
    with_every_charter: &'static str,
    charter_rows: Vec<usize>,
    recovery_key_id: &'static str,
    offered: FamilyRecord,
    statement: Value,
}

fn cases(v: &Value) -> Vec<Case> {
    let keys = all_keys(v);
    let standing = stored(v, 4);
    let next = key_record(&keys, "vec-holder-a3-recovery")
        .commitment()
        .unwrap();
    let joined_at: DateTime<Utc> = JOINED_AT.parse().unwrap();
    let request = |recovery_key_id: &str| HolderRecoveryRequest {
        old_holder_key_id: OLD.into(),
        new_holder_key_id: NEW.into(),
        recovery_key_id: recovery_key_id.into(),
        next_recovery_commitment: next.clone(),
        joined_at,
    };

    let spent = build_holder_recovery(&standing, &request("vec-holder-a-recovery")).unwrap();
    let valid = build_holder_recovery(&standing, &request("vec-holder-a2-recovery")).unwrap();
    vec![
        Case {
            id: "spent_commitment_relisted",
            rule: "CC 4.2.6 (rc20): a commitment a recovery has spent never comes back into force, even when a later charter version re-lists it",
            description: "v3 spent vec-holder-a-recovery's commitment; v4's charter re-lists it for vec-holder-a2. vec-holder-a2 recovers to vec-holder-a3 under vec-holder-a-recovery, over every charter row.",
            expect: "RecoveryKeySpent",
            with_every_charter: "RecoveryKeySpent",
            charter_rows: vec![0, 1, 2],
            recovery_key_id: "vec-holder-a-recovery",
            offered: spent.next,
            statement: spent.statement,
        },
        Case {
            id: "charter_missing",
            rule: "CC 4.2.6 (rc20): the commitment walk reads every charter version in link order; a charter row it needs and is not given fails closed, it is never skipped",
            description: "vec-holder-a2 recovers to vec-holder-a3 under vec-holder-a2-recovery (the commitment v3 named for it, still in force at v4), offered with v4's charter row withheld. Accepted with every row.",
            expect: "CharterMissing",
            with_every_charter: "accepted",
            charter_rows: vec![0, 1],
            recovery_key_id: "vec-holder-a2-recovery",
            offered: valid.next,
            statement: valid.statement,
        },
    ]
}

fn render(v: &Value) -> Value {
    let charters = v["charters"].as_array().unwrap();
    let cases: Vec<Value> = cases(v)
        .into_iter()
        .map(|c| {
            let bytes = ciris_verify_core::jcs::canonicalize(&c.statement).unwrap();
            let withheld: Vec<&Value> = (0..charters.len())
                .filter(|i| !c.charter_rows.contains(i))
                .map(|i| &charters[i]["persist_row_hash"])
                .collect();
            json!({
                "id": c.id,
                "rule": c.rule,
                "description": c.description,
                "expect_verify": c.expect,
                "with_every_charter": c.with_every_charter,
                "lineage_versions": [1, 2, 3, 4],
                "charter_rows": c.charter_rows,
                "withheld_charter_digests": withheld,
                "offered_family": c.offered,
                "statement": c.statement,
                "signing_bytes": {"hex": hex::encode(&bytes), "utf8": String::from_utf8(bytes.clone()).unwrap()},
                "recovery_key_id": c.recovery_key_id,
                "recovery_signatures": [sign(c.recovery_key_id, &bytes)],
            })
        })
        .collect();
    let added: Vec<Value> = ADDED_KEYS.iter().map(|k| key_entry(k)).collect();
    json!({
        "vector": "ciris.accord_recovery_refusals.v2",
        "produced_by": "CIRISVerify (src/ciris-verify-core/tests/accord_recovery_refusals_v2.rs)",
        "builds_on": "accord_lineage_v2.json (CIRISPersist commit 864b038, for v62), vendored beside this file: lineage_versions index its versions (1 = genesis), charter_rows index its charters",
        "synthetic": "deterministic test signers (seed = the key id's bytes over a [0x11;32] overlay), the same as accord_lineage_v2.json",
        "added_keys": added,
        "added_keys_note": "keys the cases use beyond accord_lineage_v2.json's six, from the same seed rule; the directory is persist's keys followed by these",
        "charter_note": "the charter rows are persist's stored rows, each named by its own persist_row_hash; the commitments are attestation_envelope.recovery_commitments. Pass charter_rows (indices into accord_lineage_v2.json's charters) to verify_holder_recovery_with_charters.",
        "signing": "recovery_signatures sign signing_bytes = JCS(statement) (what persist's draft_accord_recovery hands the recovery key); ML-DSA-65 covers signing_bytes ‖ ed25519_sig",
        "cases": cases,
    })
}

fn verdict_name(r: &Result<impl std::fmt::Debug, LiveQuorumError>) -> String {
    match r {
        Err(e) => format!("{e:?}")
            .split([' ', '{', '('])
            .next()
            .unwrap()
            .to_string(),
        Ok(_) => "accepted".to_string(),
    }
}

#[test]
fn the_signer_rule_reproduces_the_lineage_keys() {
    let v = lineage_vector();
    for k in v["keys"].as_array().unwrap() {
        assert_eq!(&key_entry(k["key_id"].as_str().unwrap()), k);
    }
    // vec-holder-a2-recovery is the key v3 committed to for vec-holder-a2.
    let keys = all_keys(&v);
    assert_eq!(
        key_record(&keys, "vec-holder-a2-recovery")
            .commitment()
            .unwrap(),
        version(&v, 3)["change_envelope"]["next_recovery_commitment"]
    );
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
    // A Windows checkout may carry CRLF (no .gitattributes); compare LF.
    let on_disk = std::fs::read_to_string(&path)
        .expect("refusal vector file present")
        .replace("\r\n", "\n");
    assert_eq!(
        on_disk, text,
        "{FILE} has drifted; regenerate with CIRIS_ACCORD_REFUSALS_REGENERATE=1"
    );

    let file: Value = serde_json::from_str(&on_disk).unwrap();
    let mut keys = v["keys"].as_array().unwrap().clone();
    keys.extend(file["added_keys"].as_array().unwrap().iter().cloned());
    let dir = directory(&keys);
    let every: Vec<Value> = v["charters"].as_array().unwrap().clone();
    for c in file["cases"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let versions: Vec<usize> = serde_json::from_value(c["lineage_versions"].clone()).unwrap();
        let l: Vec<RosterVersion> = lineage(&v, *versions.last().unwrap());
        assert_eq!(versions, (1..=l.len()).collect::<Vec<_>>(), "{id}");
        let rows: Vec<usize> = serde_json::from_value(c["charter_rows"].clone()).unwrap();
        let given: Vec<Value> = rows.iter().map(|&i| every[i].clone()).collect();
        let offered: FamilyRecord = serde_json::from_value(c["offered_family"].clone()).unwrap();
        let sigs: Vec<ThresholdSignature> =
            serde_json::from_value(c["recovery_signatures"].clone()).unwrap();
        let recovery_key = key_record(&keys, c["recovery_key_id"].as_str().unwrap());
        let run = |charters: &[Value]| {
            verify_holder_recovery_with_charters(
                charters,
                &l,
                &offered,
                &c["statement"],
                &recovery_key,
                &sigs,
                &dir,
            )
        };
        let got = run(&given);
        assert_eq!(
            verdict_name(&got),
            c["expect_verify"].as_str().unwrap(),
            "{id}: {got:?}"
        );
        assert!(got.is_err(), "{id}");
        let full = run(&every);
        assert_eq!(
            verdict_name(&full),
            c["with_every_charter"].as_str().unwrap(),
            "{id} with every charter row: {full:?}"
        );
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

    // The exact refusals.
    let cases = file["cases"].as_array().unwrap();
    let run = |c: &Value, rows: &[usize]| {
        let given: Vec<Value> = rows.iter().map(|&i| every[i].clone()).collect();
        verify_holder_recovery_with_charters(
            &given,
            &lineage(&v, 4),
            &serde_json::from_value(c["offered_family"].clone()).unwrap(),
            &c["statement"],
            &key_record(&keys, c["recovery_key_id"].as_str().unwrap()),
            &serde_json::from_value::<Vec<ThresholdSignature>>(c["recovery_signatures"].clone())
                .unwrap(),
            &dir,
        )
    };
    assert_eq!(
        run(&cases[0], &[0, 1, 2]),
        Err(LiveQuorumError::RecoveryKeySpent {
            key_id: "vec-holder-a-recovery".to_string()
        })
    );
    assert_eq!(
        run(&cases[1], &[0, 1]),
        Err(LiveQuorumError::CharterMissing {
            index: 3,
            charter_digest: every[2]["persist_row_hash"].as_str().unwrap().to_string(),
        })
    );
    assert_eq!(
        cases[1]["withheld_charter_digests"],
        json!([every[2]["persist_row_hash"]])
    );
}
