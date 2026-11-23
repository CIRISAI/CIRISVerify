//! Replays `tests/vectors/edition2/reply_shapes_v1.json`
//! (`gen_reply_shapes_v1.py`, independent of verify): `refs.further_prev`
//! (a set, only beside `prev`), and the earlier form's `proposal_hash` /
//! `objects_to_attestation_id` refused on the rows that may not carry them,
//! the reply and objection `refs` rules, the 64 cap on `trusted_through`, and
//! the `membership:keeps` payload rule (CC 3.1.3.2, CC rc22).
#![cfg(feature = "pqc")]

use std::collections::BTreeMap;

use ciris_crypto::composite::{CompositePublicKey, CompositeSigningKey};
use ciris_verify_core::cde;
use ciris_verify_core::edition2::family_shapes::{check_act_ack, check_membership_keeps};
use ciris_verify_core::edition2::{thumbprint, verify_row_statement, Digest32, Invalid, Verdict};
use serde_json::Value as J;

const FILE: &str = include_str!("vectors/edition2/reply_shapes_v1.json");
/// SHA-256 of the file, pinned so a regeneration is a visible change.
const FILE_SHA256: &str = "18149502507e3268a0e03385bc22dd777ae98d7ee964fa30409749080b922fa9";

fn held(c: &J) -> BTreeMap<Digest32, CompositePublicKey> {
    c["held_key_seeds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| {
            let n = u8::try_from(n.as_u64().unwrap()).unwrap();
            let k = CompositeSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(100); 32]);
            (thumbprint(k.public_key()), k.public_key().clone())
        })
        .collect()
}

#[test]
fn file_is_pinned() {
    use sha2::Digest as _;
    assert_eq!(
        hex::encode(sha2::Sha256::digest(FILE.as_bytes())),
        FILE_SHA256
    );
}

#[test]
fn reply_and_refs_shapes() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let cases = f["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 48);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let bytes = hex::decode(c["statement_hex"].as_str().unwrap()).unwrap();
        let got = match verify_row_statement(&bytes, &held(c)) {
            Verdict::Valid(_) => "valid".to_owned(),
            Verdict::Invalid(Invalid::Malformed { member }) => {
                format!("invalid:malformed:{member}")
            },
            Verdict::Invalid(Invalid::SetOrder { member }) => format!("invalid:set_order:{member}"),
            Verdict::Invalid(i) => match i.token() {
                Some(t) => format!("invalid:{t}"),
                None => format!("invalid:{i:?}"),
            },
            // None of prev / further_prev / trusted_through makes a statement wait.
            Verdict::Waiting { .. } => "waiting".to_owned(),
        };
        assert_eq!(got, c["expect"].as_str().unwrap(), "{id}");
    }
}

fn payload_verdict(r: Result<(), Invalid>) -> String {
    match r {
        Ok(()) => "valid".to_owned(),
        Err(Invalid::Malformed { member }) => format!("invalid:malformed:{member}"),
        Err(i) => match i.token() {
            Some(t) => format!("invalid:{t}"),
            None => format!("invalid:{i:?}"),
        },
    }
}

/// `membership:keeps` and `act:ack` at payload level: the stage and the
/// family are registered by CC's next pre tag, so until the re-vendor each
/// rule is replayed on the payload alone.
#[test]
fn keeps_and_act_ack_payloads() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let decode =
        |c: &J| cde::decode(&hex::decode(c["payload_hex"].as_str().unwrap()).unwrap()).unwrap();
    let keeps = f["keeps_payloads"].as_array().unwrap();
    assert_eq!(keeps.len(), 9);
    for c in keeps {
        assert_eq!(
            payload_verdict(check_membership_keeps(&decode(c))),
            c["expect"].as_str().unwrap(),
            "{}",
            c["id"]
        );
    }
    let acks = f["act_ack_payloads"].as_array().unwrap();
    assert_eq!(acks.len(), 5);
    for c in acks {
        assert_eq!(
            payload_verdict(check_act_ack(&decode(c))),
            c["expect"].as_str().unwrap(),
            "{}",
            c["id"]
        );
    }
}
