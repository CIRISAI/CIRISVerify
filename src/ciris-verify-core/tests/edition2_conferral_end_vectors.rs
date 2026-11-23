//! Replays `tests/vectors/edition2/conferral_end_v1.json`
//! (`gen_conferral_end_v1.py`, independent of verify): `lifts` is present only
//! as `true`, `receipter` is an identity reference, and `lifts` on one
//! signer's own act is refused (CC 2.4.1.1, CC 2.6.1).
#![cfg(feature = "pqc")]

use std::collections::BTreeMap;

use ciris_crypto::composite::{CompositePublicKey, CompositeSigningKey};
use ciris_verify_core::edition2::family::{
    verify_row_in_family, FamilyVerdict, VendoredFamilyModel,
};
use ciris_verify_core::edition2::{thumbprint, verify_row_statement, Digest32, Invalid, Verdict};
use serde_json::Value as J;

const FILE: &str = include_str!("vectors/edition2/conferral_end_v1.json");
/// SHA-256 of the file, pinned so a regeneration is a visible change.
const FILE_SHA256: &str = "702be508ff60ebbb80979e0720a5e4359cc4a4a94dc8ed948b1cccb7fa5aedd7";

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

fn invalid(i: &Invalid) -> String {
    match i {
        Invalid::Malformed { member } => format!("invalid:malformed:{member}"),
        other => format!("invalid:{other:?}"),
    }
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
fn lifts_and_receipter() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let cases = f["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 11);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let bytes = hex::decode(c["statement_hex"].as_str().unwrap()).unwrap();
        let got = match c["level"].as_str().unwrap() {
            "statement" => match verify_row_statement(&bytes, &held(c)) {
                Verdict::Valid(_) => "valid".to_owned(),
                Verdict::Invalid(i) => invalid(&i),
                Verdict::Waiting { .. } => "waiting".to_owned(),
            },
            "family" => match verify_row_in_family(&bytes, &held(c), &VendoredFamilyModel) {
                FamilyVerdict::Valid { role: None, .. } => "valid".to_owned(),
                FamilyVerdict::Valid { role: Some(r), .. } => format!("valid:role:{r}"),
                FamilyVerdict::FamilyInvalid(fault) => format!("family_invalid:{}", fault.token()),
                FamilyVerdict::Invalid(i) => invalid(&i),
                other => format!("{other:?}"),
            },
            other => panic!("{id}: level {other}"),
        };
        assert_eq!(got, c["expect"].as_str().unwrap(), "{id}");
    }
}
