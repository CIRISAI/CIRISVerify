//! Replays `tests/vectors/edition2/composer_v1.json` (`gen_composer_v1.py`,
//! independent of verify): a composer carries no `dimension`, and its leaf,
//! so its authorship, is the target's the caller supplies (CC rc22 db989df).
#![cfg(feature = "pqc")]

use std::collections::BTreeMap;

use ciris_crypto::composite::{CompositePublicKey, CompositeSigningKey};
use ciris_verify_core::cde;
use ciris_verify_core::edition2::family::{
    verify_row_in_family_with, FamilyVerdict, SelectContext, TargetRow, VendoredFamilyModel,
};
use ciris_verify_core::edition2::{thumbprint, Digest32, Invalid, MissingKey};
use serde_json::Value as J;

const FILE: &str = include_str!("vectors/edition2/composer_v1.json");
/// SHA-256 of the file, pinned so a regeneration is a visible change.
const FILE_SHA256: &str = "3ae2d6fef968d2ae9fd168df3e504b155ca30f3bd8a584f62df50099b753aa81";

fn hx(v: &J) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

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

fn label(v: FamilyVerdict) -> String {
    match v {
        FamilyVerdict::Valid { role: None, .. } => "valid".into(),
        FamilyVerdict::Valid { role: Some(r), .. } => format!("valid:role:{r}"),
        FamilyVerdict::FamilyInvalid(f) => format!("family_invalid:{}", f.token()),
        FamilyVerdict::Invalid(Invalid::Malformed { member }) => {
            format!("invalid:malformed:{member}")
        },
        FamilyVerdict::Waiting(m) if m.len() == 1 => match &m[0] {
            MissingKey::Row(id) => format!("waiting:row:{}", hex::encode(id)),
            other => format!("waiting:{other:?}"),
        },
        other => format!("{other:?}"),
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
fn composers_read_their_targets_leaf() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let cases = f["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 13);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let target = c.get("target").map(|t| TargetRow {
            row_id: hx(&t["row_id_hex"]).try_into().unwrap(),
            family_id: t["family_id"].as_str().unwrap().to_owned(),
            payload: cde::decode(&hx(&t["payload_hex"])).unwrap(),
        });
        let ctx = SelectContext {
            target,
            ..SelectContext::default()
        };
        let got = verify_row_in_family_with(
            &hx(&c["statement_hex"]),
            &held(c),
            &VendoredFamilyModel,
            &ctx,
        );
        assert_eq!(label(got), c["expect"].as_str().unwrap(), "{id}");
    }
}
