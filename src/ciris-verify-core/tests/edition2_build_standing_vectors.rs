//! Replays `tests/vectors/edition2/build_standing/build_standing_v1.json` and its
//! pool files (`gen_build_standing_v1.py`, independent of verify): whether a
//! build pipeline's manifest row stands (FSD-008 Phase 1b).
#![cfg(feature = "pqc")]

use std::collections::BTreeMap;

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::edition2::accord_halt::RosterHolder;
use ciris_verify_core::edition2::build_standing::{
    evaluate_build_standing, scope_satisfies, BundleRoster, BundleView, OwnerBinding, StandingInput,
};
use ciris_verify_core::edition2::keys::KeyRecordDirectory;
use ciris_verify_core::edition2::{identity_ref, thumbprint, Digest32};
use serde_json::Value as J;

const CASES: &str = include_str!("vectors/edition2/build_standing/build_standing_v1.json");
const POOL_0: &str = include_str!("vectors/edition2/build_standing/build_standing_pool_v1_0.json");
const POOL_1: &str = include_str!("vectors/edition2/build_standing/build_standing_pool_v1_1.json");
/// SHA-256 of each file, pinned so a regeneration is a visible change.
const PINS: [(&str, &str); 3] = [
    (
        CASES,
        "d535c3ef54d35d51fd896e8990802b59a64ab068edd3c322a79292e91e7f2fb4",
    ),
    (
        POOL_0,
        "274f870cd9f09b8662b185ee9d803774ce2ab01d4606e7e898ae8e23f3cdae62",
    ),
    (
        POOL_1,
        "1e60d090471c87563d0923946fcc79f61cf8a5dc30909870d628acda3a5b7600",
    ),
];

fn key(n: u8) -> CompositeSigningKey {
    CompositeSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(100); 32])
}

fn pool() -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for p in [POOL_0, POOL_1] {
        let j: J = serde_json::from_str(p).unwrap();
        for (k, v) in j["statements"].as_object().unwrap() {
            out.insert(k.clone(), hex::decode(v.as_str().unwrap()).unwrap());
        }
    }
    out
}

fn digest(s: &str) -> Digest32 {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[test]
fn files_are_pinned() {
    use sha2::Digest as _;
    for (i, (file, pin)) in PINS.iter().enumerate() {
        assert_eq!(
            hex::encode(sha2::Sha256::digest(file.as_bytes())),
            *pin,
            "file {i}"
        );
    }
}

#[test]
fn scope_match() {
    let f: J = serde_json::from_str(CASES).unwrap();
    let rows = f["scope_match"].as_array().unwrap();
    assert_eq!(rows.len(), 11);
    for r in rows {
        let held = r["held"].as_str().unwrap();
        assert_eq!(
            scope_satisfies(held, r["family"].as_str().unwrap()),
            r["satisfies"].as_bool().unwrap(),
            "{held}"
        );
    }
}

#[test]
fn build_standing_cases() {
    let f: J = serde_json::from_str(CASES).unwrap();
    let pool = pool();
    let st = |id: &J| -> &[u8] { pool[id.as_str().unwrap()].as_slice() };

    let mut keys = KeyRecordDirectory::new();
    for r in f["key_records"].as_array().unwrap() {
        keys.insert(st(r).to_vec()).unwrap();
    }
    let mut views: BTreeMap<Digest32, (String, Vec<u8>)> = BTreeMap::new();
    for b in f["bundles"].as_array().unwrap() {
        let seeds = b["holder_seeds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| u8::try_from(n.as_u64().unwrap()).unwrap())
            .collect();
        views.insert(
            digest(b["id"].as_str().unwrap()),
            (b["view"].as_str().unwrap().to_owned(), seeds),
        );
    }
    let bundles = |head: &Digest32| -> BundleView {
        match views.get(head) {
            Some((v, seeds)) if v == "holders" => BundleView::Holders(BundleRoster::new(
                *head,
                seeds
                    .iter()
                    .map(|n| {
                        let k = key(*n);
                        RosterHolder {
                            identity_ref: identity_ref(&thumbprint(k.public_key())),
                            key: k.public_key().clone(),
                        }
                    })
                    .collect(),
            )),
            Some((v, _)) if v == "void_fork" => BundleView::VoidFork,
            _ => BundleView::NotHeld,
        }
    };

    let cases = f["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 79);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let list = |k: &str| -> Vec<&[u8]> { c[k].as_array().unwrap().iter().map(st).collect() };
        let grant = list("grant");
        let gw = list("grant_withdrawals");
        let answers = list("answers");
        let aw = list("answer_withdrawals");
        let composers: Option<Vec<&[u8]>> = c["composers"]
            .as_array()
            .map(|a| a.iter().map(st).collect());
        let binding = c["owner_binding"].as_object().map(|b| OwnerBinding {
            owner: b["owner"].as_str().unwrap().to_owned(),
            key: b["key"].as_str().unwrap().to_owned(),
        });
        let blob = hex::decode(c["blob_hex"].as_str().unwrap()).unwrap();
        let input = StandingInput {
            build_row: st(&c["build_row"]),
            blob: &blob,
            keys: &keys,
            grant: &grant,
            grant_withdrawals: &gw,
            answers: &answers,
            answer_withdrawals: &aw,
            owner_binding: binding.as_ref(),
            composers: composers.as_deref(),
            bundles: &bundles,
        };
        let got = evaluate_build_standing(&input);
        let e = &c["expect"];
        assert_eq!(got.token(), e["verdict"].as_str().unwrap(), "{id}: {got:?}");
        assert_eq!(got.stands, e["verdict"] == "stands", "{id}");
        if let Some(w) = e["withdrawal_state"].as_str() {
            assert_eq!(got.withdrawal_state.as_str(), w, "{id}");
        }
        if let Some(n) = e["grant_voices"].as_u64() {
            assert_eq!(got.grant_voices, Some(usize::try_from(n).unwrap()), "{id}");
        }
        if let Some(s) = e["grant_scope"].as_str() {
            assert_eq!(got.grant_scope.as_deref(), Some(s), "{id}");
        }
        if let Some(r) = e["grant_root"].as_str() {
            assert_eq!(got.grant_root, Some(digest(r)), "{id}");
        }
        if let Some(q) = e["equivocation"].as_bool() {
            assert_eq!(got.equivocation, Some(q), "{id}");
        }
        if let Some(d) = e["detail"].as_str() {
            assert_eq!(
                got.refusal.as_ref().and_then(|r| r.detail()),
                Some(d),
                "{id}"
            );
        }
        if got.stands {
            assert_eq!(
                got.manifest_pipeline.as_deref(),
                f["pipeline"].as_str(),
                "{id}"
            );
            assert!(got.manifest.is_some(), "{id}");
            assert_eq!(got.owner.as_deref(), f["owner"].as_str(), "{id}");
        }
    }
}
