//! `ceg-genesis-bundle/2` known answers for a re-seated serve node
//! (CC 2.6.1.11, CC 2.6.1.7, CC 3.3.6.2, CIRISConstitution v1.0-rc21-wire e6fd7c6).
//!
//! A later bundle may seat a serve node at a new key while the seat keeps its
//! identity reference: the seat's new key record and its binding carry
//! `iss = author =` the seat's identity reference and are signed by the new
//! key, and the binding verifies under the key the bundle places for the seat.
//! The binding is the seat's own `identity:occurrence` (rc21): its
//! `identity_key_id` and `occurrence_key_id` are the seat's identity
//! reference, never the new key's (`reseat_binding_names_new_key`).
//!
//! `tests/vectors/edition2/genesis/genesis_reseat_v2.json` was written by
//! `gen_genesis_reseat_v2.py` beside it, over `gen_genesis_bundles_v3.py`'s
//! machinery (its own CBOR encoder, dilithium-py, pyca/cryptography and
//! kyber-py; nothing shared with verify). Its first case repeats v3's
//! `first_valid`, the predecessor of the rest. The replay is
//! `genesis_bundle_v3_vectors.rs`'s, trimmed to what these cases use.
//! `genesis_reseat_v1.json` stays byte-identical and is no longer replayed:
//! its bindings carry no `identity_key_id`, `occurrence_key_id` or
//! `device_class`.
#![cfg(all(feature = "std", feature = "pqc"))]

use std::collections::{BTreeMap, BTreeSet};

use ciris_verify_core::edition2::genesis::{
    read_genesis_bundles, Anchor, GenesisInput, GenesisPlacement, GenesisVerdict, Predecessor,
    GENESIS_BUNDLE_MALFORMED,
};
use ciris_verify_core::edition2::{thumbprint, Digest32};
use ciris_verify_core::trust_anchor_store::{environments, single, Purpose, TrustAnchorStore};
use serde_json::Value as J;

const FILE: &str = include_str!("vectors/edition2/genesis/genesis_reseat_v2.json");

fn hex32(s: &str) -> Digest32 {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn h(d: &Digest32) -> String {
    hex::encode(d)
}

fn sha_hex(b: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(b))
}

fn store(root_hex: &str) -> TrustAnchorStore {
    TrustAnchorStore::new().with_store(single(
        environments::YUBIKEY_PIV,
        Purpose::KeyAttestation,
        vec![hex::decode(root_hex).unwrap()],
    ))
}

fn pool(f: &J, k: &J) -> Vec<u8> {
    hex::decode(f["pool"][k.as_str().unwrap()].as_str().unwrap()).unwrap()
}

fn anchor(a: &J) -> Option<Anchor> {
    if a.is_null() {
        return None;
    }
    if let Some(t) = a.get("thumbprints") {
        return Some(Anchor::Thumbprints(
            t.as_array()
                .unwrap()
                .iter()
                .map(|x| hex32(x.as_str().unwrap()))
                .collect(),
        ));
    }
    Some(Anchor::ObjectId(hex32(a["object_id"].as_str().unwrap())))
}

fn strs(v: &J) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_owned())
        .collect()
}

fn check_placement(id: &str, p: &GenesisPlacement, e: &J, seat_xwing: &BTreeSet<(String, String)>) {
    assert_eq!(u64::from(p.version), e["version"].as_u64().unwrap(), "{id}");
    assert_eq!(p.asserted_at, e["asserted_at"].as_u64().unwrap(), "{id}");
    assert_eq!(
        p.family_key_id,
        e["family_key_id"].as_str().unwrap(),
        "{id}"
    );
    assert_eq!(
        p.prev.map(|d| h(&d)),
        e["prev"].as_str().map(str::to_owned),
        "{id}"
    );
    assert_eq!(h(&p.object_id), e["object_id"].as_str().unwrap(), "{id}");
    assert_eq!(p.counted, strs(&e["counted"]), "{id}: counted");
    assert_eq!(p.recovered.as_deref(), e["recovered"].as_str(), "{id}");
    assert_eq!(
        p.spent_commitments.iter().map(h).collect::<Vec<_>>(),
        strs(&e["spent_commitments"]),
        "{id}: spent"
    );
    assert_eq!(
        p.lineage_commitments.iter().map(h).collect::<Vec<_>>(),
        strs(&e["lineage_commitments"]),
        "{id}: lineage"
    );
    assert!(
        p.retired_holder_keys.is_empty(),
        "{id}: retired holder keys"
    );
    assert!(
        e["retired_holder_keys"].as_object().unwrap().is_empty(),
        "{id}"
    );
    let eh = e["holders"].as_array().unwrap();
    assert_eq!(p.holders.len(), eh.len(), "{id}");
    for (x, y) in p.holders.iter().zip(eh) {
        assert_eq!(x.identity_ref, y["identity_ref"].as_str().unwrap(), "{id}");
        assert_eq!(h(&x.kid), y["kid"].as_str().unwrap(), "{id}");
        assert_eq!(h(&x.record), y["record"].as_str().unwrap(), "{id}");
        assert_eq!(
            h(&x.recovery_commitment),
            y["recovery_commitment"].as_str().unwrap(),
            "{id}"
        );
    }
    let es = e["seats"].as_array().unwrap();
    assert_eq!(p.seats.len(), es.len(), "{id}");
    for (x, y) in p.seats.iter().zip(es) {
        assert_eq!(x.identity_ref, y["identity_ref"].as_str().unwrap(), "{id}");
        assert!(p.is_canonical(&x.identity_ref), "{id}");
        assert_eq!(h(&x.kid), y["kid"].as_str().unwrap(), "{id}");
        assert_eq!(h(&thumbprint(&x.key)), y["kid"].as_str().unwrap(), "{id}");
        assert_eq!(h(&x.record), y["record"].as_str().unwrap(), "{id}");
        assert_eq!(h(&x.binding), y["binding"].as_str().unwrap(), "{id}");
        assert_eq!(x.valid_until, y["valid_until"].as_u64().unwrap(), "{id}");
        assert_eq!(
            sha_hex(&x.transit_xwing_pubkey),
            y["transit_xwing_pubkey_sha256"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            sha_hex(&x.onion_hop_xwing_pubkey),
            y["onion_hop_xwing_pubkey_sha256"].as_str().unwrap(),
            "{id}"
        );
        assert!(seat_xwing.contains(&(
            hex::encode(x.transit_xwing_pubkey),
            hex::encode(x.onion_hop_xwing_pubkey)
        )));
    }
    assert!(p.witnesses.is_empty(), "{id}");
}

fn refused(r: &[(usize, &str)], e: &J) {
    let want: Vec<(usize, &str)> = e
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                usize::try_from(x["index"].as_u64().unwrap()).unwrap(),
                x["fault"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(r, want.as_slice());
}

#[test]
fn every_reseat_case_gives_its_verdict() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let roots = store(f["attestation_root_der"].as_str().unwrap());
    let seat_xwing: BTreeSet<(String, String)> = f["seat_xwing"]
        .as_object()
        .unwrap()
        .values()
        .map(|v| {
            (
                v["transit_xwing_pubkey"].as_str().unwrap().to_owned(),
                v["onion_hop_xwing_pubkey"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let mut valid: BTreeMap<String, Vec<GenesisPlacement>> = BTreeMap::new();
    let cases = f["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5, "the case list");
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let statements: Vec<Vec<u8>> = c["statements"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| pool(&f, k))
            .collect();
        let rows: BTreeMap<Digest32, Vec<u8>> = c["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (hex32(r["id"].as_str().unwrap()), pool(&f, &r["statement"])))
            .collect();
        let anchor = anchor(&c["anchor"]);
        let prev_placements: Vec<GenesisPlacement> = c["predecessors"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|p| valid[p["case"].as_str().unwrap()].clone())
            .collect();
        let preds: Vec<Predecessor<'_>> = prev_placements.iter().map(Predecessor::Valid).collect();
        let reading = read_genesis_bundles(&GenesisInput {
            statements: &statements,
            rows: &rows,
            anchor: anchor.as_ref(),
            predecessors: &preds,
            attestation_roots: &roots,
        });

        let top: Vec<(usize, &str)> = reading
            .refused
            .iter()
            .map(|r| (r.index, r.fault.token()))
            .collect();
        refused(&top, &c["top_refused"]);

        let expect = c["expect"].as_array().unwrap();
        assert_eq!(reading.bundles.len(), expect.len(), "{id}: objects");
        let mut here = Vec::new();
        for (b, e) in reading.bundles.iter().zip(expect) {
            assert_eq!(h(&b.object_id), e["object_id"].as_str().unwrap(), "{id}");
            let r: Vec<(usize, &str)> = b
                .refused
                .iter()
                .map(|r| (r.index, r.fault.token()))
                .collect();
            refused(&r, &e["refused"]);
            match (e["verdict"].as_str().unwrap(), &b.verdict) {
                ("valid", GenesisVerdict::Valid(p)) => {
                    check_placement(id, p, &e["placement"], &seat_xwing);
                    here.push((**p).clone());
                },
                ("invalid", GenesisVerdict::Invalid(m)) => {
                    assert_eq!(e["token"], GENESIS_BUNDLE_MALFORMED, "{id}");
                    assert_eq!(m.reason(), e["detail"].as_str().unwrap(), "{id}: {m:?}");
                },
                ("nothing", GenesisVerdict::Nothing(i)) => {
                    assert_eq!(i.token(), e["token"].as_str().unwrap(), "{id}: {i:?}");
                    assert_eq!(i.detail(), e["detail"].as_str(), "{id}: {i:?}");
                },
                (want, got) => panic!("{id}: want {want}, got {got:?}"),
            }
        }
        valid.insert(id.to_owned(), here);
    }
}

/// The re-seated seat is placed at its new key, under its unchanged identity
/// reference, with the new key's X-Wing keys.
#[test]
fn the_reseated_seat_keeps_its_identity_reference_at_the_new_key() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let c = &f["cases"][1];
    assert_eq!(c["id"], "reseat_seat_new_key");
    let s1 = &f["parties"]["S1"];
    let s1n = &f["parties"]["S1N"];
    assert_ne!(s1["kid"], s1n["kid"]);
    let seat = c["expect"][0]["placement"]["seats"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["identity_ref"] == s1["iss"])
        .unwrap();
    assert_eq!(seat["kid"], s1n["kid"]);
    let xw = &f["seat_xwing"]["S1N"];
    let digest = |k: &str| sha_hex(&hex::decode(xw[k].as_str().unwrap()).unwrap());
    assert_eq!(
        seat["transit_xwing_pubkey_sha256"].as_str().unwrap(),
        digest("transit_xwing_pubkey")
    );
    assert_eq!(
        seat["onion_hop_xwing_pubkey_sha256"].as_str().unwrap(),
        digest("onion_hop_xwing_pubkey")
    );
}
