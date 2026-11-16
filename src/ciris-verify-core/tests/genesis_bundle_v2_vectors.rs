//! `ceg-genesis-bundle/2` known answers (CC 2.6.1.11, CC 4.2.6,
//! CIRISConstitution rc20 64c5918).
//!
//! `tests/vectors/edition2/genesis/genesis_bundles_v2.json` was written by
//! `gen_genesis_bundles_v2.py` beside it: its own CBOR encoder, dilithium-py,
//! pyca/cryptography and kyber-py, sharing no code with verify. Every case is
//! replayed through [`read_genesis_bundles`]; the custody gate trusts the
//! file's mock attestation root, supplied as the reader's trust store. The
//! file also carries CC's own samples (`tools/build_cc_signed_object_v2.py`)
//! and the reference reader's answer beside ours for each case it models.
//! `genesis_bundles_v1.json` (rc20 ae09856, cited by CC) stays byte-identical
//! and is no longer replayed: rc20 64c5918 requires a seat's binding to name
//! its record, which none of v1's bindings does.
#![cfg(all(feature = "std", feature = "pqc"))]

use std::collections::{BTreeMap, BTreeSet};

use ciris_crypto::composite::{CompositePublicKey, CompositeSigningKey, COSE_ALG};
use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::genesis::{
    check_seat_binding, find_forks, follow_to_head, read_genesis_bundles, tips_in_common, Anchor,
    CustodyFault, Fork, GenesisInput, GenesisPlacement, GenesisVerdict, Head, Inconclusive,
    Predecessor, GENESIS_BUNDLE_MALFORMED, GENESIS_BUNDLE_TYP,
};
use ciris_verify_core::edition2::keys::check_key_record;
use ciris_verify_core::edition2::recovery::{
    checked_recovery_commitment, recovery_commitment, recovery_commitment_input,
};
use ciris_verify_core::edition2::{
    sig_structure, thumbprint, verify_row_statement, Digest32, Invalid, Verdict,
};
use ciris_verify_core::trust_anchor_store::{
    baked, environments, single, Purpose, TrustAnchorStore,
};
use serde_json::Value as J;

const FILE: &str = include_str!("vectors/edition2/genesis/genesis_bundles_v2.json");
/// The statements, split so each file stays under the repository's size limit.
const POOL: [&str; 8] = [
    include_str!("vectors/edition2/genesis/pool_v2_0.json"),
    include_str!("vectors/edition2/genesis/pool_v2_1.json"),
    include_str!("vectors/edition2/genesis/pool_v2_2.json"),
    include_str!("vectors/edition2/genesis/pool_v2_3.json"),
    include_str!("vectors/edition2/genesis/pool_v2_4.json"),
    include_str!("vectors/edition2/genesis/pool_v2_5.json"),
    include_str!("vectors/edition2/genesis/pool_v2_6.json"),
    include_str!("vectors/edition2/genesis/pool_v2_7.json"),
];

/// The case file, with the pool merged in under `pool`.
fn file() -> J {
    let mut f: J = serde_json::from_str(FILE).unwrap();
    let mut pool = serde_json::Map::new();
    for part in POOL {
        let J::Object(m) = serde_json::from_str::<J>(part).unwrap() else {
            panic!("a pool file is a map")
        };
        pool.extend(m);
    }
    f["pool"] = J::Object(pool);
    f
}

fn sha_hex(b: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(b))
}

thread_local! {
    /// The seats' X-Wing keys as the file states them in full.
    static SEAT_XWING: std::cell::RefCell<BTreeSet<(String, String)>> =
        const { std::cell::RefCell::new(BTreeSet::new()) };
}

fn hex32(s: &str) -> Digest32 {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn h(d: &Digest32) -> String {
    hex::encode(d)
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

fn verdict_name(v: &GenesisVerdict) -> String {
    match v {
        GenesisVerdict::Valid(_) => "valid".into(),
        GenesisVerdict::Invalid(m) => format!("invalid:{}", m.reason()),
        GenesisVerdict::Waiting(w) => format!("waiting:{w:?}"),
        GenesisVerdict::Nothing(i) => format!("nothing:{i:?}"),
    }
}

fn check_placement(id: &str, p: &GenesisPlacement, e: &J) {
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
    assert_eq!(
        u64::from(p.charter.halt_fuse()),
        e["halt_fuse"].as_u64().unwrap()
    );
    let scope: Vec<&str> = e["scope"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    assert_eq!(p.charter.scope, scope, "{id}");
    let counted: Vec<&str> = e["counted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    assert_eq!(p.counted, counted, "{id}: counted");
    assert_eq!(h(&p.object_id), e["object_id"].as_str().unwrap(), "{id}");
    assert_eq!(
        p.recovered.as_deref(),
        e["recovered"].as_str(),
        "{id}: recovered"
    );
    let set = |k: &str| -> Vec<String> {
        e[k].as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        p.spent_commitments.iter().map(h).collect::<Vec<_>>(),
        set("spent_commitments"),
        "{id}: spent"
    );
    assert_eq!(
        p.lineage_commitments.iter().map(h).collect::<Vec<_>>(),
        set("lineage_commitments"),
        "{id}: lineage"
    );
    let eh = e["holders"].as_array().unwrap();
    assert_eq!(p.holders.len(), eh.len(), "{id}");
    for (x, y) in p.holders.iter().zip(eh) {
        assert_eq!(x.identity_ref, y["identity_ref"].as_str().unwrap(), "{id}");
        assert_eq!(h(&x.kid), y["kid"].as_str().unwrap(), "{id}");
        assert_eq!(h(&thumbprint(&x.key)), y["kid"].as_str().unwrap(), "{id}");
        assert_eq!(h(&x.record), y["record"].as_str().unwrap(), "{id}");
        assert_eq!(
            h(&x.recovery_commitment),
            y["recovery_commitment"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            x.hardware_class,
            y["hardware_class"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            x.pq_custody.as_str(),
            y["pq_custody"].as_str().unwrap(),
            "{id}"
        );
    }
    let es = e["seats"].as_array().unwrap();
    assert_eq!(p.seats.len(), es.len(), "{id}");
    for (x, y) in p.seats.iter().zip(es) {
        assert_eq!(x.identity_ref, y["identity_ref"].as_str().unwrap(), "{id}");
        assert!(p.is_canonical(&x.identity_ref));
        assert_eq!(h(&x.kid), y["kid"].as_str().unwrap(), "{id}");
        assert_eq!(h(&x.record), y["record"].as_str().unwrap(), "{id}");
        assert_eq!(h(&x.binding), y["binding"].as_str().unwrap(), "{id}");
        assert_eq!(x.valid_until, y["valid_until"].as_u64().unwrap(), "{id}");
        assert_eq!(
            sha_hex(&x.transit_xwing_pubkey),
            y["transit_xwing_pubkey_sha256"].as_str().unwrap()
        );
        assert_eq!(
            sha_hex(&x.onion_hop_xwing_pubkey),
            y["onion_hop_xwing_pubkey_sha256"].as_str().unwrap()
        );
        assert!(SEAT_XWING.with(|m| m.borrow().contains(&(
            hex::encode(x.transit_xwing_pubkey),
            hex::encode(x.onion_hop_xwing_pubkey)
        ))));
    }
    let ew = e["witnesses"].as_array().unwrap();
    assert_eq!(p.witnesses.len(), ew.len(), "{id}");
    for (x, y) in p.witnesses.iter().zip(ew) {
        assert_eq!(x.identity_ref, y["identity_ref"].as_str().unwrap(), "{id}");
        assert_eq!(h(&x.kid), y["kid"].as_str().unwrap(), "{id}");
        assert_eq!(h(&x.record), y["record"].as_str().unwrap(), "{id}");
    }
}

#[test]
fn every_case_gives_its_verdict() {
    let f = file();
    let roots = store(f["attestation_root_der"].as_str().unwrap());
    SEAT_XWING.with(|m| {
        for v in f["seat_xwing"].as_object().unwrap().values() {
            m.borrow_mut().insert((
                v["transit_xwing_pubkey"].as_str().unwrap().to_owned(),
                v["onion_hop_xwing_pubkey"].as_str().unwrap().to_owned(),
            ));
        }
    });
    let mut valid: BTreeMap<String, Vec<GenesisPlacement>> = BTreeMap::new();
    let cases = f["cases"].as_array().unwrap();
    assert!(cases.len() >= 101, "the case list");
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
            .filter_map(|p| p.get("case"))
            .flat_map(|k| valid[k.as_str().unwrap()].clone())
            .collect();
        let mut preds: Vec<Predecessor<'_>> =
            prev_placements.iter().map(Predecessor::Valid).collect();
        for p in c["predecessors"].as_array().unwrap() {
            if let Some(n) = p.get("not_valid") {
                preds.push(Predecessor::NotValid(hex32(n.as_str().unwrap())));
            }
        }
        let input = GenesisInput {
            statements: &statements,
            rows: &rows,
            anchor: anchor.as_ref(),
            predecessors: &preds,
            attestation_roots: &roots,
        };
        let reading = read_genesis_bundles(&input);

        let top: Vec<(usize, &str)> = reading
            .refused
            .iter()
            .map(|r| (r.index, r.fault.token()))
            .collect();
        let want_top: Vec<(usize, &str)> = c["top_refused"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["index"].as_u64().unwrap() as usize,
                    r["fault"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(top, want_top, "{id}: statements refused before grouping");

        let expect = c["expect"].as_array().unwrap();
        assert_eq!(reading.bundles.len(), expect.len(), "{id}: objects");
        let mut here = Vec::new();
        for (b, e) in reading.bundles.iter().zip(expect) {
            assert_eq!(
                h(&b.object_id),
                e["object_id"].as_str().unwrap(),
                "{id}: object id"
            );
            let refused: Vec<(usize, &str)> = b
                .refused
                .iter()
                .map(|r| (r.index, r.fault.token()))
                .collect();
            let want: Vec<(usize, &str)> = e["refused"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| {
                    (
                        r["index"].as_u64().unwrap() as usize,
                        r["fault"].as_str().unwrap(),
                    )
                })
                .collect();
            assert_eq!(refused, want, "{id}: refused statements");
            let got = verdict_name(&b.verdict);
            match (e["verdict"].as_str().unwrap(), &b.verdict) {
                ("valid", GenesisVerdict::Valid(p)) => {
                    check_placement(id, p, &e["placement"]);
                    here.push((**p).clone());
                },
                ("invalid", GenesisVerdict::Invalid(m)) => {
                    assert_eq!(e["token"], GENESIS_BUNDLE_MALFORMED, "{id}");
                    assert_eq!(m.reason(), e["detail"].as_str().unwrap(), "{id}: {m:?}");
                },
                ("waiting", GenesisVerdict::Waiting(w)) => {
                    let ew = &e["waiting"];
                    let rows: Vec<String> = w.rows.iter().map(h).collect();
                    let kids: Vec<String> = w.kids.iter().map(h).collect();
                    let er: Vec<&str> = ew["rows"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|x| x.as_str().unwrap())
                        .collect();
                    let ek: Vec<&str> = ew["kids"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|x| x.as_str().unwrap())
                        .collect();
                    assert_eq!(rows, er, "{id}: rows");
                    assert_eq!(kids, ek, "{id}: kids");
                    assert_eq!(
                        w.prev.map(|d| h(&d)),
                        ew["prev"].as_str().map(str::to_owned),
                        "{id}: prev"
                    );
                },
                ("nothing", GenesisVerdict::Nothing(i)) => {
                    assert_eq!(i.token(), e["token"].as_str().unwrap(), "{id}: {i:?}");
                    assert_eq!(i.detail(), e["detail"].as_str(), "{id}: {i:?}");
                },
                (want, _) => panic!("{id}: want {want}, got {got}"),
            }
        }

        if let Some(fx) = c.get("forks") {
            let all: Vec<&GenesisPlacement> = prev_placements.iter().chain(here.iter()).collect();
            let forks: Vec<(String, Option<String>, Vec<String>)> = find_forks(&all)
                .into_iter()
                .map(|fk| match fk {
                    Fork::Genesis { bundles } => {
                        ("genesis".into(), None, bundles.iter().map(h).collect())
                    },
                    Fork::Successors { prev, bundles } => (
                        "successors".into(),
                        Some(h(&prev)),
                        bundles.iter().map(h).collect(),
                    ),
                })
                .collect();
            let want: Vec<(String, Option<String>, Vec<String>)> = fx["forks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| {
                    (
                        x["kind"].as_str().unwrap().into(),
                        x["prev"].as_str().map(str::to_owned),
                        x["bundles"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|b| b.as_str().unwrap().into())
                            .collect(),
                    )
                })
                .collect();
            assert_eq!(forks, want, "{id}: forks");
            match (follow_to_head(&all), fx["head"].as_str()) {
                (Head::Head(p), Some(want)) => assert_eq!(h(&p.object_id), want, "{id}: head"),
                (Head::Fork(_), None) => {},
                (other, want) => panic!("{id}: head {other:?}, want {want:?}"),
            }
            // What every tip names: a reader acts on it at a fork.
            let common = tips_in_common(&all);
            match (&common, fx["common"].as_object()) {
                (None, None) => {},
                (Some(t), Some(w)) => {
                    let list = |k: &str| -> Vec<String> {
                        w[k].as_array()
                            .unwrap()
                            .iter()
                            .map(|x| x.as_str().unwrap().to_owned())
                            .collect()
                    };
                    assert_eq!(
                        t.tips.iter().map(h).collect::<Vec<_>>(),
                        list("tips"),
                        "{id}"
                    );
                    assert_eq!(
                        t.holders
                            .iter()
                            .map(|x| x.identity_ref.clone())
                            .collect::<Vec<_>>(),
                        list("holders"),
                        "{id}: common holders"
                    );
                    assert_eq!(
                        t.seats
                            .iter()
                            .map(|x| x.identity_ref.clone())
                            .collect::<Vec<_>>(),
                        list("seats"),
                        "{id}: common seats"
                    );
                },
                (got, want) => panic!("{id}: common {got:?}, want {want:?}"),
            }
        }
        valid.insert(id.to_owned(), here);
    }
}

/// The production store (the baked Yubico roots) does not trust the mock
/// root: the valid bundle's holders are unattested there.
#[test]
fn the_baked_roots_refuse_the_mock_chain() {
    let f = file();
    let c = f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "first_valid")
        .unwrap();
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
    let a = anchor(&c["anchor"]).unwrap();
    for roots in [
        baked::default_store(),
        store(f["untrusted_root_der"].as_str().unwrap()),
    ] {
        let input = GenesisInput {
            statements: &statements,
            rows: &rows,
            anchor: Some(&a),
            predecessors: &[],
            attestation_roots: &roots,
        };
        let r = read_genesis_bundles(&input);
        assert!(matches!(
            &r.bundles[0].verdict,
            GenesisVerdict::Nothing(Inconclusive::HolderCustody {
                fault: CustodyFault::ChainInvalid,
                ..
            })
        ));
    }
}

fn key(n: u8) -> CompositeSigningKey {
    CompositeSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(100); 32])
}

#[test]
fn recovery_commitment_known_answers() {
    let f = file();
    for c in f["recovery_commitments"].as_array().unwrap() {
        let keys: Vec<CompositePublicKey> = c["key_seeds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| key(n.as_u64().unwrap() as u8).public_key().clone())
            .collect();
        assert_eq!(
            hex::encode(recovery_commitment_input(&keys)),
            c["input_hex"].as_str().unwrap()
        );
        assert_eq!(
            h(&recovery_commitment(&keys)),
            c["commitment"].as_str().unwrap()
        );
    }
    // CC's sample: a commitment over no key is refused.
    assert_eq!(checked_recovery_commitment(&[]), None);
}

/// One statement over raw payload bytes (CC's samples are payloads only).
fn voice_over(k: &CompositeSigningKey, payload: &[u8], iat: u64) -> Vec<u8> {
    let iss = ciris_verify_core::edition2::identity_ref(&thumbprint(k.public_key()));
    let protected = cde::encode(&Value::Map(vec![
        (Value::int(1), Value::int(COSE_ALG)),
        (
            Value::int(4),
            Value::Bytes(thumbprint(k.public_key()).to_vec()),
        ),
        (
            Value::int(15),
            Value::Map(vec![
                (Value::int(1), Value::Text(iss)),
                (Value::int(6), Value::Uint(iat)),
                (Value::int(-70003), Value::Uint(2)),
            ]),
        ),
        (Value::int(16), Value::Text(GENESIS_BUNDLE_TYP.into())),
    ]));
    let sig = k.sign(&sig_structure(&protected, payload)).unwrap();
    cde::encode(&Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(vec![]),
            Value::Bytes(payload.to_vec()),
            Value::Bytes(sig),
        ])),
    ))
}

#[test]
fn cc_samples() {
    let f = file();
    let cc = &f["cc"];
    let roots = baked::default_store();
    let rows = BTreeMap::new();
    let k = key(1);
    // The genesis bundle payload samples. Each broken one is Invalid for its own fault; the valid one
    // (whose `scope` is in CDE set order at 64c5918) is not Invalid: with no anchor it concludes
    // nothing, not anchored.
    for s in cc["payload_samples"].as_array().unwrap() {
        let p = hex::decode(s["payload_hex"].as_str().unwrap()).unwrap();
        let at = cde::decode(&p)
            .unwrap()
            .get_text("asserted_at")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let st = vec![voice_over(&k, &p, at / 1000)];
        let r = read_genesis_bundles(&GenesisInput {
            statements: &st,
            rows: &rows,
            anchor: None,
            predecessors: &[],
            attestation_roots: &roots,
        });
        assert!(r.refused.is_empty(), "{}", s["name"]);
        let v = &r.bundles[0].verdict;
        if s["expect"] == "invalid" {
            assert!(
                matches!(v, GenesisVerdict::Invalid(_)),
                "{}: {v:?}",
                s["name"]
            );
            continue;
        }
        assert!(
            matches!(v, GenesisVerdict::Nothing(Inconclusive::NotAnchored)),
            "{}: {v:?}",
            s["name"]
        );
    }
    // The binding samples (CC 3.3.6.2): the valid one passes the seat-binding rule (naming the record
    // its refs cite), each broken one is refused.
    let named: Digest32 = [4; 32];
    for s in cc["binding_samples"].as_array().unwrap() {
        let p = cde::decode(&hex::decode(s["payload_hex"].as_str().unwrap()).unwrap()).unwrap();
        let got = check_seat_binding(&p, k.public_key(), &named);
        match s["expect"].as_str().unwrap() {
            "ok" => assert!(got.is_ok(), "{}: {got:?}", s["name"]),
            _ => assert!(got.is_err(), "{}", s["name"]),
        }
    }
    // The key-record samples (CC 4.2.2.1). CC's key is 1984 zero bytes; where verify cannot decode it,
    // a real key stands in so the evidence member is what is judged.
    for s in cc["key_record_samples"].as_array().unwrap() {
        let p = cde::decode(&hex::decode(s["payload_hex"].as_str().unwrap()).unwrap()).unwrap();
        let Value::Map(mut m) = p else { panic!() };
        for (kk, v) in &mut m {
            if kk.as_text() == Some("key") {
                *v = ciris_verify_core::edition2::cose_key(k.public_key());
            }
        }
        let got = check_key_record(&Value::Map(m));
        match s["expect"].as_str().unwrap() {
            "ok" => assert!(got.is_ok(), "{}: {got:?}", s["name"]),
            _ => {
                let e = got.expect_err(s["name"].as_str().unwrap());
                assert!(
                    [
                        "key_record_bad_pq_custody",
                        "key_record_bad_attestation_evidence"
                    ]
                    .contains(&e.token()),
                    "{}: {e:?}",
                    s["name"]
                );
            },
        }
    }
    // The recovery input samples: the valid one is our input over its key; the broken one has no key.
    for s in cc["recovery_samples"].as_array().unwrap() {
        let b = hex::decode(s["input_hex"].as_str().unwrap()).unwrap();
        let v = cde::decode(&b).unwrap();
        let keys = v.as_array().unwrap()[1].as_array().unwrap();
        match s["expect"].as_str().unwrap() {
            "ok" => {
                let pk = keys[0].get_int(-1).and_then(Value::as_bytes).unwrap();
                match CompositePublicKey::from_bytes(pk) {
                    Ok(pk) => assert_eq!(recovery_commitment_input(&[pk]), b),
                    // A zero placeholder key: the layout alone is compared.
                    Err(_) => {
                        assert_eq!(v.as_array().unwrap()[0].as_text(), Some("CEG-recovery/2"))
                    },
                }
            },
            _ => assert!(keys.is_empty() && checked_recovery_commitment(&[]).is_none()),
        }
    }
    // CC's broken row statements: each Invalid for its own fault, never Waiting (their family,
    // custody:ack, is not registered, which is checked after every structural rule).
    for s in cc["statement_samples"].as_array().unwrap() {
        let b = hex::decode(s["statement_hex"].as_str().unwrap()).unwrap();
        let none: BTreeMap<Digest32, CompositePublicKey> = BTreeMap::new();
        let v = verify_row_statement(&b, &none);
        assert!(
            matches!(&v, Verdict::Invalid(i) if *i != Invalid::UnregisteredFamily),
            "{}: {v:?}",
            s["name"]
        );
    }
    // The reference reader over every case it models (first bundles, and later ones over its own
    // placement of the predecessor). It does not yet model the seated key of a holder in a later
    // bundle (holder_not_genesis_key, re-seated only by the holder's own counted statement under its
    // current key), so the three cases that turn on it are the known disagreements.
    let reader = cc["reader"].as_array().unwrap();
    assert!(reader.len() >= 50, "the cases CC's reader models");
    let disagree: BTreeSet<&str> = reader
        .iter()
        .filter(|r| r["agree"] == false)
        .map(|r| r["case"].as_str().unwrap())
        .collect();
    assert_eq!(
        disagree,
        BTreeSet::from([
            "recovered_holder_genesis_record",
            "roster_bundle_rotates_without_holder_voice",
            "roster_bundle_rotates_holder_voice_under_new_key"
        ])
    );
    // Each of the reference reader's breaks, valid samples and chain checks has its case here, and each
    // break's answer is that case's.
    let by_id: BTreeMap<&str, &J> = f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["id"].as_str().unwrap(), c))
        .collect();
    let answer = |c: &J| -> (String, Option<String>) {
        let e = &c["expect"][0];
        match e["verdict"].as_str().unwrap() {
            "valid" => ("Valid".into(), None),
            "waiting" => ("Waiting".into(), None),
            "invalid" => ("Invalid".into(), e["detail"].as_str().map(str::to_owned)),
            _ => {
                let t = e["token"].as_str().unwrap();
                let d = e["detail"]
                    .as_str()
                    .filter(|d| d.starts_with("recovery_commitment_"));
                (
                    "nothing".into(),
                    Some(d.map_or_else(|| t.to_owned(), |d| format!("{t}:{d}"))),
                )
            },
        }
    };
    for b in cc["reader_breaks"].as_array().unwrap() {
        let c = by_id[b["case"].as_str().unwrap()];
        let (v, d) = answer(c);
        let want = b["expect"].as_array().unwrap();
        assert_eq!(v, want[0].as_str().unwrap(), "{}", b["name"]);
        if v != "Waiting" {
            assert_eq!(d.as_deref(), want[1].as_str(), "{}", b["name"]);
        }
    }
    for b in cc["reader_valid"].as_array().unwrap() {
        assert_eq!(
            answer(by_id[b["case"].as_str().unwrap()]).0,
            "Valid",
            "{}",
            b["name"]
        );
    }
    for b in cc["reader_chain_checks"].as_array().unwrap() {
        assert!(
            by_id.contains_key(b["case"].as_str().unwrap()),
            "{}",
            b["name"]
        );
    }
}
