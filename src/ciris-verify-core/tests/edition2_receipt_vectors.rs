//! Replays `tests/vectors/edition2/receipts/receipts_v1.json` (`gen_receipts.py`,
//! independent of verify) against `edition2::receipt`: RFC 9162 inclusion,
//! receipt verification under each key form, the unsigned `receipts`
//! header, and the head-receipt count of distinct charter services.
#![cfg(feature = "pqc")]

use ciris_crypto::composite::CompositePublicKey;
use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::edition2::receipt::{
    consistency_proof, consistent, head_receipt_services, inclusion_root, merge_receipts,
    mint_receipt, parse_cose_key, receipt_header, receipts_of, verify_receipt,
    verify_receipt_for_leaf, MergeError, ReceiptClaims, ReceiptKey,
};
use serde_json::Value as J;
use std::collections::BTreeMap;

const FILE: &str = include_str!("vectors/edition2/receipts/receipts_v1.json");
/// SHA-256 of the file, pinned so a regeneration is a visible change.
const FILE_SHA256: &str = "d7e8cb35191c2094fa1cac744d8b28a0aa650e8d786e78be7689cbd8dbe474e8";

fn file() -> J {
    serde_json::from_str(FILE).unwrap()
}

fn hx(v: &J) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn h32(v: &J) -> [u8; 32] {
    hx(v).try_into().unwrap()
}

fn keys(f: &J) -> BTreeMap<String, (ReceiptKey, Option<CompositePublicKey>)> {
    f["keys"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(n, k)| {
            let rk =
                parse_cose_key(&hx(&k["cose_key_hex"])).unwrap_or_else(|e| panic!("{n}: {e:?}"));
            let comp = k["composite_hex"]
                .as_str()
                .map(|h| CompositePublicKey::from_bytes(&hex::decode(h).unwrap()).unwrap());
            (n.clone(), (rk, comp))
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
fn rfc9162_inclusion() {
    let f = file();
    let cases = f["inclusion"].as_array().unwrap();
    assert_eq!(cases.len(), 36);
    for c in cases {
        let path: Vec<[u8; 32]> = c["path_hex"].as_array().unwrap().iter().map(h32).collect();
        let (n, m) = (
            c["tree_size"].as_u64().unwrap(),
            c["leaf_index"].as_u64().unwrap(),
        );
        assert_eq!(
            inclusion_root(&h32(&c["leaf_hash_hex"]), m, n, &path),
            Some(h32(&c["root_hex"])),
            "size {n} index {m}"
        );
    }
}

/// The cases `gen_receipts_v2.py` adds: a receipt with no `iat` is refused,
/// whatever it is a receipt of (CC 2.6.1.11).
const FILE_V2: &str = include_str!("vectors/edition2/receipts/receipts_v2.json");
const FILE_V2_SHA256: &str = "d4e6f6af28b7a72ff80322e2fbea9fdfde3cbcb5d6d01f57eec6031e06cb9c26";

#[test]
fn a_receipt_names_its_instant() {
    use sha2::Digest as _;
    assert_eq!(
        hex::encode(sha2::Sha256::digest(FILE_V2.as_bytes())),
        FILE_V2_SHA256
    );
    let v2: J = serde_json::from_str(FILE_V2).unwrap();
    let cases = v2["verify"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    replay_verify(&keys(&file()), cases);
}

#[test]
fn receipts_verify_or_refuse() {
    let f = file();
    let keys = keys(&f);
    let cases = f["verify"].as_array().unwrap();
    assert_eq!(cases.len(), 22);
    replay_verify(&keys, cases);
}

fn replay_verify(keys: &BTreeMap<String, (ReceiptKey, Option<CompositePublicKey>)>, cases: &[J]) {
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let key = &keys[c["key"].as_str().unwrap()].0;
        let receipt = hx(&c["receipt_hex"]);
        let got = match c.get("leaf_hex") {
            Some(l) => verify_receipt_for_leaf(&hx(l), &receipt, key),
            None => verify_receipt(&hx(&c["statement_hex"]), &receipt, key),
        };
        match c["expect"].as_str().unwrap() {
            "ok" => {
                let v = got.unwrap_or_else(|e| panic!("{id}: {e:?}"));
                assert_eq!(v.tree_size, c["tree_size"].as_u64().unwrap(), "{id}");
                assert_eq!(v.leaf_index, c["leaf_index"].as_u64().unwrap(), "{id}");
                assert_eq!(v.iat, c["iat"].as_u64(), "{id}");
            },
            want => assert_eq!(got.expect_err(id).token(), want, "{id}"),
        }
    }
}

#[test]
fn unsigned_header_items_are_ignored() {
    let f = file();
    for c in f["receipts_of"].as_array().unwrap() {
        let held: Vec<String> = receipts_of(&hx(&c["statement_hex"]))
            .iter()
            .map(hex::encode)
            .collect();
        let want: Vec<String> = c["held_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(held, want, "{}", c["id"]);
    }
}

#[test]
fn head_receipts_count_distinct_services() {
    let f = file();
    let keys = keys(&f);
    let cases = f["head"].as_array().unwrap();
    assert_eq!(cases.len(), 10);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let statements: Vec<Vec<u8>> = c["statements_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(hx)
            .collect();
        let refs: Vec<&[u8]> = statements.iter().map(Vec::as_slice).collect();
        let ids: BTreeMap<String, String> = f["keys"]
            .as_object()
            .unwrap()
            .iter()
            .filter_map(|(n, k)| {
                k["identity_ref"]
                    .as_str()
                    .map(|r| (r.to_owned(), n.clone()))
            })
            .collect();
        let services: Vec<(String, CompositePublicKey)> = c["services"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                let n = s.as_str().unwrap();
                let id = f["keys"][n]["identity_ref"].as_str().unwrap().to_owned();
                (
                    id,
                    keys[n].1.clone().expect("a charter service is composite"),
                )
            })
            .collect();
        let got: Vec<String> = head_receipt_services(&hx(&c["head_payload_hex"]), &refs, &services)
            .into_iter()
            .map(|r| ids[&r].clone())
            .collect::<std::collections::BTreeSet<String>>()
            .into_iter()
            .collect();
        let want: Vec<String> = c["expect"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(got, want, "{id}");
    }
}

#[test]
fn keys_carry_alg_and_thumbprint() {
    let f = file();
    for (n, k) in f["keys"].as_object().unwrap() {
        let rk = parse_cose_key(&hx(&k["cose_key_hex"])).unwrap();
        assert_eq!(rk.alg(), k["alg"].as_i64().unwrap(), "{n}");
        assert_eq!(
            hex::encode(rk.thumbprint()),
            k["thumbprint_hex"].as_str().unwrap(),
            "{n}"
        );
    }
}

#[test]
fn header_reader() {
    let f = file();
    for c in f["header"].as_array().unwrap() {
        let h = receipt_header(&hx(&c["receipt_hex"])).unwrap();
        let e = &c["expect"];
        assert_eq!(h.alg, e["alg"].as_i64(), "{}", c["id"]);
        assert_eq!(h.vds, e["vds"].as_i64(), "{}", c["id"]);
        assert_eq!(
            h.kid.map(hex::encode),
            e["kid_hex"].as_str().map(str::to_owned),
            "{}",
            c["id"]
        );
        assert_eq!(h.iss.as_deref(), e["iss"].as_str(), "{}", c["id"]);
        assert_eq!(h.sub.as_deref(), e["sub"].as_str(), "{}", c["id"]);
        assert_eq!(h.iat, e["iat"].as_u64(), "{}", c["id"]);
    }
}

#[test]
fn merges() {
    let f = file();
    for c in f["merge"].as_array().unwrap() {
        let got = merge_receipts(&hx(&c["held_hex"]), &hx(&c["offered_hex"]));
        match c["expect"].as_str().unwrap() {
            "ok" => {
                let held: Vec<String> =
                    receipts_of(&got.unwrap()).iter().map(hex::encode).collect();
                let want: Vec<String> = c["held_after_hex"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_owned())
                    .collect();
                assert_eq!(held, want, "{}", c["id"]);
            },
            "different_statement" => assert_eq!(got, Err(MergeError::DifferentStatement)),
            _ => assert_eq!(got, Err(MergeError::TooMany)),
        }
    }
}

#[test]
fn rfc9162_consistency() {
    let f = file();
    let cases = f["consistency"].as_array().unwrap();
    assert_eq!(cases.len(), 37);
    let leaves: Vec<[u8; 32]> = (0..8u8)
        .map(|i| {
            use sha2::Digest as _;
            sha2::Sha256::digest([0u8, i]).into()
        })
        .collect();
    for c in cases {
        let (m, n) = (
            c["old_size"].as_u64().unwrap(),
            c["new_size"].as_u64().unwrap(),
        );
        let proof: Vec<[u8; 32]> = c["proof_hex"].as_array().unwrap().iter().map(h32).collect();
        let ok = consistent(
            m,
            &h32(&c["old_root_hex"]),
            n,
            &h32(&c["new_root_hex"]),
            &proof,
        );
        assert_eq!(ok, c["expect"].as_bool().unwrap(), "{m} -> {n}");
        if c["expect"] == true {
            assert_eq!(
                consistency_proof(m as usize, &leaves[..n as usize]).unwrap(),
                proof,
                "{m} -> {n}"
            );
        }
    }
}

#[test]
fn mint_matches_the_independent_receipt() {
    let f = file();
    let m = &f["mint"];
    let log: Vec<Vec<u8>> = m["log_hex"].as_array().unwrap().iter().map(hx).collect();
    let refs: Vec<&[u8]> = log.iter().map(Vec::as_slice).collect();
    let sk = CompositeSigningKey::from_seeds(&h32(&m["ml_seed_hex"]), &h32(&m["ed_seed_hex"]));
    let claims = ReceiptClaims {
        iss: m["iss"].as_str().map(str::to_owned),
        iat: m["iat"].as_u64(),
        ..ReceiptClaims::default()
    };
    let got = mint_receipt(&refs, m["index"].as_u64().unwrap() as usize, &sk, &claims).unwrap();
    assert_eq!(hex::encode(got), m["receipt_hex"].as_str().unwrap());
}
