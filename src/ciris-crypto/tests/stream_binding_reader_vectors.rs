//! Replays `tests/vectors/composite/stream_binding_reader_v1.json`
//! (`gen_stream_binding_reader_v1.py`, independent of verify) against
//! `stream_binding` and `stream_seal::file_stream_id`.
#![cfg(feature = "composite")]

use ciris_crypto::composite::CompositePublicKey;
use ciris_crypto::stream_binding::{parse_stream_key_binding, verify_stream_key_binding};
use ciris_crypto::stream_seal::{call_stream_id, file_stream_id};
use serde_json::Value;

const FILE: &str = include_str!("vectors/composite/stream_binding_reader_v1.json");
/// SHA-256 of the file, pinned so a regeneration is a visible change.
const FILE_SHA256: &str = "514efb1a0b5111f1513fd9ffaccc1034015d4d7d78d2aea3cbf0afc9bd211bff";

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
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
fn valid_bindings_parse_and_recompute_their_id() {
    let f: Value = serde_json::from_str(FILE).unwrap();
    for c in f["valid"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let enc = h(&c["encoding_hex"]);
        let b = parse_stream_key_binding(&enc).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        assert_eq!(
            call_stream_id(&b.room, &b.publisher, &b.join_nonce).unwrap(),
            b.stream_id,
            "{id}"
        );
        assert_eq!(b.profile == 1, b.head_interval_s.is_some(), "{id}");
    }
}

#[test]
fn refusals_give_their_tokens() {
    let f: Value = serde_json::from_str(FILE).unwrap();
    let cases = f["refusals"].as_array().unwrap();
    assert_eq!(cases.len(), 13);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let e = parse_stream_key_binding(&h(&c["encoding_hex"])).expect_err(id);
        assert_eq!(e.token(), c["error"].as_str().unwrap(), "{id}");
    }
}

#[test]
fn signatures_verify_under_the_publisher() {
    let f: Value = serde_json::from_str(FILE).unwrap();
    let pk = CompositePublicKey::from_bytes(&h(&f["_meta"]["publisher_composite_public_key_hex"]))
        .unwrap();
    for c in f["signature"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let b = parse_stream_key_binding(&h(&c["encoding_hex"])).unwrap();
        let got = verify_stream_key_binding(&b, &pk);
        match c["expect"].as_str().unwrap() {
            "ok" => assert_eq!(got, Ok(()), "{id}"),
            want => assert_eq!(got.map_err(|e| e.token()), Err(want), "{id}"),
        }
    }
}

#[test]
fn file_stream_ids() {
    let f: Value = serde_json::from_str(FILE).unwrap();
    for c in f["file_stream_ids"].as_array().unwrap() {
        let nonce: [u8; 32] = h(&c["nonce_hex"]).try_into().unwrap();
        assert_eq!(
            file_stream_id(c["producer"].as_str().unwrap(), &nonce).unwrap(),
            c["stream_id"].as_str().unwrap(),
            "{}",
            c["id"]
        );
    }
    for c in f["file_stream_id_refusals"].as_array().unwrap() {
        let nonce: [u8; 32] = h(&c["nonce_hex"]).try_into().unwrap();
        assert!(
            file_stream_id(c["producer"].as_str().unwrap(), &nonce).is_err(),
            "{}",
            c["id"]
        );
    }
}
