//! Replays `tests/vectors/edition2/receipts/stream_heads_v1.json`
//! (`gen_stream_heads.py`, independent of verify) against
//! `edition2::stream_head`: the row's own rule, a service's successor rule
//! and the binding room check.

use ciris_verify_core::cde;
use ciris_verify_core::edition2::stream_head::{
    check_against_binding, check_stream_head, check_successor, Consistency, LastHead, StreamHead,
};
use ciris_verify_core::edition2::Invalid;
use serde_json::Value as J;

const FILE: &str = include_str!("vectors/edition2/receipts/stream_heads_v1.json");
/// SHA-256 of the file, pinned so a regeneration is a visible change.
const FILE_SHA256: &str = "537c5c68fe70c2cf17c3994fb97c3adbbcb44fbfe3686d6f29a6f00d91ea3a35";

fn h32(v: &J) -> [u8; 32] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
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
fn the_door() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let cases = f["door"].as_array().unwrap();
    assert_eq!(cases.len(), 13);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let p = cde::decode(&hex::decode(c["payload_hex"].as_str().unwrap()).unwrap()).unwrap();
        let got = check_stream_head(&p, c["sub"].as_str().unwrap());
        let got = match got {
            Ok(_) => "ok".to_owned(),
            Err(Invalid::Malformed { member }) => format!("malformed:{member}"),
            Err(Invalid::UnexpectedMember { within }) => format!("unexpected:{within}"),
            Err(e) => format!("{e:?}"),
        };
        assert_eq!(got, c["expect"].as_str().unwrap(), "{id}");
    }
}

#[test]
fn a_services_successor_rule() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let cases = f["successor"].as_array().unwrap();
    assert_eq!(cases.len(), 14);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let last = (!c["last"].is_null()).then(|| LastHead {
            row_id: h32(&c["last"]["row_id"]),
            epoch: c["last"]["epoch"].as_u64().unwrap(),
            tree_size: c["last"]["tree_size"].as_u64().unwrap(),
            root: h32(&c["last"]["root"]),
            sealed: c["last"]["sealed"].as_bool().unwrap(),
        });
        let h = &c["head"];
        let head = StreamHead {
            stream_id: "av-kat".into(),
            author: "producer".into(),
            asserted_at: 0,
            epoch: h["epoch"].as_u64().unwrap(),
            tree_size: h["tree_size"].as_u64().unwrap(),
            root: h32(&h["root"]),
            sealed: h["sealed"].as_bool().unwrap(),
            room: None,
            prev: (!h["prev"].is_null()).then(|| h32(&h["prev"])),
        };
        let holds: Vec<[u8; 32]> = c["holds"].as_array().unwrap().iter().map(h32).collect();
        let consistency = match c.get("recomputed") {
            Some(r) => Consistency::Recomputed {
                prev_root: h32(&r[0]),
                new_root: h32(&r[1]),
            },
            None => Consistency::Proof(c["proof"].as_array().unwrap().iter().map(h32).collect()),
        };
        let got = check_successor(last.as_ref(), &head, |r| holds.contains(r), &consistency);
        match c["expect"].as_str().unwrap() {
            "ok" => assert_eq!(got, Ok(()), "{id}"),
            want => assert_eq!(got.map_err(|e| e.token()), Err(want), "{id}"),
        }
    }
}

#[test]
fn the_head_against_its_binding() {
    let f: J = serde_json::from_str(FILE).unwrap();
    for c in f["binding"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let p = cde::decode(&hex::decode(c["payload_hex"].as_str().unwrap()).unwrap()).unwrap();
        let head: StreamHead = check_stream_head(&p, f["_meta"]["sub"].as_str().unwrap()).unwrap();
        let got = check_against_binding(
            &head,
            c["profile"].as_u64().unwrap() as u8,
            c["binding_room"].as_str().unwrap(),
        );
        match c["expect"].as_str().unwrap() {
            "ok" => assert_eq!(got, Ok(()), "{id}"),
            want => assert_eq!(got.map_err(|e| e.token()), Err(want), "{id}"),
        }
    }
}
