//! Replays CIRISKernel's room-key cases
//! (`tests/vectors/edition2/room/kernel_room_keys.json`, vendored from
//! CIRISKernel branch `room-key-vectors` af1cc43,
//! `crates/ciris-kernel/tests/fixtures/room_keys.json`; CIRISConstitution#224,
//! CC 3.1.3.2) through the room's door, `edition2::room::check_room_row`.
//!
//! The fixture is symbolic (a room `g`, keys `rk:a0`, heads `vA+2`): each
//! name is mapped to a value of its wire type by SHA-256, the same name to
//! the same value. The roster fold is the kernel's; each case carries the
//! view it gives: for a voice's row the roster at the head named, for a
//! node's row the folded facts of the binding and its owner. Vendored at
//! af1cc43 (30 cases: 16 voice rows, 14 node rows). A public room's row is
//! not put to the door.
#![cfg(feature = "pqc")]

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::keys::{KeyRecord, RoomKeyMembers};
use ciris_verify_core::edition2::room::{
    check_node_room_row, check_room_row, is_node_room_key, NodeOwnerView, RoomRowReading,
    VoiceRoster,
};
use ciris_verify_core::edition2::{hash_digest_value, identity_ref, thumbprint, Digest32};
use serde_json::Value as J;
use sha2::{Digest as _, Sha256};

const FILE: &str = include_str!("vectors/edition2/room/kernel_room_keys.json");
const FILE_SHA256: &str = "8df6c7c7af30ca6c4de52c672887e70d0f692f2db926fd32e9cbcb832ec2c74f";

fn d(name: &str) -> Digest32 {
    Sha256::digest(name.as_bytes()).into()
}

fn group(name: &str) -> String {
    use base64::Engine as _;
    format!(
        "group-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d(name))
    )
}

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

fn record(kid: Digest32, room: Option<&str>) -> KeyRecord {
    let k = CompositeSigningKey::from_seeds(&[1; 32], &[101; 32]);
    let _ = thumbprint(k.public_key());
    KeyRecord {
        kid,
        key: k.public_key().clone(),
        identity_type: vec!["user".into()],
        asserted_at: 1,
        valid_until: None,
        pq_custody: None,
        hardware_class: None,
        chain: Vec::new(),
        room_key: room.map(|r| RoomKeyMembers {
            room: group(r),
            kem_xwing_pubkey: vec![0; 1216],
            seat_commitment: [0; 32],
        }),
    }
}

fn refs_set(names: &[&str]) -> Value {
    Value::Array(
        names
            .iter()
            .map(|h| Value::Array(vec![Value::Uint(2), hash_digest_value(&d(h))]))
            .collect(),
    )
}

fn names(v: &J) -> Vec<&str> {
    v.as_array()
        .map(|a| a.iter().map(|h| h.as_str().unwrap()).collect())
        .unwrap_or_default()
}

fn record_of(c: &J, key: &J) -> KeyRecord {
    let r = c["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == *key);
    let mut rec = record(d(key.as_str().unwrap()), r.and_then(|r| r["room"].as_str()));
    if r.is_some_and(|r| r["identity_type"] == "node") {
        rec.identity_type = vec!["node".into()];
    }
    rec
}

#[test]
fn kernel_room_key_cases() {
    assert_eq!(hex::encode(Sha256::digest(FILE.as_bytes())), FILE_SHA256);
    let f: J = serde_json::from_str(FILE).unwrap();
    let cases = f["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 30);
    let (mut voice, mut node) = (0, 0);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let row = &c["row"];
        if c["membership"] == "public" {
            // The door is a private room's; the caller does not call it.
            assert_eq!(c["verdict"], "admitted", "{name}");
            continue;
        }
        let kid = d(row["kid"].as_str().unwrap());
        let also = &row["refs"]["also"];
        let mut roles = Vec::new();
        for role in ["under", "voice"] {
            let set = names(&also[role]);
            if !set.is_empty() {
                roles.push((t(role), refs_set(&set)));
            }
        }
        let mut payload = vec![
            (t("asserted_at"), Value::Uint(1)),
            (t("cohort_scope"), t("community")),
            (t("community_id"), t(&group(row["room"].as_str().unwrap()))),
        ];
        if !roles.is_empty() {
            payload.push((t("refs"), Value::Map(vec![(t("also"), Value::Map(roles))])));
        }
        let payload = Value::Map(payload);
        let rec = record_of(c, &row["kid"]);
        let view = &c["view"];
        let got = if c["arm"] == "node" {
            node += 1;
            assert!(is_node_room_key(&rec), "{name}");
            // iss = kid: the node's own room key, as an identity reference.
            assert_eq!(row["iss"], row["kid"], "{name}");
            let iss = identity_ref(&kid);
            let (under, heads) = (names(&view["under"]), names(&view["voice_heads"]));
            let owner_rec = view["owner"].as_str().map(|_| record_of(c, &view["owner"]));
            let v = match (&owner_rec, under.as_slice(), heads.as_slice()) {
                (Some(o), [b], [h]) => Some(NodeOwnerView {
                    binding: d(b),
                    voice_head: d(h),
                    binding_in_force: view["binding_held"] == true
                        && view["binding_ended"] == false,
                    live_bindings: usize::try_from(view["live_bindings"].as_u64().unwrap())
                        .unwrap(),
                    owner_record: o,
                    owner_live: view["owner_live"] == true,
                    voice_seated: view["voice_seated"] == true,
                }),
                _ => None,
            };
            check_node_room_row(&iss, &kid, &payload, &rec, v.as_ref())
        } else {
            voice += 1;
            let live: Vec<Digest32> = names(&view["live_keys"]).iter().map(|k| d(k)).collect();
            let view_heads = names(&view["heads"]);
            let roster = (view_heads.len() == 1).then(|| VoiceRoster {
                head: d(view_heads[0]),
                voice: view["voice"].as_str().unwrap(),
                live_keys: &live,
            });
            check_room_row(
                row["iss"].as_str().unwrap(),
                &kid,
                &payload,
                &rec,
                roster.as_ref(),
            )
        };
        match (c["verdict"].as_str().unwrap(), c["refusal"].as_str(), got) {
            ("admitted", None, RoomRowReading::Valid) => {},
            ("refused", Some(tok), RoomRowReading::Refused(r)) => {
                assert_eq!(r.token(), tok, "{name}");
            },
            ("concludes_nothing", None, RoomRowReading::ConcludesNothing(_)) => {},
            (v, r, g) => panic!("{name}: fixture {v} {r:?}, door {g:?}"),
        }
    }
    assert_eq!((voice, node), (15, 14));
}
