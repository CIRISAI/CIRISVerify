//! Replays CIRISKernel's room-key cases
//! (`tests/vectors/edition2/room/kernel_room_keys.json`, vendored from
//! CIRISKernel branch `room-key-vectors` a1460cf,
//! `crates/ciris-kernel/tests/fixtures/room_keys.json`; CIRISConstitution#224,
//! CC 3.1.3.2) through the room's door, `edition2::room::check_room_row`.
//!
//! The fixture is symbolic (a room `g`, keys `rk:a0`, heads `vA+2`): each
//! name is mapped to a value of its wire type by SHA-256, the same name to
//! the same value. The roster fold is the kernel's; each case carries the
//! view it gives. Two differences from the fixture as vendored, both ruled by
//! CIRISConstitution on 2026-11-27 after it was cut: a row whose
//! `refs.also.voice` is missing or names two rows is REFUSED
//! `room_row_voice_head_malformed` (the fixture says concludes nothing, and
//! is to be re-cut), and a public room's row is not put to the door at all.
#![cfg(feature = "pqc")]

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::keys::{KeyRecord, RoomKeyMembers};
use ciris_verify_core::edition2::room::{
    check_room_row, RoomRowReading, RoomRowRefusal, VoiceRoster,
};
use ciris_verify_core::edition2::{hash_digest_value, thumbprint, Digest32};
use serde_json::Value as J;
use sha2::{Digest as _, Sha256};

const FILE: &str = include_str!("vectors/edition2/room/kernel_room_keys.json");
const FILE_SHA256: &str = "48134460929b411632bf264fef6cd9e6ebeae9019e4fa45f1f4ed99be9ac850f";

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

#[test]
fn kernel_room_key_cases() {
    assert_eq!(hex::encode(Sha256::digest(FILE.as_bytes())), FILE_SHA256);
    let f: J = serde_json::from_str(FILE).unwrap();
    let cases = f["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 16);
    let mut engaged = 0;
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let row = &c["row"];
        if c["membership"] == "public" {
            // The door is a private room's; the caller does not call it.
            assert_eq!(c["verdict"], "admitted", "{name}");
            continue;
        }
        engaged += 1;
        let kid = d(row["kid"].as_str().unwrap());
        let heads: Vec<&str> = row["refs"]["also"]["voice"]
            .as_array()
            .map(|a| a.iter().map(|h| h.as_str().unwrap()).collect())
            .unwrap_or_default();
        let mut payload = vec![
            (t("asserted_at"), Value::Uint(1)),
            (t("cohort_scope"), t("community")),
            (t("community_id"), t(&group(row["room"].as_str().unwrap()))),
        ];
        if !heads.is_empty() {
            let set = heads
                .iter()
                .map(|h| Value::Array(vec![Value::Uint(2), hash_digest_value(&d(h))]))
                .collect();
            payload.push((
                t("refs"),
                Value::Map(vec![(
                    t("also"),
                    Value::Map(vec![(t("voice"), Value::Array(set))]),
                )]),
            ));
        }
        let payload = Value::Map(payload);
        // The signer's record, as the case gives it (none: no room named).
        let rec_room = c["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["key"] == row["kid"])
            .and_then(|r| r["room"].as_str());
        let rec = record(kid, rec_room);
        let view = &c["view"];
        let live: Vec<Digest32> = view["live_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| d(k.as_str().unwrap()))
            .collect();
        let view_heads = view["heads"].as_array().unwrap();
        let roster = (view_heads.len() == 1).then(|| VoiceRoster {
            head: d(view_heads[0].as_str().unwrap()),
            voice: view["voice"].as_str().unwrap(),
            live_keys: &live,
        });
        let got = check_room_row(
            row["iss"].as_str().unwrap(),
            &kid,
            &payload,
            &rec,
            roster.as_ref(),
        );
        let malformed_head = heads.len() != 1;
        let want_refusal = c["refusal"].as_str();
        match (c["verdict"].as_str().unwrap(), want_refusal, got) {
            ("admitted", None, RoomRowReading::Valid) => {},
            ("refused", Some(tok), RoomRowReading::Refused(r)) => {
                assert_eq!(r.token(), tok, "{name}")
            },
            // Ruled after the fixture was cut: refused, by name.
            (
                "concludes_nothing",
                None,
                RoomRowReading::Refused(RoomRowRefusal::VoiceHeadMalformed),
            ) if malformed_head => {},
            ("concludes_nothing", None, RoomRowReading::ConcludesNothing(_)) if !malformed_head => {
            },
            (v, r, g) => panic!("{name}: fixture {v} {r:?}, door {g:?}"),
        }
    }
    assert_eq!(engaged, 15);
}
