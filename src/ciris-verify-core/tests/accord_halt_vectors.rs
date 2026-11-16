//! Edition-2 accord halt known answers (CC 4.2.1.1, CC 4.2.1.3, CC 4.2.6;
//! CIRISConstitution rc20 64c5918).
//!
//! `tests/vectors/accord_halt/accord_halt_v1.json` was written by
//! `gen_accord_halt.py` beside it, with its own CBOR encoder over dilithium-py
//! and pyca/cryptography, sharing no code with verify. Every invocation and
//! lifecycle case is read by `edition2::accord_halt` under the stated roster
//! and must give the stated verdict, row id and statement ids; every valid
//! statement must also be the byte-for-byte output of `sign_row_statement`
//! over its own payload. The latch sequences drive
//! `HaltLatch::apply_forward` with the roster's fuse.
#![cfg(feature = "pqc")]

use std::collections::BTreeMap;

use chrono::{DateTime, TimeZone, Utc};
use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::accord_halt_latch::{ForwardRow, HaltLatch, LatchOutcome};
use ciris_verify_core::cde;
use ciris_verify_core::edition2::accord_halt::{
    verify_invocation_row, verify_lifecycle_row, HaltRoster, InvocationRow, InvokeKind,
    LifecycleKind, LifecycleRow, RosterHolder,
};
use ciris_verify_core::edition2::{identity_ref, sign_row_statement, thumbprint};
use serde_json::Value as J;

const FILE: &str = include_str!("vectors/accord_halt/accord_halt_v1.json");

fn key(n: u8) -> CompositeSigningKey {
    CompositeSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(100); 32])
}

fn seed(j: &J) -> u8 {
    u8::try_from(j["key_seed"].as_u64().unwrap()).unwrap()
}

fn hex32(j: &J) -> [u8; 32] {
    hex::decode(j.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn bytes(j: &J) -> Vec<u8> {
    hex::decode(j.as_str().unwrap()).unwrap()
}

fn roster(f: &J) -> HaltRoster {
    let r = &f["roster"];
    let holders = r["holders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            let k = key(seed(h));
            let kid = thumbprint(k.public_key());
            assert_eq!(hex::encode(kid), h["kid_hex"].as_str().unwrap());
            assert_eq!(identity_ref(&kid), h["iss"].as_str().unwrap());
            RosterHolder {
                identity_ref: identity_ref(&kid),
                key: k.public_key().clone(),
            }
        })
        .collect();
    let roster = HaltRoster::new(
        r["accord_root"].as_str().unwrap(),
        hex32(&r["bundle_object_id_hex"]),
        holders,
        Some(u32::try_from(r["halt_fuse_secs"].as_u64().unwrap()).unwrap()),
    );
    assert_eq!(roster.majority() as u64, r["majority"].as_u64().unwrap());
    roster
}

/// A valid statement is the exact output of `sign_row_statement` over its
/// own payload (both sides sign deterministically).
fn assert_remints(case: &J, stmt: &J) {
    let k = key(seed(stmt));
    let payload = cde::decode(&bytes(&case["payload_hex"])).unwrap();
    let again = sign_row_statement(
        &k,
        stmt["iss"].as_str().unwrap(),
        case["sub"].as_str().unwrap(),
        case["row_type"].as_str().unwrap(),
        case["family"].as_str().unwrap(),
        &payload,
        vec![],
    )
    .unwrap();
    assert_eq!(
        hex::encode(again),
        stmt["statement_hex"].as_str().unwrap(),
        "{}",
        case["id"]
    );
}

fn member_text<'a>(case: &'a J, m: &str) -> &'a str {
    case["members"][m].as_str().unwrap()
}

fn member_u64(case: &J, m: &str) -> u64 {
    case["members"][m].as_u64().unwrap()
}

fn member_bstr(case: &J, m: &str) -> Vec<u8> {
    bytes(&case["members"][m]["bstr"])
}

fn read_invocations(f: &J, roster: &HaltRoster) -> BTreeMap<String, InvocationRow> {
    let mut out = BTreeMap::new();
    for c in f["invocations"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let st = &c["statement"];
        let row = verify_invocation_row(&bytes(&st["statement_hex"]), roster)
            .unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let kind = match c["kind"].as_str().unwrap() {
            "constitutional" => InvokeKind::Constitutional,
            "notify" => InvokeKind::Notify,
            "drill" => InvokeKind::Drill,
            k => panic!("{k}"),
        };
        assert_eq!(row.kind(), kind, "{id}");
        assert_eq!(kind.family(), c["family"].as_str().unwrap(), "{id}");
        assert_eq!(
            hex::encode(row.row_id()),
            c["row_id_hex"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            hex::encode(row.statement_id()),
            st["statement_id_hex"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(row.author(), member_text(c, "author"), "{id}");
        assert_eq!(row.author(), st["iss"].as_str().unwrap(), "{id}");
        assert_eq!(row.invocation_id(), member_text(c, "invocation_id"), "{id}");
        assert_eq!(row.nonce().to_vec(), member_bstr(c, "nonce"), "{id}");
        assert_eq!(row.asserted_at(), member_u64(c, "asserted_at"), "{id}");
        assert_eq!(row.valid_until(), member_u64(c, "valid_until"), "{id}");
        match c["members"].get("payload_digest") {
            Some(d) => assert_eq!(
                row.payload_digest().map(|x| x.to_vec()),
                Some(bytes(&d[1]["bstr"])),
                "{id}"
            ),
            None => assert!(row.payload_digest().is_none(), "{id}"),
        }
        assert_remints(c, st);
        out.insert(id.to_owned(), row);
    }
    out
}

fn statements(c: &J) -> Vec<Vec<u8>> {
    c["statements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| bytes(&s["statement_hex"]))
        .collect()
}

fn read_lifecycles(
    f: &J,
    roster: &HaltRoster,
    halts: &BTreeMap<String, InvocationRow>,
) -> BTreeMap<String, LifecycleRow> {
    let mut out = BTreeMap::new();
    for c in f["lifecycles"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let halt = &halts[c["halt"].as_str().unwrap()];
        let got = verify_lifecycle_row(&statements(c), roster, halt);
        let expect = c["expect"].as_str().unwrap();
        if expect != "valid" {
            let e = got.expect_err(id);
            let token = match e.reason {
                ciris_verify_core::edition2::accord_halt::HaltRefusal::CountUnmet {
                    have,
                    need,
                } => {
                    format!("count_unmet:{have}:{need}")
                },
                ref r => r.token(),
            };
            assert_eq!(token, expect, "{id}");
            continue;
        }
        let row = got.unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let kind = match c["kind"].as_str().unwrap() {
            "confirmed" => LifecycleKind::Confirmed,
            "active" => LifecycleKind::Active,
            k => panic!("{k}"),
        };
        assert_eq!(row.kind(), kind, "{id}");
        assert_eq!(
            hex::encode(row.row_id()),
            c["row_id_hex"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(row.target(), halt.row_id(), "{id}");
        assert_eq!(
            row.target().to_vec(),
            bytes(&c["members"]["refs"]["target"][1][1]["bstr"]),
            "{id}"
        );
        assert_eq!(row.head(), roster.bundle(), "{id}");
        assert_eq!(row.invocation_id(), member_text(c, "invocation_id"), "{id}");
        assert_eq!(row.nonce().to_vec(), member_bstr(c, "nonce"), "{id}");
        assert_eq!(row.asserted_at(), member_u64(c, "asserted_at"), "{id}");
        assert_eq!(row.valid_until(), member_u64(c, "valid_until"), "{id}");
        let voices: Vec<&str> = c["voices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(row.voices(), voices.as_slice(), "{id}");
        let sids: Vec<String> = row.statement_ids().iter().map(hex::encode).collect();
        let want: Vec<&str> = c["statements"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["statement_id_hex"].as_str().unwrap())
            .collect();
        assert_eq!(sids, want, "{id}");
        assert!(row.refused().is_empty(), "{id}");
        for s in c["statements"].as_array().unwrap() {
            assert_remints(c, s);
        }
        out.insert(id.to_owned(), row);
    }
    out
}

#[test]
fn invocations_lifecycles_and_refusals() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let roster = roster(&f);
    let halts = read_invocations(&f, &roster);
    assert_eq!(halts.len(), 4);
    let lifes = read_lifecycles(&f, &roster, &halts);
    assert_eq!(lifes.len(), 2);
    for c in f["invocation_refusals"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let e =
            verify_invocation_row(&bytes(&c["statement"]["statement_hex"]), &roster).expect_err(id);
        assert_eq!(e.token(), c["expect"].as_str().unwrap(), "{id}");
    }
}

fn at(ms: u64) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(i64::try_from(ms).unwrap())
        .unwrap()
}

#[test]
fn latch_sequences() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let roster = roster(&f);
    let halts = read_invocations(&f, &roster);
    let lifes = read_lifecycles(&f, &roster, &halts);
    let fuse = u64::from(roster.halt_fuse_secs());
    for seq in f["latch"].as_array().unwrap() {
        let sid = seq["id"].as_str().unwrap();
        let mut latch = HaltLatch::new();
        for step in seq["steps"].as_array().unwrap() {
            if let Some(case) = step["apply"].as_str() {
                let row = halts
                    .get(case)
                    .map(ForwardRow::Invocation)
                    .unwrap_or_else(|| {
                        ForwardRow::Lifecycle(lifes.get(case).unwrap_or_else(|| panic!("{case}")))
                    });
                let now = at(step["at_ms"].as_u64().unwrap());
                let got = match latch.apply_forward(row, now, fuse) {
                    LatchOutcome::Paused => "paused",
                    LatchOutcome::Confirmed => "confirmed",
                    LatchOutcome::Resumed => "resumed",
                    LatchOutcome::Unchanged { .. } => "unchanged",
                    _ => "other",
                };
                assert_eq!(got, step["outcome"].as_str().unwrap(), "{sid}: {case}");
            } else {
                let now = at(step["check"].as_u64().unwrap());
                assert_eq!(
                    latch.is_paused(now, fuse),
                    step["paused"].as_bool().unwrap(),
                    "{sid} at {now}"
                );
            }
        }
    }
}

/// The fuse is the charter's; absent, 86400 (CC 4.2.1.1).
#[test]
fn fuse_default_is_86400() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let r = roster(&f);
    let bare = HaltRoster::new(r.accord_root(), *r.bundle(), Vec::new(), None);
    assert_eq!(bare.halt_fuse_secs(), 86_400);
}
