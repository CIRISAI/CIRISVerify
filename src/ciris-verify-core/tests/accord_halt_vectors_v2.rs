//! Edition-2 accord halt known answers, v2 (CC 4.2.1.1, CC 4.2.1.3, CC 4.2.6,
//! CC 2.6.1.8; CIRISConstitution rc20 436b5bc).
//!
//! `tests/vectors/accord_halt/accord_halt_v2.json` was written by
//! `gen_accord_halt_v2.py` beside it, with its own CBOR encoder over
//! dilithium-py and pyca/cryptography, sharing no code with verify. Every
//! invocation and lifecycle case is read by `edition2::accord_halt` under the
//! roster it names and must give the stated answer (`valid`,
//! `waiting:<what>` with the keys and bundles waited on, or
//! `refused:<token>`), and a valid one its row id and statement ids; every
//! statement counted must also be the byte-for-byte output of
//! `sign_row_statement` over its own payload. The latch sequences drive
//! `HaltLatch::apply_forward` with the roster's fuse.
//!
//! v1 (`accord_halt_v1.json`, published at v23.2.0) stays byte-identical and
//! is no longer replayed: its `outsider_halt` (`not_a_holder`),
//! `lifecycle_outsider_voice` (`count_unmet`) and `lifecycle_other_bundle`
//! (`other_bundle`) are Waiting here.
#![cfg(feature = "pqc")]

use std::collections::BTreeMap;

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::accord_halt_latch::{ForwardRow, HaltLatch, LatchOutcome};
use ciris_verify_core::cde;
use ciris_verify_core::edition2::accord_halt::{
    named_accord_root, named_head, verify_invocation_row, verify_lifecycle_row, HaltReading,
    HaltRefusal, HaltRoster, InvocationRow, InvokeKind, LifecycleKind, LifecycleRow, RosterHolder,
};
use ciris_verify_core::edition2::{sign_row_statement, thumbprint};
use ciris_verify_core::utc::UtcDateTime;
use serde_json::Value as J;

const FILE: &str = include_str!("vectors/accord_halt/accord_halt_v2.json");

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

fn rosters(f: &J) -> BTreeMap<String, HaltRoster> {
    f["rosters"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, r)| {
            let holders = r["holders"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| {
                    let k = key(seed(h));
                    assert_eq!(
                        hex::encode(thumbprint(k.public_key())),
                        h["kid_hex"].as_str().unwrap()
                    );
                    RosterHolder {
                        identity_ref: h["iss"].as_str().unwrap().to_owned(),
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
            (name.clone(), roster)
        })
        .collect()
}

fn roster_of<'a>(rs: &'a BTreeMap<String, HaltRoster>, case: &J) -> &'a HaltRoster {
    &rs[case["roster"].as_str().unwrap()]
}

/// A counted statement is the exact output of `sign_row_statement` over its
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

/// A non-valid answer against the case's `expect`, `waiting` and `count`.
fn assert_not_valid<T>(case: &J, got: &HaltReading<T>) {
    let id = case["id"].as_str().unwrap();
    let expect = case["expect"].as_str().unwrap();
    assert_eq!(got.token(), expect, "{id}");
    match got {
        HaltReading::Waiting(w) => {
            let hexes = |j: &J| -> Vec<String> {
                j.as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_str().unwrap().to_owned())
                    .collect()
            };
            let kids: Vec<String> = w.kids.iter().map(hex::encode).collect();
            let bundles: Vec<String> = w.bundles.iter().map(hex::encode).collect();
            assert_eq!(kids, hexes(&case["waiting"]["kids_hex"]), "{id}");
            assert_eq!(bundles, hexes(&case["waiting"]["bundles_hex"]), "{id}");
        },
        HaltReading::Refused(HaltRefusal::CountUnmet { have, need }) => {
            assert_eq!(
                *have as u64,
                case["count"]["have"].as_u64().unwrap(),
                "{id}"
            );
            assert_eq!(
                *need as u64,
                case["count"]["need"].as_u64().unwrap(),
                "{id}"
            );
        },
        HaltReading::Refused(_) => assert!(case.get("count").is_none(), "{id}"),
        HaltReading::Valid(_) => unreachable!(),
    }
}

/// Every invocation case read under its roster; the valid ones by id.
fn read_invocations(
    f: &J,
    rs: &BTreeMap<String, HaltRoster>,
) -> (BTreeMap<String, InvocationRow>, usize) {
    let mut out = BTreeMap::new();
    let mut n = 0;
    for c in f["invocations"].as_array().unwrap() {
        n += 1;
        let id = c["id"].as_str().unwrap();
        let st = &c["statement"];
        let got = verify_invocation_row(&bytes(&st["statement_hex"]), roster_of(rs, c));
        let row = match got {
            HaltReading::Valid(row) => {
                assert_eq!(c["expect"], "valid", "{id}");
                row
            },
            other => {
                assert_not_valid(c, &other);
                continue;
            },
        };
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
    (out, n)
}

fn statements(c: &J) -> Vec<Vec<u8>> {
    c["statements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| bytes(&s["statement_hex"]))
        .collect()
}

/// Every lifecycle case read under its roster; the valid ones by id.
fn read_lifecycles(
    f: &J,
    rs: &BTreeMap<String, HaltRoster>,
    halts: &BTreeMap<String, InvocationRow>,
) -> (BTreeMap<String, LifecycleRow>, usize) {
    let mut out = BTreeMap::new();
    let mut n = 0;
    for c in f["lifecycles"].as_array().unwrap() {
        n += 1;
        let id = c["id"].as_str().unwrap();
        let roster = roster_of(rs, c);
        let halt = &halts[c["halt"].as_str().unwrap()];
        let row = match verify_lifecycle_row(&statements(c), roster, halt) {
            HaltReading::Valid(row) => {
                assert_eq!(c["expect"], "valid", "{id}");
                row
            },
            other => {
                assert_not_valid(c, &other);
                continue;
            },
        };
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
        assert_eq!(
            row.head().to_vec(),
            bytes(&c["members"]["refs"]["head"][1][1]["bstr"]),
            "{id}"
        );
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
        let sts = c["statements"].as_array().unwrap();
        let counted: Vec<&J> = c["counted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| &sts[usize::try_from(i.as_u64().unwrap()).unwrap()])
            .collect();
        let sids: Vec<String> = row.statement_ids().iter().map(hex::encode).collect();
        let want: Vec<&str> = counted
            .iter()
            .map(|s| s["statement_id_hex"].as_str().unwrap())
            .collect();
        assert_eq!(sids, want, "{id}");
        // A statement not counted in a valid row is an unheld one: it waits,
        // and is never listed as refused.
        assert!(row.refused().is_empty(), "{id}");
        for s in counted {
            assert_remints(c, s);
        }
        out.insert(id.to_owned(), row);
    }
    (out, n)
}

#[test]
fn invocations_and_lifecycles() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let rs = rosters(&f);
    let (halts, n_inv) = read_invocations(&f, &rs);
    assert_eq!((halts.len(), n_inv), (5, 21));
    let (lifes, n_life) = read_lifecycles(&f, &rs, &halts);
    assert_eq!((lifes.len(), n_life), (5, 22));
}

/// Every Waiting case turns valid under the roster that holds what it waits
/// on: a rotated holder's halt and a confirmation over the rotated bundle.
#[test]
fn waiting_turns_valid_under_the_roster_it_waits_on() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let rs = rosters(&f);
    let (halts, _) = read_invocations(&f, &rs);
    let case = |sec: &str, id: &str| -> J {
        f[sec]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap()
            .clone()
    };
    let unseated = case("invocations", "halt_rotated_a1_unseated");
    let seated = case("invocations", "halt_rotated_a1_seated");
    assert_eq!(unseated["statement"], seated["statement"]);
    let st = bytes(&unseated["statement"]["statement_hex"]);
    let HaltReading::Waiting(w) = verify_invocation_row(&st, &rs["genesis"]) else {
        panic!("waits under genesis");
    };
    assert_eq!(w.kids.len(), 1);
    assert!(matches!(
        verify_invocation_row(&st, &rs["rotated"]),
        HaltReading::Valid(_)
    ));
    let conf = case("lifecycles", "rotated_confirmation_unseated");
    let sts = statements(&conf);
    let head = named_head(&sts[0]).unwrap();
    assert_eq!(&head, rs["rotated"].bundle());
    let chosen = HaltRoster::find_by_head(rs.values(), &head).unwrap();
    assert!(matches!(
        verify_lifecycle_row(&sts, chosen, &halts["halt_constitutional_a1"]),
        HaltReading::Valid(_)
    ));
}

fn at(ms: u64) -> UtcDateTime {
    UtcDateTime::from_timestamp_millis(i64::try_from(ms).unwrap()).unwrap()
}

#[test]
fn latch_sequences() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let rs = rosters(&f);
    let (halts, _) = read_invocations(&f, &rs);
    let (lifes, _) = read_lifecycles(&f, &rs, &halts);
    let fuse = u64::from(rs["genesis"].halt_fuse_secs());
    assert_eq!(fuse, u64::from(rs["rotated"].halt_fuse_secs()));
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
    let r = &rosters(&f)["genesis"];
    let bare = HaltRoster::new(r.accord_root(), *r.bundle(), Vec::new(), None);
    assert_eq!(bare.halt_fuse_secs(), 86_400);
}

/// The bundle in force is the one a lifecycle row names in `refs.head`: the
/// reader picks the roster by it, and a row read under another roster waits
/// on the bundle it names; an invocation names its accord by `accord_root`.
#[test]
fn the_roster_is_the_one_the_row_names() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let rs = rosters(&f);
    let real = &rs["genesis"];
    let holders: Vec<RosterHolder> = f["rosters"]["genesis"]["holders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| RosterHolder {
            identity_ref: h["iss"].as_str().unwrap().to_owned(),
            key: key(seed(h)).public_key().clone(),
        })
        .collect();
    let decoy = HaltRoster::new(real.accord_root(), [0xEE; 32], holders, None);
    let pool = [decoy.clone(), real.clone()];
    let (halts, _) = read_invocations(&f, &rs);
    let halt = &halts["halt_constitutional_a1"];
    let halt_bytes = bytes(&f["invocations"][0]["statement"]["statement_hex"]);
    assert_eq!(
        named_accord_root(&halt_bytes).as_deref(),
        Some(real.accord_root())
    );
    let conf = f["lifecycles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "confirmed_a1_b1")
        .unwrap();
    let sts = statements(conf);
    let head = named_head(&sts[0]).unwrap();
    let chosen = HaltRoster::find_by_head(&pool, &head).unwrap();
    assert_eq!(chosen.bundle(), real.bundle());
    assert!(matches!(
        verify_lifecycle_row(&sts, chosen, halt),
        HaltReading::Valid(_)
    ));
    let HaltReading::Waiting(w) = verify_lifecycle_row(&sts, &decoy, halt) else {
        panic!("waits under another roster");
    };
    assert!(w.kids.is_empty());
    assert_eq!(w.bundles, vec![*real.bundle()]);
    assert!(named_head(&halt_bytes).is_none());
}
