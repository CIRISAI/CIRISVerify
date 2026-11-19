//! Differential replay of the key check's model (CC 2.6.1.8 step 8, ways (a)
//! and (b)) against [`KeyRecordDirectory`].
//!
//! `tests/vectors/edition2/key_of_iss_model.tsv` is `key_of_iss_expected.tsv`
//! from the model `formal/key_of_iss` (TLA+ `KeyOfIss.tla` and its Python
//! twin `key_of_iss.py`). Its `verdict chain` rows give, for every set of
//! held statement groups out of the chain world's twelve, the answer for each
//! `(kid, iss)`: `y` a key of `iss`, `n` `kid_not_of_iss`, `w` Waiting.
//!
//! A statement group is one or more voices over one `key:record` row; two
//! groups over the same row merge, as statements do. This test signs each
//! voice as a real statement, files the held ones in a
//! [`KeyRecordDirectory`] in two arrival orders, and compares `key_of` with
//! the model. The occurrence world (way (d)) is not replayed here. Way (a) (`kid` is the thumbprint inside `iss`) is
//! the reader's own and is not asked of the directory.
#![cfg(feature = "pqc")]

use std::collections::BTreeMap;

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::keys::{KeyRecordDirectory, KEY_RECORD_FAMILY};
use ciris_verify_core::edition2::{
    cose_key, identity_ref, row_id, row_ref, sign_row_statement, thumbprint, Digest32,
    KeyDirectory, KeyOf,
};

const MODEL: &str = include_str!("vectors/edition2/key_of_iss_model.tsv");

const T0: u64 = 1_763_200_000_000;
const STEP: u64 = 1_000;

/// The model's keys and the seeds standing for them.
fn key(name: &str) -> CompositeSigningKey {
    let n = match name {
        "G" => 1,
        "K1" => 2,
        "K2" => 3,
        "R" => 4,
        "S" => 5,
        "X" => 6,
        other => panic!("key {other}"),
    };
    CompositeSigningKey::from_seeds(&[n; 32], &[n + 100; 32])
}

/// The model's identities by their genesis key.
fn gen(iss: &str) -> &'static str {
    match iss {
        "I" => "G",
        "J" => "S",
        other => panic!("iss {other}"),
    }
}

struct Row {
    k: &'static str,
    iss: &'static str,
    at: u64,
    until: u64,
    tgt: Option<&'static str>,
}

/// `key_of_iss.py`'s `ROW` (its records), one for one.
const ROWS: &[(&str, Row)] = &[
    (
        "RG",
        Row {
            k: "G",
            iss: "I",
            at: 0,
            until: 2,
            tgt: None,
        },
    ),
    (
        "RK1",
        Row {
            k: "K1",
            iss: "I",
            at: 1,
            until: 4,
            tgt: Some("RG"),
        },
    ),
    (
        "RK2",
        Row {
            k: "K2",
            iss: "I",
            at: 2,
            until: 4,
            tgt: Some("RK1"),
        },
    ),
    (
        "RoS",
        Row {
            k: "S",
            iss: "I",
            at: 1,
            until: 3,
            tgt: Some("RG"),
        },
    ),
    (
        "RS",
        Row {
            k: "S",
            iss: "J",
            at: 0,
            until: 4,
            tgt: None,
        },
    ),
    (
        "RfSI",
        Row {
            k: "S",
            iss: "I",
            at: 0,
            until: 4,
            tgt: None,
        },
    ),
    (
        "RfSrot",
        Row {
            k: "S",
            iss: "I",
            at: 1,
            until: 4,
            tgt: Some("RG"),
        },
    ),
    (
        "RXG",
        Row {
            k: "X",
            iss: "I",
            at: 1,
            until: 4,
            tgt: Some("RG"),
        },
    ),
    (
        "RXGend",
        Row {
            k: "X",
            iss: "I",
            at: 2,
            until: 4,
            tgt: Some("RG"),
        },
    ),
    (
        "RXGlate",
        Row {
            k: "X",
            iss: "I",
            at: 3,
            until: 4,
            tgt: Some("RG"),
        },
    ),
    (
        "RXK2",
        Row {
            k: "X",
            iss: "I",
            at: 3,
            until: 4,
            tgt: Some("RK2"),
        },
    ),
];

/// `key_of_iss.py`'s chain-world `CATS["chain"]`: statement groups, each its
/// row and its voices.
const ENTRIES: &[(&str, &str, &[&str])] = &[
    ("rG", "RG", &["G"]),
    ("rK1n", "RK1", &["K1"]),
    ("rK1o", "RK1", &["G"]),
    ("rK2", "RK2", &["K2", "K1"]),
    ("oS", "RoS", &["G"]),
    ("rS", "RS", &["S"]),
    ("fS_I", "RfSI", &["S"]),
    ("fS_rot", "RfSrot", &["S"]),
    ("fX_G", "RXG", &["X", "G"]),
    ("fX_Gend", "RXGend", &["X", "G"]),
    ("fX_Glate", "RXGlate", &["X", "G"]),
    ("fX_K2", "RXK2", &["X", "K2"]),
];

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

fn iss_ref(iss: &str) -> String {
    identity_ref(&thumbprint(key(gen(iss)).public_key()))
}

/// Every statement group as its signed statements.
fn build() -> BTreeMap<&'static str, Vec<Vec<u8>>> {
    let mut row_ids: BTreeMap<&str, Digest32> = BTreeMap::new();
    let mut payloads: BTreeMap<&str, (Value, String)> = BTreeMap::new();
    for (id, r) in ROWS {
        let k = key(r.k);
        let mut p = vec![
            (t("key"), cose_key(k.public_key())),
            (t("identity_type"), Value::Array(vec![t("node")])),
            (t("asserted_at"), Value::Uint(T0 + r.at * STEP)),
            (t("valid_until"), Value::Uint(T0 + r.until * STEP)),
        ];
        if let Some(tgt) = r.tgt {
            p.push((
                t("refs"),
                Value::Map(vec![(t("target"), row_ref(&row_ids[tgt]))]),
            ));
        }
        let payload = Value::Map(p);
        let sub = identity_ref(&thumbprint(k.public_key()));
        row_ids.insert(
            id,
            row_id(
                "scores",
                KEY_RECORD_FAMILY,
                &sub,
                None,
                &cde::encode(&payload),
            ),
        );
        payloads.insert(id, (payload, sub));
    }
    let iss_of: BTreeMap<&str, &str> = ROWS.iter().map(|(id, r)| (*id, r.iss)).collect();
    ENTRIES
        .iter()
        .map(|(e, row, sigs)| {
            let (payload, sub) = &payloads[row];
            let sts = sigs
                .iter()
                .map(|s| {
                    sign_row_statement(
                        &key(s),
                        &iss_ref(iss_of[row]),
                        sub,
                        "scores",
                        KEY_RECORD_FAMILY,
                        payload,
                        vec![],
                    )
                    .unwrap()
                })
                .collect();
            (*e, sts)
        })
        .collect()
}

fn letter(d: &KeyRecordDirectory, kid: &str, iss: &str) -> char {
    if kid == gen(iss) {
        return 'y';
    }
    let k = thumbprint(key(kid).public_key());
    let i = thumbprint(key(gen(iss)).public_key());
    match d.key_of(&k, &i) {
        KeyOf::Yes => 'y',
        KeyOf::No => 'n',
        KeyOf::Waiting(_) => 'w',
        _ => '?',
    }
}

#[test]
fn key_record_directory_agrees_with_the_model() {
    let rows = build();
    let mut lines = MODEL.lines().filter(|l| l.starts_with("verdict\tchain\t"));
    let header: Vec<&str> = lines.next().unwrap().split('\t').collect();
    assert_eq!(header[2], "entries");
    let order: Vec<&str> = header[3].split(' ').collect();
    assert_eq!(
        order,
        ENTRIES.iter().map(|(e, _, _)| *e).collect::<Vec<_>>(),
        "catalog drift"
    );
    let stmts: Vec<(&str, &str)> = header[5]
        .split(' ')
        .map(|s| s.split_once('/').unwrap())
        .collect();

    let mut checked = 0usize;
    let mut diffs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // Every row in a release build (about 70 s). An unoptimised build (CI's
    // test profile) replays every STRIDE-th held set, both arrival orders, to
    // stay inside the runner's timeout; KEY_OF_ISS_MODEL_STRIDE=1 forces the
    // full table anywhere.
    let stride: usize = std::env::var("KEY_OF_ISS_MODEL_STRIDE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(if cfg!(debug_assertions) { 8 } else { 1 })
        .max(1);
    let mut replayed = 0usize;
    for (n, line) in lines.enumerate() {
        if n % stride != 0 {
            continue;
        }
        replayed += 1;
        let f: Vec<&str> = line.split('\t').collect();
        let held: Vec<&str> = if f[2] == "-" {
            vec![]
        } else {
            f[2].split(' ').collect()
        };
        let want: Vec<char> = f[3].chars().collect();
        // Two arrival orders: the catalog's and its reverse.
        for rev in [false, true] {
            let mut ids = held.clone();
            if rev {
                ids.reverse();
            }
            let mut d = KeyRecordDirectory::new();
            for id in &ids {
                for st in &rows[id] {
                    d.insert(st.clone()).unwrap();
                }
            }
            for (j, (kid, iss)) in stmts.iter().enumerate() {
                let got = letter(&d, kid, iss);
                checked += 1;
                if got != want[j] {
                    diffs
                        .entry(format!("{kid}/{iss} model={} verify={got}", want[j]))
                        .or_default()
                        .push(format!("{}{}", if rev { "rev:" } else { "" }, f[2]));
                }
            }
        }
    }
    assert_eq!(replayed, (1usize << ENTRIES.len()).div_ceil(stride));
    assert_eq!(checked, replayed * stmts.len() * 2);
    if !diffs.is_empty() {
        let mut msg = String::new();
        for (k, v) in &diffs {
            msg += &format!(
                "\n{k}: {} held sets, e.g. {:?}",
                v.len(),
                &v[..v.len().min(4)]
            );
        }
        panic!("verify's KeyRecordDirectory differs from the model:{msg}");
    }
}
