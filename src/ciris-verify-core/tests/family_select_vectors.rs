//! Replay CIRISConstitution's `manifests/family_select_vectors.json` (v1.0-rc20
//! d4bd2a6) against verify's port of the reference selector evaluator
//! (`edition2::family::select`, from `tools/cc_family_select.py`).
//!
//! For each vector: bind the leaf of `dimension` under `family` (null: the leaf
//! is unknown), take verb, identity, group, seats and act from `ctx` (an absent
//! key is unknown), read the `cell`, and compare with `expect` and `decided_by`.
//!
//! The `authorship` and `second_signers` cells are the vendored extract
//! `data/cc/family_authorship.json`. The `count` cells are not in CC's extract;
//! `tests/vectors/cc/family_count_cells.json` carries the count cells written as
//! arms, cut from the same `manifests/family_model.json` (its digest is pinned
//! below and must match the vectors' and the extract's).
#![cfg(feature = "pqc")]

use ciris_verify_core::edition2::family::{
    select::{self, parse_cell, Act, Arm, Cell, Decision, Group, Select, SelectContext, Signers},
    vendored_family, vendored_family_ids, FAMILY_AUTHORSHIP_JSON, FAMILY_AUTHORSHIP_SHA256,
    FAMILY_MODEL_CC_COMMIT, FAMILY_MODEL_SHA256,
};
use ciris_verify_core::namespace_match::{bind_leaf, family_id};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const VECTORS: &str = include_str!("vectors/cc/family_select_vectors.json");
const COUNT_CELLS: &str = include_str!("vectors/cc/family_count_cells.json");

/// SHA-256 of `tests/vectors/cc/family_select_vectors.json` (CC v1.0-rc20 d4bd2a6).
const VECTORS_SHA256: &str = "9b221e7b314aeac891b31ef90f35f10fcf2995391c70c6db0485591c2d26049b";
/// CC ships 246 vectors at rc22 (8c436b8).
const VECTOR_COUNT: usize = 246;

fn lf(s: &str) -> String {
    s.replace("\r\n", "\n")
}

fn sha(s: &str) -> String {
    hex::encode(Sha256::digest(lf(s).as_bytes()))
}

fn count_cells() -> BTreeMap<String, Cell> {
    let j: Value = serde_json::from_str(COUNT_CELLS).unwrap();
    j["families"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(prefix, c)| {
            let arms = c["arms"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| Arm::new(a["when"].as_str().unwrap(), a["doors"].as_str().unwrap()))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            (
                prefix.clone(),
                Cell {
                    value: c["value"].as_str().map(str::to_owned),
                    source: c["source"].as_str().unwrap().to_owned(),
                    arms,
                },
            )
        })
        .collect()
}

fn context(ctx: &Value) -> SelectContext {
    let o = ctx.as_object().unwrap();
    for k in o.keys() {
        assert!(
            // `iss` and `sub` are read from the statement, never selector
            // keys: they decide only a `subject` answer's `admits`.
            ["verb", "identity", "group", "seats", "act", "iss", "sub"].contains(&k.as_str()),
            "ctx key {k}"
        );
    }
    SelectContext {
        verb: o.get("verb").map(|v| v.as_str().unwrap().to_owned()),
        identity: o.get("identity").map(|v| {
            v.as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_owned())
                .collect()
        }),
        group: o
            .get("group")
            .map(|v| Group::parse(v.as_str().unwrap()).unwrap()),
        seats: o.get("seats").map(|v| v.as_u64().unwrap()),
        act: o
            .get("act")
            .map(|v| Act::parse(v.as_str().unwrap()).unwrap()),
    }
}

fn select_json(s: &Select) -> Value {
    match s {
        Select::Value(v) => Value::String(v.clone()),
        Select::Unknown => Value::String("unknown".into()),
        Select::Gap => Value::String("gap".into()),
        Select::Null => Value::Null,
    }
}

fn decided_json(d: Option<Decision>) -> Value {
    match d {
        Some(Decision::Arm(i)) => Value::from(i),
        Some(Decision::Unknown) => Value::String("unknown".into()),
        Some(Decision::Null) | None => Value::Null,
    }
}

#[test]
fn vendored_files_are_the_pinned_ones() {
    assert_eq!(FAMILY_MODEL_CC_COMMIT, "8c436b8");
    assert_eq!(sha(FAMILY_AUTHORSHIP_JSON), FAMILY_AUTHORSHIP_SHA256);
    assert_eq!(
        FAMILY_AUTHORSHIP_SHA256,
        "4a3304165c6cfbe5247cad2195c0f284a434789354c462da0e67638e8d2b79a6"
    );
    assert_eq!(sha(VECTORS), VECTORS_SHA256);
    // One family model under all three files.
    let extract: Value = serde_json::from_str(FAMILY_AUTHORSHIP_JSON).unwrap();
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let counts: Value = serde_json::from_str(COUNT_CELLS).unwrap();
    assert_eq!(extract["_meta"]["source_sha256"], FAMILY_MODEL_SHA256);
    assert_eq!(vectors["_meta"]["family_model_sha256"], FAMILY_MODEL_SHA256);
    assert_eq!(counts["_meta"]["source_sha256"], FAMILY_MODEL_SHA256);
    assert_eq!(extract["_meta"]["cc_version"], "1.0-rc22");
}

#[test]
fn extract_shape() {
    let extract: Value = serde_json::from_str(FAMILY_AUTHORSHIP_JSON).unwrap();
    let fams = extract["families"].as_object().unwrap();
    assert_eq!(fams.len(), 189);
    assert_eq!(vendored_family_ids().count(), 189);
    let (mut plain, mut arms, mut gap) = (0, 0, 0);
    for (prefix, f) in fams {
        let v = vendored_family(&family_id(prefix)).unwrap();
        assert_eq!(&v.prefix, prefix);
        match (v.authorship.source.as_str(), v.authorship.arms.is_empty()) {
            ("gap", _) => gap += 1,
            (_, true) => plain += 1,
            (_, false) => arms += 1,
        }
        // A cell's text reads back as its arms.
        if !v.authorship.arms.is_empty() {
            let text = f["authorship"]["value"].as_str().unwrap();
            assert_eq!(parse_cell(text).unwrap(), v.authorship.arms, "{prefix}");
        }
    }
    // CC's split at rc22 (8c436b8): 164 generic cells, 25 cc-table cells as arms, no gap.
    assert_eq!((plain, arms, gap), (164, 25, 0));
    for (prefix, c) in count_cells() {
        assert_eq!(
            parse_cell(c.value.as_deref().unwrap()).unwrap(),
            c.arms,
            "{prefix}"
        );
    }
}

#[test]
fn every_cc_vector_agrees() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = doc["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), VECTOR_COUNT);
    let counts = count_cells();
    let mut failures = Vec::new();
    let mut passed = 0usize;
    for (i, v) in vectors.iter().enumerate() {
        let prefix = v["family"].as_str().unwrap();
        let cell = v["cell"].as_str().unwrap();
        let leaf = match v["dimension"].as_str() {
            None => None,
            Some(d) => match bind_leaf(prefix, d) {
                Ok(b) => {
                    if Value::from(b.matcher_family) != v["matcher_family"] {
                        failures.push(format!(
                            "#{i} {prefix} {d}: matcher family {:?}, CC {}",
                            b.matcher_family, v["matcher_family"]
                        ));
                        continue;
                    }
                    Some(b.leaf)
                },
                Err(e) => {
                    failures.push(format!("#{i} {prefix} {d}: no leaf ({e:?})"));
                    continue;
                },
            },
        };
        if Value::from(leaf.clone()) != v["leaf"] {
            failures.push(format!("#{i} {prefix}: leaf {leaf:?}, CC {}", v["leaf"]));
            continue;
        }
        let ctx = context(&v["ctx"]);
        let leaf = leaf.as_deref();
        let (got, decided) = match cell {
            "authorship" => {
                let f = vendored_family(&family_id(prefix)).unwrap();
                let (s, d) = f.authorship.answer(leaf, &ctx);
                (select_json(&s), Some(decided_json(d)))
            },
            "count" => {
                let (s, d) = counts[prefix].answer(leaf, &ctx);
                (select_json(&s), Some(decided_json(d)))
            },
            "second_signers" => {
                let f = vendored_family(&family_id(prefix)).unwrap();
                let got = match select::second_signers(&f.second_signers, leaf, &ctx) {
                    Signers::Unknown => Value::String("unknown".into()),
                    Signers::Roles(rs) => Value::Array(
                        rs.iter()
                            .map(|r| serde_json::json!({"role": r.role, "member": r.member}))
                            .collect(),
                    ),
                };
                (got, None)
            },
            other => panic!("cell {other}"),
        };
        let want_decided = decided.as_ref().map(|_| v["decided_by"].clone());
        // A `subject` answer admits a statement exactly when its `iss` is
        // the attested key `sub` (CC 2.6.1.3; `check_family` under
        // `AUTHOR_IS_SUBJECT`); unknown when either is absent.
        if got == "subject" && v.get("admits").is_some() {
            let admits = match (v["ctx"].get("iss"), v["ctx"].get("sub")) {
                (Some(i), Some(s)) => Value::Bool(i == s),
                _ => Value::String("unknown".into()),
            };
            if admits != v["admits"] {
                failures.push(format!(
                    "#{i} {prefix}: admits {admits}, CC {}",
                    v["admits"]
                ));
                continue;
            }
        }
        if got != v["expect"] || decided != want_decided {
            failures.push(format!(
                "#{i} {prefix} {cell} {:?} {}: got {got} decided {decided:?}; CC {} decided {} ({})",
                v["dimension"], v["ctx"], v["expect"], v["decided_by"], v["kind"]
            ));
        } else {
            passed += 1;
        }
    }
    assert!(
        failures.is_empty(),
        "{passed}/{} pass; disagreements:\n{}",
        vectors.len(),
        failures.join("\n")
    );
    assert_eq!(passed, VECTOR_COUNT);
}
