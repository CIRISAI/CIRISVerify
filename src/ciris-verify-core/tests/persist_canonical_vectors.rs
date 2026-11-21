//! `persist_row_hash` against CIRISPersist's accord lineage vector (CC 3.2 T6,
//! annex 8.11).
//!
//! `tests/vectors/accord_lineage/accord_lineage_v1.json` is persist's own,
//! vendored byte for byte (persist commit `e943482e`; see the README beside
//! it). Every `canonical_bytes` (utf8 and hex) is reproduced byte for byte by
//! [`persist_canonical`] from the stored and the offered record and hashes to
//! the version's `persist_row_hash`; every canonicalizer probe and instant
//! truncation reproduces.

use ciris_verify_core::persist_canonical;
use ciris_verify_core::utc::UtcDateTime;
use serde_json::Value;
use sha2::{Digest, Sha256};

const VECTOR: &str = include_str!("vectors/accord_lineage/accord_lineage_v1.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

/// The bytes a `{utf8, hex}` pair names, checking the two agree.
fn bytes_of(v: &Value) -> Vec<u8> {
    let utf8 = v["utf8"].as_str().unwrap().as_bytes().to_vec();
    let hex = hex::decode(v["hex"].as_str().unwrap()).unwrap();
    assert_eq!(utf8, hex, "utf8 and hex name the same bytes");
    hex
}

#[test]
fn every_canonical_byte_string_and_row_hash_reproduces() {
    let v = vector();
    let mut prev = String::new();
    for n in 1..=3 {
        let r = &v["versions"][n - 1];
        let canonical = bytes_of(&r["canonical_bytes"]);
        let hash = r["persist_row_hash"].as_str().unwrap();
        for form in ["offered_family", "stored_family"] {
            assert_eq!(
                persist_canonical::persist_row_hash_preimage(&r[form]).unwrap(),
                canonical,
                "v{n} {form}: canonical bytes"
            );
            assert_eq!(
                persist_canonical::persist_row_hash(&r[form]).unwrap(),
                hash,
                "v{n} {form}: hash"
            );
        }
        assert_eq!(
            hex::encode(Sha256::digest(&canonical)),
            hash,
            "v{n}: SHA-256"
        );
        assert_eq!(r["prev_head_digest"], prev.as_str(), "v{n}: prev");
        assert_eq!(
            r["stored_family"]["persist_row_hash"], hash,
            "v{n}: stored hash"
        );
        prev = hash.to_string();
    }
}

#[test]
fn every_canonicalizer_probe_reproduces() {
    let v = vector();
    let probes = v["canonicalizer_rules"]["probes"].as_array().unwrap();
    assert_eq!(probes.len(), 24);
    for p in probes {
        let rule = p["rule"].as_str().unwrap();
        assert_eq!(
            persist_canonical::python_json_dumps(&p["input"]),
            bytes_of(&p["output"]),
            "probe {rule}"
        );
    }
    let rules: Vec<&str> = probes.iter().map(|p| p["rule"].as_str().unwrap()).collect();
    for r in [
        "non_ascii_bmp_latin",
        "non_bmp_emoji",
        "non_bmp_object_key_order",
        "control_and_escapes",
        "float_small",
        "float_1e_minus_5",
        "float_1e16",
        "float_negative_zero",
        "int_u64_max",
        "int_i64_min",
    ] {
        assert!(rules.contains(&r), "{r} is probed");
    }
}

#[test]
fn every_instant_truncation_reproduces() {
    let v = vector();
    let instants = v["canonicalizer_rules"]["instants"].as_array().unwrap();
    assert_eq!(instants.len(), 7);
    for i in instants {
        let raw = i["raw"].as_str().unwrap();
        let t: UtcDateTime = raw.parse().unwrap();
        let serde = serde_json::to_value(t).unwrap();
        assert_eq!(serde, i["serde"], "{raw}: serde rendering");
        let mut truncated = serde.clone();
        persist_canonical::truncate_instants_to_microseconds(&mut truncated);
        assert_eq!(truncated, i["truncated"], "{raw}: truncated");
    }
}
