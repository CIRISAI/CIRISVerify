//! The embedded family-model columns are CC's (rc20 a15ce94).
//!
//! `data/cc/family_columns.json` is the `authorship` / `second_signers` extract
//! of CC's `manifests/family_model.json` at a15ce94, written by
//! `data/cc/extract_family_columns.py` (see `data/cc/README.md`; the full model
//! is 1.8 MB and is not vendored). This test pins the source digest and checks
//! the extract's shape and the cells verify relies on.
#![cfg(feature = "pqc")]

use ciris_verify_core::edition2::family::FAMILY_COLUMNS_JSON;
use serde_json::Value;

const SOURCE_SHA256: &str = "daa803a680e49d6013fcd41435c4e5d2a725d52b36db568d3523e365c848757e";

#[test]
fn extract_is_pinned_and_well_formed() {
    let cols: Value = serde_json::from_str(FAMILY_COLUMNS_JSON).unwrap();
    assert_eq!(cols["_source"]["sha256"], SOURCE_SHA256);
    let fams = cols["families"].as_object().unwrap();
    assert_eq!(fams.len(), 184);
    let (mut authored, mut counted, mut other) = (0, 0, 0);
    for (prefix, f) in fams {
        match f["authorship"].as_str() {
            Some("authored") => authored += 1,
            Some("counted") => counted += 1,
            _ => other += 1,
        }
        for r in f["second_signers"].as_array().unwrap() {
            assert!(r["role"].is_string() && r["member"].is_string(), "{prefix}");
        }
    }
    // CC's split at a15ce94: 170 authored, 3 counted, 8 selectors, 3 gaps.
    assert_eq!((authored, counted, other), (170, 3, 11));
}
