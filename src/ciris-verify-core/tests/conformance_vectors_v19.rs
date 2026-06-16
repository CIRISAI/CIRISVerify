//! §19 holonomic cross-impl conformance vectors — the CIRISVerify#57 freeze gate.
//!
//! These vectors are **vendored from CIRISEdge v4.1.2**
//! (`conformance_vectors/19/`, tag sha `e11dde77ae664fedaa9493af505e0b2db87a1bea`),
//! the *fixed reference impl* the §19.6 freeze gate pins against. Each asserts
//! that CIRISVerify's **independent** `ciris_verify_core::holonomic`
//! implementation reproduces Edge's expected bytes **byte-for-byte**. When this
//! suite is green, the §19 shapes are proven cross-impl — lifting them from
//! "pinned-but-unproven, RC-grade" (§19.6) toward the CEG 1.0 GA label.
//!
//! To refresh: re-vendor the JSON from a newer Edge tag and re-run; a wire-shape
//! drift in either impl fails here (the emit-or-verify discipline).

use std::path::PathBuf;

use ciris_verify_core::holonomic::{
    bootstrap::SignedClaim,
    compute_merkle_root,
    fountain::{FountainCompressRequest, FountainHoldingClaim},
    wholeness_witness::WholenessWitness,
    DOMAIN_COMPRESS_REQUEST, DOMAIN_HOLDING_CLAIM, DOMAIN_SIGNED_CLAIM, DOMAIN_WITNESS_PREIMAGE,
};
use serde_json::Value;

fn vector(rel: &str) -> Value {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/vectors/holonomic_v19");
    p.push(rel);
    let raw = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {p:?}: {e}"))
}

fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap().to_string()
}
fn u64f(v: &Value, k: &str) -> u64 {
    v[k].as_u64().unwrap()
}
fn opt_s(v: &Value, k: &str) -> Option<String> {
    v[k].as_str().map(str::to_string)
}
fn bytes(v: &Value, k: &str) -> Vec<u8> {
    v[k].as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_u64().unwrap() as u8)
        .collect()
}
fn strvec(v: &Value, k: &str) -> Vec<String> {
    v[k].as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

// ---- §19.0 domain separators -------------------------------------------

#[test]
fn domain_separators_match() {
    let v = vector("domain_separators.json");
    assert_eq!(
        hex::encode(DOMAIN_WITNESS_PREIMAGE),
        s(&v, "witness_preimage_v1_hex")
    );
    assert_eq!(
        hex::encode(DOMAIN_SIGNED_CLAIM),
        s(&v, "signed_claim_v1_hex")
    );
    assert_eq!(
        hex::encode(DOMAIN_HOLDING_CLAIM),
        s(&v, "holding_claim_v1_hex")
    );
    assert_eq!(
        hex::encode(DOMAIN_COMPRESS_REQUEST),
        s(&v, "compress_request_v1_hex")
    );
}

// ---- §19.1 WholenessWitness Merkle root --------------------------------

fn check_merkle(rel: &str) {
    let v = vector(rel);
    let leaves: Vec<Vec<u8>> = v["leaves_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| hex::decode(h.as_str().unwrap()).unwrap())
        .collect();
    let got = hex::encode(compute_merkle_root(&leaves));
    assert_eq!(got, s(&v, "expected_root_hex"), "merkle vector {rel}");
}

#[test]
fn merkle_root_empty_sentinel() {
    check_merkle("merkle_root/empty_sentinel.json");
}
#[test]
fn merkle_root_single_leaf() {
    check_merkle("merkle_root/single_leaf.json");
}
#[test]
fn merkle_root_three_leaves_odd_dup() {
    check_merkle("merkle_root/three_leaves_odd_dup.json");
}
#[test]
fn merkle_root_lex_sort_invariance() {
    check_merkle("merkle_root/lex_sort_invariance.json");
}

// ---- §19.1 WholenessWitness canonical preimage -------------------------

fn check_witness(rel: &str) {
    let v = vector(rel);
    let root_vec = bytes(&v, "merkle_root");
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&root_vec);
    let w = WholenessWitness {
        peer_id: s(&v, "peer_id"),
        epoch_id: u64f(&v, "epoch_id"),
        claim_namespaces: strvec(&v, "claim_namespaces"),
        merkle_root,
        leaf_count: u64f(&v, "leaf_count") as u32,
        observed_at_unix_ms: u64f(&v, "observed_at_unix_ms"),
        witness_version: u64f(&v, "witness_version") as u16,
    };
    assert_eq!(
        hex::encode(w.canonical_preimage()),
        s(&v, "expected_canonical_bytes_hex"),
        "witness vector {rel}"
    );
}

#[test]
fn witness_canonical_preimage_empty() {
    check_witness("wholeness_witness/canonical_preimage_empty.json");
}
#[test]
fn witness_canonical_preimage_three_namespaces() {
    check_witness("wholeness_witness/canonical_preimage_three_namespaces.json");
}

// ---- §19.2 SignedClaim canonical bytes ---------------------------------

fn check_signed_claim(rel: &str) {
    let v = vector(rel);
    let c = SignedClaim {
        signed_at_unix_ms: u64f(&v, "signed_at_unix_ms"),
        claim_version: u64f(&v, "claim_version") as u16,
        claim_kind: s(&v, "claim_kind"),
        signer_peer_id: s(&v, "signer_peer_id"),
        claim_bytes: bytes(&v, "claim_bytes"),
        user_owner: opt_s(&v, "user_owner"),
        delegates_to: opt_s(&v, "delegates_to"),
        identity_occurrence: opt_s(&v, "identity_occurrence"),
    };
    assert_eq!(
        hex::encode(c.signing_preimage()),
        s(&v, "expected_canonical_bytes_hex"),
        "signed_claim vector {rel}"
    );
}

#[test]
fn signed_claim_no_owner_binding() {
    check_signed_claim("signed_claim/canonical_bytes_no_owner_binding.json");
}
#[test]
fn signed_claim_with_owner_binding() {
    check_signed_claim("signed_claim/canonical_bytes_with_owner_binding.json");
}

// ---- §19.3 fountain holding claim / compress request -------------------

#[test]
fn fountain_holding_claim_canonical_bytes() {
    let v = vector("fountain_holding_claim/canonical_bytes.json");
    let c = FountainHoldingClaim {
        peer_id: s(&v, "peer_id"),
        content_id: s(&v, "content_id"),
        symbol_ids: v["symbol_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as u32)
            .collect(),
        observed_at_unix_ms: u64f(&v, "observed_at_unix_ms"),
        claim_version: u64f(&v, "claim_version") as u32,
    };
    assert_eq!(
        hex::encode(c.signing_preimage()),
        s(&v, "expected_canonical_bytes_hex")
    );
}

#[test]
fn fountain_compress_request_canonical_bytes() {
    let v = vector("fountain_compress_request/canonical_bytes.json");
    let c = FountainCompressRequest {
        peer_id: s(&v, "peer_id"),
        content_id: s(&v, "content_id"),
        evicting_range_low: u64f(&v, "evicting_range_low") as u32,
        evicting_range_high: u64f(&v, "evicting_range_high") as u32,
        deadline_unix_ms: u64f(&v, "deadline_unix_ms"),
        request_version: u64f(&v, "request_version") as u32,
    };
    assert_eq!(
        hex::encode(c.signing_preimage()),
        s(&v, "expected_canonical_bytes_hex")
    );
}
