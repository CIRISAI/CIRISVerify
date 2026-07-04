//! §19.7 aggregation-pyramid conformance vectors — **authored by CIRISVerify**.
//!
//! Per CEG 1.0-RC14 §19.7's conformance note, `AggregationMetaV1` /
//! `member_commitment` / `descend` are **CEG-canonical** (no edge reference impl
//! predates them — Persist v8.3.0 stores `aggregation_meta` opaque). So the
//! *first* conformant implementation generates the §19.6/#57 vectors and a
//! second reproduces them byte-for-byte. **CIRISVerify is that first impl.**
//!
//! This harness runs **emit-or-verify**: a missing vector file is generated from
//! `ciris_verify_core::holonomic::aggregation` (emit); an existing one is read
//! back and re-derived (verify). The committed JSON files are the published
//! reference CIRISEdge / CIRISPersist reproduce to lift §19.7 from RC-grade to
//! 1.0. A drift in this impl fails the verify pass; a regeneration is an
//! explicit, reviewable diff.

use std::path::PathBuf;

use ciris_verify_core::holonomic::aggregation::{
    descend_order, member_commitment, AggregationMetaV1,
};
use ciris_verify_core::holonomic::DOMAIN_AGG_META;
use serde_json::{json, Value};

fn vectors_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/vectors/holonomic_v19_7");
    p
}

/// Emit-or-verify: if `rel` exists, assert it equals `produced` (modulo a stable
/// re-serialization); otherwise write `produced` as the reference.
fn emit_or_verify(rel: &str, produced: Value) {
    let path = vectors_dir().join(rel);
    if path.exists() {
        let on_disk: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            on_disk, produced,
            "§19.7 vector {rel} drifted — this impl no longer reproduces the published bytes \
             (regenerate intentionally if the contract changed)"
        );
    } else {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&produced).unwrap() + "\n",
        )
        .unwrap();
    }
}

fn ids(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| s.to_string()).collect()
}

#[test]
fn domain_separator() {
    emit_or_verify(
        "domain_separators.json",
        json!({
            "agg_meta_v1_hex": hex::encode(DOMAIN_AGG_META),
            "agg_meta_v1_len": DOMAIN_AGG_META.len(),
        }),
    );
    // The contract pins it at exactly 16 bytes.
    assert_eq!(DOMAIN_AGG_META.len(), 16);
}

// ---- §19.7.1.1 member_commitment (source ids → 32-byte root) ------------

fn emit_member_commitment(rel: &str, members: &[&str]) {
    let m = ids(members);
    emit_or_verify(
        rel,
        json!({
            "vector_id": rel.trim_end_matches(".json"),
            "description": "member_commitment = §19.1 WholenessWitness Merkle over SHA-256(utf8(member_id)), lexicographic.",
            "source_member_ids": members,
            "expected_commitment_hex": hex::encode(member_commitment(&m)),
        }),
    );
}

#[test]
fn member_commitment_empty() {
    emit_member_commitment("member_commitment/empty.json", &[]);
}
#[test]
fn member_commitment_single() {
    emit_member_commitment("member_commitment/single.json", &["member-alpha"]);
}
#[test]
fn member_commitment_three_unsorted() {
    // Input deliberately unsorted — the commitment MUST be order-independent.
    emit_member_commitment("member_commitment/three_unsorted.json", &["m3", "m1", "m2"]);
}

// ---- §19.7.2 descend order (unordered ids → lexicographic list) ---------

#[test]
fn descend_order_lexicographic() {
    let input = ["zeta", "alpha", "mu", "beta"];
    let out = descend_order(&ids(&input));
    emit_or_verify(
        "descend/ordered_list.json",
        json!({
            "vector_id": "descend/ordered_list",
            "description": "descend returns the lexicographic member-id order member_commitment commits to.",
            "input_member_ids": input,
            "expected_ordered_ids": out,
            "expected_commitment_hex": hex::encode(member_commitment(&out)),
        }),
    );
    // Descent-integrity: the ordered list re-derives the commitment.
    assert_eq!(member_commitment(&out), member_commitment(&ids(&input)));
}

// ---- §19.7.1 AggregationMetaV1 canonical preimage ----------------------

#[test]
fn aggregation_meta_canonical_bytes() {
    let members = ids(&["src-001", "src-002", "src-003"]);
    let m = AggregationMetaV1 {
        version: 1,
        content_id: "content-root-fixed".into(),
        corpus_kind: "trace".into(),
        tier: 2,
        aggregation_algorithm_id: "raptorq-pyramid-v1".into(),
        source_count: members.len() as u32,
        member_commitment: member_commitment(&members),
        noise_floor_descriptor: "mean+stddev".into(),
        // v1: n_eff is a neutral, un-signed placeholder — NOT in the v1 preimage,
        // so `expected_canonical_bytes_hex` is byte-identical to the pre-#167 golden.
        n_eff: members.len() as u32,
    };
    emit_or_verify(
        "aggregation_meta/canonical_bytes.json",
        json!({
            "vector_id": "aggregation_meta/canonical_bytes",
            "description": "AggregationMetaV1 §19.7.1 canonical signing preimage (16-byte AGG-META domain, u32-lp, big-endian).",
            "domain_separator_hex": hex::encode(DOMAIN_AGG_META),
            "version": m.version,
            "content_id": m.content_id,
            "corpus_kind": m.corpus_kind,
            "tier": m.tier,
            "aggregation_algorithm_id": m.aggregation_algorithm_id,
            "source_count": m.source_count,
            "source_member_ids": ["src-001", "src-002", "src-003"],
            "member_commitment_hex": hex::encode(m.member_commitment),
            "noise_floor_descriptor": m.noise_floor_descriptor,
            "expected_canonical_bytes_hex": hex::encode(m.signing_preimage()),
        }),
    );
}

// ---- §19.7.1.2 AggregationMetaV1 v2 preimage — signed n_eff (#167) ------
#[test]
fn aggregation_meta_v2_canonical_bytes_with_n_eff() {
    let members = ids(&["src-001", "src-002", "src-003"]);
    let m = AggregationMetaV1 {
        version: 2,
        content_id: "content-root-fixed".into(),
        corpus_kind: "trace".into(),
        tier: 2,
        aggregation_algorithm_id: "raptorq-pyramid-v1".into(),
        source_count: members.len() as u32,
        member_commitment: member_commitment(&members),
        noise_floor_descriptor: "mean+stddev".into(),
        // A v2 tier carries a signed effective-source-count in the preimage.
        n_eff: 3,
    };
    // The v2 preimage is the v1 layout + a trailing u32(n_eff): strictly longer.
    let mut v1 = m.clone();
    v1.version = 1;
    assert_eq!(
        m.signing_preimage().len(),
        v1.signing_preimage().len() + 4,
        "v2 appends exactly u32(n_eff) to the v1 layout"
    );
    emit_or_verify(
        "aggregation_meta/canonical_bytes_v2.json",
        json!({
            "vector_id": "aggregation_meta/canonical_bytes_v2",
            "description": "AggregationMetaV1 §19.7.1.2 v2 preimage — v1 layout followed by a trailing big-endian u32(n_eff) (CIRISVerify#167 dominance surface).",
            "domain_separator_hex": hex::encode(DOMAIN_AGG_META),
            "version": m.version,
            "content_id": m.content_id,
            "corpus_kind": m.corpus_kind,
            "tier": m.tier,
            "aggregation_algorithm_id": m.aggregation_algorithm_id,
            "source_count": m.source_count,
            "source_member_ids": ["src-001", "src-002", "src-003"],
            "member_commitment_hex": hex::encode(m.member_commitment),
            "noise_floor_descriptor": m.noise_floor_descriptor,
            "n_eff": m.n_eff,
            "expected_canonical_bytes_hex": hex::encode(m.signing_preimage()),
        }),
    );
}

// ---- CC 6.1.5.2 §Q storage-contention (CIRISVerify#170) -----------------

#[test]
fn storage_budget_v1_canonical_bytes() {
    use ciris_verify_core::holonomic::storage_contention::{ScopeBudget, StorageBudgetV1};
    use ciris_verify_core::holonomic::DOMAIN_STORAGE_BUDGET;
    assert_eq!(
        DOMAIN_STORAGE_BUDGET.len(),
        16,
        "§Q domain separator is 16 bytes"
    );
    let b = StorageBudgetV1 {
        node_id: "node-1".into(),
        epoch_id: "epoch-1".into(),
        revision: 3,
        scopes: vec![
            ScopeBudget {
                cohort_scope: "affiliations".into(),
                budget_bytes: 1000,
                pin_reserve_bytes: 200,
            },
            ScopeBudget {
                cohort_scope: "community".into(),
                budget_bytes: 2000,
                pin_reserve_bytes: 0,
            },
        ],
        pinned_class: vec!["av_chunk".into(), "trace".into()],
    };
    b.validate().expect("fixture is structurally valid");
    emit_or_verify(
        "storage_budget/canonical_bytes.json",
        json!({
            "vector_id": "storage_budget/canonical_bytes",
            "description": "StorageBudgetV1 CC 6.1.5.2 §Q canonical signing preimage (16-byte CIRIS-STG-BUDGET domain, u32-lp, big-endian; NOT JCS). CIRISVerify#170.",
            "domain_separator_hex": hex::encode(DOMAIN_STORAGE_BUDGET),
            "version": 1,
            "node_id": b.node_id,
            "epoch_id": b.epoch_id,
            "revision": b.revision,
            "scopes": [
                { "cohort_scope": "affiliations", "budget_bytes": 1000, "pin_reserve_bytes": 200 },
                { "cohort_scope": "community", "budget_bytes": 2000, "pin_reserve_bytes": 0 },
            ],
            "pinned_class": ["av_chunk", "trace"],
            "expected_canonical_bytes_hex": hex::encode(b.signing_preimage()),
        }),
    );
}

#[test]
fn corpus_want_v1_canonical_bytes() {
    use ciris_verify_core::holonomic::storage_contention::CorpusWantV1;
    use ciris_verify_core::holonomic::DOMAIN_CORPUS_WANT;
    assert_eq!(
        DOMAIN_CORPUS_WANT.len(),
        16,
        "§Q domain separator is 16 bytes"
    );
    let w = CorpusWantV1 {
        node_id: "node-1".into(),
        epoch_id: "epoch-1".into(),
        cohort_scope: "community".into(),
        size_cap_bytes: 4096,
        remaining_budget_bytes: 1800,
        want: vec!["cid-a".into(), "cid-b".into()],
    };
    w.validate().expect("fixture is structurally valid");
    emit_or_verify(
        "corpus_want/canonical_bytes.json",
        json!({
            "vector_id": "corpus_want/canonical_bytes",
            "description": "CorpusWantV1 CC 6.1.5.2 §Q canonical signing preimage (16-byte CIRIS-WANT-HAVE\\0 domain, u32-lp, big-endian; NOT JCS). CIRISVerify#170.",
            "domain_separator_hex": hex::encode(DOMAIN_CORPUS_WANT),
            "version": 1,
            "node_id": w.node_id,
            "epoch_id": w.epoch_id,
            "cohort_scope": w.cohort_scope,
            "size_cap_bytes": w.size_cap_bytes,
            "remaining_budget_bytes": w.remaining_budget_bytes,
            "want": ["cid-a", "cid-b"],
            "expected_canonical_bytes_hex": hex::encode(w.signing_preimage()),
        }),
    );
}
