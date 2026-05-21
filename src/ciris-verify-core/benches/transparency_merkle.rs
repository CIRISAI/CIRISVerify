//! Transparency-log Merkle benchmarks (CIRISVerify#23 follow-up, v2.7.0).
//!
//! Measures the v2.6.0 level-cache claim — the perf review asserted
//! O(N)→O(log N) for inclusion/consistency proofs and O(N)→O(1) for
//! root, but that was static analysis. These benches are the receipts.
//!
//! What to read in the output:
//!
//! * `transparency/merkle_root` — should be **flat and tiny** across all
//!   tree sizes (the v2.6.0 O(1) cached-root read). If it scales with N,
//!   the level cache regressed.
//! * `transparency/inclusion_proof` — should grow only ~logarithmically
//!   with N (each doubling of the tree adds one sibling). Pre-v2.6.0 this
//!   was O(N).
//! * `transparency/consistency_proof` — O(log² N); grows slowly.
//! * `transparency/append` — reported as elements/sec (Throughput); the
//!   per-append cost is the v2.6.0 incremental O(log N) update.
//! * `transparency/verify_inclusion` — pure hash-chain walk, O(log N).
//!
//! SOTA frame: RFC 6962 / Trillian / Sigstore Rekor production logs do
//! inclusion-proof generation in single-digit microseconds against
//! millions of leaves. Our O(log N) shape is the right complexity class;
//! these numbers are where we measure the constant factor.

use ciris_verify_core::transparency::{TransparencyEntry, TransparencyLog};
use ciris_verify_core::types::ValidationStatus;
use ciris_verify_core::{verify_consistency, verify_inclusion, LicenseStatus};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

/// Tree sizes swept by every bench — five geometric points (×4 each)
/// over a 256× range. Enough points that the complexity *curve* is
/// legible, not just inferable: a flat line is O(1), a line that adds a
/// constant per step is O(log N), a line that quadruples per step is
/// O(N). An unexplained upward bend is the signal to investigate
/// (accidental quadratic, allocation growth, a leak).
const SIZES: &[u64] = &[256, 1_024, 4_096, 16_384, 65_536];

/// Consistency-proof `from` size for a tree of `n`.
///
/// `n / 2` would be degenerate: for the power-of-2 sizes swept here it is
/// itself a power of 2, i.e. a perfect left subtree, which is the
/// *cheapest* possible consistency proof (one sibling) and hides the
/// real O(log² N) shape. `n / 2 - 1` is odd — never a power of 2 — so it
/// forces the full RFC 6962 SUBPROOF recursion, giving a representative
/// curve.
fn consistency_from(n: u64) -> u64 {
    n / 2 - 1
}

/// Build a license-domain log of `n` entries.
fn build_log(n: u64) -> TransparencyLog<TransparencyEntry> {
    let log = TransparencyLog::<TransparencyEntry>::new_license_log("bench", None);
    for i in 0..n {
        log.append_license(
            "bench-license",
            LicenseStatus::LicensedProfessional,
            ValidationStatus::AllSourcesAgree,
            i,
        )
        .expect("append");
    }
    log
}

/// Append throughput — builds an `n`-leaf log from empty. Reported as
/// elements/sec; per-append cost is the v2.6.0 incremental O(log N)
/// level-cache update.
fn bench_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("transparency/append");
    for &n in SIZES {
        group.throughput(Throughput::Elements(n));
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| build_log(black_box(n)));
        });
    }
    group.finish();
}

/// Inclusion-proof generation. Should grow ~logarithmically with N.
fn bench_inclusion_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("transparency/inclusion_proof");
    for &n in SIZES {
        let log = build_log(n);
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| log.inclusion_proof(black_box(n / 2)).expect("proof"));
        });
    }
    group.finish();
}

/// Inclusion-proof verification — the pure hash-chain walk.
fn bench_verify_inclusion(c: &mut Criterion) {
    let mut group = c.benchmark_group("transparency/verify_inclusion");
    for &n in SIZES {
        let log = build_log(n);
        let proof = log.inclusion_proof(n / 2).expect("proof");
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| verify_inclusion(black_box(&proof)));
        });
    }
    group.finish();
}

/// Consistency-proof generation from a non-aligned mid-point to the full
/// tree — exercises the full RFC 6962 SUBPROOF recursion (O(log² N)).
fn bench_consistency_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("transparency/consistency_proof");
    for &n in SIZES {
        let log = build_log(n);
        let from = consistency_from(n);
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| {
                log.consistency_proof(black_box(from), black_box(n))
                    .expect("proof")
            });
        });
    }
    group.finish();
}

/// Consistency-proof verification.
fn bench_verify_consistency(c: &mut Criterion) {
    let mut group = c.benchmark_group("transparency/verify_consistency");
    for &n in SIZES {
        let log = build_log(n);
        let from = consistency_from(n);
        let old_root = build_log(from).merkle_root().expect("old root");
        let new_root = log.merkle_root().expect("new root");
        let proof = log.consistency_proof(from, n).expect("proof");
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| {
                verify_consistency(
                    black_box(&old_root),
                    black_box(from),
                    black_box(&new_root),
                    black_box(n),
                    black_box(&proof),
                )
                .expect("verify")
            });
        });
    }
    group.finish();
}

/// Merkle-root read — the v2.6.0 O(1) cached-top read. Should be flat
/// and tiny across every tree size.
fn bench_merkle_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("transparency/merkle_root");
    for &n in SIZES {
        let log = build_log(n);
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| log.merkle_root().expect("root"));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_append,
    bench_inclusion_proof,
    bench_verify_inclusion,
    bench_consistency_proof,
    bench_verify_consistency,
    bench_merkle_root,
);
criterion_main!(benches);
