//! Allocation-stability / leak regression test (v2.7.0).
//!
//! The benchmark suite gives *timing* curves; this test gives the
//! *memory* guarantee behind them. It installs a counting global
//! allocator and asserts that the read-path operations — inclusion
//! proof, consistency proof, root, the verifiers, key derivation — are
//! **allocation-neutral across iterations**: each call allocates and
//! frees the same working set, so net live heap returns to baseline.
//!
//! A leak shows as net live bytes climbing linearly with the iteration
//! count. The slack below (256 KiB) is far smaller than any real leak
//! would produce over 20k iterations (bytes-per-call × 20_000 = MBs),
//! and large enough to absorb one-time lazy initialization that slips
//! past warmup.
//!
//! This is a standalone test binary (not folded into `tests/it/`)
//! precisely because it needs its own process-wide `#[global_allocator]`
//! — installing one in the shared `it` binary would distort every other
//! test and cross-contaminate the counter from parallel test threads.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI64, Ordering};

use ciris_keyring::storage::{SecureBlobStorage, SoftwareSecureBlobStorage};
use ciris_verify_core::keys::derive_symmetric_key;
use ciris_verify_core::transparency::{TransparencyEntry, TransparencyLog};
use ciris_verify_core::types::ValidationStatus;
use ciris_verify_core::{verify_consistency, verify_inclusion, LicenseStatus};

// ------------------------------------------------------------------------
// Counting global allocator — tracks net live bytes (alloc − dealloc).
// ------------------------------------------------------------------------

static LIVE_BYTES: AtomicI64 = AtomicI64::new(0);

struct CountingAllocator;

// SAFETY: delegates every operation to the system allocator unchanged;
// the only addition is a relaxed counter update. Counts are advisory
// (coarse leak detection), so Relaxed ordering is sufficient.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout.size() as i64, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        LIVE_BYTES.fetch_sub(layout.size() as i64, Ordering::Relaxed);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout.size() as i64, Ordering::Relaxed);
        }
        ptr
    }
    // `realloc` uses the default GlobalAlloc impl, which routes through
    // this type's `alloc` + `dealloc` — so it is counted correctly.
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn live_bytes() -> i64 {
    LIVE_BYTES.load(Ordering::Relaxed)
}

/// Net live-heap growth permitted across the measured loop. Any genuine
/// per-call leak would dwarf this within 20k iterations.
const SLACK_BYTES: i64 = 256 * 1024;

const WARMUP_ITERS: usize = 2_000;
const MEASURE_ITERS: usize = 20_000;

/// Run `op` `WARMUP_ITERS` times (to settle lazy init), then
/// `MEASURE_ITERS` times under measurement, and assert net live heap
/// did not climb beyond `SLACK_BYTES`.
fn assert_no_leak(label: &str, mut op: impl FnMut()) {
    for _ in 0..WARMUP_ITERS {
        op();
    }
    let baseline = live_bytes();
    for _ in 0..MEASURE_ITERS {
        op();
    }
    let growth = live_bytes() - baseline;
    assert!(
        growth < SLACK_BYTES,
        "{label}: net live heap grew {growth} bytes across {MEASURE_ITERS} iterations \
         (slack {SLACK_BYTES}) — likely a leak; per-call ≈ {} bytes",
        growth / MEASURE_ITERS as i64,
    );
}

fn build_log(n: u64) -> TransparencyLog<TransparencyEntry> {
    let log = TransparencyLog::<TransparencyEntry>::new_license_log("alloc-test", None);
    for i in 0..n {
        log.append_license(
            "alloc-test-license",
            LicenseStatus::LicensedProfessional,
            ValidationStatus::AllSourcesAgree,
            i,
        )
        .expect("append");
    }
    log
}

/// Single sequential test — one process, one allocator, no parallel
/// test threads contaminating the counter.
#[test]
fn read_path_operations_do_not_leak() {
    let log = build_log(4_096);

    // merkle_root — O(1) cached read, returns a [u8; 32] (no heap).
    assert_no_leak("merkle_root", || {
        let _ = std::hint::black_box(log.merkle_root().expect("root"));
    });

    // inclusion_proof — allocates a MerkleProof (Vec of siblings),
    // freed on drop each iteration.
    assert_no_leak("inclusion_proof", || {
        let proof = log.inclusion_proof(2_048).expect("proof");
        std::hint::black_box(&proof);
    });

    // verify_inclusion — pure hash walk, returns bool.
    let proof = log.inclusion_proof(2_048).expect("proof");
    assert_no_leak("verify_inclusion", || {
        let _ = std::hint::black_box(verify_inclusion(&proof));
    });

    // consistency_proof — allocates a ConsistencyProof (Vec), freed on drop.
    assert_no_leak("consistency_proof", || {
        let proof = log.consistency_proof(2_048, 4_096).expect("proof");
        std::hint::black_box(&proof);
    });

    // verify_consistency — allocates a small working Vec internally.
    let old_root = build_log(2_048).merkle_root().expect("old root");
    let new_root = log.merkle_root().expect("new root");
    let cproof = log.consistency_proof(2_048, 4_096).expect("proof");
    assert_no_leak("verify_consistency", || {
        let _ = std::hint::black_box(
            verify_consistency(&old_root, 2_048, &new_root, 4_096, &cproof).expect("verify"),
        );
    });

    // derive_symmetric_key — storage load (file read) + HKDF, returns Vec.
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = SoftwareSecureBlobStorage::new("alloc-test", dir.path()).expect("storage");
    storage
        .store("alloc-test-seed", &[0x5Au8; 32])
        .expect("store seed");
    assert_no_leak("derive_symmetric_key", || {
        let key = derive_symmetric_key(&storage, "alloc-test-seed", "alloc-test-context")
            .expect("derive");
        std::hint::black_box(&key);
    });
}
