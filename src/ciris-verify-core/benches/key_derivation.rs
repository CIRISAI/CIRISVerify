//! Hardware-rooted key-derivation benchmarks (CIRISVerify#25, v2.7.0).
//!
//! Measures `ciris_verify_core::keys::derive_symmetric_key` — the
//! named-key HKDF-SHA256 derivation CIRISPersist's `secrets-hw` calls
//! for the secrets-store master key.
//!
//! `derive_symmetric_key` is `storage.load(key_id)` + HKDF-Extract +
//! HKDF-Expand. With the software fallback storage the `load` is a file
//! read and dominates the measurement — that is the *real* cost a
//! caller pays per derivation, so it's the honest number to report. The
//! pure HKDF cost (no storage) is isolated in the `federation_crypto`
//! bench in `ciris-crypto`.

use ciris_keyring::storage::{SecureBlobStorage, SoftwareSecureBlobStorage};
use ciris_verify_core::keys::derive_symmetric_key;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_derive_symmetric_key(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = SoftwareSecureBlobStorage::new("bench", dir.path()).expect("storage");
    storage
        .store("bench-seed", &[0x5Au8; 32])
        .expect("store seed");

    let mut group = c.benchmark_group("key_derivation");
    // Full public-API path: storage load + HKDF. This is the per-call
    // cost CIRISPersist#87's secrets-hw pays.
    group.bench_function("derive_symmetric_key", |b| {
        b.iter(|| {
            derive_symmetric_key(
                black_box(&storage),
                black_box("bench-seed"),
                black_box("secrets-store-master-v1"),
            )
            .expect("derive")
        });
    });
    group.finish();
}

criterion_group!(benches, bench_derive_symmetric_key);
criterion_main!(benches);
