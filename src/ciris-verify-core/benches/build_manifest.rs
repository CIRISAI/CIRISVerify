//! Benchmarks for the v1.8 generic `BuildManifest` validator.
//!
//! These exercise the load-bearing pieces of the federation
//! substrate-primitive work:
//!
//! - `BuildManifest::canonical_bytes()` — serialization for signing /
//!   verification
//! - `verify_hybrid_signature()` — Ed25519 + ML-DSA-65 with bound
//!   second signature
//! - `verify_build_manifest()` — full pipeline (parse → primitive
//!   match → hybrid signature verify → extras dispatch)
//! - `ExtrasValidator` registry dispatch — RwLock contention path
//!
//! Baseline numbers feed `docs/BENCHMARKS.md`. CI gate (when added)
//! will fail on >25% regression vs baseline.

use base64::{engine::general_purpose::STANDARD, Engine};
use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};
use ciris_verify_core::security::build_manifest::{
    register_extras_validator, verify_build_manifest, BuildManifest, BuildPrimitive,
    ExtrasValidator,
};
use ciris_verify_core::security::function_integrity::{ManifestSignature, StewardPublicKey};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json::json;

/// Test-only validator that always passes.
struct AlwaysOkValidator(BuildPrimitive);

impl ExtrasValidator for AlwaysOkValidator {
    fn primitive(&self) -> BuildPrimitive {
        self.0.clone()
    }

    fn validate(
        &self,
        _extras: &serde_json::Value,
    ) -> Result<(), ciris_verify_core::error::VerifyError> {
        Ok(())
    }
}

/// Build a sample manifest with realistic-but-fake extras.
fn sample_manifest(primitive: BuildPrimitive, extras_size: usize) -> BuildManifest {
    // Synthesize extras of varying size to bound the dispatch cost.
    let mut entries = serde_json::Map::new();
    for i in 0..extras_size {
        entries.insert(
            format!("entry_{:03}", i),
            json!({"hash": format!("sha256:{:0>64x}", i), "size": 4096 + i}),
        );
    }
    let extras = json!({ "items": entries });

    BuildManifest {
        manifest_schema_version: "1.0".into(),
        primitive,
        build_id: "v0.1.0-bench".into(),
        target: "x86_64-unknown-linux-gnu".into(),
        binary_hash: "sha256:abc123def456".into(),
        binary_version: "0.1.0".into(),
        generated_at: "2026-05-01T00:00:00Z".into(),
        manifest_hash: "sha256:cafebabe".into(),
        extras: Some(extras),
        signature: ManifestSignature {
            classical: String::new(),
            classical_algorithm: "Ed25519".into(),
            pqc: String::new(),
            pqc_algorithm: "ML-DSA-65".into(),
            key_id: "bench-steward".into(),
        },
    }
}

/// Sign a manifest with newly-generated steward keys, returning
/// (signed_bytes, embedded steward keys boxed in 'static).
fn sign_for_bench(mut m: BuildManifest) -> (Vec<u8>, &'static [u8; 32], &'static [u8]) {
    let ed_signer = Ed25519Signer::random();
    let ed_pub_vec = ed_signer.public_key().expect("ed25519 pubkey");
    let mut ed_pub_arr = [0u8; 32];
    ed_pub_arr.copy_from_slice(&ed_pub_vec);

    let mldsa_signer = MlDsa65Signer::new().expect("mldsa keygen");
    let mldsa_pub = mldsa_signer.public_key().expect("mldsa pubkey");

    // Sign canonical bytes with Ed25519.
    let canonical = m.canonical_bytes();
    let classical_sig = ed_signer.sign(&canonical).expect("ed25519 sign");

    // Bound PQC signature: covers canonical || classical_sig.
    let mut bound = canonical.clone();
    bound.extend_from_slice(&classical_sig);
    let pqc_sig = mldsa_signer.sign(&bound).expect("mldsa sign");

    m.signature.classical = STANDARD.encode(&classical_sig);
    m.signature.pqc = STANDARD.encode(&pqc_sig);

    let bytes = serde_json::to_vec(&m).unwrap();

    // Leak the keys so they have 'static lifetime — only OK because
    // criterion benches are short-lived processes; this is a tiny
    // amount of memory and avoids lifetime gymnastics in the bench.
    let ed_pub_static: &'static [u8; 32] = Box::leak(Box::new(ed_pub_arr));
    let mldsa_pub_static: &'static [u8] = Box::leak(mldsa_pub.into_boxed_slice());
    (bytes, ed_pub_static, mldsa_pub_static)
}

fn bench_canonical_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("BuildManifest::canonical_bytes");

    for size in [1, 16, 256] {
        let m = sample_manifest(BuildPrimitive::Verify, size);
        group.bench_with_input(format!("extras_{}", size), &m, |b, m| {
            b.iter(|| black_box(m.canonical_bytes()));
        });
    }

    let m_no_extras = BuildManifest {
        extras: None,
        ..sample_manifest(BuildPrimitive::Verify, 0)
    };
    group.bench_function("no_extras", |b| {
        b.iter(|| black_box(m_no_extras.canonical_bytes()));
    });

    group.finish();
}

fn bench_verify_hybrid_signature(c: &mut Criterion) {
    use ciris_verify_core::security::function_integrity::verify_hybrid_signature;

    let mut group = c.benchmark_group("verify_hybrid_signature");

    for size in [1, 16, 256] {
        let m = sample_manifest(BuildPrimitive::Verify, size);
        let (bytes, ed_pub, mldsa_pub) = sign_for_bench(m);
        let parsed: BuildManifest = serde_json::from_slice(&bytes).unwrap();
        let canonical = parsed.canonical_bytes();
        let pubkey = StewardPublicKey {
            ed25519: ed_pub,
            ml_dsa_65: mldsa_pub,
        };

        group.bench_with_input(format!("extras_{}", size), &canonical, |b, canonical| {
            b.iter(|| {
                let r = verify_hybrid_signature(
                    black_box(canonical),
                    black_box(&parsed.signature),
                    black_box(&pubkey),
                );
                black_box(r.unwrap());
            });
        });
    }

    group.finish();
}

fn bench_verify_build_manifest(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_build_manifest");

    // Pre-register a validator for the benchmark primitive so dispatch
    // path is exercised. Use a unique Other key to avoid stepping on
    // any default validators.
    let bench_primitive = BuildPrimitive::Other("bench-primitive".into());
    register_extras_validator(Box::new(AlwaysOkValidator(bench_primitive.clone())));

    for size in [1, 16, 256] {
        let m = sample_manifest(bench_primitive.clone(), size);
        let (bytes, ed_pub, mldsa_pub) = sign_for_bench(m);
        let pubkey = StewardPublicKey {
            ed25519: ed_pub,
            ml_dsa_65: mldsa_pub,
        };

        group.bench_with_input(format!("extras_{}", size), &bytes, |b, bytes| {
            b.iter(|| {
                let r = verify_build_manifest(
                    black_box(bytes),
                    black_box(bench_primitive.clone()),
                    black_box(&pubkey),
                );
                black_box(r.unwrap());
            });
        });
    }

    group.finish();
}

fn bench_extras_dispatch_overhead(c: &mut Criterion) {
    // Isolate the cost of the registry RwLock + HashMap lookup +
    // dynamic dispatch from the cost of the validator's actual work.

    let primitive_with = BuildPrimitive::Other("bench-with-validator".into());
    let primitive_without = BuildPrimitive::Other("bench-no-validator".into());

    register_extras_validator(Box::new(AlwaysOkValidator(primitive_with.clone())));

    let extras = json!({"k": "v"});

    let mut group = c.benchmark_group("extras_dispatch");

    // Round-trip through verify_build_manifest with vs without registered validator
    let m_with = sample_manifest(primitive_with.clone(), 4);
    let m_without = sample_manifest(primitive_without.clone(), 4);
    let (bytes_with, ed_with, mldsa_with) = sign_for_bench(m_with);
    let (bytes_without, ed_without, mldsa_without) = sign_for_bench(m_without);
    let pk_with = StewardPublicKey {
        ed25519: ed_with,
        ml_dsa_65: mldsa_with,
    };
    let pk_without = StewardPublicKey {
        ed25519: ed_without,
        ml_dsa_65: mldsa_without,
    };

    group.bench_function("with_registered_validator", |b| {
        b.iter(|| {
            let r = verify_build_manifest(
                black_box(&bytes_with),
                black_box(primitive_with.clone()),
                black_box(&pk_with),
            );
            black_box(r.unwrap());
        });
    });

    group.bench_function("no_validator_registered", |b| {
        b.iter(|| {
            let r = verify_build_manifest(
                black_box(&bytes_without),
                black_box(primitive_without.clone()),
                black_box(&pk_without),
            );
            black_box(r.unwrap());
        });
    });

    let _ = extras; // silence unused
    group.finish();
}

criterion_group!(
    benches,
    bench_canonical_bytes,
    bench_verify_hybrid_signature,
    bench_verify_build_manifest,
    bench_extras_dispatch_overhead,
);
criterion_main!(benches);
