//! liboqs cross-check benchmarks (CIRISVerify#53 Phase 2).
//!
//! Runs the same ML-KEM-768 and ML-DSA-65 operations as
//! `federation_crypto.rs` against the upstream
//! [Open Quantum Safe](https://openquantumsafe.org/) `liboqs`
//! reference implementation (via the `oqs` Rust bindings, which build
//! liboqs from source and link statically). The point is to put a
//! number on the gap between our pure-Rust `ml-kem` + `ml-dsa` crates
//! and the liboqs AVX2 SIMD-optimized C reference.
//!
//! ## Why this is feature-gated
//!
//! Building `oqs-sys` invokes a full cmake build of liboqs, which:
//! - takes ~30s on a warm cache, multi-minute cold
//! - requires `cmake` + a working C toolchain + (for `bindgen`)
//!   libclang + access to the GCC internal include dir
//!
//! None of that is desirable on every `cargo bench` or `cargo test`,
//! so this bench is **off by default**. Activate with:
//!
//! ```text
//! cargo bench -p ciris-crypto --bench liboqs_comparison \
//!   --features bench-liboqs,ml-kem,pqc-ml-dsa
//! ```
//!
//! ## Environment notes
//!
//! If the build fails with `'limits.h' file not found` (Ubuntu 24.04
//! sometimes ships an incomplete clang setup), point bindgen at GCC's
//! internal include dir:
//!
//! ```text
//! BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-linux-gnu/12/include" \
//!   cargo bench --features bench-liboqs,ml-kem,pqc-ml-dsa
//! ```
//!
//! ## Interpreting the numbers
//!
//! Run `federation_crypto` first to get the ciris-crypto baseline,
//! then run this bench. Take the ratio `liboqs_time / ciris_crypto_time`
//! to see the SIMD optimization headroom. For ML-KEM-768, the CEG
//! 0.15 streaming-feasibility model expects ~30µs/encaps for liboqs
//! AVX2; if our pure-Rust path is ~63µs (per Phase 1), the gap is
//! ~2.1×. That's the cost of `ml-kem` being a portable
//! constant-time-Rust implementation that doesn't yet auto-vectorize.
//!
//! ## Algorithm coverage
//!
//! - `liboqs_ml_kem_768_keygen` / `encapsulate` / `decapsulate`
//! - `liboqs_ml_dsa_65_keygen` / `sign` / `verify`
//!
//! Hybrid X25519 + ML-KEM-768 KEX is NOT in liboqs — that's CIRIS's
//! own protocol layer above the KEM primitive, so there's nothing to
//! cross-check against. The ML-KEM-768 result extrapolates to the
//! KEX-internal encaps cost (the X25519 + HKDF overhead stays the
//! same on the AVX2 path; only the KEM call gets faster).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use oqs::{kem, sig};

/// ML-KEM-768 benches — keygen, encaps, decaps — against liboqs.
fn bench_liboqs_ml_kem(c: &mut Criterion) {
    oqs::init();
    let kemalg = kem::Kem::new(kem::Algorithm::MlKem768).expect("ml-kem-768 not in this liboqs");

    // Pre-generate a recipient keypair + ciphertext for the per-op
    // benches so each bench measures the primitive, not the setup.
    let (recipient_pk, recipient_sk) = kemalg.keypair().expect("liboqs keygen");
    let (ciphertext, _shared) = kemalg
        .encapsulate(&recipient_pk)
        .expect("liboqs encapsulate");

    let mut group = c.benchmark_group("liboqs_comparison");
    group.bench_function("liboqs_ml_kem_768_keygen", |b| {
        b.iter(|| kemalg.keypair().expect("keygen"));
    });
    group.bench_function("liboqs_ml_kem_768_encapsulate", |b| {
        b.iter(|| {
            kemalg
                .encapsulate(black_box(&recipient_pk))
                .expect("encaps")
        });
    });
    group.bench_function("liboqs_ml_kem_768_decapsulate", |b| {
        b.iter(|| {
            kemalg
                .decapsulate(black_box(&recipient_sk), black_box(&ciphertext))
                .expect("decaps")
        });
    });
    group.finish();
}

/// ML-DSA-65 benches — keygen, sign, verify — against liboqs.
fn bench_liboqs_ml_dsa(c: &mut Criterion) {
    oqs::init();
    let sigalg = sig::Sig::new(sig::Algorithm::MlDsa65).expect("ml-dsa-65 not in this liboqs");

    let (signer_pk, signer_sk) = sigalg.keypair().expect("liboqs keygen");
    let message = b"ciris-federation-canonical-message-payload";
    let signature = sigalg.sign(message, &signer_sk).expect("liboqs sign");

    let mut group = c.benchmark_group("liboqs_comparison");
    group.bench_function("liboqs_ml_dsa_65_keygen", |b| {
        b.iter(|| sigalg.keypair().expect("keygen"));
    });
    group.bench_function("liboqs_ml_dsa_65_sign", |b| {
        b.iter(|| {
            sigalg
                .sign(black_box(message), black_box(&signer_sk))
                .expect("sign")
        });
    });
    group.bench_function("liboqs_ml_dsa_65_verify", |b| {
        b.iter(|| {
            sigalg
                .verify(
                    black_box(message),
                    black_box(&signature),
                    black_box(&signer_pk),
                )
                .expect("verify")
        });
    });
    group.finish();
}

criterion_group!(benches, bench_liboqs_ml_kem, bench_liboqs_ml_dsa);
criterion_main!(benches);
