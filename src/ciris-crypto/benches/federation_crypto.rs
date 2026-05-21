//! Federation crypto-authority benchmarks (CIRISVerify#7, v2.7.0).
//!
//! Measures the v2.0+ primitives the CIRIS federation centralizes in
//! `ciris-crypto` so consumers never reach into RustCrypto directly:
//! hybrid Ed25519 + ML-DSA-65 signing, AES-256-GCM, HKDF/PBKDF2, HMAC.
//!
//! Requires features `aes-gcm`, `kdf`, `hmac`, `pqc-ml-dsa` — see the
//! `required-features` note in `Cargo.toml`.
//!
//! What to read:
//!
//! * `federation_crypto/hybrid_sign` / `hybrid_verify` — the dual
//!   Ed25519 + ML-DSA-65 path. ML-DSA dominates; this is the cost of
//!   post-quantum coverage on every federation signature.
//! * `federation_crypto/aes_gcm_*` — symmetric AEAD seal/open.
//! * `federation_crypto/hkdf_sha256` — pure HKDF (no storage load,
//!   unlike `key_derivation` in ciris-verify-core).
//! * `federation_crypto/pbkdf2_*` — password-based KDF; cost scales
//!   linearly with the iteration count (benched at a fixed count).
//! * `federation_crypto/hmac_sha256` — MAC over a small message.

use ciris_crypto::{
    aes_gcm, hmac, kdf, Ed25519Signer, Ed25519Verifier, HybridSigner, HybridVerifier,
    MlDsa65Signer, MlDsa65Verifier,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

/// AEAD payload sizes: a small federation message and a 64 KiB blob.
const AEAD_SIZES: &[usize] = &[256, 65_536];

/// Fixed PBKDF2 iteration count for the bench. Production parameters are
/// the caller's policy; the per-iteration cost scales linearly, so one
/// count is enough to characterize it.
const PBKDF2_ITERS: u32 = 100_000;

fn bench_hybrid_sign(c: &mut Criterion) {
    let signer = HybridSigner::new(
        Ed25519Signer::random(),
        MlDsa65Signer::new().expect("ml-dsa signer"),
    )
    .expect("hybrid signer");
    let msg = b"ciris-federation-canonical-message-payload";

    let mut group = c.benchmark_group("federation_crypto");
    group.bench_function("hybrid_sign", |b| {
        b.iter(|| signer.sign(black_box(msg)).expect("sign"));
    });
    group.finish();
}

fn bench_hybrid_verify(c: &mut Criterion) {
    let signer = HybridSigner::new(
        Ed25519Signer::random(),
        MlDsa65Signer::new().expect("ml-dsa signer"),
    )
    .expect("hybrid signer");
    let msg = b"ciris-federation-canonical-message-payload";
    let sig = signer.sign(msg).expect("sign");
    let verifier = HybridVerifier::new(Ed25519Verifier::new(), MlDsa65Verifier::new());

    let mut group = c.benchmark_group("federation_crypto");
    group.bench_function("hybrid_verify", |b| {
        b.iter(|| {
            verifier
                .verify(black_box(msg), black_box(&sig))
                .expect("verify")
        });
    });
    group.finish();
}

fn bench_aes_gcm(c: &mut Criterion) {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];

    let mut group = c.benchmark_group("federation_crypto");
    for &size in AEAD_SIZES {
        let plaintext = vec![0x5Au8; size];
        let ciphertext = aes_gcm::encrypt(&key, &nonce, &plaintext).expect("encrypt");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::new("aes_gcm_encrypt", size), |b| {
            b.iter(|| aes_gcm::encrypt(black_box(&key), black_box(&nonce), black_box(&plaintext)));
        });
        group.bench_function(BenchmarkId::new("aes_gcm_decrypt", size), |b| {
            b.iter(|| aes_gcm::decrypt(black_box(&key), black_box(&nonce), black_box(&ciphertext)));
        });
    }
    group.finish();
}

fn bench_kdf(c: &mut Criterion) {
    let ikm = [0x33u8; 32];
    let salt = b"CIRIS-federation-bench-salt";
    let info = b"federation-context-v1";

    let mut group = c.benchmark_group("federation_crypto");
    group.bench_function("hkdf_sha256", |b| {
        b.iter(|| {
            kdf::hkdf_sha256(black_box(&ikm), black_box(salt), black_box(info), 32).expect("hkdf")
        });
    });
    group.bench_function(BenchmarkId::new("pbkdf2_hmac_sha256", PBKDF2_ITERS), |b| {
        b.iter(|| {
            kdf::pbkdf2_hmac_sha256(
                black_box(&ikm),
                black_box(salt),
                black_box(PBKDF2_ITERS),
                32,
            )
            .expect("pbkdf2")
        });
    });
    group.finish();
}

fn bench_hmac(c: &mut Criterion) {
    let key = [0x44u8; 32];
    let msg = b"ciris-federation-message-authentication-payload";

    let mut group = c.benchmark_group("federation_crypto");
    group.bench_function("hmac_sha256", |b| {
        b.iter(|| hmac::sha256(black_box(&key), black_box(msg)));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_hybrid_sign,
    bench_hybrid_verify,
    bench_aes_gcm,
    bench_kdf,
    bench_hmac,
);
criterion_main!(benches);
