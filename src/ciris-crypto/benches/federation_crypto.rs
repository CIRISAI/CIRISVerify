//! Federation crypto-authority benchmarks (CIRISVerify#7, v2.7.0;
//! ML-KEM-768 / hybrid_kex / key_grant added v4.8.x for CIRISVerify#53).
//!
//! Measures the v2.0+ primitives the CIRIS federation centralizes in
//! `ciris-crypto` so consumers never reach into RustCrypto directly:
//! hybrid Ed25519 + ML-DSA-65 signing, ML-KEM-768 KEM, hybrid X25519 +
//! ML-KEM-768 KEX, AES-256-GCM AEAD, HPKE-shape DEK wrap (key_grant),
//! HKDF / PBKDF2 / HMAC.
//!
//! Requires features `aes-gcm`, `kdf`, `hmac`, `pqc-ml-dsa`, `ml-kem`,
//! `hybrid-kex`, `key-grant`, `x25519` — see the `required-features`
//! note in `Cargo.toml`. The PQC, hybrid_kex, and key_grant groups
//! were added in CIRISVerify v4.8.x for #53 (cross-check against
//! liboqs AVX2 and OpenMLS TreeKEM rekey targets).
//!
//! What to read:
//!
//! * `federation_crypto/hybrid_sign` / `hybrid_verify` — the dual
//!   Ed25519 + ML-DSA-65 path. ML-DSA dominates; this is the cost of
//!   post-quantum coverage on every federation signature.
//! * `federation_crypto/ml_kem_*` — ML-KEM-768 (FIPS 203 final)
//!   keygen / encaps / decaps. Sanity vs CEG model: encaps ~30µs.
//! * `federation_crypto/hybrid_kex_*` — full 2-party hybrid X25519 +
//!   ML-KEM-768 handshake. Initiate (ephemeral X25519 + encaps + HKDF
//!   binding) + respond (X25519 DH + decaps + HKDF re-derive).
//! * `federation_crypto/classical_kex_*` — X25519-only fallback (no
//!   ML-KEM). Delta vs `hybrid_kex_*` is the cost of PQ coverage on
//!   one handshake.
//! * `federation_crypto/key_grant_*` — HPKE-RFC-9180-base-mode-shaped
//!   DEK wrap/unwrap (X25519 ECDH → HKDF wrap key → AES-256-GCM seal).
//!   Comparison point for OpenMLS TreeKEM path-update.
//! * `federation_crypto/aes_gcm_*` — symmetric AEAD seal/open.
//! * `federation_crypto/hkdf_sha256` — pure HKDF.
//! * `federation_crypto/pbkdf2_*` — password-based KDF (linear in
//!   iteration count; benched at fixed count).
//! * `federation_crypto/hmac_sha256` — MAC over a small message.

use ciris_crypto::{
    aes_gcm, hmac, hybrid_kex, kdf, key_grant, ml_kem, x25519, Ed25519Signer, Ed25519Verifier,
    HybridSigner, HybridVerifier, MlDsa65Signer, MlDsa65Verifier,
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
        Ed25519Signer::random().unwrap().expect("ed25519 signer"),
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
        Ed25519Signer::random().unwrap().expect("ed25519 signer"),
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

fn bench_ml_kem(c: &mut Criterion) {
    // Pre-generate one keypair so encaps / decaps benches don't fold
    // keygen cost into their measurement.
    let (recipient_sk, recipient_pk) = ml_kem::generate_keypair().expect("ml-kem keygen");
    let (ciphertext, _shared_secret) =
        ml_kem::encapsulate(&recipient_pk).expect("ml-kem encapsulate");

    let mut group = c.benchmark_group("federation_crypto");
    group.bench_function("ml_kem_768_keygen", |b| {
        b.iter(|| ml_kem::generate_keypair().expect("keygen"));
    });
    group.bench_function("ml_kem_768_encapsulate", |b| {
        b.iter(|| ml_kem::encapsulate(black_box(&recipient_pk)).expect("encaps"));
    });
    group.bench_function("ml_kem_768_decapsulate", |b| {
        b.iter(|| {
            ml_kem::decapsulate(black_box(&recipient_sk), black_box(&ciphertext)).expect("decaps")
        });
    });
    group.finish();
}

fn bench_hybrid_kex(c: &mut Criterion) {
    // Pre-generate recipient long-term material (X25519 + ML-KEM-768).
    let (recipient_x_sk, recipient_x_pk) =
        x25519::generate_ephemeral_keypair().expect("x25519 keygen");
    let (recipient_mlkem_sk, recipient_mlkem_pk) =
        ml_kem::generate_keypair().expect("ml-kem keygen");

    // Pre-build a handshake message for the respond-side bench.
    let (handshake_msg, _initiator_session_key) =
        hybrid_kex::initiate_hybrid(&recipient_x_pk, &recipient_mlkem_pk).expect("initiate hybrid");

    let mut group = c.benchmark_group("federation_crypto");
    group.bench_function("hybrid_kex_initiate", |b| {
        b.iter(|| {
            hybrid_kex::initiate_hybrid(black_box(&recipient_x_pk), black_box(&recipient_mlkem_pk))
                .expect("initiate")
        });
    });
    group.bench_function("hybrid_kex_respond", |b| {
        b.iter(|| {
            hybrid_kex::respond_hybrid_with_public(
                black_box(&recipient_x_sk),
                black_box(&recipient_mlkem_sk),
                black_box(&recipient_mlkem_pk),
                black_box(&handshake_msg),
            )
            .expect("respond")
        });
    });
    group.finish();
}

fn bench_classical_kex(c: &mut Criterion) {
    // X25519-only fallback path. The delta vs `hybrid_kex_*` is the
    // cost of PQ coverage on one handshake.
    let (recipient_x_sk, recipient_x_pk) =
        x25519::generate_ephemeral_keypair().expect("x25519 keygen");
    let (classical_msg, _initiator_session_key) =
        hybrid_kex::initiate_classical(&recipient_x_pk).expect("initiate classical");

    let mut group = c.benchmark_group("federation_crypto");
    group.bench_function("classical_kex_initiate", |b| {
        b.iter(|| {
            hybrid_kex::initiate_classical(black_box(&recipient_x_pk)).expect("initiate classical")
        });
    });
    group.bench_function("classical_kex_respond", |b| {
        b.iter(|| {
            hybrid_kex::respond_classical(black_box(&recipient_x_sk), black_box(&classical_msg))
                .expect("respond classical")
        });
    });
    group.finish();
}

fn bench_key_grant(c: &mut Criterion) {
    // HPKE-RFC-9180-base-mode-shaped DEK wrap/unwrap. Comparison point
    // for OpenMLS TreeKEM path-update (one rekey edge).
    let (recipient_sk, recipient_pk) = x25519::generate_ephemeral_keypair().expect("x25519 keygen");
    let dek = [0x7Au8; 32];
    let wrap = key_grant::wrap_dek_for_recipient(&recipient_pk, &dek).expect("wrap");

    let mut group = c.benchmark_group("federation_crypto");
    group.bench_function("key_grant_wrap", |b| {
        b.iter(|| {
            key_grant::wrap_dek_for_recipient(black_box(&recipient_pk), black_box(&dek))
                .expect("wrap")
        });
    });
    group.bench_function("key_grant_unwrap", |b| {
        b.iter(|| {
            key_grant::unwrap_dek(black_box(&recipient_sk), black_box(&wrap)).expect("unwrap")
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_hybrid_sign,
    bench_hybrid_verify,
    bench_ml_kem,
    bench_hybrid_kex,
    bench_classical_kex,
    bench_key_grant,
    bench_aes_gcm,
    bench_kdf,
    bench_hmac,
);
criterion_main!(benches);
