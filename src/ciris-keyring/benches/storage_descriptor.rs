//! Benchmarks for `HardwareSigner::storage_descriptor()` and the
//! associated helper methods.
//!
//! This is a hot-path call — agents may invoke `storage_descriptor()`
//! at every boot and on every `/health` check. Establishing the
//! baseline ensures future signer impls don't accidentally introduce
//! disk I/O or syscalls behind the trait method.

use std::path::PathBuf;

use ciris_keyring::{HardwareType, KeyringScope, StorageDescriptor};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_construct_each_variant(c: &mut Criterion) {
    let mut group = c.benchmark_group("StorageDescriptor::construct");

    group.bench_function("hardware_with_blob_path", |b| {
        b.iter(|| {
            black_box(StorageDescriptor::Hardware {
                hardware_type: black_box(HardwareType::TpmFirmware),
                blob_path: Some(black_box(PathBuf::from(
                    "/var/lib/ciris-verify/agent.ed25519.tpm",
                ))),
            })
        });
    });

    group.bench_function("hardware_without_blob_path", |b| {
        b.iter(|| {
            black_box(StorageDescriptor::Hardware {
                hardware_type: black_box(HardwareType::IosSecureEnclave),
                blob_path: None,
            })
        });
    });

    group.bench_function("software_file", |b| {
        b.iter(|| {
            black_box(StorageDescriptor::SoftwareFile {
                path: black_box(PathBuf::from(
                    "/home/user/.local/share/ciris-verify/agent.p256.key",
                )),
            })
        });
    });

    group.bench_function("software_os_keyring", |b| {
        b.iter(|| {
            black_box(StorageDescriptor::SoftwareOsKeyring {
                backend: black_box("secret-service".to_string()),
                scope: black_box(KeyringScope::Unknown),
            })
        });
    });

    group.bench_function("in_memory", |b| {
        b.iter(|| black_box(StorageDescriptor::InMemory));
    });

    group.finish();
}

fn bench_helpers(c: &mut Criterion) {
    let mut group = c.benchmark_group("StorageDescriptor::helpers");

    let descriptors = [
        StorageDescriptor::Hardware {
            hardware_type: HardwareType::TpmFirmware,
            blob_path: Some(PathBuf::from("/var/lib/ciris/key.tpm")),
        },
        StorageDescriptor::SoftwareFile {
            path: PathBuf::from("/home/u/.local/share/ciris/agent.p256.key"),
        },
        StorageDescriptor::SoftwareOsKeyring {
            backend: "keychain".to_string(),
            scope: KeyringScope::System,
        },
        StorageDescriptor::InMemory,
    ];

    group.bench_function("is_hardware_backed", |b| {
        b.iter(|| {
            for d in &descriptors {
                black_box(d.is_hardware_backed());
            }
        });
    });

    group.bench_function("disk_path", |b| {
        b.iter(|| {
            for d in &descriptors {
                black_box(d.disk_path());
            }
        });
    });

    group.bench_function("hardware_type", |b| {
        b.iter(|| {
            for d in &descriptors {
                black_box(d.hardware_type());
            }
        });
    });

    group.finish();
}

fn bench_serde(c: &mut Criterion) {
    let mut group = c.benchmark_group("StorageDescriptor::serde");

    let hw = StorageDescriptor::Hardware {
        hardware_type: HardwareType::TpmFirmware,
        blob_path: Some(PathBuf::from("/var/lib/ciris/key.tpm")),
    };
    let sw = StorageDescriptor::SoftwareFile {
        path: PathBuf::from("/home/u/.local/share/ciris/agent.p256.key"),
    };

    group.bench_function("serialize_hardware", |b| {
        b.iter(|| black_box(serde_json::to_vec(black_box(&hw)).unwrap()));
    });

    group.bench_function("serialize_software_file", |b| {
        b.iter(|| black_box(serde_json::to_vec(black_box(&sw)).unwrap()));
    });

    let hw_json = serde_json::to_vec(&hw).unwrap();
    group.bench_function("deserialize_hardware", |b| {
        b.iter(|| {
            let _: StorageDescriptor = black_box(serde_json::from_slice(&hw_json).unwrap());
        });
    });

    let sw_json = serde_json::to_vec(&sw).unwrap();
    group.bench_function("deserialize_software_file", |b| {
        b.iter(|| {
            let _: StorageDescriptor = black_box(serde_json::from_slice(&sw_json).unwrap());
        });
    });

    group.finish();
}

fn bench_software_signer_descriptor(c: &mut Criterion) {
    use ciris_keyring::{HardwareSigner, SoftwareSigner};
    let key_dir = std::env::temp_dir().join("ciris_bench_storage_descriptor");
    let _ = std::fs::create_dir_all(&key_dir);

    let signer = SoftwareSigner::new("bench_descriptor", key_dir.clone()).unwrap();

    c.bench_function("SoftwareSigner::storage_descriptor", |b| {
        b.iter(|| black_box(signer.storage_descriptor()));
    });

    let _ = std::fs::remove_dir_all(&key_dir);
}

criterion_group!(
    benches,
    bench_construct_each_variant,
    bench_helpers,
    bench_serde,
    bench_software_signer_descriptor
);
criterion_main!(benches);
