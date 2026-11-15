//! Build the smoke node for wasm32-unknown-unknown and gate it. Ignored by
//! default (it runs a nested cargo build and needs the wasm32 target):
//! `cargo test -p ciris-host-abi --test smoke_wasm -- --ignored`.
//!
//! The second test builds `ciris-rt`'s smoke node (spawn + sleep + random
//! over the runtime): it lives here because the gate is native-only and
//! `ciris-rt` may not branch on target.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

use ciris_host_abi::gate::Allowlist;

#[test]
#[ignore = "nested cargo build for wasm32-unknown-unknown"]
fn smoke_module_imports_only_ciris_node() {
    let target_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/smoke-wasm");
    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "-p",
            "ciris-host-abi",
            "--example",
            "smoke-node",
            "--target",
            "wasm32-unknown-unknown",
            "--release",
            "--features",
            "getrandom-backend",
        ])
        .arg("--target-dir")
        .arg(&target_dir)
        .env(
            "CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS",
            r#"--cfg getrandom_backend="custom""#,
        )
        .status()
        .expect("cargo runs");
    assert!(status.success());
    let wasm =
        std::fs::read(target_dir.join("wasm32-unknown-unknown/release/examples/smoke_node.wasm"))
            .unwrap();
    let report = Allowlist::from_wit_str(ciris_host_abi::WIT, "node")
        .unwrap()
        .gate(&wasm)
        .unwrap();
    assert!(report.passed(), "{:?}", report.offenders);
    let modules: BTreeSet<_> = report.imports.iter().map(|i| i.module.as_str()).collect();
    assert!(modules.contains("ciris:node/random@0.1.0"));
}

#[test]
#[ignore = "nested cargo build for wasm32-unknown-unknown"]
fn rt_smoke_module_imports_only_ciris_node() {
    let target_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/rt-smoke-wasm");
    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "-p",
            "ciris-rt",
            "--example",
            "rt-smoke-node",
            "--target",
            "wasm32-unknown-unknown",
            "--release",
            "--no-default-features",
        ])
        .arg("--target-dir")
        .arg(&target_dir)
        .status()
        .expect("cargo runs");
    assert!(status.success());
    let wasm = std::fs::read(
        target_dir.join("wasm32-unknown-unknown/release/examples/rt_smoke_node.wasm"),
    )
    .unwrap();
    let report = Allowlist::from_wit_str(ciris_host_abi::WIT, "node")
        .unwrap()
        .gate(&wasm)
        .unwrap();
    assert!(report.passed(), "{:?}", report.offenders);
    let imports: BTreeSet<String> = report
        .imports
        .iter()
        .map(|i| format!("{}#{}", i.module, i.field))
        .collect();
    assert_eq!(
        imports,
        [
            "ciris:node/clock@0.1.0#monotonic-us",
            "ciris:node/log@0.1.0#metric",
            "ciris:node/log@0.1.0#record",
            "ciris:node/random@0.1.0#fill",
            "ciris:node/seal@0.1.0#take",
            "ciris:node/wake@0.1.0#next-deadline",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
}
