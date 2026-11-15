//! Build the smoke node for wasm32-unknown-unknown and gate it. Ignored by
//! default (it runs a nested cargo build and needs the wasm32 target):
//! `cargo test -p ciris-host-abi --test smoke_wasm -- --ignored`.

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
    let modules: std::collections::BTreeSet<_> =
        report.imports.iter().map(|i| i.module.as_str()).collect();
    assert!(modules.contains("ciris:node/random@0.1.0"));
}
