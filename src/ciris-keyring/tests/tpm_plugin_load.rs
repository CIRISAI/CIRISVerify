//! End-to-end load of the real `ciris-tpm-plugin` cdylib (CIRISVerify#130,
//! stage 3). Builds the plugin, points `CIRIS_TPM_PLUGIN` at the built `.so`,
//! and proves the keyring's dlopen client completes the ABI handshake. The stub
//! (default-feature) plugin reports TPM unavailable, so we assert the contract,
//! not a real seal — the `real` backend is hardware-gated.
//!
//! Skips gracefully if the plugin artifact isn't built (e.g. a `--lib`-only run).

#![cfg(feature = "tpm-plugin")]

use std::path::PathBuf;

use ciris_keyring::tpm_plugin::TpmPlugin;

/// Locate the sibling-built plugin cdylib in the same target profile dir.
fn built_plugin() -> Option<PathBuf> {
    // This integration test binary lives in target/<profile>/deps/; the plugin
    // cdylib is one level up in target/<profile>/.
    let exe = std::env::current_exe().ok()?;
    let deps = exe.parent()?; // .../deps
    let profile = deps.parent()?; // .../<profile>
    let name = if cfg!(target_os = "windows") {
        "ciris_tpm_plugin.dll"
    } else if cfg!(target_os = "macos") {
        "libciris_tpm_plugin.dylib"
    } else {
        "libciris_tpm_plugin.so"
    };
    let p = profile.join(name);
    p.exists().then_some(p)
}

#[test]
fn loads_real_plugin_and_completes_abi_handshake() {
    let Some(path) = built_plugin() else {
        eprintln!("ciris-tpm-plugin not built alongside; skipping load test");
        return;
    };
    let plugin =
        TpmPlugin::load_from(&path).expect("real plugin must load + pass the ABI version check");
    // Stub backend → no TPM device; the contract is "answers honestly", and a
    // seal attempt fails cleanly rather than panicking.
    assert!(!plugin.available(), "stub plugin reports no TPM");
    assert!(
        plugin.seal(b"seed").is_err(),
        "stub seal must error, not succeed or panic"
    );
}
