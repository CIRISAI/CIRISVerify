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

    // Signer path (ABI v2): the symbols are present (the built plugin is v2), so
    // the client reports the signer is supported — but with no TPM the ops fail
    // cleanly rather than panicking or fabricating a key/signature.
    assert!(
        plugin.signer_supported(),
        "v2 plugin must expose the signer path"
    );
    assert!(plugin.signer_create().is_err(), "stub signer_create errors");
    assert!(
        plugin.signer_public(b"blob").is_err(),
        "stub signer_public errors"
    );
    assert!(
        plugin.signer_sign(b"blob", b"data").is_err(),
        "stub signer_sign errors"
    );
}

/// Hardware validation of the ABI-v2 signer path (#141) against a **real** TPM.
///
/// `#[ignore]`d so it never runs in normal `cargo test` / CI (which load the
/// stub and have no TPM). To run on a box with a TPM:
///
/// ```text
/// cargo build -p ciris-tpm-plugin --features real
/// CIRIS_TPM_PLUGIN=target/debug/libciris_tpm_plugin.so \
///   cargo test -p ciris-keyring --features tpm-plugin \
///   --test tpm_plugin_load -- --ignored --nocapture
/// ```
///
/// Proves the create → public → sign port round-trips end-to-end: the TPM-held
/// key signs and the signature verifies under the exported SEC1 public key.
#[test]
#[ignore = "requires a real TPM + the `real` plugin via CIRIS_TPM_PLUGIN"]
fn signer_roundtrip_verifies_on_real_tpm() {
    use p256::ecdsa::signature::Verifier;

    let path = std::env::var_os("CIRIS_TPM_PLUGIN")
        .or_else(|| built_plugin().map(Into::into))
        .expect("set CIRIS_TPM_PLUGIN to a `real` plugin .so");
    let plugin = TpmPlugin::load_from(&path).expect("plugin loads");
    if !plugin.available() {
        eprintln!("no usable TPM; skipping hardware roundtrip");
        return;
    }

    let key_blob = plugin.signer_create().expect("create signing key");
    let pubkey = plugin.signer_public(&key_blob).expect("read public key");
    assert_eq!(pubkey.len(), 65, "SEC1 uncompressed P-256 key");
    assert_eq!(pubkey[0], 0x04, "uncompressed point marker");

    let message = b"ciris-tpm-plugin signer hardware validation #141";
    let sig_bytes = plugin.signer_sign(&key_blob, message).expect("sign");
    assert_eq!(sig_bytes.len(), 64, "raw r||s");

    let verifying_key =
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey).expect("valid SEC1 pubkey");
    let signature = p256::ecdsa::Signature::from_slice(&sig_bytes).expect("valid r||s");
    verifying_key
        .verify(message, &signature)
        .expect("TPM signature must verify under the exported public key");

    // A different message must NOT verify with the same signature.
    assert!(
        verifying_key.verify(b"tampered", &signature).is_err(),
        "signature must not verify for a different message"
    );
    eprintln!("✓ TPM signer roundtrip verified on real hardware");
}
