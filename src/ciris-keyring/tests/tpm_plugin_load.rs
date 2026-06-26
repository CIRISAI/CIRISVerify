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

    // Quote path (ABI v3): symbols present (v3 plugin), ops fail cleanly w/o a TPM.
    assert!(
        plugin.quote_supported(),
        "v3 plugin must expose the quote path"
    );
    assert!(plugin.ak_create().is_err(), "stub ak_create errors");
    assert!(plugin.quote(b"ak", b"nonce").is_err(), "stub quote errors");
    assert!(
        plugin.ek_certificate().is_err(),
        "stub ek_certificate errors"
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

/// Hardware validation of `PluginTpmSigner` (the `HardwareSigner` wrapper, #141
/// stage B): the full open → public_key → sign → verify path, plus the #134
/// re-open discipline (a second `open` of the same alias loads the persisted
/// blob and reproduces the SAME key — it does not mint a fresh one).
///
/// `#[ignore]`d; run as in [`signer_roundtrip_verifies_on_real_tpm`].
#[tokio::test]
#[ignore = "requires a real TPM + the `real` plugin via CIRIS_TPM_PLUGIN"]
async fn plugin_tpm_signer_persists_and_reopens_on_real_tpm() {
    use ciris_keyring::platform::PluginTpmSigner;
    use ciris_keyring::HardwareSigner;
    use p256::ecdsa::signature::Verifier;

    // The factory loads the plugin by name; the hardware test points at the real
    // one via CIRIS_TPM_PLUGIN, which PluginTpmSigner::open honors through the
    // client's plugin_path(). Skip if it can't reach a TPM.
    if std::env::var_os("CIRIS_TPM_PLUGIN").is_none() {
        if let Some(p) = built_plugin() {
            std::env::set_var("CIRIS_TPM_PLUGIN", p);
        }
    }

    let dir = std::env::temp_dir().join(format!("ciris-plugsigner-hw-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let signer = match PluginTpmSigner::open("fed-ecdsa", &dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("no usable TPM signer ({e}); skipping");
            return;
        },
    };

    let pubkey = signer.public_key().await.expect("public_key");
    assert_eq!(pubkey.len(), 65);
    let message = b"PluginTpmSigner stage-B hardware validation";
    let sig = signer.sign(message).await.expect("sign");

    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey).unwrap();
    let signature = p256::ecdsa::Signature::from_slice(&sig).unwrap();
    vk.verify(message, &signature).expect("signature verifies");

    // Re-open the SAME alias: must load the persisted blob and reproduce the same
    // public key (no silent re-mint, #134) — and still sign verifiably.
    drop(signer);
    let reopened = PluginTpmSigner::open("fed-ecdsa", &dir).expect("re-open");
    let pubkey2 = reopened.public_key().await.expect("public_key 2");
    assert_eq!(
        pubkey, pubkey2,
        "re-open must reproduce the same key (#134)"
    );
    let sig2 = reopened.sign(message).await.expect("sign 2");
    vk.verify(message, &p256::ecdsa::Signature::from_slice(&sig2).unwrap())
        .expect("re-opened signer signs verifiably under the same key");

    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("✓ PluginTpmSigner persist + re-open verified on real hardware");
}

/// Hardware validation of the ABI-v3 quote path (#141 stage C) against a real
/// TPM: create a restricted AK, quote PCRs 0-7 bound to a nonce, and confirm the
/// quote signature verifies under the AK's exported public key. `#[ignore]`d.
#[test]
#[ignore = "requires a real TPM + the `real` plugin via CIRIS_TPM_PLUGIN"]
fn quote_verifies_under_ak_pubkey_on_real_tpm() {
    use p256::ecdsa::signature::Verifier;

    let path = std::env::var_os("CIRIS_TPM_PLUGIN")
        .or_else(|| built_plugin().map(Into::into))
        .expect("set CIRIS_TPM_PLUGIN to a `real` plugin .so");
    let plugin = TpmPlugin::load_from(&path).expect("plugin loads");
    if !plugin.available() {
        eprintln!("no usable TPM; skipping quote validation");
        return;
    }

    let ak_blob = plugin.ak_create().expect("create AK");
    let nonce = [0x5au8; 32];
    let q = plugin.quote(&ak_blob, &nonce).expect("quote");

    assert_eq!(q.ak_public_key.len(), 65, "SEC1 AK pubkey");
    assert!(!q.quoted.is_empty(), "TPMS_ATTEST present");
    assert_eq!(q.signature.len(), 64, "raw r||s");
    assert_eq!(q.pcr_selection, vec![0xFF], "PCRs 0-7 selected");

    // The TPM signs SHA-256(TPMS_ATTEST) with the restricted AK. p256's
    // `verify(msg, sig)` hashes the message with SHA-256, so verifying over the
    // marshalled `quoted` is the right check.
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&q.ak_public_key).expect("AK pubkey");
    let sig = p256::ecdsa::Signature::from_slice(&q.signature).expect("r||s");
    vk.verify(&q.quoted, &sig)
        .expect("quote signature must verify under the AK public key");

    eprintln!("✓ TPM quote verified under the AK public key on real hardware");
}
