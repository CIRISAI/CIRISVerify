//! Compile-check for the Android attestation example in `README.md`.
//!
//! This exists so the README cannot rot. The snippet was first written with
//! its arguments in the wrong order and this guard caught it — which is the
//! whole argument for keeping it. Change the README example, change this too.

use ciris_verify_core::device_attestation::verify_android_key_attestation_with_store;
use ciris_verify_core::trust_anchor_store::baked;

fn main() {
    let leaf_der: &[u8] = &[];
    let intermediates: Vec<&[u8]> = Vec::new();
    let expected_pubkey: Vec<u8> = Vec::new();
    let challenge: &[u8] = b"";

    // `Ok(None)` = no anchor for that class = no hardware evidence.
    // That is a measurement, NOT a refusal.
    let _verdict = verify_android_key_attestation_with_store(
        &baked::default_store(),
        leaf_der,
        &intermediates,
        &expected_pubkey,
        challenge,
    );
}
