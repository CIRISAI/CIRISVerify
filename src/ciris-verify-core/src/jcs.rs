//! RFC 8785 JSON Canonicalization Scheme (JCS) — the cross-implementation
//! signing-bytes encoding for CEG federation Contributions
//! (CIRISVerify#59, gating CIRISPersist#172 OQ-4).
//!
//! ## Why this exists
//!
//! CEG 0.15 §0.9 is normative: *"A CEG-Conforming Producer MUST produce
//! signing bytes via JCS over the envelope object. A CEG-Conforming
//! Consumer MUST recompute signing bytes via the same JCS rule for
//! signature verification."* When CIRISPersist's `attestation_promote`
//! flips a `local` attestation to `federation` tier it hybrid-signs the
//! Contribution's canonical bytes, and **every** federation peer —
//! including CIRISVerify acting as a Conforming Consumer — must recompute
//! the *identical* bytes to verify.
//!
//! Those bytes are JCS (RFC 8785), **not** CIRISVerify's internal
//! length-prefixed binary framing. The crate's other signed units
//! ([`crate::federation_envelope`], [`crate::federation_keyset`],
//! [`crate::infrastructure_community`], [`crate::doc_integrity`]) use
//! `domain_sep · schema_version · LP(field)…` framing because they are
//! **verify-internal, verify-to-verify** primitives that never cross the
//! four-implementation boundary as JSON. A federation Contribution is the
//! opposite: a JSON object Agent / NodeCore / LensCore / Registry / Verify
//! all sign and verify, so it MUST use the JCS encoding CEG mandates.
//! Do not conflate the two framings.
//!
//! ## What JCS pins (RFC 8785 §3.2)
//!
//! - object members sorted by their UTF-16 code-unit sequence;
//! - numbers serialized via the ECMAScript `Number.prototype.toString`
//!   algorithm (RFC 8785 §3.2.2.3) — the notorious cross-implementation
//!   footgun; this module delegates it to the `ryu-js` backend rather
//!   than hand-rolling it;
//! - strings escaped per RFC 8259 §7 with the JCS narrowing (minimal
//!   escapes; `\uXXXX` lowercase for the residual control range);
//! - UTF-8 output, no insignificant whitespace.
//!
//! The behavior is locked here by RFC 8785 Appendix B known-answer
//! vectors (see `tests`), so swapping the backend can never silently
//! change the wire bytes.
//!
//! ## The §0.9 omit-vs-materialize discipline
//!
//! > Optional fields the producer **omits** MUST NOT be materialized
//! > into canonical bytes by any party; optional fields the producer
//! > explicitly **emits** (even at their default value) MUST be
//! > preserved. Documented defaults from §4 are interpretation-time
//! > semantics, not encoding-time content.
//!
//! This module canonicalizes the [`serde_json::Value`] it is given,
//! **literally** — it never injects a default, never drops a present
//! member. The discipline is therefore the caller's: parse the
//! as-received envelope into a `Value` (which preserves exactly the
//! members present) and pass it unmodified. Round-tripping through a
//! typed struct that materializes defaults would violate §0.9 and break
//! cross-implementation verification — pass the `Value`, not a
//! re-defaulted projection.
//!
//! ## Signature placement (coordination point with CIRISRegistry)
//!
//! A Contribution cannot sign an object that contains its own signature.
//! The *signed object* is therefore the envelope members **minus** the
//! signature container, and which members those are is **CEG's authority
//! (CIRISRegistry)**. [`verify_jcs_hybrid_signature`] takes the
//! already-stripped signed object — the caller (or a future CEG-schema-
//! aware wrapper) is responsible for producing it per the pinned CEG
//! Contribution member set. When Registry pins that set, a thin
//! `verify_contribution_signature` can wrap this with the stripping baked
//! in; until then this is the reusable mechanism.

#[allow(unused_imports)]
use crate::prelude::*;

use ciris_crypto::{Ed25519Verifier, HybridSignature, HybridVerifier, MlDsa65Verifier};
use serde_json::Value;

use crate::error::VerifyError;

/// Canonicalize a JSON value to its RFC 8785 (JCS) byte encoding.
///
/// The value is canonicalized **literally** — no member is added,
/// removed, or re-defaulted (the §0.9 omit-vs-materialize discipline is
/// the caller's; see the module docs). Two values that are equal as JSON
/// objects (same members, same numeric values) always produce identical
/// bytes regardless of input key order.
///
/// # Errors
///
/// [`VerifyError::IntegrityError`] if the value cannot be canonicalized
/// (e.g. a non-finite float, which JSON cannot represent).
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, VerifyError> {
    let mut out = Vec::with_capacity(128);
    write_value(value, &mut out)?;
    Ok(out)
}

// The encoder below is the one verify signs and verifies with, with and
// without `std` (CIRISVerify#325). It reproduces `serde_jcs` 0.2 byte for byte;
// `tests::matches_serde_jcs_*` hold it to that under `std`.
//
// - Numbers: every JSON number is an IEEE 754 double (RFC 8785 §3.2.2.3), so
//   an integer is converted to `f64` first and printed by the ECMAScript
//   algorithm (`ryu-js`, the formatter `serde_jcs` uses). Non-finite values
//   cannot occur in a `Value` but are refused anyway.
// - Strings: `"` and `\` escaped; U+0008, U+0009, U+000A, U+000C, U+000D as
//   `\b \t \n \f \r`; every other control character below U+0020 as
//   `\u00xx` with lowercase hex; everything else, `/` and non-ASCII included,
//   written as is (RFC 8785 §3.2.2.2).
// - Objects: members sorted by their names' UTF-16 code units (§3.2.3).

fn write_value(value: &Value, out: &mut Vec<u8>) -> Result<(), VerifyError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            #[allow(clippy::cast_precision_loss)]
            let f = if let Some(u) = n.as_u64() {
                u as f64
            } else if let Some(i) = n.as_i64() {
                i as f64
            } else {
                n.as_f64().unwrap_or(f64::NAN)
            };
            if !f.is_finite() {
                return Err(VerifyError::IntegrityError {
                    message: "JCS canonicalization failed: invalid float value".into(),
                });
            }
            let mut buf = ryu_js::Buffer::new();
            out.extend_from_slice(buf.format_finite(f).as_bytes());
        },
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        },
        Value::Object(map) => {
            let mut members: Vec<(Vec<u16>, &String, &Value)> = map
                .iter()
                .map(|(k, v)| (k.encode_utf16().collect(), k, v))
                .collect();
            members.sort_by(|a, b| a.0.cmp(&b.0));
            out.push(b'{');
            for (i, (_, k, v)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_value(v, out)?;
            }
            out.push(b'}');
        },
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    let bytes = s.as_bytes();
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let esc: &[u8] = match b {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            0x08 => b"\\b",
            0x09 => b"\\t",
            0x0A => b"\\n",
            0x0C => b"\\f",
            0x0D => b"\\r",
            0x00..=0x1F => &[],
            _ => continue,
        };
        out.extend_from_slice(&bytes[start..i]);
        if esc.is_empty() {
            out.extend_from_slice(&[
                b'\\',
                b'u',
                b'0',
                b'0',
                HEX[(b >> 4) as usize],
                HEX[(b & 0xF) as usize],
            ]);
        } else {
            out.extend_from_slice(esc);
        }
        start = i + 1;
    }
    out.extend_from_slice(&bytes[start..]);
    out.push(b'"');
}

/// Verify a detached hybrid (Ed25519 + ML-DSA-65) signature over the
/// JCS canonical bytes of `signed_object`.
///
/// `signed_object` MUST be the exact member set the producer signed —
/// i.e. the Contribution envelope **with its signature container already
/// stripped**, preserving §0.9 member presence (see module docs). This
/// function JCS-canonicalizes that object and runs the existing hybrid
/// verifier over the bytes.
///
/// Returns `Ok(true)` iff both signature halves verify; `Ok(false)` on a
/// clean signature mismatch. [`VerifyError`] only for a canonicalization
/// or crypto-layer failure (malformed signature material), never for a
/// plain "didn't verify".
pub fn verify_jcs_hybrid_signature(
    signed_object: &Value,
    signature: &HybridSignature,
    verifier: &HybridVerifier<Ed25519Verifier, MlDsa65Verifier>,
) -> Result<bool, VerifyError> {
    let bytes = canonicalize(signed_object)?;
    // The hybrid verifier returns Err on a clean classical/PQC mismatch;
    // map that to Ok(false) so a forged-or-wrong-key signature is a soft
    // "no", while genuinely malformed signature material is a hard error.
    // Same discipline as `doc_integrity::verify_document`.
    match verifier.verify(&bytes, signature) {
        Ok(valid) => Ok(valid),
        Err(
            ciris_crypto::CryptoError::ClassicalVerificationFailed { .. }
            | ciris_crypto::CryptoError::PqcVerificationFailed { .. },
        ) => Ok(false),
        Err(e) => Err(VerifyError::IntegrityError {
            message: format!("hybrid verify over JCS bytes failed: {e}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn jcs_str(v: &Value) -> String {
        String::from_utf8(canonicalize(v).unwrap()).unwrap()
    }

    // -------------------------------------------------------------------
    // RFC 8785 Appendix-B-class known-answer vectors. These lock the
    // wire bytes so the backend can never silently drift.
    // -------------------------------------------------------------------

    /// Object members are reordered into UTF-16 code-unit order, and the
    /// result is independent of input order.
    #[test]
    fn keys_sorted_and_order_independent() {
        let a = json!({"b": 2, "a": 1, "c": 3});
        let b = json!({"c": 3, "a": 1, "b": 2});
        assert_eq!(jcs_str(&a), r#"{"a":1,"b":2,"c":3}"#);
        assert_eq!(canonicalize(&a).unwrap(), canonicalize(&b).unwrap());
    }

    /// No insignificant whitespace; nested objects recurse.
    #[test]
    fn nested_no_whitespace() {
        let v = json!({"outer": {"y": 2, "x": 1}, "arr": [3, 2, 1]});
        // Array order is significant (NOT sorted); object keys are sorted.
        assert_eq!(jcs_str(&v), r#"{"arr":[3,2,1],"outer":{"x":1,"y":2}}"#);
    }

    /// Integer canonicalization — no decimal point, no exponent in the
    /// integer range.
    #[test]
    fn integers_canonical() {
        assert_eq!(jcs_str(&json!(0)), "0");
        assert_eq!(jcs_str(&json!(-0)), "0");
        assert_eq!(jcs_str(&json!(1)), "1");
        assert_eq!(jcs_str(&json!(-1)), "-1");
        assert_eq!(jcs_str(&json!(1000)), "1000");
        // 2^53 - 1, the max exactly-representable integer in an f64.
        assert_eq!(
            jcs_str(&json!(9_007_199_254_740_991i64)),
            "9007199254740991"
        );
    }

    /// Fractional canonicalization — shortest round-trippable form per
    /// the ECMAScript number algorithm (RFC 8785 §3.2.2.3). `score` /
    /// `confidence` in CEG attestations are f64, so this path is live.
    #[test]
    fn fractions_canonical() {
        assert_eq!(jcs_str(&json!(0.1)), "0.1");
        assert_eq!(jcs_str(&json!(0.5)), "0.5");
        assert_eq!(jcs_str(&json!(0.95)), "0.95");
        // The classic float that is NOT 0.3 in IEEE-754 — shortest form
        // that round-trips to the same f64.
        assert_eq!(jcs_str(&json!(0.1 + 0.2)), "0.30000000000000004");
    }

    /// Large/small magnitudes use the ECMAScript exponent rules — these
    /// are the RFC 8785 Appendix B cases that break naive impls.
    #[test]
    fn exponent_forms_canonical() {
        // 1e21 is the threshold where ECMAScript switches to exponent
        // form (numbers < 1e21 print in positional notation).
        assert_eq!(jcs_str(&json!(1e21)), "1e+21");
        // Just below the threshold: positional, all 21 digits.
        assert_eq!(jcs_str(&json!(1e20)), "100000000000000000000");
        // Smallest positive subnormal f64.
        assert_eq!(jcs_str(&json!(5e-324)), "5e-324");
    }

    /// String escaping per RFC 8259 §7 with the JCS narrowing: only the
    /// mandatory escapes; everything else literal UTF-8.
    #[test]
    fn string_escaping_minimal() {
        assert_eq!(jcs_str(&json!("plain")), r#""plain""#);
        assert_eq!(jcs_str(&json!("a\"b")), r#""a\"b""#);
        assert_eq!(jcs_str(&json!("a\\b")), r#""a\\b""#);
        assert_eq!(jcs_str(&json!("tab\there")), r#""tab\there""#);
        assert_eq!(jcs_str(&json!("nl\nhere")), r#""nl\nhere""#);
        // A control char with no short escape → lowercase \uXXXX.
        assert_eq!(jcs_str(&json!("\u{0001}")), r#""\u0001""#);
        // Non-ASCII is preserved as literal UTF-8, NOT \u-escaped.
        assert_eq!(jcs_str(&json!("café")), "\"café\"");
        assert_eq!(jcs_str(&json!("🔐")), "\"🔐\"");
    }

    /// Literals + empties.
    #[test]
    fn literals_and_empties() {
        assert_eq!(jcs_str(&json!(true)), "true");
        assert_eq!(jcs_str(&json!(false)), "false");
        assert_eq!(jcs_str(&json!(null)), "null");
        assert_eq!(jcs_str(&json!({})), "{}");
        assert_eq!(jcs_str(&json!([])), "[]");
    }

    /// Determinism: the same value always produces the same bytes.
    #[test]
    fn deterministic() {
        let v = json!({"z": [1, 2, {"k": "v"}], "a": 0.95, "m": null});
        assert_eq!(canonicalize(&v).unwrap(), canonicalize(&v).unwrap());
    }

    /// §0.9 omit-vs-materialize: an object with an optional field OMITTED
    /// canonicalizes to DIFFERENT bytes than the same object with that
    /// field materialized at its default. This is the property that makes
    /// the discipline load-bearing — a verifier MUST NOT inject the
    /// default, and this module never does.
    #[test]
    fn omit_vs_materialize_changes_bytes() {
        // Producer A omits `epistemic_mode` (relies on the §4 default
        // "direct"); Producer B emits it explicitly at that default.
        let omitted = json!({"dimension": "self_verify", "score": 1.0});
        let materialized =
            json!({"dimension": "self_verify", "score": 1.0, "epistemic_mode": "direct"});
        assert_ne!(
            canonicalize(&omitted).unwrap(),
            canonicalize(&materialized).unwrap(),
            "omitted vs materialized-default MUST produce distinct canonical bytes — \
             the §0.9 hazard. A verifier that re-defaults would break cross-impl verify."
        );
        // Both are still self-consistent (deterministic).
        assert_eq!(
            jcs_str(&omitted),
            r#"{"dimension":"self_verify","score":1}"#
        );
    }

    // -------------------------------------------------------------------
    // Detached hybrid-signature verify over JCS bytes.
    // -------------------------------------------------------------------

    /// The hybrid signature self-describes its public keys, so a keyless
    /// [`HybridVerifier`] verifies "this signature is internally valid"
    /// (binding to a *trusted* key_id is the caller's separate check) —
    /// the same pattern [`crate::doc_integrity`] uses.
    fn keyless_verifier() -> HybridVerifier<Ed25519Verifier, MlDsa65Verifier> {
        HybridVerifier::new(Ed25519Verifier::new(), MlDsa65Verifier::new())
    }

    #[test]
    fn sign_then_verify_jcs_round_trip() {
        use ciris_crypto::{Ed25519Signer, HybridSigner, MlDsa65Signer};

        let signer = HybridSigner::new(
            Ed25519Signer::random().unwrap(),
            MlDsa65Signer::new().unwrap(),
        )
        .unwrap();

        // A representative CEG-attestation-shaped signed object (already
        // stripped of its signature container).
        let signed_object = json!({
            "attestation_type": "scores",
            "witness_relation": "self",
            "dimension": "attestation:self_verify",
            "score": 0.95,
            "subject_key_ids": [],
            "valid_at": "2026-06-08T00:00:00.000Z"
        });

        // Producer signs the JCS bytes.
        let sig = signer.sign(&canonicalize(&signed_object).unwrap()).unwrap();
        let verifier = keyless_verifier();

        assert!(
            verify_jcs_hybrid_signature(&signed_object, &sig, &verifier).unwrap(),
            "signature over JCS bytes must verify"
        );

        // Reordering the input object's keys must NOT break verification
        // — JCS canonicalizes both to the same bytes.
        let reordered = json!({
            "valid_at": "2026-06-08T00:00:00.000Z",
            "score": 0.95,
            "witness_relation": "self",
            "subject_key_ids": [],
            "dimension": "attestation:self_verify",
            "attestation_type": "scores"
        });
        assert!(
            verify_jcs_hybrid_signature(&reordered, &sig, &verifier).unwrap(),
            "key reordering must not affect JCS verification"
        );
    }

    #[test]
    fn tampered_object_fails_verification() {
        use ciris_crypto::{Ed25519Signer, HybridSigner, MlDsa65Signer};

        let signer = HybridSigner::new(
            Ed25519Signer::random().unwrap(),
            MlDsa65Signer::new().unwrap(),
        )
        .unwrap();
        let verifier = keyless_verifier();

        let signed = json!({"dimension": "x", "score": 0.95});
        let sig = signer.sign(&canonicalize(&signed).unwrap()).unwrap();

        // One byte of semantic change (score 0.95 → 0.96) → different JCS
        // bytes → signature must NOT verify.
        let tampered = json!({"dimension": "x", "score": 0.96});
        assert!(
            !verify_jcs_hybrid_signature(&tampered, &sig, &verifier).unwrap(),
            "a semantic edit changes the JCS bytes and must fail verification"
        );
    }

    // -------------------------------------------------------------------
    // The encoder against `serde_jcs` 0.2, the backend it replaced
    // (CIRISVerify#325). Equal bytes for every value is the contract: a
    // signature made before 23.0.0 must verify after it.
    // -------------------------------------------------------------------

    fn assert_matches_serde_jcs(v: &Value) {
        assert_eq!(
            canonicalize(v).unwrap(),
            serde_jcs::to_vec(v).unwrap(),
            "diverged from serde_jcs on {v}"
        );
    }

    #[test]
    fn matches_serde_jcs_on_edge_values() {
        let mut every_control = String::new();
        for c in 0u8..0x20 {
            every_control.push(char::from(c));
        }
        every_control.push_str("\u{7f}/\"\\\u{2028}\u{2029}\u{e9}\u{1f600}\u{fffd}");
        let cases = vec![
            json!(null),
            json!(true),
            json!(false),
            json!(0),
            json!(-0.0),
            json!(1),
            json!(-1),
            json!(u64::MAX),
            json!(i64::MIN),
            json!(9_007_199_254_740_993_u64),
            json!(1e21),
            json!(1e-7),
            json!(123_456_789.123_457),
            json!(5e-324),
            json!(f64::MAX),
            json!(0.1),
            json!(-1.5e300),
            json!(every_control),
            json!(""),
            json!([]),
            json!({}),
            json!({"\u{20ac}": 1, "\r": 2, "\u{1f600}": 3, "\u{fb33}": 4, "1": 5, "": 6, "a": [1, {"z": null, "y": [true]}]}),
            json!([[], [[]], {"": {}}]),
        ];
        for v in &cases {
            assert_matches_serde_jcs(v);
        }
    }

    fn arb_value() -> impl proptest::strategy::Strategy<Value = Value> {
        use proptest::prelude::*;
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<u64>().prop_map(|n| json!(n)),
            any::<i64>().prop_map(|n| json!(n)),
            any::<f64>()
                .prop_filter("finite", |f| f.is_finite())
                .prop_map(|f| json!(f)),
            any::<String>().prop_map(Value::String),
            "[\\x00-\\x20\"\\\\/a-z\\u{80}-\\u{10ffff}]{0,12}".prop_map(Value::String),
        ];
        leaf.prop_recursive(4, 64, 8, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
                proptest::collection::btree_map(any::<String>(), inner, 0..8)
                    .prop_map(|m| Value::Object(m.into_iter().collect())),
            ]
        })
    }

    proptest::proptest! {
        #[test]
        fn matches_serde_jcs_on_arbitrary_values(v in arb_value()) {
            assert_matches_serde_jcs(&v);
        }
    }
}
