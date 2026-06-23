//! Accord-holder **custody attestation** — the hardware-unforgeable evidence the
//! CIRISServer admission gate verifies before admitting an accord holder
//! (CIRISVerify#91; the CIRISServer#41 safe-mesh floor).
//!
//! The accord kill-switch is only as trustworthy as the custody of its keys, so
//! a holder is admitted **only** with proof its signing key lives on a genuine
//! FIPS YubiKey under 2-factor (YubiKey + USB) custody — never a self-claim a
//! patched verify could forge. This is the **combined 2+3** design:
//!
//! - **(3) a separate signed CEG object** (`ACCORD_CUSTODY_ATTESTATION_KIND`),
//!   so the Persist `federation_keys` record stays byte-exact — the attestation
//!   is a sibling artifact, not a row field.
//! - **(2) carrying the YubiKey PIV slot-9c attestation certificate** — signed
//!   *inside* the YubiKey by its slot-f9 attestation key, chaining to **Yubico's
//!   pinned PIV attestation root**. Unforgeable: only a real YubiKey produces a
//!   valid 9c attestation, and the cert's Yubico extensions
//!   (`1.3.6.1.4.1.41482.3.*`) carry firmware, FIPS status, touch policy, and
//!   on-device generation — so one artifact proves the whole floor.
//!
//! ## What the verifier proves
//!
//! 1. The bundle's bound-hybrid signature verifies against the holder's pinned
//!    pubkeys (the holder authored it).
//! 2. The 9c cert chains `9c → f9 → [intermediate(s)…] → ` the **pinned Yubico
//!    root** — a variable-length path (3 certs for the pre-fw-5.7 PKI, 4 for the
//!    2024-12 PKI), every link a real signature verification.
//! 3. The key the 9c cert *attests* equals the holder's federation Ed25519 key
//!    (the attestation is for *this* holder's signing key, not a borrowed one).
//! 4. The Yubico extensions show **FIPS-certified** (slot-f9 `.10`) **+
//!    touch=always** (slot-9c `.8`) → `hardware_class: YubiKey_5_FIPS`. Firmware
//!    (`.3`) is recorded, not floored.
//!
//! ## ✓ Confirmed against a real key (#91, 2026-06-20)
//!
//! Validated end-to-end against a physical **YubiKey 5 FIPS fw 5.7.4** (Ed25519
//! slot-9c key, touch=always) via `examples/validate_yubikey_attestation`:
//! `verify_yubikey_piv_attestation` ADMITTED with `fips_certified:true`,
//! `touch_always:true`, `firmware:5.7.4`. So the documented Yubico encodings hold
//! on real hardware: `.3` firmware and `.8` pin/touch are inner DER OCTET STRINGs
//! (`inner_octet_string` unwraps; the touch byte is read from the unwrapped
//! `[pin, touch]` — reading the wrapper length byte would false-accept a no-touch
//! key), `.10` FIPS rides the **f9** device cert, the attested key is a bare
//! 32-byte id-Ed25519 SPKI, and the **SHA256-RSA** chain verifies through
//! `x509_parser::verify_signature`.
//!
//! **PKI note (load-bearing for the pin):** Yubico's 2024-12 overhaul made the
//! chain 4 levels — `9c → f9 (CN=Yubico PIV Attestation) → CN=Yubico PIV
//! Attestation B 1 → CN=Yubico Attestation Root 1`. Pin the durable **root**
//! (`Yubico Attestation Root 1`, `developers.yubico.com/PKI/yubico-ca-1.pem`),
//! not the rotating `B 1` intermediate; the bundle carries `[f9, B 1]`. Pre-5.7
//! keys still verify with `[f9]` under the old `Yubico PIV Root CA Serial 263751`.

use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use x509_parser::der_parser::asn1_rs::FromDer;
use x509_parser::prelude::*;

use crate::ceg_outbox::SignedCegObject;
use crate::error::VerifyError;
use crate::jcs;
use crate::self_at_login::SelfSigner;
use crate::threshold::{verify_threshold_signatures, ThresholdMember, ThresholdSignature};
use ciris_keyring::{ExternalSecureElementAttestation, PlatformAttestation};

/// CEG `kind` of an accord-holder custody attestation in the outbox.
pub const ACCORD_CUSTODY_ATTESTATION_KIND: &str = "accord_holder_custody_attestation";

/// The custody tier asserted by the portable USB-wrapped mode (#91 / v6.6.0).
pub const CUSTODY_TIER_PORTABLE_2FA: &str = "portable_2fa";

// #113 — the attestation certs are signed by COMMITMENT, not inline. A YubiKey
// `CKM_EDDSA` is single-part with a bounded input; the old inline multi-KB hex
// chain overran it (`CKR_DATA_LEN_RANGE`). The signed envelope carries the
// sha256 of each cert; the cert DERs themselves ride in the (unsigned) outer
// `SignedCegObject.body` as hash-bound evidence the verifier recomputes.
/// Signed-envelope field: hex sha256 of the slot-9c attestation cert DER.
const COMMIT_9C_SHA256: &str = "yubikey_piv_attestation_9c_sha256";
/// Signed-envelope field: hex sha256 of each chain cert DER, leaf-first.
const COMMIT_CHAIN_SHA256: &str = "yubikey_attestation_chain_sha256";
/// Outer-body evidence field: the slot-9c attestation cert DER, hex.
const EVIDENCE_9C_HEX: &str = "yubikey_piv_attestation_9c_hex";
/// Outer-body evidence field: each chain cert DER, hex, leaf-first.
const EVIDENCE_CHAIN_HEX: &str = "yubikey_attestation_chain_hex";

/// Hex sha256 of `bytes` — the cert commitment encoding (#113).
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The custody tiers the verifier recognizes. A holder-signed bundle asserting
/// any other tier is rejected — the tier is an attested self-claim, so it must
/// be allowlisted rather than echoed verbatim to a tier-gating consumer.
const ALLOWED_CUSTODY_TIERS: &[&str] = &[CUSTODY_TIER_PORTABLE_2FA];

// Yubico PIV attestation extension OIDs (arc 1.3.6.1.4.1.41482.3.*).
const OID_YUBICO_FIRMWARE: &str = "1.3.6.1.4.1.41482.3.3";
const OID_YUBICO_SERIAL: &str = "1.3.6.1.4.1.41482.3.7";
const OID_YUBICO_PIN_TOUCH_POLICY: &str = "1.3.6.1.4.1.41482.3.8";
const OID_YUBICO_FIPS_CERTIFIED: &str = "1.3.6.1.4.1.41482.3.10";

/// Ed25519 SubjectPublicKeyInfo algorithm OID (id-Ed25519, RFC 8410).
const OID_ED25519: &str = "1.3.101.112";

/// Touch-policy byte (`…3.8` second byte) meaning "touch required for every use".
/// **Cross-confirm** against a real attestation (see module note).
const TOUCH_POLICY_ALWAYS: u8 = 0x02;

/// The verified custody facts of an accord holder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyVerdict {
    /// The §9.4 hardware_class established by the attestation.
    pub hardware_class: String,
    /// The custody tier from the bundle (`portable_2fa`, …).
    pub custody_tier: String,
    /// YubiKey firmware `major.minor.patch` from the `…3.3` extension.
    pub firmware: String,
    /// YubiKey serial from the `…3.7` extension, if present.
    pub serial: Option<u32>,
    /// Whether the FIPS-certified extension (`…3.10`) is present.
    pub fips_certified: bool,
    /// Whether the touch policy (`…3.8`) is "always".
    pub touch_always: bool,
}

/// Why a custody attestation was rejected (fail-closed — admit only on `Ok`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyError {
    /// Object is not an [`ACCORD_CUSTODY_ATTESTATION_KIND`].
    WrongKind {
        /// Kind found.
        kind: String,
    },
    /// A field is missing or ill-typed.
    Malformed {
        /// Which field.
        field: String,
    },
    /// The bundle's bound-hybrid signature did not verify against the holder.
    SignatureInvalid,
    /// A certificate (9c / f9 / root) could not be parsed.
    CertParse {
        /// Which cert.
        which: &'static str,
    },
    /// The attestation chain did not verify (9c → f9 → pinned Yubico root).
    ChainInvalid {
        /// Link that failed.
        detail: String,
    },
    /// The key the 9c cert attests is not the holder's federation Ed25519 key.
    AttestedKeyMismatch,
    /// The floor was not met (not FIPS, or touch not always, or firmware too old).
    FloorNotMet {
        /// Why.
        detail: String,
    },
}

impl std::fmt::Display for CustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongKind { kind } => write!(f, "not a custody attestation: kind {kind:?}"),
            Self::Malformed { field } => {
                write!(f, "malformed custody attestation: field {field:?}")
            },
            Self::SignatureInvalid => write!(f, "bundle hybrid signature did not verify"),
            Self::CertParse { which } => write!(f, "could not parse {which} certificate"),
            Self::ChainInvalid { detail } => write!(f, "attestation chain invalid: {detail}"),
            Self::AttestedKeyMismatch => {
                write!(
                    f,
                    "the attested key is not the holder's federation Ed25519 key"
                )
            },
            Self::FloorNotMet { detail } => write!(f, "custody floor not met: {detail}"),
        }
    }
}

impl std::error::Error for CustodyError {}

/// The canonical custody-attestation envelope. The holder hybrid-signs the JCS
/// bytes of this, binding their identity to the YubiKey attestation.
fn custody_envelope(
    holder_key_id: &str,
    ed25519_pubkey_b64: &str,
    mldsa65_pubkey_sha256: &str,
    attestation_9c_sha256: &str,
    attestation_chain_sha256: &[String],
    custody_tier: &str,
    signed_at: &str,
) -> Value {
    // Built as an explicit map so the #113 commitment field names can be the
    // shared consts (the json! macro only accepts literal keys). JCS sorts keys
    // at signing, so insertion order is immaterial to the signed bytes.
    let mut m = serde_json::Map::new();
    m.insert("holder_key_id".to_string(), json!(holder_key_id));
    m.insert(
        "ed25519_public_key_base64".to_string(),
        json!(ed25519_pubkey_b64),
    );
    // The ML-DSA-65 public key is 1952 B (~2604 b64 chars) — embedding it inline
    // blew the hardware-Ed25519 preimage past the YubiKey's PKCS#11 EdDSA input
    // ceiling once the (also-committed) cert chain grew. The verifier resolves the
    // holder's ML-DSA key out-of-band (the `holder_member`) and never reads this
    // field, so we COMMIT to its sha256 instead — same pattern as the cert hashes
    // (#113) — keeping the preimage small while preserving a tamper-evident binding.
    m.insert(
        "mldsa65_public_key_sha256".to_string(),
        json!(mldsa65_pubkey_sha256),
    );
    // #113: sign a COMMITMENT to the certs, not the certs. The slot-9c cert hash;
    // and the chain above the 9c leaf, leaf-first: sha256 of each of [f9,
    // …intermediates…] up to but excluding the pinned root (the verifier pins the
    // root out-of-band). The cert DERs themselves ride as hash-bound evidence in
    // the outer body — keeping the hardware-Ed25519 preimage small.
    m.insert(COMMIT_9C_SHA256.to_string(), json!(attestation_9c_sha256));
    m.insert(
        COMMIT_CHAIN_SHA256.to_string(),
        json!(attestation_chain_sha256),
    );
    m.insert("custody_tier".to_string(), json!(custody_tier));
    m.insert("signed_at".to_string(), json!(signed_at));
    Value::Object(m)
}

/// Produce a signed accord-holder custody attestation — the holder hybrid-signs
/// an envelope binding their identity + pubkeys to the YubiKey PIV attestation
/// chain. `attestation_9c_der` is the slot-9c attestation (e.g. from
/// `ykman piv keys attest 9c`); `attestation_chain_ders` is the path above it,
/// leaf-first — `[f9]` for the pre-fw-5.7 PKI, `[f9, "Yubico PIV Attestation B
/// 1"]` for the 2024-12 PKI — excluding the pinned root the verifier holds.
///
/// # Errors
///
/// [`VerifyError`] on a signer or canonicalization fault.
pub async fn produce_accord_custody_attestation(
    holder: &dyn SelfSigner,
    attestation_9c_der: &[u8],
    attestation_chain_ders: &[&[u8]],
    custody_tier: &str,
    signed_at: &str,
) -> Result<SignedCegObject, VerifyError> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let ed_pub = holder.ed25519_public_key().await?;
    let mldsa_pub = holder.mldsa65_public_key().await?;
    // #113: the holder signs a commitment (sha256 per cert), not the cert bytes.
    let chain_sha256: Vec<String> = attestation_chain_ders
        .iter()
        .map(|d| sha256_hex(d))
        .collect();
    let envelope = custody_envelope(
        holder.key_id(),
        &b64.encode(&ed_pub),
        &sha256_hex(&mldsa_pub),
        &sha256_hex(attestation_9c_der),
        &chain_sha256,
        custody_tier,
        signed_at,
    );
    let signed = holder.sign_envelope_async(envelope).await?;
    let mut body = serde_json::to_value(&signed).map_err(|e| VerifyError::IntegrityError {
        message: format!("serialize custody attestation: {e}"),
    })?;
    // Attach the attestation certs as hash-bound evidence in the (unsigned) outer
    // body — bound to the holder signature through the sha256 commitments in the
    // signed envelope, so tampering breaks verification, while the actual
    // multi-KB cert bytes never enter the hardware-Ed25519 preimage (#113).
    let chain_hex: Vec<String> = attestation_chain_ders.iter().map(hex::encode).collect();
    if let Some(map) = body.as_object_mut() {
        map.insert(
            EVIDENCE_9C_HEX.to_string(),
            json!(hex::encode(attestation_9c_der)),
        );
        map.insert(EVIDENCE_CHAIN_HEX.to_string(), json!(chain_hex));
    }
    Ok(SignedCegObject::new(
        ACCORD_CUSTODY_ATTESTATION_KIND,
        holder.key_id(),
        signed_at,
        body,
    ))
}

fn str_field<'a>(v: &'a Value, field: &str) -> Result<&'a str, CustodyError> {
    v.get(field)
        .and_then(Value::as_str)
        .ok_or(CustodyError::Malformed {
            field: field.to_string(),
        })
}

/// Verify an accord-holder custody attestation end-to-end (CIRISVerify#91). The
/// CIRISServer admission gate calls this and admits only on `Ok` with the
/// required tier.
///
/// `holder_member` is the holder's pinned pubkeys (resolved by the caller from
/// its directory by the bundle's `holder_key_id`). `yubico_root_der` is the
/// pinned Yubico PIV attestation root (the consumer pins it — verify provides
/// the verification, not the trust root). Fail-closed: see [`CustodyError`].
///
/// # Errors
///
/// [`CustodyError`] naming the first failing step.
pub fn verify_accord_custody_attestation(
    obj: &SignedCegObject,
    holder_member: &ThresholdMember,
    yubico_root_der: &[u8],
) -> Result<CustodyVerdict, CustodyError> {
    if obj.kind != ACCORD_CUSTODY_ATTESTATION_KIND {
        return Err(CustodyError::WrongKind {
            kind: obj.kind.clone(),
        });
    }
    let env = obj
        .body
        .get("signed_envelope")
        .ok_or(CustodyError::Malformed {
            field: "signed_envelope".to_string(),
        })?;
    let ed_sig = str_field(&obj.body, "ed25519_signature_base64")?;
    let mldsa_sig = obj
        .body
        .get("mldsa65_signature_base64")
        .and_then(Value::as_str);

    // 1. The bundle is authored by the holder (bound-hybrid, RequireHybrid).
    let bytes = jcs::canonicalize(env).map_err(|_| CustodyError::Malformed {
        field: "signed_envelope (jcs)".to_string(),
    })?;
    let sig = ThresholdSignature {
        member_id: holder_member.member_id.clone(),
        ed25519_signature_base64: ed_sig.to_string(),
        mldsa65_signature_base64: mldsa_sig.map(str::to_string),
    };
    if verify_threshold_signatures(&bytes, std::slice::from_ref(holder_member), &[sig], 1) != Ok(1)
    {
        return Err(CustodyError::SignatureInvalid);
    }

    // The holder signs its own identity into the envelope; bind that self-claim
    // to the caller-resolved `holder_member` so the signed fields are
    // load-bearing, not decorative — a holder cannot sign a bundle whose
    // embedded key_id / pubkey disagree with the key the gate verified against
    // (closes the confused-deputy / record-drift surface).
    if str_field(env, "holder_key_id")? != holder_member.member_id {
        return Err(CustodyError::Malformed {
            field: "holder_key_id (≠ resolved member_id)".to_string(),
        });
    }
    if str_field(env, "ed25519_public_key_base64")? != holder_member.ed25519_public_key_base64 {
        return Err(CustodyError::Malformed {
            field: "ed25519_public_key_base64 (≠ resolved member key)".to_string(),
        });
    }
    // The ML-DSA-65 half is hash-COMMITTED (not inline) to keep the hardware
    // Ed25519 preimage under the YubiKey's EdDSA input ceiling (#116). Keep it
    // load-bearing anyway: bind the committed sha256 to the resolved member's
    // ML-DSA key (RequireHybrid guarantees the member has one once the signature
    // verified above), so a holder can't commit a different PQC half than the one
    // the gate trusts — the same record-drift gate the ed25519 field gets.
    if let Some(member_mldsa_b64) = &holder_member.mldsa65_public_key_base64 {
        let member_mldsa = base64::engine::general_purpose::STANDARD
            .decode(member_mldsa_b64)
            .map_err(|_| CustodyError::Malformed {
                field: "holder mldsa65 pubkey (base64)".to_string(),
            })?;
        if !sha256_hex(&member_mldsa)
            .eq_ignore_ascii_case(str_field(env, "mldsa65_public_key_sha256")?)
        {
            return Err(CustodyError::Malformed {
                field: "mldsa65_public_key_sha256 (≠ resolved member key)".to_string(),
            });
        }
    }

    // `custody_tier` is a holder self-claim — allowlist it so a holder cannot
    // assert a stronger tier than the one verify recognizes (a consumer that
    // gates on tier would otherwise inherit an unbounded, unverified string).
    let custody_tier = str_field(env, "custody_tier")?.to_string();
    if !ALLOWED_CUSTODY_TIERS.contains(&custody_tier.as_str()) {
        return Err(CustodyError::FloorNotMet {
            detail: format!("unrecognized custody_tier {custody_tier:?}"),
        });
    }
    // #113: the certs travel as hash-bound evidence in the OUTER body (unsigned),
    // committed to by the sha256 fields INSIDE the signed envelope. Recompute the
    // digest of each supplied cert and require it to equal the signed commitment —
    // this binds the (large) certs to the (small) holder signature without ever
    // putting them in the Ed25519 preimage. A swapped cert breaks the equality.
    let attest_9c = hex::decode(str_field(&obj.body, EVIDENCE_9C_HEX)?)
        .map_err(|_| CustodyError::CertParse { which: "9c" })?;
    if !sha256_hex(&attest_9c).eq_ignore_ascii_case(str_field(env, COMMIT_9C_SHA256)?) {
        return Err(CustodyError::Malformed {
            field: "yubikey_piv_attestation_9c (evidence ≠ signed sha256 commitment)".to_string(),
        });
    }
    let commit_chain = env
        .get(COMMIT_CHAIN_SHA256)
        .and_then(Value::as_array)
        .ok_or(CustodyError::Malformed {
            field: COMMIT_CHAIN_SHA256.to_string(),
        })?;
    let evidence_chain = obj
        .body
        .get(EVIDENCE_CHAIN_HEX)
        .and_then(Value::as_array)
        .ok_or(CustodyError::Malformed {
            field: EVIDENCE_CHAIN_HEX.to_string(),
        })?;
    if evidence_chain.len() != commit_chain.len() {
        return Err(CustodyError::Malformed {
            field: "chain evidence length ≠ signed commitment length".to_string(),
        });
    }
    let mut chain: Vec<Vec<u8>> = Vec::with_capacity(evidence_chain.len());
    for (ev, com) in evidence_chain.iter().zip(commit_chain.iter()) {
        let der = hex::decode(ev.as_str().ok_or(CustodyError::Malformed {
            field: format!("{EVIDENCE_CHAIN_HEX}[]"),
        })?)
        .map_err(|_| CustodyError::CertParse { which: "chain" })?;
        let com = com.as_str().ok_or(CustodyError::Malformed {
            field: format!("{COMMIT_CHAIN_SHA256}[]"),
        })?;
        if !sha256_hex(&der).eq_ignore_ascii_case(com) {
            return Err(CustodyError::Malformed {
                field: "yubikey_attestation_chain (evidence ≠ signed sha256 commitment)"
                    .to_string(),
            });
        }
        chain.push(der);
    }
    let chain_refs: Vec<&[u8]> = chain.iter().map(Vec::as_slice).collect();
    let holder_ed = base64::engine::general_purpose::STANDARD
        .decode(&holder_member.ed25519_public_key_base64)
        .map_err(|_| CustodyError::Malformed {
            field: "holder ed25519 pubkey".to_string(),
        })?;

    // 2-4: the YubiKey PIV attestation — chain to the pinned Yubico root, the
    // attested key == the holder's Ed25519, and the FIPS/touch floor.
    let mut verdict =
        verify_yubikey_piv_attestation(&attest_9c, &chain_refs, yubico_root_der, &holder_ed)?;
    verdict.custody_tier = custody_tier;
    Ok(verdict)
}

/// Convert a **verified** accord-holder custody attestation into a
/// [`PlatformAttestation::ExternalSecureElement`] (CIRISVerify#117) — the bridge
/// from a verify-side custody attestation to CIRISPersist's `attestation_evidence`
/// shape, so a registrar can admit/entrench an `accord_holder` **non-interactively**
/// from the outbox artifacts (no human / YubiKey in the loop once the ceremony is
/// done).
///
/// Call [`verify_accord_custody_attestation`] FIRST and pass its `obj` plus the
/// returned [`CustodyVerdict`] here. This does **not** re-verify — the caller's
/// prior `Ok(verdict)` is the proof; it reads the (already hash-bound) attestation
/// cert DERs back out of the bundle's evidence and packages them with the verdict's
/// hardware floor. The consumer re-validates the chain to its own pinned root.
///
/// # Errors
///
/// [`CustodyError`] if the bundle's evidence certs are missing or malformed.
pub fn custody_attestation_to_platform_attestation(
    obj: &SignedCegObject,
    verdict: &CustodyVerdict,
) -> Result<PlatformAttestation, CustodyError> {
    let attestation_cert_der = hex::decode(str_field(&obj.body, EVIDENCE_9C_HEX)?)
        .map_err(|_| CustodyError::CertParse { which: "9c" })?;
    let chain_vals = obj
        .body
        .get(EVIDENCE_CHAIN_HEX)
        .and_then(Value::as_array)
        .ok_or(CustodyError::Malformed {
            field: EVIDENCE_CHAIN_HEX.to_string(),
        })?;
    let attestation_chain_der = chain_vals
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or(CustodyError::Malformed {
                    field: format!("{EVIDENCE_CHAIN_HEX}[]"),
                })
                .and_then(|s| {
                    hex::decode(s).map_err(|_| CustodyError::CertParse { which: "chain" })
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PlatformAttestation::ExternalSecureElement(
        ExternalSecureElementAttestation {
            hardware_class: verdict.hardware_class.clone(),
            attestation_cert_der,
            attestation_chain_der,
            firmware: if verdict.firmware.is_empty() {
                None
            } else {
                Some(verdict.firmware.clone())
            },
            serial: verdict.serial,
            fips_certified: verdict.fips_certified,
            touch_always: verdict.touch_always,
        },
    ))
}

/// Unwrap a short-form DER OCTET STRING (`0x04 len content`), returning its
/// content when the bytes are exactly one OCTET STRING covering the whole
/// slice; otherwise returns the input unchanged. Yubico wraps the `.3` / `.8`
/// extension payloads this way on post-fix firmware (yubico-piv-tool#181) but
/// stored them bare on older firmware — tolerating both is fail-safe here
/// because the extension bytes are authenticated by the pinned attestation
/// chain (a forger can't alter them without breaking the signature).
fn inner_octet_string(raw: &[u8]) -> &[u8] {
    if raw.len() >= 2 && raw[0] == 0x04 {
        let len = raw[1] as usize;
        // Short-form length only (Yubico values are < 128 bytes, high bit clear).
        if raw[1] & 0x80 == 0 && raw.len() == 2 + len {
            return &raw[2..];
        }
    }
    raw
}

/// Verify a YubiKey PIV slot-9c attestation chain `9c → f9 → [intermediates…] →
/// pinned root`, confirm the attested key equals `expected_ed`, and extract +
/// enforce the FIPS + touch floor. The security-critical core, factored out so
/// it is directly testable against a generated chain (without the
/// bundle-signature layer).
///
/// `attestation_chain_ders` is the path **above** the 9c leaf, leaf-first:
/// `[f9, …intermediates…]` — `chain[0]` (f9) is the device attestation cert that
/// signs the 9c leaf and carries the FIPS `.10` extension; the last entry is
/// verified against `pinned_root_der`. For the pre-fw-5.7 PKI this is a single
/// `[f9]` and `pinned_root_der` is `Yubico PIV Root CA Serial 263751`; for the
/// 2024-12 PKI it is `[f9, "Yubico PIV Attestation B 1"]` and `pinned_root_der`
/// is the durable `Yubico Attestation Root 1`. Every link is a real signature
/// verification; no name/CA-flag trust is inferred.
///
/// # Errors
///
/// [`CustodyError`] naming the first failing check (incl. an empty chain).
pub fn verify_yubikey_piv_attestation(
    attest_9c_der: &[u8],
    attestation_chain_ders: &[&[u8]],
    pinned_root_der: &[u8],
    expected_ed: &[u8],
) -> Result<CustodyVerdict, CustodyError> {
    if attestation_chain_ders.is_empty() {
        return Err(CustodyError::ChainInvalid {
            detail: "empty attestation chain (need at least the f9 device cert)".to_string(),
        });
    }
    let (_, cert_9c) = X509Certificate::from_der(attest_9c_der)
        .map_err(|_| CustodyError::CertParse { which: "9c" })?;
    let chain: Vec<X509Certificate> = attestation_chain_ders
        .iter()
        .map(|der| {
            X509Certificate::from_der(der)
                .map(|(_, c)| c)
                .map_err(|_| CustodyError::CertParse { which: "chain" })
        })
        .collect::<Result<_, _>>()?;
    let (_, cert_root) = X509Certificate::from_der(pinned_root_der)
        .map_err(|_| CustodyError::CertParse { which: "root" })?;

    // 9c signed by chain[0] (f9); chain[i] signed by chain[i+1]; chain.last by root.
    cert_9c
        .verify_signature(Some(chain[0].public_key()))
        .map_err(|e| CustodyError::ChainInvalid {
            detail: format!("9c not signed by f9: {e:?}"),
        })?;
    for i in 0..chain.len() - 1 {
        chain[i]
            .verify_signature(Some(chain[i + 1].public_key()))
            .map_err(|e| CustodyError::ChainInvalid {
                detail: format!("attestation chain link {i}→{} broken: {e:?}", i + 1),
            })?;
    }
    chain[chain.len() - 1]
        .verify_signature(Some(cert_root.public_key()))
        .map_err(|e| CustodyError::ChainInvalid {
            detail: format!("top of chain not signed by the pinned Yubico root: {e:?}"),
        })?;

    // The attested key == the holder's federation Ed25519 key.
    let spki = cert_9c.public_key();
    if spki.algorithm.algorithm.to_id_string() != OID_ED25519 {
        return Err(CustodyError::FloorNotMet {
            detail: "attested key is not Ed25519".to_string(),
        });
    }
    if spki.subject_public_key.data.as_ref() != expected_ed {
        return Err(CustodyError::AttestedKeyMismatch);
    }

    // Yubico extensions → firmware + touch=always (slot-9c) and FIPS (slot-f9).
    //
    // Encoding note (cross-confirmed vs Yubico's PIV attestation docs +
    // yubico-piv-tool#181): the `.3` firmware and `.8` pin/touch values are an
    // **inner DER OCTET STRING** wrapping the raw payload (post-fix firmware;
    // older firmware stored them bare). `inner_octet_string` unwraps when
    // present and falls back to the raw bytes otherwise, so both encodings
    // parse — and the touch byte is read from the *unwrapped* `[pin, touch]`
    // content (reading the wrapper length byte instead would silently accept a
    // no-touch key, the one false-accept that matters for a kill-switch gate).
    let mut firmware = None;
    let mut serial = None;
    let mut touch_always = false;
    for ext in cert_9c.extensions() {
        match ext.oid.to_id_string().as_str() {
            OID_YUBICO_FIRMWARE => {
                let v = inner_octet_string(ext.value);
                if v.len() >= 3 {
                    firmware = Some(format!("{}.{}.{}", v[0], v[1], v[2]));
                }
            },
            OID_YUBICO_SERIAL => {
                if let Ok((_, n)) = x509_parser::der_parser::asn1_rs::Integer::from_der(ext.value) {
                    serial = n.as_u32().ok();
                }
            },
            OID_YUBICO_PIN_TOUCH_POLICY => {
                let v = inner_octet_string(ext.value);
                if v.len() >= 2 {
                    touch_always = v[1] == TOUCH_POLICY_ALWAYS;
                }
            },
            _ => {},
        }
    }

    // The FIPS-certified extension (`.10`) is carried on the factory-loaded
    // slot-**f9** device attestation cert (`chain[0]`), NOT the per-slot 9c leaf
    // — scanning the 9c cert (which never carries it) would fail-reject every
    // genuine FIPS key. Confirmed against a real YubiKey 5 FIPS fw 5.7.4 (#91).
    let fips_certified = chain[0]
        .extensions()
        .iter()
        .any(|ext| ext.oid.to_id_string() == OID_YUBICO_FIPS_CERTIFIED);
    if !fips_certified {
        return Err(CustodyError::FloorNotMet {
            detail: "YubiKey is not FIPS-certified (no 1.3.6.1.4.1.41482.3.10 on the f9 cert)"
                .to_string(),
        });
    }
    if !touch_always {
        return Err(CustodyError::FloorNotMet {
            detail: "touch policy is not 'always' — every accord signature must require a touch"
                .to_string(),
        });
    }

    Ok(CustodyVerdict {
        hardware_class: "YubiKey_5_FIPS".to_string(),
        custody_tier: String::new(), // filled by the bundle caller
        firmware: firmware.unwrap_or_default(),
        serial,
        fips_certified,
        touch_always,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair, PKCS_ED25519,
    };

    /// Raw 32-byte Ed25519 pubkey from an rcgen keypair's SPKI (trailing 32 B).
    fn raw_ed(kp: &KeyPair) -> Vec<u8> {
        let spki = kp.public_key_der();
        spki[spki.len() - 32..].to_vec()
    }

    fn params(cn: &str) -> CertificateParams {
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        p.distinguished_name = dn;
        p
    }

    /// Build a mock attestation chain root → f9 → 9c that mirrors the *documented*
    /// real YubiKey encoding: the 9c leaf carries the firmware (`.3`) + pin/touch
    /// (`.8`) extensions as **inner DER OCTET STRINGs**, and the FIPS (`.10`)
    /// extension rides the **f9** cert (not the leaf). Returns (9c, f9, root) DER.
    fn mock_chain(leaf_kp: &KeyPair, fips: bool, touch: u8) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let root_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let root = params("Yubico PIV Attestation (test root)")
            .self_signed(&root_kp)
            .unwrap();
        let f9_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut f9_params = params("YubiKey PIV Attestation (test f9)");
        if fips {
            // FIPS `.10` lives on the factory f9 cert (presence = FIPS-certified).
            f9_params.custom_extensions = vec![CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 41482, 3, 10],
                vec![],
            )];
        }
        let f9 = f9_params.signed_by(&f9_kp, &root, &root_kp).unwrap();

        let mut leaf = params("YubiKey PIV Attestation 9c");
        leaf.custom_extensions = vec![
            // firmware 5.7.4, DER OCTET STRING-wrapped: 04 03 05 07 04
            CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 41482, 3, 3],
                vec![0x04, 0x03, 5, 7, 4],
            ),
            // [pin_policy=once(0x01), touch_policy], OCTET STRING-wrapped: 04 02 01 <touch>
            CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 41482, 3, 8],
                vec![0x04, 0x02, 0x01, touch],
            ),
        ];
        let cert_9c = leaf.signed_by(leaf_kp, &f9, &f9_kp).unwrap();
        (
            cert_9c.der().to_vec(),
            f9.der().to_vec(),
            root.der().to_vec(),
        )
    }

    #[test]
    fn fips_touch_chain_verifies_and_extracts() {
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (c9, f9, root) = mock_chain(&leaf_kp, true, TOUCH_POLICY_ALWAYS);
        let v = verify_yubikey_piv_attestation(&c9, &[f9.as_slice()], &root, &raw_ed(&leaf_kp))
            .expect("a FIPS, touch-always, root-chained attestation must verify");
        assert_eq!(v.hardware_class, "YubiKey_5_FIPS");
        assert!(v.fips_certified && v.touch_always);
        assert_eq!(v.firmware, "5.7.4");
    }

    #[test]
    fn wrong_root_breaks_the_chain() {
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (c9, f9, _root) = mock_chain(&leaf_kp, true, TOUCH_POLICY_ALWAYS);
        // A different (attacker) root the f9 does not chain to.
        let other_root_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let other_root = params("attacker root").self_signed(&other_root_kp).unwrap();
        let err = verify_yubikey_piv_attestation(
            &c9,
            &[f9.as_slice()],
            other_root.der(),
            &raw_ed(&leaf_kp),
        )
        .unwrap_err();
        assert!(matches!(err, CustodyError::ChainInvalid { .. }));
    }

    #[test]
    fn non_fips_yubikey_rejected() {
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (c9, f9, root) = mock_chain(&leaf_kp, false, TOUCH_POLICY_ALWAYS);
        let err = verify_yubikey_piv_attestation(&c9, &[f9.as_slice()], &root, &raw_ed(&leaf_kp))
            .unwrap_err();
        assert!(matches!(err, CustodyError::FloorNotMet { .. }));
    }

    #[test]
    fn touch_not_always_rejected() {
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (c9, f9, root) = mock_chain(&leaf_kp, true, 0x01 /* not always */);
        let err = verify_yubikey_piv_attestation(&c9, &[f9.as_slice()], &root, &raw_ed(&leaf_kp))
            .unwrap_err();
        assert!(matches!(err, CustodyError::FloorNotMet { .. }));
    }

    #[test]
    fn attested_key_must_be_the_holder_key() {
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (c9, f9, root) = mock_chain(&leaf_kp, true, TOUCH_POLICY_ALWAYS);
        let someone_else = raw_ed(&KeyPair::generate_for(&PKCS_ED25519).unwrap());
        let err = verify_yubikey_piv_attestation(&c9, &[f9.as_slice()], &root, &someone_else)
            .unwrap_err();
        assert_eq!(err, CustodyError::AttestedKeyMismatch);
    }

    #[test]
    fn four_level_chain_with_intermediate_verifies() {
        // The 2024-12 Yubico PKI: 9c → f9 → intermediate → root. The verifier
        // must walk the intermediate up to the pinned *root* (not a fixed
        // 3-cert chain), with FIPS .10 still read off the f9 device cert.
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let root_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let root = params("Yubico Attestation Root 1 (test)")
            .self_signed(&root_kp)
            .unwrap();
        let mid_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mid = params("Yubico PIV Attestation B 1 (test)")
            .signed_by(&mid_kp, &root, &root_kp)
            .unwrap();
        let mut f9p = params("Yubico PIV Attestation (test f9)");
        f9p.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 41482, 3, 10],
            vec![],
        )];
        let f9_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let f9 = f9p.signed_by(&f9_kp, &mid, &mid_kp).unwrap();
        let mut leaf = params("YubiKey 9c (test)");
        leaf.custom_extensions = vec![
            CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 41482, 3, 3],
                vec![0x04, 0x03, 5, 7, 4],
            ),
            CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 41482, 3, 8],
                vec![0x04, 0x02, 0x01, TOUCH_POLICY_ALWAYS],
            ),
        ];
        let c9 = leaf.signed_by(&leaf_kp, &f9, &f9_kp).unwrap();

        let c9d = c9.der().to_vec();
        let f9d = f9.der().to_vec();
        let midd = mid.der().to_vec();
        let rootd = root.der().to_vec();
        let expected = raw_ed(&leaf_kp);

        // Full 4-level chain to the pinned root verifies.
        let v = verify_yubikey_piv_attestation(
            &c9d,
            &[f9d.as_slice(), midd.as_slice()],
            &rootd,
            &expected,
        )
        .expect("a 9c → f9 → intermediate → root chain must verify");
        assert_eq!(v.hardware_class, "YubiKey_5_FIPS");
        assert!(v.fips_certified && v.touch_always);
        assert_eq!(v.firmware, "5.7.4");

        // Pinning a *stranger* root (the intermediate doesn't chain to it) fails.
        let stranger_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let stranger = params("stranger root").self_signed(&stranger_kp).unwrap();
        assert!(matches!(
            verify_yubikey_piv_attestation(
                &c9d,
                &[f9d.as_slice(), midd.as_slice()],
                stranger.der(),
                &expected
            )
            .unwrap_err(),
            CustodyError::ChainInvalid { .. }
        ));

        // A missing intermediate (chain=[f9], root pinned) cannot bridge to root.
        assert!(matches!(
            verify_yubikey_piv_attestation(&c9d, &[f9d.as_slice()], &rootd, &expected).unwrap_err(),
            CustodyError::ChainInvalid { .. }
        ));

        // An empty chain is fail-closed.
        assert!(matches!(
            verify_yubikey_piv_attestation(&c9d, &[], &rootd, &expected).unwrap_err(),
            CustodyError::ChainInvalid { .. }
        ));
    }

    /// PKCS#8-PEM for an Ed25519 `seed`, so rcgen and `Ed25519Signer::from_seed`
    /// derive the *same* keypair — letting the mock 9c cert attest the holder's
    /// real federation Ed25519 key.
    fn ed25519_pkcs8_pem(seed: &[u8; 32]) -> (String, KeyPair) {
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(seed);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n");
        let kp = KeyPair::from_pkcs8_pem_and_sign_algo(&pem, &PKCS_ED25519).unwrap();
        (pem, kp)
    }

    #[tokio::test]
    async fn producer_verifier_round_trip_is_coherent() {
        // The discipline: the bundle a holder *produces* must be exactly what the
        // admission gate *verifies* — no field/hex drift between produce + verify.
        use crate::self_at_login::HybridSigningIdentity;
        use ciris_crypto::{Ed25519Signer, MlDsa65Signer};

        let seed = [7u8; 32];
        let (_pem, leaf_kp) = ed25519_pkcs8_pem(&seed);
        let (c9, f9, root) = mock_chain(&leaf_kp, true, TOUCH_POLICY_ALWAYS);

        // Holder's Ed25519 == the attested leaf key (same seed); any ML-DSA half.
        let ed = Ed25519Signer::from_seed(&seed).unwrap();
        let mldsa = MlDsa65Signer::new().unwrap();
        let holder = HybridSigningIdentity::new("accord-holder-a1", ed, mldsa);
        let member = holder.directory_member().unwrap();

        let obj = produce_accord_custody_attestation(
            &holder,
            &c9,
            &[f9.as_slice()],
            CUSTODY_TIER_PORTABLE_2FA,
            "2026-06-20T00:00:00Z",
        )
        .await
        .unwrap();
        assert_eq!(obj.kind, ACCORD_CUSTODY_ATTESTATION_KIND);

        let v = verify_accord_custody_attestation(&obj, &member, &root)
            .expect("the holder-produced bundle must verify at the gate");
        assert_eq!(v.custody_tier, CUSTODY_TIER_PORTABLE_2FA);
        assert_eq!(v.hardware_class, "YubiKey_5_FIPS");
        assert!(v.fips_certified && v.touch_always);

        // A bundle from a *different* holder key (wrong attested key) is refused
        // even though the chain itself is valid — the attestation must bind to
        // the holder the gate resolved.
        let other = HybridSigningIdentity::new(
            "accord-holder-a1",
            Ed25519Signer::from_seed(&[8u8; 32]).unwrap(),
            MlDsa65Signer::new().unwrap(),
        );
        let other_member = other.directory_member().unwrap();
        // Re-sign the same certs under the other holder; gate resolves other_member.
        let obj2 = produce_accord_custody_attestation(
            &other,
            &c9,
            &[f9.as_slice()],
            CUSTODY_TIER_PORTABLE_2FA,
            "2026-06-20T00:00:00Z",
        )
        .await
        .unwrap();
        assert_eq!(
            verify_accord_custody_attestation(&obj2, &other_member, &root).unwrap_err(),
            CustodyError::AttestedKeyMismatch
        );
    }

    #[tokio::test]
    async fn unrecognized_custody_tier_rejected() {
        // `custody_tier` is a holder self-claim — a tier outside the allowlist
        // must be refused, so a tier-gating consumer can't inherit an inflated
        // unverified claim.
        use crate::self_at_login::HybridSigningIdentity;
        use ciris_crypto::{Ed25519Signer, MlDsa65Signer};

        let seed = [11u8; 32];
        let (_pem, leaf_kp) = ed25519_pkcs8_pem(&seed);
        let (c9, f9, root) = mock_chain(&leaf_kp, true, TOUCH_POLICY_ALWAYS);
        let holder = HybridSigningIdentity::new(
            "accord-holder-c1",
            Ed25519Signer::from_seed(&seed).unwrap(),
            MlDsa65Signer::new().unwrap(),
        );
        let member = holder.directory_member().unwrap();
        let obj = produce_accord_custody_attestation(
            &holder,
            &c9,
            &[f9.as_slice()],
            "machine_bound_5fa", // a tier verify does not recognize
            "2026-06-20T00:00:00Z",
        )
        .await
        .unwrap();
        assert!(matches!(
            verify_accord_custody_attestation(&obj, &member, &root).unwrap_err(),
            CustodyError::FloorNotMet { .. }
        ));
    }

    #[tokio::test]
    async fn envelope_identity_must_match_resolved_member() {
        // The holder signs its key_id into the envelope; if the gate resolves a
        // member whose member_id disagrees, admission is refused — the signed
        // self-claim is load-bearing, not decorative.
        use crate::self_at_login::HybridSigningIdentity;
        use ciris_crypto::{Ed25519Signer, MlDsa65Signer};

        let seed = [12u8; 32];
        let (_pem, leaf_kp) = ed25519_pkcs8_pem(&seed);
        let (c9, f9, root) = mock_chain(&leaf_kp, true, TOUCH_POLICY_ALWAYS);
        let holder = HybridSigningIdentity::new(
            "accord-holder-d1",
            Ed25519Signer::from_seed(&seed).unwrap(),
            MlDsa65Signer::new().unwrap(),
        );
        let obj = produce_accord_custody_attestation(
            &holder,
            &c9,
            &[f9.as_slice()],
            CUSTODY_TIER_PORTABLE_2FA,
            "2026-06-20T00:00:00Z",
        )
        .await
        .unwrap();
        // Same pubkeys, different member_id than the envelope's holder_key_id.
        let mut mismatched = holder.directory_member().unwrap();
        mismatched.member_id = "accord-holder-IMPOSTER".to_string();
        assert!(matches!(
            verify_accord_custody_attestation(&obj, &mismatched, &root).unwrap_err(),
            CustodyError::Malformed { .. } | CustodyError::SignatureInvalid
        ));
    }

    #[tokio::test]
    async fn committed_mldsa_must_match_resolved_member(/* #116 */) {
        // The ML-DSA half is hash-committed (not inline) so it fits the token's
        // EdDSA ceiling — but it must stay load-bearing: a member whose ML-DSA key
        // hashes to something other than the committed value is refused, even with
        // a matching ed25519 half. (Else the commitment would be decorative.)
        use crate::self_at_login::HybridSigningIdentity;
        use ciris_crypto::{Ed25519Signer, MlDsa65Signer};

        let seed = [19u8; 32];
        let (_pem, leaf_kp) = ed25519_pkcs8_pem(&seed);
        let (c9, f9, root) = mock_chain(&leaf_kp, true, TOUCH_POLICY_ALWAYS);
        let holder = HybridSigningIdentity::new(
            "accord-holder-a1",
            Ed25519Signer::from_seed(&seed).unwrap(),
            MlDsa65Signer::new().unwrap(),
        );
        let obj = produce_accord_custody_attestation(
            &holder,
            &c9,
            &[f9.as_slice()],
            CUSTODY_TIER_PORTABLE_2FA,
            "2026-06-20T00:00:00Z",
        )
        .await
        .unwrap();

        // Resolve a member with the SAME ed25519 half but a DIFFERENT ML-DSA key.
        let mut swapped = holder.directory_member().unwrap();
        let other_mldsa = HybridSigningIdentity::new(
            "accord-holder-a1",
            Ed25519Signer::from_seed(&seed).unwrap(),
            MlDsa65Signer::new().unwrap(),
        )
        .directory_member()
        .unwrap();
        swapped.mldsa65_public_key_base64 = other_mldsa.mldsa65_public_key_base64;
        assert!(matches!(
            verify_accord_custody_attestation(&obj, &swapped, &root).unwrap_err(),
            CustodyError::Malformed { .. } | CustodyError::SignatureInvalid
        ));
    }

    #[tokio::test]
    async fn custody_attestation_wraps_to_external_se_platform_attestation(/* #117 */) {
        // The registration bridge: a verified custody attestation must convert to
        // a PlatformAttestation::ExternalSecureElement carrying the cert chain +
        // hardware floor, so persist can admit/entrench the accord_holder
        // non-interactively. The cert DERs must round-trip out of the evidence.
        use crate::self_at_login::HybridSigningIdentity;
        use ciris_crypto::{Ed25519Signer, MlDsa65Signer};

        let seed = [33u8; 32];
        let (_pem, leaf_kp) = ed25519_pkcs8_pem(&seed);
        let (c9, f9, root) = mock_chain(&leaf_kp, true, TOUCH_POLICY_ALWAYS);
        let holder = HybridSigningIdentity::new(
            "accord-holder-a1",
            Ed25519Signer::from_seed(&seed).unwrap(),
            MlDsa65Signer::new().unwrap(),
        );
        let member = holder.directory_member().unwrap();
        let obj = produce_accord_custody_attestation(
            &holder,
            &c9,
            &[f9.as_slice()],
            CUSTODY_TIER_PORTABLE_2FA,
            "2026-06-20T00:00:00Z",
        )
        .await
        .unwrap();

        let verdict = verify_accord_custody_attestation(&obj, &member, &root).unwrap();
        let pa = custody_attestation_to_platform_attestation(&obj, &verdict).unwrap();
        match pa {
            PlatformAttestation::ExternalSecureElement(ese) => {
                assert_eq!(ese.hardware_class, "YubiKey_5_FIPS");
                assert!(ese.fips_certified && ese.touch_always);
                assert_eq!(ese.attestation_cert_der, c9, "9c cert DER must round-trip");
                assert_eq!(
                    ese.attestation_chain_der,
                    vec![f9.clone()],
                    "chain must round-trip as [f9]"
                );
                assert!(ese.firmware.is_some(), "firmware should be carried");
            },
            other => panic!("expected ExternalSecureElement, got {other:?}"),
        }
    }

    #[test]
    fn wrong_kind_object_rejected() {
        let obj = SignedCegObject::new("something_else", "k", "t", serde_json::json!({}));
        let m = ThresholdMember {
            member_id: "k".into(),
            ed25519_public_key_base64: String::new(),
            mldsa65_public_key_base64: None,
            role: None,
        };
        assert!(matches!(
            verify_accord_custody_attestation(&obj, &m, &[]).unwrap_err(),
            CustodyError::WrongKind { .. }
        ));
    }

    #[tokio::test]
    async fn signed_preimage_is_independent_of_chain_size(/* #113 */) {
        // The bug: the holder's hardware Ed25519 (YubiKey CKM_EDDSA, single-part,
        // bounded input) was handed the full attestation chain INLINE → a preimage
        // that grew with every cert (several KB) → CKR_DATA_LEN_RANGE. The fix
        // signs a per-cert sha256 commitment, so the signed preimage no longer
        // depends on cert size at all — it stays in the same small class as a
        // normal accord holder record (whose ~2.6 KB is the ML-DSA-65 pubkey, not
        // the certs, and which signs fine on the token). Lock the *invariant*:
        // blowing the chain up by ~10 KB must NOT change the signed preimage.
        // (No token needed — we measure the JCS bytes the signer would consume.)
        use crate::self_at_login::HybridSigningIdentity;
        use ciris_crypto::{Ed25519Signer, MlDsa65Signer};

        let seed = [21u8; 32];
        let (_pem, leaf_kp) = ed25519_pkcs8_pem(&seed);
        let (c9, f9, _root) = mock_chain(&leaf_kp, true, TOUCH_POLICY_ALWAYS);
        let holder = HybridSigningIdentity::new(
            "accord-holder-a1",
            Ed25519Signer::from_seed(&seed).unwrap(),
            MlDsa65Signer::new().unwrap(),
        );
        let preimage_len = |obj: &SignedCegObject| {
            jcs::canonicalize(obj.body.get("signed_envelope").unwrap())
                .unwrap()
                .len()
        };

        let obj_small = produce_accord_custody_attestation(
            &holder,
            &c9,
            &[f9.as_slice()],
            CUSTODY_TIER_PORTABLE_2FA,
            "2026-06-20T00:00:00Z",
        )
        .await
        .unwrap();
        let len_small = preimage_len(&obj_small);

        // A pathologically large chain — 10 KB of extra "cert" bytes.
        let huge = vec![0xABu8; 10 * 1024];
        let obj_huge = produce_accord_custody_attestation(
            &holder,
            &c9,
            &[f9.as_slice(), huge.as_slice()],
            CUSTODY_TIER_PORTABLE_2FA,
            "2026-06-20T00:00:00Z",
        )
        .await
        .unwrap();
        let len_huge = preimage_len(&obj_huge);

        // The commitment is fixed-width (64 hex chars per cert), so one extra cert
        // adds only its 64-char hash to the signed bytes — NOT its 10 KB. The
        // preimage must not balloon with cert size.
        assert!(
            len_huge.saturating_sub(len_small) < 256,
            "signed preimage grew {} bytes for a 10 KB cert — it must be cert-size-independent (#113)",
            len_huge.saturating_sub(len_small)
        );
        // #116: with the certs AND the ML-DSA-65 pubkey (2604 b64 chars) all
        // hash-committed, the whole signed preimage is now a few hundred bytes —
        // well under any YubiKey's single-shot EdDSA input ceiling. Lock an
        // absolute ceiling (the inline-ML-DSA preimage was ~3 KB and failed).
        assert!(
            len_small < 1024,
            "signed preimage is {len_small} bytes — must stay small (was ~3 KB with the ML-DSA pubkey inline, #116)"
        );
        // And the raw certs ARE carried — but only as outer-body evidence, never
        // inside the signed envelope (that is what kept them out of the preimage).
        assert!(obj_small.body.get(EVIDENCE_9C_HEX).is_some());
        let env_small = obj_small.body.get("signed_envelope").unwrap();
        assert!(!env_small.as_object().unwrap().contains_key(EVIDENCE_9C_HEX));
        assert!(!env_small
            .as_object()
            .unwrap()
            .contains_key(EVIDENCE_CHAIN_HEX));
    }

    #[tokio::test]
    async fn tampered_evidence_cert_breaks_the_commitment(/* #113 */) {
        // The certs live in the unsigned outer body — so prove they are *bound*:
        // swapping an evidence cert that no longer matches the signed sha256
        // commitment must fail closed (else the hash-commitment would be hollow).
        use crate::self_at_login::HybridSigningIdentity;
        use ciris_crypto::{Ed25519Signer, MlDsa65Signer};

        let seed = [22u8; 32];
        let (_pem, leaf_kp) = ed25519_pkcs8_pem(&seed);
        let (c9, f9, root) = mock_chain(&leaf_kp, true, TOUCH_POLICY_ALWAYS);
        let holder = HybridSigningIdentity::new(
            "accord-holder-a1",
            Ed25519Signer::from_seed(&seed).unwrap(),
            MlDsa65Signer::new().unwrap(),
        );
        let member = holder.directory_member().unwrap();
        let mut obj = produce_accord_custody_attestation(
            &holder,
            &c9,
            &[f9.as_slice()],
            CUSTODY_TIER_PORTABLE_2FA,
            "2026-06-20T00:00:00Z",
        )
        .await
        .unwrap();
        // Baseline: it verifies.
        assert!(verify_accord_custody_attestation(&obj, &member, &root).is_ok());

        // Flip a byte of the 9c evidence cert (still valid hex) — commitment mismatch.
        let mut tampered = c9.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        obj.body.as_object_mut().unwrap().insert(
            EVIDENCE_9C_HEX.to_string(),
            serde_json::json!(hex::encode(&tampered)),
        );
        assert!(matches!(
            verify_accord_custody_attestation(&obj, &member, &root).unwrap_err(),
            CustodyError::Malformed { .. }
        ));
    }
}
