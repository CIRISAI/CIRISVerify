//! The edition-2 signed row (CC 2.6.1, rc20; CIRISVerify#326 / #338).
//!
//! A row statement is one COSE_Sign1 (RFC 9052 §4.2, tag 18) over a
//! deterministically encoded payload ([`crate::cde`]), signed with the
//! composite ML-DSA-65-Ed25519 ([`ciris_crypto::composite`]). This module
//! reads one statement: it checks every structural rule of
//! `manifests/signed_object_v2.cddl` that needs no family model, finds the
//! signer's key by `kid`, verifies the signature over the Sig_structure, and
//! computes the row id and the statement id.
//!
//! The answer has three forms, as CC 2.6.1 states: [`Verdict::Valid`](crate::edition2::Verdict::Valid),
//! [`Verdict::Invalid`](crate::edition2::Verdict::Invalid) (final under a held key; a structural fault is
//! Invalid whatever keys are held) and [`Verdict::Waiting`](crate::edition2::Verdict::Waiting) on a key the
//! reader does not hold. Waiting is never counted.
//!
//! Not checked here, because each needs the family model or another row:
//! `dimension` resolving to the family, the second-consent role of an `iss`
//! that is not the payload's `author`, the `author` column (authored vs
//! counted), the disclosure digests against `redacted_claim_keys`, and the
//! key record's own validity. The verified statement carries what a caller
//! needs to apply them.
//!
//! Pure: no clock, no randomness, no I/O.

pub mod disclosure;
pub mod earlier;
pub mod family;
pub mod keys;
pub mod recovery;

use crate::cde::{self, Value};
use crate::prelude::*;
use ciris_crypto::composite::{CompositePublicKey, COSE_ALG, SIGNATURE_LEN};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The constant `cty` of a row (CC 2.6.1.3).
pub const ROW_CTY: &str = "application/vnd.ciris.row+cbor";
/// The `typ` of a row.
pub const ROW_TYP: &str = "ceg-row/2";
/// The edition carried in the CWT claims.
pub const EDITION: u64 = 2;
/// The prefix of every identity reference (RFC 9679 §5.7, sha-256).
pub const IDENTITY_REF_PREFIX: &str = "urn:ietf:params:oauth:ckt:sha-256:";
/// The row types.
pub const ROW_TYPES: [&str; 5] = [
    "scores",
    "delegates_to",
    "supersedes",
    "withdraws",
    "recants",
];

const H_ALG: i64 = 1;
const H_CTY: i64 = 3;
const H_KID: i64 = 4;
const H_CWT: i64 = 15;
const H_TYP: i64 = 16;
const H_SD_CLAIMS: i64 = 17;
const H_ROW_TYPE: i64 = -70001;
const H_FAMILY: i64 = -70002;
const C_ISS: i64 = 1;
const C_SUB: i64 = 2;
const C_EXP: i64 = 4;
const C_NBF: i64 = 5;
const C_IAT: i64 = 6;
const C_EDITION: i64 = -70003;
const HASH_ALG_SHA256: i64 = -16;
const TAG_COSE_SIGN1: u64 = 18;
const TAG_REDACTED_ELEMENT: u64 = 60;
const SIMPLE_REDACTED_KEYS: u8 = 59;

/// A 32-byte digest named in the `[-16, digest]` form.
pub type Digest32 = [u8; 32];

/// Why a statement is Invalid. Structural reasons are named so a producer can
/// find its fault; a failed signature is one reason and does not say which
/// half failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Invalid {
    /// The bytes, the protected header or the payload are not the
    /// deterministic encoding of their value.
    NotDeterministic {
        /// Which part.
        part: &'static str,
        /// The codec's reason.
        error: cde::CdeError,
    },
    /// Not a tag-18 COSE_Sign1 of four members.
    NotCoseSign1,
    /// A member is missing, of the wrong type, or out of its range.
    Malformed {
        /// The member, as the CDDL names it.
        member: &'static str,
    },
    /// A member the protected header, the CWT claims or `refs` does not admit.
    UnexpectedMember {
        /// Where.
        within: &'static str,
    },
    /// `iat` is not `floor(asserted_at / 1000)`, or `nbf` / `exp` disagree
    /// with `valid_from` / `valid_until`.
    TimeDisagreement {
        /// The claim.
        claim: &'static str,
    },
    /// A set in `refs` is unsorted or repeats an element.
    SetOrder {
        /// The member.
        member: &'static str,
    },
    /// The held key under `kid` does not have that thumbprint.
    KidMismatch,
    /// The composite signature does not verify.
    BadSignature,
    /// The signer's key record is Invalid, or the key is not in force.
    KeyNotValid,
    /// A disclosure opens no digest the payload carries, opens one already
    /// opened, or repeats a member its map already holds.
    DisclosureUnmatched,
    /// A redaction digest appears twice.
    DuplicateDigest,
    /// Header -70002 names no family the CC namespace registry registers.
    UnregisteredFamily,
    /// `dimension` resolves to a family other than header -70002.
    DimensionFamily,
    /// The CC matcher refuses `dimension`; the manifest's token.
    DimensionRefused {
        /// `_meta.case_rule.refusal_tokens` value.
        token: &'static str,
    },
    /// `dimension` is open vocabulary: no registered family claims it.
    DimensionUnregistered,
}

/// The answer for one statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every rule here holds and the signature verifies.
    Valid(Box<VerifiedRow>),
    /// A rule fails.
    Invalid(Invalid),
    /// The structure holds but the signer's key is not held.
    Waiting {
        /// The keys the reader would need, deepest first.
        missing: Vec<MissingKey>,
    },
}

/// A key a Waiting statement needs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum MissingKey {
    /// A composite key, by its thumbprint.
    Kid(Digest32),
    /// The ML-DSA-65 half of a key held in part, by the SHA-256 commitment
    /// the reader holds for it (an earlier-form key known by its FedCode
    /// commitment, CC 2.6.8).
    MlDsaHalf {
        /// The thumbprint the statement names.
        kid: Digest32,
        /// SHA-256 of the missing ML-DSA-65 public key.
        commitment: Digest32,
    },
}

/// What a reader knows of the key under a `kid`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum KeyLookup {
    /// The key is held and in force.
    Held(Box<CompositePublicKey>),
    /// Nothing is known of it.
    NotHeld,
    /// Its key record, or a half of it, waits on other keys.
    Waiting(Vec<MissingKey>),
    /// Its key record is Invalid, or the key is not in force for this statement.
    Invalid,
}

/// What a valid row statement says, for the family-level rules a caller applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRow {
    /// The row id (CC 2.6.1.5), the same for every voice of the row.
    pub row_id: Digest32,
    /// The statement id, naming this one voice.
    pub statement_id: Digest32,
    /// The signer's key thumbprint.
    pub kid: Digest32,
    /// The CWT `iss`.
    pub iss: String,
    /// The CWT `sub`.
    pub sub: String,
    /// The header's row type (-70001).
    pub row_type: String,
    /// The header's family id (-70002).
    pub family: String,
    /// The payload's `author`, if present.
    pub author: Option<String>,
    /// The payload's `asserted_at`, POSIX milliseconds.
    pub asserted_at: u64,
    /// The decoded payload.
    pub payload: Value,
    /// The disclosures presented beside the statement, each opened against
    /// a digest the payload (or an earlier disclosure) carries.
    pub disclosures: Vec<disclosure::Disclosed>,
}

/// The keys a reader holds, by thumbprint.
pub trait KeyDirectory {
    /// What is known of the key whose RFC 9679 thumbprint is `kid`, for a
    /// statement asserted at `asserted_at` (POSIX ms).
    fn lookup(&self, kid: &Digest32, asserted_at: u64) -> KeyLookup;
}

impl KeyDirectory for BTreeMap<Digest32, CompositePublicKey> {
    fn lookup(&self, kid: &Digest32, _asserted_at: u64) -> KeyLookup {
        self.get(kid)
            .cloned()
            .map_or(KeyLookup::NotHeld, |k| KeyLookup::Held(Box::new(k)))
    }
}

/// The AKP COSE_Key of a composite public key, `{1: 7, 3: -70100, -1: pub}`.
#[must_use]
pub fn cose_key(pk: &CompositePublicKey) -> Value {
    Value::Map(vec![
        (Value::int(1), Value::Uint(7)),
        (Value::int(3), Value::int(COSE_ALG)),
        (Value::int(-1), Value::Bytes(pk.as_bytes().to_vec())),
    ])
}

/// The RFC 9679 thumbprint of a composite key: SHA-256 over the deterministic
/// encoding of its required members (kty, alg, pub), the key's `kid`.
#[must_use]
pub fn thumbprint(pk: &CompositePublicKey) -> Digest32 {
    Sha256::digest(cde::encode(&cose_key(pk))).into()
}

/// The identity reference of a thumbprint (RFC 9679 §5.7).
#[must_use]
pub fn identity_ref(thumbprint: &Digest32) -> String {
    use base64::Engine as _;
    let mut s = String::from(IDENTITY_REF_PREFIX);
    s.push_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(thumbprint));
    s
}

/// Does `s` match the CDDL `identity-ref`?
#[must_use]
pub fn is_identity_ref(s: &str) -> bool {
    let Some(t) = s.strip_prefix(IDENTITY_REF_PREFIX) else {
        return false;
    };
    let b = t.as_bytes();
    b.len() == 43
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
        && b"AEIMQUYcgkosw048".contains(&b[42])
}

/// Does `s` match the CDDL `family-id`?
#[must_use]
pub fn is_family_id(s: &str) -> bool {
    !s.is_empty()
        && s.split(':').all(|seg| {
            let b = seg.as_bytes();
            let head =
                |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'.';
            !b.is_empty() && head(b[0]) && b[1..].iter().all(|&c| head(c) || c == b'-')
        })
}

fn hash_digest(d: &Digest32) -> Value {
    Value::Array(vec![Value::int(HASH_ALG_SHA256), Value::Bytes(d.to_vec())])
}

fn sha256_cde(v: &Value) -> Digest32 {
    Sha256::digest(cde::encode(v)).into()
}

/// The row id: SHA-256 over `["CEG-row/2", type, family, sub, author / null, payload]`.
#[must_use]
pub fn row_id(
    row_type: &str,
    family: &str,
    sub: &str,
    author: Option<&str>,
    payload: &[u8],
) -> Digest32 {
    sha256_cde(&Value::Array(vec![
        Value::Text("CEG-row/2".into()),
        Value::Text(row_type.into()),
        Value::Text(family.into()),
        Value::Text(sub.into()),
        author.map_or(Value::Null, |a| Value::Text(a.into())),
        Value::Bytes(payload.to_vec()),
    ]))
}

/// The statement id: SHA-256 over `["CEG-statement-id/2", protected, payload]`.
#[must_use]
pub fn statement_id(protected: &[u8], payload: &[u8]) -> Digest32 {
    sha256_cde(&Value::Array(vec![
        Value::Text("CEG-statement-id/2".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(payload.to_vec()),
    ]))
}

/// The COSE Sig_structure for a Sign1 with empty external_aad.
#[must_use]
pub fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    cde::encode(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]))
}

fn malformed(member: &'static str) -> Invalid {
    Invalid::Malformed { member }
}

fn digest32(v: &Value, member: &'static str) -> Result<Digest32, Invalid> {
    v.as_bytes()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or(malformed(member))
}

/// Admit exactly the integer labels `allowed`, each at most once (the codec
/// already refuses duplicates), with `required` all present.
fn check_labels(
    m: &[(Value, Value)],
    required: &[i64],
    optional: &[i64],
    within: &'static str,
) -> Result<(), Invalid> {
    for (k, _) in m {
        match k.as_i64() {
            Some(l) if required.contains(&l) || optional.contains(&l) => {},
            _ => return Err(Invalid::UnexpectedMember { within }),
        }
    }
    for r in required {
        if !m.iter().any(|(k, _)| k.as_i64() == Some(*r)) {
            return Err(Invalid::UnexpectedMember { within });
        }
    }
    Ok(())
}

/// `ceg-value`: no null, no tag except 60 over a 32-byte digest as an array
/// element, simple(59) only as a map key over a non-empty array of digests.
fn check_ceg_value(v: &Value, in_array: bool) -> Result<(), Invalid> {
    match v {
        Value::Uint(_) | Value::Nint(_) | Value::Bytes(_) | Value::Text(_) | Value::Bool(_) => {
            Ok(())
        },
        Value::Array(a) => a.iter().try_for_each(|x| check_ceg_value(x, true)),
        Value::Map(m) => check_ceg_map(m),
        Value::Tag(TAG_REDACTED_ELEMENT, x) if in_array => {
            digest32(x, "redacted-element").map(|_| ())
        },
        Value::Tag(..) | Value::Null | Value::Simple(_) => Err(malformed("ceg-value")),
    }
}

fn check_ceg_map(m: &[(Value, Value)]) -> Result<(), Invalid> {
    for (k, v) in m {
        match k {
            Value::Simple(SIMPLE_REDACTED_KEYS) => check_redacted_keys(v)?,
            Value::Text(_) | Value::Uint(_) | Value::Nint(_) => check_ceg_value(v, false)?,
            _ => return Err(malformed("ceg-value key")),
        }
    }
    Ok(())
}

fn check_redacted_keys(v: &Value) -> Result<(), Invalid> {
    let a = v
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or(malformed("redacted_claim_keys"))?;
    a.iter()
        .try_for_each(|d| digest32(d, "redacted_claim_keys").map(|_| ()))
}

fn check_hash_digest(v: &Value, member: &'static str) -> Result<(), Invalid> {
    match v.as_array() {
        Some([alg, d]) if alg.as_i64() == Some(HASH_ALG_SHA256) => digest32(d, member).map(|_| ()),
        _ => Err(malformed(member)),
    }
}

fn check_row_ref(v: &Value, member: &'static str) -> Result<(), Invalid> {
    match v.as_array() {
        Some([ed, id]) if matches!(ed.as_u64(), Some(1 | 2)) => check_hash_digest(id, member),
        _ => Err(malformed(member)),
    }
}

/// A non-empty set of row-refs: sorted by encoding, no duplicate.
fn check_row_ref_set(v: &Value, member: &'static str) -> Result<(), Invalid> {
    let a = v
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or(malformed(member))?;
    a.iter().try_for_each(|r| check_row_ref(r, member))?;
    check_set(a, member)
}

fn check_set(a: &[Value], member: &'static str) -> Result<(), Invalid> {
    let enc: Vec<Vec<u8>> = a.iter().map(cde::encode).collect();
    if enc.windows(2).all(|w| w[0] < w[1]) {
        Ok(())
    } else {
        Err(Invalid::SetOrder { member })
    }
}

fn check_refs(v: &Value) -> Result<(), Invalid> {
    let m = v
        .as_map()
        .filter(|m| !m.is_empty())
        .ok_or(malformed("refs"))?;
    for (k, x) in m {
        match k.as_text() {
            Some(n @ ("head" | "prev" | "answers" | "target")) => check_row_ref(x, static_name(n))?,
            Some(n @ ("further_heads" | "trusted_through")) => {
                check_row_ref_set(x, static_name(n))?
            },
            Some("also") => {
                let roles = x
                    .as_map()
                    .filter(|r| !r.is_empty())
                    .ok_or(malformed("also"))?;
                for (role, set) in roles {
                    match role.as_text() {
                        Some("ack" | "cites") => check_row_ref_set(set, "also")?,
                        _ => return Err(Invalid::UnexpectedMember { within: "also" }),
                    }
                }
            },
            _ => return Err(Invalid::UnexpectedMember { within: "refs" }),
        }
    }
    Ok(())
}

fn static_name(n: &str) -> &'static str {
    match n {
        "head" => "head",
        "prev" => "prev",
        "answers" => "answers",
        "target" => "target",
        "further_heads" => "further_heads",
        _ => "trusted_through",
    }
}

fn opt_u64(m: &Value, key: &str) -> Result<Option<u64>, Invalid> {
    match m.get_text(key) {
        None => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or(Invalid::Malformed { member: "ms-time" }),
    }
}

fn int_in(v: Option<&Value>, lo: i64, hi: i64, member: &'static str) -> Result<(), Invalid> {
    match v {
        None => Ok(()),
        Some(x) => match x.as_i64() {
            Some(n) if (lo..=hi).contains(&n) => Ok(()),
            _ => Err(malformed(member)),
        },
    }
}

/// Check the envelope rules that need no family model; return `(author, asserted_at)`.
fn check_envelope(p: &Value) -> Result<(Option<String>, u64), Invalid> {
    let m = p.as_map().ok_or(malformed("attestation-envelope"))?;
    check_ceg_map(m)?;
    let author = match p.get_text("author") {
        None => None,
        Some(a) => Some(
            a.as_text()
                .filter(|s| is_identity_ref(s))
                .ok_or(malformed("author"))?
                .to_owned(),
        ),
    };
    if let Some(r) = p.get_text("refs") {
        check_refs(r)?;
    }
    if let Some(e) = p.get_text("evidence_refs") {
        let a = e
            .as_array()
            .filter(|a| !a.is_empty())
            .ok_or(malformed("evidence_refs"))?;
        a.iter()
            .try_for_each(|d| check_hash_digest(d, "evidence_refs"))?;
    }
    for k in ["carried", "seat_commitment"] {
        if let Some(d) = p.get_text(k) {
            check_hash_digest(d, "hash-digest")?;
        }
    }
    int_in(p.get_text("score"), -1_000_000, 1_000_000, "score")?;
    int_in(p.get_text("confidence"), 0, 1_000_000, "confidence")?;
    if let Some(w) = p.get_text("weight") {
        w.as_i64().ok_or(malformed("weight"))?;
    }
    match (p.get_text("passed"), p.get_text("total")) {
        (None, None) => {},
        (Some(pa), Some(to)) => {
            let pa = pa
                .as_u64()
                .filter(|n| *n <= u64::from(u32::MAX))
                .ok_or(malformed("passed"))?;
            let to = to
                .as_u64()
                .filter(|n| (1..=u64::from(u32::MAX)).contains(n))
                .ok_or(malformed("total"))?;
            if pa > to {
                return Err(malformed("passed"));
            }
        },
        _ => return Err(malformed("passed")),
    }
    let asserted_at = opt_u64(p, "asserted_at")?.ok_or(malformed("asserted_at"))?;
    for k in ["valid_from", "valid_until", "expires_at", "reason"] {
        opt_u64(p, k)?;
    }
    if let Some(s) = p.get_text("salt") {
        if s.as_bytes().map(<[u8]>::len) != Some(16) {
            return Err(malformed("salt"));
        }
    }
    if let Some(b) = p.get_text("body") {
        b.as_map().ok_or(malformed("body"))?;
        if let Some(n) = b.get_text("note") {
            if !n.as_text().is_some_and(|t| t.len() <= 2048) {
                return Err(malformed("body.note"));
            }
        }
    }
    Ok((author, asserted_at))
}

/// Read and verify one edition-2 row statement.
#[must_use]
pub fn verify_row_statement(bytes: &[u8], keys: &dyn KeyDirectory) -> Verdict {
    match read_row_statement(bytes, keys) {
        Ok(v) => v,
        Err(i) => Verdict::Invalid(i),
    }
}

fn read_row_statement(bytes: &[u8], keys: &dyn KeyDirectory) -> Result<Verdict, Invalid> {
    let nd = |part| move |error| Invalid::NotDeterministic { part, error };
    let top = cde::decode(bytes).map_err(nd("statement"))?;
    let Value::Tag(TAG_COSE_SIGN1, inner) = top else {
        return Err(Invalid::NotCoseSign1);
    };
    let [prot_b, unprot, payload_b, sig] = inner.as_array().ok_or(Invalid::NotCoseSign1)? else {
        return Err(Invalid::NotCoseSign1);
    };
    let prot_bytes = prot_b.as_bytes().ok_or(malformed("protected"))?;
    let payload_bytes = payload_b.as_bytes().ok_or(malformed("payload"))?;
    let sig = sig
        .as_bytes()
        .filter(|s| s.len() == SIGNATURE_LEN)
        .ok_or(malformed("signature"))?;

    // Protected header: exactly these members.
    let prot = cde::decode(prot_bytes).map_err(nd("protected"))?;
    let pm = prot.as_map().ok_or(malformed("protected"))?;
    check_labels(
        pm,
        &[H_ALG, H_CTY, H_KID, H_CWT, H_TYP, H_ROW_TYPE, H_FAMILY],
        &[],
        "protected",
    )?;
    if prot.get_int(H_ALG).and_then(Value::as_i64) != Some(COSE_ALG) {
        return Err(malformed("alg"));
    }
    if prot.get_int(H_CTY).and_then(Value::as_text) != Some(ROW_CTY) {
        return Err(malformed("cty"));
    }
    if prot.get_int(H_TYP).and_then(Value::as_text) != Some(ROW_TYP) {
        return Err(malformed("typ"));
    }
    let kid = digest32(prot.get_int(H_KID).expect("checked"), "kid")?;
    let row_type = prot
        .get_int(H_ROW_TYPE)
        .and_then(Value::as_text)
        .filter(|t| ROW_TYPES.contains(t))
        .ok_or(malformed("row-type"))?
        .to_owned();
    let family = prot
        .get_int(H_FAMILY)
        .and_then(Value::as_text)
        .filter(|f| is_family_id(f))
        .ok_or(malformed("family-id"))?
        .to_owned();

    let cwt = prot.get_int(H_CWT).expect("checked");
    let cm = cwt.as_map().ok_or(malformed("cwt-claims"))?;
    check_labels(
        cm,
        &[C_ISS, C_SUB, C_IAT, C_EDITION],
        &[C_NBF, C_EXP],
        "cwt-claims",
    )?;
    let iss = cwt
        .get_int(C_ISS)
        .and_then(Value::as_text)
        .filter(|s| is_identity_ref(s))
        .ok_or(malformed("iss"))?
        .to_owned();
    let sub = cwt
        .get_int(C_SUB)
        .and_then(Value::as_text)
        .ok_or(malformed("sub"))?
        .to_owned();
    let iat = cwt
        .get_int(C_IAT)
        .and_then(Value::as_u64)
        .ok_or(malformed("iat"))?;
    if cwt.get_int(C_EDITION).and_then(Value::as_u64) != Some(EDITION) {
        return Err(malformed("edition"));
    }

    // Unprotected: integer labels only; sd_claims is a non-empty array of disclosures.
    let um = unprot.as_map().ok_or(malformed("unprotected"))?;
    for (k, v) in um {
        match k.as_i64() {
            Some(H_SD_CLAIMS) => {
                let _ = v
                    .as_array()
                    .filter(|a| !a.is_empty())
                    .ok_or(malformed("sd_claims"))?;
                // Shapes and digests are checked by `disclosure::open` below.
            },
            Some(_) => {},
            None => {
                return Err(Invalid::UnexpectedMember {
                    within: "unprotected",
                })
            },
        }
    }

    // Payload.
    let payload = cde::decode(payload_bytes).map_err(nd("payload"))?;
    let (author, asserted_at) = check_envelope(&payload)?;
    if iat != asserted_at / 1000 {
        return Err(Invalid::TimeDisagreement { claim: "iat" });
    }
    for (claim, label, member) in [("nbf", C_NBF, "valid_from"), ("exp", C_EXP, "valid_until")] {
        let want = opt_u64(&payload, member)?.map(|ms| ms / 1000);
        let got = match cwt.get_int(label) {
            None => None,
            Some(v) => Some(v.as_u64().ok_or(malformed("cwt-claims"))?),
        };
        if want != got {
            return Err(Invalid::TimeDisagreement { claim });
        }
    }

    // The family is registered, and a `dimension` resolves to it (CC 3.1.7,
    // the one matcher; compared byte for byte with -70002).
    if !crate::namespace_match::is_registered_family_id(&family) {
        return Err(Invalid::UnregisteredFamily);
    }
    if let Some(d) = payload.get_text("dimension") {
        let d = d.as_text().ok_or(malformed("dimension"))?;
        match crate::namespace_match::resolve(d) {
            Ok(crate::namespace_match::Resolved::Family { family_id, .. })
                if family_id == family => {},
            Ok(crate::namespace_match::Resolved::Family { .. }) => {
                return Err(Invalid::DimensionFamily)
            },
            Ok(_) => return Err(Invalid::DimensionUnregistered),
            Err(r) => return Err(Invalid::DimensionRefused { token: r.token }),
        }
    }

    // Every disclosure presented must open a digest the payload carries.
    // Checked on every statement, so a repeated digest is refused even when
    // nothing is disclosed.
    let sd_claims: &[Value] = um
        .iter()
        .find(|(k, _)| k.as_i64() == Some(H_SD_CLAIMS))
        .and_then(|(_, v)| v.as_array())
        .unwrap_or(&[]);
    let disclosures = disclosure::open(&payload, sd_claims)?;

    // Key, then signature.
    let pk = match keys.lookup(&kid, asserted_at) {
        KeyLookup::Held(pk) => pk,
        KeyLookup::NotHeld => {
            return Ok(Verdict::Waiting {
                missing: vec![MissingKey::Kid(kid)],
            })
        },
        KeyLookup::Waiting(missing) => return Ok(Verdict::Waiting { missing }),
        KeyLookup::Invalid => return Err(Invalid::KeyNotValid),
    };
    if !bool::from(thumbprint(&pk).ct_eq(&kid)) {
        return Err(Invalid::KidMismatch);
    }
    pk.verify(&sig_structure(prot_bytes, payload_bytes), sig)
        .map_err(|_| Invalid::BadSignature)?;

    Ok(Verdict::Valid(Box::new(VerifiedRow {
        row_id: row_id(&row_type, &family, &sub, author.as_deref(), payload_bytes),
        statement_id: statement_id(prot_bytes, payload_bytes),
        kid,
        iss,
        sub,
        row_type,
        family,
        author,
        asserted_at,
        payload,
        disclosures,
    })))
}

/// What a reference names, by its form (the kernel's `Obj::from_reference`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceForm {
    /// `[-16, digest]`: a row (or object) id.
    Row(Digest32),
    /// An identity reference: a key.
    Key(String),
}

/// Type a reference by its form: a `hash-digest` is a row, an `identity-ref`
/// a key, anything else neither.
#[must_use]
pub fn classify_reference(v: &Value) -> Option<ReferenceForm> {
    match v {
        Value::Text(t) if is_identity_ref(t) => Some(ReferenceForm::Key(t.clone())),
        Value::Array(a) => match a.as_slice() {
            [alg, d] if alg.as_i64() == Some(HASH_ALG_SHA256) => d
                .as_bytes()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .map(ReferenceForm::Row),
            _ => None,
        },
        _ => None,
    }
}

/// The `typ`s of the signed objects that are not rows (CC 2.6.1, closed).
/// `ceg-boot-manifest/2`'s payload rule waits on its owner.
pub const OBJECT_TYPS: [&str; 3] = [
    "ceg-genesis-bundle/2",
    "ceg-revocation-snapshot/2",
    "ceg-boot-manifest/2",
];

/// A valid non-row object statement: header, key and signature checked;
/// the payload rule of its `typ` is the caller's (genesis bundle and
/// revocation snapshot readers build on this).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedObject {
    /// The object id: SHA-256 over `["CEG-object/2", typ, author / null, payload]`.
    pub object_id: Digest32,
    /// The statement id.
    pub statement_id: Digest32,
    /// The `typ`.
    pub typ: String,
    /// The signer's kid.
    pub kid: Digest32,
    /// The CWT `iss`.
    pub iss: String,
    /// The CWT `iat`, where the object states an instant.
    pub iat: Option<u64>,
    /// The payload's `author`, where it has one.
    pub author: Option<String>,
    /// The decoded payload.
    pub payload: Value,
}

/// The object id of a non-row signed object.
#[must_use]
pub fn object_id(typ: &str, author: Option<&str>, payload: &[u8]) -> Digest32 {
    sha256_cde(&Value::Array(vec![
        Value::Text("CEG-object/2".into()),
        Value::Text(typ.into()),
        author.map_or(Value::Null, |a| Value::Text(a.into())),
        Value::Bytes(payload.to_vec()),
    ]))
}

/// The answer for one non-row object statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectVerdict {
    /// Header, key and signature hold.
    Valid(Box<VerifiedObject>),
    /// A rule fails.
    Invalid(Invalid),
    /// The signer's key is not held.
    Waiting {
        /// The keys the reader would need.
        missing: Vec<MissingKey>,
    },
}

/// Read and verify one non-row object statement (`ceg-object-statement`):
/// protected exactly `{1: alg, 4: kid, 15: {1: iss, ?6: iat, -70003: 2}, 16: typ}`,
/// no `cty` and never -70001/-70002, a closed `typ`, a deterministic payload.
#[must_use]
pub fn verify_object_statement(bytes: &[u8], keys: &dyn KeyDirectory) -> ObjectVerdict {
    match read_object_statement(bytes, keys) {
        Ok(v) => v,
        Err(i) => ObjectVerdict::Invalid(i),
    }
}

fn read_object_statement(bytes: &[u8], keys: &dyn KeyDirectory) -> Result<ObjectVerdict, Invalid> {
    let nd = |part| move |error| Invalid::NotDeterministic { part, error };
    let top = cde::decode(bytes).map_err(nd("statement"))?;
    let Value::Tag(TAG_COSE_SIGN1, inner) = top else {
        return Err(Invalid::NotCoseSign1);
    };
    let [prot_b, unprot, payload_b, sig] = inner.as_array().ok_or(Invalid::NotCoseSign1)? else {
        return Err(Invalid::NotCoseSign1);
    };
    let prot_bytes = prot_b.as_bytes().ok_or(malformed("protected"))?;
    let payload_bytes = payload_b.as_bytes().ok_or(malformed("payload"))?;
    let sig = sig
        .as_bytes()
        .filter(|s| s.len() == SIGNATURE_LEN)
        .ok_or(malformed("signature"))?;
    let prot = cde::decode(prot_bytes).map_err(nd("protected"))?;
    let pm = prot.as_map().ok_or(malformed("protected"))?;
    // -70001 / -70002 (and cty) are refused here by the closed label set.
    check_labels(pm, &[H_ALG, H_KID, H_CWT, H_TYP], &[], "protected")?;
    if prot.get_int(H_ALG).and_then(Value::as_i64) != Some(COSE_ALG) {
        return Err(malformed("alg"));
    }
    let typ = prot
        .get_int(H_TYP)
        .and_then(Value::as_text)
        .filter(|t| OBJECT_TYPS.contains(t))
        .ok_or(malformed("typ"))?
        .to_owned();
    let kid = digest32(prot.get_int(H_KID).expect("checked"), "kid")?;
    let cwt = prot.get_int(H_CWT).expect("checked");
    let cm = cwt.as_map().ok_or(malformed("object-claims"))?;
    check_labels(cm, &[C_ISS, C_EDITION], &[C_IAT], "object-claims")?;
    let iss = cwt
        .get_int(C_ISS)
        .and_then(Value::as_text)
        .filter(|s| is_identity_ref(s))
        .ok_or(malformed("iss"))?
        .to_owned();
    if cwt.get_int(C_EDITION).and_then(Value::as_u64) != Some(EDITION) {
        return Err(malformed("edition"));
    }
    let iat = match cwt.get_int(C_IAT) {
        None => None,
        Some(v) => Some(v.as_u64().ok_or(malformed("iat"))?),
    };
    let um = unprot.as_map().ok_or(malformed("unprotected"))?;
    if um.iter().any(|(k, _)| k.as_i64().is_none()) {
        return Err(Invalid::UnexpectedMember {
            within: "unprotected",
        });
    }
    let payload = cde::decode(payload_bytes).map_err(nd("payload"))?;
    let author = match payload.get_text("author") {
        None => None,
        Some(a) => Some(
            a.as_text()
                .filter(|s| is_identity_ref(s))
                .ok_or(malformed("author"))?
                .to_owned(),
        ),
    };
    if let Some(r) = payload.get_text("refs") {
        check_refs(r)?;
    }
    let pk = match keys.lookup(&kid, iat.map_or(0, |s| s.saturating_mul(1000))) {
        KeyLookup::Held(pk) => pk,
        KeyLookup::NotHeld => {
            return Ok(ObjectVerdict::Waiting {
                missing: vec![MissingKey::Kid(kid)],
            })
        },
        KeyLookup::Waiting(missing) => return Ok(ObjectVerdict::Waiting { missing }),
        KeyLookup::Invalid => return Err(Invalid::KeyNotValid),
    };
    if !bool::from(thumbprint(&pk).ct_eq(&kid)) {
        return Err(Invalid::KidMismatch);
    }
    pk.verify(&sig_structure(prot_bytes, payload_bytes), sig)
        .map_err(|_| Invalid::BadSignature)?;
    Ok(ObjectVerdict::Valid(Box::new(VerifiedObject {
        object_id: object_id(&typ, author.as_deref(), payload_bytes),
        statement_id: statement_id(prot_bytes, payload_bytes),
        typ,
        kid,
        iss,
        iat,
        author,
        payload,
    })))
}

/// Mint a row statement. For producers and tests; the reader is
/// [`verify_row_statement`].
///
/// `payload` must be a map; it is written in the deterministic encoding.
/// `iat`, `nbf` and `exp` are derived from the payload's times.
///
/// # Errors
/// [`ciris_crypto::CryptoError`] from signing, or `InvalidSignature` if the
/// payload lacks `asserted_at`.
pub fn sign_row_statement(
    key: &ciris_crypto::composite::CompositeSigningKey,
    iss: &str,
    sub: &str,
    row_type: &str,
    family: &str,
    payload: &Value,
    unprotected: Vec<(Value, Value)>,
) -> Result<Vec<u8>, ciris_crypto::CryptoError> {
    let ms = |k: &str| payload.get_text(k).and_then(Value::as_u64);
    let asserted_at = ms("asserted_at").ok_or(ciris_crypto::CryptoError::InvalidSignature {
        reason: "payload has no asserted_at".into(),
    })?;
    let mut claims = vec![
        (Value::int(C_ISS), Value::Text(iss.into())),
        (Value::int(C_SUB), Value::Text(sub.into())),
        (Value::int(C_IAT), Value::Uint(asserted_at / 1000)),
        (Value::int(C_EDITION), Value::Uint(EDITION)),
    ];
    if let Some(v) = ms("valid_from") {
        claims.push((Value::int(C_NBF), Value::Uint(v / 1000)));
    }
    if let Some(v) = ms("valid_until") {
        claims.push((Value::int(C_EXP), Value::Uint(v / 1000)));
    }
    let protected = cde::encode(&Value::Map(vec![
        (Value::int(H_ALG), Value::int(COSE_ALG)),
        (Value::int(H_CTY), Value::Text(ROW_CTY.into())),
        (
            Value::int(H_KID),
            Value::Bytes(thumbprint(key.public_key()).to_vec()),
        ),
        (Value::int(H_CWT), Value::Map(claims)),
        (Value::int(H_TYP), Value::Text(ROW_TYP.into())),
        (Value::int(H_ROW_TYPE), Value::Text(row_type.into())),
        (Value::int(H_FAMILY), Value::Text(family.into())),
    ]));
    let payload_bytes = cde::encode(payload);
    let sig = key.sign(&sig_structure(&protected, &payload_bytes))?;
    Ok(cde::encode(&Value::Tag(
        TAG_COSE_SIGN1,
        Box::new(Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(unprotected),
            Value::Bytes(payload_bytes),
            Value::Bytes(sig),
        ])),
    )))
}

/// The `[-16, digest]` value of a digest, for building `refs`.
#[must_use]
pub fn hash_digest_value(d: &Digest32) -> Value {
    hash_digest(d)
}

/// An edition-2 `row-ref` to a row id.
#[must_use]
pub fn row_ref(d: &Digest32) -> Value {
    Value::Array(vec![Value::Uint(2), hash_digest(d)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::composite::CompositeSigningKey;

    fn key(n: u8) -> CompositeSigningKey {
        CompositeSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(100); 32])
    }

    fn dir(ks: &[&CompositeSigningKey]) -> BTreeMap<Digest32, CompositePublicKey> {
        ks.iter()
            .map(|k| (thumbprint(k.public_key()), k.public_key().clone()))
            .collect()
    }

    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn payload(author: &str) -> Value {
        Value::Map(vec![
            (t("author"), t(author)),
            (t("asserted_at"), Value::Uint(1_763_200_000_123)),
            (t("score"), Value::int(750_000)),
            (t("dimension"), t("evidence:safety_battery:capture:a:b:v1")),
        ])
    }

    fn signed(k: &CompositeSigningKey, p: &Value) -> (Vec<u8>, String) {
        let iss = identity_ref(&thumbprint(k.public_key()));
        let b = sign_row_statement(
            k,
            &iss,
            "subject",
            "scores",
            "evidence:.suite:.kind:.cell:.prefix",
            p,
            vec![],
        )
        .unwrap();
        (b, iss)
    }

    #[test]
    fn identity_ref_shape() {
        let k = key(1);
        let r = identity_ref(&thumbprint(k.public_key()));
        assert!(is_identity_ref(&r), "{r}");
        assert_eq!(r.len(), IDENTITY_REF_PREFIX.len() + 43);
        // A 43rd character carrying non-zero trailing bits is refused.
        let mut bad = r.clone();
        bad.pop();
        bad.push('B');
        assert!(!is_identity_ref(&bad));
    }

    #[test]
    fn family_id_shape() {
        for ok in [
            "accord:.",
            "evidence:.suite:.kind:.cell:.prefix",
            "key:record",
            "a-b",
        ] {
            assert!(is_family_id(ok), "{ok}");
        }
        for bad in ["", ":", "Accord", "a::b", "-a", "a:", "a b"] {
            assert!(!is_family_id(bad), "{bad}");
        }
    }

    #[test]
    fn valid_row_and_ids() {
        let k = key(1);
        let author = identity_ref(&thumbprint(k.public_key()));
        let p = payload(&author);
        let (b, iss) = signed(&k, &p);
        let Verdict::Valid(v) = verify_row_statement(&b, &dir(&[&k])) else {
            panic!("{:?}", verify_row_statement(&b, &dir(&[&k])));
        };
        assert_eq!(v.iss, iss);
        assert_eq!(v.author.as_deref(), Some(author.as_str()));
        assert_eq!(v.asserted_at, 1_763_200_000_123);
        assert_eq!(
            v.row_id,
            row_id(
                "scores",
                "evidence:.suite:.kind:.cell:.prefix",
                "subject",
                Some(&author),
                &cde::encode(&p)
            )
        );
        // A second voice over the same payload: same row id, different statement id.
        let k2 = key(2);
        let (b2, _) = signed(&k2, &p);
        let Verdict::Valid(v2) = verify_row_statement(&b2, &dir(&[&k2])) else {
            panic!()
        };
        assert_eq!(v.row_id, v2.row_id);
        assert_ne!(v.statement_id, v2.statement_id);
    }

    #[test]
    fn waiting_without_the_key_but_structure_first() {
        let k = key(1);
        let (b, _) = signed(&k, &payload(&identity_ref(&[0; 32])));
        assert_eq!(
            verify_row_statement(&b, &dir(&[])),
            Verdict::Waiting {
                missing: vec![MissingKey::Kid(thumbprint(k.public_key()))]
            }
        );
        // A structural fault is Invalid whatever keys are held, never Waiting.
        let iss = identity_ref(&thumbprint(k.public_key()));
        let p = Value::Map(vec![(t("asserted_at"), Value::Uint(5))]);
        let odd = sign_row_statement(
            &k,
            &iss,
            "s",
            "endorses",
            "evidence:.suite:.kind:.cell:.prefix",
            &p,
            vec![],
        )
        .unwrap();
        assert_eq!(
            verify_row_statement(&odd, &dir(&[])),
            Verdict::Invalid(Invalid::Malformed { member: "row-type" })
        );
        let no_time = sign_row_statement(
            &k,
            &iss,
            "s",
            "scores",
            "evidence:.suite:.kind:.cell:.prefix",
            &p,
            vec![],
        )
        .unwrap();
        assert!(matches!(
            verify_row_statement(&no_time, &dir(&[])),
            Verdict::Waiting { .. }
        ));
    }

    #[test]
    fn wrong_key_and_tamper() {
        let k = key(1);
        let other = key(3);
        let (b, _) = signed(&k, &payload(&identity_ref(&[0; 32])));
        // The directory holds another key under k's kid.
        let mut d = BTreeMap::new();
        d.insert(thumbprint(k.public_key()), other.public_key().clone());
        assert_eq!(
            verify_row_statement(&b, &d),
            Verdict::Invalid(Invalid::KidMismatch)
        );
        // Flip a signature byte.
        let mut bad = b.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert_eq!(
            verify_row_statement(&bad, &dir(&[&k])),
            Verdict::Invalid(Invalid::BadSignature)
        );
    }

    #[test]
    fn time_claims_must_agree() {
        let k = key(1);
        let iss = identity_ref(&thumbprint(k.public_key()));
        let p = Value::Map(vec![
            (t("asserted_at"), Value::Uint(10_999)),
            (t("valid_until"), Value::Uint(20_500)),
        ]);
        let b = sign_row_statement(
            &k,
            &iss,
            "s",
            "scores",
            "evidence:.suite:.kind:.cell:.prefix",
            &p,
            vec![],
        )
        .unwrap();
        assert!(matches!(
            verify_row_statement(&b, &dir(&[&k])),
            Verdict::Valid(_)
        ));
        // Re-sign a protected header whose iat disagrees.
        let bad = forge_protected(&k, &p, |claims| {
            for (kk, v) in claims.iter_mut() {
                if kk.as_i64() == Some(C_IAT) {
                    *v = Value::Uint(11);
                }
            }
        });
        assert_eq!(
            verify_row_statement(&bad, &dir(&[&k])),
            Verdict::Invalid(Invalid::TimeDisagreement { claim: "iat" })
        );
        let no_exp = forge_protected(&k, &p, |claims| {
            claims.retain(|(kk, _)| kk.as_i64() != Some(C_EXP))
        });
        assert_eq!(
            verify_row_statement(&no_exp, &dir(&[&k])),
            Verdict::Invalid(Invalid::TimeDisagreement { claim: "exp" })
        );
    }

    /// Sign a statement whose CWT claims `edit` changes after derivation.
    fn forge_protected(
        k: &CompositeSigningKey,
        p: &Value,
        mut edit: impl FnMut(&mut Vec<(Value, Value)>),
    ) -> Vec<u8> {
        let iss = identity_ref(&thumbprint(k.public_key()));
        let good = sign_row_statement(
            k,
            &iss,
            "s",
            "scores",
            "evidence:.suite:.kind:.cell:.prefix",
            p,
            vec![],
        )
        .unwrap();
        let Value::Tag(_, inner) = cde::decode(&good).unwrap() else {
            panic!()
        };
        let a = inner.as_array().unwrap();
        let Value::Map(mut pm) = cde::decode(a[0].as_bytes().unwrap()).unwrap() else {
            panic!()
        };
        for (kk, v) in pm.iter_mut() {
            if kk.as_i64() == Some(H_CWT) {
                let Value::Map(c) = v else { panic!() };
                edit(c);
            }
        }
        let prot = cde::encode(&Value::Map(pm));
        let pl = a[2].as_bytes().unwrap();
        let sig = k.sign(&sig_structure(&prot, pl)).unwrap();
        cde::encode(&Value::Tag(
            18,
            Box::new(Value::Array(vec![
                Value::Bytes(prot),
                Value::Map(vec![]),
                Value::Bytes(pl.to_vec()),
                Value::Bytes(sig),
            ])),
        ))
    }

    #[test]
    fn refs_sets_and_roles() {
        let k = key(1);
        let iss = identity_ref(&thumbprint(k.public_key()));
        let a = row_ref(&[1; 32]);
        let b = row_ref(&[2; 32]);
        let mk = |refs: Value| {
            let p = Value::Map(vec![(t("asserted_at"), Value::Uint(1)), (t("refs"), refs)]);
            let s = sign_row_statement(
                &k,
                &iss,
                "s",
                "supersedes",
                "evidence:.suite:.kind:.cell:.prefix",
                &p,
                vec![],
            )
            .unwrap();
            verify_row_statement(&s, &dir(&[&k]))
        };
        assert!(matches!(
            mk(Value::Map(vec![(
                t("further_heads"),
                Value::Array(vec![a.clone(), b.clone()])
            )])),
            Verdict::Valid(_)
        ));
        assert_eq!(
            mk(Value::Map(vec![(
                t("further_heads"),
                Value::Array(vec![b.clone(), a.clone()])
            )])),
            Verdict::Invalid(Invalid::SetOrder {
                member: "further_heads"
            })
        );
        assert_eq!(
            mk(Value::Map(vec![(
                t("further_heads"),
                Value::Array(vec![a.clone(), a.clone()])
            )])),
            Verdict::Invalid(Invalid::SetOrder {
                member: "further_heads"
            })
        );
        assert_eq!(
            mk(Value::Map(vec![])),
            Verdict::Invalid(Invalid::Malformed { member: "refs" })
        );
        assert_eq!(
            mk(Value::Map(vec![(
                t("also"),
                Value::Map(vec![(t("quotes"), Value::Array(vec![a.clone()]))])
            )])),
            Verdict::Invalid(Invalid::UnexpectedMember { within: "also" })
        );
        assert!(matches!(
            mk(Value::Map(vec![(
                t("also"),
                Value::Map(vec![(t("ack"), Value::Array(vec![a.clone()]))])
            )])),
            Verdict::Valid(_)
        ));
        assert_eq!(
            mk(Value::Map(vec![(t("pointer"), a)])),
            Verdict::Invalid(Invalid::UnexpectedMember { within: "refs" })
        );
    }

    #[test]
    fn values_refused() {
        let k = key(1);
        let iss = identity_ref(&thumbprint(k.public_key()));
        let mk = |extra: (Value, Value)| {
            let p = Value::Map(vec![(t("asserted_at"), Value::Uint(1)), extra]);
            let s = sign_row_statement(
                &k,
                &iss,
                "s",
                "scores",
                "evidence:.suite:.kind:.cell:.prefix",
                &p,
                vec![],
            )
            .unwrap();
            verify_row_statement(&s, &dir(&[&k]))
        };
        for (name, v) in [
            ("null", Value::Null),
            ("tag", Value::Tag(1, Box::new(Value::Uint(0)))),
            ("simple", Value::Simple(99)),
        ] {
            assert!(
                matches!(mk((t("x"), v)), Verdict::Invalid(Invalid::Malformed { .. })),
                "{name}"
            );
        }
        assert!(matches!(
            mk((t("score"), Value::int(1_000_001))),
            Verdict::Invalid(_)
        ));
        assert!(matches!(
            mk((t("salt"), Value::Bytes(vec![0; 15]))),
            Verdict::Invalid(_)
        ));
        // Redaction forms are admitted.
        assert!(matches!(
            mk((
                Value::Simple(59),
                Value::Array(vec![Value::Bytes(vec![7; 32])])
            )),
            Verdict::Valid(_)
        ));
        assert!(matches!(
            mk((
                t("list"),
                Value::Array(vec![
                    Value::Uint(1),
                    Value::Tag(60, Box::new(Value::Bytes(vec![7; 32])))
                ])
            )),
            Verdict::Valid(_)
        ));
    }

    #[test]
    fn non_deterministic_bytes_refused() {
        let k = key(1);
        let (b, _) = signed(&k, &payload(&identity_ref(&[0; 32])));
        // Re-encode the outer tag's array head in a long form.
        let mut long = vec![0xd2, 0x98, 0x04];
        long.extend_from_slice(&b[2..]);
        assert!(matches!(
            verify_row_statement(&long, &dir(&[&k])),
            Verdict::Invalid(Invalid::NotDeterministic {
                part: "statement",
                ..
            })
        ));
        // A COSE_Sign1 without the tag.
        assert_eq!(
            verify_row_statement(&b[1..], &dir(&[&k])),
            Verdict::Invalid(Invalid::NotCoseSign1)
        );
    }
}
