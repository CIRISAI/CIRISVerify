//! SCITT receipts (RFC 9942 COSE Receipts over the RFC 9162 SHA-256 tree, as
//! RFC 9943 carries them; CC 2.7.11): what a Transparency Service returns
//! for a signed statement it registered, the RFC 9162 inclusion and
//! consistency proofs, and the k-of-n count of a lineage head's receipts
//! from distinct charter services.
//!
//! ```text
//! statement   = #6.18([protected, unprotected, payload, signature])   (a row statement)
//!   unprotected ? 394 (receipts) => [+ bstr .cbor receipt]             (unsigned; carried, never signed)
//! leaf        = CDE(#6.18([protected, {}, payload, signature]))       (the WHOLE unprotected header emptied)
//! leaf_hash   = SHA-256(0x00 ‖ leaf)                                  (RFC 9162 §2.1.1)
//! receipt     = #6.18([protected, unprotected, nil / root, signature])
//!   protected   { 1: alg, 395 (vds): 1, 4: kid, 15: { 1: iss (the service), 2: sub (the statement's sub), 6: iat } }
//!   unprotected { 396 (vdp): { -1: [+ bstr .cbor [tree_size, leaf_index, [* bstr32]]], * int => [+ bstr] } }
//!   signature over Sig_structure("Signature1", protected, h'', root)
//! ```
//!
//! **Holding.** The `receipts` header is unsigned, so [`receipts_of`] holds
//! only items that are well-formed receipts (the tag-18 four-part shape in
//! deterministic encoding, `vdp` a map of int keys to non-empty arrays of
//! bstr), sorted in byte order and unique, at most [`MAX_RECEIPTS`] (the
//! first in byte order); any other item is ignored, never a fault of the
//! statement. [`merge_receipts`] unions two copies of one statement.
//!
//! **Verifying.** Only `vdp` key -1 is read. Each inclusion proof is exactly
//! `[tree_size, leaf_index, path]`, path hashes 32 bytes, at most
//! [`MAX_INCLUSION_PATH`]. Every proof is tried; the receipt verifies when any
//! reconstructed root verifies under the key, and every such proof is
//! returned (the first in order is reported in the top-level fields). An
//! attached payload must equal the root. The protected `alg` must equal the
//! key's exactly. The CWT `iat`, `iss` and `sub` are read from the protected
//! header only and returned as signed; none is ever a fault, and this module
//! reads no clock.
//!
//! A receipt adds no authority: it witnesses that a service registered what
//! it covers. Which services a reader trusts, and how it finds their keys, is
//! the caller's (an owner's `transparency` edge for admission, a charter's
//! named services for a head). The two paths are distinct: [`verify_receipt`]
//! takes any [`ReceiptKey`]; a head's count ([`head_receipt_services`]) takes
//! composite keys only and needs an `iat`.
//!
//! Known answers: `tests/vectors/edition2/receipts/receipts_v1.json`, from
//! `gen_receipts.py`, independent of this code.

#[allow(unused_imports)]
use crate::prelude::*;

use ciris_crypto::composite::{CompositePublicKey, CompositeSigningKey};
use ciris_crypto::{ClassicalVerifier, Ed25519Verifier, P256Verifier};
use subtle::ConstantTimeEq;

use super::Digest32;
use crate::cde::{self, Value};
use crate::transparency::{hash_leaf, hash_node};

/// The COSE header label of the `receipts` parameter (RFC 9942 §2).
pub const RECEIPTS_LABEL: i64 = 394;
/// The protected header label of the verifiable data structure (`vds`).
pub const VDS_LABEL: i64 = 395;
/// The unprotected header label of the verifiable data proofs (`vdp`).
pub const VDP_LABEL: i64 = 396;
/// `vds` RFC9162_SHA256.
pub const VDS_RFC9162_SHA256: i64 = 1;
/// The `vdp` key of the inclusion proofs.
pub const INCLUSION_PROOFS: i64 = -1;
/// The most receipts a statement holds.
pub const MAX_RECEIPTS: usize = 16;
/// The longest inclusion or consistency path read.
pub const MAX_INCLUSION_PATH: usize = 64;

/// COSE `alg` EdDSA.
pub const ALG_EDDSA: i64 = -8;
/// COSE `alg` Ed25519 (fully specified).
pub const ALG_ED25519: i64 = -19;
/// COSE `alg` ES256.
pub const ALG_ES256: i64 = -7;
/// COSE `alg` ESP256 (fully specified).
pub const ALG_ESP256: i64 = -9;
/// COSE `alg` ML-DSA-65.
pub const ALG_ML_DSA_65: i64 = -49;
/// COSE `alg` of the CC 2.6.1.7 composite.
pub const ALG_COMPOSITE: i64 = ciris_crypto::composite::COSE_ALG;

const TAG_COSE_SIGN1: u64 = 18;
const H_ALG: i64 = 1;
const H_KID: i64 = 4;
const H_CWT: i64 = 15;
const C_ISS: i64 = 1;
const C_SUB: i64 = 2;
const C_IAT: i64 = 6;

fn int_key(n: i64) -> Value {
    if n >= 0 {
        Value::Uint(n as u64)
    } else {
        Value::Nint((-1 - n) as u64)
    }
}

fn sorted_map(mut m: Vec<(Value, Value)>) -> Value {
    m.sort_by_key(|a| cde::encode(&a.0));
    Value::Map(m)
}

/// A Transparency Service's key, as a reader holds it, with its exact `alg`.
// The composite variant is the large one; keys are few and short-lived on a
// reader's stack, so boxing would buy nothing but an allocation.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum ReceiptKey {
    /// The CC 2.6.1.7 composite (alg -70100); its `kid` is its thumbprint.
    Composite(CompositePublicKey),
    /// Ed25519, under exactly `alg` (-8 or -19).
    Ed25519 {
        /// The `alg` the COSE_Key names.
        alg: i64,
        /// The 32-byte public key.
        x: [u8; 32],
        /// The COSE_Key's `kid`, if it names one.
        kid: Option<Vec<u8>>,
    },
    /// ECDSA P-256 with SHA-256, under exactly `alg` (-7 or -9); signature `r ‖ s`.
    P256 {
        /// The `alg` the COSE_Key names.
        alg: i64,
        /// The x coordinate.
        x: [u8; 32],
        /// The y coordinate.
        y: [u8; 32],
        /// The COSE_Key's `kid`, if it names one.
        kid: Option<Vec<u8>>,
    },
    /// ML-DSA-65 (alg -49), empty context.
    MlDsa65 {
        /// The 1952-byte public key.
        public: Vec<u8>,
        /// The COSE_Key's `kid`, if it names one.
        kid: Option<Vec<u8>>,
    },
}

impl ReceiptKey {
    /// The exact COSE `alg` of the key.
    #[must_use]
    pub fn alg(&self) -> i64 {
        match self {
            Self::Composite(_) => ALG_COMPOSITE,
            Self::Ed25519 { alg, .. } | Self::P256 { alg, .. } => *alg,
            Self::MlDsa65 { .. } => ALG_ML_DSA_65,
        }
    }

    /// The `kid` a receipt under this key may name: the composite's
    /// thumbprint, or the COSE_Key's own `kid`. `None` means a receipt's
    /// `kid` carries no weight for this key.
    #[must_use]
    pub fn kid(&self) -> Option<Vec<u8>> {
        match self {
            Self::Composite(pk) => Some(super::thumbprint(pk).to_vec()),
            Self::Ed25519 { kid, .. } | Self::P256 { kid, .. } | Self::MlDsa65 { kid, .. } => {
                kid.clone()
            },
        }
    }

    /// The RFC 9679 thumbprint: SHA-256 of the deterministic encoding of the
    /// key's required members (OKP `{1, -1, -2}`; EC2 `{1, -1, -2, -3}`; AKP
    /// `{1, 3, -1}`, as the composite's own thumbprint is).
    #[must_use]
    pub fn thumbprint(&self) -> Digest32 {
        use sha2::Digest as _;
        let m = match self {
            Self::Composite(pk) => return super::thumbprint(pk),
            Self::Ed25519 { x, .. } => vec![
                (int_key(1), Value::Uint(1)),
                (int_key(-1), Value::Uint(6)),
                (int_key(-2), Value::Bytes(x.to_vec())),
            ],
            Self::P256 { x, y, .. } => vec![
                (int_key(1), Value::Uint(2)),
                (int_key(-1), Value::Uint(1)),
                (int_key(-2), Value::Bytes(x.to_vec())),
                (int_key(-3), Value::Bytes(y.to_vec())),
            ],
            Self::MlDsa65 { public, .. } => vec![
                (int_key(1), Value::Uint(7)),
                (int_key(3), int_key(ALG_ML_DSA_65)),
                (int_key(-1), Value::Bytes(public.clone())),
            ],
        };
        sha2::Sha256::digest(cde::encode(&sorted_map(m))).into()
    }

    fn material(&self) -> Vec<u8> {
        match self {
            Self::Composite(pk) => pk.as_bytes().to_vec(),
            Self::Ed25519 { x, .. } => x.to_vec(),
            Self::P256 { x, y, .. } => [x.as_slice(), y].concat(),
            Self::MlDsa65 { public, .. } => public.clone(),
        }
    }

    fn verify(&self, tbs: &[u8], sig: &[u8]) -> bool {
        match self {
            Self::Composite(pk) => pk.verify(tbs, sig).is_ok(),
            Self::Ed25519 { x, .. } => Ed25519Verifier::new().verify(x, tbs, sig).unwrap_or(false),
            Self::P256 { x, y, .. } => {
                let sec1 = [&[4u8][..], x, y].concat();
                sig.len() == 64 && P256Verifier::new().verify(&sec1, tbs, sig).unwrap_or(false)
            },
            Self::MlDsa65 { public, .. } => {
                use ciris_crypto::PqcVerifier;
                ciris_crypto::MlDsa65Verifier::new()
                    .verify(public, tbs, sig)
                    .unwrap_or(false)
            },
        }
    }
}

/// Read a COSE_Key that names its `alg` (CC 2.7.11), with the key type and
/// curve that `alg` requires: OKP crv 6 with -8 or -19; EC2 crv 1 with -7 or
/// -9; AKP with -49 or -70100, the public key at -1.
///
/// # Errors
///
/// [`ReceiptError::Malformed`] for any other shape.
pub fn parse_cose_key(bytes: &[u8]) -> Result<ReceiptKey, ReceiptError> {
    let bad = ReceiptError::Malformed;
    let m = cde::decode(bytes).map_err(|_| bad.clone())?;
    if m.as_map().is_none() || cde::encode(&m) != bytes {
        return Err(bad);
    }
    let int = |l: i64| m.get_int(l).and_then(Value::as_i64);
    let byt = |l: i64| m.get_int(l).and_then(Value::as_bytes);
    let b32 = |l: i64| byt(l).and_then(|b| <[u8; 32]>::try_from(b).ok());
    let kid = byt(2).map(<[u8]>::to_vec);
    match (int(1), int(3)) {
        (Some(1), Some(alg @ (ALG_EDDSA | ALG_ED25519))) if int(-1) == Some(6) => {
            Ok(ReceiptKey::Ed25519 {
                alg,
                x: b32(-2).ok_or(bad)?,
                kid,
            })
        },
        (Some(2), Some(alg @ (ALG_ES256 | ALG_ESP256))) if int(-1) == Some(1) => {
            Ok(ReceiptKey::P256 {
                alg,
                x: b32(-2).ok_or(bad.clone())?,
                y: b32(-3).ok_or(bad)?,
                kid,
            })
        },
        (Some(7), Some(ALG_ML_DSA_65)) => {
            let p = byt(-1).filter(|p| p.len() == 1952).ok_or(bad)?;
            Ok(ReceiptKey::MlDsa65 {
                public: p.to_vec(),
                kid,
            })
        },
        (Some(7), Some(ALG_COMPOSITE)) => {
            CompositePublicKey::from_bytes(byt(-1).ok_or(bad.clone())?)
                .map(ReceiptKey::Composite)
                .map_err(|_| bad)
        },
        _ => Err(bad),
    }
}

/// Why a receipt does not verify. A reader treats every one alike (the
/// receipt is not held); the kinds are for diagnosis and vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiptError {
    /// Not a receipt of its shape, or the statement is not a COSE_Sign1.
    Malformed,
    /// `vds` is not RFC9162_SHA256.
    UnsupportedVds,
    /// The protected `alg` is not the key's.
    AlgMismatch,
    /// The receipt names a `kid` that is not the key's.
    KeyMismatch,
    /// No inclusion proof reconstructs a root from the leaf (or an attached
    /// payload is not that root).
    BadInclusionPath,
    /// The signature does not verify over any reconstructed root.
    BadSignature,
    /// A head receipt names no `iat`: nothing dates it, so it does not count.
    NoInstant,
    /// The receipt's CWT `sub` is not the registered statement's own `sub`
    /// (RFC 9943: the receipt is about the statement's subject).
    SubjectMismatch,
    /// A head receipt's CWT `iss` is not the charter service it is counted for.
    IssuerMismatch,
}

impl ReceiptError {
    /// A stable name.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            Self::Malformed => "receipt_malformed",
            Self::UnsupportedVds => "receipt_unsupported_vds",
            Self::AlgMismatch => "receipt_alg_mismatch",
            Self::KeyMismatch => "receipt_key_mismatch",
            Self::BadInclusionPath => "receipt_bad_inclusion_path",
            Self::BadSignature => "receipt_bad_signature",
            Self::NoInstant => "receipt_no_instant",
            Self::SubjectMismatch => "receipt_subject_mismatch",
            Self::IssuerMismatch => "receipt_issuer_mismatch",
        }
    }
}

/// A receipt's protected header, read without verifying anything, so a
/// reader can say which service a receipt that fails named. Every member is
/// as written (`kid` any length, `iss` / `sub` any text); the caller decides
/// what it matches on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptHeader {
    /// `alg` (1).
    pub alg: Option<i64>,
    /// `vds` (395).
    pub vds: Option<i64>,
    /// `kid` (4).
    pub kid: Option<Vec<u8>>,
    /// CWT `iss` (15 / 1).
    pub iss: Option<String>,
    /// CWT `sub` (15 / 2): the registered statement's own `sub` (RFC 9943).
    pub sub: Option<String>,
    /// CWT `iat` (15 / 6), seconds.
    pub iat: Option<u64>,
}

fn header_of(ph: &Value) -> ReceiptHeader {
    let cwt = ph.get_int(H_CWT);
    let claim_text = |c: i64| {
        cwt.and_then(|w| w.get_int(c))
            .and_then(Value::as_text)
            .map(str::to_owned)
    };
    ReceiptHeader {
        alg: ph.get_int(H_ALG).and_then(Value::as_i64),
        vds: ph.get_int(VDS_LABEL).and_then(Value::as_i64),
        kid: ph
            .get_int(H_KID)
            .and_then(Value::as_bytes)
            .map(<[u8]>::to_vec),
        iss: claim_text(C_ISS),
        sub: claim_text(C_SUB),
        iat: cwt.and_then(|w| w.get_int(C_IAT)).and_then(Value::as_u64),
    }
}

/// Read a receipt's protected header (see [`ReceiptHeader`]).
///
/// # Errors
///
/// [`ReceiptError::Malformed`] when it is not a COSE_Sign1 with a map for a
/// protected header.
pub fn receipt_header(receipt: &[u8]) -> Result<ReceiptHeader, ReceiptError> {
    let [p, ..] = sign1(receipt).ok_or(ReceiptError::Malformed)?;
    let ph = p
        .as_bytes()
        .and_then(|b| cde::decode(b).ok())
        .ok_or(ReceiptError::Malformed)?;
    if ph.as_map().is_none() {
        return Err(ReceiptError::Malformed);
    }
    Ok(header_of(&ph))
}

/// One RFC 9162 inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// The tree size.
    pub tree_size: u64,
    /// The leaf's index.
    pub leaf_index: u64,
    /// The audit path, leaf to root.
    pub path: Vec<Digest32>,
}

/// What a verified receipt states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReceipt {
    /// The tree size of the first proof that verified.
    pub tree_size: u64,
    /// The leaf index in it.
    pub leaf_index: u64,
    /// The root that proof reconstructs.
    pub root: Digest32,
    /// Every proof that verified, in the receipt's order, with its root.
    pub verified: Vec<(InclusionProof, Digest32)>,
    /// The protected header.
    pub header: ReceiptHeader,
    /// The protected `kid`, if named (also in `header`).
    pub kid: Option<Vec<u8>>,
    /// The CWT `iat`, seconds, if named (also in `header`).
    pub iat: Option<u64>,
}

fn sign1(bytes: &[u8]) -> Option<[Value; 4]> {
    if bytes.is_empty() {
        return None;
    }
    let v = cde::decode(bytes).ok()?;
    let Value::Tag(TAG_COSE_SIGN1, inner) = v else {
        return None;
    };
    let Value::Array(a) = *inner else { return None };
    <[Value; 4]>::try_from(a).ok()
}

fn sign1_value(p: Value, u: Value, pl: Value, s: Value) -> Vec<u8> {
    cde::encode(&Value::Tag(
        TAG_COSE_SIGN1,
        Box::new(Value::Array(vec![p, u, pl, s])),
    ))
}

/// The statement's leaf: its deterministic encoding with the WHOLE
/// unprotected header emptied (CC 2.7.11), so the receipts it carries, and
/// anything else unsigned, never change what was registered.
///
/// # Errors
///
/// [`ReceiptError::Malformed`] when `statement` is not a COSE_Sign1.
pub fn leaf_of(statement: &[u8]) -> Result<Vec<u8>, ReceiptError> {
    let [p, u, pl, s] = sign1(statement).ok_or(ReceiptError::Malformed)?;
    if p.as_bytes().is_none() || u.as_map().is_none() || s.as_bytes().is_none() {
        return Err(ReceiptError::Malformed);
    }
    Ok(sign1_value(p, Value::Map(Vec::new()), pl, s))
}

fn is_receipt(b: &[u8]) -> bool {
    let Some([p, u, pl, s]) = sign1(b) else {
        return false;
    };
    let vdp_ok = u
        .get_int(VDP_LABEL)
        .and_then(Value::as_map)
        .is_some_and(|m| {
            !m.is_empty()
                && m.iter().all(|(k, v)| {
                    k.as_i64().is_some()
                        && v.as_array().is_some_and(|a| {
                            !a.is_empty() && a.iter().all(|x| x.as_bytes().is_some())
                        })
                })
        });
    p.as_bytes().is_some()
        && s.as_bytes().is_some()
        && matches!(pl, Value::Null | Value::Bytes(_))
        && vdp_ok
        && sign1_value(p, u, pl, s) == b
}

fn hold(mut rs: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    rs.retain(|r| is_receipt(r));
    rs.sort();
    rs.dedup();
    rs.truncate(MAX_RECEIPTS);
    rs
}

/// The receipts a statement holds: the well-formed receipts of its
/// `receipts` header, sorted in byte order, unique, the first
/// [`MAX_RECEIPTS`]. Every other item is ignored, never a fault.
#[must_use]
pub fn receipts_of(statement: &[u8]) -> Vec<Vec<u8>> {
    let Some([_, u, _, _]) = sign1(statement) else {
        return Vec::new();
    };
    hold(
        u.get_int(RECEIPTS_LABEL)
            .and_then(Value::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(Value::as_bytes)
            .map(<[u8]>::to_vec)
            .collect(),
    )
}

/// The statement with exactly `receipts` held as its `receipts` header (the
/// well-formed ones, sorted, unique, the first [`MAX_RECEIPTS`]); the rest
/// of the unprotected header is kept.
///
/// # Errors
///
/// [`ReceiptError::Malformed`] when `statement` is not a COSE_Sign1.
pub fn with_receipts(statement: &[u8], receipts: &[Vec<u8>]) -> Result<Vec<u8>, ReceiptError> {
    let [p, u, pl, s] = sign1(statement).ok_or(ReceiptError::Malformed)?;
    let Value::Map(mut m) = u else {
        return Err(ReceiptError::Malformed);
    };
    m.retain(|(k, _)| k.as_i64() != Some(RECEIPTS_LABEL));
    let rs = hold(receipts.to_vec());
    if !rs.is_empty() {
        m.push((
            int_key(RECEIPTS_LABEL),
            Value::Array(rs.into_iter().map(Value::Bytes).collect()),
        ));
    }
    Ok(sign1_value(p, sorted_map(m), pl, s))
}

/// Why two copies of a statement were not merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MergeError {
    /// One of them is not a COSE_Sign1.
    Malformed,
    /// They are not one statement (protected header or payload differ).
    DifferentStatement,
    /// The union would hold more than [`MAX_RECEIPTS`].
    TooMany,
}

/// The held copy with the receipts of an offered copy of the same statement
/// added: the union, sorted, unique; a held receipt is never dropped. The
/// rest of the held copy's unprotected header is kept.
///
/// # Errors
///
/// [`MergeError`].
pub fn merge_receipts(held: &[u8], offered: &[u8]) -> Result<Vec<u8>, MergeError> {
    let ([hp, _, hpl, _], [op, _, opl, _]) = (
        sign1(held).ok_or(MergeError::Malformed)?,
        sign1(offered).ok_or(MergeError::Malformed)?,
    );
    if hp != op || hpl != opl {
        return Err(MergeError::DifferentStatement);
    }
    let mut all = receipts_of(held);
    all.extend(receipts_of(offered));
    all.sort();
    all.dedup();
    if all.len() > MAX_RECEIPTS {
        return Err(MergeError::TooMany);
    }
    with_receipts(held, &all).map_err(|_| MergeError::Malformed)
}

/// RFC 9162 §2.1.3.2: the root an inclusion proof reconstructs for
/// `leaf_hash` at `leaf_index` in a tree of `tree_size` leaves, or `None`.
#[must_use]
pub fn inclusion_root(
    leaf_hash: &Digest32,
    leaf_index: u64,
    tree_size: u64,
    path: &[Digest32],
) -> Option<Digest32> {
    if leaf_index >= tree_size || path.len() > MAX_INCLUSION_PATH {
        return None;
    }
    let (mut fnode, mut snode, mut r) = (leaf_index, tree_size - 1, *leaf_hash);
    for p in path {
        if snode == 0 {
            return None;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = hash_node(p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = hash_node(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    (snode == 0).then_some(r)
}

/// RFC 9162 §2.1.4.2: whether `proof` shows the tree of `old_size` leaves
/// with root `old_root` is a prefix of the tree of `new_size` with
/// `new_root`. Two receipts of one service whose roots fail this are
/// evidence of equivocation.
#[must_use]
pub fn consistent(
    old_size: u64,
    old_root: &Digest32,
    new_size: u64,
    new_root: &Digest32,
    proof: &[Digest32],
) -> bool {
    if old_size == 0 || old_size > new_size || proof.len() > MAX_INCLUSION_PATH {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && bool::from(old_root.ct_eq(new_root));
    }
    let mut path: Vec<Digest32> = proof.to_vec();
    if old_size.is_power_of_two() {
        path.insert(0, *old_root);
    }
    let Some((first, rest)) = path.split_first() else {
        return false;
    };
    let (mut fnode, mut snode) = (old_size - 1, new_size - 1);
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }
    let (mut fr, mut sr) = (*first, *first);
    for c in rest {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            fr = hash_node(c, &fr);
            sr = hash_node(c, &sr);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            sr = hash_node(&sr, c);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && bool::from(fr.ct_eq(old_root)) && bool::from(sr.ct_eq(new_root))
}

fn split(n: usize) -> usize {
    let k = n.next_power_of_two() / 2;
    if k == n {
        n / 2
    } else {
        k
    }
}

/// RFC 9162 §2.1.1 MTH over leaf hashes (the empty tree is SHA-256 of nothing).
#[must_use]
pub fn tree_root(hashes: &[Digest32]) -> Digest32 {
    match hashes.len() {
        0 => {
            use sha2::Digest as _;
            sha2::Sha256::digest([]).into()
        },
        1 => hashes[0],
        n => hash_node(
            &tree_root(&hashes[..split(n)]),
            &tree_root(&hashes[split(n)..]),
        ),
    }
}

fn path_of(m: usize, hashes: &[Digest32]) -> Vec<Digest32> {
    let n = hashes.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = split(n);
    if m < k {
        let mut p = path_of(m, &hashes[..k]);
        p.push(tree_root(&hashes[k..]));
        p
    } else {
        let mut p = path_of(m - k, &hashes[k..]);
        p.push(tree_root(&hashes[..k]));
        p
    }
}

/// RFC 9162 §2.1.3.1: the inclusion proof of leaf `index`, or `None` when it
/// is out of range.
#[must_use]
pub fn inclusion_proof(index: usize, hashes: &[Digest32]) -> Option<InclusionProof> {
    (index < hashes.len()).then(|| InclusionProof {
        tree_size: hashes.len() as u64,
        leaf_index: index as u64,
        path: path_of(index, hashes),
    })
}

fn subproof(m: usize, d: &[Digest32], b: bool) -> Vec<Digest32> {
    let n = d.len();
    if m == n {
        return if b { Vec::new() } else { vec![tree_root(d)] };
    }
    let k = split(n);
    if m <= k {
        let mut p = subproof(m, &d[..k], b);
        p.push(tree_root(&d[k..]));
        p
    } else {
        let mut p = subproof(m - k, &d[k..], false);
        p.push(tree_root(&d[..k]));
        p
    }
}

/// RFC 9162 §2.1.4.1: the consistency proof from the first `old_size`
/// leaves to all of `hashes`, or `None` when `old_size` is 0 or too large.
#[must_use]
pub fn consistency_proof(old_size: usize, hashes: &[Digest32]) -> Option<Vec<Digest32>> {
    (old_size >= 1 && old_size <= hashes.len()).then(|| subproof(old_size, hashes, true))
}

fn proof_of(b: &[u8]) -> Option<InclusionProof> {
    let v = cde::decode(b).ok()?;
    let [size, index, path] = v.as_array()? else {
        return None;
    };
    let path = path.as_array()?;
    if path.len() > MAX_INCLUSION_PATH {
        return None;
    }
    let path = path
        .iter()
        .map(|h| <Digest32>::try_from(h.as_bytes()?).ok())
        .collect::<Option<Vec<_>>>()?;
    Some(InclusionProof {
        tree_size: size.as_u64()?,
        leaf_index: index.as_u64()?,
        path,
    })
}

/// Verify one receipt over `statement` under a service's `key` (RFC 9942
/// §5.2.1 over RFC 9162 SHA-256). The ADMISSION path (CC 2.7.11): the key is
/// whatever an owner's `transparency` edge names. A head's count uses
/// [`verify_head_receipt`].
///
/// # Errors
///
/// The first [`ReceiptError`], in the order: shape, `vds`, `alg`, `kid`,
/// inclusion, signature.
pub fn verify_receipt(
    statement: &[u8],
    receipt: &[u8],
    key: &ReceiptKey,
) -> Result<VerifiedReceipt, ReceiptError> {
    let v = verify_receipt_for_leaf(&leaf_of(statement)?, receipt, key)?;
    if v.header.sub.as_deref() != statement_sub(statement).as_deref() {
        return Err(ReceiptError::SubjectMismatch);
    }
    Ok(v)
}

/// A statement's CWT `sub` (protected header 15, claim 2), if it names one.
#[must_use]
pub fn statement_sub(statement: &[u8]) -> Option<String> {
    let [p, ..] = sign1(statement)?;
    let ph = cde::decode(p.as_bytes()?).ok()?;
    ph.get_int(H_CWT)?
        .get_int(C_SUB)?
        .as_text()
        .map(str::to_owned)
}

/// [`verify_receipt`] over a leaf the caller gives (the bytes the service
/// registered, before the RFC 9162 `0x00` prefix), for an object that is not
/// a row statement.
///
/// # Errors
///
/// As [`verify_receipt`].
pub fn verify_receipt_for_leaf(
    leaf: &[u8],
    receipt: &[u8],
    key: &ReceiptKey,
) -> Result<VerifiedReceipt, ReceiptError> {
    verify_receipt_for_leaf_hash(&hash_leaf(leaf), receipt, key)
}

/// [`verify_receipt`] over a leaf hash (`SHA-256(0x00 ‖ leaf)`) the caller
/// computed.
///
/// # Errors
///
/// As [`verify_receipt`].
pub fn verify_receipt_for_leaf_hash(
    leaf_hash: &Digest32,
    receipt: &[u8],
    key: &ReceiptKey,
) -> Result<VerifiedReceipt, ReceiptError> {
    let [p, u, pl, s] = sign1(receipt).ok_or(ReceiptError::Malformed)?;
    let pb = p.as_bytes().ok_or(ReceiptError::Malformed)?;
    let sig = s.as_bytes().ok_or(ReceiptError::Malformed)?;
    let ph = cde::decode(pb).map_err(|_| ReceiptError::Malformed)?;
    if ph.as_map().is_none() || !matches!(pl, Value::Null | Value::Bytes(_)) {
        return Err(ReceiptError::Malformed);
    }
    let header = header_of(&ph);
    if header.vds != Some(VDS_RFC9162_SHA256) {
        return Err(ReceiptError::UnsupportedVds);
    }
    let alg = header.alg.ok_or(ReceiptError::Malformed)?;
    if alg != key.alg() {
        return Err(ReceiptError::AlgMismatch);
    }
    if let (Some(k), Some(want)) = (&header.kid, key.kid()) {
        if !bool::from(k.as_slice().ct_eq(&want)) {
            return Err(ReceiptError::KeyMismatch);
        }
    }
    let proofs = u
        .get_int(VDP_LABEL)
        .and_then(|v| v.get_int(INCLUSION_PROOFS))
        .and_then(Value::as_array)
        .ok_or(ReceiptError::Malformed)?;
    let rooted: Vec<(InclusionProof, Digest32)> = proofs
        .iter()
        .filter_map(Value::as_bytes)
        .filter_map(proof_of)
        .filter_map(|p| {
            inclusion_root(leaf_hash, p.leaf_index, p.tree_size, &p.path).map(|r| (p, r))
        })
        .filter(|(_, r)| match &pl {
            Value::Bytes(a) => a.as_slice() == r.as_slice(),
            _ => true,
        })
        .collect();
    if rooted.is_empty() {
        return Err(ReceiptError::BadInclusionPath);
    }
    let verified: Vec<(InclusionProof, Digest32)> = rooted
        .into_iter()
        .filter(|(_, r)| key.verify(&super::sig_structure(pb, r), sig))
        .collect();
    let (first, root) = verified
        .first()
        .cloned()
        .ok_or(ReceiptError::BadSignature)?;
    Ok(VerifiedReceipt {
        tree_size: first.tree_size,
        leaf_index: first.leaf_index,
        root,
        verified,
        kid: header.kid.clone(),
        iat: header.iat,
        header,
    })
}

/// Verify a receipt toward a lineage head's count (CC 3.2 T6, the rc22
/// model): the service is a charter's named service, its key the composite
/// its `key:record` holds, so only alg -70100 verifies; and the receipt must
/// name its `iat`, which the cadence and the attach window read (returned as
/// signed, never compared with a clock here).
///
/// # Errors
///
/// As [`verify_receipt`], [`ReceiptError::NoInstant`] and
/// [`ReceiptError::IssuerMismatch`] (`service` is the charter's identity
/// reference for it, which the receipt's CWT `iss` must be);
/// [`ReceiptError::SubjectMismatch`] also when the statement names no `sub`.
pub fn verify_head_receipt(
    statement: &[u8],
    receipt: &[u8],
    service: &str,
    key: &CompositePublicKey,
) -> Result<VerifiedReceipt, ReceiptError> {
    if statement_sub(statement).is_none() {
        return Err(ReceiptError::SubjectMismatch);
    }
    let v = verify_receipt(statement, receipt, &ReceiptKey::Composite(key.clone()))?;
    if v.header.iss.as_deref() != Some(service) {
        return Err(ReceiptError::IssuerMismatch);
    }
    if v.iat.is_none() {
        return Err(ReceiptError::NoInstant);
    }
    Ok(v)
}

/// The charter's services with at least one receipt toward the head: of
/// `statements`, only those whose payload is `head_payload` (a statement of
/// the head; any other counts for nothing), each statement's own `receipts`
/// header read, each receipt checked by [`verify_head_receipt`]. A service
/// counts once whichever statements its receipts are over, and two entries
/// with one key count once (the first id stands). The caller compares the
/// count with `receipt_quorum`; the head's own voices are counted
/// separately.
#[must_use]
pub fn head_receipt_services(
    head_payload: &[u8],
    statements: &[&[u8]],
    services: &[(String, CompositePublicKey)],
) -> BTreeSet<String> {
    let of_head: Vec<&[u8]> = statements
        .iter()
        .copied()
        .filter(|st| sign1(st).is_some_and(|[_, _, pl, _]| pl.as_bytes() == Some(head_payload)))
        .collect();
    let mut out = BTreeSet::new();
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    for (id, key) in services {
        if !seen.insert(ReceiptKey::Composite(key.clone()).material()) {
            continue;
        }
        let ok = of_head.iter().any(|st| {
            receipts_of(st)
                .iter()
                .any(|r| verify_head_receipt(st, r, id, key).is_ok())
        });
        if ok {
            out.insert(id.clone());
        }
    }
    out
}

/// The claims a service puts in a receipt's protected header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReceiptClaims {
    /// `kid` (4).
    pub kid: Option<Vec<u8>>,
    /// CWT `iss` (15 / 1).
    pub iss: Option<String>,
    /// CWT `sub` (15 / 2): the statement's own `sub`; [`mint_receipt`] sets it
    /// from the statement, whatever this says.
    pub sub: Option<String>,
    /// CWT `iat` (15 / 6), seconds.
    pub iat: Option<u64>,
}

/// Step 1 of issuing: a receipt's protected header bytes, `alg`, `vds` 1 and
/// the claims, in deterministic encoding.
#[must_use]
pub fn receipt_protected(alg: i64, claims: &ReceiptClaims) -> Vec<u8> {
    let mut m = vec![
        (int_key(H_ALG), int_key(alg)),
        (int_key(VDS_LABEL), int_key(VDS_RFC9162_SHA256)),
    ];
    if let Some(k) = &claims.kid {
        m.push((int_key(H_KID), Value::Bytes(k.clone())));
    }
    let mut cwt = Vec::new();
    if let Some(i) = &claims.iss {
        cwt.push((int_key(C_ISS), Value::Text(i.clone())));
    }
    if let Some(s) = &claims.sub {
        cwt.push((int_key(C_SUB), Value::Text(s.clone())));
    }
    if let Some(t) = claims.iat {
        cwt.push((int_key(C_IAT), Value::Uint(t)));
    }
    if !cwt.is_empty() {
        m.push((int_key(H_CWT), sorted_map(cwt)));
    }
    cde::encode(&sorted_map(m))
}

/// Step 2: the bytes the service signs, the Sig_structure over the root.
#[must_use]
pub fn receipt_to_be_signed(protected: &[u8], root: &Digest32) -> Vec<u8> {
    super::sig_structure(protected, root)
}

/// Step 3: the receipt, from the protected bytes, the inclusion proofs (each
/// for the root that was signed) and the signature; payload detached.
#[must_use]
pub fn assemble_receipt(protected: &[u8], proofs: &[InclusionProof], signature: &[u8]) -> Vec<u8> {
    let enc_proof = |p: &InclusionProof| {
        Value::Bytes(cde::encode(&Value::Array(vec![
            Value::Uint(p.tree_size),
            Value::Uint(p.leaf_index),
            Value::Array(p.path.iter().map(|h| Value::Bytes(h.to_vec())).collect()),
        ])))
    };
    let vdp = Value::Map(vec![(
        int_key(INCLUSION_PROOFS),
        Value::Array(proofs.iter().map(enc_proof).collect()),
    )]);
    sign1_value(
        Value::Bytes(protected.to_vec()),
        Value::Map(vec![(int_key(VDP_LABEL), vdp)]),
        Value::Null,
        Value::Bytes(signature.to_vec()),
    )
}

/// Issue a receipt under the composite in one call: the tree is
/// `statements`' leaves in order, the receipt is for `statements[index]`,
/// `kid` the key's thumbprint, with the given `iss`, `sub` and `iat`. A
/// service whose signer is not in memory uses the three steps.
///
/// # Errors
///
/// [`ReceiptError::Malformed`] for a statement that is not a COSE_Sign1 or
/// an index out of range; [`ReceiptError::BadSignature`] when signing fails.
pub fn mint_receipt(
    statements: &[&[u8]],
    index: usize,
    key: &CompositeSigningKey,
    claims: &ReceiptClaims,
) -> Result<Vec<u8>, ReceiptError> {
    let hashes = statements
        .iter()
        .map(|s| leaf_of(s).map(|l| hash_leaf(&l)))
        .collect::<Result<Vec<_>, _>>()?;
    let proof = inclusion_proof(index, &hashes).ok_or(ReceiptError::Malformed)?;
    let mut claims = claims.clone();
    claims.kid = Some(super::thumbprint(key.public_key()).to_vec());
    claims.sub = statement_sub(statements[index]);
    let pb = receipt_protected(ALG_COMPOSITE, &claims);
    let sig = key
        .sign(&receipt_to_be_signed(&pb, &tree_root(&hashes)))
        .map_err(|_| ReceiptError::BadSignature)?;
    Ok(assemble_receipt(&pb, &[proof], &sig))
}
