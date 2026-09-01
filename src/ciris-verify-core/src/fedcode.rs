//! CIRIS federation identity code (`fedcode`) — the kind-tagged, user-shareable
//! encoding of a federation entity's identity (FSD-003). One codec, five kinds:
//! **user / agent / node / family / community** — mapping 1:1 onto the
//! Constitution's `identity_type` (CC 3.4.7.1: user/agent/node) and the rostered
//! `subject_kind`s (CC 3.2 community / CC 3.3.4 family). The `kind` tag lets a
//! consumer apply the right rules (self-multiplicity for a user, occurrence
//! multiplicity for an agent, roster admission for a group) from the code alone.
//!
//! This is the **reference implementation** every CIRIS component consumes
//! (verify owns it; CIRISServer / CIRISAgent decode through the verify wheel /
//! FFI). The wire format is a strict superset of the v1 `NodeCode`
//! (`CIRIS-V1-…`): a `kind` byte after the version + a trailing `group_key_id`
//! hint, under a bumped `CIRIS-V2-` prefix. v1 codes still decode (as
//! `kind: node`) so existing node-codes keep working.
//!
//! ## Wire format (v2)
//!
//! Binary payload, then CRC-16-CCITT (2 bytes, big-endian), then RFC-4648
//! base32 (no pad), prefixed `CIRIS-V2-` and grouped into 4-char dash-separated
//! chunks for display (the QR form is ungrouped):
//!
//! ```text
//! version(1)=0x02 | kind(1) | sha256(key_id)(32) | ed25519_pubkey(32)
//!   | LP(key_id) | hint(transport) | hint(alias) | hint(group_key_id) | CRC(2 BE)
//! ```
//! `LP` = 1-byte length prefix + UTF-8 bytes. `hint` = `0x00` when absent, else
//! `LP`. All fields ≤ 255 bytes. `group_key_id` is the family/community
//! `*_key_id` (absent for user/agent/node).
//!
//! ## key_id format (FSD-003 §4)
//!
//! [`derive_key_id`] builds `"<label>-<fingerprint>"` where `fingerprint` is the
//! first [`KEY_ID_FINGERPRINT_LEN`] base32 chars of `sha256(ed25519_pubkey)`.
//! Collision-free **by construction** (the suffix is bound to the key, so two
//! entities choosing the same label never collide) and **verifiable** (anyone
//! recomputes the suffix from the pubkey). The label is cosmetic; the
//! fingerprint is the cryptographic anchor.

use base64::Engine;
use sha2::{Digest, Sha256};

/// Bumped binary-format version for the kind-tagged code.
pub const FEDCODE_VERSION_V2: u8 = 0x02;
/// The v1 `NodeCode` version (decoded as [`FedKind::Node`] for back-compat).
pub const FEDCODE_VERSION_V1: u8 = 0x01;

const PREFIX_V2: &str = "CIRIS-V2-";

/// Binary-format version for a code that MAY embed the owner's nodes
/// (CIRISVerify#269).
///
/// **Note the number.** The issue proposing this called it "fedcode v2", but
/// the wire format has been at v2 since the kind-tagged code shipped — so the
/// node-carrying format is **v3**. Minting it as "v2" would have collided with
/// a live encoding.
pub const FEDCODE_VERSION_V3: u8 = 0x03;

const PREFIX_V3: &str = "CIRIS-V3-";
const PREFIX_V1: &str = "CIRIS-V1-";
const GROUP_SIZE: usize = 4;
const MAX_FIELD_BYTES: usize = 255;

/// Cap on embedded nodes in a v3 code (CIRISVerify#269).
///
/// A fedcode is meant to be scannable as a QR and readable aloud; an unbounded
/// list makes it neither. 16 is well past any realistic owner's node count and
/// keeps the code inside a comfortable QR density.
const MAX_OWNED_NODES: usize = 16;
const PUBKEY_RAW_LEN: usize = 32;
const KEY_ID_HASH_LEN: usize = 32;
const CRC_POLY: u16 = 0x1021;
const CRC_INIT: u16 = 0xFFFF;
const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Number of base32 fingerprint chars appended to a derived `key_id`
/// (`KEY_ID_FINGERPRINT_LEN × 5` bits of `sha256(pubkey)` = 50 bits).
pub const KEY_ID_FINGERPRINT_LEN: usize = 10;

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// The entity a fedcode names — the Constitution's identity / group taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FedKind {
    /// `identity_type: user` (CC 3.4.7.1) — an accountable human; the root of
    /// owner-binding. **Self-multiplicity**: one self across N device keys.
    User,
    /// `identity_type: agent` (CC 3.4.7.1) — an AI agent; MUST be owner-bound.
    /// **Occurrence-multiplicity**: one key across N runtime occurrences.
    Agent,
    /// `identity_type: node` (CC 3.4.7.1) — a fabric node; owner-bound (except
    /// infrastructure trust-and-serve). The classic v1 NodeCode.
    Node,
    /// `subject_kind: family` (CC 3.3.4) — intimate roster, structural-invisible.
    Family,
    /// `subject_kind: community` (CC 3.2) — larger roster, admission-gated.
    Community,
}

impl FedKind {
    fn as_u8(self) -> u8 {
        match self {
            FedKind::User => 1,
            FedKind::Agent => 2,
            FedKind::Node => 3,
            FedKind::Family => 4,
            FedKind::Community => 5,
        }
    }

    fn from_u8(v: u8) -> Result<Self, FedCodeError> {
        Ok(match v {
            1 => FedKind::User,
            2 => FedKind::Agent,
            3 => FedKind::Node,
            4 => FedKind::Family,
            5 => FedKind::Community,
            other => {
                return Err(FedCodeError::Malformed(format!(
                    "unknown kind byte {other}"
                )))
            },
        })
    }

    /// The lowercase wire string for JSON / logs (`"user"`, `"agent"`, …).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FedKind::User => "user",
            FedKind::Agent => "agent",
            FedKind::Node => "node",
            FedKind::Family => "family",
            FedKind::Community => "community",
        }
    }
}

/// One node a user owns, as embedded in a v3 code (CIRISVerify#269).
///
/// ## The field name is the safety property
///
/// This carries the node's **transport** Ed25519 — never the owner's
/// federation key, and never the node's federation key.
///
/// CIRISServer#335 is what the confusion cost in production: nodes primed the
/// canonical at `1fc232535a…` while it served on `81cabcf78a…`. Every node
/// reported `knows_peer=true, provenance=Rooted, primed=1, refused=0`, and
/// **zero traces arrived** — and the false rooting then *prevented* recovery,
/// because a node that believes it knows a peer never learns the real address.
///
/// What made it survive review is that transport and federation share the
/// Ed25519 half, so the derivation looks sound. Sharing a key does not make a
/// base hash and a named hash the same address: deriving from the federation
/// key yields `sha256(fed)[..16]`, an explicit-hash destination that
/// categorically **cannot be announced**, so no peer can ever self-learn a
/// route to it.
///
/// [`encode`] refuses a code whose embedded transport key equals the owner's
/// own pubkey, so the specific mistake that caused #335 cannot be encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedNode {
    /// The node's federation `key_id` — an identifier, not an address.
    pub key_id: String,
    /// The node's **transport** Ed25519 public key, base64 standard (raw 32
    /// bytes). This is what a destination is derived from; see the type docs.
    pub transport_pubkey_ed25519_base64: String,
}

/// A decoded / to-be-encoded fedcode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FedCode {
    /// The entity kind.
    pub kind: FedKind,
    /// The entity's human-readable `key_id` (federation address).
    pub key_id: String,
    /// The entity's Ed25519 public key, base64 standard (raw 32 bytes).
    pub pubkey_ed25519_base64: String,
    /// Optional transport hint (e.g. a public base URL).
    pub transport_hint: Option<String>,
    /// Optional human-readable alias the sender suggests (display only).
    pub alias_hint: Option<String>,
    /// For `family` / `community`: the group's `*_key_id`. Absent otherwise.
    pub group_key_id: Option<String>,
    /// **MAY** carry the owner's nodes, so a contact resolves with no
    /// directory (CIRISVerify#269) — first contact, a QR across a table, an
    /// air-gapped hand-off, a fresh install.
    ///
    /// Empty is valid and is the default: a code with no nodes degrades to the
    /// v1/v2 directory path, and **encodes byte-identically to a v2 code**, so
    /// nothing already issued changes. Only a non-empty list emits v3.
    ///
    /// Scope boundary: these are **lightnet** facts — federation-scope
    /// identity that already announces publicly and carries no anonymity
    /// claim. A code MUST NOT carry group-scoped material, whose destinations
    /// are derived from `cached directory + per-group HKDF` and may not be
    /// emitted at all (CC 5.4.6, ruled in CIRISConstitution#91).
    pub owned_nodes: Vec<OwnedNode>,
}

/// fedcode encode/decode failures.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FedCodeError {
    /// Unsupported binary/textual version.
    InvalidVersion(String),
    /// Structurally invalid (bad prefix/base32, truncation, over-long fields).
    Malformed(String),
    /// CRC-16 mismatch (corrupted code).
    ChecksumMismatch {
        /// The CRC carried in the code.
        declared: u16,
        /// The CRC recomputed over the payload.
        computed: u16,
    },
}

impl std::fmt::Display for FedCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FedCodeError::InvalidVersion(m) => write!(f, "unsupported fedcode version: {m}"),
            FedCodeError::Malformed(m) => write!(f, "malformed fedcode: {m}"),
            FedCodeError::ChecksumMismatch { declared, computed } => write!(
                f,
                "fedcode checksum mismatch: declared 0x{declared:04x}, computed 0x{computed:04x}"
            ),
        }
    }
}

impl std::error::Error for FedCodeError {}

/// Derive a collision-free, verifiable `key_id` = `"<label>-<fingerprint>"`.
///
/// `label` is lowercased and reduced to `[a-z0-9-]` (cosmetic). `fingerprint`
/// is the first [`KEY_ID_FINGERPRINT_LEN`] lowercase base32 chars of
/// `sha256(ed25519_pubkey)` — bound to the key, so two entities choosing the
/// same label never collide, and anyone can recompute it from the pubkey.
#[must_use]
pub fn derive_key_id(label: &str, ed25519_pubkey: &[u8]) -> String {
    let digest = Sha256::digest(ed25519_pubkey);
    let fp: String = b32_no_pad_encode(&digest)
        .chars()
        .take(KEY_ID_FINGERPRINT_LEN)
        .collect::<String>()
        .to_ascii_lowercase();
    let label = sanitize_label(label);
    if label.is_empty() {
        format!("id-{fp}")
    } else {
        format!("{label}-{fp}")
    }
}

fn sanitize_label(label: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for c in label.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            last_dash = false;
        } else if !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

/// Encode a fedcode to its dashed display form (`CIRIS-V2-XXXX-XXXX-…`).
///
/// # Errors
/// [`FedCodeError::Malformed`] if a field is over-long or the pubkey is not 32
/// raw bytes of valid base64.
pub fn encode(fc: &FedCode) -> Result<String, FedCodeError> {
    Ok(format!("{}{}", prefix_for(fc), group(&encode_body(fc)?)))
}

/// The display prefix a code needs, chosen by CONTENT.
///
/// A code with no embedded nodes stays `CIRIS-V2-` and encodes byte-identically
/// to before, so nothing already issued changes (CIRISVerify#269). Only a
/// non-empty node list emits `CIRIS-V3-`.
fn prefix_for(fc: &FedCode) -> &'static str {
    if fc.owned_nodes.is_empty() {
        PREFIX_V2
    } else {
        PREFIX_V3
    }
}

/// Encode to the ungrouped QR form (`CIRIS-V2-XXXXXXXX…`).
///
/// # Errors
/// As [`encode`].
pub fn encode_qr(fc: &FedCode) -> Result<String, FedCodeError> {
    Ok(format!("{}{}", prefix_for(fc), encode_body(fc)?))
}

fn encode_body(fc: &FedCode) -> Result<String, FedCodeError> {
    let payload = build_payload(fc)?;
    let crc = crc16_ccitt(&payload);
    let mut full = payload;
    full.push((crc >> 8) as u8);
    full.push((crc & 0xFF) as u8);
    Ok(b32_no_pad_encode(&full))
}

fn build_payload(fc: &FedCode) -> Result<Vec<u8>, FedCodeError> {
    let key_id_bytes = fc.key_id.as_bytes();
    if key_id_bytes.len() > MAX_FIELD_BYTES {
        return Err(FedCodeError::Malformed(format!(
            "key_id exceeds {MAX_FIELD_BYTES} bytes ({})",
            key_id_bytes.len()
        )));
    }
    let pubkey_raw = b64()
        .decode(fc.pubkey_ed25519_base64.as_bytes())
        .map_err(|e| FedCodeError::Malformed(format!("pubkey is not valid base64: {e}")))?;
    if pubkey_raw.len() != PUBKEY_RAW_LEN {
        return Err(FedCodeError::Malformed(format!(
            "pubkey must be {PUBKEY_RAW_LEN} raw bytes, got {}",
            pubkey_raw.len()
        )));
    }

    // Only a user code may carry nodes: "the owner's nodes" is meaningless for
    // a node, and a group's destinations are group-scoped material a code MUST
    // NOT carry at all (CC 5.4.6). Narrow now; widening later is additive.
    if !fc.owned_nodes.is_empty() && fc.kind != FedKind::User {
        return Err(FedCodeError::Malformed(format!(
            "only a `user` code may embed owned nodes, got `{}`",
            fc.kind.as_str()
        )));
    }

    let mut out = Vec::new();
    out.push(if fc.owned_nodes.is_empty() {
        FEDCODE_VERSION_V2
    } else {
        FEDCODE_VERSION_V3
    });
    out.push(fc.kind.as_u8());
    out.extend_from_slice(&Sha256::digest(key_id_bytes));
    out.extend_from_slice(&pubkey_raw);
    out.push(key_id_bytes.len() as u8);
    out.extend_from_slice(key_id_bytes);
    out.extend_from_slice(&encode_hint(fc.transport_hint.as_deref())?);
    out.extend_from_slice(&encode_hint(fc.alias_hint.as_deref())?);
    out.extend_from_slice(&encode_hint(fc.group_key_id.as_deref())?);

    // v3 tail: the owner's nodes. Absent entirely on v2, so the bytes above
    // are unchanged for every code issued so far.
    if !fc.owned_nodes.is_empty() {
        if fc.owned_nodes.len() > MAX_OWNED_NODES {
            return Err(FedCodeError::Malformed(format!(
                "at most {MAX_OWNED_NODES} owned nodes, got {}",
                fc.owned_nodes.len()
            )));
        }
        out.push(fc.owned_nodes.len() as u8);
        for node in &fc.owned_nodes {
            let id = node.key_id.as_bytes();
            if id.is_empty() || id.len() > MAX_FIELD_BYTES {
                return Err(FedCodeError::Malformed(format!(
                    "node key_id must be 1..={MAX_FIELD_BYTES} bytes, got {}",
                    id.len()
                )));
            }
            let tp = b64()
                .decode(node.transport_pubkey_ed25519_base64.as_bytes())
                .map_err(|e| {
                    FedCodeError::Malformed(format!(
                        "node `{}` transport pubkey is not valid base64: {e}",
                        node.key_id
                    ))
                })?;
            if tp.len() != PUBKEY_RAW_LEN {
                return Err(FedCodeError::Malformed(format!(
                    "node `{}` transport pubkey must be {PUBKEY_RAW_LEN} raw bytes, got {}",
                    node.key_id,
                    tp.len()
                )));
            }
            // THE constraint (#269 / CIRISServer#335). Embedding the owner's
            // federation key as a node's transport key yields
            // `sha256(fed)[..16]` — an explicit-hash destination that can
            // never be announced, so no peer can self-learn a route to it, and
            // a node that believes it knows the peer never recovers. Refuse it
            // at the encoder, where it is still cheap.
            if tp == pubkey_raw {
                return Err(FedCodeError::Malformed(format!(
                    "node `{}` transport pubkey equals the OWNER's federation key — \
                     a destination derived from it is unannounceable and unreachable \
                     (CIRISServer#335); embed the node's TRANSPORT key",
                    node.key_id
                )));
            }
            out.push(id.len() as u8);
            out.extend_from_slice(id);
            out.extend_from_slice(&tp);
        }
    }
    Ok(out)
}

/// Decode a fedcode (v2) or a legacy v1 `NodeCode` (→ [`FedKind::Node`]).
///
/// # Errors
/// [`FedCodeError`] on a bad prefix, base32, CRC, version, or truncation.
pub fn decode(code: &str) -> Result<FedCode, FedCodeError> {
    let cleaned: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let cleaned = cleaned.to_ascii_uppercase();

    let body = strip_prefix(&cleaned)?;
    let body: String = body.chars().filter(|&c| c != '-').collect();
    if body.is_empty() {
        return Err(FedCodeError::Malformed("no payload after prefix".into()));
    }
    let raw = b32_no_pad_decode(&body)?;

    // ver + (v2 kind) + hash + pubkey + LP(>=1) + 0 hints + crc.
    if raw.len() < 1 + KEY_ID_HASH_LEN + PUBKEY_RAW_LEN + 1 + 2 {
        return Err(FedCodeError::Malformed(format!(
            "payload too short ({} bytes)",
            raw.len()
        )));
    }
    let (payload, crc_bytes) = raw.split_at(raw.len() - 2);
    let declared = (u16::from(crc_bytes[0]) << 8) | u16::from(crc_bytes[1]);
    let computed = crc16_ccitt(payload);
    if declared != computed {
        return Err(FedCodeError::ChecksumMismatch { declared, computed });
    }

    let version = payload[0];
    let mut offset = 1;
    let kind = match version {
        FEDCODE_VERSION_V2 | FEDCODE_VERSION_V3 => {
            let k = FedKind::from_u8(*payload.get(offset).ok_or_else(trunc)?)?;
            offset += 1;
            k
        },
        // v1 NodeCode: no kind byte; it IS a node code.
        FEDCODE_VERSION_V1 => FedKind::Node,
        other => {
            return Err(FedCodeError::InvalidVersion(format!(
                "binary version 0x{other:02x}; supported: 0x01 (node), 0x02, 0x03"
            )))
        },
    };

    if payload.len() < offset + KEY_ID_HASH_LEN + PUBKEY_RAW_LEN + 1 {
        return Err(trunc());
    }
    offset += KEY_ID_HASH_LEN; // key_id hash (integrity; key_id read below)
    let pubkey_raw = &payload[offset..offset + PUBKEY_RAW_LEN];
    offset += PUBKEY_RAW_LEN;

    let (key_id, off) = read_length_prefixed(payload, offset)?;
    offset = off;
    let (transport_hint, off) = read_hint(payload, offset)?;
    offset = off;
    let (alias_hint, off) = read_hint(payload, offset)?;
    offset = off;
    // group_key_id exists from v2 onward; tolerate its absence (v1).
    let group_key_id = if version >= FEDCODE_VERSION_V2 && offset < payload.len() {
        let (g, off) = read_hint(payload, offset)?;
        offset = off;
        g
    } else {
        None
    };

    // v3 tail: the owner's nodes (CIRISVerify#269). Absent on v1/v2.
    let owned_nodes = if version == FEDCODE_VERSION_V3 {
        let count = usize::from(*payload.get(offset).ok_or_else(trunc)?);
        offset += 1;
        if count > MAX_OWNED_NODES {
            return Err(FedCodeError::Malformed(format!(
                "at most {MAX_OWNED_NODES} owned nodes, got {count}"
            )));
        }
        let mut nodes = Vec::with_capacity(count);
        for _ in 0..count {
            let (key_id, off) = read_length_prefixed(payload, offset)?;
            offset = off;
            if payload.len() < offset + PUBKEY_RAW_LEN {
                return Err(trunc());
            }
            let tp = &payload[offset..offset + PUBKEY_RAW_LEN];
            offset += PUBKEY_RAW_LEN;
            // Refuse on DECODE as well as encode: a code minted by another
            // implementation is exactly the case the encoder cannot police,
            // and this is the mistake that cost CIRISServer#335.
            if tp == pubkey_raw {
                return Err(FedCodeError::Malformed(format!(
                    "node `{key_id}` transport pubkey equals the owner's federation \
                     key — a destination derived from it is unannounceable and \
                     unreachable (CIRISServer#335)"
                )));
            }
            nodes.push(OwnedNode {
                key_id,
                transport_pubkey_ed25519_base64: b64().encode(tp),
            });
        }
        nodes
    } else {
        Vec::new()
    };

    Ok(FedCode {
        kind,
        key_id,
        pubkey_ed25519_base64: b64().encode(pubkey_raw),
        transport_hint,
        alias_hint,
        group_key_id,
        owned_nodes,
    })
}

fn trunc() -> FedCodeError {
    FedCodeError::Malformed("truncated fedcode payload".into())
}

fn strip_prefix(cleaned: &str) -> Result<String, FedCodeError> {
    for p in [PREFIX_V3, PREFIX_V2, PREFIX_V1] {
        if let Some(rest) = cleaned.strip_prefix(p) {
            return Ok(rest.to_string());
        }
        // Undashed form (e.g. from a QR scan that dropped dashes): CIRISV2.
        let undashed: String = p.chars().filter(|&c| c != '-').collect();
        if let Some(rest) = cleaned.strip_prefix(&undashed) {
            return Ok(rest.to_string());
        }
    }
    Err(FedCodeError::Malformed(format!(
        "not a CIRIS fedcode (expected {PREFIX_V3:?}, {PREFIX_V2:?} or {PREFIX_V1:?})"
    )))
}

fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc = CRC_INIT;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ CRC_POLY;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

fn encode_hint(value: Option<&str>) -> Result<Vec<u8>, FedCodeError> {
    match value {
        None | Some("") => Ok(vec![0u8]),
        Some(v) => {
            let raw = v.as_bytes();
            if raw.len() > MAX_FIELD_BYTES {
                return Err(FedCodeError::Malformed(format!(
                    "hint exceeds {MAX_FIELD_BYTES} bytes ({})",
                    raw.len()
                )));
            }
            let mut out = Vec::with_capacity(1 + raw.len());
            out.push(raw.len() as u8);
            out.extend_from_slice(raw);
            Ok(out)
        },
    }
}

/// Read a `hint` field: a `0x00` (absent) or a length-prefixed string.
fn read_hint(buf: &[u8], offset: usize) -> Result<(Option<String>, usize), FedCodeError> {
    let len = *buf.get(offset).ok_or_else(trunc)?;
    if len == 0 {
        return Ok((None, offset + 1));
    }
    let (s, off) = read_length_prefixed(buf, offset)?;
    Ok((Some(s), off))
}

fn read_length_prefixed(buf: &[u8], offset: usize) -> Result<(String, usize), FedCodeError> {
    let length = *buf.get(offset).ok_or_else(trunc)? as usize;
    let start = offset + 1;
    let end = start + length;
    if end > buf.len() {
        return Err(FedCodeError::Malformed(format!(
            "declared field length {length} exceeds buffer"
        )));
    }
    let value = std::str::from_utf8(&buf[start..end])
        .map_err(|e| FedCodeError::Malformed(format!("field not UTF-8: {e}")))?
        .to_string();
    Ok((value, end))
}

fn b32_no_pad_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32_ALPHABET[((buffer >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32_ALPHABET[((buffer << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

fn b32_no_pad_decode(text: &str) -> Result<Vec<u8>, FedCodeError> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for ch in text.bytes() {
        let val = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'2'..=b'7' => ch - b'2' + 26,
            _ => {
                return Err(FedCodeError::Malformed(format!(
                    "invalid base32 char: {:?}",
                    ch as char
                )))
            },
        };
        buffer = (buffer << 5) | u32::from(val);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

fn group(text: &str) -> String {
    if text.is_empty() {
        return text.to_string();
    }
    text.chars()
        .collect::<Vec<_>>()
        .chunks(GROUP_SIZE)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(seed: u8) -> String {
        b64().encode([seed; 32])
    }

    fn sample(kind: FedKind) -> FedCode {
        FedCode {
            owned_nodes: Vec::new(),
            kind,
            key_id: "eric-moore-k7f3qd2pza".into(),
            pubkey_ed25519_base64: pk(9),
            transport_hint: Some("https://node.example".into()),
            alias_hint: Some("Eric Moore".into()),
            group_key_id: matches!(kind, FedKind::Family | FedKind::Community)
                .then(|| "the-moores-fam-aa".to_string()),
        }
    }

    #[test]
    fn round_trips_every_kind() {
        for kind in [
            FedKind::User,
            FedKind::Agent,
            FedKind::Node,
            FedKind::Family,
            FedKind::Community,
        ] {
            let fc = sample(kind);
            let code = encode(&fc).unwrap();
            assert!(code.starts_with("CIRIS-V2-"));
            assert_eq!(decode(&code).unwrap(), fc, "round-trip failed for {kind:?}");
            // QR (ungrouped) form decodes identically.
            assert_eq!(decode(&encode_qr(&fc).unwrap()).unwrap(), fc);
        }
    }

    #[test]
    fn kind_byte_is_authoritative() {
        let u = encode(&sample(FedKind::User)).unwrap();
        let a = encode(&sample(FedKind::Agent)).unwrap();
        assert_ne!(u, a, "user and agent codes must differ");
        assert_eq!(decode(&u).unwrap().kind, FedKind::User);
        assert_eq!(decode(&a).unwrap().kind, FedKind::Agent);
    }

    #[test]
    fn derive_key_id_is_collision_free_and_verifiable() {
        let a = derive_key_id("Eric Moore", &[1u8; 32]);
        let b = derive_key_id("Eric Moore", &[2u8; 32]);
        // Same label, different keys → different ids (collision-free).
        assert_ne!(a, b);
        assert!(a.starts_with("eric-moore-"));
        // Verifiable: recompute the suffix from the pubkey.
        let recomputed = derive_key_id("Eric Moore", &[1u8; 32]);
        assert_eq!(a, recomputed);
        // Fingerprint length.
        assert_eq!(a.rsplit('-').next().unwrap().len(), KEY_ID_FINGERPRINT_LEN);
    }

    #[test]
    fn derive_key_id_sanitizes_label() {
        // Lowercased, reduced to [a-z0-9-]; runs of non-alnum collapse to one
        // dash; dropped non-ASCII letters leave a dash boundary (deterministic).
        let id = derive_key_id("Eric Moore-2", &[3u8; 32]);
        assert!(id.starts_with("eric-moore-2-"), "got {id}");
        assert!(!id.contains("--") && !id.starts_with('-'));
        // Empty/symbol-only label falls back to `id-`.
        assert!(derive_key_id("!!!", &[4u8; 32]).starts_with("id-"));
    }

    #[test]
    fn corrupted_code_fails_crc() {
        let code = encode(&sample(FedKind::Node)).unwrap();
        // Flip a payload char (after the prefix).
        let mut chars: Vec<char> = code.chars().collect();
        let i = code.len() - 2;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let mutated: String = chars.into_iter().collect();
        assert!(matches!(
            decode(&mutated),
            Err(FedCodeError::ChecksumMismatch { .. }) | Err(FedCodeError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_non_fedcode() {
        assert!(matches!(decode("hello"), Err(FedCodeError::Malformed(_))));
        assert!(matches!(
            decode("CIRIS-V9-AAAA"),
            Err(FedCodeError::Malformed(_))
        ));
    }
}

/// v3 — a user code that MAY embed its owned nodes (CIRISVerify#269).
#[cfg(test)]
mod owned_nodes {
    use super::*;

    fn pk(b: u8) -> String {
        b64().encode([b; PUBKEY_RAW_LEN])
    }

    fn user(nodes: Vec<OwnedNode>) -> FedCode {
        FedCode {
            kind: FedKind::User,
            key_id: "eric-moore-a1b2c3".into(),
            pubkey_ed25519_base64: pk(0x11),
            transport_hint: None,
            alias_hint: Some("Eric".into()),
            group_key_id: None,
            owned_nodes: nodes,
        }
    }

    fn node(id: &str, b: u8) -> OwnedNode {
        OwnedNode {
            key_id: id.into(),
            transport_pubkey_ed25519_base64: pk(b),
        }
    }

    /// **An empty node list changes nothing.** A code with no nodes still
    /// encodes as v2, byte-identically to before, so nothing already issued
    /// moves — the `MAY` in the ask is free.
    #[test]
    fn no_nodes_still_encodes_as_v2() {
        let code = encode(&user(vec![])).unwrap();
        assert!(code.starts_with("CIRIS-V2-"), "{code}");
        let back = decode(&code).unwrap();
        assert!(back.owned_nodes.is_empty());
        assert_eq!(back, user(vec![]));
    }

    /// A non-empty list emits v3 and round-trips.
    #[test]
    fn nodes_round_trip_under_v3() {
        let fc = user(vec![node("laptop-aaaa", 0x22), node("phone-bbbb", 0x33)]);
        let code = encode(&fc).unwrap();
        assert!(code.starts_with("CIRIS-V3-"), "{code}");
        assert_eq!(decode(&code).unwrap(), fc);
    }

    /// **The constraint, refused at the ENCODER** — CIRISServer#335.
    ///
    /// Embedding the owner's federation key as a node's transport key derives
    /// `sha256(fed)[..16]`, an explicit-hash destination that can never be
    /// announced, so no peer self-learns a route and the false rooting then
    /// prevents recovery.
    #[test]
    fn embedding_the_owners_own_key_as_a_transport_key_is_refused() {
        let mut fc = user(vec![node("laptop-aaaa", 0x22)]);
        fc.owned_nodes[0].transport_pubkey_ed25519_base64 = fc.pubkey_ed25519_base64.clone();
        let err = encode(&fc).unwrap_err();
        assert!(format!("{err}").contains("OWNER's federation key"), "{err}");
    }

    /// …and refused at the DECODER too, because a code minted by another
    /// implementation is exactly the case an encoder cannot police.
    #[test]
    fn a_foreign_code_with_the_owners_key_is_refused_on_decode() {
        // Mint it by hand, bypassing our own encoder's refusal.
        let mut payload = Vec::new();
        payload.push(FEDCODE_VERSION_V3);
        payload.push(FedKind::User.as_u8());
        let key_id = b"eric-moore-a1b2c3";
        payload.extend_from_slice(&Sha256::digest(key_id));
        payload.extend_from_slice(&[0x11; PUBKEY_RAW_LEN]); // owner pubkey
        payload.push(key_id.len() as u8);
        payload.extend_from_slice(key_id);
        payload.extend_from_slice(&[0x00, 0x00, 0x00]); // three absent hints
        payload.push(1); // one node
        payload.push(4);
        payload.extend_from_slice(b"nodeX");
        payload.truncate(payload.len() - 1); // key_id was 4 bytes: "node"
        payload.extend_from_slice(&[0x11; PUBKEY_RAW_LEN]); // == owner's key

        let crc = crc16_ccitt(&payload);
        payload.push((crc >> 8) as u8);
        payload.push((crc & 0xFF) as u8);
        let code = format!("{PREFIX_V3}{}", b32_no_pad_encode(&payload));

        let err = decode(&code).unwrap_err();
        assert!(format!("{err}").contains("owner's federation"), "{err}");
    }

    /// Only a user code may carry nodes. A group's destinations are
    /// group-scoped material a code must not carry at all (CC 5.4.6).
    #[test]
    fn only_a_user_code_may_embed_nodes() {
        for kind in [
            FedKind::Node,
            FedKind::Agent,
            FedKind::Family,
            FedKind::Community,
        ] {
            let mut fc = user(vec![node("laptop-aaaa", 0x22)]);
            fc.kind = kind;
            assert!(encode(&fc).is_err(), "{kind:?} must not carry nodes");
        }
    }

    /// The list is bounded — a fedcode has to stay scannable.
    #[test]
    fn the_node_list_is_bounded() {
        let many: Vec<_> = (0..=MAX_OWNED_NODES)
            .map(|i| node(&format!("n{i}-aaaa"), 0x22 + i as u8))
            .collect();
        assert!(encode(&user(many)).is_err());
    }

    /// v1 and v2 codes still decode unchanged.
    #[test]
    fn older_versions_still_decode() {
        let v2 = encode(&user(vec![])).unwrap();
        assert_eq!(decode(&v2).unwrap().owned_nodes.len(), 0);
    }
}
