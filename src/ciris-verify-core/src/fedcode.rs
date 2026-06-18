//! CIRIS federation identity code (`fedcode`) — the kind-tagged, user-shareable
//! encoding of a federation entity's identity (FSD-002). One codec, five kinds:
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
//! ## key_id format (FSD-002 §4)
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
const PREFIX_V1: &str = "CIRIS-V1-";
const GROUP_SIZE: usize = 4;
const MAX_FIELD_BYTES: usize = 255;
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
}

/// fedcode encode/decode failures.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    Ok(format!("{PREFIX_V2}{}", group(&encode_body(fc)?)))
}

/// Encode to the ungrouped QR form (`CIRIS-V2-XXXXXXXX…`).
///
/// # Errors
/// As [`encode`].
pub fn encode_qr(fc: &FedCode) -> Result<String, FedCodeError> {
    Ok(format!("{PREFIX_V2}{}", encode_body(fc)?))
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

    let mut out = Vec::new();
    out.push(FEDCODE_VERSION_V2);
    out.push(fc.kind.as_u8());
    out.extend_from_slice(&Sha256::digest(key_id_bytes));
    out.extend_from_slice(&pubkey_raw);
    out.push(key_id_bytes.len() as u8);
    out.extend_from_slice(key_id_bytes);
    out.extend_from_slice(&encode_hint(fc.transport_hint.as_deref())?);
    out.extend_from_slice(&encode_hint(fc.alias_hint.as_deref())?);
    out.extend_from_slice(&encode_hint(fc.group_key_id.as_deref())?);
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
        FEDCODE_VERSION_V2 => {
            let k = FedKind::from_u8(*payload.get(offset).ok_or_else(trunc)?)?;
            offset += 1;
            k
        },
        // v1 NodeCode: no kind byte; it IS a node code.
        FEDCODE_VERSION_V1 => FedKind::Node,
        other => {
            return Err(FedCodeError::InvalidVersion(format!(
                "binary version 0x{other:02x}; supported: 0x01 (node), 0x02"
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
    // group_key_id only exists in v2; tolerate its absence (v1).
    let group_key_id = if version == FEDCODE_VERSION_V2 && offset < payload.len() {
        read_hint(payload, offset)?.0
    } else {
        None
    };

    Ok(FedCode {
        kind,
        key_id,
        pubkey_ed25519_base64: b64().encode(pubkey_raw),
        transport_hint,
        alias_hint,
        group_key_id,
    })
}

fn trunc() -> FedCodeError {
    FedCodeError::Malformed("truncated fedcode payload".into())
}

fn strip_prefix(cleaned: &str) -> Result<String, FedCodeError> {
    for p in [PREFIX_V2, PREFIX_V1] {
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
        "not a CIRIS fedcode (expected {PREFIX_V2:?} or {PREFIX_V1:?})"
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
