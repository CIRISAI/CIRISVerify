//! The edition-2 FedCode (`CIRIS-V4-`): the human-shareable code over a
//! composite key's thumbprint (CC 2.6.8, as verify proposes it for rc22; CC
//! 2.6.1.7 thumbprint, CC 2.6.1.12). A user code may embed its owner's nodes,
//! each with its full Reticulum transport identity and an ordered list of
//! typed dial hints, so a rootless node can add a peer with no directory.
//!
//! ```text
//! payload  = version(1)=0x04 | kind(1) | kid(32) | body
//!   kind=user                     body = node_count(1) 0..=4 | node_count × (node_kid(32) | endpoint)
//!   kind=node                     body = endpoint            (of the node the kid names)
//!   kind=agent/family/community   body = empty
//! endpoint = transport_identity(64: x25519(32) | ed25519(32)) | hint_count(1) 0..=8 | hint_count × hint
//! hint     = type(1) | len(1) | body(len)     ordered, most preferred first
//! code     = "CIRIS-V4-" ‖ base32(payload ‖ crc16_ccitt(payload) as 2 bytes BE), no padding,
//!            displayed in dash-separated groups of 4; payload ≤ 1024 bytes
//! ```
//!
//! Hint types: 1 `tcp` (port u16 ≠ 0, host 1..=253 bytes: a DNS name or an IP
//! literal, IPv6 with no brackets and no zone id), 2 `udp` (the same),
//! 3 `auto` (scope u8 0..=4 link/admin/site/organisation/global, group id
//! 1..=64 bytes), 4 `rnode` (frequency u32, bandwidth u32, spreading factor
//! 7..=12, coding rate 5..=8; exactly 10 bytes), 5 `http` (an `https://` URL,
//! ≤ 255 bytes), 6 `i2p` (the 32-byte destination hash), 7 `kiss` (frequency
//! u32 ≠ 0, bit rate u32 ≠ 0, then an AX.25 callsign-SSID of 0..=9 bytes,
//! uppercase alphanumerics and at most one inner '-'), 8 `ble` (an EMPTY body:
//! a static BLE identifier in a code would be a tracking handle). Text carries
//! no space or control character. Every other type
//! is carried as [`Hint::Unknown`] and skipped by a dialler, never refused, so
//! a new interface kind does not break an old parser; a known type whose body
//! fails its rule is refused. A hint is a dial hint only: unsigned, never a
//! secret, never a transit pair or a route row. The node's own signed route
//! row, fetched before the seal (CC 5.3.3.10 E1), is what authenticates.
//!
//! The decoder never truncates and never repairs: one payload has one code.
//! It refuses an earlier-form prefix (`CIRIS-V1-` … `CIRIS-V3-`) by name.
//! Constraint 1 (a transport key is never a federation key) needs the
//! composite keys the code names only by kid, so it is checked at resolution:
//! [`FedCodeE2::check_transport_keys`].
//!
//! Known answers: `tests/vectors/fedcode/fedcode_e2_v1.json`, from
//! `gen_fedcode_e2.py`, independent of this code.

#[allow(unused_imports)]
use crate::prelude::*;

use ciris_crypto::composite::CompositePublicKey;
use sha2::{Digest, Sha256};

use super::Digest32;

/// The binary version byte of an edition-2 code.
pub const FEDCODE_E2_VERSION: u8 = 0x04;
/// The text prefix of an edition-2 code.
pub const FEDCODE_E2_PREFIX: &str = "CIRIS-V4-";
/// The largest payload, before the CRC and base32.
pub const FEDCODE_E2_MAX_PAYLOAD: usize = 1024;
/// The most nodes a user code embeds.
pub const FEDCODE_E2_MAX_NODES: usize = 4;
/// The most hints an endpoint carries.
pub const FEDCODE_E2_MAX_HINTS: usize = 8;

const EARLIER_PREFIXES: [&str; 3] = ["CIRISV1", "CIRISV2", "CIRISV3"];
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const HINT_TCP: u8 = 1;
const HINT_UDP: u8 = 2;
const HINT_AUTO: u8 = 3;
const HINT_RNODE: u8 = 4;
const HINT_HTTP: u8 = 5;
const HINT_I2P: u8 = 6;
const HINT_KISS: u8 = 7;
const HINT_BLE: u8 = 8;

/// The entity a code names (CC 2.6.8: `kind` as in the earlier form).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// 1: a person; the only kind that embeds nodes.
    User,
    /// 2: an agent.
    Agent,
    /// 3: a node; the code carries that node's endpoint.
    Node,
    /// 4: a family.
    Family,
    /// 5: a community.
    Community,
}

impl Kind {
    fn byte(self) -> u8 {
        match self {
            Self::User => 1,
            Self::Agent => 2,
            Self::Node => 3,
            Self::Family => 4,
            Self::Community => 5,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            1 => Self::User,
            2 => Self::Agent,
            3 => Self::Node,
            4 => Self::Family,
            5 => Self::Community,
            _ => return None,
        })
    }
}

/// The scope of an `auto` (LAN multicast) interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoScope {
    /// 0.
    Link,
    /// 1.
    Admin,
    /// 2.
    Site,
    /// 3.
    Organisation,
    /// 4.
    Global,
}

/// One dial hint (unsigned; never authenticates anything). New interface
/// kinds become new variants.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Hint {
    /// A TCP listener: the node's own, or a relay it holds a client interface to.
    Tcp {
        /// DNS name or IP literal, 1..=253 bytes.
        host: String,
        /// Not 0.
        port: u16,
    },
    /// A UDP interface.
    Udp {
        /// DNS name or IP literal, 1..=253 bytes.
        host: String,
        /// Not 0.
        port: u16,
    },
    /// LAN multicast discovery.
    Auto {
        /// The multicast scope.
        scope: AutoScope,
        /// The group id, 1..=64 bytes.
        group_id: String,
    },
    /// A LoRa RNode.
    RNode {
        /// Hz, not 0.
        frequency_hz: u32,
        /// Hz, not 0.
        bandwidth_hz: u32,
        /// 7..=12.
        spreading_factor: u8,
        /// 5..=8.
        coding_rate: u8,
    },
    /// An HTTP transport, by its `https://` base URL.
    Http {
        /// The URL, ≤ 255 bytes.
        url: String,
    },
    /// An I2P destination.
    I2p {
        /// The 32-byte destination hash.
        destination: [u8; 32],
    },
    /// A KISS TNC (packet radio, serial).
    Kiss {
        /// Hz, not 0.
        frequency_hz: u32,
        /// Bits per second, not 0.
        bitrate: u32,
        /// AX.25 callsign-SSID, if named (1..=9 bytes).
        callsign: Option<String>,
    },
    /// Bluetooth LE, discovered locally: no identifier is carried.
    Ble,
    /// A type this parser does not know: carried in order, skipped by a dialler.
    Unknown {
        /// The type byte.
        tag: u8,
        /// The body as written.
        body: Vec<u8>,
    },
}

/// A node's reachability: its transport identity and its hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// The RNS transport public identity: X25519 (32) then Ed25519 (32). A
    /// transport key, never a federation key.
    pub transport_identity: [u8; 64],
    /// Most preferred first; possibly empty.
    pub hints: Vec<Hint>,
}

impl Endpoint {
    /// The RNS identity hash, `SHA-256(x25519 ‖ ed25519)[..16]` (CC 3.3.6.2).
    #[must_use]
    pub fn rns_identity_hash(&self) -> [u8; 16] {
        let d = Sha256::digest(self.transport_identity);
        let mut out = [0u8; 16];
        out.copy_from_slice(&d[..16]);
        out
    }

    fn transport_ed25519(&self) -> &[u8] {
        &self.transport_identity[32..]
    }
}

/// A node a user code embeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedNode {
    /// The node's composite-key thumbprint.
    pub kid: Digest32,
    /// How to reach it.
    pub endpoint: Endpoint,
}

/// A decoded edition-2 FedCode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FedCodeE2 {
    /// What the code names.
    pub kind: Kind,
    /// The thumbprint of the composite key (CC 2.6.1.7).
    pub kid: Digest32,
    /// A user code's nodes (empty for every other kind).
    pub nodes: Vec<EmbeddedNode>,
    /// A node code's own endpoint (`None` for every other kind).
    pub endpoint: Option<Endpoint>,
}

/// Why a code is refused. [`FedCodeE2Error::token`] names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FedCodeE2Error {
    /// Not a FedCode prefix at all.
    Prefix,
    /// A `CIRIS-V1-` … `CIRIS-V3-` code: the earlier form.
    EarlierForm,
    /// Not canonical unpadded base32.
    Base32,
    /// The CRC does not match.
    Crc,
    /// The version byte is not 0x04.
    Version,
    /// The kind byte is not 1..=5.
    Kind,
    /// The payload ends inside a field.
    Truncated,
    /// Bytes after the last field.
    TrailingBytes,
    /// Over 1024 bytes of payload.
    PayloadTooLarge,
    /// A kind other than user or node carries a body.
    NodesNotUser,
    /// More than four nodes.
    NodeCount,
    /// More than eight hints on one endpoint.
    HintCount,
    /// A known hint type whose body breaks its rule.
    HintMalformed,
    /// A node named twice, a node that is the identity itself, or two nodes
    /// with one transport identity.
    DuplicateNode,
    /// A transport identity's Ed25519 half is a federation key's (constraint 1).
    TransportIsFederationKey,
}

impl FedCodeE2Error {
    /// The stable refusal token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Prefix => "fedcode_prefix",
            Self::EarlierForm => "fedcode_earlier_form",
            Self::Base32 => "fedcode_base32",
            Self::Crc => "fedcode_crc",
            Self::Version => "fedcode_version",
            Self::Kind => "fedcode_kind",
            Self::Truncated => "fedcode_truncated",
            Self::TrailingBytes => "fedcode_trailing_bytes",
            Self::PayloadTooLarge => "fedcode_payload_too_large",
            Self::NodesNotUser => "fedcode_nodes_not_user",
            Self::NodeCount => "fedcode_node_count",
            Self::HintCount => "fedcode_hint_count",
            Self::HintMalformed => "fedcode_hint_malformed",
            Self::DuplicateNode => "fedcode_duplicate_node",
            Self::TransportIsFederationKey => "fedcode_transport_is_federation_key",
        }
    }
}

impl core::fmt::Display for FedCodeE2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.token())
    }
}

impl FedCodeE2 {
    /// A user code.
    #[must_use]
    pub fn user(kid: Digest32, nodes: Vec<EmbeddedNode>) -> Self {
        Self {
            kind: Kind::User,
            kid,
            nodes,
            endpoint: None,
        }
    }

    /// A node code.
    #[must_use]
    pub fn node(kid: Digest32, endpoint: Endpoint) -> Self {
        Self {
            kind: Kind::Node,
            kid,
            nodes: Vec::new(),
            endpoint: Some(endpoint),
        }
    }

    /// An agent, family or community code (the identity alone). A user or
    /// node `kind` here makes a code with no nodes or no endpoint.
    #[must_use]
    pub fn identity(kind: Kind, kid: Digest32) -> Self {
        Self {
            kind,
            kid,
            nodes: Vec::new(),
            endpoint: None,
        }
    }

    /// The payload bytes, before the CRC. Checks every rule the decoder does
    /// (a code another implementation minted is exactly what an encoder cannot
    /// police, so both sides enforce): an [`Hint::Unknown`] is refused here, a
    /// minter emits only the assigned types.
    ///
    /// # Errors
    ///
    /// The [`FedCodeE2Error`] the decoder would give the result.
    pub fn payload(&self) -> Result<Vec<u8>, FedCodeE2Error> {
        let mut out = vec![FEDCODE_E2_VERSION, self.kind.byte()];
        out.extend_from_slice(&self.kid);
        match self.kind {
            Kind::User => {
                if self.endpoint.is_some() {
                    return Err(FedCodeE2Error::NodesNotUser);
                }
                if self.nodes.len() > FEDCODE_E2_MAX_NODES {
                    return Err(FedCodeE2Error::NodeCount);
                }
                out.push(self.nodes.len() as u8);
                for n in &self.nodes {
                    out.extend_from_slice(&n.kid);
                    write_endpoint(&mut out, &n.endpoint)?;
                }
                check_distinct(&self.kid, &self.nodes)?;
            },
            Kind::Node => {
                if !self.nodes.is_empty() {
                    return Err(FedCodeE2Error::NodesNotUser);
                }
                let e = self.endpoint.as_ref().ok_or(FedCodeE2Error::Truncated)?;
                write_endpoint(&mut out, e)?;
            },
            _ => {
                if !self.nodes.is_empty() || self.endpoint.is_some() {
                    return Err(FedCodeE2Error::NodesNotUser);
                }
            },
        }
        if out.len() > FEDCODE_E2_MAX_PAYLOAD {
            return Err(FedCodeE2Error::PayloadTooLarge);
        }
        Ok(out)
    }

    /// The code as displayed: `CIRIS-V4-` and dash-separated groups of four.
    ///
    /// # Errors
    ///
    /// As [`Self::payload`].
    pub fn encode(&self) -> Result<String, FedCodeE2Error> {
        let body = self.qr_body()?;
        let mut s = String::from(FEDCODE_E2_PREFIX);
        for (i, c) in body.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                s.push('-');
            }
            s.push(c);
        }
        Ok(s)
    }

    /// The code for a QR: the prefix and the base32, ungrouped.
    ///
    /// # Errors
    ///
    /// As [`Self::payload`].
    pub fn encode_qr(&self) -> Result<String, FedCodeE2Error> {
        Ok(format!("{FEDCODE_E2_PREFIX}{}", self.qr_body()?))
    }

    fn qr_body(&self) -> Result<String, FedCodeE2Error> {
        let mut p = self.payload()?;
        let crc = crc16(&p);
        p.extend_from_slice(&crc.to_be_bytes());
        Ok(b32_encode(&p))
    }

    /// Decode a code, displayed or QR form (whitespace and dashes dropped,
    /// case folded).
    ///
    /// # Errors
    ///
    /// The first rule the code breaks.
    pub fn decode(code: &str) -> Result<Self, FedCodeE2Error> {
        let norm: String = code
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        if EARLIER_PREFIXES.iter().any(|p| norm.starts_with(p)) {
            return Err(FedCodeE2Error::EarlierForm);
        }
        let body = norm.strip_prefix("CIRISV4").ok_or(FedCodeE2Error::Prefix)?;
        let raw = b32_decode(body)?;
        if raw.len() < 2 {
            return Err(FedCodeE2Error::Truncated);
        }
        let (payload, crc) = raw.split_at(raw.len() - 2);
        if crc16(payload).to_be_bytes() != crc {
            return Err(FedCodeE2Error::Crc);
        }
        Self::from_payload(payload)
    }

    /// Decode the payload bytes (after the CRC is checked).
    ///
    /// # Errors
    ///
    /// The first rule the payload breaks.
    pub fn from_payload(p: &[u8]) -> Result<Self, FedCodeE2Error> {
        if p.len() > FEDCODE_E2_MAX_PAYLOAD {
            return Err(FedCodeE2Error::PayloadTooLarge);
        }
        let mut r = Reader { p, at: 0 };
        if r.u8()? != FEDCODE_E2_VERSION {
            return Err(FedCodeE2Error::Version);
        }
        let kind = Kind::from_byte(r.u8()?).ok_or(FedCodeE2Error::Kind)?;
        let kid: Digest32 = r.array()?;
        let mut code = Self::identity(kind, kid);
        match kind {
            Kind::User => {
                let n = usize::from(r.u8()?);
                if n > FEDCODE_E2_MAX_NODES {
                    return Err(FedCodeE2Error::NodeCount);
                }
                for _ in 0..n {
                    let kid = r.array()?;
                    let endpoint = read_endpoint(&mut r)?;
                    code.nodes.push(EmbeddedNode { kid, endpoint });
                }
                check_distinct(&code.kid, &code.nodes)?;
            },
            Kind::Node => code.endpoint = Some(read_endpoint(&mut r)?),
            _ => {
                if r.at < p.len() {
                    return Err(FedCodeE2Error::NodesNotUser);
                }
            },
        }
        if r.at != p.len() {
            return Err(FedCodeE2Error::TrailingBytes);
        }
        Ok(code)
    }

    /// Constraint 1 at resolution: no transport identity's Ed25519 half is
    /// the Ed25519 half of the code's own composite key or of the node's.
    /// `owner` is the key `self.kid` names (the user's, or a node code's
    /// node); `node_key` gives an embedded node's key by its kid, `None` when
    /// it is not held (that node is then checked against the owner alone).
    ///
    /// # Errors
    ///
    /// [`FedCodeE2Error::TransportIsFederationKey`].
    pub fn check_transport_keys<'a>(
        &self,
        owner: &CompositePublicKey,
        node_key: impl Fn(&Digest32) -> Option<&'a CompositePublicKey>,
    ) -> Result<(), FedCodeE2Error> {
        use subtle::ConstantTimeEq;
        let clash = |e: &Endpoint, k: &CompositePublicKey| -> bool {
            bool::from(e.transport_ed25519().ct_eq(k.ed25519_half().as_slice()))
        };
        if let Some(e) = &self.endpoint {
            if clash(e, owner) {
                return Err(FedCodeE2Error::TransportIsFederationKey);
            }
        }
        for n in &self.nodes {
            if clash(&n.endpoint, owner) || node_key(&n.kid).is_some_and(|k| clash(&n.endpoint, k))
            {
                return Err(FedCodeE2Error::TransportIsFederationKey);
            }
        }
        Ok(())
    }
}

fn check_distinct(kid: &Digest32, nodes: &[EmbeddedNode]) -> Result<(), FedCodeE2Error> {
    for (i, n) in nodes.iter().enumerate() {
        if n.kid == *kid
            || nodes[..i].iter().any(|m| {
                m.kid == n.kid || m.endpoint.transport_identity == n.endpoint.transport_identity
            })
        {
            return Err(FedCodeE2Error::DuplicateNode);
        }
    }
    Ok(())
}

struct Reader<'a> {
    p: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], FedCodeE2Error> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.p.len());
        let end = end.ok_or(FedCodeE2Error::Truncated)?;
        let s = &self.p[self.at..end];
        self.at = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, FedCodeE2Error> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FedCodeE2Error> {
        Ok(self.take(N)?.try_into().expect("take gives N bytes"))
    }
}

fn read_endpoint(r: &mut Reader<'_>) -> Result<Endpoint, FedCodeE2Error> {
    let transport_identity = r.array()?;
    let n = usize::from(r.u8()?);
    if n > FEDCODE_E2_MAX_HINTS {
        return Err(FedCodeE2Error::HintCount);
    }
    let mut hints = Vec::with_capacity(n);
    for _ in 0..n {
        let tag = r.u8()?;
        let len = usize::from(r.u8()?);
        let body = r.take(len)?;
        hints.push(parse_hint(tag, body)?);
    }
    Ok(Endpoint {
        transport_identity,
        hints,
    })
}

/// A hint's type byte and body, checked by reading them back. A
/// [`Hint::Unknown`] is not minted.
///
/// # Errors
///
/// [`FedCodeE2Error::HintMalformed`] for a hint the reader would refuse, or
/// an unknown one.
pub fn hint_parts(h: &Hint) -> Result<(u8, Vec<u8>), FedCodeE2Error> {
    let (tag, body) = hint_body(h)?;
    if body.len() > 255 {
        return Err(FedCodeE2Error::HintMalformed);
    }
    parse_hint(tag, &body)?;
    Ok((tag, body))
}

fn write_endpoint(out: &mut Vec<u8>, e: &Endpoint) -> Result<(), FedCodeE2Error> {
    if e.hints.len() > FEDCODE_E2_MAX_HINTS {
        return Err(FedCodeE2Error::HintCount);
    }
    out.extend_from_slice(&e.transport_identity);
    out.push(e.hints.len() as u8);
    for h in &e.hints {
        let (tag, body) = hint_parts(h)?;
        out.push(tag);
        out.push(body.len() as u8);
        out.extend_from_slice(&body);
    }
    Ok(())
}

fn hint_body(h: &Hint) -> Result<(u8, Vec<u8>), FedCodeE2Error> {
    let host_port = |port: u16, host: &str| {
        let mut b = port.to_be_bytes().to_vec();
        b.extend_from_slice(host.as_bytes());
        b
    };
    Ok(match h {
        Hint::Tcp { host, port } => (HINT_TCP, host_port(*port, host)),
        Hint::Udp { host, port } => (HINT_UDP, host_port(*port, host)),
        Hint::Auto { scope, group_id } => {
            let mut b = vec![*scope as u8];
            b.extend_from_slice(group_id.as_bytes());
            (HINT_AUTO, b)
        },
        Hint::RNode {
            frequency_hz,
            bandwidth_hz,
            spreading_factor,
            coding_rate,
        } => {
            let mut b = frequency_hz.to_be_bytes().to_vec();
            b.extend_from_slice(&bandwidth_hz.to_be_bytes());
            b.extend_from_slice(&[*spreading_factor, *coding_rate]);
            (HINT_RNODE, b)
        },
        Hint::Http { url } => (HINT_HTTP, url.as_bytes().to_vec()),
        Hint::I2p { destination } => (HINT_I2P, destination.to_vec()),
        Hint::Kiss {
            frequency_hz,
            bitrate,
            callsign,
        } => {
            let mut b = frequency_hz.to_be_bytes().to_vec();
            b.extend_from_slice(&bitrate.to_be_bytes());
            if let Some(c) = callsign {
                b.extend_from_slice(c.as_bytes());
            }
            (HINT_KISS, b)
        },
        Hint::Ble => (HINT_BLE, Vec::new()),
        Hint::Unknown { .. } => return Err(FedCodeE2Error::HintMalformed),
    })
}

/// Text of `lo..=hi` bytes with no space or control character.
fn text(b: &[u8], lo: usize, hi: usize) -> Result<String, FedCodeE2Error> {
    let s = core::str::from_utf8(b).map_err(|_| FedCodeE2Error::HintMalformed)?;
    if (lo..=hi).contains(&b.len()) && !s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        Ok(s.to_owned())
    } else {
        Err(FedCodeE2Error::HintMalformed)
    }
}

/// Read one hint from its type byte and body, under the rules above. An
/// unassigned type is [`Hint::Unknown`].
///
/// # Errors
///
/// [`FedCodeE2Error::HintMalformed`] for a known type with a bad body.
pub fn parse_hint(tag: u8, body: &[u8]) -> Result<Hint, FedCodeE2Error> {
    let bad = FedCodeE2Error::HintMalformed;
    let host_port = |body: &[u8]| -> Result<(String, u16), FedCodeE2Error> {
        let (p, h) = body.split_at_checked(2).ok_or(bad)?;
        let port = u16::from_be_bytes([p[0], p[1]]);
        if port == 0 {
            return Err(bad);
        }
        let host = text(h, 1, 253)?;
        // CC 2.6.8 (rc22): a DNS name or an IP literal in text form; IPv6
        // without brackets or a zone id, the port being its own field.
        if host.contains(['[', ']', '%']) {
            return Err(bad);
        }
        Ok((host, port))
    };
    Ok(match tag {
        HINT_TCP => {
            let (host, port) = host_port(body)?;
            Hint::Tcp { host, port }
        },
        HINT_UDP => {
            let (host, port) = host_port(body)?;
            Hint::Udp { host, port }
        },
        HINT_AUTO => {
            let (s, g) = body.split_first().ok_or(bad)?;
            let scope = match s {
                0 => AutoScope::Link,
                1 => AutoScope::Admin,
                2 => AutoScope::Site,
                3 => AutoScope::Organisation,
                4 => AutoScope::Global,
                _ => return Err(bad),
            };
            Hint::Auto {
                scope,
                group_id: text(g, 1, 64)?,
            }
        },
        HINT_RNODE => {
            let b: &[u8; 10] = body.try_into().map_err(|_| bad)?;
            let frequency_hz = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            let bandwidth_hz = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
            let (spreading_factor, coding_rate) = (b[8], b[9]);
            if frequency_hz == 0
                || bandwidth_hz == 0
                || !(7..=12).contains(&spreading_factor)
                || !(5..=8).contains(&coding_rate)
            {
                return Err(bad);
            }
            Hint::RNode {
                frequency_hz,
                bandwidth_hz,
                spreading_factor,
                coding_rate,
            }
        },
        HINT_HTTP => {
            let url = text(body, 9, 255)?;
            if !url.starts_with("https://") || url.len() == "https://".len() {
                return Err(bad);
            }
            Hint::Http { url }
        },
        HINT_I2P => Hint::I2p {
            destination: body.try_into().map_err(|_| bad)?,
        },
        HINT_KISS => {
            let (head, cs) = body.split_at_checked(8).ok_or(bad)?;
            let frequency_hz = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
            let bitrate = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
            if frequency_hz == 0 || bitrate == 0 || cs.len() > 9 {
                return Err(bad);
            }
            let callsign = if cs.is_empty() {
                None
            } else {
                let ok = cs
                    .iter()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'-')
                    && cs.iter().filter(|b| **b == b'-').count() <= 1
                    && cs[0] != b'-'
                    && cs[cs.len() - 1] != b'-';
                if !ok {
                    return Err(bad);
                }
                Some(String::from_utf8(cs.to_vec()).map_err(|_| bad)?)
            };
            Hint::Kiss {
                frequency_hz,
                bitrate,
                callsign,
            }
        },
        HINT_BLE => {
            if !body.is_empty() {
                return Err(bad);
            }
            Hint::Ble
        },
        tag => Hint::Unknown {
            tag,
            body: body.to_vec(),
        },
    })
}

fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn b32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Canonical unpadded base32 only: a trailing group whose unused bits are
/// not zero, or a length no byte string encodes to, is refused, so one
/// payload has one code.
fn b32_decode(s: &str) -> Result<Vec<u8>, FedCodeE2Error> {
    if matches!(s.len() % 8, 1 | 3 | 6) {
        return Err(FedCodeE2Error::Base32);
    }
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = B32
            .iter()
            .position(|&x| x == c)
            .ok_or(FedCodeE2Error::Base32)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    if acc != 0 {
        return Err(FedCodeE2Error::Base32);
    }
    Ok(out)
}
