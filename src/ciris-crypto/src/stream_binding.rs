//! The StreamKeyBinding (CC 5.3.3.5, v2): the publisher's signed statement of
//! which chunk key seals a call stream, read and verified one way by the
//! holder at the first chunk, a stream head's door and a Transparency
//! Service.
//!
//! ```text
//! version     u8 0x02
//! room        u16 len ‖ UTF-8, 1..=1024 (the community key id)
//! publisher   u16 len ‖ UTF-8, 1..=1024 (the publishing member's identity reference)
//! join_nonce  32
//! stream_id   32  = call_stream_id(room, publisher, join_nonce)
//! epoch       u64
//! chunk_key   32  (Ed25519)
//! codec_map   u8 count 0..=8 ‖ count × (class u8 ‖ u16 len ‖ token ASCII 1..=32), sorted by class, no class twice
//! replaces    u8 0 | 1 ‖ (if 1) stream_id 32
//! end         u8 0 none | 1 Left | 2 Backgrounded | 3 Ended
//! final_seq   u64, iff end ≠ 0
//! kind        u8 (0 media, 1 share; any other value reads as media)
//! framing     u8 0 | 1
//! profile     u8 0 | 1
//! head_interval_s  u32 ≥ 30, iff profile = 1
//! signature   u16 len = 3373 ‖ composite (CC 2.6.1.7)
//! ```
//!
//! The encoding is at most 8192 bytes and trailing bytes are refused. The
//! signing bytes are `"ciris-edge:av-stream-key:v2" ‖ body`, body being
//! everything before the signature's length. Known answers:
//! `tests/vectors/composite/stream_key_binding_v2_composite_v3.json`.

#[allow(unused_imports)]
use crate::prelude::*;

use crate::composite::{CompositePublicKey, SIGNATURE_LEN};
use crate::stream_seal::{call_stream_id, CALL_STREAM_FIELD_MAX};

/// The binding's version byte.
pub const STREAM_KEY_BINDING_VERSION: u8 = 0x02;
/// The signing-bytes label.
pub const STREAM_KEY_BINDING_LABEL: &[u8] = b"ciris-edge:av-stream-key:v2";
/// The largest encoding.
pub const STREAM_KEY_BINDING_MAX: usize = 8192;
/// The least `head_interval_s` an accountable binding states.
pub const HEAD_INTERVAL_FLOOR_SECS: u32 = 30;
const MAX_CODECS: usize = 8;

/// Why a binding is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BindingError {
    /// Over 8192 bytes.
    TooLarge,
    /// The encoding ends inside a field.
    Truncated,
    /// Bytes after the signature.
    TrailingBytes,
    /// The version byte is not 0x02.
    Version,
    /// A field off its rule (lengths, text, codec map, enum values).
    Malformed(&'static str),
    /// `stream_id` is not the derivation from room, publisher and join nonce.
    StreamIdMismatch,
    /// An accountable binding's `head_interval_s` is under 30.
    HeadIntervalBelowFloor,
    /// The publisher's composite signature does not verify.
    BadSignature,
}

impl BindingError {
    /// A stable name.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::TooLarge => "binding_too_large",
            Self::Truncated => "binding_truncated",
            Self::TrailingBytes => "binding_trailing_bytes",
            Self::Version => "binding_version",
            Self::Malformed(_) => "binding_malformed",
            Self::StreamIdMismatch => "binding_stream_id_mismatch",
            Self::HeadIntervalBelowFloor => "stream_head_interval_below_floor",
            Self::BadSignature => "binding_bad_signature",
        }
    }
}

/// How a stream ended, if it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEnd {
    /// 1.
    Left,
    /// 2.
    Backgrounded,
    /// 3.
    Ended,
}

/// A parsed binding. Parsing checks the layout and the stream id; the
/// signature is checked by [`verify_stream_key_binding`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamKeyBinding {
    /// The community key id.
    pub room: String,
    /// The publishing member's identity reference.
    pub publisher: String,
    /// The join nonce.
    pub join_nonce: [u8; 32],
    /// The stream id (it recomputes from the three above).
    pub stream_id: [u8; 32],
    /// The room's MLS epoch.
    pub epoch: u64,
    /// The Ed25519 chunk key.
    pub chunk_key: [u8; 32],
    /// `(class, token)`, sorted by class.
    pub codecs: Vec<(u8, String)>,
    /// The stream this one replaces.
    pub replaces: Option<[u8; 32]>,
    /// How it ended, with its final sequence number.
    pub end: Option<(StreamEnd, u64)>,
    /// 0 media, 1 share (any other value reads as media).
    pub kind: u8,
    /// 0 none, 1 fragments.
    pub framing: u8,
    /// 0 best-effort, 1 accountable.
    pub profile: u8,
    /// The most seconds between heads, for an accountable stream.
    pub head_interval_s: Option<u32>,
    /// The signed body.
    pub body: Vec<u8>,
    /// The composite signature.
    pub signature: Vec<u8>,
}

struct R<'a> {
    b: &'a [u8],
    at: usize,
}

impl R<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], BindingError> {
        let end = self
            .at
            .checked_add(n)
            .filter(|&e| e <= self.b.len())
            .ok_or(BindingError::Truncated)?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, BindingError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, BindingError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, BindingError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4")))
    }
    fn u64(&mut self) -> Result<u64, BindingError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8")))
    }
    fn a32(&mut self) -> Result<[u8; 32], BindingError> {
        Ok(self.take(32)?.try_into().expect("32"))
    }
    fn text(&mut self, max: usize, what: &'static str) -> Result<String, BindingError> {
        let n = usize::from(self.u16()?);
        if n == 0 || n > max {
            return Err(BindingError::Malformed(what));
        }
        core::str::from_utf8(self.take(n)?)
            .map(str::to_owned)
            .map_err(|_| BindingError::Malformed(what))
    }
}

/// Read a binding's encoding, checking its layout and its stream id.
///
/// # Errors
///
/// The first [`BindingError`].
pub fn parse_stream_key_binding(bytes: &[u8]) -> Result<StreamKeyBinding, BindingError> {
    if bytes.len() > STREAM_KEY_BINDING_MAX {
        return Err(BindingError::TooLarge);
    }
    let mut r = R { b: bytes, at: 0 };
    if r.u8()? != STREAM_KEY_BINDING_VERSION {
        return Err(BindingError::Version);
    }
    let room = r.text(CALL_STREAM_FIELD_MAX, "room")?;
    let publisher = r.text(CALL_STREAM_FIELD_MAX, "publisher")?;
    let join_nonce = r.a32()?;
    let stream_id = r.a32()?;
    let epoch = r.u64()?;
    let chunk_key = r.a32()?;
    let count = usize::from(r.u8()?);
    if count > MAX_CODECS {
        return Err(BindingError::Malformed("codec_map"));
    }
    let mut codecs: Vec<(u8, String)> = Vec::with_capacity(count);
    for _ in 0..count {
        let class = r.u8()?;
        let n = usize::from(r.u16()?);
        let tok = r.take(n)?;
        if !(1..=32).contains(&n) || !tok.iter().all(|c| c.is_ascii_graphic()) {
            return Err(BindingError::Malformed("codec_map"));
        }
        if codecs.last().is_some_and(|(c, _)| *c >= class) {
            return Err(BindingError::Malformed("codec_map"));
        }
        codecs.push((class, String::from_utf8(tok.to_vec()).expect("ascii")));
    }
    let replaces = match r.u8()? {
        0 => None,
        1 => Some(r.a32()?),
        _ => return Err(BindingError::Malformed("replaces")),
    };
    let end = match r.u8()? {
        0 => None,
        e @ 1..=3 => {
            let how = match e {
                1 => StreamEnd::Left,
                2 => StreamEnd::Backgrounded,
                _ => StreamEnd::Ended,
            };
            Some((how, r.u64()?))
        },
        _ => return Err(BindingError::Malformed("end")),
    };
    let kind = r.u8()?;
    let framing = r.u8()?;
    if framing > 1 {
        return Err(BindingError::Malformed("framing"));
    }
    let profile = r.u8()?;
    let head_interval_s = match profile {
        0 => None,
        1 => {
            let t = r.u32()?;
            if t < HEAD_INTERVAL_FLOOR_SECS {
                return Err(BindingError::HeadIntervalBelowFloor);
            }
            Some(t)
        },
        _ => return Err(BindingError::Malformed("profile")),
    };
    let body_end = r.at;
    if usize::from(r.u16()?) != SIGNATURE_LEN {
        return Err(BindingError::Malformed("signature"));
    }
    let signature = r.take(SIGNATURE_LEN)?.to_vec();
    if r.at != bytes.len() {
        return Err(BindingError::TrailingBytes);
    }
    let want = call_stream_id(&room, &publisher, &join_nonce)
        .map_err(|_| BindingError::Malformed("room"))?;
    if want != stream_id {
        return Err(BindingError::StreamIdMismatch);
    }
    Ok(StreamKeyBinding {
        room,
        publisher,
        join_nonce,
        stream_id,
        epoch,
        chunk_key,
        codecs,
        replaces,
        end,
        kind,
        framing,
        profile,
        head_interval_s,
        body: bytes[..body_end].to_vec(),
        signature,
    })
}

/// Verify a parsed binding's composite signature under the publisher's key,
/// which the caller resolves from `binding.publisher`.
///
/// # Errors
///
/// [`BindingError::BadSignature`].
pub fn verify_stream_key_binding(
    binding: &StreamKeyBinding,
    publisher_key: &CompositePublicKey,
) -> Result<(), BindingError> {
    let mut msg = STREAM_KEY_BINDING_LABEL.to_vec();
    msg.extend_from_slice(&binding.body);
    publisher_key
        .verify(&msg, &binding.signature)
        .map_err(|_| BindingError::BadSignature)
}
