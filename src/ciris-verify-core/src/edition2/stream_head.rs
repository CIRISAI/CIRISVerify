//! `stream:head`: a producer's signed head of a stream's chunk log (CC rc22
//! 5.3.3.8), an edition-2 row and so a SCITT Signed Statement a Transparency
//! Service registers.
//!
//! ```text
//! family   stream:head          (authored by the producer, no second signer)
//! CWT sub  "stream:" ‖ stream id (the stream id is text, "av-" ‖ 64 lowercase hex for A/V; never bare 64-hex)
//! payload  { "author": identity-ref, "asserted_at": ms-time, "epoch": uint, "tree_size": uint ≥ 1,
//!            "root": hash-digest, ? "sealed": true, ? "room": tstr, ? "refs": { "prev": row-ref } }
//! ```
//!
//! A head with a `room` is an accountable (profile-1) head, held to that
//! room's receipt policy: the room's `transparency_services` and its
//! `receipt_quorum` (the charter rule; [`super::receipt::head_receipt_services`]
//! counts). A head without one is best-effort and is never counted as
//! accountable.
//!
//! [`check_stream_head`] is the row's own rule (the door). [`check_successor`]
//! is a service's registration rule, keyed on the service's OWN last head
//! for the `sub`: consistency with it decides; `refs.prev` is the producer's
//! claim, judged only when the service holds the head it names; a first head
//! registers as the service's first.

#[allow(unused_imports)]
use crate::prelude::*;

use subtle::ConstantTimeEq;

use super::{check_hash_digest, is_identity_ref, Digest32, Invalid};
use crate::cde::Value;

/// The family of a stream head.
pub const STREAM_HEAD_FAMILY: &str = "stream:head";
/// The `sub` prefix of a stream head.
pub const STREAM_SUB_PREFIX: &str = "stream:";

/// A stream head as the door reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamHead {
    /// The stream id (the `sub` without its prefix).
    pub stream_id: String,
    /// The producer.
    pub author: String,
    /// POSIX ms.
    pub asserted_at: u64,
    /// The MLS epoch.
    pub epoch: u64,
    /// The chunk log's size.
    pub tree_size: u64,
    /// The chunk log's RFC 9162 root.
    pub root: Digest32,
    /// The sealing head.
    pub sealed: bool,
    /// The room (community key id), for an accountable head.
    pub room: Option<String>,
    /// The previous head the producer names, by row id.
    pub prev: Option<Digest32>,
}

fn bad(member: &'static str) -> Invalid {
    Invalid::Malformed { member }
}

fn is_bare_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The row's own rule: the closed payload, each member at its type, and the
/// `sub` a stream subject whose id is not bare 64-hex (that space is the
/// inline-blob log's, CIRISPersist#953).
///
/// # Errors
///
/// [`Invalid::Malformed`] naming the member off its rule.
pub fn check_stream_head(payload: &Value, sub: &str) -> Result<StreamHead, Invalid> {
    let m = payload.as_map().ok_or(bad("stream-head"))?;
    const MEMBERS: [&str; 8] = [
        "author",
        "asserted_at",
        "epoch",
        "tree_size",
        "root",
        "sealed",
        "room",
        "refs",
    ];
    if m.iter()
        .any(|(k, _)| !k.as_text().is_some_and(|t| MEMBERS.contains(&t)))
    {
        return Err(Invalid::UnexpectedMember {
            within: "stream-head",
        });
    }
    let stream_id = sub
        .strip_prefix(STREAM_SUB_PREFIX)
        .filter(|id| !id.is_empty() && !is_bare_hex64(id))
        .ok_or(bad("sub"))?
        .to_owned();
    let text = |k: &'static str| payload.get_text(k).and_then(Value::as_text);
    let uint = |k: &'static str| payload.get_text(k).and_then(Value::as_u64).ok_or(bad(k));
    let author = text("author")
        .filter(|a| is_identity_ref(a))
        .ok_or(bad("author"))?
        .to_owned();
    let asserted_at = uint("asserted_at")?;
    let epoch = uint("epoch")?;
    let tree_size =
        uint("tree_size").and_then(|n| if n >= 1 { Ok(n) } else { Err(bad("tree_size")) })?;
    let r = payload.get_text("root").ok_or(bad("root"))?;
    check_hash_digest(r, "root")?;
    let root: Digest32 = r
        .as_array()
        .and_then(|a| a[1].as_bytes())
        .and_then(|b| b.try_into().ok())
        .ok_or(bad("root"))?;
    let sealed = match payload.get_text("sealed") {
        None => false,
        Some(Value::Bool(true)) => true,
        Some(_) => return Err(bad("sealed")),
    };
    let room = match payload.get_text("room") {
        None => None,
        Some(v) => Some(
            v.as_text()
                .filter(|t| !t.is_empty())
                .ok_or(bad("room"))?
                .to_owned(),
        ),
    };
    let prev = match payload.get_text("refs") {
        None => None,
        Some(refs) => {
            let rm = refs.as_map().ok_or(bad("refs"))?;
            if rm.len() != 1 || rm[0].0.as_text() != Some("prev") {
                return Err(Invalid::UnexpectedMember { within: "refs" });
            }
            let p = &rm[0].1;
            let id = p
                .as_array()
                .filter(|a| a.len() == 2 && a[0].as_u64() == Some(2))
                .and_then(|a| a[1].as_array())
                .filter(|h| h.len() == 2)
                .and_then(|h| h[1].as_bytes())
                .and_then(|b| <Digest32>::try_from(b).ok())
                .ok_or(bad("prev"))?;
            Some(id)
        },
    };
    Ok(StreamHead {
        stream_id,
        author,
        asserted_at,
        epoch,
        tree_size,
        root,
        sealed,
        room,
        prev,
    })
}

/// The head a service last registered for a `sub`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastHead {
    /// Its row id.
    pub row_id: Digest32,
    /// Its epoch.
    pub epoch: u64,
    /// Its tree size.
    pub tree_size: u64,
    /// Its root.
    pub root: Digest32,
}

/// How the caller establishes that the new head's tree extends the last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Consistency {
    /// An RFC 9162 consistency proof from the last head's size to the new
    /// one (submission material, or RFC 9942 `vdp` key -2).
    Proof(Vec<Digest32>),
    /// A holder recomputed both roots from the chunks it holds.
    Recomputed {
        /// The root of the first `last.tree_size` leaves.
        prev_root: Digest32,
        /// The root of the first `head.tree_size` leaves.
        new_root: Digest32,
    },
}

/// Why a service refuses to register a head. Each refused head is kept as
/// evidence by the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamHeadRefusal {
    /// `refs.prev` names a head the service holds that is not its last.
    PrevNotLast,
    /// A head at a size the service registered, with another root.
    Equivocation,
    /// The same size and root again, not as the sealing head.
    Repeated,
    /// The epoch is below the last head's.
    EpochRegressed,
    /// The new tree does not extend the last (a smaller size, or the
    /// consistency check fails).
    Inconsistent,
    /// The head's `room` is not the binding's (or a profile-0 stream's head
    /// names one).
    RoomMismatch,
}

impl StreamHeadRefusal {
    /// The stable refusal token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::PrevNotLast => "stream_head_prev_not_last",
            Self::Equivocation => "stream_head_equivocation",
            Self::Repeated => "stream_head_repeated",
            Self::EpochRegressed => "stream_head_epoch_regressed",
            Self::Inconsistent => "stream_head_inconsistent",
            Self::RoomMismatch => "stream_head_room_mismatch",
        }
    }
}

/// A service's registration rule for `head` after `last` (its own last head
/// for the `sub`; `None` registers `head` as its first). `holds` says
/// whether the service holds a head by row id; `refs.prev` is judged only
/// then.
///
/// # Errors
///
/// [`StreamHeadRefusal`], in the order: prev, epoch, size, consistency.
pub fn check_successor(
    last: Option<&LastHead>,
    head: &StreamHead,
    holds: impl Fn(&Digest32) -> bool,
    consistency: &Consistency,
) -> Result<(), StreamHeadRefusal> {
    let Some(last) = last else { return Ok(()) };
    if let Some(p) = &head.prev {
        if holds(p) && !bool::from(p.ct_eq(&last.row_id)) {
            return Err(StreamHeadRefusal::PrevNotLast);
        }
    }
    if head.epoch < last.epoch {
        return Err(StreamHeadRefusal::EpochRegressed);
    }
    let same_root = bool::from(head.root.ct_eq(&last.root));
    if head.tree_size == last.tree_size {
        return match (same_root, head.sealed) {
            (true, true) => Ok(()),
            (true, false) => Err(StreamHeadRefusal::Repeated),
            (false, _) => Err(StreamHeadRefusal::Equivocation),
        };
    }
    if head.tree_size < last.tree_size {
        return Err(StreamHeadRefusal::Inconsistent);
    }
    let ok = match consistency {
        Consistency::Proof(p) => {
            super::receipt::consistent(last.tree_size, &last.root, head.tree_size, &head.root, p)
        },
        Consistency::Recomputed {
            prev_root,
            new_root,
        } => bool::from(prev_root.ct_eq(&last.root)) && bool::from(new_root.ct_eq(&head.root)),
    };
    if ok {
        Ok(())
    } else {
        Err(StreamHeadRefusal::Inconsistent)
    }
}

/// A verifier holding the stream's binding: a profile-1 binding's room must
/// be the head's; a profile-0 stream's heads name none.
///
/// # Errors
///
/// [`StreamHeadRefusal::RoomMismatch`].
pub fn check_against_binding(
    head: &StreamHead,
    profile: u8,
    binding_room: &str,
) -> Result<(), StreamHeadRefusal> {
    match (profile, head.room.as_deref()) {
        (1, Some(r)) if r == binding_room => Ok(()),
        (0, None) => Ok(()),
        _ => Err(StreamHeadRefusal::RoomMismatch),
    }
}
