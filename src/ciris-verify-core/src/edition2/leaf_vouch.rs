//! The door of an MLS leaf (CC 5.1; CIRISConstitution v1.0-rc22 f467193).
//!
//! A member vouches for the MLS leaf key of one of its devices by an
//! `mls:leaf_vouch` row ([`super::family_shapes::check_leaf_vouch`] holds its
//! shape). The row's `leaves` are blinded elements, one for each room vouched
//! for; a LeafNode's credential carries the row and that room's disclosure,
//! which opens to `[leaf_key, room, suite]`. Every Add, Update and Commit
//! path checks the vouch, and refuses a leaf whose vouch is absent, ended,
//! for another room, for another leaf key, or under a key that is not the
//! member's, in that order.
//!
//! [`check_leaf_at_door`] is that check over a row the statement reader
//! verified (the signature under the member's device key, the row's shape,
//! and that each disclosure opens a blinded element of the row are the
//! reader's). It reads no clock: `now_ms` is the caller's. A vouch the signer
//! withdrew has ended; the withdrawal is a row the caller holds, so the
//! caller says so. Authentication of the leaf under suite 0x004D is
//! classical (Ed25519): the vouch ties that leaf key to the member's
//! composite key for the vouch's term and no longer.
//!
//! Pure: no clock, no randomness, no I/O.

use super::family_shapes::{LEAF_VOUCH_FAMILY, LEAF_VOUCH_SUITE};
use super::group::is_group_ref;
use super::{Invalid, Value, VerifiedRow};
use crate::prelude::*;
use subtle::ConstantTimeEq;

/// Why a leaf is refused at a room's door, with CC's tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeafVouchRefusal {
    /// No vouching row is presented, or the row presented is not an
    /// `mls:leaf_vouch` row: `leaf_vouch_absent`.
    Absent,
    /// The presentation discloses no entry, more than one, or one that is
    /// not `[leaf_key, room, suite]`: `leaf_vouch_presentation_invalid`.
    PresentationInvalid,
    /// `now` is outside `[valid_from, valid_until)`, or the signer withdrew
    /// the vouch: `leaf_vouch_ended`.
    Ended,
    /// The entry names another room: `leaf_vouch_other_room`.
    OtherRoom,
    /// The entry names another leaf key: `leaf_vouch_other_leaf`.
    OtherLeaf,
    /// The row's signer is not the member whose leaf it is:
    /// `leaf_vouch_not_by_member`.
    NotByMember,
}

impl LeafVouchRefusal {
    /// CC's refusal token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Absent => "leaf_vouch_absent",
            Self::PresentationInvalid => "leaf_vouch_presentation_invalid",
            Self::Ended => "leaf_vouch_ended",
            Self::OtherRoom => "leaf_vouch_other_room",
            Self::OtherLeaf => "leaf_vouch_other_leaf",
            Self::NotByMember => "leaf_vouch_not_by_member",
        }
    }
}

impl From<LeafVouchRefusal> for Invalid {
    fn from(r: LeafVouchRefusal) -> Self {
        match r {
            LeafVouchRefusal::PresentationInvalid => Self::LeafVouchPresentationInvalid,
            _ => Self::Malformed { member: "leaves" },
        }
    }
}

/// What one blinded element of a leaf vouch discloses (`leaf-vouch-entry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafVouchEntry {
    /// The leaf's Ed25519 public key.
    pub leaf_key: [u8; 32],
    /// The room the leaf is vouched for, by its derived id.
    pub room: String,
}

/// Read a disclosed element's value as `[leaf_key, room, suite]`: 32 bytes,
/// a group reference, and the constant 0x004D.
#[must_use]
pub fn read_leaf_vouch_entry(value: &Value) -> Option<LeafVouchEntry> {
    match value.as_array()? {
        [k, r, s] if s.as_u64() == Some(LEAF_VOUCH_SUITE) => Some(LeafVouchEntry {
            leaf_key: k.as_bytes()?.try_into().ok()?,
            room: r.as_text().filter(|r| is_group_ref(r))?.to_owned(),
        }),
        _ => None,
    }
}

/// The value a blinded element of a leaf vouch discloses, for a producer:
/// `[leaf_key, room, 77]`.
#[must_use]
pub fn leaf_vouch_entry_value(leaf_key: &[u8; 32], room: &str) -> Value {
    Value::Array(vec![
        Value::Bytes(leaf_key.to_vec()),
        Value::Text(room.into()),
        Value::Uint(LEAF_VOUCH_SUITE),
    ])
}

/// What the door is checking a leaf against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafDoor<'a> {
    /// The room whose MLS group the leaf is in, by its derived id (the door
    /// recomputes it from the group's id, [`super::room::mls_group_id`]).
    pub room: &'a str,
    /// The LeafNode's signature key.
    pub leaf_key: &'a [u8; 32],
    /// The member whose leaf it is: a person, an agent, or in a private room
    /// a voice, as an identity reference.
    pub member: &'a str,
    /// The door's instant, POSIX milliseconds.
    pub now_ms: u64,
    /// The caller holds the signer's withdrawal of this vouch.
    pub withdrawn: bool,
}

/// Check a presented vouch at a room's door (CC 5.1). `row` is the vouching
/// row as the statement reader verified it with the presentation's
/// disclosures, or `None` where the credential carries none.
///
/// # Errors
///
/// The first of the refusals, in CC's order: `leaf_vouch_absent`,
/// `leaf_vouch_presentation_invalid` (the presentation does not disclose
/// exactly one entry), `leaf_vouch_ended`, `leaf_vouch_other_room`,
/// `leaf_vouch_other_leaf`, `leaf_vouch_not_by_member`.
pub fn check_leaf_at_door(
    row: Option<&VerifiedRow>,
    door: &LeafDoor<'_>,
) -> Result<LeafVouchEntry, LeafVouchRefusal> {
    let row = row
        .filter(|r| r.family == LEAF_VOUCH_FAMILY && r.row_type == "scores")
        .ok_or(LeafVouchRefusal::Absent)?;
    // A presentation discloses exactly one entry. Every disclosure of this
    // row opens an element of `leaves` or a member; only elements are
    // entries, and a row presented with any other disclosure is not a
    // presentation of one entry.
    let entry = match row.disclosures.as_slice() {
        [d] if d.key.is_none() => {
            read_leaf_vouch_entry(&d.value).ok_or(LeafVouchRefusal::PresentationInvalid)?
        },
        _ => return Err(LeafVouchRefusal::PresentationInvalid),
    };
    let time = |m: &str| row.payload.get_text(m).and_then(Value::as_u64);
    let live = matches!(
        (time("valid_from"), time("valid_until")),
        (Some(from), Some(until)) if from <= door.now_ms && door.now_ms < until
    );
    if !live || door.withdrawn {
        return Err(LeafVouchRefusal::Ended);
    }
    if entry.room != door.room {
        return Err(LeafVouchRefusal::OtherRoom);
    }
    if !bool::from(entry.leaf_key.ct_eq(door.leaf_key)) {
        return Err(LeafVouchRefusal::OtherLeaf);
    }
    if row.iss != door.member || row.author.as_deref() != Some(door.member) {
        return Err(LeafVouchRefusal::NotByMember);
    }
    Ok(entry)
}
