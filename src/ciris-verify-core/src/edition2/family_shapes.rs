//! Shape rules of three families, each one checked function that the
//! statement reader calls for its family and a producer may call on the
//! payload it is about to sign, so a rule has one implementation (CC rc22,
//! ruled 2026-11-22):
//!
//! - **replies** ([`check_reply`]): a `membership:acceptance` or
//!   `membership:decline` names the row it answers in `refs.answers`, and
//!   that is its whole binding to it (CC 3.1.3.2). `refs.target` keeps its
//!   composer meaning and `refs.head` belongs to a counted row, so a reply
//!   carries neither; `proposal_hash` is a member of the earlier form.
//! - **objections** ([`check_objection`]): `objection:{state}` has exactly two
//!   states in this form, `assent` and `raised` (CC 3.1.9.2), and each names
//!   what it answers in `refs.answers`: the proposal it answers or the act it
//!   objects to. `objects_to_attestation_id` and `dismisses_objection_id` are
//!   the earlier form's, a row named outside `refs`. The proposal is the
//!   proposer's own row in its own family; the earlier form's `dismissed`,
//!   `upheld` and `overruled` are not states of this form, so a row under one
//!   is an unknown leaf of a closed family and is refused by the matcher.
//! - **keeps** ([`check_membership_keeps`]): a `membership:keeps` row holds
//!   further of a leaver's rows good for one end it cites. It is counted, it
//!   names the roster head it is counted over, it cites exactly one row, and
//!   it carries `refs.trusted_through`. Whether the row cited is an end of
//!   that member's seat needs the cited row held, so that half is the fold's.
//!
//! - **receipts** ([`check_act_ack`]): an `act:ack` row names each act it
//!   acknowledges in `refs.also.ack` (1 to 256; nothing is covered by
//!   ancestry) and names no head: a receipt that carries `refs.head` is
//!   malformed, since two readers would otherwise differ on whether it is
//!   read. Who may sign one is by role and is the fold's.
//!
//! Each needs nothing beyond the row.

#[allow(unused_imports)]
use crate::prelude::*;

use super::group::is_group_ref;
use super::{family, is_identity_ref, Invalid, Value};

/// The family id of `membership:{stage}`.
pub const MEMBERSHIP_FAMILY: &str = "membership:.stage";
/// The family id of `objection:{state}`.
pub const OBJECTION_FAMILY: &str = "objection:.state";
/// The family id of `act:ack` (registered by CC's next pre tag).
pub const ACT_ACK_FAMILY: &str = "act:ack";
/// The token of a `membership:keeps` row that cites no row, or several.
pub const KEEPS_CITES_NO_END: &str = "keeps_cites_no_end";

fn bad(member: &'static str) -> Invalid {
    Invalid::Malformed { member }
}

fn refs_member<'a>(payload: &'a Value, name: &str) -> Option<&'a Value> {
    payload.get_text("refs").and_then(|r| r.get_text(name))
}

/// A reply: a `membership:acceptance` or `membership:decline` payload.
///
/// # Errors
///
/// [`Invalid::Malformed`] naming `proposal_hash` where it is carried, or
/// `refs` where `refs.answers` is absent or `refs.target` or `refs.head` is
/// present.
pub fn check_reply(payload: &Value) -> Result<(), Invalid> {
    if payload.get_text("proposal_hash").is_some() {
        return Err(bad("proposal_hash"));
    }
    if refs_member(payload, "answers").is_none()
        || refs_member(payload, "target").is_some()
        || refs_member(payload, "head").is_some()
    {
        return Err(bad("refs"));
    }
    Ok(())
}

/// An `objection:{state}` payload, by its leaf: an `assent` or a `raised`
/// row, the family's two states, names what it answers in `refs.answers`
/// (one row-ref). A leaf outside the two is refused by the namespace matcher
/// before this is reached.
///
/// # Errors
///
/// [`Invalid::Malformed`] naming `objects_to_attestation_id` or
/// `dismisses_objection_id` where one is carried, or `refs` where an assent
/// or a raised row carries no `refs.answers`.
pub fn check_objection(leaf: Option<&str>, payload: &Value) -> Result<(), Invalid> {
    if payload.get_text("objects_to_attestation_id").is_some() {
        return Err(bad("objects_to_attestation_id"));
    }
    if payload.get_text("dismisses_objection_id").is_some() {
        return Err(bad("dismisses_objection_id"));
    }
    match leaf {
        Some("assent" | "raised") if refs_member(payload, "answers").is_none() => Err(bad("refs")),
        _ => Ok(()),
    }
}

/// An `act:ack` payload: a receipt of one or more acts.
///
/// # Errors
///
/// [`Invalid::Malformed`] naming `refs` where `refs.also.ack` is absent or
/// `refs.head` is present. (More than 256 acts is
/// [`Invalid::AckNamesTooMany`], from the refs check.)
pub fn check_act_ack(payload: &Value) -> Result<(), Invalid> {
    let acks = payload
        .get_text("refs")
        .and_then(|r| r.get_text("also"))
        .and_then(|a| a.get_text("ack"))
        .and_then(Value::as_array)
        .map_or(0, <[Value]>::len);
    if acks == 0 || refs_member(payload, "head").is_some() {
        return Err(bad("refs"));
    }
    Ok(())
}

/// A `membership:keeps` payload.
///
/// # Errors
///
/// [`Invalid::KeepsCitesNoEnd`] (token `keeps_cites_no_end`) where
/// `refs.also.cites` is absent or holds more than one row-ref;
/// [`Invalid::Malformed`] naming `author` (the row is counted), `refs` (no
/// `refs.head`, or no `refs.trusted_through`), or a member that is absent or
/// off its type (`group_kind`, `group`, `member`).
pub fn check_membership_keeps(payload: &Value) -> Result<(), Invalid> {
    if payload.get_text("author").is_some() {
        return Err(bad("author"));
    }
    if refs_member(payload, "head").is_none() || refs_member(payload, "trusted_through").is_none() {
        return Err(bad("refs"));
    }
    let cites = payload
        .get_text("refs")
        .and_then(|r| r.get_text("also"))
        .and_then(|a| a.get_text("cites"))
        .and_then(Value::as_array)
        .map_or(0, <[Value]>::len);
    if cites != 1 {
        return Err(Invalid::KeepsCitesNoEnd);
    }
    if !matches!(
        payload.get_text("group_kind").and_then(Value::as_text),
        Some("family" | "community")
    ) {
        return Err(bad("group_kind"));
    }
    if !payload
        .get_text("group")
        .and_then(Value::as_text)
        .is_some_and(is_group_ref)
    {
        return Err(bad("group"));
    }
    if !payload
        .get_text("member")
        .and_then(Value::as_text)
        .is_some_and(is_identity_ref)
    {
        return Err(bad("member"));
    }
    Ok(())
}

/// The reader's call: apply the rule of `family` to `payload`, by the leaf
/// its `dimension` binds. Other families have no rule here.
pub(super) fn check_family_shape(family_id: &str, payload: &Value) -> Result<(), Invalid> {
    match family_id {
        MEMBERSHIP_FAMILY => match family::dimension_leaf(family_id, payload).as_deref() {
            Some("acceptance" | "decline") => check_reply(payload),
            Some("keeps") => check_membership_keeps(payload),
            _ => Ok(()),
        },
        ACT_ACK_FAMILY => check_act_ack(payload),
        OBJECTION_FAMILY => check_objection(
            family::dimension_leaf(family_id, payload).as_deref(),
            payload,
        ),
        _ => Ok(()),
    }
}
