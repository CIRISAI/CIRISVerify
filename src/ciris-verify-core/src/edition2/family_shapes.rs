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
//! - **the acceptance edge** ([`check_trust_accepts`]): a `trust:accepts`
//!   row is one of three kinds, said by its payload: with
//!   `attached_head_digest` it attaches a root (CC 3.2 T4a); with
//!   `service_key` it is an edge to a Transparency Service, whose `sub` is
//!   that key's name; with neither it is an admission-walk or licensor edge.
//!   None carries `refs.head` or `scope`. Whether a root edge lacks a digest
//!   it owes, the head it names, and who signed it need held bundles,
//!   Receipts and owner-bindings, and are the fold's.
//!
//! - **the owner-binding** ([`check_owner_binding`]): an
//!   `ownership:{relation}:{target_kind}:{version}` row, the owner's
//!   `delegates_to` to a key it answers for (CC 3.2). Its one purpose is
//!   `owner_binding`; `scope` is a set; its end is later than its start; it
//!   carries the group member its `cohort_scope` asks and no other; and a key
//!   held for an organisation names that affiliation in `on_behalf_of` and
//!   the affiliation's roster version in `refs.head`, the only `refs` role.
//!   Whether `on_behalf_of` names an affiliation, and which binding of a key
//!   is the live one, need rows held and are the fold's.
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
/// The family id of `trust:{job}:{version}`.
pub const TRUST_FAMILY: &str = "trust:.job:.version";
/// The token of a new root edge that names no head (CC 3.2 T4a). The fold's:
/// it needs a held lineage of the name in `sub`, so no check here gives it.
pub const TRUST_ROOT_HEAD_UNNAMED: &str = "trust_root_head_unnamed";
/// The largest `trust_depth` of an acceptance edge (CC 4.4.3.34).
pub const TRUST_DEPTH_MAX: u64 = 5;
/// The family id of `act:ack` (registered by CC's next pre tag).
pub const ACT_ACK_FAMILY: &str = "act:ack";
/// The family id of `ownership:{relation}:{target_kind}:{version}`.
pub const OWNERSHIP_FAMILY: &str = "ownership:.relation:.target_kind:.version";
/// The one `delegation_purpose` of an owner-binding.
pub const OWNER_BINDING_PURPOSE: &str = "owner_binding";
/// The seven values of `cohort_scope` (CC 2.1).
pub const COHORT_SCOPES: [&str; 7] = [
    "self",
    "family",
    "community",
    "affiliations",
    "species",
    "biosphere",
    "federation",
];
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

/// A `trust:accepts` edge, with the statement's CWT `sub`. Its payload says
/// which of three kinds it is (CC 3.2 T3/T4a, CC 2.7.11, CC 4.4.3.34):
///
/// - it carries `attached_head_digest`: it attaches a root, and `sub` is read
///   as that lineage's name (free text, so nothing of `sub` is checked);
/// - it carries `service_key`: it is an edge to a Transparency Service, and
///   `sub` is that key's RFC 9679 thumbprint in the key-segment form (the 43
///   characters after the identity-reference prefix) where `service_key` is a
///   COSE key, or the identity where it is an identity reference;
/// - it carries neither: an admission-walk or licensor edge.
///
/// No edge carries `refs.head` or `scope`; `service_key` is present exactly
/// where `trust_classes` contains `transparency`; and no edge carries both
/// `service_key` and `attached_head_digest`. That a new root edge without
/// the digest is refused ([`TRUST_ROOT_HEAD_UNNAMED`]) needs a held lineage
/// of the name in `sub`, so it is the fold's and not checked here.
///
/// `trust_classes`, where present, is a non-empty sorted set of class ids
/// with no repeat, and `trust_depth`, where present, is `0..=5`
/// ([`TRUST_DEPTH_MAX`]; CC 4.4.3.34).
///
/// # Errors
///
/// [`Invalid::TrustAcceptsClassesMalformed`] (token
/// `trust_accepts_classes_malformed`) and
/// [`Invalid::TrustAcceptsDepthOutOfRange`] (token
/// `trust_accepts_depth_out_of_range`); otherwise
/// [`Invalid::Malformed`] naming `refs` (`refs.head` present), `scope`
/// (present), `attached_head_digest` (not a hash-digest, or beside a
/// `service_key`), `service_key` (present or absent against `trust_classes`,
/// not a COSE key of a known key type nor an identity reference), or `sub`
/// (a service edge whose `sub` is not its key's name).
pub fn check_trust_accepts(sub: &str, payload: &Value) -> Result<(), Invalid> {
    if refs_member(payload, "head").is_some() {
        return Err(bad("refs"));
    }
    if payload.get_text("scope").is_some() {
        return Err(bad("scope"));
    }
    let digest = payload.get_text("attached_head_digest");
    if let Some(d) = digest {
        let is_digest = matches!(
            d.as_array(),
            Some([alg, bytes]) if alg.as_i64() == Some(-16)
                && bytes.as_bytes().is_some_and(|b| b.len() == 32)
        );
        if !is_digest {
            return Err(bad("attached_head_digest"));
        }
    }
    let classes = match payload.get_text("trust_classes") {
        None => &[][..],
        Some(v) => v
            .as_array()
            .filter(|a| {
                !a.is_empty()
                    && a.iter().all(|c| c.as_text().is_some())
                    && super::check_set(a, "trust_classes").is_ok()
            })
            .ok_or(Invalid::TrustAcceptsClassesMalformed)?,
    };
    if payload
        .get_text("trust_depth")
        .is_some_and(|d| !d.as_u64().is_some_and(|n| n <= TRUST_DEPTH_MAX))
    {
        return Err(Invalid::TrustAcceptsDepthOutOfRange);
    }
    let transparency = classes.iter().any(|c| c.as_text() == Some("transparency"));
    let service_key = payload.get_text("service_key");
    if service_key.is_some() != transparency {
        return Err(bad("service_key"));
    }
    let Some(key) = service_key else {
        return Ok(());
    };
    if digest.is_some() {
        return Err(bad("attached_head_digest"));
    }
    let name = match key.as_text() {
        Some(id) if is_identity_ref(id) => id.to_owned(),
        Some(_) => return Err(bad("service_key")),
        None => service_key_segment(key).ok_or(bad("service_key"))?,
    };
    if sub != name {
        return Err(bad("sub"));
    }
    Ok(())
}

/// The key-segment form of a COSE key's RFC 9679 thumbprint: unpadded
/// base64url of SHA-256 over the deterministic encoding of the key type's
/// required members (OKP: kty, crv, x; EC2: kty, crv, x, y; the composite
/// key type 7 of CC 2.6.1.7: kty, alg, pub). `None` for another key type or
/// a key missing one of them.
fn service_key_segment(key: &Value) -> Option<String> {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};
    key.as_map()?;
    let labels: &[i64] = match key.get_int(1)?.as_u64()? {
        1 => &[1, -1, -2],
        2 => &[1, -1, -2, -3],
        7 => &[1, 3, -1],
        _ => return None,
    };
    let members = labels
        .iter()
        .map(|l| Some((Value::int(*l), key.get_int(*l)?.clone())))
        .collect::<Option<Vec<_>>>()?;
    let digest = Sha256::digest(super::cde::encode(&Value::Map(members)));
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
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

/// A delegation's term, on any `delegates_to` row (CC 2.6.2): where present,
/// `delegation_valid_from` and `delegation_valid_until` are unsigned integers
/// of POSIX milliseconds, and the end is later than the start, the start
/// being `asserted_at` where `delegation_valid_from` is absent. The statement
/// reader applies it to every `delegates_to` row, whatever its family.
///
/// # Errors
///
/// [`Invalid::Malformed`] naming `asserted_at` or `delegation_valid_from`
/// (not an integer), or `delegation_valid_until` (not an integer, or not
/// later than the start).
pub fn check_delegation_term(payload: &Value) -> Result<(), Invalid> {
    let asserted_at = payload
        .get_text("asserted_at")
        .and_then(Value::as_u64)
        .ok_or(bad("asserted_at"))?;
    let start = match payload.get_text("delegation_valid_from") {
        None => asserted_at,
        Some(v) => v.as_u64().ok_or(bad("delegation_valid_from"))?,
    };
    if let Some(v) = payload.get_text("delegation_valid_until") {
        if !v.as_u64().is_some_and(|end| end > start) {
            return Err(bad("delegation_valid_until"));
        }
    }
    Ok(())
}

/// An owner-binding: the payload of an
/// `ownership:{relation}:{target_kind}:{version}` row.
///
/// # Errors
///
/// [`Invalid::SetOrder`] naming `scope` where it is unsorted or repeats a
/// token; otherwise [`Invalid::Malformed`] naming the member off its rule:
/// `author` (absent or not an identity-ref), `delegation_purpose` (not
/// `owner_binding`), `scope` (not a non-empty array of text),
/// `delegation_valid_from` / `asserted_at` (not an integer),
/// `delegation_valid_until` (not an integer, or not later than the start),
/// `cohort_scope` (outside the seven), `community_id` / `family_id` (present
/// or absent against `cohort_scope`, or not a group-ref), `on_behalf_of`
/// (not a group-ref, or carried without `refs`), or `refs` (carried without
/// `on_behalf_of`, without `head`, or with any other role).
pub fn check_owner_binding(payload: &Value) -> Result<(), Invalid> {
    let text = |name: &str| payload.get_text(name).and_then(Value::as_text);
    let group = |name: &'static str, wanted: bool| match payload.get_text(name) {
        None if !wanted => Ok(()),
        Some(v) if wanted && v.as_text().is_some_and(is_group_ref) => Ok(()),
        _ => Err(bad(name)),
    };
    if !text("author").is_some_and(is_identity_ref) {
        return Err(bad("author"));
    }
    if text("delegation_purpose") != Some(OWNER_BINDING_PURPOSE) {
        return Err(bad("delegation_purpose"));
    }
    if let Some(scope) = payload.get_text("scope") {
        let a = scope
            .as_array()
            .filter(|a| !a.is_empty() && a.iter().all(|t| t.as_text().is_some()))
            .ok_or(bad("scope"))?;
        super::check_set(a, "scope")?;
    }
    check_delegation_term(payload)?;
    let Some(cohort) = text("cohort_scope").filter(|c| COHORT_SCOPES.contains(c)) else {
        return Err(bad("cohort_scope"));
    };
    group(
        "community_id",
        matches!(cohort, "community" | "affiliations"),
    )?;
    group("family_id", cohort == "family")?;
    let refs = payload.get_text("refs");
    match payload.get_text("on_behalf_of") {
        None if refs.is_some() => return Err(bad("refs")),
        None => {},
        Some(v) => {
            if !v.as_text().is_some_and(is_group_ref) || refs.is_none() {
                return Err(bad("on_behalf_of"));
            }
            let only_head = refs
                .and_then(Value::as_map)
                .is_some_and(|m| matches!(m, [(k, _)] if k.as_text() == Some("head")));
            if !only_head {
                return Err(bad("refs"));
            }
        },
    }
    Ok(())
}

/// The reader's call: apply the rule of `family` to `payload`, by the leaf
/// its `dimension` binds. Other families have no rule here.
pub(super) fn check_family_shape(
    family_id: &str,
    sub: &str,
    payload: &Value,
) -> Result<(), Invalid> {
    match family_id {
        MEMBERSHIP_FAMILY => match family::dimension_leaf(family_id, payload).as_deref() {
            Some("acceptance" | "decline") => check_reply(payload),
            Some("keeps") => check_membership_keeps(payload),
            _ => Ok(()),
        },
        ACT_ACK_FAMILY => check_act_ack(payload),
        TRUST_FAMILY => match family::dimension_leaf(family_id, payload).as_deref() {
            Some("accepts") => check_trust_accepts(sub, payload),
            _ => Ok(()),
        },
        OWNERSHIP_FAMILY => check_owner_binding(payload),
        OBJECTION_FAMILY => check_objection(
            family::dimension_leaf(family_id, payload).as_deref(),
            payload,
        ),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn iref() -> Value {
        t(&super::super::identity_ref(&[7; 32]))
    }

    fn gref(n: u8) -> Value {
        use base64::Engine as _;
        t(&format!(
            "group-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([n; 32])
        ))
    }

    fn row_ref() -> Value {
        Value::Array(vec![
            Value::Uint(2),
            Value::Array(vec![Value::Nint(15), Value::Bytes(vec![9; 32])]),
        ])
    }

    /// CC's node sample (rc22 462260c `owner-binding`).
    fn node() -> Vec<(&'static str, Value)> {
        vec![
            ("author", iref()),
            ("dimension", t("ownership:responsible_party:node:v1")),
            ("delegation_purpose", t("owner_binding")),
            (
                "scope",
                Value::Array(vec![t("infra:serve"), t("infra:attest")]),
            ),
            ("delegation_valid_until", Value::Uint(1_000 + 86_400_000)),
            ("cohort_scope", t("self")),
            ("asserted_at", Value::Uint(1_000)),
        ]
    }

    /// CC's organisation sample: an agent's binding, placed in a community.
    fn org() -> Vec<(&'static str, Value)> {
        let mut p = without(node(), "scope");
        p = with(p, "dimension", t("ownership:responsible_party:agent:v1"));
        p = with(p, "cohort_scope", t("community"));
        p = with(p, "community_id", gref(5));
        p = with(p, "on_behalf_of", gref(6));
        with(p, "refs", Value::Map(vec![(t("head"), row_ref())]))
    }

    fn with(
        mut p: Vec<(&'static str, Value)>,
        k: &'static str,
        v: Value,
    ) -> Vec<(&'static str, Value)> {
        p.retain(|(n, _)| *n != k);
        p.push((k, v));
        p
    }

    fn without(mut p: Vec<(&'static str, Value)>, k: &str) -> Vec<(&'static str, Value)> {
        p.retain(|(n, _)| *n != k);
        p
    }

    fn check(p: Vec<(&'static str, Value)>) -> Result<(), Invalid> {
        check_owner_binding(&Value::Map(p.into_iter().map(|(k, v)| (t(k), v)).collect()))
    }

    #[test]
    fn owner_binding_samples_pass() {
        // "infra:attest" sorts after "infra:serve" by encoding (longer text).
        assert_eq!(check(node()), Ok(()));
        assert_eq!(check(org()), Ok(()));
        // A member the form does not name is admitted (open payload).
        assert_eq!(check(with(node(), "kind", t("node"))), Ok(()));
        assert_eq!(
            check(with(node(), "delegation_valid_from", Value::Uint(2_000))),
            Ok(())
        );
    }

    #[test]
    fn delegation_term_is_ms_time_on_any_delegation() {
        let p = |m: Vec<(&str, Value)>| Value::Map(m.into_iter().map(|(k, v)| (t(k), v)).collect());
        let at = ("asserted_at", Value::Uint(1_000));
        assert_eq!(check_delegation_term(&p(vec![at.clone()])), Ok(()));
        assert_eq!(
            check_delegation_term(&p(vec![
                at.clone(),
                ("delegation_valid_from", Value::Uint(500)),
                ("delegation_valid_until", Value::Uint(501)),
            ])),
            Ok(())
        );
        assert_eq!(
            check_delegation_term(&p(vec![
                at.clone(),
                ("delegation_valid_from", t("2026-11-23T00:00:00.000Z")),
            ])),
            Err(Invalid::Malformed {
                member: "delegation_valid_from"
            })
        );
        for end in [t("2027-01-01T00:00:00.000Z"), Value::Uint(1_000)] {
            assert_eq!(
                check_delegation_term(&p(vec![at.clone(), ("delegation_valid_until", end)])),
                Err(Invalid::Malformed {
                    member: "delegation_valid_until"
                })
            );
        }
    }

    #[test]
    fn owner_binding_breaks_are_refused() {
        let bad = |m: &'static str| Err(Invalid::Malformed { member: m });
        assert_eq!(check(without(node(), "author")), bad("author"));
        assert_eq!(
            check(without(node(), "delegation_purpose")),
            bad("delegation_purpose")
        );
        assert_eq!(
            check(with(node(), "delegation_purpose", t("act_on_behalf"))),
            bad("delegation_purpose")
        );
        assert_eq!(
            check(with(node(), "scope", t("infra:attest"))),
            bad("scope")
        );
        assert_eq!(
            check(with(node(), "scope", Value::Array(vec![]))),
            bad("scope")
        );
        for unsorted in [
            vec![t("infra:attest"), t("infra:serve")],
            vec![t("infra:serve"), t("infra:serve")],
        ] {
            assert_eq!(
                check(with(node(), "scope", Value::Array(unsorted))),
                Err(Invalid::SetOrder { member: "scope" })
            );
        }
        assert_eq!(check(without(node(), "cohort_scope")), bad("cohort_scope"));
        assert_eq!(
            check(with(node(), "cohort_scope", t("room"))),
            bad("cohort_scope")
        );
        assert_eq!(
            check(with(node(), "delegation_valid_until", t("2027-01-01"))),
            bad("delegation_valid_until")
        );
        // The end is later than the start: asserted_at, or the stated start.
        assert_eq!(
            check(with(node(), "delegation_valid_until", Value::Uint(1_000))),
            bad("delegation_valid_until")
        );
        assert_eq!(
            check(with(
                node(),
                "delegation_valid_from",
                Value::Uint(1_000 + 2 * 86_400_000)
            )),
            bad("delegation_valid_until")
        );
        // The group member the placement asks, and no other.
        assert_eq!(
            check(with(node(), "community_id", gref(5))),
            bad("community_id")
        );
        assert_eq!(
            check(with(node(), "cohort_scope", t("family"))),
            bad("family_id")
        );
        assert_eq!(check(without(org(), "community_id")), bad("community_id"));
        // on_behalf_of iff refs, and refs only head.
        assert_eq!(
            check(with(
                node(),
                "refs",
                Value::Map(vec![(t("head"), row_ref())])
            )),
            bad("refs")
        );
        assert_eq!(check(without(org(), "refs")), bad("on_behalf_of"));
        assert_eq!(
            check(with(
                org(),
                "refs",
                Value::Map(vec![
                    (t("head"), row_ref()),
                    (
                        t("also"),
                        Value::Map(vec![(t("cites"), Value::Array(vec![row_ref()]))])
                    ),
                ])
            )),
            bad("refs")
        );
    }
}
