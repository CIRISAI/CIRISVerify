//! A group's id is derived from its founding (CC rc22, ruled 2026-11-22), so
//! a room cannot be founded under another key's thumbprint or a squatted
//! name:
//!
//! ```text
//! group-id-input = ["CEG-group/2", group_kind, founders, founded_at, nonce]
//! id = "group-" ‖ base64url-nopad(SHA-256(CDE(group-id-input)))
//! group-ref = tstr .regexp "group-[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]"
//! ```
//!
//! `group_kind` and `founded_at` are the first `group:roster` version's own
//! members; `founders` is the `key` of every member that first version lists,
//! as a set in CC 2.6.1.2 set order (sorted by deterministic encoding, no
//! duplicate); `nonce` is a 32-byte member of the first version only. The id
//! has a form of its own, a `group-ref`: it is not a key thumbprint URI and
//! cannot be mistaken for a key. It has no colon, so it is a plain string in
//! the CWT `sub`. A root lineage's name (`humanity-accord`) is no group id:
//! the accord has no `group:roster` row.
//!
//! The check needs nothing beyond the row: a `group:roster` version with no
//! `refs.head` is a first version, whatever its row type, and its `group`
//! must be a `group-ref` and the derived id; a later version carries no
//! `nonce` and is judged by its descent, as before.

#[allow(unused_imports)]
use crate::prelude::*;

use sha2::{Digest, Sha256};

use super::{is_identity_ref, Invalid, Value};
use crate::cde;

/// The domain label of the group id's input.
pub const GROUP_ID_LABEL: &str = "CEG-group/2";
/// The prefix of a group's id.
pub const GROUP_REF_PREFIX: &str = "group-";
/// The family whose first version founds a group.
pub const GROUP_ROSTER_FAMILY: &str = "group:roster";

/// The id of the group a first `group:roster` version founds. `founders` are
/// the members' `key`s in any order, repeated or not: they are put in set
/// order here.
#[must_use]
pub fn derive_group_id(
    group_kind: &str,
    founders: &[&str],
    founded_at: u64,
    nonce: &[u8; 32],
) -> String {
    // Set order is the order of the elements' deterministic encodings.
    let mut set: Vec<(Vec<u8>, &str)> = founders
        .iter()
        .map(|f| (cde::encode(&Value::Text((*f).into())), *f))
        .collect();
    set.sort();
    set.dedup();
    let founders = Value::Array(
        set.into_iter()
            .map(|(_, f)| Value::Text(f.into()))
            .collect(),
    );
    let input = Value::Array(vec![
        Value::Text(GROUP_ID_LABEL.into()),
        Value::Text(group_kind.into()),
        founders,
        Value::Uint(founded_at),
        Value::Bytes(nonce.to_vec()),
    ]);
    let digest: [u8; 32] = Sha256::digest(cde::encode(&input)).into();
    group_ref(&digest)
}

/// The `group-ref` text of a 32-byte digest.
#[must_use]
pub fn group_ref(digest: &[u8; 32]) -> String {
    use base64::Engine as _;
    let mut s = String::from(GROUP_REF_PREFIX);
    s.push_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest));
    s
}

/// Whether `s` is a `group-ref`: `group-` and the canonical unpadded
/// base64url of 32 bytes (43 characters, the last one of the sixteen that
/// leave no stray bits).
#[must_use]
pub fn is_group_ref(s: &str) -> bool {
    use base64::Engine as _;
    s.strip_prefix(GROUP_REF_PREFIX).is_some_and(|t| {
        t.len() == 43
            && base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(t)
                .is_ok_and(|b| {
                    b.len() == 32
                        && base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&b) == t
                })
    })
}

/// The founding rule of a `group:roster` roster version's payload:
///
/// - a first version (no `refs.head`) carries a 32-byte `nonce`, and its
///   `group` is a `group-ref` equal to [`derive_group_id`] over its own `group_kind`, its members'
///   `key`s, its `founded_at` and that nonce;
/// - a later version (it names its predecessor in `refs.head`) carries no
///   `nonce`.
///
/// # Errors
///
/// [`Invalid::GroupIdNotOfFounding`] when a first version's `group` is not
/// the derived id; [`Invalid::Malformed`] naming `nonce` (absent or not 32
/// bytes on a first version, present on a later one) or the founding member
/// that is absent or off its type (`group_kind`, `founded_at`, `members`,
/// `group`; `group` also where it is not a `group-ref`).
pub fn check_group_roster_founding(payload: &Value) -> Result<(), Invalid> {
    let bad = |member: &'static str| Invalid::Malformed { member };
    let later = payload
        .get_text("refs")
        .and_then(|r| r.get_text("head"))
        .is_some();
    let nonce = payload.get_text("nonce");
    if later {
        return match nonce {
            Some(_) => Err(bad("nonce")),
            None => Ok(()),
        };
    }
    let nonce: [u8; 32] = nonce
        .and_then(Value::as_bytes)
        .and_then(|b| b.try_into().ok())
        .ok_or(bad("nonce"))?;
    let group_kind = payload
        .get_text("group_kind")
        .and_then(Value::as_text)
        .ok_or(bad("group_kind"))?;
    let founded_at = payload
        .get_text("founded_at")
        .and_then(Value::as_u64)
        .ok_or(bad("founded_at"))?;
    let members = payload
        .get_text("members")
        .and_then(Value::as_array)
        .ok_or(bad("members"))?;
    let mut founders = Vec::with_capacity(members.len());
    for m in members {
        let key = m
            .get_text("key")
            .and_then(Value::as_text)
            .filter(|k| is_identity_ref(k))
            .ok_or(bad("members"))?;
        founders.push(key);
    }
    // A `group` that is not a group-ref at all is a shape fault, before the
    // derivation is tried.
    let group = payload
        .get_text("group")
        .and_then(Value::as_text)
        .filter(|g| is_group_ref(g))
        .ok_or(bad("group"))?;
    if group != derive_group_id(group_kind, &founders, founded_at, &nonce) {
        return Err(Invalid::GroupIdNotOfFounding);
    }
    Ok(())
}
