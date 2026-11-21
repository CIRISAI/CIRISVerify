//! Delegation scope split and set-semantics order (CEG §8.1.12.7.1,
//! §5.6.8.10, §1.3; CC 2.6.1.2).
//!
//! - [`verify_delegation_scope_split`]: a `node`-only delegate carrying any
//!   `agency:*` scope (or a legacy agency kind) is rejected; an unknown scope
//!   fails closed. The reserved scope sets are [`INFRA_SCOPES`] and
//!   [`AGENCY_SCOPES`].
//! - [`check_set_semantics_sorted`]: the producer-side guard that a set-kind
//!   array is in UTF-16 order with no duplicate
//!   ([`FEDERATION_SET_SEMANTICS_UNSORTED`]).
//!
//! Both are pure evaluators: no I/O, and fail-closed.
//!
//! The pair-signed admission checks for `organization` / `org_membership`
//! (`resolve_role_authority`) and `partner_record`
//! (`verify_partner_record_quorum`) were removed in 23.3.3: CC 3.3.9 retired
//! those rows.

#[allow(unused_imports)]
use crate::prelude::*;

use serde_json::Value;

use crate::error::VerifyError;

/// The CC 2.6.1.2 refusal token for a set-kind array that is out of order or
/// carries a duplicate element.
pub const FEDERATION_SET_SEMANTICS_UNSORTED: &str = "federation_set_semantics_unsorted";

/// Compare two strings in UTF-16 code-unit order (RFC 8785 §3.2.3, CC 2.6.1.2).
fn utf16_cmp(a: &str, b: &str) -> core::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Producer-side guard: confirm the named members of `value` are arrays
/// whose string elements are **strictly** increasing in lexicographic order —
/// sorted AND unique (set-semantics, CC 2.6.1.2 rule 1). Returns the first
/// offending field as an error so a mis-ordered multi-signer `partner_record`
/// is caught *before* M stewards sign divergent bytes — far better than a
/// silent quorum collapse at admission.
///
/// CC 2.6.1.2: "A substrate that finds a set-kind array out of order refuses
/// the row with **`federation_set_semantics_unsorted`**, naming the member, and
/// never re-sorts it (re-sorting would move signed bytes). **A set-kind array
/// is sorted AND unique:** a duplicate element is refused under the same
/// token." (CIRISVerify#312.) The array is never re-sorted or deduplicated.
///
/// A named field that is absent or not an array is skipped (the CC 2.6.1.1
/// omit-vs-materialize discipline: this never injects or reorders, it
/// only inspects). Non-string array elements are likewise skipped.
///
/// # Errors
///
/// [`VerifyError::IntegrityError`] whose message carries
/// [`FEDERATION_SET_SEMANTICS_UNSORTED`], the member name, and whether the
/// offending adjacent pair was out of order or a duplicate.
pub fn check_set_semantics_sorted(value: &Value, fields: &[&str]) -> Result<(), VerifyError> {
    let Some(obj) = value.as_object() else {
        return Ok(());
    };
    for field in fields {
        let Some(arr) = obj.get(*field).and_then(Value::as_array) else {
            continue;
        };
        let strs: Vec<&str> = arr.iter().filter_map(Value::as_str).collect();
        if strs.len() != arr.len() {
            continue; // not a pure string array; not ours to judge
        }
        // CC 2.6.1.2: sorted "by their JCS string form (UTF-16 code-unit order,
        // ascending)". Rust's `str` order is UTF-8 byte (code point) order, which
        // differs from UTF-16 order between U+E000..U+FFFF and supplementary
        // characters, so compare code units explicitly.
        if let Some((i, w)) = strs
            .windows(2)
            .enumerate()
            .find(|(_, w)| utf16_cmp(w[0], w[1]) != core::cmp::Ordering::Less)
        {
            let what = if w[0] == w[1] {
                "carries a duplicate element"
            } else {
                "is not lexicographically sorted"
            };
            return Err(VerifyError::IntegrityError {
                message: format!(
                    "{FEDERATION_SET_SEMANTICS_UNSORTED}: set-semantics array `{field}` {what} \
                     at index {} (CC 2.6.1.2 rule 1: sorted AND unique) — multi-signer JCS \
                     bytes would diverge",
                    i + 1
                ),
            });
        }
    }
    Ok(())
}

// ===========================================================================
// Delegation scope split — `infra:*` vs `agency:*` (CEG 1.0-RC7 §8.1.12.7.1 /
// §5.6.8.10 / §1.3, CIRISRegistry#83)
// ===========================================================================

/// The reserved `infra:*` delegation scopes — server-class powers a `node`-role
/// (fabric/infrastructure) delegate MAY hold. A user-owned fabric node serves +
/// holds membership *standing* under the user's authority with these.
///
/// **RC3 crystal-vocabulary (CIRISVerify#217).** The vague membership token
/// `infra:join_communities` was retired in favour of two crystal ones —
/// `infra:hold_community_membership` and `infra:hold_family_membership` — matching
/// CIRISServer (`auth/ownership.rs`) and CIRISPersist (`federation/types.rs`).
/// This is a **hard cut**: no alias, no back-compat (pre-fleet), so a delegation
/// carrying the retired token now fail-closes as `UnknownScope`, exactly as
/// server + persist already treat it.
pub const INFRA_SCOPES: &[&str] = &[
    "infra:network_presence",
    "infra:hold_community_membership",
    "infra:hold_family_membership",
    "infra:serve",
    "infra:store",
    "infra:attest",
    "infra:transport",
];

/// The reserved `agency:*` delegation scopes — brain-only powers (reason and
/// act AS the user). FORBIDDEN for a pure `node`-role delegate (§1.3
/// "infrastructure must not have agency").
pub const AGENCY_SCOPES: &[&str] = &[
    "agency:act_on_behalf",
    "agency:message_io",
    "agency:reason",
    "agency:decide",
];

/// Legacy unprefixed kinds that convey **agency** (valid only for an
/// `agent`-role delegate — the Self-at-login agency profile; the `agency:*`
/// equivalents). `sub_delegation` is agency-class: re-granting authority is a
/// brain decision.
const LEGACY_AGENCY_KINDS: &[&str] = &[
    "act_on_behalf",
    "message_io",
    "reason",
    "decide",
    "sub_delegation",
];

/// Legacy unprefixed kinds that convey **infra** (the `infra:network_presence`
/// equivalent).
const LEGACY_INFRA_KINDS: &[&str] = &["network_presence"];

/// The brain role in an `identity_type` set (§7.0.1) — its presence is what
/// authorizes `agency:*`.
const AGENT_IDENTITY_ROLE: &str = "agent";

/// What a single delegated scope conveys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeClass {
    Infra,
    Agency,
    Unknown,
}

fn classify_scope(scope: &str) -> ScopeClass {
    if INFRA_SCOPES.contains(&scope) || LEGACY_INFRA_KINDS.contains(&scope) {
        ScopeClass::Infra
    } else if AGENCY_SCOPES.contains(&scope) || LEGACY_AGENCY_KINDS.contains(&scope) {
        ScopeClass::Agency
    } else {
        // An unrecognized scope — including an unknown suffix under a reserved
        // prefix (`infra:hack` / `agency:hack`) — is fail-closed.
        ScopeClass::Unknown
    }
}

/// Why a `delegates_to` scope set was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeSplitError {
    /// The delegate's `identity_type` is `node`-only (no `agent`/brain) but the
    /// delegation carries an agency-class scope — §1.3 violation.
    NodeCarriesAgency {
        /// The offending agency-class scope.
        scope: String,
    },
    /// A scope is not a recognized reserved (`infra:*` / `agency:*`) or legacy
    /// kind — rejected fail-closed.
    UnknownScope {
        /// The unrecognized scope.
        scope: String,
    },
}

impl core::fmt::Display for ScopeSplitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NodeCarriesAgency { scope } => write!(
                f,
                "node-only delegate may not hold agency scope {scope:?} \
                 (§1.3 infrastructure must not have agency)"
            ),
            Self::UnknownScope { scope } => {
                write!(f, "unrecognized delegation scope {scope:?} (fail-closed)")
            },
        }
    }
}

impl core::error::Error for ScopeSplitError {}

/// Enforce the CEG §8.1.12.7.1 / §5.6.8.10 `infra:*` / `agency:*` scope split on
/// a `delegates_to` — the wire-checkable form of §1.3 "infrastructure must not
/// have agency".
///
/// `attested_identity_type` is the **caller-resolved** `identity_type` (§7.0.1)
/// of the delegation's `attested_key_id`, a comma-joined SET. The delegate is a
/// **brain** iff that set contains `agent`. A non-brain (pure `node`)
/// delegate MUST carry only `infra:*` scopes: any agency-class scope is
/// rejected. An unrecognized scope is rejected fail-closed. A brain delegate
/// may hold any recognized scope (the Self-at-login agency profile).
///
/// This is a **pure evaluator** (no I/O). Cohabitation (`agent = node + brain`) is modeled
/// as two *separate* `delegates_to` (the node holds `infra:*`, the brain holds
/// `agency:*`), each checked independently — so this per-delegation check is
/// exactly right.
///
/// # Errors
///
/// [`ScopeSplitError::NodeCarriesAgency`] / [`ScopeSplitError::UnknownScope`].
pub fn verify_delegation_scope_split(
    attested_identity_type: &str,
    delegated_scope: &[String],
) -> Result<(), ScopeSplitError> {
    let is_brain = attested_identity_type
        .split(',')
        .any(|role| role.trim() == AGENT_IDENTITY_ROLE);

    for scope in delegated_scope {
        match classify_scope(scope) {
            ScopeClass::Infra => {},
            ScopeClass::Agency => {
                if !is_brain {
                    return Err(ScopeSplitError::NodeCarriesAgency {
                        scope: scope.clone(),
                    });
                }
            },
            ScopeClass::Unknown => {
                return Err(ScopeSplitError::UnknownScope {
                    scope: scope.clone(),
                });
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn partner_record_sorted() -> Value {
        json!({
            "license_id": "lic-1",
            "license_type": "professional",
            "capabilities_granted": ["billing.read", "billing.write", "identity.read"],
            "capabilities_denied": ["admin.super"],
            "status": "active",
            "revision": 1,
        })
    }

    // ---- set-semantics sorted guard --------------------------------

    #[test]
    fn sorted_arrays_pass_the_guard() {
        let pr = partner_record_sorted();
        assert!(
            check_set_semantics_sorted(&pr, &["capabilities_granted", "capabilities_denied"])
                .is_ok()
        );
    }

    #[test]
    fn unsorted_array_is_caught() {
        let pr = json!({
            "capabilities_granted": ["identity.read", "billing.read"], // out of order
        });
        let err = check_set_semantics_sorted(&pr, &["capabilities_granted"]).unwrap_err();
        match err {
            VerifyError::IntegrityError { message } => {
                assert!(message.contains("capabilities_granted"));
            },
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn duplicate_element_is_refused_under_the_same_token() {
        // CIRISVerify#312 / CC 2.6.1.2: sorted AND unique.
        let pr = json!({
            "capabilities_granted": ["billing.read", "identity.read", "identity.read"],
        });
        let err = check_set_semantics_sorted(&pr, &["capabilities_granted"]).unwrap_err();
        match err {
            VerifyError::IntegrityError { message } => {
                assert!(message.contains(FEDERATION_SET_SEMANTICS_UNSORTED));
                assert!(message.contains("capabilities_granted"));
                assert!(message.contains("duplicate"), "{message}");
            },
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn unsorted_error_names_the_token_and_the_cause() {
        let pr = json!({ "capabilities_granted": ["b", "a"] });
        let err = check_set_semantics_sorted(&pr, &["capabilities_granted"]).unwrap_err();
        let VerifyError::IntegrityError { message } = err else {
            panic!("unexpected error");
        };
        assert!(message.contains(FEDERATION_SET_SEMANTICS_UNSORTED));
        assert!(
            message.contains("not lexicographically sorted"),
            "{message}"
        );
    }

    #[test]
    fn set_order_is_utf16_code_units_not_utf8_bytes() {
        // U+FF5E (one unit, 0xFF5E) vs U+1F600 (surrogates 0xD83D 0xDE00).
        // UTF-16 order: "\u{1F600}" < "\u{FF5E}"; UTF-8 byte order is the reverse.
        let utf16_sorted = json!({ "capabilities_granted": ["\u{1F600}", "\u{FF5E}"] });
        assert!(check_set_semantics_sorted(&utf16_sorted, &["capabilities_granted"]).is_ok());
        let utf8_sorted = json!({ "capabilities_granted": ["\u{FF5E}", "\u{1F600}"] });
        assert!(check_set_semantics_sorted(&utf8_sorted, &["capabilities_granted"]).is_err());
    }

    #[test]
    fn absent_or_non_array_fields_are_skipped() {
        let pr = json!({ "license_id": "lic-1" });
        assert!(check_set_semantics_sorted(&pr, &["capabilities_granted"]).is_ok());
    }

    // ---- delegation scope split (#77 / RC7 §8.1.12.7.1 / §1.3) -----------

    fn scopes(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn node_only_with_all_infra_scopes_is_ok() {
        // A pure fabric node may serve + hold membership standing. Every RC3
        // infra token must admit (guards against an enumeration typo).
        assert!(verify_delegation_scope_split("node", &scopes(INFRA_SCOPES)).is_ok());
        let scope = scopes(&[
            "infra:network_presence",
            "infra:hold_community_membership",
            "infra:hold_family_membership",
            "infra:serve",
        ]);
        assert!(verify_delegation_scope_split("node", &scope).is_ok());
    }

    #[test]
    fn retired_join_communities_token_now_fail_closes() {
        // RC3 (#217): the vague token is gone — a delegation still carrying it
        // must be rejected, matching server + persist. No alias, no back-compat.
        assert!(!INFRA_SCOPES.contains(&"infra:join_communities"));
        let scope = scopes(&["infra:serve", "infra:join_communities"]);
        assert!(matches!(
            verify_delegation_scope_split("node", &scope),
            Err(ScopeSplitError::UnknownScope { .. })
        ));
    }

    #[test]
    fn node_only_carrying_agency_is_rejected() {
        // §1.3 wire-checkable: infrastructure must not have agency.
        let scope = scopes(&["infra:serve", "agency:act_on_behalf"]);
        assert_eq!(
            verify_delegation_scope_split("node", &scope),
            Err(ScopeSplitError::NodeCarriesAgency {
                scope: "agency:act_on_behalf".to_string()
            })
        );
    }

    #[test]
    fn node_only_carrying_legacy_agency_kind_is_rejected() {
        // Legacy unprefixed agency kind is still agency — rejected for a node.
        let scope = scopes(&["network_presence", "act_on_behalf"]);
        assert_eq!(
            verify_delegation_scope_split("node", &scope),
            Err(ScopeSplitError::NodeCarriesAgency {
                scope: "act_on_behalf".to_string()
            })
        );
    }

    #[test]
    fn agent_role_may_hold_agency() {
        // The Self-at-login agency profile: a brain reasons + acts as the user.
        let scope = scopes(&[
            "agency:act_on_behalf",
            "agency:message_io",
            "infra:network_presence",
        ]);
        assert!(verify_delegation_scope_split("agent", &scope).is_ok());
    }

    #[test]
    fn cohabiting_node_plus_agent_is_a_brain() {
        // identity_type SET (§7.0.1): "node,agent" contains the brain role.
        let scope = scopes(&["agency:decide"]);
        assert!(verify_delegation_scope_split("node,agent", &scope).is_ok());
    }

    #[test]
    fn unknown_scope_is_rejected_fail_closed() {
        // Unknown suffix under a reserved prefix is NOT a free pass.
        for bad in ["agency:hack", "infra:exfiltrate", "wat", "act_now"] {
            assert_eq!(
                verify_delegation_scope_split("agent", &scopes(&[bad])),
                Err(ScopeSplitError::UnknownScope {
                    scope: bad.to_string()
                }),
                "scope {bad:?} must be rejected fail-closed"
            );
        }
    }

    #[test]
    fn empty_scope_set_is_ok() {
        assert!(verify_delegation_scope_split("node", &[]).is_ok());
    }
}
