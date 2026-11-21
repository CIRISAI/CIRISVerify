//! The baked HUMANITY_ACCORD family genesis (CEG §9.1, CIRISVerify#107) and
//! the roster read from it.
//!
//! [`humanity_accord_genesis`](crate::accord_genesis::humanity_accord_genesis)
//! is the pinned, no-TOFU family-genesis object from the 2026-06-23 ceremony;
//! [`baked_accord_roster`](crate::accord_genesis::baked_accord_roster) resolves
//! its members against the pinned `founder_pubkeys.json`, and is the roster the
//! v4 trust-root bundle is verified against
//! ([`crate::genesis_bundle::verify_genesis_bundle`], at a strict majority of
//! that roster) and the source of
//! [`accord_holder_bootstrap_anchor`](crate::accord_genesis::accord_holder_bootstrap_anchor).
//! [`strict_majority`](crate::accord_genesis::strict_majority) and
//! [`accord_family_signing_bytes`](crate::accord_genesis::accord_family_signing_bytes)
//! are shared with CIRISPersist.
//!
//! The producers of the earlier ceremony (holder records, family co-signing and
//! assembly, invocation co-signing and concurrence, roster changes) and the
//! fixed `quorum:2/3` constants were removed in 23.3.3: the threshold is always
//! a strict majority of the standing roster, and the forward model signs with
//! the CC 2.6.1.7 composite ([`crate::edition2`]).
//!
//! **family vs community:** this is the entrenched **family** (§9.1);
//! `ciris-canonical` is the infrastructure **community**
//! ([`crate::infrastructure_community`], #31). Easy to conflate — they are not
//! the same object.

#[allow(unused_imports)]
use crate::prelude::*;

use base64::Engine;
use serde_json::Value;

use crate::ceg_outbox::SignedCegObject;
use crate::error::VerifyError;
use crate::jcs;
use crate::threshold::ThresholdMember;

/// The canonical `family_key_id` of the accord (runbook §7).
pub const HUMANITY_ACCORD_FAMILY_KEY_ID: &str = "humanity-accord";

/// CEG `kind` of the entrenched-family genesis object.
const ACCORD_FAMILY_GENESIS_KIND: &str = "accord_family_genesis";

/// The accord quorum threshold for an `n`-member roster: a **strict majority**,
/// `⌊n/2⌋ + 1` (3→2, 5→3, 7→4), [`crate::edition2::strict_majority`].
#[must_use]
pub fn strict_majority(n: usize) -> usize {
    crate::edition2::strict_majority(n)
}

/// The JCS signing bytes of a family envelope (CEG §0.9) — the one blessed
/// encoder every founder and the verifier recompute.
///
/// # Errors
///
/// [`VerifyError`] on a canonicalization fault.
pub fn accord_family_signing_bytes(envelope: &Value) -> Result<Vec<u8>, VerifyError> {
    jcs::canonicalize(envelope)
}

/// Why a family genesis object could not be read into a roster. Every variant
/// is a fail-closed reject.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AccordGenesisError {
    /// The envelope is malformed (missing/!array `members`, or a member with no
    /// `key_id`, or no members).
    MalformedEnvelope,
    /// The roster lists the same `key_id` more than once.
    DuplicateMemberKeyId,
    /// Two members carry the **same public key** under different `member_id`s —
    /// one key occupying multiple seats.
    DuplicateFounderKey,
    /// The CEG object is not an `accord_family_genesis`.
    WrongKind,
    /// A family member's `key_id` has no entry in the pinned directory.
    MemberNotInDirectory,
}

/// Extract the envelope's member `key_id`s in order.
fn envelope_member_key_ids(envelope: &Value) -> Result<Vec<String>, AccordGenesisError> {
    let members = envelope
        .get("members")
        .and_then(Value::as_array)
        .ok_or(AccordGenesisError::MalformedEnvelope)?;
    members
        .iter()
        .map(|m| {
            m.get("key_id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or(AccordGenesisError::MalformedEnvelope)
        })
        .collect()
}

/// Reject a roster where any two members share an Ed25519 or ML-DSA-65 public
/// key — one key occupying two seats. `verify_founder_quorum` dedups by
/// `member_id` *string*, so without this a single key relabeled under two
/// member_ids (or one human's primary+spare both seated) meets the quorum by
/// itself.
fn reject_duplicate_member_keys(members: &[ThresholdMember]) -> Result<(), AccordGenesisError> {
    let mut seen_ed = BTreeSet::new();
    let mut seen_pqc = BTreeSet::new();
    for m in members {
        if !seen_ed.insert(m.ed25519_public_key_base64.as_str()) {
            return Err(AccordGenesisError::DuplicateFounderKey);
        }
        if let Some(pqc) = m.mldsa65_public_key_base64.as_deref() {
            if !seen_pqc.insert(pqc) {
                return Err(AccordGenesisError::DuplicateFounderKey);
            }
        }
    }
    Ok(())
}

/// Derive the accord **kill-switch roster** from a family-genesis object: the
/// family's member set, resolved in declared order against `directory` (the
/// pinned `key_id → ThresholdMember` map). Any other identity in `directory`
/// (a cold spare) is ignored, so one human's spare never becomes a second seat.
/// Fail-closed: wrong kind, malformed or empty members, a duplicate `key_id`, a
/// member missing from `directory`, or two members with one pubkey.
///
/// **Trust boundary:** this *reads* the members; it does not re-verify the
/// object's `founder_signatures`. The baked genesis is checked by
/// `humanity_accord_genesis_is_baked_and_quorum_valid`.
fn accord_roster_from_family(
    family_genesis: &SignedCegObject,
    directory: &[ThresholdMember],
) -> Result<Vec<ThresholdMember>, AccordGenesisError> {
    if family_genesis.kind != ACCORD_FAMILY_GENESIS_KIND {
        return Err(AccordGenesisError::WrongKind);
    }
    let envelope = family_genesis
        .body
        .get("family")
        .ok_or(AccordGenesisError::MalformedEnvelope)?;
    let member_ids = envelope_member_key_ids(envelope)?;
    if member_ids.is_empty() {
        return Err(AccordGenesisError::MalformedEnvelope);
    }
    let mut seen = BTreeSet::new();
    for k in &member_ids {
        if !seen.insert(k.as_str()) {
            return Err(AccordGenesisError::DuplicateMemberKeyId);
        }
    }
    let roster = member_ids
        .iter()
        .map(|key_id| {
            directory
                .iter()
                .find(|m| &m.member_id == key_id)
                .cloned()
                .ok_or(AccordGenesisError::MemberNotInDirectory)
        })
        .collect::<Result<Vec<_>, _>>()?;
    reject_duplicate_member_keys(&roster)?;
    Ok(roster)
}

/// The **baked** canonical HUMANITY_ACCORD family-genesis object as JSON
/// (CIRISVerify#107). **BAKED 2026-06-23** from the real 6-key ceremony (#118):
/// `key_id: "humanity-accord"`, `quorum:2/3` entrenched, founders A1/B1/C1, all
/// three hardware-rooted on FIPS YubiKeys and **3-of-3 cosigned** (≥ the 2/3
/// floor). The genesis object lives as a checked-in artifact (`genesis/…json`)
/// so it is auditable as a file; `humanity_accord_genesis_is_baked_and_quorum_valid`
/// re-verifies its founder quorum against the ceremony's published holder pubkeys.
const HUMANITY_ACCORD_GENESIS_JSON: &str = include_str!("genesis/humanity_accord_genesis.json");

/// The ceremony's published founder pubkeys (A1/B1/C1 hybrid keys), checked in
/// alongside the genesis so the 2-of-3 quorum — and the #160 bootstrap anchor —
/// are independently auditable from a pinned file. Deserializes to
/// [`ThresholdMember`]s.
const FOUNDER_PUBKEYS_JSON: &str = include_str!("genesis/founder_pubkeys.json");

/// The pinned, **no-TOFU** HUMANITY_ACCORD family-genesis recognition root
/// (CIRISVerify#107). A node that was **not** at the ceremony resolves the accord
/// kill-switch roster from **this** baked object, **never** from a peer — fetching the genesis would be trust-on-first-use.
///
/// This is a constitutional trust root in the same class as the steward /
/// `ciris-canonical` / Yubico custody roots verify already pins, and explicitly
/// does **NOT** ride CIRISServer's `CANONICAL_BOOTSTRAP_PEERS` (infra/node trust,
/// not constitutional kill-switch trust).
///
/// Returns `Some(genesis)` once baked (parsed once, cached); `None` until then —
/// **absence means "not yet pinned"; a cold-start consumer MUST NOT fall back to
/// fetching it from a peer.** Parses to an `accord_family_genesis` object or
/// stays `None` (a malformed bake is treated as not-baked, fail-closed).
#[must_use]
pub fn humanity_accord_genesis() -> Option<&'static SignedCegObject> {
    static PARSED: once_cell::race::OnceBox<Option<SignedCegObject>> =
        once_cell::race::OnceBox::new();
    PARSED
        .get_or_init(|| {
            let trimmed = HUMANITY_ACCORD_GENESIS_JSON.trim();
            if trimmed.is_empty() {
                return Box::new(None);
            }
            Box::new(
                serde_json::from_str::<SignedCegObject>(trimmed)
                    .ok()
                    .filter(|o| o.kind == ACCORD_FAMILY_GENESIS_KIND),
            )
        })
        .as_ref()
}

/// The seated accord holders baked into this binary — the baked
/// `humanity_accord_genesis()` roster resolved against the pinned
/// `founder_pubkeys.json`, both halves of each key. Empty if either is not
/// baked or does not resolve: callers treat that as "no roster", never as an
/// empty quorum.
///
/// This is the roster a trust-root bundle is verified against
/// ([`crate::genesis_bundle::verify_genesis_bundle`]) and the source of
/// [`accord_holder_bootstrap_anchor`], so the two cannot drift.
#[must_use]
pub fn baked_accord_roster() -> Vec<ThresholdMember> {
    let Some(genesis) = humanity_accord_genesis() else {
        return Vec::new();
    };
    let Ok(founders) = serde_json::from_str::<Vec<ThresholdMember>>(FOUNDER_PUBKEYS_JSON) else {
        return Vec::new();
    };
    accord_roster_from_family(genesis, &founders).unwrap_or_default()
}

/// The trusted-bootstrap **rooting anchor** for genesis mesh seeding
/// (CIRISVerify#160, the "centipede head"): the Ed25519 public keys of the
/// **seated** HUMANITY_ACCORD holders (A1/B1/C1).
///
/// Rooting against it is set-**membership** (1-of-N), NOT a 2/3 threshold: a
/// chain that terminates at **any one** of these seated holder keys roots
/// during cold-start bootstrap.
///
/// **One source of truth, cross-validated:** the anchor is the *seated roster*
/// resolved from the baked [`humanity_accord_genesis()`] against the pinned
/// `founder_pubkeys.json` directory (through the same one-seat /
/// no-duplicate-pubkey integrity gates as [`baked_accord_roster`]). So the anchor and
/// the kill-switch roster can never drift, and spares (A2/B2/C2) are excluded —
/// only *seated* holders are a rooting terminus.
///
/// Returns **empty** (fail-closed) if the genesis is not baked, the pinned
/// founder directory is malformed, the roster fails to resolve, or any holder key
/// is not a valid 32-byte Ed25519 key — no anchor → nothing roots, never a
/// partial/ambiguous anchor.
///
/// ## Test-mode override (CIRISVerify#202)
///
/// In a build carrying the `test-anchor` Cargo feature, with the runtime AND-gate
/// active, a **software single-key** trust root from `CIRIS_TEST_TRUST_ROOT`
/// *replaces* the baked roster (1-of-N rooting makes one key a valid anchor). The
/// feature is absent from every production artifact, so for a prod node this call
/// is byte-for-byte the baked path below. See [`crate::test_anchor`].
#[must_use]
pub fn accord_holder_bootstrap_anchor() -> Vec<[u8; 32]> {
    // TEST-ONLY (compile-time-fenced + runtime-gated): a software test anchor for
    // the local mesh harness. `None` in prod (feature absent) → baked path.
    #[cfg(feature = "std")]
    if let Some(test_root) = crate::test_anchor::test_trust_root_override() {
        return test_root;
    }

    let roster = baked_accord_roster();
    if roster.is_empty() {
        return Vec::new();
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut anchor = Vec::with_capacity(roster.len());
    for member in &roster {
        match b64
            .decode(&member.ed25519_public_key_base64)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
        {
            Some(key) => anchor.push(key),
            // A bad/short key in the pinned directory is a hard fault: fail the
            // WHOLE anchor closed rather than root against a partial set.
            None => return Vec::new(),
        }
    }
    anchor
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_at_login::HybridSigningIdentity;
    use serde_json::json;

    fn members(ids: &[&str]) -> Vec<ThresholdMember> {
        ids.iter()
            .map(|k| {
                HybridSigningIdentity::generate(*k)
                    .unwrap()
                    .directory_member()
                    .unwrap()
            })
            .collect()
    }

    /// A family-genesis object naming `ids`. The roster reader does not
    /// verify its signatures (its trust boundary), so it carries none.
    fn genesis_of(ids: &[&str]) -> SignedCegObject {
        let members: Vec<Value> = ids.iter().map(|k| json!({ "key_id": k })).collect();
        SignedCegObject::new(
            ACCORD_FAMILY_GENESIS_KIND,
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            "2026-06-19T00:00:00Z",
            json!({ "family": { "members": members }, "founder_signatures": [] }),
        )
    }

    #[test]
    fn strict_majority_is_floor_half_plus_one() {
        for (n, m) in [(1, 1), (2, 2), (3, 2), (4, 3), (5, 3), (7, 4)] {
            assert_eq!(strict_majority(n), m);
        }
    }

    #[test]
    fn roster_from_family_selects_members_and_ignores_spares() {
        // #96: the kill-switch roster is the family member set, resolved from a
        // directory that ALSO holds a spare — the spare must NOT become a seat.
        let founders = members(&["A1", "B1", "C1"]);
        let mut directory = founders.clone();
        directory.extend(members(&["A2"]));
        let roster = accord_roster_from_family(&genesis_of(&["A1", "B1", "C1"]), &directory);
        assert_eq!(
            roster.unwrap(),
            founders,
            "the roster is the family members, in order"
        );
    }

    #[test]
    fn roster_from_family_refuses_one_key_in_two_seats() {
        let mut directory = members(&["A1", "B1", "C1"]);
        directory[1].ed25519_public_key_base64 = directory[0].ed25519_public_key_base64.clone();
        assert_eq!(
            accord_roster_from_family(&genesis_of(&["A1", "B1", "C1"]), &directory),
            Err(AccordGenesisError::DuplicateFounderKey)
        );
    }

    #[test]
    fn roster_from_family_fails_closed() {
        let directory = members(&["A1", "B1", "C1"]);
        // A declared member missing from the directory.
        assert_eq!(
            accord_roster_from_family(&genesis_of(&["A1", "B1", "D1"]), &directory),
            Err(AccordGenesisError::MemberNotInDirectory)
        );
        // A repeated member.
        assert_eq!(
            accord_roster_from_family(&genesis_of(&["A1", "A1"]), &directory),
            Err(AccordGenesisError::DuplicateMemberKeyId)
        );
        // No members.
        assert_eq!(
            accord_roster_from_family(&genesis_of(&[]), &directory),
            Err(AccordGenesisError::MalformedEnvelope)
        );
        // Another kind of object.
        let mut other = genesis_of(&["A1"]);
        other.kind = "accord_invocation".to_string();
        assert_eq!(
            accord_roster_from_family(&other, &directory),
            Err(AccordGenesisError::WrongKind)
        );
    }

    #[test]
    fn humanity_accord_genesis_is_baked_and_quorum_valid() {
        use crate::threshold::{verify_founder_quorum, ThresholdMember, ThresholdSignature};
        // #107 BAKED from the #118 six-key ceremony (was empty/no-TOFU until the
        // real genesis was in hand). Prove (a) the pinned recognition root parses
        // + is the right kind/key_id/protocol, and (b) its founder quorum
        // CRYPTOGRAPHICALLY verifies — full hybrid Ed25519 + ML-DSA-65, against the
        // ceremony's PUBLISHED holder pubkeys. The bake is validated, not pasted.
        let genesis = humanity_accord_genesis().expect("the genesis must be baked");
        assert_eq!(genesis.kind, ACCORD_FAMILY_GENESIS_KIND);
        assert_eq!(genesis.key_id, "humanity-accord");

        let family = genesis.body.get("family").expect("family");
        assert_eq!(
            family.get("consensus_protocol").and_then(Value::as_str),
            Some("quorum:2/3")
        );
        assert_eq!(
            family
                .get("consensus_protocol_entrenched")
                .and_then(Value::as_bool),
            Some(true)
        );

        // The ceremony's published founder pubkeys (the holders/ records, #118),
        // checked in alongside the genesis so the quorum is independently auditable.
        let founders: Vec<ThresholdMember> =
            serde_json::from_str(include_str!("genesis/founder_pubkeys.json")).unwrap();
        assert!(
            founders
                .iter()
                .all(|m| m.mldsa65_public_key_base64.is_some()),
            "every founder must carry its ML-DSA-65 half (hybrid-required)"
        );
        let sigs: Vec<ThresholdSignature> =
            serde_json::from_value(genesis.body.get("founder_signatures").unwrap().clone())
                .unwrap();

        let bytes = accord_family_signing_bytes(family).unwrap();
        let threshold = strict_majority(founders.len());
        assert_eq!(threshold, 2, "a strict majority of three holders");
        let count = verify_founder_quorum(&bytes, &founders, &sigs, threshold)
            .expect("the 2-of-3 hybrid founder quorum MUST verify");
        assert_eq!(
            count, 3,
            "all three founders cosigned (3-of-3, ≥ the 2/3 floor)"
        );
    }

    /// #160: the bootstrap rooting anchor is exactly the 3 seated holders'
    /// Ed25519 keys, cross-checked against the pinned founder directory, and
    /// stays in lockstep with the kill-switch roster (one source of truth).
    #[test]
    fn accord_holder_bootstrap_anchor_is_the_seated_holder_ed25519_keys() {
        // Share the crate env lock: under `--features test-anchor` a sibling test
        // may set CIRIS_TESTING_MODE, which would otherwise swap the baked roster
        // out from under this assertion (#202).
        let _g = crate::test_anchor::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let anchor = accord_holder_bootstrap_anchor();
        assert_eq!(
            anchor.len(),
            3,
            "3 seated holders (A1/B1/C1); spares are not a rooting terminus"
        );

        // Every anchor key is exactly a pinned founder ed25519 key, and vice
        // versa (order-independent set equality).
        let b64 = base64::engine::general_purpose::STANDARD;
        let founders: Vec<ThresholdMember> =
            serde_json::from_str(include_str!("genesis/founder_pubkeys.json")).unwrap();
        let expected: Vec<[u8; 32]> = founders
            .iter()
            .map(|m| {
                <[u8; 32]>::try_from(b64.decode(&m.ed25519_public_key_base64).unwrap()).unwrap()
            })
            .collect();
        assert_eq!(anchor.len(), expected.len());
        for e in &expected {
            assert!(anchor.contains(e), "founder key missing from the anchor");
        }
        // The anchor is the SAME set the accord roster resolves to (lockstep).
        let roster =
            accord_roster_from_family(humanity_accord_genesis().expect("baked"), &founders)
                .expect("roster resolves");
        assert_eq!(
            roster.len(),
            anchor.len(),
            "anchor tracks the seated roster"
        );
    }

    /// #202 acceptance: under `--features test-anchor` with the runtime AND-gate,
    /// `accord_holder_bootstrap_anchor()` returns EXACTLY the software test root
    /// from `CIRIS_TEST_TRUST_ROOT` (replacing the baked roster); with the env
    /// unset it returns the baked 3-holder roster unchanged.
    #[test]
    #[cfg(feature = "test-anchor")]
    fn test_anchor_env_swaps_the_bootstrap_anchor_else_baked() {
        use base64::Engine as _;
        let _g = crate::test_anchor::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let b64 = base64::engine::general_purpose::STANDARD;

        // Snapshot + clear, restore on drop (no leak into siblings).
        let saved: Vec<(&str, Option<String>)> = [
            "CIRIS_TESTING_MODE",
            "CIRIS_TEST_TRUST_ROOT",
            "ENVIRONMENT",
            "CIRIS_ENV",
        ]
        .iter()
        .map(|v| (*v, std::env::var(v).ok()))
        .collect();
        for (k, _) in &saved {
            std::env::remove_var(k);
        }

        // Env unset ⇒ baked roster (3 seated holders), unchanged.
        assert_eq!(accord_holder_bootstrap_anchor().len(), 3);

        // Env set ⇒ exactly the SW test key(s).
        let sw = [0xABu8; 32];
        std::env::set_var("CIRIS_TESTING_MODE", "true");
        std::env::set_var("CIRIS_TEST_TRUST_ROOT", b64.encode(sw));
        assert_eq!(accord_holder_bootstrap_anchor(), vec![sw]);

        // Anti-prod tripwire: a prod signal alongside the flags ⇒ baked, not SW.
        std::env::set_var("ENVIRONMENT", "production");
        assert_eq!(
            accord_holder_bootstrap_anchor().len(),
            3,
            "ENVIRONMENT=production must refuse the SW test root and fall back to baked"
        );

        for (k, v) in &saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
        // The rooting half — a chain terminating at a 1-of-N anchor key roots — is
        // proven independently by `provenance::tests::
        // accord_holder_terminus_roots_under_one_of_n_anchor`. This test proves the
        // anchor *becomes* the SW test key; composed, a SW-scrubbed canonical roots.
    }
}
