//! Property tests for trust-root selection (CC 5.3.4; ruling 2026-10-28).
//!
//! Whatever mix of hosts answers, the selected root is the single verified
//! bundle at the highest version, two verified bundles at that version are
//! equivocation, and a host that is down or serves an unverifiable bundle
//! never changes which root is selected.

use ciris_verify_core::genesis_bundle::{verify_genesis_bundle, VerifiedGenesisBundle};
use ciris_verify_core::types::ValidationStatus;
use ciris_verify_core::validation::{select_trust_root, SourceOutcome, SourceReport};
use proptest::prelude::*;

const V4: &str = include_str!("../vectors/genesis_bundle/v4_persist_v59_1_0.json");

fn base() -> VerifiedGenesisBundle {
    verify_genesis_bundle(&serde_json::from_str(V4).unwrap()).unwrap()
}

/// A host's report, from a generated tag: `None` = down, `Some(None)` =
/// refused, `Some(Some((version, fp)))` = verified.
fn report(
    n: usize,
    tag: Option<Option<(u32, u8)>>,
    template: &VerifiedGenesisBundle,
) -> SourceReport {
    let outcome = match tag {
        None => SourceOutcome::Unreachable("timeout".into()),
        Some(None) => SourceOutcome::Refused("quorum not met".into()),
        Some(Some((version, fp))) => {
            let mut b = template.clone();
            b.version = version;
            // A fingerprint covers the whole bundle, version included.
            b.bundle_fingerprint = format!("sha256:{version:02x}{fp:02x}");
            SourceOutcome::Verified(Box::new(b))
        },
    };
    SourceReport {
        endpoint: format!("https://host-{n}"),
        outcome,
    }
}

fn tag_strategy() -> impl Strategy<Value = Option<Option<(u32, u8)>>> {
    prop_oneof![
        Just(None),
        Just(Some(None)),
        (4u32..7, 0u8..3).prop_map(|v| Some(Some(v))),
    ]
}

proptest! {
    #[test]
    fn selection_follows_the_cc_rule(tags in prop::collection::vec(tag_strategy(), 0..6)) {
        let template = base();
        let reports: Vec<SourceReport> =
            tags.iter().enumerate().map(|(n, t)| report(n, *t, &template)).collect();
        let verified: Vec<(u32, u8)> = tags.iter().filter_map(|t| t.flatten()).collect();
        let result = select_trust_root(reports);

        match verified.iter().map(|v| v.0).max() {
            None => {
                prop_assert!(result.trust_root.is_none());
                let any_reachable = tags.iter().any(Option::is_some);
                prop_assert_eq!(
                    result.status,
                    if any_reachable { ValidationStatus::ValidationError }
                    else { ValidationStatus::NoSourcesReachable }
                );
            },
            Some(top) => {
                let mut fps: Vec<u8> =
                    verified.iter().filter(|v| v.0 == top).map(|v| v.1).collect();
                fps.sort_unstable();
                fps.dedup();
                if fps.len() > 1 {
                    prop_assert_eq!(result.status, ValidationStatus::SourcesDisagree);
                    prop_assert!(result.trust_root.is_none());
                } else {
                    let root = result.trust_root.as_ref().unwrap();
                    prop_assert_eq!(root.version, top);
                    prop_assert_eq!(&root.bundle_fingerprint, &format!("sha256:{:02x}{:02x}", top, fps[0]));
                    let all_same = tags.iter().all(|t| *t == Some(Some((top, fps[0]))));
                    prop_assert_eq!(
                        result.status,
                        if all_same { ValidationStatus::AllSourcesAgree }
                        else { ValidationStatus::PartialAgreement }
                    );
                }
            },
        }
    }

    /// Adding a host that is down or refused never changes the selected root.
    #[test]
    fn a_failing_host_never_moves_the_root(
        tags in prop::collection::vec(tag_strategy(), 1..5),
        failing_refused in any::<bool>(),
    ) {
        let template = base();
        let before = select_trust_root(
            tags.iter().enumerate().map(|(n, t)| report(n, *t, &template)).collect(),
        );
        let mut more: Vec<SourceReport> =
            tags.iter().enumerate().map(|(n, t)| report(n, *t, &template)).collect();
        more.push(report(99, if failing_refused { Some(None) } else { None }, &template));
        let after = select_trust_root(more);
        prop_assert_eq!(
            before.trust_root.map(|r| r.bundle_fingerprint),
            after.trust_root.map(|r| r.bundle_fingerprint)
        );
    }
}
