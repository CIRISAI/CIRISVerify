//! Property-based tests for multi-source validation.
//!
//! These tests verify the consensus algorithm properties and
//! fail-secure behavior.

use proptest::prelude::*;
use sha2::{Digest, Sha256};

use ciris_verify_core::validation::{ConsensusValidator, SourceData};
use ciris_verify_core::types::ValidationStatus;
use ciris_verify_core::revocation::is_revision_stale;

/// Strategy for 32-byte keys.
fn key_32_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 32)
}

/// Strategy for revocation revision numbers (YYYYMMDDNN format).
fn revision_strategy() -> impl Strategy<Value = u64> {
    (2024u64..=2030, 1u64..=12, 1u64..=28, 0u64..=99)
        .prop_map(|(y, m, d, n)| y * 1_000_000 + m * 10_000 + d * 100 + n)
}

/// Strategy for source data triplets.
fn source_data_strategy() -> impl Strategy<Value = (Vec<u8>, Vec<u8>, u64)> {
    (key_32_bytes(), key_32_bytes(), revision_strategy())
}

/// Generate a test public key (deterministic).
fn test_public_key(id: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(format!("test-pubkey-{}", id).as_bytes());
    hasher.finalize().to_vec()
}

/// Generate a test PQC fingerprint.
fn test_pqc_fingerprint(id: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(format!("test-pqc-fp-{}", id).as_bytes());
    hasher.finalize().to_vec()
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_shrink_iters: 1000,
        ..ProptestConfig::default()
    })]

    // ========================================================================
    // Consensus Algorithm Properties
    // ========================================================================

    /// Three identical sources always produce AllSourcesAgree.
    #[test]
    fn consensus_identical_sources_agree(
        (key, fp, rev) in source_data_strategy()
    ) {
        let source = SourceData {
            steward_key_classical: key.clone(),
            pqc_fingerprint: fp.clone(),
            revocation_revision: rev,
            timestamp: 1737936000,
        };

        let result = ConsensusValidator::compute_consensus(
            Some(source.clone()),
            Some(source.clone()),
            Some(source.clone()),
        );

        prop_assert_eq!(result.status, ValidationStatus::AllSourcesAgree);
        prop_assert!(result.allows_licensed());
        prop_assert!(!result.is_security_alert());
    }

    /// Two identical sources with one different produces PartialAgreement.
    #[test]
    fn consensus_two_of_three_agree(
        (key1, fp, rev) in source_data_strategy(),
        key2 in key_32_bytes()
    ) {
        // Ensure key2 is different
        prop_assume!(key1 != key2);

        let source1 = SourceData {
            steward_key_classical: key1.clone(),
            pqc_fingerprint: fp.clone(),
            revocation_revision: rev,
            timestamp: 1737936000,
        };

        let source2 = SourceData {
            steward_key_classical: key2,
            pqc_fingerprint: fp.clone(),
            revocation_revision: rev,
            timestamp: 1737936000,
        };

        let result = ConsensusValidator::compute_consensus(
            Some(source1.clone()),
            Some(source1.clone()),
            Some(source2),
        );

        prop_assert_eq!(result.status, ValidationStatus::PartialAgreement);
        prop_assert!(result.allows_licensed());
    }

    /// Three different keys produces SourcesDisagree (security alert).
    #[test]
    fn consensus_all_different_disagree(
        key1 in key_32_bytes(),
        key2 in key_32_bytes(),
        key3 in key_32_bytes(),
        fp in key_32_bytes(),
        rev in revision_strategy()
    ) {
        // Ensure all keys are different
        prop_assume!(key1 != key2 && key2 != key3 && key1 != key3);

        let source1 = SourceData {
            steward_key_classical: key1,
            pqc_fingerprint: fp.clone(),
            revocation_revision: rev,
            timestamp: 1737936000,
        };

        let source2 = SourceData {
            steward_key_classical: key2,
            pqc_fingerprint: fp.clone(),
            revocation_revision: rev,
            timestamp: 1737936000,
        };

        let source3 = SourceData {
            steward_key_classical: key3,
            pqc_fingerprint: fp.clone(),
            revocation_revision: rev,
            timestamp: 1737936000,
        };

        let result = ConsensusValidator::compute_consensus(
            Some(source1),
            Some(source2),
            Some(source3),
        );

        prop_assert_eq!(result.status, ValidationStatus::SourcesDisagree);
        prop_assert!(!result.allows_licensed());
        prop_assert!(result.is_security_alert());
    }

    /// No sources produces NoSourcesReachable.
    #[test]
    fn consensus_no_sources(_seed in any::<u64>()) {
        let result = ConsensusValidator::compute_consensus(None, None, None);

        prop_assert_eq!(result.status, ValidationStatus::NoSourcesReachable);
        prop_assert!(!result.allows_licensed());
    }

    /// Single source produces ValidationError (insufficient for consensus).
    #[test]
    fn consensus_single_source((key, fp, rev) in source_data_strategy()) {
        let source = SourceData {
            steward_key_classical: key,
            pqc_fingerprint: fp,
            revocation_revision: rev,
            timestamp: 1737936000,
        };

        // Test each position
        let result1 = ConsensusValidator::compute_consensus(Some(source.clone()), None, None);
        let result2 = ConsensusValidator::compute_consensus(None, Some(source.clone()), None);
        let result3 = ConsensusValidator::compute_consensus(None, None, Some(source));

        prop_assert_eq!(result1.status, ValidationStatus::ValidationError);
        prop_assert_eq!(result2.status, ValidationStatus::ValidationError);
        prop_assert_eq!(result3.status, ValidationStatus::ValidationError);
    }

    /// Two agreeing sources (one unavailable) produces PartialAgreement.
    #[test]
    fn consensus_two_available_agree((key, fp, rev) in source_data_strategy()) {
        let source = SourceData {
            steward_key_classical: key,
            pqc_fingerprint: fp,
            revocation_revision: rev,
            timestamp: 1737936000,
        };

        // Test each combination of two
        let result1 = ConsensusValidator::compute_consensus(
            Some(source.clone()),
            Some(source.clone()),
            None,
        );
        let result2 = ConsensusValidator::compute_consensus(
            Some(source.clone()),
            None,
            Some(source.clone()),
        );
        let result3 = ConsensusValidator::compute_consensus(
            None,
            Some(source.clone()),
            Some(source),
        );

        prop_assert_eq!(result1.status, ValidationStatus::PartialAgreement);
        prop_assert_eq!(result2.status, ValidationStatus::PartialAgreement);
        prop_assert_eq!(result3.status, ValidationStatus::PartialAgreement);

        // All should allow licensed operation
        prop_assert!(result1.allows_licensed());
        prop_assert!(result2.allows_licensed());
        prop_assert!(result3.allows_licensed());
    }

    /// Revision tolerance: ±1 is acceptable.
    #[test]
    fn consensus_revision_tolerance(
        (key, fp, base_rev) in source_data_strategy()
    ) {
        // Ensure we don't overflow
        prop_assume!(base_rev >= 1 && base_rev < u64::MAX);

        let source1 = SourceData {
            steward_key_classical: key.clone(),
            pqc_fingerprint: fp.clone(),
            revocation_revision: base_rev,
            timestamp: 1737936000,
        };

        let source2 = SourceData {
            steward_key_classical: key.clone(),
            pqc_fingerprint: fp.clone(),
            revocation_revision: base_rev + 1, // One higher
            timestamp: 1737936000,
        };

        let source3 = SourceData {
            steward_key_classical: key,
            pqc_fingerprint: fp,
            revocation_revision: base_rev, // Same as source1
            timestamp: 1737936000,
        };

        let result = ConsensusValidator::compute_consensus(
            Some(source1),
            Some(source2),
            Some(source3),
        );

        // Should still agree despite ±1 revision difference
        prop_assert_eq!(result.status, ValidationStatus::AllSourcesAgree);
    }

    // ========================================================================
    // Revocation Properties
    // ========================================================================

    /// Revision staleness is strictly increasing.
    #[test]
    fn revision_stale_monotonic(
        license_rev in revision_strategy(),
        delta in 0u64..1000
    ) {
        let current_rev = license_rev.saturating_add(delta);

        if delta == 0 {
            // Same revision is not stale
            prop_assert!(!is_revision_stale(license_rev, current_rev));
        } else {
            // Higher revision means potentially stale
            prop_assert!(is_revision_stale(license_rev, current_rev));
        }
    }

    /// Lower current revision is never stale.
    #[test]
    fn revision_older_not_stale(
        license_rev in 1000u64..u64::MAX,
        delta in 1u64..1000
    ) {
        let older_current = license_rev.saturating_sub(delta);
        prop_assert!(!is_revision_stale(license_rev, older_current));
    }
}

// ============================================================================
// Non-proptest Deterministic Tests
// ============================================================================

#[test]
fn test_consensus_preserves_key_on_agreement() {
    let key = test_public_key("consensus-key");
    let fp = test_pqc_fingerprint("consensus-fp");
    let rev = 2026012701u64;

    let source = SourceData {
        steward_key_classical: key.clone(),
        pqc_fingerprint: fp.clone(),
        revocation_revision: rev,
        timestamp: 1737936000,
    };

    let result = ConsensusValidator::compute_consensus(
        Some(source.clone()),
        Some(source.clone()),
        Some(source),
    );

    // Consensus should preserve the agreed-upon key
    assert_eq!(result.consensus_key_classical, Some(key));
    assert_eq!(result.consensus_pqc_fingerprint, Some(fp));
    assert_eq!(result.consensus_revocation_revision, Some(rev));
}

#[test]
fn test_consensus_disagreement_no_key() {
    let key1 = test_public_key("key-1");
    let key2 = test_public_key("key-2");
    let key3 = test_public_key("key-3");
    let fp = test_pqc_fingerprint("test");

    let source1 = SourceData {
        steward_key_classical: key1,
        pqc_fingerprint: fp.clone(),
        revocation_revision: 100,
        timestamp: 1737936000,
    };

    let source2 = SourceData {
        steward_key_classical: key2,
        pqc_fingerprint: fp.clone(),
        revocation_revision: 100,
        timestamp: 1737936000,
    };

    let source3 = SourceData {
        steward_key_classical: key3,
        pqc_fingerprint: fp,
        revocation_revision: 100,
        timestamp: 1737936000,
    };

    let result = ConsensusValidator::compute_consensus(
        Some(source1),
        Some(source2),
        Some(source3),
    );

    // Disagreement should NOT provide consensus key
    assert!(result.consensus_key_classical.is_none());
    assert!(result.consensus_pqc_fingerprint.is_none());
}

#[test]
fn test_source_details_tracking() {
    let key = test_public_key("test");
    let fp = test_pqc_fingerprint("test");

    let source = SourceData {
        steward_key_classical: key,
        pqc_fingerprint: fp,
        revocation_revision: 100,
        timestamp: 1737936000,
    };

    // Only dns_us and https available
    let result = ConsensusValidator::compute_consensus(
        Some(source.clone()),
        None,
        Some(source),
    );

    assert!(result.source_details.dns_us_reachable);
    assert!(!result.source_details.dns_eu_reachable);
    assert!(result.source_details.https_reachable);
}
