//! Multi-source consensus validation.
//!
//! Implements the 2-of-3 consensus requirement for CIRISVerify:
//! - DNS US source
//! - DNS EU source
//! - HTTPS endpoint
//!
//! ## Validation Rules
//!
//! - **ALL_SOURCES_AGREE**: All 3 sources return matching data
//! - **PARTIAL_AGREEMENT**: 2 of 3 sources match (degraded mode)
//! - **SOURCES_DISAGREE**: Sources return conflicting data (possible attack)
//! - **NO_SOURCES_REACHABLE**: Cannot reach any source (offline mode)
//!
//! ## Security Properties
//!
//! - ANY source reporting REVOKED triggers immediate revocation
//! - Disagreement on steward key triggers SECURITY_ALERT
//! - Minimum 2 sources required for licensed status

use std::time::Duration;

use base64::Engine;
use tracing::{debug, warn, error, instrument};

use crate::dns::{DnsTxtRecord, query_multiple_sources};
use crate::https::{StewardKeyResponse, query_https_source};
use crate::types::ValidationStatus;

/// Consensus validator for multi-source agreement.
pub struct ConsensusValidator {
    /// DNS US host.
    dns_us_host: String,
    /// DNS EU host.
    dns_eu_host: String,
    /// HTTPS endpoint.
    https_endpoint: String,
    /// Request timeout.
    timeout: Duration,
    /// Certificate pin for HTTPS.
    cert_pin: Option<String>,
}

impl ConsensusValidator {
    /// Create a new consensus validator.
    pub fn new(
        dns_us_host: String,
        dns_eu_host: String,
        https_endpoint: String,
        timeout: Duration,
        cert_pin: Option<String>,
    ) -> Self {
        Self {
            dns_us_host,
            dns_eu_host,
            https_endpoint,
            timeout,
            cert_pin,
        }
    }

    /// Validate steward key across all sources.
    ///
    /// Queries all three sources in parallel and computes consensus.
    #[instrument(skip(self))]
    pub async fn validate_steward_key(&self) -> ValidationResult {
        // Query all sources in parallel
        let (dns_result, https_result) = tokio::join!(
            query_multiple_sources(&self.dns_us_host, &self.dns_eu_host, self.timeout),
            query_https_source(&self.https_endpoint, self.timeout, self.cert_pin.as_deref()),
        );

        // Convert results to SourceData
        let dns_us = dns_result.us_result.ok().map(|r| SourceData::from_dns(&r));
        let dns_eu = dns_result.eu_result.ok().map(|r| SourceData::from_dns(&r));
        let https = https_result.ok().map(|r| SourceData::from_https(&r));

        // Log source availability
        debug!(
            dns_us_ok = dns_us.is_some(),
            dns_eu_ok = dns_eu.is_some(),
            https_ok = https.is_some(),
            "Source availability"
        );

        // Compute consensus
        Self::compute_consensus(dns_us, dns_eu, https)
    }

    /// Compute consensus from multiple source results.
    ///
    /// # Rules
    ///
    /// 1. If all 3 sources agree on steward key and PQC fingerprint → ALL_SOURCES_AGREE
    /// 2. If 2 of 3 sources agree → PARTIAL_AGREEMENT (with warning)
    /// 3. If sources actively disagree → SOURCES_DISAGREE (security alert)
    /// 4. If no sources reachable → NO_SOURCES_REACHABLE
    #[instrument(skip_all)]
    pub fn compute_consensus(
        dns_us: Option<SourceData>,
        dns_eu: Option<SourceData>,
        https: Option<SourceData>,
    ) -> ValidationResult {
        let sources: Vec<(&str, Option<&SourceData>)> = vec![
            ("dns_us", dns_us.as_ref()),
            ("dns_eu", dns_eu.as_ref()),
            ("https", https.as_ref()),
        ];

        // Count available sources
        let available: Vec<_> = sources
            .iter()
            .filter_map(|(name, data)| data.map(|d| (*name, d)))
            .collect();

        let available_count = available.len();

        debug!("Available sources: {}/3", available_count);

        // No sources reachable
        if available_count == 0 {
            warn!("No verification sources reachable");
            return ValidationResult {
                status: ValidationStatus::NoSourcesReachable,
                consensus_key_classical: None,
                consensus_pqc_fingerprint: None,
                consensus_revocation_revision: None,
                source_details: SourceDetails {
                    dns_us_reachable: false,
                    dns_eu_reachable: false,
                    https_reachable: false,
                    dns_us_error: dns_us.is_none().then(|| "Not reachable".into()),
                    dns_eu_error: dns_eu.is_none().then(|| "Not reachable".into()),
                    https_error: https.is_none().then(|| "Not reachable".into()),
                },
            };
        }

        // Only one source - cannot establish consensus
        if available_count == 1 {
            warn!("Only one source available - insufficient for consensus");
            let (_name, data) = available[0];
            return ValidationResult {
                status: ValidationStatus::ValidationError,
                consensus_key_classical: Some(data.steward_key_classical.clone()),
                consensus_pqc_fingerprint: Some(data.pqc_fingerprint.clone()),
                consensus_revocation_revision: Some(data.revocation_revision),
                source_details: SourceDetails {
                    dns_us_reachable: dns_us.is_some(),
                    dns_eu_reachable: dns_eu.is_some(),
                    https_reachable: https.is_some(),
                    dns_us_error: dns_us.is_none().then(|| "Not reachable".into()),
                    dns_eu_error: dns_eu.is_none().then(|| "Not reachable".into()),
                    https_error: https.is_none().then(|| "Not reachable".into()),
                },
            };
        }

        // Check for agreement between available sources
        let mut agreement_groups: Vec<Vec<(&str, &SourceData)>> = Vec::new();

        for (name, data) in &available {
            let mut found_group = false;
            for group in &mut agreement_groups {
                if Self::sources_agree(group[0].1, data) {
                    group.push((*name, *data));
                    found_group = true;
                    break;
                }
            }
            if !found_group {
                agreement_groups.push(vec![(*name, *data)]);
            }
        }

        // Find the largest agreement group
        let largest_group = agreement_groups
            .iter()
            .max_by_key(|g| g.len())
            .unwrap();

        let agreement_count = largest_group.len();
        let consensus_data = largest_group[0].1;

        debug!(
            agreement_count = agreement_count,
            total_sources = available_count,
            "Consensus analysis"
        );

        // Build source details
        let source_details = SourceDetails {
            dns_us_reachable: dns_us.is_some(),
            dns_eu_reachable: dns_eu.is_some(),
            https_reachable: https.is_some(),
            dns_us_error: None,
            dns_eu_error: None,
            https_error: None,
        };

        // Determine status based on agreement
        if agreement_count == available_count {
            // All available sources agree
            if available_count == 3 {
                debug!("All 3 sources agree - full consensus");
                ValidationResult {
                    status: ValidationStatus::AllSourcesAgree,
                    consensus_key_classical: Some(consensus_data.steward_key_classical.clone()),
                    consensus_pqc_fingerprint: Some(consensus_data.pqc_fingerprint.clone()),
                    consensus_revocation_revision: Some(consensus_data.revocation_revision),
                    source_details,
                }
            } else {
                // 2 sources available and agree
                warn!("Only 2 sources available but they agree - partial consensus");
                ValidationResult {
                    status: ValidationStatus::PartialAgreement,
                    consensus_key_classical: Some(consensus_data.steward_key_classical.clone()),
                    consensus_pqc_fingerprint: Some(consensus_data.pqc_fingerprint.clone()),
                    consensus_revocation_revision: Some(consensus_data.revocation_revision),
                    source_details,
                }
            }
        } else if agreement_count >= 2 {
            // 2 of 3 agree, 1 disagrees
            warn!(
                "Partial agreement: {} of {} sources agree",
                agreement_count, available_count
            );

            // Log which source disagrees
            for (name, data) in &available {
                if !Self::sources_agree(consensus_data, data) {
                    error!(
                        source = name,
                        "Source disagrees with consensus - possible attack or configuration error"
                    );
                }
            }

            ValidationResult {
                status: ValidationStatus::PartialAgreement,
                consensus_key_classical: Some(consensus_data.steward_key_classical.clone()),
                consensus_pqc_fingerprint: Some(consensus_data.pqc_fingerprint.clone()),
                consensus_revocation_revision: Some(consensus_data.revocation_revision),
                source_details,
            }
        } else {
            // No majority agreement - critical security issue
            error!(
                "SECURITY ALERT: Sources actively disagree! Possible attack detected."
            );

            ValidationResult {
                status: ValidationStatus::SourcesDisagree,
                consensus_key_classical: None,
                consensus_pqc_fingerprint: None,
                consensus_revocation_revision: None,
                source_details,
            }
        }
    }

    /// Check if two source data records agree on critical fields.
    fn sources_agree(a: &SourceData, b: &SourceData) -> bool {
        // Must agree on steward key (constant-time comparison)
        let keys_match = ciris_crypto::constant_time_eq(
            &a.steward_key_classical,
            &b.steward_key_classical,
        );

        // Must agree on PQC fingerprint
        let pqc_match = ciris_crypto::constant_time_eq(
            &a.pqc_fingerprint,
            &b.pqc_fingerprint,
        );

        // Revocation revision should match (small difference acceptable for propagation delay)
        let rev_match = a.revocation_revision == b.revocation_revision
            || (a.revocation_revision as i64 - b.revocation_revision as i64).abs() <= 1;

        keys_match && pqc_match && rev_match
    }
}

/// Data from a validation source, normalized for comparison.
#[derive(Debug, Clone)]
pub struct SourceData {
    /// Classical steward key (raw bytes).
    pub steward_key_classical: Vec<u8>,
    /// PQC key fingerprint (SHA-256, raw bytes).
    pub pqc_fingerprint: Vec<u8>,
    /// Revocation list revision number.
    pub revocation_revision: u64,
    /// Source timestamp.
    pub timestamp: i64,
}

impl SourceData {
    /// Create from DNS TXT record.
    pub fn from_dns(record: &DnsTxtRecord) -> Self {
        Self {
            steward_key_classical: record.steward_key_classical.clone(),
            pqc_fingerprint: record.pqc_fingerprint.clone(),
            revocation_revision: record.revocation_revision,
            timestamp: record.timestamp,
        }
    }

    /// Create from HTTPS response.
    pub fn from_https(response: &StewardKeyResponse) -> Self {
        // Decode the classical key
        let steward_key_classical = base64::engine::general_purpose::STANDARD
            .decode(&response.classical.key)
            .unwrap_or_default();

        // Decode the PQC fingerprint
        let pqc_fp_hex = response
            .pqc
            .fingerprint
            .strip_prefix("sha256:")
            .unwrap_or(&response.pqc.fingerprint);
        let pqc_fingerprint = hex::decode(pqc_fp_hex).unwrap_or_default();

        Self {
            steward_key_classical,
            pqc_fingerprint,
            revocation_revision: response.revision,
            timestamp: response.timestamp,
        }
    }
}

/// Result of consensus validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Overall validation status.
    pub status: ValidationStatus,
    /// Consensus steward key (classical, if available).
    pub consensus_key_classical: Option<Vec<u8>>,
    /// Consensus PQC key fingerprint (if available).
    pub consensus_pqc_fingerprint: Option<Vec<u8>>,
    /// Consensus revocation revision (if available).
    pub consensus_revocation_revision: Option<u64>,
    /// Details about each source.
    pub source_details: SourceDetails,
}

/// Details about individual source status.
#[derive(Debug, Clone)]
pub struct SourceDetails {
    /// Was DNS US source reachable?
    pub dns_us_reachable: bool,
    /// Was DNS EU source reachable?
    pub dns_eu_reachable: bool,
    /// Was HTTPS source reachable?
    pub https_reachable: bool,
    /// DNS US error message.
    pub dns_us_error: Option<String>,
    /// DNS EU error message.
    pub dns_eu_error: Option<String>,
    /// HTTPS error message.
    pub https_error: Option<String>,
}

impl ValidationResult {
    /// Check if this result allows licensed operation.
    pub fn allows_licensed(&self) -> bool {
        matches!(
            self.status,
            ValidationStatus::AllSourcesAgree | ValidationStatus::PartialAgreement
        )
    }

    /// Check if this result should trigger security alert.
    pub fn is_security_alert(&self) -> bool {
        matches!(self.status, ValidationStatus::SourcesDisagree)
    }

    /// Check if we're operating in offline/degraded mode.
    pub fn is_degraded(&self) -> bool {
        matches!(
            self.status,
            ValidationStatus::PartialAgreement
                | ValidationStatus::NoSourcesReachable
                | ValidationStatus::ValidationError
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_source_data(key: &[u8], fingerprint: &[u8], revision: u64) -> SourceData {
        SourceData {
            steward_key_classical: key.to_vec(),
            pqc_fingerprint: fingerprint.to_vec(),
            revocation_revision: revision,
            timestamp: 1737763200,
        }
    }

    #[test]
    fn test_all_sources_agree() {
        let key = vec![1u8; 32];
        let fp = vec![2u8; 32];

        let dns_us = Some(make_source_data(&key, &fp, 100));
        let dns_eu = Some(make_source_data(&key, &fp, 100));
        let https = Some(make_source_data(&key, &fp, 100));

        let result = ConsensusValidator::compute_consensus(dns_us, dns_eu, https);

        assert_eq!(result.status, ValidationStatus::AllSourcesAgree);
        assert!(result.consensus_key_classical.is_some());
        assert!(result.allows_licensed());
        assert!(!result.is_security_alert());
    }

    #[test]
    fn test_two_of_three_agree() {
        let key1 = vec![1u8; 32];
        let key2 = vec![9u8; 32]; // Different key
        let fp = vec![2u8; 32];

        let dns_us = Some(make_source_data(&key1, &fp, 100));
        let dns_eu = Some(make_source_data(&key1, &fp, 100));
        let https = Some(make_source_data(&key2, &fp, 100)); // Disagrees

        let result = ConsensusValidator::compute_consensus(dns_us, dns_eu, https);

        assert_eq!(result.status, ValidationStatus::PartialAgreement);
        assert!(result.allows_licensed());
        assert!(!result.is_security_alert());
    }

    #[test]
    fn test_all_disagree() {
        let fp = vec![2u8; 32];

        let dns_us = Some(make_source_data(&vec![1u8; 32], &fp, 100));
        let dns_eu = Some(make_source_data(&vec![2u8; 32], &fp, 100));
        let https = Some(make_source_data(&vec![3u8; 32], &fp, 100));

        let result = ConsensusValidator::compute_consensus(dns_us, dns_eu, https);

        assert_eq!(result.status, ValidationStatus::SourcesDisagree);
        assert!(!result.allows_licensed());
        assert!(result.is_security_alert());
    }

    #[test]
    fn test_no_sources_reachable() {
        let result = ConsensusValidator::compute_consensus(None, None, None);

        assert_eq!(result.status, ValidationStatus::NoSourcesReachable);
        assert!(!result.allows_licensed());
        assert!(!result.is_security_alert());
    }

    #[test]
    fn test_only_one_source() {
        let key = vec![1u8; 32];
        let fp = vec![2u8; 32];

        let dns_us = Some(make_source_data(&key, &fp, 100));

        let result = ConsensusValidator::compute_consensus(dns_us, None, None);

        assert_eq!(result.status, ValidationStatus::ValidationError);
        assert!(!result.allows_licensed());
    }

    #[test]
    fn test_two_sources_available_and_agree() {
        let key = vec![1u8; 32];
        let fp = vec![2u8; 32];

        let dns_us = Some(make_source_data(&key, &fp, 100));
        let https = Some(make_source_data(&key, &fp, 100));

        let result = ConsensusValidator::compute_consensus(dns_us, None, https);

        assert_eq!(result.status, ValidationStatus::PartialAgreement);
        assert!(result.allows_licensed());
        assert!(result.is_degraded());
    }

    #[test]
    fn test_revision_tolerance() {
        let key = vec![1u8; 32];
        let fp = vec![2u8; 32];

        // Revisions differ by 1 (acceptable propagation delay)
        let dns_us = Some(make_source_data(&key, &fp, 100));
        let dns_eu = Some(make_source_data(&key, &fp, 101));
        let https = Some(make_source_data(&key, &fp, 100));

        let result = ConsensusValidator::compute_consensus(dns_us, dns_eu, https);

        assert_eq!(result.status, ValidationStatus::AllSourcesAgree);
    }
}
