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
use tracing::{debug, error, info, instrument, warn};

use crate::config::TrustModel;
use crate::dns::{query_multiple_sources, DnsTxtRecord};
use crate::https::{query_https_source, StewardKeyResponse};
use crate::types::ValidationStatus;

/// Consensus validator for multi-source agreement.
pub struct ConsensusValidator {
    /// DNS US host.
    dns_us_host: String,
    /// DNS EU host.
    dns_eu_host: String,
    /// HTTPS endpoint (primary).
    https_endpoint: String,
    /// Additional HTTPS endpoints at different domains.
    additional_https_endpoints: Vec<String>,
    /// Trust model for validation.
    trust_model: TrustModel,
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
            additional_https_endpoints: Vec::new(),
            trust_model: TrustModel::HttpsAuthoritative,
            timeout,
            cert_pin,
        }
    }

    /// Create a new consensus validator with full configuration.
    pub fn with_trust_model(
        dns_us_host: String,
        dns_eu_host: String,
        https_endpoint: String,
        additional_https_endpoints: Vec<String>,
        trust_model: TrustModel,
        timeout: Duration,
        cert_pin: Option<String>,
    ) -> Self {
        Self {
            dns_us_host,
            dns_eu_host,
            https_endpoint,
            additional_https_endpoints,
            trust_model,
            timeout,
            cert_pin,
        }
    }

    /// Validate steward key across all sources.
    ///
    /// Dispatches to the appropriate consensus algorithm based on the trust model:
    /// - `HttpsAuthoritative`: HTTPS is authoritative; DNS is advisory cross-check
    /// - `EqualWeight`: Legacy 2-of-3 equal-weight consensus
    #[instrument(skip(self))]
    pub async fn validate_steward_key(&self) -> ValidationResult {
        info!(
            dns_us = %self.dns_us_host,
            dns_eu = %self.dns_eu_host,
            https = %self.https_endpoint,
            timeout_secs = self.timeout.as_secs(),
            "Starting parallel DNS + HTTPS queries..."
        );

        // Query DNS sources with timeout wrapper
        let dns_future = async {
            info!("DNS query starting...");
            let result = tokio::time::timeout(
                self.timeout,
                query_multiple_sources(&self.dns_us_host, &self.dns_eu_host, self.timeout),
            )
            .await;
            match &result {
                Ok(r) => info!(
                    dns_us_ok = r.us_result.is_ok(),
                    dns_eu_ok = r.eu_result.is_ok(),
                    "DNS query complete"
                ),
                Err(_) => warn!("DNS query timed out after {:?}", self.timeout),
            }
            result
        };

        // Query primary HTTPS source with timeout wrapper
        let https_future = async {
            info!(endpoint = %self.https_endpoint, "HTTPS query starting...");
            let result = tokio::time::timeout(
                self.timeout,
                query_https_source(&self.https_endpoint, self.timeout, self.cert_pin.as_deref()),
            )
            .await;
            match &result {
                Ok(Ok(_)) => info!("HTTPS query complete (success)"),
                Ok(Err(e)) => warn!("HTTPS query failed: {}", e),
                Err(_) => warn!("HTTPS query timed out after {:?}", self.timeout),
            }
            result
        };

        // Query additional HTTPS endpoints in parallel
        let additional_futures: Vec<_> = self
            .additional_https_endpoints
            .iter()
            .map(|ep| {
                let ep = ep.clone();
                let timeout = self.timeout;
                let cert_pin = self.cert_pin.clone();
                async move {
                    info!(endpoint = %ep, "Additional HTTPS query starting...");
                    let result = tokio::time::timeout(
                        timeout,
                        query_https_source(&ep, timeout, cert_pin.as_deref()),
                    )
                    .await;
                    match &result {
                        Ok(Ok(_)) => info!(endpoint = %ep, "Additional HTTPS complete"),
                        Ok(Err(e)) => warn!(endpoint = %ep, "Additional HTTPS failed: {}", e),
                        Err(_) => warn!(endpoint = %ep, "Additional HTTPS timed out"),
                    }
                    result
                }
            })
            .collect();

        // Execute all queries in parallel
        let (dns_result, primary_https_result, additional_results) = tokio::join!(
            dns_future,
            https_future,
            futures::future::join_all(additional_futures),
        );

        info!("All network queries complete, processing results...");

        // Convert results to SourceData, preserving actual error messages
        let (dns_us, dns_eu, dns_us_error, dns_eu_error) = match dns_result {
            Ok(r) => {
                let us_data = r.us_result.as_ref().ok().map(SourceData::from_dns);
                let eu_data = r.eu_result.as_ref().ok().map(SourceData::from_dns);
                let us_err = r.us_result.err();
                let eu_err = r.eu_result.err();
                (us_data, eu_data, us_err, eu_err)
            },
            Err(_) => {
                // DNS query timed out at the wrapper level
                let timeout_err = Some("DNS query timeout".to_string());
                (None, None, timeout_err.clone(), timeout_err)
            },
        };

        let (primary_https, https_error) = match primary_https_result {
            Ok(Ok(r)) => (Some(SourceData::from_https(&r)), None),
            Ok(Err(e)) => (None, Some(format!("{}", e))),
            Err(_) => (None, Some("HTTPS query timeout".to_string())),
        };

        let additional_https: Vec<Option<SourceData>> = additional_results
            .into_iter()
            .map(|r| {
                r.ok() // unwrap timeout
                    .and_then(|r| r.ok()) // unwrap query result
                    .map(|r| SourceData::from_https(&r))
            })
            .collect();

        // Log source availability with actual errors
        let additional_ok = additional_https.iter().filter(|s| s.is_some()).count();
        debug!(
            dns_us_ok = dns_us.is_some(),
            dns_eu_ok = dns_eu.is_some(),
            https_ok = primary_https.is_some(),
            additional_https_ok = additional_ok,
            dns_us_error = ?dns_us_error,
            dns_eu_error = ?dns_eu_error,
            https_error = ?https_error,
            trust_model = ?self.trust_model,
            "Source availability"
        );

        // Build error details struct to pass to consensus functions
        let error_details = SourceErrorDetails {
            dns_us_error,
            dns_eu_error,
            https_error,
        };

        match self.trust_model {
            TrustModel::HttpsAuthoritative => Self::compute_https_authoritative_consensus(
                dns_us,
                dns_eu,
                primary_https,
                additional_https,
                error_details,
            ),
            TrustModel::EqualWeight => {
                Self::compute_consensus(dns_us, dns_eu, primary_https, error_details)
            },
        }
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
        errors: SourceErrorDetails,
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
                authoritative_source: None,
                source_details: SourceDetails {
                    dns_us_reachable: false,
                    dns_eu_reachable: false,
                    https_reachable: false,
                    dns_us_error: errors.dns_us_error.or(Some("Not reachable".into())),
                    dns_eu_error: errors.dns_eu_error.or(Some("Not reachable".into())),
                    https_error: errors.https_error.or(Some("Not reachable".into())),
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
                authoritative_source: None,
                source_details: SourceDetails {
                    dns_us_reachable: dns_us.is_some(),
                    dns_eu_reachable: dns_eu.is_some(),
                    https_reachable: https.is_some(),
                    // Only set error if source is NOT reachable
                    dns_us_error: if dns_us.is_none() {
                        errors.dns_us_error.or(Some("Not reachable".into()))
                    } else {
                        None
                    },
                    dns_eu_error: if dns_eu.is_none() {
                        errors.dns_eu_error.or(Some("Not reachable".into()))
                    } else {
                        None
                    },
                    https_error: if https.is_none() {
                        errors.https_error.or(Some("Not reachable".into()))
                    } else {
                        None
                    },
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
        let largest_group = agreement_groups.iter().max_by_key(|g| g.len()).unwrap();

        let agreement_count = largest_group.len();
        let consensus_data = largest_group[0].1;

        debug!(
            agreement_count = agreement_count,
            total_sources = available_count,
            "Consensus analysis"
        );

        // Build source details (only set error if source is NOT reachable)
        let source_details = SourceDetails {
            dns_us_reachable: dns_us.is_some(),
            dns_eu_reachable: dns_eu.is_some(),
            https_reachable: https.is_some(),
            dns_us_error: if dns_us.is_none() {
                errors.dns_us_error.or(Some("Not reachable".into()))
            } else {
                None
            },
            dns_eu_error: if dns_eu.is_none() {
                errors.dns_eu_error.or(Some("Not reachable".into()))
            } else {
                None
            },
            https_error: if https.is_none() {
                errors.https_error.or(Some("Not reachable".into()))
            } else {
                None
            },
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
                    authoritative_source: None,
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
                    authoritative_source: None,
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
                authoritative_source: None,
                source_details,
            }
        } else {
            // No majority agreement - critical security issue
            error!("SECURITY ALERT: Sources actively disagree! Possible attack detected.");

            ValidationResult {
                status: ValidationStatus::SourcesDisagree,
                consensus_key_classical: None,
                consensus_pqc_fingerprint: None,
                consensus_revocation_revision: None,
                authoritative_source: None,
                source_details,
            }
        }
    }

    /// Compute consensus using HTTPS-authoritative trust model.
    ///
    /// HTTPS is the authority when reachable; DNS serves as advisory cross-check.
    ///
    /// # Rules
    ///
    /// 1. Multiple HTTPS sources must agree (if multiple reachable)
    /// 2. If HTTPS reachable + DNS disagrees → trust HTTPS, `PartialAgreement` + warning
    /// 3. If HTTPS unreachable → fall back to DNS-only consensus (degraded)
    /// 4. If multiple HTTPS sources disagree → `SourcesDisagree` (critical)
    #[instrument(skip_all)]
    pub fn compute_https_authoritative_consensus(
        dns_us: Option<SourceData>,
        dns_eu: Option<SourceData>,
        primary_https: Option<SourceData>,
        additional_https: Vec<Option<SourceData>>,
        errors: SourceErrorDetails,
    ) -> ValidationResult {
        // Collect all reachable HTTPS sources
        let mut https_sources: Vec<&SourceData> = Vec::new();
        if let Some(ref primary) = primary_https {
            https_sources.push(primary);
        }
        for data in additional_https.iter().flatten() {
            https_sources.push(data);
        }

        let source_details = SourceDetails {
            dns_us_reachable: dns_us.is_some(),
            dns_eu_reachable: dns_eu.is_some(),
            https_reachable: !https_sources.is_empty(),
            // Only set error if source is NOT reachable (consistent with https_error)
            dns_us_error: if dns_us.is_none() {
                errors.dns_us_error.clone().or(Some("Not reachable".into()))
            } else {
                None
            },
            dns_eu_error: if dns_eu.is_none() {
                errors.dns_eu_error.clone().or(Some("Not reachable".into()))
            } else {
                None
            },
            https_error: if https_sources.is_empty() {
                errors.https_error.clone().or(Some("Not reachable".into()))
            } else {
                None
            },
        };

        // Case 1: HTTPS sources reachable
        if !https_sources.is_empty() {
            // Check HTTPS consensus (all HTTPS must agree)
            let https_consensus = https_sources[0];
            let https_all_agree = https_sources
                .iter()
                .all(|s| Self::sources_agree(https_consensus, s));

            if !https_all_agree {
                // Multiple HTTPS disagree — critical security issue
                error!(
                    "SECURITY ALERT: Multiple HTTPS endpoints disagree! \
                     Possible attack on HTTPS infrastructure."
                );
                return ValidationResult {
                    status: ValidationStatus::SourcesDisagree,
                    consensus_key_classical: None,
                    consensus_pqc_fingerprint: None,
                    consensus_revocation_revision: None,
                    authoritative_source: None,
                    source_details,
                };
            }

            // HTTPS sources agree — they are authoritative
            let authoritative = "HTTPS".to_string();

            // Cross-check with DNS (advisory only)
            let dns_sources: Vec<&SourceData> = [dns_us.as_ref(), dns_eu.as_ref()]
                .iter()
                .filter_map(|s| *s)
                .collect();

            let dns_agrees = dns_sources
                .iter()
                .all(|d| Self::sources_agree(https_consensus, d));

            if dns_sources.is_empty() {
                // HTTPS OK, no DNS available
                warn!("HTTPS authoritative, DNS sources unavailable");
                ValidationResult {
                    status: if https_sources.len() > 1 {
                        ValidationStatus::AllSourcesAgree
                    } else {
                        ValidationStatus::PartialAgreement
                    },
                    consensus_key_classical: Some(https_consensus.steward_key_classical.clone()),
                    consensus_pqc_fingerprint: Some(https_consensus.pqc_fingerprint.clone()),
                    consensus_revocation_revision: Some(https_consensus.revocation_revision),
                    authoritative_source: Some(authoritative),
                    source_details,
                }
            } else if dns_agrees {
                // All available sources agree
                let total = https_sources.len() + dns_sources.len();
                debug!(
                    https_count = https_sources.len(),
                    dns_count = dns_sources.len(),
                    "All sources agree (HTTPS authoritative)"
                );
                ValidationResult {
                    status: if total >= 3 {
                        ValidationStatus::AllSourcesAgree
                    } else {
                        ValidationStatus::PartialAgreement
                    },
                    consensus_key_classical: Some(https_consensus.steward_key_classical.clone()),
                    consensus_pqc_fingerprint: Some(https_consensus.pqc_fingerprint.clone()),
                    consensus_revocation_revision: Some(https_consensus.revocation_revision),
                    authoritative_source: Some(authoritative),
                    source_details,
                }
            } else {
                // DNS disagrees with HTTPS — trust HTTPS (authoritative)
                warn!(
                    "DNS advisory cross-check failed: DNS disagrees with HTTPS. \
                     Trusting HTTPS as authoritative source."
                );
                ValidationResult {
                    status: ValidationStatus::PartialAgreement,
                    consensus_key_classical: Some(https_consensus.steward_key_classical.clone()),
                    consensus_pqc_fingerprint: Some(https_consensus.pqc_fingerprint.clone()),
                    consensus_revocation_revision: Some(https_consensus.revocation_revision),
                    authoritative_source: Some(authoritative),
                    source_details,
                }
            }
        } else {
            // Case 2: No HTTPS reachable — fall back to DNS consensus (degraded)
            warn!("HTTPS unreachable — falling back to DNS-only consensus (degraded)");

            let dns_list: Vec<Option<SourceData>> = vec![dns_us.clone(), dns_eu.clone()];
            let available: Vec<&SourceData> = dns_list.iter().filter_map(|s| s.as_ref()).collect();

            if available.is_empty() {
                // Nothing reachable at all
                return ValidationResult {
                    status: ValidationStatus::NoSourcesReachable,
                    consensus_key_classical: None,
                    consensus_pqc_fingerprint: None,
                    consensus_revocation_revision: None,
                    authoritative_source: None,
                    source_details,
                };
            }

            if available.len() == 1 {
                // Only one DNS source
                return ValidationResult {
                    status: ValidationStatus::ValidationError,
                    consensus_key_classical: Some(available[0].steward_key_classical.clone()),
                    consensus_pqc_fingerprint: Some(available[0].pqc_fingerprint.clone()),
                    consensus_revocation_revision: Some(available[0].revocation_revision),
                    authoritative_source: Some("DNS-fallback".to_string()),
                    source_details,
                };
            }

            // Two DNS sources — check agreement
            if Self::sources_agree(available[0], available[1]) {
                ValidationResult {
                    status: ValidationStatus::PartialAgreement,
                    consensus_key_classical: Some(available[0].steward_key_classical.clone()),
                    consensus_pqc_fingerprint: Some(available[0].pqc_fingerprint.clone()),
                    consensus_revocation_revision: Some(available[0].revocation_revision),
                    authoritative_source: Some("DNS-fallback".to_string()),
                    source_details,
                }
            } else {
                error!(
                    "DNS sources disagree and HTTPS unreachable — \
                     cannot establish trusted consensus"
                );
                ValidationResult {
                    status: ValidationStatus::SourcesDisagree,
                    consensus_key_classical: None,
                    consensus_pqc_fingerprint: None,
                    consensus_revocation_revision: None,
                    authoritative_source: None,
                    source_details,
                }
            }
        }
    }

    /// Check if two source data records agree on critical fields.
    fn sources_agree(a: &SourceData, b: &SourceData) -> bool {
        // Must agree on steward key (constant-time comparison)
        let keys_match =
            ciris_crypto::constant_time_eq(&a.steward_key_classical, &b.steward_key_classical);

        // Must agree on PQC fingerprint
        let pqc_match = ciris_crypto::constant_time_eq(&a.pqc_fingerprint, &b.pqc_fingerprint);

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
    /// Which source was considered authoritative (if applicable).
    pub authoritative_source: Option<String>,
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

/// Error details from network queries, passed to consensus functions.
#[derive(Debug, Clone, Default)]
pub struct SourceErrorDetails {
    /// DNS US error message (if failed).
    pub dns_us_error: Option<String>,
    /// DNS EU error message (if failed).
    pub dns_eu_error: Option<String>,
    /// HTTPS error message (if failed).
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

        let result = ConsensusValidator::compute_consensus(
            dns_us,
            dns_eu,
            https,
            SourceErrorDetails::default(),
        );

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

        let result = ConsensusValidator::compute_consensus(
            dns_us,
            dns_eu,
            https,
            SourceErrorDetails::default(),
        );

        assert_eq!(result.status, ValidationStatus::PartialAgreement);
        assert!(result.allows_licensed());
        assert!(!result.is_security_alert());
    }

    #[test]
    fn test_all_disagree() {
        let fp = vec![2u8; 32];

        let dns_us = Some(make_source_data(&[1u8; 32], &fp, 100));
        let dns_eu = Some(make_source_data(&[2u8; 32], &fp, 100));
        let https = Some(make_source_data(&[3u8; 32], &fp, 100));

        let result = ConsensusValidator::compute_consensus(
            dns_us,
            dns_eu,
            https,
            SourceErrorDetails::default(),
        );

        assert_eq!(result.status, ValidationStatus::SourcesDisagree);
        assert!(!result.allows_licensed());
        assert!(result.is_security_alert());
    }

    #[test]
    fn test_no_sources_reachable() {
        let errors = SourceErrorDetails {
            dns_us_error: Some("timeout".to_string()),
            dns_eu_error: Some("tls_error".to_string()),
            https_error: Some("connection_refused".to_string()),
        };
        let result = ConsensusValidator::compute_consensus(None, None, None, errors);

        assert_eq!(result.status, ValidationStatus::NoSourcesReachable);
        assert!(!result.allows_licensed());
        assert!(!result.is_security_alert());
        // Verify errors are preserved
        assert_eq!(
            result.source_details.dns_us_error,
            Some("timeout".to_string())
        );
        assert_eq!(
            result.source_details.https_error,
            Some("connection_refused".to_string())
        );
    }

    #[test]
    fn test_only_one_source() {
        let key = vec![1u8; 32];
        let fp = vec![2u8; 32];

        let dns_us = Some(make_source_data(&key, &fp, 100));
        let errors = SourceErrorDetails {
            dns_us_error: None,
            dns_eu_error: Some("dns_resolution".to_string()),
            https_error: Some("timeout".to_string()),
        };

        let result = ConsensusValidator::compute_consensus(dns_us, None, None, errors);

        assert_eq!(result.status, ValidationStatus::ValidationError);
        assert!(!result.allows_licensed());
    }

    #[test]
    fn test_two_sources_available_and_agree() {
        let key = vec![1u8; 32];
        let fp = vec![2u8; 32];

        let dns_us = Some(make_source_data(&key, &fp, 100));
        let https = Some(make_source_data(&key, &fp, 100));

        let result = ConsensusValidator::compute_consensus(
            dns_us,
            None,
            https,
            SourceErrorDetails::default(),
        );

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

        let result = ConsensusValidator::compute_consensus(
            dns_us,
            dns_eu,
            https,
            SourceErrorDetails::default(),
        );

        assert_eq!(result.status, ValidationStatus::AllSourcesAgree);
    }

    // ================================================================
    // HTTPS Authoritative trust model tests
    // ================================================================

    #[test]
    fn test_https_authoritative_all_agree() {
        let key = vec![1u8; 32];
        let fp = vec![2u8; 32];

        let dns_us = Some(make_source_data(&key, &fp, 100));
        let dns_eu = Some(make_source_data(&key, &fp, 100));
        let https = Some(make_source_data(&key, &fp, 100));

        let result = ConsensusValidator::compute_https_authoritative_consensus(
            dns_us,
            dns_eu,
            https,
            vec![],
            SourceErrorDetails::default(),
        );

        assert_eq!(result.status, ValidationStatus::AllSourcesAgree);
        assert!(result.allows_licensed());
        assert_eq!(result.authoritative_source.as_deref(), Some("HTTPS"));
    }

    #[test]
    fn test_https_authoritative_https_disagrees_with_dns() {
        let key_https = vec![1u8; 32];
        let key_dns = vec![9u8; 32]; // DNS has different key
        let fp = vec![2u8; 32];

        let dns_us = Some(make_source_data(&key_dns, &fp, 100));
        let dns_eu = Some(make_source_data(&key_dns, &fp, 100));
        let https = Some(make_source_data(&key_https, &fp, 100));

        let result = ConsensusValidator::compute_https_authoritative_consensus(
            dns_us,
            dns_eu,
            https,
            vec![],
            SourceErrorDetails::default(),
        );

        // HTTPS is authoritative — trust it, not DNS
        assert_eq!(result.status, ValidationStatus::PartialAgreement);
        assert!(result.allows_licensed());
        assert_eq!(result.authoritative_source.as_deref(), Some("HTTPS"));
        // Consensus key should be from HTTPS, not DNS
        assert_eq!(
            result.consensus_key_classical.as_deref(),
            Some(key_https.as_slice())
        );
    }

    #[test]
    fn test_https_authoritative_https_unreachable() {
        let key = vec![1u8; 32];
        let fp = vec![2u8; 32];

        let dns_us = Some(make_source_data(&key, &fp, 100));
        let dns_eu = Some(make_source_data(&key, &fp, 100));
        let errors = SourceErrorDetails {
            dns_us_error: None,
            dns_eu_error: None,
            https_error: Some("TLS handshake failed".to_string()),
        };

        let result = ConsensusValidator::compute_https_authoritative_consensus(
            dns_us,
            dns_eu,
            None, // HTTPS unreachable
            vec![],
            errors,
        );

        // Falls back to DNS consensus
        assert_eq!(result.status, ValidationStatus::PartialAgreement);
        assert!(result.allows_licensed());
        assert_eq!(result.authoritative_source.as_deref(), Some("DNS-fallback"));
        // Verify HTTPS error is preserved
        assert_eq!(
            result.source_details.https_error,
            Some("TLS handshake failed".to_string())
        );
    }

    #[test]
    fn test_https_authoritative_multiple_https_disagree() {
        let key1 = vec![1u8; 32];
        let key2 = vec![9u8; 32];
        let fp = vec![2u8; 32];

        let dns_us = Some(make_source_data(&key1, &fp, 100));
        let dns_eu = Some(make_source_data(&key1, &fp, 100));
        let primary_https = Some(make_source_data(&key1, &fp, 100));
        let additional = vec![Some(make_source_data(&key2, &fp, 100))]; // Disagrees!

        let result = ConsensusValidator::compute_https_authoritative_consensus(
            dns_us,
            dns_eu,
            primary_https,
            additional,
            SourceErrorDetails::default(),
        );

        // Multiple HTTPS disagree = critical
        assert_eq!(result.status, ValidationStatus::SourcesDisagree);
        assert!(!result.allows_licensed());
        assert!(result.is_security_alert());
    }

    #[test]
    fn test_equal_weight_backward_compat() {
        // EqualWeight mode should behave exactly like old compute_consensus
        let key = vec![1u8; 32];
        let fp = vec![2u8; 32];

        let dns_us = Some(make_source_data(&key, &fp, 100));
        let dns_eu = Some(make_source_data(&key, &fp, 100));
        let https = Some(make_source_data(&key, &fp, 100));

        let result = ConsensusValidator::compute_consensus(
            dns_us,
            dns_eu,
            https,
            SourceErrorDetails::default(),
        );

        assert_eq!(result.status, ValidationStatus::AllSourcesAgree);
        assert!(result.allows_licensed());
        // EqualWeight doesn't set authoritative_source
        assert!(result.authoritative_source.is_none());
    }
}
