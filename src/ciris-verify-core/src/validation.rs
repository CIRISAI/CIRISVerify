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
    /// Last reported consensus posture, so an alert fires on a **transition**
    /// rather than once per verification cycle (CIRISVerify#223).
    ///
    /// An `AtomicU8` because this is read and set on the hot verification path
    /// from whatever thread the caller drives, and it needs no allocation, no
    /// clock and no lock. `0` = not yet observed; otherwise a
    /// [`ConsensusPosture`] discriminant.
    last_posture: std::sync::atomic::AtomicU8,
}

/// The consensus posture an alert is keyed on (CIRISVerify#223).
///
/// Only a **change** in posture is worth the operator's attention: the CIRIS
/// Logging Standard (#265) asks for one event per actual failure, and the
/// incident that motivated it was a user losing a day to 3,810 log lines in
/// which the real fault appeared 13 times and was unfindable. A per-cycle
/// re-assertion of a condition the operator already knows about is the same
/// defect at a different scale — 196 identical ERRORs in 4h (CIRISAgent#936).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConsensusPosture {
    /// Sources agree, or differ only by replication lag.
    Healthy = 1,
    /// Fewer sources than configured were reachable.
    Degraded = 2,
    /// Sources conflict at the same revision — attack-shaped.
    Conflict = 3,
}

impl ConsensusPosture {
    const fn as_u8(self) -> u8 {
        self as u8
    }
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
            last_posture: std::sync::atomic::AtomicU8::new(0),
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
            last_posture: std::sync::atomic::AtomicU8::new(0),
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

        let result = match self.trust_model {
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
        };

        // The one operator-facing consensus event, emitted on a TRANSITION only
        // (CIRISVerify#223). `compute_consensus` stays a pure function — ten
        // tests call it directly and its purity is worth keeping — so the state
        // this needs lives here, on the validator, where the lifecycle is.
        let posture = match result.status {
            ValidationStatus::AllSourcesAgree => ConsensusPosture::Healthy,
            ValidationStatus::SourcesDisagree => ConsensusPosture::Conflict,
            ValidationStatus::PartialAgreement
            | ValidationStatus::NoSourcesReachable
            | ValidationStatus::ValidationError => ConsensusPosture::Degraded,
        };
        self.report_posture(posture, &format!("{:?}", result.status));
        result
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
                consensus_key_pqc: None,
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
                consensus_key_pqc: data.steward_key_pqc.clone(),
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
        // The FRESHEST member of the group, not the first one iteration happened
        // to reach (CIRISVerify#223). Now that a lagging replica counts as
        // non-conflicting, `largest_group[0]` could be the stale source — and
        // adopting its key as consensus would turn a tolerated lag into a
        // silently out-of-date trust root. Every pairwise difference inside the
        // group is pure lag, so the highest revision is the group's truth.
        let consensus_data = largest_group
            .iter()
            .max_by_key(|(_, d)| d.revocation_revision)
            .map_or(largest_group[0].1, |(_, d)| *d);

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
                debug!("All 3 sources agree (or differ only by replication lag)");
                ValidationResult {
                    status: ValidationStatus::AllSourcesAgree,
                    consensus_key_classical: Some(consensus_data.steward_key_classical.clone()),
                    consensus_key_pqc: consensus_data.steward_key_pqc.clone(),
                    consensus_pqc_fingerprint: Some(consensus_data.pqc_fingerprint.clone()),
                    consensus_revocation_revision: Some(consensus_data.revocation_revision),
                    authoritative_source: None,
                    source_details,
                }
            } else {
                // 2 sources available and agree
                debug!("only 2 sources reachable; they do not conflict");
                ValidationResult {
                    status: ValidationStatus::PartialAgreement,
                    consensus_key_classical: Some(consensus_data.steward_key_classical.clone()),
                    consensus_key_pqc: consensus_data.steward_key_pqc.clone(),
                    consensus_pqc_fingerprint: Some(consensus_data.pqc_fingerprint.clone()),
                    consensus_revocation_revision: Some(consensus_data.revocation_revision),
                    authoritative_source: None,
                    source_details,
                }
            }
        } else if agreement_count >= 2 {
            // 2 of 3 agree; one differs. Say HOW it differs (CIRISVerify#223) —
            // a lagging replica reaching this branch is benign, and reporting it
            // as "possible attack" is what buried the real signal.
            let outliers: Vec<String> = available
                .iter()
                .filter_map(
                    |(name, data)| match Self::compare_sources(consensus_data, data) {
                        SourceDivergence::Agree => None,
                        d @ SourceDivergence::ReplicaLag { behind_by, .. } => Some(format!(
                            "{name}={} (behind_by={behind_by}, rev={})",
                            d.label(),
                            data.revocation_revision
                        )),
                        d @ SourceDivergence::Conflict => Some(format!(
                            "{name}={} (rev={})",
                            d.label(),
                            data.revocation_revision
                        )),
                    },
                )
                .collect();
            let any_conflict = available
                .iter()
                .any(|(_, data)| Self::compare_sources(consensus_data, data).is_conflict());
            let detail = format!(
                "{agreement_count}/{available_count} agree; outliers: [{}]",
                outliers.join(", ")
            );
            // Detail at DEBUG every cycle (cheap, and there when you go
            // looking); the operator-facing event is emitted once per
            // transition by `validate_steward_key` (#265 / CIRISVerify#223).
            debug!(conflict = any_conflict, detail = %detail, "partial agreement");

            ValidationResult {
                status: ValidationStatus::PartialAgreement,
                consensus_key_classical: Some(consensus_data.steward_key_classical.clone()),
                consensus_key_pqc: consensus_data.steward_key_pqc.clone(),
                consensus_pqc_fingerprint: Some(consensus_data.pqc_fingerprint.clone()),
                consensus_revocation_revision: Some(consensus_data.revocation_revision),
                authoritative_source: None,
                source_details,
            }
        } else {
            // No majority. Classify before alerting (CIRISVerify#223): with no
            // majority this is serious either way and the status still degrades
            // fail-secure, but an operator needs to know whether they are
            // looking at an attack or at a fleet that is simply out of step.
            let pairs: Vec<String> = available
                .iter()
                .map(|(name, data)| {
                    format!(
                        "{name}(rev={}, {})",
                        data.revocation_revision,
                        Self::compare_sources(consensus_data, data).label()
                    )
                })
                .collect();
            let any_conflict = available
                .iter()
                .any(|(_, data)| Self::compare_sources(consensus_data, data).is_conflict());
            let detail = format!("no majority among [{}]", pairs.join(", "));
            debug!(conflict = any_conflict, detail = %detail, "no majority");

            ValidationResult {
                status: ValidationStatus::SourcesDisagree,
                consensus_key_classical: None,
                consensus_key_pqc: None,
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
                    consensus_key_pqc: None,
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
                    consensus_key_pqc: https_consensus.steward_key_pqc.clone(),
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
                    consensus_key_pqc: https_consensus.steward_key_pqc.clone(),
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
                    consensus_key_pqc: https_consensus.steward_key_pqc.clone(),
                    consensus_pqc_fingerprint: Some(https_consensus.pqc_fingerprint.clone()),
                    consensus_revocation_revision: Some(https_consensus.revocation_revision),
                    authoritative_source: Some(authoritative),
                    source_details,
                }
            }
        } else {
            // Case 2: No usable HTTPS answer — fall back to DNS (degraded).
            //
            // "No usable answer" is NOT the same as "unreachable": a server
            // that answers 200 with a drifted schema lands here too, and
            // calling that unreachable sends an operator to check firewalls
            // and TLS while the endpoint is healthy. The per-source error
            // (see VerifyError::ResponseSchemaMismatch) carries the real
            // cause; this message must not overwrite it with a guess.
            warn!(
                "No usable HTTPS answer — falling back to DNS-only consensus (degraded). \
                 Check the per-source error above for the cause: unreachable and \
                 schema-mismatch are different faults."
            );

            let dns_list: Vec<Option<SourceData>> = vec![dns_us.clone(), dns_eu.clone()];
            let available: Vec<&SourceData> = dns_list.iter().filter_map(|s| s.as_ref()).collect();

            if available.is_empty() {
                // Nothing reachable at all
                return ValidationResult {
                    status: ValidationStatus::NoSourcesReachable,
                    consensus_key_classical: None,
                    consensus_key_pqc: None,
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
                    consensus_key_pqc: available[0].steward_key_pqc.clone(),
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
                    consensus_key_pqc: available[0].steward_key_pqc.clone(),
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
                    consensus_key_pqc: None,
                    consensus_pqc_fingerprint: None,
                    consensus_revocation_revision: None,
                    authoritative_source: None,
                    source_details,
                }
            }
        }
    }

    /// Check if two source data records agree on critical fields.
    /// Report a consensus posture, emitting at ERROR/WARN **only on a
    /// transition** and at DEBUG while the posture is unchanged
    /// (CIRISVerify#223).
    ///
    /// Returns `true` if this call was the transition — so a caller can attach
    /// the expensive detail (which source, which revision) to the one event that
    /// an operator will actually read, and leave the steady state cheap.
    ///
    /// Recovery is reported too: a drop back to `Healthy` is exactly the line
    /// that tells an operator the incident is over, and it was missing entirely.
    fn report_posture(&self, posture: ConsensusPosture, detail: &str) -> bool {
        use std::sync::atomic::Ordering;
        let prev = self.last_posture.swap(posture.as_u8(), Ordering::Relaxed);
        let changed = prev != posture.as_u8();
        if !changed {
            debug!(
                posture = ?posture,
                detail = detail,
                "consensus posture unchanged"
            );
            return false;
        }
        match posture {
            ConsensusPosture::Conflict => error!(
                posture = ?posture,
                detail = detail,
                "SECURITY ALERT: validation sources CONFLICT at the same revision — \
                 not explainable by replication lag. This is reported once per \
                 transition, not per cycle (CIRISVerify#223)."
            ),
            ConsensusPosture::Degraded => warn!(
                posture = ?posture,
                detail = detail,
                "consensus degraded — fewer sources reachable than configured"
            ),
            ConsensusPosture::Healthy => {
                if prev == 0 {
                    debug!(detail = detail, "consensus healthy");
                } else {
                    info!(
                        detail = detail,
                        "consensus RECOVERED — sources agree (or differ only by \
                         replication lag)"
                    );
                }
            },
        }
        changed
    }

    /// Do these two sources fail to *conflict*? (CIRISVerify#223)
    ///
    /// Deliberately not "are they identical": a [`SourceDivergence::ReplicaLag`]
    /// is not disagreement at **any** depth, which replaces the old `±1`
    /// revision cliff. That cliff was arbitrary — a 2-revision lag escalated to
    /// `possible attack` while a 1-revision lag did not — and it is what
    /// produced 196 benign ERRORs in 4h (CIRISAgent#936).
    ///
    /// Safety note: this admits a *lagging* source into the agreement group, so
    /// the group's representative MUST be chosen by highest revision (see the
    /// `consensus_data` selection) or a stale key could become consensus.
    fn sources_agree(a: &SourceData, b: &SourceData) -> bool {
        !Self::compare_sources(a, b).is_conflict()
    }

    /// **Why** two sources differ, when they do (CIRISVerify#223).
    ///
    /// The old predicate returned a bare `bool` with a `±1` revision fudge, so a
    /// **lagging replica** and **two sources presenting different keys at the
    /// same revision** both collapsed to "disagree" — and the second is
    /// attack-shaped while the first is how replication works. In production
    /// that produced 196 identical `SECURITY ALERT: Sources disagree - possible
    /// attack` ERRORs in ~4h on one agent (CIRISAgent#936), every one of them
    /// benign propagation.
    ///
    /// The split follows `MISSION.md` §1.4, exactly as v13.3.0 split
    /// `Determination::{Authoritative, Indeterminate}` for revocation: report
    /// what was **measured**, and do not manufacture a verdict the measurement
    /// cannot support.
    ///
    /// - **Equal revision, different key material → [`SourceDivergence::Conflict`].**
    ///   At one point in a monotonic log there is one truth. Two sources
    ///   asserting different keys *for the same revision* cannot both be
    ///   honest, and no amount of propagation delay explains it.
    /// - **Different revision → [`SourceDivergence::ReplicaLag`], whether or not
    ///   the keys match.** Across a rotation a behind replica legitimately
    ///   serves the *previous* key, so differing keys at differing revisions is
    ///   the expected shape of propagation, not evidence of an attack.
    ///
    /// `ReplicaLag` is a **measurement, not an absolution**: a lagging source
    /// does not contribute its (possibly stale) key to consensus — it simply
    /// stops being counted as disagreement. Rollback *over time* is a different
    /// control and remains enforced by the anti-rollback revision check.
    fn compare_sources(a: &SourceData, b: &SourceData) -> SourceDivergence {
        let keys_match =
            ciris_crypto::constant_time_eq(&a.steward_key_classical, &b.steward_key_classical);
        let pqc_match = ciris_crypto::constant_time_eq(&a.pqc_fingerprint, &b.pqc_fingerprint);
        let material_match = keys_match && pqc_match;

        match a.revocation_revision.cmp(&b.revocation_revision) {
            std::cmp::Ordering::Equal => {
                if material_match {
                    SourceDivergence::Agree
                } else {
                    SourceDivergence::Conflict
                }
            },
            // Ordered by revision, so "behind" is well defined and signed.
            std::cmp::Ordering::Less => SourceDivergence::ReplicaLag {
                behind_by: b.revocation_revision - a.revocation_revision,
                material_match,
            },
            std::cmp::Ordering::Greater => SourceDivergence::ReplicaLag {
                behind_by: a.revocation_revision - b.revocation_revision,
                material_match,
            },
        }
    }
}

/// Why two validation sources differ (CIRISVerify#223).
///
/// A lagging replica and a same-revision key conflict are different facts, and
/// only one of them is attack-shaped. The rule:
///
/// - **equal revision, different key material → [`Self::Conflict`]** — at one
///   point in a monotonic log there is one truth, and no propagation delay
///   explains two sources asserting different keys for the same revision;
/// - **different revision → [`Self::ReplicaLag`]**, whether or not the keys
///   match, because across a rotation a behind replica legitimately serves the
///   *previous* key.
///
/// `ReplicaLag` is a measurement, not an absolution: a lagging source stops
/// counting as disagreement, but its (possibly stale) key is not adopted as
/// consensus — the freshest member of an agreeing group supplies that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceDivergence {
    /// Same revision, same key material.
    Agree,
    /// The sources sit at different points in a monotonic log. Benign
    /// propagation unless something else says otherwise.
    ReplicaLag {
        /// How many revisions apart they are (unsigned; the caller knows which
        /// side it asked about).
        behind_by: u64,
        /// Whether the key material matched anyway. `false` across a rotation
        /// is expected — the behind replica still serves the previous key.
        material_match: bool,
    },
    /// **Same revision, different key material.** No propagation delay explains
    /// this: at one revision there is one truth.
    Conflict,
}

impl SourceDivergence {
    /// Is this the attack-shaped case — the one worth an alert?
    #[must_use]
    pub const fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict)
    }

    /// A short, stable label for logs and for the consumer-visible posture.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Agree => "agree",
            Self::ReplicaLag { .. } => "replica_lag",
            Self::Conflict => "conflict",
        }
    }
}

/// Data from a validation source, normalized for comparison.
#[derive(Debug, Clone)]
pub struct SourceData {
    /// Classical steward key (raw bytes).
    pub steward_key_classical: Vec<u8>,
    /// Full PQC steward public key (raw bytes, when the source provides it).
    ///
    /// DNS sources only publish a fingerprint, so this is `None` for DNS.
    /// HTTPS sources carry the full key, enabling full hybrid license
    /// verification. The full key is always cross-checked against
    /// `pqc_fingerprint` before use (see the engine's license verifier).
    pub steward_key_pqc: Option<Vec<u8>>,
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
            // DNS publishes only the fingerprint, never the full PQC key.
            steward_key_pqc: None,
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

        // Decode the full PQC public key (HTTPS carries it; DNS does not).
        // Used for hybrid license verification; always cross-checked against
        // the fingerprint before trust is placed in it.
        let steward_key_pqc = base64::engine::general_purpose::STANDARD
            .decode(&response.pqc.key)
            .ok()
            .filter(|k| !k.is_empty());

        // Decode the PQC fingerprint
        let pqc_fp_hex = response
            .pqc
            .fingerprint
            .strip_prefix("sha256:")
            .unwrap_or(&response.pqc.fingerprint);
        let pqc_fingerprint = hex::decode(pqc_fp_hex).unwrap_or_default();

        Self {
            steward_key_classical,
            steward_key_pqc,
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
    /// Consensus full PQC steward public key (if a source provided it).
    ///
    /// Only HTTPS sources carry the full key. `None` when consensus rests on
    /// DNS-only sources (which publish just the fingerprint) — in that case
    /// hybrid license verification falls back to classical-only gating.
    pub consensus_key_pqc: Option<Vec<u8>>,
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
            steward_key_pqc: None,
            pqc_fingerprint: fingerprint.to_vec(),
            revocation_revision: revision,
            timestamp: 1737763200,
        }
    }

    /// CIRISVerify#223: a **lagging replica** is not an attack, at any depth.
    ///
    /// The old rule was `keys match AND |Δrev| ≤ 1`, so a 2-revision lag
    /// escalated to `SourcesDisagree` → *"possible attack"* while a 1-revision
    /// lag did not. That arbitrary cliff produced 196 identical ERRORs in ~4h on
    /// one production agent (CIRISAgent#936), every one benign propagation.
    #[test]
    fn a_lagging_replica_is_not_a_disagreement_at_any_depth() {
        let key = vec![1u8; 32];
        let fp = vec![2u8; 32];

        const HEAD: u64 = 1_000;
        for behind in [1u64, 2, 7, 500] {
            let result = ConsensusValidator::compute_consensus(
                Some(make_source_data(&key, &fp, HEAD)),
                Some(make_source_data(&key, &fp, HEAD - behind)),
                Some(make_source_data(&key, &fp, HEAD)),
                SourceErrorDetails::default(),
            );
            assert!(
                !result.is_security_alert(),
                "a replica {behind} revisions behind must not read as an attack"
            );
            assert_eq!(
                result.status,
                ValidationStatus::AllSourcesAgree,
                "lag is not disagreement (behind_by={behind})"
            );
        }
    }

    /// The safety property that makes the above admissible: a lagging source is
    /// tolerated but its **stale key is never adopted as consensus**.
    ///
    /// `consensus_data` used to be `largest_group[0]` — whichever source
    /// iteration reached first — so once lag counts as non-conflicting, the
    /// stale source could have supplied the trust root. The group's
    /// representative is now its highest revision.
    #[test]
    fn a_tolerated_lag_never_supplies_the_consensus_key() {
        let old_key = vec![7u8; 32];
        let new_key = vec![1u8; 32];
        let fp_old = vec![8u8; 32];
        let fp_new = vec![2u8; 32];

        // dns_us is BEHIND and still serving the pre-rotation key — the first
        // source in iteration order, which is exactly the trap.
        let result = ConsensusValidator::compute_consensus(
            Some(make_source_data(&old_key, &fp_old, 99)),
            Some(make_source_data(&new_key, &fp_new, 100)),
            Some(make_source_data(&new_key, &fp_new, 100)),
            SourceErrorDetails::default(),
        );

        assert_eq!(
            result.consensus_key_classical.as_deref(),
            Some(new_key.as_slice()),
            "consensus must take the FRESHEST member of the group, never the stale one"
        );
        assert_eq!(result.consensus_revocation_revision, Some(100));
        assert!(
            !result.is_security_alert(),
            "a rotation-lag is not an attack"
        );
    }

    /// The case that IS attack-shaped and must still alert: two sources
    /// asserting different key material **at the same revision**. No
    /// propagation delay explains it — at one point in a monotonic log there is
    /// one truth.
    #[test]
    fn different_keys_at_the_same_revision_is_still_a_conflict() {
        let fp = vec![2u8; 32];
        let a = make_source_data(&[1u8; 32], &fp, 100);
        let b = make_source_data(&[9u8; 32], &fp, 100);

        assert_eq!(
            ConsensusValidator::compare_sources(&a, &b),
            SourceDivergence::Conflict
        );
        assert!(ConsensusValidator::compare_sources(&a, &b).is_conflict());
        // ...and the same material one revision apart is NOT a conflict.
        let c = make_source_data(&[9u8; 32], &fp, 99);
        assert!(!ConsensusValidator::compare_sources(&a, &c).is_conflict());
    }

    /// The posture reporter fires on a **transition** and stays quiet while the
    /// posture holds — the whole point of #223's second ask. Recovery is
    /// reported too, which was missing entirely.
    #[test]
    fn posture_is_reported_on_transitions_not_every_cycle() {
        let v = ConsensusValidator::new(
            "us".into(),
            "eu".into(),
            "https://example.invalid".into(),
            Duration::from_secs(1),
            None,
        );

        assert!(
            v.report_posture(ConsensusPosture::Healthy, "first observation"),
            "the first observation is a transition"
        );
        assert!(!v.report_posture(ConsensusPosture::Healthy, "same"));
        assert!(!v.report_posture(ConsensusPosture::Healthy, "same again"));
        assert!(
            v.report_posture(ConsensusPosture::Conflict, "went bad"),
            "healthy -> conflict is a transition"
        );
        for _ in 0..50 {
            assert!(
                !v.report_posture(ConsensusPosture::Conflict, "still bad"),
                "a held conflict must not re-alert once per cycle — this is the \
                 196-ERRORs-in-4h defect"
            );
        }
        assert!(
            v.report_posture(ConsensusPosture::Healthy, "recovered"),
            "conflict -> healthy is a transition, and the operator needs it"
        );
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
