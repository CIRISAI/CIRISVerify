//! Trust-root validation: which GenesisBundle this node trusts (CC 5.3.4).
//!
//! Every configured HTTPS host is asked for its GenesisBundle, each bundle is
//! verified on its own against the accord holders baked into this binary
//! ([`crate::genesis_bundle::verify_genesis_bundle`]), and one is selected by
//! the CC 3.2 T8(ii) rule:
//!
//! 1. a bundle counts only if it verifies;
//! 2. among those, the highest `version` is the successor;
//! 3. two verified bundles at that version with different fingerprints are an
//!    **equivocation**: fail closed and trust neither. `produced_at` breaks no
//!    tie ("an instant selects nothing").
//!
//! A holder-quorum-signed bundle is authoritative on its own, so extra hosts
//! add availability, not trust: one verified source is enough. DNS is not a
//! trust-root source, and there is no single "steward key": the registry key
//! has no standing.

use std::collections::BTreeMap;
use std::time::Duration;

use tracing::{debug, error, info, instrument, warn};

use crate::error::VerifyError;
use crate::genesis_bundle::{verify_genesis_bundle, GenesisBundleError, VerifiedGenesisBundle};
use crate::https::query_trust_root;
use crate::types::ValidationStatus;

/// Fetches and selects the trust root.
pub struct TrustRootValidator {
    endpoints: Vec<String>,
    timeout: Duration,
    cert_pin: Option<String>,
    /// Last reported posture, so an alert fires on a **transition** rather
    /// than once per verification cycle (CIRISVerify#223, CIRIS Logging
    /// Standard #265). `0` = not yet observed.
    last_posture: std::sync::atomic::AtomicU8,
}

/// The posture an alert is keyed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConsensusPosture {
    /// A trust root was selected and every host served it.
    Healthy = 1,
    /// A trust root was selected, but some hosts failed or served another
    /// bundle; or none was selected.
    Degraded = 2,
    /// Two verified bundles at the same version — equivocation.
    Conflict = 3,
}

/// What one host returned.
#[derive(Debug, Clone)]
pub enum SourceOutcome {
    /// The host could not be reached or did not answer usably.
    Unreachable(String),
    /// The host answered, but its bundle did not verify.
    Refused(String),
    /// The host served a bundle that verified.
    Verified(Box<VerifiedGenesisBundle>),
}

/// One host's report, as surfaced to callers.
#[derive(Debug, Clone)]
pub struct SourceReport {
    /// The host's base URL.
    pub endpoint: String,
    /// What it returned.
    pub outcome: SourceOutcome,
}

impl SourceReport {
    /// Did the host answer at all?
    #[must_use]
    pub fn reachable(&self) -> bool {
        !matches!(self.outcome, SourceOutcome::Unreachable(_))
    }

    /// The verified bundle, if any.
    #[must_use]
    pub fn verified(&self) -> Option<&VerifiedGenesisBundle> {
        match &self.outcome {
            SourceOutcome::Verified(b) => Some(b),
            _ => None,
        }
    }

    /// The failure message, if any.
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        match &self.outcome {
            SourceOutcome::Unreachable(e) | SourceOutcome::Refused(e) => Some(e),
            SourceOutcome::Verified(_) => None,
        }
    }
}

/// Result of trust-root validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Overall status.
    pub status: ValidationStatus,
    /// The selected trust root, when one was selected.
    pub trust_root: Option<VerifiedGenesisBundle>,
    /// One report per configured host, in configuration order.
    pub sources: Vec<SourceReport>,
}

impl ValidationResult {
    /// A trust root was selected.
    #[must_use]
    pub fn has_trust_root(&self) -> bool {
        self.trust_root.is_some()
    }

    /// Should this raise a security alert?
    #[must_use]
    pub fn is_security_alert(&self) -> bool {
        matches!(self.status, ValidationStatus::SourcesDisagree)
    }

    /// Degraded or offline?
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        !matches!(self.status, ValidationStatus::AllSourcesAgree)
    }

    /// How many hosts answered.
    #[must_use]
    pub fn reachable_count(&self) -> usize {
        self.sources.iter().filter(|s| s.reachable()).count()
    }

    /// How many hosts served the selected trust root.
    #[must_use]
    pub fn agreeing_count(&self) -> usize {
        let Some(root) = &self.trust_root else {
            return 0;
        };
        self.sources
            .iter()
            .filter(|s| {
                s.verified()
                    .is_some_and(|b| b.bundle_fingerprint == root.bundle_fingerprint)
            })
            .count()
    }
}

impl ValidationResult {
    /// The wire form ([`crate::types::ValidationResults`]): one entry per
    /// host plus the selected root.
    #[must_use]
    pub fn to_validation_results(&self, checked_at: i64) -> crate::types::ValidationResults {
        crate::types::ValidationResults {
            sources: self
                .sources
                .iter()
                .map(|s| {
                    let err = s.error().map(str::to_string);
                    let (error_category, error_details) = categorize_error(&err);
                    crate::types::SourceResult {
                        source: s.endpoint.clone(),
                        reachable: s.reachable(),
                        valid: s.verified().is_some(),
                        checked_at,
                        error: err,
                        error_category,
                        error_details,
                        bundle_fingerprint: s.verified().map(|b| b.bundle_fingerprint.clone()),
                    }
                })
                .collect(),
            overall: self.status,
            trust_root: self
                .trust_root
                .as_ref()
                .map(crate::types::TrustRootSummary::from),
        }
    }
}

/// Categorize and sanitize error messages for client visibility.
///
/// Returns (error_category, error_details) where:
/// - error_category: Short category like "timeout", "dns_resolution", "tls_error"
/// - error_details: Sanitized message suitable for client display
pub fn categorize_error(error: &Option<String>) -> (Option<String>, Option<String>) {
    let Some(err) = error else {
        return (None, None);
    };

    let err_lower = err.to_lowercase();

    // Categorize based on error message content
    let category = if err_lower.contains("timeout") || err_lower.contains("timed out") {
        "timeout"
    } else if err_lower.contains("dns")
        || err_lower.contains("resolve")
        || err_lower.contains("no such host")
    {
        "dns_resolution"
    } else if err_lower.contains("tls")
        || err_lower.contains("ssl")
        || err_lower.contains("certificate")
    {
        "tls_error"
    } else if err_lower.contains("connection refused") || err_lower.contains("connrefused") {
        "connection_refused"
    } else if err_lower.contains("connection reset") || err_lower.contains("connreset") {
        "connection_reset"
    } else if err_lower.contains("network") || err_lower.contains("unreachable") {
        "network_unreachable"
    } else if err_lower.contains("404") || err_lower.contains("not found") {
        "not_found"
    } else if err_lower.contains("401")
        || err_lower.contains("403")
        || err_lower.contains("unauthorized")
        || err_lower.contains("forbidden")
    {
        "auth_error"
    } else if err_lower.contains("500")
        || err_lower.contains("502")
        || err_lower.contains("503")
        || err_lower.contains("504")
    {
        "server_error"
    } else {
        "unknown"
    };

    // Sanitize details - remove potential sensitive info but keep diagnostic value
    let details = if err.chars().count() > 200 {
        format!("{}...", err.chars().take(200).collect::<String>())
    } else {
        err.clone()
    };

    (Some(category.to_string()), Some(details))
}

/// Build one host's report from what a caller's own fetch returned: `Err` is
/// the host being unreachable, `Ok` is the trust-root RESPONSE body (wrapper
/// included). For callers that cannot use [`TrustRootValidator`]'s async fetch
/// (the mobile blocking paths); verification and selection are the same.
#[must_use]
pub fn source_report_from_response(
    endpoint: String,
    fetched: Result<serde_json::Value, String>,
) -> SourceReport {
    let outcome = match fetched {
        Err(e) => SourceOutcome::Unreachable(e),
        Ok(body) => match crate::https::bundle_from_response(&endpoint, body) {
            Ok(bundle) => outcome_of_bundle(&bundle),
            Err(e) => SourceOutcome::Refused(e.to_string()),
        },
    };
    SourceReport { endpoint, outcome }
}

impl TrustRootValidator {
    /// A validator over `endpoints` (base URLs, queried in parallel).
    #[must_use]
    pub fn new(endpoints: Vec<String>, timeout: Duration, cert_pin: Option<String>) -> Self {
        Self {
            endpoints,
            timeout,
            cert_pin,
            last_posture: std::sync::atomic::AtomicU8::new(0),
        }
    }

    /// The configured hosts.
    #[must_use]
    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    /// Fetch every host's bundle, verify each, and select the trust root.
    #[instrument(skip(self))]
    pub async fn validate_trust_root(&self) -> ValidationResult {
        let fetches = self.endpoints.iter().map(|ep| {
            let ep = ep.clone();
            let timeout = self.timeout;
            let pin = self.cert_pin.clone();
            async move {
                let fetched =
                    tokio::time::timeout(timeout, query_trust_root(&ep, timeout, pin.as_deref()))
                        .await;
                let outcome = match fetched {
                    Err(_) => SourceOutcome::Unreachable("timeout".to_string()),
                    Ok(Err(e)) => outcome_of_fetch_error(e),
                    Ok(Ok(bundle)) => outcome_of_bundle(&bundle),
                };
                SourceReport {
                    endpoint: ep,
                    outcome,
                }
            }
        });
        let sources = futures::future::join_all(fetches).await;
        let result = select_trust_root(sources);
        self.report_posture(&result);
        result
    }

    fn report_posture(&self, result: &ValidationResult) -> bool {
        use std::sync::atomic::Ordering;
        let posture = match result.status {
            ValidationStatus::SourcesDisagree => ConsensusPosture::Conflict,
            ValidationStatus::AllSourcesAgree => ConsensusPosture::Healthy,
            _ => ConsensusPosture::Degraded,
        };
        let prev = self.last_posture.swap(posture as u8, Ordering::Relaxed);
        if prev == posture as u8 {
            debug!(?posture, status = ?result.status, "trust-root posture unchanged");
            return false;
        }
        let root = result
            .trust_root
            .as_ref()
            .map(|r| r.bundle_fingerprint.as_str())
            .unwrap_or("none");
        match posture {
            ConsensusPosture::Conflict => error!(
                status = ?result.status,
                "SECURITY ALERT: trust-root hosts serve two different verified bundles at the \
                 same version (equivocation) — trusting neither"
            ),
            ConsensusPosture::Degraded => warn!(
                status = ?result.status,
                reachable = result.reachable_count(),
                configured = result.sources.len(),
                trust_root = root,
                "trust-root validation degraded"
            ),
            ConsensusPosture::Healthy => info!(
                trust_root = root,
                sources = result.sources.len(),
                "trust-root validation healthy"
            ),
        }
        true
    }
}

fn outcome_of_fetch_error(e: VerifyError) -> SourceOutcome {
    match e {
        // The host answered with something that is not a trust-root response.
        VerifyError::ResponseSchemaMismatch { .. } => SourceOutcome::Refused(e.to_string()),
        other => SourceOutcome::Unreachable(other.to_string()),
    }
}

fn outcome_of_bundle(bundle: &serde_json::Value) -> SourceOutcome {
    match verify_genesis_bundle(bundle) {
        Ok(v) => SourceOutcome::Verified(Box::new(v)),
        Err(e @ GenesisBundleError::NoBakedRoster) => {
            // A build without the baked genesis can verify nothing. Not the
            // host's fault, but still no trust root.
            SourceOutcome::Refused(e.to_string())
        },
        Err(e) => SourceOutcome::Refused(e.to_string()),
    }
}

/// CC's selection rule over the hosts' reports (pure; see the module docs).
#[must_use]
pub fn select_trust_root(sources: Vec<SourceReport>) -> ValidationResult {
    let verified: Vec<&VerifiedGenesisBundle> =
        sources.iter().filter_map(|s| s.verified()).collect();
    let reachable = sources.iter().filter(|s| s.reachable()).count();

    let Some(top_version) = verified.iter().map(|b| b.version).max() else {
        let status = if reachable == 0 {
            ValidationStatus::NoSourcesReachable
        } else {
            ValidationStatus::ValidationError
        };
        return ValidationResult {
            status,
            trust_root: None,
            sources,
        };
    };

    let mut at_top: BTreeMap<&str, &VerifiedGenesisBundle> = BTreeMap::new();
    for b in verified.iter().filter(|b| b.version == top_version) {
        at_top.insert(b.bundle_fingerprint.as_str(), b);
    }
    if at_top.len() > 1 {
        return ValidationResult {
            status: ValidationStatus::SourcesDisagree,
            trust_root: None,
            sources,
        };
    }
    let root = (*at_top.values().next().expect("non-empty")).clone();
    let every_host_served_it = sources.iter().all(|s| {
        s.verified()
            .is_some_and(|b| b.bundle_fingerprint == root.bundle_fingerprint)
    });
    ValidationResult {
        status: if every_host_served_it {
            ValidationStatus::AllSourcesAgree
        } else {
            ValidationStatus::PartialAgreement
        },
        trust_root: Some(root),
        sources,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis_bundle::verify_genesis_bundle;

    const V4: &str = include_str!("../tests/vectors/genesis_bundle/v4_persist_v59_1_0.json");

    fn root() -> VerifiedGenesisBundle {
        verify_genesis_bundle(&serde_json::from_str(V4).unwrap()).unwrap()
    }

    fn with(version: u32, fp: &str) -> VerifiedGenesisBundle {
        let mut b = root();
        b.version = version;
        b.bundle_fingerprint = fp.to_string();
        b
    }

    fn verified(ep: &str, b: VerifiedGenesisBundle) -> SourceReport {
        SourceReport {
            endpoint: ep.into(),
            outcome: SourceOutcome::Verified(Box::new(b)),
        }
    }

    fn down(ep: &str) -> SourceReport {
        SourceReport {
            endpoint: ep.into(),
            outcome: SourceOutcome::Unreachable("timeout".into()),
        }
    }

    fn refused(ep: &str) -> SourceReport {
        SourceReport {
            endpoint: ep.into(),
            outcome: SourceOutcome::Refused("quorum not met".into()),
        }
    }

    #[test]
    fn every_host_serving_one_verified_bundle_agrees() {
        let r = select_trust_root(vec![
            verified("a", root()),
            verified("b", root()),
            verified("c", root()),
        ]);
        assert_eq!(r.status, ValidationStatus::AllSourcesAgree);
        assert_eq!(r.agreeing_count(), 3);
    }

    /// A holder-quorum bundle is authoritative on its own: one host is enough.
    #[test]
    fn one_verified_host_is_enough() {
        let r = select_trust_root(vec![verified("a", root()), down("b"), refused("c")]);
        assert_eq!(r.status, ValidationStatus::PartialAgreement);
        assert!(r.has_trust_root());
    }

    #[test]
    fn the_higher_version_is_the_successor_not_a_conflict() {
        let r = select_trust_root(vec![
            verified("a", with(4, "sha256:old")),
            verified("b", with(5, "sha256:new")),
        ]);
        assert_eq!(r.status, ValidationStatus::PartialAgreement);
        assert_eq!(r.trust_root.unwrap().bundle_fingerprint, "sha256:new");
    }

    /// CC 3.2 T8(ii): equal version, different fingerprint is equivocation,
    /// and nothing — least of all `produced_at` — breaks the tie.
    #[test]
    fn equal_version_different_fingerprint_is_equivocation() {
        let mut later = with(4, "sha256:b");
        later.produced_at = "2099-01-01T00:00:00Z".into();
        let r = select_trust_root(vec![
            verified("a", with(4, "sha256:a")),
            verified("b", later),
        ]);
        assert_eq!(r.status, ValidationStatus::SourcesDisagree);
        assert!(r.trust_root.is_none());
        assert!(r.is_security_alert());
    }

    #[test]
    fn nothing_verified_is_an_error_when_hosts_answered_and_offline_when_not() {
        assert_eq!(
            select_trust_root(vec![refused("a"), down("b")]).status,
            ValidationStatus::ValidationError
        );
        assert_eq!(
            select_trust_root(vec![down("a"), down("b")]).status,
            ValidationStatus::NoSourcesReachable
        );
    }

    #[test]
    fn a_tampered_bundle_from_one_host_does_not_unseat_the_root() {
        let mut bad: serde_json::Value = serde_json::from_str(V4).unwrap();
        bad["produced_at"] = "2026-10-05T00:00:00Z".into();
        let r = select_trust_root(vec![
            verified("a", root()),
            SourceReport {
                endpoint: "b".into(),
                outcome: outcome_of_bundle(&bad),
            },
        ]);
        assert_eq!(r.status, ValidationStatus::PartialAgreement);
        assert!(matches!(r.sources[1].outcome, SourceOutcome::Refused(_)));
    }

    #[test]
    fn posture_is_reported_on_transitions_not_every_cycle() {
        let v = TrustRootValidator::new(vec![], Duration::from_secs(1), None);
        let healthy = select_trust_root(vec![verified("a", root())]);
        assert!(v.report_posture(&healthy));
        for _ in 0..50 {
            assert!(!v.report_posture(&healthy));
        }
        let down_r = select_trust_root(vec![down("a")]);
        assert!(v.report_posture(&down_r));
        assert!(v.report_posture(&healthy));
    }
}
