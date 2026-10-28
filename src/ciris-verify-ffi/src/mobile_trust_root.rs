//! Blocking trust-root validation for the iOS and Android sync paths
//! (CC 5.3.4).
//!
//! Those paths cannot run tokio, so they fetch with `ureq` on plain threads.
//! Everything after the fetch is the core's: each host's response is turned
//! into a report by [`source_report_from_response`] (which verifies the
//! GenesisBundle against the baked accord holders) and the root is chosen by
//! [`select_trust_root`], exactly as on desktop. This replaces the two copies
//! of the retired DNS + steward-key check these paths used to carry.

use std::time::Duration;

use ciris_verify_core::config::VerifyConfig;
use ciris_verify_core::https::{STEWARD_KEY_ALIAS_PATH, TRUST_ROOT_BUNDLE_PATH};
use ciris_verify_core::validation::{
    select_trust_root, source_report_from_response, SourceOutcome, SourceReport, ValidationResult,
};
use tracing::{info, warn};

/// Fetch one host's trust-root response: the primary path, then the registry
/// alias when the primary is not routed (404).
fn fetch(agent: &ureq::Agent, base_url: &str) -> Result<serde_json::Value, String> {
    for path in [TRUST_ROOT_BUNDLE_PATH, STEWARD_KEY_ALIAS_PATH] {
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        match agent.get(&url).call() {
            Ok(resp) => {
                return resp
                    .into_json::<serde_json::Value>()
                    .map_err(|e| format!("{url}: response is not JSON: {e}"));
            },
            Err(ureq::Error::Status(404, _)) => continue,
            Err(e) => return Err(format!("{url}: {e}")),
        }
    }
    Err(format!(
        "{base_url} serves neither {TRUST_ROOT_BUNDLE_PATH} nor {STEWARD_KEY_ALIAS_PATH}"
    ))
}

/// Query every configured trust-root host in parallel and select the root.
/// `make_agent` builds a fresh agent per thread (ureq agents are built per
/// platform by the caller).
pub(crate) fn validate_trust_root_blocking(
    timeout: Duration,
    make_agent: fn(Duration) -> ureq::Agent,
    tag: &'static str,
) -> ValidationResult {
    let hosts = VerifyConfig::default().trust_root_endpoints();
    let handles: Vec<_> = hosts
        .iter()
        .cloned()
        .map(|host| {
            std::thread::spawn(move || {
                let agent = make_agent(timeout);
                let fetched = fetch(&agent, &host);
                source_report_from_response(host, fetched)
            })
        })
        .collect();
    let reports: Vec<SourceReport> = handles
        .into_iter()
        .zip(hosts)
        .map(|(h, host)| {
            h.join().unwrap_or_else(|_| {
                warn!("{tag}: trust-root fetch thread panicked for {host}");
                SourceReport {
                    endpoint: host,
                    outcome: SourceOutcome::Unreachable("thread panic".to_string()),
                }
            })
        })
        .collect();
    let result = select_trust_root(reports);
    info!(
        "{tag}: trust-root validation {:?} ({}/{} hosts reachable, root {})",
        result.status,
        result.reachable_count(),
        result.sources.len(),
        if result.has_trust_root() {
            "selected"
        } else {
            "NOT selected"
        }
    );
    result
}
