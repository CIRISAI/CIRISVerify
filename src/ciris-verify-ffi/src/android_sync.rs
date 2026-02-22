//! Android-specific synchronous validation using blocking I/O.
//!
//! Tokio's async I/O doesn't work on Android JNI threads because:
//! 1. The event loop/epoll doesn't poll correctly
//! 2. Worker threads aren't JNI-attached
//!
//! This module provides a completely synchronous code path using ureq
//! for HTTP requests, bypassing tokio entirely.
//!
//! DNS TXT records are resolved via DNS-over-HTTPS (Google DNS) since
//! hickory-dns requires tokio and std::net only supports A/AAAA records.

#![cfg(target_os = "android")]

use std::sync::Arc;
use std::time::Duration;

use ciris_keyring::{PlatformAttestation, SoftwareAttestation};
use ciris_verify_core::license::LicenseStatus;
use ciris_verify_core::types::{
    DisclosureSeverity, LicenseStatusRequest, LicenseStatusResponse, MandatoryDisclosure,
    ResponseAttestation, ResponseMetadata, ResponseSignature, SourceResult, ValidationResults,
    ValidationStatus,
};
use rustls::ClientConfig;
use serde::Deserialize;
use tracing::{info, warn};

/// Registry API base URL
const REGISTRY_URL: &str = "https://api.registry.ciris-services-1.ai";

/// DNS-over-HTTPS endpoint (Google)
const DOH_ENDPOINT: &str = "https://dns.google/resolve";

/// DNS hostnames for TXT record validation
const DNS_US_HOSTNAME: &str = "us.registry.ciris-services-1.ai";
const DNS_EU_HOSTNAME: &str = "eu.registry.ciris-services-1.ai";

/// Create a rustls ClientConfig using bundled Mozilla CA certificates.
///
/// This is required on Android because native-certs doesn't work
/// (can't access the system certificate store from native code).
fn create_tls_config() -> Arc<ClientConfig> {
    // Use rustls 0.23 API: RootCertStore::from_iter()
    let root_store = rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    );

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Arc::new(config)
}

/// Perform license verification using blocking I/O (no tokio).
///
/// This is the Android-specific code path that bypasses tokio entirely.
pub fn get_license_status_blocking(
    _request: &LicenseStatusRequest,
    timeout: Duration,
) -> LicenseStatusResponse {
    info!("Android sync: Starting blocking license verification");
    let start = std::time::Instant::now();

    // Create TLS config with bundled Mozilla certs (native-certs doesn't work on Android)
    let tls_config = create_tls_config();

    // Create blocking HTTP client with ureq + rustls
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(timeout)
        .timeout_write(Duration::from_secs(5))
        .user_agent(&format!("CIRISVerify/{}", env!("CARGO_PKG_VERSION")))
        .tls_config(tls_config)
        .build();

    let now = chrono::Utc::now().timestamp();

    // Query DNS TXT records via DoH (parallel would be nice but we're blocking)
    info!("Android sync: Querying DNS TXT records via DoH");
    let dns_us_result = query_dns_txt_doh(&agent, DNS_US_HOSTNAME);
    let dns_eu_result = query_dns_txt_doh(&agent, DNS_EU_HOSTNAME);

    // Process DNS US result
    let (dns_us_reachable, dns_us_valid, dns_us_error, dns_us_error_category) =
        match &dns_us_result {
            Ok(txt_records) => {
                info!(
                    "Android sync: DNS US returned {} TXT records in {:?}",
                    txt_records.len(),
                    start.elapsed()
                );
                // For now, just verify we got records - actual validation would check content
                let valid = !txt_records.is_empty();
                (true, valid, None, None)
            }
            Err(e) => {
                warn!("Android sync: DNS US DoH query failed: {}", e);
                (false, false, Some(e.to_string()), Some("doh_error".to_string()))
            }
        };

    // Process DNS EU result
    let (dns_eu_reachable, dns_eu_valid, dns_eu_error, dns_eu_error_category) =
        match &dns_eu_result {
            Ok(txt_records) => {
                info!(
                    "Android sync: DNS EU returned {} TXT records",
                    txt_records.len()
                );
                let valid = !txt_records.is_empty();
                (true, valid, None, None)
            }
            Err(e) => {
                warn!("Android sync: DNS EU DoH query failed: {}", e);
                (false, false, Some(e.to_string()), Some("doh_error".to_string()))
            }
        };

    // Try to fetch steward key from HTTPS endpoint
    info!("Android sync: Fetching steward key from HTTPS");
    let https_result = fetch_steward_key_blocking(&agent, REGISTRY_URL);

    let (https_reachable, https_error, https_error_category) = match &https_result {
        Ok(_response) => {
            info!(
                "Android sync: HTTPS fetch succeeded in {:?}",
                start.elapsed()
            );
            (true, None, None)
        }
        Err(e) => {
            let (category, details) = categorize_ureq_error(e);
            warn!(
                "Android sync: HTTPS fetch failed: {} (category: {})",
                details, category
            );
            (false, Some(details), Some(category))
        }
    };

    // Determine overall validation status
    let sources_reachable = dns_us_reachable || dns_eu_reachable || https_reachable;
    let validation_status = if https_reachable && (dns_us_valid || dns_eu_valid) {
        ValidationStatus::AllSourcesAgree
    } else if https_reachable || dns_us_valid || dns_eu_valid {
        ValidationStatus::PartialAgreement
    } else if sources_reachable {
        ValidationStatus::SourcesDisagree
    } else {
        ValidationStatus::NoSourcesReachable
    };

    info!(
        "Android sync: Validation complete in {:?} - status: {:?}",
        start.elapsed(),
        validation_status
    );

    // Build response
    LicenseStatusResponse {
        status: if sources_reachable {
            LicenseStatus::UnlicensedCommunity
        } else {
            LicenseStatus::UnlicensedCommunity // Fail-secure to community mode
        },
        license: None,
        mandatory_disclosure: MandatoryDisclosure {
            text: "COMMUNITY MODE: This is an unlicensed community agent.".to_string(),
            severity: DisclosureSeverity::Warning,
            locale: "en".to_string(),
        },
        attestation: ResponseAttestation {
            platform: PlatformAttestation::Software(SoftwareAttestation {
                key_derivation: "none".to_string(),
                storage: "android-sync".to_string(),
                security_warning: "Android sync path - blocking I/O with DoH".to_string(),
            }),
            signature: ResponseSignature {
                classical: Vec::new(),
                classical_algorithm: "none".to_string(),
                pqc: Vec::new(),
                pqc_algorithm: "none".to_string(),
                pqc_public_key: Vec::new(),
                signature_mode: "Unavailable".to_string(),
            },
            integrity_valid: true,
            timestamp: now,
        },
        validation: ValidationResults {
            dns_us: SourceResult {
                source: format!("DoH:{}", DNS_US_HOSTNAME),
                reachable: dns_us_reachable,
                valid: dns_us_valid,
                checked_at: now,
                error: dns_us_error.clone(),
                error_category: dns_us_error_category.clone(),
                error_details: dns_us_error,
            },
            dns_eu: SourceResult {
                source: format!("DoH:{}", DNS_EU_HOSTNAME),
                reachable: dns_eu_reachable,
                valid: dns_eu_valid,
                checked_at: now,
                error: dns_eu_error.clone(),
                error_category: dns_eu_error_category.clone(),
                error_details: dns_eu_error,
            },
            https: SourceResult {
                source: REGISTRY_URL.to_string(),
                reachable: https_reachable,
                valid: https_reachable,
                checked_at: now,
                error: https_error.clone(),
                error_category: https_error_category.clone(),
                error_details: https_error,
            },
            overall: validation_status,
        },
        metadata: ResponseMetadata {
            protocol_version: "2.0.0".to_string(),
            binary_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: now,
            cache_ttl: 300,
            request_id: format!("android-sync-{}", now),
        },
        runtime_validation: None,
        shutdown_directive: None,
        function_integrity: None,
    }
}

/// DNS-over-HTTPS response from Google DNS.
#[derive(Debug, Deserialize)]
struct DohResponse {
    #[serde(rename = "Status")]
    status: i32,
    #[serde(rename = "Answer", default)]
    answer: Vec<DohAnswer>,
}

/// A single answer record from DoH response.
#[derive(Debug, Deserialize)]
struct DohAnswer {
    /// Record type (16 = TXT)
    #[serde(rename = "type")]
    record_type: u16,
    /// Record data (for TXT, this is the text content)
    data: String,
}

/// Query DNS TXT records using DNS-over-HTTPS (Google DNS).
///
/// This bypasses hickory-dns (which requires tokio) and uses the same
/// ureq HTTP client we're already using for HTTPS requests.
fn query_dns_txt_doh(agent: &ureq::Agent, hostname: &str) -> Result<Vec<String>, DohError> {
    let url = format!("{}?name={}&type=TXT", DOH_ENDPOINT, hostname);
    info!("Android sync: DoH query: {}", url);

    let response = agent
        .get(&url)
        .set("Accept", "application/dns-json")
        .call()
        .map_err(DohError::Http)?;

    let doh_response: DohResponse = response.into_json().map_err(DohError::Json)?;

    // Check DNS status (0 = NOERROR)
    if doh_response.status != 0 {
        return Err(DohError::DnsStatus(doh_response.status));
    }

    // Extract TXT records (type 16)
    let txt_records: Vec<String> = doh_response
        .answer
        .into_iter()
        .filter(|a| a.record_type == 16)
        .map(|a| a.data.trim_matches('"').to_string())
        .collect();

    Ok(txt_records)
}

/// Errors that can occur during DoH queries.
#[derive(Debug)]
enum DohError {
    Http(ureq::Error),
    Json(std::io::Error),
    DnsStatus(i32),
}

impl std::fmt::Display for DohError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(e) => write!(f, "HTTP error: {}", e),
            Self::Json(e) => write!(f, "JSON parse error: {}", e),
            Self::DnsStatus(code) => {
                let status_name = match code {
                    1 => "FORMERR",
                    2 => "SERVFAIL",
                    3 => "NXDOMAIN",
                    4 => "NOTIMP",
                    5 => "REFUSED",
                    _ => "UNKNOWN",
                };
                write!(f, "DNS error: {} ({})", status_name, code)
            }
        }
    }
}

/// Fetch steward key using blocking ureq HTTP client.
fn fetch_steward_key_blocking(
    agent: &ureq::Agent,
    base_url: &str,
) -> Result<StewardKeyResponse, ureq::Error> {
    let url = format!("{}/v1/steward-key", base_url);
    info!("Android sync: Fetching {}", url);

    let response = agent.get(&url).call()?;
    let body: StewardKeyResponse = response.into_json()?;

    Ok(body)
}

/// Steward key response (simplified for Android sync path).
#[derive(Debug, Deserialize)]
struct StewardKeyResponse {
    #[serde(default)]
    #[allow(dead_code)]
    revision: u64,
    #[serde(default)]
    #[allow(dead_code)]
    timestamp: i64,
}

/// Categorize ureq errors into user-friendly categories.
fn categorize_ureq_error(error: &ureq::Error) -> (String, String) {
    match error {
        ureq::Error::Status(code, _response) => {
            (format!("http_{}", code), format!("HTTP status {}", code))
        }
        ureq::Error::Transport(transport) => {
            let kind = transport.kind();
            let message = transport.message().unwrap_or("unknown");

            let category = match kind {
                ureq::ErrorKind::Dns => "dns_resolution",
                ureq::ErrorKind::ConnectionFailed => "connection_failed",
                ureq::ErrorKind::TooManyRedirects => "too_many_redirects",
                ureq::ErrorKind::BadStatus => "bad_status",
                ureq::ErrorKind::BadHeader => "bad_header",
                ureq::ErrorKind::Io => "io_error",
                ureq::ErrorKind::InvalidUrl => "invalid_url",
                ureq::ErrorKind::UnknownScheme => "unknown_scheme",
                ureq::ErrorKind::InsecureRequestHttpsOnly => "https_required",
                ureq::ErrorKind::ProxyConnect => "proxy_error",
                ureq::ErrorKind::ProxyUnauthorized => "proxy_unauthorized",
                ureq::ErrorKind::HTTP => "http_error",
                _ => "transport_error",
            };

            (category.to_string(), message.to_string())
        }
    }
}
