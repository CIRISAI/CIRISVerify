//! iOS-specific synchronous validation using blocking I/O.
//!
//! iOS has the same fundamental networking constraints as Android:
//! 1. `getaddrinfo()` can hang for 30s on iOS (IPv6 AAAA query timeout)
//! 2. hickory-resolver's DoH bootstrap triggers this hang
//! 3. tokio async I/O from FFI threads is unreliable
//!
//! This module mirrors `android_sync.rs`: blocking ureq + DNS-over-HTTPS
//! + rustls with bundled Mozilla CA certificates (webpki-roots).
//!
//! BSD sockets work fine on iOS for outbound TCP — no need for
//! Network.framework or NSURLSession. rustls meets all App Transport
//! Security requirements (TLS 1.2+, forward secrecy, SHA-256 certs).

#![cfg(target_os = "ios")]

use std::sync::Arc;
use std::time::Duration;

use ciris_keyring::PlatformAttestation;
use ciris_verify_core::license::LicenseStatus;
use ciris_verify_core::types::{
    DisclosureSeverity, LicenseStatusRequest, LicenseStatusResponse, MandatoryDisclosure,
    ResponseAttestation, ResponseMetadata, ResponseSignature, SourceResult, ValidationResults,
    ValidationStatus,
};
use serde::Deserialize;
use tracing::{error, info, warn};

/// Registry API base URL
const REGISTRY_URL: &str = "https://api.registry.ciris-services-1.ai";

/// DNS-over-HTTPS endpoint (Google)
const DOH_ENDPOINT: &str = "https://dns.google/resolve";

/// DNS hostnames for TXT record validation
const DNS_US_HOSTNAME: &str = "us.registry.ciris-services-1.ai";
const DNS_EU_HOSTNAME: &str = "eu.registry.ciris-services-1.ai";

/// Create a TLS-enabled ureq agent with bundled Mozilla CA certificates.
/// Returns None if TLS initialization fails (graceful degradation).
fn create_tls_agent(timeout: Duration) -> Option<ureq::Agent> {
    let result = std::panic::catch_unwind(|| {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(timeout)
            .timeout_write(Duration::from_secs(5))
            .user_agent(&format!("CIRISVerify/{}", env!("CARGO_PKG_VERSION")))
            .tls_config(Arc::new(tls_config))
            .build()
    });

    match result {
        Ok(agent) => {
            info!("iOS sync: TLS agent created successfully");
            Some(agent)
        },
        Err(e) => {
            error!("iOS sync: TLS initialization panicked: {:?}", e);
            None
        },
    }
}

/// Create a basic ureq agent without custom TLS config (uses defaults).
fn create_basic_agent(timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(timeout)
        .timeout_write(Duration::from_secs(5))
        .user_agent(&format!("CIRISVerify/{}", env!("CARGO_PKG_VERSION")))
        .build()
}

/// Perform license verification using blocking I/O (no tokio).
///
/// This is the iOS-specific code path that bypasses tokio entirely.
/// Uses rustls with bundled Mozilla CA certificates.
/// All three network checks (DNS US, DNS EU, HTTPS) run in parallel using threads.
pub fn get_license_status_blocking(
    _request: &LicenseStatusRequest,
    timeout: Duration,
) -> LicenseStatusResponse {
    info!("iOS sync: Starting blocking license verification (parallel)");
    let start = std::time::Instant::now();

    // Try to create TLS-enabled agent, fall back to basic agent if it fails
    let (_agent, tls_mode) = match create_tls_agent(timeout) {
        Some(agent) => (agent, "webpki-roots"),
        None => {
            warn!("iOS sync: TLS agent creation failed, using default TLS");
            (create_basic_agent(timeout), "default")
        },
    };

    info!("iOS sync: Using TLS mode: {}", tls_mode);

    let now = chrono::Utc::now().timestamp();

    // Run all three network checks in parallel using threads
    // Note: ureq agents are not Send, so we create separate agents for each thread
    info!("iOS sync: Spawning parallel network checks");

    // Thread 1: DNS US via DoH
    let timeout_clone1 = timeout;
    let dns_us_handle = std::thread::spawn(move || {
        let agent = match create_tls_agent(timeout_clone1) {
            Some(a) => a,
            None => create_basic_agent(timeout_clone1),
        };
        query_dns_txt_doh(&agent, DNS_US_HOSTNAME)
    });

    // Thread 2: DNS EU via DoH
    let timeout_clone2 = timeout;
    let dns_eu_handle = std::thread::spawn(move || {
        let agent = match create_tls_agent(timeout_clone2) {
            Some(a) => a,
            None => create_basic_agent(timeout_clone2),
        };
        query_dns_txt_doh(&agent, DNS_EU_HOSTNAME)
    });

    // Thread 3: HTTPS steward key fetch
    let timeout_clone3 = timeout;
    let https_handle = std::thread::spawn(move || {
        let agent = match create_tls_agent(timeout_clone3) {
            Some(a) => a,
            None => create_basic_agent(timeout_clone3),
        };
        fetch_steward_key_blocking(&agent, REGISTRY_URL)
    });

    // Wait for all threads to complete
    let dns_us_result = dns_us_handle
        .join()
        .unwrap_or_else(|_| Err(DohError::ThreadPanic));
    let dns_eu_result = dns_eu_handle
        .join()
        .unwrap_or_else(|_| Err(DohError::ThreadPanic));
    let https_result = https_handle.join();

    info!(
        "iOS sync: All parallel checks completed in {:?}",
        start.elapsed()
    );

    // Process DNS US result
    let (dns_us_reachable, dns_us_valid, dns_us_error, dns_us_error_category) = match &dns_us_result
    {
        Ok(txt_records) => {
            info!(
                "iOS sync: DNS US returned {} TXT records",
                txt_records.len()
            );
            let valid = !txt_records.is_empty();
            (true, valid, None, None)
        },
        Err(e) => {
            warn!("iOS sync: DNS US DoH query failed: {}", e);
            (
                false,
                false,
                Some(e.to_string()),
                Some("doh_error".to_string()),
            )
        },
    };

    // Process DNS EU result
    let (dns_eu_reachable, dns_eu_valid, dns_eu_error, dns_eu_error_category) = match &dns_eu_result
    {
        Ok(txt_records) => {
            info!(
                "iOS sync: DNS EU returned {} TXT records",
                txt_records.len()
            );
            let valid = !txt_records.is_empty();
            (true, valid, None, None)
        },
        Err(e) => {
            warn!("iOS sync: DNS EU DoH query failed: {}", e);
            (
                false,
                false,
                Some(e.to_string()),
                Some("doh_error".to_string()),
            )
        },
    };

    // Process HTTPS result
    let (https_reachable, https_error, https_error_category) = match https_result {
        Ok(Ok(_response)) => {
            info!("iOS sync: HTTPS fetch succeeded in {:?}", start.elapsed());
            (true, None, None)
        },
        Ok(Err(e)) => {
            let (category, details) = categorize_ureq_error(&e);
            warn!(
                "iOS sync: HTTPS fetch failed: {} (category: {})",
                details, category
            );
            (false, Some(details), Some(category))
        },
        Err(_) => {
            warn!("iOS sync: HTTPS thread panicked");
            (
                false,
                Some("Thread panic".to_string()),
                Some("thread_panic".to_string()),
            )
        },
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
        "iOS sync: Validation complete in {:?} - status: {:?}",
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
            platform: PlatformAttestation::Ios(ciris_keyring::IosAttestation {
                secure_enclave: true,
                app_attest: None,
                device_check_token: None,
            }),
            signature: ResponseSignature {
                classical: Vec::new(),
                classical_algorithm: "Ed25519".to_string(),
                pqc: Vec::new(),
                pqc_algorithm: "ML-DSA-65".to_string(),
                pqc_public_key: Vec::new(),
                signature_mode: "Available".to_string(),
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
            request_id: format!("ios-sync-{}", now),
        },
        runtime_validation: None,
        shutdown_directive: None,
        function_integrity: None,
        binary_integrity: None,
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
/// This bypasses hickory-dns (which requires tokio and triggers
/// `getaddrinfo()` hangs on iOS) and uses the same ureq HTTP client.
fn query_dns_txt_doh(agent: &ureq::Agent, hostname: &str) -> Result<Vec<String>, DohError> {
    let url = format!("{}?name={}&type=TXT", DOH_ENDPOINT, hostname);
    info!("iOS sync: DoH query: {}", url);

    let response = agent
        .get(&url)
        .set("Accept", "application/dns-json")
        .call()
        .map_err(DohError::Http)?;

    let doh_response: DohResponse = response.into_json().map_err(DohError::Json)?;

    if doh_response.status != 0 {
        return Err(DohError::DnsStatus(doh_response.status));
    }

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
    ThreadPanic,
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
            },
            Self::ThreadPanic => write!(f, "Thread panic"),
        }
    }
}

/// Fetch steward key using blocking ureq HTTP client.
fn fetch_steward_key_blocking(
    agent: &ureq::Agent,
    base_url: &str,
) -> Result<StewardKeyResponse, ureq::Error> {
    let url = format!("{}/v1/steward-key", base_url);
    info!("iOS sync: Fetching {}", url);

    let response = agent.get(&url).call()?;
    let body: StewardKeyResponse = response.into_json()?;

    Ok(body)
}

/// Steward key response (simplified for iOS sync path).
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
        },
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
        },
    }
}
