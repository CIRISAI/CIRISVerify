//! Android-specific synchronous validation using blocking I/O.
//!
//! Tokio's async I/O doesn't work on Android JNI threads because:
//! 1. The event loop/epoll doesn't poll correctly
//! 2. Worker threads aren't JNI-attached
//!
//! This module provides a completely synchronous code path using ureq
//! for HTTP requests, bypassing tokio entirely.

#![cfg(target_os = "android")]

use std::time::Duration;

use ciris_verify_core::types::{
    DisclosureSeverity, LicenseStatusRequest, LicenseStatusResponse, MandatoryDisclosure,
    ResponseAttestation, ResponseMetadata, ResponseSignature, SourceResult, ValidationResults,
    ValidationStatus,
};
use ciris_verify_core::license::LicenseStatus;
use ciris_keyring::PlatformAttestation;
use tracing::{info, warn, error};

/// Registry API base URL
const REGISTRY_URL: &str = "https://api.registry.ciris-services-1.ai";

/// Perform license verification using blocking I/O (no tokio).
///
/// This is the Android-specific code path that bypasses tokio entirely.
pub fn get_license_status_blocking(
    request: &LicenseStatusRequest,
    timeout: Duration,
) -> LicenseStatusResponse {
    info!("Android sync: Starting blocking license verification");
    let start = std::time::Instant::now();

    // Create blocking HTTP client with ureq
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(timeout)
        .timeout_write(Duration::from_secs(5))
        .user_agent(&format!("CIRISVerify/{}", env!("CARGO_PKG_VERSION")))
        .build();

    // Try to fetch steward key from HTTPS endpoint
    let https_result = fetch_steward_key_blocking(&agent, REGISTRY_URL);

    let now = chrono::Utc::now().timestamp();

    let (validation_status, https_reachable, https_error, https_error_category) = match &https_result {
        Ok(response) => {
            info!("Android sync: HTTPS fetch succeeded in {:?}", start.elapsed());
            (ValidationStatus::PartialAgreement, true, None, None)
        }
        Err(e) => {
            let (category, details) = categorize_ureq_error(e);
            warn!("Android sync: HTTPS fetch failed: {} (category: {})", details, category);
            (
                ValidationStatus::NoSourcesReachable,
                false,
                Some(details),
                Some(category),
            )
        }
    };

    // Build response
    LicenseStatusResponse {
        status: if https_reachable {
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
            platform: PlatformAttestation::Software {
                device_id: request.deployment_id.clone(),
            },
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
                source: "us.registry.ciris-services-1.ai".to_string(),
                reachable: false,
                valid: false,
                checked_at: now,
                error: Some("DNS skipped on Android (using HTTPS only)".to_string()),
                error_category: Some("skipped".to_string()),
                error_details: Some("DNS resolution via hickory-dns not supported on Android".to_string()),
            },
            dns_eu: SourceResult {
                source: "eu.registry.ciris-services-1.ai".to_string(),
                reachable: false,
                valid: false,
                checked_at: now,
                error: Some("DNS skipped on Android (using HTTPS only)".to_string()),
                error_category: Some("skipped".to_string()),
                error_details: Some("DNS resolution via hickory-dns not supported on Android".to_string()),
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
#[derive(Debug, serde::Deserialize)]
struct StewardKeyResponse {
    #[serde(default)]
    revision: u64,
    #[serde(default)]
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
