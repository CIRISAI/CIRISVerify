//! Mobile HTTP client using blocking ureq.
//!
//! On Android/iOS, tokio's async I/O is broken (JNI threads, iOS getaddrinfo hangs).
//! This module provides blocking HTTP using ureq with rustls and bundled Mozilla CA certs.

#![cfg(any(target_os = "android", target_os = "ios"))]

use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use crate::error::VerifyError;

/// Create a TLS-enabled ureq agent with bundled Mozilla CA certificates.
pub fn create_tls_agent(timeout: Duration) -> Result<ureq::Agent, VerifyError> {
    // rustls (0.23) + webpki-roots (0.26) come from the common [dependencies]
    // (unified after the hickory 0.25 bump, CIRISVerify#165).
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(3))
        .timeout_read(timeout.min(Duration::from_secs(8)))
        .timeout_write(Duration::from_secs(5))
        .user_agent(&format!("CIRISVerify/{}", env!("CARGO_PKG_VERSION")))
        .tls_config(Arc::new(tls_config))
        .build();

    info!("Mobile HTTP: TLS agent created with bundled Mozilla CA certs");
    Ok(agent)
}

/// GET request returning JSON.
///
/// v2.2.0+ for issue #21: maps HTTP 404 → [`VerifyError::NotFound`] and
/// HTTP 429 → [`VerifyError::RateLimited`] (with `Retry-After` header
/// parsed when present), so the caller can short-circuit dependent
/// probes and honor backoff respectively. Other non-2xx statuses still
/// flow as [`VerifyError::HttpsError`].
pub fn get_json<T: serde::de::DeserializeOwned>(
    agent: &ureq::Agent,
    url: &str,
) -> Result<T, VerifyError> {
    info!("Mobile HTTP GET: {}", url);

    let response = match agent.get(url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, resp)) => {
            // ureq returns Err for any non-2xx, with the response attached.
            let retry_after = resp
                .header("Retry-After")
                .and_then(crate::registry::parse_retry_after);
            return Err(map_mobile_status(code, url, retry_after));
        },
        Err(e) => {
            warn!("Mobile HTTP GET failed: {} - {}", url, e);
            return Err(VerifyError::HttpsError {
                message: format!("Request failed: {}", e),
            });
        },
    };

    response.into_json().map_err(|e| VerifyError::HttpsError {
        message: format!("JSON parse error: {}", e),
    })
}

/// Same status mapping as the desktop `status_to_error`, but ureq
/// already gave us a u16 directly.
fn map_mobile_status(code: u16, url: &str, retry_after_secs: Option<u64>) -> VerifyError {
    match code {
        404 => VerifyError::NotFound {
            url: url.to_string(),
        },
        429 => VerifyError::RateLimited {
            url: url.to_string(),
            retry_after_secs,
        },
        _ => VerifyError::HttpsError {
            message: format!("HTTP error: {} ({})", code, url),
        },
    }
}

/// POST request with JSON body, returning JSON.
pub fn post_json<T: serde::de::DeserializeOwned, B: serde::Serialize>(
    agent: &ureq::Agent,
    url: &str,
    body: &B,
) -> Result<(u16, T), VerifyError> {
    info!("Mobile HTTP POST: {}", url);

    let response = match agent.post(url).send_json(body) {
        Ok(r) => r,
        Err(ureq::Error::Status(code, resp)) => {
            let retry_after = resp
                .header("Retry-After")
                .and_then(crate::registry::parse_retry_after);
            return Err(map_mobile_status(code, url, retry_after));
        },
        Err(e) => {
            warn!("Mobile HTTP POST failed: {} - {}", url, e);
            return Err(VerifyError::HttpsError {
                message: format!("Request failed: {}", e),
            });
        },
    };

    // ureq returned Ok, so the response is 2xx.
    let status = response.status();

    let body: T = response.into_json().map_err(|e| VerifyError::HttpsError {
        message: format!("JSON parse error: {}", e),
    })?;

    Ok((status, body))
}

/// Check HTTP status without parsing body — returns `true` only on
/// 2xx. Intended for health-check semantics where 401/404/500 are
/// meaningfully "not healthy."
pub fn check_status(agent: &ureq::Agent, url: &str) -> Result<bool, VerifyError> {
    match agent.get(url).call() {
        Ok(response) => Ok(response.status() >= 200 && response.status() < 300),
        Err(_) => Ok(false),
    }
}

/// Network-reachability probe (v4.8.1+, CIRISVerify#56).
///
/// Returns `true` if the TCP+TLS handshake completed and ANY HTTP
/// response came back — including 401/403/404/500. The registry
/// returns HTTP 401 from its bare hostname (auth required), which
/// **proves** the network path works: DNS resolved, TCP connected,
/// TLS handshake succeeded, server responded. That's all we need
/// from a reachability probe.
///
/// Returns `false` only on:
/// - DNS resolution failure
/// - Connect refused (ECONNREFUSED) / network unreachable (ENETUNREACH)
/// - TLS handshake failure
/// - Read/write timeout
///
/// **Distinct from [`check_status`]** which is 2xx-only and intended
/// for health-check semantics. The S21U Galaxy bug (CIRISVerify#56)
/// was that the v4.8.0 mobile probe used `check_status` and classified
/// the registry's HTTP 401 response as "unreachable" — even though
/// 401 demonstrably proves the network worked.
pub fn probe_reachability(agent: &ureq::Agent, url: &str) -> bool {
    match agent.get(url).call() {
        // 2xx — network reachable, server happy.
        Ok(_) => true,
        // Non-2xx with a structured response — network reachable, server
        // returned an HTTP-level error. That's a SUCCESS for the probe.
        Err(ureq::Error::Status(_, _)) => true,
        // Any other ureq::Error variant is a transport-level failure
        // (DNS, connect, TLS, timeout). Not reachable.
        Err(e) => {
            warn!("Mobile probe: {} unreachable ({})", url, e);
            false
        },
    }
}
