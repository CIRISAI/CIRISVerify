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
    // Use extern crate names from Cargo.toml
    use rustls_mobile as rustls;
    use webpki_roots_mobile as webpki_roots;

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
pub fn get_json<T: serde::de::DeserializeOwned>(
    agent: &ureq::Agent,
    url: &str,
) -> Result<T, VerifyError> {
    info!("Mobile HTTP GET: {}", url);

    let response = agent.get(url).call().map_err(|e| {
        warn!("Mobile HTTP GET failed: {} - {}", url, e);
        VerifyError::HttpsError {
            message: format!("Request failed: {}", e),
        }
    })?;

    let status = response.status();
    if status < 200 || status >= 300 {
        return Err(VerifyError::HttpsError {
            message: format!("HTTP error: {}", status),
        });
    }

    response.into_json().map_err(|e| VerifyError::HttpsError {
        message: format!("JSON parse error: {}", e),
    })
}

/// POST request with JSON body, returning JSON.
pub fn post_json<T: serde::de::DeserializeOwned, B: serde::Serialize>(
    agent: &ureq::Agent,
    url: &str,
    body: &B,
) -> Result<(u16, T), VerifyError> {
    info!("Mobile HTTP POST: {}", url);

    let response = agent.post(url).send_json(body).map_err(|e| {
        // Check for specific HTTP status codes in transport errors
        if let ureq::Error::Status(code, _) = &e {
            return VerifyError::HttpsError {
                message: format!("HTTP error: {}", code),
            };
        }
        warn!("Mobile HTTP POST failed: {} - {}", url, e);
        VerifyError::HttpsError {
            message: format!("Request failed: {}", e),
        }
    })?;

    let status = response.status();
    if status < 200 || status >= 300 {
        return Err(VerifyError::HttpsError {
            message: format!("HTTP error: {}", status),
        });
    }

    let body: T = response.into_json().map_err(|e| VerifyError::HttpsError {
        message: format!("JSON parse error: {}", e),
    })?;

    Ok((status, body))
}

/// Check HTTP status without parsing body.
pub fn check_status(agent: &ureq::Agent, url: &str) -> Result<bool, VerifyError> {
    match agent.get(url).call() {
        Ok(response) => Ok(response.status() >= 200 && response.status() < 300),
        Err(_) => Ok(false),
    }
}
