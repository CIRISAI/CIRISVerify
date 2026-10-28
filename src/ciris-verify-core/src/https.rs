//! HTTPS client for trust-root discovery (CC 5.3.4).
//!
//! ## Endpoints
//!
//! - `GET /v1/trust-root/bundle` — the accord-authorized GenesisBundle
//!   (primary; served by registries and canonical nodes)
//! - `GET /v1/steward-key` — the same body, served by registries only
//!   (fallback when the primary path is not routed)
//!
//! The response wrapper (`bundle_fingerprint`, `charter_root_key_id`,
//! `served_by`, `community`) is unsigned convenience. Only the `bundle` member
//! is returned, and the caller verifies it
//! ([`crate::genesis_bundle::verify_genesis_bundle`]) and recomputes every
//! derived field itself.
//!
//! ## Platform-aware HTTP
//!
//! On Android/iOS, tokio's async I/O is broken. This module uses blocking
//! `ureq` (hopped onto the blocking pool) on mobile and async `reqwest` on
//! desktop.

use std::time::Duration;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
use reqwest::{Client, ClientBuilder};
use serde_json::Value;
use tracing::{debug, info, instrument, warn};

use crate::error::VerifyError;

#[cfg(any(target_os = "android", target_os = "ios"))]
use crate::mobile_http;

/// The primary trust-root path (CC 5.3.4).
pub const TRUST_ROOT_BUNDLE_PATH: &str = "/v1/trust-root/bundle";

/// The registry alias for [`TRUST_ROOT_BUNDLE_PATH`]. Canonical nodes do not
/// serve it.
pub const STEWARD_KEY_ALIAS_PATH: &str = "/v1/steward-key";

/// HTTPS client for one trust-root host.
pub struct HttpsClient {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    client: Client,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    agent: ureq::Agent,
    /// Base URL for the API.
    base_url: String,
    /// SHA-256 fingerprint of expected certificate (for pinning).
    /// Future: Will be used for actual certificate pinning validation.
    #[allow(dead_code)]
    cert_fingerprint: Option<Vec<u8>>,
}

fn parse_pin(cert_pin: Option<&str>) -> Result<Option<Vec<u8>>, VerifyError> {
    cert_pin
        .map(|pin| {
            let hex = pin.strip_prefix("sha256:").unwrap_or(pin);
            hex::decode(hex).map_err(|e| VerifyError::HttpsError {
                message: format!("Invalid certificate fingerprint: {}", e),
            })
        })
        .transpose()
}

/// Take the `bundle` member out of a trust-root response.
pub fn bundle_from_response(url: &str, body: Value) -> Result<Value, VerifyError> {
    match body {
        Value::Object(mut map) => map
            .remove("bundle")
            .filter(Value::is_object)
            .ok_or_else(|| VerifyError::ResponseSchemaMismatch {
                url: url.to_string(),
                status: 200,
                detail: "trust-root response has no `bundle` object (CC 5.3.4)".to_string(),
            }),
        _ => Err(VerifyError::ResponseSchemaMismatch {
            url: url.to_string(),
            status: 200,
            detail: "trust-root response is not a JSON object".to_string(),
        }),
    }
}

impl HttpsClient {
    /// Create a new HTTPS client (desktop).
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub fn new(
        base_url: &str,
        timeout: Duration,
        cert_pin: Option<&str>,
    ) -> Result<Self, VerifyError> {
        // Aggressive timeouts so an unreachable host fails fast (emulators can
        // hang a TCP connect indefinitely).
        let connect_timeout = Duration::from_secs(3);
        let read_timeout = timeout.min(Duration::from_secs(8));

        let client = ClientBuilder::new()
            .timeout(read_timeout)
            .connect_timeout(connect_timeout)
            .read_timeout(read_timeout)
            .pool_idle_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(1)
            .tcp_nodelay(true)
            .user_agent(format!("CIRISVerify/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Failed to create HTTP client: {}", e),
            })?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            cert_fingerprint: parse_pin(cert_pin)?,
        })
    }

    /// Create a new HTTPS client (mobile - blocking ureq).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub fn new(
        base_url: &str,
        timeout: Duration,
        cert_pin: Option<&str>,
    ) -> Result<Self, VerifyError> {
        info!("HttpsClient: using mobile blocking HTTP (ureq)");
        Ok(Self {
            agent: mobile_http::create_tls_agent(timeout)?,
            base_url: base_url.trim_end_matches('/').to_string(),
            cert_fingerprint: parse_pin(cert_pin)?,
        })
    }

    /// The host this client queries.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// GET one path; `Ok(None)` on a 404 so the caller can fall back.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    async fn get_value(&self, path: &str) -> Result<Option<Value>, VerifyError> {
        let url = format!("{}{}", self.base_url, path);
        debug!(url = %url, "HTTPS: fetching trust root");
        let response = self.client.get(&url).send().await.map_err(|e| {
            warn!(url = %url, error = %e, "HTTPS request failed");
            VerifyError::HttpsError {
                message: format!("Request to {} failed: {}", url, e),
            }
        })?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            return Err(VerifyError::RateLimited {
                url,
                retry_after_secs: retry_after,
            });
        }
        if !status.is_success() {
            return Err(VerifyError::HttpsError {
                message: format!("HTTP {} from {}", status, url),
            });
        }
        let text = response.text().await.map_err(|e| VerifyError::HttpsError {
            message: format!("Read body from {url} failed: {e}"),
        })?;
        serde_json::from_str::<Value>(&text).map(Some).map_err(|e| {
            VerifyError::ResponseSchemaMismatch {
                url,
                status: status.as_u16(),
                detail: format!("trust-root response is not JSON: {e}"),
            }
        })
    }

    /// GET one path (mobile). `ureq` reports a 404 as an error, so a failure
    /// here is `Ok(None)` for the primary path and lets the caller fall back;
    /// the alias path's error is the one returned.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    async fn get_value(&self, path: &str) -> Result<Option<Value>, VerifyError> {
        let url = format!("{}{}", self.base_url, path);
        debug!(url = %url, "HTTPS: fetching trust root (mobile)");
        match mobile_http::get_json_async::<Value>(&self.agent, &url).await {
            Ok(v) => Ok(Some(v)),
            Err(e) if path == TRUST_ROOT_BUNDLE_PATH => {
                debug!(url = %url, error = %e, "primary trust-root path failed; trying alias");
                Ok(None)
            },
            Err(e) => {
                warn!(url = %url, error = %e, "trust-root fetch failed");
                Err(e)
            },
        }
    }

    /// Fetch the GenesisBundle (the inner `bundle` object, unverified) from
    /// [`TRUST_ROOT_BUNDLE_PATH`], falling back to [`STEWARD_KEY_ALIAS_PATH`]
    /// when the primary path is not routed.
    #[instrument(skip(self), fields(base_url = %self.base_url))]
    pub async fn get_trust_root_bundle(&self) -> Result<Value, VerifyError> {
        for path in [TRUST_ROOT_BUNDLE_PATH, STEWARD_KEY_ALIAS_PATH] {
            if let Some(body) = self.get_value(path).await? {
                let url = format!("{}{}", self.base_url, path);
                let bundle = bundle_from_response(&url, body)?;
                info!(url = %url, "HTTPS: trust-root bundle received");
                return Ok(bundle);
            }
        }
        Err(VerifyError::HttpsError {
            message: format!(
                "{} serves neither {} nor {}",
                self.base_url, TRUST_ROOT_BUNDLE_PATH, STEWARD_KEY_ALIAS_PATH
            ),
        })
    }
}

/// Fetch the (unverified) GenesisBundle from one trust-root host.
#[instrument(skip_all, fields(endpoint = %endpoint))]
pub async fn query_trust_root(
    endpoint: &str,
    timeout: Duration,
    cert_pin: Option<&str>,
) -> Result<Value, VerifyError> {
    HttpsClient::new(endpoint, timeout, cert_pin)?
        .get_trust_root_bundle()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn test_client_with_cert_pin() {
        let fingerprint = "0000000000000000000000000000000000000000000000000000000000000000";
        let client = HttpsClient::new(
            "https://verify.ciris.ai/",
            Duration::from_secs(30),
            Some(fingerprint),
        )
        .unwrap();
        assert_eq!(client.cert_fingerprint.unwrap().len(), 32);
        assert_eq!(client.base_url, "https://verify.ciris.ai");
        assert!(HttpsClient::new(
            "https://verify.ciris.ai",
            Duration::from_secs(30),
            Some("zz")
        )
        .is_err());
    }

    #[test]
    fn only_the_bundle_member_is_taken() {
        let body = serde_json::json!({
            "bundle": {"version": 4},
            "bundle_fingerprint": "sha256:00",
            "served_by": {"node_key_id": "n", "accepts_this_root": true}
        });
        assert_eq!(
            bundle_from_response("u", body).unwrap(),
            serde_json::json!({"version": 4})
        );
    }

    #[test]
    fn a_response_without_a_bundle_is_a_schema_mismatch_not_unreachable() {
        for body in [
            serde_json::json!({"classical": {}, "pqc": {}}),
            serde_json::json!({"bundle": "x"}),
            serde_json::json!([1]),
        ] {
            assert!(matches!(
                bundle_from_response("u", body),
                Err(VerifyError::ResponseSchemaMismatch { .. })
            ));
        }
    }
}
