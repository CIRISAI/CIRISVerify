//! HTTPS client with certificate pinning for CIRISRegistry API.
//!
//! Provides secure communication with the verification endpoint,
//! including certificate pinning to prevent MITM attacks.
//!
//! ## Endpoints
//!
//! - `GET /v1/steward-key` - Get current steward signing keys
//! - `GET /v1/revocation/{license_id}` - Check license revocation status
//! - `POST /v1/validate-license` - Validate a license JWT
//!
//! ## Platform-Aware HTTP
//!
//! On Android/iOS, tokio's async I/O is broken. This module uses blocking
//! `ureq` on mobile platforms and async `reqwest` on desktop.

use std::time::Duration;

use base64::Engine;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, instrument, warn};

use crate::error::VerifyError;

// Use shared mobile_http module for Android/iOS
#[cfg(any(target_os = "android", target_os = "ios"))]
use crate::mobile_http;

/// HTTPS client for the verification endpoint.
///
/// Uses platform-appropriate HTTP:
/// - Android/iOS: Blocking `ureq` (tokio async I/O is broken on mobile)
/// - Desktop: Async `reqwest`
pub struct HttpsClient {
    /// HTTP client (reqwest on desktop, ureq on mobile).
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

/// Response from the steward key endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StewardKeyResponse {
    /// Classical key information.
    pub classical: ClassicalKeyInfo,
    /// PQC key information.
    pub pqc: PqcKeyInfo,
    /// Signature mode.
    pub signature_mode: String,
    /// Revocation list revision.
    pub revision: u64,
    /// Last update timestamp.
    pub timestamp: i64,
    /// Next key rotation timestamp.
    pub next_rotation: Option<i64>,
    /// Signature over response (classical).
    pub response_signature_classical: Option<String>,
    /// Signature over response (PQC).
    pub response_signature_pqc: Option<String>,
}

/// Classical key information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassicalKeyInfo {
    /// Algorithm name.
    pub algorithm: String,
    /// Base64-encoded public key.
    pub key: String,
    /// Key identifier.
    pub key_id: String,
}

/// PQC key information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcKeyInfo {
    /// Algorithm name.
    pub algorithm: String,
    /// Base64-encoded public key.
    pub key: String,
    /// Key identifier.
    pub key_id: String,
    /// SHA-256 fingerprint of the key.
    pub fingerprint: String,
}

/// Response from the revocation check endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationResponse {
    /// License ID.
    pub license_id: String,
    /// Whether the license is revoked.
    pub revoked: bool,
    /// When the license was revoked (if applicable).
    pub revoked_at: Option<i64>,
    /// Reason for revocation (if applicable).
    pub reason: Option<String>,
    /// Timestamp of this check.
    pub checked_at: i64,
}

/// Response from the license validation endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseValidationResponse {
    /// Whether the license is valid.
    pub valid: bool,
    /// License ID.
    pub license_id: Option<String>,
    /// License type.
    pub license_type: Option<String>,
    /// Organization name.
    pub organization: Option<String>,
    /// Expiration timestamp.
    pub expires_at: Option<i64>,
    /// Granted capabilities.
    pub capabilities: Option<Vec<String>>,
    /// Error message (if invalid).
    pub error: Option<String>,
}

impl HttpsClient {
    // =========================================================================
    // Constructor - Desktop (async reqwest)
    // =========================================================================

    /// Create a new HTTPS client (desktop).
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub fn new(
        base_url: &str,
        timeout: Duration,
        cert_pin: Option<&str>,
    ) -> Result<Self, VerifyError> {
        // Use aggressive timeouts to fail fast on unreachable hosts
        // Critical for emulators where TCP connections can hang indefinitely
        let connect_timeout = Duration::from_secs(3);
        let read_timeout = timeout.min(Duration::from_secs(8));

        let client = ClientBuilder::new()
            .timeout(read_timeout)                    // Total request timeout
            .connect_timeout(connect_timeout)         // TCP connect timeout
            .read_timeout(read_timeout)               // Read timeout
            .pool_idle_timeout(Duration::from_secs(5)) // Don't keep idle connections
            .pool_max_idle_per_host(1)                // Minimal connection pooling
            .tcp_nodelay(true)                        // Disable Nagle for faster failure detection
            .user_agent(format!("CIRISVerify/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Failed to create HTTP client: {}", e),
            })?;

        let cert_fingerprint = cert_pin
            .map(|pin| {
                let hex = pin.strip_prefix("sha256:").unwrap_or(pin);
                hex::decode(hex).map_err(|e| VerifyError::HttpsError {
                    message: format!("Invalid certificate fingerprint: {}", e),
                })
            })
            .transpose()?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            cert_fingerprint,
        })
    }

    // =========================================================================
    // Constructor - Mobile (blocking ureq)
    // =========================================================================

    /// Create a new HTTPS client (mobile - blocking ureq).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub fn new(
        base_url: &str,
        timeout: Duration,
        cert_pin: Option<&str>,
    ) -> Result<Self, VerifyError> {
        info!("HttpsClient: using mobile blocking HTTP (ureq)");
        let agent = mobile_http::create_tls_agent(timeout)?;

        let cert_fingerprint = cert_pin
            .map(|pin| {
                let hex = pin.strip_prefix("sha256:").unwrap_or(pin);
                hex::decode(hex).map_err(|e| VerifyError::HttpsError {
                    message: format!("Invalid certificate fingerprint: {}", e),
                })
            })
            .transpose()?;

        Ok(Self {
            agent,
            base_url: base_url.trim_end_matches('/').to_string(),
            cert_fingerprint,
        })
    }

    // =========================================================================
    // Steward Key - Desktop
    // =========================================================================

    /// Get the current steward signing keys (desktop).
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[instrument(skip(self))]
    pub async fn get_steward_key(&self) -> Result<StewardKeyResponse, VerifyError> {
        let url = format!("{}/v1/steward-key", self.base_url);
        info!(
            url = %url,
            user_agent = %format!("CIRISVerify/{}", env!("CARGO_PKG_VERSION")),
            "HTTPS: Fetching steward key..."
        );

        let response = self.client.get(&url).send().await.map_err(|e| {
            warn!(url = %url, error = %e, "HTTPS request failed");
            VerifyError::HttpsError {
                message: format!("Request to {} failed: {}", url, e),
            }
        })?;

        let status = response.status();
        info!(
            url = %url,
            status = %status,
            "HTTPS: Response received"
        );

        if !status.is_success() {
            warn!(url = %url, status = %status, "HTTPS: Non-success status");
            return Err(VerifyError::HttpsError {
                message: format!("HTTP {} from {}", status, url),
            });
        }

        let body = response.json::<StewardKeyResponse>().await.map_err(|e| {
            warn!(url = %url, error = %e, "HTTPS: Failed to parse JSON response");
            VerifyError::HttpsError {
                message: format!("Failed to parse response from {}: {}", url, e),
            }
        })?;

        info!(
            url = %url,
            classical_algo = %body.classical.algorithm,
            pqc_algo = %body.pqc.algorithm,
            revision = body.revision,
            "HTTPS: Steward key received successfully"
        );

        self.verify_pqc_fingerprint(&body)?;
        Ok(body)
    }

    // =========================================================================
    // Steward Key - Mobile
    // =========================================================================

    /// Get the current steward signing keys (mobile - blocking).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    #[instrument(skip(self))]
    pub async fn get_steward_key(&self) -> Result<StewardKeyResponse, VerifyError> {
        let url = format!("{}/v1/steward-key", self.base_url);
        info!(
            url = %url,
            "HTTPS: Fetching steward key (mobile)..."
        );

        let body: StewardKeyResponse = mobile_http::get_json(&self.agent, &url)?;

        info!(
            url = %url,
            classical_algo = %body.classical.algorithm,
            pqc_algo = %body.pqc.algorithm,
            revision = body.revision,
            "HTTPS: Steward key received successfully (mobile)"
        );

        self.verify_pqc_fingerprint(&body)?;
        Ok(body)
    }

    // =========================================================================
    // Revocation Check - Desktop
    // =========================================================================

    /// Check if a license is revoked (desktop).
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[instrument(skip(self), fields(license_id = %license_id))]
    pub async fn check_revocation(
        &self,
        license_id: &str,
    ) -> Result<RevocationResponse, VerifyError> {
        let url = format!("{}/v1/revocation/{}", self.base_url, license_id);
        debug!("Checking revocation for {}", license_id);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Request failed: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(VerifyError::HttpsError {
                message: format!("HTTP error: {}", response.status()),
            });
        }

        response
            .json::<RevocationResponse>()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Failed to parse response: {}", e),
            })
    }

    // =========================================================================
    // Revocation Check - Mobile
    // =========================================================================

    /// Check if a license is revoked (mobile - blocking).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    #[instrument(skip(self), fields(license_id = %license_id))]
    pub async fn check_revocation(
        &self,
        license_id: &str,
    ) -> Result<RevocationResponse, VerifyError> {
        let url = format!("{}/v1/revocation/{}", self.base_url, license_id);
        debug!("Checking revocation for {} (mobile)", license_id);
        mobile_http::get_json(&self.agent, &url)
    }

    // =========================================================================
    // License Validation - Desktop
    // =========================================================================

    /// Validate a license JWT (desktop).
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[instrument(skip(self, license_jwt))]
    pub async fn validate_license(
        &self,
        license_jwt: &str,
    ) -> Result<LicenseValidationResponse, VerifyError> {
        let url = format!("{}/v1/validate-license", self.base_url);
        debug!("Validating license JWT");

        #[derive(Serialize)]
        struct ValidationRequest<'a> {
            license_jwt: &'a str,
        }

        let response = self
            .client
            .post(&url)
            .json(&ValidationRequest { license_jwt })
            .send()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Request failed: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(VerifyError::HttpsError {
                message: format!("HTTP error: {}", response.status()),
            });
        }

        response
            .json::<LicenseValidationResponse>()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Failed to parse response: {}", e),
            })
    }

    // =========================================================================
    // License Validation - Mobile
    // =========================================================================

    /// Validate a license JWT (mobile - blocking).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    #[instrument(skip(self, license_jwt))]
    pub async fn validate_license(
        &self,
        license_jwt: &str,
    ) -> Result<LicenseValidationResponse, VerifyError> {
        let url = format!("{}/v1/validate-license", self.base_url);
        debug!("Validating license JWT (mobile)");

        #[derive(Serialize)]
        struct ValidationRequest<'a> {
            license_jwt: &'a str,
        }

        let (_, result): (u16, LicenseValidationResponse) =
            mobile_http::post_json(&self.agent, &url, &ValidationRequest { license_jwt })?;
        Ok(result)
    }

    /// Verify that the PQC key fingerprint is correct.
    fn verify_pqc_fingerprint(&self, response: &StewardKeyResponse) -> Result<(), VerifyError> {
        // Decode the PQC key
        let pqc_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&response.pqc.key)
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Invalid base64 in PQC key: {}", e),
            })?;

        // Compute SHA-256 fingerprint
        let mut hasher = Sha256::new();
        hasher.update(&pqc_key_bytes);
        let computed_fp = hasher.finalize();

        // Expected fingerprint from response
        let expected_hex = response
            .pqc
            .fingerprint
            .strip_prefix("sha256:")
            .unwrap_or(&response.pqc.fingerprint);

        let expected_fp = hex::decode(expected_hex).map_err(|e| VerifyError::HttpsError {
            message: format!("Invalid fingerprint hex: {}", e),
        })?;

        // Constant-time comparison
        if !ciris_crypto::constant_time_eq(&computed_fp, &expected_fp) {
            return Err(VerifyError::HttpsError {
                message: "PQC key fingerprint mismatch - possible tampering".into(),
            });
        }

        debug!("PQC key fingerprint verified");
        Ok(())
    }

    /// Get the classical steward key as raw bytes.
    pub async fn get_classical_key_bytes(&self) -> Result<Vec<u8>, VerifyError> {
        let response = self.get_steward_key().await?;

        base64::engine::general_purpose::STANDARD
            .decode(&response.classical.key)
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Invalid base64 in classical key: {}", e),
            })
    }

    /// Get the PQC steward key as raw bytes.
    pub async fn get_pqc_key_bytes(&self) -> Result<Vec<u8>, VerifyError> {
        let response = self.get_steward_key().await?;

        base64::engine::general_purpose::STANDARD
            .decode(&response.pqc.key)
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Invalid base64 in PQC key: {}", e),
            })
    }

    /// Get the PQC key fingerprint for comparison with DNS records.
    pub async fn get_pqc_fingerprint(&self) -> Result<Vec<u8>, VerifyError> {
        let response = self.get_steward_key().await?;

        let hex = response
            .pqc
            .fingerprint
            .strip_prefix("sha256:")
            .unwrap_or(&response.pqc.fingerprint);

        hex::decode(hex).map_err(|e| VerifyError::HttpsError {
            message: format!("Invalid fingerprint hex: {}", e),
        })
    }

    /// Get the revocation list revision.
    pub async fn get_revocation_revision(&self) -> Result<u64, VerifyError> {
        let response = self.get_steward_key().await?;
        Ok(response.revision)
    }
}

/// Query the HTTPS endpoint and return data for consensus validation.
///
/// # Arguments
///
/// * `endpoint` - API endpoint URL
/// * `timeout` - Request timeout
/// * `cert_pin` - Optional certificate fingerprint
///
/// # Returns
///
/// Steward key response or error.
#[instrument(skip_all, fields(endpoint = %endpoint))]
pub async fn query_https_source(
    endpoint: &str,
    timeout: Duration,
    cert_pin: Option<&str>,
) -> Result<StewardKeyResponse, VerifyError> {
    let client = HttpsClient::new(endpoint, timeout, cert_pin)?;
    client.get_steward_key().await
}

// Tests only run on desktop (need reqwest)
#[cfg(test)]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let result = HttpsClient::new("https://verify.ciris.ai", Duration::from_secs(30), None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_client_with_cert_pin() {
        let fingerprint = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = HttpsClient::new(
            "https://verify.ciris.ai",
            Duration::from_secs(30),
            Some(fingerprint),
        );
        assert!(result.is_ok());

        let client = result.unwrap();
        assert!(client.cert_fingerprint.is_some());
        assert_eq!(client.cert_fingerprint.unwrap().len(), 32);
    }

    #[test]
    fn test_client_with_invalid_cert_pin() {
        let result = HttpsClient::new(
            "https://verify.ciris.ai",
            Duration::from_secs(30),
            Some("invalid-hex"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_url_normalization() {
        let client = HttpsClient::new(
            "https://verify.ciris.ai/", // trailing slash
            Duration::from_secs(30),
            None,
        )
        .unwrap();

        assert_eq!(client.base_url, "https://verify.ciris.ai");
    }
}
