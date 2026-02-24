//! Apple App Attest client for iOS hardware attestation.
//!
//! This is a third-party attestation that adds trust but is NOT required.
//! When available, it provides Apple's hardware-backed device integrity
//! verification for iOS devices via DCAppAttestService.
//!
//! ## Flow
//!
//! 1. CIRISVerify calls `get_nonce()` to get a challenge from registry
//! 2. iOS app passes nonce to DCAppAttestService (attest_key_sync)
//! 3. App Attest returns CBOR attestation object
//! 4. CIRISVerify calls `verify_attestation()` with attestation + key_id + nonce
//! 5. Registry verifies attestation format (Apple certificate chain + receipt)
//!
//! ## Assertion Flow (post-attestation)
//!
//! After initial attestation, ongoing requests use assertions:
//! 1. CIRISVerify calls `get_nonce()` for a fresh challenge
//! 2. iOS app calls `generateAssertion(_:clientDataHash:)` on DCAppAttestService
//! 3. CIRISVerify calls `verify_assertion()` with assertion + key_id + nonce
//! 4. Registry verifies the assertion signature and counter
//!
//! ## Trust Model
//!
//! This attestation is ADVISORY - it upgrades trust level when available
//! but CIRISVerify still functions without it. Apple's attestation proves
//! the app runs on genuine Apple hardware with an unmodified app binary.

use serde::{Deserialize, Serialize};

/// Nonce response from registry for App Attest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAttestNonce {
    /// Base64 URL-safe encoded nonce.
    pub nonce: String,
    /// ISO 8601 expiration timestamp.
    pub expires_at: String,
}

/// Request to verify an App Attest attestation object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAttestVerifyRequest {
    /// CBOR-encoded attestation object from DCAppAttestService (base64).
    pub attestation: String,
    /// Key ID from DCAppAttestService.generateKey().
    pub key_id: String,
    /// Nonce used when requesting the attestation.
    pub nonce: String,
}

/// Device environment from Apple attestation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceEnvironment {
    /// Environment: "production" or "development".
    #[serde(default)]
    pub environment: String,
    /// Whether the device is genuine Apple hardware.
    #[serde(default)]
    pub is_genuine_device: bool,
    /// Whether the app binary is unmodified.
    #[serde(default)]
    pub is_unmodified_app: bool,
}

/// App identity from Apple attestation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppIdentity {
    /// App ID (team_id.bundle_id).
    #[serde(default)]
    pub app_id: Option<String>,
    /// Team ID from certificate.
    #[serde(default)]
    pub team_id: Option<String>,
    /// Bundle ID.
    #[serde(default)]
    pub bundle_id: Option<String>,
}

/// Receipt from Apple attestation (for fraud risk assessment).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttestationReceipt {
    /// Receipt type.
    #[serde(default)]
    pub receipt_type: String,
    /// Risk metric (0-100, lower is better).
    #[serde(default)]
    pub risk_metric: Option<u32>,
    /// ISO 8601 creation date.
    #[serde(default)]
    pub creation_date: Option<String>,
}

/// Response from App Attest attestation verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAttestVerifyResponse {
    /// Overall verification passed.
    pub verified: bool,
    /// Device environment details.
    #[serde(default)]
    pub device_environment: Option<DeviceEnvironment>,
    /// App identity details.
    #[serde(default)]
    pub app_identity: Option<AppIdentity>,
    /// Attestation receipt.
    #[serde(default)]
    pub receipt: Option<AttestationReceipt>,
    /// Error message if verification failed.
    #[serde(default)]
    pub error: Option<String>,
}

impl AppAttestVerifyResponse {
    /// Check if device has genuine Apple hardware attestation.
    pub fn has_genuine_device(&self) -> bool {
        self.device_environment
            .as_ref()
            .map(|d| d.is_genuine_device)
            .unwrap_or(false)
    }

    /// Check if app binary is verified unmodified.
    pub fn is_unmodified_app(&self) -> bool {
        self.device_environment
            .as_ref()
            .map(|d| d.is_unmodified_app)
            .unwrap_or(false)
    }

    /// Check if running in production environment.
    pub fn is_production(&self) -> bool {
        self.device_environment
            .as_ref()
            .map(|d| d.environment == "production")
            .unwrap_or(false)
    }

    /// Get a summary string for logging.
    pub fn summary(&self) -> String {
        if !self.verified {
            return format!(
                "FAILED: {}",
                self.error.as_deref().unwrap_or("unknown error")
            );
        }

        let device = self
            .device_environment
            .as_ref()
            .map(|d| {
                if d.is_genuine_device && d.is_unmodified_app {
                    "GENUINE+UNMODIFIED"
                } else if d.is_genuine_device {
                    "GENUINE"
                } else {
                    "UNVERIFIED"
                }
            })
            .unwrap_or("N/A");

        let env = self
            .device_environment
            .as_ref()
            .map(|d| d.environment.as_str())
            .unwrap_or("N/A");

        format!("OK device={} env={}", device, env)
    }
}

/// Request to verify an App Attest assertion (post-attestation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAttestAssertionRequest {
    /// Assertion bytes from DCAppAttestService (base64).
    pub assertion: String,
    /// Key ID (same as initial attestation).
    pub key_id: String,
    /// Client data that was signed.
    pub client_data: String,
    /// Nonce used for this assertion.
    pub nonce: String,
}

/// Response from App Attest assertion verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAttestAssertionResponse {
    /// Assertion verified successfully.
    pub verified: bool,
    /// Monotonic counter value (detects replayed assertions).
    #[serde(default)]
    pub counter: Option<u64>,
    /// Error message if verification failed.
    #[serde(default)]
    pub error: Option<String>,
}

/// Result type for App Attest operations.
pub type Result<T> = std::result::Result<T, AppAttestError>;

/// App Attest errors.
#[derive(Debug, Clone)]
pub enum AppAttestError {
    /// Registry not reachable.
    NetworkError(String),
    /// Registry returned error.
    RegistryError(String),
    /// App Attest not configured on registry.
    NotConfigured,
    /// Nonce expired or invalid.
    NonceInvalid(String),
    /// Attestation verification failed.
    AttestationFailed(String),
    /// Assertion verification failed.
    AssertionFailed(String),
    /// App Attest not supported on this device.
    NotSupported,
}

impl std::fmt::Display for AppAttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkError(msg) => write!(f, "network error: {}", msg),
            Self::RegistryError(msg) => write!(f, "registry error: {}", msg),
            Self::NotConfigured => write!(f, "App Attest not configured on registry"),
            Self::NonceInvalid(msg) => write!(f, "nonce invalid: {}", msg),
            Self::AttestationFailed(msg) => write!(f, "attestation failed: {}", msg),
            Self::AssertionFailed(msg) => write!(f, "assertion failed: {}", msg),
            Self::NotSupported => write!(f, "App Attest not supported on this device"),
        }
    }
}

impl std::error::Error for AppAttestError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_response_summary() {
        let response = AppAttestVerifyResponse {
            verified: true,
            device_environment: Some(DeviceEnvironment {
                environment: "production".into(),
                is_genuine_device: true,
                is_unmodified_app: true,
            }),
            app_identity: Some(AppIdentity {
                app_id: Some("TEAMID.ai.ciris.mobile".into()),
                team_id: Some("TEAMID".into()),
                bundle_id: Some("ai.ciris.mobile".into()),
            }),
            receipt: None,
            error: None,
        };

        assert!(response.has_genuine_device());
        assert!(response.is_unmodified_app());
        assert!(response.is_production());
        assert_eq!(
            response.summary(),
            "OK device=GENUINE+UNMODIFIED env=production"
        );
    }

    #[test]
    fn test_failed_response() {
        let response = AppAttestVerifyResponse {
            verified: false,
            device_environment: None,
            app_identity: None,
            receipt: None,
            error: Some("Invalid attestation object".into()),
        };

        assert!(!response.has_genuine_device());
        assert!(!response.is_unmodified_app());
        assert!(!response.is_production());
        assert_eq!(response.summary(), "FAILED: Invalid attestation object");
    }

    #[test]
    fn test_development_environment() {
        let response = AppAttestVerifyResponse {
            verified: true,
            device_environment: Some(DeviceEnvironment {
                environment: "development".into(),
                is_genuine_device: true,
                is_unmodified_app: false,
            }),
            app_identity: None,
            receipt: None,
            error: None,
        };

        assert!(response.has_genuine_device());
        assert!(!response.is_unmodified_app());
        assert!(!response.is_production());
        assert_eq!(response.summary(), "OK device=GENUINE env=development");
    }

    #[test]
    fn test_assertion_response_serialization() {
        let json = r#"{
            "verified": true,
            "counter": 42,
            "error": null
        }"#;

        let response: AppAttestAssertionResponse = serde_json::from_str(json).unwrap();
        assert!(response.verified);
        assert_eq!(response.counter, Some(42));
        assert!(response.error.is_none());
    }

    #[test]
    fn test_nonce_serialization() {
        let nonce = AppAttestNonce {
            nonce: "dGVzdF9ub25jZQ".to_string(),
            expires_at: "2026-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&nonce).unwrap();
        let parsed: AppAttestNonce = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.nonce, "dGVzdF9ub25jZQ");
    }

    #[test]
    fn test_verify_request_serialization() {
        let request = AppAttestVerifyRequest {
            attestation: "base64_attestation".to_string(),
            key_id: "test_key_id".to_string(),
            nonce: "test_nonce".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"attestation\""));
        assert!(json.contains("key_id"));
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            AppAttestError::NotSupported.to_string(),
            "App Attest not supported on this device"
        );
        assert_eq!(
            AppAttestError::NotConfigured.to_string(),
            "App Attest not configured on registry"
        );
        assert_eq!(
            AppAttestError::AttestationFailed("bad cert".into()).to_string(),
            "attestation failed: bad cert"
        );
    }
}
