//! Google Play Integrity client for Android hardware attestation.
//!
//! This is a third-party attestation that adds trust but is NOT required.
//! When available, it provides Google's hardware-backed device integrity
//! verification for Android devices.
//!
//! ## Flow
//!
//! 1. CIRISVerify calls `get_nonce()` to get a challenge from registry
//! 2. Android app passes nonce to Play Integrity API
//! 3. Play Integrity returns encrypted token
//! 4. CIRISVerify calls `verify_token()` with token + nonce
//! 5. Registry decrypts via Google API and returns verdict
//!
//! ## Trust Model
//!
//! This attestation is ADVISORY - it upgrades trust level when available
//! but CIRISVerify still functions without it. A compromised Google account
//! or Play Integrity service doesn't compromise the core verification.

use serde::{Deserialize, Serialize};

/// Nonce response from registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityNonce {
    /// Base64 URL-safe encoded nonce.
    pub nonce: String,
    /// ISO 8601 expiration timestamp.
    pub expires_at: String,
}

/// Request to verify a Play Integrity token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityVerifyRequest {
    /// Encrypted token from Play Integrity API.
    pub integrity_token: String,
    /// Nonce used when requesting the token.
    pub nonce: String,
}

/// Device integrity verdicts from Google.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceIntegrity {
    /// Device passes strong integrity (hardware-backed, locked bootloader).
    #[serde(default)]
    pub meets_strong_integrity: bool,
    /// Device passes device integrity (genuine device).
    #[serde(default)]
    pub meets_device_integrity: bool,
    /// Device passes basic integrity (may be rooted but not emulated).
    #[serde(default)]
    pub meets_basic_integrity: bool,
    /// Raw verdict strings from Google.
    #[serde(default)]
    pub verdicts: Vec<String>,
}

/// App integrity verdict from Google.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppIntegrity {
    /// Verdict: PLAY_RECOGNIZED, UNRECOGNIZED_VERSION, UNEVALUATED.
    #[serde(default)]
    pub verdict: String,
    /// Package name verified.
    #[serde(default)]
    pub package_name: Option<String>,
    /// App version code.
    #[serde(default)]
    pub version_code: Option<i64>,
}

/// Account licensing verdict.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountDetails {
    /// LICENSED, UNLICENSED, or UNEVALUATED.
    #[serde(default)]
    pub licensing_verdict: String,
}

/// Response from Play Integrity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityVerifyResponse {
    /// Overall verification passed.
    pub verified: bool,
    /// Device integrity details.
    #[serde(default)]
    pub device_integrity: Option<DeviceIntegrity>,
    /// App integrity details.
    #[serde(default)]
    pub app_integrity: Option<AppIntegrity>,
    /// Account details.
    #[serde(default)]
    pub account_details: Option<AccountDetails>,
    /// Error message if verification failed.
    #[serde(default)]
    pub error: Option<String>,
}

impl IntegrityVerifyResponse {
    /// Check if device has hardware-backed integrity.
    pub fn has_hardware_integrity(&self) -> bool {
        self.device_integrity
            .as_ref()
            .map(|d| d.meets_strong_integrity || d.meets_device_integrity)
            .unwrap_or(false)
    }

    /// Check if app is recognized by Play Store.
    pub fn is_play_recognized(&self) -> bool {
        self.app_integrity
            .as_ref()
            .map(|a| a.verdict == "PLAY_RECOGNIZED")
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
            .device_integrity
            .as_ref()
            .map(|d| {
                if d.meets_strong_integrity {
                    "STRONG"
                } else if d.meets_device_integrity {
                    "DEVICE"
                } else if d.meets_basic_integrity {
                    "BASIC"
                } else {
                    "NONE"
                }
            })
            .unwrap_or("N/A");

        let app = self
            .app_integrity
            .as_ref()
            .map(|a| a.verdict.as_str())
            .unwrap_or("N/A");

        format!("OK device={} app={}", device, app)
    }
}

/// Result type for Play Integrity operations.
pub type Result<T> = std::result::Result<T, PlayIntegrityError>;

/// Play Integrity errors.
#[derive(Debug, Clone)]
pub enum PlayIntegrityError {
    /// Registry not reachable.
    NetworkError(String),
    /// Registry returned error.
    RegistryError(String),
    /// Play Integrity not configured on registry.
    NotConfigured,
    /// Nonce expired or invalid.
    NonceInvalid(String),
    /// Token verification failed.
    VerificationFailed(String),
}

impl std::fmt::Display for PlayIntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkError(msg) => write!(f, "network error: {}", msg),
            Self::RegistryError(msg) => write!(f, "registry error: {}", msg),
            Self::NotConfigured => write!(f, "Play Integrity not configured on registry"),
            Self::NonceInvalid(msg) => write!(f, "nonce invalid: {}", msg),
            Self::VerificationFailed(msg) => write!(f, "verification failed: {}", msg),
        }
    }
}

impl std::error::Error for PlayIntegrityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_response_summary() {
        let response = IntegrityVerifyResponse {
            verified: true,
            device_integrity: Some(DeviceIntegrity {
                meets_strong_integrity: true,
                meets_device_integrity: true,
                meets_basic_integrity: true,
                verdicts: vec!["MEETS_STRONG_INTEGRITY".into()],
            }),
            app_integrity: Some(AppIntegrity {
                verdict: "PLAY_RECOGNIZED".into(),
                package_name: Some("ai.ciris.mobile".into()),
                version_code: Some(1),
            }),
            account_details: None,
            error: None,
        };

        assert!(response.has_hardware_integrity());
        assert!(response.is_play_recognized());
        assert_eq!(response.summary(), "OK device=STRONG app=PLAY_RECOGNIZED");
    }

    #[test]
    fn test_failed_response() {
        let response = IntegrityVerifyResponse {
            verified: false,
            device_integrity: None,
            app_integrity: None,
            account_details: None,
            error: Some("Nonce expired".into()),
        };

        assert!(!response.has_hardware_integrity());
        assert_eq!(response.summary(), "FAILED: Nonce expired");
    }
}
