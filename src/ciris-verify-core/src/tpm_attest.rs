//! TPM attestation client for desktop hardware attestation.
//!
//! This provides hardware-rooted device attestation for Linux/Windows
//! systems with TPM 2.0 (firmware or discrete), equivalent to:
//! - Play Integrity on Android
//! - App Attest on iOS
//!
//! ## Flow
//!
//! 1. CIRISVerify generates PCR quote with TPM Attestation Key (AK)
//! 2. Quote contains PCRs 0-7 (boot measurements) signed by AK
//! 3. EK certificate read from TPM NV storage (manufacturer provisioned)
//! 4. CIRISVerify sends quote + AK pubkey + EK cert to registry
//! 5. Registry verifies:
//!    - EK cert chain (TPM manufacturer → root CA)
//!    - Quote signature valid under AK
//!    - PCR values within expected range
//!
//! ## Trust Model
//!
//! TPM attestation proves:
//! - Device has genuine TPM hardware (EK cert)
//! - Boot chain integrity (PCR values)
//! - Key is TPM-resident (AK in quote signature)

use serde::{Deserialize, Serialize};

/// Request to verify TPM attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmAttestVerifyRequest {
    /// PCR quote structure (TPMS_ATTEST serialized, base64).
    pub quoted: String,
    /// Quote signature (ECDSA P-256 over quoted, base64).
    pub signature: String,
    /// PCR selection bitmap (which PCRs were quoted, base64).
    pub pcr_selection: String,
    /// Qualifying data / nonce used in quote (base64).
    pub nonce: String,
    /// Attestation Key public key (ECC P-256, uncompressed, base64).
    pub ak_public_key: String,
    /// EK certificate from TPM NV storage (DER, base64).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ek_cert: Option<String>,
    /// TPM version (e.g., "2.0").
    pub tpm_version: String,
    /// TPM manufacturer (from sysfs, e.g., "STM", "IFX", "INTC").
    pub manufacturer: String,
    /// Whether TPM is discrete (dedicated chip) vs firmware (fTPM).
    pub discrete: bool,
}

/// TPM verification result from registry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TpmAttestVerifyResponse {
    /// Overall verification result.
    pub verified: bool,
    /// EK certificate validation result.
    #[serde(default)]
    pub ek_cert_valid: bool,
    /// EK certificate issuer (TPM manufacturer).
    #[serde(default)]
    pub ek_issuer: Option<String>,
    /// Quote signature validation result.
    #[serde(default)]
    pub quote_valid: bool,
    /// Nonce matches what was requested.
    #[serde(default)]
    pub nonce_valid: bool,
    /// PCR values assessment.
    #[serde(default)]
    pub pcr_assessment: PcrAssessment,
    /// Detailed error message if verification failed.
    #[serde(default)]
    pub error: Option<String>,
    /// Risk indicators (similar to Play Integrity verdicts).
    #[serde(default)]
    pub risk_signals: TpmRiskSignals,
}

/// PCR assessment from registry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PcrAssessment {
    /// PCRs that were checked.
    #[serde(default)]
    pub pcrs_checked: Vec<u8>,
    /// Whether PCR values are within expected range.
    #[serde(default)]
    pub pcrs_acceptable: bool,
    /// Specific PCR concerns (e.g., "PCR7 unexpected value").
    #[serde(default)]
    pub concerns: Vec<String>,
}

/// Risk signals from TPM attestation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TpmRiskSignals {
    /// Firmware TPM (less secure than discrete).
    #[serde(default)]
    pub is_firmware_tpm: bool,
    /// Running in VM (virtualized TPM).
    #[serde(default)]
    pub is_virtual_tpm: bool,
    /// Unknown TPM manufacturer.
    #[serde(default)]
    pub unknown_manufacturer: bool,
    /// Debug mode enabled (PCR7 indicates debug).
    #[serde(default)]
    pub debug_mode: bool,
}

impl TpmAttestVerifyResponse {
    /// Human-readable summary of the verification result.
    pub fn summary(&self) -> String {
        if self.verified {
            let mut details = vec!["TPM attestation verified"];
            if self.ek_cert_valid {
                if let Some(ref issuer) = self.ek_issuer {
                    details.push(issuer.as_str());
                }
            }
            if self.risk_signals.is_firmware_tpm {
                details.push("fTPM");
            }
            details.join(", ")
        } else {
            format!(
                "TPM attestation failed: {}",
                self.error.as_deref().unwrap_or("unknown error")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpm_verify_request_serialization() {
        let request = TpmAttestVerifyRequest {
            quoted: "AQID".to_string(),
            signature: "BAUG".to_string(),
            pcr_selection: "/w==".to_string(),
            nonce: "CQoL".to_string(),
            ak_public_key: "DAoN".to_string(),
            ek_cert: Some("DQ4P".to_string()),
            tpm_version: "2.0".to_string(),
            manufacturer: "STM".to_string(),
            discrete: false,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("quoted"));
        assert!(json.contains("signature"));
        assert!(json.contains("ak_public_key"));
    }

    #[test]
    fn test_tpm_verify_response_summary() {
        let response = TpmAttestVerifyResponse {
            verified: true,
            ek_cert_valid: true,
            ek_issuer: Some("STMicroelectronics".to_string()),
            quote_valid: true,
            nonce_valid: true,
            pcr_assessment: PcrAssessment::default(),
            error: None,
            risk_signals: TpmRiskSignals {
                is_firmware_tpm: true,
                ..Default::default()
            },
        };

        let summary = response.summary();
        assert!(summary.contains("verified"));
        assert!(summary.contains("STMicroelectronics"));
        assert!(summary.contains("fTPM"));
    }

    #[test]
    fn test_tpm_verify_response_failed_summary() {
        let response = TpmAttestVerifyResponse {
            verified: false,
            error: Some("EK certificate chain invalid".to_string()),
            ..Default::default()
        };

        let summary = response.summary();
        assert!(summary.contains("failed"));
        assert!(summary.contains("EK certificate chain invalid"));
    }
}
