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

    /// Convert this TPM attestation result into the
    /// `federation_provenance` scalar-attestation surface (v3.2.0+).
    /// Emits one `attestation:l2:hardware` entry — `PASS` iff every
    /// sub-check held: `verified` AND `ek_cert_valid` (EK cert chains
    /// to a recognized manufacturer CA) AND `quote_valid` (TPMS_ATTEST
    /// signature verifies against AK) AND `nonce_valid` (qualifying
    /// data matches the requested challenge) AND
    /// `pcr_assessment.pcrs_acceptable` (PCR digests within expected
    /// range). CIRISVerify#34 wiring.
    ///
    /// `attester` is whoever did the chain validation — typically the
    /// registry's identity / URL.
    #[must_use]
    pub fn to_attestation_entries(
        &self,
        attester: &str,
    ) -> Vec<crate::federation_provenance::AttestationEntry> {
        use crate::federation_provenance::{dim, AttestationEntry, Score};
        let l2_ok = self.verified
            && self.ek_cert_valid
            && self.quote_valid
            && self.nonce_valid
            && self.pcr_assessment.pcrs_acceptable;
        vec![AttestationEntry::new(
            dim::L2_HARDWARE,
            if l2_ok { Score::PASS } else { Score::FAIL },
            attester,
        )]
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

    #[test]
    fn to_attestation_entries_pass_on_all_subchecks() {
        let response = TpmAttestVerifyResponse {
            verified: true,
            ek_cert_valid: true,
            ek_issuer: Some("Infineon".into()),
            quote_valid: true,
            nonce_valid: true,
            pcr_assessment: PcrAssessment {
                pcrs_checked: vec![0, 1, 2, 7],
                pcrs_acceptable: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let entries = response.to_attestation_entries("registry-steward-us");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dimension, "attestation:l2:hardware");
        assert_eq!(entries[0].score, 1.0);
    }

    #[test]
    fn to_attestation_entries_fail_on_pcr_drift() {
        // EK + quote + nonce all good, but PCRs don't match the
        // expected measurement → L2 fails.
        let response = TpmAttestVerifyResponse {
            verified: true,
            ek_cert_valid: true,
            ek_issuer: Some("Infineon".into()),
            quote_valid: true,
            nonce_valid: true,
            pcr_assessment: PcrAssessment {
                pcrs_checked: vec![0, 1, 2, 7],
                pcrs_acceptable: false, // unexpected PCR values
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(response.to_attestation_entries("registry")[0].score, 0.0);
    }

    #[test]
    fn to_attestation_entries_fail_on_ek_cert_invalid() {
        let response = TpmAttestVerifyResponse {
            verified: false,
            ek_cert_valid: false, // EK doesn't chain to a manufacturer CA
            quote_valid: true,
            nonce_valid: true,
            pcr_assessment: PcrAssessment {
                pcrs_acceptable: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(response.to_attestation_entries("registry")[0].score, 0.0);
    }
}
