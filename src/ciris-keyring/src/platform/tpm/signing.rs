//! TPM signing operations and helpers.
//!
//! This module contains helpers for TPM signing operations,
//! including ECDSA signature extraction.

use crate::error::KeyringError;

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use tss_esapi::structures::Signature;

/// Extract ECDSA signature bytes from TPM Signature structure.
///
/// Returns signature in raw format: r (32 bytes) || s (32 bytes)
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub fn extract_ecdsa_signature(signature: &Signature) -> Result<Vec<u8>, KeyringError> {
    match signature {
        Signature::EcDsa(ecdsa_sig) => {
            // Get raw bytes from EccParameter using value() method
            let r_bytes: Vec<u8> = ecdsa_sig.signature_r().value().to_vec();
            let s_bytes: Vec<u8> = ecdsa_sig.signature_s().value().to_vec();

            let mut sig = Vec::with_capacity(64);

            // Pad r to 32 bytes
            if r_bytes.len() < 32 {
                sig.extend(std::iter::repeat(0u8).take(32 - r_bytes.len()));
            }
            sig.extend(&r_bytes[r_bytes.len().saturating_sub(32)..]);

            // Pad s to 32 bytes
            if s_bytes.len() < 32 {
                sig.extend(std::iter::repeat(0u8).take(32 - s_bytes.len()));
            }
            sig.extend(&s_bytes[s_bytes.len().saturating_sub(32)..]);

            Ok(sig)
        }
        _ => Err(KeyringError::HardwareError {
            reason: "Unexpected signature type from TPM".into(),
        }),
    }
}

/// Create a null validation ticket for signing external data.
///
/// TPM signing of external (non-TPM-generated) data requires a validation
/// ticket with TPM2_RH_NULL hierarchy.
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub fn create_null_validation_ticket(
) -> Result<tss_esapi::structures::HashcheckTicket, KeyringError> {
    tss_esapi::structures::HashcheckTicket::try_from(tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
        tag: tss_esapi::constants::tss::TPM2_ST_HASHCHECK,
        hierarchy: tss_esapi::constants::tss::TPM2_RH_NULL,
        digest: tss_esapi::tss2_esys::TPM2B_DIGEST {
            size: 0,
            buffer: [0; 64],
        },
    })
    .map_err(|e| KeyringError::HardwareError {
        reason: format!("Failed to create validation ticket: {}", e),
    })
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    use super::*;

    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    #[test]
    fn test_create_null_validation_ticket() {
        let result = create_null_validation_ticket();
        assert!(result.is_ok(), "Failed to create null validation ticket");
    }
}
