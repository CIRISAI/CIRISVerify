//! TPM quote generation and EK certificate reading.
//!
//! This module handles TPM2_Quote operations for PCR attestation
//! and reading the Endorsement Key (EK) certificate from NV storage.

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use crate::error::KeyringError;

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use tss_esapi::{
    handles::{KeyHandle, NvIndexHandle, TpmHandle},
    interface_types::{algorithm::HashingAlgorithm, resource_handles::NvAuth},
    structures::{Data, HashScheme, PcrSelectionListBuilder, PcrSlot, SignatureScheme},
    traits::Marshall,
    Context,
};

/// TPM quote structure containing PCR attestation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TpmQuote {
    /// The quoted data (TPMS_ATTEST serialized)
    pub quoted: Vec<u8>,
    /// Signature over the quote (ECDSA P-256)
    pub signature: Vec<u8>,
    /// PCR selection bitmap (which PCRs were quoted)
    pub pcr_selection: Vec<u8>,
    /// Nonce used in the quote (for freshness)
    pub nonce: Vec<u8>,
}

/// Generate a TPM quote over PCRs 0-7.
///
/// This quotes PCRs 0-7 (platform configuration registers) which contain
/// measurements of the boot process, firmware, and system configuration.
///
/// # Arguments
///
/// * `context` - TPM context
/// * `ak_handle` - Attestation key handle (must be restricted signing key)
/// * `external_nonce` - Optional external challenge. If None, a random nonce is generated.
///
/// # Returns
///
/// Returns the quote data structure.
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub fn generate_quote(
    context: &mut Context,
    ak_handle: KeyHandle,
    external_nonce: Option<&[u8]>,
) -> Result<TpmQuote, KeyringError> {
    use super::signing::extract_ecdsa_signature;
    use rand_core::{OsRng, RngCore};

    tracing::info!("TPM: generating PCR quote with attestation key");

    // Use external nonce if provided, otherwise generate a fresh one
    let nonce: Vec<u8> = match external_nonce {
        Some(n) => {
            tracing::debug!(nonce_len = n.len(), "TPM: using external nonce");
            n.to_vec()
        },
        None => {
            let mut random_nonce = [0u8; 32];
            OsRng.fill_bytes(&mut random_nonce);
            tracing::debug!("TPM: using generated random nonce");
            random_nonce.to_vec()
        },
    };

    let qualifying_data =
        Data::try_from(nonce.clone()).map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to create qualifying data: {}", e),
        })?;

    // Select PCRs 0-7 (boot measurements) with SHA-256
    let pcr_selection = PcrSelectionListBuilder::new()
        .with_selection(
            HashingAlgorithm::Sha256,
            &[
                PcrSlot::Slot0,
                PcrSlot::Slot1,
                PcrSlot::Slot2,
                PcrSlot::Slot3,
                PcrSlot::Slot4,
                PcrSlot::Slot5,
                PcrSlot::Slot6,
                PcrSlot::Slot7,
            ],
        )
        .build()
        .map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to build PCR selection: {}", e),
        })?;

    // Generate quote using ECDSA with SHA-256 and the ATTESTATION key
    let signing_scheme = SignatureScheme::EcDsa {
        hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
    };

    tracing::debug!(
        pcr_slots = "0-7",
        hash_alg = "SHA-256",
        "TPM: requesting quote with attestation key"
    );

    let (attest, signature) = context
        .execute_with_nullauth_session(|ctx| {
            ctx.quote(
                ak_handle,
                qualifying_data.clone(),
                signing_scheme,
                pcr_selection.clone(),
            )
        })
        .map_err(|e| {
            tracing::error!("TPM: quote generation failed: {}", e);
            KeyringError::HardwareError {
                reason: format!("TPM quote failed: {}", e),
            }
        })?;

    // Serialize the attestation structure using TPM marshalling
    let quoted_bytes: Vec<u8> = attest.marshall().map_err(|e| KeyringError::HardwareError {
        reason: format!("Failed to marshall attestation: {}", e),
    })?;

    // Extract signature bytes
    let sig_bytes = extract_ecdsa_signature(&signature)?;

    // PCR selection as bytes (bitmap representation)
    let pcr_selection_bytes: Vec<u8> = vec![0xFF]; // PCRs 0-7 selected

    tracing::info!(
        quoted_len = quoted_bytes.len(),
        sig_len = sig_bytes.len(),
        "TPM: quote generated successfully"
    );

    Ok(TpmQuote {
        quoted: quoted_bytes,
        signature: sig_bytes,
        pcr_selection: pcr_selection_bytes,
        nonce,
    })
}

/// ECC EK certificate NV index (TCG spec).
/// RSA would be 0x01C00002, but we use ECC P-256.
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub const ECC_EK_CERT_NV_INDEX: u32 = 0x01C0_000A;

/// Read the Endorsement Key (EK) certificate from TPM NV storage.
///
/// EK certificates are provisioned by TPM manufacturers and can be used
/// to verify the TPM is genuine. ECC EK cert is at NV index 0x01C0000A.
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub fn read_ek_certificate(context: &mut Context) -> Result<Vec<u8>, KeyringError> {
    tracing::info!("TPM: reading EK certificate from NV storage");

    // Create TPM handle for NV index
    let tpm_handle = TpmHandle::NvIndex(ECC_EK_CERT_NV_INDEX.try_into().map_err(|e| {
        KeyringError::HardwareError {
            reason: format!("Invalid NV index: {:?}", e),
        }
    })?);

    // Convert TPM handle to ESYS resource handle
    let object_handle = context
        .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
        .map_err(|e| {
            tracing::warn!(
                "TPM: EK cert NV index not found (may not be provisioned): {}",
                e
            );
            KeyringError::HardwareError {
                reason: format!("EK cert NV index not accessible: {}", e),
            }
        })?;

    let nv_index_handle = NvIndexHandle::from(object_handle);

    // Read the NV public to get the size
    let (nv_public, _name) = context
        .execute_without_session(|ctx| ctx.nv_read_public(nv_index_handle))
        .map_err(|e| {
            tracing::warn!("TPM: EK cert NV read public failed: {}", e);
            KeyringError::HardwareError {
                reason: format!("EK cert NV read public failed: {}", e),
            }
        })?;

    let cert_size = nv_public.data_size() as u16;
    tracing::debug!(cert_size = cert_size, "TPM: EK cert NV size");

    if cert_size == 0 {
        return Err(KeyringError::HardwareError {
            reason: "EK certificate NV area is empty".into(),
        });
    }

    // Read the certificate data in chunks (max 1024 bytes per read)
    let mut cert_data = Vec::with_capacity(cert_size as usize);
    let mut offset = 0u16;
    const MAX_NV_READ: u16 = 1024;

    while offset < cert_size {
        let read_size = std::cmp::min(MAX_NV_READ, cert_size.saturating_sub(offset));

        let chunk = context
            .execute_with_nullauth_session(|ctx| {
                ctx.nv_read(NvAuth::Owner, nv_index_handle, read_size, offset)
            })
            .map_err(|e| {
                tracing::error!("TPM: NV read failed at offset {}: {}", offset, e);
                KeyringError::HardwareError {
                    reason: format!("NV read failed: {}", e),
                }
            })?;

        cert_data.extend_from_slice(&chunk);
        offset += read_size;
    }

    tracing::info!(
        cert_len = cert_data.len(),
        "TPM: EK certificate read successfully"
    );

    Ok(cert_data)
}

/// Read PCR values for slots 0-7.
///
/// Returns a map of PCR slot index to SHA-256 digest (32 bytes each).
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub fn read_pcr_values(
    context: &mut Context,
) -> Result<std::collections::HashMap<u8, Vec<u8>>, KeyringError> {
    tracing::info!("TPM: reading PCR values 0-7");

    // Select PCRs 0-7 with SHA-256
    let pcr_selection = PcrSelectionListBuilder::new()
        .with_selection(
            HashingAlgorithm::Sha256,
            &[
                PcrSlot::Slot0,
                PcrSlot::Slot1,
                PcrSlot::Slot2,
                PcrSlot::Slot3,
                PcrSlot::Slot4,
                PcrSlot::Slot5,
                PcrSlot::Slot6,
                PcrSlot::Slot7,
            ],
        )
        .build()
        .map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to build PCR selection: {}", e),
        })?;

    // Read PCR values
    let (_update_counter, _selection_out, digests) = context
        .execute_without_session(|ctx| ctx.pcr_read(pcr_selection))
        .map_err(|e| {
            tracing::error!("TPM: PCR read failed: {}", e);
            KeyringError::HardwareError {
                reason: format!("PCR read failed: {}", e),
            }
        })?;

    // Convert to map
    let mut pcr_map = std::collections::HashMap::new();
    for (i, digest) in digests.value().iter().enumerate() {
        pcr_map.insert(i as u8, digest.value().to_vec());
    }

    tracing::info!(
        pcr_count = pcr_map.len(),
        "TPM: PCR values read successfully"
    );

    Ok(pcr_map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpm_quote_serialization() {
        let quote = TpmQuote {
            quoted: vec![1, 2, 3, 4],
            signature: vec![5, 6, 7, 8],
            pcr_selection: vec![0xFF],
            nonce: vec![9, 10, 11, 12],
        };

        // Test serialization roundtrip
        let json = serde_json::to_string(&quote).unwrap();
        let deserialized: TpmQuote = serde_json::from_str(&json).unwrap();

        assert_eq!(quote.quoted, deserialized.quoted);
        assert_eq!(quote.signature, deserialized.signature);
        assert_eq!(quote.pcr_selection, deserialized.pcr_selection);
        assert_eq!(quote.nonce, deserialized.nonce);
    }

    #[test]
    fn test_tpm_quote_debug() {
        let quote = TpmQuote {
            quoted: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            pcr_selection: vec![0xFF],
            nonce: vec![7, 8, 9],
        };

        // Debug should not panic
        let debug_str = format!("{:?}", quote);
        assert!(debug_str.contains("TpmQuote"));
    }

    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    #[test]
    fn test_ek_cert_nv_index_constant() {
        // ECC EK cert is at TCG-specified index
        assert_eq!(ECC_EK_CERT_NV_INDEX, 0x01C0_000A);
    }
}
