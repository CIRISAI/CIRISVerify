//! TPM key creation and management.
//!
//! This module handles creating the three key types used by TpmSigner:
//! - Primary key (restricted storage key)
//! - Signing key (non-restricted, for arbitrary data)
//! - Attestation key (restricted, for TPM quotes)

use crate::error::KeyringError;

#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        resource_handles::Hierarchy,
    },
    structures::{
        EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, Public, PublicBuilder,
        PublicEccParametersBuilder, SymmetricDefinitionObject,
    },
    Context,
};

/// Create the primary storage key under the Owner hierarchy.
///
/// This is a restricted storage key (decrypt=true, restricted=true) that
/// protects child keys with AES-128-CFB encryption.
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub fn get_or_create_primary(context: &mut Context) -> Result<KeyHandle, KeyringError> {
    tracing::debug!("TPM: creating primary key under owner hierarchy");

    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()
        .map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to build object attributes: {}", e),
        })?;

    // Primary key is a restricted storage key (decrypt=true, restricted=true)
    // Must set these flags on the ECC builder to match ObjectAttributes for validation
    let ecc_params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .with_is_signing_key(false)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .build()
        .map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to build ECC parameters: {}", e),
        })?;

    let primary_public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to build primary public: {}", e),
        })?;

    let result = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, primary_public.clone(), None, None, None, None)
        })
        .map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to create primary key: {}", e),
        })?;

    tracing::info!("TPM: created primary key");
    Ok(result.key_handle)
}

/// Create a non-restricted signing key under the primary key.
///
/// This key can sign arbitrary external data using ECDSA P-256.
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub fn create_signing_key(
    context: &mut Context,
    primary_handle: KeyHandle,
) -> Result<KeyHandle, KeyringError> {
    tracing::debug!("TPM: creating signing key under primary");

    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .build()
        .map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to build signing key attributes: {}", e),
        })?;

    // Signing key is non-restricted (for signing arbitrary data)
    // Must set flags on ECC builder to match ObjectAttributes for validation
    let ecc_params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_symmetric(SymmetricDefinitionObject::Null)
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(false)
        .build()
        .map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to build signing key ECC parameters: {}", e),
        })?;

    let signing_public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to build signing key public: {}", e),
        })?;

    let result = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create(primary_handle, signing_public.clone(), None, None, None, None)
        })
        .map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to create signing key: {}", e),
        })?;

    let key_handle = context
        .execute_with_nullauth_session(|ctx| {
            ctx.load(
                primary_handle,
                result.out_private.clone(),
                result.out_public.clone(),
            )
        })
        .map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to load signing key: {}", e),
        })?;

    tracing::info!("TPM: created and loaded signing key");
    Ok(key_handle)
}

/// Create a restricted attestation key (AK) for TPM quotes.
///
/// Restricted keys can only sign TPM-generated data (quotes, certify, etc).
/// This is required for TPM2_Quote operations.
///
/// Returns the key handle and the public key bytes (uncompressed SEC1 format).
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub fn create_attestation_key(
    context: &mut Context,
    primary_handle: KeyHandle,
) -> Result<(KeyHandle, Vec<u8>), KeyringError> {
    tracing::info!("TPM: === CREATING ATTESTATION KEY (AK) ===");

    // Match tss-esapi's create_ak_public() pattern exactly:
    // - restricted = true: Can only sign TPM-generated data
    // - sign_encrypt = true: For signing quotes
    // - decrypt = false: Explicitly set (required for validation)
    // - fixed_tpm = true: Cannot be duplicated
    // - fixed_parent = true: Bound to this parent
    let object_attributes = ObjectAttributesBuilder::new()
        .with_restricted(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_decrypt(false)
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .build()
        .map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to build AK attributes: {}", e),
        })?;

    // Attestation key is a restricted signing key (for TPM quotes)
    // Must set flags on ECC builder to match ObjectAttributes for validation
    tracing::info!("TPM: AK - building ECC parameters (restricted signing key)");
    let ecc_params = PublicEccParametersBuilder::new()
        .with_symmetric(SymmetricDefinitionObject::Null)
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(true)
        .build()
        .map_err(|e| {
            tracing::error!("TPM: AK ECC params build FAILED: {}", e);
            KeyringError::HardwareError {
                reason: format!("Failed to build AK ECC parameters: {}", e),
            }
        })?;
    tracing::info!("TPM: AK - ECC parameters built successfully");

    let ak_public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to build AK public: {}", e),
        })?;

    tracing::info!("TPM: AK - calling context.create()");
    let result = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create(primary_handle, ak_public.clone(), None, None, None, None)
        })
        .map_err(|e| {
            tracing::error!("TPM: AK context.create() FAILED: {}", e);
            KeyringError::HardwareError {
                reason: format!("Failed to create AK: {}", e),
            }
        })?;
    tracing::info!("TPM: AK - context.create() succeeded");

    let key_handle = context
        .execute_with_nullauth_session(|ctx| {
            ctx.load(
                primary_handle,
                result.out_private.clone(),
                result.out_public.clone(),
            )
        })
        .map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to load AK: {}", e),
        })?;

    // Extract public key bytes for export
    let public_key_bytes = extract_public_key_from_public(&result.out_public)?;

    tracing::info!(
        ak_pubkey_len = public_key_bytes.len(),
        "TPM: created and loaded attestation key (AK)"
    );
    Ok((key_handle, public_key_bytes))
}

/// Extract public key bytes from TPM Public structure.
///
/// Returns the public key in uncompressed SEC1 format: 0x04 || X (32 bytes) || Y (32 bytes)
#[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
pub fn extract_public_key_from_public(public: &Public) -> Result<Vec<u8>, KeyringError> {
    let ecc_point = match public {
        Public::Ecc { unique, .. } => unique,
        _ => {
            return Err(KeyringError::HardwareError {
                reason: "Expected ECC public key".into(),
            })
        }
    };

    let x_bytes: Vec<u8> = ecc_point.x().value().to_vec();
    let y_bytes: Vec<u8> = ecc_point.y().value().to_vec();

    // Uncompressed SEC1 format: 0x04 || X (32 bytes) || Y (32 bytes)
    let mut pubkey = Vec::with_capacity(65);
    pubkey.push(0x04);

    // Pad x to 32 bytes
    if x_bytes.len() < 32 {
        pubkey.extend(std::iter::repeat(0u8).take(32 - x_bytes.len()));
    }
    pubkey.extend(&x_bytes[x_bytes.len().saturating_sub(32)..]);

    // Pad y to 32 bytes
    if y_bytes.len() < 32 {
        pubkey.extend(std::iter::repeat(0u8).take(32 - y_bytes.len()));
    }
    pubkey.extend(&y_bytes[y_bytes.len().saturating_sub(32)..]);

    Ok(pubkey)
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    use super::*;

    /// Test that key creation functions exist and have correct signatures.
    /// Actual TPM operations require hardware - see examples/tpm_attest.rs.
    #[cfg(all(feature = "tpm", any(target_os = "linux", target_os = "windows")))]
    #[test]
    fn test_key_functions_compile() {
        // This test verifies the module compiles correctly.
        // Actual TPM tests require hardware and are in examples/tpm_attest.rs

        // Verify function signatures by reference (no-op)
        let _: fn(&mut Context) -> Result<KeyHandle, KeyringError> = get_or_create_primary;
        let _: fn(&mut Context, KeyHandle) -> Result<KeyHandle, KeyringError> = create_signing_key;
        let _: fn(&mut Context, KeyHandle) -> Result<(KeyHandle, Vec<u8>), KeyringError> =
            create_attestation_key;
    }
}
