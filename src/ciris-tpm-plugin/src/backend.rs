//! The TPM backend behind the plugin's C ABI.
//!
//! Two implementations selected by cfg:
//! - **real** (`feature = "real"` on glibc-linux / windows): links `tss-esapi`
//!   and performs the actual TPM 2.0 operations. The seal/unseal logic is a
//!   faithful port of `ciris_keyring::storage::tpm` (SRK-parented `KeyedHash`
//!   sealing object), made **pure** — no file I/O; the keyring keeps
//!   persistence. The sealed blob is `u32_le(private_len) ‖ private ‖ public`,
//!   opaque to the caller.
//! - **stub** (everything else, incl. cross-musl): every op reports
//!   "unavailable" / "not implemented" so the crate builds with no `tss-esapi`.

#[cfg(all(
    feature = "real",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
))]
mod imp {
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        handles::KeyHandle,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm},
            ecc::EccCurve,
            key_bits::AesKeyBits,
            resource_handles::Hierarchy,
        },
        structures::{
            EccPoint, EccScheme, KeyDerivationFunctionScheme, KeyedHashScheme, Private, Public,
            PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData,
            SymmetricDefinitionObject,
        },
        tcti_ldr::TctiNameConf,
        traits::{Marshall, UnMarshall},
        Context,
    };

    /// Open an ESYS context over the platform TCTI (Linux device / Windows TBS).
    /// Ported from `ciris_keyring::platform::tpm::create_context`.
    fn create_context() -> Result<Context, String> {
        #[cfg(target_os = "linux")]
        let tcti = {
            use std::str::FromStr;
            use tss_esapi::tcti_ldr::DeviceConfig;
            let device_path = if std::path::Path::new("/dev/tpmrm0").exists() {
                "/dev/tpmrm0"
            } else {
                "/dev/tpm0"
            };
            TctiNameConf::Device(
                DeviceConfig::from_str(device_path).map_err(|e| format!("device config: {e}"))?,
            )
        };
        #[cfg(target_os = "windows")]
        let tcti = TctiNameConf::Tbs;

        Context::new(tcti).map_err(|e| format!("TPM context: {e}"))
    }

    /// The owner-hierarchy ECC P-256 primary (SRK) that parents the sealing
    /// object. Ported from `ciris_keyring::platform::tpm::get_or_create_primary`.
    fn get_or_create_primary(context: &mut Context) -> Result<KeyHandle, String> {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()
            .map_err(|e| format!("primary attrs: {e}"))?;

        let ecc_params = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::Null)
            .with_curve(EccCurve::NistP256)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .with_symmetric(SymmetricDefinitionObject::Aes {
                key_bits: AesKeyBits::Aes128,
                mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
            })
            .with_is_signing_key(false)
            .with_is_decryption_key(true)
            .with_restricted(true)
            .build()
            .map_err(|e| format!("primary ecc params: {e}"))?;

        let primary_public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(ecc_params)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(|e| format!("primary public: {e}"))?;

        let result = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(
                    Hierarchy::Owner,
                    primary_public.clone(),
                    None,
                    None,
                    None,
                    None,
                )
            })
            .map_err(|e| format!("TPM2_CreatePrimary: {e}"))?;
        Ok(result.key_handle)
    }

    pub fn available() -> i32 {
        match create_context() {
            Ok(_) => 1,
            Err(e) => {
                tracing::debug!("ciris-tpm-plugin: no usable TPM ({e})");
                0
            },
        }
    }

    /// Seal `input` under the SRK → `u32_le(private_len) ‖ private ‖ public`.
    /// Pure: no persistence (the keyring stores the returned blob).
    pub fn seal(input: &[u8]) -> Result<Vec<u8>, String> {
        let mut context = create_context()?;
        let primary = get_or_create_primary(&mut context)?;

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_user_with_auth(true)
            .build()
            .map_err(|e| format!("seal attrs: {e}"))?;

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
            .with_keyed_hash_unique_identifier(Default::default())
            .build()
            .map_err(|e| format!("seal public: {e}"))?;

        let sensitive =
            SensitiveData::try_from(input.to_vec()).map_err(|e| format!("seal sensitive: {e}"))?;

        let create_result = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create(
                    primary,
                    public.clone(),
                    None,
                    Some(sensitive.clone()),
                    None,
                    None,
                )
            })
            .map_err(|e| format!("TPM2_Create (seal): {e}"))?;

        let private_blob = create_result.out_private.to_vec();
        let public_blob = create_result
            .out_public
            .marshall()
            .map_err(|e| format!("marshall sealed public: {e}"))?;
        let _ = context.flush_context(primary.into());

        let plen = u32::try_from(private_blob.len()).map_err(|_| "private blob too large")?;
        let mut blob = Vec::with_capacity(4 + private_blob.len() + public_blob.len());
        blob.extend_from_slice(&plen.to_le_bytes());
        blob.extend_from_slice(&private_blob);
        blob.extend_from_slice(&public_blob);
        Ok(blob)
    }

    /// Unseal a blob produced by [`seal`] → the original plaintext.
    pub fn unseal(blob: &[u8]) -> Result<Vec<u8>, String> {
        if blob.len() < 4 {
            return Err("sealed blob too short".into());
        }
        let plen = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
        if blob.len() < 4 + plen {
            return Err("sealed blob truncated".into());
        }
        let private = Private::try_from(blob[4..4 + plen].to_vec())
            .map_err(|e| format!("sealed private: {e}"))?;
        let public =
            Public::unmarshall(&blob[4 + plen..]).map_err(|e| format!("sealed public: {e}"))?;

        let mut context = create_context()?;
        let primary = get_or_create_primary(&mut context)?;

        let loaded = context
            .execute_with_nullauth_session(|ctx| ctx.load(primary, private, public))
            .map_err(|e| format!("TPM2_Load (wrong TPM?): {e}"))?;
        let unsealed = context
            .execute_with_nullauth_session(|ctx| ctx.unseal(loaded.into()))
            .map_err(|e| format!("TPM2_Unseal: {e}"))?;
        let _ = context.flush_context(loaded.into());
        let _ = context.flush_context(primary.into());

        Ok(unsealed.value().to_vec())
    }
}

#[cfg(not(all(
    feature = "real",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
)))]
mod imp {
    pub fn available() -> i32 {
        super::super::CIRIS_TPM_UNAVAILABLE
    }
    pub fn seal(_input: &[u8]) -> Result<Vec<u8>, String> {
        Err("ciris-tpm-plugin built without the `real` backend".to_string())
    }
    pub fn unseal(_blob: &[u8]) -> Result<Vec<u8>, String> {
        Err("ciris-tpm-plugin built without the `real` backend".to_string())
    }
}

pub use imp::{available, seal, unseal};
