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
        handles::{KeyHandle, NvIndexHandle, TpmHandle},
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm},
            ecc::EccCurve,
            key_bits::AesKeyBits,
            resource_handles::{Hierarchy, NvAuth},
        },
        structures::{
            Data, Digest, EccPoint, EccScheme, HashScheme, HashcheckTicket,
            KeyDerivationFunctionScheme, KeyedHashScheme, PcrSelectionListBuilder, PcrSlot,
            Private, Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters,
            SensitiveData, Signature, SignatureScheme, SymmetricDefinitionObject,
        },
        tcti_ldr::TctiNameConf,
        traits::{Marshall, UnMarshall},
        Context,
    };

    /// ECC EK certificate NV index (TCG spec; ECC P-256 EK).
    const ECC_EK_CERT_NV_INDEX: u32 = 0x01C0_000A;

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

    // ----------------------------------------------------------------------
    // Signer path (#141, ABI v2): a non-restricted ECC P-256 (ECDSA-SHA256)
    // signing key created under the SRK, persisted as the same opaque blob
    // shape as seal (`u32_le(private_len) ‖ private ‖ public`). Pure: the
    // keyring owns the blob; the plugin loads it transiently per op. Faithful
    // port of `ciris_keyring::platform::tpm::{create_signing_key, tpm_sign,
    // extract_ecdsa_signature, extract_public_key_from_public}`.
    // ----------------------------------------------------------------------

    /// Create a non-restricted ECDSA P-256 signing key under the SRK and return
    /// its persistable blob (`u32_le(private_len) ‖ private ‖ public`).
    pub fn signer_create() -> Result<Vec<u8>, String> {
        let mut context = create_context()?;
        let primary = get_or_create_primary(&mut context)?;

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .build()
            .map_err(|e| format!("signer attrs: {e}"))?;

        let ecc_params = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
            .with_curve(EccCurve::NistP256)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .with_symmetric(SymmetricDefinitionObject::Null)
            .with_is_signing_key(true)
            .with_is_decryption_key(false)
            .with_restricted(false)
            .build()
            .map_err(|e| format!("signer ecc params: {e}"))?;

        let signing_public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(ecc_params)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(|e| format!("signer public: {e}"))?;

        let result = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create(primary, signing_public.clone(), None, None, None, None)
            })
            .map_err(|e| format!("TPM2_Create (signer): {e}"))?;

        let private_blob = result.out_private.to_vec();
        let public_blob = result
            .out_public
            .marshall()
            .map_err(|e| format!("marshall signer public: {e}"))?;
        let _ = context.flush_context(primary.into());

        frame_blob(private_blob, public_blob)
    }

    /// Load a signer blob and return its SEC1-uncompressed public key
    /// (`0x04 ‖ X(32) ‖ Y(32)`, 65 bytes).
    pub fn signer_public(blob: &[u8]) -> Result<Vec<u8>, String> {
        let (private, public) = parse_blob(blob)?;
        let mut context = create_context()?;
        let primary = get_or_create_primary(&mut context)?;
        let loaded = context
            .execute_with_nullauth_session(|ctx| ctx.load(primary, private, public))
            .map_err(|e| format!("TPM2_Load (signer, wrong TPM?): {e}"))?;
        let (public, _, _) = context
            .execute_without_session(|ctx| ctx.read_public(loaded))
            .map_err(|e| format!("read_public (signer): {e}"))?;
        let _ = context.flush_context(loaded.into());
        let _ = context.flush_context(primary.into());
        extract_public_key(&public)
    }

    /// Load a signer blob, hash `data` with SHA-256, and ECDSA-sign it →
    /// raw `r(32) ‖ s(32)` (64 bytes).
    pub fn signer_sign(blob: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        use sha2::{Digest as _, Sha256};

        let (private, public) = parse_blob(blob)?;
        let mut context = create_context()?;
        let primary = get_or_create_primary(&mut context)?;
        let key = context
            .execute_with_nullauth_session(|ctx| ctx.load(primary, private, public))
            .map_err(|e| format!("TPM2_Load (signer, wrong TPM?): {e}"))?;

        let hash = Sha256::digest(data);
        let digest = Digest::try_from(&hash[..]).map_err(|e| format!("signer digest: {e}"))?;

        // External (non-TPM-generated) data signs under a NULL-hierarchy ticket.
        let validation = HashcheckTicket::try_from(tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
            tag: tss_esapi::constants::tss::TPM2_ST_HASHCHECK,
            hierarchy: tss_esapi::constants::tss::TPM2_RH_NULL,
            digest: tss_esapi::tss2_esys::TPM2B_DIGEST {
                size: 0,
                buffer: [0; 64],
            },
        })
        .map_err(|e| format!("signer validation ticket: {e}"))?;

        let signature = context
            .execute_with_nullauth_session(|ctx| {
                ctx.sign(
                    key,
                    digest.clone(),
                    SignatureScheme::EcDsa {
                        hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                    },
                    validation.clone(),
                )
            })
            .map_err(|e| format!("TPM2_Sign (signer): {e}"))?;
        let _ = context.flush_context(key.into());
        let _ = context.flush_context(primary.into());

        extract_ecdsa_signature(&signature)
    }

    /// `u32_le(private_len) ‖ private ‖ public` — the opaque blob framing
    /// shared with seal.
    fn frame_blob(private: Vec<u8>, public: Vec<u8>) -> Result<Vec<u8>, String> {
        let plen = u32::try_from(private.len()).map_err(|_| "private blob too large")?;
        let mut blob = Vec::with_capacity(4 + private.len() + public.len());
        blob.extend_from_slice(&plen.to_le_bytes());
        blob.extend_from_slice(&private);
        blob.extend_from_slice(&public);
        Ok(blob)
    }

    fn parse_blob(blob: &[u8]) -> Result<(Private, Public), String> {
        if blob.len() < 4 {
            return Err("signer blob too short".into());
        }
        let plen = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
        if blob.len() < 4 + plen {
            return Err("signer blob truncated".into());
        }
        let private = Private::try_from(blob[4..4 + plen].to_vec())
            .map_err(|e| format!("signer private: {e}"))?;
        let public =
            Public::unmarshall(&blob[4 + plen..]).map_err(|e| format!("signer public: {e}"))?;
        Ok((private, public))
    }

    /// SEC1-uncompressed pubkey from an ECC `Public` (`0x04 ‖ X ‖ Y`).
    fn extract_public_key(public: &Public) -> Result<Vec<u8>, String> {
        let ecc_point = match public {
            Public::Ecc { unique, .. } => unique,
            _ => return Err("expected ECC public key".into()),
        };
        let x = ecc_point.x().value();
        let y = ecc_point.y().value();
        let mut out = Vec::with_capacity(65);
        out.push(0x04);
        pad32(&mut out, x);
        pad32(&mut out, y);
        Ok(out)
    }

    /// Raw `r(32) ‖ s(32)` from a TPM ECDSA `Signature`.
    fn extract_ecdsa_signature(signature: &Signature) -> Result<Vec<u8>, String> {
        match signature {
            Signature::EcDsa(sig) => {
                let mut out = Vec::with_capacity(64);
                pad32(&mut out, sig.signature_r().value());
                pad32(&mut out, sig.signature_s().value());
                Ok(out)
            },
            _ => Err("unexpected signature type from TPM".into()),
        }
    }

    /// Left-pad `bytes` to 32 (or take the low 32) and append.
    fn pad32(out: &mut Vec<u8>, bytes: &[u8]) {
        if bytes.len() < 32 {
            out.extend(std::iter::repeat_n(0u8, 32 - bytes.len()));
        }
        out.extend(&bytes[bytes.len().saturating_sub(32)..]);
    }

    // ----------------------------------------------------------------------
    // Quote/attestation path (#141, ABI v3): a *restricted* ECDSA P-256
    // attestation key (AK) under the SRK (quotes only TPM-generated data), a
    // PCR 0-7 quote bound to a caller nonce, and the EK certificate from NV.
    // Faithful port of `ciris_keyring::platform::tpm::{create_attestation_key,
    // generate_quote, read_ek_certificate}`. Stateless: the keyring owns the AK
    // blob, the plugin loads it transiently.
    // ----------------------------------------------------------------------

    /// Create a *restricted* ECDSA P-256 attestation key (AK) under the SRK and
    /// return its persistable blob (same framing as the signer key).
    pub fn ak_create() -> Result<Vec<u8>, String> {
        let mut context = create_context()?;
        let primary = get_or_create_primary(&mut context)?;

        let object_attributes = ObjectAttributesBuilder::new()
            .with_restricted(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .with_decrypt(false)
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .build()
            .map_err(|e| format!("ak attrs: {e}"))?;

        let ecc_params = PublicEccParametersBuilder::new()
            .with_symmetric(SymmetricDefinitionObject::Null)
            .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
            .with_curve(EccCurve::NistP256)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .with_is_signing_key(true)
            .with_is_decryption_key(false)
            .with_restricted(true)
            .build()
            .map_err(|e| format!("ak ecc params: {e}"))?;

        let ak_public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(ecc_params)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(|e| format!("ak public: {e}"))?;

        let result = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create(primary, ak_public.clone(), None, None, None, None)
            })
            .map_err(|e| format!("TPM2_Create (ak): {e}"))?;

        let private_blob = result.out_private.to_vec();
        let public_blob = result
            .out_public
            .marshall()
            .map_err(|e| format!("marshall ak public: {e}"))?;
        let _ = context.flush_context(primary.into());

        frame_blob(private_blob, public_blob)
    }

    /// Quote PCRs 0-7 (SHA-256) under the AK, bound to `nonce` (qualifying data).
    /// Returns the framed `quoted ‖ signature ‖ pcr_selection ‖ ak_pubkey`
    /// (each `u32_le`-length-prefixed) — everything a verifier needs.
    pub fn quote(ak_blob: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
        let (private, public) = parse_blob(ak_blob)?;
        let mut context = create_context()?;
        let primary = get_or_create_primary(&mut context)?;
        let ak = context
            .execute_with_nullauth_session(|ctx| ctx.load(primary, private, public))
            .map_err(|e| format!("TPM2_Load (ak, wrong TPM?): {e}"))?;

        let ak_pub = {
            let (p, _, _) = context
                .execute_without_session(|ctx| ctx.read_public(ak))
                .map_err(|e| format!("read_public (ak): {e}"))?;
            extract_public_key(&p)?
        };

        let qualifying_data = Data::try_from(nonce.to_vec())
            .map_err(|e| format!("qualifying data (nonce too long?): {e}"))?;

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
            .map_err(|e| format!("pcr selection: {e}"))?;

        let (attest, signature) = context
            .execute_with_nullauth_session(|ctx| {
                ctx.quote(
                    ak,
                    qualifying_data.clone(),
                    SignatureScheme::EcDsa {
                        hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                    },
                    pcr_selection.clone(),
                )
            })
            .map_err(|e| format!("TPM2_Quote: {e}"))?;
        let _ = context.flush_context(ak.into());
        let _ = context.flush_context(primary.into());

        let quoted = attest
            .marshall()
            .map_err(|e| format!("marshall attest: {e}"))?;
        let sig = extract_ecdsa_signature(&signature)?;
        // PCRs 0-7 selected → bitmap 0xFF (matches the link-time backend).
        let pcr_sel = vec![0xFFu8];

        Ok(frame_fields(&[&quoted, &sig, &pcr_sel, &ak_pub]))
    }

    /// Read the ECC EK certificate (X.509 DER) from NV. Errs if not provisioned.
    pub fn ek_certificate() -> Result<Vec<u8>, String> {
        let mut context = create_context()?;
        let tpm_handle = TpmHandle::NvIndex(
            ECC_EK_CERT_NV_INDEX
                .try_into()
                .map_err(|e| format!("invalid NV index: {e:?}"))?,
        );
        let object_handle = context
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
            .map_err(|e| format!("EK cert NV index not accessible (not provisioned?): {e}"))?;
        let nv_index_handle = NvIndexHandle::from(object_handle);

        let (nv_public, _name) = context
            .execute_without_session(|ctx| ctx.nv_read_public(nv_index_handle))
            .map_err(|e| format!("EK cert NV read public: {e}"))?;
        let cert_size = nv_public.data_size() as u16;
        if cert_size == 0 {
            return Err("EK certificate NV area is empty".into());
        }

        let mut cert = Vec::with_capacity(cert_size as usize);
        let mut offset = 0u16;
        const MAX_NV_READ: u16 = 1024;
        while offset < cert_size {
            let read_size = std::cmp::min(MAX_NV_READ, cert_size.saturating_sub(offset));
            let chunk = context
                .execute_with_nullauth_session(|ctx| {
                    ctx.nv_read(NvAuth::Owner, nv_index_handle, read_size, offset)
                })
                .map_err(|e| format!("NV read at offset {offset}: {e}"))?;
            cert.extend_from_slice(&chunk);
            offset += read_size;
        }
        Ok(cert)
    }

    /// Length-prefix each field (`u32_le(len) ‖ bytes`) and concatenate — the
    /// quote wire framing the keyring client splits back apart.
    fn frame_fields(fields: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for f in fields {
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(f);
        }
        out
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
    pub fn signer_create() -> Result<Vec<u8>, String> {
        Err("ciris-tpm-plugin built without the `real` backend".to_string())
    }
    pub fn signer_public(_blob: &[u8]) -> Result<Vec<u8>, String> {
        Err("ciris-tpm-plugin built without the `real` backend".to_string())
    }
    pub fn signer_sign(_blob: &[u8], _data: &[u8]) -> Result<Vec<u8>, String> {
        Err("ciris-tpm-plugin built without the `real` backend".to_string())
    }
    pub fn ak_create() -> Result<Vec<u8>, String> {
        Err("ciris-tpm-plugin built without the `real` backend".to_string())
    }
    pub fn quote(_ak_blob: &[u8], _nonce: &[u8]) -> Result<Vec<u8>, String> {
        Err("ciris-tpm-plugin built without the `real` backend".to_string())
    }
    pub fn ek_certificate() -> Result<Vec<u8>, String> {
        Err("ciris-tpm-plugin built without the `real` backend".to_string())
    }
}

pub use imp::{
    ak_create, available, ek_certificate, quote, seal, signer_create, signer_public, signer_sign,
    unseal,
};
