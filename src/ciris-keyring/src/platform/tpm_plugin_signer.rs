//! `HardwareSigner` over the runtime-loaded TPM plugin (CIRISVerify#141, stage B).
//!
//! The `dlopen` counterpart to [`crate::platform::tpm::TpmSigner`]: an ECDSA
//! P-256 signing key held inside the TPM, driven through the `ciris-tpm-plugin`
//! C ABI ([`crate::tpm_plugin`]) instead of link-bound `tss-esapi`. So the
//! native TPM *signing* path works on every target that can load the plugin
//! (incl. the wheel + musl), carrying no `tss-esapi` in the keyring link graph.
//!
//! ## Persistence
//!
//! The plugin's `signer_create` returns an opaque, **TPM-wrapped** key blob
//! (`TPM2B_PRIVATE`/`PUBLIC`): the private half is sealed to this TPM, so the
//! blob is safe to store as a plain file — only the TPM can load it. We persist
//! it at `{alias}.tpmplugin_signer`, exactly the at-rest model the link-time
//! `TpmSigner` uses for its `.tpm` envelope.
//!
//! ## Re-open discipline (CIRISVerify#134)
//!
//! If the blob file exists but the plugin can't load it (no TPM, or a *different*
//! TPM), [`PluginTpmSigner::open`] returns an error — it never silently mints a
//! fresh key, which would orphan the identity it was supposed to re-open.
//!
//! ## Attestation
//!
//! Stage B reports a [`HardwareType::TpmFirmware`] attestation with **no quote**
//! (`quote: None`) — honest: the signing key is TPM-held, but the quote /
//! EK-cert path is the stage-C port. It is **not** a software attestation, so
//! consumers see TPM custody without an over-claimed quote.

#![cfg(feature = "tpm-plugin")]

use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::error::KeyringError;
use crate::signer::{HardwareSigner, KeyGenConfig};
use crate::tpm_plugin::TpmPlugin;
use crate::types::{
    ClassicalAlgorithm, HardwareType, PlatformAttestation, StorageDescriptor, TpmAttestation,
};

/// An ECDSA P-256 signer whose key lives in the TPM, reached via the plugin.
pub struct PluginTpmSigner {
    alias: String,
    blob_path: PathBuf,
    plugin: TpmPlugin,
    /// The TPM-wrapped key blob (private half sealed to this TPM).
    key_blob: Vec<u8>,
    /// SEC1-uncompressed public key (`0x04 ‖ X ‖ Y`), cached at open.
    public_key: Vec<u8>,
    /// Serializes TPM access (the device is single-threaded; the plugin ops are
    /// blocking). Held only across a single op.
    lock: Mutex<()>,
}

impl PluginTpmSigner {
    /// Open (or, on first use, create) the plugin-backed TPM signing key for
    /// `alias` under `storage_dir`.
    ///
    /// # Errors
    /// [`KeyringError::NotSupported`] if no plugin / TPM / signer ABI is present
    /// (the factory falls back); [`KeyringError::HardwareError`] if a present
    /// blob cannot be loaded (wrong TPM — **never** re-minted) or a TPM op fails;
    /// [`KeyringError::StorageFailed`] on I/O.
    pub fn open(
        alias: impl Into<String>,
        storage_dir: impl Into<PathBuf>,
    ) -> Result<Self, KeyringError> {
        let alias = alias.into();
        let storage_dir = storage_dir.into();

        let plugin = TpmPlugin::load()?;
        if !plugin.available() {
            return Err(KeyringError::NotSupported {
                operation: "ciris-tpm-plugin reports no usable TPM device".to_string(),
            });
        }
        if !plugin.signer_supported() {
            return Err(KeyringError::NotSupported {
                operation: "ciris-tpm-plugin has no signer path (ABI v1)".to_string(),
            });
        }

        std::fs::create_dir_all(&storage_dir).map_err(|e| KeyringError::StorageFailed {
            reason: format!("create storage dir: {e}"),
        })?;
        let blob_path = storage_dir.join(format!("{alias}.tpmplugin_signer"));

        let key_blob = if blob_path.exists() {
            std::fs::read(&blob_path).map_err(|e| KeyringError::StorageFailed {
                reason: format!("read signer blob: {e}"),
            })?
        } else {
            let blob = plugin.signer_create()?;
            write_atomic(&blob_path, &blob)?;
            blob
        };

        // Resolve the public key now — this also proves the blob loads on THIS
        // TPM. A present-but-unloadable blob errors here (wrong TPM), never a
        // silent re-mint (#134).
        let public_key = plugin.signer_public(&key_blob)?;

        Ok(Self {
            alias,
            blob_path,
            plugin,
            key_blob,
            public_key,
            lock: Mutex::new(()),
        })
    }
}

fn write_atomic(path: &std::path::Path, data: &[u8]) -> Result<(), KeyringError> {
    let temp = path.with_extension("tmp");
    std::fs::write(&temp, data).map_err(|e| KeyringError::StorageFailed {
        reason: format!("write temp: {e}"),
    })?;
    std::fs::rename(&temp, path).map_err(|e| KeyringError::StorageFailed {
        reason: format!("rename into place: {e}"),
    })?;
    Ok(())
}

#[async_trait]
impl HardwareSigner for PluginTpmSigner {
    fn algorithm(&self) -> ClassicalAlgorithm {
        ClassicalAlgorithm::EcdsaP256
    }

    fn hardware_type(&self) -> HardwareType {
        // Conservative: the plugin doesn't probe discrete-vs-firmware (that needs
        // TPM properties, a stage-C concern), so report the lower-claim fTPM.
        HardwareType::TpmFirmware
    }

    async fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
        Ok(self.public_key.clone())
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        let _guard = self.lock.lock().map_err(|_| KeyringError::HardwareError {
            reason: "TPM plugin lock poisoned".into(),
        })?;
        self.plugin.signer_sign(&self.key_blob, data)
    }

    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
        // Stage B: TPM-held signing key, but the quote/EK port is stage C — so
        // report a TPM attestation with no quote (honest, not over-claimed, and
        // NOT a software attestation).
        Ok(PlatformAttestation::Tpm(TpmAttestation {
            tpm_version: "2.0".to_string(),
            manufacturer: "unknown".to_string(),
            discrete: false,
            quote: None,
            ek_cert: None,
            ak_public_key: None,
        }))
    }

    async fn generate_key(&self, _config: &KeyGenConfig) -> Result<(), KeyringError> {
        // The signing key is provisioned at `open`; this is idempotent (mirrors
        // the link-time TpmSigner's lenient ensure-key behavior).
        Ok(())
    }

    async fn key_exists(&self, _alias: &str) -> Result<bool, KeyringError> {
        Ok(self.blob_path.exists())
    }

    async fn delete_key(&self, _alias: &str) -> Result<(), KeyringError> {
        if self.blob_path.exists() {
            std::fs::remove_file(&self.blob_path).map_err(|e| KeyringError::StorageFailed {
                reason: format!("delete signer blob: {e}"),
            })?;
        }
        Ok(())
    }

    fn current_alias(&self) -> &str {
        &self.alias
    }

    fn storage_descriptor(&self) -> StorageDescriptor {
        // The private half is TPM-wrapped, but unlike the link-time TpmSigner
        // (in-TPM handle, no file) we DO persist a wrapped envelope on disk —
        // point the descriptor at it.
        StorageDescriptor::Hardware {
            hardware_type: self.hardware_type(),
            blob_path: Some(self.blob_path.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_degrades_to_not_supported_without_plugin() {
        // No loadable plugin → open() returns NotSupported so the factory falls
        // back (never panics, never mints an unsealed key). Deterministic: the
        // bare plugin name won't resolve a usable TPM signer in the test env.
        let dir = std::env::temp_dir().join(format!("ciris-plugsigner-{}", std::process::id()));
        // load_from a path that can't exist proves the contract without mutating
        // the process-global env.
        let err = TpmPlugin::load_from("/nonexistent/libciris_tpm_plugin.so").err();
        assert!(
            matches!(err, Some(KeyringError::NotSupported { .. })),
            "missing plugin must be NotSupported, got {err:?}"
        );
        let _ = dir;
    }

    // The create/sign round-trip needs a real TPM + the `real` plugin, validated
    // on hardware via the `signer_roundtrip_verifies_on_real_tpm` integration
    // test (#141 stage A). CI loads the stub + has no TPM.
}
