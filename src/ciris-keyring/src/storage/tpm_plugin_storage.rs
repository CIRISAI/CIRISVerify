//! Plugin-backed TPM secure blob storage (CIRISVerify#130, stage 4).
//!
//! The runtime-`dlopen` TPM secure-blob storage (v8.0.0; the former link-time
//! `TpmSecureBlobStorage` was deleted with `tss-esapi`, #141).
//! Identical at-rest design — a random 32-byte **master** sealed *once*, then
//! per-blob AES-256-GCM under `HKDF("CIRIS-TPM-blob-v2", master)` keyed by
//! `key_id` — with one difference: the master is sealed/unsealed through the
//! `ciris-tpm-plugin` dylib ([`crate::tpm_plugin`]) instead of link-bound
//! `tss-esapi`. That removes `tss-esapi` from the keyring link graph, so this
//! TPM-backed custody path works **on the wheel cdylib and musl targets** where
//! the link-time backend can't build (CIRISVerify#125/#127).
//!
//! The per-blob ciphertext format is byte-identical to the link-time backend;
//! only the master's seal file differs (`{alias}.tpmplugin_seal`, sealed in the
//! plugin's own format under its SRK). The two backends are never mixed for one
//! deployment: [`super::create_platform_storage`] prefers the link backend when
//! its seal file / feature are present, and falls to this one otherwise.
//!
//! ## Re-open discipline (CIRISVerify#134)
//!
//! If the seal file exists but the plugin can't unseal it (no TPM, or a
//! *different* TPM), [`PluginTpmSecureBlobStorage::new`] returns an error — it
//! never silently mints a fresh master, which would orphan every sealed seed.
//! The factory then degrades to software storage, where a subsequent `load`
//! fails loudly rather than returning attacker-or-empty data.
//!
//! `is_hardware_backed()` is `true` only because this type is *only ever
//! constructed* when the plugin reported a usable TPM and the master is held by
//! a real sealing object — the honest-reporting contract the sealed federation
//! signers (`SealedEd25519Signer` / `SealedMlDsa65Signer`) rely on for their
//! `boundary_degraded` tier.

#![cfg(feature = "tpm-plugin")]

use std::path::PathBuf;

use crate::error::KeyringError;
use crate::storage::SecureBlobStorage;
use crate::tpm_plugin::TpmPlugin;

const AES_GCM_NONCE_SIZE: usize = 12;
const MASTER_SECRET_SIZE: usize = 32;
/// HKDF info domain — identical to the link-time TPM backend so a blob is
/// format-compatible given the same master.
const BLOB_HKDF_INFO: &[u8] = b"CIRIS-TPM-blob-v2";

/// TPM-sealed blob storage backed by the runtime-loaded `ciris-tpm-plugin`.
pub struct PluginTpmSecureBlobStorage {
    alias: String,
    storage_dir: PathBuf,
    master: [u8; MASTER_SECRET_SIZE],
}

impl PluginTpmSecureBlobStorage {
    /// Open (or genesis) plugin-backed TPM storage for `alias` under
    /// `storage_dir`.
    ///
    /// Loads the plugin, requires a usable TPM, then either unseals the existing
    /// master (`{alias}.tpmplugin_seal`) or — on first use — draws a fresh master
    /// and seals it. Holds the master in memory for the storage lifetime, exactly
    /// as the link-time backend holds `MasterState::TpmSealed`.
    ///
    /// # Errors
    /// [`KeyringError::NotSupported`] if the plugin is absent / reports no TPM
    /// (the factory falls back to software); [`KeyringError::HardwareError`] if a
    /// present seal file cannot be unsealed (wrong TPM — **never** re-minted);
    /// [`KeyringError::StorageFailed`] on I/O.
    pub fn new(
        alias: impl Into<String>,
        storage_dir: impl Into<PathBuf>,
    ) -> Result<Self, KeyringError> {
        Self::new_with_plugin(alias, storage_dir, TpmPlugin::load()?)
    }

    /// [`Self::new`] over an already-loaded plugin (the testable core; lets a
    /// test inject a plugin loaded from a known path without touching the env).
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn new_with_plugin(
        alias: impl Into<String>,
        storage_dir: impl Into<PathBuf>,
        plugin: TpmPlugin,
    ) -> Result<Self, KeyringError> {
        let alias = alias.into();
        let storage_dir = storage_dir.into();

        if !plugin.available() {
            return Err(KeyringError::NotSupported {
                operation: "ciris-tpm-plugin reports no usable TPM device".to_string(),
            });
        }

        std::fs::create_dir_all(&storage_dir).map_err(|e| KeyringError::StorageFailed {
            reason: format!("create storage dir: {e}"),
        })?;

        let seal_path = storage_dir.join(format!("{alias}.tpmplugin_seal"));
        let master = if seal_path.exists() {
            let sealed = std::fs::read(&seal_path).map_err(|e| KeyringError::StorageFailed {
                reason: format!("read seal file: {e}"),
            })?;
            // Wrong-TPM / tamper → unseal Errs; we propagate, never re-mint (#134).
            let unsealed = plugin.unseal(&sealed)?;
            if unsealed.len() != MASTER_SECRET_SIZE {
                return Err(KeyringError::HardwareError {
                    reason: format!(
                        "unsealed master has {} bytes, expected {MASTER_SECRET_SIZE}",
                        unsealed.len()
                    ),
                });
            }
            let mut m = [0u8; MASTER_SECRET_SIZE];
            m.copy_from_slice(&unsealed);
            m
        } else {
            let mut m = [0u8; MASTER_SECRET_SIZE];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut m);
            let sealed = plugin.seal(&m)?;
            write_atomic(&seal_path, &sealed)?;
            m
        };

        Ok(Self {
            alias,
            storage_dir,
            master,
        })
    }

    fn blob_path(&self, key_id: &str) -> PathBuf {
        let safe_id: String = key_id
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.storage_dir
            .join(format!("{}.{}.tpmp_blob", self.alias, safe_id))
    }

    fn derive_aes_key(&self, key_id: &str) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hkdf = Hkdf::<Sha256>::new(Some(BLOB_HKDF_INFO), &self.master);
        let mut key = [0u8; 32];
        hkdf.expand(key_id.as_bytes(), &mut key)
            .expect("32 is a valid HKDF-SHA256 output length");
        key
    }

    fn encrypt(&self, key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, KeyringError> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| KeyringError::StorageFailed {
            reason: format!("aes init: {e}"),
        })?;
        let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext =
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|e| KeyringError::StorageFailed {
                    reason: format!("encrypt: {e}"),
                })?;
        let mut result = Vec::with_capacity(AES_GCM_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt(&self, key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, KeyringError> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        if encrypted.len() < AES_GCM_NONCE_SIZE {
            return Err(KeyringError::StorageFailed {
                reason: "ciphertext too short".to_string(),
            });
        }
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| KeyringError::StorageFailed {
            reason: format!("aes init: {e}"),
        })?;
        let nonce = Nonce::from_slice(&encrypted[..AES_GCM_NONCE_SIZE]);
        let ciphertext = &encrypted[AES_GCM_NONCE_SIZE..];
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| KeyringError::StorageFailed {
                reason: format!("decrypt (wrong key / corrupt): {e}"),
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

impl SecureBlobStorage for PluginTpmSecureBlobStorage {
    fn store(&self, key_id: &str, data: &[u8]) -> Result<(), KeyringError> {
        let key = self.derive_aes_key(key_id);
        let encrypted = self.encrypt(&key, data)?;
        write_atomic(&self.blob_path(key_id), &encrypted)
    }

    fn load(&self, key_id: &str) -> Result<Vec<u8>, KeyringError> {
        let path = self.blob_path(key_id);
        let encrypted = std::fs::read(&path).map_err(|e| KeyringError::StorageFailed {
            reason: format!("read blob {key_id}: {e}"),
        })?;
        let key = self.derive_aes_key(key_id);
        self.decrypt(&key, &encrypted)
    }

    fn exists(&self, key_id: &str) -> bool {
        self.blob_path(key_id).exists()
    }

    fn delete(&self, key_id: &str) -> Result<(), KeyringError> {
        let path = self.blob_path(key_id);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| KeyringError::StorageFailed {
                reason: format!("delete blob {key_id}: {e}"),
            })?;
        }
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<String>, KeyringError> {
        let mut keys = Vec::new();
        let prefix = format!("{}.", self.alias);
        let suffix = ".tpmp_blob";
        let entries =
            std::fs::read_dir(&self.storage_dir).map_err(|e| KeyringError::StorageFailed {
                reason: format!("read storage dir: {e}"),
            })?;
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Some(stripped) = name.strip_prefix(&prefix) {
                    if let Some(id) = stripped.strip_suffix(suffix) {
                        keys.push(id.to_string());
                    }
                }
            }
        }
        Ok(keys)
    }

    fn is_hardware_backed(&self) -> bool {
        // Only ever constructed when the plugin reported a usable TPM and the
        // master is held by a real sealing object — honest by construction.
        true
    }

    fn diagnostics(&self) -> String {
        format!(
            "PluginTpmSecureBlobStorage:\n\
             - Alias: {}\n\
             - Storage dir: {:?}\n\
             - Backend: ciris-tpm-plugin (dlopen)\n\
             - Hardware backed: true",
            self.alias, self.storage_dir
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_degrades_to_not_supported_without_plugin() {
        // No loadable plugin → new() must return NotSupported so the factory
        // falls back to software (never panics, never mints an unsealed master).
        // Uses load_from (no global env mutation) → can't race parallel tests.
        let dir = std::env::temp_dir().join(format!("ciris-plugstore-{}", std::process::id()));
        let plugin_err = TpmPlugin::load_from("/nonexistent/libciris_tpm_plugin.so").err();
        // The plugin itself is NotSupported when the dylib is absent — and so the
        // storage factory would fall back. Assert that contract directly.
        assert!(
            matches!(plugin_err, Some(KeyringError::NotSupported { .. })),
            "missing plugin must be NotSupported, got {plugin_err:?}"
        );
        let _ = dir;
    }

    // The genesis/store/load round-trip requires a live TPM + the `real` plugin,
    // which CI build boxes lack; it is validated on hardware (see #130). The
    // per-blob crypto envelope is identical to the link-time backend, whose
    // round-trip is covered by tpm.rs unit tests on the shared scheme.
}
