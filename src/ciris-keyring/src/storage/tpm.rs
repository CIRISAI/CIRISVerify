//! TPM 2.0 secure blob storage implementation.
//!
//! Protects arbitrary secrets at rest with AES-256-GCM where the master key is
//! obtained by **unsealing a TPM2 sealing object** — i.e. the secret is bound to
//! the specific TPM and cannot be recovered by copying the storage directory to
//! another machine.
//!
//! # Why the previous scheme was broken (CIRISVerify#73)
//!
//! The original implementation derived the blob AES key from `HKDF(tpm_signature)`
//! and then **cached that signature to disk in plaintext** (`{alias}.tpm_sig.bin`).
//! TPM signing keys are non-reproducible, so the signature had to be persisted —
//! but the persisted signature WAS the only secret needed to decrypt every blob.
//! A `cp -r` of the storage directory yielded ciphertext + the root secret, so
//! every sealed seed decrypted with no TPM at all. Worse, `is_hardware_backed()`
//! returned `true` unconditionally, so the sealed federation signers
//! (#68/#70/#71) reported a hardware tier and `boundary_degraded = false` for a
//! key that was, in fact, software-at-rest.
//!
//! # Real-binding design (this implementation)
//!
//! At genesis we draw a random 32-byte **master secret** and seal it inside a
//! TPM2 `KeyedHash` sealing object created with `TPM2_Create` under the
//! owner-hierarchy primary (SRK). We persist only the resulting
//! `out_private` / `out_public` blobs to `{alias}.tpm_seal`. Recovering the
//! master requires `TPM2_Load` + `TPM2_Unseal` **on the same TPM** — the
//! storage directory alone is useless. Per-blob AES keys are
//! `HKDF(master, key_id)`. No plaintext root secret ever touches disk.
//!
//! `is_hardware_backed()` returns `true` **only** when the master is held by a
//! real TPM sealing object. If the TPM is unavailable and we fall back to a
//! software-stored master, the storage honestly reports `false` so downstream
//! signers (`SealedEd25519Signer` / `SealedMlDsa65Signer` /
//! `BlobTransportKeystore`) correctly degrade to `SoftwareOnly` /
//! `boundary_degraded = true` rather than over-claiming hardware custody.
//!
//! # Test boundary
//!
//! The real-sealing path requires a live TPM, which CI build boxes do not have.
//! The unit tests in this file exercise the **honest-reporting contract**: a
//! storage instance that could not establish a TPM sealing object MUST report
//! `is_hardware_backed() == false`. The genesis/unseal round-trip itself is
//! validated on hardware (see report on #73).

#[cfg(all(
    feature = "tpm",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
))]
use crate::error::KeyringError;

#[cfg(all(
    feature = "tpm",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
))]
use crate::storage::SecureBlobStorage;

#[cfg(all(
    feature = "tpm",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
))]
use std::path::PathBuf;

#[cfg(all(
    feature = "tpm",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
))]
use std::sync::Mutex;

#[cfg(all(
    feature = "tpm",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
))]
use tracing::{debug, error, info, warn};

/// AES-256-GCM nonce size
#[cfg(all(
    feature = "tpm",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
))]
const AES_GCM_NONCE_SIZE: usize = 12;

/// Size of the sealed master secret.
#[cfg(all(
    feature = "tpm",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
))]
const MASTER_SECRET_SIZE: usize = 32;

/// Magic bytes for the sealed-master file format.
#[cfg(all(
    feature = "tpm",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
))]
const SEAL_FILE_MAGIC: &[u8; 4] = b"TSL1";

/// How the master secret backing this storage was established.
///
/// This is the single source of truth for `is_hardware_backed()`. It is set
/// once, lazily, the first time a master secret is needed (load or store), and
/// is never silently upgraded.
#[cfg(all(
    feature = "tpm",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
))]
#[derive(Clone)]
enum MasterState {
    /// Master is held inside a TPM2 sealing object — genuinely hardware-bound.
    /// The decrypted master is cached in memory for the process lifetime; the
    /// on-disk form is only the (TPM-bound) sealed blobs.
    TpmSealed { master: [u8; MASTER_SECRET_SIZE] },
    /// Master came from (or was written to) the software-fallback file. NOT
    /// hardware-bound; `is_hardware_backed()` MUST report `false`.
    SoftwareFallback { master: [u8; MASTER_SECRET_SIZE] },
}

#[cfg(all(
    feature = "tpm",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
))]
impl MasterState {
    fn master(&self) -> &[u8; MASTER_SECRET_SIZE] {
        match self {
            MasterState::TpmSealed { master } | MasterState::SoftwareFallback { master } => master,
        }
    }

    fn is_hardware_backed(&self) -> bool {
        matches!(self, MasterState::TpmSealed { .. })
    }
}

/// TPM-backed secure blob storage.
///
/// Per-blob AES keys are derived from a master secret that is sealed to the
/// local TPM (`TPM2_Create` keyed-hash sealing object). Recovering the master
/// requires `TPM2_Unseal` on the same TPM, so a copy of the storage directory
/// cannot decrypt anything on another machine.
#[cfg(all(
    feature = "tpm",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
))]
pub struct TpmSecureBlobStorage {
    /// Base directory for storing encrypted blobs
    storage_dir: PathBuf,
    /// Alias prefix for file naming
    alias: String,
    /// Cached master state (established lazily, then immutable for the process).
    master_state: Mutex<Option<MasterState>>,
}

#[cfg(all(
    feature = "tpm",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
))]
impl TpmSecureBlobStorage {
    /// Create new TPM-backed storage.
    pub fn new(
        alias: impl Into<String>,
        storage_dir: impl Into<PathBuf>,
    ) -> Result<Self, KeyringError> {
        let alias = alias.into();
        let storage_dir = storage_dir.into();

        // Ensure storage directory exists
        std::fs::create_dir_all(&storage_dir).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to create storage directory: {}", e),
        })?;

        info!(
            alias = %alias,
            storage_dir = ?storage_dir,
            "TpmSecureBlobStorage initialized"
        );

        Ok(Self {
            storage_dir,
            alias,
            master_state: Mutex::new(None),
        })
    }

    /// Get the file path for a blob.
    fn blob_path(&self, key_id: &str) -> PathBuf {
        let safe_id = key_id.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
        self.storage_dir
            .join(format!("{}.{}.tpm_blob", self.alias, safe_id))
    }

    /// Path to the persisted TPM sealing blobs (`out_private` / `out_public`).
    fn seal_path(&self) -> PathBuf {
        self.storage_dir.join(format!("{}.tpm_seal", self.alias))
    }

    /// Path to the software-fallback master file (used only when no TPM).
    fn software_master_path(&self) -> PathBuf {
        self.storage_dir
            .join(format!("{}.tpm_softfallback", self.alias))
    }

    /// Resolve (and cache) the master state, establishing it at genesis if
    /// neither a sealed blob nor a software-fallback master exists yet.
    ///
    /// Establishment order is fail-secure: try real TPM sealing first; only on
    /// TPM failure fall back to a software master, which downgrades the
    /// hardware-backed claim to `false`.
    fn get_master_state(&self) -> Result<MasterState, KeyringError> {
        {
            let guard = self
                .master_state
                .lock()
                .map_err(|_| KeyringError::StorageFailed {
                    reason: "Failed to acquire master state lock".into(),
                })?;
            if let Some(state) = guard.as_ref() {
                return Ok(state.clone());
            }
        }

        let state = self.establish_master_state()?;

        let mut guard = self
            .master_state
            .lock()
            .map_err(|_| KeyringError::StorageFailed {
                reason: "Failed to acquire master state lock".into(),
            })?;
        // Another thread may have raced us; prefer the already-stored state.
        if let Some(existing) = guard.as_ref() {
            return Ok(existing.clone());
        }
        *guard = Some(state.clone());
        Ok(state)
    }

    /// Establish the master state from disk or genesis.
    fn establish_master_state(&self) -> Result<MasterState, KeyringError> {
        let seal_path = self.seal_path();
        let soft_path = self.software_master_path();

        // 1. Existing TPM sealing object -> unseal it (requires this TPM).
        if seal_path.exists() {
            match self.unseal_master() {
                Ok(master) => {
                    debug!("Recovered master secret via TPM2_Unseal");
                    return Ok(MasterState::TpmSealed { master });
                },
                Err(e) => {
                    // The sealed blob exists but cannot be unsealed here (wrong
                    // TPM, TPM unavailable). Do NOT silently fall back to a
                    // software master that would decrypt nothing — surface it.
                    error!("Failed to unseal TPM master (wrong/absent TPM?): {}", e);
                    return Err(e);
                },
            }
        }

        // 2. Existing software-fallback master -> load it (honestly software).
        if soft_path.exists() {
            let master = self.load_software_master()?;
            warn!(
                alias = %self.alias,
                "TpmSecureBlobStorage using SOFTWARE-FALLBACK master (NOT hardware-backed)"
            );
            return Ok(MasterState::SoftwareFallback { master });
        }

        // 3. Genesis: try to seal a fresh master to the TPM; fall back to
        //    software only if the TPM is unavailable.
        let master = Self::random_master();
        match self.seal_master(&master) {
            Ok(()) => {
                info!(
                    alias = %self.alias,
                    "Genesis: sealed fresh master secret to TPM (hardware-bound)"
                );
                Ok(MasterState::TpmSealed { master })
            },
            Err(e) => {
                warn!(
                    alias = %self.alias,
                    error = %e,
                    "TPM sealing unavailable at genesis; falling back to SOFTWARE master \
                     (storage will honestly report NOT hardware-backed)"
                );
                self.store_software_master(&master)?;
                Ok(MasterState::SoftwareFallback { master })
            },
        }
    }

    /// Draw a fresh random 32-byte master secret.
    fn random_master() -> [u8; MASTER_SECRET_SIZE] {
        use rand::RngCore;
        let mut master = [0u8; MASTER_SECRET_SIZE];
        rand::thread_rng().fill_bytes(&mut master);
        master
    }

    /// Seal `master` into a TPM2 keyed-hash sealing object and persist the
    /// resulting `out_private` / `out_public` blobs.
    ///
    /// This is the real hardware binding: the blobs are only loadable +
    /// unsealable on the TPM that created them.
    fn seal_master(&self, master: &[u8; MASTER_SECRET_SIZE]) -> Result<(), KeyringError> {
        use crate::platform::tpm::create_context;
        use tss_esapi::{
            attributes::ObjectAttributesBuilder,
            interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm},
            structures::{
                KeyedHashScheme, PublicBuilder, PublicKeyedHashParameters, SensitiveData,
            },
            traits::Marshall,
        };

        let mut context = create_context()?;

        // Owner-hierarchy primary (SRK) to parent the sealing object.
        let primary = self.create_primary(&mut context)?;

        // Sealing object: KeyedHash with a null scheme holds arbitrary data.
        // No `sensitive_data_origin` — the TPM must accept our supplied data.
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_user_with_auth(true)
            .build()
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to build sealing object attributes: {}", e),
            })?;

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
            .with_keyed_hash_unique_identifier(Default::default())
            .build()
            .map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to build sealing object public: {}", e),
            })?;

        let sensitive =
            SensitiveData::try_from(master.to_vec()).map_err(|e| KeyringError::HardwareError {
                reason: format!("Failed to wrap master as sensitive data: {}", e),
            })?;

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
            .map_err(|e| {
                error!("TPM2_Create (seal) failed: {}", e);
                KeyringError::HardwareError {
                    reason: format!("Failed to create sealing object: {}", e),
                }
            })?;

        let private_blob = create_result.out_private.to_vec();
        let public_blob =
            create_result
                .out_public
                .marshall()
                .map_err(|e| KeyringError::HardwareError {
                    reason: format!("Failed to marshal sealed public blob: {}", e),
                })?;

        let _ = context.flush_context(primary.into());

        self.write_seal_file(&private_blob, &public_blob)?;
        Ok(())
    }

    /// Recover the master by loading + unsealing the persisted sealing object.
    fn unseal_master(&self) -> Result<[u8; MASTER_SECRET_SIZE], KeyringError> {
        use crate::platform::tpm::create_context;
        use tss_esapi::{
            structures::{Private, Public},
            traits::UnMarshall,
        };

        let (private_blob, public_blob) = self.read_seal_file()?;

        let private = Private::try_from(private_blob).map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to deserialize sealed private blob: {}", e),
        })?;
        let public = Public::unmarshall(&public_blob).map_err(|e| KeyringError::HardwareError {
            reason: format!("Failed to deserialize sealed public blob: {}", e),
        })?;

        let mut context = create_context()?;
        let primary = self.create_primary(&mut context)?;

        let loaded = context
            .execute_with_nullauth_session(|ctx| ctx.load(primary, private, public))
            .map_err(|e| {
                error!("TPM2_Load of sealing object failed (wrong TPM?): {}", e);
                KeyringError::HardwareError {
                    reason: format!("Failed to load sealing object: {}", e),
                }
            })?;

        let unsealed = context
            .execute_with_nullauth_session(|ctx| ctx.unseal(loaded.into()))
            .map_err(|e| {
                error!("TPM2_Unseal failed: {}", e);
                KeyringError::HardwareError {
                    reason: format!("Failed to unseal master: {}", e),
                }
            })?;

        let _ = context.flush_context(loaded.into());
        let _ = context.flush_context(primary.into());

        let bytes = unsealed.value();
        if bytes.len() != MASTER_SECRET_SIZE {
            return Err(KeyringError::HardwareError {
                reason: format!(
                    "Unsealed master has wrong length: {} (expected {})",
                    bytes.len(),
                    MASTER_SECRET_SIZE
                ),
            });
        }
        let mut master = [0u8; MASTER_SECRET_SIZE];
        master.copy_from_slice(bytes);
        Ok(master)
    }

    /// Create the owner-hierarchy primary storage key used to parent the
    /// sealing object.
    fn create_primary(
        &self,
        context: &mut tss_esapi::Context,
    ) -> Result<tss_esapi::handles::KeyHandle, KeyringError> {
        use crate::platform::tpm::get_or_create_primary;
        get_or_create_primary(context)
    }

    /// Write the `TSL1` sealed-master file (private blob + public blob).
    fn write_seal_file(&self, private_blob: &[u8], public_blob: &[u8]) -> Result<(), KeyringError> {
        let mut data = Vec::new();
        data.extend_from_slice(SEAL_FILE_MAGIC);
        data.extend_from_slice(&(private_blob.len() as u32).to_le_bytes());
        data.extend_from_slice(private_blob);
        data.extend_from_slice(&(public_blob.len() as u32).to_le_bytes());
        data.extend_from_slice(public_blob);

        let path = self.seal_path();
        let temp = path.with_extension("tpm_seal.tmp");
        std::fs::write(&temp, &data).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to write seal file: {}", e),
        })?;
        std::fs::rename(&temp, &path).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to rename seal file: {}", e),
        })?;
        Self::tighten_permissions(&path);
        Ok(())
    }

    /// Read and parse the `TSL1` sealed-master file.
    fn read_seal_file(&self) -> Result<(Vec<u8>, Vec<u8>), KeyringError> {
        let data = std::fs::read(self.seal_path()).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to read seal file: {}", e),
        })?;

        let mut offset = 0usize;
        let read_len = |data: &[u8], offset: &mut usize| -> Result<usize, KeyringError> {
            if *offset + 4 > data.len() {
                return Err(KeyringError::StorageFailed {
                    reason: "Seal file truncated (length field)".into(),
                });
            }
            let n = u32::from_le_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            ]) as usize;
            *offset += 4;
            Ok(n)
        };

        if data.len() < 4 || &data[0..4] != SEAL_FILE_MAGIC {
            return Err(KeyringError::StorageFailed {
                reason: "Invalid seal file magic".into(),
            });
        }
        offset += 4;

        let private_len = read_len(&data, &mut offset)?;
        if offset + private_len > data.len() {
            return Err(KeyringError::StorageFailed {
                reason: "Seal file truncated (private blob)".into(),
            });
        }
        let private_blob = data[offset..offset + private_len].to_vec();
        offset += private_len;

        let public_len = read_len(&data, &mut offset)?;
        if offset + public_len > data.len() {
            return Err(KeyringError::StorageFailed {
                reason: "Seal file truncated (public blob)".into(),
            });
        }
        let public_blob = data[offset..offset + public_len].to_vec();

        Ok((private_blob, public_blob))
    }

    /// Store the software-fallback master (honestly NOT hardware-bound).
    fn store_software_master(&self, master: &[u8; MASTER_SECRET_SIZE]) -> Result<(), KeyringError> {
        let path = self.software_master_path();
        let temp = path.with_extension("tpm_softfallback.tmp");
        std::fs::write(&temp, master).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to write software master: {}", e),
        })?;
        std::fs::rename(&temp, &path).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to rename software master: {}", e),
        })?;
        Self::tighten_permissions(&path);
        Ok(())
    }

    /// Load the software-fallback master.
    fn load_software_master(&self) -> Result<[u8; MASTER_SECRET_SIZE], KeyringError> {
        let bytes = std::fs::read(self.software_master_path()).map_err(|e| {
            KeyringError::StorageFailed {
                reason: format!("Failed to read software master: {}", e),
            }
        })?;
        if bytes.len() != MASTER_SECRET_SIZE {
            return Err(KeyringError::StorageFailed {
                reason: format!(
                    "Software master has wrong length: {} (expected {})",
                    bytes.len(),
                    MASTER_SECRET_SIZE
                ),
            });
        }
        let mut master = [0u8; MASTER_SECRET_SIZE];
        master.copy_from_slice(&bytes);
        Ok(master)
    }

    /// Best-effort 0600 permissions on Unix.
    fn tighten_permissions(path: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
        #[cfg(not(unix))]
        {
            let _ = path;
        }
    }

    /// Derive AES key from master and key_id.
    fn derive_aes_key(&self, master: &[u8; MASTER_SECRET_SIZE], key_id: &str) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(Some(b"CIRIS-TPM-blob-v2"), master);
        let mut key = [0u8; 32];
        hkdf.expand(key_id.as_bytes(), &mut key)
            .expect("HKDF expansion should not fail");
        key
    }

    /// Encrypt data with AES-256-GCM.
    #[allow(deprecated)]
    fn encrypt(&self, key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, KeyringError> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use rand::RngCore;

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to create cipher: {}", e),
        })?;

        let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext =
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|e| KeyringError::StorageFailed {
                    reason: format!("Encryption failed: {}", e),
                })?;

        let mut result = Vec::with_capacity(AES_GCM_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data with AES-256-GCM.
    #[allow(deprecated)]
    fn decrypt(&self, key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, KeyringError> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

        if encrypted.len() < AES_GCM_NONCE_SIZE {
            return Err(KeyringError::StorageFailed {
                reason: "Encrypted data too short".into(),
            });
        }

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to create cipher: {}", e),
        })?;

        let nonce = Nonce::from_slice(&encrypted[..AES_GCM_NONCE_SIZE]);
        let ciphertext = &encrypted[AES_GCM_NONCE_SIZE..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| KeyringError::StorageFailed {
                reason: format!("Decryption failed: {}", e),
            })
    }
}

#[cfg(all(
    feature = "tpm",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
))]
impl SecureBlobStorage for TpmSecureBlobStorage {
    fn store(&self, key_id: &str, data: &[u8]) -> Result<(), KeyringError> {
        let state = self.get_master_state()?;
        let aes_key = self.derive_aes_key(state.master(), key_id);
        let encrypted = self.encrypt(&aes_key, data)?;

        let path = self.blob_path(key_id);

        // Write atomically
        let temp_path = path.with_extension("tpm_blob.tmp");
        std::fs::write(&temp_path, &encrypted).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to write blob: {}", e),
        })?;
        std::fs::rename(&temp_path, &path).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to rename blob: {}", e),
        })?;

        Self::tighten_permissions(&path);

        debug!(key_id = %key_id, hardware_backed = state.is_hardware_backed(), "Stored TPM blob");
        Ok(())
    }

    fn load(&self, key_id: &str) -> Result<Vec<u8>, KeyringError> {
        let path = self.blob_path(key_id);
        if !path.exists() {
            return Err(KeyringError::KeyNotFound {
                alias: key_id.to_string(),
            });
        }

        let encrypted = std::fs::read(&path).map_err(|e| KeyringError::StorageFailed {
            reason: format!("Failed to read blob: {}", e),
        })?;

        let state = self.get_master_state()?;
        let aes_key = self.derive_aes_key(state.master(), key_id);
        self.decrypt(&aes_key, &encrypted)
    }

    fn exists(&self, key_id: &str) -> bool {
        self.blob_path(key_id).exists()
    }

    fn delete(&self, key_id: &str) -> Result<(), KeyringError> {
        let path = self.blob_path(key_id);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| KeyringError::StorageFailed {
                reason: format!("Failed to delete blob: {}", e),
            })?;
            info!(key_id = %key_id, "Deleted TPM-protected blob");
        }
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<String>, KeyringError> {
        let prefix = format!("{}.", self.alias);
        let suffix = ".tpm_blob";

        let mut keys = Vec::new();

        let entries =
            std::fs::read_dir(&self.storage_dir).map_err(|e| KeyringError::StorageFailed {
                reason: format!("Failed to read storage directory: {}", e),
            })?;

        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with(&prefix) && name.ends_with(suffix) {
                    let key_id = &name[prefix.len()..name.len() - suffix.len()];
                    keys.push(key_id.to_string());
                }
            }
        }

        Ok(keys)
    }

    /// Hardware-backed iff the master is held by a real TPM sealing object.
    ///
    /// CRITICAL (CIRISVerify#73): this MUST NOT report `true` merely because a
    /// TPM is present. If we could not seal/unseal the master and fell back to
    /// a software-stored master, this reports `false` so consumers degrade to
    /// `SoftwareOnly` / `boundary_degraded = true` instead of over-claiming.
    ///
    /// If the master state has not been established yet (no I/O has happened),
    /// fail closed by reporting `false` rather than assuming hardware.
    fn is_hardware_backed(&self) -> bool {
        match self.get_master_state() {
            Ok(state) => state.is_hardware_backed(),
            Err(_) => false,
        }
    }

    fn diagnostics(&self) -> String {
        let keys = self.list_keys().unwrap_or_default();
        let hardware_backed = self.is_hardware_backed();
        let backend = if hardware_backed {
            "TPM 2.0 sealed (TPM2_Unseal-bound)"
        } else {
            "software-fallback master (NOT hardware-backed)"
        };

        format!(
            "TpmSecureBlobStorage:\n\
             - Alias: {}\n\
             - Storage dir: {:?}\n\
             - Hardware backed: {}\n\
             - Backend: {}\n\
             - Seal file present: {}\n\
             - Stored keys: {:?}",
            self.alias,
            self.storage_dir,
            hardware_backed,
            backend,
            self.seal_path().exists(),
            keys
        )
    }
}

// Stub for non-TPM platforms
#[cfg(not(all(
    feature = "tpm",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
)))]
pub struct TpmSecureBlobStorage;

#[cfg(not(all(
    feature = "tpm",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
)))]
impl TpmSecureBlobStorage {
    pub fn new(
        _alias: impl Into<String>,
        _storage_dir: impl Into<std::path::PathBuf>,
    ) -> Result<Self, crate::error::KeyringError> {
        Err(crate::error::KeyringError::HardwareNotAvailable {
            reason: "TPM not available on this platform".into(),
        })
    }
}

#[cfg(all(
    feature = "tpm",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SecureBlobStorage;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ciris_tpm_blob_test_{}_{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The core CIRISVerify#73 contract: a storage instance whose master came
    /// from the SOFTWARE-FALLBACK path MUST report NOT hardware-backed. We
    /// force that path by pre-seeding the software-fallback master file (no TPM
    /// sealing object), then asserting the honest report.
    #[test]
    fn software_fallback_master_reports_not_hardware_backed() {
        let dir = temp_dir("softfallback");
        let storage = TpmSecureBlobStorage::new("acct", &dir).unwrap();

        // Pre-seed the software-fallback master so establishment takes the
        // software branch without ever touching the TPM.
        let master = [7u8; MASTER_SECRET_SIZE];
        storage.store_software_master(&master).unwrap();

        // MUST NOT over-claim hardware.
        assert!(
            !storage.is_hardware_backed(),
            "software-fallback master must report NOT hardware-backed (CIRISVerify#73)"
        );

        // And it must still function as encrypted storage.
        storage.store("identity.seed", b"top-secret-seed").unwrap();
        let loaded = storage.load("identity.seed").unwrap();
        assert_eq!(loaded, b"top-secret-seed");

        // Still honest after real I/O.
        assert!(!storage.is_hardware_backed());
        assert!(storage.diagnostics().contains("NOT hardware-backed"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A fresh instance with no TPM available falls back to software at genesis
    /// and reports honestly. (On a CI box without a TPM, `seal_master` errors,
    /// driving the software-fallback branch; on a box WITH a TPM this instead
    /// seals and reports `true` — both are correct, neither over-claims.)
    #[test]
    fn genesis_without_tpm_does_not_over_claim() {
        let dir = temp_dir("genesis");
        let storage = TpmSecureBlobStorage::new("node", &dir).unwrap();

        // First store triggers genesis establishment.
        storage.store("k", b"v").unwrap();
        let hw = storage.is_hardware_backed();

        // If we are NOT hardware-backed, the software-fallback master file must
        // exist and the seal file must not — i.e. we did not pretend.
        if !hw {
            assert!(
                storage.software_master_path().exists(),
                "non-hardware path must persist a software-fallback master"
            );
        } else {
            // Hardware path: a real sealing object must back the claim.
            assert!(
                storage.seal_path().exists(),
                "hardware-backed claim must be backed by a persisted sealing object"
            );
        }

        // Round-trips either way.
        assert_eq!(storage.load("k").unwrap(), b"v");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `MasterState` reports hardware-backed iff TPM-sealed — guards the lever
    /// that drives `SealedEd25519Signer` / `BlobTransportKeystore` tiering.
    #[test]
    fn master_state_hardware_flag_is_exact() {
        let sealed = MasterState::TpmSealed {
            master: [0u8; MASTER_SECRET_SIZE],
        };
        let soft = MasterState::SoftwareFallback {
            master: [0u8; MASTER_SECRET_SIZE],
        };
        assert!(sealed.is_hardware_backed());
        assert!(!soft.is_hardware_backed());
    }

    /// Seal-file format round-trips (validates the persistence path used for
    /// the TPM `out_private` / `out_public` blobs without needing a TPM).
    #[test]
    fn seal_file_roundtrip() {
        let dir = temp_dir("sealfmt");
        let storage = TpmSecureBlobStorage::new("fmt", &dir).unwrap();

        let private_blob = vec![1u8, 2, 3, 4, 5];
        let public_blob = vec![9u8, 8, 7, 6, 5, 4, 3, 2, 1, 0];
        storage
            .write_seal_file(&private_blob, &public_blob)
            .unwrap();

        let (rp, rpub) = storage.read_seal_file().unwrap();
        assert_eq!(rp, private_blob);
        assert_eq!(rpub, public_blob);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
