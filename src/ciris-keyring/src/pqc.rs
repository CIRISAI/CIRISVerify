//! Post-quantum signer trait and software implementation for ciris-keyring.
//!
//! This module is the PQC parallel to [`crate::HardwareSigner`] and
//! [`crate::Ed25519SoftwareSigner`]. It exists so consumers (CIRISPersist's
//! cold-path PQC fill-in flow, future federation_keys / federation_attestations
//! / federation_revocations writers) can ask the keyring for an ML-DSA-65
//! signer the same way they ask for a classical signer today, without
//! reaching directly into the `ml-dsa` crate and bypassing the keyring's
//! storage-descriptor + lifecycle abstraction.
//!
//! ## Why a separate trait (not `HardwareSigner` extended)
//!
//! Software-only is the realistic posture for ML-DSA in 2026 — no production
//! HSM ships ML-DSA primitives. A separate [`PqcSigner`] trait lets persist
//! get an `MlDsa65SoftwareSigner` today without churning the existing
//! classical-only [`HardwareSigner`] impls. When hybrid-HW lands (likely
//! 2030+ per major vendor roadmaps), a unified hybrid trait can subsume
//! both; until then, the parallel-trait shape is the lowest-friction path.
//!
//! ## Trait collision with `ciris_crypto::PqcSigner`
//!
//! `ciris-crypto` already exposes a synchronous `PqcSigner` trait used
//! internally by `HybridSigner` to compose hybrid signatures. That trait is
//! the cryptographic primitive; this module's [`PqcSigner`] is the keyring
//! abstraction (async, with storage descriptor, lifecycle, attestation).
//! They live in distinct crate namespaces; the
//! `MlDsa65SoftwareSigner` here implements both so a single struct can be
//! consumed by either layer.

use std::path::PathBuf;

use async_trait::async_trait;

use crate::error::KeyringError;
use crate::types::{HardwareType, PlatformAttestation, SoftwareAttestation, StorageDescriptor};

// Re-export PqcAlgorithm from ciris-crypto so downstream consumers don't need
// to take a separate ciris-crypto dependency just to name the algorithm.
pub use ciris_crypto::PqcAlgorithm;

/// Async trait for post-quantum cryptographic signing in the keyring layer.
///
/// Parallel to [`crate::HardwareSigner`]. Where `HardwareSigner` covers
/// classical algorithms (Ed25519, ECDSA P-256/P-384), `PqcSigner` covers
/// post-quantum algorithms (ML-DSA-44/65/87 today; SLH-DSA in the future).
///
/// ## Why async + storage_descriptor
///
/// Same rationale as [`crate::HardwareSigner`]: future hardware
/// implementations (post-quantum HSMs, secure enclaves with PQC primitives)
/// will need async APIs, and consumers (e.g., persist's cold-path writer)
/// need to know "where does this key live?" via [`StorageDescriptor`] for
/// the same identity-stability reasons that motivated the classical
/// descriptor.
///
/// ## Example
///
/// ```rust,ignore
/// use ciris_keyring::{get_platform_pqc_signer, PqcAlgorithm, PqcSigner};
///
/// async fn sign_cold_path(canonical: &[u8], classical_sig: &[u8])
///     -> Result<Vec<u8>, ciris_keyring::KeyringError>
/// {
///     let signer = get_platform_pqc_signer("steward-pqc-2026", PqcAlgorithm::MlDsa65)?;
///     let mut input = Vec::with_capacity(canonical.len() + classical_sig.len());
///     input.extend_from_slice(canonical);
///     input.extend_from_slice(classical_sig);
///     signer.sign(&input).await
/// }
/// ```
#[async_trait]
pub trait PqcSigner: Send + Sync {
    /// Get the PQC algorithm used by this signer.
    fn algorithm(&self) -> PqcAlgorithm;

    /// Get the hardware type for this signer.
    ///
    /// All current PQC implementations are software-only ([`HardwareType::SoftwareOnly`])
    /// because no production HSM ships ML-DSA primitives in 2026. When hardware
    /// PQC arrives this becomes more interesting.
    fn hardware_type(&self) -> HardwareType;

    /// Get the public key.
    ///
    /// Format depends on the algorithm:
    /// - ML-DSA-44: 1312 bytes
    /// - ML-DSA-65: 1952 bytes
    /// - ML-DSA-87: 2592 bytes
    ///
    /// # Errors
    ///
    /// Returns error if the key doesn't exist or cannot be accessed.
    async fn public_key(&self) -> Result<Vec<u8>, KeyringError>;

    /// Sign data with the PQC private key.
    ///
    /// # Returns
    ///
    /// Signature bytes per FIPS 204 final:
    /// - ML-DSA-44: 2420 bytes
    /// - ML-DSA-65: 3309 bytes
    /// - ML-DSA-87: 4627 bytes
    ///
    /// # Errors
    ///
    /// Returns error if the key doesn't exist or signing fails.
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError>;

    /// Get attestation data.
    ///
    /// Software signers return [`PlatformAttestation::Software`] with a
    /// SOFTWARE_ONLY warning. Hardware-backed PQC signers (when they exist)
    /// will return platform-specific attestation matching their backend.
    ///
    /// # Errors
    ///
    /// Returns error if attestation cannot be generated.
    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError>;

    /// Get the key alias currently in use.
    fn current_alias(&self) -> &str;

    /// Declare where this signer stores its identity material.
    ///
    /// **No default implementation** — every signer variant declares its
    /// own descriptor. Same stability contract as
    /// [`crate::HardwareSigner::storage_descriptor`]: a key whose storage
    /// disappears across restarts cannot accumulate longitudinal score, so
    /// consumers (boot-time logging, `--strict-storage` checks) need to
    /// detect ephemeral storage before identity churn starts breaking
    /// scoring.
    fn storage_descriptor(&self) -> StorageDescriptor;
}

/// Software ML-DSA-65 signer for the cold-path PQC fill-in flow.
///
/// Parallel to [`crate::Ed25519SoftwareSigner`] — holds an in-memory ML-DSA-65
/// keypair (typically loaded from a Portal-issued seed file or a
/// [`crate::SecureBlobStorage`]-managed wrapper) and implements [`PqcSigner`]
/// against it.
///
/// **Wire format**: bytes match `ml-dsa = 0.1.0-rc.3` (FIPS 204 final). Cross-
/// implementation byte-equivalence with `dilithium-py` (Python reference impl)
/// has been independently verified during the lens-steward bootstrap. Any
/// downstream consumer can verify the signature with either implementation.
///
/// **Storage descriptor**: this signer reports [`StorageDescriptor::InMemory`]
/// or [`StorageDescriptor::SoftwareFile`] depending on construction. If you
/// load via [`Self::from_seed_bytes`] the seed is in process memory and the
/// descriptor is `InMemory`; if you load via [`Self::from_seed_file`] the
/// descriptor is `SoftwareFile { path }` and ephemeral-storage heuristics can
/// fire on it the same way they do for classical software signers.
pub struct MlDsa65SoftwareSigner {
    // Boxed because ML-DSA-65 SigningKey + VerifyingKey are ~6KB combined; passing
    // by value through multiple `Result<Self, _>` returns during construction
    // overflows test-thread stacks (Linux 2MB default). Heap allocation keeps
    // construction stack frames small.
    inner: Option<Box<ciris_crypto::MlDsa65Signer>>,
    alias: String,
    seed_path: Option<PathBuf>,
}

impl std::fmt::Debug for MlDsa65SoftwareSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsa65SoftwareSigner")
            .field("alias", &self.alias)
            .field("has_key", &self.inner.is_some())
            .field("seed_path", &self.seed_path)
            .finish()
    }
}

impl MlDsa65SoftwareSigner {
    /// Create a new ML-DSA-65 signer with no key loaded.
    ///
    /// Use [`Self::import_seed`], [`Self::from_seed_bytes`], or
    /// [`Self::from_seed_file`] to load a key.
    #[must_use]
    pub fn new(alias: impl Into<String>) -> Self {
        let alias = alias.into();
        tracing::info!(
            alias = %alias,
            "MlDsa65SoftwareSigner: created (no key loaded)"
        );
        Self {
            inner: None,
            alias,
            seed_path: None,
        }
    }

    /// Create a signer from raw 32-byte ML-DSA-65 seed.
    ///
    /// The seed bytes are consumed into an [`ml_dsa::SigningKey`] via
    /// `MlDsa65::from_seed`. This is the format the lens-steward bootstrap
    /// uses (matches `dilithium-py`'s `from_seed`).
    ///
    /// # Errors
    ///
    /// Returns [`KeyringError::InvalidKey`] if `seed_bytes.len() != 32`.
    pub fn from_seed_bytes(
        seed_bytes: &[u8],
        alias: impl Into<String>,
    ) -> Result<Self, KeyringError> {
        let alias = alias.into();
        if seed_bytes.len() != 32 {
            return Err(KeyringError::InvalidKey {
                reason: format!("ML-DSA-65 seed must be 32 bytes, got {}", seed_bytes.len()),
            });
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(seed_bytes);

        let inner = Box::new(ciris_crypto::MlDsa65Signer::from_seed(&seed).map_err(|e| {
            KeyringError::InvalidKey {
                reason: format!("ML-DSA-65 seed rejected by ciris-crypto: {e}"),
            }
        })?);

        tracing::info!(alias = %alias, "MlDsa65SoftwareSigner: key imported from bytes");
        tracing::warn!(
            "MlDsa65SoftwareSigner: NO HARDWARE BINDING — software-only PQC signing, \
             suitable for cold-path fill-in but not for tier-restricted operations"
        );

        Ok(Self {
            inner: Some(inner),
            alias,
            seed_path: None,
        })
    }

    /// Create a signer by reading a 32-byte seed from a file.
    ///
    /// Records the path in the [`StorageDescriptor`] so consumers can detect
    /// ephemeral-storage paths (`/tmp`, container writable layer) at boot.
    ///
    /// # Errors
    ///
    /// - [`KeyringError::OperationFailed`] if the file cannot be read.
    /// - [`KeyringError::InvalidKey`] if the file is not exactly 32 bytes.
    pub fn from_seed_file(
        path: impl Into<PathBuf>,
        alias: impl Into<String>,
    ) -> Result<Self, KeyringError> {
        let path = path.into();
        let alias = alias.into();
        let bytes = std::fs::read(&path).map_err(|e| KeyringError::OperationFailed {
            reason: format!("reading ML-DSA-65 seed from {}: {e}", path.display()),
        })?;
        let mut signer = Self::from_seed_bytes(&bytes, alias)?;
        signer.seed_path = Some(path);
        Ok(signer)
    }

    /// Import a seed into an existing signer, replacing any current key.
    ///
    /// # Errors
    ///
    /// Returns [`KeyringError::InvalidKey`] if `seed_bytes.len() != 32`.
    pub fn import_seed(&mut self, seed_bytes: &[u8]) -> Result<(), KeyringError> {
        let new = Self::from_seed_bytes(seed_bytes, &self.alias)?;
        self.inner = new.inner;
        self.seed_path = None;
        tracing::info!(alias = %self.alias, "MlDsa65SoftwareSigner: seed re-imported");
        Ok(())
    }

    /// Whether a key is currently loaded.
    #[must_use]
    pub fn has_key(&self) -> bool {
        self.inner.is_some()
    }
}

#[async_trait]
impl PqcSigner for MlDsa65SoftwareSigner {
    fn algorithm(&self) -> PqcAlgorithm {
        PqcAlgorithm::MlDsa65
    }

    fn hardware_type(&self) -> HardwareType {
        HardwareType::SoftwareOnly
    }

    async fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| KeyringError::KeyNotFound {
                alias: self.alias.clone(),
            })?;
        // ciris_crypto::PqcSigner is sync; deref Box<MlDsa65Signer> to &MlDsa65Signer.
        ciris_crypto::PqcSigner::public_key(&**inner).map_err(|e| KeyringError::HardwareError {
            reason: format!("ML-DSA-65 public_key: {e}"),
        })
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| KeyringError::KeyNotFound {
                alias: self.alias.clone(),
            })?;
        ciris_crypto::PqcSigner::sign(&**inner, data).map_err(|e| KeyringError::HardwareError {
            reason: format!("ML-DSA-65 sign: {e}"),
        })
    }

    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
        Ok(PlatformAttestation::Software(SoftwareAttestation {
            key_derivation: "seed-bytes-or-file".to_string(),
            storage: match &self.seed_path {
                Some(p) => format!("software-file:{}", p.display()),
                None => "memory".to_string(),
            },
            security_warning: "SOFTWARE_ONLY: ML-DSA-65 signer has no hardware binding. \
                               Suitable for cold-path PQC fill-in (federation_keys, \
                               federation_attestations, federation_revocations) where \
                               classical Ed25519 hot-path covers the synchronous critical \
                               path. NOT suitable for tier-restricted operations until \
                               PQC HSMs ship."
                .to_string(),
        }))
    }

    fn current_alias(&self) -> &str {
        &self.alias
    }

    fn storage_descriptor(&self) -> StorageDescriptor {
        match &self.seed_path {
            Some(path) => StorageDescriptor::SoftwareFile { path: path.clone() },
            None => StorageDescriptor::InMemory,
        }
    }
}

/// Get the platform-best PQC signer for the given algorithm.
///
/// **Today (v1.9.0)**: returns [`MlDsa65SoftwareSigner`] for ML-DSA-65;
/// returns [`KeyringError::HardwareError`] for any other algorithm (no other
/// PQC algorithms have keyring impls yet).
///
/// **Tomorrow (post-quantum HSM era, ~2030+)**: this factory will probe for
/// hardware backends (post-quantum HSM, secure-enclave PQC primitives) and
/// fall back to software only when hardware is unavailable — the same
/// pattern [`crate::platform::get_platform_signer`] uses for classical
/// algorithms today.
///
/// # Behavior in v1.9.0
///
/// The signer is returned WITHOUT a loaded key. Callers must load via
/// [`MlDsa65SoftwareSigner::import_seed`], [`MlDsa65SoftwareSigner::from_seed_bytes`],
/// or [`MlDsa65SoftwareSigner::from_seed_file`] before signing. (This matches
/// the `Ed25519SoftwareSigner::new` pattern; see [`crate::Ed25519SoftwareSigner`].)
///
/// # Errors
///
/// Returns [`KeyringError::HardwareError`] if `algorithm` is not currently
/// supported by any keyring impl.
pub fn get_platform_pqc_signer(
    key_id: &str,
    algorithm: PqcAlgorithm,
) -> Result<Box<dyn PqcSigner>, KeyringError> {
    match algorithm {
        PqcAlgorithm::MlDsa65 => Ok(Box::new(MlDsa65SoftwareSigner::new(key_id))),
        other => Err(KeyringError::HardwareError {
            reason: format!(
                "no keyring impl for PQC algorithm {other:?} in v1.9.0 \
                 (only ML-DSA-65 is wired today)"
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn deterministic_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        seed
    }

    #[test]
    fn signer_starts_keyless() {
        let s = MlDsa65SoftwareSigner::new("test-pqc");
        assert!(!s.has_key());
        assert_eq!(s.current_alias(), "test-pqc");
        assert_eq!(s.algorithm(), PqcAlgorithm::MlDsa65);
        assert_eq!(s.hardware_type(), HardwareType::SoftwareOnly);
        assert_eq!(s.storage_descriptor(), StorageDescriptor::InMemory);
    }

    #[tokio::test]
    async fn sign_and_public_key_roundtrip() {
        let seed = deterministic_seed();
        let s = MlDsa65SoftwareSigner::from_seed_bytes(&seed, "roundtrip").unwrap();

        let pk = s.public_key().await.unwrap();
        // ML-DSA-65 public key is 1952 bytes per FIPS 204 final.
        assert_eq!(pk.len(), 1952);

        let sig = s.sign(b"cold-path-canary").await.unwrap();
        // ML-DSA-65 signature is 3309 bytes per FIPS 204 final.
        assert_eq!(sig.len(), 3309);
    }

    #[tokio::test]
    async fn deterministic_signer_produces_stable_pubkey() {
        // Same seed → same public key. This is the property that makes
        // the lens-steward bootstrap reproducible across Rust + Python.
        let seed = deterministic_seed();
        let a = MlDsa65SoftwareSigner::from_seed_bytes(&seed, "a").unwrap();
        let b = MlDsa65SoftwareSigner::from_seed_bytes(&seed, "b").unwrap();
        assert_eq!(a.public_key().await.unwrap(), b.public_key().await.unwrap());
    }

    #[test]
    fn from_seed_bytes_rejects_wrong_length() {
        let err = MlDsa65SoftwareSigner::from_seed_bytes(&[0u8; 31], "short").unwrap_err();
        assert!(matches!(err, KeyringError::InvalidKey { .. }));
        let err = MlDsa65SoftwareSigner::from_seed_bytes(&[0u8; 64], "long").unwrap_err();
        assert!(matches!(err, KeyringError::InvalidKey { .. }));
    }

    #[test]
    fn from_seed_file_records_path_in_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let seed_path = dir.path().join("ml-dsa-65.seed");
        let mut f = std::fs::File::create(&seed_path).unwrap();
        f.write_all(&deterministic_seed()).unwrap();
        drop(f);

        let s = MlDsa65SoftwareSigner::from_seed_file(&seed_path, "from-file").unwrap();
        assert!(s.has_key());
        match s.storage_descriptor() {
            StorageDescriptor::SoftwareFile { path } => assert_eq!(path, seed_path),
            other => panic!("expected SoftwareFile, got {other:?}"),
        }
    }

    #[test]
    fn from_seed_file_rejects_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let seed_path = dir.path().join("bad.seed");
        std::fs::write(&seed_path, b"not-32-bytes").unwrap();
        let err = MlDsa65SoftwareSigner::from_seed_file(&seed_path, "bad").unwrap_err();
        assert!(matches!(err, KeyringError::InvalidKey { .. }));
    }

    #[tokio::test]
    async fn import_seed_replaces_key() {
        let mut s = MlDsa65SoftwareSigner::new("reimport");
        assert!(!s.has_key());
        s.import_seed(&deterministic_seed()).unwrap();
        assert!(s.has_key());
        let pk1 = s.public_key().await.unwrap();

        // Reimport with a different seed → different pubkey
        let mut alt = [0u8; 32];
        for (i, b) in alt.iter_mut().enumerate() {
            *b = (255 - i) as u8;
        }
        s.import_seed(&alt).unwrap();
        let pk2 = s.public_key().await.unwrap();
        assert_ne!(pk1, pk2);
    }

    #[tokio::test]
    async fn keyless_signer_returns_key_not_found() {
        let s = MlDsa65SoftwareSigner::new("keyless");
        let err = s.sign(b"nope").await.unwrap_err();
        assert!(matches!(err, KeyringError::KeyNotFound { .. }));
        let err = s.public_key().await.unwrap_err();
        assert!(matches!(err, KeyringError::KeyNotFound { .. }));
    }

    #[tokio::test]
    async fn attestation_is_software_only_with_warning() {
        let s = MlDsa65SoftwareSigner::from_seed_bytes(&deterministic_seed(), "attest").unwrap();
        match s.attestation().await.unwrap() {
            PlatformAttestation::Software(att) => {
                assert!(att.security_warning.contains("SOFTWARE_ONLY"));
                assert!(att.security_warning.contains("ML-DSA-65"));
                assert_eq!(att.storage, "memory");
            },
            other => panic!("expected Software attestation, got {other:?}"),
        }
    }

    #[test]
    fn factory_returns_software_signer_for_ml_dsa_65() {
        let signer = get_platform_pqc_signer("steward-pqc", PqcAlgorithm::MlDsa65).unwrap();
        assert_eq!(signer.algorithm(), PqcAlgorithm::MlDsa65);
        assert_eq!(signer.hardware_type(), HardwareType::SoftwareOnly);
        assert_eq!(signer.current_alias(), "steward-pqc");
    }

    #[test]
    fn factory_rejects_unsupported_algorithm() {
        // Box<dyn PqcSigner> doesn't impl Debug, so we can't unwrap_err — match instead.
        match get_platform_pqc_signer("x", PqcAlgorithm::MlDsa44) {
            Err(KeyringError::HardwareError { .. }) => {},
            Err(other) => panic!("expected HardwareError for MlDsa44, got {other:?}"),
            Ok(_) => panic!("expected error for MlDsa44, got Ok"),
        }
        match get_platform_pqc_signer("x", PqcAlgorithm::MlDsa87) {
            Err(KeyringError::HardwareError { .. }) => {},
            Err(other) => panic!("expected HardwareError for MlDsa87, got {other:?}"),
            Ok(_) => panic!("expected error for MlDsa87, got Ok"),
        }
    }
}
