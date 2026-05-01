//! Core types for hardware keyring operations.
//!
//! These types are designed to be compatible with Veilid's CryptoKind pattern,
//! using tagged enums for algorithm identification.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Classical cryptographic algorithm for hardware-bound signatures.
///
/// Mobile HSMs (Android Keystore, iOS Secure Enclave) only support ECDSA P-256.
/// TPM 2.0 supports ECDSA P-256, RSA, and some implementations support Ed25519.
/// For cross-platform consistency, ECDSA P-256 is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum ClassicalAlgorithm {
    /// ECDSA with NIST P-256 curve (secp256r1/prime256v1)
    /// Required for mobile HSMs. Default for cross-platform compatibility.
    #[default]
    EcdsaP256 = 1,

    /// Ed25519 Edwards curve signatures
    /// Used for SGX and software-only deployments.
    Ed25519 = 2,

    /// ECDSA with NIST P-384 curve (secp384r1)
    /// Optional higher security, supported by TPM 2.0.
    EcdsaP384 = 3,
}

impl ClassicalAlgorithm {
    /// Get the signature size in bytes for this algorithm.
    #[must_use]
    pub const fn signature_size(&self) -> usize {
        match self {
            Self::EcdsaP256 => 64, // R (32) + S (32)
            Self::Ed25519 => 64,
            Self::EcdsaP384 => 96, // R (48) + S (48)
        }
    }

    /// Get the public key size in bytes for this algorithm.
    #[must_use]
    pub const fn public_key_size(&self) -> usize {
        match self {
            Self::EcdsaP256 => 65, // Uncompressed: 0x04 || X (32) || Y (32)
            Self::Ed25519 => 32,
            Self::EcdsaP384 => 97, // Uncompressed: 0x04 || X (48) || Y (48)
        }
    }
}

/// Type of hardware security module.
///
/// This determines the security guarantees and maximum license tier available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum HardwareType {
    /// Android Hardware Keystore (TEE-backed)
    AndroidKeystore = 1,

    /// Android StrongBox (dedicated secure element)
    /// Higher security than standard Keystore.
    AndroidStrongbox = 2,

    /// Apple Secure Enclave (iOS/iPadOS)
    IosSecureEnclave = 3,

    /// Apple Secure Enclave (macOS)
    MacOsSecureEnclave = 12,

    /// Discrete TPM 2.0 (dedicated chip)
    /// Higher security than firmware TPM.
    TpmDiscrete = 4,

    /// Firmware TPM 2.0 (fTPM)
    /// Runs in CPU firmware/trusted execution environment.
    TpmFirmware = 5,

    /// Intel Software Guard Extensions
    IntelSgx = 6,

    /// Software-only implementation
    /// WARNING: Limited to UNLICENSED_COMMUNITY tier maximum.
    SoftwareOnly = 7,

    /// AWS CloudHSM (FIPS 140-2 Level 3)
    AwsCloudHsm = 8,

    /// Azure Dedicated HSM / Managed HSM
    AzureHsm = 9,

    /// Google Cloud HSM
    GcpCloudHsm = 10,

    /// Yubico YubiHSM 2
    YubiHsm = 11,
}

impl HardwareType {
    /// Check if this hardware type supports professional licensing.
    ///
    /// SOFTWARE_ONLY is limited to community tier due to lack of hardware binding.
    #[must_use]
    pub const fn supports_professional_license(&self) -> bool {
        !matches!(self, Self::SoftwareOnly)
    }

    /// Get the security level (1-5, higher is better).
    #[must_use]
    pub const fn security_level(&self) -> u8 {
        match self {
            // FIPS 140-2 Level 3+ HSMs
            Self::AwsCloudHsm => 5,
            Self::AzureHsm => 5,
            Self::GcpCloudHsm => 5,
            Self::YubiHsm => 5,
            // Hardware secure elements
            Self::AndroidStrongbox => 5,
            Self::TpmDiscrete => 5,
            Self::IosSecureEnclave | Self::MacOsSecureEnclave => 5,
            // Firmware/TEE-based
            Self::TpmFirmware => 4,
            Self::IntelSgx => 4,
            Self::AndroidKeystore => 3,
            // No hardware protection
            Self::SoftwareOnly => 1,
        }
    }
}

/// Platform-specific attestation data.
///
/// This proves to remote verifiers that the key is hardware-bound.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlatformAttestation {
    /// Android attestation data
    Android(AndroidAttestation),

    /// iOS attestation data
    Ios(IosAttestation),

    /// TPM attestation data
    Tpm(TpmAttestation),

    /// Software-only (no attestation)
    Software(SoftwareAttestation),
}

/// Android-specific attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidAttestation {
    /// Key attestation certificate chain (DER-encoded).
    /// Chain: key cert -> intermediate(s) -> Google root.
    pub key_attestation_chain: Vec<Vec<u8>>,

    /// Google Play Integrity API token (optional).
    /// Provides device integrity verdict.
    pub play_integrity_token: Option<String>,

    /// Whether StrongBox was used.
    pub strongbox_backed: bool,
}

/// iOS-specific attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosAttestation {
    /// Whether Secure Enclave was used.
    pub secure_enclave: bool,

    /// App Attest data (optional).
    /// Proves app integrity and Secure Enclave key binding.
    pub app_attest: Option<Vec<u8>>,

    /// DeviceCheck token (optional).
    /// Provides device-level fraud detection.
    pub device_check_token: Option<Vec<u8>>,
}

/// TPM 2.0 attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmAttestation {
    /// TPM version string.
    pub tpm_version: String,

    /// TPM manufacturer information.
    pub manufacturer: String,

    /// Whether this is a discrete TPM (vs firmware TPM).
    pub discrete: bool,

    /// TPM quote data (TPMS_ATTEST structure), if available.
    pub quote: Option<TpmQuoteData>,

    /// Endorsement Key certificate (X.509 DER), if available.
    /// Can be validated against manufacturer CA to prove TPM genuineness.
    pub ek_cert: Option<Vec<u8>>,

    /// Attestation Key public key (for verifying quotes).
    /// Anyone can verify the quote signature using this key.
    pub ak_public_key: Option<Vec<u8>>,
}

/// TPM quote data for remote attestation.
///
/// Contains all data needed for anyone to verify a TPM quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmQuoteData {
    /// The TPMS_ATTEST structure (marshalled).
    pub quoted: Vec<u8>,

    /// Signature over the quoted data (ECDSA P-256).
    pub signature: Vec<u8>,

    /// PCR selection bitmap.
    pub pcr_selection: Vec<u8>,

    /// Qualifying data (nonce) used in the quote.
    /// Verifiers should check this matches their challenge.
    pub qualifying_data: Vec<u8>,

    /// PCR values at time of quote (SHA-256 digests).
    /// Index in vec corresponds to PCR slot number.
    pub pcr_values: Option<Vec<PcrValue>>,

    /// Timestamp when quote was generated.
    pub timestamp: u64,
}

/// A single PCR value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValue {
    /// PCR slot index (0-23).
    pub index: u8,
    /// SHA-256 digest (32 bytes).
    pub digest: Vec<u8>,
}

/// Where a signer's identity material is stored.
///
/// This descriptor lets callers detect ephemeral storage at boot time
/// (e.g., container writable layer, `/tmp`) before identity churn starts
/// silently breaking longitudinal scoring. PoB §2.4's S-factor decay window
/// (30 days for trace-bearing primitives) cannot accumulate behind an
/// unstable identity, so an identity that silently relocates each restart
/// produces zero anti-Sybil weight by construction.
///
/// **Stability contract.** A signer's storage location must be stable
/// across the score window the primitive participates in. A descriptor
/// pointing at known-ephemeral storage (`/tmp`, `/var/cache`, container
/// writable layer without a mounted volume) is a configuration bug, not
/// a normal mode. Every `HardwareSigner` impl declares its descriptor
/// through `HardwareSigner::storage_descriptor()`; consumers (boot-time
/// logging, `/health` reporters, `--strict-storage` flags) decide what
/// to do about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StorageDescriptor {
    /// Hardware-protected key.
    ///
    /// `blob_path` is informational. Some hardware backends (Android
    /// Keystore via `SecureBlobStorage`, TPM-wrapped Ed25519) write a
    /// hardware-wrapped envelope to disk. The envelope is useless without
    /// the underlying HSM, so its presence does NOT imply ephemerality
    /// risk. Absence (file deleted) means "key is gone," not "ephemeral
    /// storage." Other backends (iOS Secure Enclave, Windows Platform
    /// Crypto Provider) keep the key entirely inside the HSM and report
    /// `blob_path: None`.
    Hardware {
        /// Hardware backend type.
        hardware_type: HardwareType,
        /// Path to a hardware-wrapped envelope file, if the backend
        /// stores one. `None` means the key lives entirely inside the HSM.
        blob_path: Option<PathBuf>,
    },
    /// Software-protected seed file on the local filesystem.
    ///
    /// This is the case a "warn on ephemeral path" heuristic must match
    /// against. If `path` is in `/tmp`, `/var/cache`, or a container
    /// writable layer without a mounted volume, the identity will not
    /// persist across restarts and the failure mode that motivated this
    /// type (lens-scrub key churn) reproduces.
    SoftwareFile {
        /// Filesystem path to the seed.
        path: PathBuf,
    },
    /// OS-managed keyring (secret-service, Keychain, DPAPI).
    ///
    /// Has its own ephemerality model. A user-scope keyring entry
    /// disappears when the user session ends and is unsuitable for
    /// longitudinal-score primitives. System-scope entries survive logout
    /// and reboot but typically require elevated privileges to write.
    SoftwareOsKeyring {
        /// Backend identifier (e.g., `"secret-service"`, `"keychain"`,
        /// `"dpapi"`).
        backend: String,
        /// Keyring scope.
        scope: KeyringScope,
    },
    /// Key material is held only in process memory.
    ///
    /// The signer has no persistent storage of its own. A higher-level
    /// wrapper (e.g., a `SecureBlobStorage`-backed manager) is expected
    /// to provide persistence. If the signer is used standalone, the key
    /// dies with the process.
    ///
    /// This is structurally distinct from `SoftwareFile`: it's not
    /// ephemeral by accident, it's RAM-only by design (Portal-imported
    /// keys, dev/test scenarios). A primitive consuming a bare
    /// `InMemory` signer for longitudinal-score purposes is a bug.
    InMemory,
}

/// Scope of an OS keyring entry.
///
/// Distinguishes user-session-bound storage (which disappears at logout)
/// from system-scoped storage (which survives reboot).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyringScope {
    /// User-session-scoped. Disappears at logout / session end.
    /// NOT suitable for longitudinal-score primitives.
    User,
    /// System-scoped. Survives logout and reboot.
    System,
    /// Backend does not expose a scope distinction; treat as unknown.
    Unknown,
}

impl StorageDescriptor {
    /// Whether the underlying key is protected by a hardware security
    /// module.
    ///
    /// Returns `true` only for the `Hardware` variant. Both software
    /// variants return `false`, regardless of whether the seed is on
    /// disk or in an OS keyring.
    #[must_use]
    pub fn is_hardware_backed(&self) -> bool {
        matches!(self, Self::Hardware { .. })
    }

    /// Filesystem path the descriptor exposes, if any.
    ///
    /// - `Hardware`: returns the wrapped-envelope path (`blob_path`) if
    ///   the backend stores one. The envelope is useless without the
    ///   HSM, so this path's directory is not subject to ephemerality
    ///   heuristics.
    /// - `SoftwareFile`: returns the seed path. This IS the path that
    ///   ephemeral-storage heuristics must check.
    /// - `SoftwareOsKeyring`, `InMemory`: always return `None`.
    #[must_use]
    pub fn disk_path(&self) -> Option<&Path> {
        match self {
            Self::Hardware { blob_path, .. } => blob_path.as_deref(),
            Self::SoftwareFile { path } => Some(path.as_path()),
            Self::SoftwareOsKeyring { .. } | Self::InMemory => None,
        }
    }

    /// Hardware backend type, if the descriptor is hardware-backed.
    ///
    /// Returns `None` for both software variants.
    #[must_use]
    pub fn hardware_type(&self) -> Option<HardwareType> {
        match self {
            Self::Hardware { hardware_type, .. } => Some(*hardware_type),
            _ => None,
        }
    }
}

/// Software-only attestation (minimal).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareAttestation {
    /// Key derivation method.
    pub key_derivation: String,

    /// Storage backend used.
    pub storage: String,

    /// Security warning for software-only deployments.
    pub security_warning: String,
}

impl Default for SoftwareAttestation {
    fn default() -> Self {
        Self {
            key_derivation: "random".to_string(),
            storage: "memory".to_string(),
            security_warning: "SOFTWARE_ONLY: No hardware binding available. \
                               This deployment is limited to UNLICENSED_COMMUNITY tier. \
                               Keys can be extracted by an attacker with system access."
                .to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_sizes() {
        assert_eq!(ClassicalAlgorithm::EcdsaP256.signature_size(), 64);
        assert_eq!(ClassicalAlgorithm::EcdsaP256.public_key_size(), 65);
        assert_eq!(ClassicalAlgorithm::Ed25519.signature_size(), 64);
        assert_eq!(ClassicalAlgorithm::Ed25519.public_key_size(), 32);
    }

    #[test]
    fn test_hardware_type_professional_support() {
        assert!(HardwareType::AndroidStrongbox.supports_professional_license());
        assert!(HardwareType::IosSecureEnclave.supports_professional_license());
        assert!(HardwareType::TpmDiscrete.supports_professional_license());
        assert!(HardwareType::TpmFirmware.supports_professional_license());
        assert!(!HardwareType::SoftwareOnly.supports_professional_license());
    }

    #[test]
    fn test_storage_descriptor_hardware_backed() {
        let hw = StorageDescriptor::Hardware {
            hardware_type: HardwareType::TpmFirmware,
            blob_path: Some(PathBuf::from("/var/lib/ciris/key.tpm")),
        };
        let sw = StorageDescriptor::SoftwareFile {
            path: PathBuf::from("/var/lib/ciris/key.bin"),
        };
        let kr = StorageDescriptor::SoftwareOsKeyring {
            backend: "secret-service".to_string(),
            scope: KeyringScope::User,
        };

        assert!(hw.is_hardware_backed());
        assert!(!sw.is_hardware_backed());
        assert!(!kr.is_hardware_backed());
    }

    #[test]
    fn test_storage_descriptor_disk_path() {
        let hw_with_blob = StorageDescriptor::Hardware {
            hardware_type: HardwareType::TpmFirmware,
            blob_path: Some(PathBuf::from("/var/lib/ciris/key.tpm")),
        };
        let hw_no_blob = StorageDescriptor::Hardware {
            hardware_type: HardwareType::IosSecureEnclave,
            blob_path: None,
        };
        let sw = StorageDescriptor::SoftwareFile {
            path: PathBuf::from("/var/lib/ciris/key.bin"),
        };
        let kr = StorageDescriptor::SoftwareOsKeyring {
            backend: "keychain".to_string(),
            scope: KeyringScope::System,
        };

        assert_eq!(
            hw_with_blob.disk_path(),
            Some(Path::new("/var/lib/ciris/key.tpm"))
        );
        assert_eq!(hw_no_blob.disk_path(), None);
        assert_eq!(sw.disk_path(), Some(Path::new("/var/lib/ciris/key.bin")));
        assert_eq!(kr.disk_path(), None);
    }

    #[test]
    fn test_storage_descriptor_hardware_type_accessor() {
        let hw = StorageDescriptor::Hardware {
            hardware_type: HardwareType::AndroidStrongbox,
            blob_path: None,
        };
        let sw = StorageDescriptor::SoftwareFile {
            path: PathBuf::from("/tmp/x"),
        };

        assert_eq!(hw.hardware_type(), Some(HardwareType::AndroidStrongbox));
        assert_eq!(sw.hardware_type(), None);
    }

    #[test]
    fn test_storage_descriptor_serde_roundtrip() {
        // Hardware variant with blob path
        let hw = StorageDescriptor::Hardware {
            hardware_type: HardwareType::TpmDiscrete,
            blob_path: Some(PathBuf::from("/var/lib/ciris/key.tpm")),
        };
        let json = serde_json::to_string(&hw).unwrap();
        let back: StorageDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(hw, back);

        // SoftwareFile variant
        let sw = StorageDescriptor::SoftwareFile {
            path: PathBuf::from("/home/u/.local/share/ciris/key.bin"),
        };
        let json = serde_json::to_string(&sw).unwrap();
        let back: StorageDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(sw, back);

        // SoftwareOsKeyring variant with all scopes
        for scope in [
            KeyringScope::User,
            KeyringScope::System,
            KeyringScope::Unknown,
        ] {
            let kr = StorageDescriptor::SoftwareOsKeyring {
                backend: "secret-service".to_string(),
                scope,
            };
            let json = serde_json::to_string(&kr).unwrap();
            let back: StorageDescriptor = serde_json::from_str(&json).unwrap();
            assert_eq!(kr, back);
        }
    }

    #[test]
    fn test_storage_descriptor_in_memory() {
        let im = StorageDescriptor::InMemory;
        assert!(!im.is_hardware_backed());
        assert_eq!(im.disk_path(), None);
        assert_eq!(im.hardware_type(), None);

        let json = serde_json::to_string(&im).unwrap();
        let back: StorageDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(im, back);
    }

    #[test]
    fn test_storage_descriptor_serde_tag_format() {
        // Verify the JSON tag format matches what FFI consumers expect:
        // {"kind": "hardware", "hardware_type": ..., "blob_path": ...}
        let hw = StorageDescriptor::Hardware {
            hardware_type: HardwareType::TpmFirmware,
            blob_path: None,
        };
        let json: serde_json::Value = serde_json::to_value(&hw).unwrap();
        assert_eq!(json["kind"], "hardware");

        let sw = StorageDescriptor::SoftwareFile {
            path: PathBuf::from("/x"),
        };
        let json: serde_json::Value = serde_json::to_value(&sw).unwrap();
        assert_eq!(json["kind"], "software_file");

        let kr = StorageDescriptor::SoftwareOsKeyring {
            backend: "dpapi".to_string(),
            scope: KeyringScope::Unknown,
        };
        let json: serde_json::Value = serde_json::to_value(&kr).unwrap();
        assert_eq!(json["kind"], "software_os_keyring");
        assert_eq!(json["scope"], "unknown");

        let im = StorageDescriptor::InMemory;
        let json: serde_json::Value = serde_json::to_value(&im).unwrap();
        assert_eq!(json["kind"], "in_memory");
    }

    #[test]
    fn test_storage_descriptor_emits_hardware_type_as_string() {
        // FFI consumers (Python, Swift) need to know exactly what serde
        // emits for `hardware_type`. The repr(u8) on HardwareType is for
        // FFI integer wire formats elsewhere; with the default serde
        // derive, unit-variant enums serialize as the variant name.
        let hw = StorageDescriptor::Hardware {
            hardware_type: HardwareType::TpmFirmware,
            blob_path: None,
        };
        let json: serde_json::Value = serde_json::to_value(&hw).unwrap();
        assert_eq!(
            json["hardware_type"], "TpmFirmware",
            "FFI doc claims hardware_type is the PascalCase variant name; \
             if this assertion fails, update the FFI doc + Python bindings."
        );
    }
}
