//! Hardware-signed manifest cache for offline L1 verification.
//!
//! When internet connectivity is lost, this module provides persistent
//! storage for registry manifests that are cryptographically signed by
//! the device's hardware key. This ensures:
//!
//! 1. **Authenticity**: Only this device could have created the cache
//! 2. **Integrity**: Tampering invalidates the hardware signature
//! 3. **Provenance**: The signature proves successful registry verification
//!
//! ## Security Model
//!
//! The cached manifest is signed by the Ed25519 hardware key (TPM/SE/Keystore).
//! A forked binary cannot:
//! - Create valid signed manifests (no access to hardware key)
//! - Modify cached hashes (signature verification fails)
//! - Backdate the cache (signature covers timestamp)
//!
//! ## No Expiration
//!
//! The hashes are immutable facts about the binary. If the hardware key
//! signed them after successful registry verification, they remain valid
//! as long as:
//! - The binary hasn't changed
//! - The hardware key is intact
//!
//! If internet access is permanently lost, the agent can still reach L1
//! (self-verification) using the cached manifest.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};

use crate::registry::{BinaryManifest, BuildRecord};
use crate::security::function_integrity::FunctionManifest;

/// Filename for the signed manifest cache.
const MANIFEST_CACHE_FILENAME: &str = "manifest_cache.signed";

/// Signed manifest cache containing all manifests needed for offline L1 verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifestCache {
    /// Binary manifest (target triple → SHA-256 hash).
    pub binary_manifest: BinaryManifest,
    /// Function manifest for integrity verification.
    pub function_manifest: Option<FunctionManifest>,
    /// Agent build record for file integrity (optional).
    pub build_record: Option<BuildRecordCache>,
    /// Unix timestamp when the cache was created.
    pub cached_at: i64,
    /// CIRISVerify version that created this cache.
    pub verify_version: String,
    /// Target triple this cache was created on.
    pub target: String,
    /// Ed25519 public key fingerprint (SHA-256 hex, 64 chars).
    /// Used to verify the signature was made by the expected key.
    pub public_key_fingerprint: String,
    /// Ed25519 signature over the canonical cache data.
    /// Signs: SHA-256(canonical_json(manifest_data))
    #[serde(with = "hex_serde")]
    pub signature: Vec<u8>,
}

/// Cached build record (subset of BuildRecord for serialization).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRecordCache {
    /// Agent version.
    pub version: String,
    /// File manifest: path → SHA-256 hash.
    pub files: HashMap<String, String>,
    /// Manifest hash for quick verification.
    pub manifest_hash: String,
}

impl From<&BuildRecord> for BuildRecordCache {
    fn from(record: &BuildRecord) -> Self {
        Self {
            version: record.version.clone(),
            files: record.file_manifest_json.files().clone(),
            manifest_hash: record.file_manifest_hash.clone(),
        }
    }
}

/// Data to be signed (excludes signature field).
#[derive(Debug, Serialize)]
struct ManifestDataToSign<'a> {
    binary_manifest: &'a BinaryManifest,
    function_manifest: &'a Option<FunctionManifest>,
    build_record: &'a Option<BuildRecordCache>,
    cached_at: i64,
    verify_version: &'a str,
    target: &'a str,
    public_key_fingerprint: &'a str,
}

/// Hex serialization for signature bytes.
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

impl SignedManifestCache {
    /// Create a new unsigned manifest cache.
    ///
    /// Call `sign()` to add the hardware signature before saving.
    pub fn new(
        binary_manifest: BinaryManifest,
        function_manifest: Option<FunctionManifest>,
        build_record: Option<&BuildRecord>,
        public_key_fingerprint: String,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        Self {
            binary_manifest,
            function_manifest,
            build_record: build_record.map(BuildRecordCache::from),
            cached_at: now,
            verify_version: env!("CARGO_PKG_VERSION").to_string(),
            target: crate::registry::current_target().to_string(),
            public_key_fingerprint,
            signature: Vec::new(),
        }
    }

    /// Compute the SHA-256 hash of the data to be signed.
    pub fn compute_signing_hash(&self) -> [u8; 32] {
        let data = ManifestDataToSign {
            binary_manifest: &self.binary_manifest,
            function_manifest: &self.function_manifest,
            build_record: &self.build_record,
            cached_at: self.cached_at,
            verify_version: &self.verify_version,
            target: &self.target,
            public_key_fingerprint: &self.public_key_fingerprint,
        };

        // Canonical JSON serialization for deterministic hashing
        let json = serde_json::to_string(&data).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(b"ciris-manifest-cache-v1:");
        hasher.update(json.as_bytes());
        hasher.finalize().into()
    }

    /// Set the signature (called after signing with hardware key).
    pub fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }

    /// Verify the signature against the provided public key.
    ///
    /// Returns `true` if signature is valid.
    pub fn verify_signature(&self, public_key: &[u8]) -> bool {
        if self.signature.len() != 64 {
            warn!(
                "Manifest cache: invalid signature length ({})",
                self.signature.len()
            );
            return false;
        }

        // Verify public key fingerprint matches
        let fingerprint = compute_fingerprint(public_key);
        if fingerprint != self.public_key_fingerprint {
            warn!(
                "Manifest cache: fingerprint mismatch (expected {}, got {})",
                self.public_key_fingerprint, fingerprint
            );
            return false;
        }

        // Parse public key
        let verifying_key = match VerifyingKey::try_from(public_key) {
            Ok(k) => k,
            Err(e) => {
                warn!("Manifest cache: invalid public key: {}", e);
                return false;
            },
        };

        // Parse signature
        let signature = match Signature::from_slice(&self.signature) {
            Ok(s) => s,
            Err(e) => {
                warn!("Manifest cache: invalid signature format: {}", e);
                return false;
            },
        };

        // Compute hash and verify
        let hash = self.compute_signing_hash();
        match verifying_key.verify(&hash, &signature) {
            Ok(()) => {
                debug!("Manifest cache: signature valid");
                true
            },
            Err(e) => {
                warn!("Manifest cache: signature verification failed: {}", e);
                false
            },
        }
    }

    /// Save the signed cache to the specified directory.
    pub fn save(&self, cache_dir: &Path) -> Result<(), std::io::Error> {
        if self.signature.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Cannot save unsigned manifest cache",
            ));
        }

        std::fs::create_dir_all(cache_dir)?;
        let path = cache_dir.join(MANIFEST_CACHE_FILENAME);

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        std::fs::write(&path, json)?;

        info!(
            path = %path.display(),
            version = %self.verify_version,
            target = %self.target,
            binaries = self.binary_manifest.binaries.len(),
            functions = self.function_manifest.as_ref().map(|f| f.functions.len()).unwrap_or(0),
            "Saved signed manifest cache"
        );

        Ok(())
    }

    /// Load the signed cache from the specified directory.
    ///
    /// Does NOT verify signature - call `verify_signature()` after loading.
    pub fn load(cache_dir: &Path) -> Result<Self, std::io::Error> {
        let path = cache_dir.join(MANIFEST_CACHE_FILENAME);

        let json = std::fs::read_to_string(&path)?;
        let cache: Self = serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        debug!(
            path = %path.display(),
            version = %cache.verify_version,
            target = %cache.target,
            cached_at = cache.cached_at,
            "Loaded manifest cache (signature not yet verified)"
        );

        Ok(cache)
    }

    /// Check if a cache file exists in the specified directory.
    pub fn exists(cache_dir: &Path) -> bool {
        cache_dir.join(MANIFEST_CACHE_FILENAME).exists()
    }

    /// Get the cache file path.
    pub fn path(cache_dir: &Path) -> PathBuf {
        cache_dir.join(MANIFEST_CACHE_FILENAME)
    }
}

/// Compute Ed25519 public key fingerprint (SHA-256 hex).
fn compute_fingerprint(public_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    hex::encode(hasher.finalize())
}

/// Result of loading and verifying a cached manifest.
#[derive(Debug)]
pub enum CacheLoadResult {
    /// Cache loaded and signature verified.
    Valid(Box<SignedManifestCache>),
    /// Cache exists but signature verification failed.
    InvalidSignature,
    /// Cache exists but is for a different CIRISVerify version.
    VersionMismatch {
        /// Version in the cached file.
        cached: String,
        /// Current CIRISVerify version.
        current: String,
    },
    /// Cache exists but is for a different target.
    TargetMismatch {
        /// Target triple in the cached file.
        cached: String,
        /// Current target triple.
        current: String,
    },
    /// No cache file exists.
    NotFound,
    /// IO or parse error.
    Error(String),
}

/// Load and verify a cached manifest.
///
/// # Arguments
/// * `cache_dir` - Directory containing the cache file
/// * `public_key` - Ed25519 public key to verify signature
///
/// # Returns
/// * `CacheLoadResult::Valid` if cache is valid and signature verified
/// * Other variants indicate various failure modes
pub fn load_and_verify(cache_dir: &Path, public_key: &[u8]) -> CacheLoadResult {
    let cache = match SignedManifestCache::load(cache_dir) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return CacheLoadResult::NotFound;
        },
        Err(e) => {
            return CacheLoadResult::Error(format!("Failed to load cache: {}", e));
        },
    };

    // Check version match
    let current_version = env!("CARGO_PKG_VERSION");
    if cache.verify_version != current_version {
        warn!(
            "Manifest cache version mismatch: cached={}, current={}",
            cache.verify_version, current_version
        );
        return CacheLoadResult::VersionMismatch {
            cached: cache.verify_version.clone(),
            current: current_version.to_string(),
        };
    }

    // Check target match
    let current_target = crate::registry::current_target();
    if cache.target != current_target {
        warn!(
            "Manifest cache target mismatch: cached={}, current={}",
            cache.target, current_target
        );
        return CacheLoadResult::TargetMismatch {
            cached: cache.target.clone(),
            current: current_target.to_string(),
        };
    }

    // Verify signature
    if !cache.verify_signature(public_key) {
        error!("Manifest cache signature verification FAILED - possible tampering");
        return CacheLoadResult::InvalidSignature;
    }

    info!(
        cached_at = cache.cached_at,
        verify_version = %cache.verify_version,
        target = %cache.target,
        binaries = cache.binary_manifest.binaries.len(),
        "Loaded verified manifest cache for offline L1"
    );

    CacheLoadResult::Valid(Box::new(cache))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn create_test_binary_manifest() -> BinaryManifest {
        let mut binaries = HashMap::new();
        binaries.insert(
            "x86_64-unknown-linux-gnu".to_string(),
            "sha256:abc123".to_string(),
        );
        BinaryManifest {
            version: "1.0.0".to_string(),
            binaries,
            generated_at: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_signing_hash_deterministic() {
        let manifest = create_test_binary_manifest();
        let fingerprint = "test_fingerprint".to_string();

        let cache1 = SignedManifestCache::new(manifest.clone(), None, None, fingerprint.clone());

        // Create another with same data but different timestamp
        let mut cache2 = SignedManifestCache::new(manifest, None, None, fingerprint);
        cache2.cached_at = cache1.cached_at; // Force same timestamp

        assert_eq!(cache1.compute_signing_hash(), cache2.compute_signing_hash());
    }

    #[test]
    fn test_sign_and_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().as_bytes().to_vec();
        let fingerprint = compute_fingerprint(&public_key);

        let manifest = create_test_binary_manifest();
        let mut cache = SignedManifestCache::new(manifest, None, None, fingerprint);

        // Sign
        let hash = cache.compute_signing_hash();
        let signature = signing_key.sign(&hash);
        cache.set_signature(signature.to_bytes().to_vec());

        // Verify
        assert!(cache.verify_signature(&public_key));
    }

    #[test]
    fn test_tampered_cache_fails_verification() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().as_bytes().to_vec();
        let fingerprint = compute_fingerprint(&public_key);

        let manifest = create_test_binary_manifest();
        let mut cache = SignedManifestCache::new(manifest, None, None, fingerprint);

        // Sign
        let hash = cache.compute_signing_hash();
        let signature = signing_key.sign(&hash);
        cache.set_signature(signature.to_bytes().to_vec());

        // Tamper with the cache
        cache.cached_at += 1;

        // Verification should fail
        assert!(!cache.verify_signature(&public_key));
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().as_bytes().to_vec();
        let fingerprint = compute_fingerprint(&public_key);

        let manifest = create_test_binary_manifest();
        let mut cache = SignedManifestCache::new(manifest, None, None, fingerprint);

        // Sign with correct key
        let hash = cache.compute_signing_hash();
        let signature = signing_key.sign(&hash);
        cache.set_signature(signature.to_bytes().to_vec());

        // Try to verify with different key
        let other_key = SigningKey::generate(&mut OsRng);
        let other_public = other_key.verifying_key().as_bytes().to_vec();

        // Should fail - fingerprint mismatch
        assert!(!cache.verify_signature(&other_public));
    }

    #[test]
    fn test_save_and_load() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().as_bytes().to_vec();
        let fingerprint = compute_fingerprint(&public_key);

        let manifest = create_test_binary_manifest();
        let mut cache = SignedManifestCache::new(manifest, None, None, fingerprint);

        // Sign
        let hash = cache.compute_signing_hash();
        let signature = signing_key.sign(&hash);
        cache.set_signature(signature.to_bytes().to_vec());

        // Save
        let temp_dir = tempfile::tempdir().unwrap();
        cache.save(temp_dir.path()).unwrap();

        // Load
        let loaded = SignedManifestCache::load(temp_dir.path()).unwrap();

        // Verify
        assert!(loaded.verify_signature(&public_key));
        assert_eq!(
            loaded.binary_manifest.version,
            cache.binary_manifest.version
        );
    }

    #[test]
    fn test_load_and_verify_valid() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().as_bytes().to_vec();
        let fingerprint = compute_fingerprint(&public_key);

        let mut binaries = HashMap::new();
        binaries.insert(
            crate::registry::current_target().to_string(),
            "sha256:test".to_string(),
        );
        let manifest = BinaryManifest {
            version: env!("CARGO_PKG_VERSION").to_string(),
            binaries,
            generated_at: String::new(),
        };

        let mut cache = SignedManifestCache::new(manifest, None, None, fingerprint);

        let hash = cache.compute_signing_hash();
        let signature = signing_key.sign(&hash);
        cache.set_signature(signature.to_bytes().to_vec());

        let temp_dir = tempfile::tempdir().unwrap();
        cache.save(temp_dir.path()).unwrap();

        match load_and_verify(temp_dir.path(), &public_key) {
            CacheLoadResult::Valid(loaded) => {
                assert_eq!(loaded.verify_version, env!("CARGO_PKG_VERSION"));
            },
            other => panic!("Expected Valid, got {:?}", other),
        }
    }

    #[test]
    fn test_load_not_found() {
        let temp_dir = tempfile::tempdir().unwrap();
        let public_key = [0u8; 32];

        match load_and_verify(temp_dir.path(), &public_key) {
            CacheLoadResult::NotFound => {},
            other => panic!("Expected NotFound, got {:?}", other),
        }
    }

    #[test]
    fn test_tampered_binary_manifest_fails() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().as_bytes().to_vec();
        let fingerprint = compute_fingerprint(&public_key);

        let manifest = create_test_binary_manifest();
        let mut cache = SignedManifestCache::new(manifest, None, None, fingerprint);

        // Sign the original
        let hash = cache.compute_signing_hash();
        let signature = signing_key.sign(&hash);
        cache.set_signature(signature.to_bytes().to_vec());

        // Verify original works
        assert!(cache.verify_signature(&public_key));

        // Tamper with binary manifest
        cache.binary_manifest.binaries.insert(
            "attacker-target".to_string(),
            "sha256:malicious_hash".to_string(),
        );

        // Should now fail
        assert!(!cache.verify_signature(&public_key));
    }

    #[test]
    fn test_tampered_version_fails() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().as_bytes().to_vec();
        let fingerprint = compute_fingerprint(&public_key);

        let manifest = create_test_binary_manifest();
        let mut cache = SignedManifestCache::new(manifest, None, None, fingerprint);

        let hash = cache.compute_signing_hash();
        let signature = signing_key.sign(&hash);
        cache.set_signature(signature.to_bytes().to_vec());

        // Tamper with version
        cache.verify_version = "9.9.9".to_string();

        assert!(!cache.verify_signature(&public_key));
    }

    #[test]
    fn test_invalid_signature_length() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().as_bytes().to_vec();
        let fingerprint = compute_fingerprint(&public_key);

        let manifest = create_test_binary_manifest();
        let mut cache = SignedManifestCache::new(manifest, None, None, fingerprint);

        // Set invalid signature length (should be 64 bytes)
        cache.set_signature(vec![0u8; 32]);

        assert!(!cache.verify_signature(&public_key));
    }

    #[test]
    fn test_empty_signature_fails() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().as_bytes().to_vec();
        let fingerprint = compute_fingerprint(&public_key);

        let manifest = create_test_binary_manifest();
        let cache = SignedManifestCache::new(manifest, None, None, fingerprint);

        // Empty signature (default)
        assert!(!cache.verify_signature(&public_key));
    }

    #[test]
    fn test_save_unsigned_fails() {
        let manifest = create_test_binary_manifest();
        let cache = SignedManifestCache::new(manifest, None, None, "fingerprint".to_string());

        let temp_dir = tempfile::tempdir().unwrap();
        let result = cache.save(temp_dir.path());

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsigned"));
    }

    #[test]
    fn test_corrupted_cache_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join(MANIFEST_CACHE_FILENAME);

        // Write corrupted JSON
        std::fs::write(&path, "{ invalid json }").unwrap();

        let public_key = [0u8; 32];
        match load_and_verify(temp_dir.path(), &public_key) {
            CacheLoadResult::Error(msg) => {
                assert!(msg.contains("Failed to load"));
            },
            other => panic!("Expected Error, got {:?}", other),
        }
    }

    #[test]
    fn test_fingerprint_computation() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];

        let fp1 = compute_fingerprint(&key1);
        let fp2 = compute_fingerprint(&key2);

        // Different keys should have different fingerprints
        assert_ne!(fp1, fp2);

        // Same key should have same fingerprint
        assert_eq!(fp1, compute_fingerprint(&key1));

        // Fingerprint should be 64 hex chars (32 bytes)
        assert_eq!(fp1.len(), 64);
    }

    #[test]
    fn test_cache_exists() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Should not exist initially
        assert!(!SignedManifestCache::exists(temp_dir.path()));

        // Create a signed cache
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().as_bytes().to_vec();
        let fingerprint = compute_fingerprint(&public_key);

        let manifest = create_test_binary_manifest();
        let mut cache = SignedManifestCache::new(manifest, None, None, fingerprint);

        let hash = cache.compute_signing_hash();
        let signature = signing_key.sign(&hash);
        cache.set_signature(signature.to_bytes().to_vec());

        cache.save(temp_dir.path()).unwrap();

        // Should exist now
        assert!(SignedManifestCache::exists(temp_dir.path()));
    }

    #[test]
    fn test_cache_with_build_record() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().as_bytes().to_vec();
        let fingerprint = compute_fingerprint(&public_key);

        let binary_manifest = create_test_binary_manifest();

        // Create a build record cache directly
        let build_cache = BuildRecordCache {
            version: "1.0.0".to_string(),
            files: HashMap::from([
                ("src/main.py".to_string(), "abc123".to_string()),
                ("src/utils.py".to_string(), "def456".to_string()),
            ]),
            manifest_hash: "manifest_hash_123".to_string(),
        };

        let mut cache = SignedManifestCache {
            binary_manifest,
            function_manifest: None,
            build_record: Some(build_cache),
            cached_at: 12345,
            verify_version: env!("CARGO_PKG_VERSION").to_string(),
            target: crate::registry::current_target().to_string(),
            public_key_fingerprint: fingerprint.clone(),
            signature: Vec::new(),
        };

        let hash = cache.compute_signing_hash();
        let signature = signing_key.sign(&hash);
        cache.set_signature(signature.to_bytes().to_vec());

        let temp_dir = tempfile::tempdir().unwrap();
        cache.save(temp_dir.path()).unwrap();

        let loaded = SignedManifestCache::load(temp_dir.path()).unwrap();
        assert!(loaded.verify_signature(&public_key));
        assert!(loaded.build_record.is_some());
        assert_eq!(loaded.build_record.as_ref().unwrap().files.len(), 2);
    }

    #[test]
    fn test_load_and_verify_invalid_signature() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().as_bytes().to_vec();
        let fingerprint = compute_fingerprint(&public_key);

        let mut binaries = HashMap::new();
        binaries.insert(
            crate::registry::current_target().to_string(),
            "sha256:test".to_string(),
        );
        let manifest = BinaryManifest {
            version: env!("CARGO_PKG_VERSION").to_string(),
            binaries,
            generated_at: String::new(),
        };

        let mut cache = SignedManifestCache::new(manifest, None, None, fingerprint);

        // Sign with correct key
        let hash = cache.compute_signing_hash();
        let signature = signing_key.sign(&hash);
        cache.set_signature(signature.to_bytes().to_vec());

        let temp_dir = tempfile::tempdir().unwrap();
        cache.save(temp_dir.path()).unwrap();

        // Try to verify with DIFFERENT key
        let other_key = SigningKey::generate(&mut OsRng);
        let other_public = other_key.verifying_key().as_bytes().to_vec();

        match load_and_verify(temp_dir.path(), &other_public) {
            CacheLoadResult::InvalidSignature => {},
            other => panic!("Expected InvalidSignature, got {:?}", other),
        }
    }

    #[test]
    fn test_signature_covers_all_fields() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().as_bytes().to_vec();
        let fingerprint = compute_fingerprint(&public_key);

        let manifest = create_test_binary_manifest();
        let mut cache = SignedManifestCache::new(manifest, None, None, fingerprint.clone());

        let hash = cache.compute_signing_hash();
        let signature = signing_key.sign(&hash);
        cache.set_signature(signature.to_bytes().to_vec());

        // Verify original
        assert!(cache.verify_signature(&public_key));

        // Test each field tampering
        let test_cases = vec![
            ("binary_manifest.version", {
                let mut c = cache.clone();
                c.binary_manifest.version = "tampered".to_string();
                c
            }),
            ("target", {
                let mut c = cache.clone();
                c.target = "tampered-target".to_string();
                c
            }),
            ("public_key_fingerprint", {
                let mut c = cache.clone();
                c.public_key_fingerprint = "tampered_fingerprint".to_string();
                c
            }),
        ];

        for (field, tampered_cache) in test_cases {
            assert!(
                !tampered_cache.verify_signature(&public_key),
                "Tampering with {} should fail verification",
                field
            );
        }
    }
}
