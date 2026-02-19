//! License cache with encrypted storage.
//!
//! Provides persistent, encrypted storage for license data with TTL support.
//! Falls back to memory cache if filesystem is unavailable.
//! Uses XChaCha20-Poly1305 AEAD for authenticated encryption.

// Allow deprecated from_slice until chacha20poly1305 upgrades to generic-array 1.x
#![allow(deprecated)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, trace, warn};

use crate::error::VerifyError;
use crate::license::LicenseDetails;

/// XChaCha20-Poly1305 nonce size (24 bytes)
const NONCE_SIZE: usize = 24;

/// License cache with encrypted persistence.
pub struct LicenseCache {
    /// In-memory cache.
    memory: RwLock<HashMap<String, CacheEntry>>,
    /// Storage backend (optional).
    storage: Option<StorageBackend>,
    /// Default TTL for cached entries.
    default_ttl: Duration,
    /// Encryption key (derived from deployment ID).
    encryption_key: [u8; 32],
    /// Highest-seen revocation revision (anti-rollback).
    last_seen_revision: RwLock<u64>,
    /// Revision history for audit trail: (timestamp, revision).
    revision_history: RwLock<Vec<(i64, u64)>>,
}

/// A cached license entry.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The cached license.
    license: LicenseDetails,
    /// When the entry was cached.
    cached_at: Instant,
    /// When the entry expires.
    expires_at: Instant,
    /// Last verification timestamp.
    last_verified: i64,
}

impl CacheEntry {
    /// Check if the entry is still fresh.
    fn is_fresh(&self) -> bool {
        Instant::now() < self.expires_at
    }

    /// Check if the entry is within offline grace period.
    fn within_grace_period(&self, grace_period: Duration) -> bool {
        Instant::now() < self.cached_at + grace_period
    }
}

/// Storage backend for persistent cache.
struct StorageBackend {
    /// Path to cache directory.
    cache_dir: PathBuf,
}

/// Serializable cache data for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedEntry {
    /// License details.
    license: LicenseDetails,
    /// Cached at timestamp (Unix).
    cached_at: i64,
    /// Expires at timestamp (Unix).
    expires_at: i64,
    /// Last verification timestamp.
    last_verified: i64,
}

/// Serializable revision state for anti-rollback persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedRevisionState {
    /// Highest-seen revocation revision.
    last_seen_revision: u64,
    /// Revision history: (timestamp, revision).
    revision_history: Vec<(i64, u64)>,
}

impl LicenseCache {
    /// Create a new license cache.
    ///
    /// # Arguments
    ///
    /// * `deployment_id` - Used to derive encryption key
    /// * `cache_dir` - Optional directory for persistent storage
    /// * `default_ttl` - Default TTL for cached entries
    pub fn new(deployment_id: &str, cache_dir: Option<PathBuf>, default_ttl: Duration) -> Self {
        // Derive encryption key from deployment ID
        let mut hasher = Sha256::new();
        hasher.update(b"ciris-cache-key:");
        hasher.update(deployment_id.as_bytes());
        let encryption_key: [u8; 32] = hasher.finalize().into();

        let storage = cache_dir.map(|dir| StorageBackend { cache_dir: dir });

        // Load persisted revision state if available
        let (last_seen_revision, revision_history) =
            Self::load_revision_state(&storage, &encryption_key);

        Self {
            memory: RwLock::new(HashMap::new()),
            storage,
            default_ttl,
            encryption_key,
            last_seen_revision: RwLock::new(last_seen_revision),
            revision_history: RwLock::new(revision_history),
        }
    }

    /// Get a cached license.
    ///
    /// Returns `None` if:
    /// - No cached entry exists
    /// - Entry has expired
    pub fn get(&self, license_id: &str) -> Option<CachedLicense> {
        // Try memory first
        if let Some(entry) = self.get_from_memory(license_id) {
            if entry.is_fresh() {
                return Some(CachedLicense {
                    license: entry.license.clone(),
                    is_fresh: true,
                    last_verified: entry.last_verified,
                });
            }
        }

        // Try storage if available
        if let Some(entry) = self.get_from_storage(license_id) {
            // Re-populate memory cache
            let _ = self.put_to_memory(license_id, &entry);

            return Some(CachedLicense {
                license: entry.license.clone(),
                is_fresh: entry.is_fresh(),
                last_verified: entry.last_verified,
            });
        }

        None
    }

    /// Get a cached license if within grace period.
    ///
    /// Used for offline operation.
    pub fn get_for_offline(
        &self,
        license_id: &str,
        grace_period: Duration,
    ) -> Option<CachedLicense> {
        // Try memory first
        if let Some(entry) = self.get_from_memory(license_id) {
            if entry.within_grace_period(grace_period) {
                return Some(CachedLicense {
                    license: entry.license.clone(),
                    is_fresh: entry.is_fresh(),
                    last_verified: entry.last_verified,
                });
            }
        }

        // Try storage
        if let Some(entry) = self.get_from_storage(license_id) {
            if entry.within_grace_period(grace_period) {
                return Some(CachedLicense {
                    license: entry.license.clone(),
                    is_fresh: entry.is_fresh(),
                    last_verified: entry.last_verified,
                });
            }
        }

        None
    }

    /// Cache a license.
    pub fn put(&self, license: &LicenseDetails) {
        self.put_with_ttl(license, self.default_ttl);
    }

    /// Cache a license with custom TTL.
    pub fn put_with_ttl(&self, license: &LicenseDetails, ttl: Duration) {
        let now = Instant::now();
        let entry = CacheEntry {
            license: license.clone(),
            cached_at: now,
            expires_at: now + ttl,
            last_verified: current_timestamp(),
        };

        let _ = self.put_to_memory(&license.license_id, &entry);
        self.put_to_storage(&license.license_id, &entry);
    }

    /// Invalidate a cached license.
    pub fn invalidate(&self, license_id: &str) {
        // Remove from memory
        if let Ok(mut cache) = self.memory.write() {
            cache.remove(license_id);
        }

        // Remove from storage
        if let Some(ref storage) = self.storage {
            let path = storage.entry_path(license_id, &self.encryption_key);
            let _ = std::fs::remove_file(path);
        }
    }

    /// Clear all cached licenses.
    pub fn clear(&self) {
        // Clear memory
        if let Ok(mut cache) = self.memory.write() {
            cache.clear();
        }

        // Clear storage
        if let Some(ref storage) = self.storage {
            let _ = std::fs::remove_dir_all(&storage.cache_dir);
            let _ = std::fs::create_dir_all(&storage.cache_dir);
        }
    }

    /// Check a new revocation revision against the last seen value.
    ///
    /// Rejects if the new revision is lower than the last seen (rollback attack).
    /// Updates the stored revision if the new value is higher or equal.
    ///
    /// # Errors
    ///
    /// Returns `VerifyError::RollbackDetected` if `new_revision < last_seen`.
    pub fn check_and_update_revision(&self, new_revision: u64) -> Result<(), VerifyError> {
        let mut last_seen =
            self.last_seen_revision
                .write()
                .map_err(|_| VerifyError::CacheError {
                    message: "Failed to acquire revision lock".into(),
                })?;

        if new_revision < *last_seen {
            return Err(VerifyError::RollbackDetected {
                current: new_revision,
                last_seen: *last_seen,
            });
        }

        // Update if newer
        if new_revision > *last_seen {
            *last_seen = new_revision;
        }

        // Record in history
        if let Ok(mut history) = self.revision_history.write() {
            let ts = current_timestamp();
            history.push((ts, new_revision));

            // Cap at 1000 entries
            if history.len() > 1000 {
                let drain_count = history.len() - 1000;
                history.drain(..drain_count);
            }
        }

        // Persist revision state (non-fatal if this fails)
        self.persist_revision_state();

        Ok(())
    }

    /// Get the highest-seen revocation revision.
    #[must_use]
    pub fn last_seen_revision(&self) -> u64 {
        self.last_seen_revision.read().map(|r| *r).unwrap_or(0)
    }

    /// Get the revision history for audit purposes.
    #[must_use]
    pub fn revision_history(&self) -> Vec<(i64, u64)> {
        self.revision_history
            .read()
            .map(|h| h.clone())
            .unwrap_or_default()
    }

    /// Load persisted revision state from storage.
    fn load_revision_state(
        storage: &Option<StorageBackend>,
        encryption_key: &[u8; 32],
    ) -> (u64, Vec<(i64, u64)>) {
        let storage = match storage {
            Some(s) => s,
            None => return (0, Vec::new()),
        };

        let path = storage.cache_dir.join("revision_state.enc");
        let encrypted = match std::fs::read(&path) {
            Ok(data) => data,
            Err(e) => {
                debug!("Cache: no revision state file ({})", e);
                return (0, Vec::new());
            },
        };

        // Decrypt using XChaCha20-Poly1305
        if encrypted.len() < NONCE_SIZE {
            warn!("Cache: revision state file too small");
            return (0, Vec::new());
        }

        let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
        let nonce = XNonce::from_slice(nonce_bytes);

        let cipher = match XChaCha20Poly1305::new_from_slice(encryption_key) {
            Ok(c) => c,
            Err(e) => {
                warn!("Cache: failed to create cipher for revision state: {}", e);
                return (0, Vec::new());
            },
        };

        let decrypted = match cipher.decrypt(nonce, ciphertext) {
            Ok(d) => d,
            Err(e) => {
                warn!(
                    "Cache: failed to decrypt revision state (possibly tampered): {}",
                    e
                );
                return (0, Vec::new());
            },
        };

        match serde_json::from_slice::<PersistedRevisionState>(&decrypted) {
            Ok(state) => {
                debug!(
                    last_seen_revision = state.last_seen_revision,
                    history_len = state.revision_history.len(),
                    "Cache: loaded revision state"
                );
                (state.last_seen_revision, state.revision_history)
            },
            Err(e) => {
                warn!("Cache: failed to parse revision state: {}", e);
                (0, Vec::new())
            },
        }
    }

    /// Persist the current revision state to storage.
    fn persist_revision_state(&self) {
        let storage = match &self.storage {
            Some(s) => s,
            None => return,
        };

        if let Err(e) = std::fs::create_dir_all(&storage.cache_dir) {
            warn!("Cache: failed to create cache directory: {}", e);
            return;
        }

        let last_seen = self.last_seen_revision.read().map(|r| *r).unwrap_or(0);
        let history = self
            .revision_history
            .read()
            .map(|h| h.clone())
            .unwrap_or_default();

        let history_len = history.len();
        let state = PersistedRevisionState {
            last_seen_revision: last_seen,
            revision_history: history,
        };

        let data = match serde_json::to_vec(&state) {
            Ok(d) => d,
            Err(e) => {
                warn!("Cache: failed to serialize revision state: {}", e);
                return;
            },
        };

        // Encrypt using XChaCha20-Poly1305
        let encrypted = match self.encrypt(&data) {
            Some(e) => e,
            None => {
                warn!("Cache: failed to encrypt revision state");
                return;
            },
        };

        let path = storage.cache_dir.join("revision_state.enc");
        if let Err(e) = std::fs::write(&path, &encrypted) {
            warn!("Cache: failed to write revision state: {}", e);
        } else {
            debug!(
                last_seen_revision = last_seen,
                history_len = history_len,
                "Cache: persisted revision state"
            );
        }
    }

    /// Get entry from memory cache.
    fn get_from_memory(&self, license_id: &str) -> Option<CacheEntry> {
        self.memory
            .read()
            .ok()
            .and_then(|cache| cache.get(license_id).cloned())
    }

    /// Put entry to memory cache.
    fn put_to_memory(&self, license_id: &str, entry: &CacheEntry) -> Result<(), ()> {
        let mut cache = self.memory.write().map_err(|_| ())?;
        cache.insert(license_id.to_string(), entry.clone());
        Ok(())
    }

    /// Get entry from storage.
    fn get_from_storage(&self, license_id: &str) -> Option<CacheEntry> {
        let storage = self.storage.as_ref()?;
        let path = storage.entry_path(license_id, &self.encryption_key);

        let encrypted = std::fs::read(&path).ok()?;
        let decrypted = self.decrypt(&encrypted)?;
        let persisted: PersistedEntry = serde_json::from_slice(&decrypted).ok()?;

        // Convert timestamps back to Instant (approximate)
        let now_ts = current_timestamp();
        let cached_age = Duration::from_secs((now_ts - persisted.cached_at).max(0) as u64);
        let expires_in = Duration::from_secs((persisted.expires_at - now_ts).max(0) as u64);

        Some(CacheEntry {
            license: persisted.license,
            cached_at: Instant::now() - cached_age,
            expires_at: Instant::now() + expires_in,
            last_verified: persisted.last_verified,
        })
    }

    /// Put entry to storage.
    fn put_to_storage(&self, license_id: &str, entry: &CacheEntry) {
        let storage = match &self.storage {
            Some(s) => s,
            None => return,
        };

        // Ensure directory exists
        if std::fs::create_dir_all(&storage.cache_dir).is_err() {
            return;
        }

        let now_ts = current_timestamp();
        let ttl_secs = entry
            .expires_at
            .saturating_duration_since(entry.cached_at)
            .as_secs() as i64;

        let persisted = PersistedEntry {
            license: entry.license.clone(),
            cached_at: now_ts,
            expires_at: now_ts + ttl_secs,
            last_verified: entry.last_verified,
        };

        let data = match serde_json::to_vec(&persisted) {
            Ok(d) => d,
            Err(_) => return,
        };

        let encrypted = match self.encrypt(&data) {
            Some(e) => e,
            None => return,
        };

        let path = storage.entry_path(license_id, &self.encryption_key);
        let _ = std::fs::write(&path, &encrypted);
    }

    /// Encrypt data using XChaCha20-Poly1305 authenticated encryption.
    ///
    /// Returns nonce || ciphertext (24 bytes nonce prepended to ciphertext).
    fn encrypt(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        // Create cipher with the key
        let cipher = XChaCha20Poly1305::new_from_slice(&self.encryption_key).ok()?;

        // Encrypt
        let ciphertext = cipher.encrypt(nonce, plaintext).ok()?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        trace!(
            plaintext_len = plaintext.len(),
            ciphertext_len = result.len(),
            "Cache: encrypted data"
        );

        Some(result)
    }

    /// Decrypt data using XChaCha20-Poly1305 authenticated encryption.
    ///
    /// Expects nonce || ciphertext format.
    fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < NONCE_SIZE {
            warn!(
                data_len = data.len(),
                "Cache: data too short to contain nonce"
            );
            return None;
        }

        // Split nonce and ciphertext
        let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
        let nonce = XNonce::from_slice(nonce_bytes);

        // Create cipher with the key
        let cipher = XChaCha20Poly1305::new_from_slice(&self.encryption_key).ok()?;

        // Decrypt
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| {
                warn!("Cache: decryption failed (possible tampering): {}", e);
                e
            })
            .ok()?;

        trace!(
            ciphertext_len = data.len(),
            plaintext_len = plaintext.len(),
            "Cache: decrypted data"
        );

        Some(plaintext)
    }
}

impl StorageBackend {
    /// Get the file path for a cache entry.
    fn entry_path(&self, license_id: &str, key: &[u8; 32]) -> PathBuf {
        // Hash the license ID for filename
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(license_id.as_bytes());
        let hash = hex::encode(&hasher.finalize()[..16]);

        self.cache_dir.join(format!("{}.cache", hash))
    }
}

/// A cached license with metadata.
#[derive(Debug, Clone)]
pub struct CachedLicense {
    /// The license details.
    pub license: LicenseDetails,
    /// Whether the cache entry is still fresh.
    pub is_fresh: bool,
    /// Last successful verification timestamp.
    pub last_verified: i64,
}

/// Get current Unix timestamp.
fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::{AutonomyTier, DeploymentConstraints, LicenseType};

    fn create_test_license() -> LicenseDetails {
        LicenseDetails {
            license_id: "test-license-123".to_string(),
            license_type: LicenseType::ProfessionalMedical,
            organization_name: "Test Org".to_string(),
            organization_id: "org-123".to_string(),
            responsible_party: "Dr. Test User".to_string(),
            responsible_party_contact: "test@example.com".to_string(),
            issued_at: 1737936000,
            expires_at: 1769472000,
            not_before: 1737936000,
            capabilities: vec!["domain:medical:triage".to_string()],
            capabilities_denied: vec![],
            max_autonomy_tier: AutonomyTier::A3High,
            constraints: DeploymentConstraints::default(),
            license_jwt: "test.jwt.here.sig".to_string(),
            identity_template: String::new(),
            stewardship_tier: 0,
            permitted_actions: vec![],
            template_hash: vec![],
        }
    }

    #[test]
    fn test_cache_put_get() {
        let cache = LicenseCache::new("test-deploy", None, Duration::from_secs(300));

        let license = create_test_license();
        cache.put(&license);

        let cached = cache.get(&license.license_id).unwrap();
        assert_eq!(cached.license.license_id, license.license_id);
        assert!(cached.is_fresh);
    }

    #[test]
    fn test_cache_invalidate() {
        let cache = LicenseCache::new("test-deploy", None, Duration::from_secs(300));

        let license = create_test_license();
        cache.put(&license);

        cache.invalidate(&license.license_id);

        assert!(cache.get(&license.license_id).is_none());
    }

    #[test]
    fn test_cache_expiration() {
        let cache = LicenseCache::new("test-deploy", None, Duration::from_millis(1));

        let license = create_test_license();
        cache.put(&license);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        let cached = cache.get(&license.license_id);
        assert!(cached.is_none() || !cached.unwrap().is_fresh);
    }

    #[test]
    fn test_cache_offline_grace_period() {
        let cache = LicenseCache::new("test-deploy", None, Duration::from_millis(1));

        let license = create_test_license();
        cache.put(&license);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        // Should still be available within grace period
        let cached = cache.get_for_offline(&license.license_id, Duration::from_secs(300));
        assert!(cached.is_some());
    }

    #[test]
    fn test_cache_clear() {
        let cache = LicenseCache::new("test-deploy", None, Duration::from_secs(300));

        let license = create_test_license();
        cache.put(&license);

        cache.clear();

        assert!(cache.get(&license.license_id).is_none());
    }

    #[test]
    fn test_encryption_roundtrip() {
        let cache = LicenseCache::new("test-deploy", None, Duration::from_secs(300));

        let plaintext = b"Hello, World!";
        let encrypted = cache.encrypt(plaintext).unwrap();
        let decrypted = cache.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_revision_monotonic_increase() {
        let cache = LicenseCache::new("test-deploy", None, Duration::from_secs(300));

        // Increasing revisions should be accepted
        assert!(cache.check_and_update_revision(1).is_ok());
        assert!(cache.check_and_update_revision(2).is_ok());
        assert!(cache.check_and_update_revision(5).is_ok());
        assert!(cache.check_and_update_revision(100).is_ok());

        // Equal revision should be accepted (idempotent)
        assert!(cache.check_and_update_revision(100).is_ok());

        assert_eq!(cache.last_seen_revision(), 100);
    }

    #[test]
    fn test_revision_rollback_detected() {
        let cache = LicenseCache::new("test-deploy", None, Duration::from_secs(300));

        // Set initial revision
        assert!(cache.check_and_update_revision(50).is_ok());

        // Rollback attempt should be rejected
        let err = cache.check_and_update_revision(49).unwrap_err();
        assert!(
            err.is_restricted(),
            "Rollback should trigger restricted mode"
        );

        match err {
            VerifyError::RollbackDetected { current, last_seen } => {
                assert_eq!(current, 49);
                assert_eq!(last_seen, 50);
            },
            other => panic!("Expected RollbackDetected, got {:?}", other),
        }

        // Last seen should still be 50 (not updated on rollback)
        assert_eq!(cache.last_seen_revision(), 50);
    }

    #[test]
    fn test_revision_history_audit_trail() {
        let cache = LicenseCache::new("test-deploy", None, Duration::from_secs(300));

        cache.check_and_update_revision(1).unwrap();
        cache.check_and_update_revision(5).unwrap();
        cache.check_and_update_revision(10).unwrap();

        let history = cache.revision_history();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].1, 1);
        assert_eq!(history[1].1, 5);
        assert_eq!(history[2].1, 10);

        // All timestamps should be reasonable
        for (ts, _) in &history {
            assert!(*ts > 0, "Timestamps should be positive");
        }
    }

    #[test]
    fn test_revision_history_capped() {
        let cache = LicenseCache::new("test-deploy", None, Duration::from_secs(300));

        // Add 1050 entries
        for i in 1..=1050 {
            cache.check_and_update_revision(i).unwrap();
        }

        let history = cache.revision_history();
        assert!(
            history.len() <= 1000,
            "History should be capped at 1000, got {}",
            history.len()
        );

        // Should have the most recent entries
        assert_eq!(history.last().unwrap().1, 1050);
    }
}
