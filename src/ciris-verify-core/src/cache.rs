//! License cache with encrypted storage.
//!
//! Provides persistent, encrypted storage for license data with TTL support.
//! Falls back to memory cache if filesystem is unavailable.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::license::LicenseDetails;

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

        Self {
            memory: RwLock::new(HashMap::new()),
            storage,
            default_ttl,
            encryption_key,
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

    /// Encrypt data using XChaCha20-Poly1305 (simulated with XOR for now).
    ///
    /// TODO: Replace with actual XChaCha20-Poly1305 when adding chacha20poly1305 dep.
    fn encrypt(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        // Simple XOR encryption as placeholder
        // In production, use chacha20poly1305::XChaCha20Poly1305
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for (i, byte) in plaintext.iter().enumerate() {
            ciphertext.push(byte ^ self.encryption_key[i % 32]);
        }
        Some(ciphertext)
    }

    /// Decrypt data.
    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        // XOR is symmetric
        self.encrypt(ciphertext)
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
}
