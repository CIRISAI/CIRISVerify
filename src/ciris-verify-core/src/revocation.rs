//! License revocation checking.
//!
//! This module provides revocation status checking for licenses, implementing
//! the fail-secure requirement: ANY revocation signal triggers immediate
//! degradation to community mode.
//!
//! ## Security Properties
//!
//! - **Fail-secure**: Any revocation from any source is honored immediately
//! - **Cached checks**: Revocation status is cached to reduce network calls
//! - **Grace period**: Cached status expires to ensure eventual consistency
//!
//! ## Revocation Sources
//!
//! 1. **HTTPS API**: Primary source via `GET /v1/revocation/{license_id}`
//! 2. **Revocation revision**: Consensus revision number from multi-source validation
//! 3. **License JWT**: Embedded revocation hints in the license itself

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use tracing::{debug, warn, error, instrument};

use crate::https::{HttpsClient, RevocationResponse};

/// Revocation status for a license.
#[derive(Debug, Clone)]
pub struct RevocationStatus {
    /// License ID that was checked.
    pub license_id: String,
    /// Whether the license is revoked.
    pub revoked: bool,
    /// Timestamp when revoked (if applicable).
    pub revoked_at: Option<i64>,
    /// Reason for revocation (if applicable).
    pub reason: Option<String>,
    /// When this status was last checked.
    pub checked_at: Instant,
    /// TTL for this cached status.
    pub ttl: Duration,
}

impl RevocationStatus {
    /// Check if this cached status is still valid.
    pub fn is_valid(&self) -> bool {
        self.checked_at.elapsed() < self.ttl
    }

    /// Check if the license is currently revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Create a "not revoked" status.
    pub fn not_revoked(license_id: String, ttl: Duration) -> Self {
        Self {
            license_id,
            revoked: false,
            revoked_at: None,
            reason: None,
            checked_at: Instant::now(),
            ttl,
        }
    }

    /// Create a "revoked" status.
    pub fn revoked(
        license_id: String,
        revoked_at: Option<i64>,
        reason: Option<String>,
        ttl: Duration,
    ) -> Self {
        Self {
            license_id,
            revoked: true,
            revoked_at,
            reason,
            checked_at: Instant::now(),
            ttl,
        }
    }

    /// Create an "unknown" status (check failed).
    pub fn unknown(license_id: String, ttl: Duration) -> Self {
        // Default to NOT revoked when unknown (fail-open for availability)
        // but with a very short TTL to ensure we retry soon
        Self {
            license_id,
            revoked: false,
            revoked_at: None,
            reason: Some("Revocation check failed - status unknown".into()),
            checked_at: Instant::now(),
            ttl: ttl.min(Duration::from_secs(60)), // Max 1 minute for unknown
        }
    }
}

/// Cache entry for revocation status.
struct CacheEntry {
    status: RevocationStatus,
}

/// Revocation checker with caching.
///
/// Provides efficient revocation checking with local caching to reduce
/// network calls while maintaining security guarantees.
pub struct RevocationChecker {
    /// HTTPS client for API calls.
    client: HttpsClient,
    /// Local cache of revocation status.
    cache: RwLock<HashMap<String, CacheEntry>>,
    /// Default TTL for cache entries.
    default_ttl: Duration,
    /// TTL for revoked entries (longer since revocation is persistent).
    revoked_ttl: Duration,
}

impl RevocationChecker {
    /// Create a new revocation checker.
    ///
    /// # Arguments
    ///
    /// * `client` - HTTPS client for API calls
    /// * `default_ttl` - Default cache TTL for non-revoked status
    /// * `revoked_ttl` - Cache TTL for revoked status (can be longer)
    pub fn new(client: HttpsClient, default_ttl: Duration, revoked_ttl: Duration) -> Self {
        Self {
            client,
            cache: RwLock::new(HashMap::new()),
            default_ttl,
            revoked_ttl,
        }
    }

    /// Check if a license is revoked.
    ///
    /// This method:
    /// 1. Checks the local cache first
    /// 2. If cache miss or expired, queries the HTTPS API
    /// 3. Updates the cache with the result
    ///
    /// # Security
    ///
    /// If the check fails, we return "unknown" status with a short TTL.
    /// The caller should treat unknown status appropriately based on
    /// their security requirements.
    #[instrument(skip(self), fields(license_id = %license_id))]
    pub async fn check_revocation(&self, license_id: &str) -> RevocationStatus {
        // Check cache first
        if let Some(cached) = self.get_cached(license_id) {
            if cached.is_valid() {
                debug!(
                    license_id = %license_id,
                    revoked = cached.revoked,
                    "Using cached revocation status"
                );
                return cached;
            }
        }

        // Cache miss or expired - query API
        debug!(license_id = %license_id, "Querying revocation status from API");

        match self.client.check_revocation(license_id).await {
            Ok(response) => {
                let status = self.process_response(license_id, response);
                self.update_cache(license_id, &status);
                status
            }
            Err(e) => {
                warn!(
                    license_id = %license_id,
                    error = %e,
                    "Revocation check failed"
                );
                // Return unknown status with short TTL
                let status = RevocationStatus::unknown(
                    license_id.to_string(),
                    self.default_ttl,
                );
                self.update_cache(license_id, &status);
                status
            }
        }
    }

    /// Check multiple licenses in parallel.
    ///
    /// # Arguments
    ///
    /// * `license_ids` - License IDs to check
    ///
    /// # Returns
    ///
    /// Map of license ID to revocation status.
    pub async fn check_multiple(
        &self,
        license_ids: &[&str],
    ) -> HashMap<String, RevocationStatus> {
        let futures: Vec<_> = license_ids
            .iter()
            .map(|id| async move {
                let status = self.check_revocation(id).await;
                (id.to_string(), status)
            })
            .collect();

        let results = futures::future::join_all(futures).await;
        results.into_iter().collect()
    }

    /// Check if ANY of the given licenses are revoked.
    ///
    /// This implements the fail-secure rule: if ANY license in the chain
    /// is revoked, the entire verification fails.
    ///
    /// # Arguments
    ///
    /// * `license_ids` - License IDs to check
    ///
    /// # Returns
    ///
    /// `Some(RevocationStatus)` with the first revoked license found,
    /// or `None` if no licenses are revoked.
    #[instrument(skip(self))]
    pub async fn any_revoked(&self, license_ids: &[&str]) -> Option<RevocationStatus> {
        for id in license_ids {
            let status = self.check_revocation(id).await;
            if status.is_revoked() {
                error!(
                    license_id = %id,
                    reason = ?status.reason,
                    "REVOKED LICENSE DETECTED"
                );
                return Some(status);
            }
        }
        None
    }

    /// Force refresh the revocation status, bypassing cache.
    #[instrument(skip(self), fields(license_id = %license_id))]
    pub async fn force_refresh(&self, license_id: &str) -> RevocationStatus {
        debug!(license_id = %license_id, "Force refreshing revocation status");

        // Clear cache entry
        if let Ok(mut cache) = self.cache.write() {
            cache.remove(license_id);
        }

        // Query API
        self.check_revocation(license_id).await
    }

    /// Clear all cached revocation status.
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
            debug!("Revocation cache cleared");
        }
    }

    /// Get cache statistics.
    pub fn cache_stats(&self) -> CacheStats {
        if let Ok(cache) = self.cache.read() {
            let total = cache.len();
            let valid = cache.values().filter(|e| e.status.is_valid()).count();
            let revoked = cache.values().filter(|e| e.status.revoked).count();

            CacheStats {
                total_entries: total,
                valid_entries: valid,
                revoked_entries: revoked,
            }
        } else {
            CacheStats {
                total_entries: 0,
                valid_entries: 0,
                revoked_entries: 0,
            }
        }
    }

    // Internal methods

    fn get_cached(&self, license_id: &str) -> Option<RevocationStatus> {
        if let Ok(cache) = self.cache.read() {
            cache.get(license_id).map(|e| e.status.clone())
        } else {
            None
        }
    }

    fn update_cache(&self, license_id: &str, status: &RevocationStatus) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                license_id.to_string(),
                CacheEntry {
                    status: status.clone(),
                },
            );
        }
    }

    fn process_response(&self, license_id: &str, response: RevocationResponse) -> RevocationStatus {
        if response.revoked {
            warn!(
                license_id = %license_id,
                revoked_at = ?response.revoked_at,
                reason = ?response.reason,
                "License is REVOKED"
            );
            RevocationStatus::revoked(
                license_id.to_string(),
                response.revoked_at,
                response.reason,
                self.revoked_ttl,
            )
        } else {
            debug!(license_id = %license_id, "License is not revoked");
            RevocationStatus::not_revoked(license_id.to_string(), self.default_ttl)
        }
    }
}

/// Cache statistics.
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total entries in cache.
    pub total_entries: usize,
    /// Valid (non-expired) entries.
    pub valid_entries: usize,
    /// Entries marked as revoked.
    pub revoked_entries: usize,
}

/// Check if a license has been revoked based on revision number.
///
/// This is a quick check using the revocation revision from consensus
/// validation, without requiring a separate API call.
///
/// # Arguments
///
/// * `license_revision` - Revision number embedded in the license
/// * `current_revision` - Current revocation revision from consensus
///
/// # Returns
///
/// `true` if the license may be revoked (revision is stale).
pub fn is_revision_stale(license_revision: u64, current_revision: u64) -> bool {
    // If current revision is higher, the license may have been revoked
    // after it was issued
    current_revision > license_revision
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_status_validity() {
        let status = RevocationStatus::not_revoked(
            "test-license".into(),
            Duration::from_secs(60),
        );

        assert!(status.is_valid());
        assert!(!status.is_revoked());
    }

    #[test]
    fn test_revoked_status() {
        let status = RevocationStatus::revoked(
            "test-license".into(),
            Some(1737763200),
            Some("License holder request".into()),
            Duration::from_secs(3600),
        );

        assert!(status.is_valid());
        assert!(status.is_revoked());
        assert_eq!(status.reason, Some("License holder request".into()));
    }

    #[test]
    fn test_unknown_status_short_ttl() {
        let status = RevocationStatus::unknown(
            "test-license".into(),
            Duration::from_secs(3600), // Requested 1 hour
        );

        // Unknown status should have max 1 minute TTL
        assert!(status.ttl <= Duration::from_secs(60));
        assert!(!status.is_revoked()); // Default to not revoked
    }

    #[test]
    fn test_revision_stale_check() {
        // License issued at revision 100
        let license_rev = 100;

        // Current revision is 100 - not stale
        assert!(!is_revision_stale(license_rev, 100));

        // Current revision is 101 - might be stale
        assert!(is_revision_stale(license_rev, 101));

        // Current revision is 99 - not stale (older data)
        assert!(!is_revision_stale(license_rev, 99));
    }
}
