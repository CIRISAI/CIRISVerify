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

use tracing::{debug, error, instrument, warn};

use crate::error::VerifyError;
use crate::https::{HttpsClient, RevocationResponse};

/// **Why we believe what we believe** — did the authority answer, or did we
/// fail to obtain an answer? (CIRISVerify: the 429-becomes-revoked defect.)
///
/// Collapsing these two into one boolean manufactures a *verdict* out of the
/// *absence* of one, which `MISSION.md` §1.4 forbids: verify carries
/// measurements, never verdicts. "The authority says this license is revoked"
/// is a verdict. "I could not reach the authority" is a measurement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Determination {
    /// The revocation authority answered. [`RevocationStatus::revoked`] is its
    /// answer, and is authoritative.
    Authoritative,
    /// No answer was obtained. [`RevocationStatus::revoked`] carries the
    /// caller's configured posture, **not** the authority's word.
    Indeterminate(Indeterminate),
}

/// Why an answer could not be obtained. The distinction is load-bearing: a
/// suppressed check and a cooperative "slow down" are opposite evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Indeterminate {
    /// **HTTP 429.** The authority is alive and answering — it is asking us to
    /// come back later, and typically because of *our own* polling cadence.
    ///
    /// This is the case that must never read as revoked: it would convert our
    /// own request rate into a fleet-wide outage for correctly-licensed
    /// agents, all at once.
    RateLimited {
        /// `Retry-After` in seconds, when the authority supplied one.
        retry_after_secs: Option<u64>,
    },
    /// The authority could not be reached, or failed to answer usefully
    /// (connection failure, timeout, 5xx, undecodable body).
    ///
    /// Unlike [`RateLimited`](Self::RateLimited) this is consistent with
    /// **suppression** — an attacker who blocks the revocation endpoint to
    /// keep using a revoked license — so the fail-closed posture is defensible
    /// here in a way it is not for a 429.
    Unreachable,
}

/// Revocation status for a license.
#[derive(Debug, Clone)]
pub struct RevocationStatus {
    /// License ID that was checked.
    pub license_id: String,
    /// Whether the license is revoked.
    ///
    /// Read this together with [`Self::determination`]: it is the authority's
    /// answer only when that is [`Determination::Authoritative`].
    pub revoked: bool,
    /// Whether this reflects an answer or the absence of one.
    pub determination: Determination,
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
            determination: Determination::Authoritative,
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
            determination: Determination::Authoritative,
            revoked_at,
            reason,
            checked_at: Instant::now(),
            ttl,
        }
    }

    /// No answer was obtained — record **why**, and do not manufacture a
    /// verdict from it.
    ///
    /// `revoked` reflects the posture appropriate to the cause, not the
    /// authority's word; [`Self::determination`] says so, and
    /// [`Self::is_authoritatively_revoked`] is the honest predicate.
    ///
    /// - [`Indeterminate::Unreachable`] → `revoked = true` (fail closed). A
    ///   suppressed check is indistinguishable from an attacker blocking the
    ///   endpoint to keep using a revoked license.
    /// - [`Indeterminate::RateLimited`] → `revoked = false`. A 429 proves the
    ///   authority is **alive and answering**; it is a cooperative signal,
    ///   usually provoked by our own polling. Reading it as revoked converts
    ///   our request rate into a simultaneous outage for every correctly
    ///   licensed agent in the fleet.
    #[must_use]
    pub fn indeterminate(license_id: String, cause: Indeterminate, ttl: Duration) -> Self {
        let (revoked, reason, retry_ttl) = match &cause {
            Indeterminate::RateLimited { retry_after_secs } => (
                false,
                "Revocation authority rate-limited this check (HTTP 429). The authority is \
                 reachable and answering; this is NOT a revocation."
                    .to_string(),
                // Honor Retry-After when supplied, so we stop provoking it.
                retry_after_secs.map_or(Duration::from_secs(60), Duration::from_secs),
            ),
            Indeterminate::Unreachable => (
                true,
                "Revocation check could not obtain an answer - failing closed. This is a \
                 CHECK FAILURE, not an authority revocation."
                    .to_string(),
                Duration::from_secs(60),
            ),
        };
        Self {
            license_id,
            revoked,
            determination: Determination::Indeterminate(cause),
            revoked_at: None,
            reason: Some(reason),
            checked_at: Instant::now(),
            ttl: ttl.min(retry_ttl),
        }
    }

    /// **The authority said so.** True only for an authoritative revocation —
    /// never for a failed check.
    ///
    /// Prefer this wherever the answer is reported to a human or drives an
    /// irreversible action; [`Self::is_revoked`] folds in the fail-closed
    /// posture and cannot tell the two apart.
    #[must_use]
    pub fn is_authoritatively_revoked(&self) -> bool {
        self.revoked && self.determination == Determination::Authoritative
    }

    /// Did this status come from an actual answer?
    #[must_use]
    pub fn is_authoritative(&self) -> bool {
        self.determination == Determination::Authoritative
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
            },
            // A 429 means the authority is ALIVE and asking us to slow down —
            // the opposite evidence from an unreachable authority, and usually
            // provoked by our own polling. Reading it as a revocation takes
            // every correctly-licensed agent in the fleet offline at once.
            Err(VerifyError::RateLimited {
                url,
                retry_after_secs,
            }) => {
                warn!(
                    license_id = %license_id,
                    url = %url,
                    retry_after_secs = ?retry_after_secs,
                    "Revocation check rate-limited (429) — NOT a revocation; backing off"
                );
                let status = RevocationStatus::indeterminate(
                    license_id.to_string(),
                    Indeterminate::RateLimited { retry_after_secs },
                    self.default_ttl,
                );
                self.update_cache(license_id, &status);
                status
            },
            Err(e) => {
                warn!(
                    license_id = %license_id,
                    error = %e,
                    "Revocation check could not obtain an answer — failing closed"
                );
                let status = RevocationStatus::indeterminate(
                    license_id.to_string(),
                    Indeterminate::Unreachable,
                    self.default_ttl,
                );
                self.update_cache(license_id, &status);
                status
            },
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
    pub async fn check_multiple(&self, license_ids: &[&str]) -> HashMap<String, RevocationStatus> {
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
        let status = RevocationStatus::not_revoked("test-license".into(), Duration::from_secs(60));

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
    fn unreachable_authority_fails_closed_but_is_not_authoritative() {
        let status = RevocationStatus::indeterminate(
            "test-license".into(),
            Indeterminate::Unreachable,
            Duration::from_secs(3600), // Requested 1 hour
        );

        assert!(status.ttl <= Duration::from_secs(60), "retry soon");
        // Fail-secure posture is preserved: an unreachable authority is
        // consistent with SUPPRESSION (an attacker blocking the endpoint to
        // keep using a revoked license), so we still fail closed …
        assert!(status.is_revoked());
        // … but we do NOT claim the authority said so.
        assert!(!status.is_authoritative());
        assert!(
            !status.is_authoritatively_revoked(),
            "a failed check is not a revocation"
        );
    }

    /// **The defect this replaces.** A 429 means the authority is alive and
    /// asking us to slow down — usually because of our own polling. Treating
    /// it as a revocation takes every correctly-licensed agent in the fleet
    /// offline simultaneously.
    #[test]
    fn rate_limited_is_never_a_revocation() {
        let status = RevocationStatus::indeterminate(
            "test-license".into(),
            Indeterminate::RateLimited {
                retry_after_secs: Some(30),
            },
            Duration::from_secs(3600),
        );

        assert!(!status.is_revoked(), "429 MUST NOT read as revoked");
        assert!(!status.is_authoritatively_revoked());
        assert!(!status.is_authoritative());
        // Retry-After is honored, so we stop provoking the limit.
        assert!(status.ttl <= Duration::from_secs(30));
        assert!(status.reason.unwrap().contains("NOT a revocation"));
    }

    /// An authority that actually answers is the only source of a revocation.
    #[test]
    fn only_an_answer_is_authoritative() {
        let revoked = RevocationStatus::revoked(
            "l".into(),
            Some(1),
            Some("compromised".into()),
            Duration::from_secs(60),
        );
        assert!(revoked.is_authoritative() && revoked.is_authoritatively_revoked());

        let ok = RevocationStatus::not_revoked("l".into(), Duration::from_secs(60));
        assert!(ok.is_authoritative() && !ok.is_authoritatively_revoked());
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
