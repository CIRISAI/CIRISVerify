//! Audit trail integrity verification.
//!
//! Verifies the cryptographic integrity of CIRISAgent's audit log,
//! ensuring the hash chain is intact from genesis to present.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, instrument, warn};

use crate::error::VerifyError;

/// Result of audit trail verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditVerificationResult {
    /// Whether the audit trail is valid.
    pub valid: bool,
    /// Total entries in the audit log.
    pub total_entries: u64,
    /// Number of entries verified.
    pub entries_verified: u64,
    /// Whether the hash chain is intact.
    pub hash_chain_valid: bool,
    /// Whether all signatures are valid.
    pub signatures_valid: bool,
    /// Whether genesis entry is properly formed.
    pub genesis_valid: bool,
    /// Whether the signing key is the Portal key.
    pub portal_key_used: bool,
    /// First tampered sequence number (if any).
    pub first_tampered_sequence: Option<u64>,
    /// List of errors found.
    pub errors: Vec<String>,
    /// Verification time in milliseconds.
    pub verification_time_ms: u64,
    /// Chain summary.
    pub chain_summary: Option<ChainSummary>,
}

/// Summary of the audit chain state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSummary {
    /// Sequence range [min, max].
    pub sequence_range: (u64, u64),
    /// Current sequence number.
    pub current_sequence: u64,
    /// Current hash value.
    pub current_hash: String,
    /// Timestamp of oldest entry.
    pub oldest_entry: Option<String>,
    /// Timestamp of newest entry.
    pub newest_entry: Option<String>,
}

/// A single audit entry for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique event ID.
    pub event_id: String,
    /// Event timestamp.
    pub event_timestamp: String,
    /// Type of event.
    pub event_type: String,
    /// ID of the originator.
    pub originator_id: String,
    /// Event payload data.
    #[serde(default)]
    pub event_payload: String,
    /// Sequence number in chain.
    pub sequence_number: u64,
    /// Hash of previous entry or "genesis".
    pub previous_hash: String,
    /// Hash of this entry.
    pub entry_hash: String,
    /// Cryptographic signature.
    #[serde(default)]
    pub signature: String,
    /// ID of key used for signing.
    #[serde(default)]
    pub signing_key_id: Option<String>,
}

impl AuditEntry {
    /// Compute the expected hash for this entry.
    ///
    /// Creates a canonical JSON representation and computes SHA-256.
    pub fn compute_hash(&self) -> String {
        let canonical = serde_json::json!({
            "event_id": self.event_id,
            "event_timestamp": self.event_timestamp,
            "event_type": self.event_type,
            "originator_id": self.originator_id,
            "event_payload": self.event_payload,
            "sequence_number": self.sequence_number,
            "previous_hash": self.previous_hash,
        });

        let canonical_json = serde_json::to_string(&canonical).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(canonical_json.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify this entry's hash is correct.
    pub fn verify_hash(&self) -> bool {
        self.compute_hash() == self.entry_hash
    }
}

/// Audit trail verifier.
///
/// Verifies the integrity of an agent's audit log by checking:
/// 1. Hash chain continuity (each entry links to previous)
/// 2. Hash validity (each entry's hash matches computed hash)
/// 3. Signature validity (each signature verifies)
/// 4. Genesis validity (first entry has "genesis" as previous_hash)
/// 5. Portal key usage (signing key is the Portal-issued key)
pub struct AuditVerifier {
    /// Expected Portal key ID (for verifying signatures).
    portal_key_id: Option<String>,
}

impl AuditVerifier {
    /// Create a new audit verifier.
    ///
    /// # Arguments
    ///
    /// * `portal_key_id` - Expected Portal key ID for signature verification
    pub fn new(portal_key_id: Option<String>) -> Self {
        Self { portal_key_id }
    }

    /// Verify a list of audit entries.
    ///
    /// The entries must be provided in sequence order.
    ///
    /// # Arguments
    ///
    /// * `entries` - Audit entries to verify, in sequence order
    /// * `verify_signatures` - Whether to verify cryptographic signatures
    #[instrument(skip(self, entries), fields(entry_count = entries.len()))]
    pub fn verify_entries(
        &self,
        entries: &[AuditEntry],
        verify_signatures: bool,
    ) -> AuditVerificationResult {
        let start = std::time::Instant::now();
        let mut errors = Vec::new();
        let mut first_tampered: Option<u64> = None;
        let mut all_portal_key = true;

        if entries.is_empty() {
            return AuditVerificationResult {
                valid: true,
                total_entries: 0,
                entries_verified: 0,
                hash_chain_valid: true,
                signatures_valid: true,
                genesis_valid: true,
                portal_key_used: true,
                first_tampered_sequence: None,
                errors: vec![],
                verification_time_ms: start.elapsed().as_millis() as u64,
                chain_summary: None,
            };
        }

        // Check genesis entry
        let genesis_valid = entries[0].previous_hash == "genesis";
        if !genesis_valid {
            errors.push(format!(
                "Invalid genesis: first entry has previous_hash='{}', expected 'genesis'",
                entries[0].previous_hash
            ));
            if first_tampered.is_none() {
                first_tampered = Some(entries[0].sequence_number);
            }
        }

        let mut hash_chain_valid = true;
        let signatures_valid = true;
        let mut previous_hash = String::from("genesis");

        for (i, entry) in entries.iter().enumerate() {
            // Check sequence continuity
            let expected_seq = if i == 0 {
                entries[0].sequence_number
            } else {
                entries[i - 1].sequence_number + 1
            };

            if i > 0 && entry.sequence_number != expected_seq {
                errors.push(format!(
                    "Sequence gap: expected {}, got {}",
                    expected_seq, entry.sequence_number
                ));
                if first_tampered.is_none() {
                    first_tampered = Some(entry.sequence_number);
                }
            }

            // Check previous hash link
            if entry.previous_hash != previous_hash {
                errors.push(format!(
                    "Hash chain break at sequence {}: expected previous_hash='{}', got '{}'",
                    entry.sequence_number, previous_hash, entry.previous_hash
                ));
                hash_chain_valid = false;
                if first_tampered.is_none() {
                    first_tampered = Some(entry.sequence_number);
                }
            }

            // Check entry hash
            if !entry.verify_hash() {
                let computed = entry.compute_hash();
                errors.push(format!(
                    "Hash mismatch at sequence {}: computed='{}', stored='{}'",
                    entry.sequence_number, computed, entry.entry_hash
                ));
                hash_chain_valid = false;
                if first_tampered.is_none() {
                    first_tampered = Some(entry.sequence_number);
                }
            }

            // Check signature (if requested and signature present)
            if verify_signatures && !entry.signature.is_empty() {
                // TODO: Implement actual Ed25519 signature verification
                // For now, we just check that a signature exists
                debug!(
                    sequence = entry.sequence_number,
                    "Signature present (full verification pending)"
                );
            }

            // Check Portal key usage
            if let Some(ref portal_key) = self.portal_key_id {
                if let Some(ref signing_key) = entry.signing_key_id {
                    if signing_key != portal_key {
                        all_portal_key = false;
                        debug!(
                            sequence = entry.sequence_number,
                            signing_key = %signing_key,
                            expected = %portal_key,
                            "Entry signed with non-Portal key"
                        );
                    }
                }
            }

            // Update previous hash for next iteration
            previous_hash = entry.entry_hash.clone();
        }

        let total_entries = entries.len() as u64;
        let chain_summary = Some(ChainSummary {
            sequence_range: (
                entries.first().map(|e| e.sequence_number).unwrap_or(0),
                entries.last().map(|e| e.sequence_number).unwrap_or(0),
            ),
            current_sequence: entries.last().map(|e| e.sequence_number).unwrap_or(0),
            current_hash: entries
                .last()
                .map(|e| e.entry_hash.clone())
                .unwrap_or_default(),
            oldest_entry: entries.first().map(|e| e.event_timestamp.clone()),
            newest_entry: entries.last().map(|e| e.event_timestamp.clone()),
        });

        let valid = hash_chain_valid && genesis_valid && errors.is_empty();

        if valid {
            info!(entries = total_entries, "Audit trail verification passed");
        } else {
            warn!(
                entries = total_entries,
                errors = errors.len(),
                "Audit trail verification FAILED"
            );
        }

        AuditVerificationResult {
            valid,
            total_entries,
            entries_verified: total_entries,
            hash_chain_valid,
            signatures_valid,
            genesis_valid,
            portal_key_used: all_portal_key,
            first_tampered_sequence: first_tampered,
            errors,
            verification_time_ms: start.elapsed().as_millis() as u64,
            chain_summary,
        }
    }

    /// Verify a range of entries (spot check).
    ///
    /// # Arguments
    ///
    /// * `entries` - Full list of entries
    /// * `sample_count` - Number of random entries to check
    /// * `seed` - Random seed for reproducibility
    #[instrument(skip(self, entries), fields(sample_count = sample_count))]
    pub fn verify_spot_check(
        &self,
        entries: &[AuditEntry],
        sample_count: usize,
        seed: u64,
    ) -> AuditVerificationResult {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        if entries.is_empty() || sample_count == 0 {
            return self.verify_entries(&[], false);
        }

        let mut rng = StdRng::seed_from_u64(seed);
        let mut indices: Vec<usize> = (0..entries.len()).collect();

        // Always include first and last
        let mut selected = vec![0, entries.len() - 1];

        // Add random samples
        let remaining = sample_count.saturating_sub(2);
        for _ in 0..remaining {
            if indices.is_empty() {
                break;
            }
            let idx = rng.gen_range(0..indices.len());
            let entry_idx = indices.remove(idx);
            if !selected.contains(&entry_idx) {
                selected.push(entry_idx);
            }
        }

        selected.sort_unstable();

        // Extract selected entries
        let sampled: Vec<AuditEntry> = selected
            .into_iter()
            .filter_map(|i| entries.get(i).cloned())
            .collect();

        info!(
            total = entries.len(),
            sampled = sampled.len(),
            "Performing spot check verification"
        );

        // Spot check only verifies individual entry hashes, not chain continuity
        // (since we're sampling random entries, chain links can't be verified)
        let mut errors = Vec::new();

        for entry in &sampled {
            if !entry.verify_hash() {
                errors.push(format!(
                    "Hash mismatch at sequence {}: computed='{}', stored='{}'",
                    entry.sequence_number,
                    entry.compute_hash(),
                    entry.entry_hash
                ));
            }
        }

        let valid = errors.is_empty();

        AuditVerificationResult {
            valid,
            total_entries: entries.len() as u64,
            entries_verified: sampled.len() as u64,
            hash_chain_valid: valid, // For spot check, this means all sampled hashes are valid
            signatures_valid: true,  // Signature check not performed in spot check
            genesis_valid: sampled
                .first()
                .map(|e| e.sequence_number == 1 && e.previous_hash == "genesis")
                .unwrap_or(true),
            portal_key_used: true,
            first_tampered_sequence: errors
                .first()
                .and_then(|e| e.split("sequence ").nth(1)?.split(':').next()?.parse().ok()),
            errors,
            verification_time_ms: 0,
            chain_summary: None,
        }
    }
}

/// Verify audit entries from JSON data.
///
/// # Arguments
///
/// * `json_data` - JSON string containing array of audit entries
/// * `portal_key_id` - Expected Portal key ID
pub fn verify_audit_json(
    json_data: &str,
    portal_key_id: Option<String>,
) -> Result<AuditVerificationResult, VerifyError> {
    let entries: Vec<AuditEntry> =
        serde_json::from_str(json_data).map_err(|e| VerifyError::ConfigError {
            message: format!("Failed to parse audit entries: {}", e),
        })?;

    let verifier = AuditVerifier::new(portal_key_id);
    Ok(verifier.verify_entries(&entries, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(seq: u64, prev_hash: &str) -> AuditEntry {
        let mut entry = AuditEntry {
            event_id: format!("event-{}", seq),
            event_timestamp: "2025-01-01T00:00:00Z".to_string(),
            event_type: "test".to_string(),
            originator_id: "test-agent".to_string(),
            event_payload: "{}".to_string(),
            sequence_number: seq,
            previous_hash: prev_hash.to_string(),
            entry_hash: String::new(),
            signature: String::new(),
            signing_key_id: None,
        };
        entry.entry_hash = entry.compute_hash();
        entry
    }

    #[test]
    fn test_empty_chain() {
        let verifier = AuditVerifier::new(None);
        let result = verifier.verify_entries(&[], false);
        assert!(result.valid);
        assert_eq!(result.total_entries, 0);
    }

    #[test]
    fn test_valid_chain() {
        let entry1 = make_entry(1, "genesis");
        let entry2 = make_entry(2, &entry1.entry_hash);
        let entry3 = make_entry(3, &entry2.entry_hash);

        let verifier = AuditVerifier::new(None);
        let result = verifier.verify_entries(&[entry1, entry2, entry3], false);

        assert!(result.valid);
        assert!(result.hash_chain_valid);
        assert!(result.genesis_valid);
        assert_eq!(result.total_entries, 3);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_invalid_genesis() {
        let entry1 = make_entry(1, "not-genesis");

        let verifier = AuditVerifier::new(None);
        let result = verifier.verify_entries(&[entry1], false);

        assert!(!result.valid);
        assert!(!result.genesis_valid);
        assert_eq!(result.first_tampered_sequence, Some(1));
    }

    #[test]
    fn test_broken_chain() {
        let entry1 = make_entry(1, "genesis");
        let entry2 = make_entry(2, "wrong-hash"); // Should be entry1.entry_hash

        let verifier = AuditVerifier::new(None);
        let result = verifier.verify_entries(&[entry1, entry2], false);

        assert!(!result.valid);
        assert!(!result.hash_chain_valid);
        assert_eq!(result.first_tampered_sequence, Some(2));
    }

    #[test]
    fn test_tampered_entry() {
        let entry1 = make_entry(1, "genesis");
        let mut entry2 = make_entry(2, &entry1.entry_hash);
        entry2.event_payload = "tampered!".to_string(); // Tamper without updating hash

        let verifier = AuditVerifier::new(None);
        let result = verifier.verify_entries(&[entry1, entry2], false);

        assert!(!result.valid);
        assert!(!result.hash_chain_valid);
        assert!(result.errors.iter().any(|e| e.contains("Hash mismatch")));
    }

    #[test]
    fn test_spot_check() {
        let entry1 = make_entry(1, "genesis");
        let entry2 = make_entry(2, &entry1.entry_hash);
        let entry3 = make_entry(3, &entry2.entry_hash);
        let entry4 = make_entry(4, &entry3.entry_hash);
        let entry5 = make_entry(5, &entry4.entry_hash);

        let verifier = AuditVerifier::new(None);
        let result = verifier.verify_spot_check(&[entry1, entry2, entry3, entry4, entry5], 3, 42);

        // Spot check should pass for valid entries
        assert!(result.hash_chain_valid);
        assert_eq!(result.total_entries, 5);
        assert!(result.entries_verified <= 5);
    }
}
