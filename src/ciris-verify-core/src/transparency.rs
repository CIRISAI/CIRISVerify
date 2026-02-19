//! Transparency log with Merkle tree for tamper-evident audit trail.
//!
//! Records every verification event in an append-only log with
//! SHA-256 Merkle tree integrity proofs. Provides:
//!
//! - **Chain linking**: Each entry includes hash of previous entry
//! - **Merkle root**: Tree root changes with every append
//! - **Inclusion proofs**: Prove any entry is in the log
//! - **Tamper detection**: Modification of any entry invalidates proofs
//! - **Optional persistence**: Append-only file for crash recovery

use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::license::LicenseStatus;
use crate::types::ValidationStatus;

/// Transparency log with Merkle tree integrity.
pub struct TransparencyLog {
    /// Ordered log entries.
    entries: RwLock<Vec<TransparencyEntry>>,
    /// Leaf hashes for Merkle tree computation.
    leaf_hashes: RwLock<Vec<[u8; 32]>>,
    /// Current Merkle root.
    current_root: RwLock<[u8; 32]>,
    /// Optional append-only persistent file.
    log_path: Option<PathBuf>,
    /// Next entry index.
    next_index: RwLock<u64>,
}

/// A single transparency log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyEntry {
    /// Entry index (monotonically increasing).
    pub index: u64,
    /// Unix timestamp of the event.
    pub timestamp: i64,
    /// License/deployment ID.
    pub license_id: String,
    /// License status at time of verification.
    pub status: LicenseStatus,
    /// Consensus validation status.
    pub consensus_status: ValidationStatus,
    /// Revocation revision at time of check.
    pub revocation_revision: u64,
    /// Hash of the previous entry (chain linking).
    pub previous_hash: [u8; 32],
    /// Merkle root after this entry was appended.
    pub merkle_root: [u8; 32],
}

/// Merkle inclusion proof for a single entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Index of the entry being proved.
    pub entry_index: u64,
    /// Hash of the entry (leaf).
    pub leaf_hash: [u8; 32],
    /// Sibling hashes along the path to root, with direction (true = right).
    pub siblings: Vec<(bool, [u8; 32])>,
    /// Expected root hash.
    pub root: [u8; 32],
}

/// A proof chain covering a range of entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofChain {
    /// Start index (inclusive).
    pub start_index: u64,
    /// End index (inclusive).
    pub end_index: u64,
    /// Entries in the range.
    pub entries: Vec<TransparencyEntry>,
    /// Merkle root at the end of the range.
    pub merkle_root: [u8; 32],
}

impl TransparencyLog {
    /// Create a new transparency log.
    ///
    /// If `log_path` is provided, entries are also appended to the file.
    pub fn new(log_path: Option<PathBuf>) -> Self {
        let zero_root = [0u8; 32];
        Self {
            entries: RwLock::new(Vec::new()),
            leaf_hashes: RwLock::new(Vec::new()),
            current_root: RwLock::new(zero_root),
            log_path,
            next_index: RwLock::new(0),
        }
    }

    /// Append a verification event to the log.
    ///
    /// Returns the new Merkle root after appending.
    pub fn append(
        &self,
        license_id: &str,
        status: LicenseStatus,
        consensus_status: ValidationStatus,
        revocation_revision: u64,
    ) -> Result<[u8; 32], String> {
        let mut entries = self
            .entries
            .write()
            .map_err(|_| "Failed to acquire entries lock")?;
        let mut leaf_hashes = self
            .leaf_hashes
            .write()
            .map_err(|_| "Failed to acquire leaf_hashes lock")?;
        let mut current_root = self
            .current_root
            .write()
            .map_err(|_| "Failed to acquire root lock")?;
        let mut next_index = self
            .next_index
            .write()
            .map_err(|_| "Failed to acquire index lock")?;

        // Chain linking: hash of previous entry
        let previous_hash = if let Some(last) = entries.last() {
            hash_entry(last)
        } else {
            [0u8; 32]
        };

        let index = *next_index;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // Create entry (merkle_root will be updated after tree computation)
        let mut entry = TransparencyEntry {
            index,
            timestamp,
            license_id: license_id.to_string(),
            status,
            consensus_status,
            revocation_revision,
            previous_hash,
            merkle_root: [0u8; 32], // Placeholder
        };

        // Compute leaf hash
        let leaf = hash_entry(&entry);
        leaf_hashes.push(leaf);

        // Recompute Merkle root
        let new_root = compute_merkle_root(&leaf_hashes);
        *current_root = new_root;

        // Update the entry with the actual Merkle root
        entry.merkle_root = new_root;

        // Persist to file if configured (non-fatal on failure)
        if let Some(ref path) = self.log_path {
            let _ = append_to_file(path, &entry);
        }

        entries.push(entry);
        *next_index = index + 1;

        Ok(new_root)
    }

    /// Get the current Merkle root.
    #[must_use]
    pub fn merkle_root(&self) -> [u8; 32] {
        self.current_root.read().map(|r| *r).unwrap_or([0u8; 32])
    }

    /// Get the number of entries in the log.
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.next_index.read().map(|i| *i).unwrap_or(0)
    }

    /// Generate a Merkle inclusion proof for an entry.
    pub fn proof_for_entry(&self, index: u64) -> Option<MerkleProof> {
        let leaf_hashes = self.leaf_hashes.read().ok()?;
        let idx = index as usize;
        if idx >= leaf_hashes.len() {
            return None;
        }

        let leaf_hash = leaf_hashes[idx];
        let siblings = compute_proof_path(&leaf_hashes, idx);
        let root = self.merkle_root();

        Some(MerkleProof {
            entry_index: index,
            leaf_hash,
            siblings,
            root,
        })
    }

    /// Verify a Merkle inclusion proof.
    #[must_use]
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut current = proof.leaf_hash;
        for (is_right, sibling) in &proof.siblings {
            current = if *is_right {
                hash_pair(&current, sibling)
            } else {
                hash_pair(sibling, &current)
            };
        }
        current == proof.root
    }

    /// Export all entries.
    pub fn export(&self) -> Vec<TransparencyEntry> {
        self.entries.read().map(|e| e.clone()).unwrap_or_default()
    }

    /// Export a proof chain for a range of entries.
    pub fn export_proof_chain(&self, start: u64, end: u64) -> Option<ProofChain> {
        let entries = self.entries.read().ok()?;
        let start_idx = start as usize;
        let end_idx = (end as usize).min(entries.len().saturating_sub(1));

        if start_idx >= entries.len() {
            return None;
        }

        let chain_entries: Vec<TransparencyEntry> = entries[start_idx..=end_idx].to_vec();

        Some(ProofChain {
            start_index: start,
            end_index: end_idx as u64,
            entries: chain_entries,
            merkle_root: self.merkle_root(),
        })
    }
}

// ========================================================================
// Merkle tree internals
// ========================================================================

/// Hash a transparency entry to produce a leaf hash.
fn hash_entry(entry: &TransparencyEntry) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ciris-log-entry:");
    hasher.update(entry.index.to_le_bytes());
    hasher.update(entry.timestamp.to_le_bytes());
    hasher.update(entry.license_id.as_bytes());
    hasher.update(format!("{:?}", entry.status).as_bytes());
    hasher.update(format!("{:?}", entry.consensus_status).as_bytes());
    hasher.update(entry.revocation_revision.to_le_bytes());
    hasher.update(entry.previous_hash);
    hasher.finalize().into()
}

/// Hash two nodes to produce an internal Merkle tree node.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ciris-merkle-node:");
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Compute the Merkle root from a list of leaf hashes.
fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));

        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                next_level.push(hash_pair(&chunk[0], &chunk[1]));
            } else {
                // Odd leaf: promote unchanged
                next_level.push(chunk[0]);
            }
        }

        current_level = next_level;
    }

    current_level[0]
}

/// Compute the sibling path for a Merkle inclusion proof.
fn compute_proof_path(leaves: &[[u8; 32]], index: usize) -> Vec<(bool, [u8; 32])> {
    if leaves.len() <= 1 {
        return Vec::new();
    }

    let mut path = Vec::new();
    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;

    while current_level.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };

        if sibling_idx < current_level.len() {
            // is_right: true if the sibling is to the right of us
            let is_right = idx % 2 == 0;
            path.push((is_right, current_level[sibling_idx]));
        }
        // else: odd leaf, no sibling at this level

        // Move to next level
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                next_level.push(hash_pair(&chunk[0], &chunk[1]));
            } else {
                next_level.push(chunk[0]);
            }
        }

        idx /= 2;
        current_level = next_level;
    }

    path
}

/// Append an entry to the persistent log file.
fn append_to_file(path: &PathBuf, entry: &TransparencyEntry) -> Result<(), String> {
    use std::io::Write;

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let line = serde_json::to_string(entry).map_err(|e| e.to_string())?;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;

    writeln!(file, "{}", line).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_and_retrieve() {
        let log = TransparencyLog::new(None);

        let root = log
            .append(
                "lic-001",
                LicenseStatus::LicensedProfessional,
                ValidationStatus::AllSourcesAgree,
                100,
            )
            .unwrap();

        assert_ne!(root, [0u8; 32], "Root should not be zero after append");
        assert_eq!(log.entry_count(), 1);

        let entries = log.export();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].license_id, "lic-001");
        assert_eq!(entries[0].index, 0);
        assert_eq!(entries[0].revocation_revision, 100);
    }

    #[test]
    fn test_chain_linking() {
        let log = TransparencyLog::new(None);

        log.append(
            "lic-001",
            LicenseStatus::LicensedProfessional,
            ValidationStatus::AllSourcesAgree,
            100,
        )
        .unwrap();

        log.append(
            "lic-001",
            LicenseStatus::LicensedProfessional,
            ValidationStatus::AllSourcesAgree,
            101,
        )
        .unwrap();

        let entries = log.export();
        assert_eq!(entries.len(), 2);

        // First entry's previous_hash should be zero (no predecessor)
        assert_eq!(entries[0].previous_hash, [0u8; 32]);

        // Second entry's previous_hash should be hash of first entry
        let expected_prev = hash_entry(&entries[0]);
        assert_eq!(entries[1].previous_hash, expected_prev);
    }

    #[test]
    fn test_merkle_proof_verification() {
        let log = TransparencyLog::new(None);

        // Add several entries
        for i in 0..5 {
            log.append(
                &format!("lic-{:03}", i),
                LicenseStatus::LicensedProfessional,
                ValidationStatus::AllSourcesAgree,
                100 + i,
            )
            .unwrap();
        }

        // Verify proof for each entry
        for i in 0..5 {
            let proof = log.proof_for_entry(i).unwrap();
            assert!(
                TransparencyLog::verify_proof(&proof),
                "Proof for entry {} should verify",
                i
            );
        }
    }

    #[test]
    fn test_tamper_detection() {
        let log = TransparencyLog::new(None);

        for i in 0..3 {
            log.append(
                &format!("lic-{:03}", i),
                LicenseStatus::LicensedProfessional,
                ValidationStatus::AllSourcesAgree,
                100 + i,
            )
            .unwrap();
        }

        // Get valid proof
        let mut proof = log.proof_for_entry(1).unwrap();
        assert!(TransparencyLog::verify_proof(&proof));

        // Tamper with the leaf hash
        proof.leaf_hash[0] ^= 0xFF;
        assert!(
            !TransparencyLog::verify_proof(&proof),
            "Tampered proof should not verify"
        );
    }

    #[test]
    fn test_root_changes_on_append() {
        let log = TransparencyLog::new(None);

        let root0 = log.merkle_root();
        assert_eq!(root0, [0u8; 32], "Empty log should have zero root");

        let root1 = log
            .append(
                "lic-001",
                LicenseStatus::LicensedProfessional,
                ValidationStatus::AllSourcesAgree,
                100,
            )
            .unwrap();

        assert_ne!(root1, root0, "Root should change after first append");

        let root2 = log
            .append(
                "lic-002",
                LicenseStatus::UnlicensedCommunity,
                ValidationStatus::PartialAgreement,
                101,
            )
            .unwrap();

        assert_ne!(root2, root1, "Root should change after second append");
    }

    #[test]
    fn test_proof_chain_export() {
        let log = TransparencyLog::new(None);

        for i in 0..5 {
            log.append(
                &format!("lic-{:03}", i),
                LicenseStatus::LicensedProfessional,
                ValidationStatus::AllSourcesAgree,
                100 + i,
            )
            .unwrap();
        }

        let chain = log.export_proof_chain(1, 3).unwrap();
        assert_eq!(chain.start_index, 1);
        assert_eq!(chain.end_index, 3);
        assert_eq!(chain.entries.len(), 3);
        assert_eq!(chain.entries[0].index, 1);
        assert_eq!(chain.entries[2].index, 3);
    }

    #[test]
    fn test_persistent_log_file() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("transparency.log");

        let log = TransparencyLog::new(Some(log_path.clone()));

        log.append(
            "lic-001",
            LicenseStatus::LicensedProfessional,
            ValidationStatus::AllSourcesAgree,
            100,
        )
        .unwrap();

        log.append(
            "lic-002",
            LicenseStatus::UnlicensedCommunity,
            ValidationStatus::PartialAgreement,
            101,
        )
        .unwrap();

        // Verify file was written
        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "Should have 2 log lines");

        // Each line should be valid JSON
        for line in &lines {
            let entry: TransparencyEntry = serde_json::from_str(line).unwrap();
            assert!(!entry.license_id.is_empty());
        }
    }
}
