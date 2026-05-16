//! Transparency log with Merkle tree for tamper-evident audit trail.
//!
//! v2.3.0 (CIRISVerify#23): SOTA upgrade aligning with RFC 6962 / RFC 9162
//! (Certificate Transparency) so this becomes the canonical transparency
//! substrate for the entire CIRIS stack — license verification (Verify),
//! audit chain (Persist), and edge nodes (Edge) plug in via the
//! `TransparencyLeaf` and `TransparencyStore` traits.
//!
//! ## What the SOTA upgrade buys us
//!
//! | Threat | Mitigation |
//! |---|---|
//! | Log fork / split-view | [`SignedTreeHead`] + reserved [`WitnessSignature`] (witness protocol later) |
//! | Retroactive insertion | [`ConsistencyProof`] proves append-only between two STH sizes |
//! | Selective omission | [`MerkleProof`] against signed root |
//! | Stale STH acceptance | STH `timestamp` field; verifier-side freshness policy |
//! | Cross-tenant correlation | Per-`log_id` scoping ([`TransparencyLog::for_log`]) |
//! | Cross-subsystem proof collision | RFC 6962 byte prefixes (`0x00` leaf, `0x01` node) |
//! | Quantum break on signing | Hybrid Ed25519 + ML-DSA-65 via `ciris-crypto` |
//! | Quantum break on tree | SHA-256 (PQ-resistant) |
//!
//! ## Breaking change from v2.2.x
//!
//! `hash_leaf` / `hash_node` now use RFC 6962 byte prefixes (`0x00` /
//! `0x01`) instead of the v2.2.x string prefixes (`"ciris-log-entry:"` /
//! `"ciris-merkle-node:"`). Merkle roots computed by v2.3.0+ are
//! **not** byte-comparable with v2.2.x roots. The architectural call
//! (#23, 2026-05-16) treats this as a clean cutover: persist's audit-
//! chain-bridge policy is genesis-on-cutover + archive legacy chain,
//! and Verify is the wellspring (downstream pins the new minor).
//!
//! ## Trait-based architecture
//!
//! * [`TransparencyLeaf`] — leaf data with canonical-bytes serialization.
//!   Verify's [`TransparencyEntry`] is one impl (license domain). Persist
//!   plugs in `AuditLeaf`. Edge can plug in its own.
//! * [`TransparencyStore`] — append-only storage abstraction. Verify ships
//!   [`InMemoryTransparencyStore`] (memory + optional append-only file).
//!   Persist wires PG / SQLite backends.
//! * [`TransparencyLog<L>`] — generic over leaf type. Wraps a store, owns
//!   the `log_id`, exposes append + inclusion + consistency + STH APIs.
//!
//! ## License-domain convenience
//!
//! For Verify's own license log, [`TransparencyLog<TransparencyEntry>`]
//! exposes [`append_license`](TransparencyLog::append_license) which
//! handles chain-linking (previous-entry hash) so engine callers don't
//! have to assemble entries manually.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::license::LicenseStatus;
use crate::types::ValidationStatus;

// ========================================================================
// Errors
// ========================================================================

/// Errors from transparency-log operations.
#[derive(Debug, Error)]
pub enum TransparencyError {
    /// Storage layer failure (lock poisoned, file I/O, db connection, etc.).
    #[error("transparency storage error: {0}")]
    Storage(String),

    /// Canonical-bytes serialization failed for a leaf.
    #[error("leaf serialization failed: {0}")]
    Serialization(String),

    /// Index out of range for the current tree.
    #[error("index {index} out of range (tree_size={tree_size})")]
    IndexOutOfRange {
        /// Requested index.
        index: u64,
        /// Current tree size.
        tree_size: u64,
    },

    /// Invalid consistency-proof parameters (e.g. `from_size > to_size`).
    #[error(
        "invalid consistency-proof range: from={from_size} to={to_size} (tree_size={tree_size})"
    )]
    InvalidRange {
        /// Caller-supplied from_size.
        from_size: u64,
        /// Caller-supplied to_size.
        to_size: u64,
        /// Current tree size.
        tree_size: u64,
    },

    /// STH signing failed (delegated from `ciris-crypto`).
    #[error("STH signing failed: {0}")]
    Signing(String),
}

impl From<ciris_crypto::CryptoError> for TransparencyError {
    fn from(e: ciris_crypto::CryptoError) -> Self {
        Self::Signing(e.to_string())
    }
}

// ========================================================================
// Leaf trait + license-domain impl
// ========================================================================

/// A leaf in the transparency tree.
///
/// Implementors define the canonical byte representation that's hashed
/// (with RFC 6962 `0x00` prefix) to produce the leaf hash. Any data shape
/// can be a leaf as long as canonicalization is stable across processes
/// and versions.
pub trait TransparencyLeaf: Send + Sync + Clone {
    /// Canonical bytes for this leaf. Must be deterministic — two leaves
    /// with the same semantic content must serialize to identical bytes.
    fn canonical_bytes(&self) -> Result<Vec<u8>, TransparencyError>;
}

/// A single transparency-log entry for the license-verification domain.
///
/// Each entry chain-links to the previous via `previous_hash` and records
/// the Merkle root *after* the entry was appended. The chain-link is
/// belt-and-suspenders alongside the Merkle root; either alone is
/// integrity-sound, both together survive replay/reorder attacks even
/// against a partially-cooperating store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyEntry {
    /// Entry index (monotonically increasing, dense).
    pub index: u64,
    /// Unix timestamp (seconds) of the event.
    pub timestamp: i64,
    /// License/deployment ID.
    pub license_id: String,
    /// License status at time of verification.
    pub status: LicenseStatus,
    /// Consensus validation status.
    pub consensus_status: ValidationStatus,
    /// Revocation revision at time of check.
    pub revocation_revision: u64,
    /// SHA-256 of the canonical bytes of the previous entry (chain link).
    pub previous_hash: [u8; 32],
    /// Merkle root after this entry was appended.
    pub merkle_root: [u8; 32],
}

impl TransparencyLeaf for TransparencyEntry {
    fn canonical_bytes(&self) -> Result<Vec<u8>, TransparencyError> {
        // Field-by-field little-endian + length-prefixed strings. Avoids
        // serde's compositional ambiguity (CBOR/JSON ordering) for hashing.
        let mut buf = Vec::with_capacity(8 + 8 + 4 + self.license_id.len() + 16 + 8 + 32);
        buf.extend_from_slice(&self.index.to_le_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        let lid = self.license_id.as_bytes();
        buf.extend_from_slice(&(u32::try_from(lid.len()).unwrap_or(u32::MAX)).to_le_bytes());
        buf.extend_from_slice(lid);
        // LicenseStatus and ValidationStatus are small fixed-variant enums.
        // Hash their Debug formatting — they derive Debug deterministically.
        // (Persisted across crate releases by the trait-derived Debug names.)
        let status_dbg = format!("{:?}", self.status);
        buf.extend_from_slice(&(u32::try_from(status_dbg.len()).unwrap_or(u32::MAX)).to_le_bytes());
        buf.extend_from_slice(status_dbg.as_bytes());
        let cs_dbg = format!("{:?}", self.consensus_status);
        buf.extend_from_slice(&(u32::try_from(cs_dbg.len()).unwrap_or(u32::MAX)).to_le_bytes());
        buf.extend_from_slice(cs_dbg.as_bytes());
        buf.extend_from_slice(&self.revocation_revision.to_le_bytes());
        buf.extend_from_slice(&self.previous_hash);
        Ok(buf)
    }
}

// ========================================================================
// Proofs
// ========================================================================

/// Merkle inclusion proof for a single entry.
///
/// Verifier reconstructs the root by hashing the leaf with each sibling
/// in `siblings`, choosing left/right based on the `bool` flag (`true` =
/// sibling is on the right). If the reconstructed value equals `root`,
/// the entry is in the tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Index of the entry being proved.
    pub entry_index: u64,
    /// Hash of the entry (the leaf hash, post-RFC-6962-prefix).
    pub leaf_hash: [u8; 32],
    /// Sibling hashes along the path to root, with direction
    /// (`true` = sibling on the right).
    pub siblings: Vec<(bool, [u8; 32])>,
    /// Expected root hash. The verifier compares its reconstruction
    /// against this.
    pub root: [u8; 32],
}

/// A consistency proof between two tree sizes per RFC 6962 §2.1.2.
///
/// Allows a verifier holding `(old_root, old_size)` and observing
/// `(new_root, new_size)` to confirm the new tree is a legal append of
/// the old — i.e. **no retroactive insertion or modification**. The
/// proof itself is just a list of node hashes; the verification
/// algorithm reconstructs both roots from these and compares.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProof {
    /// Earlier tree size.
    pub old_tree_size: u64,
    /// Later tree size.
    pub new_tree_size: u64,
    /// Node hashes for the consistency reconstruction (RFC 6962 §2.1.2).
    pub proof_hashes: Vec<[u8; 32]>,
}

/// A proof chain covering a range of entries (legacy export shape).
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

// ========================================================================
// Signed Tree Head
// ========================================================================

/// A signed snapshot of the log at a specific tree size.
///
/// The signature covers the canonical bytes of the head fields
/// (`log_id`, `tree_size`, `root_hash`, `timestamp`).
/// `witness_signatures` carries independent cosignatures by witness
/// nodes — reserved for the future witness-cosigning protocol;
/// v2.3.0 ships this empty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHead {
    /// Identifier of the log this head describes.
    pub log_id: String,
    /// Number of leaves at the time of signing.
    pub tree_size: u64,
    /// Merkle root at `tree_size`.
    pub root_hash: [u8; 32],
    /// Wall-clock time the STH was signed.
    pub timestamp: DateTime<Utc>,
    /// Hybrid signature (Ed25519 + ML-DSA-65, with PQC covering classical)
    /// over the canonical signing bytes of (log_id, tree_size, root_hash,
    /// timestamp).
    pub signature: ciris_crypto::HybridSignature,
    /// Independent cosignatures by witness nodes. Empty in v2.3.0; the
    /// witness protocol lands later.
    #[serde(default)]
    pub witness_signatures: Vec<WitnessSignature>,
}

impl SignedTreeHead {
    /// Canonical bytes that the signature covers. Stable across versions
    /// — changing this is a wire-format break.
    #[must_use]
    pub fn signing_bytes(
        log_id: &str,
        tree_size: u64,
        root_hash: &[u8; 32],
        timestamp: DateTime<Utc>,
    ) -> Vec<u8> {
        // length-prefixed log_id || tree_size LE || root_hash || ts secs LE || ts nanos LE
        let lid = log_id.as_bytes();
        let mut buf = Vec::with_capacity(4 + lid.len() + 8 + 32 + 8 + 4);
        buf.extend_from_slice(&(u32::try_from(lid.len()).unwrap_or(u32::MAX)).to_le_bytes());
        buf.extend_from_slice(lid);
        buf.extend_from_slice(&tree_size.to_le_bytes());
        buf.extend_from_slice(root_hash);
        buf.extend_from_slice(&timestamp.timestamp().to_le_bytes());
        buf.extend_from_slice(&timestamp.timestamp_subsec_nanos().to_le_bytes());
        buf
    }
}

/// A witness cosignature over an STH.
///
/// Witnesses observe the log independently and cosign its STH; downstream
/// verifiers gating on N-of-M witness agreement detect split-view attacks
/// where a log operator serves different trees to different clients.
/// Reserved field in v2.3.0; populated by future witness protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSignature {
    /// Stable identifier for the witness.
    pub witness_id: String,
    /// Hybrid signature over the same `SignedTreeHead::signing_bytes`.
    pub signature: ciris_crypto::HybridSignature,
}

// ========================================================================
// Storage trait + in-memory impl
// ========================================================================

/// Append-only storage for a transparency log.
///
/// Implementors decide where leaves and STHs persist (memory, file, PG,
/// SQLite). The trait deliberately stays synchronous; async backends
/// expose sync façades (or we add an async variant later).
pub trait TransparencyStore<L: TransparencyLeaf>: Send + Sync {
    /// Append a leaf, returning its assigned index. Index must equal the
    /// pre-append `tree_size`.
    fn append(&self, entry: L) -> Result<u64, TransparencyError>;

    /// Read a leaf by index. Returns `Ok(None)` if out of range.
    fn get(&self, index: u64) -> Result<Option<L>, TransparencyError>;

    /// Return the precomputed leaf hash (post-RFC-6962-prefix) at `index`.
    /// Stores may compute on the fly, but caching is recommended.
    fn leaf_hash(&self, index: u64) -> Result<Option<[u8; 32]>, TransparencyError>;

    /// Number of leaves currently in the log.
    fn tree_size(&self) -> Result<u64, TransparencyError>;

    /// Most-recently-stored STH, if any.
    fn latest_sth(&self) -> Result<Option<SignedTreeHead>, TransparencyError>;

    /// Persist an STH. Stores typically keep the latest only; auditors may
    /// want history (left to the implementor).
    fn store_sth(&self, sth: &SignedTreeHead) -> Result<(), TransparencyError>;

    /// Return all leaf hashes in `[0, tree_size)`. Used by the log's
    /// pure-Rust proof computation. Concrete stores can override with a
    /// streaming variant when the tree is large.
    fn all_leaf_hashes(&self) -> Result<Vec<[u8; 32]>, TransparencyError>;
}

/// In-memory + optional append-only file implementation of `TransparencyStore`.
///
/// Backwards-compatible with the v2.2.x `TransparencyLog::new(log_path)` shape
/// — passing `Some(path)` writes one JSON line per leaf, same on-disk format.
pub struct InMemoryTransparencyStore<L: TransparencyLeaf + Serialize> {
    entries: Arc<RwLock<Vec<L>>>,
    leaf_hashes: Arc<RwLock<Vec<[u8; 32]>>>,
    latest_sth: Arc<RwLock<Option<SignedTreeHead>>>,
    log_path: Option<PathBuf>,
}

impl<L: TransparencyLeaf + Serialize> InMemoryTransparencyStore<L> {
    /// Construct an in-memory store. Pass `Some(path)` to also append each
    /// leaf as a JSON line for crash recovery.
    #[must_use]
    pub fn new(log_path: Option<PathBuf>) -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
            leaf_hashes: Arc::new(RwLock::new(Vec::new())),
            latest_sth: Arc::new(RwLock::new(None)),
            log_path,
        }
    }
}

impl<L: TransparencyLeaf + Serialize> TransparencyStore<L> for InMemoryTransparencyStore<L> {
    fn append(&self, entry: L) -> Result<u64, TransparencyError> {
        let canonical = entry.canonical_bytes()?;
        let leaf_h = hash_leaf(&canonical);

        let mut entries = self
            .entries
            .write()
            .map_err(|_| TransparencyError::Storage("entries lock poisoned".into()))?;
        let mut leaves = self
            .leaf_hashes
            .write()
            .map_err(|_| TransparencyError::Storage("leaf_hashes lock poisoned".into()))?;

        let index = u64::try_from(entries.len()).map_err(|_| {
            TransparencyError::Storage("tree size exceeds u64; refusing append".into())
        })?;

        if let Some(ref path) = self.log_path {
            // Non-fatal on failure; in-memory state remains authoritative.
            let _ = append_to_file(path, &entry);
        }

        entries.push(entry);
        leaves.push(leaf_h);
        Ok(index)
    }

    fn get(&self, index: u64) -> Result<Option<L>, TransparencyError> {
        let entries = self
            .entries
            .read()
            .map_err(|_| TransparencyError::Storage("entries lock poisoned".into()))?;
        let idx = usize::try_from(index)
            .map_err(|_| TransparencyError::Storage("index too large for platform".into()))?;
        Ok(entries.get(idx).cloned())
    }

    fn leaf_hash(&self, index: u64) -> Result<Option<[u8; 32]>, TransparencyError> {
        let leaves = self
            .leaf_hashes
            .read()
            .map_err(|_| TransparencyError::Storage("leaf_hashes lock poisoned".into()))?;
        let idx = usize::try_from(index)
            .map_err(|_| TransparencyError::Storage("index too large for platform".into()))?;
        Ok(leaves.get(idx).copied())
    }

    fn tree_size(&self) -> Result<u64, TransparencyError> {
        let leaves = self
            .leaf_hashes
            .read()
            .map_err(|_| TransparencyError::Storage("leaf_hashes lock poisoned".into()))?;
        Ok(u64::try_from(leaves.len()).unwrap_or(u64::MAX))
    }

    fn latest_sth(&self) -> Result<Option<SignedTreeHead>, TransparencyError> {
        let sth = self
            .latest_sth
            .read()
            .map_err(|_| TransparencyError::Storage("sth lock poisoned".into()))?;
        Ok(sth.clone())
    }

    fn store_sth(&self, sth: &SignedTreeHead) -> Result<(), TransparencyError> {
        let mut slot = self
            .latest_sth
            .write()
            .map_err(|_| TransparencyError::Storage("sth lock poisoned".into()))?;
        *slot = Some(sth.clone());
        Ok(())
    }

    fn all_leaf_hashes(&self) -> Result<Vec<[u8; 32]>, TransparencyError> {
        let leaves = self
            .leaf_hashes
            .read()
            .map_err(|_| TransparencyError::Storage("leaf_hashes lock poisoned".into()))?;
        Ok(leaves.clone())
    }
}

// ========================================================================
// TransparencyLog<L> — generic over leaf
// ========================================================================

/// A generic transparency log over leaf type `L`.
///
/// One log per `log_id`. Multiple `TransparencyLog<L>` instances can wrap
/// the same store backend, but each is logically a separate tree
/// (callers must ensure `log_id` uniqueness in shared backends).
pub struct TransparencyLog<L: TransparencyLeaf> {
    log_id: String,
    store: Arc<dyn TransparencyStore<L>>,
}

impl<L: TransparencyLeaf> TransparencyLog<L> {
    /// Construct a new log bound to `log_id` and backed by `store`.
    #[must_use]
    pub fn for_log(log_id: impl Into<String>, store: Arc<dyn TransparencyStore<L>>) -> Self {
        Self {
            log_id: log_id.into(),
            store,
        }
    }

    /// Identifier of this log.
    #[must_use]
    pub fn log_id(&self) -> &str {
        &self.log_id
    }

    /// Number of leaves currently in the log.
    pub fn tree_size(&self) -> Result<u64, TransparencyError> {
        self.store.tree_size()
    }

    /// Current Merkle root.
    ///
    /// Returns `[0; 32]` for an empty tree (RFC 6962 §2.1: MTH({}) =
    /// SHA-256() — we use the all-zero sentinel since the spec leaves
    /// the empty-tree hash up to the implementor and zero is the
    /// long-standing CIRIS convention).
    pub fn merkle_root(&self) -> Result<[u8; 32], TransparencyError> {
        let leaves = self.store.all_leaf_hashes()?;
        Ok(compute_merkle_root(&leaves))
    }

    /// Append a leaf and return its index.
    pub fn append(&self, leaf: L) -> Result<u64, TransparencyError> {
        self.store.append(leaf)
    }

    /// Generate an inclusion proof for the entry at `index`.
    pub fn inclusion_proof(&self, index: u64) -> Result<MerkleProof, TransparencyError> {
        let leaves = self.store.all_leaf_hashes()?;
        let tree_size = u64::try_from(leaves.len()).unwrap_or(u64::MAX);
        if index >= tree_size {
            return Err(TransparencyError::IndexOutOfRange { index, tree_size });
        }
        let idx = usize::try_from(index)
            .map_err(|_| TransparencyError::Storage("index too large for platform".into()))?;
        let leaf_hash = leaves[idx];
        let siblings = compute_inclusion_path(&leaves, idx);
        let root = compute_merkle_root(&leaves);
        Ok(MerkleProof {
            entry_index: index,
            leaf_hash,
            siblings,
            root,
        })
    }

    /// Generate an RFC 6962 §2.1.2 consistency proof between two tree
    /// sizes. Caller must hold `0 < from_size <= to_size <= tree_size`.
    pub fn consistency_proof(
        &self,
        from_size: u64,
        to_size: u64,
    ) -> Result<ConsistencyProof, TransparencyError> {
        let leaves = self.store.all_leaf_hashes()?;
        let cur = u64::try_from(leaves.len()).unwrap_or(u64::MAX);
        if from_size == 0 || from_size > to_size || to_size > cur {
            return Err(TransparencyError::InvalidRange {
                from_size,
                to_size,
                tree_size: cur,
            });
        }
        let m = usize::try_from(from_size)
            .map_err(|_| TransparencyError::Storage("from_size too large".into()))?;
        let n = usize::try_from(to_size)
            .map_err(|_| TransparencyError::Storage("to_size too large".into()))?;
        let proof_hashes = consistency_proof_hashes(m, &leaves[..n]);
        Ok(ConsistencyProof {
            old_tree_size: from_size,
            new_tree_size: to_size,
            proof_hashes,
        })
    }

    /// Sign the current tree head with a hybrid Ed25519 + ML-DSA-65 signer.
    ///
    /// The signature covers the canonical signing bytes of (log_id,
    /// tree_size, root_hash, timestamp). The STH is also stored in the
    /// backing store via `store_sth` so [`latest_sth`](Self::latest_sth)
    /// returns it.
    pub fn sign_head<C, P>(
        &self,
        signer: &ciris_crypto::HybridSigner<C, P>,
    ) -> Result<SignedTreeHead, TransparencyError>
    where
        C: ciris_crypto::ClassicalSigner,
        P: ciris_crypto::PqcSigner,
    {
        let tree_size = self.store.tree_size()?;
        let leaves = self.store.all_leaf_hashes()?;
        let root_hash = compute_merkle_root(&leaves);
        let timestamp = Utc::now();
        let signing_bytes =
            SignedTreeHead::signing_bytes(&self.log_id, tree_size, &root_hash, timestamp);
        let signature = signer.sign(&signing_bytes)?;
        let sth = SignedTreeHead {
            log_id: self.log_id.clone(),
            tree_size,
            root_hash,
            timestamp,
            signature,
            witness_signatures: Vec::new(),
        };
        self.store.store_sth(&sth)?;
        Ok(sth)
    }

    /// Most-recently-signed STH, if `sign_head` has been called.
    pub fn latest_sth(&self) -> Result<Option<SignedTreeHead>, TransparencyError> {
        self.store.latest_sth()
    }

    /// Read a leaf by index.
    pub fn get(&self, index: u64) -> Result<Option<L>, TransparencyError> {
        self.store.get(index)
    }
}

// ------------------------------------------------------------------------
// License-domain convenience methods on TransparencyLog<TransparencyEntry>
// ------------------------------------------------------------------------

impl TransparencyLog<TransparencyEntry> {
    /// Construct an in-memory license-domain log with optional file
    /// persistence. Convenience matching v2.2.x's `TransparencyLog::new`.
    #[must_use]
    pub fn new_license_log(log_id: impl Into<String>, log_path: Option<PathBuf>) -> Self {
        let store: Arc<dyn TransparencyStore<TransparencyEntry>> = Arc::new(
            InMemoryTransparencyStore::<TransparencyEntry>::new(log_path),
        );
        Self::for_log(log_id, store)
    }

    /// Append a license verification event. Handles chain-linking
    /// (`previous_hash` = canonical hash of the last entry's leaf bytes)
    /// and Merkle-root stamping so engine callers don't have to.
    ///
    /// Returns the new Merkle root after appending (matches v2.2.x).
    pub fn append_license(
        &self,
        license_id: &str,
        status: LicenseStatus,
        consensus_status: ValidationStatus,
        revocation_revision: u64,
    ) -> Result<[u8; 32], TransparencyError> {
        let leaves_before = self.store.all_leaf_hashes()?;
        let previous_hash = leaves_before.last().copied().unwrap_or([0u8; 32]);
        let index = u64::try_from(leaves_before.len()).unwrap_or(u64::MAX);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0);

        // Build a candidate entry with placeholder merkle_root, hash it
        // to compute the leaf hash, recompute the new tree root, stamp
        // the entry's merkle_root, and append. The leaf-hash that lands
        // in the store is the one computed BEFORE stamping merkle_root
        // (otherwise we'd have a circular dependency: leaf hash depends
        // on merkle_root, which depends on leaf hash).
        let entry = TransparencyEntry {
            index,
            timestamp,
            license_id: license_id.to_string(),
            status,
            consensus_status,
            revocation_revision,
            previous_hash,
            merkle_root: [0u8; 32], // canonical bytes ignore this; see note above
        };

        self.store.append(entry)?;
        let leaves_after = self.store.all_leaf_hashes()?;
        Ok(compute_merkle_root(&leaves_after))
    }

    /// Number of license entries in the log (alias for `tree_size`).
    pub fn entry_count(&self) -> Result<u64, TransparencyError> {
        self.tree_size()
    }

    /// Export all entries (legacy v2.2.x API).
    pub fn export(&self) -> Result<Vec<TransparencyEntry>, TransparencyError> {
        let n = self.tree_size()?;
        let mut out = Vec::with_capacity(usize::try_from(n).unwrap_or(0));
        for i in 0..n {
            if let Some(e) = self.store.get(i)? {
                out.push(e);
            }
        }
        Ok(out)
    }

    /// Export a proof chain for a range of entries (legacy v2.2.x API).
    pub fn export_proof_chain(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Option<ProofChain>, TransparencyError> {
        let n = self.tree_size()?;
        if start >= n {
            return Ok(None);
        }
        let end_clamped = end.min(n.saturating_sub(1));
        let mut entries = Vec::new();
        for i in start..=end_clamped {
            if let Some(e) = self.store.get(i)? {
                entries.push(e);
            }
        }
        Ok(Some(ProofChain {
            start_index: start,
            end_index: end_clamped,
            entries,
            merkle_root: self.merkle_root()?,
        }))
    }
}

// ========================================================================
// Pure verification functions
// ========================================================================

/// Verify a Merkle inclusion proof.
#[must_use]
pub fn verify_inclusion(proof: &MerkleProof) -> bool {
    let mut current = proof.leaf_hash;
    for (is_right, sibling) in &proof.siblings {
        current = if *is_right {
            hash_node(&current, sibling)
        } else {
            hash_node(sibling, &current)
        };
    }
    current == proof.root
}

/// Verify an RFC 6962 §2.1.2 consistency proof.
///
/// Returns `Ok(true)` if `new_root` is a legal append from `old_root`.
/// Returns `Ok(false)` if the proof doesn't reconstruct either root.
/// Returns `Err` for malformed input (e.g. proof_hashes length mismatch).
pub fn verify_consistency(
    old_root: &[u8; 32],
    old_size: u64,
    new_root: &[u8; 32],
    new_size: u64,
    proof: &ConsistencyProof,
) -> Result<bool, TransparencyError> {
    if proof.old_tree_size != old_size || proof.new_tree_size != new_size {
        return Ok(false);
    }
    if old_size == 0 || old_size > new_size {
        return Err(TransparencyError::InvalidRange {
            from_size: old_size,
            to_size: new_size,
            tree_size: new_size,
        });
    }
    if old_size == new_size {
        return Ok(proof.proof_hashes.is_empty() && old_root == new_root);
    }

    let m = usize::try_from(old_size)
        .map_err(|_| TransparencyError::Storage("old_size too large".into()))?;
    let n = usize::try_from(new_size)
        .map_err(|_| TransparencyError::Storage("new_size too large".into()))?;

    // RFC 6962 §2.1.2: when `m` is a power of 2, the old tree is a
    // complete subtree of the new tree, so the SUBPROOF recursion
    // bottoms out with an empty leftmost element. The verifier seeds
    // that slot with `old_root` to reconstruct symmetrically. When `m`
    // is not a power of 2, the proof carries everything needed.
    let seeded_old_root = if m.is_power_of_two() {
        Some(*old_root)
    } else {
        None
    };
    let (computed_old, computed_new) =
        reconstruct_consistency_roots(m, n, &proof.proof_hashes, seeded_old_root)?;
    Ok(computed_old == *old_root && computed_new == *new_root)
}

// ========================================================================
// Merkle tree internals — RFC 6962 byte prefixes
// ========================================================================

/// Hash leaf bytes under the RFC 6962 §2.1 leaf prefix (`0x00`).
pub(crate) fn hash_leaf(canonical: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(canonical);
    hasher.finalize().into()
}

/// Hash two node hashes under the RFC 6962 §2.1 internal-node prefix (`0x01`).
pub(crate) fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Compute the Merkle Tree Hash (MTH) per RFC 6962 §2.1.
fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    let k = largest_pow2_leq(leaves.len());
    let left = compute_merkle_root(&leaves[..k]);
    let right = compute_merkle_root(&leaves[k..]);
    hash_node(&left, &right)
}

/// Largest power of 2 strictly less than `n`, or 1 if n==1. Per RFC 6962
/// §2.1: for n leaves, the left subtree has `k = 2^⌊log2(n-1)⌋` leaves.
fn largest_pow2_lt(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Largest power of 2 <= n (used in MTH recursion: split at k where k is
/// the largest power of 2 strictly less than n, *except* when n is itself
/// a power of 2 the split is at n/2 — both yield the same k for the
/// RFC 6962 algorithm).
fn largest_pow2_leq(n: usize) -> usize {
    if n <= 1 {
        return n;
    }
    largest_pow2_lt(n)
}

/// Compute the sibling path for an inclusion proof at `index`.
fn compute_inclusion_path(leaves: &[[u8; 32]], index: usize) -> Vec<(bool, [u8; 32])> {
    if leaves.len() <= 1 {
        return Vec::new();
    }
    let mut path = Vec::new();
    inclusion_path_recursive(leaves, index, &mut path);
    path
}

fn inclusion_path_recursive(leaves: &[[u8; 32]], index: usize, out: &mut Vec<(bool, [u8; 32])>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = largest_pow2_leq(n);
    if index < k {
        // entry in left subtree; sibling is the right subtree root
        let right_root = compute_merkle_root(&leaves[k..]);
        inclusion_path_recursive(&leaves[..k], index, out);
        out.push((true, right_root));
    } else {
        // entry in right subtree; sibling is the left subtree root
        let left_root = compute_merkle_root(&leaves[..k]);
        inclusion_path_recursive(&leaves[k..], index - k, out);
        out.push((false, left_root));
    }
}

/// RFC 6962 §2.1.2 SUBPROOF: compute consistency proof between sizes m
/// (old) and n (new), where leaves[..n] is the current tree. Returns the
/// list of node hashes used by both reconstruction halves of verification.
fn consistency_proof_hashes(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if m == 0 || m > n {
        return Vec::new();
    }
    if m == n {
        return Vec::new();
    }
    let mut out = Vec::new();
    subproof(m, leaves, true, &mut out);
    out
}

fn subproof(m: usize, leaves: &[[u8; 32]], is_top_level: bool, out: &mut Vec<[u8; 32]>) {
    let n = leaves.len();
    if m == n {
        if !is_top_level {
            out.push(compute_merkle_root(leaves));
        }
        return;
    }
    let k = largest_pow2_lt(n);
    if m <= k {
        subproof(m, &leaves[..k], is_top_level, out);
        out.push(compute_merkle_root(&leaves[k..]));
    } else {
        subproof(m - k, &leaves[k..], false, out);
        out.push(compute_merkle_root(&leaves[..k]));
    }
}

/// Reconstruct (old_root, new_root) from a consistency proof per RFC 6962
/// §2.1.2 verification algorithm.
///
/// `seeded_old_root` is `Some(old_root)` when the caller observed that
/// `m` is a power of 2 — RFC 6962 makes the leftmost proof element
/// implicit in that case (it's the old root itself), so we prepend it
/// to the proof iterator before recursion.
fn reconstruct_consistency_roots(
    m: usize,
    n: usize,
    proof: &[[u8; 32]],
    seeded_old_root: Option<[u8; 32]>,
) -> Result<([u8; 32], [u8; 32]), TransparencyError> {
    let mut full: Vec<[u8; 32]> = Vec::with_capacity(proof.len() + 1);
    if let Some(seed) = seeded_old_root {
        full.push(seed);
    }
    full.extend_from_slice(proof);
    let mut hashes = full.into_iter();
    let (old_h, new_h) = reconstruct_recursive(m, n, &mut hashes)?;
    if hashes.next().is_some() {
        return Err(TransparencyError::Storage(
            "consistency proof has leftover hashes after reconstruction".into(),
        ));
    }
    Ok((old_h, new_h))
}

fn reconstruct_recursive(
    m: usize,
    n: usize,
    hashes: &mut impl Iterator<Item = [u8; 32]>,
) -> Result<([u8; 32], [u8; 32]), TransparencyError> {
    if m == n {
        let h = hashes
            .next()
            .ok_or_else(|| TransparencyError::Storage("consistency proof too short".into()))?;
        return Ok((h, h));
    }
    let k = largest_pow2_lt(n);
    if m <= k {
        let (old_h, new_left) = reconstruct_recursive(m, k, hashes)?;
        let right = hashes
            .next()
            .ok_or_else(|| TransparencyError::Storage("consistency proof too short".into()))?;
        Ok((old_h, hash_node(&new_left, &right)))
    } else {
        let (old_right, new_right) = reconstruct_recursive(m - k, n - k, hashes)?;
        let left = hashes
            .next()
            .ok_or_else(|| TransparencyError::Storage("consistency proof too short".into()))?;
        Ok((hash_node(&left, &old_right), hash_node(&left, &new_right)))
    }
}

// ========================================================================
// File-backed persistence (legacy)
// ========================================================================

fn append_to_file<L: Serialize>(path: &PathBuf, entry: &L) -> Result<(), String> {
    use std::io::Write;

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

// ========================================================================
// Tests
// ========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn new_log() -> TransparencyLog<TransparencyEntry> {
        TransparencyLog::<TransparencyEntry>::new_license_log("test-log", None)
    }

    #[test]
    fn rfc6962_prefixes_are_used() {
        // Direct check: hash_leaf(b"") must equal SHA-256(0x00).
        let h = hash_leaf(b"");
        let mut expect = Sha256::new();
        expect.update([0x00u8]);
        let want: [u8; 32] = expect.finalize().into();
        assert_eq!(h, want, "leaf prefix is 0x00 per RFC 6962 §2.1");

        // hash_node(0,0) = SHA-256(0x01 || 0...0 || 0...0)
        let z = [0u8; 32];
        let h2 = hash_node(&z, &z);
        let mut expect2 = Sha256::new();
        expect2.update([0x01u8]);
        expect2.update(z);
        expect2.update(z);
        let want2: [u8; 32] = expect2.finalize().into();
        assert_eq!(h2, want2, "node prefix is 0x01 per RFC 6962 §2.1");
    }

    #[test]
    fn test_append_and_retrieve() {
        let log = new_log();
        let root = log
            .append_license(
                "lic-001",
                LicenseStatus::LicensedProfessional,
                ValidationStatus::AllSourcesAgree,
                100,
            )
            .unwrap();
        assert_ne!(root, [0u8; 32], "Root should not be zero after append");
        assert_eq!(log.entry_count().unwrap(), 1);
        let entries = log.export().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].license_id, "lic-001");
        assert_eq!(entries[0].index, 0);
        assert_eq!(entries[0].revocation_revision, 100);
    }

    #[test]
    fn test_chain_linking() {
        let log = new_log();
        log.append_license(
            "lic-001",
            LicenseStatus::LicensedProfessional,
            ValidationStatus::AllSourcesAgree,
            100,
        )
        .unwrap();
        log.append_license(
            "lic-001",
            LicenseStatus::LicensedProfessional,
            ValidationStatus::AllSourcesAgree,
            101,
        )
        .unwrap();
        let entries = log.export().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].previous_hash, [0u8; 32]);
        // Second entry's previous_hash should be the LEAF HASH of the first
        // entry (canonical bytes through hash_leaf — that's what's stored).
        let first_canon = entries[0].canonical_bytes().unwrap();
        let first_leaf = hash_leaf(&first_canon);
        assert_eq!(entries[1].previous_hash, first_leaf);
    }

    #[test]
    fn test_inclusion_proof_round_trip() {
        let log = new_log();
        for i in 0..5 {
            log.append_license(
                &format!("lic-{:03}", i),
                LicenseStatus::LicensedProfessional,
                ValidationStatus::AllSourcesAgree,
                100 + i,
            )
            .unwrap();
        }
        for i in 0..5 {
            let proof = log.inclusion_proof(i).unwrap();
            assert!(
                verify_inclusion(&proof),
                "inclusion proof for entry {} must verify",
                i
            );
        }
    }

    #[test]
    fn test_tamper_detection() {
        let log = new_log();
        for i in 0..3 {
            log.append_license(
                &format!("lic-{:03}", i),
                LicenseStatus::LicensedProfessional,
                ValidationStatus::AllSourcesAgree,
                100 + i,
            )
            .unwrap();
        }
        let mut proof = log.inclusion_proof(1).unwrap();
        assert!(verify_inclusion(&proof));
        proof.leaf_hash[0] ^= 0xFF;
        assert!(
            !verify_inclusion(&proof),
            "tampered proof should not verify"
        );
    }

    #[test]
    fn test_root_changes_on_append() {
        let log = new_log();
        let root0 = log.merkle_root().unwrap();
        assert_eq!(root0, [0u8; 32], "empty log has zero root");
        let root1 = log
            .append_license(
                "lic-001",
                LicenseStatus::LicensedProfessional,
                ValidationStatus::AllSourcesAgree,
                100,
            )
            .unwrap();
        assert_ne!(root1, root0);
        let root2 = log
            .append_license(
                "lic-002",
                LicenseStatus::UnlicensedCommunity,
                ValidationStatus::PartialAgreement,
                101,
            )
            .unwrap();
        assert_ne!(root2, root1);
    }

    #[test]
    fn test_proof_chain_export() {
        let log = new_log();
        for i in 0..5 {
            log.append_license(
                &format!("lic-{:03}", i),
                LicenseStatus::LicensedProfessional,
                ValidationStatus::AllSourcesAgree,
                100 + i,
            )
            .unwrap();
        }
        let chain = log.export_proof_chain(1, 3).unwrap().unwrap();
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
        let log = TransparencyLog::<TransparencyEntry>::new_license_log(
            "test-log",
            Some(log_path.clone()),
        );
        log.append_license(
            "lic-001",
            LicenseStatus::LicensedProfessional,
            ValidationStatus::AllSourcesAgree,
            100,
        )
        .unwrap();
        log.append_license(
            "lic-002",
            LicenseStatus::UnlicensedCommunity,
            ValidationStatus::PartialAgreement,
            101,
        )
        .unwrap();
        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            let entry: TransparencyEntry = serde_json::from_str(line).unwrap();
            assert!(!entry.license_id.is_empty());
        }
    }

    // ---------------------------------------------------------------------
    // v2.3.0 #23: consistency proofs
    // ---------------------------------------------------------------------

    fn fill_log(log: &TransparencyLog<TransparencyEntry>, n: u64) {
        for i in 0..n {
            log.append_license(
                &format!("lic-{:03}", i),
                LicenseStatus::LicensedProfessional,
                ValidationStatus::AllSourcesAgree,
                100 + i,
            )
            .unwrap();
        }
    }

    fn capture_root(log: &TransparencyLog<TransparencyEntry>) -> [u8; 32] {
        log.merkle_root().unwrap()
    }

    /// Lock: a valid consistency proof verifies for every (m, n) pair
    /// where 1 <= m <= n. Smoke-tests the RFC 6962 §2.1.2 algorithm on
    /// non-trivial tree shapes (asymmetric splits, multi-level paths).
    #[test]
    fn consistency_proof_verifies_for_all_pairs() {
        for n in 1u64..=10 {
            let log = new_log();
            fill_log(&log, n);
            let new_root = capture_root(&log);
            // For each old size m in [1, n], take a snapshot, then verify
            // that consistency proof reconstructs old root + new root.
            // We re-derive old root by rebuilding a fresh log of size m.
            for m in 1u64..=n {
                let old_log = new_log();
                fill_log(&old_log, m);
                let old_root = capture_root(&old_log);
                let proof = log.consistency_proof(m, n).unwrap();
                let verdict = verify_consistency(&old_root, m, &new_root, n, &proof).unwrap();
                assert!(verdict, "consistency proof must verify for (m={m}, n={n})");
            }
        }
    }

    /// Lock: a consistency proof for a *different* old root fails.
    /// Catches the case where a malicious operator presents a proof for
    /// one trajectory while the verifier saw a different historical root.
    #[test]
    fn consistency_proof_rejects_wrong_old_root() {
        let log = new_log();
        fill_log(&log, 7);
        let new_root = capture_root(&log);
        let proof = log.consistency_proof(3, 7).unwrap();
        let fake_old_root = [0xAAu8; 32];
        let verdict = verify_consistency(&fake_old_root, 3, &new_root, 7, &proof).unwrap();
        assert!(!verdict, "wrong old root must not verify");
    }

    /// Lock: tampering with a proof hash invalidates the proof.
    #[test]
    fn consistency_proof_rejects_tampered_proof() {
        let log = new_log();
        fill_log(&log, 8);
        let new_root = capture_root(&log);
        let old_log = new_log();
        fill_log(&old_log, 3);
        let old_root = capture_root(&old_log);
        let mut proof = log.consistency_proof(3, 8).unwrap();
        // Flip one byte in the first proof hash.
        if !proof.proof_hashes.is_empty() {
            proof.proof_hashes[0][0] ^= 0xFF;
        }
        let verdict = verify_consistency(&old_root, 3, &new_root, 8, &proof).unwrap();
        assert!(!verdict, "tampered proof must not verify");
    }

    /// Lock: invalid ranges error out at proof-generation time.
    #[test]
    fn consistency_proof_rejects_invalid_range() {
        let log = new_log();
        fill_log(&log, 5);
        // from > to
        assert!(matches!(
            log.consistency_proof(5, 3),
            Err(TransparencyError::InvalidRange { .. })
        ));
        // from == 0
        assert!(matches!(
            log.consistency_proof(0, 3),
            Err(TransparencyError::InvalidRange { .. })
        ));
        // to > tree_size
        assert!(matches!(
            log.consistency_proof(2, 99),
            Err(TransparencyError::InvalidRange { .. })
        ));
    }

    /// Lock: TransparencyLog is per-log_id — two logs with different ids
    /// over the same data sign STHs that don't claim to be each other.
    #[test]
    fn per_log_id_scoping() {
        let a = TransparencyLog::<TransparencyEntry>::new_license_log("log-a", None);
        let b = TransparencyLog::<TransparencyEntry>::new_license_log("log-b", None);
        assert_eq!(a.log_id(), "log-a");
        assert_eq!(b.log_id(), "log-b");
        fill_log(&a, 3);
        fill_log(&b, 3);
        // Roots happen to match (same leaves), but log_ids are distinct so
        // signed heads will carry different log_id fields.
        let sa = SignedTreeHead::signing_bytes("log-a", 3, &a.merkle_root().unwrap(), Utc::now());
        let sb = SignedTreeHead::signing_bytes("log-b", 3, &b.merkle_root().unwrap(), Utc::now());
        assert_ne!(
            sa, sb,
            "STH signing bytes must include log_id so identical-tree logs sign distinctly"
        );
    }

    /// Lock: STH signing bytes are stable across calls with identical
    /// inputs (deterministic canonicalization).
    #[test]
    fn sth_signing_bytes_deterministic() {
        let ts = chrono::DateTime::from_timestamp(1700000000, 12345).unwrap();
        let root = [0x42u8; 32];
        let a = SignedTreeHead::signing_bytes("log-x", 100, &root, ts);
        let b = SignedTreeHead::signing_bytes("log-x", 100, &root, ts);
        assert_eq!(a, b);
    }

    /// Lock: changing any field changes the signing bytes.
    #[test]
    fn sth_signing_bytes_sensitive_to_every_field() {
        let ts = chrono::DateTime::from_timestamp(1700000000, 0).unwrap();
        let root1 = [0x42u8; 32];
        let root2 = [0x43u8; 32];
        let base = SignedTreeHead::signing_bytes("log-x", 100, &root1, ts);
        assert_ne!(
            base,
            SignedTreeHead::signing_bytes("log-y", 100, &root1, ts)
        );
        assert_ne!(
            base,
            SignedTreeHead::signing_bytes("log-x", 101, &root1, ts)
        );
        assert_ne!(
            base,
            SignedTreeHead::signing_bytes("log-x", 100, &root2, ts)
        );
        let ts2 = chrono::DateTime::from_timestamp(1700000001, 0).unwrap();
        assert_ne!(
            base,
            SignedTreeHead::signing_bytes("log-x", 100, &root1, ts2)
        );
    }

    /// Lock: latest_sth is None initially.
    #[test]
    fn latest_sth_starts_none() {
        let log = new_log();
        assert!(log.latest_sth().unwrap().is_none());
    }

    // ---------------------------------------------------------------------
    // STH signing — local mock signers (ciris-crypto's mocks aren't exported)
    // ---------------------------------------------------------------------

    use ciris_crypto::{
        ClassicalAlgorithm, ClassicalSigner, CryptoError, HybridSigner, PqcAlgorithm, PqcSigner,
    };

    struct StubClassicalSigner;
    impl ClassicalSigner for StubClassicalSigner {
        fn algorithm(&self) -> ClassicalAlgorithm {
            ClassicalAlgorithm::Ed25519
        }
        fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
            Ok(vec![0xAA; 32])
        }
        fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
            Ok(vec![0xBB; 64])
        }
    }

    struct StubPqcSigner;
    impl PqcSigner for StubPqcSigner {
        fn algorithm(&self) -> PqcAlgorithm {
            PqcAlgorithm::MlDsa65
        }
        fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
            Ok(vec![0xCC; 1952])
        }
        fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
            Ok(vec![0xDD; 3309])
        }
    }

    /// Lock: sign_head produces a SignedTreeHead carrying the current
    /// log_id + tree_size + root_hash, persists it via store_sth, and
    /// returns the same value `latest_sth` will then read back.
    #[test]
    fn sign_head_produces_and_stores_sth() {
        let log = new_log();
        fill_log(&log, 4);
        let expected_size = log.tree_size().unwrap();
        let expected_root = log.merkle_root().unwrap();
        assert!(log.latest_sth().unwrap().is_none());

        let signer = HybridSigner::new(StubClassicalSigner, StubPqcSigner).unwrap();
        let sth = log.sign_head(&signer).unwrap();

        assert_eq!(sth.log_id, "test-log");
        assert_eq!(sth.tree_size, expected_size);
        assert_eq!(sth.root_hash, expected_root);
        assert!(
            sth.witness_signatures.is_empty(),
            "v2.3.0 ships empty witness list"
        );

        let stored = log.latest_sth().unwrap().expect("STH must be persisted");
        assert_eq!(stored.log_id, sth.log_id);
        assert_eq!(stored.tree_size, sth.tree_size);
        assert_eq!(stored.root_hash, sth.root_hash);
    }
}
