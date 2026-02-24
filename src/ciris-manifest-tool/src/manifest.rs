//! Function manifest generation.
//!
//! Creates signed manifests of function hashes for runtime verification.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::parser::{parse_binary, ParseError};

// Re-export types from ciris-verify-core
pub use ciris_verify_core::security::function_integrity::{
    FunctionEntry, FunctionManifest, ManifestMetadata, ManifestSignature,
};

/// Error during manifest generation.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("Binary parsing error: {0}")]
    ParseError(#[from] ParseError),

    #[error("No functions found matching filter")]
    NoFunctionsFound,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Generate a function manifest from a binary.
///
/// # Arguments
///
/// * `binary_path` - Path to the compiled binary
/// * `target` - Target triple (e.g., "x86_64-unknown-linux-gnu")
/// * `version` - Binary version string
/// * `filter_prefix` - Optional prefix to filter function names
///
/// # Returns
///
/// An unsigned function manifest (signature fields empty).
pub fn generate_manifest(
    binary_path: &Path,
    target: &str,
    version: &str,
    filter_prefix: Option<&str>,
) -> Result<FunctionManifest, ManifestError> {
    // Parse the binary
    let parsed = parse_binary(binary_path, filter_prefix)?;

    if parsed.functions.is_empty() {
        return Err(ManifestError::NoFunctionsFound);
    }

    // Compute binary hash
    let binary_hash = compute_file_hash(binary_path)?;

    // Generate function entries
    let mut functions = BTreeMap::new();

    for func in &parsed.functions {
        if let Some(bytes) = parsed.function_bytes(func) {
            let hash = compute_hash(bytes);
            functions.insert(
                func.name.clone(),
                FunctionEntry {
                    name: func.name.clone(),
                    offset: func.offset,
                    size: func.size,
                    hash,
                },
            );
        }
    }

    // Compute manifest hash from function hashes
    let manifest_hash = compute_manifest_hash(&functions);

    Ok(FunctionManifest {
        version: "1.0.0".to_string(),
        target: target.to_string(),
        binary_hash,
        binary_version: version.to_string(),
        generated_at: Utc::now().to_rfc3339(),
        functions,
        manifest_hash,
        signature: ManifestSignature {
            classical: String::new(),
            classical_algorithm: "Ed25519".to_string(),
            pqc: String::new(),
            pqc_algorithm: "ML-DSA-65".to_string(),
            key_id: String::new(),
        },
        metadata: ManifestMetadata {
            exec_segment_vaddr: parsed.exec_segment_vaddr,
            text_section_vaddr: parsed.code_section_vaddr,
            text_section_offset: parsed.code_section_offset,
        },
    })
}

/// Compute SHA-256 hash of data and return as hex string with prefix.
fn compute_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    format!("sha256:{}", hex::encode(hash))
}

/// Compute SHA-256 hash of a file.
fn compute_file_hash(path: &Path) -> Result<String, ManifestError> {
    let data = std::fs::read(path)?;
    Ok(compute_hash(&data))
}

/// Compute the manifest hash from function hashes.
fn compute_manifest_hash(functions: &BTreeMap<String, FunctionEntry>) -> String {
    let mut hasher = Sha256::new();

    // BTreeMap iteration is sorted by key
    for entry in functions.values() {
        hasher.update(entry.hash.as_bytes());
    }

    let hash = hasher.finalize();
    format!("sha256:{}", hex::encode(hash))
}

// NOTE: Signing is handled by the CI pipeline using the steward key.
// The manifest tool generates unsigned manifests; signing is a separate step.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hash() {
        let data = b"hello world";
        let hash = compute_hash(data);
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let mut functions = BTreeMap::new();
        functions.insert(
            "func_a".to_string(),
            FunctionEntry {
                name: "func_a".to_string(),
                offset: 0,
                size: 10,
                hash: "sha256:aaa".to_string(),
            },
        );
        functions.insert(
            "func_b".to_string(),
            FunctionEntry {
                name: "func_b".to_string(),
                offset: 10,
                size: 20,
                hash: "sha256:bbb".to_string(),
            },
        );

        let hash1 = compute_manifest_hash(&functions);
        let hash2 = compute_manifest_hash(&functions);
        assert_eq!(hash1, hash2);
    }
}
