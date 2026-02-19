//! Agent file integrity verification (Tripwire-style).
//!
//! Validates that the CIRISAgent's Python files have not been modified
//! since the distribution was built. CIRISRegistry stores SHA-256 hashes
//! of all files per version (starting with 2.0.0). CIRISVerify checks
//! files at runtime against a signed manifest.
//!
//! ## Rules
//!
//! - ANY file change triggers immediate forced shutdown
//! - Exceptions: `.env`, log files (`*.log`), audit files (`*.audit`)
//! - Supports full check (all files) and spot check (random subset)
//!
//! ## Manifest Format
//!
//! JSON file containing:
//! ```json
//! {
//!   "version": "2.0.0",
//!   "generated_at": "2026-02-17T00:00:00Z",
//!   "files": {
//!     "ciris_engine/__init__.py": "sha256hex...",
//!     "ciris_engine/main.py": "sha256hex..."
//!   },
//!   "manifest_hash": "sha256hex of sorted file hashes"
//! }
//! ```

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

/// Result of a file integrity check.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileIntegrityResult {
    /// Whether all checked files passed integrity verification.
    pub integrity_valid: bool,
    /// Total files in manifest.
    pub total_files: usize,
    /// Number of files checked (may be less than total for spot checks).
    pub files_checked: usize,
    /// Number of files that passed.
    pub files_passed: usize,
    /// Number of files that failed (hash mismatch).
    pub files_failed: usize,
    /// Number of files missing from disk.
    pub files_missing: usize,
    /// Number of unexpected files found (not in manifest, not exempt).
    pub files_unexpected: usize,
    /// Opaque failure reason (does not reveal which files failed).
    pub failure_reason: String,
}

/// Agent file manifest loaded from JSON.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileManifest {
    /// Agent version this manifest corresponds to.
    pub version: String,
    /// ISO 8601 timestamp when manifest was generated.
    pub generated_at: String,
    /// Map of relative file path → SHA-256 hex hash.
    pub files: BTreeMap<String, String>,
    /// SHA-256 of the sorted concatenation of all file hashes (integrity check of the manifest itself).
    pub manifest_hash: String,
}

/// File extensions and patterns exempt from integrity checking.
const EXEMPT_EXTENSIONS: &[&str] = &[
    ".env", ".log", ".audit", ".db", ".sqlite", ".sqlite3", ".pyc", ".pyo",
];

/// Directory names exempt from integrity checking.
const EXEMPT_DIRS: &[&str] = &[
    "__pycache__",
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "data",
    "logs",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    "*.egg-info",
];

/// Check if a file path is exempt from integrity checking.
fn is_exempt(relative_path: &str) -> bool {
    let path = Path::new(relative_path);

    // Check exempt extensions
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let dot_ext = format!(".{}", ext);
        if EXEMPT_EXTENSIONS.contains(&dot_ext.as_str()) {
            return true;
        }
    }

    // Check if filename itself is exempt (e.g., ".env")
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if EXEMPT_EXTENSIONS.contains(&name) {
            return true;
        }
    }

    // Check exempt directories
    for component in path.components() {
        if let std::path::Component::Normal(c) = component {
            if let Some(dir_name) = c.to_str() {
                for exempt in EXEMPT_DIRS {
                    if let Some(suffix) = exempt.strip_prefix('*') {
                        // Wildcard suffix match (e.g., "*.egg-info")
                        if dir_name.ends_with(suffix) {
                            return true;
                        }
                    } else if dir_name == *exempt {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Compute SHA-256 hash of a file, returning hex string.
fn hash_file(path: &Path) -> std::io::Result<String> {
    let data = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

/// Verify the manifest's own integrity (manifest_hash field).
fn verify_manifest_integrity(manifest: &FileManifest) -> bool {
    let mut hasher = Sha256::new();
    // Hash all file hashes in sorted order (BTreeMap is already sorted)
    for hash in manifest.files.values() {
        hasher.update(hash.as_bytes());
    }
    let expected = hex::encode(hasher.finalize());
    // Use constant-time comparison
    super::constant_time_eq(expected.as_bytes(), manifest.manifest_hash.as_bytes())
}

/// Load a manifest from a JSON file.
///
/// # Errors
///
/// Returns error if the file cannot be read or parsed.
pub fn load_manifest(manifest_path: &Path) -> Result<FileManifest, String> {
    let data = std::fs::read_to_string(manifest_path)
        .map_err(|e| format!("Cannot read manifest: {}", e))?;
    let manifest: FileManifest =
        serde_json::from_str(&data).map_err(|e| format!("Cannot parse manifest: {}", e))?;
    Ok(manifest)
}

/// Perform a FULL integrity check of all files in the manifest.
///
/// Checks every file in the manifest against its expected hash.
/// Also detects unexpected Python files not in the manifest.
///
/// Any failure = integrity_valid: false → agent must shut down.
pub fn check_full(manifest: &FileManifest, agent_root: &Path) -> FileIntegrityResult {
    // First, verify the manifest itself
    if !verify_manifest_integrity(manifest) {
        return FileIntegrityResult {
            integrity_valid: false,
            total_files: manifest.files.len(),
            files_checked: 0,
            files_passed: 0,
            files_failed: 0,
            files_missing: 0,
            files_unexpected: 0,
            failure_reason: "manifest".to_string(),
        };
    }

    let mut files_checked = 0usize;
    let mut files_passed = 0usize;
    let mut files_failed = 0usize;
    let mut files_missing = 0usize;

    // Check every file in the manifest
    for (relative_path, expected_hash) in &manifest.files {
        let full_path = agent_root.join(relative_path);
        files_checked += 1;

        match hash_file(&full_path) {
            Ok(actual_hash) => {
                if super::constant_time_eq(actual_hash.as_bytes(), expected_hash.as_bytes()) {
                    files_passed += 1;
                } else {
                    files_failed += 1;
                }
            },
            Err(_) => {
                files_missing += 1;
            },
        }
    }

    // Scan for unexpected Python files not in the manifest
    let files_unexpected = count_unexpected_files(agent_root, &manifest.files);

    let integrity_valid = files_failed == 0 && files_missing == 0 && files_unexpected == 0;

    let failure_reason = if integrity_valid {
        String::new()
    } else if files_failed > 0 {
        "modified".to_string()
    } else if files_missing > 0 {
        "missing".to_string()
    } else {
        "unexpected".to_string()
    };

    FileIntegrityResult {
        integrity_valid,
        total_files: manifest.files.len(),
        files_checked,
        files_passed,
        files_failed,
        files_missing,
        files_unexpected,
        failure_reason,
    }
}

/// Perform a SPOT CHECK of a random subset of files.
///
/// Checks `count` randomly selected files from the manifest.
/// More efficient for periodic runtime checks.
pub fn check_spot(manifest: &FileManifest, agent_root: &Path, count: usize) -> FileIntegrityResult {
    use rand::seq::SliceRandom;

    // Verify manifest integrity first
    if !verify_manifest_integrity(manifest) {
        return FileIntegrityResult {
            integrity_valid: false,
            total_files: manifest.files.len(),
            files_checked: 0,
            files_passed: 0,
            files_failed: 0,
            files_missing: 0,
            files_unexpected: 0,
            failure_reason: "manifest".to_string(),
        };
    }

    let file_list: Vec<(&String, &String)> = manifest.files.iter().collect();
    let check_count = count.min(file_list.len());

    let mut rng = rand::thread_rng();
    let selected: Vec<_> = file_list.choose_multiple(&mut rng, check_count).collect();

    let mut files_passed = 0usize;
    let mut files_failed = 0usize;
    let mut files_missing = 0usize;

    for (relative_path, expected_hash) in &selected {
        let full_path = agent_root.join(relative_path);

        match hash_file(&full_path) {
            Ok(actual_hash) => {
                if super::constant_time_eq(actual_hash.as_bytes(), expected_hash.as_bytes()) {
                    files_passed += 1;
                } else {
                    files_failed += 1;
                }
            },
            Err(_) => {
                files_missing += 1;
            },
        }
    }

    let integrity_valid = files_failed == 0 && files_missing == 0;

    let failure_reason = if integrity_valid {
        String::new()
    } else if files_failed > 0 {
        "modified".to_string()
    } else {
        "missing".to_string()
    };

    FileIntegrityResult {
        integrity_valid,
        total_files: manifest.files.len(),
        files_checked: check_count,
        files_passed,
        files_failed,
        files_missing,
        files_unexpected: 0, // Spot check doesn't scan for unexpected files
        failure_reason,
    }
}

/// Count Python files on disk that are NOT in the manifest and NOT exempt.
fn count_unexpected_files(agent_root: &Path, manifest_files: &BTreeMap<String, String>) -> usize {
    let mut unexpected = 0usize;
    walk_python_files(agent_root, agent_root, manifest_files, &mut unexpected);
    unexpected
}

/// Recursively walk directory for .py files not in manifest.
fn walk_python_files(
    root: &Path,
    dir: &Path,
    manifest_files: &BTreeMap<String, String>,
    unexpected: &mut usize,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();

        // Get relative path
        let relative = match path.strip_prefix(root) {
            Ok(r) => r.to_string_lossy().to_string(),
            Err(_) => continue,
        };

        // Skip exempt paths
        if is_exempt(&relative) {
            continue;
        }

        if path.is_dir() {
            walk_python_files(root, &path, manifest_files, unexpected);
        } else if path.is_file() {
            // Check .py files that aren't in manifest
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if ext == "py" && !manifest_files.contains_key(&relative) {
                    *unexpected += 1;
                }
            }
        }
    }
}

/// Generate a manifest for all Python files in a directory.
///
/// Used by the build/install process to create the baseline manifest.
pub fn generate_manifest(agent_root: &Path, version: &str) -> Result<FileManifest, String> {
    let mut files = BTreeMap::new();
    collect_files(agent_root, agent_root, &mut files)?;

    // Compute manifest hash
    let mut hasher = Sha256::new();
    for hash in files.values() {
        hasher.update(hash.as_bytes());
    }
    let manifest_hash = hex::encode(hasher.finalize());

    let generated_at = chrono::Utc::now().to_rfc3339();

    Ok(FileManifest {
        version: version.to_string(),
        generated_at,
        files,
        manifest_hash,
    })
}

/// Recursively collect all non-exempt files and their hashes.
fn collect_files(
    root: &Path,
    dir: &Path,
    files: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("Cannot read directory {:?}: {}", dir, e))?;

    for entry in entries.flatten() {
        let path = entry.path();

        let relative = match path.strip_prefix(root) {
            Ok(r) => r.to_string_lossy().to_string(),
            Err(_) => continue,
        };

        if is_exempt(&relative) {
            continue;
        }

        if path.is_dir() {
            collect_files(root, &path, files)?;
        } else if path.is_file() {
            let hash = hash_file(&path).map_err(|e| format!("Cannot hash {:?}: {}", path, e))?;
            files.insert(relative, hash);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn create_test_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();

        // Create some test Python files
        let engine_dir = dir.path().join("ciris_engine");
        fs::create_dir_all(&engine_dir).unwrap();
        fs::write(engine_dir.join("__init__.py"), b"# init").unwrap();
        fs::write(engine_dir.join("main.py"), b"# main entry").unwrap();
        fs::write(engine_dir.join("engine.py"), b"# engine code").unwrap();

        // Create exempt files
        fs::write(dir.path().join(".env"), b"SECRET=123").unwrap();
        let log_dir = dir.path().join("logs");
        fs::create_dir_all(&log_dir).unwrap();
        fs::write(log_dir.join("agent.log"), b"log data").unwrap();

        // Create __pycache__ (exempt)
        let cache_dir = engine_dir.join("__pycache__");
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(cache_dir.join("main.cpython-312.pyc"), b"bytecode").unwrap();

        dir
    }

    #[test]
    fn test_generate_manifest() {
        let dir = create_test_dir();
        let manifest = generate_manifest(dir.path(), "2.0.0").unwrap();

        assert_eq!(manifest.version, "2.0.0");
        // Should include Python files but not .env, logs, or __pycache__
        assert!(manifest.files.contains_key("ciris_engine/__init__.py"));
        assert!(manifest.files.contains_key("ciris_engine/main.py"));
        assert!(manifest.files.contains_key("ciris_engine/engine.py"));
        assert!(!manifest.files.contains_key(".env"));
        assert!(!manifest.files.contains_key("logs/agent.log"));

        // Manifest hash should be non-empty
        assert!(!manifest.manifest_hash.is_empty());
    }

    #[test]
    fn test_full_check_passes_unmodified() {
        let dir = create_test_dir();
        let manifest = generate_manifest(dir.path(), "2.0.0").unwrap();
        let result = check_full(&manifest, dir.path());

        assert!(result.integrity_valid);
        assert_eq!(result.files_failed, 0);
        assert_eq!(result.files_missing, 0);
        assert_eq!(result.files_unexpected, 0);
        assert_eq!(result.files_passed, result.files_checked);
    }

    #[test]
    fn test_full_check_detects_modification() {
        let dir = create_test_dir();
        let manifest = generate_manifest(dir.path(), "2.0.0").unwrap();

        // Modify a file
        fs::write(dir.path().join("ciris_engine/main.py"), b"# TAMPERED").unwrap();

        let result = check_full(&manifest, dir.path());

        assert!(!result.integrity_valid);
        assert!(result.files_failed > 0);
        assert_eq!(result.failure_reason, "modified");
    }

    #[test]
    fn test_full_check_detects_deletion() {
        let dir = create_test_dir();
        let manifest = generate_manifest(dir.path(), "2.0.0").unwrap();

        // Delete a file
        fs::remove_file(dir.path().join("ciris_engine/engine.py")).unwrap();

        let result = check_full(&manifest, dir.path());

        assert!(!result.integrity_valid);
        assert!(result.files_missing > 0);
        assert_eq!(result.failure_reason, "missing");
    }

    #[test]
    fn test_full_check_detects_unexpected_py_file() {
        let dir = create_test_dir();
        let manifest = generate_manifest(dir.path(), "2.0.0").unwrap();

        // Add an unexpected Python file
        fs::write(
            dir.path().join("ciris_engine/backdoor.py"),
            b"# malicious code",
        )
        .unwrap();

        let result = check_full(&manifest, dir.path());

        assert!(!result.integrity_valid);
        assert!(result.files_unexpected > 0);
        assert_eq!(result.failure_reason, "unexpected");
    }

    #[test]
    fn test_exempt_files_ignored() {
        let dir = create_test_dir();
        let manifest = generate_manifest(dir.path(), "2.0.0").unwrap();

        // Modify exempt files — should NOT affect integrity
        fs::write(dir.path().join(".env"), b"NEW_SECRET=456").unwrap();
        fs::write(dir.path().join("logs/agent.log"), b"new log data here").unwrap();

        let result = check_full(&manifest, dir.path());
        assert!(result.integrity_valid);
    }

    #[test]
    fn test_spot_check() {
        let dir = create_test_dir();
        let manifest = generate_manifest(dir.path(), "2.0.0").unwrap();

        // Spot check with 2 files
        let result = check_spot(&manifest, dir.path(), 2);

        assert!(result.integrity_valid);
        assert!(result.files_checked <= 2);
        assert_eq!(result.files_failed, 0);
    }

    #[test]
    fn test_manifest_tamper_detection() {
        let dir = create_test_dir();
        let mut manifest = generate_manifest(dir.path(), "2.0.0").unwrap();

        // Tamper with the manifest hash
        manifest.manifest_hash =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();

        let result = check_full(&manifest, dir.path());
        assert!(!result.integrity_valid);
        assert_eq!(result.failure_reason, "manifest");
    }

    #[test]
    fn test_is_exempt() {
        assert!(is_exempt(".env"));
        assert!(is_exempt("logs/agent.log"));
        assert!(is_exempt("data/ciris.db"));
        assert!(is_exempt("__pycache__/main.cpython-312.pyc"));
        assert!(is_exempt("ciris_engine/__pycache__/foo.pyc"));
        assert!(is_exempt("ciris_agent.egg-info/PKG-INFO"));

        assert!(!is_exempt("ciris_engine/main.py"));
        assert!(!is_exempt("ciris_engine/engine.py"));
        assert!(!is_exempt("requirements.txt"));
    }

    #[test]
    fn test_verify_manifest_integrity() {
        let dir = create_test_dir();
        let manifest = generate_manifest(dir.path(), "2.0.0").unwrap();
        assert!(verify_manifest_integrity(&manifest));
    }
}
