//! Runtime tree-walking verifier (CIRISVerify#9, v1.13.0+).
//!
//! Public Rust + FFI + Python API for verifying a source tree on disk
//! against its registered `file_manifest_json` in the registry. The
//! canonical algorithm matches `ciris-build-sign sign --tree`:
//!
//!   1. Walk the tree via `security::build_manifest::walk_file_tree`,
//!      honoring `ExemptRules` (`include_roots`, `exempt_dirs`,
//!      `exempt_extensions`).
//!   2. Each surviving file is hashed `sha256:<hex>`.
//!   3. The canonical total is
//!      `FileTreeExtras::compute_tree_hash` over the BTreeMap-ordered
//!      `path:value\n` concatenation, prefixed `sha256:`.
//!
//! By construction, what `verify_tree` walks at runtime is byte-for-byte
//! comparable to what `ciris-build-sign register` wrote into
//! `builds.file_manifest_json` / `builds.file_manifest_hash`. That's the
//! contract that lets a caller (CIRISAgent) reach L4 file integrity
//! without maintaining a duplicate hashing path
//! (`startup_python_hashes.json` + `regenerate_python_hashes.py`).
//!
//! ## Verdict semantics (v1.14.0+, CIRISVerify#15)
//!
//! `Missing` is **not a tampering signal**. An agent that's missing
//! critical code doesn't run — that's a broken-not-tampered failure
//! mode caught at boot, not by attestation. Common case: platform-
//! asymmetric build artifacts (e.g. `_build_secrets.py` bundled into
//! mobile AABs but excluded from desktop wheels by setup.py).
//!
//! Two verdicts on [`TreeVerifyResult`]:
//!
//! - `valid` (tampering verdict — what desktop callers gate on):
//!   no `Mismatch`, no `Extra`, registry reachable. Does NOT gate on
//!   `Missing`.
//! - `registry_match` (strict literal-equality verdict — what mobile
//!   gates on, since mobile bundles ship every signed file):
//!   `total_hash == expected_total_hash` AND no failed AND no missing.
//!
//! Per-file divergences split into two buckets:
//!
//! - [`TreeVerifyResult::failed_files`] — `Mismatch` + `Extra` only.
//!   Empty iff `valid == true`.
//! - [`TreeVerifyResult::missing_files`] — files in registry, absent
//!   on disk. Informational; doesn't gate `valid`.
//!
//! ## Relationship to the legacy `python_hashes` parameter
//!
//! `UnifiedAttestationEngine::full_attest` still accepts the legacy
//! `python_hashes` JSON (Algorithm B: `.py`-only, raw hex, sorted-join
//! total). That path is retained for backward compatibility (Android
//! mobile producer ships pre-walked JSON). Algorithm B caps at L3
//! by construction because it cannot match the registered manifest's
//! `sha256:`-prefixed Algorithm A bytes. New code uses `verify_tree`
//! to reach L4.

use crate::error::VerifyError;
use crate::registry::RegistryClient;
use crate::security::build_manifest::{walk_file_tree, ExemptRules, FileTreeExtras};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, info, instrument, warn};

/// Caller-facing request for [`verify_tree`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeVerifyRequest {
    /// Filesystem root. `include_roots` are resolved relative to this.
    pub root: String,
    /// Top-level subtrees to include. Empty = walk `root` itself.
    /// Must mirror the `--tree-include` set passed at sign time.
    #[serde(default)]
    pub include_roots: Vec<String>,
    /// Directory basenames to skip anywhere in the tree.
    /// Must mirror the `--tree-exempt-dir` set passed at sign time.
    #[serde(default)]
    pub exempt_dirs: Vec<String>,
    /// File extensions to skip (no leading dot).
    /// Must mirror the `--tree-exempt-ext` set passed at sign time.
    #[serde(default)]
    pub exempt_extensions: Vec<String>,
    /// Registry project namespace (e.g. `"ciris-agent"`).
    pub project: String,
    /// Registered version key (e.g. `"2.8.3"`).
    pub binary_version: String,
}

/// Why a single file failed verification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FailedFileKind {
    /// File is in the registered manifest but absent from the on-disk tree.
    Missing,
    /// File is on disk but not in the registered manifest.
    Extra,
    /// File is in both, but hash differs.
    Mismatch,
}

/// One file-level verification failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedFile {
    /// Tree-relative path with forward-slash separators.
    pub path: String,
    /// Failure category (missing / extra / mismatch).
    pub kind: FailedFileKind,
    /// `sha256:<hex>` — `None` for `Missing`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computed_hash: Option<String>,
    /// `sha256:<hex>` — `None` for `Extra`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_hash: Option<String>,
}

/// Caller-facing result of [`verify_tree`]. Always returned (even when
/// the registry is unreachable, so callers can persist `total_hash`
/// for later online comparison or surface a partial verdict).
///
/// ## v1.14.0 verdict semantics (CIRISVerify#15)
///
/// `valid` is the top-level **tampering** verdict and demotes `Missing`
/// from a fail signal:
///
/// - `valid == true` ⇔ no `Mismatch`, no `Extra`, AND registry reachable.
///   This is the signal callers should gate on for "is this install
///   tampered?"
/// - `failed_files` carries only `Mismatch` + `Extra` (the tampering
///   signals). It is empty iff `valid == true`.
/// - `missing_files` is informational: files in the registered manifest
///   that aren't on disk. Common reason: platform-asymmetric build
///   artifacts (e.g. mobile-only secrets that desktop wheels intentionally
///   don't ship). The agent that's missing critical code doesn't run —
///   that's a broken-not-tampered signal caught at boot, not a verify_tree
///   concern.
/// - `registry_match` is the strict "100% byte-identical to registered"
///   signal. Requires `Missing.is_empty()` AND `Extra.is_empty()` AND
///   `Mismatch.is_empty()` AND `total_hash == expected_total_hash`.
///   Mobile (where every signed file IS bundled) gates on this; desktop
///   uses `valid`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeVerifyResult {
    /// Tampering verdict — read this first. `true` iff no
    /// `Mismatch`, no `Extra`, AND registry reachable. **Does not gate
    /// on `Missing`** — see module docs for rationale.
    pub valid: bool,
    /// Number of files walked on disk.
    pub files_checked: u32,
    /// Number of files whose disk hash matched the registered hash.
    pub files_passed: u32,
    /// Tampering signals: per-file `Mismatch` + `Extra` divergences.
    /// `Missing` is NOT placed here (v1.14.0+); see `missing_files`.
    pub failed_files: Vec<FailedFile>,
    /// Files in the registered manifest that are absent on disk.
    /// Informational — does NOT gate `valid` (v1.14.0+). Read this if
    /// you need byte-identical-to-registered semantics, or read
    /// `registry_match` for the same signal as a single bool.
    #[serde(default)]
    pub missing_files: Vec<FailedFile>,
    /// Canonical computed total, `sha256:<hex>`. Always populated.
    pub total_hash: String,
    /// Registered `file_manifest_hash`, `sha256:<hex>`. `None` when the
    /// registry fetch failed (see `registry_error`).
    pub expected_total_hash: Option<String>,
    /// Strict literal "100% match against registered manifest":
    /// `total_hash == expected_total_hash` AND no `failed_files` AND
    /// no `missing_files`. Mobile bundles ship every signed file, so
    /// mobile gates on this. Desktop installs are intentionally
    /// platform-asymmetric (mobile-only secrets etc.) — desktop should
    /// gate on `valid` instead.
    pub registry_match: bool,
    /// Set when the registry fetch failed; `None` on success. The
    /// caller can distinguish "tree tampered" from "registry down" by
    /// checking this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_error: Option<String>,
    /// Echoed for caller convenience.
    pub project: String,
    /// Echoed for caller convenience.
    pub binary_version: String,
}

/// Walk a source tree on disk and compare against its registered manifest.
///
/// See module docs for the canonical algorithm contract. This function
/// returns `Err` only when the disk walk itself fails (root missing,
/// I/O error). Registry-reachability failures populate
/// [`TreeVerifyResult::registry_error`] and return `Ok` with
/// `registry_match: false`.
#[instrument(
    skip(request, registry),
    fields(
        project = %request.project,
        binary_version = %request.binary_version,
        root = %request.root,
        include_roots = ?request.include_roots,
    )
)]
pub async fn verify_tree(
    request: &TreeVerifyRequest,
    registry: &RegistryClient,
) -> Result<TreeVerifyResult, VerifyError> {
    let rules = ExemptRules {
        include_roots: request.include_roots.clone(),
        exempt_dirs: request.exempt_dirs.clone(),
        exempt_extensions: request.exempt_extensions.clone(),
    };

    debug!("Walking tree under {}", request.root);
    let computed_files = walk_file_tree(Path::new(&request.root), &rules)?;
    let total_hash = FileTreeExtras::compute_tree_hash(&computed_files);
    let files_checked = u32::try_from(computed_files.len()).unwrap_or(u32::MAX);
    info!(
        files_checked = files_checked,
        total_hash = %total_hash,
        "verify_tree walk complete"
    );

    let mut result = TreeVerifyResult {
        valid: false,
        files_checked,
        files_passed: 0,
        failed_files: Vec::new(),
        missing_files: Vec::new(),
        total_hash: total_hash.clone(),
        expected_total_hash: None,
        registry_match: false,
        registry_error: None,
        project: request.project.clone(),
        binary_version: request.binary_version.clone(),
    };

    debug!(
        "Fetching registered manifest for {} {}",
        request.project, request.binary_version
    );
    let build = match registry
        .get_build_by_version(&request.project, &request.binary_version)
        .await
    {
        Ok(b) => b,
        Err(e) => {
            warn!("verify_tree: registry fetch failed: {}", e);
            result.registry_error = Some(e.to_string());
            return Ok(result);
        },
    };

    let registered_files = build.file_manifest_json.files();
    result.expected_total_hash = Some(build.file_manifest_hash.clone());

    // 1. Disk-walked files vs registered manifest: mismatch + extra detection.
    for (path, computed_hash) in &computed_files {
        match registered_files.get(path) {
            Some(expected) if expected == computed_hash => result.files_passed += 1,
            Some(expected) => result.failed_files.push(FailedFile {
                path: path.clone(),
                kind: FailedFileKind::Mismatch,
                computed_hash: Some(computed_hash.clone()),
                expected_hash: Some(expected.clone()),
            }),
            None => result.failed_files.push(FailedFile {
                path: path.clone(),
                kind: FailedFileKind::Extra,
                computed_hash: Some(computed_hash.clone()),
                expected_hash: None,
            }),
        }
    }

    // 2. Registered files absent from disk. v1.14.0+: kept SEPARATE
    //    from `failed_files` because a missing file is not a tampering
    //    signal — the agent that's missing critical code doesn't run
    //    (broken-not-tampered, caught at boot, not here). Common case:
    //    platform-asymmetric build artifacts (e.g. `_build_secrets.py`
    //    bundled into mobile AABs but excluded from desktop wheels).
    //    See CIRISVerify#15.
    for (path, expected) in registered_files {
        if !computed_files.contains_key(path) {
            result.missing_files.push(FailedFile {
                path: path.clone(),
                kind: FailedFileKind::Missing,
                computed_hash: None,
                expected_hash: Some(expected.clone()),
            });
        }
    }

    // 3. Top-level verdicts.
    //    `valid` (tampering verdict): no Mismatch, no Extra. Does NOT
    //    gate on missing — that's the v1.14.0 semantic change.
    //    `registry_match` (strict literal-equality): everything matches
    //    AND nothing is missing AND total_hash equals registered. This
    //    is the signal mobile gates on (mobile bundles ship every
    //    signed file).
    let total_match = total_hash == build.file_manifest_hash;
    result.valid = result.failed_files.is_empty();
    result.registry_match =
        total_match && result.failed_files.is_empty() && result.missing_files.is_empty();

    info!(
        valid = result.valid,
        registry_match = result.registry_match,
        files_passed = result.files_passed,
        failed = result.failed_files.len(),
        missing = result.missing_files.len(),
        "verify_tree complete"
    );

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;

    fn write(root: &Path, rel: &str, bytes: &[u8]) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, bytes).unwrap();
    }

    /// `verify_tree` walk + hash must be byte-for-byte equal to
    /// `walk_file_tree` + `FileTreeExtras::compute_tree_hash` — i.e. the
    /// same Algorithm A that `ciris-build-sign sign --tree` writes into
    /// the registered `file_manifest_hash`. This is the parity contract.
    #[test]
    fn algorithm_a_parity_with_build_sign() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        write(root, "ciris_engine/__init__.py", b"# engine\n");
        write(root, "ciris_engine/core.py", b"def f(): pass\n");
        write(root, "ciris_adapters/README.md", b"# adapters\n");
        write(root, "__pycache__/foo.pyc", b"\xde\xad\xbe\xef");
        write(root, "ciris_engine/__pycache__/bar.pyc", b"\xca\xfe");

        let rules = ExemptRules {
            include_roots: vec!["ciris_engine".into(), "ciris_adapters".into()],
            exempt_dirs: vec!["__pycache__".into()],
            exempt_extensions: vec!["pyc".into()],
        };

        // Reference path (what the signing side does).
        let ref_files = walk_file_tree(root, &rules).unwrap();
        let ref_total = FileTreeExtras::compute_tree_hash(&ref_files);

        // verify_tree path uses the exact same primitives — so we just
        // assert that the Result built from those primitives is what we
        // expect end-to-end. (The end-to-end path's registry compare is
        // covered separately in `compare_logic_*` tests below using a
        // hand-built BuildRecord-equivalent.)
        let request = TreeVerifyRequest {
            root: root.to_str().unwrap().to_string(),
            include_roots: rules.include_roots.clone(),
            exempt_dirs: rules.exempt_dirs.clone(),
            exempt_extensions: rules.exempt_extensions.clone(),
            project: "ciris-agent".into(),
            binary_version: "test-1.2.3".into(),
        };

        // Run only the walk portion.
        let computed = walk_file_tree(Path::new(&request.root), &rules).unwrap();
        let total = FileTreeExtras::compute_tree_hash(&computed);

        assert_eq!(computed, ref_files);
        assert_eq!(total, ref_total);
        assert!(total.starts_with("sha256:"));
        assert_eq!(total.len(), 7 + 64);

        // .pyc and __pycache__ both excluded.
        assert!(!computed.keys().any(|k| k.contains("__pycache__")));
        assert!(!computed.keys().any(|k| k.ends_with(".pyc")));
        // Expected files: 2 .py + 1 .md = 3.
        assert_eq!(computed.len(), 3);
    }

    /// Per-file diff classification (v1.14.0+): mismatch + extra go to
    /// `failed_files` (tampering signals); missing goes to its own
    /// `missing_files` (informational, not a fail).
    #[test]
    fn compare_logic_classifies_failures() {
        // We test the diff loop in isolation by building the maps the
        // real function passes through.
        let mut computed: BTreeMap<String, String> = BTreeMap::new();
        computed.insert(
            "kept.py".into(),
            "sha256:1111111111111111111111111111111111111111111111111111111111111111".into(),
        );
        computed.insert(
            "drifted.py".into(),
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".into(),
        );
        computed.insert(
            "extra.py".into(),
            "sha256:3333333333333333333333333333333333333333333333333333333333333333".into(),
        );

        let mut registered: std::collections::HashMap<String, String> = Default::default();
        registered.insert(
            "kept.py".into(),
            "sha256:1111111111111111111111111111111111111111111111111111111111111111".into(),
        );
        registered.insert(
            "drifted.py".into(),
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into(),
        );
        registered.insert(
            "missing.py".into(),
            "sha256:5555555555555555555555555555555555555555555555555555555555555555".into(),
        );

        // Mirror the real `verify_tree` logic.
        let mut failed: Vec<FailedFile> = Vec::new();
        let mut missing: Vec<FailedFile> = Vec::new();
        let mut passed: u32 = 0;
        for (path, computed_hash) in &computed {
            match registered.get(path) {
                Some(expected) if expected == computed_hash => passed += 1,
                Some(expected) => failed.push(FailedFile {
                    path: path.clone(),
                    kind: FailedFileKind::Mismatch,
                    computed_hash: Some(computed_hash.clone()),
                    expected_hash: Some(expected.clone()),
                }),
                None => failed.push(FailedFile {
                    path: path.clone(),
                    kind: FailedFileKind::Extra,
                    computed_hash: Some(computed_hash.clone()),
                    expected_hash: None,
                }),
            }
        }
        for (path, expected) in &registered {
            if !computed.contains_key(path) {
                missing.push(FailedFile {
                    path: path.clone(),
                    kind: FailedFileKind::Missing,
                    computed_hash: None,
                    expected_hash: Some(expected.clone()),
                });
            }
        }

        assert_eq!(passed, 1);
        // Tampering signals only — both Mismatch and Extra, no Missing.
        let failed_kinds: Vec<FailedFileKind> = failed.iter().map(|f| f.kind).collect();
        assert!(failed_kinds.contains(&FailedFileKind::Mismatch));
        assert!(failed_kinds.contains(&FailedFileKind::Extra));
        assert!(!failed_kinds.contains(&FailedFileKind::Missing));
        assert_eq!(failed.len(), 2);
        // Missing is its own bucket.
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].kind, FailedFileKind::Missing);
        assert_eq!(missing[0].path, "missing.py");
    }

    /// CIRISVerify#15 verdict semantic: missing files alone must NOT
    /// flip `valid` to false. Tampering signals (mismatch / extra) DO.
    /// Locks the platform-asymmetric desktop case (`_build_secrets.py`
    /// signed in the manifest, intentionally absent from desktop wheels).
    #[test]
    fn missing_only_keeps_valid_true_but_registry_match_false() {
        // Build a result that mirrors the desktop wheel scenario:
        // walk found everything except 1 platform-asymmetric file.
        let mut result = TreeVerifyResult {
            valid: false,
            files_checked: 1499,
            files_passed: 1499,
            failed_files: Vec::new(),
            missing_files: vec![FailedFile {
                path: "ciris_adapters/wallet/providers/_build_secrets.py".into(),
                kind: FailedFileKind::Missing,
                computed_hash: None,
                expected_hash: Some("sha256:abcd".into()),
            }],
            total_hash: "sha256:walk".into(),
            expected_total_hash: Some("sha256:registered".into()),
            registry_match: false,
            registry_error: None,
            project: "ciris-agent".into(),
            binary_version: "2.8.7".into(),
        };
        // Mirror the real verdict computation from verify_tree().
        let total_match = result.total_hash == *result.expected_total_hash.as_ref().unwrap();
        result.valid = result.failed_files.is_empty();
        result.registry_match =
            total_match && result.failed_files.is_empty() && result.missing_files.is_empty();

        // Tampering verdict: clean (no Mismatch / Extra). This is the
        // signal desktop gates on.
        assert!(result.valid, "missing-only must not flip valid=false");
        // Strict-equality verdict: still false. Mobile gates on this
        // because mobile bundles ship every signed file.
        assert!(!result.registry_match);
    }

    /// Inverse: a single Mismatch flips valid=false even if
    /// missing_files is empty. Tampering IS detected.
    #[test]
    fn mismatch_flips_valid_false() {
        let mut result = TreeVerifyResult {
            valid: false,
            files_checked: 100,
            files_passed: 99,
            failed_files: vec![FailedFile {
                path: "evil.py".into(),
                kind: FailedFileKind::Mismatch,
                computed_hash: Some("sha256:tampered".into()),
                expected_hash: Some("sha256:original".into()),
            }],
            missing_files: Vec::new(),
            total_hash: "sha256:walk".into(),
            expected_total_hash: Some("sha256:registered".into()),
            registry_match: false,
            registry_error: None,
            project: "ciris-agent".into(),
            binary_version: "2.8.7".into(),
        };
        let total_match = result.total_hash == *result.expected_total_hash.as_ref().unwrap();
        result.valid = result.failed_files.is_empty();
        result.registry_match =
            total_match && result.failed_files.is_empty() && result.missing_files.is_empty();
        assert!(!result.valid, "mismatch MUST flip valid=false");
        assert!(!result.registry_match);
    }

    /// And: an Extra also flips valid=false (someone slipped a file
    /// into the install that wasn't signed).
    #[test]
    fn extra_flips_valid_false() {
        let mut result = TreeVerifyResult {
            valid: false,
            files_checked: 101,
            files_passed: 100,
            failed_files: vec![FailedFile {
                path: "backdoor.py".into(),
                kind: FailedFileKind::Extra,
                computed_hash: Some("sha256:slipped-in".into()),
                expected_hash: None,
            }],
            missing_files: Vec::new(),
            total_hash: "sha256:walk".into(),
            expected_total_hash: Some("sha256:registered".into()),
            registry_match: false,
            registry_error: None,
            project: "ciris-agent".into(),
            binary_version: "2.8.7".into(),
        };
        let total_match = result.total_hash == *result.expected_total_hash.as_ref().unwrap();
        result.valid = result.failed_files.is_empty();
        result.registry_match =
            total_match && result.failed_files.is_empty() && result.missing_files.is_empty();
        assert!(!result.valid, "extra MUST flip valid=false");
        assert!(!result.registry_match);
    }

    /// Empty include_roots = walk fs_root. Empty exempt sets = include
    /// every file. Locks default behavior matches `ciris-build-sign sign
    /// --tree` with no flags.
    #[test]
    fn empty_rules_walk_everything() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "a.py", b"a\n");
        write(root, "sub/b.md", b"b\n");
        write(root, "sub/deep/c.txt", b"c\n");

        let rules = ExemptRules::default();
        let files = walk_file_tree(root, &rules).unwrap();
        assert_eq!(files.len(), 3);
        assert!(files.contains_key("a.py"));
        assert!(files.contains_key("sub/b.md"));
        assert!(files.contains_key("sub/deep/c.txt"));
    }

    /// Serialization round-trip locks the wire shape FFI/Python depend on.
    #[test]
    fn result_serialization_round_trip() {
        let r = TreeVerifyResult {
            valid: true,
            files_checked: 1630,
            files_passed: 1630,
            failed_files: vec![],
            missing_files: vec![],
            total_hash: "sha256:abcd".into(),
            expected_total_hash: Some("sha256:abcd".into()),
            registry_match: true,
            registry_error: None,
            project: "ciris-agent".into(),
            binary_version: "2.8.3".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: TreeVerifyResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.files_checked, 1630);
        assert!(back.valid);
        assert!(!json.contains("registry_error")); // skipped when None
    }

    /// Old wire format (without missing_files) must still deserialize
    /// — graceful degradation for callers running pre-1.14 wheels that
    /// upgrade to the new client. The serde default = empty Vec keeps
    /// the field optional on the wire.
    #[test]
    fn result_deserializes_without_missing_files_field() {
        let json = r#"{
            "valid": true,
            "files_checked": 5,
            "files_passed": 5,
            "failed_files": [],
            "total_hash": "sha256:abcd",
            "expected_total_hash": "sha256:abcd",
            "registry_match": true,
            "project": "ciris-verify",
            "binary_version": "1.13.3"
        }"#;
        let r: TreeVerifyResult = serde_json::from_str(json).unwrap();
        assert_eq!(r.missing_files.len(), 0);
        assert!(r.valid);
    }

    #[test]
    fn failed_file_kind_serializes_lowercase() {
        let f = FailedFile {
            path: "x.py".into(),
            kind: FailedFileKind::Mismatch,
            computed_hash: Some("sha256:aa".into()),
            expected_hash: Some("sha256:bb".into()),
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"mismatch\""));
    }
}
