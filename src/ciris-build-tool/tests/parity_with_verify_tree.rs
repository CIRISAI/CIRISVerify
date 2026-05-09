// Integration tests — `unwrap`/`expect` are appropriate here; the
// whole file is test code and a panic IS a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Cross-crate parity test (CIRISVerify#9): the file map + total hash
//! that `ciris-build-sign sign --tree` (i.e. `build_file_tree_extras`)
//! writes into the registered `BuildManifest::extras` MUST equal what
//! `ciris-verify-core`'s runtime walker computes — byte-for-byte.
//!
//! Both consumers today call the same canonical primitives
//! (`walk_file_tree` + `FileTreeExtras::compute_tree_hash` in
//! `ciris-verify-core::security::build_manifest`). This test guards
//! against a future refactor that accidentally introduces a second
//! algorithm — divergence here means a runtime walker would compute a
//! different `total_hash` than what got registered, and L4 would never
//! match end-to-end.
//!
//! The contract this locks:
//!   1. `files: BTreeMap<path, "sha256:hex">` produced by signing-side
//!      walker == files produced by verify-side walker.
//!   2. `file_tree_hash: "sha256:<hex>"` from signing-side ==
//!      `total_hash` from verify-side.
//!   3. ExemptRules { include_roots, exempt_dirs, exempt_extensions }
//!      passed at sign time produces the same shape as the same rules
//!      at verify time.

use ciris_build_tool::build_file_tree_extras;
use ciris_verify_core::security::build_manifest::{walk_file_tree, ExemptRules, FileTreeExtras};
use std::fs;
use std::path::Path;

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, bytes).unwrap();
}

/// Default rules (no flags passed to `ciris-build-sign sign --tree`).
/// The agent's python-source-tree target signs in this mode.
#[test]
fn default_rules_sign_verify_byte_equal() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    write(root, "ciris_engine/__init__.py", b"# engine\n");
    write(root, "ciris_engine/core.py", b"def f(): pass\n");
    write(root, "ciris_engine/sub/svc.py", b"class S: pass\n");
    write(root, "ciris_adapters/api.py", b"# adapter\n");
    write(root, "README.md", b"# top-level readme\n");

    let rules = ExemptRules::default();

    let signed = build_file_tree_extras(root, rules.clone(), None).unwrap();
    let walked = walk_file_tree(root, &rules).unwrap();
    let walked_total = FileTreeExtras::compute_tree_hash(&walked);

    assert_eq!(
        signed.files, walked,
        "signing-side BTreeMap and verify-side BTreeMap must be byte-equal"
    );
    assert_eq!(
        signed.file_tree_hash, walked_total,
        "signing-side file_tree_hash and verify-side total must be byte-equal"
    );
    assert!(signed.file_tree_hash.starts_with("sha256:"));
}

/// Iso bundle target: explicit --tree-include + --tree-exempt-dir +
/// --tree-exempt-ext flags. Mirrors the agent's
/// `client/iosApp/Resources/app` sign step in build.yml.
#[test]
fn ios_bundle_style_rules_sign_verify_byte_equal() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    write(root, "ciris_engine/init.py", b"a\n");
    write(root, "ciris_adapters/x.py", b"b\n");
    write(root, "ciris_ios/y.py", b"c\n");
    write(root, "ciris_sdk/z.py", b"d\n");

    // Files that MUST be excluded by the rules.
    write(root, "__pycache__/cached.pyc", b"\xde\xad");
    write(root, "ciris_engine/__pycache__/m.pyc", b"\xbe\xef");
    write(root, "ciris_engine/.venv/site/x.py", b"venv junk\n");
    write(root, "ciris_engine/x.pyc", b"compiled\n");
    write(root, "ciris_engine/x.log", b"log junk\n");

    // Files OUTSIDE include_roots must be excluded too.
    write(root, "node_modules/junk/foo.py", b"junk\n");
    write(root, "build/dist/x.py", b"dist\n");

    let rules = ExemptRules {
        include_roots: vec![
            "ciris_engine".into(),
            "ciris_adapters".into(),
            "ciris_ios".into(),
            "ciris_sdk".into(),
        ],
        exempt_dirs: vec![
            "__pycache__".into(),
            ".venv".into(),
            "venv".into(),
            "node_modules".into(),
            "logs".into(),
            ".pytest_cache".into(),
            ".mypy_cache".into(),
            "dist".into(),
            "build".into(),
            ".ruff_cache".into(),
            ".coverage".into(),
            ".tox".into(),
            ".nox".into(),
            ".git".into(),
        ],
        exempt_extensions: vec![
            "pyc".into(),
            "pyo".into(),
            "env".into(),
            "log".into(),
            "audit".into(),
            "db".into(),
            "sqlite".into(),
            "sqlite3".into(),
        ],
    };

    let signed = build_file_tree_extras(root, rules.clone(), None).unwrap();
    let walked = walk_file_tree(root, &rules).unwrap();
    let walked_total = FileTreeExtras::compute_tree_hash(&walked);

    assert_eq!(signed.files, walked);
    assert_eq!(signed.file_tree_hash, walked_total);
    assert_eq!(signed.file_count as usize, signed.files.len());
    // Only the 4 surviving include_root .py files.
    assert_eq!(signed.files.len(), 4);
    assert!(signed.files.contains_key("ciris_engine/init.py"));
    assert!(signed.files.contains_key("ciris_adapters/x.py"));
    assert!(signed.files.contains_key("ciris_ios/y.py"));
    assert!(signed.files.contains_key("ciris_sdk/z.py"));
}

/// Adding a new file flips the canonical hash AND the BTreeMap (so
/// per-file diff and total-hash diff both fire). Confirms the verify
/// side detects drift the signing side wouldn't have signed for.
#[test]
fn drift_detection_via_extra_file() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    write(root, "a.py", b"a\n");
    write(root, "b.py", b"b\n");

    let rules = ExemptRules::default();
    let signed = build_file_tree_extras(root, rules.clone(), None).unwrap();

    // Tampering: a new file appears AFTER signing.
    write(root, "c.py", b"c\n");

    let walked = walk_file_tree(root, &rules).unwrap();
    let walked_total = FileTreeExtras::compute_tree_hash(&walked);

    assert_ne!(
        signed.file_tree_hash, walked_total,
        "extra file MUST flip total hash"
    );
    assert!(walked.contains_key("c.py"));
    assert!(!signed.files.contains_key("c.py"));
}

/// Mutating an existing file flips the per-file hash AND the total.
#[test]
fn drift_detection_via_modified_file() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    write(root, "x.py", b"original\n");
    let rules = ExemptRules::default();
    let signed = build_file_tree_extras(root, rules.clone(), None).unwrap();

    write(root, "x.py", b"tampered\n");

    let walked = walk_file_tree(root, &rules).unwrap();
    let walked_total = FileTreeExtras::compute_tree_hash(&walked);

    assert_ne!(signed.file_tree_hash, walked_total);
    assert_ne!(signed.files["x.py"], walked["x.py"]);
}
