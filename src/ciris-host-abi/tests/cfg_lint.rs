//! The target-cfg lint.

use std::path::Path;

use ciris_host_abi::cfg_lint::{lint_crate, scan_manifest, scan_source, CrateResult};

fn names(src: &str) -> Vec<(usize, &'static str, String)> {
    scan_source(Path::new("x.rs"), src)
        .unwrap()
        .into_iter()
        .map(|f| (f.line, f.form, f.name))
        .collect()
}

#[test]
fn flags_every_form() {
    let src = r#"
#[cfg(target_arch = "wasm32")]
fn a() {}
#[cfg(unix)]
fn b() {}
#[cfg(windows)]
fn c() {}
#[cfg(not(target_os = "linux"))]
fn d() {}
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn e() {}
fn f() -> bool { cfg!(target_family = "wasm") }
#[cfg(all(feature = "x", any(test, target_pointer_width = "64")))]
fn g() {}
macro_rules! m { () => { #[cfg(target_env = "gnu")] fn h() {} } }
#[cfg_attr(feature = "y", cfg(unix))]
fn i() {}
"#;
    assert_eq!(
        names(src),
        vec![
            (2, "cfg", "target_arch".into()),
            (4, "cfg", "unix".into()),
            (6, "cfg", "windows".into()),
            (8, "cfg", "target_os".into()),
            (10, "cfg_attr", "target_os".into()),
            (12, "cfg!", "target_family".into()),
            (13, "cfg", "target_pointer_width".into()),
            (15, "cfg", "target_env".into()),
            (16, "cfg", "unix".into()),
        ]
    );
}

#[test]
fn ignores_allowed_cfgs_comments_and_strings() {
    let src = r##"
#[cfg(test)]
mod t {}
#[cfg(feature = "target_os")]
fn a() {}
#[cfg_attr(feature = "x", doc = "cfg(unix)")]
fn b() {}
// #[cfg(target_os = "linux")]
/* cfg(windows) */
/// cfg(unix) in a doc comment
fn c() -> &'static str { "#[cfg(target_arch = \"wasm32\")]" }
fn d(target_os: u8) -> u8 { target_os }
"##;
    assert!(names(src).is_empty(), "{:?}", names(src));
}

#[test]
fn manifest_target_tables() {
    let toml = "[package]\nname = \"n\"\n[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n[target.x86_64-unknown-linux-gnu.dependencies]\n[target.'cfg(feature = \"x\")'.dependencies]\n";
    let f = scan_manifest(Path::new("Cargo.toml"), toml);
    assert_eq!(f.len(), 1);
    assert_eq!((f[0].line, f[0].name.as_str()), (3, "unix"));
}

#[test]
fn host_abi_is_exempt() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(matches!(lint_crate(dir).unwrap(), CrateResult::Exempt));
}

#[test]
fn lints_a_crate_directory() {
    let dir = std::env::temp_dir().join(format!("ciris-cfg-lint-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("src/inner")).unwrap();
    std::fs::create_dir_all(dir.join("target")).unwrap();
    std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"node-x\"\n").unwrap();
    std::fs::write(dir.join("src/lib.rs"), "pub fn ok() {}\n").unwrap();
    std::fs::write(
        dir.join("src/inner/x.rs"),
        "#[cfg(unix)]\npub fn bad() {}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("target/skip.rs"),
        "#[cfg(unix)]\nfn skipped() {}\n",
    )
    .unwrap();
    let r = lint_crate(&dir).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    match r {
        CrateResult::Scanned { findings, files } => {
            assert_eq!(files, 2);
            assert_eq!(findings.len(), 1);
            assert!(findings[0].file.ends_with("src/inner/x.rs"));
        },
        CrateResult::Exempt => panic!("not exempt"),
    }
}
