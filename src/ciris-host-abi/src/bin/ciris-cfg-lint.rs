//! `ciris-cfg-lint <crate-dir>...`
//!
//! Fails (exit 1) on any `cfg(target_*)`, `cfg(unix)`, `cfg(windows)`,
//! `cfg(not(target_…))`, `cfg!(…)` or `cfg_attr(target_…, …)` in the given
//! node crates, and on `[target.'cfg(…)']` tables in their manifests
//! (FSD §4.1.2). `ciris-host-abi` is exempt and reported as such.
//! Exit 2 is a usage or read error.

use std::path::PathBuf;
use std::process::ExitCode;

use ciris_host_abi::cfg_lint::{lint_crate, CrateResult, EXEMPT_CRATE};

fn main() -> ExitCode {
    let dirs: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    if dirs.is_empty()
        || dirs
            .iter()
            .any(|d| d.as_os_str() == "-h" || d.as_os_str() == "--help")
    {
        eprintln!("usage: ciris-cfg-lint <crate-dir>...");
        return ExitCode::from(2);
    }
    let mut total = 0usize;
    for dir in &dirs {
        match lint_crate(dir) {
            Ok(CrateResult::Exempt) => println!(
                "{}: exempt ({EXEMPT_CRATE} is the one crate allowed to branch on target)",
                dir.display()
            ),
            Ok(CrateResult::Scanned { findings, files }) => {
                if findings.is_empty() {
                    println!("{}: ok ({files} files)", dir.display());
                } else {
                    println!(
                        "{}: {} target cfg(s) in {files} files",
                        dir.display(),
                        findings.len()
                    );
                    for f in &findings {
                        eprintln!("  {f}");
                    }
                    total += findings.len();
                }
            },
            Err(e) => {
                eprintln!("ciris-cfg-lint: {e}");
                return ExitCode::from(2);
            },
        }
    }
    if total == 0 {
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "FAIL: {total} target cfg(s); hosts differ by runtime answers, not cfg (FSD §4.1.2)"
        );
        ExitCode::FAILURE
    }
}
