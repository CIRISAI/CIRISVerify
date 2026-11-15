//! `ciris-abi-gate [--wit <file|dir>] [--world <name>] <module.wasm>...`
//!
//! Fails (exit 1) when any module imports anything outside the `ciris:node/*`
//! interfaces its world imports (FSD §4.1.1). The allowlist is derived from
//! the WIT: by default the copy compiled into this binary, or `--wit`.
//! `--world` defaults to `node`; use `vault` for the §8.5 vault instance.
//! Exit 2 is a usage or read error.

use std::path::PathBuf;
use std::process::ExitCode;

use ciris_host_abi::gate::Allowlist;

fn main() -> ExitCode {
    let mut wit: Option<PathBuf> = None;
    let mut world = "node".to_owned();
    let mut modules = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--wit" => wit = args.next().map(PathBuf::from),
            "--world" => match args.next() {
                Some(w) => world = w,
                None => return usage(),
            },
            "-h" | "--help" => return usage(),
            _ => modules.push(PathBuf::from(a)),
        }
    }
    if modules.is_empty() {
        return usage();
    }
    let allow = match &wit {
        Some(p) => Allowlist::from_wit_path(p, &world),
        None => Allowlist::from_wit_str(ciris_host_abi::WIT, &world),
    };
    let allow = match allow {
        Ok(a) => a,
        Err(e) => {
            eprintln!("ciris-abi-gate: {e}");
            return ExitCode::from(2);
        },
    };
    let mut failed = false;
    for m in &modules {
        let bytes = match std::fs::read(m) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("ciris-abi-gate: {}: {e}", m.display());
                return ExitCode::from(2);
            },
        };
        let report = match allow.gate(&bytes) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("ciris-abi-gate: {}: {e}", m.display());
                return ExitCode::from(2);
            },
        };
        println!(
            "{}: {} import(s), world {}",
            m.display(),
            report.imports.len(),
            allow.world
        );
        for i in &report.imports {
            println!("  {i}");
        }
        if report.passed() {
            println!("PASS: only ciris:node/* imports of world {}", allow.world);
        } else {
            failed = true;
            eprintln!("FAIL: {} offending import(s):", report.offenders.len());
            for (i, why) in &report.offenders {
                eprintln!("  {i}: {why}");
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: ciris-abi-gate [--wit <file|dir>] [--world node|vault] <module.wasm>...");
    ExitCode::from(2)
}
