//! The target-`cfg` lint (FSD §4.1.2, §4.1.4).
//!
//! Node crates contain no compile-time branch on target: differences
//! between hosts are runtime capability answers. This scans a crate's Rust
//! sources with the `proc-macro2` tokenizer (so comments and string
//! literals never match) and reports every `cfg(…)`, `cfg!(…)` and
//! `cfg_attr(…)` predicate that names `target_*`, `unix` or `windows`,
//! including under `not(…)`, `any(…)` and `all(…)`, inside attributes,
//! expressions and `macro_rules!` bodies. It also reports
//! `[target.'cfg(…)']` tables in the crate's `Cargo.toml`, the same branch
//! made in the manifest.
//!
//! `ciris-host-abi` itself is exempt: it is the one crate allowed to branch
//! on target, and the lint says so when it skips it.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use proc_macro2::{Delimiter, Spacing, TokenStream, TokenTree};

/// The crate exempt from the lint.
pub const EXEMPT_CRATE: &str = "ciris-host-abi";

/// One forbidden `cfg`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// The file.
    pub file: PathBuf,
    /// 1-based line.
    pub line: usize,
    /// `cfg`, `cfg!`, `cfg_attr` or `Cargo.toml [target]`.
    pub form: &'static str,
    /// The offending predicate name (`target_os`, `unix`, ...).
    pub name: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}: {} on `{}`",
            self.file.display(),
            self.line,
            self.form,
            self.name
        )
    }
}

/// The outcome for one crate.
#[derive(Clone, Debug)]
pub enum CrateResult {
    /// Scanned; the findings (empty when clean) and the number of files.
    Scanned {
        /// Forbidden `cfg`s.
        findings: Vec<Finding>,
        /// Files scanned.
        files: usize,
    },
    /// Skipped because it is [`EXEMPT_CRATE`].
    Exempt,
}

/// Whether `ident` is a forbidden cfg predicate name.
fn forbidden(ident: &str) -> bool {
    ident.starts_with("target_") || ident == "unix" || ident == "windows"
}

/// The first forbidden predicate name inside `stream`, if any.
fn first_forbidden(stream: &TokenStream) -> Option<String> {
    for tt in stream.clone() {
        match tt {
            TokenTree::Ident(i) if forbidden(&i.to_string()) => return Some(i.to_string()),
            TokenTree::Group(g) => {
                if let Some(n) = first_forbidden(&g.stream()) {
                    return Some(n);
                }
            },
            _ => {},
        }
    }
    None
}

/// `cfg_attr`'s predicate: the tokens before the first top-level comma.
fn cfg_attr_predicate(stream: &TokenStream) -> TokenStream {
    stream
        .clone()
        .into_iter()
        .take_while(|tt| !matches!(tt, TokenTree::Punct(p) if p.as_char() == ','))
        .collect()
}

/// Scan one Rust source text.
///
/// # Errors
/// The text does not tokenize (unbalanced delimiters, a bad literal).
pub fn scan_source(file: &Path, src: &str) -> Result<Vec<Finding>, String> {
    let stream = TokenStream::from_str(src)
        .map_err(|e| format!("{}: does not tokenize: {e}", file.display()))?;
    let mut out = Vec::new();
    walk(file, stream, &mut out);
    Ok(out)
}

fn walk(file: &Path, stream: TokenStream, out: &mut Vec<Finding>) {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    let mut i = 0;
    while i < tokens.len() {
        if let TokenTree::Ident(ident) = &tokens[i] {
            let name = ident.to_string();
            if name == "cfg" || name == "cfg_attr" {
                // `cfg(`, `cfg!(`, `cfg_attr(`.
                let mut j = i + 1;
                let mut bang = false;
                if let Some(TokenTree::Punct(p)) = tokens.get(j) {
                    if p.as_char() == '!' && p.spacing() == Spacing::Alone {
                        bang = true;
                        j += 1;
                    }
                }
                if let Some(TokenTree::Group(g)) = tokens.get(j) {
                    if g.delimiter() == Delimiter::Parenthesis {
                        let predicate = if name == "cfg" {
                            g.stream()
                        } else {
                            cfg_attr_predicate(&g.stream())
                        };
                        if let Some(bad) = first_forbidden(&predicate) {
                            out.push(Finding {
                                file: file.to_path_buf(),
                                line: ident.span().start().line,
                                form: match (name.as_str(), bang) {
                                    ("cfg", true) => "cfg!",
                                    ("cfg", false) => "cfg",
                                    _ => "cfg_attr",
                                },
                                name: bad,
                            });
                        }
                        // A `cfg_attr` body may hold a nested `cfg(…)`.
                        if name == "cfg_attr" {
                            walk(file, g.stream(), out);
                        }
                        i = j + 1;
                        continue;
                    }
                }
            }
        }
        if let TokenTree::Group(g) = &tokens[i] {
            walk(file, g.stream(), out);
        }
        i += 1;
    }
}

/// Scan a `Cargo.toml` for `[target.'cfg(…)'…]` tables naming a forbidden
/// predicate.
#[must_use]
pub fn scan_manifest(file: &Path, toml: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (n, line) in toml.lines().enumerate() {
        let t = line.trim_start();
        if !t.starts_with("[target.") && !t.starts_with("[[target.") {
            continue;
        }
        let Some(start) = t.find("cfg(") else {
            continue;
        };
        let pred = &t[start..];
        let name = pred
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .find(|w| forbidden(w));
        if let Some(name) = name {
            out.push(Finding {
                file: file.to_path_buf(),
                line: n + 1,
                form: "Cargo.toml [target]",
                name: name.to_owned(),
            });
        }
    }
    out
}

/// The `[package] name` of a manifest, by a line scan.
fn package_name(toml: &str) -> Option<String> {
    let mut in_package = false;
    for line in toml.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_package = t == "[package]";
            continue;
        }
        if in_package {
            if let Some(rest) = t.strip_prefix("name") {
                let rest = rest.trim_start().strip_prefix('=')?.trim();
                return Some(rest.trim_matches('"').to_owned());
            }
        }
    }
    None
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
    entries.sort_by_key(fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let ft = entry
            .file_type()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if ft.is_dir() {
            if name.starts_with('.') || name == "target" {
                continue;
            }
            rust_files(&path, out)?;
        } else if ft.is_file() && name.ends_with(".rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// Lint one crate directory (the directory holding its `Cargo.toml`).
///
/// # Errors
/// The directory or a source file cannot be read or tokenized.
pub fn lint_crate(dir: &Path) -> Result<CrateResult, String> {
    let manifest_path = dir.join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    if package_name(&manifest).as_deref() == Some(EXEMPT_CRATE) {
        return Ok(CrateResult::Exempt);
    }
    let mut findings = scan_manifest(&manifest_path, &manifest);
    let mut files = Vec::new();
    rust_files(dir, &mut files)?;
    for file in &files {
        let src = fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
        findings.extend(scan_source(file, &src)?);
    }
    Ok(CrateResult::Scanned {
        findings,
        files: files.len(),
    })
}
