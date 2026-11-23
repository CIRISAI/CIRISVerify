//! The `ciris-binary-manifest/1` blob output (FSD-008 §6), through
//! [`ciris_verify_core::edition2::build_manifest`].
//!
//! The blob is generated from the **final** file that ships (after every
//! post-link rewrite), because its binary hash and function offsets are
//! properties of that file. Offsets are the parser's: relative to the base the
//! runtime resolves (the executable `PT_LOAD` segment on ELF, `__TEXT` on
//! Mach-O, the image base on PE); see the codec's module docs.

use std::collections::BTreeMap;
use std::path::Path;

use ciris_verify_core::edition2::build_manifest::{self, BinaryManifest, BlobError, FunctionLeaf};
use sha2::{Digest, Sha256};

use crate::parser::{parse_bytes, ParseError};

/// Why a blob could not be generated.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BlobGenError {
    #[error("Binary parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("No functions found matching filter")]
    NoFunctionsFound,

    /// A function's bytes lie outside the file: the blob would cover less
    /// than the symbol table names, so nothing is emitted.
    #[error("function {0} lies outside the file")]
    FunctionOutsideFile(String),

    /// A function of size 0 would verify nothing.
    #[error("function {0} has size 0")]
    EmptyFunction(String),

    /// One name at two places.
    #[error("function {0} appears twice with different offsets or sizes")]
    ConflictingFunction(String),

    #[error("blob refused: {0}")]
    Blob(BlobError),
}

/// What the caller names; everything else is read from the file.
pub struct BlobRequest<'a> {
    pub project: &'a str,
    pub version: &'a str,
    pub target: &'a str,
    pub filter: Option<&'a str>,
    pub inline_functions: bool,
}

/// The blob's `tool`: the generator and its version, and nothing about the
/// run (no host, path, time or build id), so it is constant for a release
/// and the blob is a pure function of (file, project, version, target, tool).
#[must_use]
pub fn tool_name() -> String {
    format!("ciris-manifest-tool/{}", env!("CARGO_PKG_VERSION"))
}

/// A generated blob and the summary the CLI prints.
pub struct GeneratedBlob {
    pub manifest: BinaryManifest,
    pub function_count: usize,
    pub bytes: Vec<u8>,
}

/// Generate the blob for `binary_path`.
///
/// # Errors
///
/// [`BlobGenError`]; a blob is never emitted over fewer functions than the
/// filter matched.
pub fn generate_blob(
    binary_path: &Path,
    req: &BlobRequest<'_>,
) -> Result<GeneratedBlob, BlobGenError> {
    let data = std::fs::read(binary_path)?;
    let parsed = parse_bytes(&data, req.filter)?;
    if parsed.functions.is_empty() {
        return Err(BlobGenError::NoFunctionsFound);
    }
    let mut table: BTreeMap<String, FunctionLeaf> = BTreeMap::new();
    for func in &parsed.functions {
        if func.size == 0 {
            return Err(BlobGenError::EmptyFunction(func.name.clone()));
        }
        let bytes = parsed
            .function_bytes(func)
            .ok_or_else(|| BlobGenError::FunctionOutsideFile(func.name.clone()))?;
        let leaf = FunctionLeaf {
            name: func.name.clone(),
            offset: func.offset,
            size: func.size,
            hash: Sha256::digest(bytes).into(),
        };
        match table.get(&func.name) {
            Some(prev) if *prev != leaf => {
                return Err(BlobGenError::ConflictingFunction(func.name.clone()));
            },
            Some(_) => {},
            None => {
                table.insert(func.name.clone(), leaf);
            },
        }
    }
    // The whole file as the runtime hashes it (`compute_self_hash`), not the
    // parser's view: for a fat Mach-O the parser holds one slice.
    drop(parsed);
    let binary_hash = ciris_verify_core::binary_format::canonical_binary_hash(&data);
    let function_count = table.len();
    let manifest = BinaryManifest::new(
        req.project,
        req.version,
        req.target,
        binary_hash,
        table.into_values().collect(),
        req.inline_functions,
        &tool_name(),
    )
    .map_err(BlobGenError::Blob)?;
    let bytes = build_manifest::encode(&manifest).map_err(BlobGenError::Blob)?;
    // The bytes a reader is handed are the bytes it accepts.
    debug_assert_eq!(build_manifest::decode(&bytes).as_ref(), Ok(&manifest));
    Ok(GeneratedBlob {
        manifest,
        function_count,
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(inline: bool) -> BlobRequest<'static> {
        BlobRequest {
            project: "ciris-manifest-tool",
            version: "0.0.0",
            target: "test-target",
            filter: Some("main"),
            inline_functions: inline,
        }
    }

    #[test]
    fn blob_of_this_test_binary_round_trips() {
        let exe = std::env::current_exe().unwrap();
        for inline in [true, false] {
            let out = generate_blob(&exe, &req(inline)).unwrap();
            assert!(out.function_count >= 1);
            assert_eq!(build_manifest::decode(&out.bytes).unwrap(), out.manifest);
            assert_eq!(out.manifest.functions.is_some(), inline);
        }
    }

    #[test]
    fn two_runs_give_identical_bytes() {
        let exe = std::env::current_exe().unwrap();
        for inline in [true, false] {
            let a = generate_blob(&exe, &req(inline)).unwrap().bytes;
            let b = generate_blob(&exe, &req(inline)).unwrap().bytes;
            assert_eq!(a, b);
        }
    }

    #[test]
    fn tool_names_the_generator_and_version_only() {
        let exe = std::env::current_exe().unwrap();
        let out = generate_blob(&exe, &req(true)).unwrap();
        let tool = &out.manifest.tool;
        assert_eq!(*tool, tool_name());
        assert_eq!(
            *tool,
            concat!("ciris-manifest-tool/", env!("CARGO_PKG_VERSION"))
        );
        // No path, host, time or build id: one '/', then the crate version.
        let exe = exe.to_string_lossy();
        assert!(!exe.is_empty() && !tool.contains(exe.as_ref()));
        assert_eq!(tool.matches('/').count(), 1);
        assert!(!tool.contains(':') && !tool.contains('T') && !tool.contains(' '));
        let version = tool.strip_prefix("ciris-manifest-tool/").unwrap();
        assert!(version
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit())));
    }
}
