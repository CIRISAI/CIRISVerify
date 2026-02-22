//! Binary parsing for function extraction.
//!
//! Supports ELF (Linux/Android), Mach-O (macOS/iOS), and PE (Windows) formats.
//! Uses the `goblin` crate for cross-platform parsing.

mod elf;
mod macho;
mod pe;

use std::path::Path;

use thiserror::Error;

/// Information about a function extracted from a binary.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Function name (may be mangled).
    pub name: String,
    /// Offset from the start of the code section.
    pub offset: u64,
    /// Size in bytes.
    pub size: u64,
}

/// Error during binary parsing.
#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum ParseError {
    #[error("Failed to read file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to parse binary: {0}")]
    GoblinError(#[from] goblin::error::Error),

    #[error("Unsupported binary format")]
    UnsupportedFormat,

    #[error("No code section found")]
    NoCodeSection,

    #[error("Function '{0}' not found")]
    FunctionNotFound(String),
}

/// Result of parsing a binary.
pub struct ParsedBinary {
    /// Raw binary data.
    pub data: Vec<u8>,
    /// Functions found in the binary.
    pub functions: Vec<FunctionInfo>,
    /// Offset of the code section in the file.
    pub code_section_offset: u64,
    /// Size of the code section.
    #[allow(dead_code)]
    pub code_section_size: u64,
    /// Virtual address base of the code section.
    pub code_section_vaddr: u64,
}

impl ParsedBinary {
    /// Get the bytes of a function.
    #[allow(clippy::cast_possible_truncation)]
    pub fn function_bytes(&self, func: &FunctionInfo) -> Option<&[u8]> {
        // Function offset is relative to code section vaddr
        // We need to convert to file offset
        let file_offset = self.code_section_offset + (func.offset - self.code_section_vaddr);
        let start = file_offset as usize;
        let end = start + func.size as usize;

        if end <= self.data.len() {
            Some(&self.data[start..end])
        } else {
            None
        }
    }
}

/// Parse a binary file and extract function information.
///
/// # Arguments
///
/// * `path` - Path to the binary file
/// * `filter_prefix` - Optional prefix to filter function names (e.g., "`ciris_verify`_")
///
/// # Returns
///
/// Parsed binary with function information.
pub fn parse_binary(path: &Path, filter_prefix: Option<&str>) -> Result<ParsedBinary, ParseError> {
    let data = std::fs::read(path)?;

    match goblin::Object::parse(&data)? {
        goblin::Object::Elf(elf) => elf::parse_elf(&data, &elf, filter_prefix),
        goblin::Object::Mach(mach) => macho::parse_macho(&data, &mach, filter_prefix),
        goblin::Object::PE(pe) => pe::parse_pe(&data, &pe, filter_prefix),
        _ => Err(ParseError::UnsupportedFormat),
    }
}

/// Detect the target triple from a binary file.
pub fn detect_target(path: &Path) -> Result<String, ParseError> {
    let data = std::fs::read(path)?;

    match goblin::Object::parse(&data)? {
        goblin::Object::Elf(elf) => Ok(elf::detect_elf_target(&elf)),
        goblin::Object::Mach(mach) => Ok(macho::detect_macho_target(&mach)),
        goblin::Object::PE(pe) => Ok(pe::detect_pe_target(&pe)),
        _ => Err(ParseError::UnsupportedFormat),
    }
}
