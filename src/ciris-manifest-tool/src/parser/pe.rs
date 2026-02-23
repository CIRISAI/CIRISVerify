//! PE binary parsing for Windows.

use goblin::pe::PE;

use super::{FunctionInfo, ParseError, ParsedBinary};

// PE machine type constants
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

/// Parse a PE binary and extract function information.
pub fn parse_pe(
    data: &[u8],
    pe: &PE,
    filter_prefix: Option<&str>,
) -> Result<ParsedBinary, ParseError> {
    // Find the .text section
    let text_section = pe
        .sections
        .iter()
        .find(|s| {
            let name = String::from_utf8_lossy(&s.name);
            name.trim_matches('\0') == ".text"
        })
        .ok_or(ParseError::NoCodeSection)?;

    let code_section_offset = u64::from(text_section.pointer_to_raw_data);
    let code_section_size = u64::from(text_section.size_of_raw_data);
    let code_section_vaddr = u64::from(text_section.virtual_address) + pe.image_base as u64;

    // Extract functions from export table
    let mut functions = Vec::new();

    for export in &pe.exports {
        let Some(name) = export.name else {
            continue;
        };

        // Apply filter if specified
        if let Some(prefix) = filter_prefix {
            if !name.starts_with(prefix) {
                continue;
            }
        }

        // Get the RVA and convert to absolute address
        let rva = export.rva;
        if rva == 0 {
            continue;
        }
        let addr = rva as u64 + pe.image_base as u64;

        // Check if in .text section
        let section_start = u64::from(text_section.virtual_address) + pe.image_base as u64;
        let section_end = section_start + u64::from(text_section.virtual_size);

        if addr >= section_start && addr < section_end {
            functions.push(FunctionInfo {
                name: name.to_string(),
                // Convert virtual address to offset from code section base
                offset: addr - code_section_vaddr,
                size: 0, // Will be computed below
            });
        }
    }

    // Sort by offset
    functions.sort_by_key(|f| f.offset);

    // Compute sizes based on gaps
    // Since offsets are now relative to code section base, the boundary
    // is just the code section size
    for i in 0..functions.len() {
        let end = if i + 1 < functions.len() {
            functions[i + 1].offset
        } else {
            code_section_size
        };
        functions[i].size = end - functions[i].offset;
    }

    Ok(ParsedBinary {
        data: data.to_vec(),
        functions,
        code_section_offset,
        code_section_size,
        code_section_vaddr,
    })
}

/// Detect the target triple from a PE binary.
pub fn detect_pe_target(pe: &PE) -> String {
    let arch = match pe.header.coff_header.machine {
        IMAGE_FILE_MACHINE_AMD64 => "x86_64",
        IMAGE_FILE_MACHINE_I386 => "i686",
        IMAGE_FILE_MACHINE_ARM64 => "aarch64",
        _ => "unknown",
    };

    format!("{arch}-pc-windows-msvc")
}
