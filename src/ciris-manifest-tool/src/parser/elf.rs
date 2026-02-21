//! ELF binary parsing for Linux and Android.

use goblin::elf::Elf;

use super::{FunctionInfo, ParseError, ParsedBinary};

/// Parse an ELF binary and extract function information.
pub fn parse_elf(
    data: &[u8],
    elf: &Elf,
    filter_prefix: Option<&str>,
) -> Result<ParsedBinary, ParseError> {
    // Find the .text section
    let text_section = elf
        .section_headers
        .iter()
        .find(|sh| {
            elf.shdr_strtab
                .get_at(sh.sh_name)
                .map(|name| name == ".text")
                .unwrap_or(false)
        })
        .ok_or(ParseError::NoCodeSection)?;

    let code_section_offset = text_section.sh_offset;
    let code_section_size = text_section.sh_size;
    let code_section_vaddr = text_section.sh_addr;

    // Extract functions from symbol table
    let mut functions = Vec::new();

    for sym in &elf.syms {
        // Only consider function symbols
        if sym.st_type() != goblin::elf::sym::STT_FUNC {
            continue;
        }

        // Skip undefined symbols
        if sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize {
            continue;
        }

        // Get symbol name
        let name = match elf.strtab.get_at(sym.st_name) {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };

        // Apply filter if specified
        if let Some(prefix) = filter_prefix {
            if !name.starts_with(prefix) {
                continue;
            }
        }

        // Only include functions in the .text section
        if sym.st_value >= code_section_vaddr
            && sym.st_value < code_section_vaddr + code_section_size
        {
            functions.push(FunctionInfo {
                name: name.to_string(),
                offset: sym.st_value,
                size: sym.st_size,
            });
        }
    }

    // Also check dynamic symbols (for shared libraries)
    for sym in &elf.dynsyms {
        if sym.st_type() != goblin::elf::sym::STT_FUNC {
            continue;
        }

        if sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize {
            continue;
        }

        let name = match elf.dynstrtab.get_at(sym.st_name) {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };

        if let Some(prefix) = filter_prefix {
            if !name.starts_with(prefix) {
                continue;
            }
        }

        // Avoid duplicates
        if functions.iter().any(|f| f.name == name) {
            continue;
        }

        if sym.st_value >= code_section_vaddr
            && sym.st_value < code_section_vaddr + code_section_size
        {
            functions.push(FunctionInfo {
                name: name.to_string(),
                offset: sym.st_value,
                size: sym.st_size,
            });
        }
    }

    // Sort by offset for deterministic output
    functions.sort_by_key(|f| f.offset);

    Ok(ParsedBinary {
        data: data.to_vec(),
        functions,
        code_section_offset,
        code_section_size,
        code_section_vaddr,
    })
}

/// Detect the target triple from an ELF binary.
pub fn detect_elf_target(elf: &Elf) -> String {
    use goblin::elf::header::{EM_386, EM_AARCH64, EM_ARM, EM_X86_64};

    let arch = match elf.header.e_machine {
        EM_X86_64 => "x86_64",
        EM_386 => "i686",
        EM_AARCH64 => "aarch64",
        EM_ARM => "arm",
        _ => "unknown",
    };

    // Detect OS from ELF OS/ABI
    let os = match elf.header.e_ident[goblin::elf::header::EI_OSABI] {
        goblin::elf::header::ELFOSABI_LINUX | goblin::elf::header::ELFOSABI_NONE => {
            // Check for Android by looking for specific sections or notes
            // For now, assume Linux unless we can detect Android
            "unknown-linux-gnu"
        },
        _ => "unknown-linux-gnu",
    };

    format!("{}-{}", arch, os)
}
