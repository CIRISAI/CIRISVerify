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
                .is_some_and(|name| name == ".text")
        })
        .ok_or(ParseError::NoCodeSection)?;

    let code_section_offset = text_section.sh_offset;
    let code_section_size = text_section.sh_size;
    let code_section_vaddr = text_section.sh_addr;

    // Find the executable LOAD segment that contains .text
    // This is what the runtime linker maps, and what /proc/self/maps shows
    // We need offsets relative to this segment's base, not .text section
    let exec_segment_vaddr = elf
        .program_headers
        .iter()
        .find(|ph| {
            ph.p_type == goblin::elf::program_header::PT_LOAD
                && (ph.p_flags & goblin::elf::program_header::PF_X) != 0
                && code_section_vaddr >= ph.p_vaddr
                && code_section_vaddr < ph.p_vaddr + ph.p_memsz
        })
        .map_or(code_section_vaddr, |ph| ph.p_vaddr); // Fallback to section vaddr if not found

    tracing::info!(
        "parse_elf: .text section vaddr=0x{:x}, exec segment vaddr=0x{:x}, delta=0x{:x}",
        code_section_vaddr,
        exec_segment_vaddr,
        code_section_vaddr - exec_segment_vaddr
    );

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
                // Convert virtual address to offset from EXECUTABLE SEGMENT base
                // Runtime verification adds this offset to the segment load address
                // (which is what /proc/self/maps shows for r-xp regions)
                offset: sym.st_value - exec_segment_vaddr,
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
                // Convert virtual address to offset from EXECUTABLE SEGMENT base
                offset: sym.st_value - exec_segment_vaddr,
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
        exec_segment_vaddr,
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
    // TODO: Check for Android by looking for specific sections or notes
    // For now, assume Linux for all ELF binaries
    let os = "unknown-linux-gnu";

    format!("{arch}-{os}")
}
