//! Mach-O binary parsing for macOS and iOS.

use goblin::mach::{Mach, MachO};

use super::{FunctionInfo, ParseError, ParsedBinary};

/// Parse a Mach-O binary and extract function information.
pub fn parse_macho(
    data: &[u8],
    mach: &Mach,
    filter_prefix: Option<&str>,
) -> Result<ParsedBinary, ParseError> {
    match mach {
        Mach::Binary(macho) => parse_single_macho(data, macho, filter_prefix),
        Mach::Fat(fat) => {
            // For fat binaries, parse the first architecture
            // In practice, the CI should build thin binaries per-target
            let arches = fat.arches()?;
            if let Some(arch) = arches.first() {
                let slice = &data[arch.offset as usize..(arch.offset + arch.size) as usize];
                let macho = MachO::parse(slice, 0)?;
                parse_single_macho(slice, &macho, filter_prefix)
            } else {
                Err(ParseError::UnsupportedFormat)
            }
        },
    }
}

fn parse_single_macho(
    data: &[u8],
    macho: &MachO,
    filter_prefix: Option<&str>,
) -> Result<ParsedBinary, ParseError> {
    // Find the __TEXT,__text section and __TEXT segment
    let mut code_section_offset = 0u64;
    let mut code_section_size = 0u64;
    let mut code_section_vaddr = 0u64;
    let mut exec_segment_vaddr = 0u64;

    for segment in &macho.segments {
        let segname = segment.name().unwrap_or("");
        if segname == "__TEXT" {
            // Store segment vmaddr - this is what dyld loads
            exec_segment_vaddr = segment.vmaddr;
            for (section, _) in segment.sections()? {
                let sectname = section.name().unwrap_or("");
                if sectname == "__text" {
                    code_section_offset = u64::from(section.offset);
                    code_section_size = section.size;
                    code_section_vaddr = section.addr;
                    break;
                }
            }
        }
    }

    if code_section_size == 0 {
        return Err(ParseError::NoCodeSection);
    }

    // If we couldn't find segment vaddr, fall back to section vaddr
    if exec_segment_vaddr == 0 {
        exec_segment_vaddr = code_section_vaddr;
    }

    // Extract functions from symbol table
    let mut functions = Vec::new();

    if let Some(ref symbols) = macho.symbols {
        for sym_result in symbols {
            let Ok((name, nlist)) = sym_result else {
                continue;
            };

            // Skip undefined and debug symbols
            if nlist.is_undefined() || nlist.is_stab() {
                continue;
            }

            // Check if it's in the __TEXT segment
            if nlist.n_sect == 0 {
                continue;
            }

            // Get the name (strip leading underscore common in Mach-O)
            let clean_name = name.strip_prefix('_').unwrap_or(name);

            // Apply filter if specified
            if let Some(prefix) = filter_prefix {
                if !clean_name.starts_with(prefix) {
                    continue;
                }
            }

            // We don't have reliable size information in Mach-O nlist
            // We'll estimate size based on the next symbol's offset
            if nlist.n_value >= code_section_vaddr
                && nlist.n_value < code_section_vaddr + code_section_size
            {
                functions.push(FunctionInfo {
                    name: clean_name.to_string(),
                    // Convert virtual address to offset from __TEXT SEGMENT base
                    // This matches what dyld maps and what runtime code base detection finds
                    offset: nlist.n_value - exec_segment_vaddr,
                    size: 0, // Will be computed below
                });
            }
        }
    }

    // Sort by offset
    functions.sort_by_key(|f| f.offset);

    // Compute sizes based on gaps between functions
    // Offsets are relative to segment, so max offset is section end relative to segment
    let section_end_offset = (code_section_vaddr - exec_segment_vaddr) + code_section_size;
    for i in 0..functions.len() {
        let end = if i + 1 < functions.len() {
            functions[i + 1].offset
        } else {
            section_end_offset
        };
        functions[i].size = end - functions[i].offset;
    }

    Ok(ParsedBinary {
        data: data.to_vec(),
        functions,
        code_section_offset,
        code_section_size,
        code_section_vaddr,
        exec_segment_vaddr,
    })
}

/// Detect the target triple from a Mach-O binary.
pub fn detect_macho_target(mach: &Mach) -> String {
    use goblin::mach::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};

    let cputype = match mach {
        Mach::Binary(macho) => macho.header.cputype(),
        Mach::Fat(fat) => {
            if let Ok(arches) = fat.arches() {
                if let Some(arch) = arches.first() {
                    arch.cputype()
                } else {
                    return "unknown-apple-darwin".to_string();
                }
            } else {
                return "unknown-apple-darwin".to_string();
            }
        },
    };

    let arch = match cputype {
        CPU_TYPE_X86_64 => "x86_64",
        CPU_TYPE_ARM64 => "aarch64",
        _ => "unknown",
    };

    // Can't easily distinguish macOS vs iOS from the binary alone
    // The CI should provide this via --target flag
    format!("{arch}-apple-darwin")
}
