//! Binary-format-aware hashing primitives (CIRISVerify#19, v2.0.5+).
//!
//! The CIRIS federation produces and verifies binaries across multiple
//! platforms (Linux ELF, Windows PE, iOS/macOS Mach-O). For
//! code-signing-stable hashes on Mach-O, we hash the `__TEXT` segment
//! from the page-aligned post-load-commands boundary to end-of-segment,
//! NOT the whole file — the code-signing step modifies load commands
//! (adds `LC_CODE_SIGNATURE`, shifts offsets) but never touches the
//! actual code sections inside `__TEXT`.
//!
//! Three sites consumed this algorithm before v2.0.5:
//!
//! - `ciris-verify-core::registry::compute_self_hash` — runtime L2 self-verify
//! - `release.yml::macho_text_hash` — CI release-time Python algorithm
//! - `ciris-manifest-tool::manifest::compute_file_hash` — sign-time
//!   manifest generator (BUG before v2.0.5: was using whole-file hash,
//!   structurally mismatching the runtime path)
//!
//! v2.0.5 unifies all three on this module. Sign-time and runtime now
//! compute byte-equal hashes on the same Mach-O binary.

use goblin::mach::Mach;

/// Extract the hashable code region from a Mach-O `__TEXT` segment.
///
/// Returns `Some((file_offset, size))` of the code-only portion of
/// `__TEXT`, skipping the Mach-O header and load commands. Code signing
/// modifies fields in the load commands (e.g. `LC_CODE_SIGNATURE`) but
/// never touches the actual code sections (`__text`, `__stubs`,
/// `__stub_helper`). By starting after `header + sizeofcmds`, page-
/// aligned to 4096 bytes (which is always zero-padded for signing
/// stability), we get a hash that's identical before and after `codesign`.
///
/// Returns `None` if:
/// - The bytes don't parse as Mach-O (caller should fall back to
///   whole-file hash for ELF / PE / other formats).
/// - The Mach-O doesn't contain a `__TEXT` segment (malformed binary).
///
/// For fat (universal) Mach-O binaries, the function returns the
/// region for arch slice 0. (Future enhancement: take an arch hint.
/// For CIRIS today every release ships single-arch dylibs per target.)
///
/// # Page-alignment rationale
///
/// `codesign` appends an `LC_CODE_SIGNATURE` load command (16 bytes)
/// AFTER initial codesign, changing `sizeofcmds`. The bytes between
/// `cmds_end` and `page_aligned` are zero-padded in both signed and
/// unsigned binaries, so starting the hash at `max(page_aligned,
/// seg_start)` produces an identical leading-byte set regardless of
/// signing state. The `__TEXT` segment itself is page-aligned in any
/// linker-produced Mach-O, so `page_aligned` is typically equal to or
/// less than `seg_start`.
#[must_use]
pub fn macho_text_code_region(data: &[u8]) -> Option<(usize, usize)> {
    match Mach::parse(data) {
        Ok(Mach::Binary(macho)) => macho_text_code_from_parsed(&macho),
        Ok(Mach::Fat(fat)) => {
            tracing::info!(
                "macho_text_code_region: fat binary with {} arches; using arch[0]",
                fat.narches
            );
            if let Ok(goblin::mach::SingleArch::MachO(macho)) = fat.get(0) {
                macho_text_code_from_parsed(&macho)
            } else {
                tracing::warn!("macho_text_code_region: fat arch[0] is not MachO");
                None
            }
        },
        Err(e) => {
            // Not a Mach-O. Caller falls back to whole-file hash.
            tracing::debug!("macho_text_code_region: not a Mach-O ({})", e);
            None
        },
    }
}

fn macho_text_code_from_parsed(macho: &goblin::mach::MachO) -> Option<(usize, usize)> {
    let header_size: usize = if macho.is_64 { 32 } else { 28 };
    let cmds_end = header_size + macho.header.sizeofcmds as usize;
    let page_aligned = (cmds_end + 0xFFF) & !0xFFF;

    for seg in &macho.segments {
        let name = seg.name().unwrap_or("");
        if name == "__TEXT" {
            let seg_start = seg.fileoff as usize;
            let seg_end = seg_start + seg.filesize as usize;
            let hash_start = page_aligned.max(seg_start);
            let hash_size = seg_end.saturating_sub(hash_start);
            tracing::info!(
                "macho_text_code_region: __TEXT=0x{:x}..0x{:x}, cmds_end=0x{:x}, page_aligned=0x{:x}, hashing 0x{:x}..0x{:x} ({} bytes)",
                seg_start, seg_end, cmds_end, page_aligned, hash_start, hash_start + hash_size, hash_size
            );
            return Some((hash_start, hash_size));
        }
    }
    tracing::warn!("macho_text_code_region: no __TEXT segment found");
    None
}

/// Compute the canonical `binary_hash` for a binary's bytes.
///
/// Federation-wide single source of truth: sign-time (manifest tool)
/// and runtime (`compute_self_hash`) call this function with the same
/// bytes and get identical output.
///
/// Algorithm:
/// - **Mach-O** (iOS / macOS `.dylib`, fat universal binaries):
///   `sha256(__TEXT page-aligned code region)`. Stable across `codesign`.
/// - **Everything else** (ELF, PE, fallback): `sha256(whole file)`.
///
/// Returns the raw 32-byte SHA-256 digest (caller adds the `"sha256:"`
/// prefix if desired). Lossless: any binary can be hashed.
#[must_use]
pub fn canonical_binary_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    if let Some((offset, size)) = macho_text_code_region(data) {
        hasher.update(&data[offset..offset + size]);
    } else {
        hasher.update(data);
    }
    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Non-Mach-O data → falls through to None.
    #[test]
    fn elf_bytes_return_none() {
        // ELF magic: 0x7F 'E' 'L' 'F'
        let mut elf = vec![0x7F, 0x45, 0x4C, 0x46];
        elf.extend_from_slice(&[0u8; 60]); // pad to a non-trivial buffer
        assert!(macho_text_code_region(&elf).is_none());
    }

    #[test]
    fn pe_bytes_return_none() {
        // PE magic: "MZ" at offset 0
        let mut pe = vec![0x4D, 0x5A];
        pe.extend_from_slice(&[0u8; 62]);
        assert!(macho_text_code_region(&pe).is_none());
    }

    #[test]
    fn random_bytes_return_none() {
        let junk = vec![0xAB; 1024];
        assert!(macho_text_code_region(&junk).is_none());
    }

    #[test]
    fn empty_bytes_return_none() {
        assert!(macho_text_code_region(&[]).is_none());
    }

    /// `canonical_binary_hash` on ELF/PE/random bytes equals
    /// `sha256(whole bytes)` — proves ELF/PE regression-free.
    #[test]
    fn canonical_binary_hash_equals_whole_file_for_non_macho() {
        use sha2::{Digest, Sha256};
        let elf_bytes = {
            let mut v = vec![0x7F, 0x45, 0x4C, 0x46];
            v.extend_from_slice(&[0xAA; 100]);
            v
        };
        let mut expected = Sha256::new();
        expected.update(&elf_bytes);
        let expected_bytes: [u8; 32] = expected.finalize().into();
        assert_eq!(canonical_binary_hash(&elf_bytes), expected_bytes);
    }
}
