// SPDX-License-Identifier: GPL-2.0-or-later

//! Minimal ELF64 parser for x86_64 and aarch64 executables.
//!
//! Supports both ET_EXEC (static) and ET_DYN (PIE / shared library)
//! binaries with PT_LOAD segments. No section headers, no interpreter
//! handling. Returns metadata only — the caller allocates memory and
//! copies segments.

use alloc::vec::Vec;

// ── ELF constants ───────────────────────────────────────────────────

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
#[cfg(target_arch = "x86_64")]
const EM_X86_64: u16 = 0x3E;
#[cfg(target_arch = "aarch64")]
const EM_AARCH64: u16 = 0xB7;
const PT_LOAD: u32 = 1;

const ELF64_HEADER_SIZE: usize = 64;
const ELF64_PHDR_SIZE: usize = 56;

// ── Segment permission flags ────────────────────────────────────────

const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

// ── Error type ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    TooShort,
    BadMagic,
    Not64Bit,
    NotLittleEndian,
    NotExecutable,
    UnsupportedMachine,
    InvalidPhdr,
    SegmentOutOfBounds,
}

// ── ELF type ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfType {
    Exec,
    Dyn,
}

// ── Parsed types ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentFlags {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSegment {
    /// Virtual address the segment expects to be loaded at.
    pub vaddr: u64,
    /// Offset into the ELF file where segment data starts.
    pub offset: u64,
    /// Bytes to copy from the ELF file.
    pub filesz: u64,
    /// Total memory size (filesz + zero-fill for .bss).
    pub memsz: u64,
    /// Segment permissions.
    pub flags: SegmentFlags,
    /// Requested alignment.
    pub align: u64,
}

/// Parsed ELF metadata. Does not contain the actual segment data —
/// use `offset` and `filesz` to slice the original ELF bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedElf {
    pub entry_point: u64,
    pub elf_type: ElfType,
    pub segments: Vec<ElfSegment>,
}

// ── Little-endian helpers ───────────────────────────────────────────

fn u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

// ── Parser ──────────────────────────────────────────────────────────

/// Parse an ELF64 binary from raw bytes.
///
/// Returns metadata about loadable segments, the entry point, and
/// whether the binary is ET_EXEC or ET_DYN. Rejects other ELF types
/// (e.g. ET_REL, ET_CORE).
pub fn parse_elf(data: &[u8]) -> Result<ParsedElf, ElfError> {
    if data.len() < ELF64_HEADER_SIZE {
        return Err(ElfError::TooShort);
    }

    // Validate ELF magic
    if data[0..4] != ELF_MAGIC {
        return Err(ElfError::BadMagic);
    }

    // Must be 64-bit
    if data[4] != ELFCLASS64 {
        return Err(ElfError::Not64Bit);
    }

    // Must be little-endian
    if data[5] != ELFDATA2LSB {
        return Err(ElfError::NotLittleEndian);
    }

    // Must be ET_EXEC or ET_DYN
    let e_type = u16_le(data, 16);
    let elf_type = match e_type {
        ET_EXEC => ElfType::Exec,
        ET_DYN => ElfType::Dyn,
        _ => return Err(ElfError::NotExecutable),
    };

    // Must be the native machine type
    let e_machine = u16_le(data, 18);
    #[cfg(target_arch = "x86_64")]
    let expected_machine = EM_X86_64;
    #[cfg(target_arch = "aarch64")]
    let expected_machine = EM_AARCH64;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Err(ElfError::UnsupportedMachine);

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if e_machine != expected_machine {
        return Err(ElfError::UnsupportedMachine);
    }

    let entry_point = u64_le(data, 24);
    let e_phoff = u64_le(data, 32) as usize;
    let e_phentsize = u16_le(data, 54) as usize;
    let e_phnum = u16_le(data, 56) as usize;

    // Validate phdr table doesn't overlap the ELF header
    if e_phnum > 0 && e_phoff < ELF64_HEADER_SIZE {
        return Err(ElfError::InvalidPhdr);
    }

    // Validate program header table fits (only when headers exist)
    if e_phnum > 0 && e_phentsize < ELF64_PHDR_SIZE {
        return Err(ElfError::InvalidPhdr);
    }
    let ph_end = e_phoff
        .checked_add(
            e_phnum
                .checked_mul(e_phentsize)
                .ok_or(ElfError::InvalidPhdr)?,
        )
        .ok_or(ElfError::InvalidPhdr)?;
    if ph_end > data.len() {
        return Err(ElfError::TooShort);
    }

    // Parse PT_LOAD segments
    let mut segments = Vec::new();
    for i in 0..e_phnum {
        let ph = &data[e_phoff + i * e_phentsize..];
        let p_type = u32_le(ph, 0);
        if p_type != PT_LOAD {
            continue;
        }

        let p_flags = u32_le(ph, 4);
        let p_offset = u64_le(ph, 8);
        let p_vaddr = u64_le(ph, 16);
        let p_filesz = u64_le(ph, 32);
        let p_memsz = u64_le(ph, 40);
        let p_align = u64_le(ph, 48);

        // Validate memsz >= filesz (ELF spec requirement)
        if p_memsz < p_filesz {
            return Err(ElfError::SegmentOutOfBounds);
        }

        // Validate segment data fits in the ELF
        let seg_end = p_offset
            .checked_add(p_filesz)
            .ok_or(ElfError::SegmentOutOfBounds)?;
        if seg_end as usize > data.len() {
            return Err(ElfError::SegmentOutOfBounds);
        }

        segments.push(ElfSegment {
            vaddr: p_vaddr,
            offset: p_offset,
            filesz: p_filesz,
            memsz: p_memsz,
            flags: SegmentFlags {
                read: p_flags & PF_R != 0,
                write: p_flags & PF_W != 0,
                execute: p_flags & PF_X != 0,
            },
            align: p_align,
        });
    }

    Ok(ParsedElf {
        entry_point,
        elf_type,
        segments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid ELF64 binary in memory for testing.
    /// `code` is placed as a PT_LOAD segment at vaddr 0x401000.
    fn build_test_elf(code: &[u8]) -> Vec<u8> {
        let mut elf = vec![0u8; 64 + 56 + code.len()];

        // ELF magic
        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT

        // e_type = ET_EXEC (2)
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());

        // e_machine — use native machine type so tests pass on any host
        #[cfg(target_arch = "x86_64")]
        elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
        #[cfg(target_arch = "aarch64")]
        elf[18..20].copy_from_slice(&0xB7u16.to_le_bytes());
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());

        // e_version, e_entry, e_phoff
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        // e_phoff = 64 (right after header)
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        // e_shoff = 0 (no section headers)
        // e_flags = 0
        // e_ehsize = 64
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        // e_phentsize = 56
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        // e_phnum = 1
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());
        // e_shentsize = 0, e_shnum = 0, e_shstrndx = 0

        // Program header (PT_LOAD)
        let ph = &mut elf[64..120];
        // p_type = PT_LOAD (1)
        ph[0..4].copy_from_slice(&1u32.to_le_bytes());
        // p_flags = PF_R | PF_X (5)
        ph[4..8].copy_from_slice(&5u32.to_le_bytes());
        // p_offset = 120 (after headers)
        ph[8..16].copy_from_slice(&120u64.to_le_bytes());
        // p_vaddr = 0x401000
        ph[16..24].copy_from_slice(&0x401000u64.to_le_bytes());
        // p_paddr = 0x401000
        ph[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        // p_filesz = code.len()
        ph[32..40].copy_from_slice(&(code.len() as u64).to_le_bytes());
        // p_memsz = code.len()
        ph[40..48].copy_from_slice(&(code.len() as u64).to_le_bytes());
        // p_align = 0x1000
        ph[48..56].copy_from_slice(&0x1000u64.to_le_bytes());

        // Code
        elf[120..120 + code.len()].copy_from_slice(code);

        elf
    }

    #[test]
    fn parse_valid_elf() {
        let code = [0xCC; 16]; // dummy code
        let elf = build_test_elf(&code);
        let parsed = parse_elf(&elf).unwrap();
        assert_eq!(parsed.entry_point, 0x401000);
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.segments[0].vaddr, 0x401000);
        assert_eq!(parsed.segments[0].filesz, 16);
        assert_eq!(parsed.segments[0].memsz, 16);
        assert!(parsed.segments[0].flags.execute);
        assert!(parsed.segments[0].flags.read);
        assert!(!parsed.segments[0].flags.write);
    }

    #[test]
    fn segment_data_correct() {
        let code = [0x90, 0x90, 0xCC]; // nop, nop, int3
        let elf = build_test_elf(&code);
        let parsed = parse_elf(&elf).unwrap();
        let seg = &parsed.segments[0];
        let data = &elf[seg.offset as usize..(seg.offset + seg.filesz) as usize];
        assert_eq!(data, &[0x90, 0x90, 0xCC]);
    }

    #[test]
    fn reject_bad_magic() {
        let mut elf = build_test_elf(&[0xCC]);
        elf[0] = 0x00; // corrupt magic
        assert_eq!(parse_elf(&elf), Err(ElfError::BadMagic));
    }

    #[test]
    fn reject_32bit_elf() {
        let mut elf = build_test_elf(&[0xCC]);
        elf[4] = 1; // ELFCLASS32
        assert_eq!(parse_elf(&elf), Err(ElfError::Not64Bit));
    }

    #[test]
    fn reject_unsupported_machine_type() {
        let mut elf = build_test_elf(&[0xCC]);
        elf[18..20].copy_from_slice(&0x03u16.to_le_bytes()); // EM_386
        assert_eq!(parse_elf(&elf), Err(ElfError::UnsupportedMachine));
    }

    #[test]
    fn accept_et_dyn() {
        let code = [0xCC; 16];
        let mut elf = build_test_elf(&code);
        // Change e_type from ET_EXEC (2) to ET_DYN (3)
        elf[16..18].copy_from_slice(&3u16.to_le_bytes());
        let parsed = parse_elf(&elf).unwrap();
        assert_eq!(parsed.entry_point, 0x401000);
        assert_eq!(parsed.segments.len(), 1);
    }

    #[test]
    fn accept_et_exec() {
        // Existing static binaries still work
        let code = [0xCC; 16];
        let elf = build_test_elf(&code);
        let parsed = parse_elf(&elf).unwrap();
        assert_eq!(parsed.entry_point, 0x401000);
    }

    #[test]
    fn reject_et_rel() {
        let mut elf = build_test_elf(&[0xCC]);
        elf[16..18].copy_from_slice(&1u16.to_le_bytes()); // ET_REL (relocatable)
        assert_eq!(parse_elf(&elf), Err(ElfError::NotExecutable));
    }

    #[test]
    fn et_dyn_reports_elf_type() {
        let code = [0xCC; 16];
        let mut elf = build_test_elf(&code);
        elf[16..18].copy_from_slice(&3u16.to_le_bytes());
        let parsed = parse_elf(&elf).unwrap();
        assert_eq!(parsed.elf_type, ElfType::Dyn);
    }

    #[test]
    fn et_exec_reports_elf_type() {
        let code = [0xCC; 16];
        let elf = build_test_elf(&code);
        let parsed = parse_elf(&elf).unwrap();
        assert_eq!(parsed.elf_type, ElfType::Exec);
    }

    #[test]
    fn reject_truncated_header() {
        let elf = vec![0x7f, b'E', b'L', b'F']; // too short
        assert_eq!(parse_elf(&elf), Err(ElfError::TooShort));
    }

    #[test]
    fn bss_segment_has_memsz_greater_than_filesz() {
        let code = [0xCC; 16];
        let mut elf = build_test_elf(&code);
        // Set memsz > filesz (simulates .bss)
        let ph_memsz = &mut elf[64 + 40..64 + 48];
        ph_memsz.copy_from_slice(&256u64.to_le_bytes());
        let parsed = parse_elf(&elf).unwrap();
        assert_eq!(parsed.segments[0].filesz, 16);
        assert_eq!(parsed.segments[0].memsz, 256);
    }

    /// Build a minimal valid ELF64 binary with a specific machine type override.
    fn build_test_elf_with_machine(code: &[u8], machine: u16) -> Vec<u8> {
        let mut elf = build_test_elf(code);
        elf[18..20].copy_from_slice(&machine.to_le_bytes());
        elf
    }

    #[test]
    fn accept_native_machine_type() {
        let code = [0xCC; 16];
        let elf = build_test_elf(&code);
        assert!(parse_elf(&elf).is_ok());
    }

    #[test]
    fn reject_foreign_machine_type() {
        let code = [0xCC; 16];
        // Use the opposite architecture's machine type
        #[cfg(target_arch = "x86_64")]
        let elf = build_test_elf_with_machine(&code, 0xB7); // EM_AARCH64
        #[cfg(target_arch = "aarch64")]
        let elf = build_test_elf_with_machine(&code, 0x3E); // EM_X86_64
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let elf = build_test_elf_with_machine(&code, 0x3E);
        assert_eq!(parse_elf(&elf), Err(ElfError::UnsupportedMachine));
    }
}
