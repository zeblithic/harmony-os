// SPDX-License-Identifier: GPL-2.0-or-later

//! Minimal ELF64 parser for x86_64 and aarch64 executables.
//!
//! Supports both ET_EXEC (static) and ET_DYN (PIE / shared library)
//! binaries. Parses PT_LOAD segments and PT_INTERP (interpreter path).
//! Exposes program header metadata for auxiliary vector construction.
//! Returns metadata only — the caller allocates memory and copies
//! segments.

use alloc::string::String;
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
const PT_INTERP: u32 = 3;
const PT_TLS: u32 = 7;

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
    InterpreterPathInvalid,
    /// First PT_LOAD segment has `p_offset > p_vaddr`, producing a
    /// nonsensical load bias.  Reject rather than silently wrapping.
    InvalidLoadBias,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsInfo {
    /// Virtual address of the TLS template data (.tdata).
    pub vaddr: u64,
    /// Size of initialized TLS data (.tdata) in the ELF file.
    pub filesz: u64,
    /// Total TLS size in memory (.tdata + .tbss zero-fill).
    pub memsz: u64,
    /// TLS alignment requirement.
    pub align: u64,
}

/// Parsed ELF metadata. Does not contain the actual segment data —
/// use `offset` and `filesz` to slice the original ELF bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedElf {
    pub entry_point: u64,
    pub elf_type: ElfType,
    pub segments: Vec<ElfSegment>,
    /// Interpreter path from PT_INTERP (None for statically-linked binaries).
    pub interpreter: Option<String>,
    /// Offset of the program header table in the ELF file.
    pub phdr_offset: u64,
    /// Size of each program header entry.
    pub phdr_entry_size: u16,
    /// Number of program header entries.
    pub phdr_count: u16,
    /// Load bias: `first_load_vaddr - first_load_offset`.
    ///
    /// For ET_EXEC, this is typically the first PT_LOAD's vaddr (e.g.
    /// 0x400000).  For ET_DYN, it is typically 0 (first PT_LOAD has
    /// vaddr=0, offset=0).  Used to compute the in-memory address of
    /// program headers: `base + load_bias + phdr_offset`.
    pub load_bias: u64,
    /// Thread-local storage segment metadata (None if no PT_TLS).
    pub tls: Option<TlsInfo>,
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

    // Parse program headers: PT_LOAD segments, PT_INTERP, and PT_TLS
    let mut segments = Vec::new();
    let mut interpreter = None;
    let mut tls = None;

    for i in 0..e_phnum {
        let ph = &data[e_phoff + i * e_phentsize..];
        let p_type = u32_le(ph, 0);

        match p_type {
            PT_LOAD => {
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
            PT_INTERP => {
                let p_offset = u64_le(ph, 8) as usize;
                let p_filesz = u64_le(ph, 32) as usize;

                if p_offset
                    .checked_add(p_filesz)
                    .map_or(true, |end| end > data.len())
                {
                    return Err(ElfError::InterpreterPathInvalid);
                }

                let interp_bytes = &data[p_offset..p_offset + p_filesz];
                let path = interp_bytes.strip_suffix(&[0]).unwrap_or(interp_bytes);
                let path_str =
                    core::str::from_utf8(path).map_err(|_| ElfError::InterpreterPathInvalid)?;
                interpreter = Some(String::from(path_str));
            }
            PT_TLS => {
                let p_vaddr = u64_le(ph, 16);
                let p_filesz = u64_le(ph, 32);
                let p_memsz = u64_le(ph, 40);
                let p_align = u64_le(ph, 48);
                tls = Some(TlsInfo {
                    vaddr: p_vaddr,
                    filesz: p_filesz,
                    memsz: p_memsz,
                    align: p_align,
                });
            }
            _ => {}
        }
    }

    // Compute load_bias from the first PT_LOAD segment.
    // This is `p_vaddr - p_offset` for the segment that contains the
    // ELF header (typically offset=0).  Used to convert phdr_offset
    // (a file offset) into an in-memory virtual address.
    let load_bias = match segments.first() {
        Some(s) => s
            .vaddr
            .checked_sub(s.offset)
            .ok_or(ElfError::InvalidLoadBias)?,
        None => 0,
    };

    Ok(ParsedElf {
        entry_point,
        elf_type,
        segments,
        interpreter,
        phdr_offset: e_phoff as u64,
        phdr_entry_size: e_phentsize as u16,
        phdr_count: e_phnum as u16,
        load_bias,
        tls,
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

    /// Build a test ELF with a PT_INTERP segment in addition to PT_LOAD.
    fn build_test_elf_with_interp(code: &[u8], interp: &[u8]) -> Vec<u8> {
        let phdr_size = 56;
        let phnum = 2;
        let code_offset = 64 + phnum * phdr_size;
        let interp_offset = code_offset + code.len();
        let total = interp_offset + interp.len();
        let mut elf = vec![0u8; total];

        // ELF header
        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT
        elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        #[cfg(target_arch = "x86_64")]
        elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
        #[cfg(target_arch = "aarch64")]
        elf[18..20].copy_from_slice(&0xB7u16.to_le_bytes());
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&(phnum as u16).to_le_bytes());

        // PT_LOAD program header
        let ph = &mut elf[64..64 + phdr_size];
        ph[0..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        ph[4..8].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
        ph[8..16].copy_from_slice(&(code_offset as u64).to_le_bytes());
        ph[16..24].copy_from_slice(&0x401000u64.to_le_bytes());
        ph[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        ph[32..40].copy_from_slice(&(code.len() as u64).to_le_bytes());
        ph[40..48].copy_from_slice(&(code.len() as u64).to_le_bytes());
        ph[48..56].copy_from_slice(&0x1000u64.to_le_bytes());

        // PT_INTERP program header
        let pt_interp: u32 = 3;
        let iph = &mut elf[64 + phdr_size..64 + 2 * phdr_size];
        iph[0..4].copy_from_slice(&pt_interp.to_le_bytes());
        iph[4..8].copy_from_slice(&4u32.to_le_bytes()); // PF_R
        iph[8..16].copy_from_slice(&(interp_offset as u64).to_le_bytes());
        iph[32..40].copy_from_slice(&(interp.len() as u64).to_le_bytes());
        iph[40..48].copy_from_slice(&(interp.len() as u64).to_le_bytes());
        iph[48..56].copy_from_slice(&1u64.to_le_bytes());

        elf[code_offset..code_offset + code.len()].copy_from_slice(code);
        elf[interp_offset..interp_offset + interp.len()].copy_from_slice(interp);

        elf
    }

    #[test]
    fn parse_pt_interp() {
        let interp_path = b"/lib/ld-musl-aarch64.so.1\0";
        let elf = build_test_elf_with_interp(&[0xCC; 16], interp_path);
        let parsed = parse_elf(&elf).unwrap();
        assert_eq!(
            parsed.interpreter.as_deref(),
            Some("/lib/ld-musl-aarch64.so.1")
        );
    }

    #[test]
    fn no_interp_for_static_elf() {
        let code = [0xCC; 16];
        let elf = build_test_elf(&code);
        let parsed = parse_elf(&elf).unwrap();
        assert!(parsed.interpreter.is_none());
    }

    #[test]
    fn phdr_metadata_present() {
        let code = [0xCC; 16];
        let elf = build_test_elf(&code);
        let parsed = parse_elf(&elf).unwrap();
        assert_eq!(parsed.phdr_offset, 64);
        assert_eq!(parsed.phdr_entry_size, 56);
        assert_eq!(parsed.phdr_count, 1);
    }

    #[test]
    fn interp_with_phdr_metadata() {
        let interp_path = b"/lib/ld-musl-aarch64.so.1\0";
        let elf = build_test_elf_with_interp(&[0xCC; 16], interp_path);
        let parsed = parse_elf(&elf).unwrap();
        assert_eq!(parsed.phdr_count, 2); // PT_LOAD + PT_INTERP
    }

    #[test]
    fn invalid_interp_path() {
        let mut elf = build_test_elf_with_interp(&[0xCC; 16], b"/lib/ld\0");
        // Corrupt the PT_INTERP offset to point past the file
        let interp_ph_start = 64 + 56; // second phdr
        let bad_offset = (elf.len() as u64 + 100).to_le_bytes();
        elf[interp_ph_start + 8..interp_ph_start + 16].copy_from_slice(&bad_offset);
        assert_eq!(parse_elf(&elf), Err(ElfError::InterpreterPathInvalid));
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

    /// Build a test ELF with a PT_TLS segment in addition to PT_LOAD.
    fn build_test_elf_with_tls(
        code: &[u8],
        tls_data: &[u8],
        tls_memsz: u64,
        tls_align: u64,
    ) -> Vec<u8> {
        let phdr_size = 56;
        let phnum = 2; // PT_LOAD + PT_TLS
        let code_offset = 64 + phnum * phdr_size;
        let tls_offset = code_offset + code.len();
        let total = tls_offset + tls_data.len();
        let mut elf = vec![0u8; total];

        // ELF header
        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        #[cfg(target_arch = "x86_64")]
        elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
        #[cfg(target_arch = "aarch64")]
        elf[18..20].copy_from_slice(&0xB7u16.to_le_bytes());
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&(phnum as u16).to_le_bytes());

        // PT_LOAD program header
        let ph = &mut elf[64..64 + phdr_size];
        ph[0..4].copy_from_slice(&1u32.to_le_bytes());
        ph[4..8].copy_from_slice(&5u32.to_le_bytes());
        ph[8..16].copy_from_slice(&(code_offset as u64).to_le_bytes());
        ph[16..24].copy_from_slice(&0x401000u64.to_le_bytes());
        ph[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        ph[32..40].copy_from_slice(&(code.len() as u64).to_le_bytes());
        ph[40..48].copy_from_slice(&(code.len() as u64).to_le_bytes());
        ph[48..56].copy_from_slice(&0x1000u64.to_le_bytes());

        // PT_TLS program header
        let tph = &mut elf[64 + phdr_size..64 + 2 * phdr_size];
        tph[0..4].copy_from_slice(&7u32.to_le_bytes());
        tph[4..8].copy_from_slice(&4u32.to_le_bytes());
        tph[8..16].copy_from_slice(&(tls_offset as u64).to_le_bytes());
        tph[16..24].copy_from_slice(&0x403000u64.to_le_bytes());
        tph[24..32].copy_from_slice(&0x403000u64.to_le_bytes());
        tph[32..40].copy_from_slice(&(tls_data.len() as u64).to_le_bytes());
        tph[40..48].copy_from_slice(&tls_memsz.to_le_bytes());
        tph[48..56].copy_from_slice(&tls_align.to_le_bytes());

        elf[code_offset..code_offset + code.len()].copy_from_slice(code);
        elf[tls_offset..tls_offset + tls_data.len()].copy_from_slice(tls_data);

        elf
    }

    #[test]
    fn parse_pt_tls() {
        let elf = build_test_elf_with_tls(&[0xCC; 16], &[0x42; 8], 32, 16);
        let parsed = parse_elf(&elf).unwrap();

        let tls = parsed.tls.as_ref().expect("PT_TLS should be parsed");
        assert_eq!(tls.vaddr, 0x403000);
        assert_eq!(tls.filesz, 8);
        assert_eq!(tls.memsz, 32);
        assert_eq!(tls.align, 16);
    }

    #[test]
    fn no_tls_for_elf_without_pt_tls() {
        let code = [0xCC; 16];
        let elf = build_test_elf(&code);
        let parsed = parse_elf(&elf).unwrap();
        assert!(parsed.tls.is_none());
    }
}
