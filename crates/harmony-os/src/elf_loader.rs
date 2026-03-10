// SPDX-License-Identifier: GPL-2.0-or-later

//! ELF loader abstraction and interpreter-aware loader implementation.
//!
//! Provides the [`ElfLoader`] trait for loading ELF binaries into a
//! process address space via a [`SyscallBackend`], and
//! [`InterpreterLoader`] — the first concrete implementation that
//! handles both static (ET_EXEC) and dynamic (ET_DYN with PT_INTERP)
//! executables.

extern crate alloc;

use alloc::vec::Vec;

use harmony_microkernel::vm::{FrameClassification, PageFlags};
use harmony_microkernel::{Fid, IpcError, OpenMode};

use crate::elf::{parse_elf, ElfError, ElfType, ParsedElf, SegmentFlags};
use crate::linuxulator::SyscallBackend;

// ── Auxiliary vector constants ──────────────────────────────────────

/// Linux auxiliary vector entry types (from `<elf.h>`).
pub mod auxv {
    pub const AT_NULL: u64 = 0;
    pub const AT_PHDR: u64 = 3;
    pub const AT_PHENT: u64 = 4;
    pub const AT_PHNUM: u64 = 5;
    pub const AT_PAGESZ: u64 = 6;
    pub const AT_BASE: u64 = 7;
    pub const AT_ENTRY: u64 = 9;
    pub const AT_RANDOM: u64 = 25;
}

// ── Page alignment helpers ──────────────────────────────────────────

const PAGE_SIZE: u64 = 4096;

/// Round `addr` down to the nearest page boundary.
fn page_floor(addr: u64) -> u64 {
    addr & !(PAGE_SIZE - 1)
}

/// Round `size` up to the nearest page multiple.
///
/// Returns `None` if the addition would overflow (e.g. `size` near
/// `u64::MAX`).
fn page_ceil(size: u64) -> Option<u64> {
    size.checked_add(PAGE_SIZE - 1)
        .map(|v| v & !(PAGE_SIZE - 1))
}

// ── Error type ──────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ElfLoadError {
    ParseError(ElfError),
    InterpreterNotFound,
    InterpreterParseError(ElfError),
    BackendError(IpcError),
    OverlappingSegments,
    /// A PT_LOAD segment has both W and X flags — rejected by W^X policy.
    WXViolation,
}

// ── Load result ─────────────────────────────────────────────────────

#[derive(Debug)]
pub struct LoadResult {
    /// Entry point to jump to (interpreter's entry for dynamic,
    /// exe's for static).
    pub entry_point: u64,
    /// Auxiliary vector entries for stack construction.
    pub auxv: Vec<(u64, u64)>,
    /// Base address where executable was loaded (0 for ET_EXEC).
    pub exe_base: u64,
    /// Base address where interpreter was loaded (0 if no interpreter).
    pub interp_base: u64,
}

// ── ElfLoader trait ─────────────────────────────────────────────────

/// Abstraction for loading an ELF binary into a process address space.
///
/// Implementations parse the ELF, map segments via the backend, and
/// optionally load a dynamic linker (interpreter).
pub trait ElfLoader {
    fn load(
        &mut self,
        elf_bytes: &[u8],
        backend: &mut dyn SyscallBackend,
    ) -> Result<LoadResult, ElfLoadError>;
}

// ── InterpreterLoader ───────────────────────────────────────────────

/// Loads ELF executables with optional interpreter (dynamic linker)
/// support.
///
/// For ET_EXEC binaries, segments are loaded at their specified virtual
/// addresses. For ET_DYN (PIE) binaries, segments are relocated to
/// `pie_base`. When a PT_INTERP segment is present, the interpreter is
/// read from the backend filesystem and loaded at `interp_base`.
pub struct InterpreterLoader {
    /// Base address for ET_DYN executables (PIE). 0 means use ET_EXEC
    /// vaddrs.
    pub pie_base: u64,
    /// Base address for the interpreter. Must not overlap executable
    /// segments.
    pub interp_base: u64,
}

impl Default for InterpreterLoader {
    fn default() -> Self {
        Self {
            pie_base: 0x400000,
            interp_base: 0x7f000000,
        }
    }
}

/// Convert [`SegmentFlags`] to [`PageFlags`] for VM mapping.
fn segment_flags_to_page_flags(flags: &SegmentFlags) -> PageFlags {
    let mut pf = PageFlags::USER;
    if flags.read {
        pf |= PageFlags::READABLE;
    }
    if flags.write {
        pf |= PageFlags::WRITABLE;
    }
    if flags.execute {
        pf |= PageFlags::EXECUTABLE;
    }
    pf
}

/// Maximum interpreter file size we are willing to read (4 MiB).
const MAX_INTERP_SIZE: u32 = 4 * 1024 * 1024;

/// Fid used for the interpreter file walk/open/read cycle.
///
/// This is a sentinel value far from the sequential fid range that
/// LibraryServer and Linuxulator allocate from (starting near 0).
/// The walk/open/read/clunk cycle is atomic within `load()`, so the
/// fid is never exposed to user code.  If a dynamic fid allocator is
/// added later, this should be replaced with an allocated fid.
const INTERP_FID: Fid = 0xFFFF_FFF0;

impl InterpreterLoader {
    /// Load PT_LOAD segments from a parsed ELF into the backend at the
    /// given base address.
    fn load_segments(
        &self,
        parsed: &ParsedElf,
        elf_bytes: &[u8],
        base: u64,
        backend: &mut dyn SyscallBackend,
    ) -> Result<(), ElfLoadError> {
        for seg in &parsed.segments {
            // W^X enforcement: reject before allocating any pages.
            if seg.flags.write && seg.flags.execute {
                return Err(ElfLoadError::WXViolation);
            }

            let vaddr = base
                .checked_add(seg.vaddr)
                .ok_or(ElfLoadError::OverlappingSegments)?;
            let page_start = page_floor(vaddr);
            let end_vaddr = vaddr
                .checked_add(seg.memsz)
                .ok_or(ElfLoadError::OverlappingSegments)?;
            let page_end = page_ceil(end_vaddr).ok_or(ElfLoadError::OverlappingSegments)?;
            let map_len = (page_end - page_start) as usize;

            let pf = segment_flags_to_page_flags(&seg.flags);

            // Map the pages — always writable during load so we can
            // write segment data, then mprotect to final perms after.
            backend
                .vm_mmap(
                    page_start,
                    map_len,
                    pf | PageFlags::WRITABLE,
                    FrameClassification::empty(),
                )
                .map_err(|_| ElfLoadError::OverlappingSegments)?;

            // Write file-backed portion of the segment.
            if seg.filesz > 0 {
                let offset = seg.offset as usize;
                let end = offset + seg.filesz as usize;
                if end > elf_bytes.len() {
                    return Err(ElfLoadError::ParseError(
                        crate::elf::ElfError::SegmentOutOfBounds,
                    ));
                }
                backend.vm_write_bytes(vaddr, &elf_bytes[offset..end]);
            }

            // Zero the BSS region (memsz > filesz).  The ELF spec
            // requires bytes from vaddr+filesz to vaddr+memsz to be
            // zero.  vm_mmap does not guarantee zeroed pages.
            // Write in page-sized chunks to bound transient allocation.
            if seg.memsz > seg.filesz {
                let bss_start = vaddr
                    .checked_add(seg.filesz)
                    .ok_or(ElfLoadError::OverlappingSegments)?;
                let bss_len = (seg.memsz - seg.filesz) as usize;
                let chunk_size = (PAGE_SIZE as usize).min(bss_len);
                let chunk = alloc::vec![0u8; chunk_size];
                let mut written = 0usize;
                while written < bss_len {
                    let n = chunk.len().min(bss_len - written);
                    backend.vm_write_bytes(bss_start + written as u64, &chunk[..n]);
                    written += n;
                }
            }

            // Restore the caller's intended permissions (remove
            // the temporary WRITABLE if segment is not writable).
            if !seg.flags.write {
                backend
                    .vm_mprotect(page_start, map_len, pf)
                    .map_err(|_| ElfLoadError::OverlappingSegments)?;
            }
        }
        Ok(())
    }
}

impl ElfLoader for InterpreterLoader {
    fn load(
        &mut self,
        elf_bytes: &[u8],
        backend: &mut dyn SyscallBackend,
    ) -> Result<LoadResult, ElfLoadError> {
        // 1. Parse executable ELF.
        let parsed = parse_elf(elf_bytes).map_err(ElfLoadError::ParseError)?;

        // 2. Determine exe base: 0 for ET_EXEC, pie_base for ET_DYN.
        let exe_base = match parsed.elf_type {
            ElfType::Exec => 0,
            ElfType::Dyn => self.pie_base,
        };

        // 3. Load executable PT_LOAD segments.
        self.load_segments(&parsed, elf_bytes, exe_base, backend)?;

        // 4. Handle interpreter if PT_INTERP is present.
        let (final_entry, interp_base_out) = if let Some(ref interp_path) = parsed.interpreter {
            // Walk, open, read the interpreter file via the backend.
            // All operations after walk must clunk INTERP_FID on error
            // to avoid leaking the sentinel fid.
            backend.walk(interp_path, INTERP_FID).map_err(|e| match e {
                IpcError::NotFound => ElfLoadError::InterpreterNotFound,
                other => ElfLoadError::BackendError(other),
            })?;

            let interp_bytes = (|| -> Result<Vec<u8>, ElfLoadError> {
                backend
                    .open(INTERP_FID, OpenMode::Read)
                    .map_err(ElfLoadError::BackendError)?;

                let interp_stat = backend
                    .stat(INTERP_FID)
                    .map_err(ElfLoadError::BackendError)?;
                if interp_stat.size > MAX_INTERP_SIZE as u64 {
                    return Err(ElfLoadError::InterpreterParseError(
                        crate::elf::ElfError::TooShort,
                    ));
                }

                backend
                    .read(INTERP_FID, 0, MAX_INTERP_SIZE)
                    .map_err(ElfLoadError::BackendError)
            })();

            // Always clunk the interpreter fid, whether we succeeded or failed.
            let _ = backend.clunk(INTERP_FID);
            let interp_bytes = interp_bytes?;

            // Parse interpreter ELF — must be ET_DYN (position-independent).
            let interp_parsed =
                parse_elf(&interp_bytes).map_err(ElfLoadError::InterpreterParseError)?;
            if interp_parsed.elf_type != ElfType::Dyn {
                return Err(ElfLoadError::InterpreterParseError(
                    crate::elf::ElfError::NotExecutable,
                ));
            }

            // Load interpreter segments at interp_base.
            self.load_segments(&interp_parsed, &interp_bytes, self.interp_base, backend)?;

            // For ET_DYN interpreters, e_entry is a relative offset from
            // the image base.  The absolute entry in the process's
            // address space is interp_base + e_entry.
            let entry = self.interp_base + interp_parsed.entry_point;
            (entry, self.interp_base)
        } else {
            // Static binary — entry is the exe's own entry point.
            let entry = match parsed.elf_type {
                ElfType::Exec => parsed.entry_point,
                ElfType::Dyn => exe_base + parsed.entry_point,
            };
            (entry, 0u64)
        };

        // 5. Build auxiliary vector.
        let at_entry = match parsed.elf_type {
            ElfType::Exec => parsed.entry_point,
            ElfType::Dyn => exe_base + parsed.entry_point,
        };

        let auxv = alloc::vec![
            (
                auxv::AT_PHDR,
                exe_base + parsed.load_bias + parsed.phdr_offset
            ),
            (auxv::AT_PHENT, parsed.phdr_entry_size as u64),
            (auxv::AT_PHNUM, parsed.phdr_count as u64),
            (auxv::AT_PAGESZ, PAGE_SIZE),
            (auxv::AT_ENTRY, at_entry),
            (auxv::AT_BASE, interp_base_out),
            (auxv::AT_RANDOM, 0), // placeholder — stack builder fills the real address
            (auxv::AT_NULL, 0),
        ];

        // 6. Return result.
        Ok(LoadResult {
            entry_point: final_entry,
            auxv,
            exe_base,
            interp_base: interp_base_out,
        })
    }
}

// ── Stack layout construction ───────────────────────────────────────

/// Build the initial process stack for a Linux binary.
///
/// Writes strings, AT_RANDOM bytes, auxv, envp, argv, and argc into
/// `stack` memory starting from the top (high addresses). Returns the
/// initial SP value (the address where argc is stored).
///
/// The `stack_base` is the virtual address of `stack[0]` in the
/// process's address space. The returned SP is relative to this base.
pub fn build_initial_stack(
    stack: &mut [u8],
    stack_base: u64,
    argv: &[&str],
    envp: &[&str],
    auxv_entries: &[(u64, u64)],
    random_bytes: &[u8; 16],
) -> u64 {
    let stack_len = stack.len();
    let mut pos = stack_len;

    // Helper: write bytes at `pos`, moving pos down.
    // Returns the virtual address of the written data.
    let write_bytes = |stack: &mut [u8], pos: &mut usize, data: &[u8]| -> u64 {
        assert!(
            *pos >= data.len(),
            "stack buffer overflow during initial stack construction"
        );
        *pos -= data.len();
        stack[*pos..*pos + data.len()].copy_from_slice(data);
        stack_base + *pos as u64
    };

    // 1. Write AT_RANDOM bytes at the top of the stack.
    let random_addr = write_bytes(stack, &mut pos, random_bytes);

    // 2. Write argv string data (each null-terminated), recording addresses.
    let mut argv_addrs = Vec::with_capacity(argv.len());
    for arg in argv {
        let mut s = Vec::from(arg.as_bytes());
        s.push(0); // null terminator
        let addr = write_bytes(stack, &mut pos, &s);
        argv_addrs.push(addr);
    }

    // 3. Write envp string data (each null-terminated), recording addresses.
    let mut envp_addrs = Vec::with_capacity(envp.len());
    for env in envp {
        let mut s = Vec::from(env.as_bytes());
        s.push(0);
        let addr = write_bytes(stack, &mut pos, &s);
        envp_addrs.push(addr);
    }

    // 4. Pad string area to 16-byte alignment.
    pos &= !0xF;

    // Helper: write a u64 at `pos`, moving pos down by 8.
    let write_u64 = |stack: &mut [u8], pos: &mut usize, val: u64| {
        assert!(
            *pos >= 8,
            "stack buffer overflow writing u64 (pos={}, need 8 bytes)",
            *pos
        );
        *pos -= 8;
        stack[*pos..*pos + 8].copy_from_slice(&val.to_le_bytes());
    };

    // 5. To guarantee 16-byte SP alignment, count the total u64 entries
    //    we will write. If the count is odd, insert one padding u64 at
    //    the top of the structured region (before AT_NULL) so that the
    //    total byte span is a multiple of 16 and argc lands on a
    //    16-byte boundary.
    let non_null_auxv_count = auxv_entries
        .iter()
        .filter(|(k, _)| *k != auxv::AT_NULL)
        .count();
    let total_u64s = 2                       // AT_NULL (key + value)
        + non_null_auxv_count * 2            // auxv entries (key + value each)
        + 1                                  // envp NULL terminator
        + envp_addrs.len()                   // envp pointers
        + 1                                  // argv NULL terminator
        + argv_addrs.len()                   // argv pointers
        + 1; // argc

    // Write the structured data (working downward from high to low).

    // Insert alignment padding if needed (at the top, above AT_NULL).
    if total_u64s % 2 != 0 {
        write_u64(stack, &mut pos, 0);
    }

    // AT_NULL terminator (two u64 zeros).
    write_u64(stack, &mut pos, 0);
    write_u64(stack, &mut pos, auxv::AT_NULL);

    // Auxiliary vector entries in reverse order.
    // Filter out AT_NULL from the caller's entries (we wrote it above).
    for &(key, value) in auxv_entries.iter().rev() {
        if key == auxv::AT_NULL {
            continue;
        }
        let actual_value = if key == auxv::AT_RANDOM {
            random_addr
        } else {
            value
        };
        write_u64(stack, &mut pos, actual_value);
        write_u64(stack, &mut pos, key);
    }

    // envp NULL terminator.
    write_u64(stack, &mut pos, 0);

    // envp pointers in reverse.
    for addr in envp_addrs.iter().rev() {
        write_u64(stack, &mut pos, *addr);
    }

    // argv NULL terminator.
    write_u64(stack, &mut pos, 0);

    // argv pointers in reverse.
    for addr in argv_addrs.iter().rev() {
        write_u64(stack, &mut pos, *addr);
    }

    // argc.
    write_u64(stack, &mut pos, argv.len() as u64);

    // 6. SP points at argc. Verify alignment.
    debug_assert_eq!(
        (stack_base + pos as u64) % 16,
        0,
        "SP must be 16-byte aligned"
    );

    stack_base + pos as u64
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec;
    use harmony_microkernel::vm::{FrameClassification, PageFlags, VmError};
    use harmony_microkernel::{Fid, FileStat, FileType, IpcError, OpenMode, QPath};

    // ── Test ELF builders ───────────────────────────────────────────

    /// Build a minimal valid ELF64 binary with configurable type.
    /// `code` is placed as a PT_LOAD segment at `vaddr`.
    fn build_test_elf_typed(code: &[u8], elf_type: ElfType, vaddr: u64, entry: u64) -> Vec<u8> {
        let phdr_size = 56usize;
        let phnum = 1usize;
        let code_offset = 64 + phnum * phdr_size;
        let total = code_offset + code.len();
        let mut elf = vec![0u8; total];

        // ELF header
        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT

        let e_type: u16 = match elf_type {
            ElfType::Exec => 2,
            ElfType::Dyn => 3,
        };
        elf[16..18].copy_from_slice(&e_type.to_le_bytes());

        #[cfg(target_arch = "x86_64")]
        elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
        #[cfg(target_arch = "aarch64")]
        elf[18..20].copy_from_slice(&0xB7u16.to_le_bytes());
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());

        elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        elf[24..32].copy_from_slice(&entry.to_le_bytes()); // e_entry
        elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        elf[56..58].copy_from_slice(&(phnum as u16).to_le_bytes()); // e_phnum

        // PT_LOAD program header
        let ph = &mut elf[64..64 + phdr_size];
        ph[0..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        ph[4..8].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
        ph[8..16].copy_from_slice(&(code_offset as u64).to_le_bytes()); // p_offset
        ph[16..24].copy_from_slice(&vaddr.to_le_bytes()); // p_vaddr
        ph[24..32].copy_from_slice(&vaddr.to_le_bytes()); // p_paddr
        ph[32..40].copy_from_slice(&(code.len() as u64).to_le_bytes()); // p_filesz
        ph[40..48].copy_from_slice(&(code.len() as u64).to_le_bytes()); // p_memsz
        ph[48..56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align

        // Code
        elf[code_offset..code_offset + code.len()].copy_from_slice(code);

        elf
    }

    /// Build a static ET_EXEC ELF at vaddr 0x401000 with entry 0x401000.
    fn build_static_elf(code: &[u8]) -> Vec<u8> {
        build_test_elf_typed(code, ElfType::Exec, 0x401000, 0x401000)
    }

    /// Build a test ELF with a PT_INTERP segment.
    fn build_elf_with_interp(
        code: &[u8],
        interp_path: &[u8],
        elf_type: ElfType,
        vaddr: u64,
        entry: u64,
    ) -> Vec<u8> {
        let phdr_size = 56usize;
        let phnum = 2usize;
        let code_offset = 64 + phnum * phdr_size;
        let interp_offset = code_offset + code.len();
        let total = interp_offset + interp_path.len();
        let mut elf = vec![0u8; total];

        // ELF header
        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;

        let e_type: u16 = match elf_type {
            ElfType::Exec => 2,
            ElfType::Dyn => 3,
        };
        elf[16..18].copy_from_slice(&e_type.to_le_bytes());

        #[cfg(target_arch = "x86_64")]
        elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
        #[cfg(target_arch = "aarch64")]
        elf[18..20].copy_from_slice(&0xB7u16.to_le_bytes());
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());

        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[24..32].copy_from_slice(&entry.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&(phnum as u16).to_le_bytes());

        // PT_LOAD program header
        let ph = &mut elf[64..64 + phdr_size];
        ph[0..4].copy_from_slice(&1u32.to_le_bytes());
        ph[4..8].copy_from_slice(&5u32.to_le_bytes());
        ph[8..16].copy_from_slice(&(code_offset as u64).to_le_bytes());
        ph[16..24].copy_from_slice(&vaddr.to_le_bytes());
        ph[24..32].copy_from_slice(&vaddr.to_le_bytes());
        ph[32..40].copy_from_slice(&(code.len() as u64).to_le_bytes());
        ph[40..48].copy_from_slice(&(code.len() as u64).to_le_bytes());
        ph[48..56].copy_from_slice(&0x1000u64.to_le_bytes());

        // PT_INTERP program header
        let iph = &mut elf[64 + phdr_size..64 + 2 * phdr_size];
        iph[0..4].copy_from_slice(&3u32.to_le_bytes()); // PT_INTERP
        iph[4..8].copy_from_slice(&4u32.to_le_bytes()); // PF_R
        iph[8..16].copy_from_slice(&(interp_offset as u64).to_le_bytes());
        iph[32..40].copy_from_slice(&(interp_path.len() as u64).to_le_bytes());
        iph[40..48].copy_from_slice(&(interp_path.len() as u64).to_le_bytes());
        iph[48..56].copy_from_slice(&1u64.to_le_bytes());

        elf[code_offset..code_offset + code.len()].copy_from_slice(code);
        elf[interp_offset..interp_offset + interp_path.len()].copy_from_slice(interp_path);

        elf
    }

    /// Build a minimal ET_DYN ELF suitable for use as an interpreter.
    fn build_interp_elf(code: &[u8], vaddr: u64, entry: u64) -> Vec<u8> {
        build_test_elf_typed(code, ElfType::Dyn, vaddr, entry)
    }

    // ── LoaderMockBackend ───────────────────────────────────────────

    /// Test double for ELF loader tests.
    ///
    /// Supports VM operations and can serve interpreter file bytes
    /// when walked to the right path.
    struct LoaderMockBackend {
        mapped: Vec<(u64, usize, PageFlags)>,
        written: Vec<(u64, Vec<u8>)>,
        walks: Vec<(String, Fid)>,
        opens: Vec<(Fid, OpenMode)>,
        clunks: Vec<Fid>,
        /// Interpreter bytes keyed by path. When `walk()` is called
        /// with a matching path, the subsequent `read()` on that fid
        /// will return these bytes.
        interp_files: BTreeMap<String, Vec<u8>>,
        /// Maps fid -> path for files that have been walked.
        fid_to_path: BTreeMap<Fid, String>,
    }

    impl LoaderMockBackend {
        fn new() -> Self {
            Self {
                mapped: Vec::new(),
                written: Vec::new(),
                walks: Vec::new(),
                opens: Vec::new(),
                clunks: Vec::new(),
                interp_files: BTreeMap::new(),
                fid_to_path: BTreeMap::new(),
            }
        }

        /// Register interpreter ELF bytes at the given path.
        fn register_interp(&mut self, path: &str, bytes: Vec<u8>) {
            self.interp_files.insert(String::from(path), bytes);
        }
    }

    impl SyscallBackend for LoaderMockBackend {
        fn walk(&mut self, path: &str, new_fid: Fid) -> Result<QPath, IpcError> {
            self.walks.push((String::from(path), new_fid));
            if self.interp_files.contains_key(path) {
                self.fid_to_path.insert(new_fid, String::from(path));
                Ok(0)
            } else {
                Err(IpcError::NotFound)
            }
        }

        fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
            self.opens.push((fid, mode));
            Ok(())
        }

        fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
            if let Some(path) = self.fid_to_path.get(&fid) {
                if let Some(content) = self.interp_files.get(path) {
                    let start = (offset as usize).min(content.len());
                    let end = (start + count as usize).min(content.len());
                    return Ok(content[start..end].to_vec());
                }
            }
            Ok(Vec::new())
        }

        fn write(&mut self, _fid: Fid, _offset: u64, _data: &[u8]) -> Result<u32, IpcError> {
            Ok(0)
        }

        fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
            self.clunks.push(fid);
            self.fid_to_path.remove(&fid);
            Ok(())
        }

        fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
            let size = self
                .fid_to_path
                .get(&fid)
                .and_then(|path| self.interp_files.get(path))
                .map(|bytes| bytes.len() as u64)
                .unwrap_or(0);
            Ok(FileStat {
                qpath: 0,
                name: Arc::from("mock"),
                size,
                file_type: FileType::Regular,
            })
        }

        fn has_vm_support(&self) -> bool {
            true
        }

        fn vm_mmap(
            &mut self,
            vaddr: u64,
            len: usize,
            flags: PageFlags,
            _classification: FrameClassification,
        ) -> Result<u64, VmError> {
            self.mapped.push((vaddr, len, flags));
            Ok(vaddr)
        }

        fn vm_munmap(&mut self, _vaddr: u64, _len: usize) -> Result<(), VmError> {
            Ok(())
        }

        fn vm_mprotect(
            &mut self,
            _vaddr: u64,
            _len: usize,
            _flags: PageFlags,
        ) -> Result<(), VmError> {
            Ok(())
        }

        fn vm_find_free_region(&self, _len: usize) -> Result<u64, VmError> {
            Ok(0x1_0000)
        }

        fn vm_write_bytes(&mut self, addr: u64, data: &[u8]) {
            self.written.push((addr, data.to_vec()));
        }
    }

    // ── Helper: find auxv entry ─────────────────────────────────────

    fn auxv_get(auxv: &[(u64, u64)], key: u64) -> Option<u64> {
        auxv.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }

    // ── Tests ───────────────────────────────────────────────────────

    #[test]
    fn load_static_elf_returns_exe_entry() {
        let code = [0xCC; 16];
        let elf = build_static_elf(&code);

        let mut loader = InterpreterLoader::default();
        let mut backend = LoaderMockBackend::new();
        let result = loader.load(&elf, &mut backend).unwrap();

        // Static ET_EXEC: entry is the exe's own entry point.
        assert_eq!(result.entry_point, 0x401000);
        // No interpreter loaded.
        assert_eq!(result.interp_base, 0);
        // ET_EXEC base is 0 (loaded at absolute vaddrs).
        assert_eq!(result.exe_base, 0);

        // Auxv must contain required entries.
        assert_eq!(auxv_get(&result.auxv, auxv::AT_ENTRY), Some(0x401000));
        assert!(auxv_get(&result.auxv, auxv::AT_PHDR).is_some());
        assert!(auxv_get(&result.auxv, auxv::AT_PHNUM).is_some());
        assert_eq!(auxv_get(&result.auxv, auxv::AT_PAGESZ), Some(4096));
    }

    #[test]
    fn load_dynamic_elf_returns_interp_entry() {
        let interp_path = b"/lib/ld-musl-x86_64.so.1\0";
        let exe_code = [0xCC; 16];
        let exe_elf =
            build_elf_with_interp(&exe_code, interp_path, ElfType::Exec, 0x401000, 0x401000);

        // Build a minimal interpreter ELF (ET_DYN).
        let interp_code = [0x90; 8];
        let interp_entry = 0x1000u64;
        let interp_elf = build_interp_elf(&interp_code, 0x1000, interp_entry);

        let mut loader = InterpreterLoader::default();
        let mut backend = LoaderMockBackend::new();
        backend.register_interp("/lib/ld-musl-x86_64.so.1", interp_elf);

        let result = loader.load(&exe_elf, &mut backend).unwrap();

        // Entry point should be interp_base + interpreter's entry point.
        assert_eq!(
            result.entry_point,
            loader.interp_base + interp_entry,
            "entry should be interpreter's entry at interp_base"
        );

        // AT_ENTRY in auxv is the exe's entry (not the interpreter's).
        assert_eq!(auxv_get(&result.auxv, auxv::AT_ENTRY), Some(0x401000));

        // AT_BASE is the interpreter base address.
        assert_eq!(
            auxv_get(&result.auxv, auxv::AT_BASE),
            Some(loader.interp_base)
        );

        // interp_base is set.
        assert_eq!(result.interp_base, loader.interp_base);
    }

    #[test]
    fn auxv_contains_required_entries() {
        let code = [0xCC; 16];
        let elf = build_static_elf(&code);

        let mut loader = InterpreterLoader::default();
        let mut backend = LoaderMockBackend::new();
        let result = loader.load(&elf, &mut backend).unwrap();

        let required_keys = [
            auxv::AT_PHDR,
            auxv::AT_PHENT,
            auxv::AT_PHNUM,
            auxv::AT_PAGESZ,
            auxv::AT_ENTRY,
            auxv::AT_BASE,
            auxv::AT_RANDOM,
            auxv::AT_NULL,
        ];

        for key in &required_keys {
            assert!(
                auxv_get(&result.auxv, *key).is_some(),
                "auxv missing key {}",
                key
            );
        }
    }

    #[test]
    fn et_dyn_loaded_at_base_address() {
        let code = [0xCC; 16];
        let vaddr = 0x1000u64;
        let entry = 0x1000u64;
        let elf = build_test_elf_typed(&code, ElfType::Dyn, vaddr, entry);

        let mut loader = InterpreterLoader {
            pie_base: 0x200000,
            interp_base: 0x7f000000,
        };
        let mut backend = LoaderMockBackend::new();
        let result = loader.load(&elf, &mut backend).unwrap();

        // exe_base should be pie_base for ET_DYN.
        assert_eq!(result.exe_base, 0x200000);

        // Entry point = pie_base + elf entry.
        assert_eq!(result.entry_point, 0x200000 + entry);

        // Verify the segment was mapped at pie_base + vaddr.
        let mapped_addr = backend.mapped[0].0;
        let expected_page = page_floor(0x200000 + vaddr);
        assert_eq!(mapped_addr, expected_page);

        // Verify data was written at pie_base + vaddr.
        let written_addr = backend.written[0].0;
        assert_eq!(written_addr, 0x200000 + vaddr);
    }

    #[test]
    fn static_elf_segments_mapped_and_written() {
        let code = [0x90, 0x90, 0xCC, 0xCC];
        let elf = build_static_elf(&code);

        let mut loader = InterpreterLoader::default();
        let mut backend = LoaderMockBackend::new();
        loader.load(&elf, &mut backend).unwrap();

        // One PT_LOAD segment => one mmap + one write.
        assert_eq!(backend.mapped.len(), 1);
        assert_eq!(backend.written.len(), 1);

        // Segment mapped at page-aligned vaddr.
        assert_eq!(backend.mapped[0].0, page_floor(0x401000));

        // Data written at exact vaddr.
        assert_eq!(backend.written[0].0, 0x401000);
        assert_eq!(backend.written[0].1, vec![0x90, 0x90, 0xCC, 0xCC]);
    }

    #[test]
    fn interp_not_found_returns_error() {
        let interp_path = b"/lib/ld-nonexistent.so.1\0";
        let exe_code = [0xCC; 16];
        let exe_elf =
            build_elf_with_interp(&exe_code, interp_path, ElfType::Exec, 0x401000, 0x401000);

        let mut loader = InterpreterLoader::default();
        let mut backend = LoaderMockBackend::new();
        // No interpreter registered — walk will fail.

        let result = loader.load(&exe_elf, &mut backend);
        assert!(matches!(result, Err(ElfLoadError::InterpreterNotFound)));
    }

    #[test]
    fn dynamic_elf_walks_and_reads_interp() {
        let interp_path = b"/lib/ld-musl-x86_64.so.1\0";
        let exe_code = [0xCC; 16];
        let exe_elf =
            build_elf_with_interp(&exe_code, interp_path, ElfType::Exec, 0x401000, 0x401000);

        let interp_code = [0x90; 8];
        let interp_elf = build_interp_elf(&interp_code, 0x1000, 0x1000);

        let mut loader = InterpreterLoader::default();
        let mut backend = LoaderMockBackend::new();
        backend.register_interp("/lib/ld-musl-x86_64.so.1", interp_elf);

        loader.load(&exe_elf, &mut backend).unwrap();

        // Verify the backend was walked to the interpreter path.
        assert_eq!(backend.walks.len(), 1);
        assert_eq!(backend.walks[0].0, "/lib/ld-musl-x86_64.so.1");

        // Verify the fid was clunked after reading.
        assert_eq!(backend.clunks.len(), 1);
    }

    #[test]
    fn phdr_offset_in_auxv_matches_exe() {
        let code = [0xCC; 16];
        let elf = build_static_elf(&code);
        let parsed = parse_elf(&elf).unwrap();

        let mut loader = InterpreterLoader::default();
        let mut backend = LoaderMockBackend::new();
        let result = loader.load(&elf, &mut backend).unwrap();

        // AT_PHDR = exe_base + load_bias + phdr_offset.
        // For ET_EXEC, exe_base = 0.
        assert_eq!(
            auxv_get(&result.auxv, auxv::AT_PHDR),
            Some(parsed.load_bias + parsed.phdr_offset)
        );
        assert_eq!(
            auxv_get(&result.auxv, auxv::AT_PHENT),
            Some(parsed.phdr_entry_size as u64)
        );
        assert_eq!(
            auxv_get(&result.auxv, auxv::AT_PHNUM),
            Some(parsed.phdr_count as u64)
        );
    }

    #[test]
    fn at_base_zero_for_static_elf() {
        let code = [0xCC; 16];
        let elf = build_static_elf(&code);

        let mut loader = InterpreterLoader::default();
        let mut backend = LoaderMockBackend::new();
        let result = loader.load(&elf, &mut backend).unwrap();

        // No interpreter => AT_BASE = 0.
        assert_eq!(auxv_get(&result.auxv, auxv::AT_BASE), Some(0));
    }

    // ── Stack layout tests ────────────────────────────────────────

    /// Helper: read a little-endian u64 from stack at a given virtual
    /// address, using stack_base to compute the offset.
    fn read_u64_at(stack: &[u8], stack_base: u64, vaddr: u64) -> u64 {
        let offset = (vaddr - stack_base) as usize;
        u64::from_le_bytes(stack[offset..offset + 8].try_into().unwrap())
    }

    #[test]
    fn build_stack_layout() {
        let mut stack = vec![0u8; 4096];
        let stack_base = 0x7FFF_0000u64;
        let random = [0xAA; 16];
        let test_auxv = vec![
            (auxv::AT_PHDR, 0x400040),
            (auxv::AT_ENTRY, 0x401000),
            (auxv::AT_PAGESZ, 4096),
            (auxv::AT_RANDOM, 0), // placeholder
            (auxv::AT_NULL, 0),
        ];

        let sp = build_initial_stack(
            &mut stack,
            stack_base,
            &["./hello"],
            &[],
            &test_auxv,
            &random,
        );

        // SP must be 16-byte aligned.
        assert_eq!(sp % 16, 0, "SP must be 16-byte aligned");

        // argc should be 1.
        let argc = read_u64_at(&stack, stack_base, sp);
        assert_eq!(argc, 1, "argc should be 1");
    }

    #[test]
    fn stack_argv_readable() {
        let mut stack = vec![0u8; 4096];
        let stack_base = 0x7FFF_0000u64;
        let random = [0xBB; 16];
        let test_auxv = vec![
            (auxv::AT_PAGESZ, 4096),
            (auxv::AT_RANDOM, 0),
            (auxv::AT_NULL, 0),
        ];

        let sp = build_initial_stack(
            &mut stack,
            stack_base,
            &["./hello"],
            &[],
            &test_auxv,
            &random,
        );

        // argc at SP
        let argc = read_u64_at(&stack, stack_base, sp);
        assert_eq!(argc, 1);

        // argv[0] pointer at SP + 8
        let argv0_ptr = read_u64_at(&stack, stack_base, sp + 8);

        // Follow the pointer to read the string.
        let str_offset = (argv0_ptr - stack_base) as usize;
        let end = stack[str_offset..].iter().position(|&b| b == 0).unwrap();
        let s = core::str::from_utf8(&stack[str_offset..str_offset + end]).unwrap();
        assert_eq!(s, "./hello");
    }

    #[test]
    fn stack_auxv_present() {
        let mut stack = vec![0u8; 4096];
        let stack_base = 0x7FFF_0000u64;
        let random = [0xCC; 16];
        let test_auxv = vec![
            (auxv::AT_PHDR, 0x400040),
            (auxv::AT_ENTRY, 0x401000),
            (auxv::AT_PAGESZ, 4096),
            (auxv::AT_RANDOM, 0),
            (auxv::AT_NULL, 0),
        ];

        let sp = build_initial_stack(
            &mut stack,
            stack_base,
            &["./hello"],
            &[],
            &test_auxv,
            &random,
        );

        // Walk past argc (1 u64), argv pointers (1 ptr + NULL),
        // envp (NULL) to reach auxv.
        let mut cursor = sp;

        // argc
        let argc = read_u64_at(&stack, stack_base, cursor);
        assert_eq!(argc, 1);
        cursor += 8;

        // argv[0] pointer
        cursor += 8;
        // argv NULL terminator
        let argv_null = read_u64_at(&stack, stack_base, cursor);
        assert_eq!(argv_null, 0);
        cursor += 8;

        // envp NULL terminator
        let envp_null = read_u64_at(&stack, stack_base, cursor);
        assert_eq!(envp_null, 0);
        cursor += 8;

        // Now we are at auxv. Collect entries until AT_NULL.
        let mut found_auxv = Vec::new();
        loop {
            let key = read_u64_at(&stack, stack_base, cursor);
            let val = read_u64_at(&stack, stack_base, cursor + 8);
            cursor += 16;
            if key == auxv::AT_NULL {
                break;
            }
            found_auxv.push((key, val));
        }

        // Verify we found AT_PHDR, AT_ENTRY, AT_PAGESZ.
        let find = |k: u64| {
            found_auxv
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| *v)
        };
        assert_eq!(find(auxv::AT_PHDR), Some(0x400040));
        assert_eq!(find(auxv::AT_ENTRY), Some(0x401000));
        assert_eq!(find(auxv::AT_PAGESZ), Some(4096));
    }

    #[test]
    fn stack_at_random_points_to_bytes() {
        let mut stack = vec![0u8; 4096];
        let stack_base = 0x7FFF_0000u64;
        let random: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let test_auxv = vec![
            (auxv::AT_PAGESZ, 4096),
            (auxv::AT_RANDOM, 0),
            (auxv::AT_NULL, 0),
        ];

        let sp = build_initial_stack(
            &mut stack,
            stack_base,
            &["./hello"],
            &[],
            &test_auxv,
            &random,
        );

        // Walk to auxv.
        let mut cursor = sp;
        cursor += 8; // argc
        cursor += 8; // argv[0]
        cursor += 8; // argv NULL
        cursor += 8; // envp NULL

        // Find AT_RANDOM.
        let mut random_ptr = None;
        loop {
            let key = read_u64_at(&stack, stack_base, cursor);
            let val = read_u64_at(&stack, stack_base, cursor + 8);
            cursor += 16;
            if key == auxv::AT_NULL {
                break;
            }
            if key == auxv::AT_RANDOM {
                random_ptr = Some(val);
            }
        }

        let ptr = random_ptr.expect("AT_RANDOM entry must exist");

        // Follow the pointer to the random bytes.
        let offset = (ptr - stack_base) as usize;
        assert_eq!(&stack[offset..offset + 16], &random);
    }

    // ── End-to-end integration tests ──────────────────────────────

    /// Helper: walk the stack from SP to collect auxv entries.
    /// Returns (auxv_entries, cursor_after_auxv).
    fn collect_stack_auxv(stack: &[u8], stack_base: u64, sp: u64, argc: u64) -> Vec<(u64, u64)> {
        let mut cursor = sp;
        // Skip argc.
        cursor += 8;
        // Skip argv pointers (argc pointers + NULL terminator).
        cursor += (argc + 1) * 8;
        // Skip envp pointers until NULL terminator.
        loop {
            let val = read_u64_at(stack, stack_base, cursor);
            cursor += 8;
            if val == 0 {
                break;
            }
        }

        // Collect auxv entries.
        let mut found = Vec::new();
        loop {
            let key = read_u64_at(stack, stack_base, cursor);
            let val = read_u64_at(stack, stack_base, cursor + 8);
            cursor += 16;
            if key == auxv::AT_NULL {
                break;
            }
            found.push((key, val));
        }
        found
    }

    /// Helper: find a value in collected auxv entries.
    fn find_auxv(entries: &[(u64, u64)], key: u64) -> Option<u64> {
        entries.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }

    #[test]
    fn end_to_end_static_elf_load() {
        // 1. Build a synthetic ET_EXEC ELF.
        let code = [0xCC; 32];
        let exe_entry = 0x401000u64;
        let elf = build_static_elf(&code);

        // 2. Create backend and loader.
        let mut backend = LoaderMockBackend::new();
        let mut loader = InterpreterLoader::default();

        // 3. Load via InterpreterLoader.
        let result = loader.load(&elf, &mut backend).unwrap();

        // 4. Verify load result.
        assert_eq!(
            result.entry_point, exe_entry,
            "static ELF entry_point must be the exe's entry"
        );
        assert_eq!(
            result.interp_base, 0,
            "static ELF must have interp_base == 0"
        );

        // 5. Build initial stack using the returned auxv.
        let mut stack = vec![0u8; 8192];
        let stack_base = 0x7FFE_0000u64;
        let random_bytes: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];

        let sp = build_initial_stack(
            &mut stack,
            stack_base,
            &["./my_program"],
            &[],
            &result.auxv,
            &random_bytes,
        );

        // 6. Verify stack layout.

        // SP must be 16-byte aligned.
        assert_eq!(sp % 16, 0, "SP must be 16-byte aligned");

        // argc == 1.
        let argc = read_u64_at(&stack, stack_base, sp);
        assert_eq!(argc, 1, "argc should be 1");

        // argv[0] is readable and contains our program name.
        let argv0_ptr = read_u64_at(&stack, stack_base, sp + 8);
        let str_offset = (argv0_ptr - stack_base) as usize;
        let end = stack[str_offset..]
            .iter()
            .position(|&b| b == 0)
            .expect("argv[0] must be null-terminated");
        let argv0_str = core::str::from_utf8(&stack[str_offset..str_offset + end]).unwrap();
        assert_eq!(argv0_str, "./my_program");

        // Collect auxv from the stack.
        let stack_auxv = collect_stack_auxv(&stack, stack_base, sp, argc);

        // AT_PHDR = exe_base + load_bias + phdr_offset.
        // For ET_EXEC, exe_base == 0.
        let parsed = parse_elf(&elf).unwrap();
        let expected_phdr = parsed.load_bias + parsed.phdr_offset;
        let at_phdr = find_auxv(&stack_auxv, auxv::AT_PHDR).expect("AT_PHDR must be in stack auxv");
        assert_eq!(
            at_phdr, expected_phdr,
            "AT_PHDR should point to exe's phdr table in memory"
        );

        // AT_ENTRY must equal exe's entry point.
        let at_entry =
            find_auxv(&stack_auxv, auxv::AT_ENTRY).expect("AT_ENTRY must be in stack auxv");
        assert_eq!(at_entry, exe_entry, "AT_ENTRY should be exe's entry point");

        // AT_PAGESZ must be present and == 4096.
        let at_pagesz =
            find_auxv(&stack_auxv, auxv::AT_PAGESZ).expect("AT_PAGESZ must be in stack auxv");
        assert_eq!(at_pagesz, 4096, "AT_PAGESZ should be 4096");

        // AT_RANDOM must point to the random bytes we provided.
        let at_random_ptr =
            find_auxv(&stack_auxv, auxv::AT_RANDOM).expect("AT_RANDOM must be in stack auxv");
        let random_offset = (at_random_ptr - stack_base) as usize;
        assert_eq!(
            &stack[random_offset..random_offset + 16],
            &random_bytes,
            "AT_RANDOM must point to the 16 random bytes"
        );
    }

    #[test]
    fn end_to_end_dynamic_elf_with_interp() {
        // 1. Build a synthetic ET_EXEC ELF with PT_INTERP.
        let interp_path = b"/lib/ld-musl-x86_64.so.1\0";
        let exe_code = [0xCC; 32];
        let exe_entry = 0x401000u64;
        let exe_elf =
            build_elf_with_interp(&exe_code, interp_path, ElfType::Exec, 0x401000, exe_entry);

        // 2. Build a synthetic ET_DYN ELF for the interpreter.
        let interp_code = [0x90; 16];
        let interp_entry_offset = 0x1000u64;
        let interp_elf = build_interp_elf(&interp_code, 0x1000, interp_entry_offset);

        // 3. Set up backend with interpreter file.
        let mut backend = LoaderMockBackend::new();
        backend.register_interp("/lib/ld-musl-x86_64.so.1", interp_elf);

        // 4. Load via InterpreterLoader.
        let mut loader = InterpreterLoader::default();
        let expected_interp_base = loader.interp_base;
        let result = loader.load(&exe_elf, &mut backend).unwrap();

        // 5. Verify load result — entry is interpreter's, not exe's.
        assert_ne!(result.interp_base, 0, "interp_base must not be zero");
        assert_eq!(
            result.interp_base, expected_interp_base,
            "interp_base should match loader's configured interp_base"
        );
        assert_eq!(
            result.entry_point,
            expected_interp_base + interp_entry_offset,
            "entry_point must be interp_base + interpreter's entry"
        );

        // 6. Build initial stack using the returned auxv.
        let mut stack = vec![0u8; 8192];
        let stack_base = 0x7FFE_0000u64;
        let random_bytes: [u8; 16] = [
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
            0xAE, 0xAF,
        ];

        let sp = build_initial_stack(
            &mut stack,
            stack_base,
            &["./dynamic_program"],
            &[],
            &result.auxv,
            &random_bytes,
        );

        // 7. Verify stack layout.
        assert_eq!(sp % 16, 0, "SP must be 16-byte aligned");

        let argc = read_u64_at(&stack, stack_base, sp);
        assert_eq!(argc, 1, "argc should be 1");

        // Collect auxv from the stack.
        let stack_auxv = collect_stack_auxv(&stack, stack_base, sp, argc);

        // AT_ENTRY == exe's entry point (this is what ld-musl reads
        // to find the program's main).
        let at_entry =
            find_auxv(&stack_auxv, auxv::AT_ENTRY).expect("AT_ENTRY must be in stack auxv");
        assert_eq!(
            at_entry, exe_entry,
            "AT_ENTRY should be the exe's entry point, not the interpreter's"
        );

        // AT_BASE == interp_base (interpreter's load address).
        let at_base = find_auxv(&stack_auxv, auxv::AT_BASE).expect("AT_BASE must be in stack auxv");
        assert_eq!(
            at_base, expected_interp_base,
            "AT_BASE should be the interpreter's base address"
        );

        // AT_PHDR = exe_base + load_bias + phdr_offset.
        let parsed_exe = parse_elf(&exe_elf).unwrap();
        let expected_phdr = parsed_exe.load_bias + parsed_exe.phdr_offset;
        let at_phdr = find_auxv(&stack_auxv, auxv::AT_PHDR).expect("AT_PHDR must be in stack auxv");
        assert_eq!(
            at_phdr, expected_phdr,
            "AT_PHDR should point to exe's program header table in memory"
        );

        // AT_RANDOM points to the random bytes we provided.
        let at_random_ptr =
            find_auxv(&stack_auxv, auxv::AT_RANDOM).expect("AT_RANDOM must be in stack auxv");
        let random_offset = (at_random_ptr - stack_base) as usize;
        assert_eq!(
            &stack[random_offset..random_offset + 16],
            &random_bytes,
            "AT_RANDOM must point to the 16 random bytes"
        );
    }

    #[test]
    fn oversized_interpreter_rejected() {
        let interp_path = b"/lib/ld-musl-x86_64.so.1\0";
        let exe_code = [0xCC; 16];
        let exe_elf =
            build_elf_with_interp(&exe_code, interp_path, ElfType::Exec, 0x401000, 0x401000);

        // Register an interpreter whose byte length exceeds MAX_INTERP_SIZE.
        // The mock stat now returns the real content size, so the guard will trigger.
        let oversized = alloc::vec![0u8; MAX_INTERP_SIZE as usize + 1];

        let mut loader = InterpreterLoader::default();
        let mut backend = LoaderMockBackend::new();
        backend.register_interp("/lib/ld-musl-x86_64.so.1", oversized);

        let result = loader.load(&exe_elf, &mut backend);
        assert!(
            matches!(result, Err(ElfLoadError::InterpreterParseError(_))),
            "oversized interpreter should be rejected, got {:?}",
            result,
        );
    }

    #[test]
    fn stack_sp_alignment() {
        let random = [0xDD; 16];
        let test_auxv = vec![
            (auxv::AT_PAGESZ, 4096),
            (auxv::AT_RANDOM, 0),
            (auxv::AT_NULL, 0),
        ];

        // Test with various argv lengths.
        for args in &[
            vec!["a"],
            vec!["ab", "cd"],
            vec!["hello", "world", "foo"],
            vec!["x"],
            vec!["longer-argument-string"],
            vec!["a", "bb", "ccc", "dddd", "eeeee"],
        ] {
            let mut stack = vec![0u8; 4096];
            let stack_base = 0x7FFF_0000u64;
            let sp = build_initial_stack(&mut stack, stack_base, args, &[], &test_auxv, &random);
            assert_eq!(sp % 16, 0, "SP must be 16-byte aligned for argv {:?}", args);
        }
    }
}
