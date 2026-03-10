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
fn page_ceil(size: u64) -> u64 {
    (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

// ── Error type ──────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ElfLoadError {
    ParseError(ElfError),
    InterpreterNotFound,
    InterpreterParseError(ElfError),
    BackendError(IpcError),
    OverlappingSegments,
}

// ── Load result ─────────────────────────────────────────────────────

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
            let vaddr = base + seg.vaddr;
            let page_start = page_floor(vaddr);
            let page_end = page_ceil(vaddr + seg.memsz);
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
            backend.walk(interp_path, INTERP_FID).map_err(|e| match e {
                IpcError::NotFound => ElfLoadError::InterpreterNotFound,
                other => ElfLoadError::BackendError(other),
            })?;
            backend
                .open(INTERP_FID, OpenMode::Read)
                .map_err(ElfLoadError::BackendError)?;
            let interp_bytes = backend
                .read(INTERP_FID, 0, MAX_INTERP_SIZE)
                .map_err(ElfLoadError::BackendError)?;
            backend
                .clunk(INTERP_FID)
                .map_err(ElfLoadError::BackendError)?;

            // Parse interpreter ELF.
            let interp_parsed =
                parse_elf(&interp_bytes).map_err(ElfLoadError::InterpreterParseError)?;

            // Load interpreter segments at interp_base.
            self.load_segments(&interp_parsed, &interp_bytes, self.interp_base, backend)?;

            // Entry point is the interpreter's entry.
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
            (auxv::AT_PHDR, exe_base + parsed.phdr_offset),
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

        fn stat(&mut self, _fid: Fid) -> Result<FileStat, IpcError> {
            Ok(FileStat {
                qpath: 0,
                name: Arc::from("mock"),
                size: 0,
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

        // AT_PHDR should be exe_base + parsed.phdr_offset.
        // For ET_EXEC, exe_base = 0.
        assert_eq!(
            auxv_get(&result.auxv, auxv::AT_PHDR),
            Some(parsed.phdr_offset)
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
}
