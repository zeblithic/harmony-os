// SPDX-License-Identifier: GPL-2.0-or-later

//! Integration tests for dynamic ELF loading with real musl binaries.
//!
//! Fixtures (`tests/fixtures/hello` and `tests/fixtures/ld-musl-aarch64.so.1`)
//! are committed to the repository. To regenerate them (e.g. after a musl
//! version bump), run inside `nix develop`:
//!
//! ```bash
//! ./scripts/gen-musl-fixtures.sh
//! ```

use std::path::Path;

/// Path to the `hello` binary fixture (dynamically-linked aarch64 musl).
const HELLO_FIXTURE: &str = "tests/fixtures/hello";
/// Path to the `ld-musl-aarch64.so.1` fixture (musl dynamic linker).
const LD_MUSL_FIXTURE: &str = "tests/fixtures/ld-musl-aarch64.so.1";

/// Helper: read a fixture file, panicking with a useful message if absent.
fn read_fixture(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "Failed to read fixture {path}: {e}\n\
             Regenerate fixtures with: ./scripts/gen-musl-fixtures.sh (inside nix develop)"
        );
    })
}

// ── ELF parsing tests ──────────────────────────────────────────────

#[test]
fn parse_real_musl_hello() {
    let elf_bytes = read_fixture(HELLO_FIXTURE);
    let parsed = harmony_os::elf::parse_elf(&elf_bytes).expect("should parse musl hello");

    // Dynamic binary should have PT_INTERP.
    assert!(parsed.interpreter.is_some(), "should have interpreter");
    let interp = parsed.interpreter.as_deref().unwrap();
    assert!(
        interp.contains("ld-musl"),
        "interpreter should be ld-musl, got: {interp}"
    );

    // Should have loadable segments.
    assert!(!parsed.segments.is_empty(), "should have segments");

    // Should be ET_DYN (PIE) or ET_EXEC — musl-gcc default is PIE on
    // modern toolchains.
    assert!(
        parsed.elf_type == harmony_os::elf::ElfType::Dyn
            || parsed.elf_type == harmony_os::elf::ElfType::Exec,
        "unexpected ELF type: {:?}",
        parsed.elf_type
    );
}

#[test]
fn parse_real_ld_musl() {
    let elf_bytes = read_fixture(LD_MUSL_FIXTURE);
    let parsed = harmony_os::elf::parse_elf(&elf_bytes).expect("should parse ld-musl");

    // ld-musl is ET_DYN (shared library).
    assert_eq!(parsed.elf_type, harmony_os::elf::ElfType::Dyn);

    // ld-musl should NOT have its own PT_INTERP.
    assert!(
        parsed.interpreter.is_none(),
        "ld-musl should not have interpreter"
    );

    // Should have segments.
    assert!(!parsed.segments.is_empty(), "should have segments");
}

// ── Full loading test ──────────────────────────────────────────────

/// Smoke-test the full InterpreterLoader pipeline with real musl
/// binaries.
///
/// This wires up a mock SyscallBackend that serves ld-musl from the
/// fixture, then loads the dynamically-linked `hello` binary through
/// the [`InterpreterLoader`]. Verifies that the entry point, auxv,
/// and base addresses are reasonable.
#[test]
fn load_real_musl_hello() {
    use harmony_microkernel::vm::{FrameClassification, PageFlags, VmError};
    use harmony_microkernel::{Fid, FileStat, FileType, IpcError, OpenMode, QPath};
    use harmony_os::elf_loader::{ElfLoader, InterpreterLoader};
    use harmony_os::linuxulator::SyscallBackend;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    // -- Mock backend that serves ld-musl from the fixture file ------

    struct FixtureBackend {
        interp_files: BTreeMap<String, Vec<u8>>,
        fid_to_path: BTreeMap<Fid, String>,
        mapped: Vec<(u64, usize, PageFlags)>,
    }

    impl FixtureBackend {
        fn new() -> Self {
            Self {
                interp_files: BTreeMap::new(),
                fid_to_path: BTreeMap::new(),
                mapped: Vec::new(),
            }
        }

        fn register_interp(&mut self, path: &str, bytes: Vec<u8>) {
            self.interp_files.insert(String::from(path), bytes);
        }
    }

    impl SyscallBackend for FixtureBackend {
        fn walk(&mut self, path: &str, new_fid: Fid) -> Result<QPath, IpcError> {
            if self.interp_files.contains_key(path) {
                self.fid_to_path.insert(new_fid, String::from(path));
                Ok(0)
            } else {
                Err(IpcError::NotFound)
            }
        }

        fn open(&mut self, _fid: Fid, _mode: OpenMode) -> Result<(), IpcError> {
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
                name: Arc::from("fixture"),
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

        fn vm_write_bytes(&mut self, _vaddr: u64, _data: &[u8]) {}
    }

    // -- Load the real binary ----------------------------------------

    let exe_bytes = read_fixture(HELLO_FIXTURE);
    let interp_bytes = read_fixture(LD_MUSL_FIXTURE);

    // Discover the interpreter path from the executable itself.
    let exe_parsed = harmony_os::elf::parse_elf(&exe_bytes).expect("parse hello");
    let interp_path = exe_parsed
        .interpreter
        .as_deref()
        .expect("hello should be dynamically linked")
        .to_string();

    let mut backend = FixtureBackend::new();
    backend.register_interp(&interp_path, interp_bytes);

    let mut loader = InterpreterLoader {
        // Fixtures are aarch64 — allow cross-arch loading in tests.
        expected_machine: 0xB7, // EM_AARCH64
        ..InterpreterLoader::default()
    };
    let result = loader
        .load(&exe_bytes, &mut backend)
        .expect("should load hello via InterpreterLoader");

    // Entry point should be the interpreter's entry (non-zero).
    assert!(result.entry_point != 0, "entry point should be non-zero");

    // Interpreter base should be non-zero (dynamic binary).
    assert!(
        result.interp_base != 0,
        "interp_base should be non-zero for dynamic binary"
    );

    // Auxv should contain essential entries.
    let auxv_keys: Vec<u64> = result.auxv.iter().map(|(k, _)| *k).collect();
    assert!(
        auxv_keys.contains(&harmony_os::elf_loader::auxv::AT_PHDR),
        "auxv should contain AT_PHDR"
    );
    assert!(
        auxv_keys.contains(&harmony_os::elf_loader::auxv::AT_ENTRY),
        "auxv should contain AT_ENTRY"
    );
    assert!(
        auxv_keys.contains(&harmony_os::elf_loader::auxv::AT_BASE),
        "auxv should contain AT_BASE"
    );

    // At least some pages should have been mapped.
    assert!(
        !backend.mapped.is_empty(),
        "backend should have mapped pages"
    );
}

// ── Segment sanity checks ──────────────────────────────────────────

#[test]
fn hello_segments_have_sane_sizes() {
    let elf_bytes = read_fixture(HELLO_FIXTURE);
    let parsed = harmony_os::elf::parse_elf(&elf_bytes).expect("parse hello");

    for (i, seg) in parsed.segments.iter().enumerate() {
        // memsz must be >= filesz (ELF spec).
        assert!(
            seg.memsz >= seg.filesz,
            "segment {i}: memsz ({}) < filesz ({})",
            seg.memsz,
            seg.filesz
        );

        // Segments should not be zero-length.
        assert!(seg.memsz > 0, "segment {i}: memsz is 0");

        // Alignment should be a power of 2 (or 0/1 meaning no alignment).
        if seg.align > 1 {
            assert!(
                seg.align.is_power_of_two(),
                "segment {i}: align {} is not a power of 2",
                seg.align
            );
        }
    }
}

#[test]
fn ld_musl_segments_have_sane_sizes() {
    let elf_bytes = read_fixture(LD_MUSL_FIXTURE);
    let parsed = harmony_os::elf::parse_elf(&elf_bytes).expect("parse ld-musl");

    for (i, seg) in parsed.segments.iter().enumerate() {
        assert!(
            seg.memsz >= seg.filesz,
            "segment {i}: memsz ({}) < filesz ({})",
            seg.memsz,
            seg.filesz
        );
        assert!(seg.memsz > 0, "segment {i}: memsz is 0");
        if seg.align > 1 {
            assert!(
                seg.align.is_power_of_two(),
                "segment {i}: align {} is not a power of 2",
                seg.align
            );
        }
    }
}

// ── Stack building with real auxv ──────────────────────────────────

#[test]
fn build_stack_for_real_musl_hello() {
    use harmony_os::elf_loader::{auxv, build_initial_stack};

    let exe_bytes = read_fixture(HELLO_FIXTURE);
    let parsed = harmony_os::elf::parse_elf(&exe_bytes).expect("parse hello");

    // Build a plausible auxv from the parsed binary (without loading).
    let auxv_entries = vec![
        (auxv::AT_PHDR, parsed.phdr_offset),
        (auxv::AT_PHENT, parsed.phdr_entry_size as u64),
        (auxv::AT_PHNUM, parsed.phdr_count as u64),
        (auxv::AT_PAGESZ, 4096),
        (auxv::AT_ENTRY, parsed.entry_point),
        (auxv::AT_BASE, 0),
        (auxv::AT_RANDOM, 0), // placeholder
        (auxv::AT_NULL, 0),
    ];

    let mut stack = vec![0u8; 4096];
    let stack_base = 0x7FFF_F000_u64;
    let random_bytes = [0xABu8; 16];

    let sp = build_initial_stack(
        &mut stack,
        stack_base,
        &["./hello"],
        &["PATH=/usr/bin"],
        &auxv_entries,
        &random_bytes,
    );

    // SP should be within the stack region.
    assert!(
        sp >= stack_base && sp < stack_base + 4096,
        "SP {sp:#x} outside stack region [{stack_base:#x}, {:#x})",
        stack_base + 4096
    );

    // SP should be 16-byte aligned (ABI requirement).
    assert_eq!(sp % 16, 0, "SP {sp:#x} is not 16-byte aligned");

    // First u64 at SP should be argc == 1.
    let sp_offset = (sp - stack_base) as usize;
    let argc = u64::from_le_bytes(stack[sp_offset..sp_offset + 8].try_into().unwrap());
    assert_eq!(argc, 1, "argc should be 1");
}

// ── Fixture presence check ─────────────────────────────────────────

#[test]
fn fixture_dir_exists() {
    // This test always runs (not ignored) to verify the test
    // infrastructure is correctly set up. The fixtures directory
    // should exist even if empty.
    let fixtures = Path::new("tests/fixtures");
    assert!(fixtures.is_dir(), "tests/fixtures/ directory should exist");
}
