// SPDX-License-Identifier: GPL-2.0-or-later

//! ELF loader benchmarks.
//!
//! Measures the cost of parsing and loading a minimal static ELF binary.
//! Uses a mock backend that accepts mmap/write without real memory mapping.

use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use harmony_microkernel::vm::{FrameClassification, PageFlags, VmError};
use harmony_microkernel::{Fid, FileStat, FileType, IpcError, OpenMode, QPath};
use harmony_os::elf_loader::boot_static_elf;
use harmony_os::linuxulator::SyscallBackend;

// ── Minimal ELF backend ─────────────────────────────────────────────

/// Mock backend that accepts VM operations without real memory mapping.
/// ELF loading needs mmap (segment mapping) and vm_write_bytes (segment data).
struct ElfBenchBackend {
    next_vaddr: u64,
}

impl ElfBenchBackend {
    fn new() -> Self {
        Self {
            next_vaddr: 0x40_0000,
        }
    }
}

impl SyscallBackend for ElfBenchBackend {
    fn walk(&mut self, _path: &str, _new_fid: Fid) -> Result<QPath, IpcError> {
        Err(IpcError::NotFound)
    }
    fn open(&mut self, _fid: Fid, _mode: OpenMode) -> Result<(), IpcError> {
        Ok(())
    }
    fn read(&mut self, _fid: Fid, _offset: u64, _count: u32) -> Result<Vec<u8>, IpcError> {
        Ok(Vec::new())
    }
    fn write(&mut self, _fid: Fid, _offset: u64, _data: &[u8]) -> Result<u32, IpcError> {
        Ok(0)
    }
    fn clunk(&mut self, _fid: Fid) -> Result<(), IpcError> {
        Ok(())
    }
    fn stat(&mut self, _fid: Fid) -> Result<FileStat, IpcError> {
        Ok(FileStat {
            qpath: 0,
            name: Arc::from("bench"),
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
        _flags: PageFlags,
        _classification: FrameClassification,
    ) -> Result<u64, VmError> {
        if vaddr != 0 {
            Ok(vaddr)
        } else {
            let addr = self.next_vaddr;
            self.next_vaddr += len as u64;
            Ok(addr)
        }
    }
    fn vm_munmap(&mut self, _vaddr: u64, _len: usize) -> Result<(), VmError> {
        Ok(())
    }
    fn vm_mprotect(&mut self, _vaddr: u64, _len: usize, _flags: PageFlags) -> Result<(), VmError> {
        Ok(())
    }
    fn vm_find_free_region(&self, _len: usize) -> Result<u64, VmError> {
        Ok(self.next_vaddr)
    }
    fn vm_write_bytes(&mut self, _addr: u64, _data: &[u8]) {
        // No-op: don't actually write to memory.
    }
}

// ── Test ELF ────────────────────────────────────────────────────────

/// Build a minimal static x86_64 ELF binary (just headers, one PT_LOAD).
/// This is the simplest valid ELF that boot_static_elf can process.
fn build_minimal_elf() -> Vec<u8> {
    let mut elf = Vec::new();

    // ELF header (64 bytes)
    elf.extend_from_slice(&[0x7f, b'E', b'L', b'F']); // e_ident magic
    elf.push(2); // EI_CLASS: ELFCLASS64
    elf.push(1); // EI_DATA: little-endian
    elf.push(1); // EI_VERSION: current
    elf.push(0); // EI_OSABI: ELFOSABI_NONE
    elf.extend_from_slice(&[0; 8]); // padding
    elf.extend_from_slice(&2u16.to_le_bytes()); // e_type: ET_EXEC
    elf.extend_from_slice(&0x3Eu16.to_le_bytes()); // e_machine: EM_X86_64
    elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
    elf.extend_from_slice(&0x40_1000u64.to_le_bytes()); // e_entry
    elf.extend_from_slice(&64u64.to_le_bytes()); // e_phoff (phdr starts right after ehdr)
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff (no section headers)
    elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum: 1 segment
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx

    // Program header: PT_LOAD (56 bytes)
    let phdr_offset = elf.len();
    elf.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
    elf.extend_from_slice(&5u32.to_le_bytes()); // p_flags: PF_R | PF_X
    elf.extend_from_slice(&0u64.to_le_bytes()); // p_offset
    elf.extend_from_slice(&0x40_0000u64.to_le_bytes()); // p_vaddr
    elf.extend_from_slice(&0x40_0000u64.to_le_bytes()); // p_paddr
    let _ = phdr_offset; // suppress unused warning

    // File size and mem size = total ELF size (header + phdr + code)
    let total_size = 64 + 56 + 4; // ehdr + phdr + tiny code
    elf.extend_from_slice(&(total_size as u64).to_le_bytes()); // p_filesz
    elf.extend_from_slice(&(total_size as u64).to_le_bytes()); // p_memsz
    elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align

    // Tiny code at offset 120 (entry - vaddr = 0x401000 - 0x400000 = 0x1000)
    // We need the file to be at least entry_offset bytes.
    // Simpler: set entry = vaddr of segment start (0x400000 + 120)
    // and put a ret instruction there.
    elf.extend_from_slice(&[0xc3, 0x90, 0x90, 0x90]); // ret + nop padding

    // Fix entry point to point at the code we just wrote.
    let entry = 0x40_0000u64 + (64 + 56) as u64; // vaddr + code offset
    elf[24..32].copy_from_slice(&entry.to_le_bytes());

    elf
}

// ── Benchmarks ──────────────────────────────────────────────────────

fn bench_boot_static_elf(c: &mut Criterion) {
    let elf = build_minimal_elf();
    let random = [0u8; 16];

    c.bench_function("elf_loader/boot_static_elf", |b| {
        b.iter_batched(
            ElfBenchBackend::new,
            |mut backend| {
                let result = boot_static_elf(
                    &mut backend,
                    black_box(&elf),
                    &["bench"],
                    &[],
                    &random,
                    0x7FFF_F000,
                    0x1000,
                )
                .unwrap();
                black_box(result);
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_boot_static_elf);
criterion_main!(benches);
