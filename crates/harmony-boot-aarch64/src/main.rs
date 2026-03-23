// SPDX-License-Identifier: GPL-2.0-or-later
//! aarch64 UEFI boot stub for Harmony unikernel.

#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]

#[cfg(not(test))]
extern crate alloc;

mod bump_alloc;
mod mmu;
mod pl011;
mod rndr;
mod timer;

mod platform;

mod syscall;
mod vectors;
mod pe;

#[cfg(not(test))]
use linked_list_allocator::LockedHeap;

#[cfg(target_os = "uefi")]
use core::fmt::Write;
#[cfg(target_os = "uefi")]
use uefi::mem::memory_map::MemoryMap as _;
#[cfg(target_os = "uefi")]
use uefi::prelude::*;

#[cfg(not(test))]
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

#[cfg(target_os = "uefi")]
use mmu::MemoryRegion;

#[cfg(target_os = "uefi")]
use harmony_identity::PrivateIdentity;
#[cfg(target_os = "uefi")]
use harmony_microkernel::vm::PAGE_SIZE;
#[cfg(target_os = "uefi")]
use harmony_unikernel::{KernelEntropy, MemoryState, UnikernelRuntime};

/// Minimum physical address for the bump allocator region.
/// We skip the first 1 MiB to avoid legacy low-memory hazards.
#[cfg(target_os = "uefi")]
const BUMP_MIN_ADDR: u64 = 0x10_0000; // 1 MiB

/// Size of the bump allocator region in bytes (2 MiB).
/// This provides ~512 frames for page table construction.
#[cfg(target_os = "uefi")]
const BUMP_REGION_SIZE: u64 = 2 * 1024 * 1024;

/// Returns `true` if a UEFI memory type represents usable RAM after
/// ExitBootServices.
///
/// After ExitBootServices, BOOT_SERVICES_CODE and BOOT_SERVICES_DATA become
/// free memory, so we include them along with CONVENTIONAL and LOADER_*.
#[cfg(target_os = "uefi")]
fn is_usable_memory(ty: uefi::mem::memory_map::MemoryType) -> bool {
    use uefi::mem::memory_map::MemoryType;
    matches!(
        ty,
        MemoryType::CONVENTIONAL
            | MemoryType::BOOT_SERVICES_CODE
            | MemoryType::BOOT_SERVICES_DATA
            | MemoryType::LOADER_CODE
            | MemoryType::LOADER_DATA
    )
}

#[cfg(target_os = "uefi")]
#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    uefi::println!("[UEFI] Booting Harmony aarch64...");

    // ── Exit boot services ── UEFI console is no longer available after this.
    // Capture the memory map -- we need it to build the identity page table.
    let memory_map = unsafe { uefi::boot::exit_boot_services(None) };

    // ── Initialise PL011 UART (115200 8N1, FIFO enabled) ──
    unsafe { pl011::init() };

    let mut serial =
        harmony_unikernel::SerialWriter::new(|byte| unsafe { pl011::write_byte(byte) });
    let _ = writeln!(serial, "[PL011] Serial initialized: 115200 8N1");

    // ── Collect UEFI memory map into fixed-size array ──
    let mut regions = [MemoryRegion {
        base: 0,
        pages: 0,
        is_usable: false,
        is_conventional: false,
    }; 128];
    let mut region_count = 0;

    for desc in memory_map.entries() {
        let usable = is_usable_memory(desc.ty);
        if !usable {
            continue; // Only store usable regions to avoid truncating them
        }
        if region_count >= regions.len() {
            let _ = writeln!(
                serial,
                "[BOOT] WARNING: memory map truncated at {} entries",
                regions.len()
            );
            break;
        }
        regions[region_count] = MemoryRegion {
            base: desc.phys_start,
            pages: desc.page_count,
            is_usable: true,
            is_conventional: desc.ty == uefi::mem::memory_map::MemoryType::CONVENTIONAL,
        };
        region_count += 1;
    }

    let _ = writeln!(
        serial,
        "[BOOT] Memory map: {} usable regions ({} conventional)",
        region_count,
        regions[..region_count]
            .iter()
            .filter(|r| r.is_conventional)
            .count()
    );

    // ── Reserve bump allocator region from the first CONVENTIONAL region >= 1 MiB ──
    // Like heap, bump must come from CONVENTIONAL memory to avoid overwriting
    // our running binary (LOADER_CODE/DATA) or the UEFI stack (BOOT_SERVICES_DATA).
    let mut bump_base: Option<u64> = None;
    for region in &regions[..region_count] {
        if !region.is_conventional {
            continue;
        }
        let region_end = region.base + region.pages * PAGE_SIZE;
        // Find a region that starts at or above BUMP_MIN_ADDR with enough space.
        let start = if region.base >= BUMP_MIN_ADDR {
            region.base
        } else if region_end > BUMP_MIN_ADDR {
            BUMP_MIN_ADDR
        } else {
            continue;
        };
        let available = region_end.saturating_sub(start);
        if available >= BUMP_REGION_SIZE {
            bump_base = Some(start);
            break;
        }
    }

    let bump_base = bump_base.expect("no suitable region for bump allocator");

    let _ = writeln!(
        serial,
        "[BOOT] Bump allocator: base={:#x} size={:#x}",
        bump_base, BUMP_REGION_SIZE
    );
    let mut bump = bump_alloc::BumpAllocator::new(bump_base, BUMP_REGION_SIZE);

    // ── Build identity map and enable MMU ──
    unsafe { mmu::init_and_enable(&regions[..region_count], &mut bump, &mut serial) };

    // ── Initialise ARM Generic Timer ──
    unsafe { timer::init() };
    assert!(
        timer::freq() != 0,
        "CNTFRQ_EL0 is zero — timer not configured by firmware"
    );
    let _ = writeln!(
        serial,
        "[Timer] ARM generic timer: freq={} Hz",
        timer::freq()
    );

    // ── Verify RNDR hardware RNG is available ──
    assert!(
        unsafe { rndr::is_available() },
        "RNDR not available — use QEMU with -cpu max"
    );
    let _ = writeln!(serial, "[RNDR] Hardware RNG available");

    // ── Initialise heap allocator ──
    // Find the largest CONVENTIONAL sub-region after carving out the bump allocator.
    // Only CONVENTIONAL memory is safe for heap: LOADER_CODE/DATA contain our
    // running binary and BOOT_SERVICES_DATA may hold the active UEFI stack.
    // On QEMU virt, most RAM is one large CONVENTIONAL descriptor that contains
    // the bump allocator, so we must carve rather than exclude the whole region.
    // Cap at 4 MiB to avoid over-committing early in boot.
    let bump_end = bump_base + BUMP_REGION_SIZE;

    let mut best_heap: Option<(u64, u64)> = None; // (base, size)
    for r in regions[..region_count].iter().filter(|r| r.is_conventional) {
        let r_end = r.base + r.pages * PAGE_SIZE;

        // Consider up to two sub-regions: before and after the bump range.
        let candidates: [(u64, u64); 2] = [
            // Sub-region before bump allocator
            if r.base < bump_base {
                (r.base, core::cmp::min(r_end, bump_base) - r.base)
            } else {
                (0, 0)
            },
            // Sub-region after bump allocator
            if r_end > bump_end {
                let start = core::cmp::max(r.base, bump_end);
                (start, r_end - start)
            } else {
                (0, 0)
            },
        ];

        for (base, size) in candidates {
            if size > 0 {
                if best_heap.map_or(true, |(_, best_size)| size > best_size) {
                    best_heap = Some((base, size));
                }
            }
        }
    }

    let (heap_base, heap_size) = best_heap.expect("no usable memory region for heap");

    let heap_size = core::cmp::min(heap_size, 4 * 1024 * 1024);

    unsafe {
        ALLOCATOR
            .lock()
            .init(heap_base as *mut u8, heap_size as usize);
    }
    let _ = writeln!(
        serial,
        "[Heap] Initialized: {} bytes at {:#x}",
        heap_size, heap_base
    );

    // ── Generate Ed25519 identity for Reticulum wire compat ──
    //    PQ identity is generated lazily by the runtime — PQ keygen's
    //    lattice operations overflow the UEFI-provided stack.
    let mut entropy = KernelEntropy::new(|buf: &mut [u8]| {
        unsafe { rndr::fill(buf) };
    });

    let identity = PrivateIdentity::generate(&mut entropy);
    let addr = identity.public_identity().address_hash;
    let _ = writeln!(
        serial,
        "[Identity] Ed25519 address: {:02x}{:02x}{:02x}{:02x}...",
        addr[0], addr[1], addr[2], addr[3],
    );

    // ── Create runtime and enter idle loop ──
    let persistence = MemoryState::new();
    let mut runtime = UnikernelRuntime::new(identity, entropy, persistence);

    // Generate PQ identity now that the heap is available.
    if let Some(pq_addr) = runtime.generate_pq_identity() {
        let _ = writeln!(
            serial,
            "[Identity] PQ address (ML-DSA-65/ML-KEM-768): {:02x}{:02x}{:02x}{:02x}...",
            pq_addr[0], pq_addr[1], pq_addr[2], pq_addr[3],
        );
    }

    let _ = writeln!(
        serial,
        "[Runtime] UnikernelRuntime created, entering idle loop"
    );

    // ── Initialise Linuxulator ──
    // Must happen BEFORE vectors::init() so the SVC dispatch function is
    // installed before any exception can fire.
    {
        use harmony_microkernel::serial_server::SerialServer;
        use harmony_microkernel::FileServer;
        use harmony_os::linuxulator::{LinuxSyscall, Linuxulator, SyscallBackend};

        let _ = writeln!(serial, "[Linux] Initializing Linuxulator");

        // DirectBackend: wraps SerialServer directly, same pattern as x86_64
        struct DirectBackend {
            server: SerialServer,
        }

        impl DirectBackend {
            fn new() -> Self {
                Self {
                    server: SerialServer::new(),
                }
            }
        }

        impl SyscallBackend for DirectBackend {
            fn walk(
                &mut self,
                _path: &str,
                new_fid: harmony_microkernel::Fid,
            ) -> Result<harmony_microkernel::QPath, harmony_microkernel::IpcError> {
                self.server.walk(0, new_fid, "log")
            }
            fn open(
                &mut self,
                fid: harmony_microkernel::Fid,
                mode: harmony_microkernel::OpenMode,
            ) -> Result<(), harmony_microkernel::IpcError> {
                self.server.open(fid, mode)
            }
            fn read(
                &mut self,
                fid: harmony_microkernel::Fid,
                offset: u64,
                count: u32,
            ) -> Result<alloc::vec::Vec<u8>, harmony_microkernel::IpcError> {
                self.server.read(fid, offset, count)
            }
            fn write(
                &mut self,
                _fid: harmony_microkernel::Fid,
                _offset: u64,
                data: &[u8],
            ) -> Result<u32, harmony_microkernel::IpcError> {
                // Route stdout/stderr writes through PL011 serial
                for &byte in data {
                    unsafe { pl011::write_byte(byte) };
                }
                Ok(data.len() as u32)
            }
            fn clunk(
                &mut self,
                fid: harmony_microkernel::Fid,
            ) -> Result<(), harmony_microkernel::IpcError> {
                self.server.clunk(fid)
            }
            fn stat(
                &mut self,
                fid: harmony_microkernel::Fid,
            ) -> Result<harmony_microkernel::FileStat, harmony_microkernel::IpcError> {
                self.server.stat(fid)
            }
        }

        // Store Linuxulator in static for the SVC handler to access
        static mut LINUXULATOR: Option<Linuxulator<DirectBackend>> = None;
        unsafe {
            LINUXULATOR = Some(Linuxulator::new(DirectBackend::new()));
            LINUXULATOR
                .as_mut()
                .unwrap()
                .init_stdio()
                .expect("init_stdio failed");
        }

        // Install dispatch function for the SVC handler
        fn dispatch(syscall: LinuxSyscall) -> syscall::SyscallDispatchResult {
            let lx = unsafe { LINUXULATOR.as_mut().unwrap() };
            let retval = lx.dispatch_syscall(syscall);
            syscall::SyscallDispatchResult {
                retval,
                exited: lx.exited(),
                exit_code: lx.exit_code().unwrap_or(0),
            }
        }
        unsafe { syscall::set_dispatch_fn(dispatch) };

        let _ = writeln!(serial, "[Linux] Linuxulator ready, SVC dispatch installed");
    }

    // ── Install exception vector table ──
    // Placed AFTER set_dispatch_fn so the SVC handler has a valid
    // dispatch target from the moment exceptions are enabled.
    unsafe { vectors::init() };
    let _ = writeln!(serial, "[Vectors] Exception vector table installed");

    // ── Phase 3: Load and run embedded test ELF ──
    let test_exit_code: i64;
    {
        use harmony_microkernel::vm::{FrameClassification, PageFlags, VmError};
        use harmony_os::elf_loader::{ElfLoader, InterpreterLoader};
        use harmony_os::linuxulator::SyscallBackend;

        // Embedded at compile time from the cross-compiled test binary.
        // Path: crates/harmony-test-elf/target/aarch64-unknown-linux-musl/release/
        static TEST_ELF: &[u8] = include_bytes!(
            "../../../crates/harmony-test-elf/target/aarch64-unknown-linux-musl/release/harmony-test-elf"
        );

        let _ = writeln!(
            serial,
            "[ELF] Loading test binary ({} bytes)",
            TEST_ELF.len()
        );

        // Bare-metal identity-map backend for the ELF loader.
        //
        // With the MMU identity map active, all RAM is directly
        // accessible at its physical address.  vm_mmap just returns the
        // requested address (no page table manipulation needed — the
        // identity map already covers it).  vm_write_bytes uses the
        // default unsafe ptr::copy implementation.
        struct IdentityMapBackend;

        impl SyscallBackend for IdentityMapBackend {
            fn walk(
                &mut self,
                _path: &str,
                _new_fid: harmony_microkernel::Fid,
            ) -> Result<harmony_microkernel::QPath, harmony_microkernel::IpcError> {
                Err(harmony_microkernel::IpcError::NotFound)
            }
            fn open(
                &mut self,
                _fid: harmony_microkernel::Fid,
                _mode: harmony_microkernel::OpenMode,
            ) -> Result<(), harmony_microkernel::IpcError> {
                Err(harmony_microkernel::IpcError::NotFound)
            }
            fn read(
                &mut self,
                _fid: harmony_microkernel::Fid,
                _offset: u64,
                _count: u32,
            ) -> Result<alloc::vec::Vec<u8>, harmony_microkernel::IpcError> {
                Err(harmony_microkernel::IpcError::NotFound)
            }
            fn write(
                &mut self,
                _fid: harmony_microkernel::Fid,
                _offset: u64,
                _data: &[u8],
            ) -> Result<u32, harmony_microkernel::IpcError> {
                Err(harmony_microkernel::IpcError::NotFound)
            }
            fn clunk(
                &mut self,
                _fid: harmony_microkernel::Fid,
            ) -> Result<(), harmony_microkernel::IpcError> {
                Ok(())
            }
            fn stat(
                &mut self,
                _fid: harmony_microkernel::Fid,
            ) -> Result<harmony_microkernel::FileStat, harmony_microkernel::IpcError> {
                Err(harmony_microkernel::IpcError::NotFound)
            }

            fn has_vm_support(&self) -> bool {
                true
            }

            fn vm_mmap(
                &mut self,
                vaddr: u64,
                _len: usize,
                _flags: PageFlags,
                _classification: FrameClassification,
            ) -> Result<u64, VmError> {
                // Identity-mapped: the address is already accessible.
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
                // No-op: identity map has full RWX in EL1.
                Ok(())
            }

            fn vm_find_free_region(&self, _len: usize) -> Result<u64, VmError> {
                Err(VmError::PageTableError)
            }
        }

        let mut backend = IdentityMapBackend;
        let mut loader = InterpreterLoader::default();

        match loader.load(TEST_ELF, &mut backend) {
            Ok(load_result) => {
                let _ = writeln!(serial, "[ELF] Loaded: entry={:#x}", load_result.entry_point,);

                // Allocate an 8 KiB stack (2 pages) for the test binary.
                let stack_base = bump.alloc_frame().expect("stack page 1 alloc failed").0;
                let stack_page2 = bump.alloc_frame().expect("stack page 2 alloc failed").0;
                assert_eq!(
                    stack_page2,
                    stack_base + 4096,
                    "stack pages must be contiguous"
                );
                let stack_top = stack_base + 8192;

                let _ = writeln!(
                    serial,
                    "[ELF] Stack: base={:#x} top={:#x}",
                    stack_base, stack_top,
                );

                // Flush instruction cache for the loaded ELF text segment.
                // The ELF data was written via store instructions (D-cache) but
                // will be fetched via I-cache.  Without explicit cache maintenance,
                // the I-cache may hold stale (zero) data from before the write.
                unsafe {
                    // Use the ELF file size as the flush range — this is an upper
                    // bound on the loaded data, so it always covers all segments
                    // regardless of binary size or segment layout.
                    let start = load_result.entry_point & !0xFFFF; // page-align down
                    let end = start + (TEST_ELF.len() as u64);
                    let mut addr = start;
                    while addr < end {
                        core::arch::asm!("dc cvau, {}", in(reg) addr);
                        addr += 64;
                    }
                    core::arch::asm!("dsb ish");
                    addr = start;
                    while addr < end {
                        core::arch::asm!("ic ivau, {}", in(reg) addr);
                        addr += 64;
                    }
                    core::arch::asm!("dsb ish", "isb");
                }

                let _ = writeln!(serial, "[ELF] Jumping to entry point...");

                let code = unsafe { run_elf_binary(load_result.entry_point, stack_top) };
                // Clear stale return context so a future exit_group doesn't
                // redirect to an invalid stack frame.
                unsafe { syscall::reset_return_context() };
                test_exit_code = code;

                let _ = writeln!(serial, "[ELF] Test binary exited with code {}", code,);
            }
            Err(e) => {
                let _ = writeln!(serial, "[ELF] FATAL: Load failed: {:?}", e);
                test_exit_code = -1;
            }
        }
    }

    let _ = writeln!(
        serial,
        "[Runtime] Entering idle loop (test exit code: {})",
        test_exit_code,
    );

    loop {
        let now = timer::now_ms();
        let actions = runtime.tick(now);
        for action in actions {
            let _ = writeln!(serial, "[Runtime] action: {:?}", action);
        }
        // WFE = Wait For Event — ARM equivalent of HLT, saves power
        unsafe { core::arch::asm!("wfe") };
    }
}

// ── ELF binary trampoline ─────────────────────────────────────────────
// Saves kernel context (SP, LR), installs a return-address for the SVC
// handler's exit_group path, switches to the binary's stack, and jumps
// to the ELF entry point.  When exit_group fires, the SVC handler
// rewrites ELR to .Lelf_return (via set_return_context), restoring the
// kernel SP and LR so that `ret` returns to the Rust caller.

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".global run_elf_binary",
    "run_elf_binary:",
    // x0 = entry_point, x1 = stack_top
    // AAPCS64 prologue: save callee-saved regs + LR
    "stp x19, x20, [sp, #-32]!",
    "stp x29, x30, [sp, #16]",
    "mov x29, sp",
    // Save args in callee-saved regs
    "mov x19, x0", // x19 = entry_point
    "mov x20, x1", // x20 = stack_top
    // Register return context for the SVC handler's exit_group path.
    // SP is captured AFTER the prologue push so .Lelf_return can pop.
    "adr x0, .Lelf_return", // arg0 = return address
    "mov x1, sp",           // arg1 = kernel SP (post-prologue)
    "mov x2, x30",          // arg2 = kernel LR
    "bl set_return_context",
    // Switch to binary stack and jump to entry
    "mov sp, x20",
    "br x19",
    // Landing pad — SVC handler sets ELR here on exit_group.
    // Register state is fully controlled by the TrapFrame restore:
    //   x0 = exit code
    //   x1 = saved kernel SP (post-prologue)
    //   x2 = saved kernel LR
    ".Lelf_return:",
    "mov sp, x1",  // restore kernel SP (post-prologue)
    // AAPCS64 epilogue: restore callee-saved regs + LR
    "ldp x29, x30, [sp, #16]",
    "ldp x19, x20, [sp], #32",
    "ret",         // return to Rust caller with exit code in x0
);

#[cfg(target_arch = "aarch64")]
extern "C" {
    /// Run an ELF binary at `entry_point` with `stack_top` as its SP.
    ///
    /// Returns the process exit code when exit_group fires.  The SVC
    /// handler redirects control to `.Lelf_return` which restores the
    /// kernel context and returns here.
    fn run_elf_binary(entry_point: u64, stack_top: u64) -> i64;
}

// ── Panic handler ──────────────────────────────────────────────────────
// The uefi crate's panic_handler feature is disabled because after
// ExitBootServices the UEFI console is gone. This custom handler
// prints to PL011 serial so panics are visible in QEMU.

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    #[cfg(target_arch = "aarch64")]
    {
        let mut serial = harmony_unikernel::SerialWriter::new(|byte: u8| {
            unsafe { pl011::write_byte(byte) };
        });
        use core::fmt::Write;
        let _ = writeln!(serial, "\n!!! PANIC: {}", info);
    }
    loop {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("wfe")
        };
        #[cfg(not(target_arch = "aarch64"))]
        core::hint::spin_loop();
    }
}
