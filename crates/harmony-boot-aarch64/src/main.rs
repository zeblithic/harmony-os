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

mod syscall;
mod vectors;

#[cfg(not(test))]
use linked_list_allocator::LockedHeap;

#[cfg(target_os = "uefi")]
use core::fmt::Write;
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

    // ── Generate Ed25519/X25519 identity ──
    let mut entropy = KernelEntropy::new(|buf: &mut [u8]| {
        unsafe { rndr::fill(buf) };
    });

    let identity = PrivateIdentity::generate(&mut entropy);
    let addr = identity.public_identity().address_hash;
    let _ = writeln!(
        serial,
        "[Identity] Generated Ed25519 address: {:02x}{:02x}{:02x}{:02x}...",
        addr[0], addr[1], addr[2], addr[3],
    );

    // ── Create runtime and enter idle loop ──
    let persistence = MemoryState::new();
    let mut runtime = UnikernelRuntime::new(identity, entropy, persistence);
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
        use harmony_os::linuxulator::{Linuxulator, LinuxSyscall, SyscallBackend};

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
                fid: harmony_microkernel::Fid,
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
