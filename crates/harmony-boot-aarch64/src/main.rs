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

#[cfg(not(test))]
use linked_list_allocator::LockedHeap;

#[cfg(target_os = "uefi")]
use core::fmt::Write;
#[cfg(target_os = "uefi")]
use uefi::mem::memory_map::MemoryMap;
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
    }; 128];
    let mut region_count = 0;

    for desc in memory_map.entries() {
        if region_count >= regions.len() {
            break;
        }
        let usable = is_usable_memory(desc.ty);
        regions[region_count] = MemoryRegion {
            base: desc.phys_start,
            pages: desc.page_count,
            is_usable: usable,
        };
        region_count += 1;
    }

    let _ = writeln!(
        serial,
        "[BOOT] Memory map: {} regions ({} usable)",
        region_count,
        regions[..region_count]
            .iter()
            .filter(|r| r.is_usable)
            .count()
    );

    // ── Reserve bump allocator region from the first usable region >= 1 MiB ──
    let mut bump_base: u64 = 0;
    for region in &regions[..region_count] {
        if !region.is_usable {
            continue;
        }
        let region_end = region.base + region.pages * 4096;
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
            bump_base = start;
            break;
        }
    }

    assert!(bump_base != 0, "no suitable region for bump allocator");

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
    // Find the largest usable memory region that doesn't overlap the bump
    // allocator range.  Cap at 4 MiB to avoid over-committing early in boot.
    let bump_end = bump_base + BUMP_REGION_SIZE;

    let (heap_base, heap_size) = regions[..region_count]
        .iter()
        .filter(|r| {
            r.is_usable && {
                let r_end = r.base + r.pages * PAGE_SIZE;
                // Exclude regions that overlap the bump allocator range
                r_end <= bump_base || r.base >= bump_end
            }
        })
        .map(|r| (r.base, r.pages * PAGE_SIZE))
        .max_by_key(|(_, size)| *size)
        .expect("no usable memory region for heap");

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

#[cfg(target_os = "uefi")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let mut serial = harmony_unikernel::SerialWriter::new(|byte: u8| {
        unsafe { pl011::write_byte(byte) };
    });
    use core::fmt::Write;
    let _ = writeln!(serial, "\n!!! PANIC: {}", info);
    loop {
        unsafe { core::arch::asm!("wfe") };
    }
}
