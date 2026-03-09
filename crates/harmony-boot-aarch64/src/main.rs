// SPDX-License-Identifier: GPL-2.0-or-later
//! aarch64 UEFI boot stub for Harmony unikernel.

#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]

#[cfg(not(test))]
extern crate alloc;

mod bump_alloc;
mod mmu;
mod pl011;

#[cfg(target_os = "uefi")]
use core::fmt::Write;
#[cfg(target_os = "uefi")]
use uefi::mem::memory_map::MemoryMap;
#[cfg(target_os = "uefi")]
use uefi::prelude::*;

#[cfg(target_os = "uefi")]
use mmu::MemoryRegion;

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

    if bump_base == 0 {
        let _ = writeln!(
            serial,
            "[BOOT] FATAL: no suitable region for bump allocator"
        );
        loop {
            core::hint::spin_loop();
        }
    }

    let _ = writeln!(
        serial,
        "[BOOT] Bump allocator: base={:#x} size={:#x}",
        bump_base, BUMP_REGION_SIZE
    );
    let mut bump = bump_alloc::BumpAllocator::new(bump_base, BUMP_REGION_SIZE);

    // ── Build identity map and enable MMU ──
    unsafe { mmu::init_and_enable(&regions[..region_count], &mut bump, &mut serial) };

    // We cannot return Status::SUCCESS after ExitBootServices -- the UEFI
    // runtime no longer owns control flow. Loop forever (subsequent tasks
    // will replace this with a proper event loop / idle halt).
    loop {
        core::hint::spin_loop();
    }
}
