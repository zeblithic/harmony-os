// SPDX-License-Identifier: GPL-2.0-or-later
//! MMU configuration -- identity map + system register setup for aarch64.
//!
//! After ExitBootServices, builds an identity map (virt == phys) for all usable
//! RAM and the PL011 MMIO page, configures MAIR_EL1 / TCR_EL1, and enables the
//! MMU via SCTLR_EL1.

// Constants and functions used only by the aarch64-gated `init_and_enable`
// appear unused on non-aarch64 host builds (x86_64 test runner).
#![cfg_attr(not(target_arch = "aarch64"), allow(dead_code, unused_imports))]

use core::fmt::Write;

use harmony_microkernel::vm::{PageFlags, PhysAddr, VirtAddr, VmError, PAGE_SIZE};

#[cfg(target_arch = "aarch64")]
use harmony_microkernel::vm::aarch64::Aarch64PageTable;

#[cfg(target_arch = "aarch64")]
use harmony_microkernel::vm::page_table::PageTable;

use crate::bump_alloc::BumpAllocator;

// ── Memory region descriptor ────────────────────────────────────────

/// A contiguous physical memory region from the UEFI memory map.
#[derive(Clone, Copy)]
pub struct MemoryRegion {
    /// Physical base address (page-aligned).
    pub base: u64,
    /// Number of 4 KiB pages in this region.
    pub pages: u64,
    /// Whether this region is usable RAM (vs. reserved/MMIO/ACPI).
    pub is_usable: bool,
}

// ── PL011 MMIO address ──────────────────────────────────────────────

/// PL011 UART base address on QEMU aarch64 `virt` platform.
const PL011_MMIO_BASE: u64 = 0x0900_0000;

// ── System register constants ───────────────────────────────────────

/// MAIR_EL1: Memory Attribute Indirection Register.
///
/// - Attr0 (index 0) = 0xFF: Normal memory, Inner/Outer Write-Back cacheable,
///   Read-Allocate, Write-Allocate.
/// - Attr1 (index 1) = 0x00: Device-nGnRnE (strongly-ordered device memory).
///
/// The Aarch64PageTable implementation maps:
///   PageFlags without NO_CACHE -> AttrIndx=0 (ATTR_NORMAL = 0 << 2)
///   PageFlags with NO_CACHE    -> AttrIndx=1 (ATTR_DEVICE = 1 << 2)
const MAIR_VALUE: u64 = 0x00FF;

/// TCR_EL1: Translation Control Register.
///
/// Configuration for TTBR0 (lower VA range):
/// - T0SZ  = 16  (bits [5:0])   -> 48-bit virtual address space
/// - TG0   = 0b00 (bits [15:14]) -> 4 KiB granule
/// - SH0   = 0b11 (bits [13:12]) -> Inner Shareable
/// - ORGN0 = 0b01 (bits [11:10]) -> Normal, Outer Write-Back RA WA Cacheable
/// - IRGN0 = 0b01 (bits [9:8])   -> Normal, Inner Write-Back RA WA Cacheable
const TCR_VALUE: u64 = {
    let t0sz: u64 = 16; // 48-bit VA
    let irgn0: u64 = 0b01 << 8; // Inner WB RA WA
    let orgn0: u64 = 0b01 << 10; // Outer WB RA WA
    let sh0: u64 = 0b11 << 12; // Inner Shareable
    let tg0: u64 = 0b00 << 14; // 4 KiB granule
    t0sz | irgn0 | orgn0 | sh0 | tg0
};

/// SCTLR_EL1 bit: MMU enable.
const SCTLR_M: u64 = 1 << 0;
/// SCTLR_EL1 bit: Data cache enable.
const SCTLR_C: u64 = 1 << 2;
/// SCTLR_EL1 bit: Instruction cache enable.
const SCTLR_I: u64 = 1 << 12;

// ── Public API ──────────────────────────────────────────────────────

/// Build an identity page table over the given memory regions and enable the MMU.
///
/// # Safety
///
/// - Must be called exactly once, after ExitBootServices.
/// - `regions` must accurately describe the physical memory layout.
/// - `alloc` must provide valid, unused physical frames.
/// - The caller must ensure no other code modifies system registers concurrently.
#[cfg(target_arch = "aarch64")]
pub unsafe fn init_and_enable(
    regions: &[MemoryRegion],
    alloc: &mut BumpAllocator,
    serial: &mut impl Write,
) {
    // 1. Allocate and zero the root (L0) page table frame.
    let root_frame = alloc
        .alloc_frame()
        .expect("bump allocator exhausted: cannot allocate root page table");
    zero_frame(root_frame);

    // 2. Create the page table with an identity phys_to_virt mapping.
    let mut pt = Aarch64PageTable::new(root_frame, identity_phys_to_virt);

    // 3. Map all usable RAM regions as Normal cacheable memory.
    let ram_flags = PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::EXECUTABLE;
    let mut mapped_pages: u64 = 0;

    for region in regions {
        if !region.is_usable {
            continue;
        }
        for page_idx in 0..region.pages {
            let addr = region.base + page_idx * PAGE_SIZE;
            let result = pt.map(VirtAddr(addr), PhysAddr(addr), ram_flags, &mut || {
                alloc_zeroed_frame(alloc)
            });
            match result {
                Ok(()) => mapped_pages += 1,
                // Overlapping UEFI memory map regions can cause conflicts -- skip.
                Err(VmError::RegionConflict(_)) => {}
                Err(e) => {
                    let _ = writeln!(serial, "[MMU] map error at {:#x}: {:?}", addr, e);
                }
            }
        }
    }

    // 4. Map the PL011 MMIO page as Device memory (NO_CACHE).
    let mmio_flags = PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::NO_CACHE;
    let mmio_result = pt.map(
        VirtAddr(PL011_MMIO_BASE),
        PhysAddr(PL011_MMIO_BASE),
        mmio_flags,
        &mut || alloc_zeroed_frame(alloc),
    );
    match mmio_result {
        Ok(()) => mapped_pages += 1,
        Err(VmError::RegionConflict(_)) => {
            // Already mapped as part of a usable region -- acceptable.
        }
        Err(e) => {
            let _ = writeln!(serial, "[MMU] PL011 MMIO map error: {:?}", e);
        }
    }

    let _ = writeln!(serial, "[MMU] Mapped {} pages", mapped_pages);

    // 5. Configure system registers and enable the MMU.
    //
    // Aarch64PageTable::activate() is gated behind cfg(target_os = "none"),
    // which does not match our uefi target. We handle TTBR0, MAIR, TCR,
    // SCTLR, and TLB invalidation in a single asm block.
    configure_system_regs(pt.root_paddr().as_u64());

    let _ = writeln!(serial, "[MMU] MMU enabled");
}

// ── Helper functions ────────────────────────────────────────────────

/// Identity phys-to-virt mapping: in an identity map, virt == phys.
fn identity_phys_to_virt(pa: PhysAddr) -> *mut u8 {
    pa.as_u64() as *mut u8
}

/// Allocate a frame from the bump allocator and zero it before returning.
///
/// `Aarch64PageTable::map()` requires intermediate table frames to be zeroed
/// so that all 512 entries start as invalid descriptors.
fn alloc_zeroed_frame(alloc: &mut BumpAllocator) -> Option<PhysAddr> {
    let frame = alloc.alloc_frame()?;
    unsafe { zero_frame(frame) };
    Some(frame)
}

/// Zero a 4 KiB frame at the given physical address.
///
/// # Safety
///
/// The caller must ensure `frame` points to a valid, writable 4 KiB region.
unsafe fn zero_frame(frame: PhysAddr) {
    core::ptr::write_bytes(frame.as_u64() as *mut u8, 0, PAGE_SIZE as usize);
}

/// Configure MAIR_EL1, TCR_EL1, TTBR0_EL1, and enable the MMU via SCTLR_EL1.
///
/// The ARM-recommended cold-start sequence:
/// 1. DSB + ISB to synchronize before touching translation registers.
/// 2. TLBI vmalle1is + DSB ISH + ISB to invalidate stale TLB entries first.
/// 3. Write MAIR_EL1 (memory attribute definitions).
/// 4. Write TCR_EL1 (translation control: VA size, granule, cacheability).
/// 5. Write TTBR0_EL1 (root page table physical address).
/// 6. ISB to ensure register writes complete.
/// 7. Read-modify-write SCTLR_EL1 to set M (MMU), C (D-cache), I (I-cache).
/// 8. ISB after SCTLR write.
///
/// # Safety
///
/// Must only be called once, with a valid root page table address in
/// `root_paddr`. The page table must contain a correct identity mapping
/// covering all code and stack memory currently in use.
#[cfg(target_arch = "aarch64")]
unsafe fn configure_system_regs(root_paddr: u64) {
    core::arch::asm!(
        // Synchronize before touching translation registers
        "dsb ish",
        "isb",
        // Invalidate all stale TLB entries BEFORE writing translation regs
        "tlbi vmalle1is",
        "dsb ish",
        "isb",
        // Set memory attributes
        "msr mair_el1, {mair}",
        // Set translation control
        "msr tcr_el1, {tcr}",
        // Set translation table base
        "msr ttbr0_el1, {ttbr}",
        // Ensure writes are visible before enabling MMU
        "isb",
        // Read-modify-write SCTLR_EL1 to enable MMU + caches
        "mrs {tmp}, sctlr_el1",
        "orr {tmp}, {tmp}, {sctlr_bits}",
        "msr sctlr_el1, {tmp}",
        // Synchronize after MMU enable
        "isb",
        mair = in(reg) MAIR_VALUE,
        tcr = in(reg) TCR_VALUE,
        ttbr = in(reg) root_paddr,
        sctlr_bits = in(reg) SCTLR_M | SCTLR_C | SCTLR_I,
        tmp = out(reg) _,
        options(nostack),
    );
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mair_value_correct() {
        // Attr0 (bits [7:0]) = 0xFF -> Normal WB cacheable
        assert_eq!(MAIR_VALUE & 0xFF, 0xFF);
        // Attr1 (bits [15:8]) = 0x00 -> Device-nGnRnE
        assert_eq!((MAIR_VALUE >> 8) & 0xFF, 0x00);
    }

    #[test]
    fn tcr_value_correct() {
        // T0SZ = 16 (48-bit VA)
        assert_eq!(TCR_VALUE & 0x3F, 16);
        // IRGN0 = 0b01 (WB RA WA)
        assert_eq!((TCR_VALUE >> 8) & 0b11, 0b01);
        // ORGN0 = 0b01 (WB RA WA)
        assert_eq!((TCR_VALUE >> 10) & 0b11, 0b01);
        // SH0 = 0b11 (Inner Shareable)
        assert_eq!((TCR_VALUE >> 12) & 0b11, 0b11);
        // TG0 = 0b00 (4 KiB granule)
        assert_eq!((TCR_VALUE >> 14) & 0b11, 0b00);
    }

    #[test]
    fn sctlr_bits_correct() {
        assert_eq!(SCTLR_M, 1 << 0);
        assert_eq!(SCTLR_C, 1 << 2);
        assert_eq!(SCTLR_I, 1 << 12);
    }

    #[test]
    fn memory_region_default() {
        let r = MemoryRegion {
            base: 0x4_0000,
            pages: 256,
            is_usable: true,
        };
        assert_eq!(r.base, 0x4_0000);
        assert_eq!(r.pages, 256);
        assert!(r.is_usable);
    }

    #[test]
    fn identity_phys_to_virt_returns_same_address() {
        let pa = PhysAddr(0xDEAD_B000);
        let ptr = identity_phys_to_virt(pa);
        assert_eq!(ptr as u64, 0xDEAD_B000);
    }
}
