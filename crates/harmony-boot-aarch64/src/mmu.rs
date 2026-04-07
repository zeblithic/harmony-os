// SPDX-License-Identifier: GPL-2.0-or-later
//! MMU configuration -- identity map + system register setup for aarch64.
//!
//! After ExitBootServices, builds an identity map (virt == phys) for all usable
//! RAM and all platform MMIO regions, configures MAIR_EL1 / TCR_EL1, and enables
//! the MMU via SCTLR_EL1.

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
use crate::platform;

// ── Memory region descriptor ────────────────────────────────────────

/// A contiguous physical memory region from the UEFI memory map.
#[derive(Clone, Copy)]
pub struct MemoryRegion {
    /// Physical base address (page-aligned).
    pub base: u64,
    /// Number of 4 KiB pages in this region.
    pub pages: u64,
    /// Whether this region is usable RAM (vs. reserved/MMIO/ACPI).
    /// True for CONVENTIONAL, BOOT_SERVICES_*, and LOADER_*.
    pub is_usable: bool,
    /// Whether this region is safe for heap allocation.
    /// True only for CONVENTIONAL memory. LOADER_CODE/DATA contain the
    /// running binary and BOOT_SERVICES_DATA may hold the active stack,
    /// so those must not be used as heap.
    pub is_conventional: bool,
}

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
/// - T0SZ  (bits [5:0])   -> VA space size: 16 (48-bit, 4K) or 17 (47-bit, 16K)
/// - TG0   (bits [15:14]) -> Granule: 0b00 (4 KiB) or 0b10 (16 KiB)
/// - SH0   = 0b11 (bits [13:12]) -> Inner Shareable
/// - ORGN0 = 0b01 (bits [11:10]) -> Normal, Outer Write-Back RA WA Cacheable
/// - IRGN0 = 0b01 (bits [9:8])   -> Normal, Inner Write-Back RA WA Cacheable
///
/// Note: IPS (bits [34:32]) is set at runtime in [`configure_system_regs`] by
/// reading ID_AA64MMFR0_EL1.PARange to match the platform's physical address
/// width. This base value leaves IPS=0 as a placeholder.
///
/// EPD1 (bit 23) disables TTBR1_EL1 table walks. Since we only use the lower
/// VA range (TTBR0), any speculative access to an upper-half VA should fault
/// immediately rather than walking from TTBR1's uninitialized reset value.
#[cfg(not(feature = "page-16k"))]
const TCR_VALUE: u64 = {
    let t0sz: u64 = 16; // 48-bit VA
    let irgn0: u64 = 0b01 << 8; // Inner WB RA WA
    let orgn0: u64 = 0b01 << 10; // Outer WB RA WA
    let sh0: u64 = 0b11 << 12; // Inner Shareable
    let tg0: u64 = 0b00 << 14; // 4 KiB granule
    let epd1: u64 = 1 << 23; // Disable TTBR1 walks
    t0sz | irgn0 | orgn0 | sh0 | tg0 | epd1
};

#[cfg(feature = "page-16k")]
const TCR_VALUE: u64 = {
    let t0sz: u64 = 17; // 47-bit VA
    let irgn0: u64 = 0b01 << 8; // Inner WB RA WA
    let orgn0: u64 = 0b01 << 10; // Outer WB RA WA
    let sh0: u64 = 0b11 << 12; // Inner Shareable
    let tg0: u64 = 0b10 << 14; // 16 KiB granule
    let epd1: u64 = 1 << 23; // Disable TTBR1 walks
    t0sz | irgn0 | orgn0 | sh0 | tg0 | epd1
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
/// When `image_sections` is `Some`, code pages are mapped RX and data pages RW
/// (W^X enforced). When `None`, all RAM is mapped RWX as a fallback.
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
    image_sections: Option<&crate::pe::ImageSections>,
) {
    // 1. Allocate and zero the root (L0) page table frame.
    let root_frame = alloc
        .alloc_frame()
        .expect("bump allocator exhausted: cannot allocate root page table");
    zero_frame(root_frame);

    // 2. Create the page table with an identity phys_to_virt mapping.
    let mut pt = Aarch64PageTable::new(root_frame, identity_phys_to_virt);

    // 3. Map all usable RAM regions as Normal cacheable memory.
    //
    // W^X: when image_sections is Some, each page within the image is mapped
    // with per-section flags (code=RX, data=RW, rodata=RO). Pages outside the
    // image (heap, stack, ELF load targets) remain RWX because vm_mprotect is
    // currently a no-op — the ELF loader relies on it to set RX on text segments
    // after writing them. Until vm_mprotect is implemented (requires page table
    // access from SyscallBackend), outside-image pages must stay executable.
    // TODO(harmony-os-fg5-followup): implement real vm_mprotect, then change
    // default_outside to RW and keep fallback_flags as a separate decision.
    let rwx = PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::EXECUTABLE;
    let fallback_flags = rwx;
    let default_outside = rwx;

    if image_sections.is_none() {
        let _ = writeln!(
            serial,
            "[MMU] WARNING: W^X disabled — mapping all RAM as RWX"
        );
    }

    let mut mapped_pages: u64 = 0;

    for region in regions {
        if !region.is_usable {
            continue;
        }
        for page_idx in 0..region.pages {
            let addr = region.base + page_idx * PAGE_SIZE;
            let flags = match image_sections {
                Some(sections) => sections.flags_for_addr(addr).unwrap_or(default_outside),
                None => fallback_flags,
            };
            let result = pt.map(VirtAddr(addr), PhysAddr(addr), flags, &mut || {
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

    // 4. Map platform MMIO regions as Device memory (NO_CACHE).
    let mmio_flags = PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::NO_CACHE;
    for &(base, pages) in platform::MMIO_REGIONS {
        for page_idx in 0..pages {
            let addr = base as u64 + page_idx as u64 * PAGE_SIZE;
            let mmio_result = pt.map(VirtAddr(addr), PhysAddr(addr), mmio_flags, &mut || {
                alloc_zeroed_frame(alloc)
            });
            match mmio_result {
                Ok(()) => mapped_pages += 1,
                Err(VmError::RegionConflict(_)) => {
                    let _ = writeln!(
                        serial,
                        "[MMU] WARNING: MMIO {:#x} conflicts — mapped as Normal memory, MMIO unreliable",
                        addr,
                    );
                }
                Err(e) => {
                    let _ = writeln!(serial, "[MMU] MMIO map error at {:#x}: {:?}", addr, e);
                }
            }
        }
    }

    let _ = writeln!(serial, "[MMU] Mapped {} pages", mapped_pages);

    if image_sections.is_some() {
        let _ = writeln!(
            serial,
            "[MMU] W^X partial: image code=RX, image data=RW, outside image=RWX (vm_mprotect TODO)"
        );
    }

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
/// Note: `Aarch64PageTable::map()` zeroes intermediate table frames itself,
/// so this pre-zeroing is defensive rather than strictly required.
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
/// 4. Write TCR_EL1 (translation control: VA size, granule, cacheability, IPS).
/// 5. Write TTBR0_EL1 (root page table physical address).
/// 6. ISB to ensure register writes complete.
/// 7. Read-modify-write SCTLR_EL1 to set M (MMU), C (D-cache), I (I-cache).
/// 8. ISB after SCTLR write.
///
/// TCR_EL1.IPS is read from ID_AA64MMFR0_EL1.PARange at runtime so the
/// physical address space matches the platform (e.g. 36-bit on some cores,
/// 48-bit on others).
///
/// # Safety
///
/// Must only be called once, with a valid root page table address in
/// `root_paddr`. The page table must contain a correct identity mapping
/// covering all code and stack memory currently in use.
#[cfg(target_arch = "aarch64")]
unsafe fn configure_system_regs(root_paddr: u64) {
    // Read the platform's physical address range from ID_AA64MMFR0_EL1[3:0]
    // and place it into TCR_EL1.IPS (bits [34:32]).
    let mmfr0: u64;
    core::arch::asm!("mrs {}, id_aa64mmfr0_el1", out(reg) mmfr0);
    // PARange is 4 bits [3:0] but IPS is only 3 bits [34:32]. Mask to 3 bits
    // to avoid writing into TCR_EL1.AS (bit 35) if a future CPU reports a
    // PARange value with bit 3 set.
    let pa_range = mmfr0 & 0x7; // IPS field is 3 bits wide
    let tcr = TCR_VALUE | (pa_range << 32); // IPS = PARange[2:0]

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
        // Set translation control (with runtime IPS from ID_AA64MMFR0_EL1)
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
        tcr = in(reg) tcr,
        ttbr = in(reg) root_paddr,
        sctlr_bits = in(reg) SCTLR_M | SCTLR_C | SCTLR_I,
        tmp = out(reg) _,
        options(nostack),
    );
}

/// Mark a single page as inaccessible (guard page).
///
/// Reads TTBR0_EL1 to reconstruct the page table, then unmaps the page
/// at `addr`. Any subsequent access triggers a data abort. A TLB
/// invalidation ensures the stale mapping is flushed.
///
/// # Safety
///
/// - `addr` must be page-aligned and currently mapped in the identity map.
/// - The MMU must be enabled (`init_and_enable` must have been called).
/// - Must not be called concurrently with other page table modifications.
#[cfg(target_arch = "aarch64")]
pub unsafe fn mark_guard_page(addr: u64) {
    let root: u64;
    core::arch::asm!("mrs {}, ttbr0_el1", out(reg) root);

    let mut pt = Aarch64PageTable::new(PhysAddr(root), identity_phys_to_virt);

    // Unmap the page. The no-op deallocator discards the frame address —
    // the bump allocator cannot free, and the frame stays reserved as a
    // guard (not reclaimable memory).
    pt.unmap(VirtAddr(addr), &mut |_| {})
        .expect("mark_guard_page: unmap failed — page not in identity map");

    // TLB invalidate for this specific VA.
    // TLBI VALE1IS: invalidate by VA, last-level, EL1, Inner Shareable.
    // The register contains VA[47:12] (VA shifted right by 12).
    core::arch::asm!(
        "dsb ishst",
        "tlbi vale1is, {va}",
        "dsb ish",
        "isb",
        va = in(reg) addr >> 12,
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

    #[cfg(not(feature = "page-16k"))]
    #[test]
    fn tcr_value_correct() {
        // Note: IPS (bits [34:32]) is set at runtime from ID_AA64MMFR0_EL1,
        // so TCR_VALUE has IPS=0 as a placeholder.
        assert_eq!((TCR_VALUE >> 32) & 0b111, 0b000);
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
        // EPD1 = 1 (disable TTBR1 walks)
        assert_eq!((TCR_VALUE >> 23) & 0b1, 0b1);
    }

    #[cfg(feature = "page-16k")]
    #[test]
    fn tcr_value_correct_16k() {
        // IPS placeholder = 0
        assert_eq!((TCR_VALUE >> 32) & 0b111, 0b000);
        // T0SZ = 17 (47-bit VA)
        assert_eq!(TCR_VALUE & 0x3F, 17);
        // IRGN0 = 0b01 (WB RA WA)
        assert_eq!((TCR_VALUE >> 8) & 0b11, 0b01);
        // ORGN0 = 0b01 (WB RA WA)
        assert_eq!((TCR_VALUE >> 10) & 0b11, 0b01);
        // SH0 = 0b11 (Inner Shareable)
        assert_eq!((TCR_VALUE >> 12) & 0b11, 0b11);
        // TG0 = 0b10 (16 KiB granule)
        assert_eq!((TCR_VALUE >> 14) & 0b11, 0b10);
        // EPD1 = 1 (disable TTBR1 walks)
        assert_eq!((TCR_VALUE >> 23) & 0b1, 0b1);
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
            is_conventional: true,
        };
        assert_eq!(r.base, 0x4_0000);
        assert_eq!(r.pages, 256);
        assert!(r.is_usable);
        assert!(r.is_conventional);
    }

    #[test]
    fn identity_phys_to_virt_returns_same_address() {
        let pa = PhysAddr(0xDEAD_B000);
        let ptr = identity_phys_to_virt(pa);
        assert_eq!(ptr as u64, 0xDEAD_B000);
    }
}
