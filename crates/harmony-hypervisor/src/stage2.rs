// SPDX-License-Identifier: GPL-2.0-or-later
//! Stage-2 page table builder for EL2 hypervisor.
//!
//! Maps IPA (Intermediate Physical Address) → PA using runtime-selected granule
//! tables stored in VTTBR_EL2. Follows the same pattern as the Stage-1
//! implementation in `harmony_microkernel::vm::aarch64`, but with Stage-2
//! specific descriptor bits (S2AP, XN, direct MemAttr).
//!
//! The host kernel uses a compile-time granule (`PAGE_SIZE`), but guests may
//! use a different granule. [`Stage2Granule`] selects the walk geometry at
//! runtime so a 4 KiB host can map a 16 KiB guest (and vice-versa).

use crate::trap::{Stage2Flags, Stage2MemAttr};
use crate::vmid::VmId;
use harmony_microkernel::vm::{PhysAddr, VmError, PAGE_SIZE};

// ── Stage-2 descriptor bit constants ────────────────────────────────

const DESC_VALID: u64 = 0b11;
const DESC_INVALID: u64 = 0b00;
const AF: u64 = 1 << 10;
const SH_INNER: u64 = 0b11 << 8;

#[allow(dead_code)]
const S2AP_NONE: u64 = 0b00 << 6;
const S2AP_RO: u64 = 0b01 << 6;
const S2AP_WO: u64 = 0b10 << 6;
const S2AP_RW: u64 = 0b11 << 6;
pub(crate) const S2AP_MASK: u64 = 0b11 << 6;

const XN_NONE: u64 = 0;
const XN_ALL: u64 = (0b11u64) << 53;
pub(crate) const XN_MASK: u64 = 0b11u64 << 53;

pub(crate) const MEMATTR_DEVICE: u64 = 0b0000 << 2;
const MEMATTR_NORMAL_NC: u64 = 0b0101 << 2;
const MEMATTR_NORMAL_WB: u64 = 0b1111 << 2;
pub(crate) const MEMATTR_MASK: u64 = 0b1111 << 2;

// ── Runtime granule selection ─────────────────────────────────────────

/// Runtime page granule selection for guest stage-2 mappings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage2Granule {
    /// 4 KiB pages: 4-level, 512 entries, 9-bit index.
    Four,
    /// 16 KiB pages: 3-level, 2048 entries, 11-bit index.
    Sixteen,
}

impl Stage2Granule {
    pub const fn page_size(&self) -> u64 {
        match self {
            Self::Four => 4096,
            Self::Sixteen => 16384,
        }
    }
    pub const fn page_shift(&self) -> u32 {
        match self {
            Self::Four => 12,
            Self::Sixteen => 14,
        }
    }
    pub const fn level_bits(&self) -> u32 {
        match self {
            Self::Four => 9,
            Self::Sixteen => 11,
        }
    }
    pub const fn entries_per_table(&self) -> usize {
        match self {
            Self::Four => 512,
            Self::Sixteen => 2048,
        }
    }
    pub const fn start_level(&self) -> usize {
        match self {
            Self::Four => 0,
            Self::Sixteen => 1,
        }
    }
    pub const fn addr_mask(&self) -> u64 {
        match self {
            Self::Four => 0x0000_FFFF_FFFF_F000,
            Self::Sixteen => 0x0000_FFFF_FFFF_C000,
        }
    }
    pub const fn max_level(&self) -> usize {
        3
    }
}

// ── Descriptor helpers ──────────────────────────────────────────────

/// Outer Shareable — required for Device memory (ARM DDI 0487 §D8.5.5).
const SH_OUTER: u64 = 0b10 << 8;

pub(crate) fn flags_to_desc(flags: Stage2Flags) -> u64 {
    // Device memory requires Outer Shareable; Normal uses Inner Shareable.
    let sh = if flags.mem_attr == Stage2MemAttr::Device {
        SH_OUTER
    } else {
        SH_INNER
    };
    let mut desc: u64 = DESC_VALID | AF | sh;

    desc |= match (flags.readable, flags.writable) {
        (true, true) => S2AP_RW,
        (true, false) => S2AP_RO,
        (false, true) => S2AP_WO,
        (false, false) => S2AP_NONE,
    };

    if !flags.executable {
        desc |= XN_ALL;
    }

    desc |= match flags.mem_attr {
        Stage2MemAttr::NormalWriteBack => MEMATTR_NORMAL_WB,
        Stage2MemAttr::NormalNonCacheable => MEMATTR_NORMAL_NC,
        Stage2MemAttr::Device => MEMATTR_DEVICE,
    };

    desc
}

fn desc_to_flags(desc: u64) -> Stage2Flags {
    let s2ap = desc & S2AP_MASK;
    let readable = s2ap == S2AP_RO || s2ap == S2AP_RW;
    let writable = s2ap == S2AP_WO || s2ap == S2AP_RW;
    let executable = desc & XN_MASK == XN_NONE;
    let mem_attr = match desc & MEMATTR_MASK {
        MEMATTR_NORMAL_WB => Stage2MemAttr::NormalWriteBack,
        MEMATTR_NORMAL_NC => Stage2MemAttr::NormalNonCacheable,
        _ => Stage2MemAttr::Device,
    };
    Stage2Flags {
        readable,
        writable,
        executable,
        mem_attr,
    }
}

// ── Stage2PageTable ─────────────────────────────────────────────────

pub struct Stage2PageTable {
    root: PhysAddr,
    vmid: VmId,
    granule: Stage2Granule,
    phys_to_virt: fn(PhysAddr) -> *mut u8,
    /// All frames owned by this table (root + intermediates), for deallocation.
    owned_frames: alloc::vec::Vec<PhysAddr>,
}

impl Stage2PageTable {
    /// Creates a new Stage-2 page table rooted at `root`.
    ///
    /// **Precondition**: the page at `root` must already be zero-initialized.
    /// `hvc_vm_create` satisfies this via `write_bytes`; callers in other
    /// contexts must do the same.
    pub fn new(
        root: PhysAddr,
        vmid: VmId,
        granule: Stage2Granule,
        phys_to_virt: fn(PhysAddr) -> *mut u8,
    ) -> Self {
        Self {
            root,
            vmid,
            granule,
            phys_to_virt,
            owned_frames: alloc::vec![root],
        }
    }

    /// Returns all frames owned by this page table (root + intermediates).
    /// The caller is responsible for returning these to the frame allocator.
    pub fn into_owned_frames(self) -> alloc::vec::Vec<PhysAddr> {
        self.owned_frames
    }

    pub fn root_paddr(&self) -> PhysAddr {
        self.root
    }
    pub fn vmid(&self) -> VmId {
        self.vmid
    }

    pub fn map(
        &mut self,
        ipa: u64,
        pa: PhysAddr,
        flags: Stage2Flags,
        frame_alloc: &mut dyn FnMut() -> Option<PhysAddr>,
    ) -> Result<(), VmError> {
        if ipa & (self.granule.page_size() - 1) != 0 {
            return Err(VmError::Unaligned(ipa));
        }
        if pa.as_u64() & (self.granule.page_size() - 1) != 0 {
            return Err(VmError::Unaligned(pa.as_u64()));
        }

        let mut table_paddr = self.root;
        for level in ((self.granule.start_level() + 1)..=self.granule.max_level()).rev() {
            let idx = self.index(ipa, level);
            let entry = self.read_entry(table_paddr, idx);

            if entry & 0b11 == DESC_VALID {
                // Valid table descriptor — follow to next level.
                table_paddr = PhysAddr(entry & self.granule.addr_mask());
            } else if entry & 0b11 != DESC_INVALID {
                // Non-zero non-table entry (e.g., block descriptor 0b01).
                // Reject rather than silently overwrite.
                return Err(VmError::RegionConflict(harmony_microkernel::vm::VirtAddr(
                    ipa,
                )));
            } else {
                let new_frame = frame_alloc().ok_or(VmError::OutOfMemory)?;
                let new_ptr = (self.phys_to_virt)(new_frame);
                unsafe {
                    core::ptr::write_bytes(new_ptr, 0, PAGE_SIZE as usize);
                }
                self.owned_frames.push(new_frame);
                self.write_entry(
                    table_paddr,
                    idx,
                    (new_frame.as_u64() & self.granule.addr_mask()) | DESC_VALID,
                );
                table_paddr = new_frame;
            }
        }

        let idx = self.index(ipa, self.granule.start_level());
        let leaf = self.read_entry(table_paddr, idx);
        if leaf & 0b11 != DESC_INVALID {
            return Err(VmError::RegionConflict(harmony_microkernel::vm::VirtAddr(
                ipa,
            )));
        }
        self.write_entry(
            table_paddr,
            idx,
            (pa.as_u64() & self.granule.addr_mask()) | flags_to_desc(flags),
        );
        Ok(())
    }

    pub fn unmap(&mut self, ipa: u64) -> Result<PhysAddr, VmError> {
        if ipa & (self.granule.page_size() - 1) != 0 {
            return Err(VmError::Unaligned(ipa));
        }

        let mut table_paddr = self.root;
        for level in ((self.granule.start_level() + 1)..=self.granule.max_level()).rev() {
            let idx = self.index(ipa, level);
            let entry = self.read_entry(table_paddr, idx);
            if entry & 0b11 != DESC_VALID {
                return Err(VmError::NotMapped(harmony_microkernel::vm::VirtAddr(ipa)));
            }
            table_paddr = PhysAddr(entry & self.granule.addr_mask());
        }

        let idx = self.index(ipa, self.granule.start_level());
        let entry = self.read_entry(table_paddr, idx);
        if entry & 0b11 != DESC_VALID {
            return Err(VmError::NotMapped(harmony_microkernel::vm::VirtAddr(ipa)));
        }
        let pa = PhysAddr(entry & self.granule.addr_mask());
        self.write_entry(table_paddr, idx, DESC_INVALID);
        Ok(pa)
    }

    pub fn walk(&self, ipa: u64) -> Option<(PhysAddr, Stage2Flags)> {
        let mut table_paddr = self.root;
        for level in ((self.granule.start_level() + 1)..=self.granule.max_level()).rev() {
            let idx = self.index(ipa, level);
            let entry = self.read_entry(table_paddr, idx);
            if entry & 0b11 != DESC_VALID {
                return None;
            }
            table_paddr = PhysAddr(entry & self.granule.addr_mask());
        }
        let idx = self.index(ipa, self.granule.start_level());
        let entry = self.read_entry(table_paddr, idx);
        if entry & 0b11 != DESC_VALID {
            return None;
        }
        Some((
            PhysAddr(entry & self.granule.addr_mask()),
            desc_to_flags(entry),
        ))
    }

    /// Read a single 8-byte entry from a page table frame via raw pointer.
    /// Avoids fabricating `&mut [u64; 512]` references that violate aliasing rules.
    fn read_entry(&self, table_paddr: PhysAddr, idx: usize) -> u64 {
        let ptr = (self.phys_to_virt)(table_paddr) as *const u64;
        unsafe { ptr.add(idx).read() }
    }

    /// Write a single 8-byte entry to a page table frame via raw pointer.
    fn write_entry(&self, table_paddr: PhysAddr, idx: usize, value: u64) {
        let ptr = (self.phys_to_virt)(table_paddr) as *mut u64;
        unsafe { ptr.add(idx).write(value) };
    }

    fn index(&self, ipa: u64, level: usize) -> usize {
        let level_offset = (level - self.granule.start_level()) as u32;
        ((ipa >> (self.granule.page_shift() + level_offset * self.granule.level_bits()))
            & ((1u64 << self.granule.level_bits()) - 1)) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trap::{Stage2Flags, Stage2MemAttr};
    use crate::vmid::VmId;
    use alloc::vec;
    use alloc::vec::Vec;
    use harmony_microkernel::vm::PhysAddr;

    const TEST_PAGE_SIZE: u64 = 4096;

    struct TestArena {
        memory: Vec<u8>,
        next_free: usize,
    }

    impl TestArena {
        fn new(num_pages: usize) -> Self {
            // Allocate extra page for alignment
            let memory = vec![0u8; (num_pages + 1) * TEST_PAGE_SIZE as usize];
            let base = memory.as_ptr() as usize;
            let aligned = (base + TEST_PAGE_SIZE as usize - 1) & !(TEST_PAGE_SIZE as usize - 1);
            Self {
                memory,
                next_free: aligned,
            }
        }

        fn alloc_frame(&mut self) -> Option<PhysAddr> {
            let end = self.memory.as_ptr() as usize + self.memory.len();
            if self.next_free + TEST_PAGE_SIZE as usize > end {
                return None;
            }
            let addr = self.next_free;
            self.next_free += TEST_PAGE_SIZE as usize;
            unsafe {
                core::ptr::write_bytes(addr as *mut u8, 0, TEST_PAGE_SIZE as usize);
            }
            Some(PhysAddr(addr as u64))
        }

        fn phys_to_virt(pa: PhysAddr) -> *mut u8 {
            pa.0 as *mut u8
        }
    }

    #[test]
    fn map_and_walk_single_page() {
        let mut arena = TestArena::new(64);
        let root = arena.alloc_frame().unwrap();
        let mut pt =
            Stage2PageTable::new(root, VmId(1), Stage2Granule::Four, TestArena::phys_to_virt);
        let ipa = 0x4000_0000u64;
        let pa = PhysAddr(0x8000_0000);
        let flags = Stage2Flags::GUEST_RAM;
        pt.map(ipa, pa, flags, &mut || arena.alloc_frame()).unwrap();
        let result = pt.walk(ipa);
        assert_eq!(result, Some((pa, flags)));
    }

    #[test]
    fn walk_unmapped_returns_none() {
        let mut arena = TestArena::new(16);
        let root = arena.alloc_frame().unwrap();
        let pt = Stage2PageTable::new(root, VmId(1), Stage2Granule::Four, TestArena::phys_to_virt);
        assert_eq!(pt.walk(0x4000_0000), None);
    }

    #[test]
    fn map_multiple_pages() {
        let mut arena = TestArena::new(64);
        let root = arena.alloc_frame().unwrap();
        let mut pt =
            Stage2PageTable::new(root, VmId(1), Stage2Granule::Four, TestArena::phys_to_virt);
        for i in 0..4u64 {
            let ipa = 0x4000_0000 + i * TEST_PAGE_SIZE;
            let pa = PhysAddr(0x8000_0000 + i * TEST_PAGE_SIZE);
            pt.map(ipa, pa, Stage2Flags::GUEST_RAM, &mut || arena.alloc_frame())
                .unwrap();
        }
        for i in 0..4u64 {
            let ipa = 0x4000_0000 + i * TEST_PAGE_SIZE;
            let pa = PhysAddr(0x8000_0000 + i * TEST_PAGE_SIZE);
            assert_eq!(pt.walk(ipa), Some((pa, Stage2Flags::GUEST_RAM)));
        }
    }

    #[test]
    fn unmap_returns_pa() {
        let mut arena = TestArena::new(64);
        let root = arena.alloc_frame().unwrap();
        let mut pt =
            Stage2PageTable::new(root, VmId(1), Stage2Granule::Four, TestArena::phys_to_virt);
        let pa = PhysAddr(0x8000_0000);
        pt.map(0x4000_0000, pa, Stage2Flags::GUEST_RAM, &mut || {
            arena.alloc_frame()
        })
        .unwrap();
        let unmapped = pt.unmap(0x4000_0000).unwrap();
        assert_eq!(unmapped, pa);
        assert_eq!(pt.walk(0x4000_0000), None);
    }

    #[test]
    fn unmap_unmapped_returns_error() {
        let mut arena = TestArena::new(16);
        let root = arena.alloc_frame().unwrap();
        let mut pt =
            Stage2PageTable::new(root, VmId(1), Stage2Granule::Four, TestArena::phys_to_virt);
        assert!(pt.unmap(0x4000_0000).is_err());
    }

    #[test]
    fn unaligned_ipa_rejected() {
        let mut arena = TestArena::new(64);
        let root = arena.alloc_frame().unwrap();
        let mut pt =
            Stage2PageTable::new(root, VmId(1), Stage2Granule::Four, TestArena::phys_to_virt);
        let result = pt.map(
            0x4000_0001,
            PhysAddr(0x8000_0000),
            Stage2Flags::GUEST_RAM,
            &mut || arena.alloc_frame(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn descriptor_bits_correct_for_device_memory() {
        let flags = Stage2Flags {
            readable: true,
            writable: false,
            executable: false,
            mem_attr: Stage2MemAttr::Device,
        };
        let desc = flags_to_desc(flags);
        assert_eq!(desc & S2AP_MASK, S2AP_RO);
        assert_ne!(desc & XN_MASK, 0);
        assert_eq!(desc & MEMATTR_MASK, MEMATTR_DEVICE);
    }

    #[test]
    fn root_paddr_returns_root() {
        let mut arena = TestArena::new(16);
        let root = arena.alloc_frame().unwrap();
        let pt = Stage2PageTable::new(root, VmId(1), Stage2Granule::Four, TestArena::phys_to_virt);
        assert_eq!(pt.root_paddr(), root);
    }

    #[test]
    fn stage2_granule_four_geometry() {
        let g = Stage2Granule::Four;
        assert_eq!(g.page_size(), 4096);
        assert_eq!(g.page_shift(), 12);
        assert_eq!(g.level_bits(), 9);
        assert_eq!(g.entries_per_table(), 512);
        assert_eq!(g.start_level(), 0);
        assert_eq!(g.addr_mask(), 0x0000_FFFF_FFFF_F000);
    }

    #[test]
    fn stage2_granule_sixteen_geometry() {
        let g = Stage2Granule::Sixteen;
        assert_eq!(g.page_size(), 16384);
        assert_eq!(g.page_shift(), 14);
        assert_eq!(g.level_bits(), 11);
        assert_eq!(g.entries_per_table(), 2048);
        assert_eq!(g.start_level(), 1);
        assert_eq!(g.addr_mask(), 0x0000_FFFF_FFFF_C000);
    }
}
