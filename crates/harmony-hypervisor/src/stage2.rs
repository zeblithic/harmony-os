// SPDX-License-Identifier: GPL-2.0-or-later
//! Stage-2 page table builder for EL2 hypervisor.
//!
//! Maps IPA (Intermediate Physical Address) → PA using 4-level, 4KiB granule
//! tables stored in VTTBR_EL2. Follows the same pattern as the Stage-1
//! implementation in `harmony_microkernel::vm::aarch64`, but with Stage-2
//! specific descriptor bits (S2AP, XN, direct MemAttr).

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

const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

// ── Descriptor helpers ──────────────────────────────────────────────

pub(crate) fn flags_to_desc(flags: Stage2Flags) -> u64 {
    let mut desc: u64 = DESC_VALID | AF | SH_INNER;

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
    phys_to_virt: fn(PhysAddr) -> *mut u8,
}

impl Stage2PageTable {
    pub fn new(root: PhysAddr, vmid: VmId, phys_to_virt: fn(PhysAddr) -> *mut u8) -> Self {
        Self {
            root,
            vmid,
            phys_to_virt,
        }
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
        if ipa & (PAGE_SIZE - 1) != 0 {
            return Err(VmError::Unaligned(ipa));
        }
        if !pa.is_page_aligned() {
            return Err(VmError::Unaligned(pa.as_u64()));
        }

        let mut table_paddr = self.root;
        for level in (1..=3).rev() {
            let table = self.table_mut(table_paddr);
            let idx = Self::index(ipa, level);
            let entry = table[idx];

            if entry & 0b11 != DESC_INVALID {
                table_paddr = PhysAddr(entry & ADDR_MASK);
            } else {
                let new_frame = frame_alloc().ok_or(VmError::OutOfMemory)?;
                let new_ptr = (self.phys_to_virt)(new_frame);
                unsafe {
                    core::ptr::write_bytes(new_ptr, 0, PAGE_SIZE as usize);
                }
                table[idx] = (new_frame.as_u64() & ADDR_MASK) | DESC_VALID;
                table_paddr = new_frame;
            }
        }

        let table = self.table_mut(table_paddr);
        let idx = Self::index(ipa, 0);
        if table[idx] & 0b11 != DESC_INVALID {
            return Err(VmError::RegionConflict(harmony_microkernel::vm::VirtAddr(
                ipa,
            )));
        }
        table[idx] = (pa.as_u64() & ADDR_MASK) | flags_to_desc(flags);
        Ok(())
    }

    pub fn unmap(&mut self, ipa: u64) -> Result<PhysAddr, VmError> {
        if ipa & (PAGE_SIZE - 1) != 0 {
            return Err(VmError::Unaligned(ipa));
        }

        let mut table_paddr = self.root;
        for level in (1..=3).rev() {
            let table = self.table_mut(table_paddr);
            let idx = Self::index(ipa, level);
            let entry = table[idx];
            if entry & 0b11 == DESC_INVALID {
                return Err(VmError::NotMapped(harmony_microkernel::vm::VirtAddr(ipa)));
            }
            table_paddr = PhysAddr(entry & ADDR_MASK);
        }

        let table = self.table_mut(table_paddr);
        let idx = Self::index(ipa, 0);
        let entry = table[idx];
        if entry & 0b11 == DESC_INVALID {
            return Err(VmError::NotMapped(harmony_microkernel::vm::VirtAddr(ipa)));
        }
        let pa = PhysAddr(entry & ADDR_MASK);
        table[idx] = DESC_INVALID;
        Ok(pa)
    }

    pub fn walk(&self, ipa: u64) -> Option<(PhysAddr, Stage2Flags)> {
        let mut table_paddr = self.root;
        for level in (1..=3).rev() {
            let table = self.table_ref(table_paddr);
            let idx = Self::index(ipa, level);
            let entry = table[idx];
            if entry & 0b11 == DESC_INVALID {
                return None;
            }
            table_paddr = PhysAddr(entry & ADDR_MASK);
        }
        let table = self.table_ref(table_paddr);
        let idx = Self::index(ipa, 0);
        let entry = table[idx];
        if entry & 0b11 == DESC_INVALID {
            return None;
        }
        Some((PhysAddr(entry & ADDR_MASK), desc_to_flags(entry)))
    }

    #[allow(clippy::mut_from_ref)]
    fn table_mut(&self, table_paddr: PhysAddr) -> &mut [u64; 512] {
        let ptr = (self.phys_to_virt)(table_paddr);
        unsafe { &mut *(ptr as *mut [u64; 512]) }
    }

    fn table_ref(&self, table_paddr: PhysAddr) -> &[u64; 512] {
        let ptr = (self.phys_to_virt)(table_paddr);
        unsafe { &*(ptr as *const [u64; 512]) }
    }

    fn index(ipa: u64, level: usize) -> usize {
        ((ipa >> (12 + level * 9)) & 0x1FF) as usize
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
        let mut pt = Stage2PageTable::new(root, VmId(1), TestArena::phys_to_virt);
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
        let pt = Stage2PageTable::new(root, VmId(1), TestArena::phys_to_virt);
        assert_eq!(pt.walk(0x4000_0000), None);
    }

    #[test]
    fn map_multiple_pages() {
        let mut arena = TestArena::new(64);
        let root = arena.alloc_frame().unwrap();
        let mut pt = Stage2PageTable::new(root, VmId(1), TestArena::phys_to_virt);
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
        let mut pt = Stage2PageTable::new(root, VmId(1), TestArena::phys_to_virt);
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
        let mut pt = Stage2PageTable::new(root, VmId(1), TestArena::phys_to_virt);
        assert!(pt.unmap(0x4000_0000).is_err());
    }

    #[test]
    fn unaligned_ipa_rejected() {
        let mut arena = TestArena::new(64);
        let root = arena.alloc_frame().unwrap();
        let mut pt = Stage2PageTable::new(root, VmId(1), TestArena::phys_to_virt);
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
        let pt = Stage2PageTable::new(root, VmId(1), TestArena::phys_to_virt);
        assert_eq!(pt.root_paddr(), root);
    }
}
