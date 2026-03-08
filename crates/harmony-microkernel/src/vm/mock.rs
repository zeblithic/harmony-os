// SPDX-License-Identifier: GPL-2.0-or-later
//! Mock page table for testing — in-memory `BTreeMap`-based implementation.

use alloc::collections::BTreeMap;

use super::page_table::PageTable;
use super::{PageFlags, PhysAddr, VirtAddr, VmError};

/// A mock page table that stores mappings in a `BTreeMap`.
///
/// Useful for host-side testing of the VM subsystem without requiring
/// actual hardware page tables. Alignment is enforced but intermediate
/// table levels are not modelled.
pub struct MockPageTable {
    mappings: BTreeMap<VirtAddr, (PhysAddr, PageFlags)>,
    root: PhysAddr,
    activated: bool,
}

impl MockPageTable {
    /// Create a new mock page table with the given root physical address.
    pub fn new(root: PhysAddr) -> Self {
        Self {
            mappings: BTreeMap::new(),
            root,
            activated: false,
        }
    }

    /// Returns `true` if [`PageTable::activate`] has been called.
    pub fn is_activated(&self) -> bool {
        self.activated
    }

    /// Returns the number of currently mapped pages.
    pub fn mapped_count(&self) -> usize {
        self.mappings.len()
    }
}

impl PageTable for MockPageTable {
    fn map(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PageFlags,
        _frame_alloc: &mut dyn FnMut() -> Option<PhysAddr>,
    ) -> Result<(), VmError> {
        if !vaddr.is_page_aligned() {
            return Err(VmError::Unaligned(vaddr.as_u64()));
        }
        if !paddr.is_page_aligned() {
            return Err(VmError::Unaligned(paddr.as_u64()));
        }
        if self.mappings.contains_key(&vaddr) {
            return Err(VmError::RegionConflict(vaddr));
        }
        self.mappings.insert(vaddr, (paddr, flags));
        Ok(())
    }

    fn unmap(&mut self, vaddr: VirtAddr) -> Result<PhysAddr, VmError> {
        if !vaddr.is_page_aligned() {
            return Err(VmError::Unaligned(vaddr.as_u64()));
        }
        self.mappings
            .remove(&vaddr)
            .map(|(paddr, _)| paddr)
            .ok_or(VmError::NotMapped(vaddr))
    }

    fn set_flags(&mut self, vaddr: VirtAddr, flags: PageFlags) -> Result<(), VmError> {
        if !vaddr.is_page_aligned() {
            return Err(VmError::Unaligned(vaddr.as_u64()));
        }
        let entry = self
            .mappings
            .get_mut(&vaddr)
            .ok_or(VmError::NotMapped(vaddr))?;
        entry.1 = flags;
        Ok(())
    }

    fn translate(&self, vaddr: VirtAddr) -> Option<(PhysAddr, PageFlags)> {
        self.mappings.get(&vaddr).copied()
    }

    fn activate(&mut self) {
        self.activated = true;
    }

    fn root_paddr(&self) -> PhysAddr {
        self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: u64 = 4096;

    fn rw_flags() -> PageFlags {
        PageFlags::READABLE | PageFlags::WRITABLE
    }

    fn noop_alloc() -> impl FnMut() -> Option<PhysAddr> {
        || None
    }

    #[test]
    fn map_and_translate() {
        let mut pt = MockPageTable::new(PhysAddr(0x10_0000));
        let vaddr = VirtAddr(PAGE);
        let paddr = PhysAddr(2 * PAGE);
        let flags = rw_flags();

        pt.map(vaddr, paddr, flags, &mut noop_alloc()).unwrap();

        let (got_paddr, got_flags) = pt.translate(vaddr).expect("should be mapped");
        assert_eq!(got_paddr, paddr);
        assert_eq!(got_flags, flags);
    }

    #[test]
    fn translate_unmapped_returns_none() {
        let pt = MockPageTable::new(PhysAddr(0x10_0000));
        assert!(pt.translate(VirtAddr(PAGE)).is_none());
    }

    #[test]
    fn unmap_returns_paddr() {
        let mut pt = MockPageTable::new(PhysAddr(0x10_0000));
        let vaddr = VirtAddr(PAGE);
        let paddr = PhysAddr(2 * PAGE);

        pt.map(vaddr, paddr, rw_flags(), &mut noop_alloc())
            .unwrap();

        let returned = pt.unmap(vaddr).unwrap();
        assert_eq!(returned, paddr);
        assert!(pt.translate(vaddr).is_none());
    }

    #[test]
    fn unmap_unmapped_returns_error() {
        let mut pt = MockPageTable::new(PhysAddr(0x10_0000));
        let result = pt.unmap(VirtAddr(PAGE));
        assert_eq!(result, Err(VmError::NotMapped(VirtAddr(PAGE))));
    }

    #[test]
    fn map_unaligned_rejected() {
        let mut pt = MockPageTable::new(PhysAddr(0x10_0000));
        let result = pt.map(
            VirtAddr(0x1234),
            PhysAddr(PAGE),
            rw_flags(),
            &mut noop_alloc(),
        );
        assert_eq!(result, Err(VmError::Unaligned(0x1234)));
    }

    #[test]
    fn map_duplicate_rejected() {
        let mut pt = MockPageTable::new(PhysAddr(0x10_0000));
        let vaddr = VirtAddr(PAGE);

        pt.map(vaddr, PhysAddr(2 * PAGE), rw_flags(), &mut noop_alloc())
            .unwrap();

        let result = pt.map(vaddr, PhysAddr(3 * PAGE), rw_flags(), &mut noop_alloc());
        assert_eq!(result, Err(VmError::RegionConflict(vaddr)));
    }

    #[test]
    fn set_flags_updates_permissions() {
        let mut pt = MockPageTable::new(PhysAddr(0x10_0000));
        let vaddr = VirtAddr(PAGE);
        let paddr = PhysAddr(2 * PAGE);

        pt.map(vaddr, paddr, PageFlags::READABLE, &mut noop_alloc())
            .unwrap();

        let new_flags = PageFlags::READABLE | PageFlags::EXECUTABLE;
        pt.set_flags(vaddr, new_flags).unwrap();

        let (_, got_flags) = pt.translate(vaddr).unwrap();
        assert_eq!(got_flags, new_flags);
    }

    #[test]
    fn activate_sets_flag() {
        let mut pt = MockPageTable::new(PhysAddr(0x10_0000));
        assert!(!pt.is_activated());
        pt.activate();
        assert!(pt.is_activated());
    }

    #[test]
    fn root_paddr_returns_root() {
        let root = PhysAddr(0xDEAD_0000);
        let pt = MockPageTable::new(root);
        assert_eq!(pt.root_paddr(), root);
    }
}
