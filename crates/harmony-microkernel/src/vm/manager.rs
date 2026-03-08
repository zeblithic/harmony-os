// SPDX-License-Identifier: GPL-2.0-or-later
//! Address space manager — orchestrates page tables, buddy allocator, and capabilities.
//!
//! [`AddressSpaceManager`] is the central coordinator for virtual memory. It
//! owns the physical frame allocator ([`BuddyAllocator`]), capability tracker
//! ([`CapTracker`]), and per-process page tables. All policy decisions —
//! budget enforcement, region overlap checks, frame classification tracking —
//! happen here. The page table trait handles only hardware-level mapping.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::buddy::BuddyAllocator;
use super::cap_tracker::{CapTracker, MemoryBudget};
use super::page_table::PageTable;
use super::{FrameClassification, PageFlags, PhysAddr, VirtAddr, VmError, PAGE_SIZE};

// ── Constants ────────────────────────────────────────────────────────

/// Start of the user-space virtual address range (skip null-page guard).
const USER_SPACE_START: u64 = 0x1000;

/// End of the user-space virtual address range (guard before kernel half).
const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_F000;

// ── Data structures ──────────────────────────────────────────────────

/// A contiguous virtual memory region within a process's address space.
pub struct Region {
    /// Length of the region in bytes (always page-aligned).
    pub len: usize,
    /// Permission flags for all pages in this region.
    pub flags: PageFlags,
    /// Frame classification (ENCRYPTED, EPHEMERAL, etc.).
    pub classification: FrameClassification,
    /// Physical frames backing this region, one per page.
    pub frames: Vec<PhysAddr>,
}

/// Per-process address space: a page table plus tracked regions.
pub struct ProcessSpace<P: PageTable> {
    /// The hardware (or mock) page table for this process.
    pub page_table: P,
    /// Mapped regions keyed by their base virtual address.
    pub regions: BTreeMap<VirtAddr, Region>,
}

/// Central address space manager.
///
/// Coordinates the buddy allocator, capability tracker, and per-process
/// page tables. All VM policy is enforced here.
pub struct AddressSpaceManager<P: PageTable> {
    spaces: BTreeMap<u32, ProcessSpace<P>>,
    buddy: BuddyAllocator,
    cap_tracker: CapTracker,
}

impl<P: PageTable> AddressSpaceManager<P> {
    /// Create a new manager with the given buddy allocator, empty process
    /// table, and a fresh capability tracker.
    pub fn new(buddy: BuddyAllocator) -> Self {
        Self {
            spaces: BTreeMap::new(),
            buddy,
            cap_tracker: CapTracker::new(),
        }
    }

    /// Create a new process address space.
    ///
    /// Rejects duplicate PIDs with [`VmError::ProcessExists`].
    pub fn create_space(
        &mut self,
        pid: u32,
        budget: MemoryBudget,
        page_table: P,
    ) -> Result<(), VmError> {
        if self.spaces.contains_key(&pid) {
            return Err(VmError::ProcessExists(pid));
        }
        self.cap_tracker.set_budget(pid, budget);
        self.spaces.insert(
            pid,
            ProcessSpace {
                page_table,
                regions: BTreeMap::new(),
            },
        );
        Ok(())
    }

    /// Map a region of virtual memory for a process.
    ///
    /// Allocates physical frames, maps them via the page table, records
    /// each mapping in the capability tracker, and stores the region.
    pub fn map_region(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        len: usize,
        flags: PageFlags,
        classification: FrameClassification,
    ) -> Result<(), VmError> {
        // Page-align len upward, reject 0.
        if len == 0 {
            return Err(VmError::Unaligned(0));
        }
        let aligned_len = ((len as u64 + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)) as usize;
        let page_count = aligned_len / PAGE_SIZE as usize;

        // Ensure the process exists.
        if !self.spaces.contains_key(&pid) {
            return Err(VmError::NoSuchProcess(pid));
        }

        // Check budget.
        self.cap_tracker
            .check_budget(pid, aligned_len, classification)?;

        // Check overlap with existing regions (immutable borrow on space, released after).
        {
            let space = self.spaces.get(&pid).unwrap();
            let region_start = vaddr.as_u64();
            let region_end = region_start + aligned_len as u64;

            for (&existing_vaddr, existing_region) in &space.regions {
                let existing_start = existing_vaddr.as_u64();
                let existing_end = existing_start + existing_region.len as u64;

                if region_start < existing_end && region_end > existing_start {
                    return Err(VmError::RegionConflict(existing_vaddr));
                }
            }
        }

        // Allocate frames from buddy (roll back on OOM).
        let mut frames = Vec::with_capacity(page_count);
        for _ in 0..page_count {
            match self.buddy.alloc_frame() {
                Some(paddr) => frames.push(paddr),
                None => {
                    // Roll back: free all frames allocated so far.
                    for frame in &frames {
                        let _ = self.buddy.free_frame(*frame);
                    }
                    return Err(VmError::OutOfMemory);
                }
            }
        }

        // Map each page via page_table. Split borrow: `spaces` and `buddy`
        // are disjoint fields, so we can mutably borrow both simultaneously.
        // The buddy allocator provides frames for intermediate page table
        // levels (PDP/PD/PT on x86_64, L1/L2/L3 on aarch64).
        {
            let Self { spaces, buddy, .. } = self;
            let space = spaces.get_mut(&pid).unwrap();
            let mut intermediate_frames: Vec<PhysAddr> = Vec::new();
            for (i, &paddr) in frames.iter().enumerate() {
                let page_vaddr = VirtAddr(vaddr.as_u64() + (i as u64) * PAGE_SIZE);
                let result = space.page_table.map(page_vaddr, paddr, flags, &mut || {
                    let frame = buddy.alloc_frame()?;
                    intermediate_frames.push(frame);
                    Some(frame)
                });
                if let Err(e) = result {
                    // Roll back page table mappings already done.
                    for j in 0..i {
                        let rollback_vaddr = VirtAddr(vaddr.as_u64() + (j as u64) * PAGE_SIZE);
                        let _ = space.page_table.unmap(rollback_vaddr);
                    }
                    // Free all allocated data frames.
                    for frame in &frames {
                        let _ = buddy.free_frame(*frame);
                    }
                    // Free intermediate page table frames allocated so far.
                    for frame in &intermediate_frames {
                        let _ = buddy.free_frame(*frame);
                    }
                    return Err(e);
                }
            }
        }

        // Record each mapping in cap_tracker.
        for &paddr in &frames {
            self.cap_tracker.record_mapping(paddr, pid, classification);
        }

        // Insert the region.
        let space = self.spaces.get_mut(&pid).unwrap();
        space.regions.insert(
            vaddr,
            Region {
                len: aligned_len,
                flags,
                classification,
                frames,
            },
        );

        Ok(())
    }

    /// Unmap a region previously mapped at `vaddr` for process `pid`.
    ///
    /// Removes page table mappings, frees physical frames, and updates
    /// the capability tracker.
    pub fn unmap_region(&mut self, pid: u32, vaddr: VirtAddr) -> Result<(), VmError> {
        let space = self
            .spaces
            .get_mut(&pid)
            .ok_or(VmError::NoSuchProcess(pid))?;

        let region = space
            .regions
            .remove(&vaddr)
            .ok_or(VmError::NotMapped(vaddr))?;

        // Unmap each page from the page table.
        let page_count = region.len / PAGE_SIZE as usize;
        for i in 0..page_count {
            let page_vaddr = VirtAddr(vaddr.as_u64() + (i as u64) * PAGE_SIZE);
            let _ = space.page_table.unmap(page_vaddr);
        }

        // Remove from cap_tracker and free frames.
        for &paddr in &region.frames {
            let _classification = self.cap_tracker.remove_mapping(paddr, pid);
            // NOTE: If classification contains ENCRYPTED, the frame contents
            // should be zeroized before freeing. Hardware page table impls
            // will handle this; the mock does not model frame contents.
            let _ = self.buddy.free_frame(paddr);
        }

        Ok(())
    }

    /// Change the permission flags on an existing region.
    pub fn protect_region(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        new_flags: PageFlags,
    ) -> Result<(), VmError> {
        let space = self
            .spaces
            .get_mut(&pid)
            .ok_or(VmError::NoSuchProcess(pid))?;

        let region = space
            .regions
            .get_mut(&vaddr)
            .ok_or(VmError::NotMapped(vaddr))?;

        let page_count = region.len / PAGE_SIZE as usize;
        for i in 0..page_count {
            let page_vaddr = VirtAddr(vaddr.as_u64() + (i as u64) * PAGE_SIZE);
            space.page_table.set_flags(page_vaddr, new_flags)?;
        }

        region.flags = new_flags;
        Ok(())
    }

    /// Destroy a process's entire address space.
    ///
    /// Unmaps all regions, frees all physical frames, and removes the
    /// process's budget from the capability tracker.
    pub fn destroy_space(&mut self, pid: u32) -> Result<(), VmError> {
        let mut space = self
            .spaces
            .remove(&pid)
            .ok_or(VmError::NoSuchProcess(pid))?;

        for (vaddr, region) in &space.regions {
            // Unmap each page from the page table. This clears leaf entries
            // so the page table is in a consistent state before drop.
            // TODO(harmony-qv2): intermediate page table frames (PDP/PD/PT
            // levels) are not freed by unmap — they need a dedicated
            // PageTable::destroy() method to walk and reclaim.
            let page_count = region.len / PAGE_SIZE as usize;
            for i in 0..page_count {
                let page_vaddr = VirtAddr(vaddr.as_u64() + (i as u64) * PAGE_SIZE);
                let _ = space.page_table.unmap(page_vaddr);
            }

            for &paddr in &region.frames {
                let _ = self.cap_tracker.remove_mapping(paddr, pid);
                let _ = self.buddy.free_frame(paddr);
            }
        }

        self.cap_tracker.remove_budget(pid);
        Ok(())
    }

    /// Find a free region of at least `len` bytes using first-fit from
    /// `USER_SPACE_START` upward.
    pub fn find_free_region(&self, pid: u32, len: usize) -> Result<VirtAddr, VmError> {
        let space = self.spaces.get(&pid).ok_or(VmError::NoSuchProcess(pid))?;

        if len == 0 {
            return Err(VmError::Unaligned(0));
        }
        let aligned_len = (len as u64 + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        let mut candidate = USER_SPACE_START;

        // BTreeMap iterates in sorted order, so no extra sort needed.
        let sorted_regions: Vec<(u64, u64)> = space
            .regions
            .iter()
            .map(|(va, r)| (va.as_u64(), va.as_u64() + r.len as u64))
            .collect();

        for &(region_start, region_end) in &sorted_regions {
            if candidate + aligned_len <= region_start {
                // Found a gap before this region.
                return Ok(VirtAddr(candidate));
            }
            // Skip past this region.
            if region_end > candidate {
                candidate = region_end;
            }
        }

        // Check if there's space after the last region.
        if candidate + aligned_len <= USER_SPACE_END {
            return Ok(VirtAddr(candidate));
        }

        Err(VmError::OutOfMemory)
    }

    /// Activate the page table for the given process.
    pub fn switch_to(&mut self, pid: u32) -> Result<(), VmError> {
        let space = self
            .spaces
            .get_mut(&pid)
            .ok_or(VmError::NoSuchProcess(pid))?;
        space.page_table.activate();
        Ok(())
    }

    /// Mutable access to the buddy allocator.
    pub fn buddy(&mut self) -> &mut BuddyAllocator {
        &mut self.buddy
    }

    /// Read-only access to the capability tracker.
    pub fn cap_tracker(&self) -> &CapTracker {
        &self.cap_tracker
    }

    /// Read-only access to a process's address space.
    pub fn space(&self, pid: u32) -> Option<&ProcessSpace<P>> {
        self.spaces.get(&pid)
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::mock::MockPageTable;
    use super::*;

    fn make_manager(frame_count: usize) -> AddressSpaceManager<MockPageTable> {
        let buddy = BuddyAllocator::new(PhysAddr(0x10_0000), frame_count).unwrap();
        AddressSpaceManager::new(buddy)
    }

    fn default_budget() -> MemoryBudget {
        MemoryBudget::new(PAGE_SIZE as usize * 64, FrameClassification::all())
    }

    fn rw_user_flags() -> PageFlags {
        PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::USER
    }

    fn mock_pt() -> MockPageTable {
        MockPageTable::new(PhysAddr(0x20_0000))
    }

    #[test]
    fn create_and_destroy_space() {
        let mut mgr = make_manager(16);

        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        assert!(mgr.space(1).is_some());

        mgr.destroy_space(1).unwrap();
        assert!(mgr.space(1).is_none());
    }

    #[test]
    fn map_and_translate() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();

        let vaddr = VirtAddr(0x1000);
        let flags = rw_user_flags();
        mgr.map_region(
            1,
            vaddr,
            PAGE_SIZE as usize,
            flags,
            FrameClassification::empty(),
        )
        .unwrap();

        let space = mgr.space(1).unwrap();
        let (paddr, got_flags) = space.page_table.translate(vaddr).expect("should be mapped");
        assert!(paddr.is_page_aligned());
        assert_eq!(got_flags, flags);
    }

    #[test]
    fn unmap_frees_frames() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();

        let initial_free = mgr.buddy().free_frame_count();

        let vaddr = VirtAddr(0x1000);
        let len = PAGE_SIZE as usize * 4;
        mgr.map_region(1, vaddr, len, rw_user_flags(), FrameClassification::empty())
            .unwrap();

        assert_eq!(mgr.buddy().free_frame_count(), initial_free - 4);

        mgr.unmap_region(1, vaddr).unwrap();
        assert_eq!(mgr.buddy().free_frame_count(), initial_free);
    }

    #[test]
    fn budget_enforcement() {
        let mut mgr = make_manager(16);
        let small_budget = MemoryBudget::new(PAGE_SIZE as usize * 2, FrameClassification::all());
        mgr.create_space(1, small_budget, mock_pt()).unwrap();

        // Map 2 pages — should succeed.
        mgr.map_region(
            1,
            VirtAddr(0x1000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();

        // Map 1 more — should fail with BudgetExceeded.
        let err = mgr
            .map_region(
                1,
                VirtAddr(0x3000),
                PAGE_SIZE as usize,
                rw_user_flags(),
                FrameClassification::empty(),
            )
            .unwrap_err();
        assert!(
            matches!(err, VmError::BudgetExceeded { .. }),
            "expected BudgetExceeded, got {:?}",
            err
        );
    }

    #[test]
    fn region_overlap_rejected() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();

        // Map a 2-page region at 0x1000.
        mgr.map_region(
            1,
            VirtAddr(0x1000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();

        // Overlapping region at 0x2000 (overlaps second page of first region? No,
        // first region is 0x1000..0x3000). Let's overlap at 0x2000.
        let err = mgr
            .map_region(
                1,
                VirtAddr(0x2000),
                PAGE_SIZE as usize,
                rw_user_flags(),
                FrameClassification::empty(),
            )
            .unwrap_err();
        assert!(
            matches!(err, VmError::RegionConflict(_)),
            "expected RegionConflict, got {:?}",
            err
        );
    }

    #[test]
    fn protect_region_updates_flags() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();

        let vaddr = VirtAddr(0x1000);
        mgr.map_region(
            1,
            vaddr,
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();

        let new_flags = PageFlags::READABLE | PageFlags::EXECUTABLE | PageFlags::USER;
        mgr.protect_region(1, vaddr, new_flags).unwrap();

        let space = mgr.space(1).unwrap();
        let (_, got_flags) = space.page_table.translate(vaddr).unwrap();
        assert_eq!(got_flags, new_flags);
    }

    #[test]
    fn destroy_frees_all_frames() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();

        let initial_free = mgr.buddy().free_frame_count();

        mgr.map_region(
            1,
            VirtAddr(0x1000),
            PAGE_SIZE as usize * 8,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();

        assert_eq!(mgr.buddy().free_frame_count(), initial_free - 8);

        mgr.destroy_space(1).unwrap();
        assert_eq!(mgr.buddy().free_frame_count(), initial_free);
    }

    #[test]
    fn find_free_region_first_fit() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();

        // Empty space: first fit starts at USER_SPACE_START.
        let addr = mgr.find_free_region(1, PAGE_SIZE as usize).unwrap();
        assert_eq!(addr, VirtAddr(USER_SPACE_START));

        // Map a region at USER_SPACE_START.
        mgr.map_region(
            1,
            VirtAddr(USER_SPACE_START),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();

        // Next free region should be right after the mapped region.
        let addr2 = mgr.find_free_region(1, PAGE_SIZE as usize).unwrap();
        assert_eq!(addr2, VirtAddr(USER_SPACE_START + PAGE_SIZE * 2));
    }

    #[test]
    fn encrypted_frame_classification_tracked() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();

        let vaddr = VirtAddr(0x1000);
        mgr.map_region(
            1,
            vaddr,
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::ENCRYPTED,
        )
        .unwrap();

        // Verify cap_tracker has the entry.
        let encrypted_frames = mgr
            .cap_tracker()
            .frames_with_classification(FrameClassification::ENCRYPTED);
        assert_eq!(encrypted_frames.len(), 1);
        assert_eq!(encrypted_frames[0].1, vec![1]); // PID 1

        // Unmap and verify removed.
        mgr.unmap_region(1, vaddr).unwrap();
        let encrypted_frames = mgr
            .cap_tracker()
            .frames_with_classification(FrameClassification::ENCRYPTED);
        assert_eq!(encrypted_frames.len(), 0);
    }

    #[test]
    fn out_of_memory_rolls_back() {
        let mut mgr = make_manager(4);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();

        // Request 8 pages from a 4-frame buddy — should fail with OOM.
        let err = mgr
            .map_region(
                1,
                VirtAddr(0x1000),
                PAGE_SIZE as usize * 8,
                rw_user_flags(),
                FrameClassification::empty(),
            )
            .unwrap_err();
        assert_eq!(err, VmError::OutOfMemory);

        // All 4 frames should still be available (rollback succeeded).
        assert_eq!(mgr.buddy().free_frame_count(), 4);
    }

    #[test]
    fn switch_to_activates_page_table() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();

        // Not activated yet.
        assert!(!mgr.space(1).unwrap().page_table.is_activated());

        mgr.switch_to(1).unwrap();
        assert!(mgr.space(1).unwrap().page_table.is_activated());
    }

    #[test]
    fn multi_region_mapping() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();

        let flags = rw_user_flags();

        // Map region A at 0x1000 (2 pages).
        mgr.map_region(
            1,
            VirtAddr(0x1000),
            PAGE_SIZE as usize * 2,
            flags,
            FrameClassification::empty(),
        )
        .unwrap();

        // Map region B at 0x5000 (2 pages), leaving a gap.
        mgr.map_region(
            1,
            VirtAddr(0x5000),
            PAGE_SIZE as usize * 2,
            flags,
            FrameClassification::empty(),
        )
        .unwrap();

        let space = mgr.space(1).unwrap();

        // Both regions should translate.
        assert!(space.page_table.translate(VirtAddr(0x1000)).is_some());
        assert!(space.page_table.translate(VirtAddr(0x2000)).is_some());
        assert!(space.page_table.translate(VirtAddr(0x5000)).is_some());
        assert!(space.page_table.translate(VirtAddr(0x6000)).is_some());

        // Gap should not be mapped.
        assert!(space.page_table.translate(VirtAddr(0x3000)).is_none());
        assert!(space.page_table.translate(VirtAddr(0x4000)).is_none());
    }

    #[test]
    fn nonexistent_process_errors() {
        let mut mgr = make_manager(16);

        assert_eq!(
            mgr.map_region(
                99,
                VirtAddr(0x1000),
                PAGE_SIZE as usize,
                rw_user_flags(),
                FrameClassification::empty(),
            )
            .unwrap_err(),
            VmError::NoSuchProcess(99)
        );

        assert_eq!(
            mgr.unmap_region(99, VirtAddr(0x1000)).unwrap_err(),
            VmError::NoSuchProcess(99)
        );

        assert_eq!(
            mgr.protect_region(99, VirtAddr(0x1000), rw_user_flags())
                .unwrap_err(),
            VmError::NoSuchProcess(99)
        );

        assert_eq!(
            mgr.destroy_space(99).unwrap_err(),
            VmError::NoSuchProcess(99)
        );

        assert_eq!(
            mgr.find_free_region(99, PAGE_SIZE as usize).unwrap_err(),
            VmError::NoSuchProcess(99)
        );

        assert_eq!(mgr.switch_to(99).unwrap_err(), VmError::NoSuchProcess(99));
    }
}
