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

// ── Helpers ──────────────────────────────────────────────────────────

/// Compute the page-level overlap between a region starting at `base`
/// with length `region_len` and a query range `[vaddr, range_end)`.
/// Returns `(page_offset, page_count)` within the region's frame array.
///
/// Single source of truth for overlap arithmetic — used by both the
/// manager internals and the kernel guardian wrappers.
pub(crate) fn region_overlap(
    base: VirtAddr,
    region_len: usize,
    vaddr: VirtAddr,
    range_end: u64,
) -> (usize, usize) {
    let region_end = base.as_u64() + region_len as u64;
    let overlap_start = vaddr.as_u64().max(base.as_u64());
    let overlap_end = range_end.min(region_end);
    debug_assert!(
        overlap_end >= overlap_start,
        "region_overlap called with non-overlapping region: base={:?} region_len={} vaddr={:?} range_end={}",
        base, region_len, vaddr, range_end
    );
    let page_offset = ((overlap_start - base.as_u64()) / PAGE_SIZE) as usize;
    let page_count = ((overlap_end - overlap_start) / PAGE_SIZE) as usize;
    (page_offset, page_count)
}

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
///
/// Physical memory is partitioned into two pools:
/// - **public** (default) — used for normal, unclassified data frames and
///   intermediate page table frames.
/// - **kernel** — reserved for `ENCRYPTED` data frames.
pub struct AddressSpaceManager<P: PageTable> {
    spaces: BTreeMap<u32, ProcessSpace<P>>,
    buddy_public: BuddyAllocator,
    buddy_kernel: BuddyAllocator,
    cap_tracker: CapTracker,
}

impl<P: PageTable> AddressSpaceManager<P> {
    /// Create a new manager with a single buddy allocator (backward compat).
    ///
    /// All frames go into the public pool; the kernel pool is empty.
    pub fn new(buddy: BuddyAllocator) -> Self {
        Self {
            spaces: BTreeMap::new(),
            buddy_public: buddy,
            buddy_kernel: BuddyAllocator::empty(),
            cap_tracker: CapTracker::new(),
        }
    }

    /// Create a new manager with separate public and kernel buddy allocators.
    ///
    /// Public frames serve unclassified allocations and intermediate page
    /// table frames. Kernel frames serve `ENCRYPTED` allocations.
    pub fn new_dual(buddy_public: BuddyAllocator, buddy_kernel: BuddyAllocator) -> Self {
        Self {
            spaces: BTreeMap::new(),
            buddy_public,
            buddy_kernel,
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

        // Allocate data frames from the correct buddy (BEFORE the split borrow).
        // Route to the kernel buddy only when it actually has capacity (i.e.,
        // was configured via `new_dual()`). When using the backward-compat
        // `new()` constructor the kernel buddy is empty, so all allocations
        // go through the public buddy regardless of classification.
        let use_kernel_buddy = classification.contains(FrameClassification::ENCRYPTED)
            && self.buddy_kernel.total_frame_count() > 0;
        let mut frames = Vec::with_capacity(page_count);
        {
            let data_buddy = if use_kernel_buddy {
                &mut self.buddy_kernel
            } else {
                &mut self.buddy_public
            };
            for _ in 0..page_count {
                match data_buddy.alloc_frame() {
                    Some(paddr) => frames.push(paddr),
                    None => {
                        // Roll back: free all frames allocated so far.
                        for frame in &frames {
                            let _ = data_buddy.free_frame(*frame);
                        }
                        return Err(VmError::OutOfMemory);
                    }
                }
            }
        }

        // Map each page via page_table. Split borrow: `spaces` and
        // `buddy_public` are disjoint fields. Intermediate page table frames
        // (PDP/PD/PT on x86_64, L1/L2/L3 on aarch64) always come from the
        // public buddy — they're structural, not data.
        let mut map_error: Option<VmError> = None;
        {
            let Self {
                spaces,
                buddy_public,
                ..
            } = self;
            let space = spaces.get_mut(&pid).unwrap();
            let mut intermediate_frames: Vec<PhysAddr> = Vec::new();
            for (i, &paddr) in frames.iter().enumerate() {
                let page_vaddr = VirtAddr(vaddr.as_u64() + (i as u64) * PAGE_SIZE);
                let result = space.page_table.map(page_vaddr, paddr, flags, &mut || {
                    let frame = buddy_public.alloc_frame()?;
                    intermediate_frames.push(frame);
                    Some(frame)
                });
                if let Err(e) = result {
                    // Roll back page table mappings already done.
                    for j in 0..i {
                        let rollback_vaddr = VirtAddr(vaddr.as_u64() + (j as u64) * PAGE_SIZE);
                        let _ = space.page_table.unmap(rollback_vaddr, &mut |_| {});
                    }
                    // Free intermediate page table frames.
                    for frame in &intermediate_frames {
                        let _ = buddy_public.free_frame(*frame);
                    }
                    map_error = Some(e);
                    break;
                }
            }
        }

        // If page table mapping failed, free data frames (split borrow released).
        if let Some(e) = map_error {
            let data_buddy = if use_kernel_buddy {
                &mut self.buddy_kernel
            } else {
                &mut self.buddy_public
            };
            for frame in &frames {
                let _ = data_buddy.free_frame(*frame);
            }
            return Err(e);
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
        let space = self.spaces.get(&pid).ok_or(VmError::NoSuchProcess(pid))?;
        let region = space.regions.get(&vaddr).ok_or(VmError::NotMapped(vaddr))?;
        let len = region.len;
        self.unmap_partial(pid, vaddr, len)
    }

    /// Change the permission flags on an existing region.
    pub fn protect_region(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        new_flags: PageFlags,
    ) -> Result<(), VmError> {
        let space = self.spaces.get(&pid).ok_or(VmError::NoSuchProcess(pid))?;
        let region = space.regions.get(&vaddr).ok_or(VmError::NotMapped(vaddr))?;
        let len = region.len;
        self.protect_partial(pid, vaddr, len, new_flags)
    }

    /// Find all regions that overlap `[vaddr, vaddr+len)`.
    ///
    /// Returns a Vec of base addresses (sorted ascending) for every region
    /// whose range intersects the target. Returns an empty Vec if no regions
    /// overlap. Returns `Err` for invalid arguments or missing process.
    pub(crate) fn find_overlapping_regions(
        &self,
        pid: u32,
        vaddr: VirtAddr,
        len: usize,
    ) -> Result<Vec<VirtAddr>, VmError> {
        if len == 0 || vaddr.as_u64() % PAGE_SIZE != 0 || (len as u64) % PAGE_SIZE != 0 {
            return Err(VmError::Unaligned(vaddr.as_u64()));
        }
        let space = self.spaces.get(&pid).ok_or(VmError::NoSuchProcess(pid))?;
        let range_end = vaddr
            .as_u64()
            .checked_add(len as u64)
            .ok_or(VmError::Overflow(vaddr.as_u64()))?;
        let mut result = Vec::new();
        // Jump to the last region whose base ≤ vaddr (it could overlap from behind),
        // then scan forward. When `next_back()` returns Some, the first iteration
        // may be a region that ends before vaddr — the `continue` below skips it.
        // When `next_back()` returns None, every region base is > vaddr, so we
        // start the forward scan at vaddr itself; the `continue` is dead code in
        // that case since `range(vaddr..)` only yields keys ≥ vaddr.
        let start_key = space
            .regions
            .range(..=vaddr)
            .next_back()
            .map(|(&k, _)| k)
            .unwrap_or(vaddr);
        for (&base, region) in space.regions.range(start_key..) {
            let region_end = base.as_u64() + region.len as u64;
            if region_end <= vaddr.as_u64() {
                continue; // behind-region that doesn't reach vaddr (only when next_back found one)
            }
            if base.as_u64() >= range_end {
                break;
            }
            result.push(base);
        }
        Ok(result)
    }

    /// Unmap a range `[vaddr, vaddr+len)` that may span multiple regions.
    ///
    /// Each overlapping region is processed independently: the overlap is
    /// removed and surviving portions (before/after) are re-inserted.
    /// Gaps (unmapped pages) in the target range are silently skipped,
    /// matching Linux munmap semantics.
    pub fn unmap_partial(&mut self, pid: u32, vaddr: VirtAddr, len: usize) -> Result<(), VmError> {
        let bases = self.find_overlapping_regions(pid, vaddr, len)?;
        self.unmap_partial_with_bases(pid, vaddr, len, bases)
    }

    /// Internal: unmap with pre-computed overlapping region bases.
    pub(crate) fn unmap_partial_with_bases(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        len: usize,
        bases: Vec<VirtAddr>,
    ) -> Result<(), VmError> {
        debug_assert!(
            len > 0 && len as u64 % PAGE_SIZE == 0 && vaddr.as_u64() % PAGE_SIZE == 0,
            "unmap_partial_with_bases: unaligned or zero len"
        );
        if bases.is_empty() {
            return Ok(());
        }

        let range_end = vaddr
            .as_u64()
            .checked_add(len as u64)
            .ok_or(VmError::Overflow(vaddr.as_u64()))?;

        for base in bases {
            let region = {
                let space = self.spaces.get_mut(&pid).unwrap();
                match space.regions.remove(&base) {
                    Some(r) => r,
                    None => {
                        debug_assert!(false, "base {:?} not in regions map", base);
                        continue;
                    }
                }
            };
            let (overlap_page_offset, overlap_page_count) =
                region_overlap(base, region.len, vaddr, range_end);
            let overlap_start = vaddr.as_u64().max(base.as_u64());
            let overlap_end = range_end.min(base.as_u64() + region.len as u64);

            // Unmap target pages from page table. PT structure frames are
            // always allocated from the public pool regardless of data
            // classification, so the callback always frees to buddy_public.
            {
                let Self {
                    spaces,
                    buddy_public,
                    ..
                } = self;
                let space = spaces.get_mut(&pid).unwrap();
                for i in 0..overlap_page_count {
                    let page_vaddr = VirtAddr(overlap_start + (i as u64) * PAGE_SIZE);
                    let _ = space.page_table.unmap(page_vaddr, &mut |frame| {
                        let _ = buddy_public.free_frame(frame);
                    });
                }
            }

            // Partition frames: before | overlap | after
            let mut all_frames = region.frames;
            let after_frames = all_frames.split_off(overlap_page_offset + overlap_page_count);
            let target_frames = all_frames.split_off(overlap_page_offset);
            let before_frames = all_frames;

            // Free target frames.
            let use_kernel = region
                .classification
                .contains(FrameClassification::ENCRYPTED)
                && self.buddy_kernel.total_frame_count() > 0;
            let buddy = if use_kernel {
                &mut self.buddy_kernel
            } else {
                &mut self.buddy_public
            };
            for &paddr in &target_frames {
                let _ = self.cap_tracker.remove_mapping(paddr, pid);
                let _ = buddy.free_frame(paddr);
            }

            // Re-insert surviving regions.
            let space = self.spaces.get_mut(&pid).unwrap();
            if !before_frames.is_empty() {
                space.regions.insert(
                    base,
                    Region {
                        len: before_frames.len() * PAGE_SIZE as usize,
                        flags: region.flags,
                        classification: region.classification,
                        frames: before_frames,
                    },
                );
            }
            if !after_frames.is_empty() {
                debug_assert!(
                    !space.regions.contains_key(&VirtAddr(overlap_end)),
                    "after-fragment key {:?} already occupied",
                    VirtAddr(overlap_end)
                );
                space.regions.insert(
                    VirtAddr(overlap_end),
                    Region {
                        len: after_frames.len() * PAGE_SIZE as usize,
                        flags: region.flags,
                        classification: region.classification,
                        frames: after_frames,
                    },
                );
            }
        }
        Ok(())
    }

    /// Change permission flags on `[vaddr, vaddr+len)`, spanning multiple regions.
    ///
    /// Each overlapping region is split into up to three parts: before
    /// (unchanged), overlap (new flags), after (unchanged). Gaps in the
    /// target range are silently skipped.
    pub fn protect_partial(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        len: usize,
        new_flags: PageFlags,
    ) -> Result<(), VmError> {
        let bases = self.find_overlapping_regions(pid, vaddr, len)?;
        self.protect_partial_with_bases(pid, vaddr, len, new_flags, bases)
    }

    /// Internal: protect with pre-computed overlapping region bases.
    pub(crate) fn protect_partial_with_bases(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        len: usize,
        new_flags: PageFlags,
        bases: Vec<VirtAddr>,
    ) -> Result<(), VmError> {
        debug_assert!(
            len > 0 && len as u64 % PAGE_SIZE == 0 && vaddr.as_u64() % PAGE_SIZE == 0,
            "protect_partial_with_bases: unaligned or zero len"
        );
        if bases.is_empty() {
            return Ok(());
        }

        let range_end = vaddr
            .as_u64()
            .checked_add(len as u64)
            .ok_or(VmError::Overflow(vaddr.as_u64()))?;

        // Pass 1: update all HW page table entries. On failure, roll back
        // any pages already updated so HW state stays consistent with the
        // SW region map (which is not touched until Pass 2).
        {
            let space = self.spaces.get_mut(&pid).unwrap();
            // Track (page_vaddr, old_flags) for rollback on failure.
            let mut applied: Vec<(VirtAddr, PageFlags)> = Vec::new();
            let result: Result<(), VmError> = (|| {
                for &base in &bases {
                    let region = match space.regions.get(&base) {
                        Some(r) => r,
                        None => {
                            debug_assert!(false, "base {:?} not in regions map", base);
                            continue;
                        }
                    };
                    let old_flags = region.flags;
                    if new_flags == old_flags {
                        continue; // flags already match — no HW work needed
                    }
                    let (_, overlap_page_count) =
                        region_overlap(base, region.len, vaddr, range_end);
                    let overlap_start = vaddr.as_u64().max(base.as_u64());
                    for i in 0..overlap_page_count {
                        let page_vaddr = VirtAddr(overlap_start + (i as u64) * PAGE_SIZE);
                        space.page_table.set_flags(page_vaddr, new_flags)?;
                        applied.push((page_vaddr, old_flags));
                    }
                }
                Ok(())
            })();
            if let Err(e) = result {
                // Roll back: restore old HW flags for every page we already touched.
                for &(page_vaddr, old_flags) in &applied {
                    let _ = space.page_table.set_flags(page_vaddr, old_flags);
                }
                return Err(e);
            }
        }

        // Pass 2: all set_flags succeeded — now split and re-insert regions.
        for base in bases {
            let space = self.spaces.get_mut(&pid).unwrap();
            let region = match space.regions.remove(&base) {
                Some(r) => r,
                None => {
                    debug_assert!(false, "base {:?} not in regions map", base);
                    continue;
                }
            };

            // Skip splitting when flags already match — avoids fragmenting
            // the address space on redundant mprotect calls.
            if new_flags == region.flags {
                debug_assert!(
                    !space.regions.contains_key(&base),
                    "key {:?} already occupied before no-change reinsert",
                    base
                );
                space.regions.insert(base, region);
                continue;
            }

            let (overlap_page_offset, overlap_page_count) =
                region_overlap(base, region.len, vaddr, range_end);
            let overlap_start = vaddr.as_u64().max(base.as_u64());
            let overlap_end = range_end.min(base.as_u64() + region.len as u64);

            let mut all_frames = region.frames;
            let after_frames = all_frames.split_off(overlap_page_offset + overlap_page_count);
            let target_frames = all_frames.split_off(overlap_page_offset);
            let before_frames = all_frames;

            if !before_frames.is_empty() {
                space.regions.insert(
                    base,
                    Region {
                        len: before_frames.len() * PAGE_SIZE as usize,
                        flags: region.flags,
                        classification: region.classification,
                        frames: before_frames,
                    },
                );
            }
            debug_assert!(
                !target_frames.is_empty(),
                "overlap produced zero pages for region returned by find_overlapping_regions"
            );
            space.regions.insert(
                VirtAddr(overlap_start),
                Region {
                    len: target_frames.len() * PAGE_SIZE as usize,
                    flags: new_flags,
                    classification: region.classification,
                    frames: target_frames,
                },
            );
            if !after_frames.is_empty() {
                debug_assert!(
                    !space.regions.contains_key(&VirtAddr(overlap_end)),
                    "after-fragment key {:?} already occupied",
                    VirtAddr(overlap_end)
                );
                space.regions.insert(
                    VirtAddr(overlap_end),
                    Region {
                        len: after_frames.len() * PAGE_SIZE as usize,
                        flags: region.flags,
                        classification: region.classification,
                        frames: after_frames,
                    },
                );
            }
        }
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
            // Intermediate page table frames (PDP/PD/PT levels) always come
            // from the public buddy and are freed here via the callback.
            let page_count = region.len / PAGE_SIZE as usize;
            for i in 0..page_count {
                let page_vaddr = VirtAddr(vaddr.as_u64() + (i as u64) * PAGE_SIZE);
                let _ = space.page_table.unmap(page_vaddr, &mut |frame| {
                    let _ = self.buddy_public.free_frame(frame);
                });
            }

            let use_kernel = region
                .classification
                .contains(FrameClassification::ENCRYPTED)
                && self.buddy_kernel.total_frame_count() > 0;
            let buddy = if use_kernel {
                &mut self.buddy_kernel
            } else {
                &mut self.buddy_public
            };
            for &paddr in &region.frames {
                let _ = self.cap_tracker.remove_mapping(paddr, pid);
                let _ = buddy.free_frame(paddr);
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

    /// Mutable access to the public buddy allocator (backward compat).
    pub fn buddy(&mut self) -> &mut BuddyAllocator {
        &mut self.buddy_public
    }

    /// Read-only access to the public buddy allocator.
    pub fn buddy_public(&self) -> &BuddyAllocator {
        &self.buddy_public
    }

    /// Read-only access to the kernel buddy allocator.
    pub fn buddy_kernel(&self) -> &BuddyAllocator {
        &self.buddy_kernel
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

    // ── Dual buddy tests ─────────────────────────────────────────────

    #[test]
    fn dual_partition_allocation() {
        let buddy_public = BuddyAllocator::new(PhysAddr(0x10_0000), 12).unwrap();
        let buddy_kernel = BuddyAllocator::new(PhysAddr(0x20_0000), 4).unwrap();
        let mut mgr = AddressSpaceManager::new_dual(buddy_public, buddy_kernel);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();

        // Public allocation: 2 pages from public buddy.
        mgr.map_region(
            1,
            VirtAddr(0x1000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        assert_eq!(mgr.buddy_public().free_frame_count(), 10);
        assert_eq!(mgr.buddy_kernel().free_frame_count(), 4);

        // Encrypted allocation: 1 page from kernel buddy.
        mgr.map_region(
            1,
            VirtAddr(0x5000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::ENCRYPTED,
        )
        .unwrap();
        assert_eq!(mgr.buddy_public().free_frame_count(), 10);
        assert_eq!(mgr.buddy_kernel().free_frame_count(), 3);
    }

    #[test]
    fn kernel_oom_does_not_affect_public() {
        let buddy_public = BuddyAllocator::new(PhysAddr(0x10_0000), 8).unwrap();
        let buddy_kernel = BuddyAllocator::new(PhysAddr(0x20_0000), 1).unwrap();
        let mut mgr = AddressSpaceManager::new_dual(buddy_public, buddy_kernel);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();

        // Use up the single kernel frame.
        mgr.map_region(
            1,
            VirtAddr(0x1000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::ENCRYPTED,
        )
        .unwrap();

        // Second encrypted allocation should fail — kernel buddy is empty.
        let err = mgr
            .map_region(
                1,
                VirtAddr(0x5000),
                PAGE_SIZE as usize,
                rw_user_flags(),
                FrameClassification::ENCRYPTED,
            )
            .unwrap_err();
        assert_eq!(err, VmError::OutOfMemory);

        // Public allocation should still succeed.
        mgr.map_region(
            1,
            VirtAddr(0xA000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
    }

    #[test]
    fn dual_unmap_returns_to_correct_buddy() {
        let buddy_public = BuddyAllocator::new(PhysAddr(0x10_0000), 8).unwrap();
        let buddy_kernel = BuddyAllocator::new(PhysAddr(0x20_0000), 4).unwrap();
        let mut mgr = AddressSpaceManager::new_dual(buddy_public, buddy_kernel);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();

        // Map public region.
        mgr.map_region(
            1,
            VirtAddr(0x1000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();

        // Map encrypted region.
        mgr.map_region(
            1,
            VirtAddr(0x5000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::ENCRYPTED,
        )
        .unwrap();

        assert_eq!(mgr.buddy_public().free_frame_count(), 6);
        assert_eq!(mgr.buddy_kernel().free_frame_count(), 3);

        // Unmap encrypted region — should return frame to kernel buddy.
        mgr.unmap_region(1, VirtAddr(0x5000)).unwrap();
        assert_eq!(mgr.buddy_public().free_frame_count(), 6);
        assert_eq!(mgr.buddy_kernel().free_frame_count(), 4);

        // Unmap public region — should return frames to public buddy.
        mgr.unmap_region(1, VirtAddr(0x1000)).unwrap();
        assert_eq!(mgr.buddy_public().free_frame_count(), 8);
        assert_eq!(mgr.buddy_kernel().free_frame_count(), 4);
    }

    #[test]
    fn dual_destroy_returns_to_correct_buddies() {
        let buddy_public = BuddyAllocator::new(PhysAddr(0x10_0000), 8).unwrap();
        let buddy_kernel = BuddyAllocator::new(PhysAddr(0x20_0000), 4).unwrap();
        let mut mgr = AddressSpaceManager::new_dual(buddy_public, buddy_kernel);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();

        mgr.map_region(
            1,
            VirtAddr(0x1000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x5000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::ENCRYPTED,
        )
        .unwrap();

        assert_eq!(mgr.buddy_public().free_frame_count(), 6);
        assert_eq!(mgr.buddy_kernel().free_frame_count(), 2);

        mgr.destroy_space(1).unwrap();
        assert_eq!(mgr.buddy_public().free_frame_count(), 8);
        assert_eq!(mgr.buddy_kernel().free_frame_count(), 4);
    }

    // ── Partial unmap/protect tests ──────────────────────────────────

    fn rx_user_flags() -> PageFlags {
        PageFlags::READABLE | PageFlags::EXECUTABLE | PageFlags::USER
    }

    /// Map 4 pages, unmap the middle 2, verify before/after regions remain and
    /// exactly 2 frames are freed.
    #[test]
    fn unmap_partial_suffix_two_pages() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let base = VirtAddr(0x1000);
        let flags = rw_user_flags();
        mgr.map_region(
            1,
            base,
            PAGE_SIZE as usize * 4,
            flags,
            FrameClassification::empty(),
        )
        .unwrap();
        let initial_free = mgr.buddy_public().free_frame_count();

        // Unmap last 2 pages (0x3000 and 0x4000) from 4-page region.
        let unmap_start = VirtAddr(0x3000);
        mgr.unmap_partial(1, unmap_start, PAGE_SIZE as usize * 2)
            .unwrap();

        // 2 frames freed.
        assert_eq!(mgr.buddy_public().free_frame_count(), initial_free + 2);

        // Only the before region (0x1000..0x3000, 2 pages) should remain.
        let regions = &mgr.space(1).unwrap().regions;
        let before = regions.get(&base).expect("before region missing");
        assert_eq!(before.len, PAGE_SIZE as usize * 2);
        assert_eq!(regions.len(), 1);
    }

    /// Unmap only the first page of a 4-page region.
    #[test]
    fn unmap_partial_first_page() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let base = VirtAddr(0x1000);
        mgr.map_region(
            1,
            base,
            PAGE_SIZE as usize * 4,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();

        mgr.unmap_partial(1, base, PAGE_SIZE as usize).unwrap();

        let regions = &mgr.space(1).unwrap().regions;
        // No before region; after region starts at 0x2000, 3 pages.
        assert_eq!(regions.len(), 1);
        let after_base = VirtAddr(0x2000);
        let after = regions.get(&after_base).expect("after region missing");
        assert_eq!(after.len, PAGE_SIZE as usize * 3);
    }

    /// Unmap only the last page of a 4-page region.
    #[test]
    fn unmap_partial_last_page() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let base = VirtAddr(0x1000);
        mgr.map_region(
            1,
            base,
            PAGE_SIZE as usize * 4,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();

        let last_page = VirtAddr(0x4000);
        mgr.unmap_partial(1, last_page, PAGE_SIZE as usize).unwrap();

        let regions = &mgr.space(1).unwrap().regions;
        // Before region 0x1000..0x4000, 3 pages; no after region.
        assert_eq!(regions.len(), 1);
        let before = regions.get(&base).expect("before region missing");
        assert_eq!(before.len, PAGE_SIZE as usize * 3);
    }

    /// Unmap middle 2 pages of a 4-page region — produces both before and after.
    #[test]
    fn unmap_partial_middle_produces_two_regions() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let base = VirtAddr(0x1000);
        mgr.map_region(
            1,
            base,
            PAGE_SIZE as usize * 4,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();

        // Unmap pages at 0x2000 and 0x3000.
        let unmap_start = VirtAddr(0x2000);
        mgr.unmap_partial(1, unmap_start, PAGE_SIZE as usize * 2)
            .unwrap();

        let regions = &mgr.space(1).unwrap().regions;
        assert_eq!(regions.len(), 2, "expected before and after regions");

        let before = regions.get(&base).expect("before region missing");
        assert_eq!(before.len, PAGE_SIZE as usize);

        let after_base = VirtAddr(0x4000);
        let after = regions.get(&after_base).expect("after region missing");
        assert_eq!(after.len, PAGE_SIZE as usize);
    }

    /// `unmap_partial` on an unaligned vaddr returns Unaligned.
    #[test]
    fn unmap_partial_unaligned_returns_error() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let base = VirtAddr(0x1000);
        mgr.map_region(
            1,
            base,
            PAGE_SIZE as usize * 4,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();

        let err = mgr
            .unmap_partial(1, VirtAddr(0x1001), PAGE_SIZE as usize)
            .unwrap_err();
        assert!(matches!(err, VmError::Unaligned(_)));
    }

    /// `unmap_partial` on a range that spans beyond a single region succeeds,
    /// unmapping only the mapped pages and silently skipping the gap
    /// (Linux munmap semantics).
    #[test]
    fn unmap_partial_beyond_region_skips_gap() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let base = VirtAddr(0x1000);
        // Map 2 pages (0x1000..0x3000).
        mgr.map_region(
            1,
            base,
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        let initial_free = mgr.buddy_public().free_frame_count();

        // Unmap 3 pages starting at 0x1000 — only 2 are mapped; gap is skipped.
        mgr.unmap_partial(1, base, PAGE_SIZE as usize * 3).unwrap();
        assert_eq!(mgr.buddy_public().free_frame_count(), initial_free + 2);
        assert_eq!(mgr.space(1).unwrap().regions.len(), 0);
    }

    /// `protect_partial` on the first page changes only that page's flags.
    #[test]
    fn protect_partial_first_page() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let base = VirtAddr(0x1000);
        let orig_flags = rw_user_flags();
        mgr.map_region(
            1,
            base,
            PAGE_SIZE as usize * 4,
            orig_flags,
            FrameClassification::empty(),
        )
        .unwrap();

        let new_flags = rx_user_flags();
        mgr.protect_partial(1, base, PAGE_SIZE as usize, new_flags)
            .unwrap();

        let regions = &mgr.space(1).unwrap().regions;
        // Target at base (1 page), after at 0x2000 (3 pages), no before.
        assert_eq!(regions.len(), 2);
        let target = regions.get(&base).expect("target region missing");
        assert_eq!(target.flags, new_flags);
        assert_eq!(target.len, PAGE_SIZE as usize);

        let after_base = VirtAddr(0x2000);
        let after = regions.get(&after_base).expect("after region missing");
        assert_eq!(after.flags, orig_flags);
        assert_eq!(after.len, PAGE_SIZE as usize * 3);
    }

    /// `protect_partial` on the last page changes only that page's flags.
    #[test]
    fn protect_partial_last_page() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let base = VirtAddr(0x1000);
        let orig_flags = rw_user_flags();
        mgr.map_region(
            1,
            base,
            PAGE_SIZE as usize * 4,
            orig_flags,
            FrameClassification::empty(),
        )
        .unwrap();

        let last_page = VirtAddr(0x4000);
        let new_flags = rx_user_flags();
        mgr.protect_partial(1, last_page, PAGE_SIZE as usize, new_flags)
            .unwrap();

        let regions = &mgr.space(1).unwrap().regions;
        // Before at base (3 pages), target at 0x4000 (1 page), no after.
        assert_eq!(regions.len(), 2);
        let before = regions.get(&base).expect("before region missing");
        assert_eq!(before.flags, orig_flags);
        assert_eq!(before.len, PAGE_SIZE as usize * 3);

        let target = regions.get(&last_page).expect("target region missing");
        assert_eq!(target.flags, new_flags);
        assert_eq!(target.len, PAGE_SIZE as usize);
    }

    /// `protect_partial` on the middle 2 pages produces 3 regions.
    #[test]
    fn protect_partial_middle_produces_three_regions() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let base = VirtAddr(0x1000);
        let orig_flags = rw_user_flags();
        mgr.map_region(
            1,
            base,
            PAGE_SIZE as usize * 4,
            orig_flags,
            FrameClassification::empty(),
        )
        .unwrap();

        let target_start = VirtAddr(0x2000);
        let new_flags = rx_user_flags();
        mgr.protect_partial(1, target_start, PAGE_SIZE as usize * 2, new_flags)
            .unwrap();

        let regions = &mgr.space(1).unwrap().regions;
        assert_eq!(
            regions.len(),
            3,
            "expected before, target, and after regions"
        );

        let before = regions.get(&base).expect("before region missing");
        assert_eq!(before.flags, orig_flags);
        assert_eq!(before.len, PAGE_SIZE as usize);

        let target = regions.get(&target_start).expect("target region missing");
        assert_eq!(target.flags, new_flags);
        assert_eq!(target.len, PAGE_SIZE as usize * 2);

        let after_base = VirtAddr(0x4000);
        let after = regions.get(&after_base).expect("after region missing");
        assert_eq!(after.flags, orig_flags);
        assert_eq!(after.len, PAGE_SIZE as usize);
    }

    /// `protect_partial` updates the page table flags for the target pages.
    #[test]
    fn protect_partial_updates_page_table() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let base = VirtAddr(0x1000);
        mgr.map_region(
            1,
            base,
            PAGE_SIZE as usize * 4,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();

        let target = VirtAddr(0x2000);
        let new_flags = rx_user_flags();
        mgr.protect_partial(1, target, PAGE_SIZE as usize, new_flags)
            .unwrap();

        let space = mgr.space(1).unwrap();
        // Target page should have new flags.
        let (_, got_flags) = space.page_table.translate(target).unwrap();
        assert_eq!(got_flags, new_flags);

        // Other pages should still have original flags.
        let (_, orig_got) = space.page_table.translate(base).unwrap();
        assert_eq!(orig_got, rw_user_flags());
    }

    /// `protect_partial` on an unaligned vaddr returns Unaligned.
    #[test]
    fn protect_partial_unaligned_returns_error() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let base = VirtAddr(0x1000);
        mgr.map_region(
            1,
            base,
            PAGE_SIZE as usize * 4,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();

        let err = mgr
            .protect_partial(1, VirtAddr(0x1800), PAGE_SIZE as usize, rx_user_flags())
            .unwrap_err();
        assert!(matches!(err, VmError::Unaligned(_)));
    }

    /// `protect_partial` preserves `classification` on all split regions.
    #[test]
    fn protect_partial_preserves_classification() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let base = VirtAddr(0x1000);
        mgr.map_region(
            1,
            base,
            PAGE_SIZE as usize * 4,
            rw_user_flags(),
            FrameClassification::EPHEMERAL,
        )
        .unwrap();

        let target_start = VirtAddr(0x2000);
        mgr.protect_partial(1, target_start, PAGE_SIZE as usize * 2, rx_user_flags())
            .unwrap();

        let regions = &mgr.space(1).unwrap().regions;
        for (_, region) in regions.iter() {
            assert!(
                region
                    .classification
                    .contains(FrameClassification::EPHEMERAL),
                "classification not preserved: {:?}",
                region.classification
            );
        }
    }

    #[test]
    fn unmap_spanning_two_regions() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x1000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x3000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        let initial_free = mgr.buddy_public().free_frame_count();
        mgr.unmap_partial(1, VirtAddr(0x2000), PAGE_SIZE as usize * 2)
            .unwrap();
        assert_eq!(mgr.buddy_public().free_frame_count(), initial_free + 2);
        let regions = &mgr.space(1).unwrap().regions;
        assert_eq!(regions.len(), 2);
        assert_eq!(
            regions.get(&VirtAddr(0x1000)).unwrap().len,
            PAGE_SIZE as usize
        );
        assert_eq!(
            regions.get(&VirtAddr(0x4000)).unwrap().len,
            PAGE_SIZE as usize
        );
    }

    #[test]
    fn unmap_covering_middle_region() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x1000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x3000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x5000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        let initial_free = mgr.buddy_public().free_frame_count();
        mgr.unmap_partial(1, VirtAddr(0x2000), PAGE_SIZE as usize * 4)
            .unwrap();
        assert_eq!(mgr.buddy_public().free_frame_count(), initial_free + 4);
        let regions = &mgr.space(1).unwrap().regions;
        assert_eq!(regions.len(), 2);
        assert_eq!(
            regions.get(&VirtAddr(0x1000)).unwrap().len,
            PAGE_SIZE as usize
        );
        assert_eq!(
            regions.get(&VirtAddr(0x6000)).unwrap().len,
            PAGE_SIZE as usize
        );
    }

    #[test]
    fn unmap_with_gap() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x1000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x4000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        let initial_free = mgr.buddy_public().free_frame_count();
        mgr.unmap_partial(1, VirtAddr(0x1000), PAGE_SIZE as usize * 4)
            .unwrap();
        assert_eq!(mgr.buddy_public().free_frame_count(), initial_free + 2);
        assert_eq!(mgr.space(1).unwrap().regions.len(), 0);
    }

    #[test]
    fn unmap_entire_two_regions() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x1000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x3000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        let initial_free = mgr.buddy_public().free_frame_count();
        mgr.unmap_partial(1, VirtAddr(0x1000), PAGE_SIZE as usize * 4)
            .unwrap();
        assert_eq!(mgr.buddy_public().free_frame_count(), initial_free + 4);
        assert_eq!(mgr.space(1).unwrap().regions.len(), 0);
    }

    #[test]
    fn unmap_no_overlap() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x1000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        let result = mgr.unmap_partial(1, VirtAddr(0x5000), PAGE_SIZE as usize);
        assert!(result.is_ok());
    }

    #[test]
    fn find_overlapping_regions_basic() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x1000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x5000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x9000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();

        let overlaps = mgr
            .find_overlapping_regions(1, VirtAddr(0x2000), 0x8000)
            .unwrap();
        assert_eq!(overlaps.len(), 3);
        assert_eq!(overlaps[0], VirtAddr(0x1000));
        assert_eq!(overlaps[1], VirtAddr(0x5000));
        assert_eq!(overlaps[2], VirtAddr(0x9000));

        let overlaps = mgr
            .find_overlapping_regions(1, VirtAddr(0x3000), 0x2000)
            .unwrap();
        assert_eq!(overlaps.len(), 0);

        let overlaps = mgr
            .find_overlapping_regions(1, VirtAddr(0x6000), PAGE_SIZE as usize)
            .unwrap();
        assert_eq!(overlaps.len(), 1);
        assert_eq!(overlaps[0], VirtAddr(0x5000));
    }

    #[test]
    fn find_overlapping_regions_all_after_vaddr() {
        // Test the None path in find_overlapping_regions: every mapped region
        // starts strictly after vaddr, so range(..=vaddr).next_back() returns
        // None and the forward scan begins at vaddr.
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x5000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x8000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();

        // Query range [0x1000, 0x9000) — both regions are inside but none has
        // base ≤ 0x1000, so the next_back() fallback fires.
        let overlaps = mgr
            .find_overlapping_regions(1, VirtAddr(0x1000), 0x8000)
            .unwrap();
        assert_eq!(overlaps.len(), 2);
        assert_eq!(overlaps[0], VirtAddr(0x5000));
        assert_eq!(overlaps[1], VirtAddr(0x8000));

        // Query range [0x1000, 0x4000) — no region overlaps at all.
        let overlaps = mgr
            .find_overlapping_regions(1, VirtAddr(0x1000), 0x3000)
            .unwrap();
        assert_eq!(overlaps.len(), 0);
    }

    #[test]
    fn protect_spanning_two_regions() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x1000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x3000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        mgr.protect_partial(1, VirtAddr(0x2000), PAGE_SIZE as usize * 2, rx_user_flags())
            .unwrap();
        let regions = &mgr.space(1).unwrap().regions;
        assert_eq!(regions.len(), 4);
        assert_eq!(
            regions.get(&VirtAddr(0x1000)).unwrap().flags,
            rw_user_flags()
        );
        assert_eq!(
            regions.get(&VirtAddr(0x2000)).unwrap().flags,
            rx_user_flags()
        );
        assert_eq!(
            regions.get(&VirtAddr(0x3000)).unwrap().flags,
            rx_user_flags()
        );
        assert_eq!(
            regions.get(&VirtAddr(0x4000)).unwrap().flags,
            rw_user_flags()
        );
    }

    #[test]
    fn protect_with_gap() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x1000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x4000),
            PAGE_SIZE as usize,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        mgr.protect_partial(1, VirtAddr(0x1000), PAGE_SIZE as usize * 4, rx_user_flags())
            .unwrap();
        let regions = &mgr.space(1).unwrap().regions;
        assert_eq!(regions.len(), 2);
        assert_eq!(
            regions.get(&VirtAddr(0x1000)).unwrap().flags,
            rx_user_flags()
        );
        assert_eq!(
            regions.get(&VirtAddr(0x4000)).unwrap().flags,
            rx_user_flags()
        );
    }

    #[test]
    fn protect_spanning_three_regions() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x1000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x3000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        mgr.map_region(
            1,
            VirtAddr(0x5000),
            PAGE_SIZE as usize * 2,
            rw_user_flags(),
            FrameClassification::empty(),
        )
        .unwrap();
        mgr.protect_partial(1, VirtAddr(0x2000), PAGE_SIZE as usize * 4, rx_user_flags())
            .unwrap();
        let regions = &mgr.space(1).unwrap().regions;
        assert_eq!(regions.len(), 5);
        assert_eq!(
            regions.get(&VirtAddr(0x1000)).unwrap().flags,
            rw_user_flags()
        );
        assert_eq!(
            regions.get(&VirtAddr(0x2000)).unwrap().flags,
            rx_user_flags()
        );
        assert_eq!(
            regions.get(&VirtAddr(0x3000)).unwrap().flags,
            rx_user_flags()
        );
        assert_eq!(
            regions.get(&VirtAddr(0x5000)).unwrap().flags,
            rx_user_flags()
        );
        assert_eq!(
            regions.get(&VirtAddr(0x6000)).unwrap().flags,
            rw_user_flags()
        );
    }
}
