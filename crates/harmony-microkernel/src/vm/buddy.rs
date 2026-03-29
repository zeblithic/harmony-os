// SPDX-License-Identifier: GPL-2.0-or-later
//! Buddy allocator for physical frame management.
//!
//! Manages a contiguous region of physical memory using the buddy system.
//! Supports allocation at power-of-two orders (order 0 = 1 frame = PAGE_SIZE,
//! order 10 = 1024 frames), splitting larger blocks down to serve
//! smaller requests, and coalescing freed blocks with their buddies on the
//! way back up.

use alloc::vec;
use alloc::vec::Vec;

use super::{PhysAddr, VmError, PAGE_SHIFT, PAGE_SIZE};

/// Maximum allocation order. Order 10 = 2^10 = 1024 frames = 4 MiB.
pub const MAX_ORDER: usize = 10;

/// Buddy allocator for physical page frames.
///
/// Tracks free blocks using per-order free lists and a per-frame bitmap.
/// All addresses are physical and must be page-aligned.
#[derive(Debug)]
pub struct BuddyAllocator {
    /// Free lists indexed by order. `free_lists[o]` contains the base
    /// addresses of free blocks of size `2^o` frames.
    free_lists: [Vec<PhysAddr>; MAX_ORDER + 1],
    /// One bit per frame: 1 = allocated, 0 = free.
    bitmap: Vec<u8>,
    /// Base physical address of the managed region (page-aligned).
    base: PhysAddr,
    /// Total number of frames in the managed region.
    frame_count: usize,
}

impl BuddyAllocator {
    /// Create an empty allocator with zero frames. All allocations return `None`.
    pub fn empty() -> Self {
        Self {
            free_lists: Default::default(),
            bitmap: Vec::new(),
            base: PhysAddr(0),
            frame_count: 0,
        }
    }

    /// Create a new buddy allocator managing `frame_count` frames starting
    /// at `base`.
    ///
    /// Returns `Err(VmError::Unaligned)` if `base` is not page-aligned, or
    /// `Err(VmError::InvalidOrder)` if `frame_count` is zero.
    pub fn new(base: PhysAddr, frame_count: usize) -> Result<Self, VmError> {
        if !base.is_page_aligned() {
            return Err(VmError::Unaligned(base.as_u64()));
        }
        if frame_count == 0 {
            return Err(VmError::InvalidOrder(0));
        }

        let bitmap_bytes = frame_count.div_ceil(8);
        let mut alloc = Self {
            free_lists: Default::default(),
            bitmap: vec![0u8; bitmap_bytes],
            base,
            frame_count,
        };

        // Insert all frames as the largest possible buddy blocks.
        alloc.build_free_lists();

        Ok(alloc)
    }

    /// Convert a physical address to a frame index relative to `self.base`.
    pub fn frame_index(&self, addr: PhysAddr) -> Option<usize> {
        if addr.as_u64() < self.base.as_u64() {
            return None;
        }
        let offset = addr.as_u64() - self.base.as_u64();
        if offset % PAGE_SIZE != 0 {
            return None;
        }
        let idx = (offset / PAGE_SIZE) as usize;
        if idx >= self.frame_count {
            return None;
        }
        Some(idx)
    }

    /// Check whether the frame at `idx` is marked allocated in the bitmap.
    pub fn is_allocated(&self, idx: usize) -> bool {
        let byte = idx / 8;
        let bit = idx % 8;
        self.bitmap[byte] & (1 << bit) != 0
    }

    /// Mark the frame at `idx` as allocated in the bitmap.
    pub fn set_allocated(&mut self, idx: usize) {
        let byte = idx / 8;
        let bit = idx % 8;
        self.bitmap[byte] |= 1 << bit;
    }

    /// Mark the frame at `idx` as free in the bitmap.
    pub fn set_free(&mut self, idx: usize) {
        let byte = idx / 8;
        let bit = idx % 8;
        self.bitmap[byte] &= !(1 << bit);
    }

    /// Mark a contiguous range of frames as allocated in the bitmap.
    pub fn mark_range_allocated(&mut self, start_idx: usize, count: usize) {
        for idx in start_idx..start_idx + count {
            self.set_allocated(idx);
        }
    }

    /// Allocate a block of `2^order` contiguous frames.
    ///
    /// Returns the base physical address of the allocated block.
    pub fn alloc(&mut self, order: usize) -> Result<PhysAddr, VmError> {
        if order > MAX_ORDER {
            return Err(VmError::InvalidOrder(order));
        }

        // Find the smallest order with a free block >= requested order.
        let mut found_order = None;
        for o in order..=MAX_ORDER {
            if !self.free_lists[o].is_empty() {
                found_order = Some(o);
                break;
            }
        }

        let source_order = found_order.ok_or(VmError::OutOfMemory)?;

        // Pop a block from the free list at `source_order`.
        let block_addr = self.free_lists[source_order].pop().unwrap();

        // Split down from source_order to the requested order.
        let mut current_order = source_order;
        let addr = block_addr;
        while current_order > order {
            current_order -= 1;
            // The buddy (upper half) goes on the free list at the lower order.
            let buddy_addr = PhysAddr(addr.as_u64() + ((1u64 << current_order) << PAGE_SHIFT));
            self.free_lists[current_order].push(buddy_addr);
            // We keep the lower half (addr stays the same).
        }

        // Mark all frames in the allocated block as used.
        let start_idx = self.frame_index(addr).unwrap();
        let block_frames = 1usize << order;
        self.mark_range_allocated(start_idx, block_frames);

        Ok(addr)
    }

    /// Free a previously allocated block of `2^order` frames at `addr`.
    ///
    /// Coalesces with the buddy if possible, repeating up to `MAX_ORDER`.
    pub fn free(&mut self, addr: PhysAddr, order: usize) -> Result<(), VmError> {
        if order > MAX_ORDER {
            return Err(VmError::InvalidOrder(order));
        }
        if !addr.is_page_aligned() {
            return Err(VmError::Unaligned(addr.as_u64()));
        }

        let start_idx = self
            .frame_index(addr)
            .ok_or(VmError::Unaligned(addr.as_u64()))?;

        let block_frames = 1usize << order;

        // Verify all frames in this block are currently allocated (double-free check).
        for i in 0..block_frames {
            let idx = start_idx + i;
            if idx >= self.frame_count {
                return Err(VmError::Unaligned(addr.as_u64()));
            }
            if !self.is_allocated(idx) {
                // Double free: at least one frame in the block is already free.
                return Err(VmError::NotMapped(super::VirtAddr(addr.as_u64())));
            }
        }

        // Clear all frames in the bitmap.
        for i in 0..block_frames {
            self.set_free(start_idx + i);
        }

        // Coalesce with buddy.
        let mut current_addr = addr.as_u64();
        let mut current_order = order;

        while current_order < MAX_ORDER {
            let block_size_bytes = (1u64 << current_order) << PAGE_SHIFT;
            let buddy_addr = current_addr ^ block_size_bytes;

            // Check buddy is in range.
            let buddy_idx = match self.frame_index(PhysAddr(buddy_addr)) {
                Some(idx) => idx,
                None => break,
            };

            // Check all buddy frames are free.
            let buddy_frames = 1usize << current_order;
            if buddy_idx + buddy_frames > self.frame_count {
                break;
            }
            let buddy_all_free = (0..buddy_frames).all(|i| !self.is_allocated(buddy_idx + i));
            if !buddy_all_free {
                break;
            }

            // Find and remove buddy from the free list at current_order.
            let buddy_phys = PhysAddr(buddy_addr);
            let pos = self.free_lists[current_order]
                .iter()
                .position(|&a| a == buddy_phys);
            match pos {
                Some(p) => {
                    self.free_lists[current_order].swap_remove(p);
                }
                None => break, // Buddy frames are free but not in the free list at this order.
            }

            // Merge: take the lower address.
            current_addr = current_addr.min(buddy_addr);
            current_order += 1;
        }

        self.free_lists[current_order].push(PhysAddr(current_addr));
        Ok(())
    }

    /// Convenience: allocate a single frame (order 0).
    pub fn alloc_frame(&mut self) -> Option<PhysAddr> {
        self.alloc(0).ok()
    }

    /// Convenience: free a single frame (order 0).
    pub fn free_frame(&mut self, addr: PhysAddr) -> Result<(), VmError> {
        self.free(addr, 0)
    }

    /// Count the total number of free frames across all orders.
    pub fn free_frame_count(&self) -> usize {
        self.free_lists
            .iter()
            .enumerate()
            .map(|(order, list)| list.len() * (1 << order))
            .sum()
    }

    /// Total number of frames managed by this allocator.
    pub fn total_frame_count(&self) -> usize {
        self.frame_count
    }

    /// Total bytes managed by this allocator.
    pub fn total_bytes(&self) -> u64 {
        self.frame_count as u64 * PAGE_SIZE
    }

    /// Base physical address of the managed region.
    pub fn base_addr(&self) -> PhysAddr {
        self.base
    }

    /// Reserve a range of frames, marking them as allocated.
    ///
    /// This is intended for boot-time use. It marks the given frames in the
    /// bitmap and rebuilds the free lists from scratch.
    pub fn reserve_range(&mut self, start: PhysAddr, count: usize) -> Result<(), VmError> {
        if !start.is_page_aligned() {
            return Err(VmError::Unaligned(start.as_u64()));
        }
        let start_idx = self
            .frame_index(start)
            .ok_or(VmError::Unaligned(start.as_u64()))?;
        if start_idx + count > self.frame_count {
            return Err(VmError::OutOfMemory);
        }

        // Mark frames in bitmap.
        self.mark_range_allocated(start_idx, count);

        // Rebuild free lists from scratch by clearing them and walking the
        // bitmap for contiguous free runs, inserting the largest possible
        // buddy-aligned blocks.
        for list in &mut self.free_lists {
            list.clear();
        }
        self.rebuild_free_lists_from_bitmap();

        Ok(())
    }

    // ── Private helpers ──────────────────────────────────────────────

    /// Build the initial free lists by inserting all frames as the largest
    /// possible buddy-aligned blocks.
    fn build_free_lists(&mut self) {
        let mut idx = 0usize;
        while idx < self.frame_count {
            // Find the largest order block that:
            // 1. Fits within the remaining frames.
            // 2. The block's base address is naturally aligned for that order.
            let addr = self.base.as_u64() + (idx as u64) * PAGE_SIZE;
            let mut order = 0usize;
            while order < MAX_ORDER {
                let next_order = order + 1;
                let next_block_size = 1usize << next_order;
                // Check alignment: addr must be aligned to next_block_size * PAGE_SIZE.
                let align_mask = ((next_block_size as u64) << PAGE_SHIFT) - 1;
                if addr & align_mask != 0 {
                    break;
                }
                // Check fit.
                if idx + next_block_size > self.frame_count {
                    break;
                }
                order = next_order;
            }
            self.free_lists[order].push(PhysAddr(addr));
            idx += 1 << order;
        }
    }

    /// Rebuild free lists from the bitmap. Scans all frames and groups
    /// contiguous free regions into the largest possible buddy-aligned blocks.
    fn rebuild_free_lists_from_bitmap(&mut self) {
        let mut idx = 0usize;
        while idx < self.frame_count {
            if self.is_allocated(idx) {
                idx += 1;
                continue;
            }
            // Find the largest buddy-aligned free block starting at idx.
            let addr = self.base.as_u64() + (idx as u64) * PAGE_SIZE;
            let mut order = 0usize;
            while order < MAX_ORDER {
                let next_order = order + 1;
                let next_block_size = 1usize << next_order;
                // Check alignment.
                let align_mask = ((next_block_size as u64) << PAGE_SHIFT) - 1;
                if addr & align_mask != 0 {
                    break;
                }
                // Check all frames in the larger block are free.
                if idx + next_block_size > self.frame_count {
                    break;
                }
                let all_free = (idx..idx + next_block_size).all(|i| !self.is_allocated(i));
                if !all_free {
                    break;
                }
                order = next_order;
            }
            self.free_lists[order].push(PhysAddr(addr));
            idx += 1 << order;
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create an allocator with the given number of frames at a
    /// well-aligned base address.
    fn make_allocator(frame_count: usize) -> BuddyAllocator {
        BuddyAllocator::new(PhysAddr(0x10_0000), frame_count).unwrap()
    }

    #[test]
    fn alloc_single_frame() {
        let mut alloc = make_allocator(16);
        let addr = alloc.alloc_frame().expect("should allocate a frame");
        assert!(
            addr.is_page_aligned(),
            "returned address must be page-aligned"
        );
        assert!(
            addr.as_u64() >= 0x10_0000 && addr.as_u64() < 0x10_0000 + 16 * PAGE_SIZE,
            "address must be within managed region"
        );
    }

    #[test]
    fn alloc_and_free_roundtrip() {
        let mut alloc = make_allocator(16);
        let initial_free = alloc.free_frame_count();
        assert_eq!(initial_free, 16);

        let addr = alloc.alloc_frame().unwrap();
        assert_eq!(alloc.free_frame_count(), 15);

        alloc.free_frame(addr).unwrap();
        assert_eq!(alloc.free_frame_count(), 16);
    }

    #[test]
    fn alloc_all_frames() {
        let mut alloc = make_allocator(4);
        let mut addrs = Vec::new();
        for _ in 0..4 {
            addrs.push(alloc.alloc_frame().expect("should succeed"));
        }
        // All addresses must be unique.
        addrs.sort_by_key(|a| a.as_u64());
        addrs.dedup_by_key(|a| a.as_u64());
        assert_eq!(addrs.len(), 4, "all 4 addresses must be unique");
        assert_eq!(alloc.free_frame_count(), 0);
    }

    #[test]
    fn exhaustion_returns_none() {
        let mut alloc = make_allocator(1);
        let _a = alloc.alloc_frame().expect("first alloc succeeds");
        assert!(alloc.alloc_frame().is_none(), "second alloc should fail");
    }

    #[test]
    fn buddy_coalescing() {
        let mut alloc = make_allocator(4);
        let a0 = alloc.alloc_frame().unwrap();
        let a1 = alloc.alloc_frame().unwrap();
        let a2 = alloc.alloc_frame().unwrap();
        let a3 = alloc.alloc_frame().unwrap();
        assert_eq!(alloc.free_frame_count(), 0);

        // Free all 4 frames — they should coalesce back into an order-2 block.
        alloc.free_frame(a0).unwrap();
        alloc.free_frame(a1).unwrap();
        alloc.free_frame(a2).unwrap();
        alloc.free_frame(a3).unwrap();
        assert_eq!(alloc.free_frame_count(), 4);

        // Allocating an order-2 block (4 frames) should succeed.
        let block = alloc
            .alloc(2)
            .expect("order-2 alloc should succeed after coalescing");
        assert!(block.is_page_aligned());
        assert_eq!(alloc.free_frame_count(), 0);
    }

    #[test]
    fn split_larger_block() {
        let mut alloc = make_allocator(8);
        assert_eq!(alloc.free_frame_count(), 8);

        let _a = alloc.alloc_frame().unwrap();
        assert_eq!(
            alloc.free_frame_count(),
            7,
            "allocating 1 frame from 8 should leave 7 free"
        );
    }

    #[test]
    fn alloc_order_too_large() {
        let mut alloc = make_allocator(4);
        let err = alloc.alloc(MAX_ORDER + 1).unwrap_err();
        assert_eq!(err, VmError::InvalidOrder(MAX_ORDER + 1));
    }

    #[test]
    fn alloc_order_larger_than_available() {
        let mut alloc = make_allocator(4);
        // Order 3 needs 8 frames, but we only have 4.
        let err = alloc.alloc(3).unwrap_err();
        assert_eq!(err, VmError::OutOfMemory);
    }

    #[test]
    fn reserve_range_excludes_frames() {
        let mut alloc = make_allocator(8);
        assert_eq!(alloc.free_frame_count(), 8);

        // Reserve 2 frames starting at base + 2*PAGE_SIZE.
        let reserve_start = PhysAddr(0x10_0000 + 2 * PAGE_SIZE);
        alloc.reserve_range(reserve_start, 2).unwrap();
        assert_eq!(alloc.free_frame_count(), 6);

        // Allocate all 6 remaining frames, none should overlap with reserved.
        let mut addrs = Vec::new();
        for _ in 0..6 {
            addrs.push(alloc.alloc_frame().expect("should have free frames"));
        }
        let reserved_start = reserve_start.as_u64();
        let reserved_end = reserved_start + 2 * PAGE_SIZE;
        for a in &addrs {
            assert!(
                a.as_u64() < reserved_start || a.as_u64() >= reserved_end,
                "allocated frame {:#x} overlaps reserved range",
                a.as_u64()
            );
        }
        assert!(alloc.alloc_frame().is_none(), "should be exhausted");
    }

    #[test]
    fn double_free_rejected() {
        let mut alloc = make_allocator(4);
        let addr = alloc.alloc_frame().unwrap();
        alloc.free_frame(addr).unwrap();
        assert!(
            alloc.free_frame(addr).is_err(),
            "double free should be rejected"
        );
    }

    #[test]
    fn unaligned_base_rejected() {
        let err = BuddyAllocator::new(PhysAddr(0x1234), 4).unwrap_err();
        assert_eq!(err, VmError::Unaligned(0x1234));
    }

    #[test]
    fn zero_frames_rejected() {
        let err = BuddyAllocator::new(PhysAddr(0x10_0000), 0).unwrap_err();
        assert_eq!(err, VmError::InvalidOrder(0));
    }

    #[test]
    fn frame_size_matches_page_size() {
        use super::super::{PAGE_SHIFT, PAGE_SIZE};
        assert_eq!(PAGE_SIZE, 1u64 << PAGE_SHIFT);
        let base = PhysAddr(PAGE_SIZE * 16);
        let mut alloc = BuddyAllocator::new(base, 16).unwrap();
        let frame = alloc.alloc(0);
        assert!(frame.is_ok(), "order-0 alloc should succeed with 16 frames");
    }

    #[test]
    fn fragmentation_recovery() {
        // Allocate 8 frames, free in interleaved order, verify full coalescing.
        let mut alloc = make_allocator(8);
        let mut addrs = Vec::new();
        for _ in 0..8 {
            addrs.push(alloc.alloc_frame().unwrap());
        }
        assert_eq!(alloc.free_frame_count(), 0);

        // Free in interleaved order: 0, 2, 4, 6, 1, 3, 5, 7.
        alloc.free_frame(addrs[0]).unwrap();
        alloc.free_frame(addrs[2]).unwrap();
        alloc.free_frame(addrs[4]).unwrap();
        alloc.free_frame(addrs[6]).unwrap();
        alloc.free_frame(addrs[1]).unwrap();
        alloc.free_frame(addrs[3]).unwrap();
        alloc.free_frame(addrs[5]).unwrap();
        alloc.free_frame(addrs[7]).unwrap();

        assert_eq!(alloc.free_frame_count(), 8);

        // Should be able to allocate a single order-3 block (all 8 frames).
        let block = alloc
            .alloc(3)
            .expect("order-3 alloc should succeed after full coalescing");
        assert!(block.is_page_aligned());
        assert_eq!(alloc.free_frame_count(), 0);
    }

    #[test]
    fn free_frame_count_consistency() {
        let mut alloc = make_allocator(16);
        assert_eq!(alloc.free_frame_count(), 16);
        assert_eq!(alloc.total_frame_count(), 16);

        // Allocate order-2 (4 frames).
        let a = alloc.alloc(2).unwrap();
        assert_eq!(alloc.free_frame_count(), 12);

        // Allocate order-1 (2 frames).
        let b = alloc.alloc(1).unwrap();
        assert_eq!(alloc.free_frame_count(), 10);

        // Free order-1 block.
        alloc.free(b, 1).unwrap();
        assert_eq!(alloc.free_frame_count(), 12);

        // Free order-2 block.
        alloc.free(a, 2).unwrap();
        assert_eq!(alloc.free_frame_count(), 16);
    }
}
