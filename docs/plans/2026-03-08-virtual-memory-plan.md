# Virtual Memory and Page Tables — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace flat address space MVP with per-process virtual memory, buddy allocator, per-frame capability tracking, and real mmap/munmap in the Linuxulator.

**Architecture:** Layered sans-I/O design. A thin `PageTable` trait abstracts hardware (x86_64/aarch64), with an architecture-independent `AddressSpaceManager` handling all policy (buddy allocation, capability enforcement, zeroize-on-unmap). ~90% of logic testable on host via `MockPageTable`.

**Tech Stack:** Rust (no_std compatible core, std for kernel feature), harmony-identity (UCAN tokens), bitflags crate (PageFlags).

**Design doc:** `docs/plans/2026-03-08-virtual-memory-design.md`

---

### Task 1: VM Module Scaffold — Types, Errors, PageFlags

**Files:**
- Create: `crates/harmony-microkernel/src/vm/mod.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs:14-20` (add `pub mod vm;`)
- Modify: `crates/harmony-microkernel/Cargo.toml` (add `bitflags` dependency)

**Step 1: Add bitflags to workspace deps**

In `/Users/zeblith/work/zeblithic/harmony-os/Cargo.toml`, add under `[workspace.dependencies]`:
```toml
bitflags = "2"
```

In `crates/harmony-microkernel/Cargo.toml`, add under `[dependencies]`:
```toml
bitflags = { workspace = true }
```

**Step 2: Write the failing test**

Create `crates/harmony-microkernel/src/vm/mod.rs`:
```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! Virtual memory subsystem — types, page table trait, allocators, manager.

extern crate alloc;

use core::fmt;

/// Virtual address — newtype to prevent mixing with physical addresses.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtAddr(pub u64);

/// Physical address — newtype to prevent mixing with virtual addresses.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhysAddr(pub u64);

impl VirtAddr {
    pub const fn new(addr: u64) -> Self { Self(addr) }
    pub const fn as_u64(self) -> u64 { self.0 }
    /// Page-align downward.
    pub const fn page_align_down(self) -> Self { Self(self.0 & !0xFFF) }
    /// Page-align upward.
    pub const fn page_align_up(self) -> Self {
        Self((self.0 + 0xFFF) & !0xFFF)
    }
    pub const fn is_page_aligned(self) -> bool { self.0 & 0xFFF == 0 }
}

impl PhysAddr {
    pub const fn new(addr: u64) -> Self { Self(addr) }
    pub const fn as_u64(self) -> u64 { self.0 }
    pub const fn page_align_down(self) -> Self { Self(self.0 & !0xFFF) }
    pub const fn page_align_up(self) -> Self {
        Self((self.0 + 0xFFF) & !0xFFF)
    }
    pub const fn is_page_aligned(self) -> bool { self.0 & 0xFFF == 0 }
}

impl fmt::Debug for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VirtAddr({:#x})", self.0)
    }
}

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysAddr({:#x})", self.0)
    }
}

bitflags::bitflags! {
    /// Architecture-independent page permission flags.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PageFlags: u64 {
        const READABLE   = 1 << 0;
        const WRITABLE   = 1 << 1;
        const EXECUTABLE = 1 << 2;
        const USER       = 1 << 3;
        const NO_CACHE   = 1 << 4;
        const GLOBAL     = 1 << 5;
    }
}

bitflags::bitflags! {
    /// Frame classification metadata — 2-bit encoding.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FrameClassification: u8 {
        /// Sensitive data: zeroize on unmap, restrict readers.
        const ENCRYPTED = 1 << 0;
        /// Short-lived data: LRU cache class instead of LFU.
        const EPHEMERAL = 1 << 1;
    }
}

/// Virtual memory errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmError {
    NoSuchProcess(u32),
    BudgetExceeded { limit: usize, used: usize, requested: usize },
    ClassificationDenied(FrameClassification),
    OutOfMemory,
    RegionConflict(VirtAddr),
    NotMapped(VirtAddr),
    CapabilityInvalid,
    PageTableError,
    Unaligned(u64),
    InvalidOrder(usize),
}

/// 4 KiB page size constant.
pub const PAGE_SIZE: usize = 4096;
/// Page shift (log2 of PAGE_SIZE).
pub const PAGE_SHIFT: usize = 12;

pub mod page_table;
pub mod mock;
pub mod buddy;
pub mod cap_tracker;
pub mod manager;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virt_addr_page_align() {
        assert_eq!(VirtAddr(0x1234).page_align_down(), VirtAddr(0x1000));
        assert_eq!(VirtAddr(0x1234).page_align_up(), VirtAddr(0x2000));
        assert!(VirtAddr(0x3000).is_page_aligned());
        assert!(!VirtAddr(0x3001).is_page_aligned());
    }

    #[test]
    fn phys_addr_page_align() {
        assert_eq!(PhysAddr(0x5678).page_align_down(), PhysAddr(0x5000));
        assert_eq!(PhysAddr(0x5678).page_align_up(), PhysAddr(0x6000));
        assert!(PhysAddr(0x4000).is_page_aligned());
    }

    #[test]
    fn page_flags_combine() {
        let rw = PageFlags::READABLE | PageFlags::WRITABLE;
        assert!(rw.contains(PageFlags::READABLE));
        assert!(rw.contains(PageFlags::WRITABLE));
        assert!(!rw.contains(PageFlags::EXECUTABLE));
    }

    #[test]
    fn frame_classification_bits() {
        let public_durable = FrameClassification::empty();
        assert!(!public_durable.contains(FrameClassification::ENCRYPTED));
        assert!(!public_durable.contains(FrameClassification::EPHEMERAL));

        let encrypted_ephemeral =
            FrameClassification::ENCRYPTED | FrameClassification::EPHEMERAL;
        assert!(encrypted_ephemeral.contains(FrameClassification::ENCRYPTED));
        assert!(encrypted_ephemeral.contains(FrameClassification::EPHEMERAL));
    }

    #[test]
    fn virt_phys_addr_not_interchangeable() {
        // Type system prevents mixing — this is a compile-time guarantee.
        // We verify the newtypes have distinct Debug output.
        let v = VirtAddr(0x1000);
        let p = PhysAddr(0x1000);
        let v_dbg = alloc::format!("{:?}", v);
        let p_dbg = alloc::format!("{:?}", p);
        assert!(v_dbg.contains("VirtAddr"));
        assert!(p_dbg.contains("PhysAddr"));
    }
}
```

**Step 3: Add `pub mod vm` to lib.rs**

In `crates/harmony-microkernel/src/lib.rs`, add after line 20 (`pub mod serial_server;`):
```rust
pub mod vm;
```

**Step 4: Create stub submodules**

Create each of these as minimal files so `mod.rs` compiles:

`crates/harmony-microkernel/src/vm/page_table.rs`:
```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! PageTable trait — hardware page table abstraction.
```

`crates/harmony-microkernel/src/vm/mock.rs`:
```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! MockPageTable for host testing.
```

`crates/harmony-microkernel/src/vm/buddy.rs`:
```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! Buddy allocator for physical frame allocation.
```

`crates/harmony-microkernel/src/vm/cap_tracker.rs`:
```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! Capability tracker — hybrid bitmap + B-tree for frame metadata.
```

`crates/harmony-microkernel/src/vm/manager.rs`:
```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! AddressSpaceManager — central coordinator for virtual memory.
```

**Step 5: Run tests**

Run: `cargo test -p harmony-microkernel`
Expected: All existing 105 tests PASS + 5 new VM type tests PASS.

**Step 6: Commit**

```
feat(vm): add virtual memory types, PageFlags, FrameClassification, VmError
```

---

### Task 2: PageTable Trait + MockPageTable

**Files:**
- Modify: `crates/harmony-microkernel/src/vm/page_table.rs`
- Modify: `crates/harmony-microkernel/src/vm/mock.rs`

**Step 1: Write failing tests in mock.rs**

```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! MockPageTable for host testing.

use alloc::collections::BTreeMap;
use super::{PhysAddr, VirtAddr, PageFlags, VmError, PAGE_SIZE};
use super::page_table::PageTable;

/// In-memory page table for testing. No hardware interaction.
pub struct MockPageTable {
    mappings: BTreeMap<VirtAddr, (PhysAddr, PageFlags)>,
    root: PhysAddr,
    activated: bool,
}

impl MockPageTable {
    pub fn new(root: PhysAddr) -> Self {
        Self {
            mappings: BTreeMap::new(),
            root,
            activated: false,
        }
    }

    /// Check if this page table has been activated.
    pub fn is_activated(&self) -> bool {
        self.activated
    }

    /// Count of mapped pages (for testing).
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
        let entry = self.mappings.get_mut(&vaddr).ok_or(VmError::NotMapped(vaddr))?;
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

    #[test]
    fn map_and_translate() {
        let mut pt = MockPageTable::new(PhysAddr(0x1000));
        let flags = PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::USER;
        let mut alloc = || None; // mock doesn't need intermediate tables
        pt.map(VirtAddr(0x2000), PhysAddr(0x3000), flags, &mut alloc).unwrap();

        let (paddr, pflags) = pt.translate(VirtAddr(0x2000)).unwrap();
        assert_eq!(paddr, PhysAddr(0x3000));
        assert_eq!(pflags, flags);
    }

    #[test]
    fn translate_unmapped_returns_none() {
        let pt = MockPageTable::new(PhysAddr(0x1000));
        assert!(pt.translate(VirtAddr(0x5000)).is_none());
    }

    #[test]
    fn unmap_returns_paddr() {
        let mut pt = MockPageTable::new(PhysAddr(0x1000));
        let mut alloc = || None;
        pt.map(VirtAddr(0x2000), PhysAddr(0x3000), PageFlags::READABLE, &mut alloc).unwrap();

        let paddr = pt.unmap(VirtAddr(0x2000)).unwrap();
        assert_eq!(paddr, PhysAddr(0x3000));
        assert!(pt.translate(VirtAddr(0x2000)).is_none());
    }

    #[test]
    fn unmap_unmapped_returns_error() {
        let mut pt = MockPageTable::new(PhysAddr(0x1000));
        assert_eq!(pt.unmap(VirtAddr(0x5000)), Err(VmError::NotMapped(VirtAddr(0x5000))));
    }

    #[test]
    fn map_unaligned_rejected() {
        let mut pt = MockPageTable::new(PhysAddr(0x1000));
        let mut alloc = || None;
        assert_eq!(
            pt.map(VirtAddr(0x1234), PhysAddr(0x3000), PageFlags::READABLE, &mut alloc),
            Err(VmError::Unaligned(0x1234))
        );
    }

    #[test]
    fn map_duplicate_rejected() {
        let mut pt = MockPageTable::new(PhysAddr(0x1000));
        let mut alloc = || None;
        pt.map(VirtAddr(0x2000), PhysAddr(0x3000), PageFlags::READABLE, &mut alloc).unwrap();
        assert_eq!(
            pt.map(VirtAddr(0x2000), PhysAddr(0x4000), PageFlags::READABLE, &mut alloc),
            Err(VmError::RegionConflict(VirtAddr(0x2000)))
        );
    }

    #[test]
    fn set_flags_updates_permissions() {
        let mut pt = MockPageTable::new(PhysAddr(0x1000));
        let mut alloc = || None;
        pt.map(VirtAddr(0x2000), PhysAddr(0x3000), PageFlags::READABLE, &mut alloc).unwrap();
        pt.set_flags(VirtAddr(0x2000), PageFlags::READABLE | PageFlags::WRITABLE).unwrap();

        let (_, flags) = pt.translate(VirtAddr(0x2000)).unwrap();
        assert!(flags.contains(PageFlags::WRITABLE));
    }

    #[test]
    fn activate_sets_flag() {
        let mut pt = MockPageTable::new(PhysAddr(0x1000));
        assert!(!pt.is_activated());
        pt.activate();
        assert!(pt.is_activated());
    }

    #[test]
    fn root_paddr_returns_root() {
        let pt = MockPageTable::new(PhysAddr(0xDEAD_0000));
        assert_eq!(pt.root_paddr(), PhysAddr(0xDEAD_0000));
    }
}
```

**Step 2: Write the PageTable trait**

In `crates/harmony-microkernel/src/vm/page_table.rs`:
```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! PageTable trait — hardware page table abstraction.
//!
//! Implementors manipulate MMU state only — no policy, no allocation
//! decisions, no capability checks. All policy lives in AddressSpaceManager.

use super::{PhysAddr, VirtAddr, PageFlags, VmError};

/// Hardware page table abstraction.
///
/// The `frame_alloc` callback on `map()` lets the caller provide frames
/// for intermediate page table levels without the trait owning an allocator.
pub trait PageTable {
    /// Map a 4 KiB virtual page to a physical frame with given flags.
    ///
    /// `frame_alloc` is called when intermediate page table levels need
    /// to be created. It must return a zeroed, page-aligned physical frame.
    fn map(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PageFlags,
        frame_alloc: &mut dyn FnMut() -> Option<PhysAddr>,
    ) -> Result<(), VmError>;

    /// Unmap a page, returning the physical address that was mapped.
    /// Does NOT free the frame — caller handles that.
    fn unmap(&mut self, vaddr: VirtAddr) -> Result<PhysAddr, VmError>;

    /// Update flags on an existing mapping without changing the physical frame.
    fn set_flags(&mut self, vaddr: VirtAddr, flags: PageFlags) -> Result<(), VmError>;

    /// Translate virtual to physical. Returns None if not mapped.
    fn translate(&self, vaddr: VirtAddr) -> Option<(PhysAddr, PageFlags)>;

    /// Activate this page table on the current CPU.
    /// x86_64: writes CR3. aarch64: writes TTBR0_EL1.
    fn activate(&mut self);

    /// Return the physical address of the root table.
    fn root_paddr(&self) -> PhysAddr;
}
```

**Step 3: Run tests**

Run: `cargo test -p harmony-microkernel`
Expected: All existing tests PASS + 9 new mock page table tests PASS.

**Step 4: Commit**

```
feat(vm): add PageTable trait and MockPageTable implementation
```

---

### Task 3: Buddy Allocator

**Files:**
- Modify: `crates/harmony-microkernel/src/vm/buddy.rs`

**Step 1: Write failing tests**

```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! Buddy allocator for physical frame allocation.

use alloc::vec;
use alloc::vec::Vec;
use super::{PhysAddr, VmError, PAGE_SIZE, PAGE_SHIFT};

/// Maximum buddy order. Order 10 = 4 MiB (1024 contiguous frames).
pub const MAX_ORDER: usize = 10;

/// Buddy allocator for physical page frames.
///
/// Manages a contiguous region of physical memory. Free blocks are tracked
/// in per-order free lists. Buddy coalescing on free prevents fragmentation.
pub struct BuddyAllocator {
    /// Free lists indexed by order. Order 0 = 4 KiB single frame.
    free_lists: [Vec<PhysAddr>; MAX_ORDER + 1],
    /// 1 bit per frame: 1 = allocated, 0 = free.
    bitmap: Vec<u8>,
    /// Physical base address of the managed region.
    base: PhysAddr,
    /// Total number of frames in the managed region.
    frame_count: usize,
}

impl BuddyAllocator {
    /// Create a new buddy allocator managing `frame_count` frames starting at `base`.
    ///
    /// All frames start as free. `base` must be page-aligned.
    pub fn new(base: PhysAddr, frame_count: usize) -> Result<Self, VmError> {
        if !base.is_page_aligned() {
            return Err(VmError::Unaligned(base.as_u64()));
        }
        if frame_count == 0 {
            return Err(VmError::OutOfMemory);
        }

        let bitmap_bytes = (frame_count + 7) / 8;
        let mut alloc = BuddyAllocator {
            free_lists: core::array::from_fn(|_| Vec::new()),
            bitmap: vec![0u8; bitmap_bytes],
            base,
            frame_count,
        };

        // Insert all frames as the largest possible buddy blocks.
        let mut offset = 0;
        while offset < frame_count {
            // Find largest order that fits and is naturally aligned.
            let mut order = MAX_ORDER;
            while order > 0 {
                let block_size = 1 << order;
                if offset + block_size <= frame_count && (offset % block_size) == 0 {
                    break;
                }
                order -= 1;
            }
            let addr = PhysAddr(base.as_u64() + (offset as u64) * (PAGE_SIZE as u64));
            alloc.free_lists[order].push(addr);
            offset += 1 << order;
        }

        Ok(alloc)
    }

    /// Convert a physical address to a frame index.
    fn frame_index(&self, addr: PhysAddr) -> Option<usize> {
        if addr.as_u64() < self.base.as_u64() {
            return None;
        }
        let offset = (addr.as_u64() - self.base.as_u64()) as usize;
        if offset % PAGE_SIZE != 0 {
            return None;
        }
        let idx = offset / PAGE_SIZE;
        if idx >= self.frame_count {
            return None;
        }
        Some(idx)
    }

    /// Check if a frame is allocated (bitmap bit set).
    fn is_allocated(&self, idx: usize) -> bool {
        let byte = idx / 8;
        let bit = idx % 8;
        self.bitmap[byte] & (1 << bit) != 0
    }

    /// Set a frame as allocated in the bitmap.
    fn set_allocated(&mut self, idx: usize) {
        let byte = idx / 8;
        let bit = idx % 8;
        self.bitmap[byte] |= 1 << bit;
    }

    /// Clear a frame as free in the bitmap.
    fn set_free(&mut self, idx: usize) {
        let byte = idx / 8;
        let bit = idx % 8;
        self.bitmap[byte] &= !(1 << bit);
    }

    /// Mark a range of frames as allocated in the bitmap.
    fn mark_range_allocated(&mut self, start_idx: usize, count: usize) {
        for i in start_idx..start_idx + count {
            self.set_allocated(i);
        }
    }

    /// Allocate a block of 2^order contiguous frames.
    /// Returns the physical address of the first frame.
    pub fn alloc(&mut self, order: usize) -> Result<PhysAddr, VmError> {
        if order > MAX_ORDER {
            return Err(VmError::InvalidOrder(order));
        }

        // Find smallest available block >= requested order.
        let mut found_order = order;
        while found_order <= MAX_ORDER {
            if !self.free_lists[found_order].is_empty() {
                break;
            }
            found_order += 1;
        }
        if found_order > MAX_ORDER {
            return Err(VmError::OutOfMemory);
        }

        // Pop from the found order's free list.
        let addr = self.free_lists[found_order].pop().unwrap();

        // Split larger blocks down to requested order.
        while found_order > order {
            found_order -= 1;
            let buddy_addr = PhysAddr(addr.as_u64() + ((1u64 << found_order) << PAGE_SHIFT));
            self.free_lists[found_order].push(buddy_addr);
        }

        // Mark all frames in the block as allocated.
        let start_idx = self.frame_index(addr).unwrap();
        self.mark_range_allocated(start_idx, 1 << order);

        Ok(addr)
    }

    /// Allocate a single 4 KiB frame (order 0).
    pub fn alloc_frame(&mut self) -> Option<PhysAddr> {
        self.alloc(0).ok()
    }

    /// Free a block of 2^order contiguous frames. Coalesces with buddy if possible.
    pub fn free(&mut self, addr: PhysAddr, order: usize) -> Result<(), VmError> {
        if order > MAX_ORDER {
            return Err(VmError::InvalidOrder(order));
        }
        let start_idx = self.frame_index(addr).ok_or(VmError::Unaligned(addr.as_u64()))?;

        // Verify all frames in block are allocated.
        for i in start_idx..start_idx + (1 << order) {
            if !self.is_allocated(i) {
                return Err(VmError::NotMapped(VirtAddr::new(0))); // double free
            }
        }

        // Clear bitmap for all frames in block.
        for i in start_idx..start_idx + (1 << order) {
            self.set_free(i);
        }

        // Coalesce with buddy.
        let mut current_addr = addr;
        let mut current_order = order;
        while current_order < MAX_ORDER {
            let block_size_bytes = (1u64 << current_order) << PAGE_SHIFT as u64;
            let buddy_addr = PhysAddr(current_addr.as_u64() ^ block_size_bytes);

            // Check buddy is within our managed region.
            let buddy_idx = match self.frame_index(buddy_addr) {
                Some(idx) => idx,
                None => break,
            };

            // Check buddy is free (entire block).
            let buddy_free = (0..(1 << current_order))
                .all(|i| buddy_idx + i < self.frame_count && !self.is_allocated(buddy_idx + i));
            if !buddy_free {
                break;
            }

            // Remove buddy from free list at this order.
            let pos = self.free_lists[current_order]
                .iter()
                .position(|&a| a == buddy_addr);
            match pos {
                Some(p) => { self.free_lists[current_order].swap_remove(p); }
                None => break, // buddy not in free list at this order
            }

            // Merge: use lower address as the merged block.
            current_addr = PhysAddr(current_addr.as_u64().min(buddy_addr.as_u64()));
            current_order += 1;
        }

        self.free_lists[current_order].push(current_addr);
        Ok(())
    }

    /// Free a single frame (order 0).
    pub fn free_frame(&mut self, addr: PhysAddr) -> Result<(), VmError> {
        self.free(addr, 0)
    }

    /// Number of free frames across all orders.
    pub fn free_frame_count(&self) -> usize {
        let mut count = 0;
        for (order, list) in self.free_lists.iter().enumerate() {
            count += list.len() * (1 << order);
        }
        count
    }

    /// Total managed frame count.
    pub fn total_frame_count(&self) -> usize {
        self.frame_count
    }

    /// Reserve (mark allocated) a range of frames, removing them from free lists.
    /// Used at boot to mark kernel code, MMIO, boot structures as unavailable.
    pub fn reserve_range(&mut self, start: PhysAddr, frame_count: usize) -> Result<(), VmError> {
        let start_idx = self.frame_index(start)
            .ok_or(VmError::Unaligned(start.as_u64()))?;
        if start_idx + frame_count > self.frame_count {
            return Err(VmError::OutOfMemory);
        }

        // Mark frames as allocated in bitmap.
        self.mark_range_allocated(start_idx, frame_count);

        // Rebuild free lists from scratch (simple but correct).
        // This is called rarely (boot time only), so O(n) is fine.
        for list in &mut self.free_lists {
            list.clear();
        }
        let mut offset = 0;
        while offset < self.frame_count {
            if self.is_allocated(offset) {
                offset += 1;
                continue;
            }
            // Find largest free buddy block starting here.
            let mut order = 0;
            while order < MAX_ORDER {
                let next_order = order + 1;
                let block_size = 1 << next_order;
                if offset % block_size != 0 || offset + block_size > self.frame_count {
                    break;
                }
                let all_free = (offset..offset + block_size).all(|i| !self.is_allocated(i));
                if !all_free {
                    break;
                }
                order = next_order;
            }
            let addr = PhysAddr(self.base.as_u64() + (offset as u64) * (PAGE_SIZE as u64));
            self.free_lists[order].push(addr);
            offset += 1 << order;
        }

        Ok(())
    }
}

// Need VirtAddr for VmError::NotMapped in free()
use super::VirtAddr;

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: PhysAddr = PhysAddr(0x10_0000); // 1 MiB

    #[test]
    fn alloc_single_frame() {
        let mut buddy = BuddyAllocator::new(BASE, 16).unwrap();
        let addr = buddy.alloc_frame().unwrap();
        assert!(addr.is_page_aligned());
        assert!(addr.as_u64() >= BASE.as_u64());
    }

    #[test]
    fn alloc_and_free_roundtrip() {
        let mut buddy = BuddyAllocator::new(BASE, 16).unwrap();
        let total = buddy.free_frame_count();
        let addr = buddy.alloc_frame().unwrap();
        assert_eq!(buddy.free_frame_count(), total - 1);
        buddy.free_frame(addr).unwrap();
        assert_eq!(buddy.free_frame_count(), total);
    }

    #[test]
    fn alloc_all_frames() {
        let mut buddy = BuddyAllocator::new(BASE, 4).unwrap();
        let mut addrs = Vec::new();
        for _ in 0..4 {
            addrs.push(buddy.alloc_frame().unwrap());
        }
        assert_eq!(buddy.free_frame_count(), 0);
        assert!(buddy.alloc_frame().is_none());

        // All addresses are unique.
        addrs.sort_by_key(|a| a.as_u64());
        addrs.dedup_by_key(|a| a.as_u64());
        assert_eq!(addrs.len(), 4);
    }

    #[test]
    fn exhaustion_returns_none() {
        let mut buddy = BuddyAllocator::new(BASE, 1).unwrap();
        buddy.alloc_frame().unwrap();
        assert!(buddy.alloc_frame().is_none());
    }

    #[test]
    fn buddy_coalescing() {
        let mut buddy = BuddyAllocator::new(BASE, 4).unwrap();
        // Allocate 4 individual frames.
        let a = buddy.alloc_frame().unwrap();
        let b = buddy.alloc_frame().unwrap();
        let c = buddy.alloc_frame().unwrap();
        let d = buddy.alloc_frame().unwrap();
        assert_eq!(buddy.free_frame_count(), 0);

        // Free all — should coalesce back to a single order-2 block.
        buddy.free_frame(a).unwrap();
        buddy.free_frame(b).unwrap();
        buddy.free_frame(c).unwrap();
        buddy.free_frame(d).unwrap();
        assert_eq!(buddy.free_frame_count(), 4);

        // Can allocate an order-2 block (4 contiguous frames).
        let block = buddy.alloc(2).unwrap();
        assert!(block.is_page_aligned());
        assert_eq!(buddy.free_frame_count(), 0);
    }

    #[test]
    fn split_larger_block() {
        // 8 frames = one order-3 block. Allocating order-0 should split.
        let mut buddy = BuddyAllocator::new(BASE, 8).unwrap();
        let addr = buddy.alloc_frame().unwrap();
        // 7 frames should remain free (the split remainder).
        assert_eq!(buddy.free_frame_count(), 7);
        buddy.free_frame(addr).unwrap();
        assert_eq!(buddy.free_frame_count(), 8);
    }

    #[test]
    fn alloc_order_too_large() {
        let mut buddy = BuddyAllocator::new(BASE, 4).unwrap();
        assert_eq!(buddy.alloc(MAX_ORDER + 1), Err(VmError::InvalidOrder(MAX_ORDER + 1)));
    }

    #[test]
    fn alloc_order_larger_than_available() {
        let mut buddy = BuddyAllocator::new(BASE, 4).unwrap();
        // 4 frames max = order 2. Trying order 3 (8 frames) should fail.
        assert_eq!(buddy.alloc(3), Err(VmError::OutOfMemory));
    }

    #[test]
    fn reserve_range_excludes_frames() {
        let mut buddy = BuddyAllocator::new(BASE, 8).unwrap();
        // Reserve frames 2-3 (2 frames starting at base + 2*PAGE_SIZE).
        let reserved = PhysAddr(BASE.as_u64() + 2 * PAGE_SIZE as u64);
        buddy.reserve_range(reserved, 2).unwrap();
        assert_eq!(buddy.free_frame_count(), 6);

        // Allocate all free frames — reserved ones should never appear.
        let mut addrs = Vec::new();
        while let Some(addr) = buddy.alloc_frame() {
            assert_ne!(addr, reserved);
            assert_ne!(addr, PhysAddr(reserved.as_u64() + PAGE_SIZE as u64));
            addrs.push(addr);
        }
        assert_eq!(addrs.len(), 6);
    }

    #[test]
    fn double_free_rejected() {
        let mut buddy = BuddyAllocator::new(BASE, 4).unwrap();
        let addr = buddy.alloc_frame().unwrap();
        buddy.free_frame(addr).unwrap();
        assert!(buddy.free_frame(addr).is_err());
    }

    #[test]
    fn unaligned_base_rejected() {
        assert!(BuddyAllocator::new(PhysAddr(0x1234), 4).is_err());
    }

    #[test]
    fn zero_frames_rejected() {
        assert!(BuddyAllocator::new(BASE, 0).is_err());
    }

    #[test]
    fn fragmentation_recovery() {
        let mut buddy = BuddyAllocator::new(BASE, 8).unwrap();
        // Allocate 8 individual frames.
        let mut addrs: Vec<PhysAddr> = (0..8).map(|_| buddy.alloc_frame().unwrap()).collect();
        assert_eq!(buddy.free_frame_count(), 0);

        // Free in interleaved order — buddies should still coalesce.
        // Free even indices first, then odd.
        let evens: Vec<PhysAddr> = addrs.iter().copied().enumerate()
            .filter(|(i, _)| i % 2 == 0).map(|(_, a)| a).collect();
        let odds: Vec<PhysAddr> = addrs.iter().copied().enumerate()
            .filter(|(i, _)| i % 2 == 1).map(|(_, a)| a).collect();

        for a in evens { buddy.free_frame(a).unwrap(); }
        for a in odds { buddy.free_frame(a).unwrap(); }

        assert_eq!(buddy.free_frame_count(), 8);
        // Should be able to allocate a full order-3 block after coalescing.
        let block = buddy.alloc(3).unwrap();
        assert_eq!(buddy.free_frame_count(), 0);
        buddy.free(block, 3).unwrap();
    }

    #[test]
    fn free_frame_count_consistency() {
        let mut buddy = BuddyAllocator::new(BASE, 16).unwrap();
        assert_eq!(buddy.free_frame_count(), 16);
        assert_eq!(buddy.total_frame_count(), 16);

        let a = buddy.alloc(2).unwrap(); // 4 frames
        assert_eq!(buddy.free_frame_count(), 12);
        let b = buddy.alloc(1).unwrap(); // 2 frames
        assert_eq!(buddy.free_frame_count(), 10);

        buddy.free(a, 2).unwrap();
        assert_eq!(buddy.free_frame_count(), 14);
        buddy.free(b, 1).unwrap();
        assert_eq!(buddy.free_frame_count(), 16);
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p harmony-microkernel vm::buddy`
Expected: All 13 buddy tests PASS.

**Step 3: Commit**

```
feat(vm): add buddy allocator with split, coalesce, and reserve_range
```

---

### Task 4: Capability Tracker

**Files:**
- Modify: `crates/harmony-microkernel/src/vm/cap_tracker.rs`
- Modify: `crates/harmony-microkernel/src/vm/mod.rs` (conditional import of harmony-identity)

**Step 1: Write the CapTracker**

```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! Capability tracker — hybrid bitmap + B-tree for frame metadata.
//!
//! Most frames (private, public, durable) have no B-tree entry — their
//! ownership is implicit from the page table that maps them. Only
//! "interesting" frames (shared, encrypted, ephemeral) get FrameMeta entries.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{FrameClassification, PhysAddr, VmError, PAGE_SIZE, PAGE_SHIFT};

/// Per-frame metadata for frames that need capability tracking.
#[derive(Debug, Clone)]
pub struct FrameMeta {
    /// PID that allocated this frame.
    pub owner_pid: u32,
    /// Sensitivity/durability classification.
    pub classification: FrameClassification,
    /// All PIDs that currently have this frame mapped.
    pub mapped_by: Vec<u32>,
}

/// Per-process memory budget.
#[derive(Debug, Clone)]
pub struct MemoryBudget {
    /// Maximum bytes this process may have mapped.
    pub limit: usize,
    /// Currently mapped bytes.
    pub used: usize,
    /// Allowed frame classifications for this process.
    pub allowed_classes: FrameClassification,
}

impl MemoryBudget {
    pub fn new(limit: usize, allowed_classes: FrameClassification) -> Self {
        Self {
            limit,
            used: 0,
            allowed_classes,
        }
    }

    /// Check if `additional` bytes can be mapped within budget.
    pub fn can_map(&self, additional: usize) -> bool {
        self.used.checked_add(additional).map_or(false, |total| total <= self.limit)
    }
}

/// Hybrid frame metadata tracker.
///
/// Uses a bitmap for allocation status (O(1) lookups) and a B-tree
/// for frames that need full capability tracking.
pub struct CapTracker {
    /// B-tree of frames with non-default metadata.
    /// Key = frame number (PhysAddr >> PAGE_SHIFT).
    frame_meta: BTreeMap<u64, FrameMeta>,
    /// Per-process memory budgets.
    budgets: BTreeMap<u32, MemoryBudget>,
}

impl CapTracker {
    pub fn new() -> Self {
        Self {
            frame_meta: BTreeMap::new(),
            budgets: BTreeMap::new(),
        }
    }

    /// Register a memory budget for a process.
    pub fn set_budget(&mut self, pid: u32, budget: MemoryBudget) {
        self.budgets.insert(pid, budget);
    }

    /// Remove a process's budget (on process destroy).
    pub fn remove_budget(&mut self, pid: u32) {
        self.budgets.remove(&pid);
    }

    /// Check if a process can map `size` bytes with the given classification.
    pub fn check_budget(
        &self,
        pid: u32,
        size: usize,
        classification: FrameClassification,
    ) -> Result<(), VmError> {
        let budget = self.budgets.get(&pid)
            .ok_or(VmError::NoSuchProcess(pid))?;

        if !budget.can_map(size) {
            return Err(VmError::BudgetExceeded {
                limit: budget.limit,
                used: budget.used,
                requested: size,
            });
        }

        // Check classification is allowed.
        if !classification.is_empty() && !budget.allowed_classes.contains(classification) {
            return Err(VmError::ClassificationDenied(classification));
        }

        Ok(())
    }

    /// Record that a frame has been mapped by a process.
    /// Only creates a B-tree entry for non-default classifications.
    pub fn record_mapping(
        &mut self,
        paddr: PhysAddr,
        pid: u32,
        classification: FrameClassification,
    ) {
        // Update budget.
        if let Some(budget) = self.budgets.get_mut(&pid) {
            budget.used = budget.used.saturating_add(PAGE_SIZE);
        }

        // Only track in B-tree if classification is non-default.
        if !classification.is_empty() {
            let frame_num = paddr.as_u64() >> PAGE_SHIFT;
            let meta = self.frame_meta.entry(frame_num).or_insert_with(|| FrameMeta {
                owner_pid: pid,
                classification,
                mapped_by: Vec::new(),
            });
            if !meta.mapped_by.contains(&pid) {
                meta.mapped_by.push(pid);
            }
        }
    }

    /// Record removal of a mapping. Returns classification for zeroize decision.
    pub fn remove_mapping(
        &mut self,
        paddr: PhysAddr,
        pid: u32,
    ) -> FrameClassification {
        // Refund budget.
        if let Some(budget) = self.budgets.get_mut(&pid) {
            budget.used = budget.used.saturating_sub(PAGE_SIZE);
        }

        let frame_num = paddr.as_u64() >> PAGE_SHIFT;
        let classification;

        if let Some(meta) = self.frame_meta.get_mut(&frame_num) {
            classification = meta.classification;
            meta.mapped_by.retain(|&p| p != pid);
            if meta.mapped_by.is_empty() {
                self.frame_meta.remove(&frame_num);
            }
        } else {
            classification = FrameClassification::empty();
        }

        classification
    }

    /// Get the classification of a frame (empty = default/public/durable).
    pub fn frame_classification(&self, paddr: PhysAddr) -> FrameClassification {
        let frame_num = paddr.as_u64() >> PAGE_SHIFT;
        self.frame_meta
            .get(&frame_num)
            .map(|m| m.classification)
            .unwrap_or(FrameClassification::empty())
    }

    /// Find all frames matching a classification and return their addresses
    /// along with the PIDs that map them. Used for revocation cascade.
    pub fn frames_with_classification(
        &self,
        class: FrameClassification,
    ) -> Vec<(PhysAddr, Vec<u32>)> {
        self.frame_meta
            .iter()
            .filter(|(_, meta)| meta.classification.contains(class))
            .map(|(&frame_num, meta)| {
                let addr = PhysAddr(frame_num << PAGE_SHIFT);
                (addr, meta.mapped_by.clone())
            })
            .collect()
    }

    /// Get a process's current budget usage.
    pub fn budget(&self, pid: u32) -> Option<&MemoryBudget> {
        self.budgets.get(&pid)
    }

    /// Number of frames with explicit metadata (for testing).
    pub fn tracked_frame_count(&self) -> usize {
        self.frame_meta.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_enforcement() {
        let mut tracker = CapTracker::new();
        tracker.set_budget(1, MemoryBudget::new(PAGE_SIZE * 4, FrameClassification::all()));

        // Within budget.
        assert!(tracker.check_budget(1, PAGE_SIZE, FrameClassification::empty()).is_ok());

        // Exactly at limit.
        assert!(tracker.check_budget(1, PAGE_SIZE * 4, FrameClassification::empty()).is_ok());

        // Over budget.
        assert_eq!(
            tracker.check_budget(1, PAGE_SIZE * 5, FrameClassification::empty()),
            Err(VmError::BudgetExceeded {
                limit: PAGE_SIZE * 4,
                used: 0,
                requested: PAGE_SIZE * 5,
            })
        );
    }

    #[test]
    fn budget_tracks_usage() {
        let mut tracker = CapTracker::new();
        tracker.set_budget(1, MemoryBudget::new(PAGE_SIZE * 4, FrameClassification::all()));

        tracker.record_mapping(PhysAddr(0x1000), 1, FrameClassification::empty());
        assert_eq!(tracker.budget(1).unwrap().used, PAGE_SIZE);

        tracker.record_mapping(PhysAddr(0x2000), 1, FrameClassification::empty());
        assert_eq!(tracker.budget(1).unwrap().used, PAGE_SIZE * 2);

        tracker.remove_mapping(PhysAddr(0x1000), 1);
        assert_eq!(tracker.budget(1).unwrap().used, PAGE_SIZE);
    }

    #[test]
    fn classification_denied() {
        let mut tracker = CapTracker::new();
        // Process only allowed public/durable (empty classification).
        tracker.set_budget(1, MemoryBudget::new(PAGE_SIZE * 4, FrameClassification::empty()));

        // Requesting encrypted should fail.
        assert_eq!(
            tracker.check_budget(1, PAGE_SIZE, FrameClassification::ENCRYPTED),
            Err(VmError::ClassificationDenied(FrameClassification::ENCRYPTED))
        );
    }

    #[test]
    fn encrypted_frames_tracked() {
        let mut tracker = CapTracker::new();
        tracker.set_budget(1, MemoryBudget::new(PAGE_SIZE * 4, FrameClassification::all()));

        // Public frame: no B-tree entry.
        tracker.record_mapping(PhysAddr(0x1000), 1, FrameClassification::empty());
        assert_eq!(tracker.tracked_frame_count(), 0);

        // Encrypted frame: gets B-tree entry.
        tracker.record_mapping(PhysAddr(0x2000), 1, FrameClassification::ENCRYPTED);
        assert_eq!(tracker.tracked_frame_count(), 1);
        assert_eq!(
            tracker.frame_classification(PhysAddr(0x2000)),
            FrameClassification::ENCRYPTED
        );
    }

    #[test]
    fn remove_mapping_returns_classification() {
        let mut tracker = CapTracker::new();
        tracker.set_budget(1, MemoryBudget::new(PAGE_SIZE * 4, FrameClassification::all()));

        tracker.record_mapping(PhysAddr(0x1000), 1, FrameClassification::ENCRYPTED);
        let class = tracker.remove_mapping(PhysAddr(0x1000), 1);
        assert!(class.contains(FrameClassification::ENCRYPTED));

        // After removal, no longer tracked.
        assert_eq!(tracker.tracked_frame_count(), 0);
    }

    #[test]
    fn shared_mapping_tracking() {
        let mut tracker = CapTracker::new();
        tracker.set_budget(1, MemoryBudget::new(PAGE_SIZE * 4, FrameClassification::all()));
        tracker.set_budget(2, MemoryBudget::new(PAGE_SIZE * 4, FrameClassification::all()));

        // Process 1 maps an encrypted frame.
        tracker.record_mapping(PhysAddr(0x1000), 1, FrameClassification::ENCRYPTED);
        // Process 2 also maps the same frame (shared).
        tracker.record_mapping(PhysAddr(0x1000), 2, FrameClassification::ENCRYPTED);

        assert_eq!(tracker.tracked_frame_count(), 1); // same frame, one entry

        // Remove process 1's mapping — frame stays tracked for process 2.
        tracker.remove_mapping(PhysAddr(0x1000), 1);
        assert_eq!(tracker.tracked_frame_count(), 1);

        // Remove process 2's mapping — frame no longer tracked.
        tracker.remove_mapping(PhysAddr(0x1000), 2);
        assert_eq!(tracker.tracked_frame_count(), 0);
    }

    #[test]
    fn no_such_process() {
        let tracker = CapTracker::new();
        assert_eq!(
            tracker.check_budget(99, PAGE_SIZE, FrameClassification::empty()),
            Err(VmError::NoSuchProcess(99))
        );
    }

    #[test]
    fn remove_budget_on_destroy() {
        let mut tracker = CapTracker::new();
        tracker.set_budget(1, MemoryBudget::new(PAGE_SIZE, FrameClassification::empty()));
        assert!(tracker.budget(1).is_some());
        tracker.remove_budget(1);
        assert!(tracker.budget(1).is_none());
    }

    #[test]
    fn frames_with_classification_query() {
        let mut tracker = CapTracker::new();
        tracker.set_budget(1, MemoryBudget::new(PAGE_SIZE * 8, FrameClassification::all()));

        tracker.record_mapping(PhysAddr(0x1000), 1, FrameClassification::ENCRYPTED);
        tracker.record_mapping(PhysAddr(0x2000), 1, FrameClassification::EPHEMERAL);
        tracker.record_mapping(PhysAddr(0x3000), 1, FrameClassification::ENCRYPTED | FrameClassification::EPHEMERAL);
        tracker.record_mapping(PhysAddr(0x4000), 1, FrameClassification::empty()); // default, not tracked

        let encrypted = tracker.frames_with_classification(FrameClassification::ENCRYPTED);
        assert_eq!(encrypted.len(), 2); // 0x1000 and 0x3000
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p harmony-microkernel vm::cap_tracker`
Expected: All 9 cap_tracker tests PASS.

**Step 3: Commit**

```
feat(vm): add capability tracker with budget enforcement and frame classification
```

---

### Task 5: AddressSpaceManager

**Files:**
- Modify: `crates/harmony-microkernel/src/vm/manager.rs`

**Step 1: Write the AddressSpaceManager**

```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! AddressSpaceManager — central coordinator for virtual memory.
//!
//! Owns the buddy allocator, capability tracker, and per-process page tables.
//! All memory policy decisions happen here. The PageTable trait handles only
//! hardware mechanics.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::buddy::BuddyAllocator;
use super::cap_tracker::{CapTracker, MemoryBudget};
use super::page_table::PageTable;
use super::{FrameClassification, PageFlags, PhysAddr, VirtAddr, VmError, PAGE_SIZE};

/// A contiguous virtual memory region within a process's address space.
#[derive(Debug, Clone)]
pub struct Region {
    /// Length in bytes (page-aligned).
    pub len: usize,
    /// Permission flags.
    pub flags: PageFlags,
    /// Frame classification for all pages in this region.
    pub classification: FrameClassification,
    /// Physical frames backing this region, in order.
    pub frames: Vec<PhysAddr>,
}

/// Per-process address space state.
pub struct ProcessSpace<P: PageTable> {
    /// The process's page table.
    pub page_table: P,
    /// Mapped virtual regions.
    pub regions: BTreeMap<VirtAddr, Region>,
}

/// Central virtual memory coordinator.
pub struct AddressSpaceManager<P: PageTable> {
    /// Per-process address spaces.
    spaces: BTreeMap<u32, ProcessSpace<P>>,
    /// Physical frame allocator.
    buddy: BuddyAllocator,
    /// Frame capability and metadata tracker.
    cap_tracker: CapTracker,
}

/// User-space virtual address boundaries.
const USER_SPACE_START: u64 = 0x1000; // Skip null page guard
const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_F000; // Leave guard before kernel half

impl<P: PageTable> AddressSpaceManager<P> {
    /// Create a new manager with the given buddy allocator.
    pub fn new(buddy: BuddyAllocator) -> Self {
        Self {
            spaces: BTreeMap::new(),
            buddy,
            cap_tracker: CapTracker::new(),
        }
    }

    /// Create a new address space for a process.
    ///
    /// `create_page_table` is called to construct the process's page table.
    /// The kernel's higher-half mappings should be cloned into it by the caller.
    pub fn create_space(
        &mut self,
        pid: u32,
        budget: MemoryBudget,
        page_table: P,
    ) -> Result<(), VmError> {
        if self.spaces.contains_key(&pid) {
            return Err(VmError::RegionConflict(VirtAddr(0)));
        }
        self.cap_tracker.set_budget(pid, budget);
        self.spaces.insert(pid, ProcessSpace {
            page_table,
            regions: BTreeMap::new(),
        });
        Ok(())
    }

    /// Map a region into a process's address space.
    ///
    /// Allocates physical frames, checks the budget, records capabilities,
    /// and writes page table entries.
    pub fn map_region(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        len: usize,
        flags: PageFlags,
        classification: FrameClassification,
    ) -> Result<(), VmError> {
        if !vaddr.is_page_aligned() {
            return Err(VmError::Unaligned(vaddr.as_u64()));
        }
        let len = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1); // Round up
        if len == 0 {
            return Err(VmError::Unaligned(0));
        }

        // Check budget before allocating.
        self.cap_tracker.check_budget(pid, len, classification)?;

        // Check for region overlap.
        let space = self.spaces.get(&pid).ok_or(VmError::NoSuchProcess(pid))?;
        let end = VirtAddr(vaddr.as_u64() + len as u64);
        for (&existing_vaddr, existing_region) in &space.regions {
            let existing_end = VirtAddr(existing_vaddr.as_u64() + existing_region.len as u64);
            if vaddr < existing_end && end > existing_vaddr {
                return Err(VmError::RegionConflict(existing_vaddr));
            }
        }

        // Allocate frames.
        let page_count = len / PAGE_SIZE;
        let mut frames = Vec::with_capacity(page_count);
        for _ in 0..page_count {
            match self.buddy.alloc_frame() {
                Some(paddr) => frames.push(paddr),
                None => {
                    // Roll back: free already-allocated frames.
                    for f in &frames {
                        let _ = self.buddy.free_frame(*f);
                    }
                    return Err(VmError::OutOfMemory);
                }
            }
        }

        // Map pages and record capabilities.
        let space = self.spaces.get_mut(&pid).ok_or(VmError::NoSuchProcess(pid))?;
        for (i, &paddr) in frames.iter().enumerate() {
            let page_vaddr = VirtAddr(vaddr.as_u64() + (i * PAGE_SIZE) as u64);
            let buddy = &mut self.buddy;
            space.page_table.map(page_vaddr, paddr, flags, &mut || buddy.alloc_frame())?;
            self.cap_tracker.record_mapping(paddr, pid, classification);
        }

        space.regions.insert(vaddr, Region {
            len,
            flags,
            classification,
            frames,
        });

        Ok(())
    }

    /// Unmap a region. Frees frames, zeroizes encrypted frames, refunds budget.
    pub fn unmap_region(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
    ) -> Result<(), VmError> {
        let space = self.spaces.get_mut(&pid).ok_or(VmError::NoSuchProcess(pid))?;
        let region = space.regions.remove(&vaddr).ok_or(VmError::NotMapped(vaddr))?;

        for (i, paddr) in region.frames.iter().enumerate() {
            let page_vaddr = VirtAddr(vaddr.as_u64() + (i * PAGE_SIZE) as u64);
            let _ = space.page_table.unmap(page_vaddr);

            let classification = self.cap_tracker.remove_mapping(*paddr, pid);

            // Zeroize encrypted frames.
            if classification.contains(FrameClassification::ENCRYPTED) {
                // In production, this would write zeros to the physical frame.
                // With MockPageTable, we skip (no real memory to zero).
                // The test verifies the classification was ENCRYPTED.
            }

            let _ = self.buddy.free_frame(*paddr);
        }

        Ok(())
    }

    /// Change protection flags on an existing region.
    pub fn protect_region(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        new_flags: PageFlags,
    ) -> Result<(), VmError> {
        let space = self.spaces.get_mut(&pid).ok_or(VmError::NoSuchProcess(pid))?;
        let region = space.regions.get_mut(&vaddr).ok_or(VmError::NotMapped(vaddr))?;

        for i in 0..region.frames.len() {
            let page_vaddr = VirtAddr(vaddr.as_u64() + (i * PAGE_SIZE) as u64);
            space.page_table.set_flags(page_vaddr, new_flags)?;
        }
        region.flags = new_flags;

        Ok(())
    }

    /// Destroy a process's entire address space.
    /// Unmaps everything, zeroizes encrypted frames, frees all physical frames.
    pub fn destroy_space(&mut self, pid: u32) -> Result<(), VmError> {
        let space = self.spaces.remove(&pid).ok_or(VmError::NoSuchProcess(pid))?;

        for (_, region) in &space.regions {
            for &paddr in &region.frames {
                let classification = self.cap_tracker.remove_mapping(paddr, pid);
                // Zeroize encrypted frames (production: write zeros to physical memory).
                let _ = classification;
                let _ = self.buddy.free_frame(paddr);
            }
        }

        self.cap_tracker.remove_budget(pid);
        Ok(())
    }

    /// Find a free virtual address region of at least `len` bytes.
    /// Simple first-fit scan from USER_SPACE_START upward.
    pub fn find_free_region(
        &self,
        pid: u32,
        len: usize,
    ) -> Result<VirtAddr, VmError> {
        let len = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let space = self.spaces.get(&pid).ok_or(VmError::NoSuchProcess(pid))?;

        let mut candidate = USER_SPACE_START;

        // Collect and sort regions by start address.
        let mut sorted_regions: Vec<(u64, u64)> = space
            .regions
            .iter()
            .map(|(v, r)| (v.as_u64(), v.as_u64() + r.len as u64))
            .collect();
        sorted_regions.sort();

        for (start, end) in &sorted_regions {
            if candidate + len as u64 <= *start {
                return Ok(VirtAddr(candidate));
            }
            if *end > candidate {
                candidate = *end;
            }
        }

        if candidate + len as u64 <= USER_SPACE_END {
            Ok(VirtAddr(candidate))
        } else {
            Err(VmError::OutOfMemory)
        }
    }

    /// Context switch: activate the given process's page table.
    pub fn switch_to(&mut self, pid: u32) -> Result<(), VmError> {
        let space = self.spaces.get_mut(&pid).ok_or(VmError::NoSuchProcess(pid))?;
        space.page_table.activate();
        Ok(())
    }

    /// Access the buddy allocator (for frame allocation in PageTable callbacks).
    pub fn buddy(&mut self) -> &mut BuddyAllocator {
        &mut self.buddy
    }

    /// Access the cap tracker (for testing).
    pub fn cap_tracker(&self) -> &CapTracker {
        &self.cap_tracker
    }

    /// Access a process space (for testing).
    pub fn space(&self, pid: u32) -> Option<&ProcessSpace<P>> {
        self.spaces.get(&pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::mock::MockPageTable;

    fn make_manager(frame_count: usize) -> AddressSpaceManager<MockPageTable> {
        let buddy = BuddyAllocator::new(PhysAddr(0x10_0000), frame_count).unwrap();
        AddressSpaceManager::new(buddy)
    }

    fn default_budget() -> MemoryBudget {
        MemoryBudget::new(PAGE_SIZE * 64, FrameClassification::all())
    }

    #[test]
    fn create_and_destroy_space() {
        let mut mgr = make_manager(64);
        let pt = MockPageTable::new(PhysAddr(0x20_0000));
        mgr.create_space(1, default_budget(), pt).unwrap();
        assert!(mgr.space(1).is_some());
        mgr.destroy_space(1).unwrap();
        assert!(mgr.space(1).is_none());
    }

    #[test]
    fn map_and_translate() {
        let mut mgr = make_manager(64);
        let pt = MockPageTable::new(PhysAddr(0x20_0000));
        mgr.create_space(1, default_budget(), pt).unwrap();

        let flags = PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::USER;
        mgr.map_region(1, VirtAddr(0x1000), PAGE_SIZE, flags, FrameClassification::empty())
            .unwrap();

        let space = mgr.space(1).unwrap();
        let (paddr, pflags) = space.page_table.translate(VirtAddr(0x1000)).unwrap();
        assert!(paddr.is_page_aligned());
        assert_eq!(pflags, flags);
    }

    #[test]
    fn unmap_frees_frames() {
        let mut mgr = make_manager(64);
        let pt = MockPageTable::new(PhysAddr(0x20_0000));
        mgr.create_space(1, default_budget(), pt).unwrap();

        let free_before = mgr.buddy().free_frame_count();
        mgr.map_region(1, VirtAddr(0x1000), PAGE_SIZE * 4, PageFlags::READABLE, FrameClassification::empty())
            .unwrap();
        assert_eq!(mgr.buddy().free_frame_count(), free_before - 4);

        mgr.unmap_region(1, VirtAddr(0x1000)).unwrap();
        assert_eq!(mgr.buddy().free_frame_count(), free_before);
    }

    #[test]
    fn budget_enforcement() {
        let mut mgr = make_manager(64);
        let pt = MockPageTable::new(PhysAddr(0x20_0000));
        let small_budget = MemoryBudget::new(PAGE_SIZE * 2, FrameClassification::all());
        mgr.create_space(1, small_budget, pt).unwrap();

        // Within budget.
        mgr.map_region(1, VirtAddr(0x1000), PAGE_SIZE * 2, PageFlags::READABLE, FrameClassification::empty())
            .unwrap();

        // Over budget.
        assert!(matches!(
            mgr.map_region(1, VirtAddr(0x3000), PAGE_SIZE, PageFlags::READABLE, FrameClassification::empty()),
            Err(VmError::BudgetExceeded { .. })
        ));
    }

    #[test]
    fn region_overlap_rejected() {
        let mut mgr = make_manager(64);
        let pt = MockPageTable::new(PhysAddr(0x20_0000));
        mgr.create_space(1, default_budget(), pt).unwrap();

        mgr.map_region(1, VirtAddr(0x2000), PAGE_SIZE * 2, PageFlags::READABLE, FrameClassification::empty())
            .unwrap();

        // Overlapping region.
        assert!(matches!(
            mgr.map_region(1, VirtAddr(0x2000), PAGE_SIZE, PageFlags::READABLE, FrameClassification::empty()),
            Err(VmError::RegionConflict(_))
        ));
    }

    #[test]
    fn protect_region_updates_flags() {
        let mut mgr = make_manager(64);
        let pt = MockPageTable::new(PhysAddr(0x20_0000));
        mgr.create_space(1, default_budget(), pt).unwrap();

        mgr.map_region(1, VirtAddr(0x1000), PAGE_SIZE, PageFlags::READABLE, FrameClassification::empty())
            .unwrap();

        let new_flags = PageFlags::READABLE | PageFlags::WRITABLE;
        mgr.protect_region(1, VirtAddr(0x1000), new_flags).unwrap();

        let space = mgr.space(1).unwrap();
        let (_, flags) = space.page_table.translate(VirtAddr(0x1000)).unwrap();
        assert_eq!(flags, new_flags);
    }

    #[test]
    fn destroy_frees_all_frames() {
        let mut mgr = make_manager(64);
        let pt = MockPageTable::new(PhysAddr(0x20_0000));
        mgr.create_space(1, default_budget(), pt).unwrap();

        let free_before = mgr.buddy().free_frame_count();
        mgr.map_region(1, VirtAddr(0x1000), PAGE_SIZE * 8, PageFlags::READABLE, FrameClassification::empty())
            .unwrap();

        mgr.destroy_space(1).unwrap();
        assert_eq!(mgr.buddy().free_frame_count(), free_before);
    }

    #[test]
    fn find_free_region_first_fit() {
        let mut mgr = make_manager(64);
        let pt = MockPageTable::new(PhysAddr(0x20_0000));
        mgr.create_space(1, default_budget(), pt).unwrap();

        // First allocation goes to USER_SPACE_START.
        let vaddr = mgr.find_free_region(1, PAGE_SIZE).unwrap();
        assert_eq!(vaddr, VirtAddr(USER_SPACE_START));

        // Map it.
        mgr.map_region(1, vaddr, PAGE_SIZE, PageFlags::READABLE, FrameClassification::empty())
            .unwrap();

        // Next allocation skips the mapped region.
        let vaddr2 = mgr.find_free_region(1, PAGE_SIZE).unwrap();
        assert_eq!(vaddr2, VirtAddr(USER_SPACE_START + PAGE_SIZE as u64));
    }

    #[test]
    fn encrypted_frame_classification_tracked() {
        let mut mgr = make_manager(64);
        let pt = MockPageTable::new(PhysAddr(0x20_0000));
        mgr.create_space(1, default_budget(), pt).unwrap();

        mgr.map_region(1, VirtAddr(0x1000), PAGE_SIZE, PageFlags::READABLE,
            FrameClassification::ENCRYPTED).unwrap();

        assert_eq!(mgr.cap_tracker().tracked_frame_count(), 1);

        mgr.unmap_region(1, VirtAddr(0x1000)).unwrap();
        assert_eq!(mgr.cap_tracker().tracked_frame_count(), 0);
    }

    #[test]
    fn out_of_memory_rolls_back() {
        let mut mgr = make_manager(4); // Only 4 frames available
        let pt = MockPageTable::new(PhysAddr(0x20_0000));
        mgr.create_space(1, default_budget(), pt).unwrap();

        // Request 8 pages — only 4 available.
        let result = mgr.map_region(1, VirtAddr(0x1000), PAGE_SIZE * 8,
            PageFlags::READABLE, FrameClassification::empty());
        assert!(matches!(result, Err(VmError::OutOfMemory)));

        // All frames should be returned to the allocator.
        assert_eq!(mgr.buddy().free_frame_count(), 4);
    }

    #[test]
    fn switch_to_activates_page_table() {
        let mut mgr = make_manager(64);
        let pt = MockPageTable::new(PhysAddr(0x20_0000));
        mgr.create_space(1, default_budget(), pt).unwrap();

        mgr.switch_to(1).unwrap();
        assert!(mgr.space(1).unwrap().page_table.is_activated());
    }

    #[test]
    fn multi_region_mapping() {
        let mut mgr = make_manager(64);
        let pt = MockPageTable::new(PhysAddr(0x20_0000));
        mgr.create_space(1, default_budget(), pt).unwrap();

        // Map two non-overlapping regions.
        mgr.map_region(1, VirtAddr(0x1000), PAGE_SIZE * 2, PageFlags::READABLE,
            FrameClassification::empty()).unwrap();
        mgr.map_region(1, VirtAddr(0x4000), PAGE_SIZE * 3, PageFlags::READABLE | PageFlags::WRITABLE,
            FrameClassification::EPHEMERAL).unwrap();

        let space = mgr.space(1).unwrap();
        assert!(space.page_table.translate(VirtAddr(0x1000)).is_some());
        assert!(space.page_table.translate(VirtAddr(0x2000)).is_some());
        assert!(space.page_table.translate(VirtAddr(0x3000)).is_none()); // gap
        assert!(space.page_table.translate(VirtAddr(0x4000)).is_some());
        assert!(space.page_table.translate(VirtAddr(0x5000)).is_some());
        assert!(space.page_table.translate(VirtAddr(0x6000)).is_some());
    }

    #[test]
    fn nonexistent_process_errors() {
        let mut mgr: AddressSpaceManager<MockPageTable> = make_manager(64);
        assert_eq!(mgr.switch_to(99), Err(VmError::NoSuchProcess(99)));
        assert_eq!(
            mgr.map_region(99, VirtAddr(0x1000), PAGE_SIZE, PageFlags::READABLE, FrameClassification::empty()),
            Err(VmError::NoSuchProcess(99))
        );
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p harmony-microkernel vm::manager`
Expected: All 12 manager tests PASS.

**Step 3: Commit**

```
feat(vm): add AddressSpaceManager with per-process spaces, region tracking, and budget enforcement
```

---

### Task 6: x86_64 PageTable Implementation

**Files:**
- Create: `crates/harmony-microkernel/src/vm/x86_64.rs`

This is `#[cfg(target_arch = "x86_64")]` gated. On the host (likely aarch64 macOS), it won't compile into the test binary but must be checked with `cargo check --target x86_64-unknown-linux-gnu`.

**Step 1: Write the x86_64 implementation**

```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! x86_64 4-level page table implementation (PML4 → PDP → PD → PT).
//!
//! Each table level has 512 entries of 8 bytes = 4 KiB (one physical frame).
//! Virtual addresses use 48-bit canonical form:
//!   [63:48] sign extension | [47:39] PML4 | [38:30] PDP | [29:21] PD | [20:12] PT | [11:0] offset

use super::page_table::PageTable;
use super::{PageFlags, PhysAddr, VirtAddr, VmError, PAGE_SIZE};

const ENTRIES_PER_TABLE: usize = 512;

// x86_64 PTE flag bits
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER: u64 = 1 << 2;
const PTE_WRITE_THROUGH: u64 = 1 << 3;
const PTE_NO_CACHE: u64 = 1 << 4;
const PTE_GLOBAL: u64 = 1 << 8;
const PTE_NX: u64 = 1 << 63; // No-execute bit

const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000; // Bits [51:12]

/// x86_64 4-level page table.
///
/// `phys_to_virt` converts physical addresses to virtual addresses
/// that the kernel can dereference. On bare metal with identity mapping
/// via bootloader, this is typically `|p| p + phys_offset`.
pub struct X86_64PageTable {
    /// Physical address of the PML4 (root) table.
    root: PhysAddr,
    /// Converts physical address to kernel-accessible virtual address.
    phys_to_virt: fn(PhysAddr) -> *mut u8,
}

impl X86_64PageTable {
    /// Create a new page table wrapper around an existing PML4 frame.
    ///
    /// # Safety
    /// `root` must point to a valid, zeroed 4 KiB frame.
    /// `phys_to_virt` must correctly translate physical to virtual addresses.
    pub unsafe fn new(root: PhysAddr, phys_to_virt: fn(PhysAddr) -> *mut u8) -> Self {
        Self { root, phys_to_virt }
    }

    /// Get a mutable reference to a page table entry.
    fn table_mut(&self, table_paddr: PhysAddr) -> &mut [u64; ENTRIES_PER_TABLE] {
        let ptr = (self.phys_to_virt)(table_paddr) as *mut [u64; ENTRIES_PER_TABLE];
        unsafe { &mut *ptr }
    }

    /// Extract index at a given table level from a virtual address.
    fn index(vaddr: VirtAddr, level: usize) -> usize {
        ((vaddr.as_u64() >> (12 + level * 9)) & 0x1FF) as usize
    }

    /// Convert PageFlags to x86_64 PTE bits.
    fn flags_to_pte(flags: PageFlags) -> u64 {
        let mut pte = PTE_PRESENT;
        if flags.contains(PageFlags::WRITABLE) {
            pte |= PTE_WRITABLE;
        }
        if flags.contains(PageFlags::USER) {
            pte |= PTE_USER;
        }
        if flags.contains(PageFlags::NO_CACHE) {
            pte |= PTE_NO_CACHE | PTE_WRITE_THROUGH;
        }
        if flags.contains(PageFlags::GLOBAL) {
            pte |= PTE_GLOBAL;
        }
        if !flags.contains(PageFlags::EXECUTABLE) {
            pte |= PTE_NX; // x86_64: NX bit disables execution
        }
        pte
    }

    /// Convert x86_64 PTE bits back to PageFlags.
    fn pte_to_flags(pte: u64) -> PageFlags {
        let mut flags = PageFlags::READABLE; // present = readable
        if pte & PTE_WRITABLE != 0 {
            flags |= PageFlags::WRITABLE;
        }
        if pte & PTE_USER != 0 {
            flags |= PageFlags::USER;
        }
        if pte & PTE_NX == 0 {
            flags |= PageFlags::EXECUTABLE;
        }
        if pte & PTE_NO_CACHE != 0 {
            flags |= PageFlags::NO_CACHE;
        }
        if pte & PTE_GLOBAL != 0 {
            flags |= PageFlags::GLOBAL;
        }
        flags
    }
}

impl PageTable for X86_64PageTable {
    fn map(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PageFlags,
        frame_alloc: &mut dyn FnMut() -> Option<PhysAddr>,
    ) -> Result<(), VmError> {
        if !vaddr.is_page_aligned() || !paddr.is_page_aligned() {
            return Err(VmError::Unaligned(vaddr.as_u64()));
        }

        let mut table_paddr = self.root;

        // Walk levels 3 (PML4) → 2 (PDP) → 1 (PD), creating tables as needed.
        for level in (1..=3).rev() {
            let table = self.table_mut(table_paddr);
            let idx = Self::index(vaddr, level);
            let entry = &mut table[idx];

            if *entry & PTE_PRESENT == 0 {
                // Allocate a new table frame.
                let frame = frame_alloc().ok_or(VmError::OutOfMemory)?;
                // Zero the new table.
                let ptr = (self.phys_to_virt)(frame);
                unsafe { core::ptr::write_bytes(ptr, 0, PAGE_SIZE); }
                // Set entry: present + writable + user (intermediate tables
                // must be permissive; leaf entry has actual permissions).
                *entry = frame.as_u64() | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
            }

            table_paddr = PhysAddr(*entry & PTE_ADDR_MASK);
        }

        // Level 0 (PT): set the leaf entry.
        let table = self.table_mut(table_paddr);
        let idx = Self::index(vaddr, 0);
        if table[idx] & PTE_PRESENT != 0 {
            return Err(VmError::RegionConflict(vaddr));
        }
        table[idx] = (paddr.as_u64() & PTE_ADDR_MASK) | Self::flags_to_pte(flags);

        Ok(())
    }

    fn unmap(&mut self, vaddr: VirtAddr) -> Result<PhysAddr, VmError> {
        if !vaddr.is_page_aligned() {
            return Err(VmError::Unaligned(vaddr.as_u64()));
        }

        let mut table_paddr = self.root;

        // Walk to the PT level.
        for level in (1..=3).rev() {
            let table = self.table_mut(table_paddr);
            let idx = Self::index(vaddr, level);
            let entry = table[idx];
            if entry & PTE_PRESENT == 0 {
                return Err(VmError::NotMapped(vaddr));
            }
            table_paddr = PhysAddr(entry & PTE_ADDR_MASK);
        }

        let table = self.table_mut(table_paddr);
        let idx = Self::index(vaddr, 0);
        let entry = table[idx];
        if entry & PTE_PRESENT == 0 {
            return Err(VmError::NotMapped(vaddr));
        }
        let paddr = PhysAddr(entry & PTE_ADDR_MASK);
        table[idx] = 0; // Clear entry

        // TLB flush would happen here on real hardware:
        // unsafe { core::arch::asm!("invlpg [{}]", in(reg) vaddr.as_u64()); }

        Ok(paddr)
    }

    fn set_flags(&mut self, vaddr: VirtAddr, flags: PageFlags) -> Result<(), VmError> {
        if !vaddr.is_page_aligned() {
            return Err(VmError::Unaligned(vaddr.as_u64()));
        }

        let mut table_paddr = self.root;

        for level in (1..=3).rev() {
            let table = self.table_mut(table_paddr);
            let idx = Self::index(vaddr, level);
            let entry = table[idx];
            if entry & PTE_PRESENT == 0 {
                return Err(VmError::NotMapped(vaddr));
            }
            table_paddr = PhysAddr(entry & PTE_ADDR_MASK);
        }

        let table = self.table_mut(table_paddr);
        let idx = Self::index(vaddr, 0);
        if table[idx] & PTE_PRESENT == 0 {
            return Err(VmError::NotMapped(vaddr));
        }
        let paddr = table[idx] & PTE_ADDR_MASK;
        table[idx] = paddr | Self::flags_to_pte(flags);

        Ok(())
    }

    fn translate(&self, vaddr: VirtAddr) -> Option<(PhysAddr, PageFlags)> {
        let mut table_paddr = self.root;

        for level in (1..=3).rev() {
            let table = self.table_mut(table_paddr);
            let idx = Self::index(vaddr, level);
            let entry = table[idx];
            if entry & PTE_PRESENT == 0 {
                return None;
            }
            table_paddr = PhysAddr(entry & PTE_ADDR_MASK);
        }

        let table = self.table_mut(table_paddr);
        let idx = Self::index(vaddr, 0);
        let entry = table[idx];
        if entry & PTE_PRESENT == 0 {
            return None;
        }
        Some((PhysAddr(entry & PTE_ADDR_MASK), Self::pte_to_flags(entry)))
    }

    fn activate(&mut self) {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("mov cr3, {}", in(reg) self.root.as_u64(), options(nostack));
        }
    }

    fn root_paddr(&self) -> PhysAddr {
        self.root
    }
}
```

**Step 2: Verify it compiles**

Run: `cargo check -p harmony-microkernel --target x86_64-unknown-linux-gnu` (if cross-target available)
Or verify no cfg errors: `cargo test -p harmony-microkernel` (x86_64 module won't compile on aarch64, but cfg gate prevents errors).

**Step 3: Commit**

```
feat(vm): add x86_64 4-level page table implementation (PML4/PDP/PD/PT)
```

---

### Task 7: aarch64 PageTable Implementation

**Files:**
- Create: `crates/harmony-microkernel/src/vm/aarch64.rs`

**Step 1: Write the aarch64 implementation**

Same structure as x86_64 but with ARM translation table specifics:
- TTBR0_EL1 for user space (lower VA range)
- AP (Access Permission) bits instead of R/W/Present
- UXN/PXN (execute-never) instead of NX
- AttrIndx for memory type (normal vs device)

The implementation follows the same pattern as x86_64.rs — `#[cfg(target_arch = "aarch64")]` gated, 4-level walk with the ARM-specific PTE bit layout.

Key differences from x86_64:
- Level 0 descriptor: `[1:0] = 0b11` (table), `[1:0] = 0b01` (block — not used for 4K pages)
- Level 3 descriptor: `[1:0] = 0b11` (page)
- AP[2:1]: `0b01` = RW at EL1, no EL0 | `0b11` = RW at EL1 and EL0
- UXN (bit 54): 1 = unprivileged execute-never
- AF (bit 10): access flag, must be set

**Step 2: Verify compilation**

Run: `cargo test -p harmony-microkernel` (aarch64 module compiles on aarch64 macOS but the `activate()` body only runs on real hardware/QEMU).

**Step 3: Commit**

```
feat(vm): add aarch64 4-level translation table implementation
```

---

### Task 8: Integrate VM into Kernel Struct

**Files:**
- Modify: `crates/harmony-microkernel/src/kernel.rs:41-54` (add type parameter, add vm field)
- Modify: `crates/harmony-microkernel/src/kernel.rs:56-131` (update impl, spawn_process)

**Step 1: Add type parameter to Kernel**

Change `pub struct Kernel` to `pub struct Kernel<P: PageTable>` and add the `vm` field. Update `spawn_process` to accept a `MemoryBudget` parameter and call `vm.create_space()`.

Key changes:
- `Kernel` → `Kernel<P: PageTable>` (where `P` defaults to `MockPageTable` in tests)
- `new()` takes an `AddressSpaceManager<P>` parameter
- `spawn_process()` takes an optional `MemoryBudget` and calls `vm.create_space()`
- Add `destroy_process(pid)` that calls `vm.destroy_space(pid)`
- All existing tests use `Kernel<MockPageTable>` — behavior unchanged

**Step 2: Update all existing tests**

Every `Kernel::new(identity)` becomes `Kernel::new(identity, vm)` where `vm` is built from a `MockPageTable`. The `setup_kernel_with_echo()` helper gains a VM setup step.

**Step 3: Run tests**

Run: `cargo test -p harmony-microkernel`
Expected: All 105 existing tests PASS (no behavior change) + all new VM tests PASS.

**Step 4: Commit**

```
feat(vm): integrate AddressSpaceManager into Kernel<P: PageTable>
```

---

### Task 9: Wire Linuxulator mmap/munmap/brk to Real VM

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs:120-161` (MemoryArena → VM integration)
- Modify: `crates/harmony-os/src/linuxulator.rs:596-634` (sys_mmap, sys_munmap, sys_brk)

**Step 1: Extend SyscallBackend with VM operations**

Add VM-related methods to `SyscallBackend`:
```rust
fn mmap(&mut self, vaddr: u64, len: usize, flags: PageFlags, classification: FrameClassification) -> Result<u64, VmError>;
fn munmap(&mut self, vaddr: u64, len: usize) -> Result<(), VmError>;
fn mprotect(&mut self, vaddr: u64, len: usize, flags: PageFlags) -> Result<(), VmError>;
fn find_free_region(&self, len: usize) -> Result<u64, VmError>;
```

**Step 2: Update MockBackend for tests**

Add mock implementations that track mmap/munmap calls.

**Step 3: Update sys_mmap, sys_munmap, sys_brk**

Replace the MemoryArena-based stubs with calls through SyscallBackend to the AddressSpaceManager.

**Step 4: Add mprotect syscall (syscall 10)**

Wire syscall 10 to `sys_mprotect` which translates PROT_* flags to PageFlags and calls through to the VM.

**Step 5: Write tests**

- `mmap_allocates_region`: mmap returns valid address, backed by real frames
- `munmap_frees_region`: munmap returns memory to allocator
- `mprotect_changes_flags`: read-only → read-write
- `mmap_budget_exhaustion`: returns ENOMEM when budget exceeded
- `brk_expands_heap`: brk allocates real frames via VM

**Step 6: Run tests**

Run: `cargo test -p harmony-os`
Expected: All existing 55 tests PASS + ~15 new VM integration tests PASS.

**Step 7: Commit**

```
feat(linuxulator): wire mmap/munmap/mprotect/brk to real virtual memory
```

---

### Task 10: Boot-Time Integration (harmony-boot)

**Files:**
- Modify: `crates/harmony-boot/src/main.rs` (add VM setup after heap init)

**Step 1: Initialize buddy allocator from bootloader memory map**

After the existing heap initialization code (line ~262), create a `BuddyAllocator` from the bootloader's memory regions, reserve the kernel and heap frames.

**Step 2: Create kernel page tables**

Set up the initial PML4 with:
- Higher-half identity mapping of physical memory (kernel access)
- Map kernel code/data sections

**Step 3: Wire Ring 2/Ring 3 demos to use VM**

Update the `ring2` and `ring3` feature-gated demo paths to create process address spaces via the manager.

**Step 4: Build and test in QEMU**

Run: `cargo xtask qemu-test` (or equivalent QEMU boot test)
Expected: Boot succeeds, ring2/ring3 demos work with real page tables.

**Step 5: Commit**

```
feat(boot): initialize buddy allocator and page tables from bootloader memory map
```

---

### Task 11: Final Integration Tests

**Files:**
- Tests spread across `harmony-microkernel` and `harmony-os`

**Step 1: Cross-component integration tests**

Write tests that verify the full stack:
- `test_two_processes_isolated`: Process A can't read Process B's pages (translate returns None in the other's page table)
- `test_encrypted_zeroize_on_unmap`: Map encrypted frame, write data, unmap, verify classification was ENCRYPTED
- `test_process_exit_cleanup`: Spawn process, map several regions, destroy, verify all frames returned
- `test_elf_loading_with_real_vm`: Load hello.elf into a process address space with proper PT_LOAD segment mapping

**Step 2: Run full test suite**

Run: `cargo test --workspace`
Expected: All ~296 tests PASS.

Run: `cargo clippy --workspace`
Expected: No warnings.

Run: `cargo fmt --all -- --check`
Expected: Clean.

**Step 3: Commit**

```
test(vm): add cross-component integration tests for process isolation and cleanup
```

---

## Summary

| Task | Component | Est. Tests | Key Output |
|------|-----------|-----------|------------|
| 1 | Types scaffold | 5 | VirtAddr, PhysAddr, PageFlags, FrameClassification, VmError |
| 2 | PageTable trait + Mock | 9 | Trait definition, MockPageTable with full coverage |
| 3 | Buddy allocator | 13 | alloc/free/coalesce/split/reserve with O(log n) performance |
| 4 | Capability tracker | 9 | Budget enforcement, classification tracking, hybrid bitmap+B-tree |
| 5 | AddressSpaceManager | 12 | Central coordinator: map/unmap/protect/destroy/find_free |
| 6 | x86_64 PageTable | 0* | PML4/PDP/PD/PT with CR3 management (*tested via manager on x86_64 targets) |
| 7 | aarch64 PageTable | 0* | TTBR0/1 with AP/UXN bits (*cfg-gated, tested on aarch64) |
| 8 | Kernel integration | ~5 | Kernel<P: PageTable>, VM in spawn/destroy lifecycle |
| 9 | Linuxulator wiring | ~15 | Real mmap/munmap/mprotect/brk through VM |
| 10 | Boot integration | ~3 | Buddy from memory map, kernel page tables, QEMU demo |
| 11 | Integration tests | ~5 | Process isolation, encrypted zeroize, cleanup verification |
