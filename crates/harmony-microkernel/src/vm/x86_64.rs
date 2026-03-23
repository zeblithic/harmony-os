// SPDX-License-Identifier: GPL-2.0-or-later
//! x86_64 4-level page table implementation (PML4 / PDP / PD / PT).
//!
//! This module provides `X86_64PageTable`, a concrete [`PageTable`] implementation
//! for x86_64 long-mode paging. It manipulates a standard 4-level hierarchy:
//!
//! | Level | Name | VA bits  | Purpose                     |
//! |-------|------|----------|-----------------------------|
//! | 3     | PML4 | [47:39]  | Page Map Level 4            |
//! | 2     | PDP  | [38:30]  | Page Directory Pointer      |
//! | 1     | PD   | [29:21]  | Page Directory              |
//! | 0     | PT   | [20:12]  | Page Table (leaf entries)    |
//!
//! Each table contains 512 entries of 8 bytes, fitting exactly in one 4 KiB frame.
//!
//! # Design
//!
//! The struct stores a `phys_to_virt` function pointer so that the caller can
//! provide the mapping from physical addresses to kernel-accessible virtual
//! addresses. In harmony-boot this is the bootloader's physical-memory offset;
//! in tests it can be an identity map over a heap-allocated arena.
//!
//! Intermediate (non-leaf) page table entries are created with permissive flags
//! (`PRESENT | WRITABLE | USER`). Restriction happens at the leaf level.

use super::page_table::PageTable;
use super::{PageFlags, PhysAddr, VirtAddr, VmError};

// ── x86_64 PTE flag bits ────────────────────────────────────────────

/// Page is present in physical memory.
const PTE_PRESENT: u64 = 1 << 0;
/// Page is writable (otherwise read-only).
const PTE_WRITABLE: u64 = 1 << 1;
/// Page is accessible from ring 3 (user mode).
const PTE_USER: u64 = 1 << 2;
/// Write-through caching.
const PTE_WRITE_THROUGH: u64 = 1 << 3;
/// Disable caching entirely.
const PTE_NO_CACHE: u64 = 1 << 4;
/// Global page — not flushed on CR3 switch (requires CR4.PGE).
const PTE_GLOBAL: u64 = 1 << 8;
/// No-Execute bit — requires IA32_EFER.NXE.
const PTE_NX: u64 = 1 << 63;
/// Mask for extracting the physical address from a PTE (bits [51:12]).
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Permissive flags for intermediate (non-leaf) page table entries.
/// Actual restrictions are applied at the leaf level; intermediate entries
/// must be the union of all possible permissions to avoid masking leaf flags.
const INTERMEDIATE_FLAGS: u64 = PTE_PRESENT | PTE_WRITABLE | PTE_USER;

// ── X86_64PageTable ─────────────────────────────────────────────────

/// Concrete x86_64 4-level page table.
///
/// Walks a PML4 → PDP → PD → PT hierarchy stored in physical frames.
/// The `phys_to_virt` function is used to obtain writable pointers to page
/// table frames during manipulation.
pub struct X86_64PageTable {
    /// Physical address of the PML4 (root) table — loaded into CR3.
    root: PhysAddr,
    /// Converts a physical address to a kernel-accessible virtual pointer.
    phys_to_virt: fn(PhysAddr) -> *mut u8,
}

impl X86_64PageTable {
    /// Create a new page table wrapper.
    ///
    /// # Safety
    ///
    /// - `root` must point to a valid, zeroed, 4 KiB-aligned frame.
    /// - `phys_to_virt` must correctly map physical addresses to writable
    ///   virtual addresses for the lifetime of this struct.
    pub unsafe fn new(root: PhysAddr, phys_to_virt: fn(PhysAddr) -> *mut u8) -> Self {
        Self { root, phys_to_virt }
    }

    /// Obtain a mutable reference to a 512-entry page table at `table_paddr`.
    ///
    /// The physical address is translated through `phys_to_virt` and cast
    /// to a `[u64; 512]` array. The caller must ensure the address points to
    /// a valid page table frame.
    ///
    /// # Why `&self` returns `&mut`
    ///
    /// Page table entries live in physical memory accessed through a
    /// translation function — they are *not* part of `self`. This is the
    /// standard pattern in OS kernels: the page table struct is a handle,
    /// and the actual table data lives in separately-managed physical frames.
    #[allow(clippy::mut_from_ref)]
    fn table_mut(&self, table_paddr: PhysAddr) -> &mut [u64; 512] {
        let ptr = (self.phys_to_virt)(table_paddr);
        unsafe { &mut *(ptr as *mut [u64; 512]) }
    }

    /// Extract the 9-bit page table index from a virtual address at the given level.
    ///
    /// - Level 3 (PML4): bits [47:39]
    /// - Level 2 (PDP):  bits [38:30]
    /// - Level 1 (PD):   bits [29:21]
    /// - Level 0 (PT):   bits [20:12]
    fn index(vaddr: VirtAddr, level: usize) -> usize {
        ((vaddr.as_u64() >> (12 + level * 9)) & 0x1FF) as usize
    }

    /// Translate [`PageFlags`] to x86_64 PTE bits.
    ///
    /// `PTE_PRESENT` is set unconditionally: on x86_64 all mapped pages are
    /// inherently readable (there is no read-disable bit). The only way to
    /// remove a page is [`PageTable::unmap`].
    ///
    /// Note the NX inversion: `EXECUTABLE` means *clear* the NX bit.
    /// If the flag is absent, NX is set.
    fn flags_to_pte(flags: PageFlags) -> u64 {
        let mut pte: u64 = PTE_PRESENT;
        if flags.contains(PageFlags::WRITABLE) {
            pte |= PTE_WRITABLE;
        }
        if flags.contains(PageFlags::USER) {
            pte |= PTE_USER;
        }
        // NX is the inverse of EXECUTABLE: set NX when NOT executable.
        if !flags.contains(PageFlags::EXECUTABLE) {
            pte |= PTE_NX;
        }
        if flags.contains(PageFlags::NO_CACHE) {
            pte |= PTE_NO_CACHE | PTE_WRITE_THROUGH;
        }
        if flags.contains(PageFlags::GLOBAL) {
            pte |= PTE_GLOBAL;
        }

        pte
    }

    /// Translate x86_64 PTE bits back to [`PageFlags`].
    fn pte_to_flags(pte: u64) -> PageFlags {
        let mut flags = PageFlags::empty();

        if pte & PTE_PRESENT != 0 {
            flags |= PageFlags::READABLE;
        }
        if pte & PTE_WRITABLE != 0 {
            flags |= PageFlags::WRITABLE;
        }
        if pte & PTE_USER != 0 {
            flags |= PageFlags::USER;
        }
        // Executable when NX is NOT set (and page is present).
        if pte & PTE_NX == 0 && pte & PTE_PRESENT != 0 {
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

    /// Returns `true` if all 512 entries in the table are not present.
    fn is_table_empty(table: &[u64; 512]) -> bool {
        table.iter().all(|&e| e & PTE_PRESENT == 0)
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
        if !vaddr.is_page_aligned() {
            return Err(VmError::Unaligned(vaddr.as_u64()));
        }
        if !paddr.is_page_aligned() {
            return Err(VmError::Unaligned(paddr.as_u64()));
        }

        // Walk levels 3 (PML4) → 1 (PD), creating intermediate tables as needed.
        let mut table_paddr = self.root;

        for level in (1..=3).rev() {
            let table = self.table_mut(table_paddr);
            let idx = Self::index(vaddr, level);
            let entry = table[idx];

            if entry & PTE_PRESENT != 0 {
                // Intermediate table exists — follow it.
                table_paddr = PhysAddr(entry & PTE_ADDR_MASK);
            } else {
                // Allocate a new frame for the intermediate table.
                let new_frame = frame_alloc().ok_or(VmError::OutOfMemory)?;

                // Zero the new frame so all 512 entries start as not-present.
                let new_ptr = (self.phys_to_virt)(new_frame);
                unsafe {
                    core::ptr::write_bytes(new_ptr, 0, 4096);
                }

                // Install the intermediate entry with permissive flags.
                let table = self.table_mut(table_paddr);
                table[idx] = new_frame.as_u64() | INTERMEDIATE_FLAGS;

                table_paddr = new_frame;
            }
        }

        // Level 0 (PT): install the leaf entry.
        let pt = self.table_mut(table_paddr);
        let idx = Self::index(vaddr, 0);

        if pt[idx] & PTE_PRESENT != 0 {
            return Err(VmError::RegionConflict(vaddr));
        }

        pt[idx] = (paddr.as_u64() & PTE_ADDR_MASK) | Self::flags_to_pte(flags);
        Ok(())
    }

    fn unmap(
        &mut self,
        vaddr: VirtAddr,
        frame_dealloc: &mut dyn FnMut(PhysAddr),
    ) -> Result<PhysAddr, VmError> {
        if !vaddr.is_page_aligned() {
            return Err(VmError::Unaligned(vaddr.as_u64()));
        }

        // Walk levels 3 → 1, recording (parent_paddr, parent_idx) for pruning.
        let mut table_paddr = self.root;
        let mut walk: [(PhysAddr, usize); 3] = [(PhysAddr(0), 0); 3];

        for (i, level) in (1..=3).rev().enumerate() {
            let table = self.table_mut(table_paddr);
            let idx = Self::index(vaddr, level);
            let entry = table[idx];

            if entry & PTE_PRESENT == 0 {
                return Err(VmError::NotMapped(vaddr));
            }
            walk[i] = (table_paddr, idx);
            table_paddr = PhysAddr(entry & PTE_ADDR_MASK);
        }

        // Level 0: clear the leaf entry.
        let leaf_table_paddr = table_paddr;
        let pt = self.table_mut(leaf_table_paddr);
        let idx = Self::index(vaddr, 0);
        let entry = pt[idx];

        if entry & PTE_PRESENT == 0 {
            return Err(VmError::NotMapped(vaddr));
        }

        let old_paddr = PhysAddr(entry & PTE_ADDR_MASK);
        pt[idx] = 0;

        // Bottom-up prune: walk was filled top-down as walk[0]=(root, idx→PDP),
        // walk[1]=(PDP, idx→PD), walk[2]=(PD, idx→PT). Reverse so we process
        // PT→PD→PDP direction. Root (PML4) is never freed.
        let mut child_paddr = leaf_table_paddr;
        for &(parent_paddr, parent_idx) in walk.iter().rev() {
            if parent_paddr.as_u64() == 0 {
                break;
            }
            let child_table = self.table_mut(child_paddr);
            if Self::is_table_empty(child_table) {
                // Invalidate parent entry before freeing the child frame.
                let parent_table = self.table_mut(parent_paddr);
                parent_table[parent_idx] = 0;
                frame_dealloc(child_paddr);
            } else {
                break; // non-empty table; ancestors are also non-empty
            }
            child_paddr = parent_paddr;
        }

        Ok(old_paddr)
    }

    fn set_flags(&mut self, vaddr: VirtAddr, flags: PageFlags) -> Result<(), VmError> {
        if !vaddr.is_page_aligned() {
            return Err(VmError::Unaligned(vaddr.as_u64()));
        }

        // Walk levels 3 → 1.
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

        // Level 0: update flags, preserving the physical address.
        let pt = self.table_mut(table_paddr);
        let idx = Self::index(vaddr, 0);
        let entry = pt[idx];

        if entry & PTE_PRESENT == 0 {
            return Err(VmError::NotMapped(vaddr));
        }

        let phys = entry & PTE_ADDR_MASK;
        pt[idx] = phys | Self::flags_to_pte(flags);

        Ok(())
    }

    fn translate(&self, vaddr: VirtAddr) -> Option<(PhysAddr, PageFlags)> {
        // Walk all 4 levels, returning None if any intermediate entry is absent.
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

        // Level 0: read the leaf entry.
        let pt = self.table_mut(table_paddr);
        let idx = Self::index(vaddr, 0);
        let entry = pt[idx];

        if entry & PTE_PRESENT == 0 {
            return None;
        }

        let paddr = PhysAddr(entry & PTE_ADDR_MASK);
        let flags = Self::pte_to_flags(entry);
        Some((paddr, flags))
    }

    fn activate(&mut self) {
        // Load the PML4 physical address into CR3. Writing CR3 on x86_64
        // automatically flushes all non-global TLB entries.
        //
        // Guarded by target_os = "none" so this privileged instruction
        // only compiles for bare-metal targets, not hosted test builds.
        #[cfg(target_os = "none")]
        unsafe {
            core::arch::asm!(
                "mov cr3, {}",
                in(reg) self.root.as_u64(),
                options(nostack, preserves_flags),
            );
        }
    }

    fn root_paddr(&self) -> PhysAddr {
        self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    // ── Arena helpers ────────────────────────────────────────────────

    /// Size of the test arena: enough frames for root + intermediates + extras.
    const ARENA_TABLES: usize = 8;
    const ARENA_SIZE: usize = ARENA_TABLES * 4096;

    /// Create a test arena and return (arena_vec, base_address).
    fn test_arena() -> (Vec<u8>, PhysAddr) {
        let mut arena = vec![0u8; ARENA_SIZE + 4096];
        let base = arena.as_mut_ptr() as u64;
        let aligned_base = (base + 4095) & !4095;
        let arena = arena.into_boxed_slice();
        let arena = Vec::from(arena);
        let aligned_base = PhysAddr(aligned_base);
        (arena, aligned_base)
    }

    /// Identity phys_to_virt — works because test arena addresses are real heap addresses.
    fn identity_phys_to_virt(paddr: PhysAddr) -> *mut u8 {
        paddr.as_u64() as *mut u8
    }

    /// Simple allocator that hands out consecutive 4 KiB frames.
    struct TestAllocator {
        next: u64,
        limit: u64,
    }

    impl TestAllocator {
        fn new(base: u64, count: usize) -> Self {
            Self {
                next: base,
                limit: base + (count as u64) * 4096,
            }
        }

        fn alloc(&mut self) -> Option<PhysAddr> {
            if self.next >= self.limit {
                return None;
            }
            let addr = PhysAddr(self.next);
            self.next += 4096;
            Some(addr)
        }
    }

    /// Allocator that tracks allocations and accepts frees.
    struct TrackingAllocator {
        next: u64,
        limit: u64,
        alloc_count: usize,
        freed: Vec<PhysAddr>,
    }

    impl TrackingAllocator {
        fn new(base: u64, count: usize) -> Self {
            Self {
                next: base,
                limit: base + (count as u64) * 4096,
                alloc_count: 0,
                freed: Vec::new(),
            }
        }

        fn alloc(&mut self) -> Option<PhysAddr> {
            if self.next >= self.limit {
                return None;
            }
            let addr = PhysAddr(self.next);
            self.next += 4096;
            unsafe { core::ptr::write_bytes(addr.as_u64() as *mut u8, 0, 4096) };
            self.alloc_count += 1;
            Some(addr)
        }

        fn dealloc(&mut self, frame: PhysAddr) {
            self.freed.push(frame);
        }
    }

    #[test]
    fn flags_to_pte_always_sets_present() {
        // On x86_64, all mapped pages are inherently readable — PTE_PRESENT
        // must be set regardless of which PageFlags are requested.
        let empty = X86_64PageTable::flags_to_pte(PageFlags::empty());
        assert_ne!(empty & PTE_PRESENT, 0, "empty flags must still set PRESENT");

        let write_only = X86_64PageTable::flags_to_pte(PageFlags::WRITABLE);
        assert_ne!(
            write_only & PTE_PRESENT,
            0,
            "WRITABLE without READABLE must still set PRESENT"
        );

        let exec_only = X86_64PageTable::flags_to_pte(PageFlags::EXECUTABLE);
        assert_ne!(
            exec_only & PTE_PRESENT,
            0,
            "EXECUTABLE without READABLE must still set PRESENT"
        );
    }

    #[test]
    fn pte_roundtrip_preserves_readable() {
        // READABLE should always appear in the roundtrip since PRESENT is
        // always set and pte_to_flags maps PRESENT → READABLE.
        let flags = PageFlags::WRITABLE | PageFlags::EXECUTABLE;
        let pte = X86_64PageTable::flags_to_pte(flags);
        let back = X86_64PageTable::pte_to_flags(pte);
        assert!(
            back.contains(PageFlags::READABLE),
            "roundtrip must include READABLE (x86_64 pages are always readable)"
        );
        assert!(back.contains(PageFlags::WRITABLE));
        assert!(back.contains(PageFlags::EXECUTABLE));
    }

    // ── Integration tests using heap-backed page table arena ────────

    #[test]
    fn map_and_translate() {
        let (_arena, arena_base) = test_arena();
        let aligned = (arena_base.as_u64() + 4095) & !4095;
        let root = PhysAddr(aligned);
        unsafe { core::ptr::write_bytes(root.as_u64() as *mut u8, 0, 4096) };
        let mut allocator = TestAllocator::new(aligned + 4096, ARENA_TABLES - 1);
        let mut pt = unsafe { X86_64PageTable::new(root, identity_phys_to_virt) };

        let vaddr = VirtAddr(0x1000);
        let paddr = PhysAddr(0xDEAD_B000);
        let flags = PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::USER;

        pt.map(vaddr, paddr, flags, &mut || allocator.alloc())
            .unwrap();

        let translated = pt.translate(vaddr);
        assert!(translated.is_some(), "translate should find the mapping");
        let (got_paddr, got_flags) = translated.unwrap();
        assert_eq!(got_paddr, paddr, "physical address must match");
        assert_eq!(got_flags, flags, "flags must match");
    }

    #[test]
    fn map_then_unmap() {
        let (_arena, arena_base) = test_arena();
        let aligned = (arena_base.as_u64() + 4095) & !4095;
        let root = PhysAddr(aligned);
        unsafe { core::ptr::write_bytes(root.as_u64() as *mut u8, 0, 4096) };
        let mut allocator = TestAllocator::new(aligned + 4096, ARENA_TABLES - 1);
        let mut pt = unsafe { X86_64PageTable::new(root, identity_phys_to_virt) };

        let vaddr = VirtAddr(0x2000);
        let paddr = PhysAddr(0xBEEF_0000);
        let flags = PageFlags::READABLE | PageFlags::EXECUTABLE;

        pt.map(vaddr, paddr, flags, &mut || allocator.alloc())
            .unwrap();
        assert!(pt.translate(vaddr).is_some());

        let unmapped = pt.unmap(vaddr, &mut |_| {}).unwrap();
        assert_eq!(unmapped, paddr, "unmap should return the original paddr");
        assert!(pt.translate(vaddr).is_none(), "should be unmapped now");
    }

    #[test]
    fn unmap_prunes_empty_intermediate() {
        let (_arena, arena_base) = test_arena();
        let aligned = (arena_base.as_u64() + 4095) & !4095;
        let root = PhysAddr(aligned);
        unsafe { core::ptr::write_bytes(root.as_u64() as *mut u8, 0, 4096) };
        let mut alloc = TrackingAllocator::new(aligned + 4096, ARENA_TABLES - 1);
        let mut pt = unsafe { X86_64PageTable::new(root, identity_phys_to_virt) };

        let vaddr = VirtAddr(0x1000);
        let paddr = PhysAddr(0xBEEF_0000);
        pt.map(vaddr, paddr, PageFlags::READABLE, &mut || alloc.alloc())
            .unwrap();

        let intermediates_allocated = alloc.alloc_count;
        assert_eq!(
            intermediates_allocated, 3,
            "mapping one page needs 3 intermediate tables"
        );

        let result = pt.unmap(vaddr, &mut |frame| alloc.dealloc(frame)).unwrap();
        assert_eq!(result, paddr);
        assert_eq!(
            alloc.freed.len(),
            3,
            "all 3 intermediate tables should be freed"
        );
    }

    #[test]
    fn unmap_preserves_sibling_intermediates() {
        let (_arena, arena_base) = test_arena();
        let aligned = (arena_base.as_u64() + 4095) & !4095;
        let root = PhysAddr(aligned);
        unsafe { core::ptr::write_bytes(root.as_u64() as *mut u8, 0, 4096) };
        let mut alloc = TrackingAllocator::new(aligned + 4096, ARENA_TABLES - 1);
        let mut pt = unsafe { X86_64PageTable::new(root, identity_phys_to_virt) };

        let vaddr1 = VirtAddr(0x1000);
        let vaddr2 = VirtAddr(0x2000);
        pt.map(
            vaddr1,
            PhysAddr(0xA000_0000),
            PageFlags::READABLE,
            &mut || alloc.alloc(),
        )
        .unwrap();
        pt.map(
            vaddr2,
            PhysAddr(0xB000_0000),
            PageFlags::READABLE,
            &mut || alloc.alloc(),
        )
        .unwrap();

        pt.unmap(vaddr1, &mut |frame| alloc.dealloc(frame)).unwrap();
        assert_eq!(alloc.freed.len(), 0, "sibling keeps intermediate alive");

        pt.unmap(vaddr2, &mut |frame| alloc.dealloc(frame)).unwrap();
        assert_eq!(
            alloc.freed.len(),
            3,
            "all intermediates freed after last sibling removed"
        );
    }
}
