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
        _frame_dealloc: &mut dyn FnMut(PhysAddr),
    ) -> Result<PhysAddr, VmError> {
        if !vaddr.is_page_aligned() {
            return Err(VmError::Unaligned(vaddr.as_u64()));
        }

        // Walk levels 3 → 1; if any intermediate entry is not present, the
        // page is not mapped.
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

        // Level 0: clear the leaf entry.
        let pt = self.table_mut(table_paddr);
        let idx = Self::index(vaddr, 0);
        let entry = pt[idx];

        if entry & PTE_PRESENT == 0 {
            return Err(VmError::NotMapped(vaddr));
        }

        let old_paddr = PhysAddr(entry & PTE_ADDR_MASK);
        pt[idx] = 0;

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
}
