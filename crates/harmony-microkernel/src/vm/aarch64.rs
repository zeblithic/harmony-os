// SPDX-License-Identifier: GPL-2.0-or-later
//! aarch64 4-level translation table implementation (L0 → L1 → L2 → L3).
//!
//! This module provides `Aarch64PageTable`, a concrete [`PageTable`] implementation
//! for aarch64 with 4 KiB granule. It manipulates a standard 4-level hierarchy:
//!
//! | Level | VA bits  | Purpose                     |
//! |-------|----------|-----------------------------|
//! | 3     | [47:39]  | L0 table                    |
//! | 2     | [38:30]  | L1 table                    |
//! | 1     | [29:21]  | L2 table                    |
//! | 0     | [20:12]  | L3 table (leaf page desc.)  |
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
//! Intermediate (non-leaf) table descriptors use `DESC_TABLE` with no AP
//! restrictions — permission enforcement happens at the leaf (L3) level.

use super::page_table::PageTable;
use super::{PageFlags, PhysAddr, VirtAddr, VmError};

// ── aarch64 descriptor bits ─────────────────────────────────────────

/// Table descriptor (L0-L2) or page descriptor (L3) — bits [1:0] = 0b11.
const DESC_TABLE: u64 = 0b11;

/// Invalid descriptor — bits [1:0] = 0b00.
const DESC_INVALID: u64 = 0b00;

/// Access Flag — must be set to avoid an access fault on first use.
const AF: u64 = 1 << 10;

/// Inner Shareable — required for SMP coherence.
const SH_INNER: u64 = 0b11 << 8;

/// AP[2:1] = 0b00: Read/Write at EL1 only (no EL0 access).
const AP_RW_EL1: u64 = 0b00 << 6;

/// AP[2:1] = 0b01: Read/Write at EL1 and EL0 (user accessible).
const AP_RW_ALL: u64 = 0b01 << 6;

/// AP[2:1] = 0b10: Read-Only at EL1 only.
const AP_RO_EL1: u64 = 0b10 << 6;

/// AP[2:1] = 0b11: Read-Only at EL1 and EL0.
const AP_RO_ALL: u64 = 0b11 << 6;

/// Unprivileged Execute-Never.
const UXN: u64 = 1 << 54;

/// Privileged Execute-Never.
const PXN: u64 = 1 << 53;

/// AttrIndx[2:0] = 0 — normal cacheable memory (MAIR slot 0).
const ATTR_NORMAL: u64 = 0 << 2;

/// AttrIndx[2:0] = 1 — device/uncacheable memory (MAIR slot 1).
const ATTR_DEVICE: u64 = 1 << 2;

/// Mask for extracting the output address from a descriptor (bits [47:12]).
const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// Mask for AP bits [7:6].
const AP_MASK: u64 = 0b11 << 6;

/// Mask for AttrIndx bits [4:2].
const ATTR_IDX_MASK: u64 = 0b111 << 2;

/// Permissive intermediate table descriptor flags.
/// Intermediate descriptors carry DESC_TABLE only — AP and UXN/PXN are
/// not enforced at non-leaf levels in the aarch64 translation regime.
const INTERMEDIATE_FLAGS: u64 = DESC_TABLE;

// ── Aarch64PageTable ────────────────────────────────────────────────

/// Concrete aarch64 4-level page table.
///
/// Walks an L0 → L1 → L2 → L3 hierarchy stored in physical frames.
/// The `phys_to_virt` function is used to obtain writable pointers to page
/// table frames during manipulation.
pub struct Aarch64PageTable {
    /// Physical address of the L0 (root) table — loaded into TTBR0_EL1.
    root: PhysAddr,
    /// Converts a physical address to a kernel-accessible virtual pointer.
    phys_to_virt: fn(PhysAddr) -> *mut u8,
}

impl Aarch64PageTable {
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
    /// - Level 3 (L0): bits [47:39]
    /// - Level 2 (L1): bits [38:30]
    /// - Level 1 (L2): bits [29:21]
    /// - Level 0 (L3): bits [20:12]
    fn index(vaddr: VirtAddr, level: usize) -> usize {
        ((vaddr.as_u64() >> (12 + level * 9)) & 0x1FF) as usize
    }

    /// Translate [`PageFlags`] to aarch64 descriptor bits for a leaf (L3) entry.
    ///
    /// Note the UXN/PXN inversion: `EXECUTABLE` means *clear* the XN bits.
    /// If the flag is absent, both UXN and PXN are set to disable execution.
    fn flags_to_desc(flags: PageFlags) -> u64 {
        let mut desc: u64 = DESC_TABLE | AF | SH_INNER | ATTR_NORMAL;

        // AP bits encode both writability and user accessibility.
        let writable = flags.contains(PageFlags::WRITABLE);
        let user = flags.contains(PageFlags::USER);

        desc |= match (writable, user) {
            (true, true) => AP_RW_ALL,
            (true, false) => AP_RW_EL1,
            (false, true) => AP_RO_ALL,
            (false, false) => AP_RO_EL1,
        };

        // UXN/PXN are the inverse of EXECUTABLE: set both when NOT executable.
        if !flags.contains(PageFlags::EXECUTABLE) {
            desc |= UXN | PXN;
        }

        // NO_CACHE selects device memory attribute instead of normal.
        if flags.contains(PageFlags::NO_CACHE) {
            // Clear ATTR_NORMAL bits and set ATTR_DEVICE.
            desc = (desc & !ATTR_IDX_MASK) | ATTR_DEVICE;
        }

        // GLOBAL is implicit for TTBR1 kernel pages on aarch64; ignored here.

        desc
    }

    /// Translate aarch64 descriptor bits back to [`PageFlags`].
    fn desc_to_flags(desc: u64) -> PageFlags {
        let mut flags = PageFlags::empty();

        // If the descriptor is valid, the page is readable.
        if desc & 0b11 == DESC_TABLE {
            flags |= PageFlags::READABLE;
        } else {
            return flags;
        }

        // Decode AP bits for WRITABLE and USER.
        match desc & AP_MASK {
            x if x == AP_RW_ALL => {
                flags |= PageFlags::WRITABLE | PageFlags::USER;
            }
            x if x == AP_RW_EL1 => {
                flags |= PageFlags::WRITABLE;
            }
            x if x == AP_RO_ALL => {
                flags |= PageFlags::USER;
            }
            _ => {
                // AP_RO_EL1 or unrecognized — kernel read-only, no extra flags.
            }
        }

        // Executable when UXN is NOT set.
        if desc & UXN == 0 {
            flags |= PageFlags::EXECUTABLE;
        }

        // Check AttrIndx for device/uncacheable memory.
        if desc & ATTR_IDX_MASK == ATTR_DEVICE {
            flags |= PageFlags::NO_CACHE;
        }

        flags
    }

    /// Returns `true` if the descriptor is valid (bits [1:0] != 0b00).
    fn is_valid(desc: u64) -> bool {
        desc & 0b11 != DESC_INVALID
    }

    /// Returns `true` if all 512 entries in the table are invalid.
    fn is_table_empty(table: &[u64; 512]) -> bool {
        table.iter().all(|&e| !Self::is_valid(e))
    }
}

impl PageTable for Aarch64PageTable {
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

        // Walk levels 3 (L0) → 1 (L2), creating intermediate tables as needed.
        let mut table_paddr = self.root;

        for level in (1..=3).rev() {
            let table = self.table_mut(table_paddr);
            let idx = Self::index(vaddr, level);
            let entry = table[idx];

            if Self::is_valid(entry) {
                // Intermediate table exists — follow it.
                table_paddr = PhysAddr(entry & ADDR_MASK);
            } else {
                // Allocate a new frame for the intermediate table.
                let new_frame = frame_alloc().ok_or(VmError::OutOfMemory)?;

                // Zero the new frame so all 512 entries start as invalid.
                let new_ptr = (self.phys_to_virt)(new_frame);
                unsafe {
                    core::ptr::write_bytes(new_ptr, 0, 4096);
                }

                // Install the intermediate table descriptor.
                let table = self.table_mut(table_paddr);
                table[idx] = new_frame.as_u64() | INTERMEDIATE_FLAGS;

                table_paddr = new_frame;
            }
        }

        // Level 0 (L3): install the leaf page descriptor.
        let pt = self.table_mut(table_paddr);
        let idx = Self::index(vaddr, 0);

        if Self::is_valid(pt[idx]) {
            return Err(VmError::RegionConflict(vaddr));
        }

        pt[idx] = (paddr.as_u64() & ADDR_MASK) | Self::flags_to_desc(flags);
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

            if !Self::is_valid(entry) {
                return Err(VmError::NotMapped(vaddr));
            }
            walk[i] = (table_paddr, idx);
            table_paddr = PhysAddr(entry & ADDR_MASK);
        }

        // Level 0: clear the leaf descriptor.
        let leaf_table_paddr = table_paddr;
        let pt = self.table_mut(leaf_table_paddr);
        let idx = Self::index(vaddr, 0);
        let entry = pt[idx];

        if !Self::is_valid(entry) {
            return Err(VmError::NotMapped(vaddr));
        }

        let old_paddr = PhysAddr(entry & ADDR_MASK);
        pt[idx] = 0;

        // Bottom-up prune: walk was filled top-down as walk[0]=(L3/root, idx→L2),
        // walk[1]=(L2, idx→L1), walk[2]=(L1, idx→L0/leaf). Reverse so we process
        // L0→L1→L2 direction. Root (L3) is never freed.
        let mut child_paddr = leaf_table_paddr;
        for &(parent_paddr, parent_idx) in walk.iter().rev() {
            if parent_paddr.as_u64() == 0 {
                break;
            }
            let child_table = self.table_mut(child_paddr);
            if Self::is_table_empty(child_table) {
                // Invalidate parent entry before freeing the child frame —
                // ensures the frame is unreachable before it's returned to the allocator.
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

            if !Self::is_valid(entry) {
                return Err(VmError::NotMapped(vaddr));
            }
            table_paddr = PhysAddr(entry & ADDR_MASK);
        }

        // Level 0: update flags, preserving the physical address.
        let pt = self.table_mut(table_paddr);
        let idx = Self::index(vaddr, 0);
        let entry = pt[idx];

        if !Self::is_valid(entry) {
            return Err(VmError::NotMapped(vaddr));
        }

        let phys = entry & ADDR_MASK;
        pt[idx] = phys | Self::flags_to_desc(flags);

        Ok(())
    }

    fn translate(&self, vaddr: VirtAddr) -> Option<(PhysAddr, PageFlags)> {
        // Walk all 4 levels, returning None if any intermediate descriptor is invalid.
        let mut table_paddr = self.root;

        for level in (1..=3).rev() {
            let table = self.table_mut(table_paddr);
            let idx = Self::index(vaddr, level);
            let entry = table[idx];

            if !Self::is_valid(entry) {
                return None;
            }
            table_paddr = PhysAddr(entry & ADDR_MASK);
        }

        // Level 0: read the leaf descriptor.
        let pt = self.table_mut(table_paddr);
        let idx = Self::index(vaddr, 0);
        let entry = pt[idx];

        if !Self::is_valid(entry) {
            return None;
        }

        let paddr = PhysAddr(entry & ADDR_MASK);
        let flags = Self::desc_to_flags(entry);
        Some((paddr, flags))
    }

    fn activate(&mut self) {
        // Load the L0 table physical address into TTBR0_EL1.
        //
        // This is a privileged operation that requires EL1 — it will trap
        // in userspace. Guard with target_os = "none" so it only runs on
        // bare-metal targets.
        #[cfg(target_os = "none")]
        unsafe {
            core::arch::asm!(
                "msr ttbr0_el1, {}",
                in(reg) self.root.as_u64(),
                options(nostack),
            );
            // ISB ensures the TTBR0 write completes before any further
            // instruction fetch.
            core::arch::asm!("isb", options(nostack));
            // Invalidate all TLB entries for ASID 0 (inner-shareable).
            // Without this, stale entries from the previous address space
            // could allow cross-process memory access.
            core::arch::asm!("tlbi vmalle1is", options(nostack));
            // DSB ensures the TLB invalidation broadcast completes across
            // all cores before we continue.
            core::arch::asm!("dsb ish", options(nostack));
            // Final ISB synchronizes the instruction pipeline.
            core::arch::asm!("isb", options(nostack));
        }
    }

    fn root_paddr(&self) -> PhysAddr {
        self.root
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Verify R/W + USER → AP_RW_ALL with AF and DESC_TABLE.
    #[test]
    fn flags_to_desc_rw_user() {
        let flags = PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::USER;
        let desc = Aarch64PageTable::flags_to_desc(flags);

        // Must have table descriptor type bits.
        assert_eq!(desc & 0b11, DESC_TABLE, "descriptor type must be 0b11");
        // Must have Access Flag.
        assert_ne!(desc & AF, 0, "AF must be set");
        // Must have Inner Shareable.
        assert_ne!(desc & SH_INNER, 0, "SH_INNER must be set");
        // AP must be RW_ALL (EL1 + EL0 read/write).
        assert_eq!(
            desc & AP_MASK,
            AP_RW_ALL,
            "AP must be RW_ALL for writable+user"
        );
        // Not executable → both UXN and PXN set.
        assert_ne!(desc & UXN, 0, "UXN must be set when not executable");
        assert_ne!(desc & PXN, 0, "PXN must be set when not executable");
        // Normal memory attribute.
        assert_eq!(desc & ATTR_IDX_MASK, ATTR_NORMAL, "should be normal memory");
    }

    /// Verify READABLE only → AP_RO_EL1, AF, UXN|PXN set (not executable).
    #[test]
    fn flags_to_desc_ro_kernel() {
        let flags = PageFlags::READABLE;
        let desc = Aarch64PageTable::flags_to_desc(flags);

        assert_eq!(desc & 0b11, DESC_TABLE);
        assert_ne!(desc & AF, 0);
        assert_eq!(
            desc & AP_MASK,
            AP_RO_EL1,
            "AP must be RO_EL1 for kernel read-only"
        );
        // Not executable.
        assert_ne!(desc & UXN, 0, "UXN set when not executable");
        assert_ne!(desc & PXN, 0, "PXN set when not executable");
    }

    /// Verify READABLE|EXECUTABLE → no UXN, no PXN.
    #[test]
    fn flags_to_desc_executable() {
        let flags = PageFlags::READABLE | PageFlags::EXECUTABLE;
        let desc = Aarch64PageTable::flags_to_desc(flags);

        assert_eq!(desc & 0b11, DESC_TABLE);
        assert_ne!(desc & AF, 0);
        assert_eq!(
            desc & AP_MASK,
            AP_RO_EL1,
            "AP must be RO_EL1 for kernel read-only"
        );
        // Executable → both XN bits clear.
        assert_eq!(desc & UXN, 0, "UXN must be clear for executable");
        assert_eq!(desc & PXN, 0, "PXN must be clear for executable");
    }

    /// Verify NO_CACHE selects ATTR_DEVICE instead of ATTR_NORMAL.
    #[test]
    fn flags_to_desc_no_cache() {
        let flags = PageFlags::READABLE | PageFlags::NO_CACHE;
        let desc = Aarch64PageTable::flags_to_desc(flags);

        assert_eq!(
            desc & ATTR_IDX_MASK,
            ATTR_DEVICE,
            "NO_CACHE must select device memory attribute"
        );
    }

    /// Encode flags → descriptor → decode back to flags. Roundtrip must match.
    #[test]
    fn desc_to_flags_roundtrip() {
        let test_cases = vec![
            PageFlags::READABLE,
            PageFlags::READABLE | PageFlags::WRITABLE,
            PageFlags::READABLE | PageFlags::USER,
            PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::USER,
            PageFlags::READABLE | PageFlags::EXECUTABLE,
            PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::EXECUTABLE,
            PageFlags::READABLE | PageFlags::NO_CACHE,
            PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::USER | PageFlags::EXECUTABLE,
            PageFlags::READABLE
                | PageFlags::WRITABLE
                | PageFlags::USER
                | PageFlags::EXECUTABLE
                | PageFlags::NO_CACHE,
        ];

        for flags in test_cases {
            let desc = Aarch64PageTable::flags_to_desc(flags);
            let recovered = Aarch64PageTable::desc_to_flags(desc);
            assert_eq!(
                recovered, flags,
                "roundtrip failed for {flags:?}: desc={desc:#018x}, recovered={recovered:?}"
            );
        }
    }

    /// Verify VA index extraction matches expected 9-bit values.
    #[test]
    fn index_extraction() {
        // VA = 0x0000_7F_BF_DF_EF_F000
        //   L0 index (level 3, bits [47:39]) = 0xFF = 255
        //   L1 index (level 2, bits [38:30]) = 0x1EF = ... let's compute manually.
        //
        // Use a simpler example: VA where each level index is distinct.
        // bits [47:39] = L0, [38:30] = L1, [29:21] = L2, [20:12] = L3
        //
        // L0=1, L1=2, L2=3, L3=4 →
        // VA = (1 << 39) | (2 << 30) | (3 << 21) | (4 << 12)
        let va = VirtAddr((1 << 39) | (2 << 30) | (3 << 21) | (4 << 12));
        assert_eq!(Aarch64PageTable::index(va, 3), 1, "L0 index");
        assert_eq!(Aarch64PageTable::index(va, 2), 2, "L1 index");
        assert_eq!(Aarch64PageTable::index(va, 1), 3, "L2 index");
        assert_eq!(Aarch64PageTable::index(va, 0), 4, "L3 index");

        // All zeros → all indices zero.
        let va0 = VirtAddr(0);
        for level in 0..4 {
            assert_eq!(Aarch64PageTable::index(va0, level), 0);
        }

        // Max 9-bit index = 511.
        let va_max = VirtAddr(0x0000_FFFF_FFFF_F000);
        for level in 0..4 {
            assert_eq!(Aarch64PageTable::index(va_max, level), 511);
        }
    }

    /// Verify that an invalid descriptor produces empty PageFlags.
    #[test]
    fn desc_to_flags_invalid() {
        let flags = Aarch64PageTable::desc_to_flags(0);
        assert_eq!(flags, PageFlags::empty(), "invalid descriptor → no flags");
    }

    // ── Integration tests using heap-backed page table arena ────────

    /// Size of the test arena: enough for root + 3 intermediate + 1 leaf = 5 tables.
    const ARENA_TABLES: usize = 8;
    const ARENA_SIZE: usize = ARENA_TABLES * 4096;

    /// Create a test arena and return (arena_vec, base_address, phys_to_virt_fn).
    ///
    /// The arena is a heap-allocated buffer whose address serves as both the
    /// "physical" and virtual address, making `phys_to_virt` an identity function
    /// offset to the arena base.
    fn test_arena() -> (Vec<u8>, PhysAddr) {
        // Allocate page-aligned memory.
        let mut arena = vec![0u8; ARENA_SIZE + 4096];
        let base = arena.as_mut_ptr() as u64;
        let aligned_base = (base + 4095) & !4095;
        // We'll use the aligned base as our "physical address" origin.
        // Leak the vec to get a stable address for the test duration.
        let arena = arena.into_boxed_slice();
        let arena = Vec::from(arena);
        let aligned_base = PhysAddr(aligned_base);
        (arena, aligned_base)
    }

    /// Identity phys_to_virt — works because test arena addresses are real heap addresses.
    fn identity_phys_to_virt(paddr: PhysAddr) -> *mut u8 {
        paddr.as_u64() as *mut u8
    }

    /// Allocator that hands out consecutive 4 KiB frames from the arena.
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

    #[test]
    fn map_and_translate() {
        let (_arena, arena_base) = test_arena();
        let aligned = (arena_base.as_u64() + 4095) & !4095;

        // Root table = first page-aligned frame in arena.
        let root = PhysAddr(aligned);
        // Zero the root frame.
        unsafe {
            core::ptr::write_bytes(root.as_u64() as *mut u8, 0, 4096);
        }

        // Allocator hands out frames starting after the root.
        let mut allocator = TestAllocator::new(aligned + 4096, ARENA_TABLES - 1);

        let mut pt = unsafe { Aarch64PageTable::new(root, identity_phys_to_virt) };

        let vaddr = VirtAddr(0x1000); // page-aligned
        let paddr = PhysAddr(0xDEAD_B000); // page-aligned
        let flags = PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::USER;

        let result = pt.map(vaddr, paddr, flags, &mut || allocator.alloc());
        assert!(result.is_ok(), "map should succeed");

        // Translate should return the mapped physical address and flags.
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
        unsafe {
            core::ptr::write_bytes(root.as_u64() as *mut u8, 0, 4096);
        }
        let mut allocator = TestAllocator::new(aligned + 4096, ARENA_TABLES - 1);
        let mut pt = unsafe { Aarch64PageTable::new(root, identity_phys_to_virt) };

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
    fn set_flags_updates_permissions() {
        let (_arena, arena_base) = test_arena();
        let aligned = (arena_base.as_u64() + 4095) & !4095;
        let root = PhysAddr(aligned);
        unsafe {
            core::ptr::write_bytes(root.as_u64() as *mut u8, 0, 4096);
        }
        let mut allocator = TestAllocator::new(aligned + 4096, ARENA_TABLES - 1);
        let mut pt = unsafe { Aarch64PageTable::new(root, identity_phys_to_virt) };

        let vaddr = VirtAddr(0x3000);
        let paddr = PhysAddr(0xCAFE_0000);
        let flags = PageFlags::READABLE | PageFlags::WRITABLE;

        pt.map(vaddr, paddr, flags, &mut || allocator.alloc())
            .unwrap();

        // Change to read-only + executable.
        let new_flags = PageFlags::READABLE | PageFlags::EXECUTABLE;
        pt.set_flags(vaddr, new_flags).unwrap();

        let (got_paddr, got_flags) = pt.translate(vaddr).unwrap();
        assert_eq!(got_paddr, paddr, "paddr must not change");
        assert_eq!(got_flags, new_flags, "flags must be updated");
    }

    #[test]
    fn double_map_returns_conflict() {
        let (_arena, arena_base) = test_arena();
        let aligned = (arena_base.as_u64() + 4095) & !4095;
        let root = PhysAddr(aligned);
        unsafe {
            core::ptr::write_bytes(root.as_u64() as *mut u8, 0, 4096);
        }
        let mut allocator = TestAllocator::new(aligned + 4096, ARENA_TABLES - 1);
        let mut pt = unsafe { Aarch64PageTable::new(root, identity_phys_to_virt) };

        let vaddr = VirtAddr(0x4000);
        let paddr = PhysAddr(0xAAAA_0000);
        let flags = PageFlags::READABLE;

        pt.map(vaddr, paddr, flags, &mut || allocator.alloc())
            .unwrap();

        // Second map to same vaddr should fail.
        let result = pt.map(vaddr, PhysAddr(0xBBBB_0000), flags, &mut || {
            allocator.alloc()
        });
        assert_eq!(
            result,
            Err(VmError::RegionConflict(vaddr)),
            "double map must fail with RegionConflict"
        );
    }

    #[test]
    fn unmap_unmapped_returns_not_mapped() {
        let (_arena, arena_base) = test_arena();
        let aligned = (arena_base.as_u64() + 4095) & !4095;
        let root = PhysAddr(aligned);
        unsafe {
            core::ptr::write_bytes(root.as_u64() as *mut u8, 0, 4096);
        }
        let mut pt = unsafe { Aarch64PageTable::new(root, identity_phys_to_virt) };

        let vaddr = VirtAddr(0x5000);
        assert_eq!(
            pt.unmap(vaddr, &mut |_| {}),
            Err(VmError::NotMapped(vaddr)),
            "unmap of unmapped address must fail"
        );
    }

    #[test]
    fn unaligned_address_errors() {
        let (_arena, arena_base) = test_arena();
        let aligned = (arena_base.as_u64() + 4095) & !4095;
        let root = PhysAddr(aligned);
        unsafe {
            core::ptr::write_bytes(root.as_u64() as *mut u8, 0, 4096);
        }
        let mut pt = unsafe { Aarch64PageTable::new(root, identity_phys_to_virt) };

        let unaligned = VirtAddr(0x1001);
        let flags = PageFlags::READABLE;

        assert_eq!(
            pt.map(unaligned, PhysAddr(0x2000), flags, &mut || None),
            Err(VmError::Unaligned(0x1001))
        );
        assert_eq!(
            pt.unmap(unaligned, &mut |_| {}),
            Err(VmError::Unaligned(0x1001))
        );
        assert_eq!(
            pt.set_flags(unaligned, flags),
            Err(VmError::Unaligned(0x1001))
        );
    }

    #[test]
    fn root_paddr_returns_root() {
        let (_arena, arena_base) = test_arena();
        let aligned = (arena_base.as_u64() + 4095) & !4095;
        let root = PhysAddr(aligned);
        let pt = unsafe { Aarch64PageTable::new(root, identity_phys_to_virt) };
        assert_eq!(pt.root_paddr(), root);
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
    fn unmap_prunes_empty_intermediate() {
        let (_arena, arena_base) = test_arena();
        let aligned = (arena_base.as_u64() + 4095) & !4095;
        let root = PhysAddr(aligned);
        unsafe { core::ptr::write_bytes(root.as_u64() as *mut u8, 0, 4096) };
        let mut alloc = TrackingAllocator::new(aligned + 4096, ARENA_TABLES - 1);
        let mut pt = unsafe { Aarch64PageTable::new(root, identity_phys_to_virt) };

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
        let mut pt = unsafe { Aarch64PageTable::new(root, identity_phys_to_virt) };

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
