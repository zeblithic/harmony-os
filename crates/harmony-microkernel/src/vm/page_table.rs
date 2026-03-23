// SPDX-License-Identifier: GPL-2.0-or-later
//! PageTable trait — hardware page table abstraction.
//!
//! Implementors manipulate MMU state only — no policy, no allocation
//! decisions, no capability checks. All policy lives in AddressSpaceManager.

use super::{PageFlags, PhysAddr, VirtAddr, VmError};

/// Hardware page table abstraction.
///
/// The `frame_alloc` callback on `map()` lets the caller provide frames
/// for intermediate page table levels without the trait owning an allocator.
pub trait PageTable {
    /// Map `vaddr` to `paddr` with the given flags.
    ///
    /// `frame_alloc` is called when the implementation needs a physical frame
    /// for an intermediate page table level. Mock implementations may ignore it.
    fn map(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PageFlags,
        frame_alloc: &mut dyn FnMut() -> Option<PhysAddr>,
    ) -> Result<(), VmError>;

    /// Remove the mapping at `vaddr`, returning the physical address that was mapped.
    ///
    /// `frame_dealloc` is called for each intermediate page table frame that
    /// becomes empty after the leaf is removed. Mock implementations may ignore it.
    fn unmap(
        &mut self,
        vaddr: VirtAddr,
        frame_dealloc: &mut dyn FnMut(PhysAddr),
    ) -> Result<PhysAddr, VmError>;

    /// Update the permission flags on an existing mapping at `vaddr`.
    fn set_flags(&mut self, vaddr: VirtAddr, flags: PageFlags) -> Result<(), VmError>;

    /// Translate `vaddr` to its mapped physical address and flags.
    ///
    /// Returns `None` if the address is not mapped.
    fn translate(&self, vaddr: VirtAddr) -> Option<(PhysAddr, PageFlags)>;

    /// Activate this page table (e.g., load into CR3 / TTBR0).
    fn activate(&mut self);

    /// Return the physical address of the root page table structure.
    fn root_paddr(&self) -> PhysAddr;
}
