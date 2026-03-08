// SPDX-License-Identifier: GPL-2.0-or-later
//! Virtual memory subsystem — types, errors, and submodule declarations.
//!
//! This module provides the foundational types for hardware-backed virtual
//! memory management: address newtypes, page flags, frame classifications,
//! and the error enum shared across all VM operations.

use core::fmt;

use bitflags::bitflags;

// ── Constants ────────────────────────────────────────────────────────

/// Page size in bytes (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

/// Number of bits to shift for page-frame alignment.
pub const PAGE_SHIFT: u32 = 12;

// ── Address newtypes ─────────────────────────────────────────────────

/// A virtual address. Wraps a raw `u64` and provides page-alignment helpers.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtAddr(pub u64);

impl VirtAddr {
    /// Round down to the nearest page boundary.
    pub fn page_align_down(self) -> Self {
        Self(self.0 & !(PAGE_SIZE - 1))
    }

    /// Round up to the nearest page boundary.
    pub fn page_align_up(self) -> Self {
        Self((self.0 + PAGE_SIZE - 1) & !(PAGE_SIZE - 1))
    }

    /// Returns `true` if the address is page-aligned.
    pub fn is_page_aligned(self) -> bool {
        self.0 & (PAGE_SIZE - 1) == 0
    }

    /// Return the raw `u64` value.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VirtAddr({:#x})", self.0)
    }
}

/// A physical address. Wraps a raw `u64` and provides page-alignment helpers.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhysAddr(pub u64);

impl PhysAddr {
    /// Round down to the nearest page boundary.
    pub fn page_align_down(self) -> Self {
        Self(self.0 & !(PAGE_SIZE - 1))
    }

    /// Round up to the nearest page boundary.
    pub fn page_align_up(self) -> Self {
        Self((self.0 + PAGE_SIZE - 1) & !(PAGE_SIZE - 1))
    }

    /// Returns `true` if the address is page-aligned.
    pub fn is_page_aligned(self) -> bool {
        self.0 & (PAGE_SIZE - 1) == 0
    }

    /// Return the raw `u64` value.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysAddr({:#x})", self.0)
    }
}

// ── Bitflags ─────────────────────────────────────────────────────────

bitflags! {
    /// Page-level permission and caching flags.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PageFlags: u32 {
        const READABLE   = 1 << 0;
        const WRITABLE   = 1 << 1;
        const EXECUTABLE = 1 << 2;
        const USER       = 1 << 3;
        const NO_CACHE   = 1 << 4;
        const GLOBAL     = 1 << 5;
    }
}

bitflags! {
    /// Classification bits attached to physical frames.
    ///
    /// An empty set means the frame is public and durable (the default).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FrameClassification: u8 {
        /// Frame contents are encrypted at rest.
        const ENCRYPTED = 1 << 0;
        /// Frame is ephemeral — may be reclaimed without write-back.
        const EPHEMERAL = 1 << 1;
    }
}

// ── Error enum ───────────────────────────────────────────────────────

/// Errors returned by VM operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmError {
    /// The target process does not exist.
    NoSuchProcess(u32),
    /// The operation would exceed the process's memory budget.
    BudgetExceeded {
        limit: u64,
        used: u64,
        requested: u64,
    },
    /// The requested frame classification is not permitted.
    ClassificationDenied(FrameClassification),
    /// No physical memory available.
    OutOfMemory,
    /// A mapping already exists that overlaps the requested region.
    RegionConflict(VirtAddr),
    /// The address is not currently mapped.
    NotMapped(VirtAddr),
    /// The provided capability token is invalid or expired.
    CapabilityInvalid,
    /// Low-level page table manipulation failed.
    PageTableError,
    /// An address or size is not properly aligned.
    Unaligned(u64),
    /// The requested buddy order is out of range.
    InvalidOrder(usize),
}

// ── Submodules ───────────────────────────────────────────────────────

pub mod page_table;
pub mod mock;
pub mod buddy;
pub mod cap_tracker;
pub mod manager;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn virt_addr_page_align() {
        let addr = VirtAddr(4097);
        assert_eq!(addr.page_align_down(), VirtAddr(4096));
        assert_eq!(addr.page_align_up(), VirtAddr(8192));
        assert!(!addr.is_page_aligned());

        let aligned = VirtAddr(4096);
        assert!(aligned.is_page_aligned());
        assert_eq!(aligned.page_align_down(), aligned);
        assert_eq!(aligned.page_align_up(), aligned);
    }

    #[test]
    fn phys_addr_page_align() {
        let addr = PhysAddr(4097);
        assert_eq!(addr.page_align_down(), PhysAddr(4096));
        assert_eq!(addr.page_align_up(), PhysAddr(8192));
        assert!(!addr.is_page_aligned());

        let aligned = PhysAddr(4096);
        assert!(aligned.is_page_aligned());
        assert_eq!(aligned.page_align_down(), aligned);
        assert_eq!(aligned.page_align_up(), aligned);
    }

    #[test]
    fn page_flags_combine() {
        let rw = PageFlags::READABLE | PageFlags::WRITABLE;
        assert!(rw.contains(PageFlags::READABLE));
        assert!(rw.contains(PageFlags::WRITABLE));
        assert!(!rw.contains(PageFlags::EXECUTABLE));

        let rwx = rw | PageFlags::EXECUTABLE;
        assert!(rwx.contains(PageFlags::EXECUTABLE));
    }

    #[test]
    fn frame_classification_bits() {
        let empty = FrameClassification::empty();
        assert!(!empty.contains(FrameClassification::ENCRYPTED));
        assert!(!empty.contains(FrameClassification::EPHEMERAL));

        let both = FrameClassification::ENCRYPTED | FrameClassification::EPHEMERAL;
        assert!(both.contains(FrameClassification::ENCRYPTED));
        assert!(both.contains(FrameClassification::EPHEMERAL));
    }

    #[test]
    fn virt_phys_addr_not_interchangeable() {
        let v = VirtAddr(0x1000);
        let p = PhysAddr(0x1000);
        let v_dbg = format!("{:?}", v);
        let p_dbg = format!("{:?}", p);
        assert!(v_dbg.contains("VirtAddr"), "expected VirtAddr in debug output");
        assert!(p_dbg.contains("PhysAddr"), "expected PhysAddr in debug output");
        assert_ne!(v_dbg, p_dbg);
    }
}
