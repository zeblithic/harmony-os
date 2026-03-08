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

// ── Integrity shared types ──────────────────────────────────────────

/// Which memory zone a frame belongs to, derived from FrameClassification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(usize)]
pub enum MemoryZone {
    PublicDurable = 0,
    PublicEphemeral = 1,
    KernelDurable = 2,
    KernelEphemeral = 3,
}

impl From<FrameClassification> for MemoryZone {
    fn from(class: FrameClassification) -> Self {
        match (
            class.contains(FrameClassification::ENCRYPTED),
            class.contains(FrameClassification::EPHEMERAL),
        ) {
            (false, false) => MemoryZone::PublicDurable,
            (false, true) => MemoryZone::PublicEphemeral,
            (true, false) => MemoryZone::KernelDurable,
            (true, true) => MemoryZone::KernelEphemeral,
        }
    }
}

impl MemoryZone {
    pub fn is_kernel(self) -> bool {
        matches!(self, Self::KernelDurable | Self::KernelEphemeral)
    }

    pub fn is_ephemeral(self) -> bool {
        matches!(self, Self::PublicEphemeral | Self::KernelEphemeral)
    }
}

/// A 32-byte content hash (BLAKE3) used for frame integrity verification.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash(pub [u8; 32]);

impl ContentHash {
    pub const ZERO: Self = Self([0u8; 32]);
}

impl Default for ContentHash {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentHash({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

/// What kind of access is being performed on a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessOp {
    Read,
    Write,
    Execute,
}

/// Reason for an integrity violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationReason {
    ContentTampered,
    UnauthorizedAccess,
    GuardianStateCorrupted,
    BehavioralMismatch,
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
    /// A process space with this PID already exists.
    ProcessExists(u32),
}

// ── Submodules ───────────────────────────────────────────────────────

pub mod buddy;
pub mod cap_tracker;
pub mod manager;
pub mod mock;
pub mod page_table;

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
        assert!(
            v_dbg.contains("VirtAddr"),
            "expected VirtAddr in debug output"
        );
        assert!(
            p_dbg.contains("PhysAddr"),
            "expected PhysAddr in debug output"
        );
        assert_ne!(v_dbg, p_dbg);
    }

    #[test]
    fn memory_zone_from_classification() {
        assert_eq!(
            MemoryZone::from(FrameClassification::empty()),
            MemoryZone::PublicDurable,
        );
        assert_eq!(
            MemoryZone::from(FrameClassification::EPHEMERAL),
            MemoryZone::PublicEphemeral,
        );
        assert_eq!(
            MemoryZone::from(FrameClassification::ENCRYPTED),
            MemoryZone::KernelDurable,
        );
        assert_eq!(
            MemoryZone::from(FrameClassification::ENCRYPTED | FrameClassification::EPHEMERAL),
            MemoryZone::KernelEphemeral,
        );
    }

    #[test]
    fn content_hash_default_is_zeroed() {
        let h = ContentHash::default();
        assert_eq!(h.0, [0u8; 32]);
    }

    #[test]
    fn access_op_variants_exist() {
        let _r = AccessOp::Read;
        let _w = AccessOp::Write;
        let _x = AccessOp::Execute;
    }

    #[test]
    fn violation_reason_variants_exist() {
        let _ct = ViolationReason::ContentTampered;
        let _ua = ViolationReason::UnauthorizedAccess;
        let _gs = ViolationReason::GuardianStateCorrupted;
        let _bm = ViolationReason::BehavioralMismatch;
    }
}
