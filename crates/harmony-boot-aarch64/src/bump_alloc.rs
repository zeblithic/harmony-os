// SPDX-License-Identifier: GPL-2.0-or-later
//! Bump frame allocator for boot-time page table construction.

use harmony_microkernel::vm::{PhysAddr, PAGE_SIZE};

/// A simple bump allocator that hands out 4 KiB frames sequentially.
///
/// Never frees — used only during early boot before heap is available.
pub struct BumpAllocator {
    next: u64,
    end: u64,
}

impl BumpAllocator {
    /// Create a new bump allocator over the region `[base, base + size)`.
    ///
    /// `base` is rounded up to the next page boundary. `size` is truncated
    /// to a page boundary from `base + size`.
    pub fn new(base: u64, size: u64) -> Self {
        let aligned_base = (base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let end = (base + size) & !(PAGE_SIZE - 1);
        Self {
            next: aligned_base,
            end: if end > aligned_base {
                end
            } else {
                aligned_base
            },
        }
    }

    /// Allocate a single 4 KiB frame, returning its physical address.
    ///
    /// Returns `None` if the allocator is exhausted.
    pub fn alloc_frame(&mut self) -> Option<PhysAddr> {
        if self.next >= self.end {
            return None;
        }
        let frame = self.next;
        self.next += PAGE_SIZE;
        Some(PhysAddr(frame))
    }

    /// Number of frames remaining.
    pub fn remaining(&self) -> u64 {
        (self.end - self.next) / PAGE_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_sequential_frames() {
        let mut alloc = BumpAllocator::new(0x10_0000, 3 * PAGE_SIZE);
        assert_eq!(alloc.remaining(), 3);
        let f1 = alloc.alloc_frame().unwrap();
        assert_eq!(f1, PhysAddr(0x10_0000));
        let f2 = alloc.alloc_frame().unwrap();
        assert_eq!(f2, PhysAddr(0x10_1000));
        let f3 = alloc.alloc_frame().unwrap();
        assert_eq!(f3, PhysAddr(0x10_2000));
        assert_eq!(alloc.remaining(), 0);
        assert!(alloc.alloc_frame().is_none());
    }

    #[test]
    fn unaligned_base_rounds_up() {
        let mut alloc = BumpAllocator::new(0x10_0500, 2 * PAGE_SIZE);
        let f1 = alloc.alloc_frame().unwrap();
        assert_eq!(f1, PhysAddr(0x10_1000));
    }

    #[test]
    fn zero_size_returns_none() {
        let mut alloc = BumpAllocator::new(0x10_0000, 0);
        assert!(alloc.alloc_frame().is_none());
        assert_eq!(alloc.remaining(), 0);
    }

    #[test]
    fn size_smaller_than_page_returns_none() {
        let mut alloc = BumpAllocator::new(0x10_0000, 100);
        assert!(alloc.alloc_frame().is_none());
    }
}
