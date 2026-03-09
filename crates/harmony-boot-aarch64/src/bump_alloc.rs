// SPDX-License-Identifier: GPL-2.0-or-later
//! Bump frame allocator for boot-time page table construction.

use harmony_microkernel::vm::{PhysAddr, PAGE_SIZE};

pub struct BumpAllocator {
    next: u64, // next frame to hand out (always page-aligned)
    end: u64,  // one past last usable byte
}

impl BumpAllocator {
    pub fn new(base: u64, size: u64) -> Self {
        let aligned_base = (base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let end = (base + size) & !(PAGE_SIZE - 1);
        Self {
            next: aligned_base,
            end: if end > aligned_base { end } else { aligned_base },
        }
    }

    pub fn alloc_frame(&mut self) -> Option<PhysAddr> {
        if self.next >= self.end {
            return None;
        }
        let frame = self.next;
        self.next += PAGE_SIZE;
        Some(PhysAddr(frame))
    }

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
