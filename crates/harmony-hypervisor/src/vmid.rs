// SPDX-License-Identifier: GPL-2.0-or-later
//! VMID allocator — 8-bit namespace, max 256 VMs.
//!
//! VmId(0) is reserved for the host (no Stage-2 restriction).
//! Allocation starts at 1 and wraps around, using a 256-bit bitmap.

/// 8-bit VM identifier. VmId(0) is the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VmId(pub u8);

/// Bitmap-based VMID allocator. Slot 0 is permanently reserved.
pub struct VmIdAllocator {
    /// 256-bit bitmap: bit N set = slot N is in use.
    bitmap: [u64; 4],
}

impl Default for VmIdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl VmIdAllocator {
    pub fn new() -> Self {
        let mut bitmap = [0u64; 4];
        bitmap[0] = 1; // Reserve bit 0 (host)
        Self { bitmap }
    }

    pub fn alloc(&mut self) -> Option<VmId> {
        for (chunk_idx, chunk) in self.bitmap.iter_mut().enumerate() {
            if *chunk != u64::MAX {
                let bit = (!*chunk).trailing_zeros() as u8;
                let id = (chunk_idx as u8) * 64 + bit;
                *chunk |= 1u64 << bit;
                return Some(VmId(id));
            }
        }
        None
    }

    pub fn free(&mut self, id: VmId) {
        if id.0 == 0 {
            return;
        }
        let chunk_idx = (id.0 / 64) as usize;
        let bit = id.0 % 64;
        self.bitmap[chunk_idx] &= !(1u64 << bit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmid_zero_reserved_for_host() {
        let mut alloc = VmIdAllocator::new();
        let id = alloc.alloc().unwrap();
        assert_eq!(id, VmId(1));
    }

    #[test]
    fn vmid_alloc_sequential() {
        let mut alloc = VmIdAllocator::new();
        let a = alloc.alloc().unwrap();
        let b = alloc.alloc().unwrap();
        assert_eq!(a, VmId(1));
        assert_eq!(b, VmId(2));
    }

    #[test]
    fn vmid_free_and_reuse() {
        let mut alloc = VmIdAllocator::new();
        let id = alloc.alloc().unwrap();
        alloc.free(id);
        let reused = alloc.alloc().unwrap();
        assert_eq!(reused, id);
    }

    #[test]
    fn vmid_exhaustion() {
        let mut alloc = VmIdAllocator::new();
        for _ in 0..255 {
            alloc.alloc().unwrap();
        }
        assert!(alloc.alloc().is_none());
    }

    #[test]
    fn vmid_free_zero_is_noop() {
        let mut alloc = VmIdAllocator::new();
        alloc.free(VmId(0));
        let id = alloc.alloc().unwrap();
        assert_eq!(id, VmId(1));
    }
}
