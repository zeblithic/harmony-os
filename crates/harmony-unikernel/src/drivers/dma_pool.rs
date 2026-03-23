// SPDX-License-Identifier: GPL-2.0-or-later
//! DMA buffer pool — pre-allocated buffers with known physical addresses.
//!
//! Used by drivers that need DMA-accessible memory. The platform layer
//! allocates physical pages at boot and constructs the pool; the driver
//! allocates/frees buffers by index.

/// Metadata for a single DMA-accessible buffer.
#[derive(Clone, Copy, Debug)]
pub struct DmaBuffer {
    /// CPU-accessible virtual address.
    pub virt: *mut u8,
    /// Physical address for hardware DMA descriptors.
    pub phys: u64,
}

// SAFETY: DmaBuffer contains a raw pointer but is only used in single-threaded
// bare-metal contexts where Send/Sync are not meaningful. The pointer is valid
// for the lifetime of the boot-allocated memory.
unsafe impl Send for DmaBuffer {}
unsafe impl Sync for DmaBuffer {}

/// Errors from DMA pool operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaPoolError {
    /// Attempted to free a buffer that is already free.
    DoubleFree(usize),
}

/// Fixed-size pool of pre-allocated DMA buffers.
pub struct DmaPool<const N: usize> {
    buffers: [DmaBuffer; N],
    free: [bool; N],
    buf_size: usize,
}

impl<const N: usize> DmaPool<N> {
    /// Create a pool from pre-allocated buffers.
    pub fn new(buffers: [DmaBuffer; N], buf_size: usize) -> Self {
        Self {
            buffers,
            free: [true; N],
            buf_size,
        }
    }

    /// Allocate a buffer, returning its index. Returns None if pool exhausted.
    pub fn alloc(&mut self) -> Option<usize> {
        for i in 0..N {
            if self.free[i] {
                self.free[i] = false;
                return Some(i);
            }
        }
        None
    }

    /// Free a buffer by index. Returns error on double-free.
    ///
    /// # Panics
    /// Panics if `index >= N`.
    pub fn free(&mut self, index: usize) -> Result<(), DmaPoolError> {
        if self.free[index] {
            return Err(DmaPoolError::DoubleFree(index));
        }
        self.free[index] = true;
        Ok(())
    }

    /// Get buffer metadata by index.
    ///
    /// # Panics
    /// Panics if `index >= N`.
    pub fn get(&self, index: usize) -> &DmaBuffer {
        &self.buffers[index]
    }

    /// Find the buffer index for a given physical address. O(N) scan.
    /// Only matches allocated (in-use) buffers.
    pub fn find_by_phys(&self, phys: u64) -> Option<usize> {
        self.buffers
            .iter()
            .enumerate()
            .find(|(i, b)| !self.free[*i] && b.phys == phys)
            .map(|(i, _)| i)
    }

    /// Buffer size in bytes.
    pub fn buf_size(&self) -> usize {
        self.buf_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn make_pool<const N: usize>() -> DmaPool<N> {
        let mut buffers = [DmaBuffer {
            virt: core::ptr::null_mut(),
            phys: 0,
        }; N];
        for buf in buffers.iter_mut() {
            // Use heap allocation for test buffers.
            let heap_buf = vec![0u8; 2048].into_boxed_slice();
            let ptr = Box::into_raw(heap_buf) as *mut u8;
            *buf = DmaBuffer {
                virt: ptr,
                phys: ptr as u64, // identity-mapped in tests
            };
        }
        DmaPool::new(buffers, 2048)
    }

    #[test]
    fn pool_alloc_and_free() {
        let mut pool = make_pool::<4>();

        // Alloc all 4
        let i0 = pool.alloc().unwrap();
        let i1 = pool.alloc().unwrap();
        let i2 = pool.alloc().unwrap();
        let i3 = pool.alloc().unwrap();
        assert!(pool.alloc().is_none(), "pool should be exhausted");

        // Free one, alloc again
        pool.free(i1).unwrap();
        let i4 = pool.alloc().unwrap();
        assert_eq!(i4, i1, "should reuse freed index");
        assert!(pool.alloc().is_none());

        // Cleanup (avoid leaks in test)
        for idx in [i0, i2, i3, i4] {
            let buf = pool.get(idx);
            unsafe {
                drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(buf.virt, 2048)));
            }
        }
    }

    #[test]
    fn pool_double_free_returns_error() {
        let mut pool = make_pool::<2>();
        let idx = pool.alloc().unwrap();
        pool.free(idx).unwrap();
        assert_eq!(pool.free(idx), Err(DmaPoolError::DoubleFree(idx)));

        // Cleanup
        for i in 0..2 {
            let buf = pool.get(i);
            unsafe {
                drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(buf.virt, 2048)));
            }
        }
    }

    #[test]
    fn pool_find_by_phys() {
        let mut pool = make_pool::<4>();
        let idx = pool.alloc().unwrap();
        let phys = pool.get(idx).phys;
        assert_eq!(pool.find_by_phys(phys), Some(idx));
        assert_eq!(pool.find_by_phys(0xDEAD), None);

        // Cleanup
        pool.free(idx).unwrap();
        for i in 0..4 {
            let buf = pool.get(i);
            unsafe {
                drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(buf.virt, 2048)));
            }
        }
    }

    #[test]
    fn pool_get_returns_correct_buffer() {
        let pool = make_pool::<2>();
        let b0 = pool.get(0);
        let b1 = pool.get(1);
        assert_ne!(b0.phys, b1.phys, "each buffer has a unique address");

        // Cleanup
        for i in 0..2 {
            let buf = pool.get(i);
            unsafe {
                drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(buf.virt, 2048)));
            }
        }
    }
}
