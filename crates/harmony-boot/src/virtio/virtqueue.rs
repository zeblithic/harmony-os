// SPDX-License-Identifier: GPL-2.0-or-later
//! VirtIO 1.0 split virtqueue implementation with static buffer pool.
//!
//! Implements the split virtqueue layout described in VirtIO 1.0 §2.6,
//! using a fixed-size descriptor table and pre-allocated packet buffers.

use alloc::alloc::{alloc_zeroed, Layout};
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{fence, Ordering};

/// Number of descriptors in each virtqueue (must be a power of 2).
pub const QUEUE_SIZE: u16 = 32;

/// Size of each pre-allocated packet buffer in bytes.
pub const BUF_SIZE: usize = 2048;

/// Descriptor flag: buffer is device-writable (host reads, device writes).
pub const VIRTQ_DESC_F_WRITE: u16 = 2;

// ---------------------------------------------------------------------------
// VirtIO ring structures (§2.6)
// ---------------------------------------------------------------------------

/// Virtqueue descriptor entry (§2.6.5).
#[repr(C)]
pub struct VirtqDesc {
    /// Physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// Descriptor flags (`VIRTQ_DESC_F_*`).
    pub flags: u16,
    /// Index of the next descriptor if `VIRTQ_DESC_F_NEXT` is set.
    pub next: u16,
}

/// Available ring — guest populates, device consumes (§2.6.6).
#[repr(C)]
pub struct VirtqAvail {
    /// Flags (currently unused, set to 0).
    pub flags: u16,
    /// Index of the next entry the guest will write.
    pub idx: u16,
    /// Ring of descriptor chain head indices.
    pub ring: [u16; QUEUE_SIZE as usize],
    /// Used event index (§2.6.7) — always present, only meaningful when
    /// `VIRTIO_F_EVENT_IDX` is negotiated.
    pub used_event: u16,
}

/// Element in the used ring, written by the device.
#[repr(C)]
pub struct VirtqUsedElem {
    /// Index of the descriptor chain head that was consumed.
    pub id: u32,
    /// Number of bytes written into the descriptor chain's buffers.
    pub len: u32,
}

/// Used ring — device populates, guest consumes (§2.6.8).
#[repr(C)]
pub struct VirtqUsed {
    /// Flags (currently unused).
    pub flags: u16,
    /// Index of the next entry the device will write.
    pub idx: u16,
    /// Ring of used elements.
    pub ring: [VirtqUsedElem; QUEUE_SIZE as usize],
    /// Available event index (§2.6.8) — always present, only meaningful when
    /// `VIRTIO_F_EVENT_IDX` is negotiated.
    pub avail_event: u16,
}

// ---------------------------------------------------------------------------
// Virtqueue
// ---------------------------------------------------------------------------

/// A VirtIO split virtqueue backed by a static buffer pool.
///
/// The queue owns heap-allocated descriptor table, available ring, used ring,
/// and a contiguous buffer region. Physical addresses are derived by
/// subtracting the bootloader's physical memory offset from virtual addresses.
pub struct Virtqueue {
    /// Virtual pointer to the descriptor table.
    pub desc: *mut VirtqDesc,
    /// Virtual pointer to the available ring.
    pub avail: *mut VirtqAvail,
    /// Virtual pointer to the used ring.
    pub used: *mut VirtqUsed,
    /// Virtual pointer to the contiguous buffer region.
    pub buffers: *mut u8,

    /// Physical address of the descriptor table.
    pub desc_phys: u64,
    /// Physical address of the available ring.
    pub avail_phys: u64,
    /// Physical address of the used ring.
    pub used_phys: u64,
    /// Physical address of the buffer region.
    pub buffers_phys: u64,

    /// Negotiated queue size (may be smaller than `QUEUE_SIZE`).
    queue_size: u16,
    /// Tracks the last used ring index we processed.
    last_used_idx: u16,
    /// Per-descriptor free/allocated state.
    free: [bool; QUEUE_SIZE as usize],
}

impl Virtqueue {
    /// Allocate and initialise a new split virtqueue.
    ///
    /// # Arguments
    ///
    /// * `phys_offset` — The kernel's physical-to-virtual offset provided by
    ///   the bootloader. Virtual addresses are converted to physical by
    ///   subtracting this value.
    ///
    /// # Panics
    ///
    /// Panics if any of the heap allocations fail.
    pub fn new(phys_offset: u64) -> Self {
        // Allocate each region with the alignment required by the VirtIO spec.
        let desc_layout =
            Layout::from_size_align(core::mem::size_of::<VirtqDesc>() * QUEUE_SIZE as usize, 16)
                .unwrap();

        let avail_layout = Layout::from_size_align(core::mem::size_of::<VirtqAvail>(), 2).unwrap();

        let used_layout = Layout::from_size_align(core::mem::size_of::<VirtqUsed>(), 4).unwrap();

        let buffers_layout = Layout::from_size_align(BUF_SIZE * QUEUE_SIZE as usize, 4096).unwrap();

        let desc = unsafe { alloc_zeroed(desc_layout) } as *mut VirtqDesc;
        let avail = unsafe { alloc_zeroed(avail_layout) } as *mut VirtqAvail;
        let used = unsafe { alloc_zeroed(used_layout) } as *mut VirtqUsed;
        let buffers = unsafe { alloc_zeroed(buffers_layout) };

        assert!(!desc.is_null(), "virtqueue: desc allocation failed");
        assert!(!avail.is_null(), "virtqueue: avail allocation failed");
        assert!(!used.is_null(), "virtqueue: used allocation failed");
        assert!(!buffers.is_null(), "virtqueue: buffers allocation failed");

        let desc_phys = desc as u64 - phys_offset;
        let avail_phys = avail as u64 - phys_offset;
        let used_phys = used as u64 - phys_offset;
        let buffers_phys = buffers as u64 - phys_offset;

        Virtqueue {
            desc,
            avail,
            used,
            buffers,
            desc_phys,
            avail_phys,
            used_phys,
            buffers_phys,
            queue_size: QUEUE_SIZE,
            last_used_idx: 0,
            free: [true; QUEUE_SIZE as usize],
        }
    }

    /// Set the negotiated queue size. Must be called before any ring
    /// operations if the device reports a size smaller than `QUEUE_SIZE`.
    pub fn set_queue_size(&mut self, size: u16) {
        self.queue_size = size;
    }

    /// Allocate the first free descriptor, returning its index.
    ///
    /// Returns `None` if all descriptors are in use.
    pub fn alloc_desc(&mut self) -> Option<u16> {
        for i in 0..self.queue_size as usize {
            if self.free[i] {
                self.free[i] = false;
                return Some(i as u16);
            }
        }
        None
    }

    /// Return a descriptor to the free pool.
    pub fn free_desc(&mut self, idx: u16) {
        if (idx as usize) < QUEUE_SIZE as usize {
            self.free[idx as usize] = true;
        }
    }

    /// Return a pointer to the buffer for descriptor `idx`.
    fn buffer_ptr(&self, idx: u16) -> *mut u8 {
        unsafe { self.buffers.add(idx as usize * BUF_SIZE) }
    }

    /// Return the physical address of the buffer for descriptor `idx`.
    fn buffer_phys(&self, idx: u16) -> u64 {
        self.buffers_phys + (idx as u64 * BUF_SIZE as u64)
    }

    /// Post a receive buffer: allocate a descriptor, configure it as
    /// device-writable, and add it to the available ring.
    ///
    /// Returns the descriptor index on success, or `None` if no descriptors
    /// are free.
    pub fn post_receive(&mut self) -> Option<u16> {
        let idx = self.alloc_desc()?;

        unsafe {
            // Volatile writes for descriptor table — device reads via DMA.
            let desc = self.desc.add(idx as usize);
            ptr::write_volatile(&raw mut (*desc).addr, self.buffer_phys(idx));
            ptr::write_volatile(&raw mut (*desc).len, BUF_SIZE as u32);
            ptr::write_volatile(&raw mut (*desc).flags, VIRTQ_DESC_F_WRITE);
            ptr::write_volatile(&raw mut (*desc).next, 0);

            // Volatile writes for avail ring — device reads via DMA.
            let avail_idx = ptr::read_volatile(&(*self.avail).idx);
            let ring_slot = &mut (*self.avail).ring[(avail_idx % self.queue_size) as usize];
            ptr::write_volatile(ring_slot, idx);

            // Ensure descriptor writes are visible before the device sees
            // the updated available index.
            fence(Ordering::Release);
            ptr::write_volatile(&mut (*self.avail).idx, avail_idx.wrapping_add(1));
        }

        Some(idx)
    }

    /// Submit a send buffer: allocate a descriptor, copy `data` into its
    /// buffer, configure it as device-readable, and add to the available ring.
    ///
    /// Returns the descriptor index on success, or `None` if no descriptors
    /// are free or `data` exceeds `BUF_SIZE`.
    ///
    /// Note: [`prepare_send`]/[`commit_send`] is preferred for new code —
    /// it avoids the intermediate copy. This method is retained as a
    /// convenience for callers that already have a complete buffer.
    #[allow(dead_code)]
    pub fn submit_send(&mut self, data: &[u8]) -> Option<u16> {
        if data.len() > BUF_SIZE {
            return None;
        }

        let idx = self.alloc_desc()?;

        unsafe {
            let buf = self.buffer_ptr(idx);
            ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len());

            // Volatile writes for descriptor table — device reads via DMA.
            let desc = self.desc.add(idx as usize);
            ptr::write_volatile(&raw mut (*desc).addr, self.buffer_phys(idx));
            ptr::write_volatile(&raw mut (*desc).len, data.len() as u32);
            ptr::write_volatile(&raw mut (*desc).flags, 0u16);
            ptr::write_volatile(&raw mut (*desc).next, 0u16);

            // Volatile writes for avail ring — device reads via DMA.
            let avail_idx = ptr::read_volatile(&(*self.avail).idx);
            let ring_slot = &mut (*self.avail).ring[(avail_idx % self.queue_size) as usize];
            ptr::write_volatile(ring_slot, idx);

            // Ensure descriptor + data writes are visible before the device
            // sees the updated available index.
            fence(Ordering::Release);
            ptr::write_volatile(&mut (*self.avail).idx, avail_idx.wrapping_add(1));
        }

        Some(idx)
    }

    /// Allocate a TX descriptor and return a raw pointer to its DMA buffer.
    ///
    /// The caller writes frame data directly into the returned buffer, then
    /// calls [`commit_send`] to finalize. This avoids the intermediate copy
    /// that [`submit_send`] performs.
    ///
    /// Returns `(desc_idx, buffer_ptr)` or `None` if no descriptors are free.
    ///
    /// # Safety contract
    ///
    /// The caller must:
    /// - Write at most `BUF_SIZE` bytes through the returned pointer
    /// - Call `commit_send(idx, len)` exactly once after writing
    pub fn prepare_send(&mut self) -> Option<(u16, *mut u8)> {
        let idx = self.alloc_desc()?;
        Some((idx, self.buffer_ptr(idx)))
    }

    /// Finalize a TX send started by [`prepare_send`].
    ///
    /// Writes the descriptor table entry and adds the descriptor to the
    /// available ring so the device can consume it.
    ///
    /// # Arguments
    ///
    /// * `idx` — Descriptor index returned by `prepare_send`.
    /// * `len` — Number of bytes written into the buffer.
    pub fn commit_send(&mut self, idx: u16, len: usize) {
        debug_assert!(
            (idx as usize) < QUEUE_SIZE as usize,
            "commit_send: idx out of range"
        );
        debug_assert!(len <= BUF_SIZE, "commit_send: len exceeds BUF_SIZE");
        unsafe {
            // Volatile writes for descriptor table — device reads via DMA.
            let desc = self.desc.add(idx as usize);
            ptr::write_volatile(&raw mut (*desc).addr, self.buffer_phys(idx));
            ptr::write_volatile(&raw mut (*desc).len, len as u32);
            ptr::write_volatile(&raw mut (*desc).flags, 0u16);
            ptr::write_volatile(&raw mut (*desc).next, 0u16);

            // Volatile writes for avail ring — device reads via DMA.
            let avail_idx = ptr::read_volatile(&(*self.avail).idx);
            let ring_slot = &mut (*self.avail).ring[(avail_idx % self.queue_size) as usize];
            ptr::write_volatile(ring_slot, idx);

            // Ensure descriptor + data writes are visible before the device
            // sees the updated available index.
            fence(Ordering::Release);
            ptr::write_volatile(&mut (*self.avail).idx, avail_idx.wrapping_add(1));
        }
    }

    /// Poll the used ring for completed descriptors.
    ///
    /// Returns `Some((desc_id, bytes_written))` if the device has placed a
    /// new entry in the used ring, or `None` if no new entries are available.
    pub fn poll_used(&mut self) -> Option<(u16, u32)> {
        // Ensure we see the latest used.idx written by the device.
        fence(Ordering::Acquire);

        // Volatile read: device writes used.idx via DMA.
        let used_idx = unsafe { ptr::read_volatile(&(*self.used).idx) };

        if self.last_used_idx == used_idx {
            return None;
        }

        // Volatile reads: device writes used ring entries via DMA.
        let (raw_id, len) = unsafe {
            let ring_idx = (self.last_used_idx % self.queue_size) as usize;
            let elem = &(*self.used).ring[ring_idx];
            (ptr::read_volatile(&elem.id), ptr::read_volatile(&elem.len))
        };

        self.last_used_idx = self.last_used_idx.wrapping_add(1);

        // Validate device-provided descriptor id is in range.
        // If invalid, we skip this entry (last_used_idx already advanced).
        // The original descriptor leaks, but we can't free it safely
        // because the device-provided id is garbage. This can only happen
        // with misbehaving firmware — not possible on QEMU.
        if raw_id >= self.queue_size as u32 {
            return None;
        }

        Some((raw_id as u16, len))
    }

    /// Copy `len` bytes from the buffer associated with `desc_idx` into a
    /// new `Vec<u8>`.
    ///
    /// # Panics
    ///
    /// Panics if `len` exceeds `BUF_SIZE`. Callers should clamp `len`
    /// before calling to defend against misbehaving devices.
    pub fn read_buffer(&self, desc_idx: u16, len: u32) -> Vec<u8> {
        let len = len as usize;
        assert!(len <= BUF_SIZE, "read_buffer: len exceeds BUF_SIZE");

        let mut out = alloc::vec![0u8; len];
        unsafe {
            let src = self.buffer_ptr(desc_idx);
            ptr::copy_nonoverlapping(src, out.as_mut_ptr(), len);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a Virtqueue for testing.
    /// Uses phys_offset=0 so virtual == physical addresses.
    fn test_queue() -> Virtqueue {
        Virtqueue::new(0)
    }

    #[test]
    fn prepare_send_returns_valid_index_and_pointer() {
        let mut vq = test_queue();
        let (idx, ptr) = vq.prepare_send().expect("should allocate");
        assert!(idx < QUEUE_SIZE);
        assert!(!ptr.is_null());
    }

    #[test]
    fn prepare_send_exhaustion_returns_none() {
        let mut vq = test_queue();
        // Allocate all descriptors.
        for _ in 0..QUEUE_SIZE {
            assert!(vq.prepare_send().is_some());
        }
        // Next one should fail.
        assert!(vq.prepare_send().is_none());
    }

    #[test]
    fn prepare_commit_sets_descriptor_metadata() {
        let mut vq = test_queue();
        let (idx, buf_ptr) = vq.prepare_send().expect("should allocate");

        // Write known bytes into the DMA buffer via the raw pointer.
        let test_data = b"hello DMA";
        unsafe {
            core::ptr::copy_nonoverlapping(
                test_data.as_ptr(),
                buf_ptr,
                test_data.len(),
            );
        }

        vq.commit_send(idx, test_data.len());

        // Verify the descriptor table entry.
        unsafe {
            let desc = vq.desc.add(idx as usize);
            let addr = core::ptr::read_volatile(&(*desc).addr);
            let len = core::ptr::read_volatile(&(*desc).len);
            let flags = core::ptr::read_volatile(&(*desc).flags);

            // With phys_offset=0, buffer_phys == buffer_ptr as u64.
            assert_eq!(addr, vq.buffer_phys(idx));
            assert_eq!(len, test_data.len() as u32);
            assert_eq!(flags, 0); // device-readable (TX)
        }

        // Verify the available ring was advanced.
        unsafe {
            let avail_idx = core::ptr::read_volatile(&(*vq.avail).idx);
            assert_eq!(avail_idx, 1);
        }
    }
}
