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

/// Descriptor flag: buffer continues via the `next` field.
pub const VIRTQ_DESC_F_NEXT: u16 = 1;

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
        self.free[idx as usize] = true;
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
            let desc = &mut *self.desc.add(idx as usize);
            desc.addr = self.buffer_phys(idx);
            desc.len = BUF_SIZE as u32;
            desc.flags = VIRTQ_DESC_F_WRITE;
            desc.next = 0;

            // Use volatile for avail ring since the device reads it via DMA.
            let avail_idx = ptr::read_volatile(&(*self.avail).idx);
            (*self.avail).ring[(avail_idx % self.queue_size) as usize] = idx;

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
    pub fn submit_send(&mut self, data: &[u8]) -> Option<u16> {
        if data.len() > BUF_SIZE {
            return None;
        }

        let idx = self.alloc_desc()?;

        unsafe {
            let buf = self.buffer_ptr(idx);
            ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len());

            let desc = &mut *self.desc.add(idx as usize);
            desc.addr = self.buffer_phys(idx);
            desc.len = data.len() as u32;
            desc.flags = 0; // device-readable
            desc.next = 0;

            // Use volatile for avail ring since the device reads it via DMA.
            let avail_idx = ptr::read_volatile(&(*self.avail).idx);
            (*self.avail).ring[(avail_idx % self.queue_size) as usize] = idx;

            // Ensure descriptor + data writes are visible before the device
            // sees the updated available index.
            fence(Ordering::Release);
            ptr::write_volatile(&mut (*self.avail).idx, avail_idx.wrapping_add(1));
        }

        Some(idx)
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
            (
                ptr::read_volatile(&elem.id),
                ptr::read_volatile(&elem.len),
            )
        };

        self.last_used_idx = self.last_used_idx.wrapping_add(1);

        // Validate device-provided descriptor id is in range.
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
