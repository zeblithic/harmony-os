// SPDX-License-Identifier: GPL-2.0-or-later

//! VirtIO 1.2 split virtqueue operating on caller-provided shared memory.
//!
//! Implements the split virtqueue as described in VirtIO 1.2 §2.7.6 and §2.7.8.
//! All memory access is performed on a caller-supplied `&[u8]` / `&mut [u8]` slice,
//! making this suitable for `no_std` hypervisor and unikernel contexts.

pub const MAX_QUEUE_SIZE: u16 = 256;
const DESC_SIZE: usize = 16;

pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;
pub const VRING_DESC_F_INDIRECT: u16 = 4;
pub const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;

// ── little-endian memory helpers ────────────────────────────────────────────

fn read_u16(mem: &[u8], offset: usize) -> u16 {
    let bytes = [mem[offset], mem[offset + 1]];
    u16::from_le_bytes(bytes)
}

fn write_u16(mem: &mut [u8], offset: usize, val: u16) {
    let bytes = val.to_le_bytes();
    mem[offset] = bytes[0];
    mem[offset + 1] = bytes[1];
}

fn read_u32(mem: &[u8], offset: usize) -> u32 {
    let bytes = [
        mem[offset],
        mem[offset + 1],
        mem[offset + 2],
        mem[offset + 3],
    ];
    u32::from_le_bytes(bytes)
}

fn write_u32(mem: &mut [u8], offset: usize, val: u32) {
    let bytes = val.to_le_bytes();
    mem[offset] = bytes[0];
    mem[offset + 1] = bytes[1];
    mem[offset + 2] = bytes[2];
    mem[offset + 3] = bytes[3];
}

fn read_u64(mem: &[u8], offset: usize) -> u64 {
    let bytes = [
        mem[offset],
        mem[offset + 1],
        mem[offset + 2],
        mem[offset + 3],
        mem[offset + 4],
        mem[offset + 5],
        mem[offset + 6],
        mem[offset + 7],
    ];
    u64::from_le_bytes(bytes)
}

// ── public types ─────────────────────────────────────────────────────────────

/// A parsed VirtIO descriptor table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

/// Iterator over a descriptor chain in shared memory.
pub struct DescriptorChain {
    head: u16,
    next: Option<u16>,
    queue_size: u16,
    desc_offset: usize,
    hops: u16,
}

impl DescriptorChain {
    /// Returns the index of the head descriptor for this chain.
    pub fn head_id(&self) -> u16 {
        self.head
    }

    /// Reads and returns the next descriptor in the chain.
    ///
    /// Returns `Ok(None)` when the chain is exhausted, `Err` on invalid chain.
    pub fn next(&mut self, mem: &[u8]) -> Result<Option<Descriptor>, VirtQueueError> {
        let next_idx = match self.next {
            None => return Ok(None),
            Some(idx) => idx,
        };

        if self.hops >= self.queue_size {
            return Err(VirtQueueError::ChainTooLong);
        }

        let base = self.desc_offset + (next_idx as usize) * DESC_SIZE;
        let addr = read_u64(mem, base);
        let len = read_u32(mem, base + 8);
        let flags = read_u16(mem, base + 12);
        let next_field = read_u16(mem, base + 14);

        if flags & VRING_DESC_F_INDIRECT != 0 {
            return Err(VirtQueueError::IndirectNotSupported);
        }

        let desc = Descriptor {
            addr,
            len,
            flags,
            next: next_field,
        };

        if flags & VRING_DESC_F_NEXT != 0 {
            self.next = Some(next_field);
        } else {
            self.next = None;
        }

        self.hops += 1;
        Ok(Some(desc))
    }
}

/// A VirtIO 1.2 split virtqueue.
///
/// All state is in this struct; the shared memory buffer is passed in on each
/// operation so the caller retains full control of the memory region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtQueue {
    queue_size: u16,
    desc_offset: usize,
    avail_offset: usize,
    used_offset: usize,
    last_avail_idx: u16,
}

/// Errors that can arise when constructing or operating a `VirtQueue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VirtQueueError {
    /// The requested queue size is not a power of two or exceeds `MAX_QUEUE_SIZE`.
    InvalidQueueSize(u16),
    /// The shared memory region is too small for the requested layout.
    RegionTooSmall { needed: usize, available: usize },
    /// Indirect descriptors are not supported by this implementation.
    IndirectNotSupported,
    /// A descriptor chain contains more links than `queue_size` allows.
    ChainTooLong,
}

impl VirtQueue {
    /// Construct a new `VirtQueue` with the given layout.
    ///
    /// # Errors
    ///
    /// - `InvalidQueueSize` if `queue_size` is 0, not a power of two, or > 256.
    /// - `RegionTooSmall` if any of the three ring regions extends past `region_len`.
    pub fn new(
        queue_size: u16,
        desc_offset: usize,
        avail_offset: usize,
        used_offset: usize,
        region_len: usize,
    ) -> Result<Self, VirtQueueError> {
        if queue_size == 0 || !queue_size.is_power_of_two() || queue_size > MAX_QUEUE_SIZE {
            return Err(VirtQueueError::InvalidQueueSize(queue_size));
        }

        let qs = queue_size as usize;

        // Descriptor table: 16 bytes × queue_size
        let desc_end = desc_offset.saturating_add(qs * DESC_SIZE);
        if desc_end > region_len {
            return Err(VirtQueueError::RegionTooSmall {
                needed: desc_end,
                available: region_len,
            });
        }

        // Available ring: flags(2) + idx(2) + ring[queue_size](2 each) + used_event(2)
        let avail_size = 6 + 2 * qs;
        let avail_end = avail_offset.saturating_add(avail_size);
        if avail_end > region_len {
            return Err(VirtQueueError::RegionTooSmall {
                needed: avail_end,
                available: region_len,
            });
        }

        // Used ring: flags(2) + idx(2) + ring[queue_size](8 each) + avail_event(2)
        let used_size = 6 + 8 * qs;
        let used_end = used_offset.saturating_add(used_size);
        if used_end > region_len {
            return Err(VirtQueueError::RegionTooSmall {
                needed: used_end,
                available: region_len,
            });
        }

        Ok(Self {
            queue_size,
            desc_offset,
            avail_offset,
            used_offset,
            last_avail_idx: 0,
        })
    }

    /// Pop the next available descriptor chain from the available ring.
    ///
    /// Returns `None` when the available ring has no new entries.
    pub fn pop_available(&mut self, mem: &[u8]) -> Option<(u16, DescriptorChain)> {
        let avail_idx = read_u16(mem, self.avail_offset + 2);
        if avail_idx == self.last_avail_idx {
            return None;
        }

        let ring_slot = (self.last_avail_idx % self.queue_size) as usize;
        let desc_head = read_u16(mem, self.avail_offset + 4 + ring_slot * 2);

        self.last_avail_idx = self.last_avail_idx.wrapping_add(1);

        let chain = DescriptorChain {
            head: desc_head,
            next: Some(desc_head),
            queue_size: self.queue_size,
            desc_offset: self.desc_offset,
            hops: 0,
        };

        Some((desc_head, chain))
    }

    /// Push a completed descriptor chain into the used ring.
    pub fn push_used(&self, mem: &mut [u8], desc_id: u16, bytes_written: u32) {
        let used_idx = read_u16(mem, self.used_offset + 2);
        let slot = (used_idx % self.queue_size) as usize;
        let entry_offset = self.used_offset + 4 + slot * 8;

        write_u32(mem, entry_offset, desc_id as u32);
        write_u32(mem, entry_offset + 4, bytes_written);
        write_u16(mem, self.used_offset + 2, used_idx.wrapping_add(1));
    }

    /// Returns `true` if the driver should be notified after `push_used`.
    ///
    /// Checks the `VRING_AVAIL_F_NO_INTERRUPT` flag in the available ring.
    pub fn needs_notification(&self, mem: &[u8]) -> bool {
        let avail_flags = read_u16(mem, self.avail_offset);
        avail_flags & VRING_AVAIL_F_NO_INTERRUPT == 0
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── test memory layout helpers ───────────────────────────────────────────

    /// Write a descriptor table entry at `desc_offset + idx * 16`.
    fn write_descriptor(
        mem: &mut [u8],
        desc_offset: usize,
        idx: u16,
        addr: u64,
        len: u32,
        flags: u16,
        next: u16,
    ) {
        let base = desc_offset + idx as usize * DESC_SIZE;
        let addr_bytes = addr.to_le_bytes();
        mem[base..base + 8].copy_from_slice(&addr_bytes);
        write_u32(mem, base + 8, len);
        write_u16(mem, base + 12, flags);
        write_u16(mem, base + 14, next);
    }

    /// Write one entry into the available ring's `ring[]` array and advance `idx`.
    ///
    /// `avail_idx` is the current value of the available ring's `idx` field
    /// (i.e., how many entries have already been published). This function
    /// writes `desc_idx` into `ring[avail_idx % queue_size]` and stores
    /// `avail_idx + 1` into the ring's `idx` field.
    fn write_avail_entry(
        mem: &mut [u8],
        avail_offset: usize,
        queue_size: u16,
        avail_idx: u16,
        desc_idx: u16,
    ) {
        let slot = (avail_idx % queue_size) as usize;
        write_u16(mem, avail_offset + 4 + slot * 2, desc_idx);
        write_u16(mem, avail_offset + 2, avail_idx.wrapping_add(1));
    }

    // ── standard layout for tests ────────────────────────────────────────────

    const QUEUE_SIZE: u16 = 4;
    const DESC_OFF: usize = 0;
    // avail ring: 4 * 16 = 64 bytes for descriptors
    const AVAIL_OFF: usize = 64;
    // avail ring size = 6 + 2*4 = 14; used ring starts at 64+14=78, round up to 80
    const USED_OFF: usize = 80;
    // used ring size = 6 + 8*4 = 38; total needed = 80+38 = 118
    const MEM_LEN: usize = 256;

    fn make_queue() -> VirtQueue {
        VirtQueue::new(QUEUE_SIZE, DESC_OFF, AVAIL_OFF, USED_OFF, MEM_LEN).unwrap()
    }

    // ── test 1 ───────────────────────────────────────────────────────────────

    #[test]
    fn new_rejects_non_power_of_2() {
        let result = VirtQueue::new(3, 0, 64, 80, 512);
        assert_eq!(result, Err(VirtQueueError::InvalidQueueSize(3)));
    }

    // ── test 2 ───────────────────────────────────────────────────────────────

    #[test]
    fn new_rejects_zero() {
        let result = VirtQueue::new(0, 0, 64, 80, 512);
        assert_eq!(result, Err(VirtQueueError::InvalidQueueSize(0)));
    }

    // ── test 3 ───────────────────────────────────────────────────────────────

    #[test]
    fn new_rejects_overflow() {
        // desc table alone would be 256 * 16 = 4096 bytes; use a 10-byte region
        let result = VirtQueue::new(16, 0, 256, 512, 10);
        assert!(matches!(result, Err(VirtQueueError::RegionTooSmall { .. })));
    }

    // ── test 4 ───────────────────────────────────────────────────────────────

    #[test]
    fn pop_available_empty() {
        let mut vq = make_queue();
        let mem = [0u8; MEM_LEN];
        assert!(vq.pop_available(&mem).is_none());
    }

    // ── test 5 ───────────────────────────────────────────────────────────────

    #[test]
    fn pop_available_single() {
        let mut mem = [0u8; MEM_LEN];
        write_descriptor(&mut mem, DESC_OFF, 0, 0x1000, 64, 0, 0);
        write_avail_entry(&mut mem, AVAIL_OFF, QUEUE_SIZE, 0, 0);

        let mut vq = make_queue();
        let (head, mut chain) = vq.pop_available(&mem).expect("should have entry");
        assert_eq!(head, 0);
        assert_eq!(chain.head_id(), 0);

        let desc = chain.next(&mem).unwrap().expect("should have descriptor");
        assert_eq!(desc.addr, 0x1000);
        assert_eq!(desc.len, 64);
        assert_eq!(desc.flags, 0);

        let end = chain.next(&mem).unwrap();
        assert!(end.is_none());
    }

    // ── test 6 ───────────────────────────────────────────────────────────────

    #[test]
    fn pop_available_chained() {
        let mut mem = [0u8; MEM_LEN];
        // desc 0 → desc 1 (NEXT flag), desc 1 has no NEXT
        write_descriptor(&mut mem, DESC_OFF, 0, 0x1000, 32, VRING_DESC_F_NEXT, 1);
        write_descriptor(&mut mem, DESC_OFF, 1, 0x2000, 48, VRING_DESC_F_WRITE, 0);
        write_avail_entry(&mut mem, AVAIL_OFF, QUEUE_SIZE, 0, 0);

        let mut vq = make_queue();
        let (_head, mut chain) = vq.pop_available(&mem).unwrap();

        let d0 = chain.next(&mem).unwrap().unwrap();
        assert_eq!(d0.addr, 0x1000);
        assert_eq!(d0.len, 32);
        assert!(d0.flags & VRING_DESC_F_NEXT != 0);

        let d1 = chain.next(&mem).unwrap().unwrap();
        assert_eq!(d1.addr, 0x2000);
        assert_eq!(d1.len, 48);
        assert!(d1.flags & VRING_DESC_F_WRITE != 0);

        let end = chain.next(&mem).unwrap();
        assert!(end.is_none());
    }

    // ── test 7 ───────────────────────────────────────────────────────────────

    #[test]
    fn push_used_updates_ring() {
        let mut mem = [0u8; MEM_LEN];
        let vq = make_queue();

        vq.push_used(&mut mem, 2, 100);

        // used_idx should be 1
        let used_idx = read_u16(&mem, USED_OFF + 2);
        assert_eq!(used_idx, 1);

        // entry 0: id=2, len=100
        let id = read_u32(&mem, USED_OFF + 4);
        let len = read_u32(&mem, USED_OFF + 8);
        assert_eq!(id, 2);
        assert_eq!(len, 100);
    }

    // ── test 8 ───────────────────────────────────────────────────────────────

    #[test]
    fn pop_push_roundtrip() {
        let mut mem = [0u8; MEM_LEN];
        write_descriptor(&mut mem, DESC_OFF, 0, 0xDEAD, 16, 0, 0);
        write_avail_entry(&mut mem, AVAIL_OFF, QUEUE_SIZE, 0, 0);

        let mut vq = make_queue();
        let (head, _chain) = vq.pop_available(&mem).unwrap();

        // Nothing more in the ring
        assert!(vq.pop_available(&mem).is_none());

        vq.push_used(&mut mem, head, 16);

        let used_idx = read_u16(&mem, USED_OFF + 2);
        assert_eq!(used_idx, 1);
        let id = read_u32(&mem, USED_OFF + 4);
        assert_eq!(id, head as u32);
    }

    // ── test 9 ───────────────────────────────────────────────────────────────

    #[test]
    fn chain_too_long_detected() {
        let mut mem = [0u8; MEM_LEN];
        // Create a circular chain: desc 0 → desc 1 → desc 0 → …
        write_descriptor(&mut mem, DESC_OFF, 0, 0x1000, 8, VRING_DESC_F_NEXT, 1);
        write_descriptor(&mut mem, DESC_OFF, 1, 0x2000, 8, VRING_DESC_F_NEXT, 0);
        write_avail_entry(&mut mem, AVAIL_OFF, QUEUE_SIZE, 0, 0);

        let mut vq = make_queue();
        let (_head, mut chain) = vq.pop_available(&mem).unwrap();

        // Walk the chain until we get ChainTooLong
        let mut got_error = false;
        for _ in 0..(QUEUE_SIZE as usize + 4) {
            match chain.next(&mem) {
                Err(VirtQueueError::ChainTooLong) => {
                    got_error = true;
                    break;
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(e) => panic!("unexpected error: {:?}", e),
            }
        }
        assert!(got_error, "expected ChainTooLong error");
    }

    // ── test 10 ──────────────────────────────────────────────────────────────

    #[test]
    fn indirect_rejected() {
        let mut mem = [0u8; MEM_LEN];
        write_descriptor(&mut mem, DESC_OFF, 0, 0x5000, 32, VRING_DESC_F_INDIRECT, 0);
        write_avail_entry(&mut mem, AVAIL_OFF, QUEUE_SIZE, 0, 0);

        let mut vq = make_queue();
        let (_head, mut chain) = vq.pop_available(&mem).unwrap();

        let result = chain.next(&mem);
        assert_eq!(result, Err(VirtQueueError::IndirectNotSupported));
    }

    // ── test 11 ──────────────────────────────────────────────────────────────

    #[test]
    fn index_wrapping() {
        let mut mem = [0u8; MEM_LEN];

        // Start with last_avail_idx near u16::MAX
        let start_idx = u16::MAX - 1;

        // We need to set last_avail_idx on the queue; construct it and then
        // manually drive it by writing avail entries and popping.
        // Write descriptors 0 and 1
        write_descriptor(&mut mem, DESC_OFF, 0, 0xAAAA, 8, 0, 0);
        write_descriptor(&mut mem, DESC_OFF, 1, 0xBBBB, 8, 0, 0);

        // Place two entries at ring slots corresponding to start_idx and start_idx+1
        // ring slot = avail_idx % queue_size
        let slot0 = (start_idx % QUEUE_SIZE) as usize;
        let slot1 = (start_idx.wrapping_add(1) % QUEUE_SIZE) as usize;
        write_u16(&mut mem, AVAIL_OFF + 4 + slot0 * 2, 0);
        write_u16(&mut mem, AVAIL_OFF + 4 + slot1 * 2, 1);
        // Set avail ring idx = start_idx + 2
        write_u16(&mut mem, AVAIL_OFF + 2, start_idx.wrapping_add(2));

        // Build a VirtQueue and fast-forward last_avail_idx to start_idx by
        // constructing it directly.
        let mut vq = VirtQueue {
            queue_size: QUEUE_SIZE,
            desc_offset: DESC_OFF,
            avail_offset: AVAIL_OFF,
            used_offset: USED_OFF,
            last_avail_idx: start_idx,
        };

        let (h0, _) = vq.pop_available(&mem).expect("first pop");
        assert_eq!(h0, 0);

        let (h1, _) = vq.pop_available(&mem).expect("second pop (wrapping)");
        assert_eq!(h1, 1);

        assert!(vq.pop_available(&mem).is_none());
        assert_eq!(vq.last_avail_idx, start_idx.wrapping_add(2));
    }
}
