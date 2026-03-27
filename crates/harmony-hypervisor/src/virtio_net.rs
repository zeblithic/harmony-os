// SPDX-License-Identifier: GPL-2.0-or-later

//! VirtIO-net device: TX/RX packet operations on top of VirtIO MMIO transport.
//!
//! Wraps a `VirtioMmio` transport with two `VirtQueue` instances (RX=0, TX=1).
//! Packet data lives in shared memory that the caller manages; this module
//! performs only virtqueue bookkeeping and a minimal virtio-net header
//! read/write.  All actual I/O is performed through caller-provided function
//! pointers, keeping the implementation suitable for `no_std` contexts.

use crate::trap::AccessType;
use crate::virtio_mmio::{
    MmioResponse, QueueConfig, VirtioMmio, VIRTIO_F_VERSION_1, VIRTIO_NET_F_MAC,
    VIRTIO_NET_F_STATUS,
};
use crate::virtqueue::VirtQueue;

// ── virtio-net header ─────────────────────────────────────────────────────────

/// Size of the `virtio_net_hdr` structure prepended to every RX/TX buffer.
pub const VIRTIO_NET_HDR_SIZE: usize = 12;

/// virtio-net header as defined in VirtIO 1.2 §5.1.6.
#[repr(C)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    /// Set to 1 on RX; ignored on TX.
    pub num_buffers: u16,
}

// ── device ────────────────────────────────────────────────────────────────────

/// A VirtIO-net device backed by a `VirtioMmio` transport.
///
/// `rx_queue` and `tx_queue` are populated lazily the first time
/// `ensure_queues` is called after the guest driver marks a queue ready.
pub struct VirtioNetDevice {
    pub mmio: VirtioMmio,
    pub mac: [u8; 6],
    rx_queue: Option<VirtQueue>,
    tx_queue: Option<VirtQueue>,
}

impl VirtioNetDevice {
    /// Create a new VirtIO-net device with the given MAC address.
    ///
    /// Feature bits `VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS | VIRTIO_F_VERSION_1`
    /// are advertised automatically.
    pub fn new(mac: [u8; 6]) -> Self {
        let features = VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS | VIRTIO_F_VERSION_1;
        Self {
            mmio: VirtioMmio::new(1, features, mac),
            mac,
            rx_queue: None,
            tx_queue: None,
        }
    }

    /// Construct `VirtQueue` objects for any queue that the driver has marked
    /// ready but that we have not yet instantiated.
    ///
    /// Called at the start of every `poll_tx` / `push_rx` so the queues are
    /// created as soon as the driver finishes setup, without requiring a
    /// separate "driver-ok" callback.
    pub fn ensure_queues(&mut self, region_base_ipa: u64, region_len: usize) {
        if self.rx_queue.is_none() {
            self.rx_queue = try_make_queue(&self.mmio.queues[0], region_base_ipa, region_len);
        }
        if self.tx_queue.is_none() {
            self.tx_queue = try_make_queue(&self.mmio.queues[1], region_base_ipa, region_len);
        }
    }

    /// Attempt to dequeue one packet from the TX virtqueue.
    ///
    /// The `ipa_to_ptr` callback translates a guest IPA (descriptor `addr`
    /// field) to a host pointer from which the descriptor's bytes may be read.
    ///
    /// # Returns
    ///
    /// `Some(n)` where `n` is the number of bytes written into `out_buf`
    /// (frame bytes only, virtio-net header stripped), or `None` if no packet
    /// was available or no TX queue has been configured yet.
    ///
    /// # Safety (internal)
    ///
    /// Descriptor `addr` values come from untrusted guest memory.  The caller
    /// is responsible for supplying an `ipa_to_ptr` that returns a valid
    /// pointer for every IPA the guest may produce, or panics / returns a
    /// sentinel otherwise.  The unsafe block below dereferences the raw pointer
    /// for exactly `desc.len` bytes, which are within the region the caller
    /// has mapped.
    pub fn poll_tx(
        &mut self,
        mem: &mut [u8],
        region_base_ipa: u64,
        ipa_to_ptr: fn(u64) -> *const u8,
        out_buf: &mut [u8],
    ) -> Option<usize> {
        self.ensure_queues(region_base_ipa, mem.len());

        let tx = self.tx_queue.as_mut()?;

        let (head, mut chain) = tx.pop_available(mem)?;

        let mut raw_bytes: [u8; 2048] = [0u8; 2048];
        let mut raw_len: usize = 0;

        // Walk the descriptor chain, accumulating all bytes into raw_bytes.
        loop {
            let desc = match chain.next(mem) {
                Ok(Some(d)) => d,
                Ok(None) => break,
                Err(_) => break,
            };

            let copy_len = desc.len as usize;
            if copy_len == 0 {
                continue;
            }

            // SAFETY: `ipa_to_ptr` is provided by the caller and must return a
            // pointer valid for `desc.len` contiguous readable bytes.  We read
            // exactly that many bytes and do not retain the pointer beyond this
            // block.
            let src = ipa_to_ptr(desc.addr);
            let end = raw_len.saturating_add(copy_len).min(raw_bytes.len());
            let actual = end - raw_len;
            unsafe {
                core::ptr::copy_nonoverlapping(src, raw_bytes[raw_len..end].as_mut_ptr(), actual);
            }
            raw_len += actual;
        }

        // Strip the 12-byte virtio-net header; the remainder is the Ethernet frame.
        let frame_start = VIRTIO_NET_HDR_SIZE.min(raw_len);
        let frame = &raw_bytes[frame_start..raw_len];
        let copy_len = frame.len().min(out_buf.len());
        out_buf[..copy_len].copy_from_slice(&frame[..copy_len]);

        tx.push_used(mem, head, raw_len as u32);

        Some(copy_len)
    }

    /// Inject a received Ethernet `frame` into the RX virtqueue.
    ///
    /// The `ipa_to_ptr` callback translates a guest IPA to a host *mutable*
    /// pointer into which the header + frame bytes are written.
    ///
    /// # Returns
    ///
    /// `true` if the frame was successfully injected, `false` if the RX queue
    /// is not yet configured, has no available buffers, or the first available
    /// buffer is too small to hold the 12-byte header plus the frame.
    ///
    /// # Safety (internal)
    ///
    /// The caller must guarantee that `ipa_to_ptr` returns a pointer valid for
    /// at least `12 + frame.len()` contiguous writable bytes.  The unsafe
    /// block writes exactly `12 + frame.len()` bytes starting at that pointer.
    pub fn push_rx(
        &mut self,
        frame: &[u8],
        mem: &mut [u8],
        region_base_ipa: u64,
        ipa_to_ptr: fn(u64) -> *mut u8,
    ) -> bool {
        self.ensure_queues(region_base_ipa, mem.len());

        let rx = match self.rx_queue.as_mut() {
            Some(q) => q,
            None => return false,
        };

        let (head, mut chain) = match rx.pop_available(mem) {
            Some(pair) => pair,
            None => return false,
        };

        // RX uses single-descriptor buffers; read the first (and only) descriptor.
        let desc = match chain.next(mem) {
            Ok(Some(d)) => d,
            _ => {
                rx.push_used(mem, head, 0);
                return false;
            }
        };

        let required = VIRTIO_NET_HDR_SIZE + frame.len();
        if (desc.len as usize) < required {
            rx.push_used(mem, head, 0);
            return false;
        }

        // Build the 12-byte virtio-net header: all zeros except num_buffers=1.
        let mut hdr = [0u8; VIRTIO_NET_HDR_SIZE];
        // num_buffers is at bytes [10..12], little-endian value 1.
        hdr[10] = 1;
        hdr[11] = 0;

        // SAFETY: `ipa_to_ptr` is provided by the caller and must return a
        // pointer valid for `required` contiguous writable bytes.  We write
        // exactly `VIRTIO_NET_HDR_SIZE` header bytes followed by `frame.len()`
        // frame bytes and do not retain the pointer beyond this block.
        let dst = ipa_to_ptr(desc.addr);
        unsafe {
            core::ptr::copy_nonoverlapping(hdr.as_ptr(), dst, VIRTIO_NET_HDR_SIZE);
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                dst.add(VIRTIO_NET_HDR_SIZE),
                frame.len(),
            );
        }

        rx.push_used(mem, head, required as u32);
        true
    }

    /// Forward an MMIO access to the underlying `VirtioMmio` transport.
    pub fn handle_mmio(&mut self, offset: u32, access: AccessType) -> MmioResponse {
        self.mmio.handle_mmio(offset, access)
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Attempt to construct a `VirtQueue` from a `QueueConfig`.
///
/// Returns `None` if the queue is not yet marked ready or if `VirtQueue::new`
/// returns an error (e.g. the region is too small for the requested layout).
fn try_make_queue(cfg: &QueueConfig, region_base_ipa: u64, region_len: usize) -> Option<VirtQueue> {
    if !cfg.ready || cfg.num == 0 {
        return None;
    }
    // Guest writes raw IPAs to queue address registers. Subtract the shared
    // memory base IPA to get byte offsets into the region slice.
    let desc_off = cfg.desc_addr.checked_sub(region_base_ipa)? as usize;
    let avail_off = cfg.avail_addr.checked_sub(region_base_ipa)? as usize;
    let used_off = cfg.used_addr.checked_sub(region_base_ipa)? as usize;
    VirtQueue::new(cfg.num, desc_off, avail_off, used_off, region_len).ok()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trap::AccessType;
    use crate::virtqueue::VRING_DESC_F_WRITE;

    const TEST_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    // ── memory layout constants ───────────────────────────────────────────────
    //
    // Two virtqueues (RX=0, TX=1) of size 4 each.
    //
    //  Queue size N=4:
    //    desc  table : N * 16 = 64 bytes
    //    avail ring  : 6 + 2*N = 14 bytes
    //    used  ring  : 6 + 8*N = 38 bytes
    //
    //  Layout (byte offsets):
    //    RX desc   :   0
    //    RX avail  :  64
    //    RX used   :  80   (64 + 14 = 78, round up)
    //    TX desc   : 128   (80 + 38 = 118, round up)
    //    TX avail  : 192   (128 + 64)
    //    TX used   : 208   (192 + 14 = 206, round up)
    //    packet buf: 256   (208 + 38 = 246, round up)

    const QUEUE_SIZE: u16 = 4;

    const RX_DESC_OFF: usize = 0;
    const RX_AVAIL_OFF: usize = 64;
    const RX_USED_OFF: usize = 80;

    const TX_DESC_OFF: usize = 128;
    const TX_AVAIL_OFF: usize = 192;
    const TX_USED_OFF: usize = 208;

    const PKT_BUF_OFF: usize = 256;
    const MEM_LEN: usize = 1024;

    // ── little-endian helpers (mirrors virtqueue.rs internals) ────────────────

    fn write_u16_le(mem: &mut [u8], offset: usize, val: u16) {
        let b = val.to_le_bytes();
        mem[offset] = b[0];
        mem[offset + 1] = b[1];
    }

    fn read_u16_le(mem: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes([mem[offset], mem[offset + 1]])
    }

    fn write_u32_le(mem: &mut [u8], offset: usize, val: u32) {
        let b = val.to_le_bytes();
        mem[offset..offset + 4].copy_from_slice(&b);
    }

    fn read_u32_le(mem: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(mem[offset..offset + 4].try_into().unwrap())
    }

    /// Write a descriptor table entry.
    fn write_descriptor(
        mem: &mut [u8],
        desc_off: usize,
        idx: u16,
        addr: u64,
        len: u32,
        flags: u16,
        next: u16,
    ) {
        let base = desc_off + idx as usize * 16;
        mem[base..base + 8].copy_from_slice(&addr.to_le_bytes());
        write_u32_le(mem, base + 8, len);
        write_u16_le(mem, base + 12, flags);
        write_u16_le(mem, base + 14, next);
    }

    /// Write one entry into the available ring and increment its idx.
    fn push_avail(mem: &mut [u8], avail_off: usize, queue_size: u16, desc_idx: u16) {
        let cur_idx = read_u16_le(mem, avail_off + 2);
        let slot = (cur_idx % queue_size) as usize;
        write_u16_le(mem, avail_off + 4 + slot * 2, desc_idx);
        write_u16_le(mem, avail_off + 2, cur_idx.wrapping_add(1));
    }

    /// Configure a queue in the `VirtioMmio` transport (simulate guest driver
    /// init) and return a ready `VirtioNetDevice`.
    fn make_device_with_queues(rx_ready: bool, tx_ready: bool) -> (VirtioNetDevice, Vec<u8>) {
        let mut dev = VirtioNetDevice::new(TEST_MAC);
        let mem = vec![0u8; MEM_LEN];

        // Configure RX queue (index 0).
        dev.mmio.queues[0].num = QUEUE_SIZE;
        dev.mmio.queues[0].desc_addr = RX_DESC_OFF as u64;
        dev.mmio.queues[0].avail_addr = RX_AVAIL_OFF as u64;
        dev.mmio.queues[0].used_addr = RX_USED_OFF as u64;
        dev.mmio.queues[0].ready = rx_ready;

        // Configure TX queue (index 1).
        dev.mmio.queues[1].num = QUEUE_SIZE;
        dev.mmio.queues[1].desc_addr = TX_DESC_OFF as u64;
        dev.mmio.queues[1].avail_addr = TX_AVAIL_OFF as u64;
        dev.mmio.queues[1].used_addr = TX_USED_OFF as u64;
        dev.mmio.queues[1].ready = tx_ready;

        (dev, mem)
    }

    // ── test 1 ────────────────────────────────────────────────────────────────

    #[test]
    fn new_creates_device_with_mac() {
        let dev = VirtioNetDevice::new(TEST_MAC);
        assert_eq!(dev.mac, TEST_MAC);

        // Verify device_id=1 via MMIO read at offset 0x008 (REG_DEVICE_ID).
        let mut dev = dev;
        match dev.mmio.handle_mmio(0x008, AccessType::Read) {
            MmioResponse::ReadValue(v) => assert_eq!(v, 1),
            other => panic!("expected ReadValue(1), got {:?}", other),
        }
    }

    // ── test 2 ────────────────────────────────────────────────────────────────

    #[test]
    fn handle_mmio_delegates() {
        let mut dev = VirtioNetDevice::new(TEST_MAC);
        // REG_MAGIC = 0x000, expected value 0x7472_6976 ("virt" LE).
        match dev.handle_mmio(0x000, AccessType::Read) {
            MmioResponse::ReadValue(v) => assert_eq!(v, 0x7472_6976),
            other => panic!("expected ReadValue, got {:?}", other),
        }
    }

    // ── test 3 ────────────────────────────────────────────────────────────────

    #[test]
    fn poll_tx_empty_returns_none() {
        // No queues configured → poll_tx returns None.
        let mut dev = VirtioNetDevice::new(TEST_MAC);
        let mut mem = vec![0u8; MEM_LEN];
        let mut out_buf = [0u8; 1500];
        let result = dev.poll_tx(&mut mem, 0, |addr| addr as *const u8, &mut out_buf);
        assert!(result.is_none());
    }

    // ── test 4 ────────────────────────────────────────────────────────────────

    #[test]
    fn poll_tx_extracts_frame() {
        let (mut dev, mut mem) = make_device_with_queues(false, true);

        // Build a TX descriptor: 12-byte virtio-net header + 4-byte "frame".
        let test_frame = [0xDE, 0xAD, 0xBE, 0xEF_u8];
        let pkt_len = VIRTIO_NET_HDR_SIZE + test_frame.len(); // 16 bytes

        // Write packet data into the buffer region.
        // Header (12 bytes) = all zeros (default); frame starts at PKT_BUF_OFF+12.
        mem[PKT_BUF_OFF + VIRTIO_NET_HDR_SIZE..PKT_BUF_OFF + pkt_len].copy_from_slice(&test_frame);

        // The descriptor addr stores the actual pointer into the Vec.
        // We record the base pointer before passing &mut mem to poll_tx, so
        // we compute the addr after the descriptor is written, using the
        // stable base address of the Vec.
        let pkt_ptr = mem[PKT_BUF_OFF..].as_ptr() as u64;

        // Descriptor 0: addr = actual pointer to packet buffer.
        write_descriptor(&mut mem, TX_DESC_OFF, 0, pkt_ptr, pkt_len as u32, 0, 0);

        // Make descriptor 0 available in the TX ring.
        push_avail(&mut mem, TX_AVAIL_OFF, QUEUE_SIZE, 0);

        let mut out_buf = [0u8; 1500];
        let n = dev
            .poll_tx(&mut mem, 0, |addr| addr as *const u8, &mut out_buf)
            .expect("should return Some");

        assert_eq!(n, test_frame.len());
        assert_eq!(&out_buf[..n], &test_frame);
    }

    // ── test 5 ────────────────────────────────────────────────────────────────

    #[test]
    fn push_rx_injects_frame() {
        let (mut dev, mut mem) = make_device_with_queues(true, false);

        // The descriptor addr must be the actual pointer into the Vec so that
        // the identity ipa_to_ptr works correctly.
        let pkt_ptr = mem[PKT_BUF_OFF..].as_mut_ptr() as u64;

        write_descriptor(
            &mut mem,
            RX_DESC_OFF,
            0,
            pkt_ptr,
            256,
            VRING_DESC_F_WRITE,
            0,
        );
        push_avail(&mut mem, RX_AVAIL_OFF, QUEUE_SIZE, 0);

        let frame = [0x11, 0x22, 0x33, 0x44_u8];
        let ok = dev.push_rx(&frame, &mut mem, 0, |addr| addr as *mut u8);
        assert!(ok);

        // Verify that the used ring was advanced.
        let used_idx = read_u16_le(&mem, RX_USED_OFF + 2);
        assert_eq!(used_idx, 1);

        // Verify bytes_written in used ring entry 0.
        let bytes_written = read_u32_le(&mem, RX_USED_OFF + 4 + 4); // entry[0].len
        assert_eq!(bytes_written as usize, VIRTIO_NET_HDR_SIZE + frame.len());

        // Verify header (zeroed except num_buffers=1 at bytes 10–11).
        assert_eq!(mem[PKT_BUF_OFF + 10], 1);
        assert_eq!(mem[PKT_BUF_OFF + 11], 0);

        // Verify frame bytes follow the header.
        assert_eq!(
            &mem[PKT_BUF_OFF + VIRTIO_NET_HDR_SIZE
                ..PKT_BUF_OFF + VIRTIO_NET_HDR_SIZE + frame.len()],
            &frame
        );
    }

    // ── test 6 ────────────────────────────────────────────────────────────────

    #[test]
    fn push_rx_full_queue_returns_false() {
        // RX queue is ready but available ring has no entries → false.
        let (mut dev, mut mem) = make_device_with_queues(true, false);
        let frame = [0x01, 0x02_u8];
        let ok = dev.push_rx(&frame, &mut mem, 0, |addr| addr as *mut u8);
        assert!(!ok);
    }

    // ── test 7 ────────────────────────────────────────────────────────────────

    #[test]
    fn virtio_net_hdr_size_is_12() {
        assert_eq!(core::mem::size_of::<VirtioNetHdr>(), 12);
    }

    // ── test 8 ────────────────────────────────────────────────────────────────

    #[test]
    fn push_rx_oversized_frame_returns_false() {
        let (mut dev, mut mem) = make_device_with_queues(true, false);

        // Buffer is only 10 bytes, but frame needs 12+4 = 16 bytes.
        // Addr must still be a valid pointer (even though we won't write to it
        // because the size check fires first).
        let pkt_ptr = mem[PKT_BUF_OFF..].as_mut_ptr() as u64;
        write_descriptor(
            &mut mem,
            RX_DESC_OFF,
            0,
            pkt_ptr,
            10, // too small
            VRING_DESC_F_WRITE,
            0,
        );
        push_avail(&mut mem, RX_AVAIL_OFF, QUEUE_SIZE, 0);

        let frame = [0xAA, 0xBB, 0xCC, 0xDD_u8];
        let ok = dev.push_rx(&frame, &mut mem, 0, |addr| addr as *mut u8);
        assert!(!ok);
    }
}
