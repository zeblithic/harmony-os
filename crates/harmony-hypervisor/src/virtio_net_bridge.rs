// SPDX-License-Identifier: GPL-2.0-or-later
//! Borrowing adapter connecting VirtioNetDevice to the NetworkDevice trait.

use crate::virtio_net::VirtioNetDevice;
use harmony_microkernel::net_device::NetworkDevice;

/// Adapter that implements [`NetworkDevice`] by delegating to a borrowed
/// [`VirtioNetDevice`] and its associated shared memory region.
///
/// The bridge holds mutable references to both the device and the memory
/// slice for the duration of its lifetime, allowing the caller to drive the
/// device through the trait interface without exposing the VirtIO-specific
/// memory-translation parameters.
pub struct VirtioNetBridge<'a> {
    device: &'a mut VirtioNetDevice,
    mem: &'a mut [u8],
    region_base_ipa: u64,
    ipa_to_ptr_read: fn(u64) -> *const u8,
    ipa_to_ptr_write: fn(u64) -> *mut u8,
}

impl<'a> VirtioNetBridge<'a> {
    /// Create a new bridge wrapping `device` and its shared memory region.
    ///
    /// - `mem` — the entire shared-memory region the virtqueues live in.
    /// - `region_base_ipa` — IPA of the first byte of `mem`.
    /// - `ipa_to_ptr_read` — translates a guest IPA to a host read pointer.
    /// - `ipa_to_ptr_write` — translates a guest IPA to a host write pointer.
    pub fn new(
        device: &'a mut VirtioNetDevice,
        mem: &'a mut [u8],
        region_base_ipa: u64,
        ipa_to_ptr_read: fn(u64) -> *const u8,
        ipa_to_ptr_write: fn(u64) -> *mut u8,
    ) -> Self {
        Self {
            device,
            mem,
            region_base_ipa,
            ipa_to_ptr_read,
            ipa_to_ptr_write,
        }
    }
}

impl NetworkDevice for VirtioNetBridge<'_> {
    fn poll_tx(&mut self, out: &mut [u8]) -> Option<usize> {
        self.device
            .poll_tx(self.mem, self.region_base_ipa, self.ipa_to_ptr_read, out)
    }

    fn push_rx(&mut self, frame: &[u8]) -> bool {
        self.device
            .push_rx(frame, self.mem, self.region_base_ipa, self.ipa_to_ptr_write)
    }

    fn mac(&self) -> [u8; 6] {
        self.device.mac
    }

    fn link_up(&self) -> bool {
        true
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio_net::{VirtioNetDevice, VIRTIO_NET_HDR_SIZE};
    use crate::virtqueue::VRING_DESC_F_WRITE;

    // ── memory layout (mirrors virtio_net.rs tests) ───────────────────────────
    //
    // Two virtqueues (RX=0, TX=1), size N=4.
    //
    //  desc  table : N * 16 = 64 bytes
    //  avail ring  : 6 + 2*N = 14 bytes
    //  used  ring  : 6 + 8*N = 38 bytes
    //
    //  RX desc   :   0
    //  RX avail  :  64
    //  RX used   :  80
    //  TX desc   : 128
    //  TX avail  : 192
    //  TX used   : 208
    //  packet buf: 256

    const QUEUE_SIZE: u16 = 4;

    const RX_DESC_OFF: usize = 0;
    const RX_AVAIL_OFF: usize = 64;
    const RX_USED_OFF: usize = 80;

    const TX_DESC_OFF: usize = 128;
    const TX_AVAIL_OFF: usize = 192;
    const TX_USED_OFF: usize = 208;

    const PKT_BUF_OFF: usize = 256;
    const MEM_LEN: usize = 1024;

    // ── little-endian helpers ─────────────────────────────────────────────────

    fn write_u16_le(mem: &mut [u8], offset: usize, val: u16) {
        let b = val.to_le_bytes();
        mem[offset] = b[0];
        mem[offset + 1] = b[1];
    }

    fn read_u16_le(mem: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes([mem[offset], mem[offset + 1]])
    }

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
        let b = len.to_le_bytes();
        mem[base + 8..base + 12].copy_from_slice(&b);
        write_u16_le(mem, base + 12, flags);
        write_u16_le(mem, base + 14, next);
    }

    fn push_avail(mem: &mut [u8], avail_off: usize, queue_size: u16, desc_idx: u16) {
        let cur_idx = read_u16_le(mem, avail_off + 2);
        let slot = (cur_idx % queue_size) as usize;
        write_u16_le(mem, avail_off + 4 + slot * 2, desc_idx);
        write_u16_le(mem, avail_off + 2, cur_idx.wrapping_add(1));
    }

    /// Build a device with both queues configured and return (device, mem).
    fn make_device(rx_ready: bool, tx_ready: bool) -> (VirtioNetDevice, Vec<u8>) {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mut dev = VirtioNetDevice::new(mac);
        let mem = vec![0u8; MEM_LEN];

        dev.mmio.queues[0].num = QUEUE_SIZE;
        dev.mmio.queues[0].desc_addr = RX_DESC_OFF as u64;
        dev.mmio.queues[0].avail_addr = RX_AVAIL_OFF as u64;
        dev.mmio.queues[0].used_addr = RX_USED_OFF as u64;
        dev.mmio.queues[0].ready = rx_ready;

        dev.mmio.queues[1].num = QUEUE_SIZE;
        dev.mmio.queues[1].desc_addr = TX_DESC_OFF as u64;
        dev.mmio.queues[1].avail_addr = TX_AVAIL_OFF as u64;
        dev.mmio.queues[1].used_addr = TX_USED_OFF as u64;
        dev.mmio.queues[1].ready = tx_ready;

        (dev, mem)
    }

    // ── test 1 ────────────────────────────────────────────────────────────────

    #[test]
    fn bridge_poll_tx_delegates() {
        let (mut dev, mut mem) = make_device(false, true);

        let test_frame = [0xDE, 0xAD, 0xBE, 0xEF_u8];
        let pkt_len = VIRTIO_NET_HDR_SIZE + test_frame.len();

        // Write frame bytes after the 12-byte virtio-net header.
        let pkt_ptr = mem[PKT_BUF_OFF..].as_ptr() as u64;
        mem[PKT_BUF_OFF + VIRTIO_NET_HDR_SIZE..PKT_BUF_OFF + pkt_len].copy_from_slice(&test_frame);

        write_descriptor(&mut mem, TX_DESC_OFF, 0, pkt_ptr, pkt_len as u32, 0, 0);
        push_avail(&mut mem, TX_AVAIL_OFF, QUEUE_SIZE, 0);

        let mut bridge =
            VirtioNetBridge::new(&mut dev, &mut mem, 0, |a| a as *const u8, |a| a as *mut u8);

        let mut out = [0u8; 1500];
        let n = bridge.poll_tx(&mut out).expect("should return Some");

        assert_eq!(n, test_frame.len());
        assert_eq!(&out[..n], &test_frame);
    }

    // ── test 2 ────────────────────────────────────────────────────────────────

    #[test]
    fn bridge_push_rx_delegates() {
        let (mut dev, mut mem) = make_device(true, false);

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

        let mut bridge =
            VirtioNetBridge::new(&mut dev, &mut mem, 0, |a| a as *const u8, |a| a as *mut u8);

        let accepted = bridge.push_rx(&frame);
        assert!(accepted);
    }

    // ── test 3 ────────────────────────────────────────────────────────────────

    #[test]
    fn bridge_mac_returns_device_mac() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mut dev = VirtioNetDevice::new(mac);
        let mut mem = vec![0u8; MEM_LEN];

        let bridge =
            VirtioNetBridge::new(&mut dev, &mut mem, 0, |a| a as *const u8, |a| a as *mut u8);

        assert_eq!(bridge.mac(), mac);
    }

    // ── test 4 ────────────────────────────────────────────────────────────────

    #[test]
    fn bridge_link_up_returns_true() {
        let mut dev = VirtioNetDevice::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        let mut mem = vec![0u8; MEM_LEN];

        let bridge =
            VirtioNetBridge::new(&mut dev, &mut mem, 0, |a| a as *const u8, |a| a as *mut u8);

        assert!(bridge.link_up());
    }
}
