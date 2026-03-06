// SPDX-License-Identifier: GPL-2.0-or-later
//! VirtIO 1.0+ network device driver implementing [`NetworkInterface`].
//!
//! Performs the full VirtIO 1.0 §3.1 initialization sequence via MMIO
//! registers discovered through PCI capabilities, manages split
//! virtqueues for RX/TX, and frames payloads in Ethernet with the
//! IEEE Local Experimental EtherType (0x88B5).

use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use harmony_platform::error::PlatformError;
use harmony_platform::network::NetworkInterface;

use super::pci_cap::VirtioPciCaps;
use super::virtqueue::{Virtqueue, BUF_SIZE, QUEUE_SIZE};

// ---------------------------------------------------------------------------
// Ethernet constants
// ---------------------------------------------------------------------------

/// IEEE 802 Local Experimental EtherType for Harmony protocol traffic.
const ETHERTYPE_HARMONY: [u8; 2] = [0x88, 0xB5];

/// Ethernet header length: 6 (dst) + 6 (src) + 2 (ethertype).
const ETH_HEADER_LEN: usize = 14;

/// Broadcast MAC address.
const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

/// VirtIO net header length (VirtIO 1.0 §5.1.6).
/// 12 bytes: 10-byte base header + 2-byte `num_buffers` (always present in 1.0+).
const VIRTIO_NET_HDR_LEN: usize = 12;

// ---------------------------------------------------------------------------
// VirtIO common config MMIO offsets (VirtIO 1.0 §4.1.4.3)
// ---------------------------------------------------------------------------

const DEVICE_FEATURE_SELECT: usize = 0x00;
const DEVICE_FEATURE: usize = 0x04;
const DRIVER_FEATURE_SELECT: usize = 0x08;
const DRIVER_FEATURE: usize = 0x0C;
const DEVICE_STATUS: usize = 0x14;
const QUEUE_SELECT: usize = 0x16;
const QUEUE_SIZE_REG: usize = 0x18;
const QUEUE_ENABLE: usize = 0x1C;
const QUEUE_NOTIFY_OFF: usize = 0x1E;
const QUEUE_DESC: usize = 0x20;
const QUEUE_AVAIL: usize = 0x28;
const QUEUE_USED: usize = 0x30;

// ---------------------------------------------------------------------------
// Device status bits (VirtIO 1.0 §2.1)
// ---------------------------------------------------------------------------

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;

// ---------------------------------------------------------------------------
// Feature bits
// ---------------------------------------------------------------------------

/// The device has a valid MAC address in its configuration space.
const VIRTIO_NET_F_MAC: u32 = 1 << 5;

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Read a `u8` from a memory-mapped register.
///
/// # Safety
///
/// `addr` must point to a valid MMIO register.
#[inline(always)]
unsafe fn mmio_read8(addr: usize) -> u8 {
    read_volatile(addr as *const u8)
}

/// Read a `u16` from a memory-mapped register.
///
/// # Safety
///
/// `addr` must be 2-byte aligned and point to a valid MMIO register.
#[inline(always)]
unsafe fn mmio_read16(addr: usize) -> u16 {
    read_volatile(addr as *const u16)
}

/// Read a `u32` from a memory-mapped register.
///
/// # Safety
///
/// `addr` must be 4-byte aligned and point to a valid MMIO register.
#[inline(always)]
unsafe fn mmio_read32(addr: usize) -> u32 {
    read_volatile(addr as *const u32)
}

/// Write a `u8` to a memory-mapped register.
///
/// # Safety
///
/// `addr` must point to a valid MMIO register.
#[inline(always)]
unsafe fn mmio_write8(addr: usize, val: u8) {
    write_volatile(addr as *mut u8, val);
}

/// Write a `u16` to a memory-mapped register.
///
/// # Safety
///
/// `addr` must be 2-byte aligned and point to a valid MMIO register.
#[inline(always)]
unsafe fn mmio_write16(addr: usize, val: u16) {
    write_volatile(addr as *mut u16, val);
}

/// Write a `u32` to a memory-mapped register.
///
/// # Safety
///
/// `addr` must be 4-byte aligned and point to a valid MMIO register.
#[inline(always)]
unsafe fn mmio_write32(addr: usize, val: u32) {
    write_volatile(addr as *mut u32, val);
}

// ---------------------------------------------------------------------------
// VirtioNet driver
// ---------------------------------------------------------------------------

/// VirtIO 1.0+ network device driver.
///
/// Manages a pair of split virtqueues (RX index 0, TX index 1) and
/// provides the [`NetworkInterface`] trait for the unikernel event loop.
pub struct VirtioNet {
    rx_queue: Virtqueue,
    tx_queue: Virtqueue,
    mac: [u8; 6],
    rx_notify_addr: usize,
    tx_notify_addr: usize,
}

impl VirtioNet {
    /// Initialise a VirtIO 1.0 network device following §3.1.
    ///
    /// # Arguments
    ///
    /// * `caps` — Parsed MMIO addresses from PCI capability scanning.
    /// * `phys_offset` — The bootloader's physical-to-virtual memory offset.
    ///
    /// # Errors
    ///
    /// Returns an error string if feature negotiation fails.
    pub fn init(caps: VirtioPciCaps, phys_offset: u64) -> Result<Self, &'static str> {
        let common = caps.common_cfg;

        // §3.1.1 — Reset the device.
        unsafe { mmio_write8(common + DEVICE_STATUS, 0) };

        // §3.1.1 — Set ACKNOWLEDGE status bit.
        unsafe { mmio_write8(common + DEVICE_STATUS, STATUS_ACKNOWLEDGE) };

        // §3.1.1 — Set DRIVER status bit.
        unsafe { mmio_write8(common + DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER) };

        // §3.1.1 — Read device features (feature set 0).
        unsafe { mmio_write32(common + DEVICE_FEATURE_SELECT, 0) };
        let device_features = unsafe { mmio_read32(common + DEVICE_FEATURE) };

        // Negotiate VIRTIO_NET_F_MAC — require it.
        if device_features & VIRTIO_NET_F_MAC == 0 {
            return Err("virtio-net: device does not offer VIRTIO_NET_F_MAC");
        }

        // Write driver features: MAC (feature word 0).
        unsafe { mmio_write32(common + DRIVER_FEATURE_SELECT, 0) };
        unsafe { mmio_write32(common + DRIVER_FEATURE, VIRTIO_NET_F_MAC) };

        // VIRTIO_F_VERSION_1 is bit 32 (bit 0 of feature word 1) — required by §6.
        unsafe { mmio_write32(common + DRIVER_FEATURE_SELECT, 1) };
        unsafe { mmio_write32(common + DRIVER_FEATURE, 1) };

        // §3.1.1 — Set FEATURES_OK.
        unsafe {
            mmio_write8(
                common + DEVICE_STATUS,
                STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
            )
        };

        // Memory fence to ensure the status write is visible before re-read.
        fence(Ordering::SeqCst);

        // §3.1.1 — Re-read status to confirm FEATURES_OK was accepted.
        let status = unsafe { mmio_read8(common + DEVICE_STATUS) };
        if status & STATUS_FEATURES_OK == 0 {
            return Err("virtio-net: device did not accept FEATURES_OK");
        }

        // Read MAC address from device-specific config (6 bytes at offset 0..5).
        let mut mac = [0u8; 6];
        for (i, byte) in mac.iter_mut().enumerate() {
            *byte = unsafe { mmio_read8(caps.device_cfg + i) };
        }

        // Setup RX queue (index 0).
        let mut rx_queue = Virtqueue::new(phys_offset);
        let rx_queue_size = Self::setup_queue(common, 0, &rx_queue)
            .ok_or("virtio-net: RX queue not available (max_size=0)")?;
        rx_queue.set_queue_size(rx_queue_size);

        // Setup TX queue (index 1).
        let mut tx_queue = Virtqueue::new(phys_offset);
        let tx_queue_size = Self::setup_queue(common, 1, &tx_queue)
            .ok_or("virtio-net: TX queue not available (max_size=0)")?;
        tx_queue.set_queue_size(tx_queue_size);

        // Compute notification addresses for each queue.
        let rx_notify_off = Self::read_queue_notify_off(common, 0);
        let tx_notify_off = Self::read_queue_notify_off(common, 1);

        let rx_notify_addr =
            caps.notify_base + rx_notify_off as usize * caps.notify_off_multiplier as usize;
        let tx_notify_addr =
            caps.notify_base + tx_notify_off as usize * caps.notify_off_multiplier as usize;

        // §3.1.1 — Set DRIVER_OK: device is live.
        // Must be set before any queue notifications (§3.1.1 step 8).
        unsafe {
            mmio_write8(
                common + DEVICE_STATUS,
                STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
            )
        };

        // Ensure DRIVER_OK is visible before any queue access or notification.
        fence(Ordering::SeqCst);

        let mut driver = VirtioNet {
            rx_queue,
            tx_queue,
            mac,
            rx_notify_addr,
            tx_notify_addr,
        };

        // Pre-post RX buffers (capped at negotiated queue size).
        for _ in 0..rx_queue_size {
            driver.rx_queue.post_receive();
        }

        // Notify the device that RX buffers are available.
        unsafe { mmio_write16(driver.rx_notify_addr, 0) };

        Ok(driver)
    }

    /// Configure a single virtqueue on the device.
    ///
    /// Returns `None` if the device reports `max_size=0` (queue not
    /// available per VirtIO 1.0 §4.1.5.1.3).
    fn setup_queue(common: usize, queue_idx: u16, vq: &Virtqueue) -> Option<u16> {
        let size = unsafe {
            // Select the queue.
            mmio_write16(common + QUEUE_SELECT, queue_idx);

            // Read the device's maximum queue size.
            let max_size = mmio_read16(common + QUEUE_SIZE_REG);

            // §4.1.5.1.3: max_size == 0 means queue is not available.
            if max_size == 0 {
                return None;
            }

            // Use the smaller of our compiled size and the device maximum.
            let size = if max_size < QUEUE_SIZE {
                max_size
            } else {
                QUEUE_SIZE
            };
            mmio_write16(common + QUEUE_SIZE_REG, size);

            // Write the physical addresses of the descriptor table,
            // available ring, and used ring.
            // VirtIO 1.0 §4.1.3.1: use paired 32-bit writes for portability.
            mmio_write32(common + QUEUE_DESC, vq.desc_phys as u32);
            mmio_write32(common + QUEUE_DESC + 4, (vq.desc_phys >> 32) as u32);
            mmio_write32(common + QUEUE_AVAIL, vq.avail_phys as u32);
            mmio_write32(common + QUEUE_AVAIL + 4, (vq.avail_phys >> 32) as u32);
            mmio_write32(common + QUEUE_USED, vq.used_phys as u32);
            mmio_write32(common + QUEUE_USED + 4, (vq.used_phys >> 32) as u32);

            // Enable the queue.
            mmio_write16(common + QUEUE_ENABLE, 1);

            size
        };

        Some(size)
    }

    /// Read the notification offset for a queue (used to compute the
    /// queue's notification MMIO address).
    fn read_queue_notify_off(common: usize, queue_idx: u16) -> u16 {
        unsafe {
            mmio_write16(common + QUEUE_SELECT, queue_idx);
            mmio_read16(common + QUEUE_NOTIFY_OFF)
        }
    }

    /// Return the device's MAC address.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Format the MAC address as `"xx:xx:xx:xx:xx:xx"` into the provided
    /// 17-byte buffer.
    pub fn mac_str(&self, buf: &mut [u8; 17]) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (i, &byte) in self.mac.iter().enumerate() {
            let offset = i * 3;
            buf[offset] = HEX[(byte >> 4) as usize];
            buf[offset + 1] = HEX[(byte & 0x0F) as usize];
            if i < 5 {
                buf[offset + 2] = b':';
            }
        }
    }

    /// Poll the TX used ring and free completed descriptors back to the
    /// pool so they can be reused for subsequent sends.
    pub fn reclaim_tx(&mut self) {
        while let Some((desc_id, _len)) = self.tx_queue.poll_used() {
            self.tx_queue.free_desc(desc_id);
        }
    }
}

impl NetworkInterface for VirtioNet {
    fn name(&self) -> &str {
        "virtio0"
    }

    fn mtu(&self) -> usize {
        1500
    }

    fn send(&mut self, data: &[u8]) -> Result<(), PlatformError> {
        // Reclaim completed TX descriptors first.
        self.reclaim_tx();

        let frame_len = VIRTIO_NET_HDR_LEN + ETH_HEADER_LEN + data.len();
        if frame_len > BUF_SIZE {
            return Err(PlatformError::SendFailed);
        }

        // Build virtio_net_hdr + Ethernet frame on the stack.
        // Bytes 0..12: virtio_net_hdr (all zeros = no GSO, no checksum offload).
        let mut frame = [0u8; BUF_SIZE];
        let h = VIRTIO_NET_HDR_LEN;
        // Destination: broadcast.
        frame[h..h + 6].copy_from_slice(&BROADCAST_MAC);
        // Source: our MAC.
        frame[h + 6..h + 12].copy_from_slice(&self.mac);
        // EtherType: Harmony (0x88B5).
        frame[h + 12..h + 14].copy_from_slice(&ETHERTYPE_HARMONY);
        // Payload.
        frame[h + ETH_HEADER_LEN..h + ETH_HEADER_LEN + data.len()].copy_from_slice(data);

        match self.tx_queue.submit_send(&frame[..frame_len]) {
            Some(_) => {
                // Notify the device that a TX buffer is available.
                unsafe { mmio_write16(self.tx_notify_addr, 1) };
                Ok(())
            }
            None => Err(PlatformError::SendFailed),
        }
    }

    fn receive(&mut self) -> Option<Vec<u8>> {
        // Loop to drain non-Harmony frames (ARP, mDNS, etc.) so that
        // returning None means "used ring empty", not "got a filtered frame."
        loop {
            let (desc_id, len) = self.rx_queue.poll_used()?;

            // Read the raw buffer (virtio_net_hdr + Ethernet frame).
            // Clamp len to BUF_SIZE to defend against misbehaving devices
            // without leaking the descriptor (read_buffer cannot fail).
            let clamped_len = if (len as usize) > BUF_SIZE {
                BUF_SIZE as u32
            } else {
                len
            };
            let frame = self.rx_queue.read_buffer(desc_id, clamped_len);

            // Free the descriptor and re-post a receive buffer.
            // This must happen unconditionally to avoid descriptor leaks.
            self.rx_queue.free_desc(desc_id);
            self.rx_queue.post_receive();

            // Notify the device that a new RX buffer is available.
            unsafe { mmio_write16(self.rx_notify_addr, 0) };

            // Skip short frames and non-Harmony EtherTypes.
            if frame.len() < VIRTIO_NET_HDR_LEN + ETH_HEADER_LEN {
                continue;
            }

            let eth = &frame[VIRTIO_NET_HDR_LEN..];

            if eth[12..14] != ETHERTYPE_HARMONY {
                continue;
            }

            // Strip virtio_net_hdr + Ethernet header and return the payload.
            return Some(eth[ETH_HEADER_LEN..].to_vec());
        }
    }
}
