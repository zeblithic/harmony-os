// SPDX-License-Identifier: GPL-2.0-or-later

//! [`NetworkDevice`] adapter for [`CdcEthernetDriver`].
//!
//! Wraps the CDC driver's `poll_rx_frame` / `queue_tx_frame` methods
//! into the `NetworkDevice` trait, enabling `VirtioNetServer` reuse.

extern crate alloc;

use alloc::vec::Vec;

use harmony_unikernel::drivers::cdc_ethernet::{CdcAction, CdcEthernetDriver};

use crate::net_device::NetworkDevice;

/// [`NetworkDevice`] adapter wrapping a [`CdcEthernetDriver`].
///
/// Bridges the CDC driver's sans-I/O methods to the `NetworkDevice` trait
/// so that `VirtioNetServer<CdcNetDevice>` exposes USB CDC-ECM/NCM devices
/// as 9P `/dev/net/cdc0/` with zero new Ring 2 code.
pub struct CdcNetDevice {
    driver: CdcEthernetDriver,
}

impl CdcNetDevice {
    /// Wrap a [`CdcEthernetDriver`] as a [`NetworkDevice`].
    pub fn new(driver: CdcEthernetDriver) -> Self {
        Self { driver }
    }

    /// Access the underlying driver for feeding bulk IN / interrupt data.
    pub fn driver_mut(&mut self) -> &mut CdcEthernetDriver {
        &mut self.driver
    }

    /// Drain pending USB actions from `push_rx` calls.
    ///
    /// After calling [`NetworkDevice::push_rx`], the CDC driver buffers
    /// [`CdcAction::BulkOut`] actions internally.  Call this method to
    /// retrieve them for execution by the xHCI layer.
    pub fn drain_actions(&mut self) -> Vec<CdcAction> {
        self.driver.drain_pending_actions()
    }
}

impl NetworkDevice for CdcNetDevice {
    fn poll_tx(&mut self, out: &mut [u8]) -> Option<usize> {
        self.driver.poll_rx_frame(out)
    }

    fn push_rx(&mut self, frame: &[u8]) -> bool {
        self.driver.queue_tx_frame(frame)
    }

    fn mac(&self) -> [u8; 6] {
        self.driver.mac()
    }

    fn link_up(&self) -> bool {
        self.driver.link_up()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio_net_server::VirtioNetServer;

    /// Build a minimal ECM configuration descriptor (80 bytes).
    ///
    /// Mirrors `harmony_unikernel::drivers::cdc_ethernet::descriptor::tests::build_ecm_config_desc`
    /// but is available cross-crate (the original is behind `#[cfg(test)]`).
    fn build_ecm_config_desc() -> Vec<u8> {
        let mut v = Vec::new();
        // Config (9)
        v.extend_from_slice(&[9, 0x02, 80, 0x00, 2, 1, 0, 0xC0, 50]);
        // Comm Interface: class=0x02, subclass=0x06 (ECM)
        v.extend_from_slice(&[9, 0x04, 0, 0, 1, 0x02, 0x06, 0x00, 0]);
        // Header FD
        v.extend_from_slice(&[5, 0x24, 0x00, 0x10, 0x01]);
        // Union FD (control=0, data=1)
        v.extend_from_slice(&[5, 0x24, 0x06, 0, 1]);
        // Ethernet FD (mac_string_index=3, max_segment_size=1514)
        v.extend_from_slice(&[13, 0x24, 0x0F, 3, 0, 0, 0, 0, 0xEA, 0x05, 0, 0, 0]);
        // Interrupt IN EP (addr=0x83, mps=16)
        v.extend_from_slice(&[7, 0x05, 0x83, 0x03, 16, 0x00, 11]);
        // Data Interface alt 0 (0 endpoints)
        v.extend_from_slice(&[9, 0x04, 1, 0, 0, 0x0A, 0, 0, 0]);
        // Data Interface alt 1 (2 endpoints)
        v.extend_from_slice(&[9, 0x04, 1, 1, 2, 0x0A, 0, 0, 0]);
        // Bulk IN EP (addr=0x81, mps=512)
        v.extend_from_slice(&[7, 0x05, 0x81, 0x02, 0x00, 0x02, 0]);
        // Bulk OUT EP (addr=0x02, mps=512)
        v.extend_from_slice(&[7, 0x05, 0x02, 0x02, 0x00, 0x02, 0]);
        assert_eq!(v.len(), 80);
        v
    }

    /// Build a USB string descriptor for a MAC address in UTF-16LE.
    fn build_mac_string(mac_hex: &str) -> Vec<u8> {
        let chars: Vec<u8> = mac_hex.bytes().collect();
        let mut desc = Vec::new();
        desc.push((2 + chars.len() * 2) as u8);
        desc.push(0x03);
        for &c in &chars {
            desc.push(c);
            desc.push(0);
        }
        desc
    }

    /// Create an initialized `CdcNetDevice` with MAC `DE:AD:BE:EF:CA:FE`.
    fn make_cdc_net_device() -> CdcNetDevice {
        let config = build_ecm_config_desc();
        let (mut driver, _actions) =
            harmony_unikernel::drivers::cdc_ethernet::CdcEthernetDriver::from_config_descriptor(
                1, &config,
            )
            .unwrap()
            .unwrap();
        driver
            .complete_init(&build_mac_string("DEADBEEFCAFE"))
            .unwrap();
        CdcNetDevice::new(driver)
    }

    #[test]
    fn network_device_mac() {
        let dev = make_cdc_net_device();
        assert_eq!(dev.mac(), [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
    }

    #[test]
    fn network_device_link_up_default() {
        let dev = make_cdc_net_device();
        assert!(!dev.link_up());
    }

    #[test]
    fn network_device_push_rx_and_drain() {
        let mut dev = make_cdc_net_device();
        let frame = [0xAA; 64];
        assert!(dev.push_rx(&frame));

        let actions = dev.drain_actions();
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], CdcAction::BulkOut { .. }));
    }

    #[test]
    fn network_device_poll_tx_after_bulk_in() {
        let mut dev = make_cdc_net_device();
        // Feed a raw Ethernet frame via the bulk IN path.
        let frame = [0xBB; 60];
        let _requeue = dev.driver_mut().receive_bulk_in(&frame);

        // poll_tx should return the frame.
        let mut buf = [0u8; 2048];
        let len = dev.poll_tx(&mut buf).expect("frame must be available");
        assert_eq!(len, 60);
        assert_eq!(&buf[..len], &frame);
    }

    #[test]
    fn network_device_poll_tx_empty() {
        let mut dev = make_cdc_net_device();
        let mut buf = [0u8; 2048];
        assert!(dev.poll_tx(&mut buf).is_none());
    }

    #[test]
    fn virtio_net_server_type_check() {
        // Compile-time verification that VirtioNetServer<CdcNetDevice> compiles.
        let dev = make_cdc_net_device();
        let _server: VirtioNetServer<CdcNetDevice> = VirtioNetServer::new(dev, "cdc0");
    }
}
