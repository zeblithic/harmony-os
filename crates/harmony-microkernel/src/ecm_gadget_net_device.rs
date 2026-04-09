// SPDX-License-Identifier: GPL-2.0-or-later

//! [`NetworkDevice`] adapter for [`EcmGadget`].
//!
//! Wraps the ECM gadget's `poll_rx_frame` / `queue_tx_frame` methods
//! into the `NetworkDevice` trait, enabling `VirtioNetServer` reuse.

extern crate alloc;

use harmony_unikernel::drivers::dwc2::types::GadgetRequest;
use harmony_unikernel::drivers::ecm_gadget::EcmGadget;

use crate::net_device::NetworkDevice;

/// [`NetworkDevice`] adapter wrapping an [`EcmGadget`].
///
/// Bridges the ECM gadget's sans-I/O methods to the `NetworkDevice` trait
/// so that `VirtioNetServer<EcmGadgetNetDevice>` exposes DWC2 ECM gadget
/// devices as 9P `/dev/net/usb0/` with zero new Ring 2 code.
pub struct EcmGadgetNetDevice {
    gadget: EcmGadget,
}

impl EcmGadgetNetDevice {
    /// Wrap an [`EcmGadget`] as a [`NetworkDevice`].
    pub fn new(gadget: EcmGadget) -> Self {
        Self { gadget }
    }

    /// Access the underlying gadget for feeding events.
    pub fn gadget_mut(&mut self) -> &mut EcmGadget {
        &mut self.gadget
    }

    /// Take the next pending USB request from `push_rx` calls.
    ///
    /// Returns one request at a time for single-transfer-per-endpoint
    /// flow control on the bulk IN path.
    pub fn drain_request(&mut self) -> Option<GadgetRequest> {
        self.gadget.drain_pending_requests()
    }
}

impl NetworkDevice for EcmGadgetNetDevice {
    fn poll_tx(&mut self, out: &mut [u8]) -> Option<usize> {
        self.gadget.poll_rx_frame(out)
    }

    fn push_rx(&mut self, frame: &[u8]) -> bool {
        self.gadget.queue_tx_frame(frame)
    }

    fn mac(&self) -> [u8; 6] {
        self.gadget.mac()
    }

    fn link_up(&self) -> bool {
        self.gadget.link_up()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio_net_server::VirtioNetServer;
    use harmony_unikernel::drivers::dwc2::types::GadgetEvent;

    const TEST_MAC: [u8; 6] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];

    /// Create an `EcmGadgetNetDevice` with MAC `DE:AD:BE:EF:CA:FE`.
    fn make_gadget_net_device() -> EcmGadgetNetDevice {
        let (gadget, _, _, _) = EcmGadget::new(TEST_MAC);
        EcmGadgetNetDevice::new(gadget)
    }

    /// Create a configured `EcmGadgetNetDevice` (link is up).
    fn make_configured_device() -> EcmGadgetNetDevice {
        let mut dev = make_gadget_net_device();
        dev.gadget_mut().handle_event(GadgetEvent::Configured);
        dev
    }

    #[test]
    fn network_device_mac() {
        let dev = make_gadget_net_device();
        assert_eq!(dev.mac(), TEST_MAC);
    }

    #[test]
    fn network_device_link_up_default() {
        let dev = make_gadget_net_device();
        assert!(!dev.link_up());
    }

    #[test]
    fn network_device_link_up_after_configured() {
        let dev = make_configured_device();
        assert!(dev.link_up());
    }

    #[test]
    fn network_device_push_rx_and_drain() {
        let mut dev = make_configured_device();
        let frame = [0xAA; 64];
        assert!(dev.push_rx(&frame));

        let req = dev
            .drain_request()
            .expect("should have one pending request");
        assert!(matches!(req, GadgetRequest::BulkIn { ep: 1, .. }));
    }

    #[test]
    fn network_device_poll_tx_after_bulk_out() {
        let mut dev = make_gadget_net_device();
        let frame = [0xBB; 60];
        // Feed a BulkOut event directly via gadget_mut().
        dev.gadget_mut().handle_event(GadgetEvent::BulkOut {
            ep: 2,
            data: frame.to_vec(),
        });

        // poll_tx should return the frame.
        let mut buf = [0u8; 2048];
        let len = dev.poll_tx(&mut buf).expect("frame must be available");
        assert_eq!(len, 60);
        assert_eq!(&buf[..len], &frame);
    }

    #[test]
    fn network_device_poll_tx_empty() {
        let mut dev = make_gadget_net_device();
        let mut buf = [0u8; 2048];
        assert!(dev.poll_tx(&mut buf).is_none());
    }

    #[test]
    fn push_rx_before_configured_fails() {
        let mut dev = make_gadget_net_device();
        assert!(!dev.push_rx(&[0u8; 64]));
    }

    #[test]
    fn virtio_net_server_type_check() {
        // Compile-time verification that VirtioNetServer<EcmGadgetNetDevice> compiles.
        let dev = make_gadget_net_device();
        let _server: VirtioNetServer<EcmGadgetNetDevice> = VirtioNetServer::new(dev, "usb0");
    }
}
