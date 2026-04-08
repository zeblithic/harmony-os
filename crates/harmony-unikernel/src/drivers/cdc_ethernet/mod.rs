// SPDX-License-Identifier: GPL-2.0-or-later

//! USB CDC-ECM/NCM Ethernet class driver.
//!
//! Sans-I/O design: the driver never performs USB transfers directly.  Instead,
//! methods return [`CdcAction`] values that the caller (xHCI layer) must
//! execute.  Responses flow back in via `receive_bulk_in`, `receive_interrupt`,
//! and `complete_init`.

pub mod codec;
pub mod descriptor;
pub mod ncm;
pub mod notification;

pub use codec::CdcCodec;
pub use descriptor::{CdcDescriptors, CdcProtocol, EndpointInfo};
pub use notification::{CdcError, CdcNotification};

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use codec::CdcCodec as Codec;
use descriptor::parse_cdc_config;
use notification::{parse_notification, CdcNotification as Notif};

// ── CdcAction ────────────────────────────────────────────────────────────────

/// An action the driver returns for the caller to execute via xHCI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdcAction {
    /// Send data to a bulk OUT endpoint.
    BulkOut {
        /// Endpoint number (low 4 bits of address).
        ep: u8,
        /// Payload to transmit.
        data: Vec<u8>,
    },
    /// Queue a read on a bulk IN endpoint.
    BulkIn {
        /// Endpoint number (low 4 bits of address).
        ep: u8,
        /// Maximum bytes to read.
        max_len: u16,
    },
    /// Send a control transfer (host → device, with optional data stage).
    ControlOut {
        /// The 8-byte setup packet.
        request: [u8; 8],
        /// Optional data stage payload (may be empty).
        data: Vec<u8>,
    },
    /// Queue a control transfer (device → host).
    ControlIn {
        /// The 8-byte setup packet.
        request: [u8; 8],
        /// Maximum bytes to read in the data stage.
        max_len: u16,
    },
    /// Queue a read on an interrupt IN endpoint.
    InterruptIn {
        /// Endpoint number (low 4 bits of address).
        ep: u8,
        /// Maximum bytes to read.
        max_len: u16,
    },
}

// ── USB control request builders (private) ───────────────────────────────────

/// SET_CONFIGURATION (standard device request).
fn set_configuration(config_value: u8) -> [u8; 8] {
    [
        0x00, // bmRequestType: host-to-device, standard, device
        0x09, // bRequest: SET_CONFIGURATION
        config_value,
        0x00, // wValue high
        0x00, // wIndex low
        0x00, // wIndex high
        0x00, // wLength low
        0x00, // wLength high
    ]
}

/// SET_INTERFACE (standard interface request).
fn set_interface(interface: u8, alt_setting: u8) -> [u8; 8] {
    [
        0x01, // bmRequestType: host-to-device, standard, interface
        0x0B, // bRequest: SET_INTERFACE
        alt_setting,
        0x00, // wValue high
        interface,
        0x00, // wIndex high
        0x00, // wLength low
        0x00, // wLength high
    ]
}

/// GET_DESCRIPTOR for a string descriptor (standard device request).
fn get_string_descriptor(index: u8, max_len: u16) -> [u8; 8] {
    let w_value: u16 = (0x03u16 << 8) | index as u16;
    [
        0x80, // bmRequestType: device-to-host, standard, device
        0x06, // bRequest: GET_DESCRIPTOR
        (w_value & 0xFF) as u8,
        (w_value >> 8) as u8,
        0x09, // wIndex low  (0x0409 = English)
        0x04, // wIndex high
        (max_len & 0xFF) as u8,
        (max_len >> 8) as u8,
    ]
}

/// SET_ETHERNET_PACKET_FILTER (CDC class interface request).
fn set_packet_filter(interface: u8, filter: u16) -> [u8; 8] {
    [
        0x21, // bmRequestType: host-to-device, class, interface
        0x43, // bRequest: SET_ETHERNET_PACKET_FILTER
        (filter & 0xFF) as u8,
        (filter >> 8) as u8,
        interface,
        0x00, // wIndex high
        0x00, // wLength low
        0x00, // wLength high
    ]
}

// ── hex_nibble helper ────────────────────────────────────────────────────────

/// Convert an ASCII hex character to its 4-bit value.
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'F' => Some(c - b'A' + 10),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

// ── CdcEthernetDriver ───────────────────────────────────────────────────────

/// Sans-I/O CDC ECM/NCM Ethernet class driver.
///
/// Created via [`CdcEthernetDriver::from_config_descriptor`], which parses a
/// USB configuration descriptor and returns an initial set of [`CdcAction`]s
/// the caller must execute.  Subsequent USB events are fed back via
/// `receive_bulk_in`, `receive_interrupt`, and `complete_init`.
pub struct CdcEthernetDriver {
    /// Parsed descriptor information (endpoints, protocol, etc.).
    descriptors: CdcDescriptors,
    /// Codec for encoding/decoding bulk transfers.
    codec: Codec,
    /// Whether the network link is up.
    link_up: bool,
    /// Downstream speed in bits/s (from CONNECTION_SPEED_CHANGE).
    speed_down: u32,
    /// Upstream speed in bits/s (from CONNECTION_SPEED_CHANGE).
    speed_up: u32,
    /// Received Ethernet frames waiting to be consumed.
    rx_queue: VecDeque<Vec<u8>>,
    /// Actions accumulated by `queue_tx_frame` and other buffering methods.
    pending_actions: Vec<CdcAction>,
    /// MAC address (populated by `complete_init`).
    mac: [u8; 6],
    /// Whether `complete_init` has been called successfully.
    initialized: bool,
}

impl CdcEthernetDriver {
    /// Parse a USB configuration descriptor and create a driver instance.
    ///
    /// Returns `Ok(None)` if no CDC ECM/NCM interface is found.  On success,
    /// returns the driver and a set of initial [`CdcAction`]s the caller must
    /// execute: `SET_CONFIGURATION`, `SET_INTERFACE`, `GET_STRING` (for MAC),
    /// `SET_PACKET_FILTER`, plus initial `BulkIn` and `InterruptIn` reads.
    ///
    /// `slot_id` is accepted for caller convenience but not stored.
    ///
    /// # Errors
    ///
    /// Returns [`CdcError`] if the descriptor is malformed.
    pub fn from_config_descriptor(
        _slot_id: u8,
        config_desc: &[u8],
    ) -> Result<Option<(Self, Vec<CdcAction>)>, CdcError> {
        let descs = match parse_cdc_config(config_desc)? {
            Some(d) => d,
            None => return Ok(None),
        };

        let codec = match descs.protocol {
            CdcProtocol::Ecm => Codec::Ecm,
            CdcProtocol::Ncm => Codec::Ncm {
                max_ntb_size: descs.max_ntb_size,
                sequence: 0,
            },
        };

        let bulk_in_addr = descs.bulk_in_ep.address & 0x0F;
        let interrupt_addr = descs.interrupt_ep.address & 0x0F;

        // Bulk IN buffer must hold a complete transfer, not just one USB packet.
        // ECM: one Ethernet frame up to max_segment_size (typically 1514).
        // NCM: one NTB up to max_ntb_size (typically 2048-16384).
        let bulk_in_max = match descs.protocol {
            CdcProtocol::Ecm => descs.max_segment_size.max(1514),
            CdcProtocol::Ncm => (descs.max_ntb_size.min(u16::MAX as u32)) as u16,
        };

        let mut actions = vec![
            // 1. SET_CONFIGURATION
            CdcAction::ControlOut {
                request: set_configuration(descs.config_value),
                data: vec![],
            },
            // 2. SET_INTERFACE (activate data alt setting with bulk endpoints)
            CdcAction::ControlOut {
                request: set_interface(descs.data_interface, descs.data_alt_setting),
                data: vec![],
            },
        ];

        // 3. GET_STRING for MAC address (only if mac_string_index > 0;
        // index 0 is the USB Language ID list, not a MAC address)
        if descs.mac_string_index > 0 {
            actions.push(CdcAction::ControlIn {
                request: get_string_descriptor(descs.mac_string_index, 26),
                max_len: 26,
            });
        }

        // 4. SET_PACKET_FILTER — directed | multicast | broadcast
        // Bit 2 = directed, bit 3 = broadcast, bit 1 = all-multicast = 0x000E
        actions.push(CdcAction::ControlOut {
            request: set_packet_filter(descs.control_interface, 0x000E),
            data: vec![],
        });

        // 5. Initial bulk IN read (sized for a complete transfer)
        actions.push(CdcAction::BulkIn {
            ep: bulk_in_addr,
            max_len: bulk_in_max,
        });

        // 6. Initial interrupt IN read
        actions.push(CdcAction::InterruptIn {
            ep: interrupt_addr,
            max_len: descs.interrupt_ep.max_packet_size,
        });

        // If mac_string_index is 0, there's no MAC string descriptor to
        // fetch — mark driver as initialized with a zero MAC. The caller
        // can discover the MAC via other means (e.g., SET_NET_ADDRESS or
        // the first received frame's destination).
        let initialized = descs.mac_string_index == 0;

        let driver = Self {
            descriptors: descs,
            codec,
            link_up: false,
            speed_down: 0,
            speed_up: 0,
            rx_queue: VecDeque::new(),
            pending_actions: Vec::new(),
            mac: [0u8; 6],
            initialized,
        };

        Ok(Some((driver, actions)))
    }

    /// Complete driver initialization by parsing a USB MAC address string
    /// descriptor.
    ///
    /// The `mac_string` must be a USB string descriptor (UTF-16LE) containing
    /// 12 hex characters encoding 6 MAC bytes: `[bLength, 0x03, c0_lo, 0x00,
    /// c1_lo, 0x00, ...]`.  Minimum 26 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CdcError::InvalidMacString`] if the descriptor is too short
    /// or contains non-hex characters.
    pub fn complete_init(&mut self, mac_string: &[u8]) -> Result<(), CdcError> {
        // USB string descriptor: [bLength, 0x03, char0_lo, char0_hi, ...]
        // For ASCII hex chars, hi byte is 0x00.
        // 12 hex chars × 2 bytes/char + 2 header = 26 bytes minimum.
        if mac_string.len() < 26 {
            return Err(CdcError::InvalidMacString);
        }

        // Extract the 12 low bytes (hex ASCII characters).
        let mut hex_chars = [0u8; 12];
        for i in 0..12 {
            hex_chars[i] = mac_string[2 + i * 2]; // skip header, take low byte
        }

        // Parse pairs of hex nibbles into MAC bytes.
        for i in 0..6 {
            let hi = hex_nibble(hex_chars[i * 2]).ok_or(CdcError::InvalidMacString)?;
            let lo = hex_nibble(hex_chars[i * 2 + 1]).ok_or(CdcError::InvalidMacString)?;
            self.mac[i] = (hi << 4) | lo;
        }

        self.initialized = true;
        Ok(())
    }

    /// Process data received on the bulk IN endpoint.
    ///
    /// Decodes the transfer via the codec, queues any resulting Ethernet
    /// frames, and returns a re-queued `BulkIn` action.
    pub fn receive_bulk_in(&mut self, data: &[u8]) -> Vec<CdcAction> {
        let mut frames = Vec::new();
        // Decode errors are silently dropped — malformed transfers are common
        // on USB and retrying is the correct response.
        let _ = self.codec.decode_rx(data, &mut frames);
        for frame in frames {
            self.rx_queue.push_back(frame);
        }

        let bulk_in_addr = self.descriptors.bulk_in_ep.address & 0x0F;
        vec![CdcAction::BulkIn {
            ep: bulk_in_addr,
            max_len: self.bulk_in_buffer_size(),
        }]
    }

    /// Process data received on the interrupt IN endpoint.
    ///
    /// Parses the CDC notification, updates driver state (link up/down, speed),
    /// and returns a re-queued `InterruptIn` action.
    pub fn receive_interrupt(&mut self, data: &[u8]) -> Vec<CdcAction> {
        if let Ok(notif) = parse_notification(data) {
            match notif {
                Notif::NetworkConnection { connected } => {
                    self.link_up = connected;
                }
                Notif::ConnectionSpeedChange {
                    downstream,
                    upstream,
                } => {
                    self.speed_down = downstream;
                    self.speed_up = upstream;
                }
                Notif::Unknown { .. } => {}
            }
        }
        // Always re-queue the interrupt IN regardless of parse result.
        let interrupt_addr = self.descriptors.interrupt_ep.address & 0x0F;
        vec![CdcAction::InterruptIn {
            ep: interrupt_addr,
            max_len: self.descriptors.interrupt_ep.max_packet_size,
        }]
    }

    /// Encode an Ethernet frame for transmission.
    ///
    /// # Errors
    ///
    /// - [`CdcError::NotReady`] if `complete_init` has not been called.
    /// - [`CdcError::FrameTooLarge`] if the frame exceeds `max_segment_size`
    ///   (ECM) or codec limits (NCM).
    pub fn send_frame(&mut self, frame: &[u8]) -> Result<Vec<CdcAction>, CdcError> {
        if !self.initialized {
            return Err(CdcError::NotReady);
        }

        if frame.is_empty() {
            return Err(CdcError::FrameEmpty);
        }

        // ECM: check max_segment_size.  NCM: the codec handles size limits.
        if self.descriptors.max_segment_size > 0
            && frame.len() > self.descriptors.max_segment_size as usize
        {
            return Err(CdcError::FrameTooLarge);
        }

        let encoded = self.codec.encode_tx(frame)?;
        let bulk_out_addr = self.descriptors.bulk_out_ep.address & 0x0F;

        Ok(vec![CdcAction::BulkOut {
            ep: bulk_out_addr,
            data: encoded,
        }])
    }

    /// Drain all pending actions accumulated by `queue_tx_frame`.
    pub fn drain_pending_actions(&mut self) -> Vec<CdcAction> {
        core::mem::take(&mut self.pending_actions)
    }

    /// Return the detected CDC protocol variant.
    pub fn protocol(&self) -> CdcProtocol {
        self.descriptors.protocol
    }

    /// Compute the bulk IN buffer size for a complete transfer.
    /// ECM: one Ethernet frame. NCM: one NTB.
    fn bulk_in_buffer_size(&self) -> u16 {
        match self.descriptors.protocol {
            CdcProtocol::Ecm => self.descriptors.max_segment_size.max(1514),
            CdcProtocol::Ncm => {
                (self.descriptors.max_ntb_size.min(u16::MAX as u32) as u16).max(2048)
            }
        }
    }

    // ── NetworkDevice-compatible methods ─────────────────────────────────────

    /// Pop the next received Ethernet frame into `out`, returning the frame
    /// length, or `None` if the receive queue is empty.
    ///
    /// If the front frame is larger than `out`, it is **dropped** to prevent
    /// head-of-line blocking (an oversized frame would otherwise permanently
    /// stall the queue).  Network protocols recover from drops via
    /// retransmission.
    pub fn poll_rx_frame(&mut self, out: &mut [u8]) -> Option<usize> {
        let frame = self.rx_queue.front()?;
        if frame.len() > out.len() {
            // Drop the oversized frame so it doesn't block subsequent frames.
            self.rx_queue.pop_front();
            return None;
        }
        let frame = self.rx_queue.pop_front().unwrap();
        out[..frame.len()].copy_from_slice(&frame);
        Some(frame.len())
    }

    /// Queue an Ethernet frame for transmission.
    ///
    /// Returns `true` on success.  The resulting [`CdcAction`] is buffered in
    /// `pending_actions`; call [`drain_pending_actions`](Self::drain_pending_actions)
    /// to retrieve it.
    pub fn queue_tx_frame(&mut self, frame: &[u8]) -> bool {
        match self.send_frame(frame) {
            Ok(actions) => {
                self.pending_actions.extend(actions);
                true
            }
            Err(_) => false,
        }
    }

    /// Return the MAC address (all zeros until `complete_init` succeeds).
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Return whether the network link is up.
    pub fn link_up(&self) -> bool {
        self.link_up
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a USB string descriptor containing a MAC address in UTF-16LE.
    ///
    /// `ascii_hex` must be exactly 12 ASCII hex characters (e.g. "AABBCCDDEEFF").
    fn build_mac_string_descriptor(ascii_hex: &[u8; 12]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(26);
        buf.push(26); // bLength
        buf.push(0x03); // bDescriptorType: STRING
        for &ch in ascii_hex.iter() {
            buf.push(ch); // low byte (ASCII)
            buf.push(0x00); // high byte (0 for ASCII)
        }
        assert_eq!(buf.len(), 26);
        buf
    }

    // ── from_config_descriptor ───────────────────────────────────────────────

    #[test]
    fn from_config_descriptor_ecm() {
        let desc = super::descriptor::tests::build_ecm_config_desc();
        let (driver, actions) = CdcEthernetDriver::from_config_descriptor(1, &desc)
            .expect("parse must not fail")
            .expect("must find CDC ECM");

        // 6 actions: SET_CONFIG, SET_INTERFACE, GET_STRING, SET_PACKET_FILTER,
        //            BulkIn, InterruptIn
        assert_eq!(actions.len(), 6);

        // Verify action types in order.
        assert!(matches!(actions[0], CdcAction::ControlOut { .. }));
        assert!(matches!(actions[1], CdcAction::ControlOut { .. }));
        assert!(matches!(actions[2], CdcAction::ControlIn { .. }));
        assert!(matches!(actions[3], CdcAction::ControlOut { .. }));
        assert!(matches!(actions[4], CdcAction::BulkIn { .. }));
        assert!(matches!(actions[5], CdcAction::InterruptIn { .. }));

        // Driver state.
        assert_eq!(driver.protocol(), CdcProtocol::Ecm);
        assert!(!driver.initialized);
        assert!(!driver.link_up());
        assert_eq!(driver.mac(), [0; 6]);
    }

    #[test]
    fn from_config_descriptor_no_cdc() {
        // HID-only config descriptor — no CDC interface.
        let desc = &[
            9, 0x02, 25, 0x00, 1, 1, 0, 0x80, 50, // Config (9)
            9, 0x04, 0, 0, 1, 0x03, 0x01, 0x01, 0, // HID Interface (9)
            7, 0x05, 0x81, 0x03, 8, 0x00, 10, // Interrupt EP (7)
        ];
        let result =
            CdcEthernetDriver::from_config_descriptor(1, desc).expect("parse must not fail");
        assert!(result.is_none());
    }

    // ── complete_init ────────────────────────────────────────────────────────

    #[test]
    fn complete_init_parses_mac() {
        let desc = super::descriptor::tests::build_ecm_config_desc();
        let (mut driver, _) = CdcEthernetDriver::from_config_descriptor(1, &desc)
            .unwrap()
            .unwrap();

        let mac_str = build_mac_string_descriptor(b"AABBCCDDEEFF");
        driver.complete_init(&mac_str).unwrap();

        assert_eq!(driver.mac(), [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert!(driver.initialized);
    }

    #[test]
    fn complete_init_lowercase_mac() {
        let desc = super::descriptor::tests::build_ecm_config_desc();
        let (mut driver, _) = CdcEthernetDriver::from_config_descriptor(1, &desc)
            .unwrap()
            .unwrap();

        let mac_str = build_mac_string_descriptor(b"aabbccddeeff");
        driver.complete_init(&mac_str).unwrap();

        assert_eq!(driver.mac(), [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn complete_init_too_short() {
        let desc = super::descriptor::tests::build_ecm_config_desc();
        let (mut driver, _) = CdcEthernetDriver::from_config_descriptor(1, &desc)
            .unwrap()
            .unwrap();

        // Only 24 bytes — needs 26.
        let short = vec![
            24, 0x03, b'A', 0, b'A', 0, b'B', 0, b'B', 0, b'C', 0, b'C', 0, b'D', 0, b'D', 0, b'E',
            0, b'E', 0, b'F', 0,
        ];
        assert_eq!(
            driver.complete_init(&short),
            Err(CdcError::InvalidMacString)
        );
    }

    #[test]
    fn complete_init_invalid_hex() {
        let desc = super::descriptor::tests::build_ecm_config_desc();
        let (mut driver, _) = CdcEthernetDriver::from_config_descriptor(1, &desc)
            .unwrap()
            .unwrap();

        let mac_str = build_mac_string_descriptor(b"GGHHIIJJKKLL");
        assert_eq!(
            driver.complete_init(&mac_str),
            Err(CdcError::InvalidMacString)
        );
    }

    // ── receive_bulk_in ──────────────────────────────────────────────────────

    #[test]
    fn receive_ecm_frame() {
        let desc = super::descriptor::tests::build_ecm_config_desc();
        let (mut driver, _) = CdcEthernetDriver::from_config_descriptor(1, &desc)
            .unwrap()
            .unwrap();

        let frame = [0xAAu8; 64];
        let actions = driver.receive_bulk_in(&frame);

        // Re-queues a BulkIn.
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], CdcAction::BulkIn { .. }));

        // Frame should be in the rx queue.
        let mut buf = [0u8; 128];
        let len = driver
            .poll_rx_frame(&mut buf)
            .expect("frame must be queued");
        assert_eq!(len, 64);
        assert_eq!(&buf[..len], &frame);
    }

    #[test]
    fn receive_empty_bulk_in() {
        let desc = super::descriptor::tests::build_ecm_config_desc();
        let (mut driver, _) = CdcEthernetDriver::from_config_descriptor(1, &desc)
            .unwrap()
            .unwrap();

        let actions = driver.receive_bulk_in(&[]);

        // Still re-queues BulkIn.
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], CdcAction::BulkIn { .. }));

        // No frame queued.
        let mut buf = [0u8; 64];
        assert!(driver.poll_rx_frame(&mut buf).is_none());
    }

    // ── send_frame ───────────────────────────────────────────────────────────

    #[test]
    fn send_ecm_frame() {
        let desc = super::descriptor::tests::build_ecm_config_desc();
        let (mut driver, _) = CdcEthernetDriver::from_config_descriptor(1, &desc)
            .unwrap()
            .unwrap();

        // Initialize so send_frame works.
        let mac_str = build_mac_string_descriptor(b"001122334455");
        driver.complete_init(&mac_str).unwrap();

        let frame = [0x55u8; 100];
        let actions = driver.send_frame(&frame).unwrap();

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            CdcAction::BulkOut { ep, data } => {
                // Bulk OUT EP address is 0x02, low 4 bits = 2.
                assert_eq!(*ep, 2);
                // ECM: passthrough, data == frame.
                assert_eq!(data.as_slice(), &frame);
            }
            other => panic!("expected BulkOut, got {:?}", other),
        }
    }

    #[test]
    fn send_before_init_fails() {
        let desc = super::descriptor::tests::build_ecm_config_desc();
        let (mut driver, _) = CdcEthernetDriver::from_config_descriptor(1, &desc)
            .unwrap()
            .unwrap();

        let result = driver.send_frame(&[0u8; 64]);
        assert_eq!(result, Err(CdcError::NotReady));
    }

    #[test]
    fn send_oversized_frame_fails() {
        let desc = super::descriptor::tests::build_ecm_config_desc();
        let (mut driver, _) = CdcEthernetDriver::from_config_descriptor(1, &desc)
            .unwrap()
            .unwrap();

        let mac_str = build_mac_string_descriptor(b"001122334455");
        driver.complete_init(&mac_str).unwrap();

        // max_segment_size = 1514 in our test descriptor.
        let oversized = vec![0u8; 1515];
        assert_eq!(driver.send_frame(&oversized), Err(CdcError::FrameTooLarge));
    }

    #[test]
    fn send_empty_frame_fails() {
        let desc = super::descriptor::tests::build_ecm_config_desc();
        let (mut driver, _) = CdcEthernetDriver::from_config_descriptor(1, &desc)
            .unwrap()
            .unwrap();

        let mac_str = build_mac_string_descriptor(b"001122334455");
        driver.complete_init(&mac_str).unwrap();

        assert_eq!(driver.send_frame(&[]), Err(CdcError::FrameEmpty));
    }

    // ── queue_tx_frame ───────────────────────────────────────────────────────

    #[test]
    fn queue_tx_frame_buffers_actions() {
        let desc = super::descriptor::tests::build_ecm_config_desc();
        let (mut driver, _) = CdcEthernetDriver::from_config_descriptor(1, &desc)
            .unwrap()
            .unwrap();

        let mac_str = build_mac_string_descriptor(b"001122334455");
        driver.complete_init(&mac_str).unwrap();

        assert!(driver.queue_tx_frame(&[0xAB; 60]));

        let drained = driver.drain_pending_actions();
        assert_eq!(drained.len(), 1);
        assert!(matches!(drained[0], CdcAction::BulkOut { .. }));

        // Second drain should be empty.
        assert!(driver.drain_pending_actions().is_empty());
    }

    // ── receive_interrupt (notifications) ────────────────────────────────────

    #[test]
    fn receive_link_up_notification() {
        let desc = super::descriptor::tests::build_ecm_config_desc();
        let (mut driver, _) = CdcEthernetDriver::from_config_descriptor(1, &desc)
            .unwrap()
            .unwrap();

        assert!(!driver.link_up());

        // NETWORK_CONNECTION, wValue=1 (connected).
        let notif = [0xA1, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        let actions = driver.receive_interrupt(&notif);

        assert!(driver.link_up());
        // Re-queues InterruptIn.
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], CdcAction::InterruptIn { .. }));
    }

    #[test]
    fn receive_link_down_notification() {
        let desc = super::descriptor::tests::build_ecm_config_desc();
        let (mut driver, _) = CdcEthernetDriver::from_config_descriptor(1, &desc)
            .unwrap()
            .unwrap();

        // Set link up first.
        let up = [0xA1, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        driver.receive_interrupt(&up);
        assert!(driver.link_up());

        // NETWORK_CONNECTION, wValue=0 (disconnected).
        let down = [0xA1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        driver.receive_interrupt(&down);
        assert!(!driver.link_up());
    }

    #[test]
    fn receive_speed_change_notification() {
        let desc = super::descriptor::tests::build_ecm_config_desc();
        let (mut driver, _) = CdcEthernetDriver::from_config_descriptor(1, &desc)
            .unwrap()
            .unwrap();

        // CONNECTION_SPEED_CHANGE: downstream=100Mbps, upstream=10Mbps.
        let mut notif = [0u8; 16];
        notif[0] = 0xA1;
        notif[1] = 0x2A; // CONNECTION_SPEED_CHANGE
        notif[6] = 8; // wLength = 8
        notif[8..12].copy_from_slice(&100_000_000u32.to_le_bytes());
        notif[12..16].copy_from_slice(&10_000_000u32.to_le_bytes());

        let actions = driver.receive_interrupt(&notif);
        assert_eq!(driver.speed_down, 100_000_000);
        assert_eq!(driver.speed_up, 10_000_000);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], CdcAction::InterruptIn { .. }));
    }

    #[test]
    fn poll_rx_drops_oversized_frame() {
        let desc = super::descriptor::tests::build_ecm_config_desc();
        let (mut driver, _) = CdcEthernetDriver::from_config_descriptor(1, &desc)
            .unwrap()
            .unwrap();

        // Queue two frames: a large one (128 bytes) and a small one (32 bytes).
        driver.receive_bulk_in(&[0xAA; 128]);
        driver.receive_bulk_in(&[0xBB; 32]);
        assert_eq!(driver.rx_queue.len(), 2);

        // Try to poll with a 64-byte buffer — too small for the first frame.
        let mut buf = [0u8; 64];
        assert!(driver.poll_rx_frame(&mut buf).is_none());

        // The oversized frame was dropped, not left blocking the queue.
        assert_eq!(driver.rx_queue.len(), 1);

        // The second (smaller) frame is now accessible.
        let len = driver
            .poll_rx_frame(&mut buf)
            .expect("second frame must be available");
        assert_eq!(len, 32);
        assert_eq!(&buf[..len], &[0xBB; 32]);
    }

    #[test]
    fn receive_malformed_notification_ignored() {
        let desc = super::descriptor::tests::build_ecm_config_desc();
        let (mut driver, _) = CdcEthernetDriver::from_config_descriptor(1, &desc)
            .unwrap()
            .unwrap();

        // Only 4 bytes — too short for a notification header.
        let short = [0xA1, 0x00, 0x01, 0x00];
        let actions = driver.receive_interrupt(&short);

        // Should not panic, and should still re-queue InterruptIn.
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], CdcAction::InterruptIn { .. }));
    }
}
