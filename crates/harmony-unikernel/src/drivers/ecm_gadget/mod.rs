// SPDX-License-Identifier: GPL-2.0-or-later
//! CDC-ECM USB gadget function.
pub mod descriptor;

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use super::dwc2::types::{GadgetEvent, GadgetRequest};
use descriptor::{build_config_descriptor, build_device_descriptor, build_string_descriptors};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum Ethernet frame size (excl. FCS), matching IEEE 802.3.
pub const MAX_FRAME_SIZE: usize = 1514;

/// CDC notification: NETWORK_CONNECTION
const NOTIF_NETWORK_CONNECTION: u8 = 0x00;
/// CDC notification: CONNECTION_SPEED_CHANGE
const NOTIF_CONNECTION_SPEED_CHANGE: u8 = 0x2A;

/// Interrupt IN endpoint number (EP3).
const EP_INTERRUPT_IN: u8 = 3;
/// Bulk IN endpoint number (EP1).
const EP_BULK_IN: u8 = 1;

/// bRequest: SET_ETHERNET_PACKET_FILTER
const REQ_SET_ETHERNET_PACKET_FILTER: u8 = 0x43;

// ── Struct ───────────────────────────────────────────────────────────────────

/// CDC-ECM gadget class driver.
///
/// Implements sans-I/O class request handling, CDC notification building, and
/// Ethernet frame bridging between the USB bulk endpoints and the caller's
/// network stack.
pub struct EcmGadget {
    mac: [u8; 6],
    configured: bool,
    rx_queue: VecDeque<Vec<u8>>,
    pending_requests: Vec<GadgetRequest>,
}

// ── Public API ───────────────────────────────────────────────────────────────

impl EcmGadget {
    /// Create a new `EcmGadget` and return the USB descriptors.
    ///
    /// Returns `(gadget, device_desc, config_desc, string_descs)`.
    pub fn new(mac: [u8; 6]) -> (Self, Vec<u8>, Vec<u8>, Vec<Vec<u8>>) {
        let device_desc = build_device_descriptor();
        let config_desc = build_config_descriptor();
        let string_descs = build_string_descriptors(&mac);

        let gadget = EcmGadget {
            mac,
            configured: false,
            rx_queue: VecDeque::new(),
            pending_requests: Vec::new(),
        };

        (gadget, device_desc, config_desc, string_descs)
    }

    /// Handle a gadget event and return zero or more requests for the controller.
    pub fn handle_event(&mut self, event: GadgetEvent) -> Vec<GadgetRequest> {
        match event {
            GadgetEvent::Reset => {
                self.configured = false;
                self.rx_queue.clear();
                self.pending_requests.clear();
                vec![GadgetRequest::InterruptIn {
                    ep: EP_INTERRUPT_IN,
                    data: Self::build_network_connection(false),
                }]
            }

            GadgetEvent::Configured => {
                self.configured = true;
                vec![
                    GadgetRequest::InterruptIn {
                        ep: EP_INTERRUPT_IN,
                        data: Self::build_network_connection(true),
                    },
                    GadgetRequest::InterruptIn {
                        ep: EP_INTERRUPT_IN,
                        data: Self::build_speed_change(480_000_000, 480_000_000),
                    },
                ]
            }

            GadgetEvent::SetupClassRequest { setup } => self.handle_class_request(setup),

            GadgetEvent::GetDescriptor { .. } => {
                // All descriptors are pre-registered with the controller.
                vec![GadgetRequest::ControlStall]
            }

            GadgetEvent::BulkOut { data, .. } => {
                if !data.is_empty() && data.len() <= MAX_FRAME_SIZE {
                    self.rx_queue.push_back(data);
                }
                vec![]
            }

            GadgetEvent::BulkInComplete { .. } => {
                // Nothing — handled by queue_tx_frame / drain_pending_requests.
                vec![]
            }

            GadgetEvent::Suspended => {
                vec![GadgetRequest::InterruptIn {
                    ep: EP_INTERRUPT_IN,
                    data: Self::build_network_connection(false),
                }]
            }

            GadgetEvent::Resumed => {
                if self.configured {
                    vec![GadgetRequest::InterruptIn {
                        ep: EP_INTERRUPT_IN,
                        data: Self::build_network_connection(true),
                    }]
                } else {
                    vec![]
                }
            }
        }
    }

    /// Pop the next received Ethernet frame into `out`.
    ///
    /// Returns `Some(len)` on success, `None` if the queue is empty.
    /// Frames that are larger than `out` are dropped (not re-queued).
    pub fn poll_rx_frame(&mut self, out: &mut [u8]) -> Option<usize> {
        let frame = self.rx_queue.pop_front()?;
        if frame.len() > out.len() {
            // Drop oversized frame — same pattern as host driver.
            return None;
        }
        let len = frame.len();
        out[..len].copy_from_slice(&frame);
        Some(len)
    }

    /// Enqueue an Ethernet frame for transmission over the bulk IN endpoint.
    ///
    /// Returns `false` if the gadget is not configured, the frame is empty,
    /// or the frame exceeds `MAX_FRAME_SIZE`.
    pub fn queue_tx_frame(&mut self, frame: &[u8]) -> bool {
        if !self.configured || frame.is_empty() || frame.len() > MAX_FRAME_SIZE {
            return false;
        }
        self.pending_requests.push(GadgetRequest::BulkIn {
            ep: EP_BULK_IN,
            data: frame.to_vec(),
        });
        true
    }

    /// Take all pending requests (e.g. queued TX frames) for the controller.
    pub fn drain_pending_requests(&mut self) -> Vec<GadgetRequest> {
        core::mem::take(&mut self.pending_requests)
    }

    /// Return the gadget MAC address.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Returns `true` when the host has configured the device (link is up).
    pub fn link_up(&self) -> bool {
        self.configured
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

impl EcmGadget {
    /// Dispatch a CDC class-specific SETUP request.
    fn handle_class_request(&self, setup: [u8; 8]) -> Vec<GadgetRequest> {
        // setup[1] = bRequest
        if setup[1] == REQ_SET_ETHERNET_PACKET_FILTER {
            vec![GadgetRequest::ControlAck]
        } else {
            vec![GadgetRequest::ControlStall]
        }
    }

    /// Build an 8-byte CDC NETWORK_CONNECTION notification.
    ///
    /// ```text
    /// [bmRequestType, bNotification, wValue_lo, wValue_hi,
    ///  wIndex_lo, wIndex_hi, wLength_lo, wLength_hi]
    /// ```
    /// `wValue` encodes the connection state: 0=disconnected, 1=connected.
    fn build_network_connection(connected: bool) -> Vec<u8> {
        vec![
            0xA1,                     // bmRequestType: class, interface, device-to-host
            NOTIF_NETWORK_CONNECTION, // bNotification: NETWORK_CONNECTION (0x00)
            connected as u8,          // wValue low: 0=disconnected, 1=connected
            0x00,                     // wValue high
            0x00,                     // wIndex low  (interface 0)
            0x00,                     // wIndex high
            0x00,                     // wLength low  (no data stage)
            0x00,                     // wLength high
        ]
    }

    /// Build a 16-byte CDC CONNECTION_SPEED_CHANGE notification.
    ///
    /// ```text
    /// [bmRequestType, bNotification, wValue=0, wIndex=0, wLength=8]
    /// followed by DLBitRate (LE u32) and ULBitRate (LE u32)
    /// ```
    fn build_speed_change(downstream: u32, upstream: u32) -> Vec<u8> {
        let mut v = vec![
            0xA1,                          // bmRequestType
            NOTIF_CONNECTION_SPEED_CHANGE, // bNotification: CONNECTION_SPEED_CHANGE (0x2A)
            0x00,                          // wValue low
            0x00,                          // wValue high
            0x00,                          // wIndex low
            0x00,                          // wIndex high
            0x08,                          // wLength low  (8 bytes of data follow)
            0x00,                          // wLength high
        ];
        v.extend_from_slice(&downstream.to_le_bytes());
        v.extend_from_slice(&upstream.to_le_bytes());
        v
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gadget() -> EcmGadget {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let (gadget, _, _, _) = EcmGadget::new(mac);
        gadget
    }

    // ── Constructor ──────────────────────────────────────────────────────────

    #[test]
    fn new_returns_descriptors() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let (gadget, dev, cfg, strings) = EcmGadget::new(mac);
        assert_eq!(dev.len(), 18);
        assert_eq!(cfg.len(), 80);
        assert_eq!(strings.len(), 5);
        assert!(!gadget.configured);
        assert!(!gadget.link_up());
    }

    // ── Reset ────────────────────────────────────────────────────────────────

    #[test]
    fn reset_clears_state() {
        let mut g = make_gadget();
        g.handle_event(GadgetEvent::Configured);
        // Push a frame so the rx_queue is non-empty.
        g.handle_event(GadgetEvent::BulkOut {
            ep: 2,
            data: vec![0u8; 60],
        });
        assert!(g.configured);

        let reqs = g.handle_event(GadgetEvent::Reset);
        assert!(!g.configured, "configured must be false after reset");
        assert!(g.rx_queue.is_empty(), "rx_queue must be empty after reset");
        // Must send NETWORK_CONNECTION(disconnected) on EP3.
        assert_eq!(reqs.len(), 1);
        if let GadgetRequest::InterruptIn { ep, data } = &reqs[0] {
            assert_eq!(*ep, EP_INTERRUPT_IN);
            assert_eq!(data[2], 0x00, "connected byte must be 0");
        } else {
            panic!("expected InterruptIn");
        }
    }

    // ── Configured ───────────────────────────────────────────────────────────

    #[test]
    fn configured_sends_network_connection() {
        let mut g = make_gadget();
        let reqs = g.handle_event(GadgetEvent::Configured);
        assert!(g.configured);
        assert!(g.link_up());
        assert_eq!(reqs.len(), 2, "must return 2 requests");

        // First: NETWORK_CONNECTION(connected)
        if let GadgetRequest::InterruptIn { ep, data } = &reqs[0] {
            assert_eq!(*ep, EP_INTERRUPT_IN);
            assert_eq!(data[1], NOTIF_NETWORK_CONNECTION);
            assert_eq!(data[2], 0x01, "wValue must be 1 (connected)");
        } else {
            panic!("first request must be InterruptIn");
        }

        // Second: CONNECTION_SPEED_CHANGE (480 Mbps)
        if let GadgetRequest::InterruptIn { ep, data } = &reqs[1] {
            assert_eq!(*ep, EP_INTERRUPT_IN);
            assert_eq!(data[1], NOTIF_CONNECTION_SPEED_CHANGE);
            assert_eq!(data.len(), 16);
            let downstream = u32::from_le_bytes(data[8..12].try_into().unwrap());
            let upstream = u32::from_le_bytes(data[12..16].try_into().unwrap());
            assert_eq!(downstream, 480_000_000);
            assert_eq!(upstream, 480_000_000);
        } else {
            panic!("second request must be InterruptIn");
        }
    }

    // ── Class requests ───────────────────────────────────────────────────────

    #[test]
    fn class_request_packet_filter() {
        let g = make_gadget();
        let setup = [0x21, REQ_SET_ETHERNET_PACKET_FILTER, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00];
        let reqs = g.handle_class_request(setup);
        assert_eq!(reqs, vec![GadgetRequest::ControlAck]);
    }

    #[test]
    fn unknown_class_request_stalled() {
        let g = make_gadget();
        let setup = [0x21, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let reqs = g.handle_class_request(setup);
        assert_eq!(reqs, vec![GadgetRequest::ControlStall]);
    }

    // ── BulkOut / rx_queue ───────────────────────────────────────────────────

    #[test]
    fn bulk_out_queues_frame() {
        let mut g = make_gadget();
        let frame = vec![0xABu8; 60];
        let reqs = g.handle_event(GadgetEvent::BulkOut { ep: 2, data: frame.clone() });
        assert!(reqs.is_empty());
        assert_eq!(g.rx_queue.len(), 1);

        let mut buf = [0u8; 1514];
        let len = g.poll_rx_frame(&mut buf).expect("must return a frame");
        assert_eq!(len, 60);
        assert_eq!(&buf[..60], frame.as_slice());
    }

    #[test]
    fn oversized_bulk_out_dropped() {
        let mut g = make_gadget();
        let big = vec![0u8; MAX_FRAME_SIZE + 1];
        g.handle_event(GadgetEvent::BulkOut { ep: 2, data: big });
        assert!(g.rx_queue.is_empty(), "oversized BulkOut must be dropped");
    }

    // ── queue_tx_frame / drain ───────────────────────────────────────────────

    #[test]
    fn push_rx_returns_bulk_in() {
        let mut g = make_gadget();
        g.handle_event(GadgetEvent::Configured);
        let frame = vec![0xBBu8; 100];
        assert!(g.queue_tx_frame(&frame));
        let reqs = g.drain_pending_requests();
        assert_eq!(reqs.len(), 1);
        if let GadgetRequest::BulkIn { ep, data } = &reqs[0] {
            assert_eq!(*ep, EP_BULK_IN);
            assert_eq!(data, &frame);
        } else {
            panic!("expected BulkIn");
        }
    }

    #[test]
    fn push_rx_before_configured_fails() {
        let mut g = make_gadget();
        assert!(!g.queue_tx_frame(&[0u8; 64]));
    }

    #[test]
    fn oversized_frame_rejected() {
        let mut g = make_gadget();
        g.handle_event(GadgetEvent::Configured);
        let big = vec![0u8; MAX_FRAME_SIZE + 1];
        assert!(!g.queue_tx_frame(&big));
    }

    #[test]
    fn empty_frame_rejected() {
        let mut g = make_gadget();
        g.handle_event(GadgetEvent::Configured);
        assert!(!g.queue_tx_frame(&[]));
    }

    // ── mac() / link_up() ────────────────────────────────────────────────────

    #[test]
    fn mac_address() {
        let mac = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let (g, _, _, _) = EcmGadget::new(mac);
        assert_eq!(g.mac(), mac);
    }

    // ── Suspended / Resumed ──────────────────────────────────────────────────

    #[test]
    fn suspended_sends_disconnect_notification() {
        let mut g = make_gadget();
        g.handle_event(GadgetEvent::Configured);
        let reqs = g.handle_event(GadgetEvent::Suspended);
        assert_eq!(reqs.len(), 1);
        if let GadgetRequest::InterruptIn { ep, data } = &reqs[0] {
            assert_eq!(*ep, EP_INTERRUPT_IN);
            assert_eq!(data[2], 0x00, "wValue must be 0 (disconnected)");
        } else {
            panic!("expected InterruptIn");
        }
    }

    #[test]
    fn resumed_while_configured_sends_connect() {
        let mut g = make_gadget();
        g.handle_event(GadgetEvent::Configured);
        let reqs = g.handle_event(GadgetEvent::Resumed);
        assert_eq!(reqs.len(), 1);
        if let GadgetRequest::InterruptIn { ep, data } = &reqs[0] {
            assert_eq!(*ep, EP_INTERRUPT_IN);
            assert_eq!(data[2], 0x01, "wValue must be 1 (connected)");
        } else {
            panic!("expected InterruptIn");
        }
    }

    #[test]
    fn resumed_while_not_configured_no_notification() {
        let mut g = make_gadget();
        let reqs = g.handle_event(GadgetEvent::Resumed);
        assert!(reqs.is_empty());
    }

    // ── GetDescriptor ────────────────────────────────────────────────────────

    #[test]
    fn get_descriptor_unknown_stalls() {
        let mut g = make_gadget();
        let reqs = g.handle_event(GadgetEvent::GetDescriptor {
            desc_type: 0xFF,
            desc_index: 0,
            max_len: 255,
        });
        assert_eq!(reqs, vec![GadgetRequest::ControlStall]);
    }

    // ── poll_rx_frame oversized buffer drop ──────────────────────────────────

    #[test]
    fn poll_rx_drops_oversized_for_buffer() {
        let mut g = make_gadget();
        // Enqueue a 128-byte frame.
        g.handle_event(GadgetEvent::BulkOut { ep: 2, data: vec![0xAAu8; 128] });
        // Enqueue a 32-byte frame.
        g.handle_event(GadgetEvent::BulkOut { ep: 2, data: vec![0xBBu8; 32] });

        // Try to pop into a 64-byte buffer — first frame (128 bytes) is too big → dropped.
        let mut buf = [0u8; 64];
        let result = g.poll_rx_frame(&mut buf);
        assert!(result.is_none(), "oversized frame must be dropped (return None)");

        // Second frame (32 bytes) must be accessible.
        let len = g.poll_rx_frame(&mut buf).expect("second frame must be returned");
        assert_eq!(len, 32);
        assert!(buf[..32].iter().all(|&b| b == 0xBB));
    }
}
