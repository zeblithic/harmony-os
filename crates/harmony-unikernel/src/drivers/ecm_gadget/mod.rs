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
    /// A bulk IN transfer is currently in-flight on EP1.
    tx_in_flight: bool,
    /// An interrupt IN transfer is currently in-flight on EP3.
    intr_in_flight: bool,
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
            tx_in_flight: false,
            intr_in_flight: false,
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
                self.tx_in_flight = false;
                self.intr_in_flight = false;
                self.rx_queue.clear();
                self.pending_requests.clear();
                // No notification — EP3 is disabled during bus reset / deconfigure.
                // The host isn't listening on a reset bus anyway.
                vec![]
            }

            GadgetEvent::Configured => {
                self.configured = true;
                // Send NETWORK_CONNECTION immediately, queue SPEED_CHANGE
                // for deferred delivery after EP3 InTransferComplete.
                // Only one interrupt IN transfer can be active at a time.
                self.intr_in_flight = true;
                self.pending_requests.push(GadgetRequest::InterruptIn {
                    ep: EP_INTERRUPT_IN,
                    data: Self::build_speed_change(480_000_000, 480_000_000),
                });
                vec![GadgetRequest::InterruptIn {
                    ep: EP_INTERRUPT_IN,
                    data: Self::build_network_connection(true),
                }]
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

            GadgetEvent::BulkInComplete { ep } => {
                if ep == 1 {
                    self.tx_in_flight = false;
                } else if ep == 3 {
                    self.intr_in_flight = false;
                }
                vec![]
            }

            GadgetEvent::Suspended => {
                if self.configured && !self.intr_in_flight {
                    self.intr_in_flight = true;
                    vec![GadgetRequest::InterruptIn {
                        ep: EP_INTERRUPT_IN,
                        data: Self::build_network_connection(false),
                    }]
                } else {
                    vec![]
                }
            }

            GadgetEvent::Resumed => {
                // Clear intr_in_flight unconditionally: any in-flight notification
                // from Suspended cannot have completed (host wasn't polling during
                // suspend), so it's stale. The connect notification supersedes it.
                self.intr_in_flight = false;
                if self.configured {
                    self.intr_in_flight = true;
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
        let frame = self.rx_queue.front()?;
        if frame.len() > out.len() {
            // Drop the oversized frame to prevent head-of-line blocking.
            // Same pattern as the host-side CdcEthernetDriver::poll_rx_frame.
            self.rx_queue.pop_front();
            return None;
        }
        let frame = self.rx_queue.pop_front().unwrap();
        out[..frame.len()].copy_from_slice(&frame);
        Some(frame.len())
    }

    /// Enqueue an Ethernet frame for transmission over the bulk IN endpoint.
    ///
    /// Returns `false` if the gadget is not configured, the frame is empty,
    /// the frame exceeds `MAX_FRAME_SIZE`, or a transfer is already in-flight.
    /// USB allows at most one active IN transfer per endpoint — call this
    /// again after receiving `BulkInComplete`.
    pub fn queue_tx_frame(&mut self, frame: &[u8]) -> bool {
        if !self.configured || self.tx_in_flight || frame.is_empty() || frame.len() > MAX_FRAME_SIZE
        {
            return false;
        }
        self.tx_in_flight = true;
        self.pending_requests.push(GadgetRequest::BulkIn {
            ep: EP_BULK_IN,
            data: frame.to_vec(),
        });
        true
    }

    /// Take the next pending request for the controller.
    ///
    /// Returns one request at a time to enforce single-transfer-per-endpoint
    /// flow control on the bulk IN path.
    pub fn drain_pending_requests(&mut self) -> Option<GadgetRequest> {
        if self.pending_requests.is_empty() {
            return None;
        }
        let req = self.pending_requests.remove(0);
        // Set in-flight for interrupt requests queued internally (e.g.,
        // SPEED_CHANGE from Configured). BulkIn is already guarded by
        // queue_tx_frame setting tx_in_flight eagerly on enqueue.
        if matches!(&req, GadgetRequest::InterruptIn { .. }) {
            self.intr_in_flight = true;
        }
        Some(req)
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

    /// Create a configured gadget with all pending notifications drained.
    fn make_configured_gadget() -> EcmGadget {
        let mut g = make_gadget();
        g.handle_event(GadgetEvent::Configured);
        // Simulate EP3 completion to release intr_in_flight.
        g.handle_event(GadgetEvent::BulkInComplete { ep: 3 });
        // Drain the queued SPEED_CHANGE notification.
        let _ = g.drain_pending_requests();
        // Simulate EP3 completion for the SPEED_CHANGE.
        g.handle_event(GadgetEvent::BulkInComplete { ep: 3 });
        g
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
        // No notification on reset — EP3 is disabled, host isn't listening.
        assert!(reqs.is_empty());
    }

    // ── Configured ───────────────────────────────────────────────────────────

    #[test]
    fn configured_sends_network_connection() {
        let mut g = make_gadget();
        let reqs = g.handle_event(GadgetEvent::Configured);
        assert!(g.configured);
        assert!(g.link_up());

        // Only NETWORK_CONNECTION sent immediately (one transfer per EP3 at a time).
        assert_eq!(reqs.len(), 1, "must return 1 immediate request");
        if let GadgetRequest::InterruptIn { ep, data } = &reqs[0] {
            assert_eq!(*ep, EP_INTERRUPT_IN);
            assert_eq!(data[1], NOTIF_NETWORK_CONNECTION);
            assert_eq!(data[2], 0x01, "wValue must be 1 (connected)");
        } else {
            panic!("first request must be InterruptIn");
        }

        // SPEED_CHANGE is queued for deferred delivery after EP3 completes.
        assert!(g.intr_in_flight);
        // Simulate EP3 transfer complete.
        g.handle_event(GadgetEvent::BulkInComplete { ep: 3 });
        assert!(!g.intr_in_flight);

        // Now drain the queued SPEED_CHANGE notification.
        let speed_req = g
            .drain_pending_requests()
            .expect("SPEED_CHANGE must be queued");
        if let GadgetRequest::InterruptIn { ep, data } = &speed_req {
            assert_eq!(*ep, EP_INTERRUPT_IN);
            assert_eq!(data[1], NOTIF_CONNECTION_SPEED_CHANGE);
            assert_eq!(data.len(), 16);
            let downstream = u32::from_le_bytes(data[8..12].try_into().unwrap());
            assert_eq!(downstream, 480_000_000);
        } else {
            panic!("queued request must be InterruptIn SPEED_CHANGE");
        }
    }

    // ── Class requests ───────────────────────────────────────────────────────

    #[test]
    fn class_request_packet_filter() {
        let g = make_gadget();
        let setup = [
            0x21,
            REQ_SET_ETHERNET_PACKET_FILTER,
            0x00,
            0x00,
            0x00,
            0x00,
            0x02,
            0x00,
        ];
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
        let reqs = g.handle_event(GadgetEvent::BulkOut {
            ep: 2,
            data: frame.clone(),
        });
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
        let mut g = make_configured_gadget();
        let frame = vec![0xBBu8; 100];
        assert!(g.queue_tx_frame(&frame));
        let req = g
            .drain_pending_requests()
            .expect("should have one pending request");
        if let GadgetRequest::BulkIn { ep, data } = &req {
            assert_eq!(*ep, EP_BULK_IN);
            assert_eq!(data, &frame);
        } else {
            panic!("expected BulkIn, got {:?}", req);
        }
    }

    #[test]
    fn push_rx_before_configured_fails() {
        let mut g = make_gadget();
        assert!(!g.queue_tx_frame(&[0u8; 64]));
    }

    #[test]
    fn push_rx_while_in_flight_rejected() {
        let mut g = make_configured_gadget();
        assert!(g.queue_tx_frame(&[0xAA; 60]));
        // Second frame rejected — transfer still in-flight.
        assert!(!g.queue_tx_frame(&[0xBB; 60]));
        // After BulkInComplete, next frame is accepted.
        g.handle_event(GadgetEvent::BulkInComplete { ep: 1 });
        assert!(g.queue_tx_frame(&[0xCC; 60]));
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
        let mut g = make_configured_gadget();
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
        let mut g = make_configured_gadget();
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

    #[test]
    fn suspended_while_not_configured_no_notification() {
        let mut g = make_gadget();
        let reqs = g.handle_event(GadgetEvent::Suspended);
        assert!(reqs.is_empty());
    }

    #[test]
    fn suspend_then_resume_sends_both_notifications() {
        let mut g = make_configured_gadget();

        // Suspend — sends disconnect.
        let reqs = g.handle_event(GadgetEvent::Suspended);
        assert_eq!(reqs.len(), 1);
        if let GadgetRequest::InterruptIn { ep, data } = &reqs[0] {
            assert_eq!(*ep, EP_INTERRUPT_IN);
            assert_eq!(data[2], 0x00, "must be disconnected");
        } else {
            panic!("expected InterruptIn");
        }
        assert!(g.intr_in_flight);

        // Resume — clears stale in-flight, sends connect.
        // (The disconnect couldn't have completed — host wasn't polling.)
        let reqs = g.handle_event(GadgetEvent::Resumed);
        assert_eq!(reqs.len(), 1);
        if let GadgetRequest::InterruptIn { data, .. } = &reqs[0] {
            assert_eq!(data[2], 0x01, "must be connected");
        } else {
            panic!("expected InterruptIn");
        }
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
        g.handle_event(GadgetEvent::BulkOut {
            ep: 2,
            data: vec![0xAAu8; 128],
        });
        // Enqueue a 32-byte frame.
        g.handle_event(GadgetEvent::BulkOut {
            ep: 2,
            data: vec![0xBBu8; 32],
        });

        // Try to pop into a 64-byte buffer — first frame (128 bytes) is too big → dropped.
        let mut buf = [0u8; 64];
        let result = g.poll_rx_frame(&mut buf);
        assert!(
            result.is_none(),
            "oversized frame must be dropped (return None)"
        );

        // Second frame (32 bytes) must be accessible.
        let len = g
            .poll_rx_frame(&mut buf)
            .expect("second frame must be returned");
        assert_eq!(len, 32);
        assert!(buf[..32].iter().all(|&b| b == 0xBB));
    }
}
