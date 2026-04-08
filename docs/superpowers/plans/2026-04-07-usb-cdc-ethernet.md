# USB CDC-ECM/NCM Ethernet Class Driver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a unified CDC-ECM/NCM Ethernet class driver at Ring 1 that implements the `NetworkDevice` trait, enabling reuse of the existing `VirtioNetServer` at Ring 2 for 9P exposure.

**Architecture:** Sans-I/O driver in `harmony-unikernel` parses CDC descriptors from USB config data, encodes/decodes Ethernet frames via a `CdcCodec` enum (ECM passthrough or NCM NTH16/NDP16), parses interrupt notifications, and returns `CdcAction` variants for the caller to execute via xHCI. The driver implements `NetworkDevice` so `VirtioNetServer` works unchanged at Ring 2.

**Tech Stack:** Rust (`no_std`/`alloc`), USB CDC-ECM (USB class 0x02/0x06), USB CDC-NCM (USB class 0x02/0x0D), xHCI bulk/interrupt/control transfers

---

## Context

### Existing infrastructure

- **xHCI driver:** `crates/harmony-unikernel/src/drivers/dwc_usb/` — Phase 3 complete (bulk transfers). Sans-I/O, returns `XhciAction` variants. Has `parse_configuration_tree()` in `context.rs` that walks USB config descriptors but skips unknown descriptor types (including CDC functional descriptors, type 0x24).
- **USB class driver pattern:** `mass_storage.rs` — sans-I/O, builds byte arrays for host to send, parses responses. Caller orchestrates xHCI transfers. `hid_boot.rs` — same pattern with `HidAction` return type.
- **NetworkDevice trait:** `crates/harmony-microkernel/src/net_device.rs` — `poll_tx`, `push_rx`, `mac`, `link_up`. Object-safe.
- **VirtioNetServer:** `crates/harmony-microkernel/src/virtio_net_server.rs` — generic over `NetworkDevice`, exposes 9P namespace `/dev/net/<name>/{data, mac, mtu, stats, link}`. Has comprehensive tests.
- **Driver module registry:** `crates/harmony-unikernel/src/drivers/mod.rs` — lists all driver submodules.

### Key design decisions

- **Unified driver:** One `CdcEthernetDriver` handles both ECM and NCM. A `CdcCodec` enum dispatches the data path.
- **Two-phase init:** `from_config_descriptor()` returns setup actions including a GET_DESCRIPTOR(STRING) for the MAC address. `complete_init()` finalizes with the MAC string response.
- **Polling-based:** Caller drives the loop. `CdcAction` return type supports future event-driven mode without API change.
- **CDC class matching only:** `bInterfaceClass=0x02`, subclass 0x06 (ECM) or 0x0D (NCM). No vendor quirks.

---

### Task 1: CDC notification parser

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/cdc_ethernet/notification.rs`

This is the simplest component — small, self-contained, no dependencies on other CDC code. Building it first establishes the module and error type pattern.

- [ ] **Step 1: Create the module directory and notification.rs with types**

Create `crates/harmony-unikernel/src/drivers/cdc_ethernet/notification.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! CDC notification parser for interrupt IN endpoint data.
//!
//! CDC devices send notifications as 8-byte headers on the interrupt
//! endpoint, optionally followed by payload data. This module parses
//! NETWORK_CONNECTION and CONNECTION_SPEED_CHANGE notifications.

// ── CDC notification codes ──────────────────────────────────────

/// NETWORK_CONNECTION — link state changed.
const NOTIF_NETWORK_CONNECTION: u8 = 0x00;

/// CONNECTION_SPEED_CHANGE — speed renegotiated.
const NOTIF_CONNECTION_SPEED_CHANGE: u8 = 0x2A;

/// Expected bmRequestType for CDC notifications (device-to-host, class, interface).
const CDC_NOTIF_REQUEST_TYPE: u8 = 0xA1;

// ── Types ───────────────────────────────────────────────────────

/// A parsed CDC notification from the interrupt IN endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdcNotification {
    /// Link state changed.
    NetworkConnection { connected: bool },
    /// Speed renegotiated. Values in bits/sec.
    ConnectionSpeedChange { downstream: u32, upstream: u32 },
    /// Notification type not handled — ignore silently.
    Unknown { request: u8 },
}

/// Errors from CDC operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdcError {
    // Descriptor parsing
    /// Config descriptor data truncated.
    DescriptorTooShort,
    /// No CDC ECM/NCM interface found in config descriptor.
    NoCdcInterface,
    /// Required bulk or interrupt endpoint not found.
    MissingEndpoint,
    /// Required CDC functional descriptor absent.
    MissingFunctionalDescriptor,
    /// MAC string descriptor malformed or wrong length.
    InvalidMacString,

    // NCM transfer blocks
    /// NTH16/NDP16 structure invalid (bad signature, out-of-bounds offset, etc.).
    MalformedNtb,

    // Data path
    /// Frame exceeds max_segment_size.
    FrameTooLarge,
    /// Driver not fully initialized (awaiting MAC string response).
    NotReady,

    // Notifications
    /// Notification data too short to parse.
    NotificationTooShort,
}

/// Parse a CDC notification from interrupt IN transfer data.
///
/// The `data` slice contains the 8-byte notification header plus any
/// payload. Returns `Ok(CdcNotification::Unknown)` for unrecognized
/// notification codes — the caller should ignore these, not treat them
/// as errors.
pub fn parse_notification(data: &[u8]) -> Result<CdcNotification, CdcError> {
    if data.len() < 8 {
        return Err(CdcError::NotificationTooShort);
    }

    let _bm_request_type = data[0]; // 0xA1 expected but not enforced
    let b_notification = data[1];
    let w_value = u16::from_le_bytes([data[2], data[3]]);
    let _w_index = u16::from_le_bytes([data[4], data[5]]);
    let w_length = u16::from_le_bytes([data[6], data[7]]);

    match b_notification {
        NOTIF_NETWORK_CONNECTION => {
            Ok(CdcNotification::NetworkConnection {
                connected: w_value != 0,
            })
        }
        NOTIF_CONNECTION_SPEED_CHANGE => {
            // Payload: 8 bytes — downstream (u32 LE) + upstream (u32 LE)
            if w_length < 8 || data.len() < 16 {
                return Err(CdcError::NotificationTooShort);
            }
            let downstream = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
            let upstream = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
            Ok(CdcNotification::ConnectionSpeedChange {
                downstream,
                upstream,
            })
        }
        other => Ok(CdcNotification::Unknown { request: other }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_network_connection_connected() {
        let mut data = [0u8; 8];
        data[0] = CDC_NOTIF_REQUEST_TYPE;
        data[1] = NOTIF_NETWORK_CONNECTION;
        data[2] = 0x01; // wValue = 1 (connected)
        data[3] = 0x00;
        assert_eq!(
            parse_notification(&data),
            Ok(CdcNotification::NetworkConnection { connected: true })
        );
    }

    #[test]
    fn parse_network_connection_disconnected() {
        let mut data = [0u8; 8];
        data[0] = CDC_NOTIF_REQUEST_TYPE;
        data[1] = NOTIF_NETWORK_CONNECTION;
        // wValue = 0 (disconnected) — already zeroed
        assert_eq!(
            parse_notification(&data),
            Ok(CdcNotification::NetworkConnection { connected: false })
        );
    }

    #[test]
    fn parse_speed_change() {
        let mut data = [0u8; 16];
        data[0] = CDC_NOTIF_REQUEST_TYPE;
        data[1] = NOTIF_CONNECTION_SPEED_CHANGE;
        data[6] = 0x08; // wLength = 8
        // Downstream: 1_000_000_000 (1 Gbps)
        data[8..12].copy_from_slice(&1_000_000_000u32.to_le_bytes());
        // Upstream: 1_000_000_000 (1 Gbps)
        data[12..16].copy_from_slice(&1_000_000_000u32.to_le_bytes());
        assert_eq!(
            parse_notification(&data),
            Ok(CdcNotification::ConnectionSpeedChange {
                downstream: 1_000_000_000,
                upstream: 1_000_000_000,
            })
        );
    }

    #[test]
    fn parse_speed_change_asymmetric() {
        let mut data = [0u8; 16];
        data[0] = CDC_NOTIF_REQUEST_TYPE;
        data[1] = NOTIF_CONNECTION_SPEED_CHANGE;
        data[6] = 0x08;
        data[8..12].copy_from_slice(&100_000_000u32.to_le_bytes()); // 100 Mbps down
        data[12..16].copy_from_slice(&10_000_000u32.to_le_bytes()); // 10 Mbps up
        assert_eq!(
            parse_notification(&data),
            Ok(CdcNotification::ConnectionSpeedChange {
                downstream: 100_000_000,
                upstream: 10_000_000,
            })
        );
    }

    #[test]
    fn parse_speed_change_payload_too_short() {
        let mut data = [0u8; 12]; // Only 4 bytes of payload (need 8)
        data[0] = CDC_NOTIF_REQUEST_TYPE;
        data[1] = NOTIF_CONNECTION_SPEED_CHANGE;
        data[6] = 0x08; // wLength says 8 but buffer too short
        assert_eq!(
            parse_notification(&data),
            Err(CdcError::NotificationTooShort)
        );
    }

    #[test]
    fn parse_unknown_notification() {
        let mut data = [0u8; 8];
        data[0] = CDC_NOTIF_REQUEST_TYPE;
        data[1] = 0x42; // Unknown notification code
        assert_eq!(
            parse_notification(&data),
            Ok(CdcNotification::Unknown { request: 0x42 })
        );
    }

    #[test]
    fn parse_too_short() {
        assert_eq!(
            parse_notification(&[0u8; 7]),
            Err(CdcError::NotificationTooShort)
        );
        assert_eq!(
            parse_notification(&[]),
            Err(CdcError::NotificationTooShort)
        );
    }
}
```

- [ ] **Step 2: Create mod.rs stub to make the module compile**

Create `crates/harmony-unikernel/src/drivers/cdc_ethernet/mod.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! USB CDC-ECM/NCM Ethernet class driver.
//!
//! Sans-I/O driver that parses CDC descriptors, encodes/decodes Ethernet
//! frames (ECM passthrough or NCM NTH16/NDP16), and implements
//! [`NetworkDevice`] for Ring 2 integration via `VirtioNetServer`.

pub mod notification;

pub use notification::{CdcError, CdcNotification};
```

- [ ] **Step 3: Register the module in the driver registry**

In `crates/harmony-unikernel/src/drivers/mod.rs`, add `pub mod cdc_ethernet;` after the existing `pub mod console;` line (alphabetical order):

```rust
pub mod cdc_ethernet;
pub mod console;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-unikernel --lib drivers::cdc_ethernet::notification`

Expected: All 7 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/cdc_ethernet/
git add crates/harmony-unikernel/src/drivers/mod.rs
git commit -m "feat(usb): add CDC notification parser

Parse NETWORK_CONNECTION and CONNECTION_SPEED_CHANGE notifications
from the CDC interrupt IN endpoint. Foundation for the CDC-ECM/NCM
Ethernet class driver.

Bead: harmony-os-y66"
```

---

### Task 2: NCM transfer block codec

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/cdc_ethernet/ncm.rs`
- Modify: `crates/harmony-unikernel/src/drivers/cdc_ethernet/mod.rs`

NTH16/NDP16 encode/decode is the most complex parsing in the driver. Building it as a standalone module with thorough test vectors ensures correctness before integrating it into the codec layer.

- [ ] **Step 1: Create ncm.rs with decode and encode functions**

Create `crates/harmony-unikernel/src/drivers/cdc_ethernet/ncm.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! NCM Transfer Block (NTB) encoding and decoding.
//!
//! NCM wraps Ethernet frames in a two-level header structure:
//! - NTH16 (12 bytes): transfer header with block length and pointer to NDP
//! - NDP16 (16+ bytes): datagram pointer table with (offset, length) pairs
//!
//! This module handles the NTB16 format only. NTB32 (for transfers > 64KB)
//! is out of scope — it is extremely rare in practice.

extern crate alloc;
use alloc::vec::Vec;

use super::CdcError;

// ── NTH16 constants ─────────────────────────────────────────────

/// NTH16 signature "NCMH" in little-endian.
const NTH16_SIGNATURE: u32 = 0x484D_434E;

/// NTH16 header size.
const NTH16_SIZE: usize = 12;

// ── NDP16 constants ─────────────────────────────────────────────

/// NDP16 signature "NCM0" (no CRC) in little-endian.
const NDP16_SIGNATURE_NO_CRC: u32 = 0x304D_434E;

/// Minimum NDP16 size: 8-byte header + one datagram pointer (4 bytes) + terminator (4 bytes) = 16.
const NDP16_MIN_SIZE: usize = 16;

/// Each datagram pointer entry is 4 bytes (wDatagramIndex u16 + wDatagramLength u16).
const DATAGRAM_ENTRY_SIZE: usize = 4;

/// Decode an NCM Transfer Block (NTB16) into individual Ethernet frames.
///
/// Walks the NTH16 header, then follows the NDP16 chain extracting each
/// datagram. All offsets are bounds-checked. Malformed data returns
/// `CdcError::MalformedNtb`.
pub fn decode_ntb(data: &[u8], out: &mut Vec<Vec<u8>>) -> Result<(), CdcError> {
    if data.len() < NTH16_SIZE {
        return Err(CdcError::MalformedNtb);
    }

    // ── NTH16 ────────────────────────────────────────────────────
    let sig = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if sig != NTH16_SIGNATURE {
        return Err(CdcError::MalformedNtb);
    }

    let header_length = u16::from_le_bytes([data[4], data[5]]) as usize;
    if header_length != NTH16_SIZE {
        return Err(CdcError::MalformedNtb);
    }

    // wSequence at [6..8] — informational, not validated
    let block_length = u16::from_le_bytes([data[8], data[9]]) as usize;
    if block_length > data.len() {
        return Err(CdcError::MalformedNtb);
    }

    let mut ndp_index = u16::from_le_bytes([data[10], data[11]]) as usize;
    if ndp_index == 0 {
        return Err(CdcError::MalformedNtb); // Must have at least one NDP
    }

    // ── NDP16 chain ──────────────────────────────────────────────
    // Safety limit to prevent infinite loops on malformed data.
    let mut ndp_count = 0u8;
    while ndp_index != 0 {
        ndp_count += 1;
        if ndp_count > 16 {
            return Err(CdcError::MalformedNtb); // Too many chained NDPs
        }

        if ndp_index + NDP16_MIN_SIZE > block_length {
            return Err(CdcError::MalformedNtb);
        }

        let ndp_sig = u32::from_le_bytes([
            data[ndp_index],
            data[ndp_index + 1],
            data[ndp_index + 2],
            data[ndp_index + 3],
        ]);
        if ndp_sig != NDP16_SIGNATURE_NO_CRC {
            return Err(CdcError::MalformedNtb);
        }

        let ndp_length = u16::from_le_bytes([data[ndp_index + 4], data[ndp_index + 5]]) as usize;
        if ndp_length < NDP16_MIN_SIZE || ndp_index + ndp_length > block_length {
            return Err(CdcError::MalformedNtb);
        }

        let next_ndp = u16::from_le_bytes([data[ndp_index + 6], data[ndp_index + 7]]) as usize;

        // Walk datagram pointer entries starting at ndp_index + 8
        let entries_start = ndp_index + 8;
        let entries_end = ndp_index + ndp_length;
        let mut pos = entries_start;

        while pos + DATAGRAM_ENTRY_SIZE <= entries_end {
            let dg_index = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            let dg_length = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += DATAGRAM_ENTRY_SIZE;

            // Terminator: (0, 0)
            if dg_index == 0 && dg_length == 0 {
                break;
            }

            // Validate bounds
            if dg_length == 0 || dg_index + dg_length > block_length {
                return Err(CdcError::MalformedNtb);
            }

            out.push(data[dg_index..dg_index + dg_length].to_vec());
        }

        ndp_index = next_ndp;
    }

    Ok(())
}

/// Encode a single Ethernet frame as an NCM Transfer Block (NTB16).
///
/// Layout: NTH16 (12) + NDP16 with one datagram + terminator (16) + frame data.
/// Total overhead: 28 bytes. Multi-frame batching is a future optimization.
pub fn encode_ntb(frame: &[u8], sequence: u16) -> Result<Vec<u8>, CdcError> {
    if frame.is_empty() {
        return Err(CdcError::FrameTooLarge); // Zero-length frame is invalid
    }

    // Layout:
    //   [0..12)   NTH16
    //   [12..28)  NDP16 (header 8 + one entry 4 + terminator 4 = 16)
    //   [28..)    frame data
    let ndp_offset: u16 = 12;
    let frame_offset: u16 = 28;
    let block_length = 28 + frame.len();

    if block_length > u16::MAX as usize {
        return Err(CdcError::FrameTooLarge);
    }

    let mut ntb = Vec::with_capacity(block_length);

    // ── NTH16 ────────────────────────────────────────────────────
    ntb.extend_from_slice(&NTH16_SIGNATURE.to_le_bytes()); // dwSignature
    ntb.extend_from_slice(&(NTH16_SIZE as u16).to_le_bytes()); // wHeaderLength
    ntb.extend_from_slice(&sequence.to_le_bytes()); // wSequence
    ntb.extend_from_slice(&(block_length as u16).to_le_bytes()); // wBlockLength
    ntb.extend_from_slice(&ndp_offset.to_le_bytes()); // wNdpIndex

    // ── NDP16 ────────────────────────────────────────────────────
    ntb.extend_from_slice(&NDP16_SIGNATURE_NO_CRC.to_le_bytes()); // dwSignature
    ntb.extend_from_slice(&16u16.to_le_bytes()); // wLength (8 header + 4 entry + 4 terminator)
    ntb.extend_from_slice(&0u16.to_le_bytes()); // wNextNdpIndex (no chaining)
    // Datagram pointer: (frame_offset, frame.len())
    ntb.extend_from_slice(&frame_offset.to_le_bytes());
    ntb.extend_from_slice(&(frame.len() as u16).to_le_bytes());
    // Terminator: (0, 0)
    ntb.extend_from_slice(&0u16.to_le_bytes());
    ntb.extend_from_slice(&0u16.to_le_bytes());

    // ── Frame data ───────────────────────────────────────────────
    ntb.extend_from_slice(frame);

    Ok(ntb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Build a minimal NTB with one frame for testing.
    fn make_single_frame_ntb(frame: &[u8], sequence: u16) -> Vec<u8> {
        encode_ntb(frame, sequence).unwrap()
    }

    // ── encode tests ────────────────────────────────────────────

    #[test]
    fn encode_single_frame_structure() {
        let frame = [0xAA; 60]; // minimum Ethernet frame
        let ntb = encode_ntb(&frame, 42).unwrap();

        // Total: 12 (NTH16) + 16 (NDP16) + 60 (frame) = 88
        assert_eq!(ntb.len(), 88);

        // NTH16 signature
        assert_eq!(&ntb[0..4], &NTH16_SIGNATURE.to_le_bytes());
        // wHeaderLength = 12
        assert_eq!(u16::from_le_bytes([ntb[4], ntb[5]]), 12);
        // wSequence = 42
        assert_eq!(u16::from_le_bytes([ntb[6], ntb[7]]), 42);
        // wBlockLength = 88
        assert_eq!(u16::from_le_bytes([ntb[8], ntb[9]]), 88);
        // wNdpIndex = 12
        assert_eq!(u16::from_le_bytes([ntb[10], ntb[11]]), 12);

        // NDP16 signature
        assert_eq!(&ntb[12..16], &NDP16_SIGNATURE_NO_CRC.to_le_bytes());
        // wLength = 16
        assert_eq!(u16::from_le_bytes([ntb[16], ntb[17]]), 16);
        // wNextNdpIndex = 0
        assert_eq!(u16::from_le_bytes([ntb[18], ntb[19]]), 0);
        // Datagram pointer: offset=28, length=60
        assert_eq!(u16::from_le_bytes([ntb[20], ntb[21]]), 28);
        assert_eq!(u16::from_le_bytes([ntb[22], ntb[23]]), 60);
        // Terminator: (0, 0)
        assert_eq!(u16::from_le_bytes([ntb[24], ntb[25]]), 0);
        assert_eq!(u16::from_le_bytes([ntb[26], ntb[27]]), 0);

        // Frame data
        assert_eq!(&ntb[28..], &frame);
    }

    #[test]
    fn encode_empty_frame_rejected() {
        assert_eq!(encode_ntb(&[], 0), Err(CdcError::FrameTooLarge));
    }

    #[test]
    fn encode_sequence_increments() {
        let ntb0 = encode_ntb(&[0x01; 10], 0).unwrap();
        let ntb1 = encode_ntb(&[0x01; 10], 1).unwrap();
        assert_eq!(u16::from_le_bytes([ntb0[6], ntb0[7]]), 0);
        assert_eq!(u16::from_le_bytes([ntb1[6], ntb1[7]]), 1);
    }

    // ── decode tests ────────────────────────────────────────────

    #[test]
    fn decode_single_frame_roundtrip() {
        let frame = vec![0xBB; 64];
        let ntb = make_single_frame_ntb(&frame, 0);

        let mut out = Vec::new();
        decode_ntb(&ntb, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], frame);
    }

    #[test]
    fn decode_multi_frame_ntb() {
        // Build an NTB with two frames manually
        let frame1 = vec![0x11; 60];
        let frame2 = vec![0x22; 100];

        // NDP16 needs: 8 header + 4 entry1 + 4 entry2 + 4 terminator = 20 bytes
        let ndp_offset: u16 = 12;
        let frame1_offset: u16 = 32; // 12 NTH + 20 NDP
        let frame2_offset: u16 = frame1_offset + 60;
        let block_length: u16 = frame2_offset + 100;

        let mut ntb = Vec::new();

        // NTH16
        ntb.extend_from_slice(&NTH16_SIGNATURE.to_le_bytes());
        ntb.extend_from_slice(&12u16.to_le_bytes()); // wHeaderLength
        ntb.extend_from_slice(&0u16.to_le_bytes()); // wSequence
        ntb.extend_from_slice(&block_length.to_le_bytes()); // wBlockLength
        ntb.extend_from_slice(&ndp_offset.to_le_bytes()); // wNdpIndex

        // NDP16 (20 bytes)
        ntb.extend_from_slice(&NDP16_SIGNATURE_NO_CRC.to_le_bytes());
        ntb.extend_from_slice(&20u16.to_le_bytes()); // wLength
        ntb.extend_from_slice(&0u16.to_le_bytes()); // wNextNdpIndex
        ntb.extend_from_slice(&frame1_offset.to_le_bytes());
        ntb.extend_from_slice(&60u16.to_le_bytes());
        ntb.extend_from_slice(&frame2_offset.to_le_bytes());
        ntb.extend_from_slice(&100u16.to_le_bytes());
        ntb.extend_from_slice(&0u16.to_le_bytes()); // terminator
        ntb.extend_from_slice(&0u16.to_le_bytes());

        // Frame data
        ntb.extend_from_slice(&frame1);
        ntb.extend_from_slice(&frame2);

        assert_eq!(ntb.len(), block_length as usize);

        let mut out = Vec::new();
        decode_ntb(&ntb, &mut out).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], frame1);
        assert_eq!(out[1], frame2);
    }

    #[test]
    fn decode_chained_ndp() {
        // NTH16 → NDP16 #1 (one frame) → NDP16 #2 (one frame)
        let frame1 = vec![0xAA; 40];
        let frame2 = vec![0xBB; 50];

        // Layout:
        //   [0..12)    NTH16 — ndp_index = 12
        //   [12..28)   NDP16 #1 — 16 bytes, next_ndp = 28
        //   [28..44)   NDP16 #2 — 16 bytes, next_ndp = 0
        //   [44..84)   frame1 (40 bytes)
        //   [84..134)  frame2 (50 bytes)
        let ndp1_offset: u16 = 12;
        let ndp2_offset: u16 = 28;
        let frame1_offset: u16 = 44;
        let frame2_offset: u16 = 84;
        let block_length: u16 = 134;

        let mut ntb = Vec::new();

        // NTH16
        ntb.extend_from_slice(&NTH16_SIGNATURE.to_le_bytes());
        ntb.extend_from_slice(&12u16.to_le_bytes());
        ntb.extend_from_slice(&0u16.to_le_bytes());
        ntb.extend_from_slice(&block_length.to_le_bytes());
        ntb.extend_from_slice(&ndp1_offset.to_le_bytes());

        // NDP16 #1 → points to frame1, chains to NDP #2
        ntb.extend_from_slice(&NDP16_SIGNATURE_NO_CRC.to_le_bytes());
        ntb.extend_from_slice(&16u16.to_le_bytes());
        ntb.extend_from_slice(&ndp2_offset.to_le_bytes()); // next NDP
        ntb.extend_from_slice(&frame1_offset.to_le_bytes());
        ntb.extend_from_slice(&40u16.to_le_bytes());
        ntb.extend_from_slice(&0u16.to_le_bytes()); // terminator
        ntb.extend_from_slice(&0u16.to_le_bytes());

        // NDP16 #2 → points to frame2, no chain
        ntb.extend_from_slice(&NDP16_SIGNATURE_NO_CRC.to_le_bytes());
        ntb.extend_from_slice(&16u16.to_le_bytes());
        ntb.extend_from_slice(&0u16.to_le_bytes()); // no next
        ntb.extend_from_slice(&frame2_offset.to_le_bytes());
        ntb.extend_from_slice(&50u16.to_le_bytes());
        ntb.extend_from_slice(&0u16.to_le_bytes());
        ntb.extend_from_slice(&0u16.to_le_bytes());

        // Frames
        ntb.extend_from_slice(&frame1);
        ntb.extend_from_slice(&frame2);

        assert_eq!(ntb.len(), block_length as usize);

        let mut out = Vec::new();
        decode_ntb(&ntb, &mut out).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], frame1);
        assert_eq!(out[1], frame2);
    }

    // ── Malformed NTB tests ─────────────────────────────────────

    #[test]
    fn decode_too_short() {
        assert_eq!(decode_ntb(&[0u8; 11], &mut Vec::new()), Err(CdcError::MalformedNtb));
    }

    #[test]
    fn decode_bad_nth_signature() {
        let mut ntb = encode_ntb(&[0x01; 10], 0).unwrap();
        ntb[0] = 0xFF; // corrupt signature
        assert_eq!(decode_ntb(&ntb, &mut Vec::new()), Err(CdcError::MalformedNtb));
    }

    #[test]
    fn decode_bad_ndp_signature() {
        let mut ntb = encode_ntb(&[0x01; 10], 0).unwrap();
        ntb[12] = 0xFF; // corrupt NDP signature
        assert_eq!(decode_ntb(&ntb, &mut Vec::new()), Err(CdcError::MalformedNtb));
    }

    #[test]
    fn decode_block_length_exceeds_data() {
        let mut ntb = encode_ntb(&[0x01; 10], 0).unwrap();
        // Set wBlockLength to something larger than actual data
        ntb[8..10].copy_from_slice(&1000u16.to_le_bytes());
        assert_eq!(decode_ntb(&ntb, &mut Vec::new()), Err(CdcError::MalformedNtb));
    }

    #[test]
    fn decode_datagram_out_of_bounds() {
        let mut ntb = encode_ntb(&[0x01; 10], 0).unwrap();
        // Set datagram offset to point past end of block
        ntb[20..22].copy_from_slice(&500u16.to_le_bytes());
        assert_eq!(decode_ntb(&ntb, &mut Vec::new()), Err(CdcError::MalformedNtb));
    }

    #[test]
    fn decode_zero_ndp_index() {
        let mut ntb = encode_ntb(&[0x01; 10], 0).unwrap();
        // Set wNdpIndex to 0 (invalid — must have at least one NDP)
        ntb[10..12].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(decode_ntb(&ntb, &mut Vec::new()), Err(CdcError::MalformedNtb));
    }

    #[test]
    fn decode_ndp_length_too_small() {
        let mut ntb = encode_ntb(&[0x01; 10], 0).unwrap();
        // Set NDP wLength to less than minimum (16)
        ntb[16..18].copy_from_slice(&8u16.to_le_bytes());
        assert_eq!(decode_ntb(&ntb, &mut Vec::new()), Err(CdcError::MalformedNtb));
    }
}
```

- [ ] **Step 2: Add ncm module to mod.rs**

In `crates/harmony-unikernel/src/drivers/cdc_ethernet/mod.rs`, add:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! USB CDC-ECM/NCM Ethernet class driver.
//!
//! Sans-I/O driver that parses CDC descriptors, encodes/decodes Ethernet
//! frames (ECM passthrough or NCM NTH16/NDP16), and implements
//! [`NetworkDevice`] for Ring 2 integration via `VirtioNetServer`.

pub mod ncm;
pub mod notification;

pub use notification::{CdcError, CdcNotification};
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p harmony-unikernel --lib drivers::cdc_ethernet::ncm`

Expected: All 12 tests pass (3 encode + 3 decode + 6 malformed).

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/cdc_ethernet/ncm.rs
git add crates/harmony-unikernel/src/drivers/cdc_ethernet/mod.rs
git commit -m "feat(usb): add NCM NTH16/NDP16 encode/decode

Decode multi-frame NTBs with NDP16 chain following. Encode single
frame per NTB (multi-frame batching deferred). Bounds-checked with
malformed NTB detection.

Bead: harmony-os-y66"
```

---

### Task 3: CdcCodec enum (ECM + NCM dispatch)

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/cdc_ethernet/codec.rs`
- Modify: `crates/harmony-unikernel/src/drivers/cdc_ethernet/mod.rs`

The codec enum dispatches between ECM (passthrough) and NCM (NTH16/NDP16). This layer sits between the driver and the raw USB data.

- [ ] **Step 1: Create codec.rs**

Create `crates/harmony-unikernel/src/drivers/cdc_ethernet/codec.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! CDC Ethernet codec — dispatches between ECM and NCM data encoding.
//!
//! ECM: raw Ethernet frame per USB transfer (passthrough).
//! NCM: frames wrapped in NTH16/NDP16 headers (see [`super::ncm`]).

extern crate alloc;
use alloc::vec::Vec;

use super::ncm;
use super::CdcError;

/// Codec for encoding/decoding Ethernet frames on the USB data path.
///
/// Selected at enumeration time based on `bInterfaceSubclass`:
/// - 0x06 → `Ecm`
/// - 0x0D → `Ncm`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdcCodec {
    /// CDC-ECM: one raw Ethernet frame per bulk transfer.
    Ecm,
    /// CDC-NCM: frames wrapped in NTH16/NDP16 transfer blocks.
    Ncm {
        /// Maximum NTB size reported by the device (from NCM functional descriptor).
        max_ntb_size: u32,
        /// Monotonic sequence counter for outgoing NTBs.
        sequence: u16,
    },
}

impl CdcCodec {
    /// Decode a bulk IN transfer into zero or more Ethernet frames.
    ///
    /// - ECM: `data` is the raw Ethernet frame (pushed as-is if non-empty).
    /// - NCM: `data` is an NTB16, decoded into individual datagrams.
    pub fn decode_rx(&self, data: &[u8], out: &mut Vec<Vec<u8>>) -> Result<(), CdcError> {
        match self {
            CdcCodec::Ecm => {
                if !data.is_empty() {
                    out.push(data.to_vec());
                }
                Ok(())
            }
            CdcCodec::Ncm { .. } => ncm::decode_ntb(data, out),
        }
    }

    /// Encode an Ethernet frame for a bulk OUT transfer.
    ///
    /// - ECM: returns the frame unchanged.
    /// - NCM: wraps in NTH16/NDP16 with incrementing sequence number.
    pub fn encode_tx(&mut self, frame: &[u8]) -> Result<Vec<u8>, CdcError> {
        match self {
            CdcCodec::Ecm => Ok(frame.to_vec()),
            CdcCodec::Ncm { sequence, .. } => {
                let seq = *sequence;
                *sequence = sequence.wrapping_add(1);
                ncm::encode_ntb(frame, seq)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // ── ECM tests ───────────────────────────────────────────────

    #[test]
    fn ecm_decode_passthrough() {
        let codec = CdcCodec::Ecm;
        let frame = vec![0xAA; 64];
        let mut out = Vec::new();
        codec.decode_rx(&frame, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], frame);
    }

    #[test]
    fn ecm_decode_empty_produces_nothing() {
        let codec = CdcCodec::Ecm;
        let mut out = Vec::new();
        codec.decode_rx(&[], &mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn ecm_encode_passthrough() {
        let mut codec = CdcCodec::Ecm;
        let frame = vec![0xBB; 100];
        let encoded = codec.encode_tx(&frame).unwrap();
        assert_eq!(encoded, frame);
    }

    // ── NCM tests ───────────────────────────────────────────────

    #[test]
    fn ncm_roundtrip() {
        let mut codec = CdcCodec::Ncm {
            max_ntb_size: 2048,
            sequence: 0,
        };
        let frame = vec![0xCC; 60];

        // Encode
        let ntb = codec.encode_tx(&frame).unwrap();

        // Decode
        let decode_codec = CdcCodec::Ncm {
            max_ntb_size: 2048,
            sequence: 0,
        };
        let mut out = Vec::new();
        decode_codec.decode_rx(&ntb, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], frame);
    }

    #[test]
    fn ncm_sequence_increments() {
        let mut codec = CdcCodec::Ncm {
            max_ntb_size: 2048,
            sequence: 0,
        };

        let ntb0 = codec.encode_tx(&[0x01; 10]).unwrap();
        let ntb1 = codec.encode_tx(&[0x02; 10]).unwrap();

        // Sequence is at NTH16 offset [6..8]
        assert_eq!(u16::from_le_bytes([ntb0[6], ntb0[7]]), 0);
        assert_eq!(u16::from_le_bytes([ntb1[6], ntb1[7]]), 1);

        // Verify internal state advanced
        match codec {
            CdcCodec::Ncm { sequence, .. } => assert_eq!(sequence, 2),
            _ => panic!("expected Ncm"),
        }
    }

    #[test]
    fn ncm_sequence_wraps() {
        let mut codec = CdcCodec::Ncm {
            max_ntb_size: 2048,
            sequence: u16::MAX,
        };

        let ntb = codec.encode_tx(&[0x01; 10]).unwrap();
        assert_eq!(u16::from_le_bytes([ntb[6], ntb[7]]), u16::MAX);

        // Next should wrap to 0
        let ntb2 = codec.encode_tx(&[0x01; 10]).unwrap();
        assert_eq!(u16::from_le_bytes([ntb2[6], ntb2[7]]), 0);
    }
}
```

- [ ] **Step 2: Add codec module to mod.rs**

Update `crates/harmony-unikernel/src/drivers/cdc_ethernet/mod.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! USB CDC-ECM/NCM Ethernet class driver.
//!
//! Sans-I/O driver that parses CDC descriptors, encodes/decodes Ethernet
//! frames (ECM passthrough or NCM NTH16/NDP16), and implements
//! [`NetworkDevice`] for Ring 2 integration via `VirtioNetServer`.

pub mod codec;
pub mod ncm;
pub mod notification;

pub use codec::CdcCodec;
pub use notification::{CdcError, CdcNotification};
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p harmony-unikernel --lib drivers::cdc_ethernet::codec`

Expected: All 6 tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/cdc_ethernet/codec.rs
git add crates/harmony-unikernel/src/drivers/cdc_ethernet/mod.rs
git commit -m "feat(usb): add CdcCodec enum for ECM/NCM dispatch

ECM is a passthrough (raw frame per transfer). NCM wraps/unwraps
via NTH16/NDP16 with monotonic sequence counter. Codec selected
at enumeration time based on bInterfaceSubclass.

Bead: harmony-os-y66"
```

---

### Task 4: CDC descriptor parser

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/cdc_ethernet/descriptor.rs`
- Modify: `crates/harmony-unikernel/src/drivers/cdc_ethernet/mod.rs`

This is the most complex parsing task. It walks the raw USB config descriptor bytes to find CDC ECM/NCM interfaces and extract endpoint/functional descriptor information.

- [ ] **Step 1: Create descriptor.rs**

Create `crates/harmony-unikernel/src/drivers/cdc_ethernet/descriptor.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! CDC descriptor parser — extracts ECM/NCM configuration from USB
//! config descriptor bytes.
//!
//! USB config descriptors are a flat TLV byte stream. CDC adds
//! "functional descriptors" (type 0x24, CS_INTERFACE) between the
//! interface and endpoint descriptors. This parser walks the stream,
//! identifies CDC Communication interfaces, and extracts the
//! functional descriptors needed to configure the driver.

use super::CdcError;

// ── USB descriptor types ────────────────────────────────────────

const USB_DESC_CONFIGURATION: u8 = 0x02;
const USB_DESC_INTERFACE: u8 = 0x04;
const USB_DESC_ENDPOINT: u8 = 0x05;
const USB_DESC_CS_INTERFACE: u8 = 0x24;

// ── CDC interface class/subclass ────────────────────────────────

/// CDC Communication Interface Class.
const CDC_INTERFACE_CLASS: u8 = 0x02;

/// CDC Data Interface Class.
const CDC_DATA_INTERFACE_CLASS: u8 = 0x0A;

/// ECM subclass (Ethernet Control Model).
const CDC_SUBCLASS_ECM: u8 = 0x06;

/// NCM subclass (Network Control Model).
const CDC_SUBCLASS_NCM: u8 = 0x0D;

// ── CDC functional descriptor subtypes ──────────────────────────

/// Header Functional Descriptor.
const CDC_FUNC_HEADER: u8 = 0x00;

/// Union Functional Descriptor.
const CDC_FUNC_UNION: u8 = 0x06;

/// Ethernet Networking Functional Descriptor.
const CDC_FUNC_ETHERNET: u8 = 0x0F;

/// NCM Functional Descriptor.
const CDC_FUNC_NCM: u8 = 0x1A;

// ── Types ───────────────────────────────────────────────────────

/// CDC protocol variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdcProtocol {
    /// Ethernet Control Model (subclass 0x06).
    Ecm,
    /// Network Control Model (subclass 0x0D).
    Ncm,
}

/// Endpoint information extracted from a USB endpoint descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointInfo {
    /// bEndpointAddress (bit 7 = direction, bits 3:0 = endpoint number).
    pub address: u8,
    /// wMaxPacketSize.
    pub max_packet_size: u16,
}

/// Parsed CDC descriptor information from a USB config descriptor.
///
/// Contains everything needed to initialize a `CdcEthernetDriver`:
/// which protocol, which interfaces, which endpoints, and device
/// parameters (MAC string index, max segment size, NTB size).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdcDescriptors {
    /// ECM or NCM.
    pub protocol: CdcProtocol,
    /// bInterfaceNumber of the CDC Communication Interface.
    pub control_interface: u8,
    /// bInterfaceNumber of the CDC Data Interface.
    pub data_interface: u8,
    /// bAlternateSetting of the data interface that has endpoints.
    pub data_alt_setting: u8,
    /// Interrupt IN endpoint (notifications).
    pub interrupt_ep: EndpointInfo,
    /// Bulk IN endpoint (data from device).
    pub bulk_in_ep: EndpointInfo,
    /// Bulk OUT endpoint (data to device).
    pub bulk_out_ep: EndpointInfo,
    /// String descriptor index for the MAC address.
    pub mac_string_index: u8,
    /// Maximum Ethernet segment size (from Ethernet Networking functional desc).
    pub max_segment_size: u16,
    /// Maximum NTB size (NCM only; 0 for ECM).
    pub max_ntb_size: u32,
    /// bConfigurationValue to use in SET_CONFIGURATION.
    pub config_value: u8,
}

/// Parse a USB config descriptor to find and extract CDC ECM/NCM configuration.
///
/// Returns `Ok(Some(descriptors))` if a CDC Ethernet interface is found,
/// `Ok(None)` if no CDC Ethernet interface exists, or `Err(CdcError)`
/// if a CDC interface is found but is malformed.
pub fn parse_cdc_config(config_desc: &[u8]) -> Result<Option<CdcDescriptors>, CdcError> {
    if config_desc.len() < 9 {
        return Err(CdcError::DescriptorTooShort);
    }
    if config_desc[1] != USB_DESC_CONFIGURATION {
        return Err(CdcError::DescriptorTooShort);
    }

    let total_length = u16::from_le_bytes([config_desc[2], config_desc[3]]) as usize;
    if total_length < 9 || config_desc.len() < total_length {
        return Err(CdcError::DescriptorTooShort);
    }

    let config_value = config_desc[5];

    // State for the search
    let mut cdc_protocol: Option<CdcProtocol> = None;
    let mut control_interface: Option<u8> = None;
    let mut found_header = false;
    let mut union_data_interface: Option<u8> = None;
    let mut mac_string_index: Option<u8> = None;
    let mut max_segment_size: u16 = 1514; // default
    let mut max_ntb_size: u32 = 0;
    let mut interrupt_ep: Option<EndpointInfo> = None;

    // Data interface endpoints (found in alt setting with endpoints)
    let mut data_alt_setting: u8 = 0;
    let mut bulk_in_ep: Option<EndpointInfo> = None;
    let mut bulk_out_ep: Option<EndpointInfo> = None;

    // Walk the descriptor stream
    let mut pos = 9; // skip config descriptor header
    let mut in_cdc_control = false; // currently inside the CDC communication interface
    let mut in_data_interface = false; // currently inside the CDC data interface
    let mut current_iface_alt: u8 = 0;

    while pos + 1 < total_length {
        let b_length = config_desc[pos] as usize;
        if b_length < 2 || pos + b_length > total_length {
            break; // malformed descriptor entry — stop walking
        }
        let b_desc_type = config_desc[pos + 1];

        match b_desc_type {
            USB_DESC_INTERFACE if b_length >= 9 => {
                let iface_number = config_desc[pos + 2];
                let alt_setting = config_desc[pos + 3];
                let iface_class = config_desc[pos + 5];
                let iface_subclass = config_desc[pos + 6];

                in_cdc_control = false;
                in_data_interface = false;

                if iface_class == CDC_INTERFACE_CLASS {
                    match iface_subclass {
                        CDC_SUBCLASS_ECM if cdc_protocol.is_none() => {
                            cdc_protocol = Some(CdcProtocol::Ecm);
                            control_interface = Some(iface_number);
                            in_cdc_control = true;
                        }
                        CDC_SUBCLASS_NCM if cdc_protocol.is_none() => {
                            cdc_protocol = Some(CdcProtocol::Ncm);
                            control_interface = Some(iface_number);
                            in_cdc_control = true;
                        }
                        _ => {}
                    }
                } else if iface_class == CDC_DATA_INTERFACE_CLASS
                    && union_data_interface == Some(iface_number)
                {
                    in_data_interface = true;
                    current_iface_alt = alt_setting;
                }
            }

            USB_DESC_CS_INTERFACE if in_cdc_control && b_length >= 3 => {
                let subtype = config_desc[pos + 2];
                match subtype {
                    CDC_FUNC_HEADER if b_length >= 5 => {
                        found_header = true;
                    }
                    CDC_FUNC_UNION if b_length >= 5 => {
                        // bControlInterface at [3], bSubordinateInterface0 at [4]
                        union_data_interface = Some(config_desc[pos + 4]);
                    }
                    CDC_FUNC_ETHERNET if b_length >= 13 => {
                        mac_string_index = Some(config_desc[pos + 3]);
                        max_segment_size =
                            u16::from_le_bytes([config_desc[pos + 5], config_desc[pos + 6]]);
                    }
                    CDC_FUNC_NCM if b_length >= 6 => {
                        // NTB parameters: wNtbInMaxSize at offset 3 (but NCM func desc
                        // uses GetNtbParameters, so we store a default here).
                        // The bitmask of supported NTB formats is at offset 4.
                        // For now, use a default max NTB size.
                        max_ntb_size = 2048;
                    }
                    _ => {} // skip unknown functional descriptors
                }
            }

            USB_DESC_ENDPOINT if b_length >= 7 => {
                let ep_addr = config_desc[pos + 2];
                let ep_attrs = config_desc[pos + 3];
                let ep_mps =
                    u16::from_le_bytes([config_desc[pos + 4], config_desc[pos + 5]]);
                let ep_info = EndpointInfo {
                    address: ep_addr,
                    max_packet_size: ep_mps,
                };

                let transfer_type = ep_attrs & 0x03;
                let is_in = ep_addr & 0x80 != 0;

                if in_cdc_control && transfer_type == 3 && is_in {
                    // Interrupt IN on the control interface = notification endpoint
                    interrupt_ep = Some(ep_info);
                } else if in_data_interface && current_iface_alt > 0 {
                    // Bulk endpoints on data interface alt setting > 0
                    if transfer_type == 2 {
                        if is_in {
                            bulk_in_ep = Some(ep_info);
                        } else {
                            bulk_out_ep = Some(ep_info);
                        }
                        data_alt_setting = current_iface_alt;
                    }
                }
            }

            _ => {} // skip all other descriptor types
        }

        pos += b_length;
    }

    // ── Validate results ─────────────────────────────────────────

    let protocol = match cdc_protocol {
        Some(p) => p,
        None => return Ok(None), // No CDC interface found — not an error
    };

    if !found_header {
        return Err(CdcError::MissingFunctionalDescriptor);
    }

    let data_iface = match union_data_interface {
        Some(i) => i,
        None => return Err(CdcError::MissingFunctionalDescriptor),
    };

    let mac_idx = match mac_string_index {
        Some(i) if protocol == CdcProtocol::Ecm => i,
        None if protocol == CdcProtocol::Ecm => {
            return Err(CdcError::MissingFunctionalDescriptor);
        }
        Some(i) => i,
        None => 0, // NCM may not have Ethernet functional descriptor; MAC from other source
    };

    let int_ep = interrupt_ep.ok_or(CdcError::MissingEndpoint)?;
    let bin_ep = bulk_in_ep.ok_or(CdcError::MissingEndpoint)?;
    let bout_ep = bulk_out_ep.ok_or(CdcError::MissingEndpoint)?;

    Ok(Some(CdcDescriptors {
        protocol,
        control_interface: control_interface.unwrap(), // safe: set when cdc_protocol is set
        data_interface: data_iface,
        data_alt_setting,
        interrupt_ep: int_ep,
        bulk_in_ep: bin_ep,
        bulk_out_ep: bout_ep,
        mac_string_index: mac_idx,
        max_segment_size,
        max_ntb_size,
        config_value,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    /// Build a minimal ECM config descriptor for testing.
    ///
    /// Structure:
    ///   Config (9) + Comm Interface (9) + Header FD (5) + Union FD (5) +
    ///   Ethernet FD (13) + Interrupt EP (7) + Data Interface alt0 (9) +
    ///   Data Interface alt1 (9) + Bulk IN EP (7) + Bulk OUT EP (7) = 80 bytes
    fn build_ecm_config_desc() -> Vec<u8> {
        let total_length: u16 = 80;
        let mut d = Vec::new();

        // Config descriptor (9 bytes)
        d.push(9); // bLength
        d.push(USB_DESC_CONFIGURATION);
        d.extend_from_slice(&total_length.to_le_bytes());
        d.push(2); // bNumInterfaces
        d.push(1); // bConfigurationValue
        d.push(0); // iConfiguration
        d.push(0x80); // bmAttributes
        d.push(250); // bMaxPower

        // Communication Interface (9 bytes)
        d.push(9);
        d.push(USB_DESC_INTERFACE);
        d.push(0); // bInterfaceNumber
        d.push(0); // bAlternateSetting
        d.push(1); // bNumEndpoints
        d.push(CDC_INTERFACE_CLASS);
        d.push(CDC_SUBCLASS_ECM);
        d.push(0); // bInterfaceProtocol
        d.push(0); // iInterface

        // CDC Header Functional Descriptor (5 bytes)
        d.push(5);
        d.push(USB_DESC_CS_INTERFACE);
        d.push(CDC_FUNC_HEADER);
        d.push(0x10); // bcdCDC low
        d.push(0x01); // bcdCDC high (1.10)

        // CDC Union Functional Descriptor (5 bytes)
        d.push(5);
        d.push(USB_DESC_CS_INTERFACE);
        d.push(CDC_FUNC_UNION);
        d.push(0); // bControlInterface
        d.push(1); // bSubordinateInterface0 (data interface)

        // CDC Ethernet Networking Functional Descriptor (13 bytes)
        d.push(13);
        d.push(USB_DESC_CS_INTERFACE);
        d.push(CDC_FUNC_ETHERNET);
        d.push(3); // iMACAddress (string descriptor index)
        d.push(0); // bmEthernetStatistics (4 bytes)
        d.extend_from_slice(&1514u16.to_le_bytes()); // wMaxSegmentSize
        d.push(0); // ... rest of statistics
        d.push(0);
        d.push(0); // wNumberMCFilters (2 bytes)
        d.push(0);
        d.push(0); // bNumberPowerFilters

        // Interrupt IN endpoint (7 bytes) — EP3 IN
        d.push(7);
        d.push(USB_DESC_ENDPOINT);
        d.push(0x83); // bEndpointAddress: EP3 IN
        d.push(0x03); // bmAttributes: interrupt
        d.extend_from_slice(&16u16.to_le_bytes()); // wMaxPacketSize
        d.push(32); // bInterval

        // Data Interface alt 0 (9 bytes) — no endpoints
        d.push(9);
        d.push(USB_DESC_INTERFACE);
        d.push(1); // bInterfaceNumber
        d.push(0); // bAlternateSetting = 0
        d.push(0); // bNumEndpoints = 0
        d.push(CDC_DATA_INTERFACE_CLASS);
        d.push(0); // bInterfaceSubclass
        d.push(0); // bInterfaceProtocol
        d.push(0);

        // Data Interface alt 1 (9 bytes) — active, has endpoints
        d.push(9);
        d.push(USB_DESC_INTERFACE);
        d.push(1); // bInterfaceNumber
        d.push(1); // bAlternateSetting = 1
        d.push(2); // bNumEndpoints = 2
        d.push(CDC_DATA_INTERFACE_CLASS);
        d.push(0);
        d.push(0);
        d.push(0);

        // Bulk IN endpoint (7 bytes) — EP1 IN
        d.push(7);
        d.push(USB_DESC_ENDPOINT);
        d.push(0x81); // bEndpointAddress: EP1 IN
        d.push(0x02); // bmAttributes: bulk
        d.extend_from_slice(&512u16.to_le_bytes()); // wMaxPacketSize
        d.push(0); // bInterval

        // Bulk OUT endpoint (7 bytes) — EP2 OUT
        d.push(7);
        d.push(USB_DESC_ENDPOINT);
        d.push(0x02); // bEndpointAddress: EP2 OUT
        d.push(0x02); // bmAttributes: bulk
        d.extend_from_slice(&512u16.to_le_bytes()); // wMaxPacketSize
        d.push(0); // bInterval

        assert_eq!(d.len(), total_length as usize);
        d
    }

    /// Build a minimal NCM config descriptor for testing.
    ///
    /// Same structure as ECM but with NCM subclass and NCM functional descriptor.
    fn build_ncm_config_desc() -> Vec<u8> {
        let total_length: u16 = 74;
        let mut d = Vec::new();

        // Config descriptor (9)
        d.push(9);
        d.push(USB_DESC_CONFIGURATION);
        d.extend_from_slice(&total_length.to_le_bytes());
        d.push(2);
        d.push(1);
        d.push(0);
        d.push(0x80);
        d.push(250);

        // Communication Interface (9) — NCM subclass
        d.push(9);
        d.push(USB_DESC_INTERFACE);
        d.push(0); d.push(0); d.push(1);
        d.push(CDC_INTERFACE_CLASS);
        d.push(CDC_SUBCLASS_NCM);
        d.push(0x01); // bInterfaceProtocol
        d.push(0);

        // Header FD (5)
        d.push(5);
        d.push(USB_DESC_CS_INTERFACE);
        d.push(CDC_FUNC_HEADER);
        d.push(0x10); d.push(0x01);

        // Union FD (5)
        d.push(5);
        d.push(USB_DESC_CS_INTERFACE);
        d.push(CDC_FUNC_UNION);
        d.push(0); // control
        d.push(1); // data

        // NCM FD (6) — instead of Ethernet FD
        d.push(6);
        d.push(USB_DESC_CS_INTERFACE);
        d.push(CDC_FUNC_NCM);
        d.push(0x00); // bcdNcmVersion low
        d.push(0x01); // bcdNcmVersion high
        d.push(0x03); // bmNetworkCapabilities

        // Interrupt IN endpoint (7) — EP3 IN
        d.push(7);
        d.push(USB_DESC_ENDPOINT);
        d.push(0x83);
        d.push(0x03);
        d.extend_from_slice(&16u16.to_le_bytes());
        d.push(32);

        // Data Interface alt 0 (9) — no endpoints
        d.push(9);
        d.push(USB_DESC_INTERFACE);
        d.push(1); d.push(0); d.push(0);
        d.push(CDC_DATA_INTERFACE_CLASS);
        d.push(0); d.push(0); d.push(0);

        // Data Interface alt 1 (9) — active
        d.push(9);
        d.push(USB_DESC_INTERFACE);
        d.push(1); d.push(1); d.push(2);
        d.push(CDC_DATA_INTERFACE_CLASS);
        d.push(0); d.push(0); d.push(0);

        // Bulk IN (7) — EP1 IN
        d.push(7);
        d.push(USB_DESC_ENDPOINT);
        d.push(0x81);
        d.push(0x02);
        d.extend_from_slice(&512u16.to_le_bytes());
        d.push(0);

        // Bulk OUT (7) — EP2 OUT
        d.push(7);
        d.push(USB_DESC_ENDPOINT);
        d.push(0x02);
        d.push(0x02);
        d.extend_from_slice(&512u16.to_le_bytes());
        d.push(0);

        assert_eq!(d.len(), total_length as usize);
        d
    }

    // ── ECM parsing ─────────────────────────────────────────────

    #[test]
    fn parse_ecm_config() {
        let desc = build_ecm_config_desc();
        let result = parse_cdc_config(&desc).unwrap().unwrap();

        assert_eq!(result.protocol, CdcProtocol::Ecm);
        assert_eq!(result.control_interface, 0);
        assert_eq!(result.data_interface, 1);
        assert_eq!(result.data_alt_setting, 1);
        assert_eq!(result.config_value, 1);

        assert_eq!(result.interrupt_ep.address, 0x83);
        assert_eq!(result.interrupt_ep.max_packet_size, 16);

        assert_eq!(result.bulk_in_ep.address, 0x81);
        assert_eq!(result.bulk_in_ep.max_packet_size, 512);

        assert_eq!(result.bulk_out_ep.address, 0x02);
        assert_eq!(result.bulk_out_ep.max_packet_size, 512);

        assert_eq!(result.mac_string_index, 3);
        assert_eq!(result.max_segment_size, 1514);
        assert_eq!(result.max_ntb_size, 0);
    }

    // ── NCM parsing ─────────────────────────────────────────────

    #[test]
    fn parse_ncm_config() {
        let desc = build_ncm_config_desc();
        let result = parse_cdc_config(&desc).unwrap().unwrap();

        assert_eq!(result.protocol, CdcProtocol::Ncm);
        assert_eq!(result.control_interface, 0);
        assert_eq!(result.data_interface, 1);
        assert_eq!(result.data_alt_setting, 1);

        assert_eq!(result.interrupt_ep.address, 0x83);
        assert_eq!(result.bulk_in_ep.address, 0x81);
        assert_eq!(result.bulk_out_ep.address, 0x02);

        assert_eq!(result.max_ntb_size, 2048);
    }

    // ── No CDC interface ────────────────────────────────────────

    #[test]
    fn parse_no_cdc_interface() {
        // A config with a non-CDC interface (HID class)
        let mut d = Vec::new();
        let total: u16 = 18;
        d.push(9); d.push(USB_DESC_CONFIGURATION);
        d.extend_from_slice(&total.to_le_bytes());
        d.push(1); d.push(1); d.push(0); d.push(0x80); d.push(250);

        d.push(9); d.push(USB_DESC_INTERFACE);
        d.push(0); d.push(0); d.push(0);
        d.push(0x03); // HID class
        d.push(0x01); d.push(0x01); d.push(0);

        assert!(parse_cdc_config(&d).unwrap().is_none());
    }

    // ── Error cases ─────────────────────────────────────────────

    #[test]
    fn parse_too_short() {
        assert_eq!(parse_cdc_config(&[0u8; 8]), Err(CdcError::DescriptorTooShort));
    }

    #[test]
    fn parse_missing_header_fd() {
        // Build ECM but remove the Header FD
        let mut d = build_ecm_config_desc();
        // Header FD is at offset 18..23 (5 bytes). Replace with zeros.
        // Actually, easier to build a descriptor without it.
        let total: u16 = 75;
        let mut desc = Vec::new();

        // Config (9)
        desc.push(9); desc.push(USB_DESC_CONFIGURATION);
        desc.extend_from_slice(&total.to_le_bytes());
        desc.push(2); desc.push(1); desc.push(0); desc.push(0x80); desc.push(250);

        // Comm Interface (9) — ECM
        desc.push(9); desc.push(USB_DESC_INTERFACE);
        desc.push(0); desc.push(0); desc.push(1);
        desc.push(CDC_INTERFACE_CLASS); desc.push(CDC_SUBCLASS_ECM);
        desc.push(0); desc.push(0);

        // Union FD (5) — NO header FD
        desc.push(5); desc.push(USB_DESC_CS_INTERFACE); desc.push(CDC_FUNC_UNION);
        desc.push(0); desc.push(1);

        // Ethernet FD (13)
        desc.push(13); desc.push(USB_DESC_CS_INTERFACE); desc.push(CDC_FUNC_ETHERNET);
        desc.push(3); desc.push(0);
        desc.extend_from_slice(&1514u16.to_le_bytes());
        desc.push(0); desc.push(0); desc.push(0); desc.push(0); desc.push(0);

        // Interrupt EP (7)
        desc.push(7); desc.push(USB_DESC_ENDPOINT);
        desc.push(0x83); desc.push(0x03);
        desc.extend_from_slice(&16u16.to_le_bytes()); desc.push(32);

        // Data Interface alt0 (9)
        desc.push(9); desc.push(USB_DESC_INTERFACE);
        desc.push(1); desc.push(0); desc.push(0);
        desc.push(CDC_DATA_INTERFACE_CLASS); desc.push(0); desc.push(0); desc.push(0);

        // Data Interface alt1 (9) + Bulk IN (7) + Bulk OUT (7)
        desc.push(9); desc.push(USB_DESC_INTERFACE);
        desc.push(1); desc.push(1); desc.push(2);
        desc.push(CDC_DATA_INTERFACE_CLASS); desc.push(0); desc.push(0); desc.push(0);

        desc.push(7); desc.push(USB_DESC_ENDPOINT);
        desc.push(0x81); desc.push(0x02);
        desc.extend_from_slice(&512u16.to_le_bytes()); desc.push(0);

        desc.push(7); desc.push(USB_DESC_ENDPOINT);
        desc.push(0x02); desc.push(0x02);
        desc.extend_from_slice(&512u16.to_le_bytes()); desc.push(0);

        assert_eq!(desc.len(), total as usize);
        assert_eq!(parse_cdc_config(&desc), Err(CdcError::MissingFunctionalDescriptor));
    }

    #[test]
    fn parse_missing_bulk_endpoints() {
        // ECM config with no data interface alt1 (so no bulk endpoints)
        let total: u16 = 62;
        let mut d = Vec::new();

        // Config (9)
        d.push(9); d.push(USB_DESC_CONFIGURATION);
        d.extend_from_slice(&total.to_le_bytes());
        d.push(2); d.push(1); d.push(0); d.push(0x80); d.push(250);

        // Comm Interface (9)
        d.push(9); d.push(USB_DESC_INTERFACE);
        d.push(0); d.push(0); d.push(1);
        d.push(CDC_INTERFACE_CLASS); d.push(CDC_SUBCLASS_ECM);
        d.push(0); d.push(0);

        // Header FD (5), Union FD (5), Ethernet FD (13)
        d.push(5); d.push(USB_DESC_CS_INTERFACE); d.push(CDC_FUNC_HEADER);
        d.push(0x10); d.push(0x01);
        d.push(5); d.push(USB_DESC_CS_INTERFACE); d.push(CDC_FUNC_UNION);
        d.push(0); d.push(1);
        d.push(13); d.push(USB_DESC_CS_INTERFACE); d.push(CDC_FUNC_ETHERNET);
        d.push(3); d.push(0);
        d.extend_from_slice(&1514u16.to_le_bytes());
        d.push(0); d.push(0); d.push(0); d.push(0); d.push(0);

        // Interrupt EP (7)
        d.push(7); d.push(USB_DESC_ENDPOINT);
        d.push(0x83); d.push(0x03);
        d.extend_from_slice(&16u16.to_le_bytes()); d.push(32);

        // Data Interface alt0 only (9) — no alt1, no bulk endpoints
        d.push(9); d.push(USB_DESC_INTERFACE);
        d.push(1); d.push(0); d.push(0);
        d.push(CDC_DATA_INTERFACE_CLASS); d.push(0); d.push(0); d.push(0);

        assert_eq!(d.len(), total as usize);
        assert_eq!(parse_cdc_config(&d), Err(CdcError::MissingEndpoint));
    }
}
```

- [ ] **Step 2: Add descriptor module to mod.rs**

Update `crates/harmony-unikernel/src/drivers/cdc_ethernet/mod.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! USB CDC-ECM/NCM Ethernet class driver.
//!
//! Sans-I/O driver that parses CDC descriptors, encodes/decodes Ethernet
//! frames (ECM passthrough or NCM NTH16/NDP16), and implements
//! [`NetworkDevice`] for Ring 2 integration via `VirtioNetServer`.

pub mod codec;
pub mod descriptor;
pub mod ncm;
pub mod notification;

pub use codec::CdcCodec;
pub use descriptor::{CdcDescriptors, CdcProtocol, EndpointInfo};
pub use notification::{CdcError, CdcNotification};
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p harmony-unikernel --lib drivers::cdc_ethernet::descriptor`

Expected: All 6 tests pass (ECM, NCM, no CDC, too short, missing header, missing endpoints).

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/cdc_ethernet/descriptor.rs
git add crates/harmony-unikernel/src/drivers/cdc_ethernet/mod.rs
git commit -m "feat(usb): add CDC descriptor parser for ECM/NCM

Walk USB config descriptor byte stream, match CDC Communication
interfaces (class 0x02, subclass 0x06 ECM or 0x0D NCM), extract
functional descriptors and endpoint info. Two-phase init: MAC
comes from a separate string descriptor request.

Bead: harmony-os-y66"
```

---

### Task 5: CdcEthernetDriver — main driver with NetworkDevice impl

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/cdc_ethernet/mod.rs` (major rewrite — becomes the driver)

This task brings everything together: the driver struct, `from_config_descriptor`, `complete_init`, `receive_bulk_in`, `receive_interrupt`, `send_frame`, and the `NetworkDevice` trait implementation.

- [ ] **Step 1: Rewrite mod.rs to include the full driver**

Replace `crates/harmony-unikernel/src/drivers/cdc_ethernet/mod.rs` with:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! USB CDC-ECM/NCM Ethernet class driver.
//!
//! Sans-I/O driver that parses CDC descriptors, encodes/decodes Ethernet
//! frames (ECM passthrough or NCM NTH16/NDP16), and implements
//! [`NetworkDevice`](harmony_microkernel::net_device::NetworkDevice) for
//! Ring 2 integration via `VirtioNetServer`.
//!
//! ## Usage
//!
//! ```rust,ignore
//! // 1. Parse USB config descriptor
//! let (mut driver, actions) = CdcEthernetDriver::from_config_descriptor(slot, &config_desc)?
//!     .ok_or("no CDC interface")?;
//! // 2. Execute actions via xHCI (SET_CONFIG, GET_STRING for MAC, queue endpoints)
//! // 3. Feed MAC string response
//! driver.complete_init(&mac_string_response)?;
//! // 4. Poll loop: feed bulk IN and interrupt IN completions
//! let more_actions = driver.receive_bulk_in(&bulk_data);
//! let notif_actions = driver.receive_interrupt(&interrupt_data);
//! ```

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

pub mod codec;
pub mod descriptor;
pub mod ncm;
pub mod notification;

pub use codec::CdcCodec;
pub use descriptor::{CdcDescriptors, CdcProtocol, EndpointInfo};
pub use notification::{CdcError, CdcNotification};

// ── CdcAction ───────────────────────────────────────────────────

/// Actions the CDC driver returns for the caller to execute via xHCI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdcAction {
    /// Send data on a bulk OUT endpoint.
    BulkOut { ep: u8, data: Vec<u8> },
    /// Queue a bulk IN transfer (receive up to `max_len` bytes).
    BulkIn { ep: u8, max_len: u16 },
    /// Send a control transfer on endpoint 0 (SETUP packet + optional data).
    ControlOut { request: [u8; 8], data: Vec<u8> },
    /// Request a control transfer IN on endpoint 0 (SETUP + receive data).
    ControlIn { request: [u8; 8], max_len: u16 },
    /// Queue an interrupt IN transfer.
    InterruptIn { ep: u8, max_len: u16 },
}

// ── USB control request builders ────────────────────────────────

/// Build SET_CONFIGURATION SETUP packet.
fn set_configuration(config_value: u8) -> [u8; 8] {
    let mut p = [0u8; 8];
    p[0] = 0x00; // bmRequestType: host-to-device, standard, device
    p[1] = 0x09; // SET_CONFIGURATION
    p[2] = config_value;
    p
}

/// Build SET_INTERFACE SETUP packet.
fn set_interface(interface: u8, alt_setting: u8) -> [u8; 8] {
    let mut p = [0u8; 8];
    p[0] = 0x01; // bmRequestType: host-to-device, standard, interface
    p[1] = 0x0B; // SET_INTERFACE
    p[2] = alt_setting; // wValue
    p[4] = interface; // wIndex
    p
}

/// Build GET_DESCRIPTOR(STRING) SETUP packet.
fn get_string_descriptor(index: u8, max_len: u16) -> [u8; 8] {
    let mut p = [0u8; 8];
    p[0] = 0x80; // bmRequestType: device-to-host, standard, device
    p[1] = 0x06; // GET_DESCRIPTOR
    p[2] = index; // wValue low: descriptor index
    p[3] = 0x03; // wValue high: STRING descriptor type
    p[4] = 0x09; // wIndex low: language ID (English)
    p[5] = 0x04; // wIndex high
    p[6..8].copy_from_slice(&max_len.to_le_bytes()); // wLength
    p
}

/// Build SET_ETHERNET_PACKET_FILTER SETUP packet.
/// Filter bitmap: bit 0 = promiscuous, bit 1 = all multicast,
/// bit 2 = directed, bit 3 = broadcast, bit 4 = multicast.
fn set_packet_filter(interface: u8, filter: u16) -> [u8; 8] {
    let mut p = [0u8; 8];
    p[0] = 0x21; // bmRequestType: host-to-device, class, interface
    p[1] = 0x43; // SET_ETHERNET_PACKET_FILTER
    p[2..4].copy_from_slice(&filter.to_le_bytes()); // wValue
    p[4] = interface; // wIndex
    p
}

// ── Driver ──────────────────────────────────────────────────────

/// CDC-ECM/NCM Ethernet class driver.
///
/// Sans-I/O: the caller executes [`CdcAction`]s via the xHCI driver
/// and feeds responses back. The driver decodes frames, tracks link
/// state, and queues decoded Ethernet frames for consumption via
/// [`NetworkDevice`](harmony_microkernel::net_device::NetworkDevice).
pub struct CdcEthernetDriver {
    /// Parsed CDC configuration from USB descriptors.
    descriptors: CdcDescriptors,
    /// ECM/NCM codec for the data path.
    codec: CdcCodec,
    /// Whether the link is up (from CDC notifications).
    link_up: bool,
    /// Downstream speed in bits/sec (from SPEED_CHANGE notification).
    speed_down: u32,
    /// Upstream speed in bits/sec.
    speed_up: u32,
    /// Ethernet frames received from USB, ready for poll_tx.
    rx_queue: VecDeque<Vec<u8>>,
    /// Buffered CdcActions from push_rx (NetworkDevice can't return actions).
    pending_actions: Vec<CdcAction>,
    /// MAC address (populated by complete_init).
    mac: [u8; 6],
    /// Whether complete_init has been called.
    initialized: bool,
}

impl CdcEthernetDriver {
    /// Parse a USB config descriptor and create a driver if a CDC ECM/NCM
    /// interface is found.
    ///
    /// Returns `Ok(Some((driver, actions)))` with setup actions to execute,
    /// `Ok(None)` if no CDC interface exists, or `Err` if the descriptor
    /// is malformed.
    ///
    /// The returned actions include:
    /// - SET_CONFIGURATION
    /// - SET_INTERFACE (activate data alt setting)
    /// - GET_DESCRIPTOR(STRING) for the MAC address
    /// - SET_ETHERNET_PACKET_FILTER (directed + broadcast + multicast)
    /// - Initial BulkIn + InterruptIn queues
    ///
    /// After executing these actions, feed the MAC string descriptor
    /// response to [`complete_init`](Self::complete_init).
    pub fn from_config_descriptor(
        slot_id: u8,
        config_desc: &[u8],
    ) -> Result<Option<(Self, Vec<CdcAction>)>, CdcError> {
        let descriptors = match descriptor::parse_cdc_config(config_desc)? {
            Some(d) => d,
            None => return Ok(None),
        };

        let codec = match descriptors.protocol {
            CdcProtocol::Ecm => CdcCodec::Ecm,
            CdcProtocol::Ncm => CdcCodec::Ncm {
                max_ntb_size: descriptors.max_ntb_size,
                sequence: 0,
            },
        };

        let mut actions = Vec::new();

        // SET_CONFIGURATION
        actions.push(CdcAction::ControlOut {
            request: set_configuration(descriptors.config_value),
            data: Vec::new(),
        });

        // SET_INTERFACE (activate data interface alt setting with endpoints)
        actions.push(CdcAction::ControlOut {
            request: set_interface(
                descriptors.data_interface,
                descriptors.data_alt_setting,
            ),
            data: Vec::new(),
        });

        // GET_DESCRIPTOR(STRING) for MAC address
        if descriptors.mac_string_index > 0 {
            actions.push(CdcAction::ControlIn {
                request: get_string_descriptor(descriptors.mac_string_index, 26),
                max_len: 26, // 2 header + 12 hex chars × 2 bytes each = 26
            });
        }

        // SET_ETHERNET_PACKET_FILTER — accept directed + broadcast + multicast
        let filter: u16 = 0x0C | 0x02; // directed(2) | broadcast(3) | all-multicast(1)
        actions.push(CdcAction::ControlOut {
            request: set_packet_filter(descriptors.control_interface, filter),
            data: Vec::new(),
        });

        // Queue initial bulk IN (start receiving) and interrupt IN (start notifications)
        actions.push(CdcAction::BulkIn {
            ep: descriptors.bulk_in_ep.address,
            max_len: descriptors.bulk_in_ep.max_packet_size,
        });
        actions.push(CdcAction::InterruptIn {
            ep: descriptors.interrupt_ep.address,
            max_len: descriptors.interrupt_ep.max_packet_size,
        });

        let driver = Self {
            descriptors,
            codec,
            link_up: false,
            speed_down: 0,
            speed_up: 0,
            rx_queue: VecDeque::new(),
            pending_actions: Vec::new(),
            mac: [0u8; 6],
            initialized: false,
        };

        Ok(Some((driver, actions)))
    }

    /// Complete initialization with the MAC address string descriptor response.
    ///
    /// USB string descriptors are UTF-16LE with a 2-byte header:
    /// `[bLength, bDescriptorType=3, char0_lo, char0_hi, char1_lo, char1_hi, ...]`
    ///
    /// The MAC is encoded as 12 hex ASCII characters (e.g., "AABBCCDDEEFF").
    pub fn complete_init(&mut self, mac_string: &[u8]) -> Result<(), CdcError> {
        if mac_string.len() < 26 {
            // Need at least 2 header + 24 (12 chars × 2 bytes UTF-16LE)
            return Err(CdcError::InvalidMacString);
        }

        // Extract UTF-16LE characters (take low byte of each pair)
        let mut hex_chars = [0u8; 12];
        for i in 0..12 {
            hex_chars[i] = mac_string[2 + i * 2]; // low byte of UTF-16LE
        }

        // Parse hex pairs into bytes
        for i in 0..6 {
            let hi = hex_nibble(hex_chars[i * 2]).ok_or(CdcError::InvalidMacString)?;
            let lo = hex_nibble(hex_chars[i * 2 + 1]).ok_or(CdcError::InvalidMacString)?;
            self.mac[i] = (hi << 4) | lo;
        }

        self.initialized = true;
        Ok(())
    }

    /// Feed a completed bulk IN transfer. Decodes frame(s) via the codec
    /// and queues them for `poll_tx`. Returns actions to re-queue the
    /// bulk IN transfer.
    pub fn receive_bulk_in(&mut self, data: &[u8]) -> Vec<CdcAction> {
        let mut frames = Vec::new();
        // Decode errors are per-transfer — log and drop
        let _ = self.codec.decode_rx(data, &mut frames);

        for frame in frames {
            self.rx_queue.push_back(frame);
        }

        // Re-queue bulk IN
        alloc::vec![CdcAction::BulkIn {
            ep: self.descriptors.bulk_in_ep.address,
            max_len: self.descriptors.bulk_in_ep.max_packet_size,
        }]
    }

    /// Feed a completed interrupt IN transfer. Updates link/speed state.
    /// Returns actions to re-queue the interrupt transfer.
    pub fn receive_interrupt(&mut self, data: &[u8]) -> Vec<CdcAction> {
        if let Ok(notif) = notification::parse_notification(data) {
            match notif {
                CdcNotification::NetworkConnection { connected } => {
                    self.link_up = connected;
                }
                CdcNotification::ConnectionSpeedChange {
                    downstream,
                    upstream,
                } => {
                    self.speed_down = downstream;
                    self.speed_up = upstream;
                }
                CdcNotification::Unknown { .. } => {} // ignore
            }
        }

        // Re-queue interrupt IN
        alloc::vec![CdcAction::InterruptIn {
            ep: self.descriptors.interrupt_ep.address,
            max_len: self.descriptors.interrupt_ep.max_packet_size,
        }]
    }

    /// Encode and queue a frame for transmission. Returns bulk OUT action.
    pub fn send_frame(&mut self, frame: &[u8]) -> Result<Vec<CdcAction>, CdcError> {
        if !self.initialized {
            return Err(CdcError::NotReady);
        }
        if frame.len() > self.descriptors.max_segment_size as usize {
            return Err(CdcError::FrameTooLarge);
        }

        let encoded = self.codec.encode_tx(frame)?;
        Ok(alloc::vec![CdcAction::BulkOut {
            ep: self.descriptors.bulk_out_ep.address,
            data: encoded,
        }])
    }

    /// Drain any pending actions buffered by `push_rx`.
    ///
    /// `NetworkDevice::push_rx` can't return actions directly, so they
    /// accumulate in `pending_actions`. The caller should drain these
    /// after each `push_rx` call (or batch of calls).
    pub fn drain_pending_actions(&mut self) -> Vec<CdcAction> {
        core::mem::take(&mut self.pending_actions)
    }

    /// The CDC protocol variant (ECM or NCM).
    pub fn protocol(&self) -> CdcProtocol {
        self.descriptors.protocol
    }

}

/// Convert an ASCII hex character to its nibble value.
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'F' => Some(c - b'A' + 10),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

// ── NetworkDevice implementation ────────────────────────────────

// This impl requires harmony-microkernel as a dependency. Since
// harmony-unikernel does NOT depend on harmony-microkernel (Ring 1
// is lower than Ring 2), the NetworkDevice impl lives in
// harmony-microkernel via a wrapper or the trait is defined in a
// shared location.
//
// Looking at the codebase: NetworkDevice is in harmony-microkernel,
// and VirtioNetServer is also in harmony-microkernel. The existing
// pattern (GenetServer) has the Ring 2 code directly access the
// Ring 1 driver.
//
// For CdcEthernetDriver, we provide the methods that match
// NetworkDevice semantics. The actual trait impl will be in
// harmony-microkernel (or the trait can be moved to a shared crate).
// For now, we expose the methods with matching signatures.

impl CdcEthernetDriver {
    /// Extract the next received Ethernet frame (from USB bulk IN).
    /// Matches `NetworkDevice::poll_tx` semantics.
    pub fn poll_rx_frame(&mut self, out: &mut [u8]) -> Option<usize> {
        let frame = self.rx_queue.pop_front()?;
        let n = frame.len().min(out.len());
        out[..n].copy_from_slice(&frame[..n]);
        Some(frame.len())
    }

    /// Queue a frame for transmission via USB bulk OUT.
    /// Matches `NetworkDevice::push_rx` semantics.
    /// Buffered actions must be retrieved via `drain_pending_actions`.
    pub fn queue_tx_frame(&mut self, frame: &[u8]) -> bool {
        match self.send_frame(frame) {
            Ok(actions) => {
                self.pending_actions.extend(actions);
                true
            }
            Err(_) => false,
        }
    }

    /// The device's MAC address.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Whether the link is currently up.
    pub fn link_up(&self) -> bool {
        self.link_up
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Build a USB string descriptor for a MAC address.
    /// Format: [bLength, 0x03, UTF-16LE chars...]
    fn build_mac_string_descriptor(mac_hex: &str) -> Vec<u8> {
        let chars: Vec<u8> = mac_hex.bytes().collect();
        let mut desc = Vec::new();
        desc.push((2 + chars.len() * 2) as u8); // bLength
        desc.push(0x03); // bDescriptorType = STRING
        for &c in &chars {
            desc.push(c); // low byte (ASCII)
            desc.push(0); // high byte (0 for ASCII)
        }
        desc
    }

    /// Create a driver from the test ECM config descriptor.
    fn make_ecm_driver() -> (CdcEthernetDriver, Vec<CdcAction>) {
        let config = super::descriptor::tests::build_ecm_config_desc();
        CdcEthernetDriver::from_config_descriptor(1, &config)
            .unwrap()
            .unwrap()
    }

    // ── Initialization ──────────────────────────────────────────

    #[test]
    fn from_config_descriptor_ecm() {
        let (driver, actions) = make_ecm_driver();

        assert_eq!(driver.protocol(), CdcProtocol::Ecm);
        assert!(!driver.initialized);
        assert!(!driver.link_up);

        // Should have: SET_CONFIG, SET_INTERFACE, GET_STRING, SET_PACKET_FILTER,
        //              BulkIn, InterruptIn
        assert_eq!(actions.len(), 6);
        assert!(matches!(actions[0], CdcAction::ControlOut { .. }));
        assert!(matches!(actions[1], CdcAction::ControlOut { .. }));
        assert!(matches!(actions[2], CdcAction::ControlIn { .. }));
        assert!(matches!(actions[3], CdcAction::ControlOut { .. }));
        assert!(matches!(actions[4], CdcAction::BulkIn { .. }));
        assert!(matches!(actions[5], CdcAction::InterruptIn { .. }));
    }

    #[test]
    fn from_config_descriptor_no_cdc() {
        // Non-CDC config
        let mut d = Vec::new();
        let total: u16 = 18;
        d.push(9); d.push(0x02);
        d.extend_from_slice(&total.to_le_bytes());
        d.push(1); d.push(1); d.push(0); d.push(0x80); d.push(250);
        d.push(9); d.push(0x04);
        d.push(0); d.push(0); d.push(0); d.push(0x03); d.push(0x01);
        d.push(0x01); d.push(0);
        assert!(CdcEthernetDriver::from_config_descriptor(1, &d).unwrap().is_none());
    }

    #[test]
    fn complete_init_parses_mac() {
        let (mut driver, _) = make_ecm_driver();
        let mac_str = build_mac_string_descriptor("AABBCCDDEEFF");
        driver.complete_init(&mac_str).unwrap();

        assert!(driver.initialized);
        assert_eq!(driver.mac(), [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn complete_init_lowercase_mac() {
        let (mut driver, _) = make_ecm_driver();
        let mac_str = build_mac_string_descriptor("aabbccddeeff");
        driver.complete_init(&mac_str).unwrap();
        assert_eq!(driver.mac(), [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn complete_init_too_short() {
        let (mut driver, _) = make_ecm_driver();
        assert_eq!(driver.complete_init(&[0x03, 0x03]), Err(CdcError::InvalidMacString));
    }

    #[test]
    fn complete_init_invalid_hex() {
        let (mut driver, _) = make_ecm_driver();
        let mac_str = build_mac_string_descriptor("GGHHIIJJKKLL");
        assert_eq!(driver.complete_init(&mac_str), Err(CdcError::InvalidMacString));
    }

    // ── Receive (bulk IN) ───────────────────────────────────────

    #[test]
    fn receive_ecm_frame() {
        let (mut driver, _) = make_ecm_driver();
        let mac_str = build_mac_string_descriptor("AABBCCDDEEFF");
        driver.complete_init(&mac_str).unwrap();

        let frame = vec![0xDE; 64];
        let actions = driver.receive_bulk_in(&frame);

        // Should re-queue bulk IN
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], CdcAction::BulkIn { .. }));

        // Frame should be in rx_queue
        let mut buf = [0u8; 128];
        let n = driver.poll_rx_frame(&mut buf).unwrap();
        assert_eq!(n, 64);
        assert_eq!(&buf[..64], &[0xDE; 64]);
    }

    #[test]
    fn receive_empty_bulk_in() {
        let (mut driver, _) = make_ecm_driver();

        let actions = driver.receive_bulk_in(&[]);
        assert_eq!(actions.len(), 1); // re-queue

        // No frame queued
        let mut buf = [0u8; 128];
        assert!(driver.poll_rx_frame(&mut buf).is_none());
    }

    // ── Send (bulk OUT) ─────────────────────────────────────────

    #[test]
    fn send_ecm_frame() {
        let (mut driver, _) = make_ecm_driver();
        let mac_str = build_mac_string_descriptor("AABBCCDDEEFF");
        driver.complete_init(&mac_str).unwrap();

        let frame = vec![0xAA; 60];
        let actions = driver.send_frame(&frame).unwrap();

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            CdcAction::BulkOut { ep, data } => {
                assert_eq!(*ep, 0x02); // bulk OUT endpoint
                assert_eq!(data, &frame); // ECM: passthrough
            }
            _ => panic!("expected BulkOut"),
        }
    }

    #[test]
    fn send_before_init_fails() {
        let (mut driver, _) = make_ecm_driver();
        assert_eq!(driver.send_frame(&[0x01; 60]), Err(CdcError::NotReady));
    }

    #[test]
    fn send_oversized_frame_fails() {
        let (mut driver, _) = make_ecm_driver();
        let mac_str = build_mac_string_descriptor("AABBCCDDEEFF");
        driver.complete_init(&mac_str).unwrap();

        // max_segment_size is 1514 from test descriptor
        let frame = vec![0x01; 1515];
        assert_eq!(driver.send_frame(&frame), Err(CdcError::FrameTooLarge));
    }

    // ── NetworkDevice-compatible methods ─────────────────────────

    #[test]
    fn queue_tx_frame_buffers_actions() {
        let (mut driver, _) = make_ecm_driver();
        let mac_str = build_mac_string_descriptor("AABBCCDDEEFF");
        driver.complete_init(&mac_str).unwrap();

        assert!(driver.queue_tx_frame(&[0xBB; 60]));
        let actions = driver.drain_pending_actions();
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], CdcAction::BulkOut { .. }));

        // Drain again should be empty
        assert!(driver.drain_pending_actions().is_empty());
    }

    // ── Notifications ───────────────────────────────────────────

    #[test]
    fn receive_link_up_notification() {
        let (mut driver, _) = make_ecm_driver();
        assert!(!driver.link_up());

        let mut notif = [0u8; 8];
        notif[0] = 0xA1;
        notif[1] = 0x00; // NETWORK_CONNECTION
        notif[2] = 0x01; // connected

        let actions = driver.receive_interrupt(&notif);
        assert!(driver.link_up());
        assert_eq!(actions.len(), 1); // re-queue
    }

    #[test]
    fn receive_link_down_notification() {
        let (mut driver, _) = make_ecm_driver();
        driver.link_up = true;

        let mut notif = [0u8; 8];
        notif[0] = 0xA1;
        notif[1] = 0x00;
        // wValue = 0 → disconnected

        let actions = driver.receive_interrupt(&notif);
        assert!(!driver.link_up());
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn receive_speed_change_notification() {
        let (mut driver, _) = make_ecm_driver();

        let mut notif = [0u8; 16];
        notif[0] = 0xA1;
        notif[1] = 0x2A; // CONNECTION_SPEED_CHANGE
        notif[6] = 0x08; // wLength = 8
        notif[8..12].copy_from_slice(&1_000_000_000u32.to_le_bytes());
        notif[12..16].copy_from_slice(&100_000_000u32.to_le_bytes());

        driver.receive_interrupt(&notif);
        assert_eq!(driver.speed_down, 1_000_000_000);
        assert_eq!(driver.speed_up, 100_000_000);
    }

    #[test]
    fn receive_malformed_notification_ignored() {
        let (mut driver, _) = make_ecm_driver();
        // Too short — parse_notification returns Err, but receive_interrupt doesn't panic
        let actions = driver.receive_interrupt(&[0x01, 0x02]);
        assert_eq!(actions.len(), 1); // still re-queues
    }
}
```

**Note about `descriptor::tests::build_ecm_config_desc`:** The test helper in `descriptor.rs` needs to be `pub(super)` for the mod.rs tests to use it. Update the visibility:

In `descriptor.rs`, change:
```rust
#[cfg(test)]
mod tests {
```
to:
```rust
#[cfg(test)]
pub(super) mod tests {
```

And change:
```rust
    fn build_ecm_config_desc() -> Vec<u8> {
```
to:
```rust
    pub(super) fn build_ecm_config_desc() -> Vec<u8> {
```

- [ ] **Step 2: Run all cdc_ethernet tests**

Run: `cargo test -p harmony-unikernel --lib drivers::cdc_ethernet`

Expected: All tests pass across all submodules (notification: 7, ncm: 12, codec: 6, descriptor: 6, mod: 14 = ~45 total).

- [ ] **Step 3: Run full workspace tests**

Run: `cargo test --workspace`

Expected: All tests pass. The new module doesn't break anything.

- [ ] **Step 4: Run clippy**

Run: `cargo clippy --workspace`

Expected: No warnings in the new code.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/cdc_ethernet/
git commit -m "feat(usb): add CdcEthernetDriver with NetworkDevice-compatible API

Unified CDC-ECM/NCM driver with two-phase init, CdcAction return type,
polling-based data path. Parses config descriptors, decodes/encodes
frames via CdcCodec, handles CDC notifications for link state.

Exposes poll_rx_frame/queue_tx_frame matching NetworkDevice semantics
for Ring 2 VirtioNetServer integration.

Bead: harmony-os-y66"
```

---

### Task 6: NetworkDevice trait impl in harmony-microkernel

**Files:**
- Create: `crates/harmony-microkernel/src/cdc_net_device.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs`

The `NetworkDevice` trait lives in `harmony-microkernel`. `CdcEthernetDriver` lives in `harmony-unikernel`. Since microkernel depends on unikernel (Ring 2 uses Ring 1 drivers), we can implement the trait in microkernel.

- [ ] **Step 1: Check the microkernel's dependency on unikernel**

Run: `grep harmony-unikernel crates/harmony-microkernel/Cargo.toml`

Expected: `harmony-unikernel` is listed as a dependency (this is the pattern used by `GenetServer`).

- [ ] **Step 2: Create cdc_net_device.rs**

Create `crates/harmony-microkernel/src/cdc_net_device.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! [`NetworkDevice`] adapter for [`CdcEthernetDriver`].
//!
//! Wraps the CDC driver's `poll_rx_frame` / `queue_tx_frame` methods
//! into the `NetworkDevice` trait, enabling `VirtioNetServer` reuse.
//!
//! The caller must periodically call [`CdcNetDevice::drain_actions`]
//! to retrieve pending USB actions generated by `push_rx` (frame TX).

extern crate alloc;
use alloc::vec::Vec;

use harmony_unikernel::drivers::cdc_ethernet::{CdcAction, CdcEthernetDriver};

use crate::net_device::NetworkDevice;

/// A [`NetworkDevice`] wrapper around [`CdcEthernetDriver`].
///
/// This adapter bridges the CDC driver's action-based API with the
/// `NetworkDevice` trait expected by `VirtioNetServer`.
pub struct CdcNetDevice {
    driver: CdcEthernetDriver,
}

impl CdcNetDevice {
    /// Wrap an initialized `CdcEthernetDriver`.
    pub fn new(driver: CdcEthernetDriver) -> Self {
        Self { driver }
    }

    /// Access the underlying CDC driver (e.g., to feed bulk IN / interrupt data).
    pub fn driver_mut(&mut self) -> &mut CdcEthernetDriver {
        &mut self.driver
    }

    /// Drain pending USB actions generated by `push_rx` calls.
    ///
    /// Must be called after each `push_rx` (or batch) to retrieve
    /// the `CdcAction::BulkOut` actions for the xHCI driver.
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
    use alloc::vec;

    /// Build a USB string descriptor for a MAC address.
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

    /// Create an initialized CdcNetDevice from the test ECM descriptor.
    fn make_cdc_net_device() -> CdcNetDevice {
        // We need the ECM config descriptor from the descriptor module's tests
        let config = harmony_unikernel::drivers::cdc_ethernet::descriptor::tests::build_ecm_config_desc();
        let (mut driver, _actions) =
            CdcEthernetDriver::from_config_descriptor(1, &config)
                .unwrap()
                .unwrap();
        driver.complete_init(&build_mac_string("DEADBEEFCAFE")).unwrap();
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

        assert!(dev.push_rx(&[0xAA; 60]));
        let actions = dev.drain_actions();
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], CdcAction::BulkOut { .. }));
    }

    #[test]
    fn network_device_poll_tx_after_bulk_in() {
        let mut dev = make_cdc_net_device();

        // Feed a bulk IN frame to the driver
        let _requeue = dev.driver_mut().receive_bulk_in(&[0xBB; 64]);

        // poll_tx should return it
        let mut buf = [0u8; 128];
        let n = dev.poll_tx(&mut buf).unwrap();
        assert_eq!(n, 64);
        assert_eq!(&buf[..64], &[0xBB; 64]);
    }

    #[test]
    fn network_device_poll_tx_empty() {
        let mut dev = make_cdc_net_device();
        let mut buf = [0u8; 128];
        assert!(dev.poll_tx(&mut buf).is_none());
    }

    #[test]
    fn virtio_net_server_type_check() {
        // Verify VirtioNetServer<CdcNetDevice> compiles
        fn _accepts(dev: CdcNetDevice) {
            let _server = crate::virtio_net_server::VirtioNetServer::new(dev, "cdc0");
        }
    }
}
```

- [ ] **Step 3: Register the module in lib.rs**

In `crates/harmony-microkernel/src/lib.rs`, add:

```rust
pub mod cdc_net_device;
```

(Add it in alphabetical order among the existing module declarations.)

- [ ] **Step 4: Make descriptor test helpers accessible**

The `build_ecm_config_desc` helper in `descriptor.rs` needs `pub(crate)` visibility so the microkernel tests can reach it through the public API. Update `descriptor.rs`:

Change `pub(super) mod tests` to just `pub mod tests` and `pub(super) fn build_ecm_config_desc` to `pub fn build_ecm_config_desc`.

This is fine — test helper visibility in a `#[cfg(test)]` module only matters in test builds.

- [ ] **Step 5: Run tests**

Run: `cargo test -p harmony-microkernel --lib cdc_net_device`

Expected: All 6 tests pass, including the `VirtioNetServer<CdcNetDevice>` type check.

- [ ] **Step 6: Run full workspace tests**

Run: `cargo test --workspace`

Expected: All tests pass.

- [ ] **Step 7: Run clippy and format**

Run: `cargo clippy --workspace && cargo +nightly fmt --all -- --check`

Expected: No warnings or format issues.

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-microkernel/src/cdc_net_device.rs
git add crates/harmony-microkernel/src/lib.rs
git add crates/harmony-unikernel/src/drivers/cdc_ethernet/descriptor.rs
git commit -m "feat(microkernel): add CdcNetDevice adapter for NetworkDevice trait

Wraps CdcEthernetDriver in a NetworkDevice impl so VirtioNetServer
can expose CDC-ECM/NCM devices as 9P /dev/net/cdc0/ with zero new
Ring 2 code. Includes type-level verification that
VirtioNetServer<CdcNetDevice> compiles.

Bead: harmony-os-y66"
```

---

## Manual Operator Steps

After all tasks are implemented and merged:

1. **Test with real hardware:** Plug a USB-Ethernet dongle (CDC-ECM or NCM class) into an RPi5 and verify:
   - xHCI enumeration detects the CDC interface
   - `from_config_descriptor` parses the device's config descriptor
   - MAC address is extracted correctly
   - Frames flow through bulk endpoints
   - Link notifications update state

2. **Create gadget mode bead:** Already created as harmony-os-eyn during brainstorming.
