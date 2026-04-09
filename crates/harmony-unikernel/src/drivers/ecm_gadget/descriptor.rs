// SPDX-License-Identifier: GPL-2.0-or-later
//! CDC-ECM descriptor builders for USB device mode.
//!
//! Constructs the exact byte sequences a USB host expects during enumeration.
//! The layout mirrors the host-side parser in
//! `crate::drivers::cdc_ethernet::descriptor` so that
//! `build_config_descriptor()` → `parse_cdc_config()` round-trips cleanly.

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

// ── Constants ────────────────────────────────────────────────────────────────

/// USB Vendor ID — pid.codes test VID.
const VID: u16 = 0x1209;
/// USB Product ID — generic test PID.
const PID: u16 = 0x0001;

// String descriptor indices.
// 0 = LANGID list (mandatory), 1 = Manufacturer, 2 = Product,
// 3 = Serial, 4 = MAC address.
const SIDX_MAC: u8 = 4;

/// Endpoint addresses.
const EP_BULK_IN: u8 = 0x81;
const EP_BULK_OUT: u8 = 0x02;
const EP_INTERRUPT_IN: u8 = 0x83;

/// wMaxSegmentSize for CDC-ECM (IEEE 802.3 max frame, excl. FCS).
const MAX_SEGMENT_SIZE: u16 = 1514;

/// Total length of the configuration descriptor chain (bytes).
///
/// Config(9) + CommIf(9) + HeaderFD(5) + UnionFD(5) + EthernetFD(13) +
/// IntrEP(7) + DataIf-alt0(9) + DataIf-alt1(9) + BulkIN(7) + BulkOUT(7) = 80
const CONFIG_TOTAL_LENGTH: u16 = 80;

// ── Device descriptor ────────────────────────────────────────────────────────

/// Build the 18-byte USB device descriptor.
///
/// - USB 2.0 (bcdUSB = 0x0200)
/// - Device class 0x02 (CDC)
/// - VID = 0x1209, PID = 0x0001
/// - String indices: Manufacturer=1, Product=2, Serial=3
/// - 1 configuration
pub fn build_device_descriptor() -> Vec<u8> {
    let mut v = Vec::with_capacity(18);
    v.extend_from_slice(&[
        18,   // bLength
        0x01, // bDescriptorType: DEVICE
        0x00, // bcdUSB low  (USB 2.0 = 0x0200)
        0x02, // bcdUSB high
        0x02, // bDeviceClass: CDC
        0x00, // bDeviceSubClass
        0x00, // bDeviceProtocol
        64,   // bMaxPacketSize0 (EP0, 64 bytes for HS)
        (VID & 0xFF) as u8,
        (VID >> 8) as u8,
        (PID & 0xFF) as u8,
        (PID >> 8) as u8,
        0x00, // bcdDevice low
        0x01, // bcdDevice high  (device release 1.0)
        1,    // iManufacturer  (string index)
        2,    // iProduct
        3,    // iSerialNumber
        1,    // bNumConfigurations
    ]);
    debug_assert_eq!(v.len(), 18);
    v
}

// ── Configuration descriptor chain ──────────────────────────────────────────

/// Build the 80-byte CDC-ECM configuration descriptor chain.
///
/// Layout (offset → descriptor):
/// ```text
///  0 .. 9   Configuration header
///  9 .. 18  Communication Interface 0 (CDC, ECM subclass, 1 EP)
/// 18 .. 23  Header Functional Descriptor (CDC 1.10)
/// 23 .. 28  Union Functional Descriptor  (ctrl=0, data=1)
/// 28 .. 41  Ethernet Functional Descriptor (iMAC=4, seg=1514)
/// 41 .. 48  Interrupt IN endpoint (0x83, MPS=16)
/// 48 .. 57  Data Interface 1 alt 0 (0 endpoints)
/// 57 .. 66  Data Interface 1 alt 1 (2 endpoints, CDC Data 0x0A)
/// 66 .. 73  Bulk IN endpoint  (0x81, MPS=512)
/// 73 .. 80  Bulk OUT endpoint (0x02, MPS=512)
/// ```
pub fn build_config_descriptor() -> Vec<u8> {
    let mut v = Vec::with_capacity(CONFIG_TOTAL_LENGTH as usize);

    // ── Configuration descriptor (9 bytes) ──────────────────────────────────
    v.extend_from_slice(&[
        9,                                       // bLength
        0x02,                                    // bDescriptorType: CONFIGURATION
        (CONFIG_TOTAL_LENGTH & 0xFF) as u8,      // wTotalLength low
        (CONFIG_TOTAL_LENGTH >> 8) as u8,        // wTotalLength high
        2,                                       // bNumInterfaces
        1,                                       // bConfigurationValue
        0,                                       // iConfiguration
        0xC0,                                    // bmAttributes: self-powered
        50,                                      // bMaxPower (100 mA)
    ]);

    // ── Communication Interface 0, alt 0 (9 bytes) ──────────────────────────
    v.extend_from_slice(&[
        9,    // bLength
        0x04, // bDescriptorType: INTERFACE
        0,    // bInterfaceNumber (control)
        0,    // bAlternateSetting
        1,    // bNumEndpoints (interrupt IN)
        0x02, // bInterfaceClass: CDC
        0x06, // bInterfaceSubClass: ECM
        0x00, // bInterfaceProtocol
        0,    // iInterface
    ]);

    // ── Header Functional Descriptor (5 bytes) ───────────────────────────────
    v.extend_from_slice(&[
        5,    // bLength
        0x24, // bDescriptorType: CS_INTERFACE
        0x00, // bDescriptorSubType: Header
        0x10, // bcdCDC low  (CDC 1.10)
        0x01, // bcdCDC high
    ]);

    // ── Union Functional Descriptor (5 bytes) ────────────────────────────────
    v.extend_from_slice(&[
        5,    // bLength
        0x24, // bDescriptorType: CS_INTERFACE
        0x06, // bDescriptorSubType: Union
        0,    // bControlInterface (interface 0)
        1,    // bSubordinateInterface0 (data interface, number 1)
    ]);

    // ── Ethernet Functional Descriptor (13 bytes) ────────────────────────────
    // iMACAddress = SIDX_MAC (4), wMaxSegmentSize = 1514 = 0x05EA
    v.extend_from_slice(&[
        13,                                         // bLength
        0x24,                                       // bDescriptorType: CS_INTERFACE
        0x0F,                                       // bDescriptorSubType: Ethernet Networking
        SIDX_MAC,                                   // iMACAddress
        0x00,                                       // bmEthernetStatistics[0]
        0x00,                                       // bmEthernetStatistics[1]
        0x00,                                       // bmEthernetStatistics[2]
        0x00,                                       // bmEthernetStatistics[3]
        (MAX_SEGMENT_SIZE & 0xFF) as u8,            // wMaxSegmentSize low  (0xEA)
        (MAX_SEGMENT_SIZE >> 8) as u8,              // wMaxSegmentSize high (0x05)
        0x00,                                       // wNumberMCFilters low
        0x00,                                       // wNumberMCFilters high
        0,                                          // bNumberPowerFilters
    ]);

    // ── Interrupt IN Endpoint (7 bytes) ──────────────────────────────────────
    v.extend_from_slice(&[
        7,     // bLength
        0x05,  // bDescriptorType: ENDPOINT
        EP_INTERRUPT_IN, // bEndpointAddress: IN, EP 3 = 0x83
        0x03,  // bmAttributes: Interrupt
        16,    // wMaxPacketSize low
        0x00,  // wMaxPacketSize high
        11,    // bInterval (ms)
    ]);

    // ── Data Interface 1, alt 0 (9 bytes, 0 endpoints) ───────────────────────
    v.extend_from_slice(&[
        9,    // bLength
        0x04, // bDescriptorType: INTERFACE
        1,    // bInterfaceNumber (data)
        0,    // bAlternateSetting = 0
        0,    // bNumEndpoints = 0
        0x0A, // bInterfaceClass: CDC Data
        0x00, // bInterfaceSubClass
        0x00, // bInterfaceProtocol
        0,    // iInterface
    ]);

    // ── Data Interface 1, alt 1 (9 bytes, 2 endpoints) ───────────────────────
    v.extend_from_slice(&[
        9,    // bLength
        0x04, // bDescriptorType: INTERFACE
        1,    // bInterfaceNumber (data)
        1,    // bAlternateSetting = 1
        2,    // bNumEndpoints = 2
        0x0A, // bInterfaceClass: CDC Data
        0x00, // bInterfaceSubClass
        0x00, // bInterfaceProtocol
        0,    // iInterface
    ]);

    // ── Bulk IN Endpoint (7 bytes) ────────────────────────────────────────────
    // address=0x81, bulk, MPS=512 = 0x0200
    v.extend_from_slice(&[
        7,          // bLength
        0x05,       // bDescriptorType: ENDPOINT
        EP_BULK_IN, // bEndpointAddress: IN, EP 1 = 0x81
        0x02,       // bmAttributes: Bulk
        0x00,       // wMaxPacketSize low  (512 = 0x0200)
        0x02,       // wMaxPacketSize high
        0,          // bInterval
    ]);

    // ── Bulk OUT Endpoint (7 bytes) ───────────────────────────────────────────
    // address=0x02, bulk, MPS=512 = 0x0200
    v.extend_from_slice(&[
        7,           // bLength
        0x05,        // bDescriptorType: ENDPOINT
        EP_BULK_OUT, // bEndpointAddress: OUT, EP 2 = 0x02
        0x02,        // bmAttributes: Bulk
        0x00,        // wMaxPacketSize low  (512 = 0x0200)
        0x02,        // wMaxPacketSize high
        0,           // bInterval
    ]);

    debug_assert_eq!(
        v.len(),
        CONFIG_TOTAL_LENGTH as usize,
        "config descriptor must be exactly {} bytes",
        CONFIG_TOTAL_LENGTH
    );
    v
}

// ── String descriptors ───────────────────────────────────────────────────────

/// Build a USB string descriptor from a UTF-8 string.
///
/// Format: `[bLength, 0x03, char0_lo, 0x00, char1_lo, 0x00, ...]`
/// Only the low byte of each UTF-16LE code unit is used (ASCII subset).
fn build_string_descriptor(s: &str) -> Vec<u8> {
    let chars: Vec<u16> = s.encode_utf16().collect();
    let blen = 2 + chars.len() * 2;
    let mut v = Vec::with_capacity(blen);
    v.push(blen as u8);
    v.push(0x03); // bDescriptorType: STRING
    for ch in chars {
        v.push((ch & 0xFF) as u8);
        v.push((ch >> 8) as u8);
    }
    v
}

/// Convert a 6-byte MAC address to an uppercase hex string (12 chars).
fn mac_to_hex_string(mac: &[u8; 6]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(12);
    for &byte in mac.iter() {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0F) as usize] as char);
    }
    s
}

/// Build all 5 string descriptors for the ECM gadget.
///
/// Indices:
/// - 0: LANGID list (`[4, 0x03, 0x09, 0x04]` — English US)
/// - 1: Manufacturer ("Harmony")
/// - 2: Product ("Harmony ECM Gadget")
/// - 3: Serial (MAC as 12 uppercase hex chars)
/// - 4: MAC address (12 uppercase hex chars, same encoding)
///
/// The MAC address string at index 4 is what the host reads via `GET_DESCRIPTOR`
/// after parsing `iMACAddress` from the Ethernet Functional Descriptor.
pub fn build_string_descriptors(mac: &[u8; 6]) -> Vec<Vec<u8>> {
    let mac_str = mac_to_hex_string(mac);

    vec![
        // Index 0: LANGID list — English US (0x0409)
        vec![4, 0x03, 0x09, 0x04],
        // Index 1: Manufacturer
        build_string_descriptor("Harmony"),
        // Index 2: Product
        build_string_descriptor("Harmony ECM Gadget"),
        // Index 3: Serial number (MAC hex)
        build_string_descriptor(&mac_str),
        // Index 4: MAC address string (iMACAddress)
        build_string_descriptor(&mac_str),
    ]
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::drivers::cdc_ethernet::descriptor::parse_cdc_config;
    use crate::drivers::cdc_ethernet::{CdcProtocol, EndpointInfo};

    #[test]
    fn device_descriptor_length_and_class() {
        let desc = build_device_descriptor();
        assert_eq!(desc.len(), 18, "device descriptor must be 18 bytes");
        assert_eq!(desc[4], 0x02, "bDeviceClass must be CDC (0x02)");
    }

    #[test]
    fn device_descriptor_vid_pid() {
        let desc = build_device_descriptor();
        let vid = u16::from_le_bytes([desc[8], desc[9]]);
        let pid = u16::from_le_bytes([desc[10], desc[11]]);
        assert_eq!(vid, VID, "VID mismatch");
        assert_eq!(pid, PID, "PID mismatch");
    }

    #[test]
    fn config_descriptor_total_length() {
        let desc = build_config_descriptor();
        let w_total = u16::from_le_bytes([desc[2], desc[3]]);
        assert_eq!(
            w_total,
            desc.len() as u16,
            "wTotalLength must equal actual byte length"
        );
        assert_eq!(w_total, 80, "wTotalLength must be 80");
    }

    #[test]
    fn config_descriptor_ecm_subclass() {
        let desc = build_config_descriptor();
        // Comm interface starts at offset 9.
        // Interface descriptor layout: bLength(0) bType(1) bIfNum(2) bAlt(3)
        //   bNumEP(4) bIfClass(5) bIfSubClass(6) bIfProto(7) iIf(8)
        // Subclass is at offset 9 + 6 = 15.
        assert_eq!(
            desc[15], 0x06,
            "bInterfaceSubClass must be ECM (0x06) at byte 15"
        );
    }

    #[test]
    fn cdc_functional_descriptors_present() {
        let desc = build_config_descriptor();

        let mut found_header = false;
        let mut found_union = false;
        let mut found_ethernet = false;

        let mut pos = 0usize;
        while pos < desc.len() {
            let b_len = desc[pos] as usize;
            if b_len < 2 || pos + b_len > desc.len() {
                break;
            }
            let b_type = desc[pos + 1];
            if b_type == 0x24 && desc.len() > pos + 2 {
                match desc[pos + 2] {
                    0x00 => found_header = true,
                    0x06 => found_union = true,
                    0x0F => found_ethernet = true,
                    _ => {}
                }
            }
            pos += b_len;
        }

        assert!(found_header, "Header FD (subtype 0x00) missing");
        assert!(found_union, "Union FD (subtype 0x06) missing");
        assert!(found_ethernet, "Ethernet FD (subtype 0x0F) missing");
    }

    #[test]
    fn string_descriptor_mac_format() {
        let mac = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let s = mac_to_hex_string(&mac);
        assert_eq!(s, "DEADBEEFCAFE");
    }

    #[test]
    fn string_descriptors_correct_count() {
        let mac = [0x00u8; 6];
        let descs = build_string_descriptors(&mac);
        assert_eq!(descs.len(), 5, "must return exactly 5 string descriptors");
    }

    #[test]
    fn langid_descriptor() {
        let mac = [0x00u8; 6];
        let descs = build_string_descriptors(&mac);
        assert_eq!(
            descs[0],
            vec![4, 0x03, 0x09, 0x04],
            "LANGID descriptor must be [4, 0x03, 0x09, 0x04]"
        );
    }

    /// Feed `build_config_descriptor()` into the host-side parser and verify
    /// that all fields round-trip correctly.  This is the primary interop test.
    #[test]
    fn roundtrip_with_host_parser() {
        let config_desc = build_config_descriptor();
        let result =
            parse_cdc_config(&config_desc).expect("host parser must not return an error");
        let info = result.expect("host parser must find a CDC interface");

        assert_eq!(info.protocol, CdcProtocol::Ecm, "protocol must be ECM");
        assert_eq!(info.control_interface, 0, "control interface must be 0");
        assert_eq!(info.data_interface, 1, "data interface must be 1");
        assert_eq!(info.data_alt_setting, 1, "data alt setting must be 1");
        assert_eq!(
            info.bulk_in_ep,
            EndpointInfo {
                address: EP_BULK_IN,
                max_packet_size: 512,
            },
            "bulk IN endpoint mismatch"
        );
        assert_eq!(
            info.bulk_out_ep,
            EndpointInfo {
                address: EP_BULK_OUT,
                max_packet_size: 512,
            },
            "bulk OUT endpoint mismatch"
        );
        assert_eq!(
            info.interrupt_ep,
            EndpointInfo {
                address: EP_INTERRUPT_IN,
                max_packet_size: 16,
            },
            "interrupt endpoint mismatch"
        );
        assert_eq!(
            info.mac_string_index, SIDX_MAC,
            "mac_string_index must be {SIDX_MAC}"
        );
        assert_eq!(
            info.max_segment_size, MAX_SEGMENT_SIZE,
            "max_segment_size must be {MAX_SEGMENT_SIZE}"
        );
        assert_eq!(info.config_value, 1, "config_value must be 1");
    }
}
