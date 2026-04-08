// SPDX-License-Identifier: GPL-2.0-or-later

//! CDC descriptor parser.
//!
//! Walks a raw USB configuration descriptor byte stream to find CDC ECM/NCM
//! Communication interfaces and extract endpoint and functional descriptor info.
//!
//! USB config descriptors are flat TLV byte streams. Each entry:
//! `[bLength, bDescriptorType, ...data...]`. Walk by advancing `pos += bLength`.
//! CDC functional descriptors have `bDescriptorType=0x24` with a subtype at `[pos+2]`.

use super::CdcError;

// ── USB standard descriptor types ────────────────────────────────────────────

const USB_DESC_CONFIGURATION: u8 = 0x02;
const USB_DESC_INTERFACE: u8 = 0x04;
const USB_DESC_ENDPOINT: u8 = 0x05;
const USB_DESC_CS_INTERFACE: u8 = 0x24;

// ── CDC class/subclass codes ──────────────────────────────────────────────────

const CDC_INTERFACE_CLASS: u8 = 0x02;
const CDC_DATA_INTERFACE_CLASS: u8 = 0x0A;
const CDC_SUBCLASS_ECM: u8 = 0x06;
const CDC_SUBCLASS_NCM: u8 = 0x0D;

// ── CDC functional descriptor subtypes ───────────────────────────────────────

const CDC_FUNC_HEADER: u8 = 0x00;
const CDC_FUNC_UNION: u8 = 0x06;
const CDC_FUNC_ETHERNET: u8 = 0x0F;
const CDC_FUNC_NCM: u8 = 0x1A;

// ── Types ─────────────────────────────────────────────────────────────────────

/// CDC protocol variant detected in the configuration descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdcProtocol {
    /// CDC ECM (Ethernet Control Model), subclass 0x06.
    Ecm,
    /// CDC NCM (Network Control Model), subclass 0x0D.
    Ncm,
}

/// Basic information about a USB endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointInfo {
    /// `bEndpointAddress` byte (direction bit in bit 7).
    pub address: u8,
    /// `wMaxPacketSize` from the endpoint descriptor.
    pub max_packet_size: u16,
}

/// All CDC-relevant information extracted from a USB configuration descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdcDescriptors {
    /// Protocol variant (ECM or NCM).
    pub protocol: CdcProtocol,
    /// `bInterfaceNumber` of the CDC Communication interface.
    pub control_interface: u8,
    /// `bInterfaceNumber` of the CDC Data interface.
    pub data_interface: u8,
    /// `bAlternateSetting` of the Data interface that carries bulk endpoints.
    pub data_alt_setting: u8,
    /// Interrupt IN endpoint on the Communication interface.
    pub interrupt_ep: EndpointInfo,
    /// Bulk IN endpoint on the Data interface.
    pub bulk_in_ep: EndpointInfo,
    /// Bulk OUT endpoint on the Data interface.
    pub bulk_out_ep: EndpointInfo,
    /// `iMACAddress` string index from the Ethernet functional descriptor.
    pub mac_string_index: u8,
    /// `wMaxSegmentSize` from the Ethernet functional descriptor (ECM only; 0 for NCM).
    pub max_segment_size: u16,
    /// `dwNtbInMaxSize` from the NCM functional descriptor (NCM only; 0 for ECM).
    pub max_ntb_size: u32,
    /// `bConfigurationValue` from the config descriptor header.
    pub config_value: u8,
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse a USB configuration descriptor byte stream to find a CDC ECM/NCM interface.
///
/// Returns `Ok(None)` if no CDC Communication interface is found (not an error —
/// the device simply does not implement CDC ECM/NCM).  Returns `Err(CdcError)` if
/// a CDC interface is found but the descriptor stream is malformed.
///
/// # Errors
///
/// - [`CdcError::DescriptorTooShort`] — fewer than 9 bytes or a descriptor's
///   `bLength` field points past the end of the buffer.
/// - [`CdcError::MissingFunctionalDescriptor`] — the Header or Union functional
///   descriptor was absent from the Communication interface.
/// - [`CdcError::MissingEndpoint`] — the interrupt IN, bulk IN, or bulk OUT
///   endpoint could not be found.
pub fn parse_cdc_config(config_desc: &[u8]) -> Result<Option<CdcDescriptors>, CdcError> {
    // A configuration descriptor is at least 9 bytes.
    if config_desc.len() < 9 {
        return Err(CdcError::DescriptorTooShort);
    }

    // Validate the outer config descriptor type.
    let config_value = config_desc[5]; // bConfigurationValue

    // ── First pass: find a CDC Communication interface ────────────────────────
    // Walk all descriptors; when we find an Interface descriptor with
    // class=0x02 and subclass ECM or NCM, we enter CDC parsing mode.

    let mut pos: usize = 0;

    // State accumulated during the walk.
    let mut protocol: Option<CdcProtocol> = None;
    let mut control_interface: u8 = 0;
    let mut data_interface: u8 = 0;
    let mut data_interface_known = false;
    let mut mac_string_index: u8 = 0;
    let mut max_segment_size: u16 = 0;
    let mut max_ntb_size: u32 = 0;
    let mut interrupt_ep: Option<EndpointInfo> = None;
    let mut bulk_in_ep: Option<EndpointInfo> = None;
    let mut bulk_out_ep: Option<EndpointInfo> = None;
    let mut data_alt_setting: u8 = 0;
    let mut header_fd_found = false;
    let mut union_fd_found = false;

    // Tracks whether we are inside a CDC Control interface block.
    let mut in_cdc_control = false;
    // Tracks whether we are inside the CDC Data interface (alt > 0).
    let mut in_data_interface = false;

    while pos < config_desc.len() {
        // Every descriptor starts with bLength, bDescriptorType.
        if pos + 2 > config_desc.len() {
            break; // trailing garbage — stop gracefully
        }

        let b_length = config_desc[pos] as usize;
        let b_type = config_desc[pos + 1];

        if b_length < 2 {
            break; // malformed length — stop
        }

        if pos + b_length > config_desc.len() {
            // Only error if we are already inside a CDC section.
            if protocol.is_some() {
                return Err(CdcError::DescriptorTooShort);
            }
            break;
        }

        let desc = &config_desc[pos..pos + b_length];

        match b_type {
            USB_DESC_CONFIGURATION => {
                // Already captured config_value above; nothing more to do.
            }

            USB_DESC_INTERFACE => {
                // Interface descriptor layout (9 bytes minimum):
                // [0] bLength, [1] bDescriptorType, [2] bInterfaceNumber,
                // [3] bAlternateSetting, [4] bNumEndpoints, [5] bInterfaceClass,
                // [6] bInterfaceSubClass, [7] bInterfaceProtocol, [8] iInterface
                if desc.len() < 9 {
                    if protocol.is_some() {
                        return Err(CdcError::DescriptorTooShort);
                    }
                    pos += b_length;
                    continue;
                }

                let if_number = desc[2];
                let alt_setting = desc[3];
                let if_class = desc[5];
                let if_subclass = desc[6];

                // Reset context flags on every new interface.
                in_cdc_control = false;
                in_data_interface = false;

                if if_class == CDC_INTERFACE_CLASS && protocol.is_none() {
                    match if_subclass {
                        CDC_SUBCLASS_ECM => {
                            protocol = Some(CdcProtocol::Ecm);
                            control_interface = if_number;
                            in_cdc_control = true;
                        }
                        CDC_SUBCLASS_NCM => {
                            protocol = Some(CdcProtocol::Ncm);
                            control_interface = if_number;
                            in_cdc_control = true;
                        }
                        _ => {}
                    }
                } else if if_class == CDC_DATA_INTERFACE_CLASS && data_interface_known {
                    // We're inside the data interface from the Union FD.
                    if if_number == data_interface && alt_setting > 0 {
                        in_data_interface = true;
                        data_alt_setting = alt_setting;
                    }
                }
            }

            USB_DESC_CS_INTERFACE if in_cdc_control => {
                // Class-specific (functional) interface descriptor.
                // Layout: [0] bLength, [1] 0x24, [2] bDescriptorSubType, [3..] data
                if desc.len() < 3 {
                    return Err(CdcError::DescriptorTooShort);
                }
                let subtype = desc[2];

                match subtype {
                    CDC_FUNC_HEADER => {
                        // Header FD: [0..2] std, [2] subtype, [3..4] bcdCDC
                        header_fd_found = true;
                    }
                    CDC_FUNC_UNION => {
                        // Union FD: [3] bControlInterface, [4] bSubordinateInterface0
                        if desc.len() < 5 {
                            return Err(CdcError::DescriptorTooShort);
                        }
                        data_interface = desc[4];
                        data_interface_known = true;
                        union_fd_found = true;
                    }
                    CDC_FUNC_ETHERNET => {
                        // Ethernet FD (ECM): 13 bytes.
                        // [0] bLength, [1] 0x24, [2] subtype, [3] iMACAddress,
                        // [4..7] bmEthernetStatistics (4 bytes LE),
                        // [8..9] wMaxSegmentSize (LE), [10..11] wNumberMCFilters,
                        // [12] bNumberPowerFilters
                        if desc.len() < 13 {
                            return Err(CdcError::DescriptorTooShort);
                        }
                        mac_string_index = desc[3];
                        max_segment_size = u16::from_le_bytes([desc[8], desc[9]]);
                    }
                    CDC_FUNC_NCM => {
                        // NCM FD: 6 bytes.
                        // [3..4] bcdNcmVersion, [5] bmNetworkCapabilities
                        // dwNtbInMaxSize comes from the NTB Parameters descriptor,
                        // not here — we set a sensible default.
                        if desc.len() < 6 {
                            return Err(CdcError::DescriptorTooShort);
                        }
                        // Default NTB size; real value comes from GET_NTB_PARAMETERS.
                        max_ntb_size = 16384;
                    }
                    _ => {} // ignore other functional descriptors
                }
            }

            USB_DESC_ENDPOINT => {
                // Endpoint descriptor: 7 bytes minimum.
                // [2] bEndpointAddress, [3] bmAttributes, [4..5] wMaxPacketSize (LE)
                if desc.len() < 7 {
                    if protocol.is_some() {
                        return Err(CdcError::DescriptorTooShort);
                    }
                    pos += b_length;
                    continue;
                }

                let addr = desc[2];
                let attrs = desc[3] & 0x03; // transfer type bits
                let mps = u16::from_le_bytes([desc[4], desc[5]]);

                if in_cdc_control && attrs == 0x03 {
                    // Interrupt endpoint on the control interface.
                    interrupt_ep = Some(EndpointInfo {
                        address: addr,
                        max_packet_size: mps,
                    });
                } else if in_data_interface && attrs == 0x02 {
                    if addr & 0x80 != 0 {
                        // IN endpoint (host ← device).
                        bulk_in_ep = Some(EndpointInfo {
                            address: addr,
                            max_packet_size: mps,
                        });
                    } else {
                        // OUT endpoint (host → device).
                        bulk_out_ep = Some(EndpointInfo {
                            address: addr,
                            max_packet_size: mps,
                        });
                    }
                }
            }

            _ => {} // skip unknown descriptor types
        }

        pos += b_length;
    }

    // No CDC interface found — not an error.
    let protocol = match protocol {
        None => return Ok(None),
        Some(p) => p,
    };

    // Validate required functional descriptors.
    if !header_fd_found || !union_fd_found {
        return Err(CdcError::MissingFunctionalDescriptor);
    }

    // Validate required endpoints.
    let interrupt_ep = interrupt_ep.ok_or(CdcError::MissingEndpoint)?;
    let bulk_in_ep = bulk_in_ep.ok_or(CdcError::MissingEndpoint)?;
    let bulk_out_ep = bulk_out_ep.ok_or(CdcError::MissingEndpoint)?;

    Ok(Some(CdcDescriptors {
        protocol,
        control_interface,
        data_interface,
        data_alt_setting,
        interrupt_ep,
        bulk_in_ep,
        bulk_out_ep,
        mac_string_index,
        max_segment_size,
        max_ntb_size,
        config_value,
    }))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Build a minimal ECM configuration descriptor (80 bytes).
    ///
    /// Layout:
    /// Config (9) + Comm Interface (9) + Header FD (5) + Union FD (5) +
    /// Ethernet FD (13) + Interrupt EP (7) + Data Interface alt0 (9) +
    /// Data Interface alt1 (9) + Bulk IN EP (7) + Bulk OUT EP (7) = 80 bytes
    pub fn build_ecm_config_desc() -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec::Vec::new();

        // ── Configuration descriptor (9 bytes) ──────────────────────────────
        // wTotalLength = 80 = 0x50
        v.extend_from_slice(&[
            9,    // bLength
            0x02, // bDescriptorType: CONFIGURATION
            80,   // wTotalLength low
            0x00, // wTotalLength high
            2,    // bNumInterfaces
            1,    // bConfigurationValue
            0,    // iConfiguration
            0xC0, // bmAttributes
            50,   // bMaxPower (100 mA)
        ]);

        // ── Comm Interface (9 bytes) — interface 0, alt 0 ───────────────────
        v.extend_from_slice(&[
            9,    // bLength
            0x04, // bDescriptorType: INTERFACE
            0,    // bInterfaceNumber (control)
            0,    // bAlternateSetting
            1,    // bNumEndpoints
            0x02, // bInterfaceClass: CDC
            0x06, // bInterfaceSubClass: ECM
            0x00, // bInterfaceProtocol
            0,    // iInterface
        ]);

        // ── Header Functional Descriptor (5 bytes) ───────────────────────────
        v.extend_from_slice(&[
            5,    // bLength
            0x24, // bDescriptorType: CS_INTERFACE
            0x00, // bDescriptorSubType: Header
            0x10, // bcdCDC low (CDC 1.10)
            0x01, // bcdCDC high
        ]);

        // ── Union Functional Descriptor (5 bytes) ────────────────────────────
        v.extend_from_slice(&[
            5,    // bLength
            0x24, // bDescriptorType: CS_INTERFACE
            0x06, // bDescriptorSubType: Union
            0,    // bControlInterface
            1,    // bSubordinateInterface0 (data interface)
        ]);

        // ── Ethernet Functional Descriptor (13 bytes) ───────────────────────
        // mac_string_index = 3, max_segment_size = 1514 = 0x05EA
        v.extend_from_slice(&[
            13,   // bLength
            0x24, // bDescriptorType: CS_INTERFACE
            0x0F, // bDescriptorSubType: Ethernet Networking
            3,    // iMACAddress (string index)
            0x00, // bmEthernetStatistics[0]
            0x00, // bmEthernetStatistics[1]
            0x00, // bmEthernetStatistics[2]
            0x00, // bmEthernetStatistics[3]
            0xEA, // wMaxSegmentSize low  (1514 = 0x05EA)
            0x05, // wMaxSegmentSize high
            0x00, // wNumberMCFilters low
            0x00, // wNumberMCFilters high
            0,    // bNumberPowerFilters
        ]);

        // ── Interrupt IN Endpoint (7 bytes) ──────────────────────────────────
        // address=0x83, attrs=0x03 (interrupt), mps=16
        v.extend_from_slice(&[
            7,    // bLength
            0x05, // bDescriptorType: ENDPOINT
            0x83, // bEndpointAddress: IN, EP 3
            0x03, // bmAttributes: Interrupt
            16,   // wMaxPacketSize low
            0x00, // wMaxPacketSize high
            11,   // bInterval
        ]);

        // ── Data Interface alt 0 (9 bytes, 0 endpoints) ──────────────────────
        v.extend_from_slice(&[
            9,    // bLength
            0x04, // bDescriptorType: INTERFACE
            1,    // bInterfaceNumber (data)
            0,    // bAlternateSetting = 0
            0,    // bNumEndpoints = 0 (no endpoints in alt 0)
            0x0A, // bInterfaceClass: CDC Data
            0x00, // bInterfaceSubClass
            0x00, // bInterfaceProtocol
            0,    // iInterface
        ]);

        // ── Data Interface alt 1 (9 bytes, 2 endpoints) ──────────────────────
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

        // ── Bulk IN Endpoint (7 bytes) ────────────────────────────────────────
        // address=0x81, attrs=0x02 (bulk), mps=512
        v.extend_from_slice(&[
            7,    // bLength
            0x05, // bDescriptorType: ENDPOINT
            0x81, // bEndpointAddress: IN, EP 1
            0x02, // bmAttributes: Bulk
            0x00, // wMaxPacketSize low (512 = 0x0200)
            0x02, // wMaxPacketSize high
            0,    // bInterval
        ]);

        // ── Bulk OUT Endpoint (7 bytes) ───────────────────────────────────────
        // address=0x02, attrs=0x02 (bulk), mps=512
        v.extend_from_slice(&[
            7,    // bLength
            0x05, // bDescriptorType: ENDPOINT
            0x02, // bEndpointAddress: OUT, EP 2
            0x02, // bmAttributes: Bulk
            0x00, // wMaxPacketSize low (512 = 0x0200)
            0x02, // wMaxPacketSize high
            0,    // bInterval
        ]);

        assert_eq!(v.len(), 80, "ECM descriptor must be 80 bytes");
        v
    }

    /// Build a minimal NCM configuration descriptor (73 bytes).
    ///
    /// Similar to ECM but uses CDC_SUBCLASS_NCM and an NCM FD (6 bytes)
    /// instead of the 13-byte Ethernet FD.  No mac_string_index or
    /// max_segment_size (those are zero for NCM).
    pub fn build_ncm_config_desc() -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec::Vec::new();

        // ── Configuration descriptor (9 bytes) ──────────────────────────────
        // wTotalLength = 73 = 0x49
        v.extend_from_slice(&[
            9,    // bLength
            0x02, // bDescriptorType: CONFIGURATION
            73,   // wTotalLength low
            0x00, // wTotalLength high
            2,    // bNumInterfaces
            1,    // bConfigurationValue
            0,    // iConfiguration
            0xC0, // bmAttributes
            50,   // bMaxPower
        ]);

        // ── Comm Interface (9 bytes) — interface 0, alt 0 ───────────────────
        v.extend_from_slice(&[
            9,    // bLength
            0x04, // bDescriptorType: INTERFACE
            0,    // bInterfaceNumber (control)
            0,    // bAlternateSetting
            1,    // bNumEndpoints
            0x02, // bInterfaceClass: CDC
            0x0D, // bInterfaceSubClass: NCM
            0x00, // bInterfaceProtocol
            0,    // iInterface
        ]);

        // ── Header Functional Descriptor (5 bytes) ───────────────────────────
        v.extend_from_slice(&[
            5,    // bLength
            0x24, // bDescriptorType: CS_INTERFACE
            0x00, // bDescriptorSubType: Header
            0x10, // bcdCDC low
            0x01, // bcdCDC high
        ]);

        // ── Union Functional Descriptor (5 bytes) ────────────────────────────
        v.extend_from_slice(&[
            5,    // bLength
            0x24, // bDescriptorType: CS_INTERFACE
            0x06, // bDescriptorSubType: Union
            0,    // bControlInterface
            1,    // bSubordinateInterface0 (data interface)
        ]);

        // ── NCM Functional Descriptor (6 bytes) ──────────────────────────────
        v.extend_from_slice(&[
            6,    // bLength
            0x24, // bDescriptorType: CS_INTERFACE
            0x1A, // bDescriptorSubType: NCM
            0x00, // bcdNcmVersion low
            0x01, // bcdNcmVersion high
            0x00, // bmNetworkCapabilities
        ]);

        // ── Interrupt IN Endpoint (7 bytes) ──────────────────────────────────
        v.extend_from_slice(&[
            7,    // bLength
            0x05, // bDescriptorType: ENDPOINT
            0x83, // bEndpointAddress: IN, EP 3
            0x03, // bmAttributes: Interrupt
            16,   // wMaxPacketSize low
            0x00, // wMaxPacketSize high
            11,   // bInterval
        ]);

        // ── Data Interface alt 0 (9 bytes) ───────────────────────────────────
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

        // ── Data Interface alt 1 (9 bytes) ───────────────────────────────────
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

        // ── Bulk IN Endpoint (7 bytes) ────────────────────────────────────────
        v.extend_from_slice(&[
            7,    // bLength
            0x05, // bDescriptorType: ENDPOINT
            0x81, // bEndpointAddress: IN, EP 1
            0x02, // bmAttributes: Bulk
            0x00, // wMaxPacketSize low (512)
            0x02, // wMaxPacketSize high
            0,    // bInterval
        ]);

        // ── Bulk OUT Endpoint (7 bytes) ───────────────────────────────────────
        v.extend_from_slice(&[
            7,    // bLength
            0x05, // bDescriptorType: ENDPOINT
            0x02, // bEndpointAddress: OUT, EP 2
            0x02, // bmAttributes: Bulk
            0x00, // wMaxPacketSize low (512)
            0x02, // wMaxPacketSize high
            0,    // bInterval
        ]);

        assert_eq!(v.len(), 73, "NCM descriptor must be 73 bytes");
        v
    }

    #[test]
    fn parse_ecm_config() {
        let desc = build_ecm_config_desc();
        let result = parse_cdc_config(&desc).expect("parse must not fail");
        let info = result.expect("must find CDC ECM interface");

        assert_eq!(info.protocol, CdcProtocol::Ecm);
        assert_eq!(info.control_interface, 0);
        assert_eq!(info.data_interface, 1);
        assert_eq!(info.data_alt_setting, 1);
        assert_eq!(
            info.interrupt_ep,
            EndpointInfo {
                address: 0x83,
                max_packet_size: 16,
            }
        );
        assert_eq!(
            info.bulk_in_ep,
            EndpointInfo {
                address: 0x81,
                max_packet_size: 512,
            }
        );
        assert_eq!(
            info.bulk_out_ep,
            EndpointInfo {
                address: 0x02,
                max_packet_size: 512,
            }
        );
        assert_eq!(info.mac_string_index, 3);
        assert_eq!(info.max_segment_size, 1514);
        assert_eq!(info.max_ntb_size, 0);
        assert_eq!(info.config_value, 1);
    }

    #[test]
    fn parse_ncm_config() {
        let desc = build_ncm_config_desc();
        let result = parse_cdc_config(&desc).expect("parse must not fail");
        let info = result.expect("must find CDC NCM interface");

        assert_eq!(info.protocol, CdcProtocol::Ncm);
        assert_eq!(info.control_interface, 0);
        assert_eq!(info.data_interface, 1);
        assert_eq!(info.data_alt_setting, 1);
        assert_eq!(
            info.interrupt_ep,
            EndpointInfo {
                address: 0x83,
                max_packet_size: 16,
            }
        );
        assert_eq!(
            info.bulk_in_ep,
            EndpointInfo {
                address: 0x81,
                max_packet_size: 512,
            }
        );
        assert_eq!(
            info.bulk_out_ep,
            EndpointInfo {
                address: 0x02,
                max_packet_size: 512,
            }
        );
        // NCM FD sets a default max_ntb_size
        assert!(info.max_ntb_size > 0);
        assert_eq!(info.config_value, 1);
    }

    #[test]
    fn parse_no_cdc_interface() {
        // A HID class configuration — no CDC Communication interface.
        let desc = &[
            9,    // bLength
            0x02, // bDescriptorType: CONFIGURATION
            25,   // wTotalLength low
            0x00, // wTotalLength high
            1,    // bNumInterfaces
            1,    // bConfigurationValue
            0,    // iConfiguration
            0x80, // bmAttributes
            50,   // bMaxPower
            // Interface: class 0x03 (HID)
            9,    // bLength
            0x04, // bDescriptorType: INTERFACE
            0,    // bInterfaceNumber
            0,    // bAlternateSetting
            1,    // bNumEndpoints
            0x03, // bInterfaceClass: HID
            0x01, // bInterfaceSubClass: Boot
            0x01, // bInterfaceProtocol: Keyboard
            0,    // iInterface
            // One interrupt endpoint
            7,    // bLength
            0x05, // bDescriptorType: ENDPOINT
            0x81, // bEndpointAddress: IN, EP 1
            0x03, // bmAttributes: Interrupt
            8,    // wMaxPacketSize low
            0x00, // wMaxPacketSize high
            10,   // bInterval
        ];
        let result = parse_cdc_config(desc).expect("parse must not fail");
        assert!(result.is_none(), "HID config must return None");
    }

    #[test]
    fn parse_too_short() {
        let desc = &[0x09, 0x02, 0x12, 0x00, 0x01, 0x01, 0x00]; // only 7 bytes
        assert_eq!(parse_cdc_config(desc), Err(CdcError::DescriptorTooShort));
    }

    #[test]
    fn parse_missing_header_fd() {
        // ECM descriptor without the Header FD.
        let mut desc = build_ecm_config_desc();

        // Locate and remove the Header FD (5 bytes: 05 24 00 10 01).
        // In our layout the Header FD starts right after the Comm Interface (at offset 18).
        // Splice it out and patch wTotalLength.
        let header_fd_offset = 18usize;
        let header_fd_len = 5usize;
        desc.drain(header_fd_offset..header_fd_offset + header_fd_len);

        // Patch wTotalLength (bytes 2-3 LE).
        let new_total = desc.len() as u16;
        desc[2] = (new_total & 0xFF) as u8;
        desc[3] = (new_total >> 8) as u8;

        assert_eq!(
            parse_cdc_config(&desc),
            Err(CdcError::MissingFunctionalDescriptor)
        );
    }

    #[test]
    fn parse_missing_bulk_endpoints() {
        // ECM descriptor without the alt-1 data interface entry (and its endpoints),
        // so the bulk IN/OUT endpoints are never found.
        let mut desc = build_ecm_config_desc();

        // The alt-1 data interface + 2 bulk endpoints = 9 + 7 + 7 = 23 bytes at the end.
        let trim_len = 9 + 7 + 7;
        let new_len = desc.len() - trim_len;
        desc.truncate(new_len);

        // Also remove the alt-0 data interface (9 bytes) since it has no endpoints either.
        // Actually, leave alt-0 in — the parser needs data_interface from the Union FD.
        // Patch wTotalLength.
        let new_total = desc.len() as u16;
        desc[2] = (new_total & 0xFF) as u8;
        desc[3] = (new_total >> 8) as u8;

        assert_eq!(parse_cdc_config(&desc), Err(CdcError::MissingEndpoint));
    }

    #[test]
    fn parse_multi_cdc_uses_first() {
        // Build a config descriptor with two CDC interfaces: ECM then NCM.
        // The parser should lock in the first (ECM) and ignore the second.
        let ecm = build_ecm_config_desc();
        let ncm = build_ncm_config_desc();

        // Combine: ECM config header + ECM body + NCM body (skip NCM's config header).
        let mut combined = ecm.clone();
        combined.extend_from_slice(&ncm[9..]); // skip NCM's 9-byte config header

        // Patch wTotalLength and bNumInterfaces.
        let total = combined.len() as u16;
        combined[2] = (total & 0xFF) as u8;
        combined[3] = (total >> 8) as u8;
        combined[4] = 4; // 4 interfaces total

        let info = parse_cdc_config(&combined)
            .expect("parse must not fail")
            .expect("must find CDC interface");

        // First CDC interface (ECM) wins.
        assert_eq!(info.protocol, CdcProtocol::Ecm);
    }
}
