// SPDX-License-Identifier: GPL-2.0-or-later

//! xHCI device context builders and USB descriptor parsing.
//!
//! Pure functions that construct byte arrays for xHCI Input Contexts
//! and parse USB standard descriptors. No driver state needed.

use super::trb;
use super::types::{
    ConfigDescriptor, ConfigurationTree, DeviceDescriptor, EndpointDescriptor, InterfaceDescriptor,
    UsbSpeed, XhciError,
};

extern crate alloc;

/// Return the default EP0 max packet size for a given link speed.
pub fn max_packet_size_for_speed(speed: UsbSpeed) -> u16 {
    match speed {
        UsbSpeed::LowSpeed => 8,
        UsbSpeed::FullSpeed => 8, // safe default; update from bMaxPacketSize0 after GET_DESCRIPTOR
        UsbSpeed::HighSpeed => 64,
        UsbSpeed::SuperSpeed | UsbSpeed::SuperSpeedPlus => 512,
        UsbSpeed::Unknown(_) => 8, // safe minimum
    }
}

/// Speed enum to xHCI speed ID for Slot Context.
fn speed_to_id(speed: UsbSpeed) -> u8 {
    match speed {
        UsbSpeed::FullSpeed => 1,
        UsbSpeed::LowSpeed => 2,
        UsbSpeed::HighSpeed => 3,
        UsbSpeed::SuperSpeed => 4,
        UsbSpeed::SuperSpeedPlus => 5,
        UsbSpeed::Unknown(id) => id,
    }
}

/// Build a 96-byte Input Context for Address Device.
///
/// Layout: Input Control Context (32B) + Slot Context (32B) + EP0 Context (32B).
/// Assumes 32-byte contexts (CSZ=0, RPi5 BCM2712).
pub fn build_input_context(port: u8, speed: UsbSpeed, transfer_ring_phys: u64) -> [u8; 96] {
    let mut ctx = [0u8; 96];

    // ── Input Control Context (bytes 0..31) ──────────────────────
    // DWord 1 (offset 4): Add Context Flags = 0x03 (Slot + EP0)
    ctx[4..8].copy_from_slice(&0x03u32.to_le_bytes());

    // ── Slot Context (bytes 32..63) ──────────────────────────────
    // DWord 0: Context Entries=1 (bits 31:27), Speed (bits 23:20), Route String=0
    let context_entries: u32 = 1 << 27;
    let speed_field: u32 = (speed_to_id(speed) as u32) << 20;
    let slot_dw0 = context_entries | speed_field;
    ctx[32..36].copy_from_slice(&slot_dw0.to_le_bytes());

    // DWord 1: Root Hub Port Number (bits 23:16)
    let slot_dw1: u32 = (port as u32) << 16;
    ctx[36..40].copy_from_slice(&slot_dw1.to_le_bytes());

    // ── Endpoint 0 Context (bytes 64..95) ────────────────────────
    // DWord 1: CErr=3 (bits 2:1), EP Type=4 (Control Bidir, bits 5:3), Max Packet Size (bits 31:16)
    // CErr=3: retry up to 3 times on USB bus errors before reporting failure.
    // CErr=0 would cause infinite retries, hanging the controller.
    let cerr: u32 = 3 << 1;
    let ep_type: u32 = 4 << 3;
    let mps: u32 = (max_packet_size_for_speed(speed) as u32) << 16;
    let ep_dw1 = cerr | ep_type | mps;
    ctx[68..72].copy_from_slice(&ep_dw1.to_le_bytes());

    // DWord 2-3: TR Dequeue Pointer (64-bit) | DCS=1
    // Bits 3:1 are RsvdP — pointer must be 16-byte aligned (xHCI §6.2.3).
    debug_assert!(
        transfer_ring_phys & 0xF == 0,
        "TR Dequeue Pointer must be 16-byte aligned, got {:#x}",
        transfer_ring_phys
    );
    let tr_ptr = transfer_ring_phys | 1; // DCS (Dequeue Cycle State) = 1
    ctx[72..76].copy_from_slice(&(tr_ptr as u32).to_le_bytes());
    ctx[76..80].copy_from_slice(&((tr_ptr >> 32) as u32).to_le_bytes());

    // DWord 4: Average TRB Length = 8 (bits 15:0)
    ctx[80..84].copy_from_slice(&8u32.to_le_bytes());

    ctx
}

/// Build an 8-byte USB SETUP packet for GET_DESCRIPTOR.
pub fn get_descriptor_setup_packet(desc_type: u8, desc_index: u8, length: u16) -> [u8; 8] {
    let mut pkt = [0u8; 8];
    pkt[0] = 0x80; // bmRequestType: device-to-host, standard, device
    pkt[1] = trb::USB_REQ_GET_DESCRIPTOR;
    let wvalue = ((desc_type as u16) << 8) | (desc_index as u16);
    pkt[2..4].copy_from_slice(&wvalue.to_le_bytes());
    // wIndex = 0 (bytes 4..6, already zero)
    pkt[6..8].copy_from_slice(&length.to_le_bytes());
    pkt
}

/// Parse an 18-byte USB Device Descriptor.
pub fn parse_device_descriptor(data: &[u8]) -> Result<DeviceDescriptor, XhciError> {
    if data.len() < trb::USB_DEVICE_DESCRIPTOR_SIZE as usize {
        return Err(XhciError::InvalidDescriptor);
    }
    if data[0] != trb::USB_DEVICE_DESCRIPTOR_SIZE || data[1] != trb::USB_DESC_DEVICE {
        return Err(XhciError::InvalidDescriptor);
    }
    Ok(DeviceDescriptor {
        usb_version: u16::from_le_bytes([data[2], data[3]]),
        device_class: data[4],
        device_subclass: data[5],
        device_protocol: data[6],
        max_packet_size_ep0: data[7],
        vendor_id: u16::from_le_bytes([data[8], data[9]]),
        product_id: u16::from_le_bytes([data[10], data[11]]),
        device_version: u16::from_le_bytes([data[12], data[13]]),
        // data[14..17] are string descriptor indices — skip
        num_configurations: data[17],
    })
}

/// Parse a 9-byte USB Configuration Descriptor header.
pub fn parse_config_descriptor(data: &[u8]) -> Result<ConfigDescriptor, XhciError> {
    if data.len() < 9 {
        return Err(XhciError::InvalidDescriptor);
    }
    if data[0] != 9 || data[1] != trb::USB_DESC_CONFIGURATION {
        return Err(XhciError::InvalidDescriptor);
    }
    Ok(ConfigDescriptor {
        total_length: u16::from_le_bytes([data[2], data[3]]),
        num_interfaces: data[4],
        config_value: data[5],
        attributes: data[7],
        max_power: data[8],
    })
}

/// Parse a full USB configuration descriptor tree.
pub fn parse_configuration_tree(data: &[u8]) -> Result<ConfigurationTree, XhciError> {
    let config = parse_config_descriptor(data)?;
    let total = config.total_length as usize;
    if total < 9 || data.len() < total {
        return Err(XhciError::InvalidDescriptor);
    }

    let mut interfaces = alloc::vec::Vec::new();
    let mut current_iface: Option<InterfaceDescriptor> = None;
    let mut current_eps = alloc::vec::Vec::new();
    let mut pos = 9; // skip config header

    while pos < total {
        if pos + 1 >= total {
            break;
        }
        let b_length = data[pos] as usize;
        if b_length == 0 {
            return Err(XhciError::InvalidDescriptor);
        }
        if pos + b_length > total {
            break;
        }
        let b_desc_type = data[pos + 1];

        match b_desc_type {
            trb::USB_DESC_INTERFACE if b_length >= 9 => {
                if let Some(iface) = current_iface.take() {
                    interfaces.push((iface, core::mem::take(&mut current_eps)));
                }
                current_iface = Some(InterfaceDescriptor {
                    interface_number: data[pos + 2],
                    alternate_setting: data[pos + 3],
                    num_endpoints: data[pos + 4],
                    interface_class: data[pos + 5],
                    interface_subclass: data[pos + 6],
                    interface_protocol: data[pos + 7],
                });
            }
            trb::USB_DESC_ENDPOINT if b_length >= 7 => {
                current_eps.push(EndpointDescriptor {
                    endpoint_address: data[pos + 2],
                    attributes: data[pos + 3],
                    max_packet_size: u16::from_le_bytes([data[pos + 4], data[pos + 5]]),
                    interval: data[pos + 6],
                });
            }
            _ => {} // skip unknown descriptors
        }
        pos += b_length;
    }
    // Save last interface
    if let Some(iface) = current_iface.take() {
        interfaces.push((iface, current_eps));
    }

    Ok(ConfigurationTree { config, interfaces })
}

/// Convert USB endpoint address byte to xHCI endpoint ID (DCI).
///
/// Formula: `2 * endpoint_number + direction` where direction = 1 for IN, 0 for OUT.
/// EP0 is always DCI 1 (handled separately by address_device).
pub fn endpoint_id_from_address(address: u8) -> u8 {
    let ep_num = address & 0x0F;
    if ep_num == 0 {
        return 1; // EP0 is always DCI 1 (Default Control Endpoint)
    }
    let dir = if address & 0x80 != 0 { 1u8 } else { 0u8 };
    2 * ep_num + dir
}

/// Build an 8-byte SETUP packet for SET_CONFIGURATION (no data stage).
pub fn set_configuration_setup_packet(config_value: u8) -> [u8; 8] {
    let mut pkt = [0u8; 8];
    pkt[0] = 0x00; // bmRequestType: host-to-device, standard, device
    pkt[1] = trb::USB_REQ_SET_CONFIGURATION;
    pkt[2] = config_value; // wValue low byte
                           // pkt[3] = 0 (wValue high byte)
                           // wIndex = 0, wLength = 0 (all zeros already)
    pkt
}

/// Build Input Context for Configure Endpoint command.
///
/// Layout: Input Control Context (32B) + Slot Context (32B) + EP Contexts (32B each).
///
/// Per xHCI §4.6.6, the Slot Context in the Input Context must be a copy
/// of the existing Device Context's Slot Context, with the Context Entries
/// field updated to reflect the new endpoint set. `slot_context` should be
/// the 32-byte Slot Context read from the Output Device Context.
pub fn build_configure_endpoint_input_context(
    slot_context: &[u8],
    endpoints: &[EndpointDescriptor],
    xfer_ring_phys: &[(u8, u64)], // (endpoint_id, ring_phys)
) -> alloc::vec::Vec<u8> {
    // Find max DCI to size the context
    let max_dci = endpoints
        .iter()
        .map(|ep| endpoint_id_from_address(ep.endpoint_address))
        .max()
        .unwrap_or(1);

    // Context size: 32B per entry (Input Control + Slot + EP0..max_dci)
    let num_entries = 2 + max_dci as usize; // Input Control + Slot + endpoints
    let ctx_size = num_entries * 32;
    let mut ctx = alloc::vec![0u8; ctx_size];

    // Input Control Context (bytes 0..31)
    // DWord 1 (offset 4): Add Context Flags — set bit for Slot (0) and each endpoint
    let mut add_flags: u32 = 0x01; // Slot context (bit 0)
    for ep in endpoints {
        let dci = endpoint_id_from_address(ep.endpoint_address);
        add_flags |= 1u32 << dci;
    }
    ctx[4..8].copy_from_slice(&add_flags.to_le_bytes());

    // Slot Context (bytes 32..63) — copy from existing Device Context,
    // then update Context Entries field (xHCI §4.6.6).
    let copy_len = slot_context.len().min(32);
    ctx[32..32 + copy_len].copy_from_slice(&slot_context[..copy_len]);
    // Update DWord 0 bits 31:27 with new Context Entries = max_dci
    let mut slot_dw0 = u32::from_le_bytes(ctx[32..36].try_into().unwrap());
    slot_dw0 = (slot_dw0 & 0x07FF_FFFF) | ((max_dci as u32) << 27);
    ctx[32..36].copy_from_slice(&slot_dw0.to_le_bytes());

    // Endpoint Contexts (each 32 bytes, starting at offset 64)
    // EP context for DCI n starts at byte 32 * (1 + n) from ctx start
    for ep in endpoints {
        let dci = endpoint_id_from_address(ep.endpoint_address);
        let ep_offset = 32 * (1 + dci as usize);
        if ep_offset + 32 > ctx_size {
            continue;
        }

        // Look up the ring phys for this endpoint
        let ring_phys = xfer_ring_phys
            .iter()
            .find(|(id, _)| *id == dci)
            .map(|(_, phys)| *phys)
            .unwrap_or(0);

        // EP Type: bulk OUT = 2, bulk IN = 6 (see xHCI Table 6-9)
        let is_in = ep.endpoint_address & 0x80 != 0;
        let transfer_type = ep.attributes & 0x03;
        let ep_type: u32 = match (transfer_type, is_in) {
            (2, false) => 2, // Bulk OUT
            (2, true) => 6,  // Bulk IN
            (0, _) => 4,     // Control
            (1, false) => 1, // Isoch OUT
            (1, true) => 5,  // Isoch IN
            (3, false) => 3, // Interrupt OUT
            (3, true) => 7,  // Interrupt IN
            _ => 2,          // fallback to Bulk OUT
        };

        // DWord 1: CErr=3, EP Type, Max Packet Size
        let cerr: u32 = 3 << 1;
        let mps: u32 = (ep.max_packet_size as u32) << 16;
        let ep_dw1 = cerr | (ep_type << 3) | mps;
        ctx[ep_offset + 4..ep_offset + 8].copy_from_slice(&ep_dw1.to_le_bytes());

        // DWord 2-3: TR Dequeue Pointer | DCS=1
        let tr_ptr = ring_phys | 1;
        ctx[ep_offset + 8..ep_offset + 12].copy_from_slice(&(tr_ptr as u32).to_le_bytes());
        ctx[ep_offset + 12..ep_offset + 16].copy_from_slice(&((tr_ptr >> 32) as u32).to_le_bytes());

        // DWord 4: Average TRB Length (512 for bulk, 8 for control)
        let avg_trb = if transfer_type == 2 { 512u32 } else { 8u32 };
        ctx[ep_offset + 16..ep_offset + 20].copy_from_slice(&avg_trb.to_le_bytes());
    }

    ctx
}

#[cfg(test)]
mod tests {
    use super::super::trb;
    use super::*;

    #[test]
    fn input_context_add_flags() {
        let ctx = build_input_context(1, UsbSpeed::HighSpeed, 0x5000_0000);
        // Input Control Context DWord 1 (bytes 4..8): Add Context Flags = 0x03
        let flags = u32::from_le_bytes(ctx[4..8].try_into().unwrap());
        assert_eq!(flags, 0x03, "should add Slot (bit 0) + EP0 (bit 1)");
    }

    #[test]
    fn input_context_slot_speed() {
        // HighSpeed = speed ID 3
        let ctx = build_input_context(1, UsbSpeed::HighSpeed, 0x5000_0000);
        // Slot Context DWord 0 (bytes 32..36): speed in bits 23:20
        let dword0 = u32::from_le_bytes(ctx[32..36].try_into().unwrap());
        let speed = (dword0 >> 20) & 0xF;
        assert_eq!(speed, 3, "HighSpeed = speed ID 3");
    }

    #[test]
    fn input_context_slot_port() {
        let ctx = build_input_context(4, UsbSpeed::SuperSpeed, 0x5000_0000);
        // Slot Context DWord 1 (bytes 36..40): port in bits 23:16
        let dword1 = u32::from_le_bytes(ctx[36..40].try_into().unwrap());
        let port = (dword1 >> 16) & 0xFF;
        assert_eq!(port, 4);
    }

    #[test]
    fn input_context_ep0_max_packet_per_speed() {
        for (speed, expected) in [
            (UsbSpeed::LowSpeed, 8u16),
            (UsbSpeed::FullSpeed, 8),
            (UsbSpeed::HighSpeed, 64),
            (UsbSpeed::SuperSpeed, 512),
            (UsbSpeed::SuperSpeedPlus, 512),
            (UsbSpeed::Unknown(0), 8),
        ] {
            let ctx = build_input_context(1, speed, 0x5000_0000);
            // EP0 Context DWord 1 (bytes 68..72): max packet in bits 31:16
            let dword1 = u32::from_le_bytes(ctx[68..72].try_into().unwrap());
            let mps = (dword1 >> 16) & 0xFFFF;
            assert_eq!(
                mps, expected as u32,
                "speed {:?} should have MPS {}",
                speed, expected
            );
        }
    }

    #[test]
    fn input_context_ep0_tr_dequeue_pointer() {
        let ring_phys: u64 = 0x1_2345_6780; // must be 16-byte aligned
        let ctx = build_input_context(1, UsbSpeed::HighSpeed, ring_phys);
        // EP0 Context DWord 2-3 (bytes 72..80): TR Dequeue Pointer | DCS
        let lo = u32::from_le_bytes(ctx[72..76].try_into().unwrap());
        let hi = u32::from_le_bytes(ctx[76..80].try_into().unwrap());
        let ptr = ((hi as u64) << 32) | (lo as u64);
        assert_eq!(ptr, ring_phys | 1, "should set DCS bit (bit 0)");
    }

    #[test]
    fn get_descriptor_setup_packet_layout() {
        let pkt = get_descriptor_setup_packet(trb::USB_DESC_DEVICE, 0, 18);
        assert_eq!(
            pkt[0], 0x80,
            "bmRequestType: device-to-host, standard, device"
        );
        assert_eq!(
            pkt[1],
            trb::USB_REQ_GET_DESCRIPTOR,
            "bRequest: GET_DESCRIPTOR"
        );
        let wvalue = u16::from_le_bytes([pkt[2], pkt[3]]);
        assert_eq!(
            wvalue,
            (trb::USB_DESC_DEVICE as u16) << 8,
            "wValue: descriptor type << 8"
        );
        let windex = u16::from_le_bytes([pkt[4], pkt[5]]);
        assert_eq!(windex, 0, "wIndex: 0");
        let wlength = u16::from_le_bytes([pkt[6], pkt[7]]);
        assert_eq!(wlength, 18, "wLength: 18");
    }

    #[test]
    fn parse_device_descriptor_valid() {
        // Standard 18-byte device descriptor for a hypothetical device
        let data: [u8; 18] = [
            18, // bLength
            1,  // bDescriptorType = Device
            0x00, 0x02, // bcdUSB = 2.00
            0xFF, // bDeviceClass = vendor-specific
            0x01, // bDeviceSubClass
            0x02, // bDeviceProtocol
            64,   // bMaxPacketSize0
            0xAD, 0xDE, // idVendor = 0xDEAD
            0xEF, 0xBE, // idProduct = 0xBEEF
            0x00, 0x01, // bcdDevice = 1.00
            0,    // iManufacturer (string index, ignored)
            0,    // iProduct (string index, ignored)
            0,    // iSerialNumber (string index, ignored)
            2,    // bNumConfigurations
        ];
        let desc = parse_device_descriptor(&data).unwrap();
        assert_eq!(desc.usb_version, 0x0200);
        assert_eq!(desc.device_class, 0xFF);
        assert_eq!(desc.device_subclass, 0x01);
        assert_eq!(desc.device_protocol, 0x02);
        assert_eq!(desc.max_packet_size_ep0, 64);
        assert_eq!(desc.vendor_id, 0xDEAD);
        assert_eq!(desc.product_id, 0xBEEF);
        assert_eq!(desc.device_version, 0x0100);
        assert_eq!(desc.num_configurations, 2);
    }

    #[test]
    fn parse_device_descriptor_too_short() {
        let data = [0u8; 17]; // one byte short
        assert_eq!(
            parse_device_descriptor(&data),
            Err(XhciError::InvalidDescriptor)
        );
    }

    #[test]
    fn parse_device_descriptor_wrong_type() {
        let mut data = [0u8; 18];
        data[0] = 18;
        data[1] = 2; // wrong type (should be 1 = Device)
        assert_eq!(
            parse_device_descriptor(&data),
            Err(XhciError::InvalidDescriptor)
        );
    }

    #[test]
    fn parse_config_descriptor_valid() {
        let data: [u8; 9] = [
            9, // bLength
            2, // bDescriptorType = Configuration
            0x20, 0x00, // wTotalLength = 32
            1,    // bNumInterfaces
            1,    // bConfigurationValue
            0,    // iConfiguration (string index)
            0x80, // bmAttributes (bus-powered)
            50,   // bMaxPower (100mA)
        ];
        let desc = parse_config_descriptor(&data).unwrap();
        assert_eq!(desc.total_length, 32);
        assert_eq!(desc.num_interfaces, 1);
        assert_eq!(desc.config_value, 1);
        assert_eq!(desc.attributes, 0x80);
        assert_eq!(desc.max_power, 50);
    }

    #[test]
    fn parse_config_descriptor_too_short() {
        assert_eq!(
            parse_config_descriptor(&[0u8; 8]),
            Err(XhciError::InvalidDescriptor)
        );
    }

    #[test]
    fn parse_config_descriptor_wrong_type() {
        let mut data = [0u8; 9];
        data[0] = 9;
        data[1] = 1; // Device, not Configuration
        assert_eq!(
            parse_config_descriptor(&data),
            Err(XhciError::InvalidDescriptor)
        );
    }

    #[test]
    fn parse_configuration_tree_valid() {
        // Config(9) + Interface(9) + Endpoint(7) + Endpoint(7) = 32 bytes
        let data: [u8; 32] = [
            // Config descriptor
            9, 2, 32, 0, 1, 1, 0, 0x80, 50, // Interface descriptor
            9, 4, 0, 0, 2, 0x08, 0x06, 0x50, 0, // Endpoint descriptor (bulk OUT 0x02)
            7, 5, 0x02, 0x02, 0x00, 0x02, 0, // Endpoint descriptor (bulk IN 0x82)
            7, 5, 0x82, 0x02, 0x00, 0x02, 0,
        ];
        let tree = parse_configuration_tree(&data).unwrap();
        assert_eq!(tree.config.config_value, 1);
        assert_eq!(tree.interfaces.len(), 1);
        let (iface, eps) = &tree.interfaces[0];
        assert_eq!(iface.interface_class, 0x08); // Mass Storage
        assert_eq!(eps.len(), 2);
        assert_eq!(eps[0].endpoint_address, 0x02); // bulk OUT
        assert_eq!(eps[1].endpoint_address, 0x82); // bulk IN
    }

    #[test]
    fn parse_configuration_tree_zero_blength_guard() {
        let mut data = [0u8; 16];
        data[0] = 9;
        data[1] = 2;
        data[2] = 16; // config header, total=16
                      // byte 9: bLength=0 would cause infinite loop
        assert_eq!(
            parse_configuration_tree(&data),
            Err(XhciError::InvalidDescriptor)
        );
    }

    #[test]
    fn endpoint_id_mapping() {
        assert_eq!(endpoint_id_from_address(0x00), 1); // EP0 → DCI 1
        assert_eq!(endpoint_id_from_address(0x80), 1); // EP0 IN → DCI 1
        assert_eq!(endpoint_id_from_address(0x01), 2); // OUT EP1
        assert_eq!(endpoint_id_from_address(0x81), 3); // IN EP1
        assert_eq!(endpoint_id_from_address(0x02), 4); // OUT EP2
        assert_eq!(endpoint_id_from_address(0x82), 5); // IN EP2
    }

    #[test]
    fn set_configuration_setup_packet_layout() {
        let pkt = set_configuration_setup_packet(1);
        assert_eq!(pkt[0], 0x00, "bmRequestType: host-to-device");
        assert_eq!(pkt[1], trb::USB_REQ_SET_CONFIGURATION);
        assert_eq!(pkt[2], 1, "wValue = config_value");
        assert_eq!(u16::from_le_bytes([pkt[6], pkt[7]]), 0, "wLength = 0");
    }

    #[test]
    fn configure_endpoint_input_context_bulk_pair() {
        use super::super::types::EndpointDescriptor;
        let eps = alloc::vec![
            EndpointDescriptor {
                endpoint_address: 0x02,
                attributes: 0x02,
                max_packet_size: 512,
                interval: 0,
            },
            EndpointDescriptor {
                endpoint_address: 0x82,
                attributes: 0x02,
                max_packet_size: 512,
                interval: 0,
            },
        ];
        let rings = alloc::vec![(4u8, 0xA000_0000u64), (5u8, 0xB000_0000u64)];
        // Fake existing Slot Context: speed=3 (HighSpeed), port=1
        let mut slot_ctx = [0u8; 32];
        let slot_dw0_orig: u32 = (1 << 27) | (3 << 20);
        slot_ctx[0..4].copy_from_slice(&slot_dw0_orig.to_le_bytes());
        slot_ctx[4..8].copy_from_slice(&(1u32 << 16).to_le_bytes());

        let ctx = build_configure_endpoint_input_context(&slot_ctx, &eps, &rings);

        // Add flags: bit 0 (Slot) + bit 4 (EP2 OUT) + bit 5 (EP2 IN)
        let flags = u32::from_le_bytes(ctx[4..8].try_into().unwrap());
        assert_eq!(flags, 0x01 | (1 << 4) | (1 << 5));

        // Slot Context Entries = 5 (max DCI), speed preserved from original
        let slot_dw0 = u32::from_le_bytes(ctx[32..36].try_into().unwrap());
        assert_eq!(
            (slot_dw0 >> 27) & 0x1F,
            5,
            "Context Entries should be max DCI"
        );
        assert_eq!(
            (slot_dw0 >> 20) & 0xF,
            3,
            "Speed should be preserved from original"
        );

        // Slot Context DWord 1: port should be preserved from original
        let slot_dw1 = u32::from_le_bytes(ctx[36..40].try_into().unwrap());
        assert_eq!(
            (slot_dw1 >> 16) & 0xFF,
            1,
            "Port should be preserved from original"
        );
    }
}
