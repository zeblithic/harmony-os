// SPDX-License-Identifier: GPL-2.0-or-later

//! xHCI device context builders and USB descriptor parsing.
//!
//! Pure functions that construct byte arrays for xHCI Input Contexts
//! and parse USB standard descriptors. No driver state needed.

use super::trb;
use super::types::{DeviceDescriptor, UsbSpeed, XhciError};

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

#[cfg(test)]
mod tests {
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
}
