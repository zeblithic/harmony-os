// SPDX-License-Identifier: GPL-2.0-or-later

//! xHCI Transfer Request Block (TRB) — the fundamental 16-byte data unit.

// ── TRB type constants ───────────────────────────────────────────

/// Link TRB — wraps ring back to base.
pub const TRB_LINK: u8 = 6;
/// No-Op Command TRB — tests ring machinery.
pub const TRB_NOOP_CMD: u8 = 23;
/// Command Completion Event TRB.
pub const TRB_COMMAND_COMPLETION: u8 = 33;
/// Port Status Change Event TRB.
pub const TRB_PORT_STATUS_CHANGE: u8 = 34;

// ── Command TRB types ────────────────────────────────────────────

/// Enable Slot Command TRB — allocates a device slot.
pub const TRB_ENABLE_SLOT: u8 = 9;
/// Address Device Command TRB — assigns USB address and transitions to Addressed state.
pub const TRB_ADDRESS_DEVICE: u8 = 11;
/// Configure Endpoint Command TRB — sets up non-zero endpoints.
pub const TRB_CONFIGURE_ENDPOINT: u8 = 12;

// ── Transfer TRB types ───────────────────────────────────────────

/// Setup Stage TRB — first TRB in a control transfer (SETUP packet).
pub const TRB_SETUP_STAGE: u8 = 2;
/// Data Stage TRB — optional data phase of a control transfer.
pub const TRB_DATA_STAGE: u8 = 3;
/// Status Stage TRB — final handshake TRB of a control transfer.
pub const TRB_STATUS_STAGE: u8 = 4;

// ── Event TRB types ──────────────────────────────────────────────

/// Transfer Event TRB — signals completion (or error) of a transfer TRB.
pub const TRB_TRANSFER_EVENT: u8 = 32;

// ── Transfer control flags ────────────────────────────────────────

/// Transfer Type IN (bits 17:16 = 11) — control read from device.
pub const TRT_IN: u32 = 3 << 16;
/// Direction IN (bit 16) — Data Stage direction bit for device-to-host.
pub const DIR_IN: u32 = 1 << 16;
/// Immediate Data (bit 6) — TRB data is inline in the parameter field.
pub const IDT: u32 = 1 << 6;
/// Interrupt On Completion (bit 5) — generate Transfer Event on completion.
pub const IOC: u32 = 1 << 5;
/// Interrupt on Short Packet (bit 2) — generate Transfer Event on short packet.
pub const ISP: u32 = 1 << 2;

// ── USB request/descriptor constants ─────────────────────────────

/// GET_DESCRIPTOR standard USB request code (bmRequest=0x80, bRequest=6).
pub const USB_REQ_GET_DESCRIPTOR: u8 = 6;
/// Device Descriptor type (wValue high byte = 1).
pub const USB_DESC_DEVICE: u8 = 1;
/// Size in bytes of the standard USB Device Descriptor (bLength field = 18).
pub const USB_DEVICE_DESCRIPTOR_SIZE: u8 = 18;
/// SET_CONFIGURATION standard USB request code (bRequest = 9).
pub const USB_REQ_SET_CONFIGURATION: u8 = 9;
/// Configuration Descriptor type (wValue high byte = 2).
pub const USB_DESC_CONFIGURATION: u8 = 2;
/// Interface Descriptor type (bDescriptorType = 4).
pub const USB_DESC_INTERFACE: u8 = 4;
/// Endpoint Descriptor type (bDescriptorType = 5).
pub const USB_DESC_ENDPOINT: u8 = 5;
/// Size in bytes of the standard USB Configuration Descriptor header (bLength = 9).
pub const USB_CONFIG_DESCRIPTOR_HEADER_SIZE: u16 = 9;

// ── Completion codes ─────────────────────────────────────────────

pub const COMPLETION_SUCCESS: u8 = 1;
pub const COMPLETION_TRB_ERROR: u8 = 5;
pub const COMPLETION_NO_SLOTS: u8 = 9;

// ── Link TRB control flags ──────────────────────────────────────

/// Toggle Cycle bit in Link TRB (bit 1 of control).
pub const LINK_TOGGLE_CYCLE: u32 = 1 << 1;

// ── Trb struct ───────────────────────────────────────────────────

/// A 16-byte Transfer Request Block — the fundamental xHCI data unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Trb {
    /// Parameter field (TRB-type-specific, 8 bytes).
    pub parameter: u64,
    /// Status field (completion code, transfer length, etc.).
    pub status: u32,
    /// Control field: TRB type (bits 15:10), cycle bit (bit 0), flags.
    pub control: u32,
}

impl Trb {
    /// Extract the TRB type (bits 15:10 of control).
    pub fn trb_type(&self) -> u8 {
        ((self.control >> 10) & 0x3F) as u8
    }

    /// Read the cycle bit (bit 0 of control).
    pub fn cycle_bit(&self) -> bool {
        self.control & 1 != 0
    }

    /// Set or clear the cycle bit (bit 0 of control).
    pub fn set_cycle_bit(&mut self, bit: bool) {
        if bit {
            self.control |= 1;
        } else {
            self.control &= !1;
        }
    }

    /// Deserialize from 16 little-endian bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self {
            parameter: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            status: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            control: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        }
    }

    /// Serialize to 16 little-endian bytes.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&self.parameter.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.status.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.control.to_le_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_to_bytes_round_trip() {
        let trb = Trb {
            parameter: 0xDEAD_BEEF_CAFE_BABE,
            status: 0x1234_5678,
            control: 0xABCD_EF01,
        };
        let bytes = trb.to_bytes();
        let decoded = Trb::from_bytes(bytes);
        assert_eq!(trb, decoded);
    }

    #[test]
    fn trb_type_extraction() {
        // Type field is bits 15:10 of control
        let trb = Trb {
            parameter: 0,
            status: 0,
            control: (TRB_NOOP_CMD as u32) << 10,
        };
        assert_eq!(trb.trb_type(), TRB_NOOP_CMD);
    }

    #[test]
    fn cycle_bit_manipulation() {
        let mut trb = Trb {
            parameter: 0,
            status: 0,
            control: 0,
        };
        assert!(!trb.cycle_bit());
        trb.set_cycle_bit(true);
        assert!(trb.cycle_bit());
        assert_eq!(trb.control & 1, 1);
        trb.set_cycle_bit(false);
        assert!(!trb.cycle_bit());
        assert_eq!(trb.control & 1, 0);
    }

    #[test]
    fn cycle_bit_preserves_other_fields() {
        // Use bits 9:1 (0x03FE) as "other bits" — they don't overlap the type
        // field (bits 15:10) or the cycle bit (bit 0).
        let mut trb = Trb {
            parameter: 0,
            status: 0,
            control: (TRB_NOOP_CMD as u32) << 10 | 0x03FE,
        };
        trb.set_cycle_bit(true);
        assert_eq!(trb.trb_type(), TRB_NOOP_CMD);
        assert_eq!(trb.control & 0x03FE, 0x03FE);
    }

    #[test]
    fn command_completion_field_extraction() {
        // Command Completion Event TRB layout (xHCI Table 6-38):
        // parameter = Command TRB Pointer (64-bit physical address)
        // status bits 31:24 = Completion Code
        // control bits 31:24 = Slot ID, bits 15:10 = TRB Type (33), bit 0 = cycle
        let slot_id: u8 = 5;
        let completion_code: u8 = COMPLETION_SUCCESS;
        let trb = Trb {
            parameter: 0x2000_0000, // command TRB pointer
            status: (completion_code as u32) << 24,
            control: (slot_id as u32) << 24 | (TRB_COMMAND_COMPLETION as u32) << 10 | 1,
        };
        assert_eq!(trb.trb_type(), TRB_COMMAND_COMPLETION);
        assert_eq!((trb.control >> 24) as u8, slot_id);
        assert_eq!((trb.status >> 24) as u8, COMPLETION_SUCCESS);
        assert!(trb.cycle_bit());
    }
}
