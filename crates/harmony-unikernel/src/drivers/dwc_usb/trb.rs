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
