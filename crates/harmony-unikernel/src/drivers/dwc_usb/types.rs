// SPDX-License-Identifier: GPL-2.0-or-later

//! Types for the DWC xHCI USB host controller driver.
//!
//! `XhciError`, `UsbSpeed`, `PortStatus`, `XhciAction`, and `XhciEvent` — shared across the module.

use super::trb::Trb;

// ── xHCI speed IDs ───────────────────────────────────────────────
const SPEED_FULL: u8 = 1; // 12 Mbps
const SPEED_LOW: u8 = 2; // 1.5 Mbps
const SPEED_HIGH: u8 = 3; // 480 Mbps
const SPEED_SUPER: u8 = 4; // 5 Gbps
const SPEED_SUPER_PLUS: u8 = 5; // 10 Gbps

// ── Error type ───────────────────────────────────────────────────

/// Errors from xHCI driver operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XhciError {
    /// Controller did not halt (USBSTS.HCH not set) within poll limit.
    HaltTimeout,
    /// Reset did not complete (USBCMD.HCRST not cleared) within poll limit.
    ResetTimeout,
    /// Controller Not Ready (USBSTS.CNR still set) after reset.
    NotReady,
    /// Operation attempted in wrong state.
    InvalidState,
    /// Command ring is full; cannot enqueue new TRB.
    CommandRingFull,
    /// Event TRB has an unrecognized or unsupported type.
    InvalidEvent,
}

// ── USB speed ────────────────────────────────────────────────────

/// USB link speed negotiated on a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbSpeed {
    /// 1.5 Mbps (speed ID 2).
    LowSpeed,
    /// 12 Mbps (speed ID 1).
    FullSpeed,
    /// 480 Mbps (speed ID 3).
    HighSpeed,
    /// 5 Gbps (speed ID 4).
    SuperSpeed,
    /// 10 Gbps (speed ID 5).
    SuperSpeedPlus,
    /// Unrecognized speed ID from hardware.
    Unknown(u8),
}

impl UsbSpeed {
    /// Convert an xHCI port speed ID to a `UsbSpeed` variant.
    pub fn from_id(id: u8) -> Self {
        match id {
            SPEED_FULL => Self::FullSpeed,
            SPEED_LOW => Self::LowSpeed,
            SPEED_HIGH => Self::HighSpeed,
            SPEED_SUPER => Self::SuperSpeed,
            SPEED_SUPER_PLUS => Self::SuperSpeedPlus,
            other => Self::Unknown(other),
        }
    }
}

// ── Port status ──────────────────────────────────────────────────

/// Status of a single USB port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortStatus {
    /// Zero-based port index.
    pub port: u8,
    /// Whether a device is connected (PORTSC.CCS).
    pub connected: bool,
    /// Whether the port is enabled (PORTSC.PED).
    pub enabled: bool,
    /// Negotiated link speed (PORTSC bits 13:10).
    pub speed: UsbSpeed,
}

// ── Driver actions ───────────────────────────────────────────────

/// Actions the driver returns for the caller to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XhciAction {
    /// Write a TRB to DMA memory at the given physical address.
    WriteTrb { phys: u64, trb: Trb },
    /// Ring a doorbell register (pre-computed offset and value).
    RingDoorbell { offset: usize, value: u32 },
    /// Update Event Ring Dequeue Pointer in interrupter register.
    UpdateDequeuePointer { phys: u64 },
    /// Write a 32-bit value to a register (offset from MMIO base).
    WriteRegister { offset: usize, value: u32 },
    /// Write a 64-bit value as LO/HI pair (offset_lo, offset_lo + 4).
    WriteRegister64 { offset_lo: usize, value: u64 },
}

// ── Driver events ────────────────────────────────────────────────

/// Parsed events from the xHCI event ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XhciEvent {
    /// A command completed.
    CommandCompletion { slot_id: u8, completion_code: u8 },
    /// A port status changed (connect/disconnect).
    PortStatusChange { port_id: u8 },
    /// Unrecognized event TRB type.
    Unknown { trb_type: u8 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xhci_action_variants_constructible() {
        let _write = XhciAction::WriteTrb {
            phys: 0x1000,
            trb: super::super::trb::Trb {
                parameter: 0,
                status: 0,
                control: 0,
            },
        };
        let _doorbell = XhciAction::RingDoorbell {
            offset: 0x2000,
            value: 0,
        };
        let _dequeue = XhciAction::UpdateDequeuePointer { phys: 0x3000 };
        let _reg32 = XhciAction::WriteRegister {
            offset: 0x38,
            value: 1,
        };
        let _reg64 = XhciAction::WriteRegister64 {
            offset_lo: 0x30,
            value: 0xDEAD,
        };
    }

    #[test]
    fn xhci_event_variants_constructible() {
        let _cmd = XhciEvent::CommandCompletion {
            slot_id: 1,
            completion_code: 1,
        };
        let _psc = XhciEvent::PortStatusChange { port_id: 3 };
        let _unk = XhciEvent::Unknown { trb_type: 99 };
    }
}
