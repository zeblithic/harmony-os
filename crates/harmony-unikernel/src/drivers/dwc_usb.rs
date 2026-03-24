// SPDX-License-Identifier: GPL-2.0-or-later

//! DWC (DesignWare Core) xHCI USB host controller driver.
//!
//! Sans-I/O driver for the xHCI controller on RPi5 (BCM2712).
//! Phase 1: controller init + port detection.
//!
//! All register access goes through the [`RegisterBank`] trait —
//! the driver is a pure state machine with no embedded I/O.

extern crate alloc;
#[allow(unused_imports)] // used in Phase 2+
use alloc::vec::Vec;

#[allow(unused_imports)] // used in Phase 2+
use super::register_bank::RegisterBank;

// ── Capability registers (offset from MMIO base) ─────────────────
#[allow(dead_code)] // Phase 2+
const CAPLENGTH_HCIVERSION: usize = 0x00;
#[allow(dead_code)]
const HCSPARAMS1: usize = 0x04;
#[allow(dead_code)] // Phase 2+
const HCSPARAMS2: usize = 0x08;
#[allow(dead_code)]
const HCSPARAMS3: usize = 0x0C;
#[allow(dead_code)]
const HCCPARAMS1: usize = 0x10;
#[allow(dead_code)]
const DBOFF: usize = 0x14;
#[allow(dead_code)]
const RTSOFF: usize = 0x18;
#[allow(dead_code)]
const HCCPARAMS2: usize = 0x1C;

// ── Operational registers (offset from cap_length) ───────────────
#[allow(dead_code)]
const USBCMD: usize = 0x00;
#[allow(dead_code)]
const USBSTS: usize = 0x04;
#[allow(dead_code)]
const PAGESIZE: usize = 0x08;
#[allow(dead_code)]
const DNCTRL: usize = 0x14;
#[allow(dead_code)]
const CRCR_LO: usize = 0x18;
#[allow(dead_code)]
const CRCR_HI: usize = 0x1C;
#[allow(dead_code)]
const DCBAAP_LO: usize = 0x30;
#[allow(dead_code)]
const DCBAAP_HI: usize = 0x34;
#[allow(dead_code)]
const CONFIG: usize = 0x38;

// ── USBCMD bits ──────────────────────────────────────────────────
#[allow(dead_code)]
const USBCMD_RUN: u32 = 1 << 0;
#[allow(dead_code)]
const USBCMD_HCRST: u32 = 1 << 1;
#[allow(dead_code)]
const USBCMD_INTE: u32 = 1 << 2;

// ── USBSTS bits ──────────────────────────────────────────────────
#[allow(dead_code)]
const USBSTS_HCH: u32 = 1 << 0; // HC Halted
#[allow(dead_code)]
const USBSTS_CNR: u32 = 1 << 11; // Controller Not Ready

// ── PORTSC registers (offset from operational base) ──────────────
/// First PORTSC relative to operational base.
#[allow(dead_code)]
const PORTSC_BASE: usize = 0x400;
/// Byte spacing between successive PORTSC registers.
#[allow(dead_code)]
const PORTSC_STRIDE: usize = 0x10;

// ── PORTSC bits ──────────────────────────────────────────────────
#[allow(dead_code)]
const PORTSC_CCS: u32 = 1 << 0; // Current Connect Status
#[allow(dead_code)]
const PORTSC_PED: u32 = 1 << 1; // Port Enabled/Disabled
#[allow(dead_code)]
const PORTSC_SPEED_SHIFT: u32 = 10;
#[allow(dead_code)]
const PORTSC_SPEED_MASK: u32 = 0xF << PORTSC_SPEED_SHIFT;

// ── xHCI speed IDs ───────────────────────────────────────────────
const SPEED_FULL: u8 = 1; // 12 Mbps
const SPEED_LOW: u8 = 2; // 1.5 Mbps
const SPEED_HIGH: u8 = 3; // 480 Mbps
const SPEED_SUPER: u8 = 4; // 5 Gbps
const SPEED_SUPER_PLUS: u8 = 5; // 10 Gbps

// ── Polling limit ────────────────────────────────────────────────
#[allow(dead_code)]
const MAX_POLL_ITERATIONS: u32 = 1000;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usb_speed_from_id() {
        assert!(matches!(UsbSpeed::from_id(1), UsbSpeed::FullSpeed));
        assert!(matches!(UsbSpeed::from_id(2), UsbSpeed::LowSpeed));
        assert!(matches!(UsbSpeed::from_id(3), UsbSpeed::HighSpeed));
        assert!(matches!(UsbSpeed::from_id(4), UsbSpeed::SuperSpeed));
        assert!(matches!(UsbSpeed::from_id(5), UsbSpeed::SuperSpeedPlus));
        assert!(matches!(UsbSpeed::from_id(0), UsbSpeed::Unknown(0)));
        assert!(matches!(UsbSpeed::from_id(15), UsbSpeed::Unknown(15)));
    }
}
