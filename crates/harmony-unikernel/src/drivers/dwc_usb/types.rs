// SPDX-License-Identifier: GPL-2.0-or-later

//! Types for the DWC xHCI USB host controller driver.
//!
//! `XhciError`, `UsbSpeed`, and `PortStatus` — shared across the module.

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
