// SPDX-License-Identifier: GPL-2.0-or-later

//! DWC (DesignWare Core) xHCI USB host controller driver.
//!
//! Sans-I/O driver for the xHCI controller on RPi5 (BCM2712).
//! Phase 1: controller init + port detection.
//!
//! All register access goes through the [`RegisterBank`] trait —
//! the driver is a pure state machine with no embedded I/O.

extern crate alloc;
#[allow(unused_imports)] // used by detect_ports in Phase 1 Task 3
use alloc::vec::Vec;

use super::register_bank::RegisterBank;

// ── Capability registers (offset from MMIO base) ─────────────────
const CAPLENGTH_HCIVERSION: usize = 0x00;
const HCSPARAMS1: usize = 0x04;
#[allow(dead_code)] // Phase 2+
const HCSPARAMS2: usize = 0x08;
#[allow(dead_code)]
const HCSPARAMS3: usize = 0x0C;
#[allow(dead_code)]
const HCCPARAMS1: usize = 0x10;
const DBOFF: usize = 0x14;
const RTSOFF: usize = 0x18;
#[allow(dead_code)]
const HCCPARAMS2: usize = 0x1C;

// ── Operational registers (offset from cap_length) ───────────────
const USBCMD: usize = 0x00;
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
const USBCMD_RUN: u32 = 1 << 0;
const USBCMD_HCRST: u32 = 1 << 1;
#[allow(dead_code)]
const USBCMD_INTE: u32 = 1 << 2;

// ── USBSTS bits ──────────────────────────────────────────────────
const USBSTS_HCH: u32 = 1 << 0; // HC Halted
const USBSTS_CNR: u32 = 1 << 11; // Controller Not Ready

// ── PORTSC registers (offset from operational base) ──────────────
/// First PORTSC relative to operational base.
#[allow(dead_code)] // Phase 2+
const PORTSC_BASE: usize = 0x400;
/// Byte spacing between successive PORTSC registers.
#[allow(dead_code)] // Phase 2+
const PORTSC_STRIDE: usize = 0x10;

// ── PORTSC bits ──────────────────────────────────────────────────
#[allow(dead_code)] // Phase 2+
const PORTSC_CCS: u32 = 1 << 0; // Current Connect Status
#[allow(dead_code)] // Phase 2+
const PORTSC_PED: u32 = 1 << 1; // Port Enabled/Disabled
#[allow(dead_code)] // Phase 2+
const PORTSC_SPEED_SHIFT: u32 = 10;
#[allow(dead_code)] // Phase 2+
const PORTSC_SPEED_MASK: u32 = 0xF << PORTSC_SPEED_SHIFT;

// ── xHCI speed IDs ───────────────────────────────────────────────
const SPEED_FULL: u8 = 1; // 12 Mbps
const SPEED_LOW: u8 = 2; // 1.5 Mbps
const SPEED_HIGH: u8 = 3; // 480 Mbps
const SPEED_SUPER: u8 = 4; // 5 Gbps
const SPEED_SUPER_PLUS: u8 = 5; // 10 Gbps

// ── Polling limit ────────────────────────────────────────────────
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

// ── Driver state ─────────────────────────────────────────────────

/// Internal driver state.
#[derive(Debug, Clone, PartialEq, Eq)]
enum XhciState {
    /// Controller halted and reset, ready for port detection.
    Ready,
    /// Unrecoverable error.
    #[allow(dead_code)] // Phase 2+
    Error(XhciError),
}

/// Sans-I/O xHCI USB host controller driver.
///
/// Manages the DesignWare xHCI controller on RPi5. All register access
/// goes through `RegisterBank` methods — no embedded I/O.
///
/// # Lifecycle
///
/// 1. `XhciDriver::init(bank)` — halt, reset, read capabilities → `Ready`
/// 2. `driver.detect_ports(bank)` — scan PORTSC registers → `Vec<PortStatus>`
#[derive(Debug, PartialEq, Eq)]
pub struct XhciDriver {
    /// Number of downstream ports (HCSPARAMS1 bits 31:24).
    max_ports: u8,
    /// Maximum device slots (HCSPARAMS1 bits 7:0).
    max_slots: u8,
    /// Capability register length — offset to operational registers.
    cap_length: usize,
    /// Runtime register offset (RTSOFF, stored for Phase 2+).
    #[allow(dead_code)]
    rts_offset: u32,
    /// Doorbell register offset (DBOFF, stored for Phase 2+).
    #[allow(dead_code)]
    db_offset: u32,
    /// Current driver state.
    state: XhciState,
}

impl XhciDriver {
    /// Initialize the xHCI controller.
    ///
    /// Reads capability registers, halts the controller, performs a
    /// hardware reset, and waits for the controller to become ready.
    /// Returns the driver in `Ready` state, or an error if any step
    /// times out.
    pub fn init(bank: &mut impl RegisterBank) -> Result<Self, XhciError> {
        // 1. Read capability registers.
        let cap_raw = bank.read(CAPLENGTH_HCIVERSION);
        let cap_length = (cap_raw & 0xFF) as usize;

        let hcsparams1 = bank.read(HCSPARAMS1);
        let max_slots = (hcsparams1 & 0xFF) as u8;
        let max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;

        let db_offset = bank.read(DBOFF);
        let rts_offset = bank.read(RTSOFF);

        // 2. Halt the controller: clear RUN, wait for HCH.
        let cmd = bank.read(cap_length + USBCMD);
        bank.write(cap_length + USBCMD, cmd & !USBCMD_RUN);

        let mut halted = false;
        for _ in 0..MAX_POLL_ITERATIONS {
            if bank.read(cap_length + USBSTS) & USBSTS_HCH != 0 {
                halted = true;
                break;
            }
        }
        if !halted {
            return Err(XhciError::HaltTimeout);
        }

        // 3. Reset: set HCRST, wait for self-clear + CNR clear.
        let cmd = bank.read(cap_length + USBCMD);
        bank.write(cap_length + USBCMD, cmd | USBCMD_HCRST);

        let mut reset_done = false;
        for _ in 0..MAX_POLL_ITERATIONS {
            if bank.read(cap_length + USBCMD) & USBCMD_HCRST == 0 {
                reset_done = true;
                break;
            }
        }
        if !reset_done {
            return Err(XhciError::ResetTimeout);
        }

        // Wait for CNR to clear (controller ready).
        let mut ready = false;
        for _ in 0..MAX_POLL_ITERATIONS {
            if bank.read(cap_length + USBSTS) & USBSTS_CNR == 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return Err(XhciError::NotReady);
        }

        Ok(Self {
            max_ports,
            max_slots,
            cap_length,
            rts_offset,
            db_offset,
            state: XhciState::Ready,
        })
    }

    /// Number of downstream USB ports.
    pub fn max_ports(&self) -> u8 {
        self.max_ports
    }

    /// Maximum device slots supported.
    pub fn max_slots(&self) -> u8 {
        self.max_slots
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::register_bank::mock::MockRegisterBank;
    use alloc::vec;

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

    /// Build a mock that passes init: cap_length=0x20, 4 ports, 32 slots,
    /// halts immediately, resets immediately.
    fn mock_init_success() -> MockRegisterBank {
        let mut bank = MockRegisterBank::new();
        // Capability registers
        bank.on_read(CAPLENGTH_HCIVERSION, vec![0x0100_0020]); // hci_ver=1.0, cap_length=0x20
        bank.on_read(HCSPARAMS1, vec![0x0400_0020]); // 4 ports (bits 31:24), 32 slots (bits 7:0)
        bank.on_read(DBOFF, vec![0x1000]);
        bank.on_read(RTSOFF, vec![0x2000]);
        // Operational registers (at cap_length=0x20)
        bank.on_read(0x20 + USBCMD, vec![USBCMD_RUN, 0]); // first read has RUN set, second cleared
        bank.on_read(0x20 + USBSTS, vec![0, USBSTS_HCH, USBSTS_HCH]); // not halted, then halted
                                                                      // After reset: HCRST clears, CNR clears
                                                                      // USBCMD reads after reset write: HCRST set (first poll), then cleared
                                                                      // We need sequential reads that handle both the halt write-back and the reset sequence.
                                                                      // Simplify: after halt, USBCMD reads return 0 (HCRST already cleared), CNR=0.
        bank
    }

    #[test]
    fn init_reads_capability_registers() {
        let mut bank = mock_init_success();
        let driver = XhciDriver::init(&mut bank).unwrap();
        assert_eq!(driver.max_ports(), 4);
        assert_eq!(driver.max_slots(), 32);
    }

    #[test]
    fn init_halts_then_resets() {
        let mut bank = mock_init_success();
        let _driver = XhciDriver::init(&mut bank).unwrap();
        // Verify writes: should have cleared RUN, then set HCRST
        let cmd_writes: Vec<_> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == 0x20 + USBCMD)
            .map(|(_, val)| *val)
            .collect();
        // First write: clear RUN (value should not have RUN bit set)
        assert_eq!(cmd_writes[0] & USBCMD_RUN, 0, "should clear RUN bit");
        // Second write: set HCRST
        assert_ne!(cmd_writes[1] & USBCMD_HCRST, 0, "should set HCRST bit");
    }

    #[test]
    fn init_halt_timeout() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(CAPLENGTH_HCIVERSION, vec![0x20]); // cap_length=0x20
        bank.on_read(HCSPARAMS1, vec![0x0100_0001]);
        bank.on_read(DBOFF, vec![0]);
        bank.on_read(RTSOFF, vec![0]);
        bank.on_read(0x20 + USBCMD, vec![USBCMD_RUN]); // RUN always set (sticky)
        bank.on_read(0x20 + USBSTS, vec![0]); // HCH never set (sticky 0)
        assert_eq!(XhciDriver::init(&mut bank), Err(XhciError::HaltTimeout));
    }

    #[test]
    fn init_reset_timeout() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(CAPLENGTH_HCIVERSION, vec![0x20]);
        bank.on_read(HCSPARAMS1, vec![0x0100_0001]);
        bank.on_read(DBOFF, vec![0]);
        bank.on_read(RTSOFF, vec![0]);
        bank.on_read(
            0x20 + USBCMD,
            vec![
                USBCMD_RUN,   // pre-halt read
                USBCMD_HCRST, // post-reset: HCRST never clears (sticky)
            ],
        );
        bank.on_read(
            0x20 + USBSTS,
            vec![
                0, USBSTS_HCH, // halt succeeds (0 then HCH)
            ],
        );
        assert_eq!(XhciDriver::init(&mut bank), Err(XhciError::ResetTimeout));
    }
}
