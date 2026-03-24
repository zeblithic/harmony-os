// SPDX-License-Identifier: GPL-2.0-or-later

//! DWC (DesignWare Core) xHCI USB host controller driver.
//!
//! Sans-I/O driver for the xHCI controller on RPi5 (BCM2712).
//! Phase 1: controller init + port detection.
//!
//! All register access goes through the [`RegisterBank`] trait —
//! the driver is a pure state machine with no embedded I/O.

extern crate alloc;
use alloc::vec::Vec;

pub mod types;
pub use types::*;

pub mod trb;
pub use trb::*;

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
const PORTSC_BASE: usize = 0x400;
/// Byte spacing between successive PORTSC registers.
const PORTSC_STRIDE: usize = 0x10;

// ── PORTSC bits ──────────────────────────────────────────────────
const PORTSC_CCS: u32 = 1 << 0; // Current Connect Status
const PORTSC_PED: u32 = 1 << 1; // Port Enabled/Disabled
const PORTSC_SPEED_SHIFT: u32 = 10;
const PORTSC_SPEED_MASK: u32 = 0xF << PORTSC_SPEED_SHIFT;

// ── Polling limit ────────────────────────────────────────────────
const MAX_POLL_ITERATIONS: u32 = 1000;

// ── Driver state ─────────────────────────────────────────────────

/// Internal driver state.
#[derive(Debug, Clone, PartialEq, Eq)]
enum XhciState {
    /// Controller halted and reset, ready for port detection.
    Ready,
    /// Unrecoverable error.
    #[allow(dead_code)] // Phase 2+ transitions; Phase 1 tests construct directly
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

    /// Scan all ports and return their status.
    ///
    /// Reads the PORTSC register for each port and reports connection
    /// state, enabled state, and negotiated speed.
    ///
    /// Requires `Ready` state (call `init` first).
    pub fn detect_ports(&self, bank: &impl RegisterBank) -> Result<Vec<PortStatus>, XhciError> {
        if self.state != XhciState::Ready {
            return Err(XhciError::InvalidState);
        }

        let mut ports = Vec::with_capacity(self.max_ports as usize);
        for i in 0..self.max_ports {
            let offset = self.cap_length + PORTSC_BASE + PORTSC_STRIDE * (i as usize);
            let portsc = bank.read(offset);

            let speed_id = ((portsc & PORTSC_SPEED_MASK) >> PORTSC_SPEED_SHIFT) as u8;

            ports.push(PortStatus {
                port: i,
                connected: portsc & PORTSC_CCS != 0,
                enabled: portsc & PORTSC_PED != 0,
                speed: UsbSpeed::from_id(speed_id),
            });
        }

        Ok(ports)
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
        bank.on_read(0x20 + USBCMD, vec![USBCMD_RUN, 0]); // pre-halt: RUN set; pre-reset + poll: 0 (HCRST self-clears)
        bank.on_read(0x20 + USBSTS, vec![0, USBSTS_HCH, 0]); // halt: 0 then HCH; CNR poll: 0 (ready)
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

    /// Build a mock for port detection: 4 ports with specified PORTSC values.
    fn mock_with_ports(cap_length: usize, portsc_values: &[u32]) -> MockRegisterBank {
        let mut bank = mock_init_success();
        for (i, &val) in portsc_values.iter().enumerate() {
            bank.on_read(cap_length + PORTSC_BASE + PORTSC_STRIDE * i, vec![val]);
        }
        bank
    }

    #[test]
    fn detect_ports_empty() {
        let mut bank = mock_with_ports(0x20, &[0, 0, 0, 0]);
        let driver = XhciDriver::init(&mut bank).unwrap();
        let ports = driver.detect_ports(&bank).unwrap();
        assert_eq!(ports.len(), 4);
        assert!(ports.iter().all(|p| !p.connected));
    }

    #[test]
    fn detect_ports_one_usb2_device() {
        // Port 0: CCS=1, PED=1, speed=HighSpeed(3)
        let portsc = PORTSC_CCS | PORTSC_PED | (3 << PORTSC_SPEED_SHIFT);
        let mut bank = mock_with_ports(0x20, &[portsc, 0, 0, 0]);
        let driver = XhciDriver::init(&mut bank).unwrap();
        let ports = driver.detect_ports(&bank).unwrap();
        assert_eq!(ports[0].port, 0);
        assert!(ports[0].connected);
        assert!(ports[0].enabled);
        assert_eq!(ports[0].speed, UsbSpeed::HighSpeed);
        assert!(!ports[1].connected);
    }

    #[test]
    fn detect_ports_mixed_speeds() {
        let fs = PORTSC_CCS | PORTSC_PED | (1 << PORTSC_SPEED_SHIFT); // Full Speed
        let hs = PORTSC_CCS | PORTSC_PED | (3 << PORTSC_SPEED_SHIFT); // High Speed
        let ss = PORTSC_CCS | PORTSC_PED | (4 << PORTSC_SPEED_SHIFT); // SuperSpeed
        let mut bank = mock_with_ports(0x20, &[fs, 0, hs, ss]);
        let driver = XhciDriver::init(&mut bank).unwrap();
        let ports = driver.detect_ports(&bank).unwrap();
        assert_eq!(ports[0].speed, UsbSpeed::FullSpeed);
        assert!(!ports[1].connected);
        assert_eq!(ports[2].speed, UsbSpeed::HighSpeed);
        assert_eq!(ports[3].speed, UsbSpeed::SuperSpeed);
    }

    #[test]
    fn detect_ports_unknown_speed() {
        let portsc = PORTSC_CCS | (15 << PORTSC_SPEED_SHIFT);
        let mut bank = mock_with_ports(0x20, &[portsc, 0, 0, 0]);
        let driver = XhciDriver::init(&mut bank).unwrap();
        let ports = driver.detect_ports(&bank).unwrap();
        assert_eq!(ports[0].speed, UsbSpeed::Unknown(15));
    }

    #[test]
    fn init_not_ready_timeout() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(CAPLENGTH_HCIVERSION, vec![0x20]);
        bank.on_read(HCSPARAMS1, vec![0x0100_0001]);
        bank.on_read(DBOFF, vec![0]);
        bank.on_read(RTSOFF, vec![0]);
        // Halt succeeds, reset completes, but CNR never clears.
        bank.on_read(0x20 + USBCMD, vec![USBCMD_RUN, 0]); // halt ok, HCRST self-clears
        bank.on_read(0x20 + USBSTS, vec![0, USBSTS_HCH, USBSTS_CNR]); // halt ok, then CNR sticky
        assert_eq!(XhciDriver::init(&mut bank), Err(XhciError::NotReady));
    }

    #[test]
    fn detect_ports_in_error_state_fails() {
        // Directly construct a driver in Error state to test the guard.
        let driver = XhciDriver {
            max_ports: 1,
            max_slots: 1,
            cap_length: 0x20,
            rts_offset: 0,
            db_offset: 0,
            state: XhciState::Error(XhciError::HaltTimeout),
        };
        let bank = MockRegisterBank::new();
        assert_eq!(driver.detect_ports(&bank), Err(XhciError::InvalidState));
    }
}
