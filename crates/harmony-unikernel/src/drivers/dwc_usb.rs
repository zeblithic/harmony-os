// SPDX-License-Identifier: GPL-2.0-or-later

//! DWC (DesignWare Core) xHCI USB host controller — register map stub.
//!
//! This module defines register offset constants for the DWC USB
//! controller found on RPi5 (BCM2712). No driver logic is implemented
//! yet — this is a placeholder for a future bead.

#![allow(dead_code)]

// ── Capability registers ──────────────────────────────────────────
// CAPLENGTH (bits [7:0]) and HCIVERSION (bits [31:16]) share a single
// 32-bit dword at offset 0x00.  Extract via:
//   caplength  = (bank.read(CAPLENGTH_HCIVERSION) & 0xFF) as usize;
//   hciversion = (bank.read(CAPLENGTH_HCIVERSION) >> 16) as u16;
const CAPLENGTH_HCIVERSION: usize = 0x00;
const HCSPARAMS1: usize = 0x04;
const HCSPARAMS2: usize = 0x08;
const HCSPARAMS3: usize = 0x0C;
const HCCPARAMS1: usize = 0x10;
const DBOFF: usize = 0x14;
const RTSOFF: usize = 0x18;
const HCCPARAMS2: usize = 0x1C;

// ── Operational registers ─────────────────────────────────────────
// Base address = mmio_base + caplength (read from CAPLENGTH_HCIVERSION & 0xFF).
// All offsets below are relative to that computed operational base.
const USBCMD: usize = 0x00;
const USBSTS: usize = 0x04;
const PAGESIZE: usize = 0x08;
const DNCTRL: usize = 0x14;
const CRCR_LO: usize = 0x18;
const CRCR_HI: usize = 0x1C;
const DCBAAP_LO: usize = 0x30;
const DCBAAP_HI: usize = 0x34;
const CONFIG: usize = 0x38;

// ── USBCMD bits ───────────────────────────────────────────────────
const USBCMD_RUN: u32 = 1 << 0;
const USBCMD_HCRST: u32 = 1 << 1;
const USBCMD_INTE: u32 = 1 << 2;

// ── USBSTS bits ───────────────────────────────────────────────────
const USBSTS_HCH: u32 = 1 << 0; // HC Halted
const USBSTS_CNR: u32 = 1 << 11; // Controller Not Ready

/// Placeholder for the DWC xHCI USB host controller driver.
///
/// Not implemented — register map only. See bead description for
/// future work scope.
pub struct DwcUsbDriver {
    _private: (),
}
