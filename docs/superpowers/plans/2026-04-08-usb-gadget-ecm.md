# USB Gadget Mode CDC-ECM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a DWC2 OTG device controller and CDC-ECM gadget function so an RPi5 can present itself as a USB Ethernet adapter to a connected host, enabling direct point-to-point peering over USB-C.

**Architecture:** Two sans-I/O layers in Ring 1: `Dwc2Controller` (hardware state machine using `RegisterBank` trait) and `EcmGadget` (CDC-ECM class logic), communicating via `GadgetEvent`/`GadgetRequest` enums. Ring 2 reuses `VirtioNetServer` unchanged via the `NetworkDevice` trait.

**Tech Stack:** Rust (no_std + alloc), `RegisterBank` trait for MMIO abstraction, `MockRegisterBank` for testing.

**Spec:** `docs/superpowers/specs/2026-04-08-usb-gadget-ecm-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `crates/harmony-unikernel/src/drivers/dwc2/types.rs` | Create | `Dwc2Event`, `Dwc2Action`, `GadgetEvent`, `GadgetRequest`, `Dwc2Error`, `UsbDeviceState`, `DeviceSpeed` |
| `crates/harmony-unikernel/src/drivers/dwc2/regs.rs` | Create | DWC2 register offset constants and bitfield masks |
| `crates/harmony-unikernel/src/drivers/dwc2/fifo.rs` | Create | Static FIFO partition constants and configuration helpers |
| `crates/harmony-unikernel/src/drivers/dwc2/mod.rs` | Create | `Dwc2Controller` state machine — init, event handling, SETUP dispatch, data path |
| `crates/harmony-unikernel/src/drivers/ecm_gadget/descriptor.rs` | Create | CDC-ECM descriptor builders (device, config, string, functional) |
| `crates/harmony-unikernel/src/drivers/ecm_gadget/mod.rs` | Create | `EcmGadget` — class request handling, NetworkDevice-compatible methods, notifications |
| `crates/harmony-unikernel/src/drivers/mod.rs` | Modify | Add `pub mod dwc2;` and `pub mod ecm_gadget;` |
| `crates/harmony-microkernel/src/ecm_gadget_net_device.rs` | Create | `EcmGadgetNetDevice` adapter for `VirtioNetServer` |
| `crates/harmony-microkernel/src/lib.rs` | Modify | Add `pub mod ecm_gadget_net_device;` |

---

### Task 1: DWC2 Types and Module Scaffolding

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/dwc2/types.rs`
- Create: `crates/harmony-unikernel/src/drivers/dwc2/mod.rs` (stub)
- Create: `crates/harmony-unikernel/src/drivers/dwc2/regs.rs` (stub)
- Create: `crates/harmony-unikernel/src/drivers/dwc2/fifo.rs` (stub)
- Create: `crates/harmony-unikernel/src/drivers/ecm_gadget/mod.rs` (stub)
- Create: `crates/harmony-unikernel/src/drivers/ecm_gadget/descriptor.rs` (stub)
- Modify: `crates/harmony-unikernel/src/drivers/mod.rs`

- [ ] **Step 1: Write failing test for type constructibility**

Create `crates/harmony-unikernel/src/drivers/dwc2/types.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! Types for the DWC2 USB device controller and gadget interface.

extern crate alloc;

use alloc::vec::Vec;

// ── USB device state machine ────────────────────────────────────────────────

/// USB device state per the USB 2.0 spec chapter 9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbDeviceState {
    /// After power-on or bus reset. No address assigned.
    Default,
    /// Address assigned via SET_ADDRESS. Not yet configured.
    Address,
    /// Configuration selected via SET_CONFIGURATION. Endpoints active.
    Configured,
}

/// USB device speed negotiated during enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceSpeed {
    /// 12 Mbps.
    FullSpeed,
    /// 480 Mbps.
    HighSpeed,
}

// ── DWC2 hardware events (caller → controller) ─────────────────────────────

/// Hardware-level events fed to the DWC2 controller.
///
/// The caller reads DWC2 interrupt status registers and translates
/// them into these events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dwc2Event {
    /// USB bus reset detected (GINTSTS.USBRst).
    BusReset,
    /// Enumeration complete — speed negotiated (GINTSTS.EnumDone).
    EnumerationDone { speed: DeviceSpeed },
    /// SETUP packet received on EP0 (GRXSTSP status = 6).
    SetupReceived { data: [u8; 8] },
    /// RX FIFO has data (GINTSTS.RxFLvl).
    RxFifoNonEmpty,
    /// IN transfer completed on endpoint (DIEPINTn.XferCompl).
    InTransferComplete { ep: u8 },
    /// OUT transfer completed on endpoint (DOEPINTn.XferCompl).
    OutTransferComplete { ep: u8 },
    /// USB suspend detected (GINTSTS.USBSusp).
    Suspend,
    /// USB resume / remote wakeup detected (GINTSTS.WkUpInt).
    Resume,
}

// ── DWC2 hardware actions (controller → caller) ────────────────────────────

/// Actions the DWC2 controller returns for the caller to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dwc2Action {
    /// Write a 32-bit value to a register at `offset`.
    WriteRegister { offset: usize, value: u32 },
    /// Write data to a TX FIFO for the given IN endpoint.
    WriteTxFifo { ep: u8, data: Vec<u8> },
    /// Read `words` 32-bit words from the RX FIFO (GRXSTSP pop).
    ReadRxFifo { words: usize },
    /// Stall an endpoint (set STALL bit in DIEPCTLn/DOEPCTLn).
    Stall { ep: u8 },
}

// ── Gadget interface (controller ↔ class driver) ────────────────────────────

/// Events from `Dwc2Controller` to the gadget class driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GadgetEvent {
    /// Bus reset — gadget should reset its state.
    Reset,
    /// SET_CONFIGURATION completed — data endpoints are active.
    Configured,
    /// Class-specific SETUP request (bmRequestType type bits = Class).
    SetupClassRequest { setup: [u8; 8] },
    /// GET_DESCRIPTOR request the controller doesn't own.
    GetDescriptor {
        desc_type: u8,
        desc_index: u8,
        max_len: u16,
    },
    /// Data received on a bulk OUT endpoint.
    BulkOut { ep: u8, data: Vec<u8> },
    /// Bulk IN transfer completed — endpoint ready for next frame.
    BulkInComplete { ep: u8 },
    /// USB bus suspended.
    Suspended,
    /// USB bus resumed.
    Resumed,
}

/// Requests from the gadget class driver to `Dwc2Controller`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GadgetRequest {
    /// Respond to a control IN request with data.
    ControlIn { data: Vec<u8> },
    /// Acknowledge a control OUT request (zero-length status stage).
    ControlAck,
    /// Stall the control endpoint (unsupported request).
    ControlStall,
    /// Send data on a bulk IN endpoint.
    BulkIn { ep: u8, data: Vec<u8> },
    /// Send a CDC notification on an interrupt IN endpoint.
    InterruptIn { ep: u8, data: Vec<u8> },
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Errors from DWC2 controller operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dwc2Error {
    /// FIFO partition exceeds available RAM.
    FifoOverflow,
    /// Operation invalid for the current USB device state.
    InvalidState {
        current: UsbDeviceState,
        attempted: &'static str,
    },
    /// Endpoint number out of range (0-3 for this device).
    InvalidEndpoint { ep: u8 },
    /// TX FIFO is full — retry after InTransferComplete.
    TxFifoFull { ep: u8 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn device_state_default() {
        let state = UsbDeviceState::Default;
        assert_eq!(state, UsbDeviceState::Default);
    }

    #[test]
    fn dwc2_event_variants_constructible() {
        let _reset = Dwc2Event::BusReset;
        let _enum_done = Dwc2Event::EnumerationDone {
            speed: DeviceSpeed::HighSpeed,
        };
        let _setup = Dwc2Event::SetupReceived { data: [0; 8] };
        let _rx = Dwc2Event::RxFifoNonEmpty;
        let _in_done = Dwc2Event::InTransferComplete { ep: 1 };
        let _out_done = Dwc2Event::OutTransferComplete { ep: 2 };
        let _suspend = Dwc2Event::Suspend;
        let _resume = Dwc2Event::Resume;
    }

    #[test]
    fn dwc2_action_variants_constructible() {
        let _write = Dwc2Action::WriteRegister {
            offset: 0x800,
            value: 0,
        };
        let _fifo = Dwc2Action::WriteTxFifo {
            ep: 1,
            data: vec![0xAA; 64],
        };
        let _read = Dwc2Action::ReadRxFifo { words: 4 };
        let _stall = Dwc2Action::Stall { ep: 0 };
    }

    #[test]
    fn gadget_event_variants_constructible() {
        let _reset = GadgetEvent::Reset;
        let _conf = GadgetEvent::Configured;
        let _class = GadgetEvent::SetupClassRequest { setup: [0; 8] };
        let _desc = GadgetEvent::GetDescriptor {
            desc_type: 1,
            desc_index: 0,
            max_len: 64,
        };
        let _bulk = GadgetEvent::BulkOut {
            ep: 2,
            data: vec![0xBB; 60],
        };
        let _done = GadgetEvent::BulkInComplete { ep: 1 };
        let _susp = GadgetEvent::Suspended;
        let _resu = GadgetEvent::Resumed;
    }

    #[test]
    fn gadget_request_variants_constructible() {
        let _cin = GadgetRequest::ControlIn {
            data: vec![0; 18],
        };
        let _ack = GadgetRequest::ControlAck;
        let _stall = GadgetRequest::ControlStall;
        let _bulk = GadgetRequest::BulkIn {
            ep: 1,
            data: vec![0xCC; 100],
        };
        let _intr = GadgetRequest::InterruptIn {
            ep: 3,
            data: vec![0xA1, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00],
        };
    }

    #[test]
    fn dwc2_error_variants_constructible() {
        let _fifo = Dwc2Error::FifoOverflow;
        let _state = Dwc2Error::InvalidState {
            current: UsbDeviceState::Default,
            attempted: "bulk_in",
        };
        let _ep = Dwc2Error::InvalidEndpoint { ep: 5 };
        let _full = Dwc2Error::TxFifoFull { ep: 1 };
    }
}
```

- [ ] **Step 2: Create module stubs and wire into drivers/mod.rs**

Create `crates/harmony-unikernel/src/drivers/dwc2/mod.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! DWC2 OTG USB device controller driver.
//!
//! Sans-I/O design: the controller never performs MMIO directly. All register
//! access goes through the [`RegisterBank`](super::RegisterBank) trait, and
//! the driver returns [`Dwc2Action`] values for the caller to execute.

pub mod fifo;
pub mod regs;
pub mod types;

pub use types::{
    DeviceSpeed, Dwc2Action, Dwc2Error, Dwc2Event, GadgetEvent, GadgetRequest, UsbDeviceState,
};
```

Create `crates/harmony-unikernel/src/drivers/dwc2/regs.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! DWC2 register offset constants and bitfield masks.
```

Create `crates/harmony-unikernel/src/drivers/dwc2/fifo.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! DWC2 FIFO partition constants for CDC-ECM gadget mode.
```

Create `crates/harmony-unikernel/src/drivers/ecm_gadget/mod.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! CDC-ECM USB gadget function.

pub mod descriptor;
```

Create `crates/harmony-unikernel/src/drivers/ecm_gadget/descriptor.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! CDC-ECM descriptor builders for USB device mode.
```

Modify `crates/harmony-unikernel/src/drivers/mod.rs` — add after the `pub mod dwc_usb;` line:

```rust
pub mod dwc2;
pub mod ecm_gadget;
```

- [ ] **Step 3: Run tests to verify compilation**

Run: `cargo test -p harmony-unikernel --lib drivers::dwc2::types -- --nocapture`
Expected: 6 tests PASS

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc2/ crates/harmony-unikernel/src/drivers/ecm_gadget/ crates/harmony-unikernel/src/drivers/mod.rs
git commit -m "feat(usb): add DWC2 types and module scaffolding for gadget mode"
```

---

### Task 2: DWC2 Register Constants and FIFO Configuration

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/dwc2/regs.rs` (replace stub)
- Create: `crates/harmony-unikernel/src/drivers/dwc2/fifo.rs` (replace stub)

- [ ] **Step 1: Write failing tests for register constants and FIFO sizing**

Add to the bottom of `crates/harmony-unikernel/src/drivers/dwc2/regs.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! DWC2 register offset constants and bitfield masks.
//!
//! Register layout follows the Synopsys DesignWare USB 2.0 OTG controller
//! databook. Offsets are from the peripheral MMIO base address.

// ── Core Global Registers ───────────────────────────────────────────────────

/// OTG Control and Status Register.
pub const GOTGCTL: usize = 0x000;
/// AHB Configuration Register.
pub const GAHBCFG: usize = 0x008;
/// USB Configuration Register.
pub const GUSBCFG: usize = 0x00C;
/// Reset Register.
pub const GRSTCTL: usize = 0x010;
/// Interrupt Status Register.
pub const GINTSTS: usize = 0x014;
/// Interrupt Mask Register.
pub const GINTMSK: usize = 0x018;
/// Receive Status Read and Pop Register.
pub const GRXSTSP: usize = 0x020;
/// Receive FIFO Size Register.
pub const GRXFSIZ: usize = 0x024;
/// Non-Periodic TX FIFO Size Register (EP0 TX).
pub const GNPTXFSIZ: usize = 0x028;

/// Device IN Endpoint TX FIFO Size Register for EP `n` (1-based).
/// EP1 = 0x104, EP2 = 0x108, EP3 = 0x10C.
pub const fn dieptxf(n: u8) -> usize {
    0x104 + (n as usize - 1) * 4
}

// ── Device Mode Registers ───────────────────────────────────────────────────

/// Device Configuration Register.
pub const DCFG: usize = 0x800;
/// Device Control Register.
pub const DCTL: usize = 0x804;
/// Device Status Register.
pub const DSTS: usize = 0x808;
/// Device IN Endpoint Common Interrupt Mask Register.
pub const DIEPMSK: usize = 0x810;
/// Device OUT Endpoint Common Interrupt Mask Register.
pub const DOEPMSK: usize = 0x814;
/// Device All Endpoints Interrupt Register.
pub const DAINT: usize = 0x818;
/// Device All Endpoints Interrupt Mask Register.
pub const DAINTMSK: usize = 0x81C;

// ── Per-Endpoint Registers (stride = 0x20) ──────────────────────────────────

/// Device IN Endpoint `n` Control Register.
pub const fn diepctl(n: u8) -> usize {
    0x900 + n as usize * 0x20
}
/// Device IN Endpoint `n` Interrupt Register.
pub const fn diepint(n: u8) -> usize {
    0x908 + n as usize * 0x20
}
/// Device IN Endpoint `n` Transfer Size Register.
pub const fn dieptsiz(n: u8) -> usize {
    0x910 + n as usize * 0x20
}
/// Device IN Endpoint `n` TX FIFO Status Register.
pub const fn dtxfsts(n: u8) -> usize {
    0x918 + n as usize * 0x20
}
/// Device OUT Endpoint `n` Control Register.
pub const fn doepctl(n: u8) -> usize {
    0xB00 + n as usize * 0x20
}
/// Device OUT Endpoint `n` Interrupt Register.
pub const fn doepint(n: u8) -> usize {
    0xB08 + n as usize * 0x20
}
/// Device OUT Endpoint `n` Transfer Size Register.
pub const fn doeptsiz(n: u8) -> usize {
    0xB10 + n as usize * 0x20
}

/// Data FIFO base address for endpoint `n`.
/// Each endpoint's FIFO occupies a 4KB window: EP0 at 0x1000, EP1 at 0x2000, etc.
pub const fn ep_fifo(n: u8) -> usize {
    0x1000 + n as usize * 0x1000
}

// ── GUSBCFG bits ────────────────────────────────────────────────────────────

/// Force Device Mode (bit 30).
pub const GUSBCFG_FORCE_DEV: u32 = 1 << 30;
/// USB Turnaround Time — 9 for HS on internal PHY (bits 13:10).
pub const GUSBCFG_TURNAROUND_9: u32 = 9 << 10;

// ── GAHBCFG bits ────────────────────────────────────────────────────────────

/// Global Interrupt Mask (bit 0). Set to enable interrupts.
pub const GAHBCFG_GLBL_INTR_EN: u32 = 1 << 0;

// ── GRSTCTL bits ────────────────────────────────────────────────────────────

/// Core Soft Reset (bit 0).
pub const GRSTCTL_CSRST: u32 = 1 << 0;
/// AHB Master Idle (bit 31). Wait for this before issuing soft reset.
pub const GRSTCTL_AHB_IDLE: u32 = 1 << 31;

// ── GINTSTS / GINTMSK bits ─────────────────────────────────────────────────

/// RX FIFO Non-Empty (bit 4).
pub const GINTSTS_RXFLVL: u32 = 1 << 4;
/// USB Reset (bit 12).
pub const GINTSTS_USBRST: u32 = 1 << 12;
/// Enumeration Done (bit 13).
pub const GINTSTS_ENUMDNE: u32 = 1 << 13;
/// IN Endpoints Interrupt (bit 18).
pub const GINTSTS_IEPINT: u32 = 1 << 18;
/// OUT Endpoints Interrupt (bit 19).
pub const GINTSTS_OEPINT: u32 = 1 << 19;
/// USB Suspend (bit 11).
pub const GINTSTS_USBSUSP: u32 = 1 << 11;
/// Resume / Remote Wakeup (bit 31).
pub const GINTSTS_WKUPINT: u32 = 1 << 31;

// ── GRXSTSP bits ────────────────────────────────────────────────────────────

/// Extract endpoint number from GRXSTSP (bits 3:0).
pub const fn grxstsp_epnum(val: u32) -> u8 {
    (val & 0xF) as u8
}
/// Extract byte count from GRXSTSP (bits 10:4).
pub const fn grxstsp_bcnt(val: u32) -> u16 {
    ((val >> 4) & 0x7FF) as u16
}
/// Extract packet status from GRXSTSP (bits 20:17).
pub const fn grxstsp_pktsts(val: u32) -> u8 {
    ((val >> 17) & 0xF) as u8
}
/// Packet status: OUT data packet received.
pub const PKTSTS_OUT_DATA: u8 = 2;
/// Packet status: OUT transfer completed.
pub const PKTSTS_OUT_COMPLETE: u8 = 3;
/// Packet status: SETUP transaction completed.
pub const PKTSTS_SETUP_COMPLETE: u8 = 4;
/// Packet status: SETUP data packet received.
pub const PKTSTS_SETUP_DATA: u8 = 6;

// ── DCFG bits ───────────────────────────────────────────────────────────────

/// Device Speed: High Speed (bits 1:0 = 0b00).
pub const DCFG_DEVSPD_HS: u32 = 0;
/// Device Address mask (bits 10:4).
pub const DCFG_DAD_MASK: u32 = 0x7F << 4;
/// Build DCFG Device Address field value.
pub const fn dcfg_dad(addr: u8) -> u32 {
    ((addr as u32) & 0x7F) << 4
}

// ── DCTL bits ───────────────────────────────────────────────────────────────

/// Soft Disconnect (bit 1). Set to disconnect from bus.
pub const DCTL_SFTDISCON: u32 = 1 << 1;
/// Clear Global IN NAK (bit 8).
pub const DCTL_CGINAK: u32 = 1 << 8;
/// Clear Global OUT NAK (bit 10).
pub const DCTL_CGONAK: u32 = 1 << 10;

// ── DSTS bits ───────────────────────────────────────────────────────────────

/// Extract Enumerated Speed from DSTS (bits 2:1). 0=HS, 1=FS.
pub const fn dsts_enumspd(val: u32) -> u8 {
    ((val >> 1) & 0x3) as u8
}
/// Enumerated speed: High Speed (480 Mbps).
pub const ENUMSPD_HS: u8 = 0;
/// Enumerated speed: Full Speed (12 Mbps, 48 MHz PHY).
pub const ENUMSPD_FS_48: u8 = 1;

// ── DIEPCTLn / DOEPCTLn bits ───────────────────────────────────────────────

/// Maximum Packet Size mask (bits 10:0).
pub const EPCTL_MPS_MASK: u32 = 0x7FF;
/// USB Active Endpoint (bit 15).
pub const EPCTL_USBAEP: u32 = 1 << 15;
/// Endpoint Type (bits 19:18). 0=Control, 2=Bulk, 3=Interrupt.
pub const fn epctl_eptype(t: u8) -> u32 {
    ((t as u32) & 0x3) << 18
}
/// TX FIFO Number (bits 25:22) — IN endpoints only.
pub const fn epctl_txfnum(n: u8) -> u32 {
    ((n as u32) & 0xF) << 22
}
/// Stall Handshake (bit 21).
pub const EPCTL_STALL: u32 = 1 << 21;
/// Clear NAK (bit 26).
pub const EPCTL_CNAK: u32 = 1 << 26;
/// Set NAK (bit 27).
pub const EPCTL_SNAK: u32 = 1 << 27;
/// Endpoint Disable (bit 30).
pub const EPCTL_EPDIS: u32 = 1 << 30;
/// Endpoint Enable (bit 31).
pub const EPCTL_EPENA: u32 = 1 << 31;

/// Endpoint type: Control.
pub const EPTYPE_CONTROL: u8 = 0;
/// Endpoint type: Bulk.
pub const EPTYPE_BULK: u8 = 2;
/// Endpoint type: Interrupt.
pub const EPTYPE_INTERRUPT: u8 = 3;

// ── DIEPINTn / DOEPINTn bits ────────────────────────────────────────────────

/// Transfer Completed (bit 0).
pub const DEPINT_XFERCOMPL: u32 = 1 << 0;
/// Endpoint Disabled (bit 1).
pub const DEPINT_EPDISBLD: u32 = 1 << 1;
/// SETUP Phase Done — EP0 OUT only (bit 3).
pub const DOEPINT_SETUP: u32 = 1 << 3;

// ── DOEPTSIZn bits ──────────────────────────────────────────────────────────

/// SETUP Packet Count for EP0 (bits 30:29). Set to 1 for single SETUP.
pub const DOEPTSIZ0_SUPCNT_1: u32 = 1 << 29;
/// Packet Count (bit 19) for EP0 OUT — set to 1 for one packet.
pub const DOEPTSIZ0_PKTCNT_1: u32 = 1 << 19;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_register_offsets_non_overlapping() {
        // IN EP0-3 control registers should be distinct
        let in_ctrls: Vec<usize> = (0..4).map(diepctl).collect();
        for i in 0..in_ctrls.len() {
            for j in (i + 1)..in_ctrls.len() {
                assert_ne!(in_ctrls[i], in_ctrls[j], "DIEPCTL overlap at {i} and {j}");
            }
        }
        // OUT EP0-3 control registers should be distinct
        let out_ctrls: Vec<usize> = (0..4).map(doepctl).collect();
        for i in 0..out_ctrls.len() {
            for j in (i + 1)..out_ctrls.len() {
                assert_ne!(out_ctrls[i], out_ctrls[j], "DOEPCTL overlap at {i} and {j}");
            }
        }
        // IN and OUT should not overlap
        for &ic in &in_ctrls {
            for &oc in &out_ctrls {
                assert_ne!(ic, oc, "DIEPCTL and DOEPCTL overlap at {ic:#x}");
            }
        }
    }

    #[test]
    fn dieptxf_offsets() {
        assert_eq!(dieptxf(1), 0x104);
        assert_eq!(dieptxf(2), 0x108);
        assert_eq!(dieptxf(3), 0x10C);
    }

    #[test]
    fn ep_fifo_offsets() {
        assert_eq!(ep_fifo(0), 0x1000);
        assert_eq!(ep_fifo(1), 0x2000);
        assert_eq!(ep_fifo(2), 0x3000);
    }

    #[test]
    fn grxstsp_field_extraction() {
        // EP2, 64 bytes, SETUP data (status 6)
        let val: u32 = 2 | (64 << 4) | (6 << 17);
        assert_eq!(grxstsp_epnum(val), 2);
        assert_eq!(grxstsp_bcnt(val), 64);
        assert_eq!(grxstsp_pktsts(val), 6);
    }

    #[test]
    fn dcfg_device_address_encoding() {
        assert_eq!(dcfg_dad(0), 0);
        assert_eq!(dcfg_dad(5), 5 << 4);
        assert_eq!(dcfg_dad(127), 127 << 4);
    }

    #[test]
    fn epctl_field_encoding() {
        // Bulk IN: type=2, FIFO=1, MPS=512, active, enable
        let val = epctl_eptype(EPTYPE_BULK) | epctl_txfnum(1)
            | (512 & EPCTL_MPS_MASK) | EPCTL_USBAEP | EPCTL_EPENA | EPCTL_CNAK;
        assert!(val & EPCTL_USBAEP != 0);
        assert!(val & EPCTL_EPENA != 0);
        assert_eq!((val >> 18) & 0x3, 2); // bulk
        assert_eq!((val >> 22) & 0xF, 1); // FIFO 1
        assert_eq!(val & EPCTL_MPS_MASK, 512);
    }
}
```

- [ ] **Step 2: Write FIFO partition constants and test**

Replace `crates/harmony-unikernel/src/drivers/dwc2/fifo.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! DWC2 FIFO partition constants for CDC-ECM gadget mode.
//!
//! The DWC2 has ~4KB of shared internal RAM that must be partitioned
//! across endpoint FIFOs. FIFO sizes are specified in 32-bit words.

/// Total shared FIFO RAM in 32-bit words (4096 bytes / 4).
pub const FIFO_RAM_WORDS: u32 = 1024;

/// RX FIFO size in words (shared across all OUT endpoints).
/// 256 words = 1024 bytes — fits 2x 512-byte max bulk packets.
pub const RX_FIFO_WORDS: u32 = 256;

/// EP0 TX FIFO size in words.
/// 32 words = 128 bytes — 64-byte max packet + overhead.
pub const TX0_FIFO_WORDS: u32 = 32;

/// EP1 TX FIFO size in words (bulk IN — Ethernet frames).
/// 384 words = 1536 bytes — fits one 1514-byte Ethernet frame + padding.
pub const TX1_FIFO_WORDS: u32 = 384;

/// EP3 TX FIFO size in words (interrupt IN — CDC notifications).
/// 16 words = 64 bytes — notifications are 8-16 bytes.
pub const TX3_FIFO_WORDS: u32 = 16;

/// GNPTXFSIZ register value for EP0 TX FIFO.
/// Bits 31:16 = depth in words, bits 15:0 = start address in words.
/// EP0 TX starts immediately after RX FIFO.
pub const fn gnptxfsiz_value() -> u32 {
    (TX0_FIFO_WORDS << 16) | RX_FIFO_WORDS
}

/// DIEPTXF(n) register value for a TX FIFO.
/// Bits 31:16 = depth in words, bits 15:0 = start address in words.
pub const fn dieptxf_value(start_word: u32, depth_words: u32) -> u32 {
    (depth_words << 16) | start_word
}

/// EP1 TX FIFO start word (after RX + EP0 TX).
pub const TX1_START: u32 = RX_FIFO_WORDS + TX0_FIFO_WORDS;

/// EP3 TX FIFO start word (after RX + EP0 TX + EP1 TX).
pub const TX3_START: u32 = TX1_START + TX1_FIFO_WORDS;

/// Total words consumed by the static FIFO partition.
pub const TOTAL_FIFO_WORDS: u32 =
    RX_FIFO_WORDS + TX0_FIFO_WORDS + TX1_FIFO_WORDS + TX3_FIFO_WORDS;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_partition_fits_in_4kb() {
        assert!(
            TOTAL_FIFO_WORDS <= FIFO_RAM_WORDS,
            "FIFO partition ({} words = {} bytes) exceeds available RAM ({} words = {} bytes)",
            TOTAL_FIFO_WORDS,
            TOTAL_FIFO_WORDS * 4,
            FIFO_RAM_WORDS,
            FIFO_RAM_WORDS * 4,
        );
    }

    #[test]
    fn fifo_regions_do_not_overlap() {
        // RX: [0, RX_FIFO_WORDS)
        // EP0 TX: [RX_FIFO_WORDS, RX_FIFO_WORDS + TX0_FIFO_WORDS)
        // EP1 TX: [TX1_START, TX1_START + TX1_FIFO_WORDS)
        // EP3 TX: [TX3_START, TX3_START + TX3_FIFO_WORDS)
        assert_eq!(TX1_START, RX_FIFO_WORDS + TX0_FIFO_WORDS);
        assert_eq!(TX3_START, TX1_START + TX1_FIFO_WORDS);
        // End of last FIFO must not exceed total
        let end = TX3_START + TX3_FIFO_WORDS;
        assert_eq!(end, TOTAL_FIFO_WORDS);
    }

    #[test]
    fn gnptxfsiz_register_value() {
        let val = gnptxfsiz_value();
        let start = val & 0xFFFF;
        let depth = val >> 16;
        assert_eq!(start, RX_FIFO_WORDS);
        assert_eq!(depth, TX0_FIFO_WORDS);
    }

    #[test]
    fn dieptxf_register_values() {
        let ep1 = dieptxf_value(TX1_START, TX1_FIFO_WORDS);
        assert_eq!(ep1 & 0xFFFF, TX1_START);
        assert_eq!(ep1 >> 16, TX1_FIFO_WORDS);

        let ep3 = dieptxf_value(TX3_START, TX3_FIFO_WORDS);
        assert_eq!(ep3 & 0xFFFF, TX3_START);
        assert_eq!(ep3 >> 16, TX3_FIFO_WORDS);
    }

    #[test]
    fn rx_fifo_holds_two_bulk_packets() {
        // USB2 HS bulk max packet = 512 bytes = 128 words
        assert!(RX_FIFO_WORDS >= 128 * 2, "RX FIFO must hold 2x bulk packets");
    }

    #[test]
    fn tx1_fifo_holds_ethernet_frame() {
        // Max Ethernet frame = 1514 bytes = 379 words (rounded up)
        let eth_words = (1514 + 3) / 4;
        assert!(
            TX1_FIFO_WORDS >= eth_words,
            "TX1 FIFO ({} words) must hold Ethernet frame ({} words)",
            TX1_FIFO_WORDS,
            eth_words,
        );
    }
}
```

- [ ] **Step 3: Run tests to verify compilation and correctness**

Run: `cargo test -p harmony-unikernel --lib drivers::dwc2 -- --nocapture`
Expected: All tests PASS (types + regs + fifo)

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc2/regs.rs crates/harmony-unikernel/src/drivers/dwc2/fifo.rs
git commit -m "feat(usb): add DWC2 register constants and FIFO partition"
```

---

### Task 3: DWC2 Controller — Init, Bus Reset, Enumeration

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc2/mod.rs`

- [ ] **Step 1: Write failing tests for init and bus reset**

Replace `crates/harmony-unikernel/src/drivers/dwc2/mod.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! DWC2 OTG USB device controller driver.
//!
//! Sans-I/O design: the controller never performs MMIO directly. All register
//! access goes through the [`RegisterBank`](super::RegisterBank) trait, and
//! the driver returns [`Dwc2Action`] values for the caller to execute.

pub mod fifo;
pub mod regs;
pub mod types;

pub use types::{
    DeviceSpeed, Dwc2Action, Dwc2Error, Dwc2Event, GadgetEvent, GadgetRequest, UsbDeviceState,
};

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use super::RegisterBank;
use regs::*;
use fifo::*;

/// Maximum number of endpoints supported (EP0-EP3).
const MAX_ENDPOINTS: u8 = 4;

/// DWC2 OTG controller in fixed device (peripheral) mode.
///
/// Manages the USB device state machine, FIFO allocation, SETUP packet
/// routing, and endpoint transfers. Communicates with the gadget class
/// driver via [`GadgetEvent`] and [`GadgetRequest`].
pub struct Dwc2Controller {
    /// Current USB device state.
    state: UsbDeviceState,
    /// Negotiated speed after enumeration.
    speed: DeviceSpeed,
    /// Assigned USB device address (0 = default).
    address: u8,
    /// Pending SETUP packet data (8 bytes) for two-phase handling.
    setup_data: Option<[u8; 8]>,
    /// Descriptor provider callback data — set by the gadget after init.
    /// Holds pre-built descriptors the controller serves during GET_DESCRIPTOR.
    device_desc: Vec<u8>,
    config_desc: Vec<u8>,
    string_descs: Vec<Vec<u8>>,
}

impl Dwc2Controller {
    /// Initialize the DWC2 controller in device mode.
    ///
    /// Forces peripheral mode, configures FIFO sizes, sets HS speed,
    /// unmasks device interrupts, and performs soft-connect (clears SFTDISCON).
    ///
    /// Returns the controller and a list of register writes for the caller
    /// to execute.
    pub fn init(bank: &mut impl RegisterBank) -> Result<(Self, Vec<Dwc2Action>), Dwc2Error> {
        // Verify FIFO partition fits.
        if TOTAL_FIFO_WORDS > FIFO_RAM_WORDS {
            return Err(Dwc2Error::FifoOverflow);
        }

        let mut actions = Vec::new();

        // 1. Force device mode (GUSBCFG bit 30).
        let gusbcfg = bank.read(GUSBCFG) | GUSBCFG_FORCE_DEV | GUSBCFG_TURNAROUND_9;
        bank.write(GUSBCFG, gusbcfg);
        actions.push(Dwc2Action::WriteRegister {
            offset: GUSBCFG,
            value: gusbcfg,
        });

        // 2. Configure device speed: High Speed (DCFG bits 1:0 = 0).
        let dcfg = DCFG_DEVSPD_HS;
        bank.write(DCFG, dcfg);
        actions.push(Dwc2Action::WriteRegister {
            offset: DCFG,
            value: dcfg,
        });

        // 3. Configure FIFO sizes.
        bank.write(GRXFSIZ, RX_FIFO_WORDS);
        actions.push(Dwc2Action::WriteRegister {
            offset: GRXFSIZ,
            value: RX_FIFO_WORDS,
        });

        let nptx = gnptxfsiz_value();
        bank.write(GNPTXFSIZ, nptx);
        actions.push(Dwc2Action::WriteRegister {
            offset: GNPTXFSIZ,
            value: nptx,
        });

        let tx1 = dieptxf_value(TX1_START, TX1_FIFO_WORDS);
        bank.write(regs::dieptxf(1), tx1);
        actions.push(Dwc2Action::WriteRegister {
            offset: regs::dieptxf(1),
            value: tx1,
        });

        let tx3 = dieptxf_value(TX3_START, TX3_FIFO_WORDS);
        bank.write(regs::dieptxf(3), tx3);
        actions.push(Dwc2Action::WriteRegister {
            offset: regs::dieptxf(3),
            value: tx3,
        });

        // 4. Enable global interrupts (GAHBCFG bit 0).
        let gahbcfg = GAHBCFG_GLBL_INTR_EN;
        bank.write(GAHBCFG, gahbcfg);
        actions.push(Dwc2Action::WriteRegister {
            offset: GAHBCFG,
            value: gahbcfg,
        });

        // 5. Unmask device interrupts.
        let intmsk = GINTSTS_USBRST | GINTSTS_ENUMDNE | GINTSTS_RXFLVL
            | GINTSTS_IEPINT | GINTSTS_OEPINT | GINTSTS_USBSUSP | GINTSTS_WKUPINT;
        bank.write(GINTMSK, intmsk);
        actions.push(Dwc2Action::WriteRegister {
            offset: GINTMSK,
            value: intmsk,
        });

        // 6. Unmask EP0 IN/OUT endpoint interrupts.
        bank.write(DAINTMSK, (1 << 0) | (1 << 16)); // EP0 IN + EP0 OUT
        actions.push(Dwc2Action::WriteRegister {
            offset: DAINTMSK,
            value: (1 << 0) | (1 << 16),
        });

        // 7. Enable transfer complete interrupts on endpoints.
        bank.write(DIEPMSK, DEPINT_XFERCOMPL);
        actions.push(Dwc2Action::WriteRegister {
            offset: DIEPMSK,
            value: DEPINT_XFERCOMPL,
        });
        bank.write(DOEPMSK, DEPINT_XFERCOMPL | DOEPINT_SETUP);
        actions.push(Dwc2Action::WriteRegister {
            offset: DOEPMSK,
            value: DEPINT_XFERCOMPL | DOEPINT_SETUP,
        });

        // 8. Prepare EP0 OUT to receive SETUP packets.
        let doeptsiz0 = DOEPTSIZ0_SUPCNT_1 | DOEPTSIZ0_PKTCNT_1 | 64; // 64 bytes max
        bank.write(doeptsiz(0), doeptsiz0);
        actions.push(Dwc2Action::WriteRegister {
            offset: doeptsiz(0),
            value: doeptsiz0,
        });

        let doepctl0 = EPCTL_EPENA | EPCTL_CNAK;
        bank.write(doepctl(0), doepctl0);
        actions.push(Dwc2Action::WriteRegister {
            offset: doepctl(0),
            value: doepctl0,
        });

        // 9. Soft-connect: clear SFTDISCON.
        let dctl = bank.read(DCTL) & !DCTL_SFTDISCON;
        bank.write(DCTL, dctl);
        actions.push(Dwc2Action::WriteRegister {
            offset: DCTL,
            value: dctl,
        });

        let controller = Dwc2Controller {
            state: UsbDeviceState::Default,
            speed: DeviceSpeed::HighSpeed,
            address: 0,
            setup_data: None,
            device_desc: Vec::new(),
            config_desc: Vec::new(),
            string_descs: Vec::new(),
        };

        Ok((controller, actions))
    }

    /// Register descriptors that the controller serves during GET_DESCRIPTOR.
    ///
    /// Called by the gadget after init to provide device, config, and string
    /// descriptors.
    pub fn set_descriptors(
        &mut self,
        device_desc: Vec<u8>,
        config_desc: Vec<u8>,
        string_descs: Vec<Vec<u8>>,
    ) {
        self.device_desc = device_desc;
        self.config_desc = config_desc;
        self.string_descs = string_descs;
    }

    /// Return the current USB device state.
    pub fn state(&self) -> UsbDeviceState {
        self.state
    }

    /// Return the negotiated device speed.
    pub fn speed(&self) -> DeviceSpeed {
        self.speed
    }

    /// Process a hardware event and return gadget-level events.
    pub fn handle_event(
        &mut self,
        event: Dwc2Event,
        bank: &mut impl RegisterBank,
    ) -> Result<Vec<GadgetEvent>, Dwc2Error> {
        match event {
            Dwc2Event::BusReset => Ok(self.handle_bus_reset(bank)),
            Dwc2Event::EnumerationDone { speed } => {
                self.speed = speed;
                Ok(vec![])
            }
            Dwc2Event::SetupReceived { data } => self.handle_setup(data, bank),
            Dwc2Event::RxFifoNonEmpty => self.handle_rx_fifo(bank),
            Dwc2Event::InTransferComplete { ep } => {
                if ep < MAX_ENDPOINTS {
                    Ok(vec![GadgetEvent::BulkInComplete { ep }])
                } else {
                    Err(Dwc2Error::InvalidEndpoint { ep })
                }
            }
            Dwc2Event::OutTransferComplete { ep } => {
                // Re-arm EP0 OUT for next SETUP/data.
                if ep == 0 {
                    let doeptsiz0 = DOEPTSIZ0_SUPCNT_1 | DOEPTSIZ0_PKTCNT_1 | 64;
                    bank.write(doeptsiz(0), doeptsiz0);
                    bank.write(doepctl(0), EPCTL_EPENA | EPCTL_CNAK);
                }
                Ok(vec![])
            }
            Dwc2Event::Suspend => Ok(vec![GadgetEvent::Suspended]),
            Dwc2Event::Resume => Ok(vec![GadgetEvent::Resumed]),
        }
    }

    /// Handle USB bus reset: return to Default state, disable endpoints.
    fn handle_bus_reset(&mut self, bank: &mut impl RegisterBank) -> Vec<GadgetEvent> {
        self.state = UsbDeviceState::Default;
        self.address = 0;
        self.setup_data = None;

        // Clear device address.
        let dcfg = bank.read(DCFG) & !DCFG_DAD_MASK;
        bank.write(DCFG, dcfg);

        // Disable non-EP0 endpoints.
        for ep in 1..MAX_ENDPOINTS {
            bank.write(diepctl(ep), EPCTL_SNAK | EPCTL_EPDIS);
            bank.write(doepctl(ep), EPCTL_SNAK);
        }

        // Re-arm EP0 OUT for SETUP packets.
        let doeptsiz0 = DOEPTSIZ0_SUPCNT_1 | DOEPTSIZ0_PKTCNT_1 | 64;
        bank.write(doeptsiz(0), doeptsiz0);
        bank.write(doepctl(0), EPCTL_EPENA | EPCTL_CNAK);

        // Unmask only EP0 initially.
        bank.write(DAINTMSK, (1 << 0) | (1 << 16));

        vec![GadgetEvent::Reset]
    }

    /// Handle SETUP packet received on EP0.
    fn handle_setup(
        &mut self,
        setup: [u8; 8],
        bank: &mut impl RegisterBank,
    ) -> Result<Vec<GadgetEvent>, Dwc2Error> {
        let bm_request_type = setup[0];
        let b_request = setup[1];
        let w_value = u16::from_le_bytes([setup[2], setup[3]]);
        let _w_index = u16::from_le_bytes([setup[4], setup[5]]);
        let w_length = u16::from_le_bytes([setup[6], setup[7]]);

        let req_type = (bm_request_type >> 5) & 0x3;

        match req_type {
            0 => {
                // Standard request — handle internally.
                self.handle_standard_setup(b_request, w_value, w_length, bank)
            }
            1 => {
                // Class request — forward to gadget.
                Ok(vec![GadgetEvent::SetupClassRequest { setup }])
            }
            _ => {
                // Vendor/reserved — stall.
                bank.write(diepctl(0), EPCTL_STALL);
                Ok(vec![])
            }
        }
    }

    /// Handle a standard USB SETUP request.
    fn handle_standard_setup(
        &mut self,
        b_request: u8,
        w_value: u16,
        w_length: u16,
        bank: &mut impl RegisterBank,
    ) -> Result<Vec<GadgetEvent>, Dwc2Error> {
        match b_request {
            // SET_ADDRESS (0x05)
            0x05 => {
                let addr = (w_value & 0x7F) as u8;
                self.address = addr;
                let dcfg = (bank.read(DCFG) & !DCFG_DAD_MASK) | dcfg_dad(addr);
                bank.write(DCFG, dcfg);
                self.state = UsbDeviceState::Address;
                // Send ZLP status.
                self.write_ep0_in(bank, &[]);
                Ok(vec![])
            }
            // GET_DESCRIPTOR (0x06)
            0x06 => {
                let desc_type = (w_value >> 8) as u8;
                let desc_index = (w_value & 0xFF) as u8;
                let max_len = w_length;

                let data = match desc_type {
                    1 => Some(self.device_desc.clone()), // Device
                    2 => Some(self.config_desc.clone()), // Configuration
                    3 => {
                        // String descriptor
                        self.string_descs.get(desc_index as usize).cloned()
                    }
                    _ => None,
                };

                match data {
                    Some(mut d) => {
                        d.truncate(max_len as usize);
                        self.write_ep0_in(bank, &d);
                        Ok(vec![])
                    }
                    None => {
                        // Descriptor not found — ask gadget or stall.
                        Ok(vec![GadgetEvent::GetDescriptor {
                            desc_type,
                            desc_index,
                            max_len,
                        }])
                    }
                }
            }
            // SET_CONFIGURATION (0x09)
            0x09 => {
                self.state = UsbDeviceState::Configured;
                self.enable_data_endpoints(bank);
                // Send ZLP status.
                self.write_ep0_in(bank, &[]);
                Ok(vec![GadgetEvent::Configured])
            }
            // SET_INTERFACE (0x0B)
            0x0B => {
                // Acknowledge — endpoints already configured.
                self.write_ep0_in(bank, &[]);
                Ok(vec![])
            }
            // Unsupported standard request — stall.
            _ => {
                bank.write(diepctl(0), EPCTL_STALL);
                Ok(vec![])
            }
        }
    }

    /// Enable bulk IN (EP1), bulk OUT (EP2), and interrupt IN (EP3) endpoints.
    fn enable_data_endpoints(&self, bank: &mut impl RegisterBank) {
        // EP1 IN: bulk, MPS=512, FIFO=1
        let ep1ctl = EPCTL_USBAEP | epctl_eptype(EPTYPE_BULK)
            | epctl_txfnum(1) | 512 | EPCTL_EPENA | EPCTL_CNAK;
        bank.write(diepctl(1), ep1ctl);

        // EP2 OUT: bulk, MPS=512
        let ep2ctl = EPCTL_USBAEP | epctl_eptype(EPTYPE_BULK) | 512 | EPCTL_EPENA | EPCTL_CNAK;
        bank.write(doepctl(2), ep2ctl);

        // EP2 OUT transfer size: one packet, 512 bytes.
        bank.write(doeptsiz(2), (1 << 19) | 512);

        // EP3 IN: interrupt, MPS=16, FIFO=3
        let ep3ctl = EPCTL_USBAEP | epctl_eptype(EPTYPE_INTERRUPT)
            | epctl_txfnum(3) | 16 | EPCTL_EPENA | EPCTL_CNAK;
        bank.write(diepctl(3), ep3ctl);

        // Unmask all active endpoint interrupts.
        // IN: EP0(bit0) + EP1(bit1) + EP3(bit3). OUT: EP0(bit16) + EP2(bit18).
        bank.write(DAINTMSK, (1 << 0) | (1 << 1) | (1 << 3) | (1 << 16) | (1 << 18));
    }

    /// Handle RX FIFO non-empty: read the status word and extract data.
    fn handle_rx_fifo(
        &mut self,
        bank: &mut impl RegisterBank,
    ) -> Result<Vec<GadgetEvent>, Dwc2Error> {
        let status = bank.read(GRXSTSP);
        let ep = grxstsp_epnum(status);
        let bcnt = grxstsp_bcnt(status) as usize;
        let pktsts = grxstsp_pktsts(status);

        match pktsts {
            PKTSTS_SETUP_DATA => {
                // Read 8-byte SETUP packet from FIFO (2 words).
                let w0 = bank.read(ep_fifo(0));
                let w1 = bank.read(ep_fifo(0));
                let mut data = [0u8; 8];
                data[0..4].copy_from_slice(&w0.to_le_bytes());
                data[4..8].copy_from_slice(&w1.to_le_bytes());
                self.setup_data = Some(data);
                Ok(vec![])
            }
            PKTSTS_SETUP_COMPLETE => {
                // SETUP phase done — dispatch the buffered SETUP packet.
                if let Some(data) = self.setup_data.take() {
                    self.handle_setup(data, bank)
                } else {
                    Ok(vec![])
                }
            }
            PKTSTS_OUT_DATA if ep > 0 && bcnt > 0 => {
                // Bulk OUT data — read from EP FIFO.
                let words = (bcnt + 3) / 4;
                let mut buf = Vec::with_capacity(bcnt);
                for i in 0..words {
                    let word = bank.read(ep_fifo(ep));
                    let remaining = bcnt - i * 4;
                    let take = remaining.min(4);
                    buf.extend_from_slice(&word.to_le_bytes()[..take]);
                }
                Ok(vec![GadgetEvent::BulkOut {
                    ep,
                    data: buf,
                }])
            }
            PKTSTS_OUT_COMPLETE if ep > 0 => {
                // Re-arm the OUT endpoint for the next transfer.
                bank.write(doeptsiz(ep), (1 << 19) | 512);
                bank.write(doepctl(ep), EPCTL_EPENA | EPCTL_CNAK);
                Ok(vec![])
            }
            _ => {
                // Global OUT NAK, EP0 data, or other — ignore.
                if bcnt > 0 {
                    // Drain FIFO words to avoid stall.
                    let words = (bcnt + 3) / 4;
                    for _ in 0..words {
                        bank.read(ep_fifo(ep));
                    }
                }
                Ok(vec![])
            }
        }
    }

    /// Submit a gadget request, translating it into hardware actions.
    pub fn submit_request(
        &mut self,
        req: GadgetRequest,
        bank: &mut impl RegisterBank,
    ) -> Result<Vec<Dwc2Action>, Dwc2Error> {
        match req {
            GadgetRequest::ControlIn { data } => {
                self.write_ep0_in(bank, &data);
                Ok(vec![])
            }
            GadgetRequest::ControlAck => {
                self.write_ep0_in(bank, &[]);
                Ok(vec![])
            }
            GadgetRequest::ControlStall => {
                bank.write(diepctl(0), EPCTL_STALL);
                Ok(vec![Dwc2Action::Stall { ep: 0 }])
            }
            GadgetRequest::BulkIn { ep, data } => {
                if ep >= MAX_ENDPOINTS {
                    return Err(Dwc2Error::InvalidEndpoint { ep });
                }
                if self.state != UsbDeviceState::Configured {
                    return Err(Dwc2Error::InvalidState {
                        current: self.state,
                        attempted: "bulk_in",
                    });
                }
                self.write_tx_fifo(ep, &data, bank);
                Ok(vec![Dwc2Action::WriteTxFifo { ep, data }])
            }
            GadgetRequest::InterruptIn { ep, data } => {
                if ep >= MAX_ENDPOINTS {
                    return Err(Dwc2Error::InvalidEndpoint { ep });
                }
                self.write_tx_fifo(ep, &data, bank);
                Ok(vec![Dwc2Action::WriteTxFifo { ep, data }])
            }
        }
    }

    /// Write data to EP0 IN (control IN response).
    fn write_ep0_in(&self, bank: &mut impl RegisterBank, data: &[u8]) {
        // Program transfer size.
        let pktcnt: u32 = if data.is_empty() { 1 } else { 1 };
        bank.write(dieptsiz(0), (pktcnt << 19) | data.len() as u32);

        // Enable endpoint.
        bank.write(diepctl(0), EPCTL_EPENA | EPCTL_CNAK);

        // Write data to FIFO.
        self.write_fifo_words(0, data, bank);
    }

    /// Write data to an IN endpoint's TX FIFO.
    fn write_tx_fifo(&self, ep: u8, data: &[u8], bank: &mut impl RegisterBank) {
        let pktcnt: u32 = if data.is_empty() {
            1
        } else {
            ((data.len() as u32) + 511) / 512
        };
        bank.write(dieptsiz(ep), (pktcnt << 19) | data.len() as u32);
        bank.write(diepctl(ep), bank.read(diepctl(ep)) | EPCTL_EPENA | EPCTL_CNAK);
        self.write_fifo_words(ep, data, bank);
    }

    /// Write raw bytes to an endpoint's FIFO as 32-bit words.
    fn write_fifo_words(&self, ep: u8, data: &[u8], bank: &mut impl RegisterBank) {
        let fifo_addr = ep_fifo(ep);
        let mut offset = 0;
        while offset < data.len() {
            let remaining = data.len() - offset;
            let mut word = [0u8; 4];
            let take = remaining.min(4);
            word[..take].copy_from_slice(&data[offset..offset + take]);
            bank.write(fifo_addr, u32::from_le_bytes(word));
            offset += 4;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::register_bank::mock::MockRegisterBank;
    use alloc::vec;

    fn init_controller() -> (Dwc2Controller, MockRegisterBank) {
        let mut bank = MockRegisterBank::new();
        // Pre-configure DCTL read for soft-connect (clear SFTDISCON).
        bank.on_read(DCTL, vec![DCTL_SFTDISCON]);
        let (ctrl, _actions) = Dwc2Controller::init(&mut bank).expect("init must succeed");
        // Clear writes from init so tests only see their own writes.
        bank.writes.clear();
        (ctrl, bank)
    }

    #[test]
    fn init_forces_device_mode() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(GUSBCFG, vec![0]);
        bank.on_read(DCTL, vec![DCTL_SFTDISCON]);
        let (ctrl, _actions) = Dwc2Controller::init(&mut bank).expect("init must succeed");

        assert_eq!(ctrl.state(), UsbDeviceState::Default);
        assert_eq!(ctrl.speed(), DeviceSpeed::HighSpeed);

        // Verify GUSBCFG had force-device bit set.
        let gusbcfg_write = bank.writes.iter().find(|(off, _)| *off == GUSBCFG);
        assert!(gusbcfg_write.is_some());
        let (_, val) = gusbcfg_write.unwrap();
        assert!(val & GUSBCFG_FORCE_DEV != 0, "Force Device bit must be set");
    }

    #[test]
    fn init_configures_fifos() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(DCTL, vec![DCTL_SFTDISCON]);
        let (_ctrl, _actions) = Dwc2Controller::init(&mut bank).expect("init must succeed");

        // Verify GRXFSIZ was written.
        assert!(
            bank.writes.iter().any(|(off, val)| *off == GRXFSIZ && *val == RX_FIFO_WORDS),
            "RX FIFO size must be programmed"
        );
        // Verify GNPTXFSIZ was written.
        assert!(
            bank.writes.iter().any(|(off, _)| *off == GNPTXFSIZ),
            "EP0 TX FIFO must be programmed"
        );
    }

    #[test]
    fn init_soft_connects() {
        let mut bank = MockRegisterBank::new();
        bank.on_read(DCTL, vec![DCTL_SFTDISCON]);
        let (_ctrl, _actions) = Dwc2Controller::init(&mut bank).expect("init must succeed");

        // Verify DCTL was written with SFTDISCON cleared.
        let dctl_write = bank.writes.iter().rev().find(|(off, _)| *off == DCTL);
        assert!(dctl_write.is_some());
        let (_, val) = dctl_write.unwrap();
        assert!(val & DCTL_SFTDISCON == 0, "SFTDISCON must be cleared");
    }

    #[test]
    fn bus_reset_returns_to_default() {
        let (mut ctrl, mut bank) = init_controller();
        // Simulate: first addressed, then reset.
        ctrl.state = UsbDeviceState::Address;
        ctrl.address = 5;

        bank.on_read(DCFG, vec![dcfg_dad(5)]);
        let events = ctrl
            .handle_event(Dwc2Event::BusReset, &mut bank)
            .expect("bus reset must succeed");

        assert_eq!(ctrl.state(), UsbDeviceState::Default);
        assert_eq!(ctrl.address, 0);
        assert_eq!(events, vec![GadgetEvent::Reset]);

        // Verify DCFG address was cleared.
        let dcfg_write = bank.writes.iter().find(|(off, _)| *off == DCFG);
        assert!(dcfg_write.is_some());
        let (_, val) = dcfg_write.unwrap();
        assert_eq!(val & DCFG_DAD_MASK, 0, "Device address must be cleared");
    }

    #[test]
    fn enumeration_done_sets_speed() {
        let (mut ctrl, mut bank) = init_controller();
        let events = ctrl
            .handle_event(
                Dwc2Event::EnumerationDone {
                    speed: DeviceSpeed::FullSpeed,
                },
                &mut bank,
            )
            .expect("enum done must succeed");

        assert_eq!(ctrl.speed(), DeviceSpeed::FullSpeed);
        assert!(events.is_empty());
    }

    #[test]
    fn set_address_programs_dcfg() {
        let (mut ctrl, mut bank) = init_controller();
        // SET_ADDRESS(5): bmRequestType=0x00, bRequest=0x05, wValue=5
        let setup = [0x00, 0x05, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];

        bank.on_read(DCFG, vec![0]);
        let events = ctrl
            .handle_event(Dwc2Event::SetupReceived { data: setup }, &mut bank)
            .expect("setup must succeed");

        assert_eq!(ctrl.state(), UsbDeviceState::Address);
        assert_eq!(ctrl.address, 5);
        assert!(events.is_empty()); // SET_ADDRESS is handled internally

        // Verify DCFG has address = 5.
        let dcfg_write = bank.writes.iter().find(|(off, _)| *off == DCFG);
        assert!(dcfg_write.is_some());
        let (_, val) = dcfg_write.unwrap();
        assert_eq!(val & DCFG_DAD_MASK, dcfg_dad(5));
    }

    #[test]
    fn set_configuration_enables_endpoints() {
        let (mut ctrl, mut bank) = init_controller();
        ctrl.state = UsbDeviceState::Address;

        // SET_CONFIGURATION(1): bmRequestType=0x00, bRequest=0x09, wValue=1
        let setup = [0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        let events = ctrl
            .handle_event(Dwc2Event::SetupReceived { data: setup }, &mut bank)
            .expect("setup must succeed");

        assert_eq!(ctrl.state(), UsbDeviceState::Configured);
        assert_eq!(events, vec![GadgetEvent::Configured]);

        // Verify EP1 IN (bulk) was enabled.
        assert!(
            bank.writes.iter().any(|(off, val)| *off == diepctl(1) && val & EPCTL_USBAEP != 0),
            "EP1 IN must be activated"
        );
        // Verify EP2 OUT (bulk) was enabled.
        assert!(
            bank.writes.iter().any(|(off, val)| *off == doepctl(2) && val & EPCTL_USBAEP != 0),
            "EP2 OUT must be activated"
        );
        // Verify EP3 IN (interrupt) was enabled.
        assert!(
            bank.writes.iter().any(|(off, val)| *off == diepctl(3) && val & EPCTL_USBAEP != 0),
            "EP3 IN must be activated"
        );
    }

    #[test]
    fn class_request_forwarded_to_gadget() {
        let (mut ctrl, mut bank) = init_controller();
        // Class request: bmRequestType=0x21 (class, interface, host-to-device)
        let setup = [0x21, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let events = ctrl
            .handle_event(Dwc2Event::SetupReceived { data: setup }, &mut bank)
            .expect("setup must succeed");

        assert_eq!(events, vec![GadgetEvent::SetupClassRequest { setup }]);
    }

    #[test]
    fn unsupported_standard_request_stalls() {
        let (mut ctrl, mut bank) = init_controller();
        // SYNCH_FRAME (0x0C) — not supported.
        let setup = [0x82, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00];
        let _events = ctrl
            .handle_event(Dwc2Event::SetupReceived { data: setup }, &mut bank)
            .expect("setup must succeed");

        // Verify EP0 was stalled.
        assert!(
            bank.writes
                .iter()
                .any(|(off, val)| *off == diepctl(0) && val & EPCTL_STALL != 0),
            "EP0 must be stalled on unsupported request"
        );
    }

    #[test]
    fn get_descriptor_serves_device_desc() {
        let (mut ctrl, mut bank) = init_controller();
        let device_desc = vec![
            18, 0x01, 0x00, 0x02, 0x02, 0x00, 0x00, 64,
            0x09, 0x12, 0x01, 0x00, 0x00, 0x01, 0x01, 0x02,
            0x03, 0x01,
        ];
        ctrl.set_descriptors(device_desc.clone(), vec![], vec![]);

        // GET_DESCRIPTOR(Device, index=0, wLength=18)
        let setup = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 18, 0x00];
        let events = ctrl
            .handle_event(Dwc2Event::SetupReceived { data: setup }, &mut bank)
            .expect("setup must succeed");

        // Descriptor served internally — no gadget events.
        assert!(events.is_empty());

        // Verify data was written to EP0 IN FIFO.
        let fifo_writes: Vec<_> = bank.writes.iter().filter(|(off, _)| *off == ep_fifo(0)).collect();
        assert!(!fifo_writes.is_empty(), "Device descriptor must be written to EP0 FIFO");
    }

    #[test]
    fn rx_fifo_bulk_out_produces_gadget_event() {
        let (mut ctrl, mut bank) = init_controller();
        ctrl.state = UsbDeviceState::Configured;

        // Simulate GRXSTSP: EP2, 60 bytes, OUT_DATA (status 2)
        let grxstsp_val: u32 = 2 | (60 << 4) | ((PKTSTS_OUT_DATA as u32) << 17);
        bank.on_read(GRXSTSP, vec![grxstsp_val]);

        // 60 bytes = 15 words in the EP2 FIFO.
        for i in 0..15u32 {
            bank.on_read(ep_fifo(2), vec![i]);
        }

        let events = ctrl
            .handle_event(Dwc2Event::RxFifoNonEmpty, &mut bank)
            .expect("rx fifo must succeed");

        assert_eq!(events.len(), 1);
        match &events[0] {
            GadgetEvent::BulkOut { ep, data } => {
                assert_eq!(*ep, 2);
                assert_eq!(data.len(), 60);
            }
            other => panic!("expected BulkOut, got {:?}", other),
        }
    }

    #[test]
    fn submit_bulk_in_before_configured_fails() {
        let (mut ctrl, mut bank) = init_controller();
        // State is Default — bulk transfers should fail.
        let result = ctrl.submit_request(
            GadgetRequest::BulkIn {
                ep: 1,
                data: vec![0xAA; 64],
            },
            &mut bank,
        );
        assert_eq!(
            result,
            Err(Dwc2Error::InvalidState {
                current: UsbDeviceState::Default,
                attempted: "bulk_in",
            })
        );
    }

    #[test]
    fn submit_bulk_in_writes_tx_fifo() {
        let (mut ctrl, mut bank) = init_controller();
        ctrl.state = UsbDeviceState::Configured;
        bank.on_read(diepctl(1), vec![0]); // For read-modify-write

        let data = vec![0xBB; 60];
        let actions = ctrl
            .submit_request(GadgetRequest::BulkIn { ep: 1, data: data.clone() }, &mut bank)
            .expect("bulk in must succeed");

        assert_eq!(actions.len(), 1);
        assert_eq!(
            actions[0],
            Dwc2Action::WriteTxFifo {
                ep: 1,
                data: data,
            }
        );
    }

    #[test]
    fn submit_control_stall() {
        let (mut ctrl, mut bank) = init_controller();
        let actions = ctrl
            .submit_request(GadgetRequest::ControlStall, &mut bank)
            .expect("control stall must succeed");

        assert_eq!(actions, vec![Dwc2Action::Stall { ep: 0 }]);
        assert!(
            bank.writes
                .iter()
                .any(|(off, val)| *off == diepctl(0) && val & EPCTL_STALL != 0),
            "EP0 must be stalled"
        );
    }

    #[test]
    fn suspend_and_resume_events() {
        let (mut ctrl, mut bank) = init_controller();

        let events = ctrl
            .handle_event(Dwc2Event::Suspend, &mut bank)
            .expect("suspend must succeed");
        assert_eq!(events, vec![GadgetEvent::Suspended]);

        let events = ctrl
            .handle_event(Dwc2Event::Resume, &mut bank)
            .expect("resume must succeed");
        assert_eq!(events, vec![GadgetEvent::Resumed]);
    }

    #[test]
    fn invalid_endpoint_rejected() {
        let (mut ctrl, mut bank) = init_controller();
        let result = ctrl.handle_event(
            Dwc2Event::InTransferComplete { ep: 5 },
            &mut bank,
        );
        assert_eq!(result, Err(Dwc2Error::InvalidEndpoint { ep: 5 }));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p harmony-unikernel --lib drivers::dwc2 -- --nocapture`
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc2/mod.rs
git commit -m "feat(usb): implement DWC2 controller state machine"
```

---

### Task 4: ECM Gadget Descriptor Builders

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/ecm_gadget/descriptor.rs` (replace stub)

- [ ] **Step 1: Write failing test for descriptor roundtrip with host parser**

Replace `crates/harmony-unikernel/src/drivers/ecm_gadget/descriptor.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! CDC-ECM descriptor builders for USB device mode.
//!
//! These builders construct the exact byte sequences a USB host expects
//! during enumeration. The device, config, and string descriptors are
//! pre-built at init and served by the [`Dwc2Controller`] during
//! GET_DESCRIPTOR requests.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

// ── VID/PID ─────────────────────────────────────────────────────────────────

/// pid.codes VID for open-source hardware (free for development).
const VID: u16 = 0x1209;
/// Test PID — reserved for prototyping on pid.codes.
const PID: u16 = 0x0001;

// ── String descriptor indices ───────────────────────────────────────────────

/// Index 0: USB Language ID (English).
const STRING_IDX_LANGID: u8 = 0;
/// Index 1: Manufacturer string.
const STRING_IDX_MANUFACTURER: u8 = 1;
/// Index 2: Product string.
const STRING_IDX_PRODUCT: u8 = 2;
/// Index 3: Serial number string.
const STRING_IDX_SERIAL: u8 = 3;
/// Index 4: MAC address string (12 hex ASCII chars).
const STRING_IDX_MAC: u8 = 4;

// ── Endpoint addresses ──────────────────────────────────────────────────────

/// Bulk IN endpoint (EP1, direction IN = 0x81).
const EP_BULK_IN: u8 = 0x81;
/// Bulk OUT endpoint (EP2, direction OUT = 0x02).
const EP_BULK_OUT: u8 = 0x02;
/// Interrupt IN endpoint (EP3, direction IN = 0x83).
const EP_INTERRUPT_IN: u8 = 0x83;

// ── Builder functions ───────────────────────────────────────────────────────

/// Build the 18-byte USB Device Descriptor.
pub fn build_device_descriptor() -> Vec<u8> {
    vec![
        18,   // bLength
        0x01, // bDescriptorType: DEVICE
        0x00, 0x02, // bcdUSB: USB 2.0
        0x02, // bDeviceClass: CDC
        0x00, // bDeviceSubClass
        0x00, // bDeviceProtocol
        64,   // bMaxPacketSize0
        (VID & 0xFF) as u8, (VID >> 8) as u8,
        (PID & 0xFF) as u8, (PID >> 8) as u8,
        0x00, 0x01, // bcdDevice: 1.00
        STRING_IDX_MANUFACTURER, // iManufacturer
        STRING_IDX_PRODUCT,      // iProduct
        STRING_IDX_SERIAL,       // iSerialNumber
        1,    // bNumConfigurations
    ]
}

/// Build the complete Configuration Descriptor chain.
///
/// Includes: config header + comm interface + CDC functional descriptors +
/// interrupt EP + data interface alt0 + data interface alt1 + bulk endpoints.
///
/// Total: 80 bytes (same layout as the host driver's test descriptor).
pub fn build_config_descriptor() -> Vec<u8> {
    let total_length: u16 = 80;
    let mut v = Vec::with_capacity(total_length as usize);

    // ── Configuration descriptor (9 bytes) ────────────────────────
    v.extend_from_slice(&[
        9,    // bLength
        0x02, // bDescriptorType: CONFIGURATION
        (total_length & 0xFF) as u8, (total_length >> 8) as u8,
        2,    // bNumInterfaces
        1,    // bConfigurationValue
        0,    // iConfiguration
        0xC0, // bmAttributes: self-powered
        50,   // bMaxPower: 100 mA
    ]);

    // ── Communication Interface (9 bytes) ─────────────────────────
    v.extend_from_slice(&[
        9,    // bLength
        0x04, // bDescriptorType: INTERFACE
        0,    // bInterfaceNumber (control)
        0,    // bAlternateSetting
        1,    // bNumEndpoints (interrupt IN)
        0x02, // bInterfaceClass: CDC
        0x06, // bInterfaceSubClass: ECM
        0x00, // bInterfaceProtocol
        0,    // iInterface
    ]);

    // ── Header Functional Descriptor (5 bytes) ────────────────────
    v.extend_from_slice(&[
        5,    // bLength
        0x24, // bDescriptorType: CS_INTERFACE
        0x00, // bDescriptorSubType: Header
        0x10, 0x01, // bcdCDC: 1.10
    ]);

    // ── Union Functional Descriptor (5 bytes) ─────────────────────
    v.extend_from_slice(&[
        5,    // bLength
        0x24, // bDescriptorType: CS_INTERFACE
        0x06, // bDescriptorSubType: Union
        0,    // bControlInterface
        1,    // bSubordinateInterface0 (data)
    ]);

    // ── Ethernet Networking Functional Descriptor (13 bytes) ──────
    v.extend_from_slice(&[
        13,   // bLength
        0x24, // bDescriptorType: CS_INTERFACE
        0x0F, // bDescriptorSubType: Ethernet Networking
        STRING_IDX_MAC, // iMACAddress
        0x00, 0x00, 0x00, 0x00, // bmEthernetStatistics
        0xEA, 0x05, // wMaxSegmentSize: 1514
        0x00, 0x00, // wNumberMCFilters
        0,    // bNumberPowerFilters
    ]);

    // ── Interrupt IN Endpoint (7 bytes) ───────────────────────────
    v.extend_from_slice(&[
        7,    // bLength
        0x05, // bDescriptorType: ENDPOINT
        EP_INTERRUPT_IN,
        0x03, // bmAttributes: Interrupt
        16, 0x00, // wMaxPacketSize: 16
        11,   // bInterval
    ]);

    // ── Data Interface alt 0 (9 bytes, 0 endpoints) ───────────────
    v.extend_from_slice(&[
        9,    // bLength
        0x04, // bDescriptorType: INTERFACE
        1,    // bInterfaceNumber (data)
        0,    // bAlternateSetting
        0,    // bNumEndpoints
        0x0A, // bInterfaceClass: CDC Data
        0x00, // bInterfaceSubClass
        0x00, // bInterfaceProtocol
        0,    // iInterface
    ]);

    // ── Data Interface alt 1 (9 bytes, 2 endpoints) ───────────────
    v.extend_from_slice(&[
        9,    // bLength
        0x04, // bDescriptorType: INTERFACE
        1,    // bInterfaceNumber (data)
        1,    // bAlternateSetting
        2,    // bNumEndpoints
        0x0A, // bInterfaceClass: CDC Data
        0x00, // bInterfaceSubClass
        0x00, // bInterfaceProtocol
        0,    // iInterface
    ]);

    // ── Bulk IN Endpoint (7 bytes) ────────────────────────────────
    v.extend_from_slice(&[
        7,    // bLength
        0x05, // bDescriptorType: ENDPOINT
        EP_BULK_IN,
        0x02, // bmAttributes: Bulk
        0x00, 0x02, // wMaxPacketSize: 512
        0,    // bInterval
    ]);

    // ── Bulk OUT Endpoint (7 bytes) ───────────────────────────────
    v.extend_from_slice(&[
        7,    // bLength
        0x05, // bDescriptorType: ENDPOINT
        EP_BULK_OUT,
        0x02, // bmAttributes: Bulk
        0x00, 0x02, // wMaxPacketSize: 512
        0,    // bInterval
    ]);

    assert_eq!(v.len(), total_length as usize);
    v
}

/// Build a USB String Descriptor from an ASCII string.
///
/// Format: [bLength, 0x03, char0_lo, 0x00, char1_lo, 0x00, ...]
fn build_string_descriptor(s: &str) -> Vec<u8> {
    let chars: &[u8] = s.as_bytes();
    let b_length = 2 + chars.len() * 2;
    let mut v = Vec::with_capacity(b_length);
    v.push(b_length as u8);
    v.push(0x03); // bDescriptorType: STRING
    for &c in chars {
        v.push(c);
        v.push(0x00);
    }
    v
}

/// Build all string descriptors for the ECM gadget.
///
/// Index 0 = Language ID, 1 = Manufacturer, 2 = Product, 3 = Serial, 4 = MAC.
pub fn build_string_descriptors(mac: &[u8; 6]) -> Vec<Vec<u8>> {
    // Index 0: Language ID descriptor (English US = 0x0409).
    let langid = vec![4, 0x03, 0x09, 0x04];

    // Index 1: Manufacturer.
    let manufacturer = build_string_descriptor("Harmony");

    // Index 2: Product.
    let product = build_string_descriptor("Harmony ECM Gadget");

    // Index 3: Serial number (use MAC as serial for uniqueness).
    let serial_str = mac_to_hex_string(mac);
    let serial = build_string_descriptor(&serial_str);

    // Index 4: MAC address (12 hex chars, uppercase).
    let mac_str = mac_to_hex_string(mac);
    let mac_desc = build_string_descriptor(&mac_str);

    vec![langid, manufacturer, product, serial, mac_desc]
}

/// Convert a 6-byte MAC address to a 12-character uppercase hex string.
fn mac_to_hex_string(mac: &[u8; 6]) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::with_capacity(12);
    for &b in mac {
        let _ = write!(s, "{:02X}", b);
    }
    s
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn device_descriptor_length_and_class() {
        let desc = build_device_descriptor();
        assert_eq!(desc.len(), 18);
        assert_eq!(desc[0], 18); // bLength
        assert_eq!(desc[1], 0x01); // bDescriptorType
        assert_eq!(desc[4], 0x02); // bDeviceClass: CDC
    }

    #[test]
    fn device_descriptor_vid_pid() {
        let desc = build_device_descriptor();
        let vid = u16::from_le_bytes([desc[8], desc[9]]);
        let pid = u16::from_le_bytes([desc[10], desc[11]]);
        assert_eq!(vid, 0x1209);
        assert_eq!(pid, 0x0001);
    }

    #[test]
    fn config_descriptor_total_length() {
        let desc = build_config_descriptor();
        let total = u16::from_le_bytes([desc[2], desc[3]]) as usize;
        assert_eq!(total, desc.len());
        assert_eq!(desc.len(), 80);
    }

    #[test]
    fn config_descriptor_ecm_subclass() {
        let desc = build_config_descriptor();
        // Comm interface at offset 9: bInterfaceSubClass at offset 9+6 = 15.
        assert_eq!(desc[15], 0x06, "Must be ECM subclass");
    }

    #[test]
    fn cdc_functional_descriptors_present() {
        let desc = build_config_descriptor();
        // Walk descriptors looking for CS_INTERFACE (0x24).
        let mut pos = 0;
        let mut subtypes = Vec::new();
        while pos < desc.len() {
            let b_len = desc[pos] as usize;
            if b_len < 2 || pos + b_len > desc.len() {
                break;
            }
            if desc[pos + 1] == 0x24 && b_len >= 3 {
                subtypes.push(desc[pos + 2]);
            }
            pos += b_len;
        }
        assert!(subtypes.contains(&0x00), "Header FD missing");
        assert!(subtypes.contains(&0x06), "Union FD missing");
        assert!(subtypes.contains(&0x0F), "Ethernet FD missing");
    }

    #[test]
    fn string_descriptor_mac_format() {
        let mac = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let descs = build_string_descriptors(&mac);

        // Index 4 = MAC string.
        let mac_desc = &descs[4];
        assert_eq!(mac_desc[0] as usize, mac_desc.len()); // bLength matches
        assert_eq!(mac_desc[1], 0x03); // bDescriptorType: STRING

        // Extract ASCII characters (low bytes of UTF-16LE pairs).
        let chars: Vec<u8> = (0..12).map(|i| mac_desc[2 + i * 2]).collect();
        assert_eq!(
            core::str::from_utf8(&chars).unwrap(),
            "DEADBEEFCAFE"
        );
    }

    #[test]
    fn string_descriptors_correct_count() {
        let mac = [0x00; 6];
        let descs = build_string_descriptors(&mac);
        assert_eq!(descs.len(), 5); // langid, manufacturer, product, serial, mac
    }

    #[test]
    fn langid_descriptor() {
        let mac = [0x00; 6];
        let descs = build_string_descriptors(&mac);
        let langid = &descs[0];
        assert_eq!(langid, &[4, 0x03, 0x09, 0x04]); // English US
    }

    #[test]
    fn roundtrip_with_host_parser() {
        // Feed our gadget-built config descriptor into the host-side parser
        // to verify both sides agree on the wire format.
        let config = build_config_descriptor();
        let result = crate::drivers::cdc_ethernet::descriptor::parse_cdc_config(&config)
            .expect("host parser must not fail");
        let info = result.expect("host parser must find CDC ECM interface");

        assert_eq!(info.protocol, crate::drivers::cdc_ethernet::CdcProtocol::Ecm);
        assert_eq!(info.control_interface, 0);
        assert_eq!(info.data_interface, 1);
        assert_eq!(info.data_alt_setting, 1);
        assert_eq!(info.bulk_in_ep.address, 0x81);
        assert_eq!(info.bulk_out_ep.address, 0x02);
        assert_eq!(info.interrupt_ep.address, 0x83);
        assert_eq!(info.mac_string_index, 4);
        assert_eq!(info.max_segment_size, 1514);
        assert_eq!(info.config_value, 1);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p harmony-unikernel --lib drivers::ecm_gadget -- --nocapture`
Expected: All tests PASS, including `roundtrip_with_host_parser`

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/ecm_gadget/descriptor.rs
git commit -m "feat(usb): add ECM gadget descriptor builders with host-parser roundtrip"
```

---

### Task 5: ECM Gadget Class Driver

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/ecm_gadget/mod.rs`

- [ ] **Step 1: Implement EcmGadget with tests**

Replace `crates/harmony-unikernel/src/drivers/ecm_gadget/mod.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! CDC-ECM USB gadget function.
//!
//! `EcmGadget` handles CDC-ECM class requests, builds CDC notifications,
//! and bridges bulk IN/OUT transfers to NetworkDevice-compatible methods.
//! It communicates with `Dwc2Controller` via `GadgetEvent`/`GadgetRequest`.

pub mod descriptor;

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use super::dwc2::types::{GadgetEvent, GadgetRequest};
use descriptor::{build_config_descriptor, build_device_descriptor, build_string_descriptors};

/// Maximum Ethernet frame size (standard MTU + header).
const MAX_FRAME_SIZE: usize = 1514;

/// CDC-ECM gadget function.
///
/// Handles class-specific SETUP requests, generates CDC notifications,
/// and provides NetworkDevice-compatible `poll_rx_frame` / `queue_tx_frame`
/// methods for Ring 2 integration.
pub struct EcmGadget {
    /// Device MAC address.
    mac: [u8; 6],
    /// Whether the device is in the Configured state.
    configured: bool,
    /// Received Ethernet frames (from host via bulk OUT).
    rx_queue: VecDeque<Vec<u8>>,
    /// Pending gadget requests to send to the controller.
    pending_requests: Vec<GadgetRequest>,
}

impl EcmGadget {
    /// Create a new ECM gadget with the given MAC address.
    ///
    /// Also returns the pre-built descriptors that should be registered
    /// with `Dwc2Controller::set_descriptors()`.
    pub fn new(mac: [u8; 6]) -> (Self, Vec<u8>, Vec<u8>, Vec<Vec<u8>>) {
        let device_desc = build_device_descriptor();
        let config_desc = build_config_descriptor();
        let string_descs = build_string_descriptors(&mac);

        let gadget = EcmGadget {
            mac,
            configured: false,
            rx_queue: VecDeque::new(),
            pending_requests: Vec::new(),
        };

        (gadget, device_desc, config_desc, string_descs)
    }

    /// Process a gadget event from the DWC2 controller.
    ///
    /// Returns a list of requests to send back to the controller.
    pub fn handle_event(&mut self, event: GadgetEvent) -> Vec<GadgetRequest> {
        match event {
            GadgetEvent::Reset => {
                self.configured = false;
                self.rx_queue.clear();
                self.pending_requests.clear();
                // Send NETWORK_CONNECTION(disconnected) notification.
                vec![GadgetRequest::InterruptIn {
                    ep: 3,
                    data: build_network_connection(false),
                }]
            }
            GadgetEvent::Configured => {
                self.configured = true;
                // Send NETWORK_CONNECTION(connected) + SPEED_CHANGE notifications.
                vec![
                    GadgetRequest::InterruptIn {
                        ep: 3,
                        data: build_network_connection(true),
                    },
                    GadgetRequest::InterruptIn {
                        ep: 3,
                        data: build_speed_change(480_000_000, 480_000_000),
                    },
                ]
            }
            GadgetEvent::SetupClassRequest { setup } => {
                self.handle_class_request(setup)
            }
            GadgetEvent::GetDescriptor { .. } => {
                // All descriptors are pre-registered with the controller.
                // If we get here, the descriptor wasn't found — stall.
                vec![GadgetRequest::ControlStall]
            }
            GadgetEvent::BulkOut { ep: _, data } => {
                if !data.is_empty() && data.len() <= MAX_FRAME_SIZE {
                    self.rx_queue.push_back(data);
                }
                vec![]
            }
            GadgetEvent::BulkInComplete { .. } => {
                // Endpoint ready for next frame — nothing to do unless
                // we have pending frames (handled by queue_tx_frame).
                vec![]
            }
            GadgetEvent::Suspended => {
                vec![GadgetRequest::InterruptIn {
                    ep: 3,
                    data: build_network_connection(false),
                }]
            }
            GadgetEvent::Resumed => {
                if self.configured {
                    vec![GadgetRequest::InterruptIn {
                        ep: 3,
                        data: build_network_connection(true),
                    }]
                } else {
                    vec![]
                }
            }
        }
    }

    /// Handle a CDC class-specific SETUP request.
    fn handle_class_request(&self, setup: [u8; 8]) -> Vec<GadgetRequest> {
        let b_request = setup[1];
        match b_request {
            // SET_ETHERNET_PACKET_FILTER (0x43)
            0x43 => vec![GadgetRequest::ControlAck],
            // Unknown class request — stall.
            _ => vec![GadgetRequest::ControlStall],
        }
    }

    // ── NetworkDevice-compatible methods ─────────────────────────────────────

    /// Pop the next received Ethernet frame into `out`.
    ///
    /// Returns the frame length, or `None` if the queue is empty.
    /// Oversized frames are dropped to prevent head-of-line blocking.
    pub fn poll_rx_frame(&mut self, out: &mut [u8]) -> Option<usize> {
        let frame = self.rx_queue.front()?;
        if frame.len() > out.len() {
            self.rx_queue.pop_front();
            return None;
        }
        let frame = self.rx_queue.pop_front().unwrap();
        out[..frame.len()].copy_from_slice(&frame);
        Some(frame.len())
    }

    /// Queue an Ethernet frame for transmission to the host.
    ///
    /// Returns `true` on success. The resulting `GadgetRequest::BulkIn` is
    /// buffered in `pending_requests`; call `drain_pending_requests()` to
    /// retrieve it.
    pub fn queue_tx_frame(&mut self, frame: &[u8]) -> bool {
        if !self.configured || frame.is_empty() || frame.len() > MAX_FRAME_SIZE {
            return false;
        }
        self.pending_requests.push(GadgetRequest::BulkIn {
            ep: 1,
            data: frame.to_vec(),
        });
        true
    }

    /// Drain pending requests accumulated by `queue_tx_frame`.
    pub fn drain_pending_requests(&mut self) -> Vec<GadgetRequest> {
        core::mem::take(&mut self.pending_requests)
    }

    /// Return the device MAC address.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Whether the USB link is up (Configured state).
    pub fn link_up(&self) -> bool {
        self.configured
    }
}

// ── CDC notification builders ───────────────────────────────────────────────

/// Build a NETWORK_CONNECTION notification (8 bytes).
fn build_network_connection(connected: bool) -> Vec<u8> {
    vec![
        0xA1, // bmRequestType: class, interface, device-to-host
        0x00, // bNotificationCode: NETWORK_CONNECTION
        if connected { 0x01 } else { 0x00 },
        0x00, // wValue high
        0x00, // wIndex low
        0x00, // wIndex high
        0x00, // wLength low
        0x00, // wLength high
    ]
}

/// Build a CONNECTION_SPEED_CHANGE notification (16 bytes).
fn build_speed_change(downstream: u32, upstream: u32) -> Vec<u8> {
    let mut v = vec![
        0xA1, // bmRequestType
        0x2A, // bNotificationCode: CONNECTION_SPEED_CHANGE
        0x00, 0x00, // wValue
        0x00, 0x00, // wIndex
        0x08, 0x00, // wLength = 8
    ];
    v.extend_from_slice(&downstream.to_le_bytes());
    v.extend_from_slice(&upstream.to_le_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gadget() -> EcmGadget {
        let mac = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let (gadget, _, _, _) = EcmGadget::new(mac);
        gadget
    }

    #[test]
    fn new_returns_descriptors() {
        let mac = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let (gadget, dev_desc, cfg_desc, str_descs) = EcmGadget::new(mac);
        assert_eq!(dev_desc.len(), 18);
        assert_eq!(cfg_desc.len(), 80);
        assert_eq!(str_descs.len(), 5);
        assert!(!gadget.configured);
        assert!(!gadget.link_up());
    }

    #[test]
    fn reset_clears_state() {
        let mut gadget = make_gadget();
        gadget.configured = true;
        gadget.rx_queue.push_back(vec![0xAA; 60]);

        let reqs = gadget.handle_event(GadgetEvent::Reset);
        assert!(!gadget.configured);
        assert!(gadget.rx_queue.is_empty());

        // Should send NETWORK_CONNECTION(disconnected).
        assert_eq!(reqs.len(), 1);
        match &reqs[0] {
            GadgetRequest::InterruptIn { ep, data } => {
                assert_eq!(*ep, 3);
                assert_eq!(data[1], 0x00); // NETWORK_CONNECTION
                assert_eq!(data[2], 0x00); // disconnected
            }
            other => panic!("expected InterruptIn, got {:?}", other),
        }
    }

    #[test]
    fn configured_sends_network_connection() {
        let mut gadget = make_gadget();
        let reqs = gadget.handle_event(GadgetEvent::Configured);

        assert!(gadget.configured);
        assert!(gadget.link_up());
        assert_eq!(reqs.len(), 2);

        // First: NETWORK_CONNECTION(connected)
        match &reqs[0] {
            GadgetRequest::InterruptIn { data, .. } => {
                assert_eq!(data[1], 0x00); // NETWORK_CONNECTION
                assert_eq!(data[2], 0x01); // connected
            }
            other => panic!("expected InterruptIn, got {:?}", other),
        }

        // Second: CONNECTION_SPEED_CHANGE
        match &reqs[1] {
            GadgetRequest::InterruptIn { data, .. } => {
                assert_eq!(data[1], 0x2A); // CONNECTION_SPEED_CHANGE
                let downstream = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
                assert_eq!(downstream, 480_000_000);
            }
            other => panic!("expected InterruptIn, got {:?}", other),
        }
    }

    #[test]
    fn class_request_packet_filter() {
        let gadget = make_gadget();
        // SET_ETHERNET_PACKET_FILTER
        let setup = [0x21, 0x43, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00];
        let reqs = gadget.handle_class_request(setup);
        assert_eq!(reqs, vec![GadgetRequest::ControlAck]);
    }

    #[test]
    fn unknown_class_request_stalled() {
        let gadget = make_gadget();
        let setup = [0x21, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let reqs = gadget.handle_class_request(setup);
        assert_eq!(reqs, vec![GadgetRequest::ControlStall]);
    }

    #[test]
    fn bulk_out_queues_frame() {
        let mut gadget = make_gadget();
        gadget.configured = true;

        let frame = vec![0xAA; 60];
        let reqs = gadget.handle_event(GadgetEvent::BulkOut {
            ep: 2,
            data: frame.clone(),
        });

        assert!(reqs.is_empty());
        assert_eq!(gadget.rx_queue.len(), 1);

        // poll_rx_frame should return the frame.
        let mut buf = [0u8; 1514];
        let len = gadget.poll_rx_frame(&mut buf).expect("frame must be available");
        assert_eq!(len, 60);
        assert_eq!(&buf[..len], &frame[..]);
    }

    #[test]
    fn push_rx_returns_bulk_in() {
        let mut gadget = make_gadget();
        gadget.configured = true;

        let frame = [0xBB; 100];
        assert!(gadget.queue_tx_frame(&frame));

        let reqs = gadget.drain_pending_requests();
        assert_eq!(reqs.len(), 1);
        match &reqs[0] {
            GadgetRequest::BulkIn { ep, data } => {
                assert_eq!(*ep, 1);
                assert_eq!(data.as_slice(), &frame);
            }
            other => panic!("expected BulkIn, got {:?}", other),
        }
    }

    #[test]
    fn push_rx_before_configured_fails() {
        let mut gadget = make_gadget();
        assert!(!gadget.configured);
        assert!(!gadget.queue_tx_frame(&[0xCC; 60]));
    }

    #[test]
    fn oversized_frame_rejected() {
        let mut gadget = make_gadget();
        gadget.configured = true;
        assert!(!gadget.queue_tx_frame(&vec![0u8; 1515]));
    }

    #[test]
    fn empty_frame_rejected() {
        let mut gadget = make_gadget();
        gadget.configured = true;
        assert!(!gadget.queue_tx_frame(&[]));
    }

    #[test]
    fn oversized_bulk_out_dropped() {
        let mut gadget = make_gadget();
        let reqs = gadget.handle_event(GadgetEvent::BulkOut {
            ep: 2,
            data: vec![0u8; 1515],
        });
        assert!(reqs.is_empty());
        assert!(gadget.rx_queue.is_empty());
    }

    #[test]
    fn mac_address() {
        let gadget = make_gadget();
        assert_eq!(gadget.mac(), [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
    }

    #[test]
    fn suspended_sends_disconnect_notification() {
        let mut gadget = make_gadget();
        gadget.configured = true;

        let reqs = gadget.handle_event(GadgetEvent::Suspended);
        assert_eq!(reqs.len(), 1);
        match &reqs[0] {
            GadgetRequest::InterruptIn { data, .. } => {
                assert_eq!(data[2], 0x00); // disconnected
            }
            other => panic!("expected InterruptIn, got {:?}", other),
        }
    }

    #[test]
    fn resumed_while_configured_sends_connect() {
        let mut gadget = make_gadget();
        gadget.configured = true;

        let reqs = gadget.handle_event(GadgetEvent::Resumed);
        assert_eq!(reqs.len(), 1);
        match &reqs[0] {
            GadgetRequest::InterruptIn { data, .. } => {
                assert_eq!(data[2], 0x01); // connected
            }
            other => panic!("expected InterruptIn, got {:?}", other),
        }
    }

    #[test]
    fn resumed_while_not_configured_no_notification() {
        let mut gadget = make_gadget();
        let reqs = gadget.handle_event(GadgetEvent::Resumed);
        assert!(reqs.is_empty());
    }

    #[test]
    fn get_descriptor_unknown_stalls() {
        let mut gadget = make_gadget();
        let reqs = gadget.handle_event(GadgetEvent::GetDescriptor {
            desc_type: 0xFF,
            desc_index: 0,
            max_len: 64,
        });
        assert_eq!(reqs, vec![GadgetRequest::ControlStall]);
    }

    #[test]
    fn poll_rx_drops_oversized_for_buffer() {
        let mut gadget = make_gadget();
        gadget.rx_queue.push_back(vec![0xAA; 128]);
        gadget.rx_queue.push_back(vec![0xBB; 32]);

        // Buffer too small for first frame — it should be dropped.
        let mut buf = [0u8; 64];
        assert!(gadget.poll_rx_frame(&mut buf).is_none());
        assert_eq!(gadget.rx_queue.len(), 1);

        // Second frame should now be accessible.
        let len = gadget.poll_rx_frame(&mut buf).expect("frame must be available");
        assert_eq!(len, 32);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p harmony-unikernel --lib drivers::ecm_gadget -- --nocapture`
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/ecm_gadget/mod.rs
git commit -m "feat(usb): implement ECM gadget class driver"
```

---

### Task 6: Ring 2 Adapter — EcmGadgetNetDevice

**Files:**
- Create: `crates/harmony-microkernel/src/ecm_gadget_net_device.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs`

- [ ] **Step 1: Implement the adapter with tests**

Create `crates/harmony-microkernel/src/ecm_gadget_net_device.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! [`NetworkDevice`] adapter for [`EcmGadget`].
//!
//! Wraps the ECM gadget's `poll_rx_frame` / `queue_tx_frame` methods
//! into the `NetworkDevice` trait, enabling `VirtioNetServer` reuse.

extern crate alloc;

use alloc::vec::Vec;

use harmony_unikernel::drivers::dwc2::types::GadgetRequest;
use harmony_unikernel::drivers::ecm_gadget::EcmGadget;

use crate::net_device::NetworkDevice;

/// [`NetworkDevice`] adapter wrapping an [`EcmGadget`].
///
/// Bridges the ECM gadget's sans-I/O methods to the `NetworkDevice` trait
/// so that `VirtioNetServer<EcmGadgetNetDevice>` exposes the USB gadget
/// as 9P `/dev/net/usb0/` with zero new Ring 2 code.
pub struct EcmGadgetNetDevice {
    gadget: EcmGadget,
}

impl EcmGadgetNetDevice {
    /// Wrap an [`EcmGadget`] as a [`NetworkDevice`].
    pub fn new(gadget: EcmGadget) -> Self {
        Self { gadget }
    }

    /// Access the underlying gadget for feeding events.
    pub fn gadget_mut(&mut self) -> &mut EcmGadget {
        &mut self.gadget
    }

    /// Drain pending USB requests from `push_rx` calls.
    pub fn drain_requests(&mut self) -> Vec<GadgetRequest> {
        self.gadget.drain_pending_requests()
    }
}

impl NetworkDevice for EcmGadgetNetDevice {
    fn poll_tx(&mut self, out: &mut [u8]) -> Option<usize> {
        self.gadget.poll_rx_frame(out)
    }

    fn push_rx(&mut self, frame: &[u8]) -> bool {
        self.gadget.queue_tx_frame(frame)
    }

    fn mac(&self) -> [u8; 6] {
        self.gadget.mac()
    }

    fn link_up(&self) -> bool {
        self.gadget.link_up()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio_net_server::VirtioNetServer;
    use harmony_unikernel::drivers::dwc2::types::GadgetEvent;

    fn make_gadget_net_device() -> EcmGadgetNetDevice {
        let mac = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let (gadget, _, _, _) = EcmGadget::new(mac);
        EcmGadgetNetDevice::new(gadget)
    }

    fn make_configured_device() -> EcmGadgetNetDevice {
        let mut dev = make_gadget_net_device();
        dev.gadget_mut().handle_event(GadgetEvent::Configured);
        dev
    }

    #[test]
    fn network_device_mac() {
        let dev = make_gadget_net_device();
        assert_eq!(dev.mac(), [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
    }

    #[test]
    fn network_device_link_up_default() {
        let dev = make_gadget_net_device();
        assert!(!dev.link_up());
    }

    #[test]
    fn network_device_link_up_after_configured() {
        let dev = make_configured_device();
        assert!(dev.link_up());
    }

    #[test]
    fn network_device_push_rx_and_drain() {
        let mut dev = make_configured_device();
        let frame = [0xAA; 64];
        assert!(dev.push_rx(&frame));

        let reqs = dev.drain_requests();
        assert_eq!(reqs.len(), 1);
        match &reqs[0] {
            GadgetRequest::BulkIn { ep, data } => {
                assert_eq!(*ep, 1);
                assert_eq!(data.as_slice(), &frame);
            }
            other => panic!("expected BulkIn, got {:?}", other),
        }
    }

    #[test]
    fn network_device_poll_tx_after_bulk_out() {
        let mut dev = make_configured_device();
        let frame = vec![0xBB; 60];
        dev.gadget_mut()
            .handle_event(GadgetEvent::BulkOut { ep: 2, data: frame.clone() });

        let mut buf = [0u8; 2048];
        let len = dev.poll_tx(&mut buf).expect("frame must be available");
        assert_eq!(len, 60);
        assert_eq!(&buf[..len], &frame[..]);
    }

    #[test]
    fn network_device_poll_tx_empty() {
        let mut dev = make_configured_device();
        let mut buf = [0u8; 2048];
        assert!(dev.poll_tx(&mut buf).is_none());
    }

    #[test]
    fn push_rx_before_configured_fails() {
        let mut dev = make_gadget_net_device();
        assert!(!dev.push_rx(&[0xCC; 60]));
    }

    #[test]
    fn virtio_net_server_type_check() {
        let dev = make_configured_device();
        let _server: VirtioNetServer<EcmGadgetNetDevice> = VirtioNetServer::new(dev, "usb0");
    }
}
```

- [ ] **Step 2: Add module to microkernel lib.rs**

Add after the `pub mod cdc_net_device;` line in `crates/harmony-microkernel/src/lib.rs`:

```rust
pub mod ecm_gadget_net_device;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p harmony-microkernel --lib ecm_gadget_net_device -- --nocapture`
Expected: All tests PASS, including `virtio_net_server_type_check`

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-microkernel/src/ecm_gadget_net_device.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(usb): add EcmGadgetNetDevice adapter for VirtioNetServer reuse"
```

---

### Task 7: Integration Test — Full Enumeration Flow

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc2/mod.rs` (add integration test)

- [ ] **Step 1: Add full enumeration flow integration test**

Add the following test to the `#[cfg(test)] mod tests` block in `crates/harmony-unikernel/src/drivers/dwc2/mod.rs`:

```rust
    #[test]
    fn full_enumeration_flow() {
        // Complete lifecycle: init -> bus reset -> enum done -> SET_ADDRESS ->
        // GET_DESCRIPTOR(Device) -> SET_CONFIGURATION -> bulk OUT -> poll_tx ->
        // push_rx -> bulk IN.
        use crate::drivers::ecm_gadget::EcmGadget;

        let mac = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let mut bank = MockRegisterBank::new();
        bank.on_read(DCTL, vec![DCTL_SFTDISCON, 0]); // init, then bus reset reads

        // 1. Init controller.
        let (mut ctrl, _) = Dwc2Controller::init(&mut bank).unwrap();

        // 2. Create gadget and register descriptors.
        let (mut gadget, dev_desc, cfg_desc, str_descs) = EcmGadget::new(mac);
        ctrl.set_descriptors(dev_desc.clone(), cfg_desc, str_descs);

        // 3. Bus reset.
        bank.writes.clear();
        bank.on_read(DCFG, vec![0]);
        let events = ctrl.handle_event(Dwc2Event::BusReset, &mut bank).unwrap();
        assert_eq!(events, vec![GadgetEvent::Reset]);
        let reqs = gadget.handle_event(GadgetEvent::Reset);
        // Gadget sends disconnect notification.
        assert_eq!(reqs.len(), 1);

        // 4. Enumeration done.
        let events = ctrl
            .handle_event(Dwc2Event::EnumerationDone { speed: DeviceSpeed::HighSpeed }, &mut bank)
            .unwrap();
        assert!(events.is_empty());

        // 5. SET_ADDRESS(7).
        bank.on_read(DCFG, vec![0]);
        let setup_addr = [0x00, 0x05, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00];
        let events = ctrl.handle_event(Dwc2Event::SetupReceived { data: setup_addr }, &mut bank).unwrap();
        assert!(events.is_empty());
        assert_eq!(ctrl.state(), UsbDeviceState::Address);

        // 6. GET_DESCRIPTOR(Device).
        bank.writes.clear();
        let setup_get_dev = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 18, 0x00];
        let events = ctrl.handle_event(Dwc2Event::SetupReceived { data: setup_get_dev }, &mut bank).unwrap();
        assert!(events.is_empty()); // Handled internally.
        // Verify device descriptor was written to EP0 FIFO.
        let fifo_writes: Vec<_> = bank.writes.iter().filter(|(off, _)| *off == ep_fifo(0)).collect();
        assert!(!fifo_writes.is_empty());

        // 7. SET_CONFIGURATION(1).
        bank.writes.clear();
        let setup_set_cfg = [0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        let events = ctrl.handle_event(Dwc2Event::SetupReceived { data: setup_set_cfg }, &mut bank).unwrap();
        assert_eq!(ctrl.state(), UsbDeviceState::Configured);
        // Forward Configured event to gadget.
        assert!(events.contains(&GadgetEvent::Configured));
        let reqs = gadget.handle_event(GadgetEvent::Configured);
        assert_eq!(reqs.len(), 2); // NETWORK_CONNECTION + SPEED_CHANGE

        // 8. Bulk OUT: host sends Ethernet frame.
        bank.writes.clear();
        let frame_data: Vec<u8> = (0..60).collect();
        let words = (frame_data.len() + 3) / 4;
        let grxstsp_val: u32 = 2 | ((frame_data.len() as u32) << 4) | ((PKTSTS_OUT_DATA as u32) << 17);
        bank.on_read(GRXSTSP, vec![grxstsp_val]);
        for i in 0..words {
            let offset = i * 4;
            let mut word_bytes = [0u8; 4];
            let take = (frame_data.len() - offset).min(4);
            word_bytes[..take].copy_from_slice(&frame_data[offset..offset + take]);
            bank.on_read(ep_fifo(2), vec![u32::from_le_bytes(word_bytes)]);
        }
        let events = ctrl.handle_event(Dwc2Event::RxFifoNonEmpty, &mut bank).unwrap();
        assert_eq!(events.len(), 1);
        let gadget_reqs = gadget.handle_event(events.into_iter().next().unwrap());
        assert!(gadget_reqs.is_empty()); // Frame queued internally.

        // 9. poll_tx — retrieve the frame.
        let mut buf = [0u8; 2048];
        let len = gadget.poll_rx_frame(&mut buf).unwrap();
        assert_eq!(len, 60);
        assert_eq!(&buf[..len], &frame_data[..]);

        // 10. push_rx — send a frame back to host.
        let tx_frame = vec![0xFF; 100];
        assert!(gadget.queue_tx_frame(&tx_frame));
        let pending = gadget.drain_pending_requests();
        assert_eq!(pending.len(), 1);

        // Submit to controller.
        bank.on_read(diepctl(1), vec![0]); // For read-modify-write.
        let actions = ctrl.submit_request(pending.into_iter().next().unwrap(), &mut bank).unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Dwc2Action::WriteTxFifo { ep, data } => {
                assert_eq!(*ep, 1);
                assert_eq!(data.as_slice(), &tx_frame[..]);
            }
            other => panic!("expected WriteTxFifo, got {:?}", other),
        }
    }
```

- [ ] **Step 2: Run all tests**

Run: `cargo test -p harmony-unikernel --lib drivers::dwc2 -- --nocapture`
Expected: All tests PASS including `full_enumeration_flow`

Then run the full workspace to verify no regressions:

Run: `cargo test --workspace`
Expected: All existing tests PASS

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc2/mod.rs
git commit -m "test(usb): add full enumeration flow integration test for DWC2 + ECM gadget"
```

---

### Task 8: Final Wiring and Workspace Verification

**Files:**
- None new — verify everything compiles and all tests pass.

- [ ] **Step 1: Run full workspace tests**

Run: `cargo test --workspace`
Expected: All tests PASS (existing + new)

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace`
Expected: No warnings in new code

- [ ] **Step 3: Run format check**

Run: `cargo +nightly fmt --all -- --check`
Expected: No formatting issues (fix any that appear with `cargo +nightly fmt --all`)

- [ ] **Step 4: Final commit if any fixes needed**

```bash
git add -A
git commit -m "fix(usb): address clippy/fmt issues in DWC2 gadget"
```

(Skip this commit if no fixes were needed.)
