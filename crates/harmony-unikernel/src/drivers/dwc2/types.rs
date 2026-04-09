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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dwc2Event {
    BusReset,
    EnumerationDone { speed: DeviceSpeed },
    SetupReceived { data: [u8; 8] },
    RxFifoNonEmpty,
    InTransferComplete { ep: u8 },
    OutTransferComplete { ep: u8 },
    Suspend,
    Resume,
}

// ── DWC2 hardware actions (controller → caller) ────────────────────────────

/// Actions the DWC2 controller returns for the caller to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dwc2Action {
    WriteRegister { offset: usize, value: u32 },
    WriteTxFifo { ep: u8, data: Vec<u8> },
    Stall { ep: u8 },
}

// ── Gadget interface (controller ↔ class driver) ────────────────────────────

/// Events from `Dwc2Controller` to the gadget class driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GadgetEvent {
    Reset,
    Configured,
    SetupClassRequest {
        setup: [u8; 8],
    },
    GetDescriptor {
        desc_type: u8,
        desc_index: u8,
        max_len: u16,
    },
    BulkOut {
        ep: u8,
        data: Vec<u8>,
    },
    BulkInComplete {
        ep: u8,
    },
    Suspended,
    Resumed,
}

/// Requests from the gadget class driver to `Dwc2Controller`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GadgetRequest {
    ControlIn { data: Vec<u8> },
    ControlAck,
    ControlStall,
    BulkIn { ep: u8, data: Vec<u8> },
    InterruptIn { ep: u8, data: Vec<u8> },
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Errors from DWC2 controller operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dwc2Error {
    FifoOverflow,
    InvalidState {
        current: UsbDeviceState,
        attempted: &'static str,
    },
    InvalidEndpoint {
        ep: u8,
    },
    TxFifoFull {
        ep: u8,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_state_default() {
        let state = UsbDeviceState::Default;
        assert_eq!(state, UsbDeviceState::Default);
        assert_ne!(state, UsbDeviceState::Address);
        assert_ne!(state, UsbDeviceState::Configured);
    }

    #[test]
    fn dwc2_event_variants_constructible() {
        let _reset = Dwc2Event::BusReset;
        let _done = Dwc2Event::EnumerationDone {
            speed: DeviceSpeed::HighSpeed,
        };
        let _setup = Dwc2Event::SetupReceived { data: [0u8; 8] };
        let _rx = Dwc2Event::RxFifoNonEmpty;
        let _in_complete = Dwc2Event::InTransferComplete { ep: 1 };
        let _out_complete = Dwc2Event::OutTransferComplete { ep: 2 };
        let _suspend = Dwc2Event::Suspend;
        let _resume = Dwc2Event::Resume;
    }

    #[test]
    fn dwc2_action_variants_constructible() {
        let _reg = Dwc2Action::WriteRegister {
            offset: 0x00,
            value: 0xDEAD_BEEF,
        };
        let _fifo = Dwc2Action::WriteTxFifo {
            ep: 1,
            data: alloc::vec![0u8; 64],
        };
        let _stall = Dwc2Action::Stall { ep: 0 };
    }

    #[test]
    fn gadget_event_variants_constructible() {
        let _reset = GadgetEvent::Reset;
        let _configured = GadgetEvent::Configured;
        let _setup = GadgetEvent::SetupClassRequest { setup: [0u8; 8] };
        let _get_desc = GadgetEvent::GetDescriptor {
            desc_type: 1,
            desc_index: 0,
            max_len: 255,
        };
        let _bulk_out = GadgetEvent::BulkOut {
            ep: 2,
            data: alloc::vec![0u8; 64],
        };
        let _bulk_in_complete = GadgetEvent::BulkInComplete { ep: 1 };
        let _suspended = GadgetEvent::Suspended;
        let _resumed = GadgetEvent::Resumed;
    }

    #[test]
    fn gadget_request_variants_constructible() {
        let _control_in = GadgetRequest::ControlIn {
            data: alloc::vec![0u8; 18],
        };
        let _ack = GadgetRequest::ControlAck;
        let _stall = GadgetRequest::ControlStall;
        let _bulk_in = GadgetRequest::BulkIn {
            ep: 1,
            data: alloc::vec![0u8; 64],
        };
        let _interrupt_in = GadgetRequest::InterruptIn {
            ep: 3,
            data: alloc::vec![0u8; 8],
        };
    }

    #[test]
    fn dwc2_error_variants_constructible() {
        let _overflow = Dwc2Error::FifoOverflow;
        let _invalid_state = Dwc2Error::InvalidState {
            current: UsbDeviceState::Default,
            attempted: "send_data",
        };
        let _invalid_ep = Dwc2Error::InvalidEndpoint { ep: 15 };
        let _tx_full = Dwc2Error::TxFifoFull { ep: 1 };
    }
}
