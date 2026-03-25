// SPDX-License-Identifier: GPL-2.0-or-later

//! Types for the DWC xHCI USB host controller driver.
//!
//! `XhciError`, `UsbSpeed`, `PortStatus`, `XhciAction`, `XhciEvent`, and `DeviceDescriptor` — shared across the module.

extern crate alloc;

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
    /// No transfer ring allocated for the requested endpoint.
    NoTransferRing,
    /// Received descriptor data is malformed or too short to parse.
    InvalidDescriptor,
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
    ///
    /// **Phase 2b note:** When interrupt-driven operation is enabled,
    /// the caller must OR bit 3 (EHB = Event Handler Busy) into the
    /// ERDP write value to acknowledge the interrupt and allow the
    /// next one to fire. In polling-only mode (Phase 2a), EHB is
    /// not relevant since interrupts are not enabled.
    UpdateDequeuePointer { phys: u64 },
    /// Write a 32-bit value to a register (offset from MMIO base).
    WriteRegister { offset: usize, value: u32 },
    /// Write a 64-bit value as LO/HI pair (offset_lo, offset_lo + 4).
    WriteRegister64 { offset_lo: usize, value: u64 },
    /// Write a DMA buffer to physical memory (e.g. Input Context or transfer data).
    WriteDma {
        phys: u64,
        data: alloc::vec::Vec<u8>,
    },
}

// ── Driver events ────────────────────────────────────────────────

/// Parsed events from the xHCI event ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XhciEvent {
    /// A command completed.
    CommandCompletion { slot_id: u8, completion_code: u8 },
    /// A port status changed (connect/disconnect).
    PortStatusChange { port_id: u8 },
    /// A transfer TRB completed (or errored).
    TransferEvent {
        /// Slot ID of the device that generated the event.
        slot_id: u8,
        /// Endpoint ID (DCI: 1 = EP0 OUT, 2 = EP0 IN, …).
        endpoint_id: u8,
        /// xHCI completion code (1 = Success, 13 = Short Packet, etc.).
        completion_code: u8,
        /// Number of bytes NOT transferred (residual length from TRB status).
        residual_length: u32,
        /// Physical address of the TRB that completed (for event-to-transfer matching).
        trb_pointer: u64,
    },
    /// Unrecognized event TRB type.
    Unknown { trb_type: u8 },
}

// ── Device Descriptor ─────────────────────────────────────────────

/// Parsed USB Device Descriptor (subset of bLength=18 standard fields).
///
/// All multi-byte fields are stored in host byte order after parsing
/// from the little-endian wire format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceDescriptor {
    /// USB specification version (BCD, e.g. 0x0200 = USB 2.0).
    pub usb_version: u16,
    /// Class code assigned by USB-IF (0 = class info in Interface Descriptors).
    pub device_class: u8,
    /// Subclass code (qualified by `device_class`).
    pub device_subclass: u8,
    /// Protocol code (qualified by `device_class` and `device_subclass`).
    pub device_protocol: u8,
    /// Maximum packet size for endpoint zero (8, 16, 32, or 64 bytes).
    pub max_packet_size_ep0: u8,
    /// Vendor ID assigned by USB-IF.
    pub vendor_id: u16,
    /// Product ID assigned by the manufacturer.
    pub product_id: u16,
    /// Device release number (BCD).
    pub device_version: u16,
    /// Number of possible configurations.
    pub num_configurations: u8,
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
        let _dma = XhciAction::WriteDma {
            phys: 0x4000,
            data: alloc::vec![0u8; 64],
        };
    }

    #[test]
    fn xhci_event_variants_constructible() {
        let _cmd = XhciEvent::CommandCompletion {
            slot_id: 1,
            completion_code: 1,
        };
        let _psc = XhciEvent::PortStatusChange { port_id: 3 };
        let _transfer = XhciEvent::TransferEvent {
            slot_id: 2,
            endpoint_id: 2,
            completion_code: 1,
            residual_length: 0,
            trb_pointer: 0x8000,
        };
        let _unk = XhciEvent::Unknown { trb_type: 99 };
    }

    #[test]
    fn xhci_error_variants_constructible() {
        let _no_ring = XhciError::NoTransferRing;
        let _bad_desc = XhciError::InvalidDescriptor;
    }

    #[test]
    fn device_descriptor_constructible() {
        let desc = DeviceDescriptor {
            usb_version: 0x0200,
            device_class: 0,
            device_subclass: 0,
            device_protocol: 0,
            max_packet_size_ep0: 64,
            vendor_id: 0x045E,
            product_id: 0x028E,
            device_version: 0x0100,
            num_configurations: 1,
        };
        assert_eq!(desc.usb_version, 0x0200);
        assert_eq!(desc.max_packet_size_ep0, 64);
        assert_eq!(desc.vendor_id, 0x045E);
        assert_eq!(desc.product_id, 0x028E);
        assert_eq!(desc.num_configurations, 1);
    }
}
