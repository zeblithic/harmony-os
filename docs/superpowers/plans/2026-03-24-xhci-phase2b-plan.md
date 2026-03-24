# xHCI Phase 2b: Enable Slot + Address Device + GET_DESCRIPTOR — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable device slots, assign USB addresses, and read device descriptors via control transfers — identifying connected USB devices by vendor ID, product ID, and device class.

**Architecture:** Extends the Phase 2a xHCI driver with device context builders, a TransferRing for EP0 control transfers, and four new driver methods (setup_dcbaa via extended setup_rings, enable_slot, address_device, get_device_descriptor). Sans-I/O: driver returns actions + byte arrays, caller handles DMA and register writes.

**Tech Stack:** Rust, `no_std` + `alloc`, `BTreeMap` for per-slot transfer rings, byte-array builders for xHCI contexts.

**Spec:** `docs/superpowers/specs/2026-03-24-xhci-phase2b-design.md`

---

### Task 1: New TRB type constants and transfer flags

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/trb.rs`

**Context:**
- Add command TRB types (Enable Slot, Address Device), transfer TRB types (Setup/Data/Status Stage), event TRB type (Transfer Event), transfer direction/control flags, and USB standard request constants.
- All constants only — no logic changes.

- [ ] **Step 1: Add constants**

Add to `trb.rs` after the existing TRB type constants:

```rust
// ── Command TRB types (Phase 2b) ────────────────────────────────
/// Enable Slot Command TRB — allocate a device slot.
pub const TRB_ENABLE_SLOT: u8 = 9;
/// Address Device Command TRB — assign USB address + configure device context.
pub const TRB_ADDRESS_DEVICE: u8 = 11;

// ── Transfer TRB types ──────────────────────────────────────────
/// Setup Stage TRB — carries the 8-byte USB SETUP packet.
pub const TRB_SETUP_STAGE: u8 = 2;
/// Data Stage TRB — carries/points to data payload.
pub const TRB_DATA_STAGE: u8 = 3;
/// Status Stage TRB — handshake completion.
pub const TRB_STATUS_STAGE: u8 = 4;

// ── Event TRB types (Phase 2b) ─────────────────────────────────
/// Transfer Event TRB — a transfer completed on an endpoint.
pub const TRB_TRANSFER_EVENT: u8 = 32;

// ── Transfer TRB control flags ──────────────────────────────────
/// Transfer Type = IN (device-to-host) for Setup Stage TRB.
pub const TRT_IN: u32 = 3 << 16;
/// Direction = IN for Data Stage TRB.
pub const DIR_IN: u32 = 1 << 16;
/// Immediate Data — Setup TRB contains the 8-byte SETUP packet inline.
pub const IDT: u32 = 1 << 6;
/// Interrupt On Completion — post event when this TRB completes.
pub const IOC: u32 = 1 << 5;

// ── USB standard request constants ──────────────────────────────
pub const USB_REQ_GET_DESCRIPTOR: u8 = 6;
pub const USB_DESC_DEVICE: u8 = 1;
pub const USB_DEVICE_DESCRIPTOR_SIZE: usize = 18;
```

- [ ] **Step 2: Verify compilation + clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/trb.rs
git commit -m "feat(usb): add Phase 2b TRB type constants and transfer flags

Enable Slot, Address Device, Setup/Data/Status Stage, Transfer Event,
direction flags (TRT_IN, DIR_IN, IDT, IOC), USB GET_DESCRIPTOR constants.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: New types — WriteDma, TransferEvent, DeviceDescriptor, error variants

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/types.rs`

**Context:**
- Add `WriteDma` to `XhciAction`, `TransferEvent` to `XhciEvent`, `DeviceDescriptor` struct, and new `XhciError` variants.
- `WriteDma { phys: u64, data: Vec<u8> }` — needs `extern crate alloc; use alloc::vec::Vec;` (check if already present).

- [ ] **Step 1: Add new types**

Add to `types.rs`:

In `XhciAction` enum, add variant:
```rust
    /// Write arbitrary bytes to DMA memory (e.g., DCBAA slot entries).
    WriteDma { phys: u64, data: alloc::vec::Vec<u8> },
```

In `XhciEvent` enum, add variant:
```rust
    /// A transfer completed on an endpoint.
    TransferEvent {
        slot_id: u8,
        endpoint_id: u8,
        completion_code: u8,
        transfer_length: u32,
    },
```

In `XhciError` enum, add variants:
```rust
    /// No transfer ring configured for this slot/endpoint.
    NoTransferRing,
    /// Device descriptor data is malformed or too short.
    InvalidDescriptor,
```

Add `DeviceDescriptor` struct:
```rust
/// Parsed USB Device Descriptor (18 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceDescriptor {
    /// USB specification version (BCD, e.g., 0x0200 = USB 2.0).
    pub usb_version: u16,
    /// Device class code (0 = per-interface, 0xFF = vendor-specific).
    pub device_class: u8,
    /// Device subclass code.
    pub device_subclass: u8,
    /// Device protocol code.
    pub device_protocol: u8,
    /// Maximum packet size for endpoint 0.
    pub max_packet_size_ep0: u8,
    /// Vendor ID.
    pub vendor_id: u16,
    /// Product ID.
    pub product_id: u16,
    /// Device release number (BCD).
    pub device_version: u16,
    /// Number of configurations.
    pub num_configurations: u8,
}
```

Add `extern crate alloc;` if not already present at top of `types.rs`.

- [ ] **Step 2: Update constructibility tests**

Update existing tests to cover new variants.

- [ ] **Step 3: Verify + clippy + nightly fmt**

Run: `cargo test -p harmony-unikernel dwc_usb::types && cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/types.rs
git commit -m "feat(usb): add WriteDma, TransferEvent, DeviceDescriptor, new error variants

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Device context builder (`context.rs`)

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/dwc_usb/context.rs`
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs` (add `pub mod context; pub use context::*;`)

**Context:**
- Pure functions that build byte arrays for xHCI data structures. No driver state, no RegisterBank.
- `build_input_context(port, speed, transfer_ring_phys) -> [u8; 96]`
- `max_packet_size_for_speed(speed) -> u16`
- `get_descriptor_setup_packet(desc_type, desc_index, length) -> [u8; 8]`
- `parse_device_descriptor(data) -> Result<DeviceDescriptor, XhciError>`

- [ ] **Step 1: Write failing tests**

Create `context.rs` with tests:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! xHCI device context builders and USB descriptor parsing.
//!
//! Pure functions that construct byte arrays for xHCI Input Contexts
//! and parse USB standard descriptors. No driver state needed.

use super::trb;
use super::types::{DeviceDescriptor, UsbSpeed, XhciError};

// Implementation goes here (step 3)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_context_add_flags() {
        let ctx = build_input_context(1, UsbSpeed::HighSpeed, 0x5000_0000);
        // Input Control Context DWord 1 (bytes 4..8): Add Context Flags = 0x03
        let flags = u32::from_le_bytes(ctx[4..8].try_into().unwrap());
        assert_eq!(flags, 0x03, "should add Slot (bit 0) + EP0 (bit 1)");
    }

    #[test]
    fn input_context_slot_speed() {
        // HighSpeed = speed ID 3
        let ctx = build_input_context(1, UsbSpeed::HighSpeed, 0x5000_0000);
        // Slot Context DWord 0 (bytes 32..36): speed in bits 23:20
        let dword0 = u32::from_le_bytes(ctx[32..36].try_into().unwrap());
        let speed = (dword0 >> 20) & 0xF;
        assert_eq!(speed, 3, "HighSpeed = speed ID 3");
    }

    #[test]
    fn input_context_slot_port() {
        let ctx = build_input_context(4, UsbSpeed::SuperSpeed, 0x5000_0000);
        // Slot Context DWord 1 (bytes 36..40): port in bits 23:16
        let dword1 = u32::from_le_bytes(ctx[36..40].try_into().unwrap());
        let port = (dword1 >> 16) & 0xFF;
        assert_eq!(port, 4);
    }

    #[test]
    fn input_context_ep0_max_packet_per_speed() {
        for (speed, expected) in [
            (UsbSpeed::LowSpeed, 8u16),
            (UsbSpeed::FullSpeed, 64),
            (UsbSpeed::HighSpeed, 64),
            (UsbSpeed::SuperSpeed, 512),
            (UsbSpeed::SuperSpeedPlus, 512),
            (UsbSpeed::Unknown(0), 8),
        ] {
            let ctx = build_input_context(1, speed, 0x5000_0000);
            // EP0 Context DWord 1 (bytes 68..72): max packet in bits 31:16
            let dword1 = u32::from_le_bytes(ctx[68..72].try_into().unwrap());
            let mps = (dword1 >> 16) & 0xFFFF;
            assert_eq!(mps, expected as u32, "speed {:?} should have MPS {}", speed, expected);
        }
    }

    #[test]
    fn input_context_ep0_tr_dequeue_pointer() {
        let ring_phys: u64 = 0x1_2345_6780; // must be 16-byte aligned
        let ctx = build_input_context(1, UsbSpeed::HighSpeed, ring_phys);
        // EP0 Context DWord 2-3 (bytes 72..80): TR Dequeue Pointer | DCS
        let lo = u32::from_le_bytes(ctx[72..76].try_into().unwrap());
        let hi = u32::from_le_bytes(ctx[76..80].try_into().unwrap());
        let ptr = ((hi as u64) << 32) | (lo as u64);
        assert_eq!(ptr, ring_phys | 1, "should set DCS bit (bit 0)");
    }

    #[test]
    fn get_descriptor_setup_packet_layout() {
        let pkt = get_descriptor_setup_packet(trb::USB_DESC_DEVICE, 0, 18);
        assert_eq!(pkt[0], 0x80, "bmRequestType: device-to-host, standard, device");
        assert_eq!(pkt[1], trb::USB_REQ_GET_DESCRIPTOR, "bRequest: GET_DESCRIPTOR");
        let wvalue = u16::from_le_bytes([pkt[2], pkt[3]]);
        assert_eq!(wvalue, (trb::USB_DESC_DEVICE as u16) << 8, "wValue: descriptor type << 8");
        let windex = u16::from_le_bytes([pkt[4], pkt[5]]);
        assert_eq!(windex, 0, "wIndex: 0");
        let wlength = u16::from_le_bytes([pkt[6], pkt[7]]);
        assert_eq!(wlength, 18, "wLength: 18");
    }

    #[test]
    fn parse_device_descriptor_valid() {
        // Standard 18-byte device descriptor for a hypothetical device
        let data: [u8; 18] = [
            18,   // bLength
            1,    // bDescriptorType = Device
            0x00, 0x02, // bcdUSB = 2.00
            0xFF, // bDeviceClass = vendor-specific
            0x01, // bDeviceSubClass
            0x02, // bDeviceProtocol
            64,   // bMaxPacketSize0
            0xAD, 0xDE, // idVendor = 0xDEAD
            0xEF, 0xBE, // idProduct = 0xBEEF
            0x00, 0x01, // bcdDevice = 1.00
            0,    // iManufacturer (string index, ignored)
            0,    // iProduct (string index, ignored)
            0,    // iSerialNumber (string index, ignored)
            2,    // bNumConfigurations
        ];
        let desc = parse_device_descriptor(&data).unwrap();
        assert_eq!(desc.usb_version, 0x0200);
        assert_eq!(desc.device_class, 0xFF);
        assert_eq!(desc.device_subclass, 0x01);
        assert_eq!(desc.device_protocol, 0x02);
        assert_eq!(desc.max_packet_size_ep0, 64);
        assert_eq!(desc.vendor_id, 0xDEAD);
        assert_eq!(desc.product_id, 0xBEEF);
        assert_eq!(desc.device_version, 0x0100);
        assert_eq!(desc.num_configurations, 2);
    }

    #[test]
    fn parse_device_descriptor_too_short() {
        let data = [0u8; 17]; // one byte short
        assert_eq!(parse_device_descriptor(&data), Err(XhciError::InvalidDescriptor));
    }

    #[test]
    fn parse_device_descriptor_wrong_type() {
        let mut data = [0u8; 18];
        data[0] = 18;
        data[1] = 2; // wrong type (should be 1 = Device)
        assert_eq!(parse_device_descriptor(&data), Err(XhciError::InvalidDescriptor));
    }
}
```

- [ ] **Step 2: Add module declaration**

In `dwc_usb/mod.rs`, add after the `trb` module:
```rust
pub mod context;
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel dwc_usb::context`
Expected: FAIL — functions don't exist.

- [ ] **Step 4: Implement**

Add above the test module in `context.rs`:

```rust
/// Return the default EP0 max packet size for a given link speed.
pub fn max_packet_size_for_speed(speed: UsbSpeed) -> u16 {
    match speed {
        UsbSpeed::LowSpeed => 8,
        UsbSpeed::FullSpeed | UsbSpeed::HighSpeed => 64,
        UsbSpeed::SuperSpeed | UsbSpeed::SuperSpeedPlus => 512,
        UsbSpeed::Unknown(_) => 8, // safe minimum
    }
}

/// Speed enum to xHCI speed ID for Slot Context.
fn speed_to_id(speed: UsbSpeed) -> u8 {
    match speed {
        UsbSpeed::FullSpeed => 1,
        UsbSpeed::LowSpeed => 2,
        UsbSpeed::HighSpeed => 3,
        UsbSpeed::SuperSpeed => 4,
        UsbSpeed::SuperSpeedPlus => 5,
        UsbSpeed::Unknown(id) => id,
    }
}

/// Build a 96-byte Input Context for Address Device.
///
/// Layout: Input Control Context (32B) + Slot Context (32B) + EP0 Context (32B).
/// Assumes 32-byte contexts (CSZ=0, RPi5 BCM2712).
pub fn build_input_context(
    port: u8,
    speed: UsbSpeed,
    transfer_ring_phys: u64,
) -> [u8; 96] {
    let mut ctx = [0u8; 96];

    // ── Input Control Context (bytes 0..31) ──────────────────────
    // DWord 1 (offset 4): Add Context Flags = 0x03 (Slot + EP0)
    ctx[4..8].copy_from_slice(&0x03u32.to_le_bytes());

    // ── Slot Context (bytes 32..63) ──────────────────────────────
    // DWord 0: Context Entries=1 (bits 31:27), Speed (bits 23:20), Route String=0
    let context_entries: u32 = 1 << 27;
    let speed_field: u32 = (speed_to_id(speed) as u32) << 20;
    let slot_dw0 = context_entries | speed_field;
    ctx[32..36].copy_from_slice(&slot_dw0.to_le_bytes());

    // DWord 1: Root Hub Port Number (bits 23:16)
    let slot_dw1: u32 = (port as u32) << 16;
    ctx[36..40].copy_from_slice(&slot_dw1.to_le_bytes());

    // ── Endpoint 0 Context (bytes 64..95) ────────────────────────
    // DWord 1: EP Type=4 (Control Bidir, bits 5:3), Max Packet Size (bits 31:16)
    let ep_type: u32 = 4 << 3;
    let mps: u32 = (max_packet_size_for_speed(speed) as u32) << 16;
    let ep_dw1 = ep_type | mps;
    ctx[68..72].copy_from_slice(&ep_dw1.to_le_bytes());

    // DWord 2-3: TR Dequeue Pointer (64-bit) | DCS=1
    let tr_ptr = transfer_ring_phys | 1; // DCS (Dequeue Cycle State) = 1
    ctx[72..76].copy_from_slice(&(tr_ptr as u32).to_le_bytes());
    ctx[76..80].copy_from_slice(&((tr_ptr >> 32) as u32).to_le_bytes());

    // DWord 4: Average TRB Length = 8 (bits 15:0)
    ctx[80..84].copy_from_slice(&8u32.to_le_bytes());

    ctx
}

/// Build an 8-byte USB SETUP packet for GET_DESCRIPTOR.
pub fn get_descriptor_setup_packet(desc_type: u8, desc_index: u8, length: u16) -> [u8; 8] {
    let mut pkt = [0u8; 8];
    pkt[0] = 0x80; // bmRequestType: device-to-host, standard, device
    pkt[1] = trb::USB_REQ_GET_DESCRIPTOR;
    let wvalue = ((desc_type as u16) << 8) | (desc_index as u16);
    pkt[2..4].copy_from_slice(&wvalue.to_le_bytes());
    // wIndex = 0 (bytes 4..6, already zero)
    pkt[6..8].copy_from_slice(&length.to_le_bytes());
    pkt
}

/// Parse an 18-byte USB Device Descriptor.
pub fn parse_device_descriptor(data: &[u8]) -> Result<DeviceDescriptor, XhciError> {
    if data.len() < trb::USB_DEVICE_DESCRIPTOR_SIZE {
        return Err(XhciError::InvalidDescriptor);
    }
    if data[1] != trb::USB_DESC_DEVICE {
        return Err(XhciError::InvalidDescriptor);
    }
    Ok(DeviceDescriptor {
        usb_version: u16::from_le_bytes([data[2], data[3]]),
        device_class: data[4],
        device_subclass: data[5],
        device_protocol: data[6],
        max_packet_size_ep0: data[7],
        vendor_id: u16::from_le_bytes([data[8], data[9]]),
        product_id: u16::from_le_bytes([data[10], data[11]]),
        device_version: u16::from_le_bytes([data[12], data[13]]),
        // data[14..17] are string descriptor indices — skip
        num_configurations: data[17],
    })
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p harmony-unikernel dwc_usb::context`
Expected: all 9 PASS.

- [ ] **Step 6: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/context.rs crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs
git commit -m "feat(usb): add device context builder and descriptor parser

build_input_context (96-byte Input Context), get_descriptor_setup_packet,
parse_device_descriptor → DeviceDescriptor, max_packet_size_for_speed.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: TransferRing with `enqueue_control_in`

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/ring.rs`

**Context:**
- `TransferRing` has the same ring mechanics as `CommandRing` (64 entries, enqueue index, cycle bit, Link TRB wrapping). No `pending_count`.
- `enqueue_control_in(setup_packet, data_buf_phys, data_len)` builds 3 TRBs: Setup, Data, Status.
- The internal `enqueue_one(trb_type, parameter, status, extra_flags)` method handles cycle bit + Link TRB wrapping for each individual TRB.

- [ ] **Step 1: Write failing tests**

Add to `ring.rs` test module:

```rust
    // ── TransferRing tests ──────────────────────────────────────────

    #[test]
    fn transfer_ring_enqueue_control_returns_3_trbs() {
        let mut ring = TransferRing::new(BASE);
        let setup = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00]; // GET_DESCRIPTOR(Device)
        let entries = ring.enqueue_control_in(setup, 0xA000_0000, 18).unwrap();
        // Should be exactly 3 TRBs (Setup, Data, Status) — no Link TRB at start
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].1.trb_type(), TRB_SETUP_STAGE);
        assert_eq!(entries[1].1.trb_type(), TRB_DATA_STAGE);
        assert_eq!(entries[2].1.trb_type(), TRB_STATUS_STAGE);
    }

    #[test]
    fn transfer_ring_setup_trb_flags() {
        let mut ring = TransferRing::new(BASE);
        let setup = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00];
        let entries = ring.enqueue_control_in(setup, 0xA000_0000, 18).unwrap();
        let ctrl = entries[0].1.control;
        // Should have: TRT_IN, IDT, cycle bit
        assert_ne!(ctrl & TRT_IN, 0, "Setup TRB should have TRT_IN");
        assert_ne!(ctrl & IDT, 0, "Setup TRB should have IDT (Immediate Data)");
        assert!(entries[0].1.cycle_bit(), "Setup TRB should have cycle bit set");
        // Setup TRB parameter = 8-byte setup packet as u64 LE
        let pkt_bytes = entries[0].1.parameter.to_le_bytes();
        assert_eq!(&pkt_bytes, &setup);
        // Setup TRB status = 8 (transfer length)
        assert_eq!(entries[0].1.status, 8);
    }

    #[test]
    fn transfer_ring_data_trb_fields() {
        let mut ring = TransferRing::new(BASE);
        let setup = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00];
        let entries = ring.enqueue_control_in(setup, 0xA000_0000, 18).unwrap();
        let data_trb = &entries[1].1;
        assert_eq!(data_trb.parameter, 0xA000_0000, "Data TRB parameter = data buffer phys");
        assert_eq!(data_trb.status, 18, "Data TRB status = data length");
        assert_ne!(data_trb.control & DIR_IN, 0, "Data TRB should have DIR_IN");
        // No IOC on Data TRB (only on Status)
        assert_eq!(data_trb.control & IOC, 0, "Data TRB should NOT have IOC");
    }

    #[test]
    fn transfer_ring_status_trb_flags() {
        let mut ring = TransferRing::new(BASE);
        let setup = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00];
        let entries = ring.enqueue_control_in(setup, 0xA000_0000, 18).unwrap();
        let status_trb = &entries[2].1;
        assert_ne!(status_trb.control & IOC, 0, "Status TRB should have IOC");
        // Direction OUT (no DIR_IN flag) — opposite of data phase
        assert_eq!(status_trb.control & DIR_IN, 0, "Status TRB should NOT have DIR_IN (direction OUT)");
    }

    #[test]
    fn transfer_ring_phys_addresses_sequential() {
        let mut ring = TransferRing::new(BASE);
        let setup = [0; 8];
        let entries = ring.enqueue_control_in(setup, 0xA000, 18).unwrap();
        assert_eq!(entries[0].0, BASE);         // Setup at index 0
        assert_eq!(entries[1].0, BASE + 16);    // Data at index 1
        assert_eq!(entries[2].0, BASE + 32);    // Status at index 2
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel dwc_usb::ring::tests::transfer_ring`
Expected: FAIL — `TransferRing` doesn't exist.

- [ ] **Step 3: Implement TransferRing**

Add to `ring.rs` after `EventRing`:

```rust
/// Transfer ring size — same as command ring.
pub const TRANSFER_RING_SIZE: usize = 64;
const TRANSFER_RING_USABLE: usize = TRANSFER_RING_SIZE - 1;

/// Transfer ring state — per-endpoint data transfer.
#[derive(Debug, PartialEq, Eq)]
pub struct TransferRing {
    base_phys: u64,
    enqueue_index: u16,
    cycle_bit: bool,
}

impl TransferRing {
    pub fn new(base_phys: u64) -> Self {
        Self {
            base_phys,
            enqueue_index: 0,
            cycle_bit: true,
        }
    }

    /// Enqueue a single TRB, handling Link TRB wrap if needed.
    fn enqueue_one(
        &mut self,
        trb_type: u8,
        parameter: u64,
        status: u32,
        extra_flags: u32,
    ) -> Result<Vec<(u64, Trb)>, XhciError> {
        let phys = self.base_phys + (self.enqueue_index as u64) * TRB_SIZE;
        let mut trb = Trb {
            parameter,
            status,
            control: (trb_type as u32) << 10 | extra_flags,
        };
        trb.set_cycle_bit(self.cycle_bit);

        let mut entries = Vec::with_capacity(2);
        entries.push((phys, trb));

        self.enqueue_index += 1;

        if self.enqueue_index >= TRANSFER_RING_USABLE as u16 {
            let link_phys = self.base_phys + (TRANSFER_RING_USABLE as u64) * TRB_SIZE;
            let mut link = Trb {
                parameter: self.base_phys,
                status: 0,
                control: (TRB_LINK as u32) << 10 | LINK_TOGGLE_CYCLE,
            };
            link.set_cycle_bit(self.cycle_bit);
            entries.push((link_phys, link));

            self.enqueue_index = 0;
            self.cycle_bit = !self.cycle_bit;
        }

        Ok(entries)
    }

    /// Enqueue a control IN transfer (Setup + Data + Status).
    ///
    /// Returns TRB entries to write to DMA. May include Link TRBs
    /// if the ring wraps mid-sequence.
    pub fn enqueue_control_in(
        &mut self,
        setup_packet: [u8; 8],
        data_buf_phys: u64,
        data_len: u16,
    ) -> Result<Vec<(u64, Trb)>, XhciError> {
        use super::trb::*;

        let mut all_entries = Vec::new();

        // 1. Setup TRB: parameter = setup packet as u64 LE, status = 8
        let setup_param = u64::from_le_bytes(setup_packet);
        let setup_entries = self.enqueue_one(TRB_SETUP_STAGE, setup_param, 8, TRT_IN | IDT)?;
        all_entries.extend(setup_entries);

        // 2. Data TRB: parameter = data buffer phys, status = data_len
        let data_entries = self.enqueue_one(TRB_DATA_STAGE, data_buf_phys, data_len as u32, DIR_IN)?;
        all_entries.extend(data_entries);

        // 3. Status TRB: direction OUT (no DIR_IN), IOC
        let status_entries = self.enqueue_one(TRB_STATUS_STAGE, 0, 0, IOC)?;
        all_entries.extend(status_entries);

        Ok(all_entries)
    }
}
```

Add imports at top of `ring.rs` (after existing imports):
```rust
use super::trb::{TRB_SETUP_STAGE, TRB_DATA_STAGE, TRB_STATUS_STAGE, TRT_IN, DIR_IN, IDT, IOC};
```

Or use `super::trb::*` within the method body as shown.

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-unikernel dwc_usb::ring`
Expected: all pass (existing 11 + 5 new = 16).

- [ ] **Step 5: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/ring.rs
git commit -m "feat(usb): add TransferRing with enqueue_control_in for EP0 transfers

3-TRB control IN transfer (Setup + Data + Status) with correct
direction flags, IOC on Status only, and Link TRB wrapping.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Extend `setup_rings` with DCBAA support

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs`

**Context:**
- Add `dcbaa_phys: u64` and `max_slots_enabled: u8` parameters to `setup_rings`.
- Add `dcbaa_phys: Option<u64>` and `transfer_rings: BTreeMap<u8, ring::TransferRing>` fields to `XhciDriver`.
- Update `init()` to initialize new fields.
- Update existing tests that call `setup_rings` to pass the two new parameters (0, 0 for Phase 2a compat).

- [ ] **Step 1: Add new imports and fields**

At top of `mod.rs`, add:
```rust
use alloc::collections::BTreeMap;
```

Add to `XhciDriver` struct:
```rust
    /// DCBAA physical address (set after setup_rings with non-zero dcbaa_phys).
    dcbaa_phys: Option<u64>,
    /// Per-slot EP0 transfer rings. Key = slot_id.
    transfer_rings: BTreeMap<u8, ring::TransferRing>,
```

Update `init()` to initialize: `dcbaa_phys: None, transfer_rings: BTreeMap::new()`.

- [ ] **Step 2: Extend `setup_rings` signature**

Change signature to:
```rust
pub fn setup_rings(
    &mut self,
    cmd_ring_phys: u64,
    event_ring_phys: u64,
    erst_phys: u64,
    dcbaa_phys: u64,
    max_slots_enabled: u8,
) -> Result<Vec<XhciAction>, XhciError>
```

Update the CONFIG and DCBAAP actions:
```rust
// 1. CONFIG: MaxSlotsEn
actions.push(XhciAction::WriteRegister {
    offset: op + CONFIG,
    value: max_slots_enabled as u32,
});

// 2. DCBAAP
actions.push(XhciAction::WriteRegister64 {
    offset_lo: op + DCBAAP_LO,
    value: dcbaa_phys,
});
```

Store: `self.dcbaa_phys = if dcbaa_phys != 0 { Some(dcbaa_phys) } else { None };`

- [ ] **Step 3: Update ALL existing tests**

Every test that calls `setup_rings` needs two extra args `(0, 0)`:
```rust
driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0, 0).unwrap();
```

Also update any direct `XhciDriver` struct construction to include `dcbaa_phys: None, transfer_rings: BTreeMap::new()`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-unikernel dwc_usb`
Expected: all existing tests pass with updated signatures.

- [ ] **Step 5: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs
git commit -m "feat(usb): extend setup_rings with DCBAA support

Add dcbaa_phys + max_slots_enabled parameters, dcbaa_phys and
transfer_rings fields to XhciDriver. Phase 2a callers pass (0, 0).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: `enable_slot` and `address_device` driver methods

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs`

**Context:**
- `enable_slot()` enqueues an Enable Slot command TRB, returns WriteTrb + RingDoorbell.
- `address_device()` builds Input Context, writes DCBAA slot entry, enqueues Address Device command. Returns `(actions, input_context_bytes)`.
- Both require `Running` state.

- [ ] **Step 1: Write failing tests**

Add to `mod.rs` test module:

```rust
    #[test]
    fn enable_slot_enqueues_command() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0x5000_0000, 4).unwrap();

        let actions = driver.enable_slot().unwrap();
        // Should have WriteTrb (Enable Slot cmd) + RingDoorbell
        assert!(actions.len() >= 2);
        match &actions[0] {
            XhciAction::WriteTrb { trb, .. } => {
                assert_eq!(trb.trb_type(), trb::TRB_ENABLE_SLOT);
            }
            other => panic!("expected WriteTrb, got {:?}", other),
        }
    }

    #[test]
    fn address_device_returns_input_context_and_actions() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0x5000_0000, 4).unwrap();

        let (actions, input_ctx) = driver.address_device(
            1, // slot_id
            2, // port
            UsbSpeed::HighSpeed,
            0x6000_0000, // input_context_phys
            0x7000_0000, // output_context_phys
            0x8000_0000, // transfer_ring_phys
        ).unwrap();

        // Input context should be 96 bytes
        assert_eq!(input_ctx.len(), 96);

        // Should have: WriteDma (DCBAA slot) + WriteTrb (Address Device cmd) + RingDoorbell
        assert!(actions.len() >= 3);

        // First action: WriteDma for DCBAA slot 1 at dcbaa_phys + 8
        match &actions[0] {
            XhciAction::WriteDma { phys, data } => {
                assert_eq!(*phys, 0x5000_0000 + 8); // slot 1 * 8
                assert_eq!(data.len(), 8);
                let ptr = u64::from_le_bytes(data[..8].try_into().unwrap());
                assert_eq!(ptr, 0x7000_0000); // output_context_phys
            }
            other => panic!("expected WriteDma, got {:?}", other),
        }

        // Address Device command TRB
        let cmd_action = actions.iter().find(|a| matches!(a, XhciAction::WriteTrb { trb, .. } if trb.trb_type() == trb::TRB_ADDRESS_DEVICE));
        assert!(cmd_action.is_some(), "should have Address Device command TRB");
    }

    #[test]
    fn address_device_creates_transfer_ring() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0x5000_0000, 4).unwrap();

        driver.address_device(1, 2, UsbSpeed::HighSpeed, 0x6000, 0x7000, 0x8000).unwrap();

        // get_device_descriptor should now work for slot 1
        assert!(driver.get_device_descriptor(1, 0x9000).is_ok());
    }

    #[test]
    fn address_device_without_dcbaa_fails() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        // setup_rings with dcbaa_phys=0 → no DCBAA
        driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0, 0).unwrap();

        let result = driver.address_device(1, 2, UsbSpeed::HighSpeed, 0x6000, 0x7000, 0x8000);
        assert_eq!(result, Err(XhciError::InvalidState));
    }
```

- [ ] **Step 2: Implement `enable_slot`**

```rust
    /// Enqueue an Enable Slot command.
    ///
    /// After processing the `CommandCompletion` event, the `slot_id`
    /// field contains the assigned slot number (1-based).
    pub fn enable_slot(&mut self) -> Result<Vec<XhciAction>, XhciError> {
        if self.state != XhciState::Running {
            return Err(XhciError::InvalidState);
        }

        let cmd_ring = self.command_ring.as_mut().ok_or(XhciError::InvalidState)?;
        let entries = cmd_ring.enqueue(trb::TRB_ENABLE_SLOT, 0)?;

        let mut actions: Vec<XhciAction> = entries
            .into_iter()
            .map(|(phys, t)| XhciAction::WriteTrb { phys, trb: t })
            .collect();

        actions.push(XhciAction::RingDoorbell {
            offset: self.db_offset as usize,
            value: 0,
        });

        Ok(actions)
    }
```

- [ ] **Step 3: Implement `address_device`**

```rust
    /// Set up a device context and enqueue an Address Device command.
    ///
    /// Returns `(actions, input_context_bytes)`. The caller must:
    /// 1. Write `input_context_bytes` to `input_context_phys` in DMA
    /// 2. Execute all actions in order
    /// 3. Process the `CommandCompletion` event
    pub fn address_device(
        &mut self,
        slot_id: u8,
        port: u8,
        speed: UsbSpeed,
        input_context_phys: u64,
        output_context_phys: u64,
        transfer_ring_phys: u64,
    ) -> Result<(Vec<XhciAction>, [u8; 96]), XhciError> {
        if self.state != XhciState::Running {
            return Err(XhciError::InvalidState);
        }
        let dcbaa_phys = self.dcbaa_phys.ok_or(XhciError::InvalidState)?;

        // Build Input Context
        let input_ctx = context::build_input_context(port, speed, transfer_ring_phys);

        let mut actions = Vec::new();

        // 1. Write Output Context pointer to DCBAA[slot_id]
        let dcbaa_slot_phys = dcbaa_phys + (slot_id as u64) * 8;
        actions.push(XhciAction::WriteDma {
            phys: dcbaa_slot_phys,
            data: output_context_phys.to_le_bytes().to_vec(),
        });

        // 2. Enqueue Address Device command
        // parameter = input_context_phys, slot_id in control bits 31:24
        let cmd_ring = self.command_ring.as_mut().ok_or(XhciError::InvalidState)?;
        let entries = cmd_ring.enqueue(trb::TRB_ADDRESS_DEVICE, input_context_phys)?;

        for (phys, mut t) in entries {
            // Set slot_id in control bits 31:24 for the Address Device TRB
            // (not for Link TRBs)
            if t.trb_type() == trb::TRB_ADDRESS_DEVICE {
                t.control |= (slot_id as u32) << 24;
            }
            actions.push(XhciAction::WriteTrb { phys, trb: t });
        }

        actions.push(XhciAction::RingDoorbell {
            offset: self.db_offset as usize,
            value: 0,
        });

        // Create transfer ring for this slot's EP0
        self.transfer_rings.insert(slot_id, ring::TransferRing::new(transfer_ring_phys));

        Ok((actions, input_ctx))
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-unikernel dwc_usb`
Expected: all pass.

- [ ] **Step 5: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs
git commit -m "feat(usb): implement enable_slot and address_device

Enable Slot command enqueue, Address Device with Input Context builder,
DCBAA slot entry, and per-slot TransferRing creation.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: `get_device_descriptor`, Transfer Event handling, full integration

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs`

**Context:**
- `get_device_descriptor` uses the slot's TransferRing to enqueue a 3-TRB control transfer.
- `process_event` extended for `TRB_TRANSFER_EVENT`.
- Re-export `parse_device_descriptor` and `DeviceDescriptor` from mod.rs.

- [ ] **Step 1: Write failing tests**

Add to `mod.rs` test module:

```rust
    #[test]
    fn get_device_descriptor_enqueues_3_trbs_and_doorbell() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0x5000_0000, 4).unwrap();
        driver.address_device(1, 2, UsbSpeed::HighSpeed, 0x6000, 0x7000, 0x8000).unwrap();

        let actions = driver.get_device_descriptor(1, 0x9000_0000).unwrap();

        // Count WriteTrb actions (should be 3: Setup, Data, Status)
        let write_trbs: Vec<_> = actions.iter()
            .filter(|a| matches!(a, XhciAction::WriteTrb { .. }))
            .collect();
        assert_eq!(write_trbs.len(), 3);

        // Last action should be RingDoorbell for slot 1
        match actions.last().unwrap() {
            XhciAction::RingDoorbell { offset, value } => {
                assert_eq!(*offset, 0x1000 + 4); // db_offset + 4 * slot_id
                assert_eq!(*value, 1); // endpoint 0 doorbell value = 1
            }
            other => panic!("expected RingDoorbell, got {:?}", other),
        }
    }

    #[test]
    fn get_device_descriptor_without_transfer_ring_fails() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0x5000_0000, 4).unwrap();
        // No address_device call → no transfer ring for slot 1
        assert_eq!(
            driver.get_device_descriptor(1, 0x9000),
            Err(XhciError::NoTransferRing)
        );
    }

    #[test]
    fn process_transfer_event() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0x5000_0000, 4).unwrap();

        let slot_id: u8 = 1;
        let endpoint_id: u8 = 1; // EP0 = endpoint ID 1 in xHCI
        let evt_trb = trb::Trb {
            parameter: 0x8000_0010, // TRB pointer (not parsed in Phase 2b)
            status: (trb::COMPLETION_SUCCESS as u32) << 24 | 0, // 0 residual
            control: (slot_id as u32) << 24
                | (endpoint_id as u32) << 16
                | (trb::TRB_TRANSFER_EVENT as u32) << 10
                | 1, // cycle bit
        };

        let (event, actions) = driver.process_event(evt_trb).unwrap();
        assert_eq!(event, XhciEvent::TransferEvent {
            slot_id: 1,
            endpoint_id: 1,
            completion_code: trb::COMPLETION_SUCCESS,
            transfer_length: 0,
        });
        assert!(actions.iter().any(|a| matches!(a, XhciAction::UpdateDequeuePointer { .. })));
    }

    #[test]
    fn parse_device_descriptor_integration() {
        let data: [u8; 18] = [
            18, 1, 0x10, 0x02, 0x00, 0x00, 0x00, 64,
            0x6B, 0x1D, // vendor = 0x1D6B (Linux Foundation)
            0x02, 0x00, // product = 0x0002
            0x10, 0x05, // version = 5.10
            1, 2, 3, 1, // string indices + num_configurations
        ];
        let desc = context::parse_device_descriptor(&data).unwrap();
        assert_eq!(desc.vendor_id, 0x1D6B);
        assert_eq!(desc.product_id, 0x0002);
        assert_eq!(desc.usb_version, 0x0210);
        assert_eq!(desc.num_configurations, 1);
    }
```

- [ ] **Step 2: Implement `get_device_descriptor`**

```rust
    /// Enqueue a GET_DESCRIPTOR(Device) control transfer on a slot's EP0.
    ///
    /// After execution, poll for `TransferEvent`, then read 18 bytes from
    /// `data_buf_phys` and pass to `parse_device_descriptor`.
    pub fn get_device_descriptor(
        &mut self,
        slot_id: u8,
        data_buf_phys: u64,
    ) -> Result<Vec<XhciAction>, XhciError> {
        if self.state != XhciState::Running {
            return Err(XhciError::InvalidState);
        }

        let xfer_ring = self.transfer_rings.get_mut(&slot_id)
            .ok_or(XhciError::NoTransferRing)?;

        let setup = context::get_descriptor_setup_packet(
            trb::USB_DESC_DEVICE, 0, trb::USB_DEVICE_DESCRIPTOR_SIZE as u16,
        );
        let entries = xfer_ring.enqueue_control_in(setup, data_buf_phys, trb::USB_DEVICE_DESCRIPTOR_SIZE as u16)?;

        let mut actions: Vec<XhciAction> = entries
            .into_iter()
            .map(|(phys, t)| XhciAction::WriteTrb { phys, trb: t })
            .collect();

        // Ring doorbell for this slot's EP0: value = 1 (default control endpoint)
        actions.push(XhciAction::RingDoorbell {
            offset: self.db_offset as usize + 4 * (slot_id as usize),
            value: 1, // EP0 doorbell target = 1
        });

        Ok(actions)
    }
```

- [ ] **Step 3: Extend `process_event` for Transfer Events**

In the match block, add before `other =>`:
```rust
            trb::TRB_TRANSFER_EVENT => {
                let slot_id = (trb.control >> 24) as u8;
                let endpoint_id = ((trb.control >> 16) & 0x1F) as u8;
                let completion_code = (trb.status >> 24) as u8;
                let transfer_length = trb.status & 0x00FF_FFFF;
                XhciEvent::TransferEvent {
                    slot_id,
                    endpoint_id,
                    completion_code,
                    transfer_length,
                }
            }
```

- [ ] **Step 4: Add re-exports**

In `mod.rs`, ensure `context` module is accessible (added in Task 3) and re-export `parse_device_descriptor`:
```rust
pub use context::parse_device_descriptor;
```

- [ ] **Step 5: Run all tests**

Run: `cargo test -p harmony-unikernel dwc_usb`
Expected: all pass.

- [ ] **Step 6: Run full workspace + clippy + nightly fmt**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs
git commit -m "feat(usb): implement get_device_descriptor and Transfer Event handling

Control transfer enqueue on EP0 transfer ring, Transfer Event parsing,
parse_device_descriptor re-export. Completes xHCI Phase 2b — the driver
can now identify connected USB devices.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```
