# USB Gadget Mode CDC-ECM (DWC2 OTG)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Beads:** harmony-os-eyn (USB gadget mode CDC-ECM/NCM)

**Goal:** Implement a native Rust DWC2 OTG device controller and CDC-ECM gadget function so an RPi5 can present itself as a USB Ethernet adapter to a connected host. This enables direct point-to-point peering over a USB-C cable — one RPi5 acts as host (xHCI, already shipped in PR #131), the other as gadget (DWC2, this work).

**Prerequisite:** CDC-ECM/NCM host driver (PR #131) — complete.

---

## Architecture

Two sans-I/O layers in Ring 1, with Ring 2 reuse:

```
Host (laptop/RPi5)
  | USB-C cable
DWC2 hardware registers
  | RegisterBank trait (read32/write32)
Dwc2Controller (Ring 1)         <- new: hardware state machine
  | GadgetEvent / GadgetRequest
EcmGadget (Ring 1)              <- new: CDC-ECM class logic
  | NetworkDevice trait
VirtioNetServer (Ring 2)        <- reused unchanged
  | 9P
/dev/net/usb0/{data,mac,mtu,stats,link}
```

**`Dwc2Controller`** owns the USB device state machine (Default -> Address -> Configured), FIFO allocation, endpoint management, and SETUP packet dispatch. It never knows about CDC — it routes control requests and transfer completions upward via `GadgetEvent`.

**`EcmGadget`** owns descriptor construction, CDC class request handling, notification generation, and frame bridging. It implements `NetworkDevice` so Ring 2 reuses `VirtioNetServer` unchanged — same pattern as the host-side `CdcEthernetDriver`.

### Design decisions

- **ECM only, no NCM.** For point-to-point USB-C peering, ECM's simplicity wins. One Ethernet frame per bulk transfer, no NTB negotiation. The NCM codec already exists in the host driver and can be added as a future enhancement if throughput matters.
- **Fixed device mode, no OTG.** The DWC2 driver forces peripheral mode at init. No OTG role detection or host-device switching. The user decides which board is host and which is gadget — a deployment decision, not a runtime one.
- **Reuse `RegisterBank` trait.** Same `read32`/`write32` interface as xHCI. DWC2 register offsets as named constants. `MockRegisterBank` for hardware-free testing.
- **Static FIFO allocation.** Hardcoded partition for the known ECM endpoint layout. No runtime negotiation. Revisit if a second gadget function is added.
- **Two-layer stack.** `Dwc2Controller` (hardware) and `EcmGadget` (class protocol) communicate via `GadgetEvent`/`GadgetRequest` enums. Clean separation enables independent testing and future reuse of `Dwc2Controller` for other gadget functions.

### Data flow

**RX (host -> device):**
1. Host sends Ethernet frame as bulk OUT transfer
2. DWC2 hardware fires RX FIFO interrupt
3. Caller reads interrupt status, creates `Dwc2Event::RxFifoNonEmpty`
4. `Dwc2Controller` reads FIFO data via `RegisterBank`, returns `GadgetEvent::BulkOut { ep: 2, data }`
5. `EcmGadget` queues frame to `rx_queue`
6. Ring 2 calls `poll_tx()` to retrieve the frame

**TX (device -> host):**
1. Ring 2 calls `push_rx(frame)` on `EcmGadget`
2. `EcmGadget` returns `GadgetRequest::BulkIn { ep: 1, data: frame }`
3. `Dwc2Controller` translates to `Dwc2Action::WriteTxFifo { ep: 1, data }` + register pokes
4. Caller executes MMIO writes
5. Host receives bulk IN transfer

---

## DWC2 Controller — Hardware Layer

### USB device state machine

```
PowerOn -> Default -> Address -> Configured
             ^ bus reset returns here
```

The controller tracks the current state and rejects operations invalid for that state (e.g., no bulk transfers in Default/Address states).

### Register layout

Named constants for DWC2 offsets, grouped logically:

| Group | Key Registers | Purpose |
|-------|--------------|---------|
| Core Global | `GOTGCTL`, `GAHBCFG`, `GUSBCFG`, `GRSTCTL`, `GINTSTS`, `GINTMSK` | OTG control, AHB config, USB config, reset, interrupt status/mask |
| Device Mode | `DCFG`, `DCTL`, `DSTS`, `DIEPMSK`, `DOEPMSK`, `DAINT`, `DAINTMSK` | Device config (speed, address), control, status, endpoint interrupt masks |
| Endpoint IN | `DIEPCTL0..3`, `DIEPTSIZ0..3`, `DIEPINT0..3`, `DTXFSTS0..3` | Per-endpoint control, transfer size, interrupt status, TX FIFO status |
| Endpoint OUT | `DOEPCTL0..3`, `DOEPTSIZ0..3`, `DOEPINT0..3` | Per-endpoint control, transfer size, interrupt status |
| FIFO | `GRXFSIZ`, `GNPTXFSIZ`, `DIEPTXF1..3`, `GRXSTSP` | FIFO sizing and RX status pop |

### Static FIFO partition

~4KB shared RAM, partitioned at init:

| FIFO | Size | Rationale |
|------|------|-----------|
| RX (shared) | 1024 bytes | All OUT endpoints share one RX FIFO; fits 2x max bulk packet |
| TX EP0 | 128 bytes | Control transfers, 64-byte max packet + overhead |
| TX EP1 (bulk IN) | 1536 bytes | Ethernet frames up to 1514 + headers |
| TX EP3 (interrupt IN) | 64 bytes | CDC notifications are 8-16 bytes |

### Events and actions

```rust
pub enum Dwc2Event {
    BusReset,
    EnumerationDone { speed: UsbSpeed },
    SetupReceived { data: [u8; 8] },
    RxFifoNonEmpty,
    InTransferComplete { ep: u8 },
    OutTransferComplete { ep: u8 },
    Suspend,
    Resume,
}

pub enum Dwc2Action {
    WriteRegister { offset: u32, value: u32 },
    ReadRegister { offset: u32 },
    WriteTxFifo { ep: u8, data: Vec<u8> },
    ReadRxFifo { words: usize },
    Stall { ep: u8 },
    EnableInterrupt { mask: u32 },
}
```

### Public API

```rust
impl Dwc2Controller {
    /// Initialize DWC2 in device mode: force peripheral, configure FIFOs,
    /// set USB2 HS speed, unmask interrupts, soft-connect.
    pub fn init(bank: &mut impl RegisterBank) -> Result<(Self, Vec<Dwc2Action>), Dwc2Error>;

    /// Process a hardware event. Returns class-level events for the gadget.
    pub fn handle_event(
        &mut self,
        event: Dwc2Event,
        bank: &mut impl RegisterBank,
    ) -> Result<Vec<GadgetEvent>, Dwc2Error>;

    /// Accept a request from the gadget layer. Returns hardware actions.
    pub fn submit_request(
        &mut self,
        req: GadgetRequest,
    ) -> Result<Vec<Dwc2Action>, Dwc2Error>;

    /// Program the device address into DCFG after SET_ADDRESS completes.
    pub fn set_address(&mut self, addr: u8, bank: &mut impl RegisterBank) -> Vec<Dwc2Action>;
}
```

---

## EcmGadget — CDC-ECM Class Layer

### Descriptor construction

The gadget *builds* descriptors (reverse of the host driver which *parses* them). Built once at init, served to the host during GET_DESCRIPTOR requests:

| Descriptor | Content |
|-----------|---------|
| Device | USB 2.0, class 0x02 (CDC), VID 0x1209 / PID 0x0001 (pid.codes open-source test), serial string |
| Configuration | Single config, self-powered, 2 interfaces |
| Interface 0 (Communication) | Class 0x02, subclass 0x06 (ECM), protocol 0x00. CDC functional descriptors + interrupt EP3 IN |
| CDC Header FD | CDC spec version 1.10 |
| CDC Union FD | Control interface 0, data interface 1 |
| CDC Ethernet Networking FD | MAC string index, max segment size 1514 |
| Interface 1 alt 0 (Data, idle) | No endpoints — selected before SET_CONFIGURATION |
| Interface 1 alt 1 (Data, active) | Bulk EP1 IN + Bulk EP2 OUT |

### Standard control requests

Handled by `Dwc2Controller`, but descriptors provided by `EcmGadget`:

| Request | Response |
|---------|----------|
| `GET_DESCRIPTOR(Device)` | Device descriptor bytes |
| `GET_DESCRIPTOR(Configuration)` | Full config descriptor chain |
| `GET_DESCRIPTOR(String, idx)` | String descriptors (manufacturer, product, serial, MAC) |
| `SET_CONFIGURATION(1)` | Activate data interface alt 1, enable bulk endpoints |
| `SET_INTERFACE(1, 1)` | Activate data alt setting 1 |

### CDC class requests

Routed to `EcmGadget` by `Dwc2Controller`:

| Request | Action |
|---------|--------|
| `SET_ETHERNET_PACKET_FILTER` | Store filter flags (accept all — mesh node) |
| Others | Stall (unsupported) |

### GadgetEvent / GadgetRequest interface

```rust
/// Events from Dwc2Controller -> EcmGadget
pub enum GadgetEvent {
    /// Bus reset — gadget should reset state
    Reset,
    /// SET_CONFIGURATION completed — data endpoints active
    Configured,
    /// Class-specific SETUP request
    SetupClassRequest { setup: [u8; 8] },
    /// GET_DESCRIPTOR for a descriptor the controller doesn't own
    GetDescriptor { desc_type: u8, desc_index: u8, max_len: u16 },
    /// Bulk OUT data received
    BulkOut { ep: u8, data: Vec<u8> },
    /// Bulk IN transfer completed (ready for next)
    BulkInComplete { ep: u8 },
    /// Suspended
    Suspended,
    /// Resumed
    Resumed,
}

/// Requests from EcmGadget -> Dwc2Controller
pub enum GadgetRequest {
    /// Respond to control IN with data
    ControlIn { data: Vec<u8> },
    /// Acknowledge control OUT (zero-length status)
    ControlAck,
    /// Stall the control endpoint
    ControlStall,
    /// Send data on bulk IN endpoint
    BulkIn { ep: u8, data: Vec<u8> },
    /// Send CDC notification on interrupt IN
    InterruptIn { ep: u8, data: Vec<u8> },
}
```

### NetworkDevice implementation

Identical semantics to the host driver:
- `poll_tx()` — pops from `rx_queue` (frames received from host via bulk OUT)
- `push_rx(frame)` — queues frame for TX to host via bulk IN, returns `GadgetRequest::BulkIn`
- `mac()` — returns the device's MAC address (generated at init from identity key hash)
- `link_up()` — true when in Configured state

### Notification generation

- On transition to Configured: send `NETWORK_CONNECTION { connected: true }` on interrupt EP
- On bus reset/suspend: send `NETWORK_CONNECTION { connected: false }`
- Speed change: `CONNECTION_SPEED_CHANGE { 480_000_000, 480_000_000 }` (USB2 HS = 480 Mbps)

---

## File Structure

All new code in `crates/harmony-unikernel/src/drivers/`:

| File | Responsibility | ~LOC |
|------|---------------|------|
| `dwc2/mod.rs` | `Dwc2Controller` state machine — init, event handling, SETUP dispatch, endpoint management | ~400 |
| `dwc2/regs.rs` | Named register offset constants and bitfield masks | ~150 |
| `dwc2/fifo.rs` | Static FIFO partition constants and FIFO read/write helpers | ~80 |
| `dwc2/types.rs` | `Dwc2Event`, `Dwc2Action`, `GadgetEvent`, `GadgetRequest`, `Dwc2Error`, `UsbDeviceState` | ~100 |
| `ecm_gadget/mod.rs` | `EcmGadget` — class request handling, `NetworkDevice` impl, notification generation | ~250 |
| `ecm_gadget/descriptor.rs` | Descriptor builders — device, config, string, CDC functional descriptors as byte arrays | ~200 |

Ring 2 — one new adapter file:

| File | Responsibility | ~LOC |
|------|---------------|------|
| `crates/harmony-microkernel/src/ecm_gadget_net_device.rs` | `EcmGadgetNetDevice` adapter for `VirtioNetServer` reuse | ~60 |

Reused unchanged:
- `register_bank.rs` — `RegisterBank` trait + `MockRegisterBank`
- `cdc_ethernet/` — host-side driver (separate, not modified)
- Ring 2 `VirtioNetServer` — reused via `NetworkDevice` trait

Total new code: ~1,240 lines + tests.

---

## Error Handling

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dwc2Error {
    /// FIFO RAM exhausted during init (shouldn't happen with static partition)
    FifoOverflow,
    /// Operation invalid for current USB device state
    InvalidState { current: UsbDeviceState, attempted: &'static str },
    /// Endpoint number out of range (0-3)
    InvalidEndpoint { ep: u8 },
    /// TX FIFO full — caller should retry after InTransferComplete
    TxFifoFull { ep: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcmGadgetError {
    /// Frame exceeds max segment size (1514 bytes)
    FrameTooLarge,
    /// push_rx called before Configured state
    NotReady,
}
```

- Init errors (`FifoOverflow`, `InvalidEndpoint`) are bugs — programming errors in FIFO sizing or endpoint setup.
- `InvalidState` prevents operations in wrong USB states (e.g., bulk transfer before Configured).
- `TxFifoFull` is the only expected runtime error — caller retries on next `InTransferComplete`.
- `FrameTooLarge` and `NotReady` bubble up through `NetworkDevice::push_rx` returning `false`.
- Malformed SETUP packets from the host get stalled (standard USB response), not returned as errors.
- No retry logic — caller's responsibility (sans-I/O principle).

---

## Testing

All unit tests with hand-crafted byte vectors and `MockRegisterBank`. No hardware dependencies.

### DWC2 Controller tests

- `init_forces_device_mode` — verify `GUSBCFG` force-device-mode bit set, FIFO registers programmed, soft-connect via `DCTL`
- `bus_reset_returns_to_default` — state transitions back to Default, endpoints disabled
- `set_address_programs_dcfg` — `SET_ADDRESS(5)` -> `DCFG` device address field = 5, state -> Address
- `set_configuration_enables_endpoints` — state -> Configured, bulk/interrupt endpoint control registers enabled
- `setup_standard_routed_internally` — GET_DESCRIPTOR handled by controller (descriptors provided by gadget)
- `setup_class_routed_to_gadget` — class-type SETUP request -> `GadgetEvent::SetupClassRequest`
- `rx_fifo_read_produces_bulk_out` — RX FIFO pop -> `GadgetEvent::BulkOut` with correct data
- `tx_fifo_write_from_gadget_request` — `GadgetRequest::BulkIn` -> `Dwc2Action::WriteTxFifo`
- `stall_on_unsupported_request` — unknown standard request -> `Dwc2Action::Stall { ep: 0 }`

### FIFO tests

- `static_partition_fits_in_4kb` — sum of all FIFO sizes <= 4096 bytes
- `fifo_register_values_correct` — verify computed register values match expected offsets/depths

### Descriptor builder tests

- `device_descriptor_length_and_class` — 18 bytes, bDeviceClass = 0x02
- `config_descriptor_total_length` — wTotalLength matches actual concatenated length
- `cdc_functional_descriptors_present` — Header, Union, Ethernet Networking FDs in correct order
- `string_descriptor_mac_format` — MAC string is 12 hex ASCII chars in USB string descriptor format
- `roundtrip_with_host_parser` — feed built descriptors into the existing `parse_cdc_config()` from the host driver. Validates gadget and host agree on the wire format.

### EcmGadget tests

- `reset_clears_state` — `GadgetEvent::Reset` -> link_up false, rx_queue empty
- `configured_sends_network_connection` — -> `GadgetRequest::InterruptIn` with connection notification bytes
- `class_request_packet_filter` — `SET_ETHERNET_PACKET_FILTER` -> `ControlAck`
- `unknown_class_request_stalled` — -> `ControlStall`
- `bulk_out_queues_frame` — `GadgetEvent::BulkOut` -> frame in `rx_queue`, `poll_tx()` returns it
- `push_rx_returns_bulk_in` — `push_rx(frame)` -> `GadgetRequest::BulkIn` with frame bytes
- `push_rx_before_configured_fails` — returns false
- `oversized_frame_rejected` — >1514 bytes -> returns false

### Integration test

- `full_enumeration_flow` — init -> bus reset -> SET_ADDRESS -> GET_DESCRIPTOR -> SET_CONFIGURATION -> bulk OUT -> poll_tx -> push_rx -> bulk IN. Verifies the complete lifecycle with `MockRegisterBank`.

### Cross-driver roundtrip

- Feed `EcmGadget`-built descriptors into the host-side `CdcEthernetDriver::from_config_descriptor()`. Confirms both drivers agree on the descriptor format — the gadget equivalent of the Reticulum interop tests.

---

## Scope Boundary

**In scope:**
- `Dwc2Controller` — DWC2 OTG hardware state machine, fixed device mode, static FIFO allocation, SETUP routing, endpoint management
- `EcmGadget` — CDC-ECM descriptor construction, class request handling, notification generation, `NetworkDevice` impl
- `GadgetEvent`/`GadgetRequest` boundary between the two layers
- DWC2 register offset constants and bitfield masks
- Ring 2 adapter (`EcmGadgetNetDevice`) for `VirtioNetServer` reuse
- Unit tests with `MockRegisterBank`, descriptor roundtrip with host parser
- ECM passthrough only (one frame per bulk transfer)

**Out of scope:**
- NCM gadget mode (future enhancement if throughput matters)
- OTG role detection / host-device switching
- Dynamic FIFO sizing
- USB3 SuperSpeed (DWC2 is USB2 only; RPi5's USB3 is on xHCI)
- Multiple gadget functions / composite device
- Suspend/resume power management (events accepted but clocks not gated)
- VID/PID allocation (test/prototype values used)
- Hot-plug detection on the device side
- Multi-frame TX batching
