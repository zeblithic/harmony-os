# USB CDC-ECM/NCM Ethernet Class Driver

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Beads:** harmony-os-y66 (CDC-ECM/NCM driver)

**Goal:** Implement a native Rust CDC-ECM and CDC-NCM class driver for USB-Ethernet adapters. Host mode only (xHCI). Sans-I/O at Ring 1, reusing `VirtioNetServer` at Ring 2 via the `NetworkDevice` trait.

**Prerequisite:** xHCI Phase 3 (bulk transfers) — complete.

---

## Architecture

The driver follows the established two-ring pattern:

**Ring 1 (harmony-unikernel):** A sans-I/O `CdcEthernetDriver` that parses CDC descriptors, encodes/decodes Ethernet frames via a `CdcCodec` enum (ECM passthrough or NCM NTH16/NDP16), parses interrupt notifications, and implements the `NetworkDevice` trait. All USB transfers are expressed as `CdcAction` variants returned to the caller.

**Ring 2 (harmony-microkernel):** Reuses `VirtioNetServer<CdcEthernetDriver>` directly. Since the driver implements `NetworkDevice`, the existing 9P server provides `/dev/net/<name>/{data, mac, mtu, stats, link}` with no new Ring 2 code.

**Data flow:**

```
USB Adapter ←→ xHCI bulk endpoints ←→ CdcEthernetDriver (codec) ←→ NetworkDevice trait
    ←→ VirtioNetServer (9P) ←→ user processes read/write /dev/net/cdc0/data
```

### Unified ECM/NCM via codec enum

ECM and NCM share 95% of their infrastructure: descriptor parsing framework, control requests, notification handling, 9P interface. The only difference is the data transfer encoding:

- **ECM:** One raw Ethernet frame per USB bulk transfer (passthrough).
- **NCM:** Frames wrapped in NTH16 + NDP16 headers, supporting multiple frames per transfer.

A `CdcCodec` enum selects the encoding at enumeration time based on `bInterfaceSubclass`. ECM's codec is trivial (passthrough). NCM's codec handles NTH16/NDP16 wrapping/unwrapping.

### Transfer strategy

Polling-based. The caller drives the loop:
1. Queue bulk IN + interrupt IN transfers via `CdcAction`
2. Feed completed transfers back to `receive_bulk_in` / `receive_interrupt`
3. Each returns new `CdcAction`s to re-queue transfers

Event-driven mode (matching xHCI completion events to pending transfers) is a future enhancement once Phase 3b lands. The `CdcAction` return type supports both — the caller just changes how it schedules them.

---

## File Structure

All new code in `crates/harmony-unikernel/src/drivers/cdc_ethernet/`:

| File | Responsibility |
|------|---------------|
| `mod.rs` | `CdcEthernetDriver` struct, `CdcAction`/`CdcError` enums, `NetworkDevice` impl, control request builders, two-phase init |
| `descriptor.rs` | CDC descriptor parsing — config descriptor bytes → `CdcDescriptors` struct |
| `codec.rs` | `CdcCodec` enum (`Ecm`/`Ncm` variants), `decode_rx`/`encode_tx` dispatch |
| `ncm.rs` | NTH16/NDP16 header parsing (`decode_ntb`) and building (`encode_ntb`) |
| `notification.rs` | Interrupt IN notification parsing — link state, speed changes |

No new Ring 2 files. `VirtioNetServer` is reused unchanged.

---

## Data Structures

### CdcConfig — extracted from USB descriptors

```rust
pub struct CdcConfig {
    pub slot_id: u8,
    pub protocol: CdcProtocol,
    pub bulk_in_ep: u8,
    pub bulk_out_ep: u8,
    pub interrupt_ep: u8,
    pub mac: [u8; 6],
    pub max_segment_size: u16,
    pub data_interface: u8,
    pub data_alt_setting: u8,
}

pub enum CdcProtocol { Ecm, Ncm }
```

### CdcAction — sans-I/O transfer requests

```rust
pub enum CdcAction {
    BulkOut { ep: u8, data: Vec<u8> },
    BulkIn { ep: u8, max_len: u16 },
    ControlOut { request: [u8; 8], data: Vec<u8> },
    InterruptIn { ep: u8, max_len: u16 },
}
```

### CdcEthernetDriver — main driver struct

```rust
pub struct CdcEthernetDriver {
    config: CdcConfig,
    codec: CdcCodec,
    link_up: bool,
    speed_down: u32,
    speed_up: u32,
    rx_queue: VecDeque<Vec<u8>>,
    tx_pending: bool,
}
```

### Public API

```rust
impl CdcEthernetDriver {
    /// Parse USB config descriptor, find CDC ECM/NCM interface.
    /// Returns None if no CDC-Ethernet interface found.
    /// Returns initial CdcActions: SET_CONFIGURATION, SET_INTERFACE,
    /// SET_ETHERNET_PACKET_FILTER, plus initial BulkIn/InterruptIn queues.
    /// MAC string descriptor request is included — caller must feed response
    /// to complete_init().
    pub fn from_config_descriptor(slot_id: u8, desc: &[u8])
        -> Result<Option<(Self, Vec<CdcAction>)>, CdcError>

    /// Complete initialization with the MAC string descriptor response.
    pub fn complete_init(&mut self, mac_string: &[u8]) -> Result<(), CdcError>

    /// Feed a completed bulk IN transfer. Decodes frames, queues to rx_queue.
    /// Returns re-queue action.
    pub fn receive_bulk_in(&mut self, data: &[u8]) -> Vec<CdcAction>

    /// Feed a completed interrupt IN transfer. Updates link/speed state.
    /// Returns re-queue action.
    pub fn receive_interrupt(&mut self, data: &[u8]) -> Vec<CdcAction>

    /// Encode and send a frame. Returns BulkOut action.
    pub fn send_frame(&mut self, frame: &[u8]) -> Result<Vec<CdcAction>, CdcError>
}

impl NetworkDevice for CdcEthernetDriver {
    fn poll_tx(&mut self, out: &mut [u8]) -> Option<usize>;
    fn push_rx(&mut self, frame: &[u8]) -> bool;
    fn mac(&self) -> [u8; 6];
    fn link_up(&self) -> bool;
}
```

**Two-phase init:** USB Ethernet Networking functional descriptors contain a MAC string descriptor *index*, not the MAC itself. `from_config_descriptor` returns a `CdcAction::ControlOut` to request the string descriptor. The caller feeds the response to `complete_init`, which parses the USB string descriptor format into a 6-byte MAC.

**NetworkDevice semantics:** `poll_tx` pops from `rx_queue` (frames received from USB adapter). `push_rx` sends frames out via USB bulk OUT. The naming follows the network stack's perspective, not the USB direction.

---

## CDC Descriptor Parsing

The parser walks raw USB configuration descriptor bytes (flat TLV stream):

```
Config Descriptor (9 bytes)
  Interface Descriptor (class 0x02, subclass 0x06=ECM or 0x0D=NCM)
    CDC Header Functional Descriptor (5 bytes, CS_INTERFACE type 0x24)
    CDC Union Functional Descriptor (5 bytes) — control + data interface numbers
    CDC Ethernet Networking Functional Descriptor (13 bytes) — MAC index, max segment
    [OR] CDC NCM Functional Descriptor (6 bytes) — NTB parameters
    Endpoint Descriptor — interrupt IN
  Interface Descriptor — Data Interface alt 0 (no endpoints, idle)
  Interface Descriptor — Data Interface alt 1 (active)
    Endpoint Descriptor — bulk IN
    Endpoint Descriptor — bulk OUT
```

**Matching rules:**
- `bInterfaceClass = 0x02` (Communication Interface Class)
- `bInterfaceSubclass = 0x06` (ECM) or `0x0D` (NCM)
- Functional descriptors: `bDescriptorType = 0x24` (CS_INTERFACE)
- Union descriptor links control interface to data interface
- Data interface alt setting 1 has the actual bulk endpoints

```rust
// descriptor.rs
pub fn parse_cdc_config(config_desc: &[u8]) -> Result<CdcDescriptors, CdcError>

pub struct CdcDescriptors {
    pub protocol: CdcProtocol,
    pub control_interface: u8,
    pub data_interface: u8,
    pub data_alt_setting: u8,
    pub interrupt_ep: EndpointInfo,
    pub bulk_in_ep: EndpointInfo,
    pub bulk_out_ep: EndpointInfo,
    pub mac_string_index: u8,
    pub max_segment_size: u16,
    pub max_ntb_size: u32,        // NCM only, 0 for ECM
}

pub struct EndpointInfo {
    pub address: u8,
    pub max_packet_size: u16,
}
```

---

## NCM Transfer Format

NCM wraps Ethernet frames in NTH16 + NDP16 headers within each USB bulk transfer:

```
┌─────────────────────────────────────────┐
│ NTH16 (12 bytes)                        │
│   dwSignature: 0x484D434E ("NCMH")     │
│   wHeaderLength: 12                      │
│   wSequence: monotonic counter           │
│   wBlockLength: total transfer size      │
│   wNdpIndex: offset to first NDP16      │
├─────────────────────────────────────────┤
│ NDP16 (16+ bytes)                       │
│   dwSignature: 0x304D434E ("NCM0")     │
│   wLength: size of this NDP             │
│   wNextNdpIndex: 0 (no chaining)        │
│   Datagram pointers: (index, length)    │
│   Terminator: (0, 0)                    │
├─────────────────────────────────────────┤
│ Ethernet frame 0                         │
│ Ethernet frame 1 ...                     │
└─────────────────────────────────────────┘
```

**Decode:** Validate NTH16 signature → walk NDP16 datagram pointers → extract frames. Follow `wNextNdpIndex` chain if non-zero. Bounds-check all offsets.

**Encode:** Single frame per NTB (28 bytes overhead). Multi-frame batching is a future optimization.

```rust
// ncm.rs
pub fn decode_ntb(data: &[u8], out: &mut Vec<Vec<u8>>) -> Result<(), CdcError>
pub fn encode_ntb(frame: &[u8], sequence: u16) -> Result<Vec<u8>, CdcError>
```

Malformed NTBs (bad signature, out-of-bounds offsets, overlapping datagrams) return `CdcError::MalformedNtb`.

---

## CDC Notifications

Arrive on the interrupt IN endpoint. 8-byte header, optional payload.

```rust
pub enum CdcNotification {
    NetworkConnection { connected: bool },
    ConnectionSpeedChange { downstream: u32, upstream: u32 },
    Unknown { request: u8 },
}

pub fn parse_notification(data: &[u8]) -> Result<CdcNotification, CdcError>
```

- `NETWORK_CONNECTION` (0x00): `wValue` = 0 (disconnected) or 1 (connected). No payload.
- `CONNECTION_SPEED_CHANGE` (0x2A): 8-byte payload, two LE u32 (downstream, upstream).
- Unknown types: returned as `Unknown`, not errors. Silently ignored by the driver.

---

## Error Handling

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdcError {
    // Descriptor parsing
    DescriptorTooShort,
    NoCdcInterface,
    MissingEndpoint,
    MissingFunctionalDescriptor,
    InvalidMacString,

    // NCM transfer blocks
    MalformedNtb,

    // Data path
    FrameTooLarge,
    NotReady,
}
```

- Descriptor errors are fatal — device unusable. `from_config_descriptor` returns `Ok(None)` if no CDC interface found, `Err(CdcError)` if found but malformed.
- NCM decode errors are per-transfer — drop the NTB, re-queue bulk IN.
- TX errors bubble up through `NetworkDevice::push_rx` returning `false`.
- No retry logic — caller's responsibility (sans-I/O principle).

---

## Testing

All unit tests with hand-crafted byte vectors. No hardware dependencies.

**Descriptor parsing:** ECM and NCM config descriptor byte arrays, missing descriptors, truncated input, no CDC interface, multiple interfaces.

**NCM codec:** Single-frame and multi-frame NTB round-trip, chained NDP16, malformed NTBs (bad signature, out-of-bounds, overlaps, zero-length).

**ECM codec:** Passthrough verification — encode/decode are identity functions.

**Notifications:** NETWORK_CONNECTION, CONNECTION_SPEED_CHANGE with payload, unknown type, truncated data.

**Driver integration:** Full `from_config_descriptor` → `complete_init` → `receive_bulk_in` → `poll_tx` flow for both ECM and NCM. `push_rx` → `CdcAction::BulkOut` verification. Link state changes via `receive_interrupt`. Confirm `VirtioNetServer<CdcEthernetDriver>` compiles.

---

## Scope Boundary

**In scope:**
- `CdcEthernetDriver` (Ring 1, `harmony-unikernel`)
- ECM + NCM via `CdcCodec` enum
- CDC descriptor parsing from USB config descriptor bytes
- Two-phase init (descriptors, then MAC string response)
- NTH16/NDP16 encode/decode
- CDC notification parsing
- `NetworkDevice` trait implementation (reuses `VirtioNetServer` at Ring 2)
- `CdcAction` return type for sans-I/O
- Polling-based data path
- Unit tests with byte vectors
- Pure CDC class matching (`bInterfaceClass=0x02`, subclass 0x06 or 0x0D)

**Out of scope:**
- Ring 2 9P server (reuses `VirtioNetServer` unchanged)
- USB gadget/device mode (separate future bead — DWC2 OTG)
- Vendor-specific quirks / device ID table
- Event-driven transfer completion
- NCM multi-frame TX batching (single frame per NTB initially)
- NTB32 format (only for transfers > 64KB, extremely rare)
- NCM datagram CRC (optional per spec, almost never used)
- Hot-swap `/state` file
- xHCI Phase 3b integration (interrupt transfers not landed yet)
