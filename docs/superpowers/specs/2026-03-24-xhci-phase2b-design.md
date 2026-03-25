# xHCI Phase 2b: Enable Slot + Address Device + GET_DESCRIPTOR

## Goal

Enable device slots, assign USB addresses, and read device descriptors via control transfers on endpoint 0. After Phase 2b, the driver can identify every connected USB device by vendor ID, product ID, and device class.

## Scope

**In scope:**
- New TRB types: Enable Slot, Address Device, Setup/Data/Status Stage, Transfer Event
- Device context byte-array builder (Input Context: 96 bytes)
- DCBAA setup (CONFIG + DCBAAP write with actual slot count)
- TransferRing for EP0 control transfers
- `enable_slot()`, `address_device()`, `get_device_descriptor()` driver methods
- `DeviceDescriptor` struct parsed from 18-byte USB descriptor
- `parse_device_descriptor()` static parsing method
- Transfer Event handling in `process_event()`

**Out of scope:**
- Configuration selection (Phase 3)
- Interface/endpoint enumeration (Phase 3)
- Class drivers (mass storage, HID, network)
- Multiple configurations or alternate settings
- Interrupt-driven operation (polling only)
- USB hubs (only root port devices)
- Isochronous or bulk transfers

## Architecture

### Sans-I/O Pattern (Continued)

Same as Phase 2a: driver returns `Vec<XhciAction>` for the caller to execute. Phase 2b adds `WriteDma` for non-TRB DMA writes (DCBAA entries). The caller sequences four method calls with event processing between each:

```
setup_dcbaa(dcbaa_phys)
    → caller writes DCBAA, executes register actions
enable_slot()
    → caller executes actions, polls for CommandCompletion → slot_id
address_device(slot_id, port, speed, ...)
    → caller writes Input Context to DMA, executes actions, polls for CommandCompletion
get_device_descriptor(slot_id, data_buf_phys)
    → caller executes actions, polls for TransferEvent, reads 18 bytes from data_buf_phys
parse_device_descriptor(data)
    → DeviceDescriptor { vendor_id, product_id, device_class, ... }
```

### Data Flow

```
Caller allocates DMA:
  - DCBAA: (max_slots + 1) * 8 bytes
  - Input Context: 96 bytes per device
  - Output Context: 96 bytes per device (controller writes here)
  - EP0 Transfer Ring: 64 * 16 = 1024 bytes per device
  - Data buffer: 18 bytes for device descriptor
    ↓
driver.setup_dcbaa(dcbaa_phys) → [WriteRegister(CONFIG), WriteRegister64(DCBAAP)]
    ↓
driver.enable_slot() → [WriteTrb(Enable Slot cmd), RingDoorbell(0)]
    ↓ caller processes CommandCompletion → slot_id
driver.address_device(slot_id, port, speed, input_ctx_phys, output_ctx_phys, xfer_ring_phys)
    → ([WriteDma(DCBAA slot), WriteTrb(Address Device cmd), RingDoorbell(0)], [u8; 96])
    ↓ caller writes 96-byte Input Context to input_ctx_phys, executes actions
    ↓ caller processes CommandCompletion
driver.get_device_descriptor(slot_id, data_buf_phys)
    → [WriteTrb(Setup), WriteTrb(Data), WriteTrb(Status), RingDoorbell(slot)]
    ↓ caller executes actions
    ↓ caller processes TransferEvent, reads 18 bytes from data_buf_phys
parse_device_descriptor(&data) → DeviceDescriptor
```

## New TRB Types and Constants

### Command TRBs
```rust
pub const TRB_ENABLE_SLOT: u8 = 9;
pub const TRB_ADDRESS_DEVICE: u8 = 11;
```

### Transfer TRBs
```rust
pub const TRB_SETUP_STAGE: u8 = 2;
pub const TRB_DATA_STAGE: u8 = 3;
pub const TRB_STATUS_STAGE: u8 = 4;
```

### Event TRBs
```rust
pub const TRB_TRANSFER_EVENT: u8 = 32;
```

### Transfer TRB Flags
```rust
/// Transfer Type = IN (device-to-host) for Setup TRB.
pub const TRT_IN: u32 = 3 << 16;
/// Direction = IN for Data TRB.
pub const DIR_IN: u32 = 1 << 16;
/// Immediate Data — Setup TRB contains the 8-byte SETUP packet inline.
pub const IDT: u32 = 1 << 6;
/// Interrupt On Completion — post event when this TRB completes.
pub const IOC: u32 = 1 << 5;
```

### USB Standard Request Constants
```rust
pub const USB_REQ_GET_DESCRIPTOR: u8 = 6;
pub const USB_DESC_DEVICE: u8 = 1;
pub const USB_DEVICE_DESCRIPTOR_SIZE: usize = 18;
```

## Device Context Builder (`context.rs`)

### build_input_context

```rust
pub fn build_input_context(
    port: u8,
    speed: UsbSpeed,
    transfer_ring_phys: u64,
) -> [u8; 96]
```

Packs a 96-byte Input Context:

**Input Control Context** (bytes 0..31):
- DWord 1 (offset 4): Add Context Flags = `0x03` (add Slot + EP0)
- All other bytes zero.

**Slot Context** (bytes 32..63):
- DWord 0: Context Entries = 1 (bits 31:27), Speed (bits 23:20), Route String = 0
- DWord 1: Root Hub Port Number (bits 23:16) = `port`
- All other bytes zero.

**Endpoint 0 Context** (bytes 64..95):
- DWord 1: EP Type = Control Bidirectional = 4 (bits 5:3), Max Packet Size (bits 31:16)
  - Max Packet Size: 8 (LowSpeed/FullSpeed), 64 (HighSpeed), 512 (SuperSpeed/SuperSpeedPlus)
  - FullSpeed uses 8 as conservative initial default (USB 2.0 §9.6.1 allows 8/16/32/64); update from bMaxPacketSize0 after GET_DESCRIPTOR
- DWord 2 (low 32 bits of TR Dequeue Pointer): `transfer_ring_phys as u32 | 1` (DCS = 1)
- DWord 3 (high 32 bits): `(transfer_ring_phys >> 32) as u32`
- DWord 4: Average TRB Length = 8 (bits 15:0)

### max_packet_size_for_speed

```rust
pub fn max_packet_size_for_speed(speed: UsbSpeed) -> u16
```

Returns the default max packet size for EP0 based on link speed. Returns 8 for `Unknown` (safe minimum — USB spec allows 8-byte packets on any speed).

Note: the 96-byte Input Context assumes 32-byte contexts (CSZ=0 in HCCPARAMS1). RPi5's BCM2712 xHCI uses 32-byte contexts. If CSZ=1 (64-byte contexts), sizes would double to 192 bytes — revisit for future hardware ports.

### get_descriptor_setup_packet

```rust
pub fn get_descriptor_setup_packet(desc_type: u8, desc_index: u8, length: u16) -> [u8; 8]
```

Packs the 8-byte USB SETUP packet:
- Byte 0: bmRequestType = `0x80` (device-to-host, standard, device recipient)
- Byte 1: bRequest = `USB_REQ_GET_DESCRIPTOR` (6)
- Bytes 2-3: wValue = `(desc_type << 8) | desc_index` (LE)
- Bytes 4-5: wIndex = 0 (LE)
- Bytes 6-7: wLength = `length` (LE)

### parse_device_descriptor

```rust
pub fn parse_device_descriptor(data: &[u8]) -> Result<DeviceDescriptor, XhciError>
```

Parses the standard 18-byte USB Device Descriptor:
- Validates `data.len() >= 18`
- Validates `data[1] == USB_DESC_DEVICE` (descriptor type field)
- Extracts all fields using little-endian byte order

## DeviceDescriptor

```rust
pub struct DeviceDescriptor {
    /// USB specification version (BCD, e.g., 0x0200 = USB 2.0).
    pub usb_version: u16,
    /// Device class code (0 = per-interface, 0xFF = vendor-specific).
    pub device_class: u8,
    /// Device subclass code.
    pub device_subclass: u8,
    /// Device protocol code.
    pub device_protocol: u8,
    /// Maximum packet size for endpoint 0 (8, 16, 32, or 64 bytes).
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

## TransferRing

```rust
pub struct TransferRing {
    base_phys: u64,
    enqueue_index: u16,
    cycle_bit: bool,
}
```

Same size as CommandRing: 64 entries (63 usable + 1 Link TRB). Same enqueue/wrap/cycle-toggle mechanics. No `pending_count` — Phase 2b does one control transfer at a time.

### enqueue_control_in

```rust
pub fn enqueue_control_in(
    &mut self,
    setup_packet: [u8; 8],
    data_buf_phys: u64,
    data_len: u16,
) -> Result<Vec<(u64, Trb)>, XhciError>
```

Returns 3 TRBs (possibly + Link TRBs if wrapping occurs mid-sequence):

1. **Setup TRB**: parameter = setup_packet as u64 LE, status = 8, control = `TRB_SETUP_STAGE << 10 | TRT_IN | IDT | cycle`
2. **Data TRB**: parameter = data_buf_phys, status = data_len as u32, control = `TRB_DATA_STAGE << 10 | DIR_IN | cycle`
3. **Status TRB**: parameter = 0, status = 0, control = `TRB_STATUS_STAGE << 10 | IOC | cycle` (direction OUT — opposite of data phase, no DIR_IN flag)

IOC is set only on the Status TRB — one Transfer Event per control transfer. The controller still writes data to `data_buf_phys` during the Data stage; IOC only controls when the event is posted.

## XhciDriver Method Extensions

### setup_dcbaa

`setup_dcbaa(&mut self, dcbaa_phys: u64) -> Result<Vec<XhciAction>, XhciError>`

- Requires `Running` state
- Stores `dcbaa_phys` in driver
- Returns actions: WriteRegister(CONFIG, max_slots), WriteRegister64(DCBAAP, dcbaa_phys)
- Note: the controller must be stopped (USBCMD.RUN=0) to change DCBAAP safely. The method returns a halt→write→run sequence, or we document that this must be called immediately after `setup_rings` before any commands. The simpler approach: require this to be called before the first `enable_slot`, and have `setup_rings` call it internally if a DCBAA phys is provided. **Decision: add dcbaa_phys as an optional parameter to setup_rings.** This avoids the halt/restart dance.

**Revised: extend `setup_rings` signature:**
```rust
pub fn setup_rings(
    &mut self,
    cmd_ring_phys: u64,
    event_ring_phys: u64,
    erst_phys: u64,
    dcbaa_phys: u64,  // NEW — was zeroed in Phase 2a
    max_slots_enabled: u8,  // NEW — was 0 in Phase 2a
) -> Result<Vec<XhciAction>, XhciError>
```

Phase 2a callers pass `dcbaa_phys=0, max_slots_enabled=0` for backward compatibility. Phase 2b callers pass real values.

### enable_slot

`enable_slot(&mut self) -> Result<Vec<XhciAction>, XhciError>`

- Requires `Running` state
- Enqueues Enable Slot command on command ring
- Returns WriteTrb + RingDoorbell actions
- Caller processes `CommandCompletion { slot_id, completion_code }` — slot_id > 0 on success

### address_device

```rust
pub fn address_device(
    &mut self,
    slot_id: u8,
    port: u8,
    speed: UsbSpeed,
    input_context_phys: u64,
    output_context_phys: u64,
    transfer_ring_phys: u64,
) -> Result<(Vec<XhciAction>, [u8; 96]), XhciError>
```

- Requires `Running` state
- Builds Input Context via `build_input_context(port, speed, transfer_ring_phys)` → 96 bytes
- Creates DCBAA slot entry: `WriteDma` at `dcbaa_phys + slot_id * 8` with `output_context_phys` (8 bytes LE)
- Enqueues Address Device command: parameter = `input_context_phys`, control bits 31:24 = `slot_id`
- Returns `(actions, input_context_bytes)` — caller writes `input_context_bytes` to `input_context_phys` in DMA, then executes actions
- Creates and stores `TransferRing::new(transfer_ring_phys)` for this slot

### get_device_descriptor

`get_device_descriptor(&mut self, slot_id: u8, data_buf_phys: u64) -> Result<Vec<XhciAction>, XhciError>`

- Requires `Running` state + transfer ring for slot
- Builds setup packet: `get_descriptor_setup_packet(USB_DESC_DEVICE, 0, 18)`
- Enqueues 3-TRB control transfer via `transfer_ring.enqueue_control_in(setup, data_buf_phys, 18)`
- Returns WriteTrb actions + `RingDoorbell { offset: db_offset + 4 * slot_id, value: 1 }` (EP0 doorbell)

### process_event extension

Extend `process_event` to handle `TRB_TRANSFER_EVENT`:
```rust
TRB_TRANSFER_EVENT => {
    let slot_id = (trb.control >> 24) as u8;
    let endpoint_id = ((trb.control >> 16) & 0x1F) as u8;
    let completion_code = (trb.status >> 24) as u8;
    let transfer_length = trb.status & 0x00FF_FFFF;
    XhciEvent::TransferEvent { slot_id, endpoint_id, completion_code, transfer_length }
}
```

### parse_device_descriptor

`parse_device_descriptor(data: &[u8]) -> Result<DeviceDescriptor, XhciError>`

- Static method (no `&self`)
- Validates length >= 18 and descriptor type == 1
- Returns parsed `DeviceDescriptor`

## New Types

### XhciAction::WriteDma
```rust
/// Write arbitrary bytes to DMA memory (e.g., DCBAA slot entries).
WriteDma { phys: u64, data: Vec<u8> },
```

### XhciEvent::TransferEvent
```rust
/// A transfer completed on an endpoint.
TransferEvent {
    slot_id: u8,
    endpoint_id: u8,
    completion_code: u8,
    transfer_length: u32,
}
```

### New XhciError variants
```rust
/// No transfer ring configured for this slot/endpoint.
NoTransferRing,
/// Device descriptor data is malformed or too short.
InvalidDescriptor,
```

## File Map

| File | Change |
|------|--------|
| `dwc_usb/context.rs` | NEW: `build_input_context()`, `max_packet_size_for_speed()`, `get_descriptor_setup_packet()`, `parse_device_descriptor()`, `DeviceDescriptor` |
| `dwc_usb/ring.rs` | Add `TransferRing` with `enqueue_control_in()` |
| `dwc_usb/trb.rs` | Add TRB type constants, USB request constants, transfer TRB flags |
| `dwc_usb/types.rs` | Add `WriteDma` action, `TransferEvent` event, `DeviceDescriptor`, new error variants |
| `dwc_usb/mod.rs` | Extend `setup_rings` signature, add `enable_slot`, `address_device`, `get_device_descriptor`, `parse_device_descriptor` re-export, extend `process_event` for Transfer Events, `dcbaa_phys` + `transfer_rings` fields |

## Testing Strategy

### context.rs tests (~6 tests)
- `build_input_context_add_flags` — verify bytes 4..8 = 0x03 (Slot + EP0)
- `build_input_context_slot_context_speed` — verify speed bits in DWord 0
- `build_input_context_slot_context_port` — verify port number in DWord 1
- `build_input_context_ep0_max_packet_per_speed` — verify max packet size for each UsbSpeed
- `get_descriptor_setup_packet_layout` — verify 8-byte packet matches USB spec
- `parse_device_descriptor_valid` — parse known 18-byte descriptor
- `parse_device_descriptor_too_short` — 17 bytes → InvalidDescriptor
- `parse_device_descriptor_wrong_type` — byte[1] != 1 → InvalidDescriptor

### ring.rs tests (~4 tests)
- `transfer_ring_enqueue_control_returns_3_trbs` — verify Setup/Data/Status types and flags
- `transfer_ring_setup_trb_has_idt_and_trt_in` — verify IDT and TRT_IN flags
- `transfer_ring_data_trb_has_correct_phys_and_length` — verify data_buf_phys and data_len
- `transfer_ring_status_trb_has_ioc_and_dir_out` — verify IOC, no DIR_IN (direction OUT)

### mod.rs tests (~8 tests)
- `enable_slot_enqueues_command` — verify TRB type and doorbell
- `address_device_returns_input_context` — verify 96-byte array returned
- `address_device_writes_dcbaa_slot` — verify WriteDma at correct offset
- `address_device_creates_transfer_ring` — verify get_device_descriptor works after
- `get_device_descriptor_enqueues_3_trbs_and_doorbell` — verify transfer ring actions + slot doorbell
- `process_transfer_event` — feed Transfer Event TRB, verify TransferEvent parsed
- `parse_device_descriptor_integration` — build known descriptor bytes, verify all fields
- `get_device_descriptor_before_address_fails` — NoTransferRing error

## Future Work (Explicitly Deferred)

- **Phase 3 (harmony-os-e4v):** Configuration/interface/endpoint enumeration
- **USB hubs:** Hub device class requires port power, reset, and status management
- **Multiple endpoints:** Only EP0 (default control pipe) in Phase 2b
- **Interrupt-driven operation:** Polling only, EHB handling deferred
- **Error recovery:** Command failures are reported but not retried
- **Scratchpad buffers:** HCSPARAMS2 requirements deferred until real hardware testing
