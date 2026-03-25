# xHCI Phase 3: Configuration Enumeration + Bulk Endpoint — Design Spec

## Goal

Read configuration descriptors, parse the interface/endpoint tree,
SET_CONFIGURATION, and set up one bulk IN/OUT endpoint pair. After this,
a device is fully enumerable and ready for a class driver (mass storage,
network adapter) to issue bulk transfers.

## Background

Phase 2 delivers: `enable_slot` → `address_device` → `get_device_descriptor`.
The device has a USB address but no active configuration. Phase 3 completes
the enumeration sequence so the host knows what the device offers and can
talk to its bulk endpoints.

## USB Configuration Enumeration Flow

1. `GET_DESCRIPTOR(Configuration, index, 9)` — read 9-byte config header
   to learn `wTotalLength`
2. `GET_DESCRIPTOR(Configuration, index, wTotalLength)` — read full
   descriptor tree
3. Parse config → interface → endpoint descriptor chain
4. `SET_CONFIGURATION(bConfigurationValue)` — activate the configuration
5. `Configure Endpoint` xHCI command — set up transfer rings for the
   selected bulk endpoints

## New Data Types (`context.rs`)

### ConfigDescriptor

```rust
pub struct ConfigDescriptor {
    pub total_length: u16,
    pub num_interfaces: u8,
    pub config_value: u8,
    pub attributes: u8,
    pub max_power: u8,
}
```

Parsed from 9-byte USB Configuration Descriptor (bDescriptorType = 2).

### InterfaceDescriptor

```rust
pub struct InterfaceDescriptor {
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub num_endpoints: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
}
```

Parsed from 9-byte USB Interface Descriptor (bDescriptorType = 4).

### EndpointDescriptor

```rust
pub struct EndpointDescriptor {
    pub endpoint_address: u8,  // bit 7 = direction (1=IN), bits 3:0 = number
    pub attributes: u8,        // bits 1:0 = transfer type (2=bulk)
    pub max_packet_size: u16,
    pub interval: u8,
}
```

Parsed from 7-byte USB Endpoint Descriptor (bDescriptorType = 5).

### ConfigurationTree

```rust
pub struct ConfigurationTree {
    pub config: ConfigDescriptor,
    pub interfaces: Vec<(InterfaceDescriptor, Vec<EndpointDescriptor>)>,
}
```

Complete parsed configuration with all interfaces and their endpoints.

## Parsing

`parse_config_descriptor(data: &[u8]) -> Result<ConfigDescriptor, XhciError>`
— Parses just the 9-byte config header. Used after the first
GET_DESCRIPTOR to extract `wTotalLength`.

`parse_configuration_tree(data: &[u8]) -> Result<ConfigurationTree, XhciError>`
— Walks the full descriptor chain using `bLength` + `bDescriptorType`
at each position. Collects interface and endpoint descriptors into a tree.
Guards against zero `bLength` (infinite loop), truncated descriptors,
and unknown descriptor types (skipped).

## New Driver Methods (`mod.rs`)

### get_config_descriptor_header

```rust
pub fn get_config_descriptor_header(
    &mut self,
    slot_id: u8,
    config_index: u8,
    data_buf_phys: u64,
) -> Result<Vec<XhciAction>, XhciError>
```

Issues GET_DESCRIPTOR(Configuration, config_index, 9) as a 3-TRB
control-IN transfer on EP0. Same pattern as `get_device_descriptor`.

### get_config_descriptor_full

```rust
pub fn get_config_descriptor_full(
    &mut self,
    slot_id: u8,
    config_index: u8,
    data_buf_phys: u64,
    total_length: u16,
) -> Result<Vec<XhciAction>, XhciError>
```

Issues GET_DESCRIPTOR(Configuration, config_index, total_length) as a
3-TRB control-IN transfer. `total_length` comes from the previously
parsed `ConfigDescriptor.total_length`.

### set_configuration

```rust
pub fn set_configuration(
    &mut self,
    slot_id: u8,
    config_value: u8,
) -> Result<Vec<XhciAction>, XhciError>
```

Issues SET_CONFIGURATION as a control transfer (no data stage):
- bmRequestType = 0x00 (host-to-device, standard, device)
- bRequest = 9 (SET_CONFIGURATION)
- wValue = config_value
- wIndex = 0, wLength = 0

Uses a 2-TRB sequence: Setup + Status (no Data stage).

### configure_endpoint

```rust
pub fn configure_endpoint(
    &mut self,
    slot_id: u8,
    endpoints: &[EndpointDescriptor],
    input_ctx_phys: u64,
    xfer_ring_phys: &[(u8, u64)],  // (endpoint_id, ring_phys)
) -> Result<Vec<XhciAction>, XhciError>
```

Issues the xHCI Configure Endpoint command:
1. Builds Input Context with Add Flags for each endpoint
2. Populates Endpoint Context entries (EP type, max packet size,
   TR Dequeue Pointer, interval)
3. Enqueues Configure Endpoint TRB on the command ring
4. Creates `TransferRing` for each endpoint in `self.transfer_rings`

Endpoint ID mapping: `endpoint_id = 2 * ep_number + direction` where
direction = 0 for OUT, 1 for IN. EP0 is always endpoint_id 1.

## New Constants

```rust
pub const TRB_CONFIGURE_ENDPOINT: u8 = 12;
pub const USB_REQ_SET_CONFIGURATION: u8 = 9;
pub const USB_DESC_CONFIGURATION: u8 = 2;
pub const USB_DESC_INTERFACE: u8 = 4;
pub const USB_DESC_ENDPOINT: u8 = 5;
pub const CONFIG_DESCRIPTOR_SIZE: u16 = 9;
```

## Helpers

`endpoint_id_from_address(address: u8) -> u8` — Converts USB endpoint
address byte to xHCI endpoint ID:
`2 * (address & 0x0F) + if address & 0x80 != 0 { 1 } else { 0 }`

`build_configure_endpoint_input_context(slot_id, endpoints: &[EndpointDescriptor], xfer_ring_phys: &[(u8, u64)]) -> Vec<u8>`
— Builds the Input Context for Configure Endpoint command. `xfer_ring_phys`
maps each endpoint_id to its transfer ring physical address. Sets Add
Flags for each endpoint. Populates Endpoint Context entries based on
EndpointDescriptor fields.

`set_configuration_setup_packet(config_value) -> [u8; 8]` — Builds
8-byte SETUP packet for SET_CONFIGURATION (no data stage).

## TransferRing Key Changes

Currently `transfer_rings: BTreeMap<u8, TransferRing>` is keyed by
`slot_id` (only EP0). Change to `BTreeMap<u16, TransferRing>` keyed by
`(slot_id as u16) << 8 | endpoint_id as u16` to support multiple
endpoints per slot.

The existing `get_device_descriptor` and `remove_transfer_ring` methods
need updating to use the new key format (EP0 = endpoint_id 1).

## API Changes Summary

| Function | Location | Change |
|----------|----------|--------|
| `ConfigDescriptor` | context.rs | New struct |
| `InterfaceDescriptor` | context.rs | New struct |
| `EndpointDescriptor` | context.rs | New struct |
| `ConfigurationTree` | context.rs | New struct |
| `parse_config_descriptor` | context.rs | New function |
| `parse_configuration_tree` | context.rs | New function |
| `endpoint_id_from_address` | context.rs | New helper |
| `build_configure_endpoint_input_context` | context.rs | New helper |
| `set_configuration_setup_packet` | context.rs | New helper |
| `get_config_descriptor_header` | mod.rs | New method |
| `get_config_descriptor_full` | mod.rs | New method |
| `set_configuration` | mod.rs | New method |
| `configure_endpoint` | mod.rs | New method |
| `transfer_rings` key | mod.rs | `BTreeMap<u8>` → `BTreeMap<u16>` |
| `get_device_descriptor` | mod.rs | Update transfer ring key |
| `remove_transfer_ring` | mod.rs | Update transfer ring key |

## Testing

- **Config descriptor header parse**: 9-byte known vector → verify fields
- **Full config tree parse**: config + interface + 2 endpoints blob →
  verify tree structure
- **Parse malformed**: truncated, wrong type, zero bLength
- **get_config_descriptor_header**: 3 TRBs, wValue=(2<<8)|index, wLength=9
- **get_config_descriptor_full**: 3 TRBs, wLength=total_length
- **set_configuration**: Setup TRB bmRequestType=0x00, bRequest=9,
  wValue=config_value, no data stage (2 TRBs)
- **configure_endpoint**: Input Context flags, EP entries, command TRB,
  transfer rings created with correct keys
- **endpoint_id_from_address**: bulk IN 0x81 → 3, bulk OUT 0x02 → 4
- **Transfer ring key migration**: existing EP0 tests still pass

## Out of Scope

- Interrupt/isochronous endpoint setup (Phase 3b, bead harmony-os-ho8)
- Class drivers (mass storage, HID, network)
- USB hubs
- Error recovery / endpoint halt/stall handling
- Multiple configurations (rare in practice)
- Actual bulk data transfers (separate bead)
