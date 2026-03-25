# xHCI Phase 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Read configuration descriptors, parse interface/endpoint tree, SET_CONFIGURATION, and set up one bulk IN/OUT endpoint pair via Configure Endpoint.

**Architecture:** Extends the existing sans-I/O `XhciDriver` with four new methods (two GET_DESCRIPTOR variants, SET_CONFIGURATION control transfer, Configure Endpoint xHCI command) and USB descriptor parsing for config/interface/endpoint. Transfer ring key changes from `u8` (slot-only) to `u16` (slot+endpoint) to support multiple endpoints per device.

**Tech Stack:** Rust, `no_std` (alloc), xHCI spec, USB 2.0 descriptor format

---

## File Structure

| File | Change | Responsibility |
|------|--------|---------------|
| `crates/harmony-unikernel/src/drivers/dwc_usb/trb.rs` | Modify | Add TRB_CONFIGURE_ENDPOINT, USB descriptor/request constants |
| `crates/harmony-unikernel/src/drivers/dwc_usb/types.rs` | Modify | Add ConfigDescriptor, InterfaceDescriptor, EndpointDescriptor, ConfigurationTree structs |
| `crates/harmony-unikernel/src/drivers/dwc_usb/context.rs` | Modify | Add descriptor parsers, setup packet builders, Input Context builder for Configure Endpoint |
| `crates/harmony-unikernel/src/drivers/dwc_usb/ring.rs` | Modify | Add `enqueue_control_no_data` for SET_CONFIGURATION (Setup + Status, no Data stage) |
| `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs` | Modify | Transfer ring key migration, 4 new methods |

---

### Task 1: New constants and descriptor structs

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/trb.rs`
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/types.rs`

- [ ] **Step 1: Add TRB and USB constants to trb.rs**

Add after the existing `TRB_ADDRESS_DEVICE` constant:

```rust
/// Configure Endpoint Command TRB — sets up non-zero endpoints.
pub const TRB_CONFIGURE_ENDPOINT: u8 = 12;
```

Add after `USB_DEVICE_DESCRIPTOR_SIZE`:

```rust
pub const USB_REQ_SET_CONFIGURATION: u8 = 9;
pub const USB_DESC_CONFIGURATION: u8 = 2;
pub const USB_DESC_INTERFACE: u8 = 4;
pub const USB_DESC_ENDPOINT: u8 = 5;
pub const USB_CONFIG_DESCRIPTOR_HEADER_SIZE: u16 = 9;
```

- [ ] **Step 2: Add descriptor structs to types.rs**

Add after `DeviceDescriptor`:

```rust
/// Parsed USB Configuration Descriptor (9-byte header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDescriptor {
    pub total_length: u16,
    pub num_interfaces: u8,
    pub config_value: u8,
    pub attributes: u8,
    pub max_power: u8,
}

/// Parsed USB Interface Descriptor (9 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceDescriptor {
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub num_endpoints: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
}

/// Parsed USB Endpoint Descriptor (7 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointDescriptor {
    /// Bit 7 = direction (1=IN, 0=OUT), bits 3:0 = endpoint number.
    pub endpoint_address: u8,
    /// Bits 1:0 = transfer type (0=control, 1=iso, 2=bulk, 3=interrupt).
    pub attributes: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

/// Complete parsed USB configuration with interfaces and endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationTree {
    pub config: ConfigDescriptor,
    pub interfaces: Vec<(InterfaceDescriptor, Vec<EndpointDescriptor>)>,
}
```

Add `Vec` import at top: `use alloc::vec::Vec;`

- [ ] **Step 3: Run tests**

Run: `cargo test -p harmony-unikernel dwc_usb`
Expected: ALL PASS (no behavior change, just new types)

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/trb.rs crates/harmony-unikernel/src/drivers/dwc_usb/types.rs
git commit -m "feat(xhci): add Phase 3 constants and descriptor structs"
```

---

### Task 2: Descriptor parsing + helper functions

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/context.rs`

- [ ] **Step 1: Write failing tests for config descriptor parsing**

Add to `mod tests` in context.rs:

```rust
#[test]
fn parse_config_descriptor_valid() {
    let data: [u8; 9] = [
        9,    // bLength
        2,    // bDescriptorType = Configuration
        0x20, 0x00, // wTotalLength = 32
        1,    // bNumInterfaces
        1,    // bConfigurationValue
        0,    // iConfiguration (string index)
        0x80, // bmAttributes (bus-powered)
        50,   // bMaxPower (100mA)
    ];
    let desc = parse_config_descriptor(&data).unwrap();
    assert_eq!(desc.total_length, 32);
    assert_eq!(desc.num_interfaces, 1);
    assert_eq!(desc.config_value, 1);
    assert_eq!(desc.attributes, 0x80);
    assert_eq!(desc.max_power, 50);
}

#[test]
fn parse_config_descriptor_too_short() {
    assert_eq!(parse_config_descriptor(&[0u8; 8]), Err(XhciError::InvalidDescriptor));
}

#[test]
fn parse_config_descriptor_wrong_type() {
    let mut data = [0u8; 9];
    data[0] = 9;
    data[1] = 1; // Device, not Configuration
    assert_eq!(parse_config_descriptor(&data), Err(XhciError::InvalidDescriptor));
}
```

- [ ] **Step 2: Implement parse_config_descriptor**

```rust
/// Parse a 9-byte USB Configuration Descriptor header.
pub fn parse_config_descriptor(data: &[u8]) -> Result<ConfigDescriptor, XhciError> {
    if data.len() < 9 {
        return Err(XhciError::InvalidDescriptor);
    }
    if data[1] != trb::USB_DESC_CONFIGURATION {
        return Err(XhciError::InvalidDescriptor);
    }
    Ok(ConfigDescriptor {
        total_length: u16::from_le_bytes([data[2], data[3]]),
        num_interfaces: data[4],
        config_value: data[5],
        attributes: data[7],
        max_power: data[8],
    })
}
```

Add imports: `use super::types::{ConfigDescriptor, InterfaceDescriptor, EndpointDescriptor, ConfigurationTree};`

- [ ] **Step 3: Write failing tests for configuration tree parsing**

```rust
#[test]
fn parse_configuration_tree_valid() {
    // Config(9) + Interface(9) + Endpoint(7) + Endpoint(7) = 32 bytes
    let data: [u8; 32] = [
        // Config descriptor
        9, 2, 32, 0, 1, 1, 0, 0x80, 50,
        // Interface descriptor
        9, 4, 0, 0, 2, 0x08, 0x06, 0x50, 0,
        // Endpoint descriptor (bulk OUT 0x02)
        7, 5, 0x02, 0x02, 0x00, 0x02, 0,
        // Endpoint descriptor (bulk IN 0x82)
        7, 5, 0x82, 0x02, 0x00, 0x02, 0,
    ];
    let tree = parse_configuration_tree(&data).unwrap();
    assert_eq!(tree.config.config_value, 1);
    assert_eq!(tree.interfaces.len(), 1);
    let (iface, eps) = &tree.interfaces[0];
    assert_eq!(iface.interface_class, 0x08); // Mass Storage
    assert_eq!(eps.len(), 2);
    assert_eq!(eps[0].endpoint_address, 0x02); // bulk OUT
    assert_eq!(eps[1].endpoint_address, 0x82); // bulk IN
}

#[test]
fn parse_configuration_tree_zero_blength_guard() {
    let mut data = [0u8; 16];
    data[0] = 9; data[1] = 2; data[2] = 16; // config header, total=16
    // byte 9: bLength=0 would cause infinite loop
    assert_eq!(parse_configuration_tree(&data), Err(XhciError::InvalidDescriptor));
}
```

- [ ] **Step 4: Implement parse_configuration_tree**

```rust
/// Parse a full USB configuration descriptor tree.
pub fn parse_configuration_tree(data: &[u8]) -> Result<ConfigurationTree, XhciError> {
    let config = parse_config_descriptor(data)?;
    let total = config.total_length as usize;
    if data.len() < total {
        return Err(XhciError::InvalidDescriptor);
    }

    let mut interfaces = Vec::new();
    let mut current_iface: Option<InterfaceDescriptor> = None;
    let mut current_eps = Vec::new();
    let mut pos = 9; // skip config header

    while pos < total {
        if pos + 1 >= total {
            break;
        }
        let b_length = data[pos] as usize;
        if b_length == 0 {
            return Err(XhciError::InvalidDescriptor);
        }
        if pos + b_length > total {
            break;
        }
        let b_desc_type = data[pos + 1];

        match b_desc_type {
            trb::USB_DESC_INTERFACE if b_length >= 9 => {
                // Save previous interface if any
                if let Some(iface) = current_iface.take() {
                    interfaces.push((iface, core::mem::take(&mut current_eps)));
                }
                current_iface = Some(InterfaceDescriptor {
                    interface_number: data[pos + 2],
                    alternate_setting: data[pos + 3],
                    num_endpoints: data[pos + 4],
                    interface_class: data[pos + 5],
                    interface_subclass: data[pos + 6],
                    interface_protocol: data[pos + 7],
                });
            }
            trb::USB_DESC_ENDPOINT if b_length >= 7 => {
                current_eps.push(EndpointDescriptor {
                    endpoint_address: data[pos + 2],
                    attributes: data[pos + 3],
                    max_packet_size: u16::from_le_bytes([data[pos + 4], data[pos + 5]]),
                    interval: data[pos + 6],
                });
            }
            _ => {} // skip unknown descriptors
        }
        pos += b_length;
    }
    // Save last interface
    if let Some(iface) = current_iface.take() {
        interfaces.push((iface, current_eps));
    }

    Ok(ConfigurationTree { config, interfaces })
}
```

- [ ] **Step 5: Add endpoint_id_from_address helper and test**

```rust
/// Convert USB endpoint address byte to xHCI endpoint ID (DCI).
///
/// Formula: `2 * endpoint_number + direction` where direction = 1 for IN, 0 for OUT.
/// EP0 is always DCI 1 (handled separately by address_device).
pub fn endpoint_id_from_address(address: u8) -> u8 {
    let ep_num = address & 0x0F;
    let dir = if address & 0x80 != 0 { 1u8 } else { 0u8 };
    2 * ep_num + dir
}
```

Test:
```rust
#[test]
fn endpoint_id_mapping() {
    assert_eq!(endpoint_id_from_address(0x01), 2);  // OUT EP1
    assert_eq!(endpoint_id_from_address(0x81), 3);  // IN EP1
    assert_eq!(endpoint_id_from_address(0x02), 4);  // OUT EP2
    assert_eq!(endpoint_id_from_address(0x82), 5);  // IN EP2
}
```

- [ ] **Step 6: Add set_configuration_setup_packet helper and test**

```rust
/// Build an 8-byte SETUP packet for SET_CONFIGURATION (no data stage).
pub fn set_configuration_setup_packet(config_value: u8) -> [u8; 8] {
    let mut pkt = [0u8; 8];
    pkt[0] = 0x00; // bmRequestType: host-to-device, standard, device
    pkt[1] = trb::USB_REQ_SET_CONFIGURATION;
    pkt[2] = config_value; // wValue low byte
    // pkt[3] = 0 (wValue high byte)
    // wIndex = 0, wLength = 0 (all zeros already)
    pkt
}
```

Test:
```rust
#[test]
fn set_configuration_setup_packet_layout() {
    let pkt = set_configuration_setup_packet(1);
    assert_eq!(pkt[0], 0x00, "bmRequestType: host-to-device");
    assert_eq!(pkt[1], trb::USB_REQ_SET_CONFIGURATION);
    assert_eq!(pkt[2], 1, "wValue = config_value");
    assert_eq!(u16::from_le_bytes([pkt[6], pkt[7]]), 0, "wLength = 0");
}
```

- [ ] **Step 7: Run tests and clippy**

Run: `cargo test -p harmony-unikernel dwc_usb && cargo clippy --workspace --all-targets -- -D warnings`
Expected: ALL PASS

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/context.rs
git commit -m "feat(xhci): config/interface/endpoint descriptor parsing + helpers"
```

---

### Task 3: Transfer ring key migration + enqueue_control_no_data

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs`
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/ring.rs`

- [ ] **Step 1: Add enqueue_control_no_data to TransferRing**

Add to `ring.rs` TransferRing impl:

```rust
/// Enqueue a control transfer with no data stage (Setup + Status).
///
/// Used for SET_CONFIGURATION and similar host-to-device requests
/// where wLength = 0.
pub fn enqueue_control_no_data(
    &mut self,
    setup_packet: [u8; 8],
) -> Result<Vec<(u64, Trb)>, XhciError> {
    use super::trb::{IDT, IOC, TRB_SETUP_STAGE, TRB_STATUS_STAGE};

    let mut all_entries = Vec::new();

    // 1. Setup TRB: parameter = setup packet as u64 LE, status = 8
    // TRT = 0 (No Data Stage) — bits 17:16 = 00
    let setup_param = u64::from_le_bytes(setup_packet);
    let setup_entries = self.enqueue_one(TRB_SETUP_STAGE, setup_param, 8, IDT)?;
    all_entries.extend(setup_entries);

    // 2. Status TRB: direction IN (device sends zero-length ACK), IOC
    // For no-data control transfers, Status stage direction is IN.
    let status_entries =
        self.enqueue_one(TRB_STATUS_STAGE, 0, 0, super::trb::DIR_IN | IOC)?;
    all_entries.extend(status_entries);

    Ok(all_entries)
}
```

Test in ring.rs tests:
```rust
#[test]
fn control_no_data_produces_two_trbs() {
    let mut ring = TransferRing::new(0x9000_0000);
    let setup = [0u8; 8];
    let entries = ring.enqueue_control_no_data(setup).unwrap();
    // Setup + Status = 2 TRBs minimum (no Link wraps at index 0)
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].1.trb_type(), TRB_SETUP_STAGE);
    assert_eq!(entries[1].1.trb_type(), TRB_STATUS_STAGE);
}
```

- [ ] **Step 2: Migrate transfer_rings key from u8 to u16, add test helper**

In `mod.rs`, change:

```rust
transfer_rings: BTreeMap<u8, ring::TransferRing>,
```
to:
```rust
transfer_rings: BTreeMap<u16, ring::TransferRing>,
```

Add a helper:
```rust
/// Compute transfer ring key: (slot_id << 8) | endpoint_id.
fn ring_key(slot_id: u8, endpoint_id: u8) -> u16 {
    (slot_id as u16) << 8 | endpoint_id as u16
}
```

Update `address_device`:
- `self.transfer_rings.contains_key(&slot_id)` → `self.transfer_rings.contains_key(&ring_key(slot_id, 1))`
- `self.transfer_rings.insert(slot_id, ...)` → `self.transfer_rings.insert(ring_key(slot_id, 1), ...)`

Update `remove_transfer_ring`:
- `self.transfer_rings.remove(&slot_id)` → `self.transfer_rings.remove(&ring_key(slot_id, 1))`

Update `get_device_descriptor`:
- `self.transfer_rings.get_mut(&slot_id)` → `self.transfer_rings.get_mut(&ring_key(slot_id, 1))`

Update all test initializations where `transfer_rings: BTreeMap::new()` — these don't need changes (empty map with different key type).

Add a test helper inside `#[cfg(test)] mod tests` in mod.rs:

```rust
/// Helper: create a Running driver with a slot addressed and ready for transfers.
fn make_running_driver_with_slot(slot_id: u8) -> XhciDriver {
    let mut bank = mock_init_success();
    let mut driver = XhciDriver::init(&mut bank).unwrap();
    driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000, 0x5000_0000, 4).unwrap();
    driver.address_device(slot_id, 1, UsbSpeed::HighSpeed, 0x6000_0000, 0x7000_0000, 0x8000_0000).unwrap();
    driver
}
```

- [ ] **Step 3: Run ALL existing tests**

Run: `cargo test -p harmony-unikernel dwc_usb`
Expected: ALL existing tests still pass (key migration is mechanical)

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs crates/harmony-unikernel/src/drivers/dwc_usb/ring.rs
git commit -m "refactor(xhci): transfer ring key u8→u16 for multi-endpoint, add enqueue_control_no_data"
```

---

### Task 4: New driver methods

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs`
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/context.rs`

- [ ] **Step 1: Add get_config_descriptor_header and test**

In mod.rs, add method (follows `get_device_descriptor` pattern exactly):

```rust
/// Enqueue GET_DESCRIPTOR(Configuration) for the 9-byte header.
pub fn get_config_descriptor_header(
    &mut self,
    slot_id: u8,
    config_index: u8,
    data_buf_phys: u64,
) -> Result<Vec<XhciAction>, XhciError> {
    if self.state != XhciState::Running || slot_id == 0 || slot_id > self.max_slots_enabled {
        return Err(XhciError::InvalidState);
    }
    let xfer_ring = self
        .transfer_rings
        .get_mut(&ring_key(slot_id, 1))
        .ok_or(XhciError::NoTransferRing)?;

    let setup = context::get_descriptor_setup_packet(
        trb::USB_DESC_CONFIGURATION,
        config_index,
        trb::USB_CONFIG_DESCRIPTOR_HEADER_SIZE,
    );
    let entries = xfer_ring.enqueue_control_in(
        setup,
        data_buf_phys,
        trb::USB_CONFIG_DESCRIPTOR_HEADER_SIZE,
    )?;

    let mut actions: Vec<XhciAction> = entries
        .into_iter()
        .map(|(phys, t)| XhciAction::WriteTrb { phys, trb: t })
        .collect();

    actions.push(XhciAction::RingDoorbell {
        offset: self.db_offset as usize + 4 * (slot_id as usize),
        value: 1,
    });

    Ok(actions)
}
```

Test:
```rust
#[test]
fn get_config_descriptor_header_produces_trbs() {
    let mut driver = make_running_driver_with_slot(1);
    let actions = driver.get_config_descriptor_header(1, 0, 0xB000_0000).unwrap();
    // 3 TRBs (Setup/Data/Status) + 1 RingDoorbell = 4 actions
    let trb_count = actions.iter().filter(|a| matches!(a, XhciAction::WriteTrb { .. })).count();
    assert_eq!(trb_count, 3);
    assert!(actions.iter().any(|a| matches!(a, XhciAction::RingDoorbell { .. })));
}
```

(Note: `make_running_driver_with_slot` is a test helper that creates a Running-state driver with slot 1 addressed. Build this from the existing test patterns in mod.rs.)

- [ ] **Step 2: Add get_config_descriptor_full and test**

Same as header but with caller-provided `total_length`:

```rust
/// Enqueue GET_DESCRIPTOR(Configuration) for the full descriptor tree.
pub fn get_config_descriptor_full(
    &mut self,
    slot_id: u8,
    config_index: u8,
    data_buf_phys: u64,
    total_length: u16,
) -> Result<Vec<XhciAction>, XhciError> {
    if self.state != XhciState::Running || slot_id == 0 || slot_id > self.max_slots_enabled {
        return Err(XhciError::InvalidState);
    }
    let xfer_ring = self
        .transfer_rings
        .get_mut(&ring_key(slot_id, 1))
        .ok_or(XhciError::NoTransferRing)?;

    let setup = context::get_descriptor_setup_packet(
        trb::USB_DESC_CONFIGURATION,
        config_index,
        total_length,
    );
    let entries = xfer_ring.enqueue_control_in(setup, data_buf_phys, total_length)?;

    let mut actions: Vec<XhciAction> = entries
        .into_iter()
        .map(|(phys, t)| XhciAction::WriteTrb { phys, trb: t })
        .collect();

    actions.push(XhciAction::RingDoorbell {
        offset: self.db_offset as usize + 4 * (slot_id as usize),
        value: 1,
    });

    Ok(actions)
}
```

- [ ] **Step 3: Add set_configuration and test**

```rust
/// Enqueue SET_CONFIGURATION control transfer (no data stage).
pub fn set_configuration(
    &mut self,
    slot_id: u8,
    config_value: u8,
) -> Result<Vec<XhciAction>, XhciError> {
    if self.state != XhciState::Running || slot_id == 0 || slot_id > self.max_slots_enabled {
        return Err(XhciError::InvalidState);
    }
    let xfer_ring = self
        .transfer_rings
        .get_mut(&ring_key(slot_id, 1))
        .ok_or(XhciError::NoTransferRing)?;

    let setup = context::set_configuration_setup_packet(config_value);
    let entries = xfer_ring.enqueue_control_no_data(setup)?;

    let mut actions: Vec<XhciAction> = entries
        .into_iter()
        .map(|(phys, t)| XhciAction::WriteTrb { phys, trb: t })
        .collect();

    actions.push(XhciAction::RingDoorbell {
        offset: self.db_offset as usize + 4 * (slot_id as usize),
        value: 1,
    });

    Ok(actions)
}
```

Test:
```rust
#[test]
fn set_configuration_produces_two_trbs() {
    let mut driver = make_running_driver_with_slot(1);
    let actions = driver.set_configuration(1, 1).unwrap();
    let trb_count = actions.iter().filter(|a| matches!(a, XhciAction::WriteTrb { .. })).count();
    assert_eq!(trb_count, 2, "Setup + Status, no Data stage");
}
```

- [ ] **Step 4: Add build_configure_endpoint_input_context helper**

In context.rs:

```rust
/// Build Input Context for Configure Endpoint command.
///
/// Layout: Input Control Context (32B) + Slot Context (32B) + EP Contexts (32B each).
/// xHCI §6.2.2.2: Context Entries in Slot Context must be ≥ largest endpoint DCI.
pub fn build_configure_endpoint_input_context(
    endpoints: &[EndpointDescriptor],
    xfer_ring_phys: &[(u8, u64)], // (endpoint_id, ring_phys)
) -> Vec<u8> {
    // Find max DCI to size the context
    let max_dci = endpoints
        .iter()
        .map(|ep| endpoint_id_from_address(ep.endpoint_address))
        .max()
        .unwrap_or(1);

    // Context size: 32B per entry (Input Control + Slot + EP0..max_dci)
    let num_entries = 2 + max_dci as usize; // Input Control + Slot + endpoints
    let ctx_size = num_entries * 32;
    let mut ctx = alloc::vec![0u8; ctx_size];

    // Input Control Context (bytes 0..31)
    // DWord 1 (offset 4): Add Context Flags — set bit for Slot (0) and each endpoint
    let mut add_flags: u32 = 0x01; // Slot context (bit 0)
    for ep in endpoints {
        let dci = endpoint_id_from_address(ep.endpoint_address);
        add_flags |= 1u32 << dci;
    }
    ctx[4..8].copy_from_slice(&add_flags.to_le_bytes());

    // Slot Context (bytes 32..63)
    // DWord 0: Context Entries = max_dci (bits 31:27)
    let slot_dw0: u32 = (max_dci as u32) << 27;
    ctx[32..36].copy_from_slice(&slot_dw0.to_le_bytes());

    // Endpoint Contexts (each 32 bytes, starting at offset 64)
    // EP context for DCI n starts at byte 32 * (1 + n) from ctx start
    for ep in endpoints {
        let dci = endpoint_id_from_address(ep.endpoint_address);
        let ep_offset = 32 * (1 + dci as usize);
        if ep_offset + 32 > ctx_size {
            continue;
        }

        // Look up the ring phys for this endpoint
        let ring_phys = xfer_ring_phys
            .iter()
            .find(|(id, _)| *id == dci)
            .map(|(_, phys)| *phys)
            .unwrap_or(0);

        // EP Type: bulk OUT = 2, bulk IN = 6 (see xHCI Table 6-9)
        let is_in = ep.endpoint_address & 0x80 != 0;
        let transfer_type = ep.attributes & 0x03;
        let ep_type: u32 = match (transfer_type, is_in) {
            (2, false) => 2, // Bulk OUT
            (2, true) => 6,  // Bulk IN
            (0, _) => 4,     // Control
            (1, false) => 1, // Isoch OUT
            (1, true) => 5,  // Isoch IN
            (3, false) => 3, // Interrupt OUT
            (3, true) => 7,  // Interrupt IN
            _ => 2,          // fallback to Bulk OUT
        };

        // DWord 1: CErr=3, EP Type, Max Packet Size
        let cerr: u32 = 3 << 1;
        let mps: u32 = (ep.max_packet_size as u32) << 16;
        let ep_dw1 = cerr | (ep_type << 3) | mps;
        ctx[ep_offset + 4..ep_offset + 8].copy_from_slice(&ep_dw1.to_le_bytes());

        // DWord 2-3: TR Dequeue Pointer | DCS=1
        let tr_ptr = ring_phys | 1;
        ctx[ep_offset + 8..ep_offset + 12].copy_from_slice(&(tr_ptr as u32).to_le_bytes());
        ctx[ep_offset + 12..ep_offset + 16].copy_from_slice(&((tr_ptr >> 32) as u32).to_le_bytes());

        // DWord 4: Average TRB Length (512 for bulk, 8 for control)
        let avg_trb = if transfer_type == 2 { 512u32 } else { 8u32 };
        ctx[ep_offset + 16..ep_offset + 20].copy_from_slice(&avg_trb.to_le_bytes());
    }

    ctx
}
```

Test:
```rust
#[test]
fn configure_endpoint_input_context_bulk_pair() {
    let eps = vec![
        EndpointDescriptor { endpoint_address: 0x02, attributes: 0x02, max_packet_size: 512, interval: 0 },
        EndpointDescriptor { endpoint_address: 0x82, attributes: 0x02, max_packet_size: 512, interval: 0 },
    ];
    let rings = vec![(4u8, 0xA000_0000u64), (5u8, 0xB000_0000u64)];
    let ctx = build_configure_endpoint_input_context(&eps, &rings);

    // Add flags: bit 0 (Slot) + bit 4 (EP2 OUT) + bit 5 (EP2 IN)
    let flags = u32::from_le_bytes(ctx[4..8].try_into().unwrap());
    assert_eq!(flags, 0x01 | (1 << 4) | (1 << 5));

    // Slot Context Entries = 5 (max DCI)
    let slot_dw0 = u32::from_le_bytes(ctx[32..36].try_into().unwrap());
    assert_eq!((slot_dw0 >> 27) & 0x1F, 5);
}
```

- [ ] **Step 5: Add configure_endpoint driver method and test**

In mod.rs:

```rust
/// Enqueue Configure Endpoint xHCI command.
///
/// Sets up transfer rings for the specified endpoints after
/// SET_CONFIGURATION succeeds.
pub fn configure_endpoint(
    &mut self,
    slot_id: u8,
    endpoints: &[EndpointDescriptor],
    input_ctx_phys: u64,
    xfer_ring_phys: &[(u8, u64)],
) -> Result<Vec<XhciAction>, XhciError> {
    if self.state != XhciState::Running || slot_id == 0 || slot_id > self.max_slots_enabled {
        return Err(XhciError::InvalidState);
    }

    let input_ctx = context::build_configure_endpoint_input_context(endpoints, xfer_ring_phys);

    let mut actions = Vec::new();

    // 1. Write Input Context to DMA
    actions.push(XhciAction::WriteDma {
        phys: input_ctx_phys,
        data: input_ctx,
    });

    // 2. Enqueue Configure Endpoint command
    let cmd_ring = self.command_ring.as_mut().ok_or(XhciError::InvalidState)?;
    let entries = cmd_ring.enqueue(trb::TRB_CONFIGURE_ENDPOINT, input_ctx_phys)?;

    for (phys, mut t) in entries {
        if t.trb_type() == trb::TRB_CONFIGURE_ENDPOINT {
            t.control |= (slot_id as u32) << 24;
        }
        actions.push(XhciAction::WriteTrb { phys, trb: t });
    }

    actions.push(XhciAction::RingDoorbell {
        offset: self.db_offset as usize,
        value: 0, // command doorbell
    });

    // 3. Create transfer rings for each endpoint
    for &(ep_id, ring_phys) in xfer_ring_phys {
        self.transfer_rings
            .insert(ring_key(slot_id, ep_id), ring::TransferRing::new(ring_phys));
    }

    Ok(actions)
}
```

Test:
```rust
#[test]
fn configure_endpoint_creates_rings_and_command() {
    use super::context::EndpointDescriptor;

    let mut driver = make_running_driver_with_slot(1);
    let eps = vec![
        EndpointDescriptor { endpoint_address: 0x02, attributes: 0x02, max_packet_size: 512, interval: 0 },
        EndpointDescriptor { endpoint_address: 0x82, attributes: 0x02, max_packet_size: 512, interval: 0 },
    ];
    let rings = vec![(4u8, 0xA000_0000u64), (5u8, 0xB000_0000u64)];
    let actions = driver.configure_endpoint(1, &eps, 0xC000_0000, &rings).unwrap();

    // Should have: WriteDma (input ctx) + WriteTrb (command) + RingDoorbell
    assert!(actions.iter().any(|a| matches!(a, XhciAction::WriteDma { .. })));
    assert!(actions.iter().any(|a| matches!(a, XhciAction::RingDoorbell { offset: _, value: 0 })));

    // Transfer rings should be created for both endpoints
    assert!(driver.transfer_rings.contains_key(&ring_key(1, 4)));
    assert!(driver.transfer_rings.contains_key(&ring_key(1, 5)));
}
```

(Note: the test needs access to `ring_key` and `transfer_rings`. Since `transfer_rings` is private and tests are `mod tests` inside mod.rs, this works. `ring_key` is a private fn in mod.rs, accessible from tests.)

- [ ] **Step 6: Run all tests and CI-parity checks**

```bash
cargo test -p harmony-unikernel dwc_usb
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
rustup run nightly cargo fmt --all -- --check
```

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/
git commit -m "feat(xhci): Phase 3 — config enumeration, SET_CONFIGURATION, Configure Endpoint"
```
