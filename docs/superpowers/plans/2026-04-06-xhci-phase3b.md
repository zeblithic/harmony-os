# xHCI Phase 3b: Interrupt Transfers + Evaluate Context — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add interrupt endpoint transfers, speed-correct interval encoding, and Evaluate Context (EP0 MPS update) to the xHCI driver, unblocking HID class drivers.

**Architecture:** All changes in `crates/harmony-unikernel/src/drivers/dwc_usb/`. Sans-I/O pattern preserved — methods return `Vec<XhciAction>`, caller executes. Four additions: interval encoding fix, interrupt transfer methods, Evaluate Context command, average TRB length tuning.

**Tech Stack:** Rust (no_std, alloc), MockRegisterBank for tests.

**Spec:** `docs/superpowers/specs/2026-04-06-xhci-phase3b-design.md`

---

## File Map

| File | Changes |
|------|---------|
| `crates/harmony-unikernel/src/drivers/dwc_usb/context.rs` | Add `interval_to_xhci_exponent()`, add `speed` param to `build_configure_endpoint_input_context()`, add `build_evaluate_context_ep0()`, fix avg TRB length |
| `crates/harmony-unikernel/src/drivers/dwc_usb/ring.rs` | Extract `enqueue_normal()` from `enqueue_bulk()`, add `enqueue_interrupt()` |
| `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs` | Add `slot_speeds` field, populate in `address_device()`, pass speed in `configure_endpoint()`, add `interrupt_transfer_in/out()`, add `evaluate_context()` |
| `crates/harmony-unikernel/src/drivers/dwc_usb/trb.rs` | Add `TRB_EVALUATE_CONTEXT` constant |

---

### Task 1: Interval Encoding + Average TRB Length

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/context.rs:249-349` (build_configure_endpoint_input_context)
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs:119-143` (XhciDriver struct)
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs:345-428` (address_device)
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs:828-882` (configure_endpoint)

This task adds speed-correct interval encoding for interrupt/isochronous endpoints, tracks device speed per slot, and fixes average TRB length for interrupt endpoints. All existing callers of `build_configure_endpoint_input_context` and `configure_endpoint` are updated.

- [ ] **Step 1: Write interval encoding tests**

Add these tests to the `#[cfg(test)] mod tests` block at the bottom of `context.rs` (after the existing `configure_endpoint_input_context_bulk_pair` test):

```rust
    #[test]
    fn interval_to_xhci_exponent_hs_interrupt_passthrough() {
        // HS interrupt: bInterval is already an exponent, pass through
        assert_eq!(interval_to_xhci_exponent(4, UsbSpeed::HighSpeed, 3), 4);
    }

    #[test]
    fn interval_to_xhci_exponent_fs_interrupt_conversion() {
        // FS bInterval=10 (10ms) → 80 microframes → exponent 7 (2^7=128 >= 80)
        assert_eq!(interval_to_xhci_exponent(10, UsbSpeed::FullSpeed, 3), 7);
    }

    #[test]
    fn interval_to_xhci_exponent_ls_interrupt_conversion() {
        // LS bInterval=8 (8ms) → 64 microframes → exponent 6 (2^6=64 >= 64)
        assert_eq!(interval_to_xhci_exponent(8, UsbSpeed::LowSpeed, 3), 6);
    }

    #[test]
    fn interval_to_xhci_exponent_ss_interrupt_passthrough() {
        // SS interrupt: bInterval is already an exponent, pass through
        assert_eq!(interval_to_xhci_exponent(3, UsbSpeed::SuperSpeed, 3), 3);
    }

    #[test]
    fn interval_to_xhci_exponent_bulk_stays_zero() {
        // Bulk endpoints always get interval=0 regardless of speed
        assert_eq!(interval_to_xhci_exponent(0, UsbSpeed::HighSpeed, 2), 0);
        assert_eq!(interval_to_xhci_exponent(5, UsbSpeed::FullSpeed, 2), 0);
    }

    #[test]
    fn interval_to_xhci_exponent_fs_minimum() {
        // FS bInterval=1 (1ms) → 8 microframes → exponent 3 (2^3=8 >= 8)
        assert_eq!(interval_to_xhci_exponent(1, UsbSpeed::FullSpeed, 3), 3);
    }

    #[test]
    fn interrupt_endpoint_avg_trb_length() {
        // Interrupt endpoint (attributes=0x03) should get avg TRB length 1024
        let eps = alloc::vec![EndpointDescriptor {
            endpoint_address: 0x81,
            attributes: 0x03,
            max_packet_size: 64,
            interval: 4,
        }];
        let rings = alloc::vec![(3u8, 0xA000_0000u64)];
        let mut slot_ctx = [0u8; 32];
        let slot_dw0: u32 = (1 << 27) | (3 << 20);
        slot_ctx[0..4].copy_from_slice(&slot_dw0.to_le_bytes());
        slot_ctx[4..8].copy_from_slice(&(1u32 << 16).to_le_bytes());

        let ctx = build_configure_endpoint_input_context(&slot_ctx, &eps, &rings, UsbSpeed::HighSpeed);

        // EP3 (Interrupt IN at DCI 3) context starts at byte offset 32 * (1 + 3) = 128
        let ep_offset = 32 * (1 + 3);
        // DWord 4 (offset 16 within EP context): Average TRB Length
        let avg_trb = u32::from_le_bytes(ctx[ep_offset + 16..ep_offset + 20].try_into().unwrap());
        assert_eq!(avg_trb, 1024, "interrupt endpoint should have avg TRB length 1024");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel interval_to_xhci -- --no-run 2>&1; cargo test -p harmony-unikernel interrupt_endpoint_avg -- --no-run 2>&1`
Expected: Compilation errors — `interval_to_xhci_exponent` doesn't exist yet, `build_configure_endpoint_input_context` doesn't accept `speed` parameter.

- [ ] **Step 3: Implement interval encoding + update configure endpoint input context**

In `context.rs`, add the `interval_to_xhci_exponent` function before `build_configure_endpoint_input_context` (around line 241):

```rust
/// Convert USB bInterval to xHCI endpoint context Interval field.
///
/// xHCI §6.2.3.6: Interval = exponent where polling period = 2^Interval * 125us.
/// - Bulk/Control: always 0 (interval not used)
/// - HS/SS/SSP interrupt/isoch: bInterval is already an exponent, clamp to 1..=16
/// - FS/LS interrupt: bInterval is milliseconds, convert to 125us microframes
fn interval_to_xhci_exponent(binterval: u8, speed: UsbSpeed, transfer_type: u8) -> u8 {
    // Bulk (2) and Control (0): interval not used
    if transfer_type != 1 && transfer_type != 3 {
        return 0;
    }

    match speed {
        UsbSpeed::HighSpeed | UsbSpeed::SuperSpeed | UsbSpeed::SuperSpeedPlus => {
            // bInterval is already an exponent per USB 2.0 §9.6.6 / USB 3.x §9.6.6
            binterval.max(1).min(16)
        }
        UsbSpeed::FullSpeed | UsbSpeed::LowSpeed | UsbSpeed::Unknown(_) => {
            // bInterval is in milliseconds. Convert to 125us microframes.
            // microframes = bInterval * 8 (1ms = 8 microframes at 125us each)
            // Find smallest exponent n where 2^n >= microframes
            if binterval == 0 {
                return 1; // minimum valid interval
            }
            let microframes = (binterval as u32) * 8;
            let mut exponent: u8 = 0;
            let mut val: u32 = 1;
            while val < microframes && exponent < 16 {
                exponent += 1;
                val <<= 1;
            }
            exponent.max(1).min(16)
        }
    }
}
```

Update `build_configure_endpoint_input_context` signature to add `speed: UsbSpeed`:

```rust
pub fn build_configure_endpoint_input_context(
    slot_context: &[u8],
    endpoints: &[EndpointDescriptor],
    xfer_ring_phys: &[(u8, u64)],
    speed: UsbSpeed,
) -> alloc::vec::Vec<u8> {
```

Replace the interval assignment block (lines 319-328) with:

```rust
        // DWord 0: Interval (bits 23:16) — speed-correct exponent encoding.
        let interval = interval_to_xhci_exponent(ep.interval, speed, transfer_type);
        if interval > 0 {
            let interval_dw0: u32 = (interval as u32) << 16;
            ctx[ep_offset..ep_offset + 4].copy_from_slice(&interval_dw0.to_le_bytes());
        }
```

Replace the average TRB length line (line 344) with:

```rust
        // DWord 4: Average TRB Length
        let avg_trb = match transfer_type {
            2 => 512u32,  // Bulk
            3 => 1024,    // Interrupt
            _ => 8,       // Control and others
        };
```

- [ ] **Step 4: Update existing test to pass speed parameter**

Update the existing `configure_endpoint_input_context_bulk_pair` test (line 606 in context.rs) to pass the new speed parameter:

Change:
```rust
        let ctx = build_configure_endpoint_input_context(&slot_ctx, &eps, &rings);
```
To:
```rust
        let ctx = build_configure_endpoint_input_context(&slot_ctx, &eps, &rings, UsbSpeed::HighSpeed);
```

- [ ] **Step 5: Add `slot_speeds` field and populate in `address_device`**

In `mod.rs`, add a new field to `XhciDriver` (after `transfer_rings` at line 142):

```rust
    /// USB speed per device slot (populated by address_device).
    slot_speeds: BTreeMap<u8, UsbSpeed>,
```

Initialize it in `XhciDriver::init()` — add after `transfer_rings: BTreeMap::new(),` (line 222):

```rust
            slot_speeds: BTreeMap::new(),
```

In `address_device()`, record the speed. Add after the `self.transfer_rings.insert(...)` call (after line 425):

```rust
        self.slot_speeds.insert(slot_id, speed);
```

- [ ] **Step 6: Update `configure_endpoint` to pass speed**

In `mod.rs`, update `configure_endpoint` to look up the slot speed and pass it to the context builder. Replace the `context::build_configure_endpoint_input_context` call (lines 845-849):

Change:
```rust
        let input_ctx = context::build_configure_endpoint_input_context(
            slot_context,
            endpoints,
            xfer_ring_phys,
        );
```
To:
```rust
        let speed = self.slot_speeds.get(&slot_id).copied().unwrap_or(UsbSpeed::HighSpeed);

        let input_ctx = context::build_configure_endpoint_input_context(
            slot_context,
            endpoints,
            xfer_ring_phys,
            speed,
        );
```

- [ ] **Step 7: Run all tests**

Run: `cargo test -p harmony-unikernel`
Expected: All existing tests pass + 7 new interval/avg-TRB tests pass. The `configure_endpoint_input_context_bulk_pair` test still passes (bulk interval stays 0, avg TRB stays 512).

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/context.rs crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs
git commit -m "feat(xhci): add speed-correct interval encoding and avg TRB length tuning

Add interval_to_xhci_exponent() for HS/SS passthrough vs FS/LS ms-to-
microframe conversion. build_configure_endpoint_input_context gains speed
param. Interrupt endpoints get avg TRB length 1024. XhciDriver tracks
slot_speeds via address_device for configure_endpoint lookup."
```

---

### Task 2: Interrupt Transfers

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/ring.rs:226-243` (enqueue_bulk → extract enqueue_normal)
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs:884-974` (bulk methods, add interrupt methods)

This task extracts a shared `enqueue_normal()` helper from `enqueue_bulk()`, adds `enqueue_interrupt()` as a thin wrapper, and adds `interrupt_transfer_in/out()` driver methods. The bulk API is unchanged — `enqueue_bulk` delegates to `enqueue_normal`.

- [ ] **Step 1: Write interrupt transfer ring test**

Add to the `#[cfg(test)] mod tests` block at the bottom of `ring.rs` (after the `enqueue_bulk_produces_one_normal_trb` test):

```rust
    #[test]
    fn enqueue_interrupt_produces_normal_trb() {
        let mut ring = TransferRing::new(0x9000_0000);
        let entries = ring.enqueue_interrupt(0xD000_0000, 64, IOC | ISP).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.trb_type(), TRB_NORMAL);
        assert_eq!(entries[0].1.parameter, 0xD000_0000);
        assert_eq!(entries[0].1.status, 64);
        let flags = entries[0].1.control & 0xFF;
        assert_ne!(flags & (1 << 5), 0, "IOC should be set");
        assert_ne!(flags & (1 << 2), 0, "ISP should be set");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-unikernel enqueue_interrupt -- --no-run 2>&1`
Expected: Compilation error — `enqueue_interrupt` doesn't exist.

- [ ] **Step 3: Extract `enqueue_normal` and add `enqueue_interrupt`**

In `ring.rs`, refactor `enqueue_bulk` (lines 226-242). Replace the entire `enqueue_bulk` method and add `enqueue_normal` + `enqueue_interrupt` before it:

```rust
    /// Enqueue a Normal TRB for data transfer (bulk or interrupt).
    ///
    /// Shared implementation for `enqueue_bulk` and `enqueue_interrupt`.
    /// `data_buf_phys` must be DWORD-aligned. `data_len` must fit in
    /// 17 bits (max 131071 bytes).
    fn enqueue_normal(
        &mut self,
        data_buf_phys: u64,
        data_len: u32,
        flags: u32,
    ) -> Result<Vec<(u64, Trb)>, XhciError> {
        use super::trb::TRB_NORMAL;
        // DMA buffer must be DWORD-aligned (xHCI §4.11.1).
        if data_buf_phys & 0x3 != 0 {
            return Err(XhciError::InvalidState);
        }
        // xHCI §6.4.1.1: Transfer Buffer Length is bits 16:0 (17-bit, max 131071).
        if data_len > 0x1_FFFF {
            return Err(XhciError::TransferTooLarge);
        }
        self.enqueue_one(TRB_NORMAL, data_buf_phys, data_len, flags)
    }

    /// Enqueue a bulk data transfer (single Normal TRB).
    ///
    /// `data_buf_phys` is the DMA buffer physical address.
    /// `data_len` is the transfer length in bytes.
    /// `flags` is caller-provided TRB control flags (e.g. `IOC` for OUT,
    /// `IOC | ISP` for IN transfers).
    ///
    /// Returns `Err(TransferTooLarge)` if `data_len` exceeds the 17-bit
    /// TRB field limit (131,071 bytes).
    pub fn enqueue_bulk(
        &mut self,
        data_buf_phys: u64,
        data_len: u32,
        flags: u32,
    ) -> Result<Vec<(u64, Trb)>, XhciError> {
        self.enqueue_normal(data_buf_phys, data_len, flags)
    }

    /// Enqueue an interrupt data transfer (single Normal TRB).
    ///
    /// Mechanically identical to bulk — both use Normal TRBs. Separate
    /// entry point for API clarity (interrupt vs bulk semantics).
    pub fn enqueue_interrupt(
        &mut self,
        data_buf_phys: u64,
        data_len: u32,
        flags: u32,
    ) -> Result<Vec<(u64, Trb)>, XhciError> {
        self.enqueue_normal(data_buf_phys, data_len, flags)
    }
```

- [ ] **Step 4: Run ring tests**

Run: `cargo test -p harmony-unikernel ring::tests`
Expected: All existing ring tests pass + `enqueue_interrupt_produces_normal_trb` passes.

- [ ] **Step 5: Write interrupt driver method tests**

Add these tests to the `#[cfg(test)] mod tests` block in `mod.rs`. First add a helper after `make_driver_with_bulk_endpoints` (around line 1766):

```rust
    /// Helper: create a driver with slot 1 addressed + interrupt IN endpoint configured.
    fn make_driver_with_interrupt_endpoint() -> XhciDriver {
        let mut driver = make_running_driver_with_slot(1);
        let eps = alloc::vec![EndpointDescriptor {
            endpoint_address: 0x81, // Interrupt IN, EP1
            attributes: 0x03,       // Interrupt transfer type
            max_packet_size: 64,
            interval: 4,
        }];
        let mut slot_ctx = [0u8; 32];
        let slot_dw0: u32 = (1 << 27) | (3 << 20); // Context Entries=1, speed=HS
        slot_ctx[0..4].copy_from_slice(&slot_dw0.to_le_bytes());
        slot_ctx[4..8].copy_from_slice(&(1u32 << 16).to_le_bytes()); // port 1
        let rings = alloc::vec![(3u8, 0xA000_0000u64)]; // DCI 3 = EP1 IN
        driver
            .configure_endpoint(1, &slot_ctx, &eps, 0xC000_0000, &rings)
            .unwrap();
        driver
    }
```

Then add the test functions:

```rust
    #[test]
    fn interrupt_transfer_in_produces_trb_and_doorbell() {
        let mut driver = make_driver_with_interrupt_endpoint();
        let actions = driver
            .interrupt_transfer_in(1, 3, 0xD000_0000, 64)
            .unwrap();

        let trb_count = actions
            .iter()
            .filter(|a| matches!(a, XhciAction::WriteTrb { .. }))
            .count();
        assert_eq!(trb_count, 1, "should produce 1 Normal TRB");

        // Doorbell target = endpoint_id (3 for interrupt IN EP1)
        assert!(actions.iter().any(|a| matches!(
            a,
            XhciAction::RingDoorbell {
                offset: _,
                value: 3,
            }
        )));
    }

    #[test]
    fn interrupt_transfer_out_produces_trb_and_doorbell() {
        // Set up an interrupt OUT endpoint (DCI 2 = EP1 OUT)
        let mut driver = make_running_driver_with_slot(1);
        let eps = alloc::vec![EndpointDescriptor {
            endpoint_address: 0x01, // Interrupt OUT, EP1
            attributes: 0x03,
            max_packet_size: 64,
            interval: 4,
        }];
        let mut slot_ctx = [0u8; 32];
        let slot_dw0: u32 = (1 << 27) | (3 << 20);
        slot_ctx[0..4].copy_from_slice(&slot_dw0.to_le_bytes());
        slot_ctx[4..8].copy_from_slice(&(1u32 << 16).to_le_bytes());
        let rings = alloc::vec![(2u8, 0xA000_0000u64)]; // DCI 2 = EP1 OUT
        driver
            .configure_endpoint(1, &slot_ctx, &eps, 0xC000_0000, &rings)
            .unwrap();

        let actions = driver
            .interrupt_transfer_out(1, 2, 0xD000_0000, 64)
            .unwrap();

        let trb_count = actions
            .iter()
            .filter(|a| matches!(a, XhciAction::WriteTrb { .. }))
            .count();
        assert_eq!(trb_count, 1);

        assert!(actions.iter().any(|a| matches!(
            a,
            XhciAction::RingDoorbell {
                offset: _,
                value: 2,
            }
        )));
    }

    #[test]
    fn interrupt_transfer_in_has_isp_flag() {
        let mut driver = make_driver_with_interrupt_endpoint();
        let actions = driver
            .interrupt_transfer_in(1, 3, 0xD000_0000, 64)
            .unwrap();

        // Find the WriteTrb action and check ISP flag
        let trb_action = actions
            .iter()
            .find(|a| matches!(a, XhciAction::WriteTrb { .. }))
            .unwrap();
        if let XhciAction::WriteTrb { trb: t, .. } = trb_action {
            assert_ne!(
                t.control & trb::ISP,
                0,
                "interrupt IN should have ISP for short packet handling"
            );
            assert_ne!(t.control & trb::IOC, 0, "should have IOC");
        }
    }

    #[test]
    fn interrupt_transfer_wrong_state() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        // Driver is Ready, not Running
        assert_eq!(
            driver.interrupt_transfer_in(1, 3, 0xD000_0000, 64),
            Err(XhciError::InvalidState)
        );
    }

    #[test]
    fn interrupt_transfer_no_ring() {
        let mut driver = make_running_driver_with_slot(1);
        // No interrupt endpoint configured — only EP0 ring exists
        assert_eq!(
            driver.interrupt_transfer_in(1, 3, 0xD000_0000, 64),
            Err(XhciError::NoTransferRing)
        );
    }
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel interrupt_transfer -- --no-run 2>&1`
Expected: Compilation error — `interrupt_transfer_in` and `interrupt_transfer_out` don't exist.

- [ ] **Step 7: Implement interrupt transfer driver methods**

In `mod.rs`, add after the `enqueue_bulk_with_flags` method (after line 974), before the closing `}` of the impl block and the `#[cfg(test)]` module:

```rust
    // ── Interrupt data transfers ───────────────────────────────────────

    /// Enqueue an interrupt IN (device-to-host) transfer.
    ///
    /// Used for HID reports (keyboard, mouse, gamepad). `endpoint_id` must
    /// be an odd DCI (IN endpoint). Variable-length reports are expected,
    /// so ISP (Interrupt on Short Packet) is always set.
    pub fn interrupt_transfer_in(
        &mut self,
        slot_id: u8,
        endpoint_id: u8,
        data_buf_phys: u64,
        data_len: u16,
    ) -> Result<Vec<XhciAction>, XhciError> {
        if endpoint_id % 2 == 0 || endpoint_id < 2 {
            return Err(XhciError::InvalidState);
        }
        self.enqueue_interrupt_with_flags(
            slot_id,
            endpoint_id,
            data_buf_phys,
            data_len as u32,
            trb::IOC | trb::ISP,
        )
    }

    /// Enqueue an interrupt OUT (host-to-device) transfer.
    ///
    /// Used for HID output reports (e.g., keyboard LEDs). `endpoint_id`
    /// must be an even DCI (OUT endpoint).
    pub fn interrupt_transfer_out(
        &mut self,
        slot_id: u8,
        endpoint_id: u8,
        data_buf_phys: u64,
        data_len: u16,
    ) -> Result<Vec<XhciAction>, XhciError> {
        if endpoint_id % 2 != 0 || endpoint_id < 2 {
            return Err(XhciError::InvalidState);
        }
        self.enqueue_interrupt_with_flags(
            slot_id,
            endpoint_id,
            data_buf_phys,
            data_len as u32,
            trb::IOC,
        )
    }

    /// Shared interrupt transfer enqueue logic.
    fn enqueue_interrupt_with_flags(
        &mut self,
        slot_id: u8,
        endpoint_id: u8,
        data_buf_phys: u64,
        data_len: u32,
        flags: u32,
    ) -> Result<Vec<XhciAction>, XhciError> {
        if self.state != XhciState::Running || slot_id == 0 || slot_id > self.max_slots_enabled {
            return Err(XhciError::InvalidState);
        }
        if data_buf_phys & 0x3 != 0 {
            return Err(XhciError::InvalidState);
        }

        let xfer_ring = self
            .transfer_rings
            .get_mut(&ring_key(slot_id, endpoint_id))
            .ok_or(XhciError::NoTransferRing)?;

        let entries = xfer_ring.enqueue_interrupt(data_buf_phys, data_len, flags)?;

        let mut actions: Vec<XhciAction> = entries
            .into_iter()
            .map(|(phys, t)| XhciAction::WriteTrb { phys, trb: t })
            .collect();

        actions.push(XhciAction::RingDoorbell {
            offset: self.db_offset as usize + 4 * (slot_id as usize),
            value: endpoint_id as u32,
        });

        Ok(actions)
    }
```

- [ ] **Step 8: Run all tests**

Run: `cargo test -p harmony-unikernel`
Expected: All existing tests pass + 6 new tests pass (1 ring + 5 driver).

- [ ] **Step 9: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/ring.rs crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs
git commit -m "feat(xhci): add interrupt transfer methods

Extract enqueue_normal() from enqueue_bulk() as shared Normal TRB helper.
Add enqueue_interrupt() wrapper on TransferRing. Add interrupt_transfer_in()
and interrupt_transfer_out() driver methods with IOC/ISP flags. Same TRB
type as bulk but separate API surface for HID class driver clarity."
```

---

### Task 3: Evaluate Context Command

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/trb.rs:23` (add TRB_EVALUATE_CONTEXT constant)
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/context.rs` (add build_evaluate_context_ep0)
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs` (add evaluate_context method)

This task adds the Evaluate Context xHCI command for updating EP0 max packet size after reading the device descriptor. Follows the same command ring pattern as `configure_endpoint` and `address_device`.

- [ ] **Step 1: Write evaluate context input context builder test**

Add to the `#[cfg(test)] mod tests` block at the bottom of `context.rs`:

```rust
    #[test]
    fn evaluate_context_ep0_layout() {
        let ctx = build_evaluate_context_ep0(64);

        // Input Control Context DWord 1 (bytes 4..8): Add flags = 0x02 (EP0 only)
        let flags = u32::from_le_bytes(ctx[4..8].try_into().unwrap());
        assert_eq!(flags, 0x02, "Add flags: bit 1 (EP0) only, not bit 0 (Slot)");

        // Slot Context (bytes 32..63): should be all zeros (not evaluated)
        assert_eq!(&ctx[32..64], &[0u8; 32], "Slot Context should be zeroed");

        // EP0 Context DWord 1 (bytes 68..72): EP Type=4 (Control Bidir), MPS=64
        let ep_dw1 = u32::from_le_bytes(ctx[68..72].try_into().unwrap());
        let ep_type = (ep_dw1 >> 3) & 0x7;
        assert_eq!(ep_type, 4, "EP Type should be 4 (Control Bidir)");
        let mps = (ep_dw1 >> 16) & 0xFFFF;
        assert_eq!(mps, 64, "Max Packet Size should be 64");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-unikernel evaluate_context_ep0_layout -- --no-run 2>&1`
Expected: Compilation error — `build_evaluate_context_ep0` doesn't exist.

- [ ] **Step 3: Add TRB constant and build evaluate context**

In `trb.rs`, add after the `TRB_CONFIGURE_ENDPOINT` constant (line 23):

```rust
/// Evaluate Context Command TRB — updates endpoint parameters without reconfigure.
pub const TRB_EVALUATE_CONTEXT: u8 = 13;
```

In `context.rs`, add the builder function after `build_configure_endpoint_input_context` (after line 349, before `#[cfg(test)]`):

```rust
/// Build a 96-byte Input Context for Evaluate Context (EP0 MPS update).
///
/// Layout: Input Control Context (32B) + Slot Context (32B) + EP0 Context (32B).
///
/// Per xHCI §4.6.7, only Max Packet Size is evaluatable for EP0.
/// The Slot Context is zeroed (not evaluated). Add flags = 0x02 (EP0 only).
pub fn build_evaluate_context_ep0(max_packet_size: u16) -> [u8; 96] {
    let mut ctx = [0u8; 96];

    // Input Control Context DWord 1 (offset 4): Add Context Flags = 0x02 (EP0 only)
    // Bit 0 (Slot) is NOT set — Evaluate Context for EP0 MPS doesn't need slot updates.
    ctx[4..8].copy_from_slice(&0x02u32.to_le_bytes());

    // Slot Context (bytes 32..63): zeroed — not evaluated.

    // EP0 Context (bytes 64..95):
    // DWord 1: EP Type=4 (Control Bidir, bits 5:3), Max Packet Size (bits 31:16)
    let ep_type: u32 = 4 << 3;
    let mps: u32 = (max_packet_size as u32) << 16;
    let ep_dw1 = ep_type | mps;
    ctx[68..72].copy_from_slice(&ep_dw1.to_le_bytes());

    ctx
}
```

- [ ] **Step 4: Run context tests**

Run: `cargo test -p harmony-unikernel context::tests`
Expected: All context tests pass including `evaluate_context_ep0_layout`.

- [ ] **Step 5: Write evaluate context driver method tests**

Add to the `#[cfg(test)] mod tests` block in `mod.rs`:

```rust
    #[test]
    fn evaluate_context_produces_dma_trb_doorbell() {
        let mut driver = make_running_driver_with_slot(1);
        let actions = driver.evaluate_context(1, 64, 0xE000_0000).unwrap();

        // Should have: WriteDma (input context) + WriteTrb (command) + RingDoorbell(0)
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, XhciAction::WriteDma { .. })),
            "should write input context to DMA"
        );

        let trb_actions: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, XhciAction::WriteTrb { .. }))
            .collect();
        assert!(!trb_actions.is_empty(), "should enqueue command TRB");

        // Verify TRB type is Evaluate Context (13) with slot_id in bits 31:24
        if let XhciAction::WriteTrb { trb: t, .. } = trb_actions[0] {
            assert_eq!(t.trb_type(), trb::TRB_EVALUATE_CONTEXT);
            assert_eq!((t.control >> 24) as u8, 1, "slot_id should be 1");
        }

        // Command doorbell (value 0)
        assert!(actions.iter().any(|a| matches!(
            a,
            XhciAction::RingDoorbell {
                offset: _,
                value: 0,
            }
        )));
    }

    #[test]
    fn evaluate_context_trb_has_input_ctx_pointer() {
        let mut driver = make_running_driver_with_slot(1);
        let actions = driver.evaluate_context(1, 64, 0xE000_0000).unwrap();

        let trb_action = actions
            .iter()
            .find(|a| matches!(a, XhciAction::WriteTrb { .. }))
            .unwrap();
        if let XhciAction::WriteTrb { trb: t, .. } = trb_action {
            assert_eq!(
                t.parameter, 0xE000_0000,
                "TRB parameter should be input context physical address"
            );
        }
    }

    #[test]
    fn evaluate_context_wrong_state() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        assert_eq!(
            driver.evaluate_context(1, 64, 0xE000_0000),
            Err(XhciError::InvalidState)
        );
    }
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel evaluate_context -- --no-run 2>&1`
Expected: Compilation error — `evaluate_context` method doesn't exist on `XhciDriver`.

- [ ] **Step 7: Implement evaluate_context driver method**

In `mod.rs`, add after the `enqueue_interrupt_with_flags` method (inside the `impl XhciDriver` block, before the closing `}`):

```rust
    // ── Evaluate Context command ───────────────────────────────────────

    /// Enqueue an Evaluate Context command to update EP0 max packet size.
    ///
    /// Builds the Input Context internally and returns a `WriteDma` action
    /// to write it to `input_ctx_phys`, followed by the command TRB and
    /// doorbell. Same pattern as `configure_endpoint`.
    ///
    /// Use after `get_device_descriptor` reveals the real `bMaxPacketSize0`
    /// (which may differ from the speed-default guess used in `address_device`).
    pub fn evaluate_context(
        &mut self,
        slot_id: u8,
        max_packet_size: u16,
        input_ctx_phys: u64,
    ) -> Result<Vec<XhciAction>, XhciError> {
        if self.state != XhciState::Running || slot_id == 0 || slot_id > self.max_slots_enabled {
            return Err(XhciError::InvalidState);
        }
        debug_assert!(
            input_ctx_phys & 0x3F == 0,
            "Input Context must be 64-byte aligned, got {:#x}",
            input_ctx_phys
        );

        let input_ctx = context::build_evaluate_context_ep0(max_packet_size);

        let mut actions = Vec::new();

        // 1. Write Input Context to DMA
        actions.push(XhciAction::WriteDma {
            phys: input_ctx_phys,
            data: input_ctx.to_vec(),
        });

        // 2. Enqueue Evaluate Context command on command ring
        let cmd_ring = self.command_ring.as_mut().ok_or(XhciError::InvalidState)?;
        let entries = cmd_ring.enqueue(trb::TRB_EVALUATE_CONTEXT, input_ctx_phys)?;

        for (phys, mut t) in entries {
            if t.trb_type() == trb::TRB_EVALUATE_CONTEXT {
                t.control |= (slot_id as u32) << 24;
            }
            actions.push(XhciAction::WriteTrb { phys, trb: t });
        }

        actions.push(XhciAction::RingDoorbell {
            offset: self.db_offset as usize,
            value: 0, // command doorbell
        });

        Ok(actions)
    }
```

- [ ] **Step 8: Run all tests**

Run: `cargo test -p harmony-unikernel`
Expected: All tests pass — existing + Task 1 interval tests + Task 2 interrupt tests + Task 3 evaluate context tests.

- [ ] **Step 9: Run clippy and fmt**

Run: `cargo clippy -p harmony-unikernel -- -D warnings && cargo +nightly fmt --all -- --check`
Expected: No warnings, no formatting issues.

- [ ] **Step 10: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/trb.rs crates/harmony-unikernel/src/drivers/dwc_usb/context.rs crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs
git commit -m "feat(xhci): add Evaluate Context command for EP0 MPS update

Add TRB_EVALUATE_CONTEXT constant (type 13), build_evaluate_context_ep0()
input context builder, and evaluate_context() driver method. Used after
get_device_descriptor reveals actual bMaxPacketSize0 that differs from the
speed-default guess. Follows same command ring pattern as configure_endpoint."
```
