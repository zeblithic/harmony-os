# xHCI Phase 3b: Interrupt Transfers + Evaluate Context

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Bead:** harmony-os-ho8

**Goal:** Add interrupt endpoint transfers, speed-correct interval encoding, and Evaluate Context (EP0 max packet size update) to the xHCI driver. This unblocks HID class drivers (keyboard, mouse, gamepad).

**Prerequisite:** xHCI Phase 3 (harmony-os-e4v) is merged.

---

## Architecture

All changes are in `crates/harmony-unikernel/src/drivers/dwc_usb/`. The sans-I/O pattern is preserved — methods return `Vec<XhciAction>`, the caller executes actions against MMIO/DMA.

### Four additions

1. **Interval encoding fix** (`context.rs`) — `build_configure_endpoint_input_context()` currently writes USB `bInterval` directly for all speeds. Fix to apply xHCI spec interval encoding: HS/SS endpoints use `bInterval` as-is (already an exponent), FS/LS endpoints need conversion from milliseconds to 125us microframes. Requires a new `speed: UsbSpeed` parameter.

2. **Interrupt transfers** (`mod.rs` + `ring.rs`) — `interrupt_transfer_in()` and `interrupt_transfer_out()` driver methods, backed by a shared `enqueue_normal()` private helper on `TransferRing` that both bulk and interrupt wrappers call. Same Normal TRB type, distinct public API for class driver clarity.

3. **Evaluate Context** (`mod.rs` + `context.rs`) — `evaluate_context()` driver method + `build_evaluate_context_ep0()` input context builder. Updates EP0 max packet size after device descriptor read. Uses xHCI Evaluate Context command (TRB type 13).

4. **Average TRB Length tuning** (`context.rs`) — Interrupt endpoints get 1024 (typical HID report + overhead) instead of the current fallback of 8.

### What stays the same

- `XhciDriver` state machine — unchanged (all new methods use existing `Running` check)
- `CommandRing`, `EventRing` — unchanged
- `Trb` struct — unchanged
- All existing commands and transfers — unchanged
- All existing tests — unchanged (mechanical parameter additions only)

---

## Interval Encoding

### The problem

`build_configure_endpoint_input_context()` at `context.rs:319-327` writes `bInterval` directly to the endpoint context's Interval field. This is correct for HS/SS (where bInterval is already an exponent per USB 2.0 §9.6.6) but wrong for FS/LS (where bInterval is a linear millisecond polling rate).

xHCI §6.2.3.6 defines the Interval field as an exponent: the polling interval is 2^(Interval) * 125 microseconds.

### The fix

New private helper:

```rust
fn interval_to_xhci_exponent(binterval: u8, speed: UsbSpeed, transfer_type: u8) -> u8
```

- **Bulk/Control** (transfer_type 0 or 2): returns 0 (interval not used)
- **HS/SS/SSP interrupt** (transfer_type 3): returns `binterval` clamped to 1..=16 (already an exponent per USB 2.0 §9.6.6)
- **FS/LS interrupt** (transfer_type 3): converts `binterval` ms to microframes (`binterval * 8`), finds smallest exponent `n` where `2^n >= binterval * 8`, clamps result to 1..=16

Examples:
- FS bInterval=10 (10ms) → 80 microframes → exponent 7 (2^7=128 >= 80)
- FS bInterval=1 (1ms) → 8 microframes → exponent 3 (2^3=8 >= 8)
- LS bInterval=8 (8ms) → 64 microframes → exponent 6 (2^6=64 >= 64)
- HS bInterval=4 → 4 (passthrough)

### Signature change

`build_configure_endpoint_input_context()` gains a `speed` parameter:

```rust
pub fn build_configure_endpoint_input_context(
    slot_context: &[u8],
    endpoints: &[EndpointDescriptor],
    xfer_ring_phys: &[(u8, u64)],
    speed: UsbSpeed,
) -> Vec<u8>
```

The interval assignment at line 326 changes from:
```rust
let interval_dw0: u32 = (ep.interval as u32) << 16;
```
to:
```rust
let interval_dw0: u32 = (interval_to_xhci_exponent(ep.interval, speed, transfer_type) as u32) << 16;
```

---

## Interrupt Transfers

### TransferRing changes (`ring.rs`)

Extract shared helper from `enqueue_bulk()`:

```rust
fn enqueue_normal(&mut self, data_phys: u64, length: u16, ioc: bool, isp: bool) -> (Trb, u64)
```

Builds a Normal TRB (type 1) with:
- Parameter: `data_phys` (64-bit data buffer pointer)
- Status: `length` in bits 16:0
- Control: TRB type 1, cycle bit, IOC flag (bit 5), ISP flag (bit 2)

`enqueue_bulk()` becomes: `self.enqueue_normal(data_phys, length, ioc, isp)`

New `enqueue_interrupt()`: `self.enqueue_normal(data_phys, length, ioc, isp)` — identical implementation, separate entry point.

### Driver methods (`mod.rs`)

```rust
pub fn interrupt_transfer_in(
    &mut self,
    slot_id: u8,
    endpoint_id: u8,
    data_phys: u64,
    length: u16,
) -> Result<Vec<XhciAction>, XhciError>
```

Same pattern as `bulk_transfer_in()`:
- State must be `Running`
- Transfer ring must exist for `(slot_id, endpoint_id)` key
- Enqueues Normal TRB with IOC + ISP flags (ISP for short packet handling — HID reports are variable length)
- Returns `[WriteTrb, RingDoorbell]` actions
- Doorbell value: endpoint_id (same as bulk)

```rust
pub fn interrupt_transfer_out(
    &mut self,
    slot_id: u8,
    endpoint_id: u8,
    data_phys: u64,
    length: u16,
) -> Result<Vec<XhciAction>, XhciError>
```

Same pattern as `bulk_transfer_out()`:
- IOC flag only (no ISP for OUT direction)
- Returns `[WriteTrb, RingDoorbell]` actions

---

## Evaluate Context

### Input Context builder (`context.rs`)

```rust
pub fn build_evaluate_context_ep0(max_packet_size: u16) -> [u8; 96]
```

Returns a 96-byte Input Context:

| Bytes | Section | Content |
|-------|---------|---------|
| 0-31 | Input Control Context | Add flags = 0x02 (bit 1 = EP0 only). Drop flags = 0. |
| 32-63 | Slot Context | Zeroed (not evaluated for EP0 MPS update) |
| 64-95 | EP0 Context | DWord 1: EP Type=4 (Control Bidir), Max Packet Size in bits 31:16. All other fields zeroed. |

Per xHCI §4.6.7, Evaluate Context only examines fields listed in Table 6-9. For EP0, only Max Packet Size is evaluatable. The Slot Context bit is NOT set in Add flags because we're only updating EP0.

### Driver method (`mod.rs`)

```rust
pub fn evaluate_context(
    &mut self,
    slot_id: u8,
    input_ctx_phys: u64,
) -> Result<Vec<XhciAction>, XhciError>
```

- State must be `Running`
- Enqueues Evaluate Context TRB (type 13) on command ring:
  - Parameter: `input_ctx_phys` (64-bit pointer to Input Context in DMA memory)
  - Status: 0
  - Control: TRB type 13, slot_id in bits 31:24, cycle bit
- Returns `[WriteDma(input_ctx), WriteTrb, RingDoorbell(0)]` actions
- Doorbell 0 = host controller command doorbell (same as all command ring TRBs)

### New constant (`trb.rs`)

```rust
pub const TRB_EVALUATE_CONTEXT: u8 = 13;
```

---

## Speed Tracking

### New field on `XhciDriver`

```rust
slot_speeds: BTreeMap<u8, UsbSpeed>
```

Populated during `address_device()` which already takes `speed: UsbSpeed` as a parameter. After the address device TRB is enqueued, `slot_speeds.insert(slot_id, speed)` records it.

Looked up during `configure_endpoint()` to pass to `build_configure_endpoint_input_context()`:
```rust
let speed = self.slot_speeds.get(&slot_id).copied().ok_or(XhciError::InvalidSlot)?;
```

### Average TRB Length

In `build_configure_endpoint_input_context()`, the average TRB length logic changes from:

```rust
let avg_trb = if transfer_type == 2 { 512u32 } else { 8u32 };
```

to:

```rust
let avg_trb = match transfer_type {
    2 => 512,  // Bulk
    3 => 1024, // Interrupt
    _ => 8,    // Control and others
};
```

---

## Testing

All tests use `MockRegisterBank`. No hardware, no DMA.

### Interval encoding tests

1. **HS interrupt interval passthrough** — HS endpoint with bInterval=4 → xHCI interval=4
2. **FS interrupt interval conversion** — FS endpoint with bInterval=10 → exponent=7
3. **LS interrupt interval conversion** — LS endpoint with bInterval=8 → exponent=6
4. **SS interrupt interval passthrough** — SS endpoint with bInterval=3 → interval=3
5. **Bulk interval stays zero** — Bulk endpoints always get interval=0 regardless of speed
6. **FS minimum interval** — bInterval=1 → exponent=3 (2^3=8 >= 8 microframes)

### Interrupt transfer tests

7. **enqueue_interrupt produces Normal TRB** — Same TRB type as bulk, correct data pointer and length
8. **interrupt_transfer_in actions** — WriteTrb + RingDoorbell with correct slot/endpoint doorbell
9. **interrupt_transfer_out actions** — WriteTrb + RingDoorbell, IOC set, no ISP
10. **interrupt_transfer_in ISP flag** — ISP bit set for short packet handling
11. **interrupt wrong state** — Not Running → XhciError
12. **interrupt missing transfer ring** — No ring for endpoint → XhciError

### Evaluate Context tests

13. **build_evaluate_context_ep0 layout** — Add flags = 0x02, EP0 context has correct MPS, slot context zeroed
14. **evaluate_context actions** — WriteDma + WriteTrb (type 13) + RingDoorbell(0)
15. **evaluate_context TRB fields** — Slot ID in bits 31:24, input context pointer in parameter
16. **evaluate_context wrong state** — Not Running → XhciError

### Existing test updates

17. **configure_endpoint callers** — All existing calls gain `speed` parameter. No behavioral change for bulk (interval stays 0).
18. **Bulk methods unchanged** — Existing bulk tests pass after `enqueue_normal` extraction.
19. **Interrupt endpoint avg TRB length** — Interrupt endpoints get 1024 in endpoint context

---

## Scope Boundary

**In scope:**
- `interval_to_xhci_exponent()` private helper for speed-specific interval encoding
- `build_configure_endpoint_input_context()` gains `speed: UsbSpeed` parameter
- `slot_speeds: BTreeMap<u8, UsbSpeed>` on `XhciDriver`, populated by `address_device()`
- `enqueue_normal()` shared private helper on `TransferRing`
- `enqueue_interrupt()` wrapper on `TransferRing`
- `interrupt_transfer_in()` / `interrupt_transfer_out()` driver methods
- `build_evaluate_context_ep0(max_packet_size)` input context builder
- `evaluate_context(slot_id, input_ctx_phys)` driver method
- `TRB_EVALUATE_CONTEXT` constant (type 13)
- Average TRB length: 1024 for interrupt endpoints
- All 19 tests listed above
- Mechanical update of existing `configure_endpoint` callers to pass `speed`

**Out of scope:**
- Isochronous transfers — separate bead (different TRB type, frame scheduling, no retry)
- Generic Evaluate Context for arbitrary endpoints — YAGNI, EP0 MPS is the real use case
- HID class driver — consumer of interrupt transfers, separate concern
- Max Exit Latency updates via Evaluate Context
- Stream transfers (SuperSpeed bulk streams)
- Error recovery / endpoint halt / stall handling
- USB hubs
- Multiple alternate settings on interfaces
