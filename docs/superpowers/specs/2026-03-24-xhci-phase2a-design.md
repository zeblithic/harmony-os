# xHCI Phase 2a: TRB Ring Infrastructure + Command/Event Rings

## Goal

Implement the TRB ring machinery that underpins all xHCI communication: a command ring for host→controller commands, an event ring for controller→host notifications, and the setup sequence to configure and start the controller with these rings. This is the plumbing layer — Phase 2b (harmony-os-lv7) builds on it to do device enumeration.

## Scope

**In scope:**
- `Trb` struct — 16-byte TRB with serialization, type extraction, cycle bit manipulation
- `CommandRing` — 64-entry ring with enqueue, Link TRB wrapping, cycle bit toggle
- `EventRing` — 256-entry ring with dequeue, cycle bit matching, wrap detection
- `XhciAction` enum — fine-grained actions (WriteTrb, RingDoorbell, UpdateDequeuePointer, WriteRegister, WriteRegister64)
- `XhciEvent` enum — parsed events (CommandCompletion, PortStatusChange, Unknown)
- `XhciDriver::setup_rings()` — configure DCBAAP, CRCR, interrupter 0, set RUN
- `XhciDriver::enqueue_noop()` — No-Op command for testing ring round-trip
- `XhciDriver::process_event()` — parse one event TRB, advance dequeue pointer
- File split: `dwc_usb.rs` → `dwc_usb/` module directory

**Out of scope (Phase 2b — harmony-os-lv7):**
- Enable Slot command
- Address Device command
- Control transfers (SETUP/DATA/STATUS on endpoint 0)
- Device descriptor reads (GET_DESCRIPTOR)
- Device context allocation

**Out of scope (Phase 3 — harmony-os-e4v):**
- Configuration/interface/endpoint enumeration
- Class drivers

## Architecture

### Sans-I/O Pattern

Same as Phase 1: the driver is a pure state machine. All DMA memory is owned by the caller. The driver computes what to write and where, returning `XhciAction` variants. The caller executes them (MMIO writes, DMA buffer writes, doorbell rings).

**Paradigm shift from Phase 1:** Phase 1 methods (`init`, `detect_ports`) take `&mut impl RegisterBank` directly — they're one-shot operations during boot before the rings exist. Phase 2a methods (`setup_rings`, `enqueue_noop`, `process_event`) return `Vec<XhciAction>` instead — the caller executes actions against both registers and DMA memory. Both patterns coexist in the same driver.

### Ring Protocol

xHCI uses circular TRB rings for all communication:

- **Command ring** (host→controller): Host writes command TRBs, rings doorbell 0. Controller reads and processes them, posts completion events on the event ring.
- **Event ring** (controller→host): Controller writes event TRBs. Host polls by checking the cycle bit at the dequeue pointer — if it matches the expected Consumer Cycle State, there's a new event.
- **Cycle bit protocol**: Producer sets the cycle bit on TRBs it writes. Consumer expects TRBs with a matching cycle bit. On ring wrap, both sides toggle their cycle bit. This allows the consumer to distinguish new TRBs from stale ones without a separate "valid" flag.
- **Link TRB**: The last entry in a command ring is a Link TRB that points back to the ring base. When the hardware hits it, it follows the link and optionally toggles its cycle bit. Event rings don't use Link TRBs — they wrap implicitly.

### Data Flow

```
Caller allocates DMA buffers for command ring (64 * 16 bytes) and event ring (256 * 16 bytes)
    ↓
driver.setup_rings(cmd_phys, evt_phys, erst_phys) → Vec<XhciAction>
    ↓
Caller executes actions: write DCBAAP, CRCR, interrupter regs, set RUN
    ↓
driver.enqueue_noop() → Vec<XhciAction> [WriteTrb + RingDoorbell]
    ↓
Caller writes TRB to DMA, rings doorbell register
    ↓
Controller processes No-Op, writes CommandCompletion event to event ring
    ↓
Caller reads TRB from event ring DMA, checks cycle bit
    ↓
driver.process_event(trb) → Ok((XhciEvent::CommandCompletion { ... }, actions))
    ↓
Caller executes actions: update ERDP
```

## Types

### Trb

```rust
/// A 16-byte Transfer Request Block — the fundamental xHCI data unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Trb {
    /// Parameter field (TRB-type-specific, 8 bytes).
    pub parameter: u64,
    /// Status field (completion code, transfer length, etc.).
    pub status: u32,
    /// Control field: TRB type (bits 15:10), cycle bit (bit 0), flags.
    pub control: u32,
}
```

Methods:
- `trb_type() -> u8` — `(control >> 10) & 0x3F`
- `cycle_bit() -> bool` — `control & 1 != 0`
- `set_cycle_bit(&mut self, bit: bool)` — set/clear bit 0 of control
- `from_bytes(bytes: [u8; 16]) -> Self` — little-endian deserialization
- `to_bytes(&self) -> [u8; 16]` — little-endian serialization

### TRB Type Constants

```rust
// Command TRBs
pub const TRB_NOOP_CMD: u8 = 23;
pub const TRB_LINK: u8 = 6;

// Event TRBs
pub const TRB_COMMAND_COMPLETION: u8 = 33;
pub const TRB_PORT_STATUS_CHANGE: u8 = 34;
```

### Completion Codes

```rust
pub const COMPLETION_SUCCESS: u8 = 1;
pub const COMPLETION_TRB_ERROR: u8 = 5;
pub const COMPLETION_NO_SLOTS: u8 = 9;
```

### XhciAction

```rust
pub enum XhciAction {
    /// Write a TRB to DMA memory at the given physical address.
    WriteTrb { phys: u64, trb: Trb },
    /// Ring a doorbell register. Pre-computed offset = db_offset + 4 * slot.
    /// slot=0 means command ring.
    RingDoorbell { offset: usize, value: u32 },
    /// Update Event Ring Dequeue Pointer in interrupter register.
    UpdateDequeuePointer { phys: u64 },
    /// Write a 32-bit value to a register (offset from MMIO base).
    WriteRegister { offset: usize, value: u32 },
    /// Write a 64-bit value as two 32-bit writes (LO then HI).
    WriteRegister64 { offset_lo: usize, value: u64 },
}
```

### XhciEvent

```rust
pub enum XhciEvent {
    /// A command completed.
    CommandCompletion {
        slot_id: u8,
        completion_code: u8,
    },
    /// A port status changed (connect/disconnect).
    PortStatusChange {
        port_id: u8,
    },
    /// Unrecognized event TRB type.
    Unknown {
        trb_type: u8,
    },
}
```

### XhciError Extensions

```rust
pub enum XhciError {
    // ... existing Phase 1 variants ...
    /// Command ring is full (all 63 usable slots occupied).
    CommandRingFull,
    /// Malformed event TRB.
    InvalidEvent,
}
```

## Ring State

### CommandRing

```rust
const COMMAND_RING_SIZE: usize = 64;  // 63 usable + 1 Link TRB

pub struct CommandRing {
    /// Physical base address of the ring.
    base_phys: u64,
    /// Next slot to write (0..62, slot 63 is always the Link TRB).
    enqueue_index: u16,
    /// Producer Cycle State — toggled on wrap.
    cycle_bit: bool,
    /// Number of commands pending completion.
    pending_count: u16,
}
```

- `new(base_phys) -> Self` — starts at index 0, cycle_bit=true, pending=0
- `enqueue(trb_type, parameter) -> Result<Vec<XhciAction>, XhciError>` — build TRB with current cycle bit, return WriteTrb action. If index reaches 63, write Link TRB (parameter=base_phys, toggle cycle bit flag set), reset index to 0, toggle cycle_bit. Returns `CommandRingFull` if pending_count == 63.
- `complete_one()` — decrement pending_count (called when event ring delivers a completion)
- `crcr_value() -> u64` — `base_phys | (cycle_bit as u64)` for writing to CRCR register

### EventRing

```rust
const EVENT_RING_SIZE: usize = 256;

pub struct EventRing {
    /// Physical base address of the event ring segment.
    base_phys: u64,
    /// Next slot to read.
    dequeue_index: u16,
    /// Consumer Cycle State.
    cycle_bit: bool,
}
```

- `new(base_phys) -> Self` — starts at index 0, cycle_bit=true
- `should_process(trb_cycle_bit: bool) -> bool` — `trb_cycle_bit == self.cycle_bit`
- `advance()` — increment dequeue_index, wrap at 256, toggle cycle_bit on wrap
- `dequeue_pointer() -> u64` — `base_phys + dequeue_index * 16` for ERDP update

## XhciDriver Extensions

### New State

```rust
enum XhciState {
    Ready,    // controller reset, ports scannable
    Running,  // rings configured, controller running
    Error(XhciError),
}
```

### New Fields

```rust
pub struct XhciDriver {
    // ... existing Phase 1 fields ...
    command_ring: Option<CommandRing>,
    event_ring: Option<EventRing>,
}
```

### setup_rings

`setup_rings(&mut self, cmd_ring_phys: u64, event_ring_phys: u64, erst_phys: u64) -> Result<Vec<XhciAction>, XhciError>`

Requires `Ready` state. Returns actions to:
1. Write CONFIG register with MaxSlotsEn=0 (no slots needed in Phase 2a; Phase 2b bumps this when allocating the DCBAA)
2. Write DCBAAP to 0 (valid because MaxSlotsEn=0 — the controller won't dereference slot contexts)
3. Write CRCR with command ring base + cycle bit
4. Write interrupter 0 registers: ERSTSZ (segment table size = 1), ERSTBA (segment table base), ERDP (initial dequeue pointer)
5. Write USBCMD (RUN + INTE)

Transitions to `Running` state. Creates `CommandRing` and `EventRing` with the provided physical addresses.

**Event Ring Segment Table (ERST):** xHCI requires an indirection — the ERSTBA points to a segment table, which contains entries pointing to actual event ring segments. Each entry is 16 bytes: `{base_phys: u64, size: u32, reserved: u32}`. The caller must write one ERST entry at `erst_phys` with the event ring base and size. The driver returns a `WriteTrb` action for this (reusing the action type since it's the same operation: write 16 bytes to a physical address).

### enqueue_noop

`enqueue_noop(&mut self) -> Result<Vec<XhciAction>, XhciError>`

Requires `Running` state. Enqueues a No-Op command TRB on the command ring and returns WriteTrb + RingDoorbell actions.

### process_event

`process_event(&mut self, trb: Trb) -> Result<(XhciEvent, Vec<XhciAction>), XhciError>`

Requires `Running` state. Parses the event TRB type:
- `TRB_COMMAND_COMPLETION` → extract slot_id (bits 31:24 of parameter high dword), completion_code (bits 31:24 of status). Call `command_ring.complete_one()`.
- `TRB_PORT_STATUS_CHANGE` → extract port_id (bits 31:24 of parameter high dword).
- Other → `XhciEvent::Unknown`.

Advances event ring dequeue pointer, returns `UpdateDequeuePointer` action.

### should_process_event

`should_process_event(&self, cycle_bit: bool) -> bool`

Delegates to `event_ring.should_process(cycle_bit)`. Caller checks this before calling `process_event`.

## Interrupter Register Offsets

Runtime registers are at `rts_offset` from MMIO base. Interrupter 0 is at `rts_offset + 0x20`:

```rust
const IMAN: usize = 0x00;      // Interrupter Management
const IMOD: usize = 0x04;      // Interrupter Moderation
const ERSTSZ: usize = 0x08;    // Event Ring Segment Table Size
const ERSTBA_LO: usize = 0x10; // ERST Base Address (low)
const ERSTBA_HI: usize = 0x14; // ERST Base Address (high)
const ERDP_LO: usize = 0x18;   // Event Ring Dequeue Pointer (low)
const ERDP_HI: usize = 0x1C;   // Event Ring Dequeue Pointer (high)
```

Absolute offset for interrupter 0 register X: `rts_offset + 0x20 + X`.

## File Structure

Split `dwc_usb.rs` into a module directory:

| File | Responsibility | ~Lines |
|------|---------------|--------|
| `dwc_usb/mod.rs` | `XhciDriver` struct, `XhciState`, `init`, `detect_ports`, `setup_rings`, `enqueue_noop`, `process_event`, re-exports | ~400 |
| `dwc_usb/trb.rs` | `Trb` struct, TRB type constants, `from_bytes`/`to_bytes`, completion codes | ~80 |
| `dwc_usb/ring.rs` | `CommandRing`, `EventRing`, ring state management, enqueue/dequeue logic | ~150 |
| `dwc_usb/types.rs` | `XhciAction`, `XhciEvent`, `XhciError`, `UsbSpeed`, `PortStatus` | ~100 |

The module's `mod.rs` re-exports all public types so external code still uses `drivers::dwc_usb::XhciDriver`.

## Testing Strategy

### trb.rs tests (~5 tests)
- `from_bytes_to_bytes_round_trip` — serialize then deserialize, assert equality
- `trb_type_extraction` — set known type bits, verify `trb_type()` returns correct value
- `cycle_bit_manipulation` — set/clear/read cycle bit
- `link_trb_construction` — build a Link TRB, verify type and parameter
- `command_completion_parsing` — build a completion TRB, extract slot_id and completion_code

### ring.rs tests (~8 tests)
- `command_ring_enqueue_returns_correct_phys` — first enqueue at base_phys + 0
- `command_ring_enqueue_advances_index` — second enqueue at base_phys + 16
- `command_ring_wrap_generates_link_trb` — enqueue 63 times, 63rd produces Link TRB + index reset
- `command_ring_cycle_toggles_on_wrap` — cycle bit flips after wrap
- `command_ring_full_returns_error` — 63 enqueues without completion → CommandRingFull
- `event_ring_should_process_matches_cycle` — matching cycle returns true
- `event_ring_advance_wraps_at_256` — dequeue through 256 entries, verify wrap + cycle toggle
- `event_ring_dequeue_pointer_computation` — verify physical address = base + index * 16

### mod.rs tests (~7 tests)
- `setup_rings_returns_register_actions` — verify DCBAAP, CRCR, ERSTSZ, ERSTBA, ERDP, USBCMD.RUN actions
- `setup_rings_transitions_to_running` — state check
- `setup_rings_before_ready_fails` — state guard
- `enqueue_noop_returns_write_and_doorbell` — WriteTrb + RingDoorbell actions
- `enqueue_before_running_fails` — state guard
- `process_command_completion` — feed completion TRB, get CommandCompletion event + UpdateDequeuePointer action
- `process_port_status_change` — feed PSC TRB, get PortStatusChange event

## Future Work (Explicitly Deferred)

- **Phase 2b (harmony-os-lv7):** Enable Slot, Address Device, control transfers, GET_DESCRIPTOR
- **Phase 3 (harmony-os-e4v):** Full configuration enumeration
- **DCBAAP allocation:** Phase 2b allocates device context arrays; Phase 2a writes a zeroed DCBAAP
- **Scratchpad buffers:** HCSPARAMS2 reports scratchpad buffer requirements; deferred until real hardware testing reveals if they're needed
- **Multiple interrupters:** Phase 2a uses interrupter 0 only
- **MSI/MSI-X interrupts:** Polling-only for now; interrupt support deferred
