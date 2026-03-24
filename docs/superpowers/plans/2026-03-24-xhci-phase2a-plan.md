# xHCI Phase 2a: TRB Ring Infrastructure — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement TRB ring infrastructure (command ring + event ring) with the xHCI setup sequence, enabling the controller to process No-Op commands and report events.

**Architecture:** Split `dwc_usb.rs` into a module directory (`dwc_usb/`). Add TRB data model, ring state machines (CommandRing/EventRing), action/event enums, and extend `XhciDriver` with `setup_rings`, `enqueue_noop`, and `process_event`. Sans-I/O: driver returns `XhciAction` variants, caller handles DMA + register writes.

**Tech Stack:** Rust, `no_std` + `alloc`, `RegisterBank` trait, `MockRegisterBank` for testing.

**Spec:** `docs/superpowers/specs/2026-03-24-xhci-phase2a-design.md`

---

### Task 1: Split `dwc_usb.rs` into module directory

**Files:**
- Delete: `crates/harmony-unikernel/src/drivers/dwc_usb.rs`
- Create: `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs`
- Create: `crates/harmony-unikernel/src/drivers/dwc_usb/types.rs`

**Context:**
- The current `dwc_usb.rs` is 468 lines. Phase 2a will push it to ~900+ lines. Split into a module directory now before adding new code.
- `drivers/mod.rs` already has `pub mod dwc_usb;` — Rust will find `dwc_usb/mod.rs` automatically. No change to `drivers/mod.rs` needed.
- This task moves types (`XhciError`, `UsbSpeed`, `PortStatus`) into `types.rs` and keeps everything else (register constants, `XhciState`, `XhciDriver`, tests) in `mod.rs`. The driver code re-exports from `types.rs` so external callers don't see the split.
- **All existing tests must continue to pass unchanged.**

- [ ] **Step 1: Create directory and types.rs**

Create `crates/harmony-unikernel/src/drivers/dwc_usb/` directory.

Create `crates/harmony-unikernel/src/drivers/dwc_usb/types.rs` with:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! Public types for the xHCI USB driver.

extern crate alloc;
use alloc::vec::Vec;

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
    /// Command ring is full (all 63 usable slots occupied).
    CommandRingFull,
    /// Malformed event TRB.
    InvalidEvent,
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

// Speed ID constants (xHCI spec Table 157)
const SPEED_FULL: u8 = 1;
const SPEED_LOW: u8 = 2;
const SPEED_HIGH: u8 = 3;
const SPEED_SUPER: u8 = 4;
const SPEED_SUPER_PLUS: u8 = 5;

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
```

- [ ] **Step 2: Create mod.rs from existing dwc_usb.rs**

Move `dwc_usb.rs` to `dwc_usb/mod.rs`. Remove the types that are now in `types.rs` (XhciError, UsbSpeed, PortStatus, speed constants, UsbSpeed::from_id impl). Add `pub mod types;` and `pub use types::*;` at the top so everything is re-exported.

The `mod.rs` should have:
- `pub mod types;` and `pub use types::*;`
- All register constants (unchanged)
- `XhciState` enum (private, stays in mod.rs)
- `XhciDriver` struct and impl (uses types via `use`)
- All existing tests (unchanged — they use `super::*` which picks up re-exports)

- [ ] **Step 3: Delete old dwc_usb.rs**

The old file at `crates/harmony-unikernel/src/drivers/dwc_usb.rs` must be deleted since it's replaced by `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs`.

- [ ] **Step 4: Verify all tests pass**

Run: `cargo test -p harmony-unikernel dwc_usb`
Expected: all 11 existing tests PASS (no functional changes).

- [ ] **Step 5: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(usb): split dwc_usb.rs into module directory

Move XhciError, UsbSpeed, PortStatus into dwc_usb/types.rs.
Register constants, XhciDriver, and tests stay in dwc_usb/mod.rs.
Re-exports preserve the public API — no external changes.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: TRB data model (`trb.rs`)

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/dwc_usb/trb.rs`
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs` (add `pub mod trb;` + re-export)

**Context:**
- The `Trb` struct is `#[repr(C)]` with `parameter: u64, status: u32, control: u32`.
- TRB type is in bits 15:10 of `control`. Cycle bit is bit 0 of `control`.
- `from_bytes`/`to_bytes` use little-endian byte order (xHCI is LE).
- TRB type constants: `TRB_LINK=6`, `TRB_NOOP_CMD=23`, `TRB_COMMAND_COMPLETION=33`, `TRB_PORT_STATUS_CHANGE=34`.
- Completion codes: `COMPLETION_SUCCESS=1`, `COMPLETION_TRB_ERROR=5`, `COMPLETION_NO_SLOTS=9`.

- [ ] **Step 1: Write failing tests**

Create `crates/harmony-unikernel/src/drivers/dwc_usb/trb.rs` with SPDX header, imports, and test module:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! xHCI Transfer Request Block (TRB) — the fundamental 16-byte data unit.

// TRB type constants + completion codes + Trb struct go here (step 3)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_to_bytes_round_trip() {
        let trb = Trb {
            parameter: 0xDEAD_BEEF_CAFE_BABE,
            status: 0x1234_5678,
            control: 0xABCD_EF01,
        };
        let bytes = trb.to_bytes();
        let decoded = Trb::from_bytes(bytes);
        assert_eq!(trb, decoded);
    }

    #[test]
    fn trb_type_extraction() {
        // Type field is bits 15:10 of control
        let trb = Trb {
            parameter: 0,
            status: 0,
            control: (TRB_NOOP_CMD as u32) << 10,
        };
        assert_eq!(trb.trb_type(), TRB_NOOP_CMD);
    }

    #[test]
    fn cycle_bit_manipulation() {
        let mut trb = Trb { parameter: 0, status: 0, control: 0 };
        assert!(!trb.cycle_bit());
        trb.set_cycle_bit(true);
        assert!(trb.cycle_bit());
        assert_eq!(trb.control & 1, 1);
        trb.set_cycle_bit(false);
        assert!(!trb.cycle_bit());
        assert_eq!(trb.control & 1, 0);
    }

    #[test]
    fn cycle_bit_preserves_other_fields() {
        let mut trb = Trb {
            parameter: 0,
            status: 0,
            control: (TRB_NOOP_CMD as u32) << 10 | 0xFF00,
        };
        trb.set_cycle_bit(true);
        assert_eq!(trb.trb_type(), TRB_NOOP_CMD);
        assert_eq!(trb.control & 0xFF00, 0xFF00);
    }

    #[test]
    fn command_completion_field_extraction() {
        // Command Completion Event TRB layout (xHCI Table 6-38):
        // parameter = Command TRB Pointer (64-bit physical address)
        // status bits 31:24 = Completion Code
        // control bits 31:24 = Slot ID, bits 15:10 = TRB Type (33), bit 0 = cycle
        let slot_id: u8 = 5;
        let completion_code: u8 = COMPLETION_SUCCESS;
        let trb = Trb {
            parameter: 0x2000_0000, // command TRB pointer
            status: (completion_code as u32) << 24,
            control: (slot_id as u32) << 24 | (TRB_COMMAND_COMPLETION as u32) << 10 | 1,
        };
        assert_eq!(trb.trb_type(), TRB_COMMAND_COMPLETION);
        assert_eq!((trb.control >> 24) as u8, slot_id);
        assert_eq!((trb.status >> 24) as u8, COMPLETION_SUCCESS);
        assert!(trb.cycle_bit());
    }
}
```

- [ ] **Step 2: Add module to mod.rs**

In `dwc_usb/mod.rs`, add after the `types` module:
```rust
pub mod trb;
pub use trb::*;
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel dwc_usb::trb`
Expected: FAIL — `Trb` doesn't exist.

- [ ] **Step 4: Implement Trb**

Add above the test module in `trb.rs`:

```rust
// ── TRB type constants ───────────────────────────────────────────

/// Link TRB — wraps ring back to base.
pub const TRB_LINK: u8 = 6;
/// No-Op Command TRB — tests ring machinery.
pub const TRB_NOOP_CMD: u8 = 23;
/// Command Completion Event TRB.
pub const TRB_COMMAND_COMPLETION: u8 = 33;
/// Port Status Change Event TRB.
pub const TRB_PORT_STATUS_CHANGE: u8 = 34;

// ── Completion codes ─────────────────────────────────────────────

pub const COMPLETION_SUCCESS: u8 = 1;
pub const COMPLETION_TRB_ERROR: u8 = 5;
pub const COMPLETION_NO_SLOTS: u8 = 9;

// ── Link TRB control flags ──────────────────────────────────────

/// Toggle Cycle bit in Link TRB (bit 1 of control).
pub const LINK_TOGGLE_CYCLE: u32 = 1 << 1;

// ── Trb struct ───────────────────────────────────────────────────

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

impl Trb {
    /// Extract the TRB type (bits 15:10 of control).
    pub fn trb_type(&self) -> u8 {
        ((self.control >> 10) & 0x3F) as u8
    }

    /// Read the cycle bit (bit 0 of control).
    pub fn cycle_bit(&self) -> bool {
        self.control & 1 != 0
    }

    /// Set or clear the cycle bit (bit 0 of control).
    pub fn set_cycle_bit(&mut self, bit: bool) {
        if bit {
            self.control |= 1;
        } else {
            self.control &= !1;
        }
    }

    /// Deserialize from 16 little-endian bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self {
            parameter: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            status: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            control: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        }
    }

    /// Serialize to 16 little-endian bytes.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&self.parameter.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.status.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.control.to_le_bytes());
        bytes
    }
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p harmony-unikernel dwc_usb::trb`
Expected: all 5 PASS.

- [ ] **Step 6: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/trb.rs crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs
git commit -m "feat(usb): add Trb data model with serialization and type constants

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Ring state machines (`ring.rs`)

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/dwc_usb/ring.rs`
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs` (add `pub mod ring;`)

**Context:**
- `CommandRing`: 64 entries (63 usable + 1 Link TRB at index 63). Tracks enqueue_index, cycle_bit, pending_count. Produces `Trb` values with correct physical addresses.
- `EventRing`: 256 entries. Tracks dequeue_index, cycle_bit. Checks cycle bit match for new events.
- Both rings deal only with indices and physical addresses — no RegisterBank, no DMA.
- `CommandRing::enqueue` returns a `Vec` of `(u64, Trb)` pairs (phys_addr, trb_data). The Link TRB at wrap produces a second pair.
- These are internal types — not re-exported from mod.rs (only used by XhciDriver).

- [ ] **Step 1: Write failing tests**

Create `crates/harmony-unikernel/src/drivers/dwc_usb/ring.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! xHCI ring state machines — CommandRing and EventRing.

extern crate alloc;
use alloc::vec::Vec;

use super::trb::{Trb, LINK_TOGGLE_CYCLE, TRB_LINK};
use super::types::XhciError;

// Implementation goes here (step 3)

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x1000_0000;

    #[test]
    fn command_ring_enqueue_returns_correct_phys() {
        let mut ring = CommandRing::new(BASE);
        let entries = ring.enqueue(23, 0).unwrap(); // TRB_NOOP_CMD
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, BASE); // first TRB at base
    }

    #[test]
    fn command_ring_enqueue_advances_index() {
        let mut ring = CommandRing::new(BASE);
        ring.enqueue(23, 0).unwrap();
        let entries = ring.enqueue(23, 0).unwrap();
        assert_eq!(entries[0].0, BASE + 16); // second TRB at base + 16
    }

    #[test]
    fn command_ring_enqueue_sets_cycle_bit() {
        let mut ring = CommandRing::new(BASE);
        let entries = ring.enqueue(23, 0).unwrap();
        assert!(entries[0].1.cycle_bit(), "initial cycle bit should be true");
    }

    #[test]
    fn command_ring_wrap_generates_link_trb() {
        let mut ring = CommandRing::new(BASE);
        // Enqueue 63 commands to fill all usable slots
        for i in 0..63 {
            let entries = ring.enqueue(23, i as u64).unwrap();
            if i < 62 {
                assert_eq!(entries.len(), 1, "non-wrap enqueue should produce 1 entry");
            } else {
                // Last enqueue (index 62) should also produce the Link TRB at index 63
                assert_eq!(entries.len(), 2, "wrap enqueue should produce command + link");
                let link = &entries[1];
                assert_eq!(link.0, BASE + 63 * 16, "link TRB at slot 63");
                assert_eq!(link.1.trb_type(), TRB_LINK);
                assert_eq!(link.1.parameter, BASE, "link points back to base");
            }
        }
    }

    #[test]
    fn command_ring_cycle_toggles_on_wrap() {
        let mut ring = CommandRing::new(BASE);
        for _ in 0..63 {
            ring.enqueue(23, 0).unwrap();
        }
        // After wrap, cycle bit should have toggled
        let entries = ring.enqueue(23, 0).unwrap();
        assert!(!entries[0].1.cycle_bit(), "cycle should toggle after wrap");
    }

    #[test]
    fn command_ring_second_lap_uses_toggled_cycle() {
        let mut ring = CommandRing::new(BASE);
        // Fill first lap
        for _ in 0..63 {
            ring.enqueue(23, 0).unwrap();
            ring.complete_one();
        }
        // Second lap — first enqueue should use toggled cycle bit (false)
        let entries = ring.enqueue(23, 0).unwrap();
        assert!(!entries[0].1.cycle_bit());
        assert_eq!(entries[0].0, BASE); // back at base
    }

    #[test]
    fn command_ring_full_returns_error() {
        let mut ring = CommandRing::new(BASE);
        for _ in 0..63 {
            ring.enqueue(23, 0).unwrap();
        }
        // Ring is full (63 pending, no completions)
        assert_eq!(ring.enqueue(23, 0), Err(XhciError::CommandRingFull));
    }

    #[test]
    fn command_ring_crcr_value() {
        let ring = CommandRing::new(BASE);
        // Initial: base + cycle bit 1
        assert_eq!(ring.crcr_value(), BASE | 1);
    }

    #[test]
    fn event_ring_should_process_matches_cycle() {
        let ring = EventRing::new(BASE);
        assert!(ring.should_process(true), "initial CCS is true");
        assert!(!ring.should_process(false), "mismatched cycle should reject");
    }

    #[test]
    fn event_ring_advance_wraps_at_256() {
        let mut ring = EventRing::new(BASE);
        for i in 0..255 {
            ring.advance();
            assert!(ring.should_process(true), "cycle should stay true before wrap (i={})", i);
        }
        // 256th advance wraps to 0 and toggles cycle
        ring.advance();
        assert!(ring.should_process(false), "cycle should toggle after 256 advances");
    }

    #[test]
    fn event_ring_dequeue_pointer() {
        let mut ring = EventRing::new(BASE);
        assert_eq!(ring.dequeue_pointer(), BASE);
        ring.advance();
        assert_eq!(ring.dequeue_pointer(), BASE + 16);
        ring.advance();
        assert_eq!(ring.dequeue_pointer(), BASE + 32);
    }
}
```

- [ ] **Step 2: Add module declaration**

In `dwc_usb/mod.rs`, add (not re-exported — internal):
```rust
mod ring;
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel dwc_usb::ring`
Expected: FAIL — `CommandRing` and `EventRing` don't exist.

- [ ] **Step 4: Implement CommandRing and EventRing**

Add above the test module in `ring.rs`:

```rust
/// Number of TRB entries in the command ring (63 usable + 1 Link).
pub const COMMAND_RING_SIZE: usize = 64;
/// Number of usable command slots (last slot is the Link TRB).
const COMMAND_RING_USABLE: usize = COMMAND_RING_SIZE - 1;

/// Number of TRB entries in the event ring.
pub const EVENT_RING_SIZE: usize = 256;

/// TRB size in bytes.
const TRB_SIZE: u64 = 16;

/// Command ring state — host enqueues commands, controller dequeues.
pub struct CommandRing {
    base_phys: u64,
    enqueue_index: u16,
    cycle_bit: bool,
    pending_count: u16,
}

impl CommandRing {
    /// Create a new command ring at the given physical base address.
    pub fn new(base_phys: u64) -> Self {
        Self {
            base_phys,
            enqueue_index: 0,
            cycle_bit: true,
            pending_count: 0,
        }
    }

    /// Enqueue a command TRB. Returns (phys_addr, trb) pairs to write.
    ///
    /// Normally returns 1 pair. When the enqueue fills the last usable
    /// slot, returns 2 pairs: the command TRB + the Link TRB at slot 63.
    pub fn enqueue(&mut self, trb_type: u8, parameter: u64) -> Result<Vec<(u64, Trb)>, XhciError> {
        if self.pending_count >= COMMAND_RING_USABLE as u16 {
            return Err(XhciError::CommandRingFull);
        }

        let phys = self.base_phys + (self.enqueue_index as u64) * TRB_SIZE;
        let mut trb = Trb {
            parameter,
            status: 0,
            control: (trb_type as u32) << 10,
        };
        trb.set_cycle_bit(self.cycle_bit);

        let mut entries = Vec::with_capacity(2);
        entries.push((phys, trb));

        self.enqueue_index += 1;
        self.pending_count += 1;

        // If we just wrote to the last usable slot, append Link TRB and wrap
        if self.enqueue_index >= COMMAND_RING_USABLE as u16 {
            let link_phys = self.base_phys + (COMMAND_RING_USABLE as u64) * TRB_SIZE;
            let mut link = Trb {
                parameter: self.base_phys, // points back to ring base
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

    /// Record that one command completed (decrements pending count).
    pub fn complete_one(&mut self) {
        self.pending_count = self.pending_count.saturating_sub(1);
    }

    /// CRCR register value: base address | cycle bit.
    pub fn crcr_value(&self) -> u64 {
        self.base_phys | (self.cycle_bit as u64)
    }
}

/// Event ring state — controller enqueues events, host dequeues.
pub struct EventRing {
    base_phys: u64,
    dequeue_index: u16,
    cycle_bit: bool,
}

impl EventRing {
    /// Create a new event ring at the given physical base address.
    pub fn new(base_phys: u64) -> Self {
        Self {
            base_phys,
            dequeue_index: 0,
            cycle_bit: true,
        }
    }

    /// Check if a TRB's cycle bit matches the expected Consumer Cycle State.
    pub fn should_process(&self, trb_cycle_bit: bool) -> bool {
        trb_cycle_bit == self.cycle_bit
    }

    /// Advance the dequeue pointer by one slot.
    pub fn advance(&mut self) {
        self.dequeue_index += 1;
        if self.dequeue_index >= EVENT_RING_SIZE as u16 {
            self.dequeue_index = 0;
            self.cycle_bit = !self.cycle_bit;
        }
    }

    /// Current dequeue pointer physical address (for ERDP update).
    pub fn dequeue_pointer(&self) -> u64 {
        self.base_phys + (self.dequeue_index as u64) * TRB_SIZE
    }
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p harmony-unikernel dwc_usb::ring`
Expected: all 11 PASS.

- [ ] **Step 6: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/ring.rs crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs
git commit -m "feat(usb): add CommandRing and EventRing state machines

64-entry command ring with Link TRB wrapping, cycle bit toggle,
pending count tracking. 256-entry event ring with cycle bit matching
and dequeue pointer computation.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Action and Event enums in `types.rs`

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/types.rs`

**Context:**
- Add `XhciAction` and `XhciEvent` enums to the existing `types.rs`.
- `XhciAction::RingDoorbell` includes pre-computed offset and value (reviewer feedback).
- `XhciEvent` is what `process_event` returns after parsing an event TRB.
- These types must be re-exported from `mod.rs` (they already are via `pub use types::*`).

- [ ] **Step 1: Write failing tests**

Add to `types.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xhci_action_variants_constructible() {
        let _write = XhciAction::WriteTrb {
            phys: 0x1000,
            trb: super::super::trb::Trb { parameter: 0, status: 0, control: 0 },
        };
        let _doorbell = XhciAction::RingDoorbell { offset: 0x2000, value: 0 };
        let _dequeue = XhciAction::UpdateDequeuePointer { phys: 0x3000 };
        let _reg32 = XhciAction::WriteRegister { offset: 0x38, value: 1 };
        let _reg64 = XhciAction::WriteRegister64 { offset_lo: 0x30, value: 0xDEAD };
    }

    #[test]
    fn xhci_event_variants_constructible() {
        let _cmd = XhciEvent::CommandCompletion { slot_id: 1, completion_code: 1 };
        let _psc = XhciEvent::PortStatusChange { port_id: 3 };
        let _unk = XhciEvent::Unknown { trb_type: 99 };
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel dwc_usb::types`
Expected: FAIL — `XhciAction` and `XhciEvent` don't exist.

- [ ] **Step 3: Implement**

Add to `types.rs` after `PortStatus`:

```rust
use super::trb::Trb;

// ── Driver actions ───────────────────────────────────────────────

/// Actions the driver returns for the caller to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XhciAction {
    /// Write a TRB to DMA memory at the given physical address.
    WriteTrb { phys: u64, trb: Trb },
    /// Ring a doorbell register (pre-computed offset and value).
    RingDoorbell { offset: usize, value: u32 },
    /// Update Event Ring Dequeue Pointer in interrupter register.
    UpdateDequeuePointer { phys: u64 },
    /// Write a 32-bit value to a register (offset from MMIO base).
    WriteRegister { offset: usize, value: u32 },
    /// Write a 64-bit value as LO/HI pair (offset_lo, offset_lo + 4).
    WriteRegister64 { offset_lo: usize, value: u64 },
}

// ── Driver events ────────────────────────────────────────────────

/// Parsed events from the xHCI event ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XhciEvent {
    /// A command completed.
    CommandCompletion { slot_id: u8, completion_code: u8 },
    /// A port status changed (connect/disconnect).
    PortStatusChange { port_id: u8 },
    /// Unrecognized event TRB type.
    Unknown { trb_type: u8 },
}
```

Note: the `use super::trb::Trb;` import needs to be at the top of the file or in the appropriate scope since `types.rs` and `trb.rs` are sibling modules under `dwc_usb/`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-unikernel dwc_usb::types`
Expected: all PASS.

- [ ] **Step 5: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/types.rs
git commit -m "feat(usb): add XhciAction and XhciEvent enums

Fine-grained action vocabulary (WriteTrb, RingDoorbell, WriteRegister,
etc.) and parsed event types (CommandCompletion, PortStatusChange).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: XhciDriver setup_rings — controller startup

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs`

**Context:**
- `setup_rings` transitions `Ready` → `Running`. Creates `CommandRing` and `EventRing`, returns actions to configure DCBAAP, CRCR, interrupter 0, and set USBCMD.RUN.
- Interrupter 0 registers are at `rts_offset + 0x20 + register_offset`.
- Event Ring Segment Table (ERST) entry: 16 bytes at `erst_phys` containing `{event_ring_phys: u64, EVENT_RING_SIZE as u32, reserved: u32}`. Written as a `WriteTrb` action (same 16-byte layout).
- `MaxSlotsEn = 0` in CONFIG register (Phase 2a doesn't need slots).
- DCBAAP = 0 (valid because MaxSlotsEn = 0).
- New register constants needed: interrupter register offsets (ERSTSZ, ERSTBA_LO/HI, ERDP_LO/HI).
- `db_offset` and `rts_offset` are already stored from Phase 1 init.

- [ ] **Step 1: Add interrupter register constants**

Add to `mod.rs` after the existing USBSTS bits:

```rust
// ── Interrupter 0 registers (offset from rts_offset + 0x20) ─────
const INTERRUPTER_0_BASE: usize = 0x20;
#[allow(dead_code)]
const IMAN: usize = 0x00;
#[allow(dead_code)]
const IMOD: usize = 0x04;
const ERSTSZ: usize = 0x08;
const ERSTBA_LO: usize = 0x10;
const ERSTBA_HI: usize = 0x14;
const ERDP_LO: usize = 0x18;
const ERDP_HI: usize = 0x1C;
```

- [ ] **Step 2: Write failing tests**

Add to the `mod.rs` test module:

```rust
    #[test]
    fn setup_rings_returns_register_actions() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        let actions = driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000).unwrap();

        // Should contain: CONFIG, DCBAAP(64), CRCR(64), ERST entry(WriteTrb),
        // ERSTSZ, ERSTBA(64), ERDP(64), USBCMD(RUN|INTE)
        // That's at least 8 actions
        assert!(actions.len() >= 8, "expected at least 8 setup actions, got {}", actions.len());

        // Verify USBCMD.RUN is the last action (controller starts)
        let last = actions.last().unwrap();
        match last {
            XhciAction::WriteRegister { offset, value } => {
                assert_eq!(*offset, 0x20 + USBCMD); // cap_length + USBCMD
                assert_ne!(*value & USBCMD_RUN, 0, "should set RUN");
                assert_ne!(*value & USBCMD_INTE, 0, "should set INTE");
            }
            _ => panic!("last action should be WriteRegister for USBCMD"),
        }
    }

    #[test]
    fn setup_rings_transitions_to_running() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000).unwrap();
        // Enqueue should work (Running state)
        assert!(driver.enqueue_noop().is_ok());
    }

    #[test]
    fn setup_rings_before_ready_fails() {
        let mut driver = XhciDriver {
            max_ports: 1,
            max_slots: 1,
            cap_length: 0x20,
            rts_offset: 0x2000,
            db_offset: 0x1000,
            state: XhciState::Error(XhciError::HaltTimeout),
            command_ring: None,
            event_ring: None,
        };
        assert_eq!(
            driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000),
            Err(XhciError::InvalidState)
        );
    }
```

Note: `setup_rings` test references `enqueue_noop` which is implemented in Task 6. For Task 5, either: (a) implement a minimal stub `enqueue_noop` that returns `Err(XhciError::InvalidState)`, or (b) skip the `setup_rings_transitions_to_running` test and add it in Task 6. **Implementer should choose (b) — move that test to Task 6.**

- [ ] **Step 3: Add `command_ring` and `event_ring` fields to XhciDriver**

Update `XhciDriver` struct in `mod.rs`:

```rust
pub struct XhciDriver {
    max_ports: u8,
    max_slots: u8,
    cap_length: usize,
    rts_offset: u32,
    db_offset: u32,
    state: XhciState,
    command_ring: Option<ring::CommandRing>,
    event_ring: Option<ring::EventRing>,
}
```

Update `init` to set both to `None`. Update `XhciState` to add `Running`.

- [ ] **Step 4: Implement setup_rings**

Add to `impl XhciDriver`:

```rust
    /// Configure command ring, event ring, and start the controller.
    ///
    /// The caller must allocate DMA memory for:
    /// - Command ring: 64 * 16 = 1024 bytes at `cmd_ring_phys`
    /// - Event ring: 256 * 16 = 4096 bytes at `event_ring_phys`
    /// - Event Ring Segment Table: 16 bytes at `erst_phys`
    ///
    /// Returns actions to write register values and the ERST entry.
    /// Execute all actions in order, then the controller is running.
    pub fn setup_rings(
        &mut self,
        cmd_ring_phys: u64,
        event_ring_phys: u64,
        erst_phys: u64,
    ) -> Result<Vec<XhciAction>, XhciError> {
        if self.state != XhciState::Ready {
            return Err(XhciError::InvalidState);
        }

        let cmd_ring = ring::CommandRing::new(cmd_ring_phys);
        let evt_ring = ring::EventRing::new(event_ring_phys);

        let mut actions = Vec::new();
        let op = self.cap_length;
        let intr = self.rts_offset as usize + INTERRUPTER_0_BASE;

        // 1. CONFIG: MaxSlotsEn = 0 (Phase 2a doesn't need slots)
        actions.push(XhciAction::WriteRegister { offset: op + CONFIG, value: 0 });

        // 2. DCBAAP = 0 (valid because MaxSlotsEn = 0)
        actions.push(XhciAction::WriteRegister64 { offset_lo: op + DCBAAP_LO, value: 0 });

        // 3. CRCR: command ring base + cycle bit
        actions.push(XhciAction::WriteRegister64 {
            offset_lo: op + CRCR_LO,
            value: cmd_ring.crcr_value(),
        });

        // 4. Write ERST entry (16 bytes): {event_ring_phys, EVENT_RING_SIZE, 0}
        actions.push(XhciAction::WriteTrb {
            phys: erst_phys,
            trb: trb::Trb {
                parameter: event_ring_phys,
                status: ring::EVENT_RING_SIZE as u32,
                control: 0, // reserved
            },
        });

        // 5. ERSTSZ = 1 (one segment)
        actions.push(XhciAction::WriteRegister { offset: intr + ERSTSZ, value: 1 });

        // 6. ERSTBA = erst_phys
        actions.push(XhciAction::WriteRegister64 { offset_lo: intr + ERSTBA_LO, value: erst_phys });

        // 7. ERDP = event ring dequeue pointer
        actions.push(XhciAction::WriteRegister64 {
            offset_lo: intr + ERDP_LO,
            value: evt_ring.dequeue_pointer(),
        });

        // 8. USBCMD: RUN + INTE
        actions.push(XhciAction::WriteRegister {
            offset: op + USBCMD,
            value: USBCMD_RUN | USBCMD_INTE,
        });

        self.command_ring = Some(cmd_ring);
        self.event_ring = Some(evt_ring);
        self.state = XhciState::Running;

        Ok(actions)
    }
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p harmony-unikernel dwc_usb`
Expected: all pass (existing + new setup_rings tests).

- [ ] **Step 6: Clippy + nightly fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs
git commit -m "feat(usb): implement setup_rings — DCBAAP, CRCR, interrupter, USBCMD.RUN

Configures command ring, event ring segment table, interrupter 0
registers, and starts the controller. Returns XhciAction list for
caller to execute. Transitions Ready → Running.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: enqueue_noop + process_event — command/event round-trip

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs`

**Context:**
- `enqueue_noop` wraps `CommandRing::enqueue(TRB_NOOP_CMD, 0)` and adds a `RingDoorbell` action.
- `process_event` takes a `Trb`, parses the event type, advances the event ring dequeue pointer, returns `(XhciEvent, Vec<XhciAction>)`.
- `should_process_event` is a simple cycle bit check.
- Doorbell value for command ring: slot=0, endpoint=0 → value=0. Offset = db_offset + 4 * 0 = db_offset.

- [ ] **Step 1: Write failing tests**

Add to `mod.rs` test module:

```rust
    #[test]
    fn enqueue_noop_returns_write_and_doorbell() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000).unwrap();

        let actions = driver.enqueue_noop().unwrap();
        // Should have: WriteTrb + RingDoorbell (minimum 2)
        assert!(actions.len() >= 2);

        // First action: WriteTrb for the No-Op command
        match &actions[0] {
            XhciAction::WriteTrb { phys, trb } => {
                assert_eq!(*phys, 0x2000_0000); // base of command ring
                assert_eq!(trb.trb_type(), trb::TRB_NOOP_CMD);
                assert!(trb.cycle_bit());
            }
            other => panic!("expected WriteTrb, got {:?}", other),
        }

        // Last action: RingDoorbell
        let last = actions.last().unwrap();
        match last {
            XhciAction::RingDoorbell { offset, value } => {
                assert_eq!(*offset, 0x1000); // db_offset from mock
                assert_eq!(*value, 0); // slot 0, endpoint 0
            }
            other => panic!("expected RingDoorbell, got {:?}", other),
        }
    }

    #[test]
    fn enqueue_before_running_fails() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        // Still in Ready state, not Running
        assert_eq!(driver.enqueue_noop(), Err(XhciError::InvalidState));
    }

    #[test]
    fn process_command_completion() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000).unwrap();
        driver.enqueue_noop().unwrap();

        // Simulate controller posting a Command Completion event
        // slot_id is in control bits 31:24 (xHCI Table 6-38)
        let slot_id: u8 = 3;
        let evt_trb = trb::Trb {
            parameter: 0x2000_0000, // command TRB pointer
            status: (COMPLETION_SUCCESS as u32) << 24,
            control: (slot_id as u32) << 24
                | (trb::TRB_COMMAND_COMPLETION as u32) << 10
                | 1, // cycle bit
        };

        let (event, actions) = driver.process_event(evt_trb).unwrap();
        assert_eq!(event, XhciEvent::CommandCompletion {
            slot_id: 3,
            completion_code: COMPLETION_SUCCESS,
        });

        // Should have UpdateDequeuePointer action
        assert!(actions.iter().any(|a| matches!(a, XhciAction::UpdateDequeuePointer { .. })));
    }

    #[test]
    fn process_port_status_change() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000).unwrap();

        let evt_trb = trb::Trb {
            parameter: (3u64) << 24, // port_id = 3 (bits 31:24 of parameter low dword)
            status: 0,
            control: (trb::TRB_PORT_STATUS_CHANGE as u32) << 10 | 1,
        };

        let (event, _) = driver.process_event(evt_trb).unwrap();
        assert_eq!(event, XhciEvent::PortStatusChange { port_id: 3 });
    }

    #[test]
    fn process_unknown_event() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000).unwrap();

        let evt_trb = trb::Trb {
            parameter: 0,
            status: 0,
            control: (63u32) << 10 | 1, // unknown type 63
        };

        let (event, _) = driver.process_event(evt_trb).unwrap();
        assert_eq!(event, XhciEvent::Unknown { trb_type: 63 });
    }

    #[test]
    fn should_process_event_delegates_to_event_ring() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000).unwrap();

        assert!(driver.should_process_event(true)); // initial CCS = true
        assert!(!driver.should_process_event(false));
    }

    #[test]
    fn setup_rings_transitions_to_running() {
        let mut bank = mock_init_success();
        let mut driver = XhciDriver::init(&mut bank).unwrap();
        driver.setup_rings(0x2000_0000, 0x3000_0000, 0x4000_0000).unwrap();
        // Enqueue should succeed (Running state)
        assert!(driver.enqueue_noop().is_ok());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel dwc_usb`
Expected: FAIL — `enqueue_noop`, `process_event`, `should_process_event` don't exist.

- [ ] **Step 3: Implement**

Add to `impl XhciDriver` in `mod.rs`:

```rust
    /// Enqueue a No-Op command on the command ring.
    ///
    /// Returns WriteTrb actions for the command (and Link TRB if wrapping),
    /// plus a RingDoorbell action to kick the controller.
    pub fn enqueue_noop(&mut self) -> Result<Vec<XhciAction>, XhciError> {
        if self.state != XhciState::Running {
            return Err(XhciError::InvalidState);
        }

        let cmd_ring = self.command_ring.as_mut().ok_or(XhciError::InvalidState)?;
        let entries = cmd_ring.enqueue(trb::TRB_NOOP_CMD, 0)?;

        let mut actions: Vec<XhciAction> = entries
            .into_iter()
            .map(|(phys, trb)| XhciAction::WriteTrb { phys, trb })
            .collect();

        // Ring doorbell 0 (command ring): offset = db_offset + 4 * 0
        actions.push(XhciAction::RingDoorbell {
            offset: self.db_offset as usize,
            value: 0,
        });

        Ok(actions)
    }

    /// Check if the next event TRB has a matching cycle bit.
    ///
    /// The caller reads the cycle bit from the TRB at the event ring's
    /// dequeue pointer in DMA memory, then calls this to check if it's
    /// a new event. If true, read the full TRB and pass to `process_event`.
    pub fn should_process_event(&self, cycle_bit: bool) -> bool {
        self.event_ring
            .as_ref()
            .map(|r| r.should_process(cycle_bit))
            .unwrap_or(false)
    }

    /// Process one event TRB from the event ring.
    ///
    /// Parses the event type, updates internal state, advances the
    /// event ring dequeue pointer. Returns the parsed event and actions
    /// to execute (UpdateDequeuePointer).
    pub fn process_event(
        &mut self,
        trb: trb::Trb,
    ) -> Result<(XhciEvent, Vec<XhciAction>), XhciError> {
        if self.state != XhciState::Running {
            return Err(XhciError::InvalidState);
        }

        let evt_ring = self.event_ring.as_mut().ok_or(XhciError::InvalidState)?;

        let event = match trb.trb_type() {
            trb::TRB_COMMAND_COMPLETION => {
                let slot_id = (trb.control >> 24) as u8;
                let completion_code = (trb.status >> 24) as u8;
                // Record completion in command ring
                if let Some(cmd_ring) = self.command_ring.as_mut() {
                    cmd_ring.complete_one();
                }
                XhciEvent::CommandCompletion { slot_id, completion_code }
            }
            trb::TRB_PORT_STATUS_CHANGE => {
                let port_id = ((trb.parameter >> 24) & 0xFF) as u8;
                XhciEvent::PortStatusChange { port_id }
            }
            other => XhciEvent::Unknown { trb_type: other },
        };

        evt_ring.advance();

        let actions = alloc::vec![XhciAction::UpdateDequeuePointer {
            phys: evt_ring.dequeue_pointer(),
        }];

        Ok((event, actions))
    }
```

Also add the `COMPLETION_SUCCESS` import from `trb` module to the test module so tests can reference it. The constant is already `pub` in `trb.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-unikernel dwc_usb`
Expected: all pass (11 existing + 5 trb + 11 ring + ~7 new = ~34 total).

- [ ] **Step 5: Run full workspace + clippy + nightly fmt**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all && rustup run nightly cargo fmt --all -- --check`

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/dwc_usb/mod.rs
git commit -m "feat(usb): implement enqueue_noop + process_event — command/event round-trip

No-Op command enqueue with RingDoorbell action, event ring processing
for CommandCompletion and PortStatusChange, dequeue pointer updates.
Completes the xHCI ring infrastructure for Phase 2a.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```
