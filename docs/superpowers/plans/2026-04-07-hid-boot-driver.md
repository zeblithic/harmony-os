# HID Boot Protocol Driver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a native USB HID boot protocol driver for keyboards and mice, producing Linux-compatible input events via 9P.

**Architecture:** Ring 1 sans-I/O state machine (`HidBootDriver`) parses 8-byte keyboard and 3-4 byte mouse boot reports, diffs against previous state, and emits `InputEvent`s with Linux-compatible keycodes. Ring 2 `HidServer` implements `FileServer`, mediating between xHCI and HID driver, exposing `/hid0/events` and `/hid0/info` via 9P reads.

**Tech Stack:** Rust, `no_std`/`alloc`, sans-I/O pattern, `FidTracker` for 9P state

---

## File Structure

| File | Responsibility |
|------|----------------|
| **Create:** `crates/harmony-unikernel/src/drivers/input_event.rs` | `InputEvent` struct, Linux-compatible event type/code/value constants, USB HID Usage ID → Linux keycode mapping table |
| **Create:** `crates/harmony-unikernel/src/drivers/hid_boot.rs` | `HidBootDriver` sans-I/O state machine, `HidAction` enum, keyboard/mouse boot protocol parsing |
| **Modify:** `crates/harmony-unikernel/src/drivers/mod.rs` | Add `pub mod input_event;` and `pub mod hid_boot;` |
| **Create:** `crates/harmony-microkernel/src/hid_server.rs` | `HidServer` FileServer implementation, event ring buffer, `/hid0/events` and `/hid0/info` 9P paths |
| **Modify:** `crates/harmony-microkernel/src/lib.rs` | Add `pub mod hid_server;` |

---

## Task 1: Input Event Types and Keycode Mapping

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/input_event.rs`
- Modify: `crates/harmony-unikernel/src/drivers/mod.rs`

This task creates the shared data types and mapping table used by both Ring 1 and Ring 2.

- [ ] **Step 1: Create input_event.rs with InputEvent struct and Linux constants**

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! Linux-compatible input event types for HID drivers.
//!
//! Event format matches Linux `input_event` semantics (type, code, value)
//! but drops the timestamp — in our sans-I/O model the caller owns time.

// ── Event types (linux/input-event-codes.h) ─────────────────────

/// Synchronization event — marks the end of an event batch.
pub const EV_SYN: u8 = 0x00;
/// Key/button press or release.
pub const EV_KEY: u8 = 0x01;
/// Relative axis movement (mouse dx/dy/wheel).
pub const EV_REL: u8 = 0x02;

// ── Synchronization codes ───────────────────────────────────────

/// Separates events into batches (one per HID report).
pub const SYN_REPORT: u16 = 0x0000;

// ── Relative axis codes ─────────────────────────────────────────

pub const REL_X: u16 = 0x00;
pub const REL_Y: u16 = 0x01;
pub const REL_WHEEL: u16 = 0x08;

// ── Mouse button codes ──────────────────────────────────────────

pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;

// ── Modifier key codes ──────────────────────────────────────────

pub const KEY_LEFTCTRL: u16 = 29;
pub const KEY_LEFTSHIFT: u16 = 42;
pub const KEY_LEFTALT: u16 = 56;
pub const KEY_LEFTMETA: u16 = 125;
pub const KEY_RIGHTCTRL: u16 = 97;
pub const KEY_RIGHTSHIFT: u16 = 54;
pub const KEY_RIGHTALT: u16 = 100;
pub const KEY_RIGHTMETA: u16 = 126;

// ── Standard key codes (USB HID Usage ID order) ─────────────────
// These map to Linux KEY_* constants. The array index is the
// USB HID Usage ID minus 0x04 (Usage 0x04 = KEY_A).

pub const KEY_A: u16 = 30;
pub const KEY_B: u16 = 48;
pub const KEY_C: u16 = 46;
pub const KEY_D: u16 = 32;
pub const KEY_E: u16 = 18;
pub const KEY_F: u16 = 33;
pub const KEY_G: u16 = 34;
pub const KEY_H: u16 = 35;
pub const KEY_I: u16 = 23;
pub const KEY_J: u16 = 36;
pub const KEY_K: u16 = 37;
pub const KEY_L: u16 = 38;
pub const KEY_M: u16 = 50;
pub const KEY_N: u16 = 49;
pub const KEY_O: u16 = 24;
pub const KEY_P: u16 = 25;
pub const KEY_Q: u16 = 16;
pub const KEY_R: u16 = 19;
pub const KEY_S: u16 = 31;
pub const KEY_T: u16 = 20;
pub const KEY_U: u16 = 22;
pub const KEY_V: u16 = 47;
pub const KEY_W: u16 = 17;
pub const KEY_X: u16 = 45;
pub const KEY_Y: u16 = 21;
pub const KEY_Z: u16 = 44;
pub const KEY_1: u16 = 2;
pub const KEY_2: u16 = 3;
pub const KEY_3: u16 = 4;
pub const KEY_4: u16 = 5;
pub const KEY_5: u16 = 6;
pub const KEY_6: u16 = 7;
pub const KEY_7: u16 = 8;
pub const KEY_8: u16 = 9;
pub const KEY_9: u16 = 10;
pub const KEY_0: u16 = 11;
pub const KEY_ENTER: u16 = 28;
pub const KEY_ESC: u16 = 1;
pub const KEY_BACKSPACE: u16 = 14;
pub const KEY_TAB: u16 = 15;
pub const KEY_SPACE: u16 = 57;
pub const KEY_MINUS: u16 = 12;
pub const KEY_EQUAL: u16 = 13;
pub const KEY_LEFTBRACE: u16 = 26;
pub const KEY_RIGHTBRACE: u16 = 27;
pub const KEY_BACKSLASH: u16 = 43;
pub const KEY_SEMICOLON: u16 = 39;
pub const KEY_APOSTROPHE: u16 = 40;
pub const KEY_GRAVE: u16 = 41;
pub const KEY_COMMA: u16 = 51;
pub const KEY_DOT: u16 = 52;
pub const KEY_SLASH: u16 = 53;
pub const KEY_CAPSLOCK: u16 = 58;
pub const KEY_F1: u16 = 59;
pub const KEY_F2: u16 = 60;
pub const KEY_F3: u16 = 61;
pub const KEY_F4: u16 = 62;
pub const KEY_F5: u16 = 63;
pub const KEY_F6: u16 = 64;
pub const KEY_F7: u16 = 65;
pub const KEY_F8: u16 = 66;
pub const KEY_F9: u16 = 67;
pub const KEY_F10: u16 = 68;
pub const KEY_F11: u16 = 87;
pub const KEY_F12: u16 = 88;
pub const KEY_SYSRQ: u16 = 99;
pub const KEY_SCROLLLOCK: u16 = 70;
pub const KEY_PAUSE: u16 = 119;
pub const KEY_INSERT: u16 = 110;
pub const KEY_HOME: u16 = 102;
pub const KEY_PAGEUP: u16 = 104;
pub const KEY_DELETE: u16 = 111;
pub const KEY_END: u16 = 107;
pub const KEY_PAGEDOWN: u16 = 109;
pub const KEY_RIGHT: u16 = 106;
pub const KEY_LEFT: u16 = 105;
pub const KEY_DOWN: u16 = 108;
pub const KEY_UP: u16 = 103;
pub const KEY_NUMLOCK: u16 = 69;
pub const KEY_KPSLASH: u16 = 98;
pub const KEY_KPASTERISK: u16 = 55;
pub const KEY_KPMINUS: u16 = 74;
pub const KEY_KPPLUS: u16 = 78;
pub const KEY_KPENTER: u16 = 96;
pub const KEY_KP1: u16 = 79;
pub const KEY_KP2: u16 = 80;
pub const KEY_KP3: u16 = 81;
pub const KEY_KP4: u16 = 75;
pub const KEY_KP5: u16 = 76;
pub const KEY_KP6: u16 = 77;
pub const KEY_KP7: u16 = 71;
pub const KEY_KP8: u16 = 72;
pub const KEY_KP9: u16 = 73;
pub const KEY_KP0: u16 = 82;
pub const KEY_KPDOT: u16 = 83;
pub const KEY_102ND: u16 = 86;
pub const KEY_COMPOSE: u16 = 127;

/// USB HID Usage ID → Linux keycode lookup table.
///
/// Index = usage_id - 0x04 (Usage 0x04 = KEY_A is index 0).
/// Covers USB HID Usage Table §10, pages 0x04 through 0x65.
/// A value of 0 means "no mapping" (should not emit an event).
pub const HID_USAGE_TO_LINUX: [u16; 98] = [
    KEY_A,          // 0x04
    KEY_B,          // 0x05
    KEY_C,          // 0x06
    KEY_D,          // 0x07
    KEY_E,          // 0x08
    KEY_F,          // 0x09
    KEY_G,          // 0x0A
    KEY_H,          // 0x0B
    KEY_I,          // 0x0C
    KEY_J,          // 0x0D
    KEY_K,          // 0x0E
    KEY_L,          // 0x0F
    KEY_M,          // 0x10
    KEY_N,          // 0x11
    KEY_O,          // 0x12
    KEY_P,          // 0x13
    KEY_Q,          // 0x14
    KEY_R,          // 0x15
    KEY_S,          // 0x16
    KEY_T,          // 0x17
    KEY_U,          // 0x18
    KEY_V,          // 0x19
    KEY_W,          // 0x1A
    KEY_X,          // 0x1B
    KEY_Y,          // 0x1C
    KEY_Z,          // 0x1D
    KEY_1,          // 0x1E
    KEY_2,          // 0x1F
    KEY_3,          // 0x20
    KEY_4,          // 0x21
    KEY_5,          // 0x22
    KEY_6,          // 0x23
    KEY_7,          // 0x24
    KEY_8,          // 0x25
    KEY_9,          // 0x26
    KEY_0,          // 0x27
    KEY_ENTER,      // 0x28
    KEY_ESC,        // 0x29
    KEY_BACKSPACE,  // 0x2A
    KEY_TAB,        // 0x2B
    KEY_SPACE,      // 0x2C
    KEY_MINUS,      // 0x2D
    KEY_EQUAL,      // 0x2E
    KEY_LEFTBRACE,  // 0x2F
    KEY_RIGHTBRACE, // 0x30
    KEY_BACKSLASH,  // 0x31
    0,              // 0x32 — Non-US # (rare, no standard Linux mapping)
    KEY_SEMICOLON,  // 0x33
    KEY_APOSTROPHE, // 0x34
    KEY_GRAVE,      // 0x35
    KEY_COMMA,      // 0x36
    KEY_DOT,        // 0x37
    KEY_SLASH,      // 0x38
    KEY_CAPSLOCK,   // 0x39
    KEY_F1,         // 0x3A
    KEY_F2,         // 0x3B
    KEY_F3,         // 0x3C
    KEY_F4,         // 0x3D
    KEY_F5,         // 0x3E
    KEY_F6,         // 0x3F
    KEY_F7,         // 0x40
    KEY_F8,         // 0x41
    KEY_F9,         // 0x42
    KEY_F10,        // 0x43
    KEY_F11,        // 0x44
    KEY_F12,        // 0x45
    KEY_SYSRQ,      // 0x46 — PrintScreen
    KEY_SCROLLLOCK,  // 0x47
    KEY_PAUSE,       // 0x48
    KEY_INSERT,      // 0x49
    KEY_HOME,        // 0x4A
    KEY_PAGEUP,      // 0x4B
    KEY_DELETE,      // 0x4C
    KEY_END,         // 0x4D
    KEY_PAGEDOWN,    // 0x4E
    KEY_RIGHT,       // 0x4F
    KEY_LEFT,        // 0x50
    KEY_DOWN,        // 0x51
    KEY_UP,          // 0x52
    KEY_NUMLOCK,     // 0x53
    KEY_KPSLASH,     // 0x54
    KEY_KPASTERISK,  // 0x55
    KEY_KPMINUS,     // 0x56
    KEY_KPPLUS,      // 0x57
    KEY_KPENTER,     // 0x58
    KEY_KP1,         // 0x59
    KEY_KP2,         // 0x5A
    KEY_KP3,         // 0x5B
    KEY_KP4,         // 0x5C
    KEY_KP5,         // 0x5D
    KEY_KP6,         // 0x5E
    KEY_KP7,         // 0x5F
    KEY_KP8,         // 0x60
    KEY_KP9,         // 0x61
    KEY_KP0,         // 0x62
    KEY_KPDOT,       // 0x63
    KEY_102ND,       // 0x64 — Non-US backslash
    KEY_COMPOSE,     // 0x65 — Application (Menu key)
];

/// Modifier bitmap (byte 0 of keyboard boot report) → Linux keycode.
///
/// Index = bit position (0..8). Each modifier key occupies one bit.
pub const MODIFIER_TO_LINUX: [u16; 8] = [
    KEY_LEFTCTRL,   // bit 0
    KEY_LEFTSHIFT,  // bit 1
    KEY_LEFTALT,    // bit 2
    KEY_LEFTMETA,   // bit 3
    KEY_RIGHTCTRL,  // bit 4
    KEY_RIGHTSHIFT, // bit 5
    KEY_RIGHTALT,   // bit 6
    KEY_RIGHTMETA,  // bit 7
];

/// Convert a USB HID Usage ID (keyboard page) to a Linux keycode.
///
/// Returns `Some(keycode)` for valid mappings (0x04..=0x65),
/// `None` for unmapped or reserved usage IDs (0x00-0x03, > 0x65).
pub fn usage_to_keycode(usage_id: u8) -> Option<u16> {
    if usage_id < 0x04 || usage_id > 0x65 {
        return None;
    }
    let code = HID_USAGE_TO_LINUX[(usage_id - 0x04) as usize];
    if code == 0 {
        None
    } else {
        Some(code)
    }
}

// ── InputEvent ──────────────────────────────────────────────────

/// A single input event — key press/release, relative axis movement,
/// or synchronization marker.
///
/// 5 bytes packed. Uses Linux `input-event-codes.h` constants for
/// type, code, and value fields. No timestamp — in our sans-I/O
/// model the caller owns time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputEvent {
    /// Event type: `EV_KEY`, `EV_REL`, or `EV_SYN`.
    pub event_type: u8,
    /// Event code: `KEY_A`, `BTN_LEFT`, `REL_X`, `SYN_REPORT`, etc.
    pub code: u16,
    /// Event value: 1=press / 0=release for keys, signed delta for axes.
    pub value: i16,
}

impl InputEvent {
    /// Create a key press or release event.
    pub fn key(code: u16, pressed: bool) -> Self {
        Self {
            event_type: EV_KEY,
            code,
            value: if pressed { 1 } else { 0 },
        }
    }

    /// Create a relative axis event.
    pub fn rel(code: u16, delta: i16) -> Self {
        Self {
            event_type: EV_REL,
            code,
            value: delta,
        }
    }

    /// Create a SYN_REPORT event (terminates an event batch).
    pub fn syn() -> Self {
        Self {
            event_type: EV_SYN,
            code: SYN_REPORT,
            value: 0,
        }
    }

    /// Serialize to 5 bytes: [type, code_lo, code_hi, value_lo, value_hi].
    pub fn to_bytes(&self) -> [u8; 5] {
        let code_bytes = self.code.to_le_bytes();
        let value_bytes = self.value.to_le_bytes();
        [
            self.event_type,
            code_bytes[0],
            code_bytes[1],
            value_bytes[0],
            value_bytes[1],
        ]
    }

    /// Deserialize from 5 bytes. Returns None if slice is too short.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 5 {
            return None;
        }
        Some(Self {
            event_type: bytes[0],
            code: u16::from_le_bytes([bytes[1], bytes[2]]),
            value: i16::from_le_bytes([bytes[3], bytes[4]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_to_keycode_a() {
        assert_eq!(usage_to_keycode(0x04), Some(KEY_A));
    }

    #[test]
    fn usage_to_keycode_z() {
        assert_eq!(usage_to_keycode(0x1D), Some(KEY_Z));
    }

    #[test]
    fn usage_to_keycode_enter() {
        assert_eq!(usage_to_keycode(0x28), Some(KEY_ENTER));
    }

    #[test]
    fn usage_to_keycode_compose() {
        assert_eq!(usage_to_keycode(0x65), Some(KEY_COMPOSE));
    }

    #[test]
    fn usage_to_keycode_no_key() {
        assert_eq!(usage_to_keycode(0x00), None);
    }

    #[test]
    fn usage_to_keycode_error_rollover() {
        assert_eq!(usage_to_keycode(0x01), None);
    }

    #[test]
    fn usage_to_keycode_out_of_range() {
        assert_eq!(usage_to_keycode(0x66), None);
        assert_eq!(usage_to_keycode(0xFF), None);
    }

    #[test]
    fn usage_to_keycode_non_us_hash_unmapped() {
        // Usage 0x32 (Non-US #) has no standard Linux mapping
        assert_eq!(usage_to_keycode(0x32), None);
    }

    #[test]
    fn usage_to_keycode_all_letters_mapped() {
        // Usage IDs 0x04-0x1D (A-Z) must all have non-zero mappings
        for usage in 0x04..=0x1D {
            assert!(
                usage_to_keycode(usage).is_some(),
                "Usage 0x{:02X} should map to a keycode",
                usage
            );
        }
    }

    #[test]
    fn usage_to_keycode_all_digits_mapped() {
        // Usage IDs 0x1E-0x27 (1-0) must all have non-zero mappings
        for usage in 0x1E..=0x27 {
            assert!(
                usage_to_keycode(usage).is_some(),
                "Usage 0x{:02X} should map to a keycode",
                usage
            );
        }
    }

    #[test]
    fn input_event_key_press() {
        let ev = InputEvent::key(KEY_A, true);
        assert_eq!(ev.event_type, EV_KEY);
        assert_eq!(ev.code, KEY_A);
        assert_eq!(ev.value, 1);
    }

    #[test]
    fn input_event_key_release() {
        let ev = InputEvent::key(KEY_A, false);
        assert_eq!(ev.value, 0);
    }

    #[test]
    fn input_event_rel() {
        let ev = InputEvent::rel(REL_X, -5);
        assert_eq!(ev.event_type, EV_REL);
        assert_eq!(ev.code, REL_X);
        assert_eq!(ev.value, -5);
    }

    #[test]
    fn input_event_syn() {
        let ev = InputEvent::syn();
        assert_eq!(ev.event_type, EV_SYN);
        assert_eq!(ev.code, SYN_REPORT);
        assert_eq!(ev.value, 0);
    }

    #[test]
    fn input_event_round_trip() {
        let ev = InputEvent::key(KEY_LEFTSHIFT, true);
        let bytes = ev.to_bytes();
        assert_eq!(bytes.len(), 5);
        let decoded = InputEvent::from_bytes(&bytes).unwrap();
        assert_eq!(ev, decoded);
    }

    #[test]
    fn input_event_from_bytes_too_short() {
        assert_eq!(InputEvent::from_bytes(&[0, 0, 0, 0]), None);
    }

    #[test]
    fn modifier_table_has_8_entries() {
        assert_eq!(MODIFIER_TO_LINUX.len(), 8);
    }

    #[test]
    fn modifier_table_left_ctrl() {
        assert_eq!(MODIFIER_TO_LINUX[0], KEY_LEFTCTRL);
    }

    #[test]
    fn modifier_table_right_meta() {
        assert_eq!(MODIFIER_TO_LINUX[7], KEY_RIGHTMETA);
    }
}
```

- [ ] **Step 2: Register the module in drivers/mod.rs**

Add two lines to `crates/harmony-unikernel/src/drivers/mod.rs` after the existing module declarations:

```rust
pub mod input_event;
pub mod hid_boot;
```

Note: `hid_boot` won't exist yet — this will cause a compilation error until Task 2 creates it. If your build system rejects missing modules, create `hid_boot.rs` as an empty file first:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! USB HID boot protocol driver — placeholder.
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p harmony-unikernel -- input_event`
Expected: All 18 tests pass

- [ ] **Step 4: Run clippy**

Run: `cargo clippy -p harmony-unikernel`
Expected: No warnings

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/input_event.rs crates/harmony-unikernel/src/drivers/hid_boot.rs crates/harmony-unikernel/src/drivers/mod.rs
git commit -m "feat(hid): add InputEvent types and USB HID usage-to-keycode mapping

Linux-compatible input event struct (EV_KEY, EV_REL, EV_SYN) with
5-byte serialization. Static lookup table mapping USB HID Usage IDs
(0x04-0x65) to Linux KEY_* constants. 18 tests."
```

---

## Task 2: HID Boot Driver State Machine (Ring 1)

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/hid_boot.rs` (replace placeholder from Task 1)

This task builds the complete sans-I/O HID boot driver with keyboard and mouse parsing.

- [ ] **Step 1: Write the HidBootDriver struct, HidAction enum, HidError enum, and state types**

Replace the placeholder `hid_boot.rs` with:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! USB HID boot protocol driver (keyboards and mice).
//!
//! Sans-I/O state machine: accepts raw interrupt IN report bytes,
//! produces [`HidAction`] variants. The caller orchestrates actual
//! USB transfers via the xHCI driver.
//!
//! Supports:
//! - 8-byte keyboard boot reports (modifier byte + 6 keycodes)
//! - 3-4 byte mouse boot reports (buttons + dx + dy + optional wheel)

extern crate alloc;
use alloc::vec::Vec;

use super::input_event::{
    usage_to_keycode, InputEvent, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, MODIFIER_TO_LINUX, REL_WHEEL,
    REL_X, REL_Y,
};

// ── HID constants ───────────────────────────────────────────────

/// USB HID interface class code.
pub const HID_INTERFACE_CLASS: u8 = 0x03;

/// USB HID boot interface subclass.
pub const HID_BOOT_SUBCLASS: u8 = 0x01;

/// Boot protocol keyboard (interface protocol = 1).
const PROTOCOL_KEYBOARD: u8 = 1;

/// Boot protocol mouse (interface protocol = 2).
const PROTOCOL_MOUSE: u8 = 2;

/// USB HID Usage ID for ErrorRollOver — phantom key, ignore report.
const USAGE_ERROR_ROLLOVER: u8 = 0x01;

// ── Driver types ────────────────────────────────────────────────

/// Errors from HID driver operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HidError {
    /// Unsupported interface protocol (not 1=keyboard or 2=mouse).
    UnsupportedProtocol(u8),
    /// Operation attempted in wrong state.
    InvalidState,
}

/// Actions the HID driver returns for the caller to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HidAction {
    /// Caller should send SET_PROTOCOL(0) control transfer.
    /// bRequest=0x0B, wValue=0 (boot protocol), wIndex=interface_number.
    SendSetProtocol { interface_number: u8 },
    /// Caller should queue an interrupt IN transfer.
    QueueInterruptIn { endpoint_id: u8, length: u16 },
    /// Caller should deliver this input event to consumers.
    EmitInputEvent(InputEvent),
}

/// Internal driver state.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HidState {
    /// No device bound.
    Unbound,
    /// SET_PROTOCOL sent, waiting for completion.
    BindingKeyboard,
    /// SET_PROTOCOL sent, waiting for completion.
    BindingMouse,
    /// Keyboard active — polling for reports.
    ActiveKeyboard,
    /// Mouse active — polling for reports.
    ActiveMouse,
}

// ── Driver ──────────────────────────────────────────────────────

/// Sans-I/O USB HID boot protocol driver.
///
/// Accepts bind requests and raw interrupt IN data, produces
/// [`HidAction`] variants. Tracks key/button state internally
/// to diff press/release events across reports.
pub struct HidBootDriver {
    state: HidState,
    /// Interrupt IN endpoint DCI (set during bind).
    endpoint_id: u8,
    /// Interface number (for SET_PROTOCOL).
    interface_number: u8,
    /// Last keyboard modifier byte (for diff).
    prev_modifiers: u8,
    /// Last keyboard keycodes (for diff).
    prev_keys: [u8; 6],
    /// Last mouse button byte (for diff).
    prev_buttons: u8,
}

impl HidBootDriver {
    /// Create a new unbound HID driver.
    pub fn new() -> Self {
        Self {
            state: HidState::Unbound,
            endpoint_id: 0,
            interface_number: 0,
            prev_modifiers: 0,
            prev_keys: [0; 6],
            prev_buttons: 0,
        }
    }

    /// Bind to a HID boot interface.
    ///
    /// `interface_protocol`: 1 = keyboard, 2 = mouse.
    /// `endpoint_id`: DCI of the interrupt IN endpoint.
    /// `interface_number`: USB interface number (for SET_PROTOCOL).
    ///
    /// Returns `SendSetProtocol` action. Call `set_protocol_complete()`
    /// when the control transfer finishes.
    pub fn bind(
        &mut self,
        interface_protocol: u8,
        endpoint_id: u8,
        interface_number: u8,
    ) -> Result<Vec<HidAction>, HidError> {
        if self.state != HidState::Unbound {
            return Err(HidError::InvalidState);
        }
        self.endpoint_id = endpoint_id;
        self.interface_number = interface_number;
        match interface_protocol {
            PROTOCOL_KEYBOARD => {
                self.state = HidState::BindingKeyboard;
            }
            PROTOCOL_MOUSE => {
                self.state = HidState::BindingMouse;
            }
            other => return Err(HidError::UnsupportedProtocol(other)),
        }
        Ok(alloc::vec![HidAction::SendSetProtocol {
            interface_number,
        }])
    }

    /// Notify that SET_PROTOCOL completed successfully.
    ///
    /// Transitions to active state and returns `QueueInterruptIn`
    /// to start polling.
    pub fn set_protocol_complete(&mut self) -> Result<Vec<HidAction>, HidError> {
        let length = match self.state {
            HidState::BindingKeyboard => {
                self.state = HidState::ActiveKeyboard;
                8 // 8-byte keyboard boot report
            }
            HidState::BindingMouse => {
                self.state = HidState::ActiveMouse;
                8 // Request up to 8 bytes — mice send 3-4, extra is harmless
            }
            _ => return Err(HidError::InvalidState),
        };
        Ok(alloc::vec![HidAction::QueueInterruptIn {
            endpoint_id: self.endpoint_id,
            length,
        }])
    }

    /// Handle a completed interrupt IN transfer.
    ///
    /// Parses the boot report, diffs against previous state, and
    /// emits `InputEvent`s. Always re-queues the next interrupt IN.
    pub fn handle_interrupt_data(&mut self, data: &[u8]) -> Result<Vec<HidAction>, HidError> {
        match self.state {
            HidState::ActiveKeyboard => self.parse_keyboard_report(data),
            HidState::ActiveMouse => self.parse_mouse_report(data),
            _ => Err(HidError::InvalidState),
        }
    }

    /// Handle an interrupt transfer error (stall, etc.).
    ///
    /// Re-queues the interrupt IN — transient errors are normal for HID.
    pub fn handle_interrupt_error(&mut self) -> Result<Vec<HidAction>, HidError> {
        match self.state {
            HidState::ActiveKeyboard | HidState::ActiveMouse => {
                Ok(alloc::vec![HidAction::QueueInterruptIn {
                    endpoint_id: self.endpoint_id,
                    length: 8,
                }])
            }
            _ => Err(HidError::InvalidState),
        }
    }

    // ── Keyboard parsing ────────────────────────────────────────

    fn parse_keyboard_report(&mut self, data: &[u8]) -> Result<Vec<HidAction>, HidError> {
        // Short reports are dropped; re-queue interrupt IN.
        if data.len() < 8 {
            return Ok(alloc::vec![HidAction::QueueInterruptIn {
                endpoint_id: self.endpoint_id,
                length: 8,
            }]);
        }

        let modifiers = data[0];
        let keys = &data[2..8];

        // Check for ErrorRollOver — phantom keys, ignore entire report.
        if keys.iter().any(|&k| k == USAGE_ERROR_ROLLOVER) {
            return Ok(alloc::vec![HidAction::QueueInterruptIn {
                endpoint_id: self.endpoint_id,
                length: 8,
            }]);
        }

        let mut actions = Vec::new();

        // Diff modifier bits.
        let mod_diff = modifiers ^ self.prev_modifiers;
        for bit in 0..8u8 {
            if mod_diff & (1 << bit) != 0 {
                let pressed = modifiers & (1 << bit) != 0;
                actions.push(HidAction::EmitInputEvent(InputEvent::key(
                    MODIFIER_TO_LINUX[bit as usize],
                    pressed,
                )));
            }
        }

        // Keys released: in prev but not in current.
        for &prev_usage in &self.prev_keys {
            if prev_usage == 0 {
                continue;
            }
            if !keys.contains(&prev_usage) {
                if let Some(code) = usage_to_keycode(prev_usage) {
                    actions.push(HidAction::EmitInputEvent(InputEvent::key(code, false)));
                }
            }
        }

        // Keys pressed: in current but not in prev.
        for &cur_usage in keys {
            if cur_usage == 0 {
                continue;
            }
            if !self.prev_keys.contains(&cur_usage) {
                if let Some(code) = usage_to_keycode(cur_usage) {
                    actions.push(HidAction::EmitInputEvent(InputEvent::key(code, true)));
                }
            }
        }

        // SYN_REPORT to terminate batch (only if we emitted events).
        if !actions.is_empty() {
            actions.push(HidAction::EmitInputEvent(InputEvent::syn()));
        }

        // Update state.
        self.prev_modifiers = modifiers;
        self.prev_keys.copy_from_slice(keys);

        // Re-queue interrupt IN.
        actions.push(HidAction::QueueInterruptIn {
            endpoint_id: self.endpoint_id,
            length: 8,
        });

        Ok(actions)
    }

    // ── Mouse parsing ───────────────────────────────────────────

    fn parse_mouse_report(&mut self, data: &[u8]) -> Result<Vec<HidAction>, HidError> {
        // Short reports are dropped; re-queue interrupt IN.
        if data.len() < 3 {
            return Ok(alloc::vec![HidAction::QueueInterruptIn {
                endpoint_id: self.endpoint_id,
                length: 8,
            }]);
        }

        let buttons = data[0];
        let dx = data[1] as i8;
        let dy = data[2] as i8;

        let mut actions = Vec::new();

        // Button codes: bit 0 = left, bit 1 = right, bit 2 = middle.
        let button_codes = [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE];
        let btn_diff = buttons ^ self.prev_buttons;
        for (bit, &code) in button_codes.iter().enumerate() {
            if btn_diff & (1 << bit) != 0 {
                let pressed = buttons & (1 << bit) != 0;
                actions.push(HidAction::EmitInputEvent(InputEvent::key(code, pressed)));
            }
        }

        // Relative axes.
        if dx != 0 {
            actions.push(HidAction::EmitInputEvent(InputEvent::rel(
                REL_X,
                dx as i16,
            )));
        }
        if dy != 0 {
            actions.push(HidAction::EmitInputEvent(InputEvent::rel(
                REL_Y,
                dy as i16,
            )));
        }

        // Optional wheel (byte 3).
        if data.len() >= 4 {
            let wheel = data[3] as i8;
            if wheel != 0 {
                actions.push(HidAction::EmitInputEvent(InputEvent::rel(
                    REL_WHEEL,
                    wheel as i16,
                )));
            }
        }

        // SYN_REPORT if we emitted events.
        if !actions.is_empty() {
            actions.push(HidAction::EmitInputEvent(InputEvent::syn()));
        }

        // Update state.
        self.prev_buttons = buttons;

        // Re-queue interrupt IN.
        actions.push(HidAction::QueueInterruptIn {
            endpoint_id: self.endpoint_id,
            length: 8,
        });

        Ok(actions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::input_event::*;

    fn make_keyboard() -> HidBootDriver {
        let mut d = HidBootDriver::new();
        d.bind(1, 3, 0).unwrap();
        d.set_protocol_complete().unwrap();
        d
    }

    fn make_mouse() -> HidBootDriver {
        let mut d = HidBootDriver::new();
        d.bind(2, 3, 0).unwrap();
        d.set_protocol_complete().unwrap();
        d
    }

    /// Extract only EmitInputEvent actions (filter out QueueInterruptIn).
    fn events(actions: &[HidAction]) -> Vec<InputEvent> {
        actions
            .iter()
            .filter_map(|a| match a {
                HidAction::EmitInputEvent(ev) => Some(*ev),
                _ => None,
            })
            .collect()
    }

    // ── Bind tests ──────────────────────────────────────────────

    #[test]
    fn bind_keyboard_returns_set_protocol() {
        let mut d = HidBootDriver::new();
        let actions = d.bind(1, 3, 0).unwrap();
        assert_eq!(
            actions,
            alloc::vec![HidAction::SendSetProtocol {
                interface_number: 0
            }]
        );
    }

    #[test]
    fn bind_mouse_returns_set_protocol() {
        let mut d = HidBootDriver::new();
        let actions = d.bind(2, 5, 1).unwrap();
        assert_eq!(
            actions,
            alloc::vec![HidAction::SendSetProtocol {
                interface_number: 1
            }]
        );
    }

    #[test]
    fn bind_invalid_protocol() {
        let mut d = HidBootDriver::new();
        assert_eq!(d.bind(3, 3, 0), Err(HidError::UnsupportedProtocol(3)));
    }

    #[test]
    fn bind_wrong_state() {
        let mut d = make_keyboard();
        assert_eq!(d.bind(1, 3, 0), Err(HidError::InvalidState));
    }

    // ── Set protocol complete ───────────────────────────────────

    #[test]
    fn set_protocol_complete_returns_queue_interrupt() {
        let mut d = HidBootDriver::new();
        d.bind(1, 3, 0).unwrap();
        let actions = d.set_protocol_complete().unwrap();
        assert_eq!(
            actions,
            alloc::vec![HidAction::QueueInterruptIn {
                endpoint_id: 3,
                length: 8
            }]
        );
    }

    // ── Keyboard parsing ────────────────────────────────────────

    #[test]
    fn keyboard_single_key_press() {
        let mut d = make_keyboard();
        // Usage 0x04 = KEY_A
        let actions = d.handle_interrupt_data(&[0, 0, 0x04, 0, 0, 0, 0, 0]).unwrap();
        let evts = events(&actions);
        assert_eq!(evts[0], InputEvent::key(KEY_A, true));
        assert_eq!(evts[1], InputEvent::syn());
    }

    #[test]
    fn keyboard_key_release() {
        let mut d = make_keyboard();
        d.handle_interrupt_data(&[0, 0, 0x04, 0, 0, 0, 0, 0]).unwrap();
        let actions = d.handle_interrupt_data(&[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let evts = events(&actions);
        assert_eq!(evts[0], InputEvent::key(KEY_A, false));
        assert_eq!(evts[1], InputEvent::syn());
    }

    #[test]
    fn keyboard_modifier_press() {
        let mut d = make_keyboard();
        // Bit 1 = Left Shift
        let actions = d.handle_interrupt_data(&[0x02, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let evts = events(&actions);
        assert_eq!(evts[0], InputEvent::key(KEY_LEFTSHIFT, true));
        assert_eq!(evts[1], InputEvent::syn());
    }

    #[test]
    fn keyboard_multiple_simultaneous_keys() {
        let mut d = make_keyboard();
        let actions = d
            .handle_interrupt_data(&[0, 0, 0x04, 0x05, 0x06, 0, 0, 0])
            .unwrap();
        let evts = events(&actions);
        // 3 key presses + SYN
        assert_eq!(evts.len(), 4);
        assert!(evts.contains(&InputEvent::key(KEY_A, true)));
        assert!(evts.contains(&InputEvent::key(KEY_B, true)));
        assert!(evts.contains(&InputEvent::key(KEY_C, true)));
        assert_eq!(evts[3], InputEvent::syn());
    }

    #[test]
    fn keyboard_rollover_only_emits_deltas() {
        let mut d = make_keyboard();
        // Press A
        d.handle_interrupt_data(&[0, 0, 0x04, 0, 0, 0, 0, 0]).unwrap();
        // Press B while A held
        let actions = d
            .handle_interrupt_data(&[0, 0, 0x04, 0x05, 0, 0, 0, 0])
            .unwrap();
        let evts = events(&actions);
        // Only B press + SYN (A was already held)
        assert_eq!(evts.len(), 2);
        assert_eq!(evts[0], InputEvent::key(KEY_B, true));
        assert_eq!(evts[1], InputEvent::syn());
    }

    #[test]
    fn keyboard_error_rollover_ignored() {
        let mut d = make_keyboard();
        // ErrorRollOver (0x01) in keycodes — phantom, ignore
        let actions = d
            .handle_interrupt_data(&[0, 0, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01])
            .unwrap();
        let evts = events(&actions);
        assert!(evts.is_empty());
    }

    #[test]
    fn keyboard_short_report_dropped() {
        let mut d = make_keyboard();
        let actions = d.handle_interrupt_data(&[0, 0, 0x04]).unwrap();
        let evts = events(&actions);
        assert!(evts.is_empty());
        // But must still re-queue interrupt IN
        assert!(actions
            .iter()
            .any(|a| matches!(a, HidAction::QueueInterruptIn { .. })));
    }

    // ── Mouse parsing ───────────────────────────────────────────

    #[test]
    fn mouse_movement() {
        let mut d = make_mouse();
        let actions = d.handle_interrupt_data(&[0, 5, 0xFD]).unwrap(); // dx=5, dy=-3
        let evts = events(&actions);
        assert!(evts.contains(&InputEvent::rel(REL_X, 5)));
        assert!(evts.contains(&InputEvent::rel(REL_Y, -3)));
        assert_eq!(*evts.last().unwrap(), InputEvent::syn());
    }

    #[test]
    fn mouse_button_press_release() {
        let mut d = make_mouse();
        // Press left button
        let actions = d.handle_interrupt_data(&[1, 0, 0]).unwrap();
        let evts = events(&actions);
        assert_eq!(evts[0], InputEvent::key(BTN_LEFT, true));
        // Release left button
        let actions = d.handle_interrupt_data(&[0, 0, 0]).unwrap();
        let evts = events(&actions);
        assert_eq!(evts[0], InputEvent::key(BTN_LEFT, false));
    }

    #[test]
    fn mouse_with_wheel() {
        let mut d = make_mouse();
        let actions = d.handle_interrupt_data(&[0, 0, 0, 1]).unwrap(); // wheel up
        let evts = events(&actions);
        assert!(evts.contains(&InputEvent::rel(REL_WHEEL, 1)));
    }

    #[test]
    fn mouse_3_byte_no_wheel() {
        let mut d = make_mouse();
        let actions = d.handle_interrupt_data(&[0, 0, 0]).unwrap();
        let evts = events(&actions);
        // No movement, no buttons, no wheel — no events emitted
        assert!(evts.is_empty());
    }

    #[test]
    fn mouse_short_report_dropped() {
        let mut d = make_mouse();
        let actions = d.handle_interrupt_data(&[0, 0]).unwrap();
        let evts = events(&actions);
        assert!(evts.is_empty());
        assert!(actions
            .iter()
            .any(|a| matches!(a, HidAction::QueueInterruptIn { .. })));
    }

    // ── Re-queue behavior ───────────────────────────────────────

    #[test]
    fn every_handle_interrupt_data_requeues() {
        let mut d = make_keyboard();
        // Normal report
        let actions = d.handle_interrupt_data(&[0, 0, 0x04, 0, 0, 0, 0, 0]).unwrap();
        assert!(actions
            .iter()
            .any(|a| matches!(a, HidAction::QueueInterruptIn { .. })));
        // Short report
        let actions = d.handle_interrupt_data(&[0]).unwrap();
        assert!(actions
            .iter()
            .any(|a| matches!(a, HidAction::QueueInterruptIn { .. })));
    }

    #[test]
    fn handle_interrupt_error_requeues() {
        let mut d = make_keyboard();
        let actions = d.handle_interrupt_error().unwrap();
        assert_eq!(
            actions,
            alloc::vec![HidAction::QueueInterruptIn {
                endpoint_id: 3,
                length: 8
            }]
        );
    }

    #[test]
    fn handle_interrupt_data_wrong_state() {
        let d = HidBootDriver::new();
        // Unbound — can't handle data
        assert_eq!(
            d.clone().handle_interrupt_data(&[0; 8]),
            Err(HidError::InvalidState)
        );
    }
}
```

Note: The `handle_interrupt_data_wrong_state` test uses `d.clone()`. Add `#[derive(Clone)]` to `HidBootDriver`:

The struct definition should include `Clone`:

```rust
#[derive(Clone)]
pub struct HidBootDriver {
```

Actually, looking again — the test can just use a mutable reference without clone. Simpler version:

```rust
    #[test]
    fn handle_interrupt_data_wrong_state() {
        let mut d = HidBootDriver::new();
        assert_eq!(
            d.handle_interrupt_data(&[0; 8]),
            Err(HidError::InvalidState)
        );
    }
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p harmony-unikernel -- hid_boot`
Expected: All 16 tests pass

- [ ] **Step 3: Run clippy**

Run: `cargo clippy -p harmony-unikernel`
Expected: No warnings

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/hid_boot.rs
git commit -m "feat(hid): add HidBootDriver sans-I/O state machine

Keyboard boot report parsing (8-byte, modifier + keycode diffing),
mouse boot report parsing (3-4 byte, buttons + dx/dy + optional wheel),
HidAction return type for caller orchestration. 16 tests."
```

---

## Task 3: HID Server (Ring 2 FileServer)

**Files:**
- Create: `crates/harmony-microkernel/src/hid_server.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs`

This task builds the Ring 2 9P server that wraps the HidBootDriver and exposes input events.

- [ ] **Step 1: Create hid_server.rs**

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! HID boot protocol 9P server.
//!
//! Wraps a [`HidBootDriver`] and exposes input events via 9P:
//! - `/hid0/events` — read-only, returns serialized [`InputEvent`] structs
//! - `/hid0/info` — read-only, returns device type string
//!
//! Unlike hardware-facing servers (SdServer, GenetServer), HidServer
//! has no `RegisterBank` generic — the HID driver is pure byte-in /
//! events-out with no register access.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fid_tracker::FidTracker;
use crate::{slice_at_offset, Fid, FileStat, FileType, IpcError, OpenMode, QPath};

use harmony_unikernel::drivers::hid_boot::{HidAction, HidBootDriver, HidError};
use harmony_unikernel::drivers::input_event::InputEvent;

// ── QPath constants ─────────────────────────────────────────────

const QPATH_ROOT: QPath = 0;
const QPATH_EVENTS: QPath = 1;
const QPATH_INFO: QPath = 2;

// ── Event ring buffer ───────────────────────────────────────────

const EVENT_RING_SIZE: usize = 256;

struct EventRing {
    buf: [InputEvent; EVENT_RING_SIZE],
    head: usize, // next write position
    tail: usize, // next read position
    count: usize,
}

impl EventRing {
    fn new() -> Self {
        Self {
            buf: [InputEvent::syn(); EVENT_RING_SIZE],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    fn push(&mut self, event: InputEvent) {
        self.buf[self.head] = event;
        self.head = (self.head + 1) % EVENT_RING_SIZE;
        if self.count == EVENT_RING_SIZE {
            // Overflow: drop oldest by advancing tail.
            self.tail = (self.tail + 1) % EVENT_RING_SIZE;
        } else {
            self.count += 1;
        }
    }

    fn drain(&mut self, max_events: usize) -> Vec<InputEvent> {
        let n = self.count.min(max_events);
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.buf[self.tail]);
            self.tail = (self.tail + 1) % EVENT_RING_SIZE;
            self.count -= 1;
        }
        out
    }

    fn len(&self) -> usize {
        self.count
    }
}

// ── HidServer ───────────────────────────────────────────────────

/// 9P file server for a HID boot protocol device.
///
/// Wraps a [`HidBootDriver`] and an event ring buffer. The caller
/// feeds xHCI transfer completions via [`process_actions`]; consumers
/// read events via 9P `read("/hid0/events")`.
pub struct HidServer {
    driver: HidBootDriver,
    events: EventRing,
    tracker: FidTracker<()>,
    device_type: &'static str,
}

impl HidServer {
    /// Create a new HID server.
    ///
    /// `device_type` should be "keyboard" or "mouse" — determines
    /// what `/hid0/info` returns.
    pub fn new(device_type: &'static str) -> Self {
        Self {
            driver: HidBootDriver::new(),
            events: EventRing::new(),
            tracker: FidTracker::new(QPATH_ROOT, ()),
            device_type,
        }
    }

    /// Get a mutable reference to the inner driver (for bind/set_protocol).
    pub fn driver_mut(&mut self) -> &mut HidBootDriver {
        &mut self.driver
    }

    /// Process a list of HidActions: push EmitInputEvent to the ring
    /// buffer and return remaining actions (SendSetProtocol,
    /// QueueInterruptIn) for the caller to execute.
    pub fn process_actions(&mut self, actions: Vec<HidAction>) -> Vec<HidAction> {
        let mut remaining = Vec::new();
        for action in actions {
            match action {
                HidAction::EmitInputEvent(ev) => {
                    self.events.push(ev);
                }
                other => remaining.push(other),
            }
        }
        remaining
    }

    /// Feed interrupt completion data from xHCI to the driver, then
    /// process the resulting actions. Returns non-event actions for
    /// the caller to execute (QueueInterruptIn, etc.).
    pub fn handle_interrupt_data(&mut self, data: &[u8]) -> Result<Vec<HidAction>, HidError> {
        let actions = self.driver.handle_interrupt_data(data)?;
        Ok(self.process_actions(actions))
    }

    /// Number of events waiting in the ring buffer.
    pub fn pending_events(&self) -> usize {
        self.events.len()
    }
}

impl crate::FileServer for HidServer {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let entry = self.tracker.get(fid)?;
        if entry.qpath != QPATH_ROOT {
            return Err(IpcError::NotDirectory);
        }
        let qpath = match name {
            "events" => QPATH_EVENTS,
            "info" => QPATH_INFO,
            _ => return Err(IpcError::NotFound),
        };
        self.tracker.insert(new_fid, qpath, ())?;
        Ok(qpath)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let entry = self.tracker.begin_open(fid)?;
        // All files are read-only.
        if mode != OpenMode::Read {
            return Err(IpcError::ReadOnly);
        }
        entry.mark_open(mode);
        Ok(())
    }

    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.is_open() {
            return Err(IpcError::NotOpen);
        }
        match entry.qpath {
            QPATH_EVENTS => {
                // Drain events — offset is ignored (stream semantics).
                let max_events = (count as usize) / 5; // 5 bytes per event
                if max_events == 0 {
                    return Ok(Vec::new());
                }
                let events = self.events.drain(max_events);
                let mut buf = Vec::with_capacity(events.len() * 5);
                for ev in &events {
                    buf.extend_from_slice(&ev.to_bytes());
                }
                Ok(buf)
            }
            QPATH_INFO => {
                let info = alloc::format!("{}\n", self.device_type);
                Ok(slice_at_offset(info.as_bytes(), offset, count as usize))
            }
            _ => Err(IpcError::InvalidFid),
        }
    }

    fn write(&mut self, fid: Fid, _offset: u64, _data: &[u8]) -> Result<u32, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.is_open() {
            return Err(IpcError::NotOpen);
        }
        // All files are read-only.
        Err(IpcError::PermissionDenied)
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        self.tracker.clunk(fid)
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let entry = self.tracker.get(fid)?;
        match entry.qpath {
            QPATH_ROOT => Ok(FileStat {
                qpath: QPATH_ROOT,
                name: Arc::from("hid0"),
                size: 0,
                file_type: FileType::Directory,
            }),
            QPATH_EVENTS => Ok(FileStat {
                qpath: QPATH_EVENTS,
                name: Arc::from("events"),
                size: (self.events.len() * 5) as u64,
                file_type: FileType::Regular,
            }),
            QPATH_INFO => Ok(FileStat {
                qpath: QPATH_INFO,
                name: Arc::from("info"),
                size: (self.device_type.len() + 1) as u64, // +1 for newline
                file_type: FileType::Regular,
            }),
            _ => Err(IpcError::InvalidFid),
        }
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        self.tracker.clone_fid(fid, new_fid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileServer, OpenMode};
    use harmony_unikernel::drivers::input_event::*;

    fn make_keyboard_server() -> HidServer {
        let mut server = HidServer::new("keyboard");
        let actions = server.driver_mut().bind(1, 3, 0).unwrap();
        server.process_actions(actions);
        let actions = server.driver_mut().set_protocol_complete().unwrap();
        server.process_actions(actions);
        server
    }

    fn make_mouse_server() -> HidServer {
        let mut server = HidServer::new("mouse");
        let actions = server.driver_mut().bind(2, 5, 0).unwrap();
        server.process_actions(actions);
        let actions = server.driver_mut().set_protocol_complete().unwrap();
        server.process_actions(actions);
        server
    }

    // ── Walk tests ──────────────────────────────────────────────

    #[test]
    fn walk_events() {
        let mut s = make_keyboard_server();
        let qpath = s.walk(0, 1, "events").unwrap();
        assert_eq!(qpath, QPATH_EVENTS);
    }

    #[test]
    fn walk_info() {
        let mut s = make_keyboard_server();
        let qpath = s.walk(0, 1, "info").unwrap();
        assert_eq!(qpath, QPATH_INFO);
    }

    #[test]
    fn walk_nonexistent() {
        let mut s = make_keyboard_server();
        assert_eq!(s.walk(0, 1, "nope"), Err(IpcError::NotFound));
    }

    #[test]
    fn walk_from_non_root() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "events").unwrap();
        assert_eq!(s.walk(1, 2, "anything"), Err(IpcError::NotDirectory));
    }

    // ── Read tests ──────────────────────────────────────────────

    #[test]
    fn read_info_keyboard() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "info").unwrap();
        s.open(1, OpenMode::Read).unwrap();
        let data = s.read(1, 0, 256).unwrap();
        assert_eq!(data, b"keyboard\n");
    }

    #[test]
    fn read_info_mouse() {
        let mut s = make_mouse_server();
        s.walk(0, 1, "info").unwrap();
        s.open(1, OpenMode::Read).unwrap();
        let data = s.read(1, 0, 256).unwrap();
        assert_eq!(data, b"mouse\n");
    }

    #[test]
    fn read_events_empty() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "events").unwrap();
        s.open(1, OpenMode::Read).unwrap();
        let data = s.read(1, 0, 256).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn read_events_with_data() {
        let mut s = make_keyboard_server();
        // Generate a key press
        s.handle_interrupt_data(&[0, 0, 0x04, 0, 0, 0, 0, 0]).unwrap();
        s.walk(0, 1, "events").unwrap();
        s.open(1, OpenMode::Read).unwrap();
        let data = s.read(1, 0, 256).unwrap();
        // KEY_A press + SYN_REPORT = 2 events * 5 bytes = 10 bytes
        assert_eq!(data.len(), 10);
        let ev0 = InputEvent::from_bytes(&data[0..5]).unwrap();
        assert_eq!(ev0, InputEvent::key(KEY_A, true));
        let ev1 = InputEvent::from_bytes(&data[5..10]).unwrap();
        assert_eq!(ev1, InputEvent::syn());
    }

    #[test]
    fn read_events_drains() {
        let mut s = make_keyboard_server();
        s.handle_interrupt_data(&[0, 0, 0x04, 0, 0, 0, 0, 0]).unwrap();
        s.walk(0, 1, "events").unwrap();
        s.open(1, OpenMode::Read).unwrap();
        let data1 = s.read(1, 0, 256).unwrap();
        assert!(!data1.is_empty());
        // Second read should be empty — events were drained
        let data2 = s.read(1, 0, 256).unwrap();
        assert!(data2.is_empty());
    }

    #[test]
    fn event_ring_overflow() {
        let mut s = make_keyboard_server();
        // Push 257 events via alternating key press/release
        for i in 0..129 {
            let usage = 0x04 + (i % 26) as u8; // cycle through A-Z
            s.handle_interrupt_data(&[0, 0, usage, 0, 0, 0, 0, 0]).unwrap();
            s.handle_interrupt_data(&[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        }
        // Ring holds at most 256 events — oldest were dropped
        assert!(s.pending_events() <= EVENT_RING_SIZE);
        s.walk(0, 1, "events").unwrap();
        s.open(1, OpenMode::Read).unwrap();
        // Can read up to 256 events
        let data = s.read(1, 0, 5 * 256).unwrap();
        assert!(data.len() <= 5 * 256);
        assert!(data.len() > 0);
    }

    // ── Write rejected ──────────────────────────────────────────

    #[test]
    fn write_events_rejected() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "events").unwrap();
        s.open(1, OpenMode::Read).unwrap();
        assert_eq!(
            s.write(1, 0, &[0, 0, 0, 0, 0]),
            Err(IpcError::PermissionDenied)
        );
    }

    #[test]
    fn open_write_mode_rejected() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "events").unwrap();
        assert_eq!(s.open(1, OpenMode::Write), Err(IpcError::ReadOnly));
    }

    // ── Stat tests ──────────────────────────────────────────────

    #[test]
    fn stat_root() {
        let mut s = make_keyboard_server();
        let stat = s.stat(0).unwrap();
        assert_eq!(stat.file_type, FileType::Directory);
        assert_eq!(&*stat.name, "hid0");
    }

    #[test]
    fn stat_events() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "events").unwrap();
        let stat = s.stat(1).unwrap();
        assert_eq!(&*stat.name, "events");
        assert_eq!(stat.file_type, FileType::Regular);
    }

    #[test]
    fn stat_info() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "info").unwrap();
        let stat = s.stat(1).unwrap();
        assert_eq!(&*stat.name, "info");
        assert_eq!(stat.size, 9); // "keyboard\n"
    }

    // ── Clunk tests ─────────────────────────────────────────────

    #[test]
    fn clunk_root_rejected() {
        let mut s = make_keyboard_server();
        assert_eq!(s.clunk(0), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn clunk_walked_fid() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "events").unwrap();
        s.clunk(1).unwrap();
    }

    // ── Clone tests ─────────────────────────────────────────────

    #[test]
    fn clone_fid_works() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "events").unwrap();
        let qpath = s.clone_fid(1, 2).unwrap();
        assert_eq!(qpath, QPATH_EVENTS);
    }
}
```

- [ ] **Step 2: Register the module in microkernel lib.rs**

Add to `crates/harmony-microkernel/src/lib.rs` after the existing module declarations (e.g., after `pub mod genet_server;`):

```rust
pub mod hid_server;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p harmony-microkernel -- hid_server`
Expected: All 18 tests pass

- [ ] **Step 4: Run full workspace tests**

Run: `cargo test --workspace`
Expected: All existing tests + 52 new tests pass (18 input_event + 16 hid_boot + 18 hid_server)

- [ ] **Step 5: Run clippy**

Run: `cargo clippy --workspace`
Expected: No warnings

- [ ] **Step 6: Format**

Run: `cargo +nightly fmt --all`
Expected: Clean (nightly rustfmt required per CI)

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-microkernel/src/hid_server.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(hid): add HidServer 9P FileServer for keyboard/mouse events

Ring 2 server wrapping HidBootDriver. Exposes /hid0/events (stream
of 5-byte InputEvent structs) and /hid0/info (device type string).
256-slot event ring buffer with lossy overflow. 18 tests."
```

---

## Self-Review

**Spec coverage:**
- InputEvent struct + Linux constants — Task 1 ✓
- USB HID Usage ID → keycode mapping — Task 1 ✓
- HidBootDriver state machine — Task 2 ✓
- Keyboard boot report parsing (8-byte, modifier diff, key diff) — Task 2 ✓
- Mouse boot report parsing (3-4 byte, buttons, dx/dy, wheel) — Task 2 ✓
- HidServer FileServer — Task 3 ✓
- Event ring buffer (256 slots, lossy overflow) — Task 3 ✓
- `/hid0/events` and `/hid0/info` paths — Task 3 ✓
- 26 spec tests — covered: 18 (input_event) + 16 (hid_boot) + 18 (hid_server) = 52 total, exceeds spec's 26

**Placeholder scan:** No TBD, TODO, or placeholder code. All steps have complete code.

**Type consistency:**
- `InputEvent` — consistent across all three tasks (struct in Task 1, used in Tasks 2 and 3)
- `HidAction` — defined in Task 2, used in Task 3's `process_actions()`
- `HidError` — defined in Task 2, used in Task 3's `handle_interrupt_data()`
- `HidBootDriver` — defined in Task 2, wrapped in Task 3's `HidServer`
- `usage_to_keycode()` — defined in Task 1, called in Task 2's keyboard parser
- `MODIFIER_TO_LINUX` — defined in Task 1, used in Task 2's modifier diff
- `FidTracker<()>` — matches existing pattern (uart_server, sd_server)
- `FileServer` trait methods — all 7 implemented (walk, open, read, write, clunk, stat, clone_fid)
