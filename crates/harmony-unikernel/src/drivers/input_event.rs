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
    KEY_SCROLLLOCK, // 0x47
    KEY_PAUSE,      // 0x48
    KEY_INSERT,     // 0x49
    KEY_HOME,       // 0x4A
    KEY_PAGEUP,     // 0x4B
    KEY_DELETE,     // 0x4C
    KEY_END,        // 0x4D
    KEY_PAGEDOWN,   // 0x4E
    KEY_RIGHT,      // 0x4F
    KEY_LEFT,       // 0x50
    KEY_DOWN,       // 0x51
    KEY_UP,         // 0x52
    KEY_NUMLOCK,    // 0x53
    KEY_KPSLASH,    // 0x54
    KEY_KPASTERISK, // 0x55
    KEY_KPMINUS,    // 0x56
    KEY_KPPLUS,     // 0x57
    KEY_KPENTER,    // 0x58
    KEY_KP1,        // 0x59
    KEY_KP2,        // 0x5A
    KEY_KP3,        // 0x5B
    KEY_KP4,        // 0x5C
    KEY_KP5,        // 0x5D
    KEY_KP6,        // 0x5E
    KEY_KP7,        // 0x5F
    KEY_KP8,        // 0x60
    KEY_KP9,        // 0x61
    KEY_KP0,        // 0x62
    KEY_KPDOT,      // 0x63
    KEY_102ND,      // 0x64 — Non-US backslash
    KEY_COMPOSE,    // 0x65 — Application (Menu key)
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
    if !(0x04..=0x65).contains(&usage_id) {
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
