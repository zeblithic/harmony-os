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

impl Default for HidBootDriver {
    fn default() -> Self {
        Self::new()
    }
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
        Ok(alloc::vec![HidAction::SendSetProtocol { interface_number }])
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
        if keys.contains(&USAGE_ERROR_ROLLOVER) {
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
            actions.push(HidAction::EmitInputEvent(InputEvent::rel(REL_X, dx as i16)));
        }
        if dy != 0 {
            actions.push(HidAction::EmitInputEvent(InputEvent::rel(REL_Y, dy as i16)));
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
        let actions = d
            .handle_interrupt_data(&[0, 0, 0x04, 0, 0, 0, 0, 0])
            .unwrap();
        let evts = events(&actions);
        assert_eq!(evts[0], InputEvent::key(KEY_A, true));
        assert_eq!(evts[1], InputEvent::syn());
    }

    #[test]
    fn keyboard_key_release() {
        let mut d = make_keyboard();
        d.handle_interrupt_data(&[0, 0, 0x04, 0, 0, 0, 0, 0])
            .unwrap();
        let actions = d.handle_interrupt_data(&[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let evts = events(&actions);
        assert_eq!(evts[0], InputEvent::key(KEY_A, false));
        assert_eq!(evts[1], InputEvent::syn());
    }

    #[test]
    fn keyboard_modifier_press() {
        let mut d = make_keyboard();
        // Bit 1 = Left Shift
        let actions = d
            .handle_interrupt_data(&[0x02, 0, 0, 0, 0, 0, 0, 0])
            .unwrap();
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
        d.handle_interrupt_data(&[0, 0, 0x04, 0, 0, 0, 0, 0])
            .unwrap();
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
        let actions = d
            .handle_interrupt_data(&[0, 0, 0x04, 0, 0, 0, 0, 0])
            .unwrap();
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
        let mut d = HidBootDriver::new();
        assert_eq!(
            d.handle_interrupt_data(&[0; 8]),
            Err(HidError::InvalidState)
        );
    }
}
