# HID Boot Protocol Driver

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Bead:** harmony-os-yrg

**Goal:** Add a native USB HID boot protocol driver for keyboards and mice, producing Linux-compatible input events via 9P. This unblocks basic input on USB-connected hardware.

**Prerequisite:** xHCI Phase 3b (harmony-os-ho8) is merged.

---

## Architecture

Two new units, following the existing Ring 1 driver + Ring 2 server pattern:

**Ring 1 — `HidBootDriver`** (`harmony-unikernel/src/drivers/hid_boot.rs`)
Sans-I/O state machine. Accepts bind requests and raw interrupt IN data, produces `HidAction` variants. Parses 8-byte keyboard boot reports and 3-4 byte mouse boot reports. Tracks key/button state internally to diff press/release events.

**Ring 2 — `HidServer`** (`harmony-microkernel/src/hid_server.rs`)
`FileServer` implementation. Mediates between xHCI and HID driver. Exposes `/hid0/events` (input events) and `/hid0/info` (device metadata) via 9P reads. Queues events in a fixed-size ring buffer.

**Shared types** — `InputEvent` struct and Linux-compatible constants live in Ring 1 (`harmony-unikernel/src/drivers/input_event.rs`) where they're produced. Ring 2 imports them.

### What stays the same

- xHCI driver — unchanged (HID driver consumes its outputs, doesn't modify it)
- All existing `FileServer` implementations — unchanged
- All existing tests — unchanged

---

## Input Event Format

5 bytes, packed:

| Field | Type | Description |
|-------|------|-------------|
| type | u8 | `EV_KEY` (0x01), `EV_REL` (0x02), `EV_SYN` (0x00) |
| code | u16 | Linux-compatible: `KEY_A` (30), `BTN_LEFT` (0x110), `REL_X` (0x00), etc. |
| value | i16 | Keys: 1=press, 0=release. Relative axes: signed delta. |

Uses Linux `input-event-codes.h` constants. No timestamp (sans-I/O — caller owns time). The Linuxulator can pass these through with minimal translation.

---

## HID Boot Driver (Ring 1)

### State Machine

```
Unbound
  → bind(protocol=1) → BindingKeyboard  [returns SendSetProtocol]
  → bind(protocol=2) → BindingMouse     [returns SendSetProtocol]
  → bind(other)      → Error

BindingKeyboard / BindingMouse
  → set_protocol_complete() → ActiveKeyboard / ActiveMouse  [returns QueueInterruptIn]

ActiveKeyboard / ActiveMouse
  → handle_interrupt_data(&[u8]) → same state  [returns EmitInputEvent* + QueueInterruptIn]
  → handle_interrupt_error(u8)   → same state  [returns QueueInterruptIn]
```

### HidAction Enum

- `SendSetProtocol { interface_number: u8 }` — Caller builds SET_PROTOCOL(0) control transfer (bRequest=0x0B, wValue=0 for boot protocol)
- `QueueInterruptIn { endpoint_id: u8, length: u16 }` — Caller calls `xhci.interrupt_transfer_in()`
- `EmitInputEvent(InputEvent)` — Caller delivers to event queue

### Internal State

- `prev_keys: [u8; 6]` — Last keyboard report's keycode bytes (for diff)
- `prev_modifiers: u8` — Last keyboard report's modifier byte (for diff)
- `prev_buttons: u8` — Last mouse report's button byte (for diff)
- `endpoint_id: u8` — Interrupt IN endpoint (set during bind)

### Keyboard Report Parsing (8-byte boot protocol)

```
Byte 0: modifier keys (bitmap)
  bit 0: Left Control    bit 4: Right Control
  bit 1: Left Shift      bit 5: Right Shift
  bit 2: Left Alt        bit 6: Right Alt
  bit 3: Left GUI        bit 7: Right GUI
Byte 1: reserved (0x00)
Bytes 2-7: up to 6 simultaneous keycodes (USB HID Usage ID)
  0x00 = no key, 0x01 = ErrorRollOver (phantom, ignore)
```

Parsing logic:
1. Diff modifier byte bit-by-bit against `prev_modifiers`. Each changed bit emits `EV_KEY` press (1) or release (0) for the corresponding modifier keycode.
2. Diff keycodes (bytes 2-7) against `prev_keys`:
   - Usage IDs in current but not prev → `EV_KEY` press
   - Usage IDs in prev but not current → `EV_KEY` release
   - Skip 0x00 (empty) and 0x01 (ErrorRollOver)
3. Emit `EV_SYN SYN_REPORT` to terminate the event batch.
4. Update `prev_modifiers` and `prev_keys`.

### Mouse Report Parsing (3-4 byte boot protocol)

```
Byte 0: buttons (bit 0=left, bit 1=right, bit 2=middle)
Byte 1: X displacement (i8, signed)
Byte 2: Y displacement (i8, signed)
Byte 3: wheel delta (i8, optional)
```

Parsing logic:
1. Diff button byte against `prev_buttons`. Each changed bit emits `EV_KEY` press/release for `BTN_LEFT`/`BTN_RIGHT`/`BTN_MIDDLE`.
2. Non-zero X → `EV_REL REL_X` with delta value.
3. Non-zero Y → `EV_REL REL_Y` with delta value.
4. If report length >= 4 and non-zero wheel → `EV_REL REL_WHEEL` with delta value.
5. Emit `EV_SYN SYN_REPORT`.
6. Update `prev_buttons`.

### USB HID Usage ID to Linux Keycode Mapping

A static lookup table mapping USB HID Usage IDs (0x04-0x65) to Linux `KEY_*` constants. Covers the standard 104-key US keyboard layout used by boot protocol:

- 0x04-0x1D: KEY_A through KEY_Z
- 0x1E-0x27: KEY_1 through KEY_0
- 0x28: KEY_ENTER, 0x29: KEY_ESC, 0x2A: KEY_BACKSPACE, 0x2B: KEY_TAB
- 0x2C: KEY_SPACE, 0x2D-0x38: punctuation/symbols
- 0x39: KEY_CAPSLOCK, 0x3A-0x45: KEY_F1 through KEY_F12
- 0x46-0x65: navigation, editing, keypad keys

Modifier keycodes (from byte 0 bitmap):
- bit 0 → KEY_LEFTCTRL (29), bit 4 → KEY_RIGHTCTRL (97)
- bit 1 → KEY_LEFTSHIFT (42), bit 5 → KEY_RIGHTSHIFT (54)
- bit 2 → KEY_LEFTALT (56), bit 6 → KEY_RIGHTALT (100)
- bit 3 → KEY_LEFTMETA (125), bit 7 → KEY_RIGHTMETA (126)

### Error Handling

- Short report (< 8 bytes keyboard, < 3 bytes mouse): drop silently, re-queue interrupt IN
- ErrorRollOver (0x01 in any keycode byte): ignore entire report (phantom keys), re-queue
- Interrupt transfer error/stall: re-queue interrupt IN (transient stalls are normal for HID)
- No escalation or recovery state machine needed for boot protocol

---

## HID Server (Ring 2)

### FileServer Implementation

`HidServer` wraps a `HidBootDriver` and mediates xHCI interaction. Unlike hardware-facing servers (SdServer, GenetServer), HidServer has no `RegisterBank` generic — the HID driver is pure byte-in/events-out with no register access.

**9P namespace:**
- `/hid0/events` — read-only, returns serialized `InputEvent` structs
- `/hid0/info` — read-only, returns device type string ("keyboard\n" or "mouse\n")

**Event ring buffer:**
- Fixed-size `[InputEvent; 256]` circular buffer with head/tail indices
- `read("/hid0/events")` drains all available events (up to `count` bytes)
- If buffer fills, oldest events are dropped — input devices are inherently lossy
- Events are serialized as 5-byte packed structs in the read buffer

**Orchestration:**
The server's `process_xhci_completion()` method (called by the system when an xHCI transfer completes) feeds data to the `HidBootDriver` and processes the returned `HidAction`s:
- `EmitInputEvent` → push to ring buffer
- `QueueInterruptIn` → call xHCI driver's `interrupt_transfer_in()`
- `SendSetProtocol` → call xHCI driver's `control_transfer()`

---

## Testing

All tests use existing sans-I/O patterns. No hardware, no DMA.

### Ring 1 — HidBootDriver unit tests

1. **bind keyboard** — `bind(1)` returns `SendSetProtocol`, state → `BindingKeyboard`
2. **bind mouse** — `bind(2)` returns `SendSetProtocol`, state → `BindingMouse`
3. **bind invalid protocol** — `bind(3)` returns error
4. **bind wrong state** — `bind()` when already active returns error
5. **set_protocol_complete** — transitions to Active, returns `QueueInterruptIn`
6. **keyboard single key press** — `[0,0,4,0,0,0,0,0]` → `EV_KEY KEY_A 1` + `EV_SYN`
7. **keyboard key release** — follow-up `[0,0,0,0,0,0,0,0]` → `EV_KEY KEY_A 0` + `EV_SYN`
8. **keyboard modifier press** — `[0x02,0,0,0,0,0,0,0]` → `EV_KEY KEY_LEFTSHIFT 1`
9. **keyboard multiple simultaneous keys** — `[0,0,4,5,6,0,0,0]` → three press events
10. **keyboard rollover** — keys held across reports only emit delta events
11. **mouse movement** — `[0,5,-3]` → `EV_REL REL_X 5`, `EV_REL REL_Y -3`, `EV_SYN`
12. **mouse button press/release** — `[1,0,0]` then `[0,0,0]` → BTN_LEFT press then release
13. **mouse with wheel** — 4-byte `[0,0,0,1]` → `EV_REL REL_WHEEL 1`
14. **mouse 3-byte report (no wheel)** — gracefully handled, no wheel event
15. **short report dropped** — 2-byte report → no events, `QueueInterruptIn` returned
16. **every action re-queues interrupt** — all `handle_interrupt_data` calls include `QueueInterruptIn`

### Ring 2 — HidServer unit tests

17. **walk /events** — returns valid QPath
18. **walk /info** — returns valid QPath
19. **walk /nonexistent** — returns NotFound
20. **read /info** — returns "keyboard" or "mouse" string
21. **read /events empty** — returns empty
22. **read /events with data** — push events, read returns serialized InputEvents
23. **event ring buffer overflow** — 257 events pushed, oldest dropped, newest 256 readable
24. **write /events** — returns PermissionDenied

### Mapping tests

25. **usage_to_keycode coverage** — all boot protocol usage IDs (0x04-0x65) map to correct Linux KEY_* constants
26. **usage 0x00 (no key)** — skipped, no event emitted

---

## Scope Boundary

**In scope:**
- `HidBootDriver` sans-I/O state machine (`hid_boot.rs` in Ring 1)
- `InputEvent` struct + Linux-compatible constants (`input_event.rs` in Ring 1)
- USB HID Usage ID → Linux keycode mapping table
- Boot protocol keyboard parsing (8-byte, modifier diff, key diff)
- Boot protocol mouse parsing (3-4 byte, buttons, dx/dy, optional wheel)
- `HidServer` FileServer implementation (`hid_server.rs` in Ring 2)
- Event ring buffer (fixed 256 slots, lossy overflow)
- `/hid0/events` and `/hid0/info` 9P paths
- All 26 tests listed above

**Out of scope:**
- HID report protocol / report descriptor parsing (harmony-os-vf9)
- USB device enumeration manager / class driver dispatch
- Mass storage class driver (harmony-os-yko)
- CDC-ECM/NCM class driver (harmony-os-y66)
- DDE / Linux driver shims (deferred)
- LED output reports (Caps Lock / Num Lock indicators)
- Multiple HID devices simultaneously (single `/hid0/` for now)
- Keyboard layout / keymap translation (consumer concern)
- Gamepad / joystick support (needs report protocol)
