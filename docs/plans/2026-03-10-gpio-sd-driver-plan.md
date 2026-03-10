# GPIO + SD/eMMC Driver Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add RP1 GPIO and SDHCI SD/eMMC sans-I/O drivers with 9P FileServer wrappers.

**Architecture:** Abstract `GpioController` trait with RP1 implementation using three RegisterBanks (io, pads, rio). SDHCI driver with PIO transfers and card initialization state machine returning `SdAction` variants. Both exposed as 9P FileServers in harmony-microkernel.

**Tech Stack:** Rust, `no_std`, `alloc`, `RegisterBank` trait, `MockRegisterBank` for testing.

**Design doc:** `docs/plans/2026-03-10-gpio-sd-driver-design.md`

**Existing patterns to follow:**
- `crates/harmony-unikernel/src/drivers/pl011.rs` — driver structure, RegisterBank usage
- `crates/harmony-microkernel/src/uart_server.rs` — 9P FileServer wrapping a driver
- `crates/harmony-unikernel/src/drivers/register_bank.rs` — MockRegisterBank for tests

**Build/test commands:**
- `cargo test -p harmony-unikernel` — driver tests
- `cargo test -p harmony-microkernel` — server tests
- `cargo clippy --workspace` — lint
- `cargo test --workspace` — all tests

---

## Task 1: GPIO Driver — Types and GpioController Trait

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/gpio.rs`
- Modify: `crates/harmony-unikernel/src/drivers/mod.rs:8` (add `pub mod gpio;`)

### Step 1: Write the types and trait (test-first)

Create `gpio.rs` with the public API: error types, enums, and the `GpioController` trait. Start with a test that the types exist and trait is object-safe.

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! GPIO controller abstraction and RP1 implementation.
//!
//! The [`GpioController`] trait defines pin operations (direction,
//! function select, pull, read, write). [`Rp1Gpio`] implements it
//! for the RP1 south-bridge chip on the Raspberry Pi 5.

use super::register_bank::RegisterBank;

// ── Error type ──────────────────────────────────────────────────

/// Errors returned by GPIO operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpioError {
    /// Pin number exceeds the controller's pin count.
    InvalidPin,
}

// ── Pin configuration enums ─────────────────────────────────────

/// Pin function — input, output, or one of six alternate functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinFunction {
    Input,
    Output,
    Alt0,
    Alt1,
    Alt2,
    Alt3,
    Alt4,
    Alt5,
}

/// Pin direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinDirection {
    Input,
    Output,
}

/// Internal pull resistor configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pull {
    None,
    Up,
    Down,
}

// ── GpioController trait ────────────────────────────────────────

/// Abstract GPIO controller.
///
/// Implementations map these operations onto specific hardware
/// register layouts (e.g. RP1, BCM2835).
pub trait GpioController {
    /// Set the pin's function (input, output, or alternate).
    fn set_function(&mut self, pin: u8, func: PinFunction) -> Result<(), GpioError>;

    /// Set the pin's direction (input or output).
    fn set_direction(&mut self, pin: u8, dir: PinDirection) -> Result<(), GpioError>;

    /// Configure the internal pull resistor.
    fn set_pull(&mut self, pin: u8, pull: Pull) -> Result<(), GpioError>;

    /// Read the current logic level of the pin.
    fn read_pin(&self, pin: u8) -> Result<bool, GpioError>;

    /// Set the output value of the pin.
    fn write_pin(&mut self, pin: u8, value: bool) -> Result<(), GpioError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpio_error_is_eq() {
        assert_eq!(GpioError::InvalidPin, GpioError::InvalidPin);
    }

    #[test]
    fn pin_function_variants_exist() {
        let funcs = [
            PinFunction::Input, PinFunction::Output,
            PinFunction::Alt0, PinFunction::Alt1,
            PinFunction::Alt2, PinFunction::Alt3,
            PinFunction::Alt4, PinFunction::Alt5,
        ];
        assert_eq!(funcs.len(), 8);
    }
}
```

### Step 2: Register the module

Add `pub mod gpio;` to `crates/harmony-unikernel/src/drivers/mod.rs` after the `pub mod pl011;` line.

### Step 3: Run tests

Run: `cargo test -p harmony-unikernel -- gpio`
Expected: PASS (2 tests)

### Step 4: Commit

```
feat(unikernel): add GpioController trait and GPIO types
```

---

## Task 2: GPIO Driver — Rp1Gpio Implementation

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/gpio.rs`

### RP1 Register Constants

```rust
// ── RP1 Register offsets ────────────────────────────────────────

// IO bank: per-pin function select and status
const IO_STATUS_OFFSET: usize = 0x00; // pin * 8 + 0x00
const IO_CTRL_OFFSET: usize = 0x04;   // pin * 8 + 0x04
const IO_PIN_STRIDE: usize = 8;

// CTRL register fields
const CTRL_FUNCSEL_MASK: u32 = 0x1F;    // bits 4:0
const CTRL_FUNCSEL_SHIFT: u32 = 0;

// Funcsel values (RP1-specific)
const FUNCSEL_GPIO: u32 = 5;  // SYS_RIO (direct GPIO control)
const FUNCSEL_ALT0: u32 = 0;
const FUNCSEL_ALT1: u32 = 1;
const FUNCSEL_ALT2: u32 = 2;
const FUNCSEL_ALT3: u32 = 3;
const FUNCSEL_ALT4: u32 = 4;
const FUNCSEL_NULL: u32 = 0x1F; // disabled

// Pads bank: per-pin electrical configuration
const PADS_PIN_OFFSET: usize = 0x04; // pin * 4 + 0x04 (pad 0 is at 0x04)
const PADS_PIN_STRIDE: usize = 4;

// Pad register fields
const PAD_PULL_UP: u32 = 1 << 3;
const PAD_PULL_DOWN: u32 = 1 << 2;
const PAD_PULL_MASK: u32 = PAD_PULL_UP | PAD_PULL_DOWN;

// RIO bank: registered I/O (bit-per-pin)
const RIO_OUT: usize = 0x00;
const RIO_OE: usize = 0x04;
const RIO_IN: usize = 0x08;

// Atomic set/clear offsets (added to base register offset)
const RIO_SET: usize = 0x2000;
const RIO_CLR: usize = 0x3000;
```

### Step 1: Write failing tests for Rp1Gpio

Add tests for each GpioController method. Tests use three separate `MockRegisterBank` instances.

```rust
// ── Rp1Gpio ─────────────────────────────────────────────────────

/// RP1 GPIO controller for Raspberry Pi 5.
///
/// Operates on GPIO bank 0 (pins 0-27, exposed on the 40-pin header).
/// Requires three [`RegisterBank`] instances: one each for the IO,
/// pads, and RIO register blocks.
pub struct Rp1Gpio<IO: RegisterBank, PADS: RegisterBank, RIO: RegisterBank> {
    io: IO,
    pads: PADS,
    rio: RIO,
}

const RP1_BANK0_NUM_PINS: u8 = 28;

impl<IO: RegisterBank, PADS: RegisterBank, RIO: RegisterBank> Rp1Gpio<IO, PADS, RIO> {
    /// Create a new RP1 GPIO controller for bank 0.
    pub fn new(io: IO, pads: PADS, rio: RIO) -> Self {
        Self { io, pads, rio }
    }

    fn check_pin(pin: u8) -> Result<(), GpioError> {
        if pin >= RP1_BANK0_NUM_PINS {
            Err(GpioError::InvalidPin)
        } else {
            Ok(())
        }
    }
}
```

Tests (add to `mod tests`):

```rust
use crate::drivers::register_bank::mock::MockRegisterBank;

fn test_gpio() -> Rp1Gpio<MockRegisterBank, MockRegisterBank, MockRegisterBank> {
    Rp1Gpio::new(
        MockRegisterBank::new(),
        MockRegisterBank::new(),
        MockRegisterBank::new(),
    )
}

#[test]
fn invalid_pin_rejected() {
    let mut gpio = test_gpio();
    assert_eq!(gpio.set_function(28, PinFunction::Input), Err(GpioError::InvalidPin));
    assert_eq!(gpio.set_direction(28, PinDirection::Output), Err(GpioError::InvalidPin));
    assert_eq!(gpio.set_pull(28, Pull::Up), Err(GpioError::InvalidPin));
    assert_eq!(gpio.read_pin(28), Err(GpioError::InvalidPin));
    assert_eq!(gpio.write_pin(28, true), Err(GpioError::InvalidPin));
}

#[test]
fn set_function_output_writes_funcsel_gpio() {
    let mut gpio = test_gpio();
    gpio.set_function(14, PinFunction::Output).unwrap();
    // Pin 14 CTRL register at offset 14 * 8 + 0x04 = 0x74
    let ctrl_writes: Vec<(usize, u32)> = gpio.io.writes
        .iter().filter(|(off, _)| *off == 0x74).copied().collect();
    assert!(!ctrl_writes.is_empty());
    // Should write FUNCSEL_GPIO (5) to bits 4:0
    let (_, val) = ctrl_writes.last().unwrap();
    assert_eq!(val & CTRL_FUNCSEL_MASK, FUNCSEL_GPIO);
}

#[test]
fn set_function_alt0_writes_funcsel() {
    let mut gpio = test_gpio();
    gpio.set_function(2, PinFunction::Alt0).unwrap();
    // Pin 2 CTRL at offset 2 * 8 + 0x04 = 0x14
    let (_, val) = gpio.io.writes.iter()
        .filter(|(off, _)| *off == 0x14).last().unwrap();
    assert_eq!(val & CTRL_FUNCSEL_MASK, FUNCSEL_ALT0);
}

#[test]
fn set_direction_output_sets_oe_bit() {
    let mut gpio = test_gpio();
    gpio.set_direction(5, PinDirection::Output).unwrap();
    // Should write to RIO_OE + RIO_SET (0x04 + 0x2000 = 0x2004)
    let set_writes: Vec<(usize, u32)> = gpio.rio.writes
        .iter().filter(|(off, _)| *off == RIO_OE + RIO_SET).copied().collect();
    assert!(!set_writes.is_empty());
    assert_eq!(set_writes[0].1, 1 << 5); // bit 5
}

#[test]
fn set_direction_input_clears_oe_bit() {
    let mut gpio = test_gpio();
    gpio.set_direction(5, PinDirection::Input).unwrap();
    // Should write to RIO_OE + RIO_CLR (0x04 + 0x3000 = 0x3004)
    let clr_writes: Vec<(usize, u32)> = gpio.rio.writes
        .iter().filter(|(off, _)| *off == RIO_OE + RIO_CLR).copied().collect();
    assert!(!clr_writes.is_empty());
    assert_eq!(clr_writes[0].1, 1 << 5);
}

#[test]
fn write_pin_high_sets_out_bit() {
    let mut gpio = test_gpio();
    gpio.write_pin(3, true).unwrap();
    // RIO_OUT + RIO_SET = 0x00 + 0x2000
    let set_writes: Vec<(usize, u32)> = gpio.rio.writes
        .iter().filter(|(off, _)| *off == RIO_OUT + RIO_SET).copied().collect();
    assert_eq!(set_writes[0].1, 1 << 3);
}

#[test]
fn write_pin_low_clears_out_bit() {
    let mut gpio = test_gpio();
    gpio.write_pin(3, false).unwrap();
    // RIO_OUT + RIO_CLR = 0x00 + 0x3000
    let clr_writes: Vec<(usize, u32)> = gpio.rio.writes
        .iter().filter(|(off, _)| *off == RIO_OUT + RIO_CLR).copied().collect();
    assert_eq!(clr_writes[0].1, 1 << 3);
}

#[test]
fn read_pin_returns_bit_value() {
    let mut gpio = test_gpio();
    // RIO_IN at offset 0x08 — set bit 7
    gpio.rio.on_read(RIO_IN, vec![1 << 7]);
    assert_eq!(gpio.read_pin(7), Ok(true));

    let mut gpio2 = test_gpio();
    gpio2.rio.on_read(RIO_IN, vec![0]);
    assert_eq!(gpio2.read_pin(7), Ok(false));
}

#[test]
fn set_pull_up_writes_pad_register() {
    let mut gpio = test_gpio();
    // Pre-load current pad value (need to read-modify-write)
    gpio.pads.on_read(PADS_PIN_OFFSET + 10 * PADS_PIN_STRIDE, vec![0]);
    gpio.set_pull(10, Pull::Up).unwrap();
    // Pad for pin 10 at 0x04 + 10*4 = 0x2C
    let (_, val) = gpio.pads.writes.iter()
        .filter(|(off, _)| *off == 0x2C).last().unwrap();
    assert_eq!(val & PAD_PULL_MASK, PAD_PULL_UP);
}

#[test]
fn set_pull_down_writes_pad_register() {
    let mut gpio = test_gpio();
    gpio.pads.on_read(PADS_PIN_OFFSET + 10 * PADS_PIN_STRIDE, vec![0]);
    gpio.set_pull(10, Pull::Down).unwrap();
    let (_, val) = gpio.pads.writes.iter()
        .filter(|(off, _)| *off == 0x2C).last().unwrap();
    assert_eq!(val & PAD_PULL_MASK, PAD_PULL_DOWN);
}

#[test]
fn set_pull_none_clears_both_pull_bits() {
    let mut gpio = test_gpio();
    gpio.pads.on_read(PADS_PIN_OFFSET + 10 * PADS_PIN_STRIDE, vec![PAD_PULL_UP]);
    gpio.set_pull(10, Pull::None).unwrap();
    let (_, val) = gpio.pads.writes.iter()
        .filter(|(off, _)| *off == 0x2C).last().unwrap();
    assert_eq!(val & PAD_PULL_MASK, 0);
}
```

### Step 2: Implement GpioController for Rp1Gpio

```rust
impl<IO: RegisterBank, PADS: RegisterBank, RIO: RegisterBank> GpioController
    for Rp1Gpio<IO, PADS, RIO>
{
    fn set_function(&mut self, pin: u8, func: PinFunction) -> Result<(), GpioError> {
        Self::check_pin(pin)?;
        let funcsel = match func {
            PinFunction::Input | PinFunction::Output => FUNCSEL_GPIO,
            PinFunction::Alt0 => FUNCSEL_ALT0,
            PinFunction::Alt1 => FUNCSEL_ALT1,
            PinFunction::Alt2 => FUNCSEL_ALT2,
            PinFunction::Alt3 => FUNCSEL_ALT3,
            PinFunction::Alt4 => FUNCSEL_ALT4,
            PinFunction::Alt5 => FUNCSEL_NULL, // alt5 = disabled on RP1
        };
        let ctrl_offset = pin as usize * IO_PIN_STRIDE + IO_CTRL_OFFSET;
        let current = self.io.read(ctrl_offset);
        let new_val = (current & !CTRL_FUNCSEL_MASK) | (funcsel << CTRL_FUNCSEL_SHIFT);
        self.io.write(ctrl_offset, new_val);
        Ok(())
    }

    fn set_direction(&mut self, pin: u8, dir: PinDirection) -> Result<(), GpioError> {
        Self::check_pin(pin)?;
        let bit = 1u32 << pin;
        match dir {
            PinDirection::Output => self.rio.write(RIO_OE + RIO_SET, bit),
            PinDirection::Input => self.rio.write(RIO_OE + RIO_CLR, bit),
        }
        Ok(())
    }

    fn set_pull(&mut self, pin: u8, pull: Pull) -> Result<(), GpioError> {
        Self::check_pin(pin)?;
        let pad_offset = PADS_PIN_OFFSET + pin as usize * PADS_PIN_STRIDE;
        let current = self.pads.read(pad_offset);
        let new_val = match pull {
            Pull::None => current & !PAD_PULL_MASK,
            Pull::Up => (current & !PAD_PULL_MASK) | PAD_PULL_UP,
            Pull::Down => (current & !PAD_PULL_MASK) | PAD_PULL_DOWN,
        };
        self.pads.write(pad_offset, new_val);
        Ok(())
    }

    fn read_pin(&self, pin: u8) -> Result<bool, GpioError> {
        Self::check_pin(pin)?;
        let val = self.rio.read(RIO_IN);
        Ok((val >> pin) & 1 != 0)
    }

    fn write_pin(&mut self, pin: u8, value: bool) -> Result<(), GpioError> {
        Self::check_pin(pin)?;
        let bit = 1u32 << pin;
        if value {
            self.rio.write(RIO_OUT + RIO_SET, bit);
        } else {
            self.rio.write(RIO_OUT + RIO_CLR, bit);
        }
        Ok(())
    }
}
```

### Step 3: Run tests

Run: `cargo test -p harmony-unikernel -- gpio`
Expected: PASS (all GPIO tests)

### Step 4: Run clippy

Run: `cargo clippy --workspace`
Expected: no warnings

### Step 5: Commit

```
feat(unikernel): add Rp1Gpio — RP1 GPIO driver with GpioController trait
```

---

## Task 3: GpioServer — 9P FileServer for GPIO

**Files:**
- Create: `crates/harmony-microkernel/src/gpio_server.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs:23` (add `pub mod gpio_server;`)

### Step 1: Write GpioServer with tests

Follow the same pattern as `uart_server.rs`. Walk to pin number as filename. Read returns `"0\n"` or `"1\n"`. Write accepts value or configuration strings.

The server is generic over `GpioController`:

```rust
pub struct GpioServer<G: GpioController> {
    gpio: G,
    fids: BTreeMap<Fid, FidState>,
}
```

**QPath scheme:** `QPATH_ROOT = 0`, pins are `1 + pin_number` (so pin 0 = qpath 1, pin 27 = qpath 28).

**Key tests to include:**

```rust
// Walk tests
fn walk_to_pin_14()           // walk(0, 1, "14") -> Ok(15)
fn walk_to_pin_0()            // walk(0, 1, "0") -> Ok(1)
fn walk_to_pin_27()           // walk(0, 1, "27") -> Ok(28)
fn walk_invalid_pin_28()      // walk(0, 1, "28") -> Err(NotFound)
fn walk_non_numeric()         // walk(0, 1, "foo") -> Err(NotFound)
fn walk_from_non_root()       // walk from pin fid -> Err(NotDirectory)

// Read tests (uses a mock GpioController)
fn read_returns_one()         // gpio.read_pin returns true -> "1\n"
fn read_returns_zero()        // gpio.read_pin returns false -> "0\n"
fn read_denied_in_write_mode()

// Write tests
fn write_sets_output_high()   // write "1" -> gpio.write_pin(pin, true)
fn write_sets_output_low()    // write "0" -> gpio.write_pin(pin, false)
fn write_configures_input()   // write "in" -> gpio.set_function(Input) + set_direction(Input)
fn write_configures_output()  // write "out" -> gpio.set_function(Output) + set_direction(Output)
fn write_configures_alt0()    // write "alt0" -> gpio.set_function(Alt0)
fn write_configures_pull_up() // write "pull_up" -> gpio.set_pull(Up)
fn write_invalid_command()    // write "bogus" -> Err(InvalidArgument)
fn write_denied_in_read_mode()

// Stat/clunk/clone
fn stat_root()                // name "/", Directory
fn stat_pin()                 // name "14", Regular, size 0
fn clunk_root_rejected()
fn clunk_releases_fid()
fn clone_fid_duplicates()
```

For testing the server, create a `MockGpio` that implements `GpioController` and records calls:

```rust
#[cfg(test)]
struct MockGpio {
    pins: [bool; 28],
    last_function: Option<(u8, PinFunction)>,
    last_direction: Option<(u8, PinDirection)>,
    last_pull: Option<(u8, Pull)>,
    last_write: Option<(u8, bool)>,
}
```

### Step 2: Register the module

Add `pub mod gpio_server;` to `crates/harmony-microkernel/src/lib.rs`.

### Step 3: Run tests

Run: `cargo test -p harmony-microkernel -- gpio_server`
Expected: PASS (all GpioServer tests)

### Step 4: Run clippy + full test suite

Run: `cargo clippy --workspace && cargo test --workspace`
Expected: clean clippy, all tests pass

### Step 5: Commit

```
feat(microkernel): add GpioServer — 9P FileServer for GPIO pins
```

---

## Task 4: SD Driver — Types and SdhciDriver

**Files:**
- Create: `crates/harmony-unikernel/src/drivers/sdhci.rs`
- Modify: `crates/harmony-unikernel/src/drivers/mod.rs` (add `pub mod sdhci;`)

### SDHCI Register Constants

```rust
// ── SDHCI register offsets ──────────────────────────────────────
const SDHCI_DMA_ADDR: usize = 0x00;
const SDHCI_BLOCK_SIZE: usize = 0x04;
const SDHCI_BLOCK_COUNT: usize = 0x06;
const SDHCI_ARGUMENT: usize = 0x08;
const SDHCI_TRANSFER_MODE: usize = 0x0C;
const SDHCI_COMMAND: usize = 0x0E;
const SDHCI_RESPONSE_0: usize = 0x10;
const SDHCI_RESPONSE_1: usize = 0x14;
const SDHCI_RESPONSE_2: usize = 0x18;
const SDHCI_RESPONSE_3: usize = 0x1C;
const SDHCI_BUFFER_DATA: usize = 0x20;
const SDHCI_PRESENT_STATE: usize = 0x24;
const SDHCI_HOST_CONTROL: usize = 0x28;
const SDHCI_CLOCK_CONTROL: usize = 0x2C;
const SDHCI_TIMEOUT_CONTROL: usize = 0x2E;
const SDHCI_SOFTWARE_RESET: usize = 0x2F;
const SDHCI_INT_STATUS: usize = 0x30;
const SDHCI_INT_ENABLE: usize = 0x34;
const SDHCI_ERR_INT_STATUS: usize = 0x38;

// ── Present state bits ──────────────────────────────────────────
const STATE_CMD_INHIBIT: u32 = 1 << 0;
const STATE_DATA_INHIBIT: u32 = 1 << 1;
const STATE_BUFFER_READ_READY: u32 = 1 << 11;
const STATE_BUFFER_WRITE_READY: u32 = 1 << 10;
const STATE_CARD_INSERTED: u32 = 1 << 16;

// ── Interrupt status bits ───────────────────────────────────────
const INT_CMD_COMPLETE: u32 = 1 << 0;
const INT_TRANSFER_COMPLETE: u32 = 1 << 1;
const INT_BUFFER_READ_READY: u32 = 1 << 5;
const INT_BUFFER_WRITE_READY: u32 = 1 << 4;
const INT_ERROR: u32 = 1 << 15;

// ── Error interrupt bits ────────────────────────────────────────
const ERR_CMD_TIMEOUT: u32 = 1 << 0;
const ERR_CMD_CRC: u32 = 1 << 1;
const ERR_CMD_INDEX: u32 = 1 << 3;
const ERR_DATA_TIMEOUT: u32 = 1 << 4;
const ERR_DATA_CRC: u32 = 1 << 5;

// ── Clock control bits ──────────────────────────────────────────
const CLOCK_INTERNAL_EN: u32 = 1 << 0;
const CLOCK_INTERNAL_STABLE: u32 = 1 << 1;
const CLOCK_SD_EN: u32 = 1 << 2;
const CLOCK_DIVIDER_SHIFT: u32 = 8;

// ── Software reset bits ─────────────────────────────────────────
const RESET_ALL: u32 = 1 << 0;
const RESET_CMD: u32 = 1 << 1;
const RESET_DATA: u32 = 1 << 2;

// ── Command register encoding ───────────────────────────────────
const CMD_INDEX_SHIFT: u32 = 8;
const CMD_RESP_NONE: u32 = 0x00;
const CMD_RESP_136: u32 = 0x01;  // R2
const CMD_RESP_48: u32 = 0x02;   // R1, R3, R6, R7
const CMD_RESP_48_BUSY: u32 = 0x03; // R1b
const CMD_CRC_CHECK: u32 = 1 << 3;
const CMD_INDEX_CHECK: u32 = 1 << 4;
const CMD_DATA_PRESENT: u32 = 1 << 5;

// ── Transfer mode bits ──────────────────────────────────────────
const XFER_READ: u32 = 1 << 4;
const XFER_MULTI_BLOCK: u32 = 1 << 5;
const XFER_BLOCK_COUNT_EN: u32 = 1 << 1;

// ── SD command numbers ──────────────────────────────────────────
const CMD0_GO_IDLE: u8 = 0;
const CMD2_ALL_SEND_CID: u8 = 2;
const CMD3_SEND_RCA: u8 = 3;
const CMD7_SELECT_CARD: u8 = 7;
const CMD8_SEND_IF_COND: u8 = 8;
const CMD16_SET_BLOCKLEN: u8 = 16;
const CMD17_READ_SINGLE: u8 = 17;
const CMD18_READ_MULTI: u8 = 18;
const CMD24_WRITE_SINGLE: u8 = 24;
const CMD25_WRITE_MULTI: u8 = 25;
const CMD55_APP_CMD: u8 = 55;
const ACMD41_SD_SEND_OP_COND: u8 = 41;

const SD_BLOCK_SIZE: usize = 512;
```

### Step 1: Write types and basic driver structure

```rust
/// Errors returned by SD/eMMC operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdError {
    /// Card not inserted or not detected.
    NoCard,
    /// Command timed out.
    Timeout,
    /// CRC check failed.
    CrcError,
    /// Command index mismatch.
    IndexError,
    /// Data transfer error.
    DataError,
    /// Controller is busy (command or data inhibit set).
    Busy,
    /// Software reset did not complete.
    ResetFailed,
    /// Clock did not stabilize.
    ClockUnstable,
    /// Card initialization failed (ACMD41 never ready).
    InitFailed,
}

/// Response from an SD command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    None,
    Short(u32),
    Long([u32; 4]),
}

/// Card state after initialization.
#[derive(Debug, Clone, Copy)]
pub struct CardInfo {
    /// Relative Card Address (from CMD3).
    pub rca: u16,
    /// Card capacity in blocks (512 bytes each).
    pub capacity_blocks: u32,
}

/// Sans-I/O SDHCI driver.
///
/// All operations take a `&mut impl RegisterBank` for register access.
/// No internal state beyond the card info learned during init.
pub struct SdhciDriver {
    card: Option<CardInfo>,
}
```

### Step 2: Implement core methods with tests

Implement in this order, TDD for each:

**2a. `reset` — software reset**

Test:
```rust
#[test]
fn reset_writes_reset_all_and_polls() {
    let mut driver = SdhciDriver::new();
    let mut bank = MockRegisterBank::new();
    // First read: RESET_ALL still set, second read: cleared
    bank.on_read(SDHCI_SOFTWARE_RESET, vec![RESET_ALL, 0]);
    driver.reset(&mut bank).unwrap();
    assert!(bank.writes.contains(&(SDHCI_SOFTWARE_RESET, RESET_ALL)));
}
```

**2b. `set_clock` — clock configuration**

Test:
```rust
#[test]
fn set_clock_enables_internal_then_sd_clock() {
    let mut driver = SdhciDriver::new();
    let mut bank = MockRegisterBank::new();
    // Clock stable on first poll
    bank.on_read(SDHCI_CLOCK_CONTROL, vec![CLOCK_INTERNAL_STABLE]);
    driver.set_clock(&mut bank, 400).unwrap(); // 400 kHz for init
    // Should write: internal enable, then (after stable) SD enable
    let clock_writes: Vec<u32> = bank.writes.iter()
        .filter(|(off, _)| *off == SDHCI_CLOCK_CONTROL)
        .map(|(_, v)| *v).collect();
    assert!(clock_writes.len() >= 2);
}
```

**2c. `send_command` — command issue and response**

Test:
```rust
#[test]
fn send_command_writes_arg_and_cmd() {
    let mut driver = SdhciDriver::new();
    let mut bank = MockRegisterBank::new();
    // Not inhibited
    bank.on_read(SDHCI_PRESENT_STATE, vec![0]);
    // Command completes
    bank.on_read(SDHCI_INT_STATUS, vec![INT_CMD_COMPLETE]);
    // Response
    bank.on_read(SDHCI_RESPONSE_0, vec![0x1234]);

    let resp = driver.send_command(&mut bank, CMD8_SEND_IF_COND,
        0x1AA, CMD_RESP_48 | CMD_CRC_CHECK | CMD_INDEX_CHECK).unwrap();
    assert_eq!(resp, Response::Short(0x1234));
    assert!(bank.writes.contains(&(SDHCI_ARGUMENT, 0x1AA)));
}

#[test]
fn send_command_returns_timeout_on_error() {
    let mut driver = SdhciDriver::new();
    let mut bank = MockRegisterBank::new();
    bank.on_read(SDHCI_PRESENT_STATE, vec![0]);
    bank.on_read(SDHCI_INT_STATUS, vec![INT_ERROR]);
    bank.on_read(SDHCI_ERR_INT_STATUS, vec![ERR_CMD_TIMEOUT]);

    let result = driver.send_command(&mut bank, CMD0_GO_IDLE, 0, CMD_RESP_NONE);
    assert_eq!(result, Err(SdError::Timeout));
}
```

**2d. `read_block` / `write_block` — PIO data transfer**

Test:
```rust
#[test]
fn read_block_reads_512_bytes_from_data_port() {
    let mut driver = SdhciDriver::new();
    let mut bank = MockRegisterBank::new();
    // Buffer read ready
    bank.on_read(SDHCI_INT_STATUS, vec![INT_BUFFER_READ_READY]);
    // 128 reads of 4 bytes each = 512 bytes
    let mut data_values = Vec::new();
    for i in 0..128u32 {
        data_values.push(i);
    }
    bank.on_read(SDHCI_BUFFER_DATA, data_values);

    let mut buf = [0u8; 512];
    driver.read_block(&mut bank, &mut buf).unwrap();
    // First 4 bytes should be u32 value 0 in little-endian
    assert_eq!(buf[0..4], [0, 0, 0, 0]);
    // Bytes 4-7 should be u32 value 1
    assert_eq!(buf[4..8], [1, 0, 0, 0]);
}
```

### Step 3: Implement card initialization state machine

```rust
/// Initialize the SD card.
///
/// Performs the standard SD card init sequence:
/// CMD0 → CMD8 → ACMD41 loop → CMD2 → CMD3 → CMD7 → CMD16
pub fn init_card(&mut self, bank: &mut impl RegisterBank) -> Result<CardInfo, SdError> {
    // ... implementation
}
```

Test:
```rust
#[test]
fn init_card_sends_correct_command_sequence() {
    // Set up MockRegisterBank with responses for the full init sequence
    // Verify CMD0, CMD8, CMD55+ACMD41 (with retry), CMD2, CMD3, CMD7, CMD16
    // are sent in order with correct arguments
}
```

### Step 4: Register the module, run tests, commit

Add `pub mod sdhci;` to `crates/harmony-unikernel/src/drivers/mod.rs`.

Run: `cargo test -p harmony-unikernel -- sdhci`
Expected: PASS

```
feat(unikernel): add SdhciDriver — sans-I/O SD card driver with PIO
```

---

## Task 5: SdServer — 9P FileServer for SD Card

**Files:**
- Create: `crates/harmony-microkernel/src/sd_server.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs` (add `pub mod sd_server;`)

### Step 1: Write SdServer with tests

Similar structure to UartServer but with block semantics:

```rust
pub struct SdServer<B: RegisterBank> {
    driver: SdhciDriver,
    bank: B,
    fids: BTreeMap<Fid, FidState>,
}
```

**Key differences from UartServer:**
- Offset is honored (block device, not stream)
- Read/write must be 512-byte aligned, else `InvalidArgument`
- `stat` returns card capacity in `size` field

**Tests:**

```rust
fn walk_to_sd0()
fn walk_invalid_name()
fn read_block_at_offset_zero()     // read(fid, 0, 512) -> first block
fn read_block_at_offset_512()      // read(fid, 512, 512) -> second block
fn read_unaligned_offset_rejected() // read(fid, 100, 512) -> Err(InvalidArgument)
fn write_block_at_offset_zero()
fn write_unaligned_rejected()
fn stat_returns_capacity()         // size = capacity_blocks * 512
fn write_denied_in_read_mode()
fn read_denied_in_write_mode()
fn clunk_root_rejected()
fn clone_fid_duplicates()
```

### Step 2: Register module, run full suite

Add `pub mod sd_server;` to lib.rs.

Run: `cargo clippy --workspace && cargo test --workspace`
Expected: clean clippy, all tests pass

### Step 3: Commit

```
feat(microkernel): add SdServer — 9P FileServer for SD block device
```

---

## Task 6: Final Verification

### Step 1: Run full quality gates

```bash
cargo fmt --all -- --check
cargo clippy --workspace
cargo test --workspace
```

### Step 2: Verify test count increased

Count new tests added across all tasks. Expected: ~30+ new tests.

### Step 3: Final commit if any cleanup needed

---

## Summary

| Task | What | Crate | Tests |
|------|------|-------|-------|
| 1 | GpioController trait + types | harmony-unikernel | ~2 |
| 2 | Rp1Gpio implementation | harmony-unikernel | ~11 |
| 3 | GpioServer (9P) | harmony-microkernel | ~15 |
| 4 | SdhciDriver + card init | harmony-unikernel | ~6 |
| 5 | SdServer (9P) | harmony-microkernel | ~11 |
| 6 | Final verification | all | — |
