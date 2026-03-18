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
    /// Requested function is not available on this controller.
    UnsupportedFunction,
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

// ── RP1 Register offsets ────────────────────────────────────────

// IO bank: per-pin function select and status
const IO_CTRL_OFFSET: usize = 0x04; // pin * 8 + 0x04
const IO_PIN_STRIDE: usize = 8;

// CTRL register fields
const CTRL_FUNCSEL_MASK: u32 = 0x1F; // bits 4:0
const CTRL_FUNCSEL_SHIFT: u32 = 0;

// Funcsel values (RP1-specific)
const FUNCSEL_GPIO: u32 = 5; // SYS_RIO (direct GPIO control)
const FUNCSEL_ALT0: u32 = 0;
const FUNCSEL_ALT1: u32 = 1;
const FUNCSEL_ALT2: u32 = 2;
const FUNCSEL_ALT3: u32 = 3;
const FUNCSEL_ALT4: u32 = 4;

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

// ── Rp1Gpio struct ──────────────────────────────────────────────

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

// ── GpioController implementation for Rp1Gpio ───────────────────

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
            PinFunction::Alt5 => return Err(GpioError::UnsupportedFunction), // no Alt5 on RP1 bank 0
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::register_bank::mock::MockRegisterBank;

    #[test]
    fn gpio_error_is_eq() {
        assert_eq!(GpioError::InvalidPin, GpioError::InvalidPin);
    }

    #[test]
    fn pin_function_variants_exist() {
        let funcs = [
            PinFunction::Input,
            PinFunction::Output,
            PinFunction::Alt0,
            PinFunction::Alt1,
            PinFunction::Alt2,
            PinFunction::Alt3,
            PinFunction::Alt4,
            PinFunction::Alt5,
        ];
        assert_eq!(funcs.len(), 8);
    }

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
        assert_eq!(
            gpio.set_function(28, PinFunction::Input),
            Err(GpioError::InvalidPin)
        );
        assert_eq!(
            gpio.set_direction(28, PinDirection::Output),
            Err(GpioError::InvalidPin)
        );
        assert_eq!(gpio.set_pull(28, Pull::Up), Err(GpioError::InvalidPin));
        assert_eq!(gpio.read_pin(28), Err(GpioError::InvalidPin));
        assert_eq!(gpio.write_pin(28, true), Err(GpioError::InvalidPin));
    }

    #[test]
    fn set_function_alt5_unsupported() {
        let mut gpio = test_gpio();
        assert_eq!(
            gpio.set_function(14, PinFunction::Alt5),
            Err(GpioError::UnsupportedFunction)
        );
    }

    #[test]
    fn set_function_output_writes_funcsel_gpio() {
        let mut gpio = test_gpio();
        gpio.set_function(14, PinFunction::Output).unwrap();
        // Pin 14 CTRL register at offset 14 * 8 + 0x04 = 0x74
        let ctrl_writes: Vec<(usize, u32)> = gpio
            .io
            .writes
            .iter()
            .filter(|(off, _)| *off == 0x74)
            .copied()
            .collect();
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
        let (_, val) = gpio
            .io
            .writes
            .iter()
            .filter(|(off, _)| *off == 0x14)
            .last()
            .unwrap();
        assert_eq!(val & CTRL_FUNCSEL_MASK, FUNCSEL_ALT0);
    }

    #[test]
    fn set_direction_output_sets_oe_bit() {
        let mut gpio = test_gpio();
        gpio.set_direction(5, PinDirection::Output).unwrap();
        // Should write to RIO_OE + RIO_SET (0x04 + 0x2000 = 0x2004)
        let set_writes: Vec<(usize, u32)> = gpio
            .rio
            .writes
            .iter()
            .filter(|(off, _)| *off == RIO_OE + RIO_SET)
            .copied()
            .collect();
        assert!(!set_writes.is_empty());
        assert_eq!(set_writes[0].1, 1 << 5); // bit 5
    }

    #[test]
    fn set_direction_input_clears_oe_bit() {
        let mut gpio = test_gpio();
        gpio.set_direction(5, PinDirection::Input).unwrap();
        // Should write to RIO_OE + RIO_CLR (0x04 + 0x3000 = 0x3004)
        let clr_writes: Vec<(usize, u32)> = gpio
            .rio
            .writes
            .iter()
            .filter(|(off, _)| *off == RIO_OE + RIO_CLR)
            .copied()
            .collect();
        assert!(!clr_writes.is_empty());
        assert_eq!(clr_writes[0].1, 1 << 5);
    }

    #[test]
    fn write_pin_high_sets_out_bit() {
        let mut gpio = test_gpio();
        gpio.write_pin(3, true).unwrap();
        // RIO_OUT + RIO_SET = 0x00 + 0x2000
        let set_writes: Vec<(usize, u32)> = gpio
            .rio
            .writes
            .iter()
            .filter(|(off, _)| *off == RIO_OUT + RIO_SET)
            .copied()
            .collect();
        assert_eq!(set_writes[0].1, 1 << 3);
    }

    #[test]
    fn write_pin_low_clears_out_bit() {
        let mut gpio = test_gpio();
        gpio.write_pin(3, false).unwrap();
        // RIO_OUT + RIO_CLR = 0x00 + 0x3000
        let clr_writes: Vec<(usize, u32)> = gpio
            .rio
            .writes
            .iter()
            .filter(|(off, _)| *off == RIO_OUT + RIO_CLR)
            .copied()
            .collect();
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
        gpio.pads
            .on_read(PADS_PIN_OFFSET + 10 * PADS_PIN_STRIDE, vec![0]);
        gpio.set_pull(10, Pull::Up).unwrap();
        // Pad for pin 10 at 0x04 + 10*4 = 0x2C
        let (_, val) = gpio
            .pads
            .writes
            .iter()
            .filter(|(off, _)| *off == 0x2C)
            .last()
            .unwrap();
        assert_eq!(val & PAD_PULL_MASK, PAD_PULL_UP);
    }

    #[test]
    fn set_pull_down_writes_pad_register() {
        let mut gpio = test_gpio();
        gpio.pads
            .on_read(PADS_PIN_OFFSET + 10 * PADS_PIN_STRIDE, vec![0]);
        gpio.set_pull(10, Pull::Down).unwrap();
        let (_, val) = gpio
            .pads
            .writes
            .iter()
            .filter(|(off, _)| *off == 0x2C)
            .next_back()
            .unwrap();
        assert_eq!(val & PAD_PULL_MASK, PAD_PULL_DOWN);
    }

    #[test]
    fn set_pull_none_clears_both_pull_bits() {
        let mut gpio = test_gpio();
        gpio.pads
            .on_read(PADS_PIN_OFFSET + 10 * PADS_PIN_STRIDE, vec![PAD_PULL_UP]);
        gpio.set_pull(10, Pull::None).unwrap();
        let (_, val) = gpio
            .pads
            .writes
            .iter()
            .filter(|(off, _)| *off == 0x2C)
            .next_back()
            .unwrap();
        assert_eq!(val & PAD_PULL_MASK, 0);
    }
}
