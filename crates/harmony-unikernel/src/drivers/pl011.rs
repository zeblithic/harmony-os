// SPDX-License-Identifier: GPL-2.0-or-later

//! Sans-I/O PL011 UART driver.
//!
//! Uses the [`RegisterBank`] trait for all register access, enabling
//! full unit testing without hardware.

use super::register_bank::RegisterBank;

// ── Register offsets ──────────────────────────────────────────────
#[allow(dead_code)]
const UARTDR: usize = 0x000;
#[allow(dead_code)]
const UARTFR: usize = 0x018;
const UARTIBRD: usize = 0x024;
const UARTFBRD: usize = 0x028;
const UARTLCR_H: usize = 0x02C;
const UARTCR: usize = 0x030;

// ── Flag register bits ──────────────────────────────────────────
#[allow(dead_code)]
const UARTFR_TXFF: u32 = 1 << 5; // TX FIFO full
#[allow(dead_code)]
const UARTFR_RXFE: u32 = 1 << 4; // RX FIFO empty

/// Compute integer and fractional baud-rate divisors for the PL011.
///
/// Formula (PL011 TRM):
///   BRD  = clock_hz / (16 * baud)
///   IBRD = integer part of BRD
///   FBRD = integer(fractional_part * 64 + 0.5)
///
/// Avoids floating-point by working in 128ths then rounding to 64ths.
pub fn baud_divisors(clock_hz: u32, baud: u32) -> (u16, u8) {
    if baud == 0 {
        return (0, 0);
    }
    let div_x128 = (clock_hz as u64 * 8) / baud as u64;
    let div_x64 = div_x128.div_ceil(2);
    let ibrd = (div_x64 / 64) as u16;
    let fbrd = (div_x64 % 64) as u8;
    (ibrd, fbrd)
}

/// Sans-I/O PL011 UART driver.
///
/// Generic over `N`: the RX ring buffer capacity in bytes.
#[allow(dead_code)]
pub struct Pl011Driver<const N: usize> {
    rx_buf: [u8; N],
    rx_head: usize,
    rx_tail: usize,
    rx_count: usize,
}

impl<const N: usize> Default for Pl011Driver<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Pl011Driver<N> {
    /// Create a new driver with an empty RX ring buffer.
    pub fn new() -> Self {
        Self {
            rx_buf: [0u8; N],
            rx_head: 0,
            rx_tail: 0,
            rx_count: 0,
        }
    }

    /// Initialise the PL011: set baud rate, 8N1, FIFO, enable TX+RX.
    pub fn init(&self, bank: &mut impl RegisterBank, clock_hz: u32, baud: u32) {
        // 1. Disable UART
        bank.write(UARTCR, 0);

        // 2. Baud-rate divisors
        let (ibrd, fbrd) = baud_divisors(clock_hz, baud);
        bank.write(UARTIBRD, ibrd as u32);
        bank.write(UARTFBRD, fbrd as u32);

        // 3. 8-bit word length (WLEN=0b11 << 5) + FIFO enable (bit 4) = 0x70
        bank.write(UARTLCR_H, 0x70);

        // 4. Enable UART (bit 0) + TX (bit 8) + RX (bit 9) = 0x301
        bank.write(UARTCR, 0x301);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::register_bank::mock::MockRegisterBank;

    #[test]
    fn init_writes_correct_registers() {
        let driver: Pl011Driver<256> = Pl011Driver::new();
        let mut bank = MockRegisterBank::new();
        driver.init(&mut bank, 24_000_000, 115_200);

        assert_eq!(
            bank.writes,
            vec![
                (UARTCR, 0),       // disable
                (UARTIBRD, 13),    // baud integer
                (UARTFBRD, 1),     // baud fractional
                (UARTLCR_H, 0x70), // 8N1 + FIFO
                (UARTCR, 0x301),   // enable TX+RX
            ]
        );
    }

    #[test]
    fn baud_115200_at_24mhz() {
        assert_eq!(baud_divisors(24_000_000, 115_200), (13, 1));
    }

    #[test]
    fn baud_9600_at_24mhz() {
        assert_eq!(baud_divisors(24_000_000, 9_600), (156, 16));
    }

    #[test]
    fn baud_zero_does_not_panic() {
        assert_eq!(baud_divisors(24_000_000, 0), (0, 0));
        assert_eq!(baud_divisors(0, 115_200), (0, 0));
    }

    #[test]
    fn baud_48mhz_rounds_correctly() {
        assert_eq!(baud_divisors(48_000_000, 115_200), (26, 3));
    }
}
