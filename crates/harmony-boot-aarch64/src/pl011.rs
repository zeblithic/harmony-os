// SPDX-License-Identifier: GPL-2.0-or-later
//! PL011 UART driver for QEMU `virt` machine (TX-only).
//!
//! The PL011 is mapped at physical address `0x0900_0000` on the QEMU aarch64
//! `virt` platform. This driver initialises the UART at 115200 baud, 8N1, with
//! FIFO enabled and provides a blocking `write_byte` function suitable for
//! early boot serial output after ExitBootServices.

// Register constants and flag bits are only referenced by the hardware access
// functions, which are gated behind `cfg(target_arch = "aarch64")`.  Suppress
// dead-code warnings on hosts where those functions are compiled out.
#![cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]

/// PL011 base address on QEMU aarch64 `virt`.
const PL011_BASE: usize = 0x0900_0000;

// ── Register offsets ──────────────────────────────────────────────────
const UARTDR: usize = 0x000; // Data register
const UARTFR: usize = 0x018; // Flag register
const UARTIBRD: usize = 0x024; // Integer baud rate divisor
const UARTFBRD: usize = 0x028; // Fractional baud rate divisor
const UARTLCR_H: usize = 0x02C; // Line control register
const UARTCR: usize = 0x030; // Control register

// ── Flag register bits ────────────────────────────────────────────────
const UARTFR_TXFF: u32 = 1 << 5; // TX FIFO full

// ── Baud-rate divisor calculation (pure math — runs on any host) ─────

/// Compute integer and fractional baud-rate divisors for the PL011.
///
/// Formula: BRD = clock_hz / (16 * baud).  IBRD = integer part.
/// FBRD = round(fractional_part * 64).
///
/// We avoid floating-point by working in fixed-point:
///   div_x64 = (clock_hz * 4) / baud
///   ibrd    = div_x64 / 64
///   fbrd    = div_x64 % 64
pub fn baud_divisors(clock_hz: u32, baud: u32) -> (u16, u8) {
    let div_x64 = (clock_hz as u64 * 4) / baud as u64;
    let ibrd = (div_x64 / 64) as u16;
    let fbrd = (div_x64 % 64) as u8;
    (ibrd, fbrd)
}

// ── Hardware access (aarch64 only) ────────────────────────────────────

#[cfg(target_arch = "aarch64")]
unsafe fn write_reg(offset: usize, val: u32) {
    let addr = (PL011_BASE + offset) as *mut u32;
    core::ptr::write_volatile(addr, val);
}

#[cfg(target_arch = "aarch64")]
unsafe fn read_reg(offset: usize) -> u32 {
    let addr = (PL011_BASE + offset) as *const u32;
    core::ptr::read_volatile(addr)
}

/// Initialise PL011 UART: 115200 baud, 8N1, FIFO enabled.
///
/// Assumes a 24 MHz reference clock (QEMU `virt` default).
///
/// # Safety
/// Must only be called after ExitBootServices on a platform with PL011
/// mapped at `PL011_BASE`.
#[cfg(target_arch = "aarch64")]
pub unsafe fn init() {
    // 1. Disable UART
    write_reg(UARTCR, 0);

    // 2. Baud-rate divisors for 115200 at 24 MHz
    let (ibrd, fbrd) = baud_divisors(24_000_000, 115_200);
    write_reg(UARTIBRD, ibrd as u32);
    write_reg(UARTFBRD, fbrd as u32);

    // 3. 8-bit word length (WLEN = 0b11 << 5) + FIFO enable (bit 4) = 0x70
    write_reg(UARTLCR_H, 0x70);

    // 4. Enable UART (bit 0) + TX enable (bit 8) + RX enable (bit 9) = 0x301
    write_reg(UARTCR, 0x301);
}

/// Transmit a single byte, spinning until the TX FIFO has space.
///
/// # Safety
/// Must only be called after [`init`] on a platform with PL011 mapped at
/// `PL011_BASE`.
#[cfg(target_arch = "aarch64")]
pub unsafe fn write_byte(byte: u8) {
    // Spin while TX FIFO is full
    while read_reg(UARTFR) & UARTFR_TXFF != 0 {}
    write_reg(UARTDR, byte as u32);
}

// ── Tests (run on host) ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baud_115200_at_24mhz() {
        assert_eq!(baud_divisors(24_000_000, 115200), (13, 1));
    }

    #[test]
    fn baud_9600_at_24mhz() {
        assert_eq!(baud_divisors(24_000_000, 9600), (156, 16));
    }

    #[test]
    fn baud_zero_clock_does_not_panic() {
        assert_eq!(baud_divisors(0, 115200), (0, 0));
    }
}
