// SPDX-License-Identifier: GPL-2.0-or-later

//! Sans-I/O PL011 UART driver.
//!
//! Uses the [`RegisterBank`] trait for all register access, enabling
//! full unit testing without hardware.

use super::register_bank::RegisterBank;

// ── Register offsets ──────────────────────────────────────────────
const UARTDR: usize = 0x000;
const UARTFR: usize = 0x018;
const UARTIBRD: usize = 0x024;
const UARTFBRD: usize = 0x028;
const UARTLCR_H: usize = 0x02C;
const UARTCR: usize = 0x030;

// ── Flag register bits ──────────────────────────────────────────
const UARTFR_TXFF: u32 = 1 << 5; // TX FIFO full
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
    if baud == 0 || clock_hz == 0 {
        return (0, 0);
    }
    let div_x128 = (clock_hz as u64 * 8) / baud as u64;
    let div_x64 = div_x128.div_ceil(2);
    let ibrd = (div_x64 / 64) as u16;
    let fbrd = (div_x64 % 64) as u8;
    (ibrd, fbrd)
}

/// Error returned when [`Pl011Driver::init`] is given parameters that
/// produce an invalid baud-rate divisor (IBRD = 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidBaudRate;

/// Sans-I/O PL011 UART driver.
///
/// Generic over `N`: the RX ring buffer capacity in bytes.
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
        const { assert!(N > 0, "ring buffer size must be at least 1") };
        Self {
            rx_buf: [0u8; N],
            rx_head: 0,
            rx_tail: 0,
            rx_count: 0,
        }
    }

    /// Initialise the PL011: set baud rate, 8N1, FIFO, enable TX+RX.
    ///
    /// Returns [`InvalidBaudRate`] if the computed baud divisor is zero
    /// (e.g. when `clock_hz` or `baud` is zero), since IBRD=0 is undefined
    /// per the PL011 TRM. The UART is left disabled in this case.
    pub fn init(
        &self,
        bank: &mut impl RegisterBank,
        clock_hz: u32,
        baud: u32,
    ) -> Result<(), InvalidBaudRate> {
        // 1. Disable UART
        bank.write(UARTCR, 0);

        // 2. Baud-rate divisors
        let (ibrd, fbrd) = baud_divisors(clock_hz, baud);
        if ibrd == 0 {
            return Err(InvalidBaudRate);
        }
        bank.write(UARTIBRD, ibrd as u32);
        bank.write(UARTFBRD, fbrd as u32);

        // 3. 8-bit word length (WLEN=0b11 << 5) + FIFO enable (bit 4) = 0x70
        bank.write(UARTLCR_H, 0x70);

        // 4. Enable UART (bit 0) + TX (bit 8) + RX (bit 9) = 0x301
        bank.write(UARTCR, 0x301);
        Ok(())
    }

    /// Check whether the TX FIFO has space.
    pub fn tx_ready(&self, bank: &impl RegisterBank) -> bool {
        bank.read(UARTFR) & UARTFR_TXFF == 0
    }

    /// Transmit bytes, spinning while the TX FIFO is full.
    ///
    /// **Warning:** This method spins indefinitely if the TX FIFO never
    /// drains.  Callers in interrupt-driven contexts should use
    /// [`tx_ready`](Self::tx_ready) and write byte-by-byte instead.
    pub fn write_bytes(&self, bank: &mut impl RegisterBank, data: &[u8]) {
        for &byte in data {
            while !self.tx_ready(bank) {
                core::hint::spin_loop();
            }
            bank.write(UARTDR, byte as u32);
        }
    }

    /// Poll the RX FIFO and drain available bytes into the ring buffer.
    ///
    /// Call this periodically (e.g. in the event loop or before reads).
    /// If the ring buffer is full, incoming bytes are dropped.
    pub fn poll_rx(&mut self, bank: &impl RegisterBank) {
        while bank.read(UARTFR) & UARTFR_RXFE == 0 {
            let byte = (bank.read(UARTDR) & 0xFF) as u8;
            if self.rx_count < N {
                self.rx_buf[self.rx_head] = byte;
                self.rx_head = (self.rx_head + 1) % N;
                self.rx_count += 1;
            }
            // If full, drop the byte.
        }
    }

    /// Read buffered RX data into `buf`. Returns the number of bytes copied.
    pub fn read_buffered(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.rx_count);
        for slot in buf[..n].iter_mut() {
            *slot = self.rx_buf[self.rx_tail];
            self.rx_tail = (self.rx_tail + 1) % N;
            self.rx_count -= 1;
        }
        n
    }

    /// Number of bytes available in the RX ring buffer.
    pub fn rx_available(&self) -> usize {
        self.rx_count
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
        driver.init(&mut bank, 24_000_000, 115_200).unwrap();

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
    fn init_rejects_zero_baud() {
        let driver: Pl011Driver<256> = Pl011Driver::new();
        let mut bank = MockRegisterBank::new();
        assert_eq!(driver.init(&mut bank, 24_000_000, 0), Err(InvalidBaudRate));
        // UART should be disabled but no baud registers written.
        assert_eq!(bank.writes, vec![(UARTCR, 0)]);
    }

    #[test]
    fn init_rejects_zero_clock() {
        let driver: Pl011Driver<256> = Pl011Driver::new();
        let mut bank = MockRegisterBank::new();
        assert_eq!(driver.init(&mut bank, 0, 115_200), Err(InvalidBaudRate));
        assert_eq!(bank.writes, vec![(UARTCR, 0)]);
    }

    #[test]
    fn baud_48mhz_rounds_correctly() {
        assert_eq!(baud_divisors(48_000_000, 115_200), (26, 3));
    }

    #[test]
    fn write_bytes_sends_to_data_register() {
        let driver: Pl011Driver<256> = Pl011Driver::new();
        let mut bank = MockRegisterBank::new();
        // FR returns 0 (FIFO not full) for every read.
        bank.on_read(UARTFR, vec![0]);

        driver.write_bytes(&mut bank, b"Hi");
        // Should read FR twice (once per byte) and write DR twice.
        let data_writes: Vec<(usize, u32)> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == UARTDR)
            .copied()
            .collect();
        assert_eq!(
            data_writes,
            vec![(UARTDR, b'H' as u32), (UARTDR, b'i' as u32)]
        );
    }

    #[test]
    fn write_bytes_spins_on_txff() {
        let driver: Pl011Driver<256> = Pl011Driver::new();
        let mut bank = MockRegisterBank::new();
        // First read: TXFF set, second read: clear, third read: clear.
        bank.on_read(UARTFR, vec![UARTFR_TXFF, 0]);

        driver.write_bytes(&mut bank, b"A");
        // Should have read FR twice (spin + success) then written DR once.
        let data_writes: Vec<(usize, u32)> = bank
            .writes
            .iter()
            .filter(|(off, _)| *off == UARTDR)
            .copied()
            .collect();
        assert_eq!(data_writes, vec![(UARTDR, b'A' as u32)]);
    }

    #[test]
    fn poll_rx_drains_fifo_into_ring() {
        let mut driver: Pl011Driver<256> = Pl011Driver::new();
        let mut bank = MockRegisterBank::new();
        // FR: not empty, not empty, empty (stop)
        bank.on_read(UARTFR, vec![0, 0, UARTFR_RXFE]);
        // DR: two bytes available
        bank.on_read(UARTDR, vec![b'A' as u32, b'B' as u32]);

        driver.poll_rx(&bank);
        assert_eq!(driver.rx_available(), 2);

        let mut buf = [0u8; 4];
        let n = driver.read_buffered(&mut buf);
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], b"AB");
    }

    #[test]
    fn ring_buffer_wraps() {
        let mut driver: Pl011Driver<4> = Pl011Driver::new();
        let mut bank = MockRegisterBank::new();

        // Fill ring with 3 bytes
        bank.on_read(UARTFR, vec![0, 0, 0, UARTFR_RXFE]);
        bank.on_read(UARTDR, vec![1, 2, 3]);
        driver.poll_rx(&bank);

        // Drain 2
        let mut buf = [0u8; 2];
        driver.read_buffered(&mut buf);
        assert_eq!(buf, [1, 2]);
        assert_eq!(driver.rx_available(), 1);

        // Add 3 more (wraps around)
        let mut bank2 = MockRegisterBank::new();
        bank2.on_read(UARTFR, vec![0, 0, 0, UARTFR_RXFE]);
        bank2.on_read(UARTDR, vec![4, 5, 6]);
        driver.poll_rx(&bank2);
        assert_eq!(driver.rx_available(), 4); // full

        let mut out = [0u8; 4];
        let n = driver.read_buffered(&mut out);
        assert_eq!(n, 4);
        assert_eq!(out, [3, 4, 5, 6]);
    }

    #[test]
    fn ring_buffer_overflow_drops_bytes() {
        let mut driver: Pl011Driver<2> = Pl011Driver::new();
        let mut bank = MockRegisterBank::new();
        // 3 bytes available but ring is only 2
        bank.on_read(UARTFR, vec![0, 0, 0, UARTFR_RXFE]);
        bank.on_read(UARTDR, vec![b'X' as u32, b'Y' as u32, b'Z' as u32]);

        driver.poll_rx(&bank);
        assert_eq!(driver.rx_available(), 2);

        let mut buf = [0u8; 2];
        driver.read_buffered(&mut buf);
        assert_eq!(&buf, b"XY"); // Z was dropped
    }

    #[test]
    fn read_buffered_empty() {
        let mut driver: Pl011Driver<256> = Pl011Driver::new();
        let mut buf = [0u8; 4];
        let n = driver.read_buffered(&mut buf);
        assert_eq!(n, 0);
    }
}
