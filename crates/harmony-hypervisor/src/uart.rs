// SPDX-License-Identifier: GPL-2.0-or-later

//! PL011 virtual UART register emulation.
//!
//! Provides a pure state-machine emulation of the ARM PrimeCell PL011 UART.
//! No I/O is performed; callers drive reads/writes via MMIO offset dispatch.

/// PL011 MMIO register offsets.
pub mod reg {
    pub const UARTDR: u16 = 0x000;
    pub const UARTFR: u16 = 0x018;
    pub const UARTIBRD: u16 = 0x024;
    pub const UARTFBRD: u16 = 0x028;
    pub const UARTLCR_H: u16 = 0x02C;
    pub const UARTCR: u16 = 0x030;
    pub const UARTIMSC: u16 = 0x038;
    pub const UARTICR: u16 = 0x044;
    pub const PERIPHID0: u16 = 0xFE0;
    pub const PERIPHID1: u16 = 0xFE4;
    pub const PERIPHID2: u16 = 0xFE8;
    pub const PERIPHID3: u16 = 0xFEC;
}

/// UARTFR value with TX FIFO empty (bit 7) and RX FIFO empty (bit 4) set.
pub const UARTFR_TXFE_RXFE: u64 = (1 << 7) | (1 << 4);

/// PL011 peripheral ID bytes (revision r1p5).
pub const PERIPHID: [u64; 4] = [0x11, 0x10, 0x34, 0x00];

/// Virtual PL011 UART register state.
///
/// Stores only the writable configuration registers. UARTFR, UARTDR (RX),
/// UARTIMSC, and the peripheral ID registers are read-only constants.
pub struct VirtualUart {
    ibrd: u16,
    fbrd: u8,
    lcr_h: u8,
    cr: u16,
}

impl Default for VirtualUart {
    fn default() -> Self {
        Self {
            ibrd: 0,
            fbrd: 0,
            lcr_h: 0,
            cr: 0x0300, // PL011 reset default: TXE | RXE enabled
        }
    }
}

impl VirtualUart {
    /// Create a new `VirtualUart` with PL011 power-on defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a register by MMIO offset.
    ///
    /// Returns `0` for unknown offsets.
    pub fn read(&self, offset: u16) -> u64 {
        match offset {
            reg::UARTDR => 0,
            reg::UARTFR => UARTFR_TXFE_RXFE,
            reg::UARTIBRD => self.ibrd as u64,
            reg::UARTFBRD => self.fbrd as u64,
            reg::UARTLCR_H => self.lcr_h as u64,
            reg::UARTCR => self.cr as u64,
            reg::UARTIMSC => 0,
            reg::PERIPHID0 => PERIPHID[0],
            reg::PERIPHID1 => PERIPHID[1],
            reg::PERIPHID2 => PERIPHID[2],
            reg::PERIPHID3 => PERIPHID[3],
            _ => 0,
        }
    }

    /// Write a register by MMIO offset.
    ///
    /// Returns `Some(ch)` when a byte is written to UARTDR (TX path).
    /// Returns `None` for all other registers (including unknown offsets).
    pub fn write(&mut self, offset: u16, value: u64) -> Option<u8> {
        match offset {
            reg::UARTDR => Some((value & 0xFF) as u8),
            reg::UARTIBRD => {
                self.ibrd = (value & 0xFFFF) as u16;
                None
            }
            reg::UARTFBRD => {
                self.fbrd = (value & 0x3F) as u8;
                None
            }
            reg::UARTLCR_H => {
                self.lcr_h = (value & 0xFF) as u8;
                None
            }
            reg::UARTCR => {
                self.cr = (value & 0xFFFF) as u16;
                None
            }
            reg::UARTIMSC | reg::UARTICR => None,
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uartdr_write_emits_character() {
        let mut uart = VirtualUart::new();
        assert_eq!(uart.write(reg::UARTDR, b'A' as u64), Some(b'A'));
        assert_eq!(uart.write(reg::UARTDR, 0x7F), Some(0x7F));
        // Only low 8 bits are returned.
        assert_eq!(uart.write(reg::UARTDR, 0x1_0041), Some(b'A'));
    }

    #[test]
    fn uartdr_read_returns_zero() {
        let uart = VirtualUart::new();
        assert_eq!(uart.read(reg::UARTDR), 0);
    }

    #[test]
    fn uartfr_returns_txfe_rxfe() {
        let uart = VirtualUart::new();
        assert_eq!(uart.read(reg::UARTFR), UARTFR_TXFE_RXFE);
        // Confirm the constant itself encodes the expected PL011 bit pattern.
        assert_eq!(
            UARTFR_TXFE_RXFE, 0x90,
            "bit 7 (TXFE) and bit 4 (RXFE) must be set"
        );
    }

    #[test]
    fn periph_id_returns_pl011_id() {
        let uart = VirtualUart::new();
        assert_eq!(uart.read(reg::PERIPHID0), PERIPHID[0]);
        assert_eq!(uart.read(reg::PERIPHID1), PERIPHID[1]);
        assert_eq!(uart.read(reg::PERIPHID2), PERIPHID[2]);
        assert_eq!(uart.read(reg::PERIPHID3), PERIPHID[3]);
        assert_eq!(uart.read(reg::PERIPHID0), 0x11);
        assert_eq!(uart.read(reg::PERIPHID1), 0x10);
        assert_eq!(uart.read(reg::PERIPHID2), 0x34);
        assert_eq!(uart.read(reg::PERIPHID3), 0x00);
    }

    #[test]
    fn baud_rate_registers_round_trip() {
        let mut uart = VirtualUart::new();
        // IBRD: 16-bit value
        assert_eq!(uart.write(reg::UARTIBRD, 0xABCD), None);
        assert_eq!(uart.read(reg::UARTIBRD), 0xABCD);
        // Truncated to 16 bits
        assert_eq!(uart.write(reg::UARTIBRD, 0x1_FFFF), None);
        assert_eq!(uart.read(reg::UARTIBRD), 0xFFFF);

        // FBRD: 6-bit value (mask 0x3F)
        assert_eq!(uart.write(reg::UARTFBRD, 0x3F), None);
        assert_eq!(uart.read(reg::UARTFBRD), 0x3F);
        // Bits above 6 are dropped
        assert_eq!(uart.write(reg::UARTFBRD, 0xFF), None);
        assert_eq!(uart.read(reg::UARTFBRD), 0x3F);
    }

    #[test]
    fn control_registers_round_trip() {
        let mut uart = VirtualUart::new();
        // LCR_H: 8-bit
        assert_eq!(uart.write(reg::UARTLCR_H, 0x70), None);
        assert_eq!(uart.read(reg::UARTLCR_H), 0x70);
        assert_eq!(uart.write(reg::UARTLCR_H, 0x1FF), None);
        assert_eq!(uart.read(reg::UARTLCR_H), 0xFF);

        // CR: 16-bit, starts at 0x0300
        assert_eq!(uart.read(reg::UARTCR), 0x0300);
        assert_eq!(uart.write(reg::UARTCR, 0x0301), None);
        assert_eq!(uart.read(reg::UARTCR), 0x0301);
        assert_eq!(uart.write(reg::UARTCR, 0x1_FFFF), None);
        assert_eq!(uart.read(reg::UARTCR), 0xFFFF);
    }

    #[test]
    fn uartimsc_reads_zero() {
        let uart = VirtualUart::new();
        assert_eq!(uart.read(reg::UARTIMSC), 0);
    }

    #[test]
    fn uarticr_write_is_noop() {
        let mut uart = VirtualUart::new();
        assert_eq!(uart.write(reg::UARTICR, 0x7FF), None);
        // State is unaffected — spot-check CR still at default
        assert_eq!(uart.read(reg::UARTCR), 0x0300);
    }

    #[test]
    fn unknown_offset_read_returns_zero() {
        let uart = VirtualUart::new();
        assert_eq!(uart.read(0x001), 0);
        assert_eq!(uart.read(0x100), 0);
        assert_eq!(uart.read(0xFFF), 0);
    }

    #[test]
    fn unknown_offset_write_returns_none() {
        let mut uart = VirtualUart::new();
        assert_eq!(uart.write(0x001, 0xDEAD), None);
        assert_eq!(uart.write(0x100, 0xBEEF), None);
        assert_eq!(uart.write(0xFFF, 0x1234), None);
    }
}
