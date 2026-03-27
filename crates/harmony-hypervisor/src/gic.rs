// SPDX-License-Identifier: GPL-2.0-or-later

//! GICv3 virtual interrupt controller — distributor register emulation.
//!
//! Provides a pure state-machine emulation of the ARM GICv3 interrupt
//! distributor (GICD) and redistributor (GICR) regions. No I/O is
//! performed; callers drive reads/writes via MMIO offset dispatch.

/// Total number of supported IRQs (SGIs 0-15, PPIs 16-31, SPIs 32-63).
pub const IRQ_COUNT: usize = 64;

/// GIC Distributor register offsets.
pub mod reg {
    pub const CTLR: u32 = 0x0000;
    pub const TYPER: u32 = 0x0004;
    pub const IIDR: u32 = 0x0008;
    pub const IGROUPR: u32 = 0x0080;
    pub const ISENABLER: u32 = 0x0100;
    pub const ICENABLER: u32 = 0x0180;
    pub const ISPENDR: u32 = 0x0200;
    pub const ICPENDR: u32 = 0x0280;
    pub const IPRIORITYR: u32 = 0x0400;
    pub const ITARGETSR: u32 = 0x0800;
    pub const ICFGR: u32 = 0x0C00;
    pub const PIDR2: u32 = 0xFFE8;
}

/// Identifies which GIC MMIO region an access targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GicRegion {
    /// GIC Distributor (GICD).
    Distributor,
    /// GIC Redistributor RD_base frame (GICR RD).
    RedistributorRd,
    /// GIC Redistributor SGI_base frame (GICR SGI).
    RedistributorSgi,
}

/// Virtual GICv3 interrupt controller state.
///
/// Tracks distributor configuration for up to [`IRQ_COUNT`] IRQs. The
/// redistributor frames are recognized but not yet modeled in detail.
pub struct VirtualGic {
    /// GICD_CTLR — distributor control register.
    ctlr: u32,
    /// GICD_IGROUPR[0..2] — interrupt group bits (one bit per IRQ).
    group: [u32; 2],
    /// GICD_ISENABLER / GICD_ICENABLER[0..2] — enable bits.
    enable: [u32; 2],
    /// GICD_ISPENDR / GICD_ICPENDR[0..2] — pending bits.
    pending: [u32; 2],
    /// GICD_IPRIORITYR — 8-bit priority per IRQ.
    priority: [u8; IRQ_COUNT],
    /// GICD_ICFGR[0..4] — interrupt configuration (edge/level).
    config: [u32; 4],
    /// GICR_WAKER — redistributor waker register (modeled in future redistributor work).
    #[allow(dead_code)]
    waker: u32,
}

impl Default for VirtualGic {
    fn default() -> Self {
        Self {
            ctlr: 0,
            group: [0; 2],
            enable: [0; 2],
            pending: [0; 2],
            priority: [0; IRQ_COUNT],
            config: [0; 4],
            waker: 0,
        }
    }
}

impl VirtualGic {
    /// Create a new `VirtualGic` with power-on defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a GIC Distributor register by MMIO offset.
    ///
    /// Returns `0` for unknown or unimplemented offsets.
    pub fn read_gicd(&self, offset: u32) -> u64 {
        match offset {
            reg::CTLR => self.ctlr as u64,

            reg::TYPER => 1, // ITLinesNumber=1 → 64 IRQs

            reg::IIDR => 0x0100_0000, // Harmony implementer ID

            // IGROUPR[0..1]: one bit per IRQ indicating Group 0 or Group 1
            o if (reg::IGROUPR..reg::IGROUPR + 8).contains(&o) => {
                let idx = ((o - reg::IGROUPR) / 4) as usize;
                self.group[idx] as u64
            }

            // ISENABLER[0..1] and ICENABLER[0..1]: both read current enable bits
            o if (reg::ISENABLER..reg::ISENABLER + 8).contains(&o) => {
                let idx = ((o - reg::ISENABLER) / 4) as usize;
                self.enable[idx] as u64
            }
            o if (reg::ICENABLER..reg::ICENABLER + 8).contains(&o) => {
                let idx = ((o - reg::ICENABLER) / 4) as usize;
                self.enable[idx] as u64
            }

            // ISPENDR[0..1] and ICPENDR[0..1]: both read current pending bits
            o if (reg::ISPENDR..reg::ISPENDR + 8).contains(&o) => {
                let idx = ((o - reg::ISPENDR) / 4) as usize;
                self.pending[idx] as u64
            }
            o if (reg::ICPENDR..reg::ICPENDR + 8).contains(&o) => {
                let idx = ((o - reg::ICPENDR) / 4) as usize;
                self.pending[idx] as u64
            }

            // IPRIORITYR[0..15]: 4 priority bytes packed per 32-bit read
            o if (reg::IPRIORITYR..reg::IPRIORITYR + 64).contains(&o) => {
                let base = ((o - reg::IPRIORITYR) / 4 * 4) as usize;
                let p = &self.priority;
                (p[base] as u64)
                    | ((p[base + 1] as u64) << 8)
                    | ((p[base + 2] as u64) << 16)
                    | ((p[base + 3] as u64) << 24)
            }

            // ITARGETSR[0..15]: all IRQs target CPU 0
            o if (reg::ITARGETSR..reg::ITARGETSR + 64).contains(&o) => 0x0101_0101,

            // ICFGR[0..3]: interrupt configuration (edge/level)
            o if (reg::ICFGR..reg::ICFGR + 16).contains(&o) => {
                let idx = ((o - reg::ICFGR) / 4) as usize;
                self.config[idx] as u64
            }

            reg::PIDR2 => 0x3B, // GICv3 architecture revision

            _ => 0,
        }
    }

    /// Write a GIC Distributor register by MMIO offset.
    ///
    /// Unknown offsets are silently ignored.
    pub fn write_gicd(&mut self, offset: u32, value: u64) {
        let v32 = value as u32;
        match offset {
            reg::CTLR => self.ctlr = v32,

            // IGROUPR: direct store
            o if (reg::IGROUPR..reg::IGROUPR + 8).contains(&o) => {
                let idx = ((o - reg::IGROUPR) / 4) as usize;
                self.group[idx] = v32;
            }

            // ISENABLER: write-1-to-set
            o if (reg::ISENABLER..reg::ISENABLER + 8).contains(&o) => {
                let idx = ((o - reg::ISENABLER) / 4) as usize;
                self.enable[idx] |= v32;
            }

            // ICENABLER: write-1-to-clear
            o if (reg::ICENABLER..reg::ICENABLER + 8).contains(&o) => {
                let idx = ((o - reg::ICENABLER) / 4) as usize;
                self.enable[idx] &= !v32;
            }

            // ISPENDR: write-1-to-set
            o if (reg::ISPENDR..reg::ISPENDR + 8).contains(&o) => {
                let idx = ((o - reg::ISPENDR) / 4) as usize;
                self.pending[idx] |= v32;
            }

            // ICPENDR: write-1-to-clear
            o if (reg::ICPENDR..reg::ICPENDR + 8).contains(&o) => {
                let idx = ((o - reg::ICPENDR) / 4) as usize;
                self.pending[idx] &= !v32;
            }

            // IPRIORITYR: unpack 4 priority bytes per word
            o if (reg::IPRIORITYR..reg::IPRIORITYR + 64).contains(&o) => {
                let base = ((o - reg::IPRIORITYR) / 4 * 4) as usize;
                self.priority[base] = (v32 & 0xFF) as u8;
                self.priority[base + 1] = ((v32 >> 8) & 0xFF) as u8;
                self.priority[base + 2] = ((v32 >> 16) & 0xFF) as u8;
                self.priority[base + 3] = ((v32 >> 24) & 0xFF) as u8;
            }

            // ICFGR: direct store
            o if (reg::ICFGR..reg::ICFGR + 16).contains(&o) => {
                let idx = ((o - reg::ICFGR) / 4) as usize;
                self.config[idx] = v32;
            }

            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gicd_typer_returns_it_lines_number_1() {
        let gic = VirtualGic::new();
        let typer = gic.read_gicd(reg::TYPER);
        // ITLinesNumber=1 means 64 IRQs ((ITLinesNumber+1)*32).
        assert_eq!(typer, 1, "TYPER ITLinesNumber must be 1 for 64 IRQs");
    }

    #[test]
    fn gicd_pidr2_returns_gicv3_revision() {
        let gic = VirtualGic::new();
        // PIDR2[7:4] = 0x3 → GICv3 architecture revision.
        assert_eq!(gic.read_gicd(reg::PIDR2), 0x3B);
    }

    #[test]
    fn gicd_isenabler_icenabler_set_clear() {
        let mut gic = VirtualGic::new();

        // IRQ 33 is SPI 1 → lives in enable[1], bit 1 (IRQ 33 mod 32 = 1).
        // ISENABLER[1] is at offset 0x0100 + 4 = 0x0104.
        let isenabler1 = reg::ISENABLER + 4;
        let icenabler1 = reg::ICENABLER + 4;

        // Initially disabled.
        assert_eq!(gic.read_gicd(isenabler1), 0);

        // Set enable for IRQ 33.
        gic.write_gicd(isenabler1, 1 << 1);
        assert_eq!(
            gic.read_gicd(isenabler1),
            1 << 1,
            "IRQ 33 enable bit must be set after ISENABLER write"
        );

        // ICENABLER reads the same array.
        assert_eq!(
            gic.read_gicd(icenabler1),
            1 << 1,
            "ICENABLER read must mirror enable state"
        );

        // Clear enable for IRQ 33 via ICENABLER.
        gic.write_gicd(icenabler1, 1 << 1);
        assert_eq!(
            gic.read_gicd(isenabler1),
            0,
            "IRQ 33 enable bit must be cleared after ICENABLER write"
        );
    }

    #[test]
    fn gicd_ispendr_icpendr_set_clear() {
        let mut gic = VirtualGic::new();

        // IRQ 27 is PPI → lives in pending[0], bit 27.
        // ISPENDR[0] is at offset 0x0200, ICPENDR[0] at 0x0280.
        let ispendr0 = reg::ISPENDR;
        let icpendr0 = reg::ICPENDR;

        assert_eq!(gic.read_gicd(ispendr0), 0);

        // Pend IRQ 27.
        gic.write_gicd(ispendr0, 1 << 27);
        assert_eq!(
            gic.read_gicd(ispendr0),
            1 << 27,
            "IRQ 27 pending bit must be set after ISPENDR write"
        );

        // Clear pending via ICPENDR.
        gic.write_gicd(icpendr0, 1 << 27);
        assert_eq!(
            gic.read_gicd(ispendr0),
            0,
            "IRQ 27 pending bit must be cleared after ICPENDR write"
        );
    }

    #[test]
    fn gicd_priority_byte_access() {
        let mut gic = VirtualGic::new();

        // IRQ 33: word index = 33/4 = 8, byte lane = 33%4 = 1.
        // IPRIORITYR word for IRQs 32-35 is at offset 0x0400 + 8*4 = 0x0420.
        let ipriorityr_word = reg::IPRIORITYR + 8 * 4;

        // Write priority 0xA0 for IRQ 33 (byte lane 1), others 0.
        gic.write_gicd(ipriorityr_word, 0x00_00_A0_00);
        let readback = gic.read_gicd(ipriorityr_word);
        // Byte lane 1 should be 0xA0.
        assert_eq!(
            (readback >> 8) & 0xFF,
            0xA0,
            "priority for IRQ 33 must round-trip via IPRIORITYR"
        );
        // Other lanes must be zero.
        assert_eq!(readback & 0xFF, 0);
        assert_eq!((readback >> 16) & 0xFF, 0);
        assert_eq!((readback >> 24) & 0xFF, 0);
    }

    #[test]
    fn gicd_itargetsr_returns_cpu0() {
        let gic = VirtualGic::new();
        // Every ITARGETSR word should indicate CPU 0 for all four bytes.
        assert_eq!(gic.read_gicd(reg::ITARGETSR), 0x0101_0101);
        assert_eq!(gic.read_gicd(reg::ITARGETSR + 4), 0x0101_0101);
        assert_eq!(gic.read_gicd(reg::ITARGETSR + 60), 0x0101_0101);
    }

    #[test]
    fn gicd_unknown_register_reads_zero() {
        let gic = VirtualGic::new();
        assert_eq!(gic.read_gicd(0x0010), 0, "offset 0x0010 must return 0");
        assert_eq!(gic.read_gicd(0x0050), 0, "offset 0x0050 must return 0");
        assert_eq!(gic.read_gicd(0x1000), 0, "offset 0x1000 must return 0");
    }
}
