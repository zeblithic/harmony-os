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

/// GIC Redistributor register offsets.
///
/// The GICR has two 64 KiB frames:
/// - RD_base (frame 0): per-CPU control registers.
/// - SGI_base (frame 1, starting at offset 0x10000): enable/pending/priority
///   for SGIs and PPIs (IRQs 0-31). These share backing storage with the
///   corresponding GICD registers.
pub mod gicr {
    // RD_base frame
    pub const CTLR: u32 = 0x0000;
    pub const IIDR: u32 = 0x0004;
    pub const TYPER_LO: u32 = 0x0008;
    pub const TYPER_HI: u32 = 0x000C;
    pub const WAKER: u32 = 0x0014;
    // SGI_base frame (offsets relative to SGI_base start, i.e. 0x10000 subtracted by caller)
    pub const SGI_ISENABLER0: u32 = 0x0100;
    pub const SGI_ICENABLER0: u32 = 0x0180;
    pub const SGI_ISPENDR0: u32 = 0x0200;
    pub const SGI_ICPENDR0: u32 = 0x0280;
    pub const SGI_IPRIORITYR: u32 = 0x0400;
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
    /// GICR_WAKER — redistributor waker register.
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

    /// Read a GIC Redistributor RD_base frame register by MMIO offset.
    ///
    /// Returns `0` for unknown or unimplemented offsets.
    pub fn read_gicr_rd(&self, offset: u32) -> u64 {
        match offset {
            gicr::CTLR => 0,
            gicr::IIDR => 0x0100_0000, // Harmony implementer ID
            gicr::TYPER_LO => 0x10,    // Last=1 (bit 4), ProcessorNumber=0
            gicr::TYPER_HI => 0,
            gicr::WAKER => self.waker as u64,
            _ => 0,
        }
    }

    /// Write a GIC Redistributor RD_base frame register by MMIO offset.
    ///
    /// Unknown offsets are silently ignored.
    pub fn write_gicr_rd(&mut self, offset: u32, value: u64) {
        if offset == gicr::WAKER {
            self.waker = value as u32;
        }
    }

    /// Read a GIC Redistributor SGI_base frame register by MMIO offset.
    ///
    /// `offset` is relative to the SGI_base start (0x10000 already subtracted
    /// by the caller). SGI/PPI registers share backing storage with the
    /// distributor (`enable[0]`, `pending[0]`, `priority[0..31]`).
    ///
    /// Returns `0` for unknown or unimplemented offsets.
    pub fn read_gicr_sgi(&self, offset: u32) -> u64 {
        match offset {
            gicr::SGI_ISENABLER0 | gicr::SGI_ICENABLER0 => self.enable[0] as u64,
            gicr::SGI_ISPENDR0 | gicr::SGI_ICPENDR0 => self.pending[0] as u64,
            // SGI_IPRIORITYR[0..7]: 4 priority bytes per 32-bit word for IRQs 0-31
            o if (gicr::SGI_IPRIORITYR..gicr::SGI_IPRIORITYR + 32).contains(&o) => {
                let base = ((o - gicr::SGI_IPRIORITYR) / 4 * 4) as usize;
                let p = &self.priority;
                (p[base] as u64)
                    | ((p[base + 1] as u64) << 8)
                    | ((p[base + 2] as u64) << 16)
                    | ((p[base + 3] as u64) << 24)
            }
            _ => 0,
        }
    }

    /// Write a GIC Redistributor SGI_base frame register by MMIO offset.
    ///
    /// `offset` is relative to the SGI_base start (0x10000 already subtracted
    /// by the caller). Writes to SGI/PPI registers are reflected in the shared
    /// distributor backing arrays.
    ///
    /// Unknown offsets are silently ignored.
    pub fn write_gicr_sgi(&mut self, offset: u32, value: u64) {
        let v32 = value as u32;
        match offset {
            gicr::SGI_ISENABLER0 => self.enable[0] |= v32,
            gicr::SGI_ICENABLER0 => self.enable[0] &= !v32,
            gicr::SGI_ISPENDR0 => self.pending[0] |= v32,
            gicr::SGI_ICPENDR0 => self.pending[0] &= !v32,
            o if (gicr::SGI_IPRIORITYR..gicr::SGI_IPRIORITYR + 32).contains(&o) => {
                let base = ((o - gicr::SGI_IPRIORITYR) / 4 * 4) as usize;
                self.priority[base] = (v32 & 0xFF) as u8;
                self.priority[base + 1] = ((v32 >> 8) & 0xFF) as u8;
                self.priority[base + 2] = ((v32 >> 16) & 0xFF) as u8;
                self.priority[base + 3] = ((v32 >> 24) & 0xFF) as u8;
            }
            _ => {}
        }
    }

    /// Mark an IRQ as pending.
    pub fn pend(&mut self, irq: u32) {
        if (irq as usize) < IRQ_COUNT {
            let idx = (irq / 32) as usize;
            self.pending[idx] |= 1 << (irq % 32);
        }
    }

    /// Clear the pending state of an IRQ.
    pub fn unpend(&mut self, irq: u32) {
        if (irq as usize) < IRQ_COUNT {
            let idx = (irq / 32) as usize;
            self.pending[idx] &= !(1 << (irq % 32));
        }
    }

    /// Return `true` if the given IRQ is currently pending.
    pub fn is_pending(&self, irq: u32) -> bool {
        if (irq as usize) < IRQ_COUNT {
            let idx = (irq / 32) as usize;
            self.pending[idx] & (1 << (irq % 32)) != 0
        } else {
            false
        }
    }

    /// Return `true` if the given IRQ is currently enabled.
    pub fn is_enabled(&self, irq: u32) -> bool {
        if (irq as usize) < IRQ_COUNT {
            let idx = (irq / 32) as usize;
            self.enable[idx] & (1 << (irq % 32)) != 0
        } else {
            false
        }
    }

    /// Scan pending+enabled IRQs and populate List Registers.
    pub fn sync_lrs(&self, ich_lr: &mut [u64; 4], ich_hcr: &mut u64) {
        use crate::platform::LR_COUNT;

        *ich_lr = [0u64; 4];

        // Collect pending+enabled IRQs with priorities
        let mut candidates = [(0u32, 0xFFu8); IRQ_COUNT];
        let mut count = 0usize;

        for irq in 0..IRQ_COUNT as u32 {
            let idx = (irq / 32) as usize;
            let bit = 1 << (irq % 32);
            if self.pending[idx] & bit != 0 && self.enable[idx] & bit != 0 {
                candidates[count] = (irq, self.priority[irq as usize]);
                count += 1;
            }
        }

        // Sort by priority (lower = higher priority) — insertion sort
        for i in 1..count {
            let key = candidates[i];
            let mut j = i;
            while j > 0 && candidates[j - 1].1 > key.1 {
                candidates[j] = candidates[j - 1];
                j -= 1;
            }
            candidates[j] = key;
        }

        // Pack top LR_COUNT into LR format
        let lr_count = count.min(LR_COUNT);
        for i in 0..lr_count {
            let (irq, prio) = candidates[i];
            ich_lr[i] = (0b01u64 << 62)    // State = pending
                | (1u64 << 60)              // Group = 1
                | ((prio as u64) << 48)     // Priority
                | (irq as u64); // vINTID
        }

        if lr_count > 0 {
            *ich_hcr |= 1; // ICH_HCR_EL2.En = 1
        } else {
            *ich_hcr &= !1; // Clear En when no virtual interrupts pending
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

    // ---- GICR tests ----

    #[test]
    fn gicr_typer_reports_last_cpu() {
        let gic = VirtualGic::new();
        // TYPER_LO bit 4 = Last; ProcessorNumber = 0 in upper bits.
        let typer_lo = gic.read_gicr_rd(gicr::TYPER_LO);
        assert_eq!(
            typer_lo & (1 << 4),
            1 << 4,
            "TYPER_LO bit 4 (Last) must be set for single redistributor"
        );
        assert_eq!(
            typer_lo & !0x10u64,
            0,
            "TYPER_LO ProcessorNumber and other fields must be 0"
        );
        assert_eq!(gic.read_gicr_rd(gicr::TYPER_HI), 0, "TYPER_HI must be 0");
    }

    #[test]
    fn gicr_waker_round_trip() {
        let mut gic = VirtualGic::new();
        // Initially zero.
        assert_eq!(gic.read_gicr_rd(gicr::WAKER), 0);
        // Write a sentinel value and read it back.
        gic.write_gicr_rd(gicr::WAKER, 0xDEAD_BEEF);
        assert_eq!(
            gic.read_gicr_rd(gicr::WAKER),
            0xDEAD_BEEF,
            "GICR_WAKER must round-trip through read/write"
        );
    }

    #[test]
    fn gicr_sgi_enable_shared_with_gicd() {
        let mut gic = VirtualGic::new();
        // Enable PPI 27 via GICR SGI_ISENABLER0 (bit 27).
        gic.write_gicr_sgi(gicr::SGI_ISENABLER0, 1 << 27);
        // The same bit must be visible when reading GICD_ISENABLER[0].
        assert_eq!(
            gic.read_gicd(reg::ISENABLER),
            1 << 27,
            "enable[0] set via GICR must be visible in GICD_ISENABLER[0]"
        );
        // Reading via GICR SGI_ISENABLER0 must also reflect the state.
        assert_eq!(
            gic.read_gicr_sgi(gicr::SGI_ISENABLER0),
            1 << 27,
            "GICR_SGI_ISENABLER0 read must return the shared enable state"
        );
    }

    #[test]
    fn gicr_sgi_pending_shared_with_gicd() {
        let mut gic = VirtualGic::new();
        // Pend PPI 27 via GICR SGI_ISPENDR0 (bit 27).
        gic.write_gicr_sgi(gicr::SGI_ISPENDR0, 1 << 27);
        // The same bit must be visible when reading GICD_ISPENDR[0].
        assert_eq!(
            gic.read_gicd(reg::ISPENDR),
            1 << 27,
            "pending[0] set via GICR must be visible in GICD_ISPENDR[0]"
        );
        // Reading via GICR SGI_ISPENDR0 must also reflect the state.
        assert_eq!(
            gic.read_gicr_sgi(gicr::SGI_ISPENDR0),
            1 << 27,
            "GICR_SGI_ISPENDR0 read must return the shared pending state"
        );
    }

    #[test]
    fn pend_unpend_round_trip() {
        let mut gic = VirtualGic::new();
        gic.pend(27);
        assert!(gic.is_pending(27));
        gic.unpend(27);
        assert!(!gic.is_pending(27));
    }

    #[test]
    fn sync_lrs_populates_lr_for_pending_enabled_irq() {
        let mut gic = VirtualGic::new();
        gic.pend(27);
        gic.write_gicr_sgi(gicr::SGI_ISENABLER0, 1 << 27);
        gic.priority[27] = 0xA0;

        let mut lr = [0u64; 4];
        let mut hcr = 0u64;
        gic.sync_lrs(&mut lr, &mut hcr);

        assert_ne!(lr[0], 0);
        assert_eq!(lr[0] & 0xFFFF_FFFF, 27);
        assert_eq!((lr[0] >> 62) & 0x3, 0b01); // pending
        assert_eq!((lr[0] >> 48) & 0xFF, 0xA0);
        assert_eq!(hcr & 1, 1); // En
    }

    #[test]
    fn sync_lrs_skips_disabled_irqs() {
        let mut gic = VirtualGic::new();
        gic.pend(27);
        let mut lr = [0u64; 4];
        let mut hcr = 0u64;
        gic.sync_lrs(&mut lr, &mut hcr);
        assert_eq!(lr[0], 0);
    }

    #[test]
    fn sync_lrs_respects_priority_ordering() {
        let mut gic = VirtualGic::new();
        gic.pend(33);
        gic.write_gicd(0x0104, 1 << 1); // Enable SPI 33 (ISENABLER[1] bit 1)
        gic.priority[33] = 0xC0;
        gic.pend(27);
        gic.write_gicr_sgi(gicr::SGI_ISENABLER0, 1 << 27);
        gic.priority[27] = 0x40;

        let mut lr = [0u64; 4];
        let mut hcr = 0u64;
        gic.sync_lrs(&mut lr, &mut hcr);

        assert_eq!(lr[0] & 0xFFFF_FFFF, 27); // Higher priority first
        assert_eq!(lr[1] & 0xFFFF_FFFF, 33);
    }

    #[test]
    fn sync_lrs_caps_at_lr_count() {
        let mut gic = VirtualGic::new();
        for irq in 0..6u32 {
            gic.pend(irq);
            gic.enable[0] |= 1 << irq;
            gic.priority[irq as usize] = (irq as u8) * 0x10;
        }
        let mut lr = [0u64; 4];
        let mut hcr = 0u64;
        gic.sync_lrs(&mut lr, &mut hcr);

        assert_ne!(lr[3], 0); // 4th LR used
        assert_eq!(lr[0] & 0xFFFF_FFFF, 0); // Highest priority
        assert_eq!(lr[3] & 0xFFFF_FFFF, 3);
    }
}
