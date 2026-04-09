// SPDX-License-Identifier: GPL-2.0-or-later

//! DWC2 register offset constants and bitfield masks.
//!
//! Register layout follows the Synopsys DesignWare USB 2.0 OTG controller
//! databook. Offsets are from the peripheral MMIO base address.

// ── Core Global Registers ───────────────────────────────────────────────────

pub const GOTGCTL: usize = 0x000;
pub const GAHBCFG: usize = 0x008;
pub const GUSBCFG: usize = 0x00C;
pub const GRSTCTL: usize = 0x010;
pub const GINTSTS: usize = 0x014;
pub const GINTMSK: usize = 0x018;
pub const GRXSTSP: usize = 0x020;
pub const GRXFSIZ: usize = 0x024;
pub const GNPTXFSIZ: usize = 0x028;

/// Device IN Endpoint TX FIFO Size Register for EP `n` (1-based, n >= 1).
/// EP0's TX FIFO is configured via GNPTXFSIZ, not this register.
///
/// # Panics
///
/// Panics in debug mode if `n == 0` (no DIEPTXF0 register exists).
pub const fn dieptxf(n: u8) -> usize {
    // Safety: n=0 would underflow. EP0 uses GNPTXFSIZ instead.
    assert!(n >= 1, "dieptxf(0) is invalid — use GNPTXFSIZ for EP0");
    0x104 + (n as usize - 1) * 4
}

// ── Device Mode Registers ───────────────────────────────────────────────────

pub const DCFG: usize = 0x800;
pub const DCTL: usize = 0x804;
pub const DSTS: usize = 0x808;
pub const DIEPMSK: usize = 0x810;
pub const DOEPMSK: usize = 0x814;
pub const DAINT: usize = 0x818;
pub const DAINTMSK: usize = 0x81C;

// ── Per-Endpoint Registers (stride = 0x20) ──────────────────────────────────

pub const fn diepctl(n: u8) -> usize {
    0x900 + n as usize * 0x20
}
pub const fn diepint(n: u8) -> usize {
    0x908 + n as usize * 0x20
}
pub const fn dieptsiz(n: u8) -> usize {
    0x910 + n as usize * 0x20
}
pub const fn dtxfsts(n: u8) -> usize {
    0x918 + n as usize * 0x20
}
pub const fn doepctl(n: u8) -> usize {
    0xB00 + n as usize * 0x20
}
pub const fn doepint(n: u8) -> usize {
    0xB08 + n as usize * 0x20
}
pub const fn doeptsiz(n: u8) -> usize {
    0xB10 + n as usize * 0x20
}

pub const fn ep_fifo(n: u8) -> usize {
    0x1000 + n as usize * 0x1000
}

// ── GUSBCFG bits ────────────────────────────────────────────────────────────

pub const GUSBCFG_FORCE_DEV: u32 = 1 << 30;
pub const GUSBCFG_TURNAROUND_9: u32 = 9 << 10;

// ── GAHBCFG bits ────────────────────────────────────────────────────────────

pub const GAHBCFG_GLBL_INTR_EN: u32 = 1 << 0;

// ── GRSTCTL bits ────────────────────────────────────────────────────────────

pub const GRSTCTL_CSRST: u32 = 1 << 0;
pub const GRSTCTL_AHB_IDLE: u32 = 1 << 31;

// ── GINTSTS / GINTMSK bits ─────────────────────────────────────────────────

pub const GINTSTS_RXFLVL: u32 = 1 << 4;
pub const GINTSTS_USBSUSP: u32 = 1 << 11;
pub const GINTSTS_USBRST: u32 = 1 << 12;
pub const GINTSTS_ENUMDNE: u32 = 1 << 13;
pub const GINTSTS_IEPINT: u32 = 1 << 18;
pub const GINTSTS_OEPINT: u32 = 1 << 19;
pub const GINTSTS_WKUPINT: u32 = 1 << 31;

// ── GRXSTSP bits ────────────────────────────────────────────────────────────

pub const fn grxstsp_epnum(val: u32) -> u8 {
    (val & 0xF) as u8
}
pub const fn grxstsp_bcnt(val: u32) -> u16 {
    ((val >> 4) & 0x7FF) as u16
}
pub const fn grxstsp_pktsts(val: u32) -> u8 {
    ((val >> 17) & 0xF) as u8
}

pub const PKTSTS_OUT_DATA: u8 = 2;
pub const PKTSTS_OUT_COMPLETE: u8 = 3;
pub const PKTSTS_SETUP_COMPLETE: u8 = 4;
pub const PKTSTS_SETUP_DATA: u8 = 6;

// ── DCFG bits ───────────────────────────────────────────────────────────────

pub const DCFG_DEVSPD_HS: u32 = 0;
pub const DCFG_DAD_MASK: u32 = 0x7F << 4;
pub const fn dcfg_dad(addr: u8) -> u32 {
    ((addr as u32) & 0x7F) << 4
}

// ── DCTL bits ───────────────────────────────────────────────────────────────

pub const DCTL_SFTDISCON: u32 = 1 << 1;
pub const DCTL_CGINAK: u32 = 1 << 8;
pub const DCTL_CGONAK: u32 = 1 << 10;

// ── DSTS bits ───────────────────────────────────────────────────────────────

pub const fn dsts_enumspd(val: u32) -> u8 {
    ((val >> 1) & 0x3) as u8
}
pub const ENUMSPD_HS: u8 = 0;
pub const ENUMSPD_FS_48: u8 = 1;

// ── DIEPCTLn / DOEPCTLn bits ───────────────────────────────────────────────

pub const EPCTL_MPS_MASK: u32 = 0x7FF;
pub const EPCTL_USBAEP: u32 = 1 << 15;
pub const fn epctl_eptype(t: u8) -> u32 {
    ((t as u32) & 0x3) << 18
}
pub const fn epctl_txfnum(n: u8) -> u32 {
    ((n as u32) & 0xF) << 22
}
pub const EPCTL_STALL: u32 = 1 << 21;
pub const EPCTL_CNAK: u32 = 1 << 26;
pub const EPCTL_SNAK: u32 = 1 << 27;
pub const EPCTL_EPDIS: u32 = 1 << 30;
pub const EPCTL_EPENA: u32 = 1 << 31;

pub const EPTYPE_CONTROL: u8 = 0;
pub const EPTYPE_BULK: u8 = 2;
pub const EPTYPE_INTERRUPT: u8 = 3;

// ── DIEPINTn / DOEPINTn bits ────────────────────────────────────────────────

pub const DEPINT_XFERCOMPL: u32 = 1 << 0;
pub const DEPINT_EPDISBLD: u32 = 1 << 1;
pub const DOEPINT_SETUP: u32 = 1 << 3;

// ── DOEPTSIZn bits ──────────────────────────────────────────────────────────

pub const DOEPTSIZ0_SUPCNT_1: u32 = 1 << 29;
pub const DOEPTSIZ0_PKTCNT_1: u32 = 1 << 19;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_register_offsets_non_overlapping() {
        // IN EP control registers for EP0-3
        let in_eps: [usize; 4] = [diepctl(0), diepctl(1), diepctl(2), diepctl(3)];
        // OUT EP control registers for EP0-3
        let out_eps: [usize; 4] = [doepctl(0), doepctl(1), doepctl(2), doepctl(3)];

        // Verify all IN EP registers are distinct
        for i in 0..in_eps.len() {
            for j in (i + 1)..in_eps.len() {
                assert_ne!(
                    in_eps[i], in_eps[j],
                    "IN EP{} and IN EP{} have overlapping offsets",
                    i, j
                );
            }
        }

        // Verify all OUT EP registers are distinct
        for i in 0..out_eps.len() {
            for j in (i + 1)..out_eps.len() {
                assert_ne!(
                    out_eps[i], out_eps[j],
                    "OUT EP{} and OUT EP{} have overlapping offsets",
                    i, j
                );
            }
        }

        // Verify IN and OUT EP registers don't overlap
        for (i, &in_off) in in_eps.iter().enumerate() {
            for (j, &out_off) in out_eps.iter().enumerate() {
                assert_ne!(
                    in_off, out_off,
                    "IN EP{} and OUT EP{} have overlapping offsets",
                    i, j
                );
            }
        }
    }

    #[test]
    fn dieptxf_offsets() {
        assert_eq!(dieptxf(1), 0x104);
        assert_eq!(dieptxf(2), 0x108);
        assert_eq!(dieptxf(3), 0x10C);
    }

    #[test]
    fn ep_fifo_offsets() {
        assert_eq!(ep_fifo(0), 0x1000);
        assert_eq!(ep_fifo(1), 0x2000);
        assert_eq!(ep_fifo(2), 0x3000);
    }

    #[test]
    fn grxstsp_field_extraction() {
        // Build a GRXSTSP value: EP=2, bcnt=64, pktsts=6 (SETUP_DATA)
        // epnum: bits [3:0]  = 2
        // bcnt:  bits [14:4] = 64
        // pktsts:bits [20:17] = 6
        let epnum: u32 = 2;
        let bcnt: u32 = 64;
        let pktsts: u32 = 6;
        let val: u32 = epnum | (bcnt << 4) | (pktsts << 17);

        assert_eq!(grxstsp_epnum(val), 2);
        assert_eq!(grxstsp_bcnt(val), 64);
        assert_eq!(grxstsp_pktsts(val), PKTSTS_SETUP_DATA);
    }

    #[test]
    fn dcfg_device_address_encoding() {
        assert_eq!(dcfg_dad(0), 0);
        assert_eq!(dcfg_dad(5), 5 << 4);
        assert_eq!(dcfg_dad(127), 127 << 4);
    }

    #[test]
    fn epctl_field_encoding() {
        // Build bulk IN config: type=BULK(2), FIFO=1, MPS=512, active, enable
        let mps: u32 = 512;
        let val = mps | EPCTL_USBAEP | epctl_eptype(EPTYPE_BULK) | epctl_txfnum(1) | EPCTL_EPENA;

        // Verify MPS field
        assert_eq!(val & EPCTL_MPS_MASK, 512);
        // Verify active bit
        assert_ne!(val & EPCTL_USBAEP, 0);
        // Verify endpoint type = BULK (2) at bits [19:18]
        assert_eq!((val >> 18) & 0x3, EPTYPE_BULK as u32);
        // Verify TX FIFO number = 1 at bits [25:22]
        assert_eq!((val >> 22) & 0xF, 1);
        // Verify enable bit
        assert_ne!(val & EPCTL_EPENA, 0);
    }
}
