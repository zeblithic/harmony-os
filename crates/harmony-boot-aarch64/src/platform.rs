// SPDX-License-Identifier: GPL-2.0-or-later
//! Platform-specific hardware constants selected at compile time.
//!
//! Exactly one of `qemu-virt` or `rpi5` must be enabled. The build
//! fails with a compile_error! if neither or both are active.

#[cfg(all(feature = "qemu-virt", feature = "rpi5"))]
compile_error!("Features `qemu-virt` and `rpi5` are mutually exclusive");

#[cfg(not(any(feature = "qemu-virt", feature = "rpi5")))]
compile_error!("Exactly one platform feature must be enabled: `qemu-virt` or `rpi5`");

/// PL011 UART base address.
#[cfg(feature = "qemu-virt")]
pub const PL011_BASE: usize = 0x0900_0000;

/// GICv3 Distributor base address (QEMU virt).
#[cfg(feature = "qemu-virt")]
pub const GICD_BASE: usize = 0x0800_0000;

/// GICv3 Redistributor base address (QEMU virt).
#[cfg(feature = "qemu-virt")]
pub const GICR_BASE: usize = 0x080A_0000;

/// PL011 UART base address for RPi5 (BCM2712 debug UART).
///
/// This is the SoC-native debug UART at 0x107d001000, connected to the
/// 3-pin JST debug connector. It is always-on and does not require PCIe
/// or RP1 initialization — safe to use immediately after ExitBootServices.
///
/// The GPIO-header UART (GPIO 14/15) goes through RP1 via PCIe at
/// 0x1F00030000, but requires PCIe controller initialization which we
/// don't do in bare-metal mode.
#[cfg(feature = "rpi5")]
pub const PL011_BASE: usize = 0x10_7D00_1000;

/// UART reference clock frequency in Hz.
#[cfg(feature = "qemu-virt")]
pub const UART_CLOCK_HZ: u32 = 24_000_000;

/// BCM2712 debug UART clock (48 MHz from crystal oscillator).
#[cfg(feature = "rpi5")]
pub const UART_CLOCK_HZ: u32 = 48_000_000;

/// BCM2712 GENET Ethernet controller base address (RPi5).
///
/// Accessed through RP1 PCIe BAR at 0x1F_0058_0000. UEFI performs PCIe
/// initialization before ExitBootServices; the BAR assignment is preserved
/// by passing `pciex4_reset=0` in the kernel command line.
#[cfg(feature = "rpi5")]
pub const GENET_BASE: usize = 0x1F_0058_0000;

/// BCM2712 DesignWare xHCI USB controller base address (RPi5).
///
/// Accessed through RP1 PCIe BAR at offset 0xD0000. UEFI performs PCIe
/// initialization; the BAR assignment is preserved by `pciex4_reset=0`.
/// Maps 16 pages (~64KB) covering capability, operational, port,
/// runtime, and doorbell register regions.
#[cfg(feature = "rpi5")]
pub const XHCI_BASE: usize = 0x1F_000D_0000;

/// MMIO regions to map as Device memory (NO_CACHE) during MMU init.
/// Each entry: (base_address, page_count).
#[cfg(feature = "qemu-virt")]
pub const MMIO_REGIONS: &[(usize, usize)] = &[
    (PL011_BASE, 1),  // PL011 UART (4 KiB)
    (GICD_BASE, 16),  // GICv3 Distributor (64 KiB)
    (GICR_BASE, 256), // GICv3 Redistributor (1 MiB — 128 KiB per CPU × 8 max)
];

/// Locally-administered test MAC address for GENET (RPi5).
///
/// 0x02 prefix = locally administered unicast. Future work: read real
/// MAC from OTP/firmware.
#[cfg(feature = "rpi5")]
pub const NODE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

#[cfg(feature = "rpi5")]
pub const MMIO_REGIONS: &[(usize, usize)] = &[
    (PL011_BASE, 1),
    (GENET_BASE, 16), // SYS through TDMA + descriptor RAM (~64KB)
    (XHCI_BASE, 16),  // xHCI capability + operational + port registers (~64KB)
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pl011_base_is_set() {
        assert_ne!(PL011_BASE, 0);
    }

    #[test]
    fn uart_clock_is_set() {
        assert!(UART_CLOCK_HZ > 0);
    }

    #[test]
    fn gic_bases_are_set() {
        #[cfg(feature = "qemu-virt")]
        {
            assert_ne!(GICD_BASE, 0);
            assert_ne!(GICR_BASE, 0);
            // GICR must be after GICD (separate MMIO region)
            assert!(GICR_BASE > GICD_BASE);
        }
    }

    #[test]
    fn mmio_regions_include_gic() {
        #[cfg(feature = "qemu-virt")]
        {
            let has_gicd = MMIO_REGIONS.iter().any(|&(base, _)| base == GICD_BASE);
            let has_gicr = MMIO_REGIONS.iter().any(|&(base, _)| base == GICR_BASE);
            assert!(has_gicd, "MMIO_REGIONS must include GICD");
            assert!(has_gicr, "MMIO_REGIONS must include GICR");
        }
    }
}
