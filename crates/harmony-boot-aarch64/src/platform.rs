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

/// PL011 UART base address for RPi5.
///
/// TODO(rpi5-hw): This is the BCM2711 (RPi4) legacy peripheral address.
/// BCM2712 (RPi5) routes UART through the RP1 south-bridge — the correct
/// post-ExitBootServices address needs verification on real hardware.
#[cfg(feature = "rpi5")]
pub const PL011_BASE: usize = 0xFE20_1000;

/// UART reference clock frequency in Hz.
#[cfg(feature = "qemu-virt")]
pub const UART_CLOCK_HZ: u32 = 24_000_000;

#[cfg(feature = "rpi5")]
pub const UART_CLOCK_HZ: u32 = 48_000_000;

// RPi5-only peripherals (reserved for future network driver)
// TODO(rpi5-hw): Verify GENET base address on BCM2712 hardware.
#[cfg(feature = "rpi5")]
#[allow(dead_code)]
pub const GENET_BASE: usize = 0xFD58_0000;

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
}
