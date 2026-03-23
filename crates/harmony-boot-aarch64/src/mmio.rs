// SPDX-License-Identifier: GPL-2.0-or-later
//! MMIO RegisterBank — volatile read/write wrapper for hardware registers.
//!
//! Implements the `RegisterBank` trait from `harmony_unikernel` so that
//! sans-I/O drivers (GENET, PL011, SDHCI, GPIO) can be used with real
//! hardware. The base address is platform-specific and set at construction.

use harmony_unikernel::drivers::register_bank::RegisterBank;

/// Concrete MMIO register bank for aarch64 hardware.
///
/// Wraps volatile pointer read/write at a fixed base address.
/// All offsets are in bytes relative to `base`.
pub struct MmioRegisterBank {
    base: usize,
}

impl MmioRegisterBank {
    /// Create a new MMIO register bank at the given physical base address.
    ///
    /// # Safety
    ///
    /// The caller must ensure `base` points to a valid MMIO region that is
    /// mapped in the page table (e.g., with `PageFlags::NO_CACHE`).
    pub const unsafe fn new(base: usize) -> Self {
        Self { base }
    }

    /// Return the base address.
    pub fn base(&self) -> usize {
        self.base
    }
}

impl RegisterBank for MmioRegisterBank {
    /// Read a 32-bit register at `offset` bytes from base.
    ///
    /// # Panics
    /// Debug-asserts that `offset` is 4-byte aligned (required for u32 MMIO on aarch64).
    fn read(&self, offset: usize) -> u32 {
        debug_assert!(offset % 4 == 0, "MMIO offset {offset:#x} is not 4-byte aligned");
        let addr = (self.base + offset) as *const u32;
        unsafe { core::ptr::read_volatile(addr) }
    }

    /// Write a 32-bit register at `offset` bytes from base.
    ///
    /// # Panics
    /// Debug-asserts that `offset` is 4-byte aligned (required for u32 MMIO on aarch64).
    fn write(&mut self, offset: usize, value: u32) {
        debug_assert!(offset % 4 == 0, "MMIO offset {offset:#x} is not 4-byte aligned");
        let addr = (self.base + offset) as *mut u32;
        unsafe { core::ptr::write_volatile(addr, value) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmio_register_bank_read_write() {
        // Use a stack-allocated buffer as a mock MMIO region.
        let mut buf = [0u32; 4];
        let base = buf.as_mut_ptr() as usize;

        let mut bank = unsafe { MmioRegisterBank::new(base) };

        // Write and read back via volatile path only (no aliasing with buf).
        bank.write(4, 0xDEAD_BEEF);
        assert_eq!(bank.read(4), 0xDEAD_BEEF);

        bank.write(0, 0xCAFE_BABE);
        assert_eq!(bank.read(0), 0xCAFE_BABE);

        // Drop bank before inspecting buf to end its raw-pointer borrow.
        drop(bank);
        assert_eq!(buf[0], 0xCAFE_BABE);
        assert_eq!(buf[1], 0xDEAD_BEEF);
    }

    #[test]
    fn mmio_base_returned() {
        let bank = unsafe { MmioRegisterBank::new(0x1234_0000) };
        assert_eq!(bank.base(), 0x1234_0000);
    }
}
