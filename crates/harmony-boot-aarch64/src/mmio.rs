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
    fn read(&self, offset: usize) -> u32 {
        let addr = (self.base + offset) as *const u32;
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn write(&mut self, offset: usize, value: u32) {
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

        // Write to offset 4 (second u32)
        bank.write(4, 0xDEAD_BEEF);
        assert_eq!(buf[1], 0xDEAD_BEEF);

        // Read back
        let val = bank.read(4);
        assert_eq!(val, 0xDEAD_BEEF);

        // Write to offset 0 (first u32)
        bank.write(0, 0xCAFE_BABE);
        assert_eq!(buf[0], 0xCAFE_BABE);
        assert_eq!(bank.read(0), 0xCAFE_BABE);
    }

    #[test]
    fn mmio_base_returned() {
        let bank = unsafe { MmioRegisterBank::new(0x1234_0000) };
        assert_eq!(bank.base(), 0x1234_0000);
    }
}
