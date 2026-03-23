// SPDX-License-Identifier: GPL-2.0-or-later
//! AArch64 data cache maintenance for DMA coherency.
//!
//! On Cortex-A76 (RPi5), normal memory is cacheable. Before the DMA engine
//! reads a TX buffer, CPU caches must be cleaned. After the DMA engine
//! writes an RX buffer, CPU caches must be invalidated.

/// Cache line size on Cortex-A76 (64 bytes).
const CACHE_LINE_SIZE: usize = 64;

/// Clean data cache lines covering [start, start+len).
///
/// Ensures CPU writes are visible to the DMA device. Call before TX DMA.
///
/// # Safety
///
/// `start` must be a valid pointer for `len` bytes.
#[cfg(target_arch = "aarch64")]
pub unsafe fn clean_range(start: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    let mut addr = (start as usize) & !(CACHE_LINE_SIZE - 1);
    let end = (start as usize) + len;
    while addr < end {
        core::arch::asm!("dc cvau, {}", in(reg) addr);
        addr += CACHE_LINE_SIZE;
    }
    core::arch::asm!("dsb sy");
}

/// Invalidate data cache lines covering [start, start+len).
///
/// Ensures CPU sees DMA device writes. Call after RX DMA.
///
/// # Safety
///
/// `start` must be a valid pointer for `len` bytes. Any dirty cache data
/// in the range is discarded — only call on buffers owned by the device.
#[cfg(target_arch = "aarch64")]
pub unsafe fn invalidate_range(start: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    let mut addr = (start as usize) & !(CACHE_LINE_SIZE - 1);
    let end = (start as usize) + len;
    while addr < end {
        core::arch::asm!("dc civac, {}", in(reg) addr);
        addr += CACHE_LINE_SIZE;
    }
    core::arch::asm!("dsb sy");
}

/// No-op stubs for non-aarch64 (test builds on x86_64 host).
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn clean_range(_start: *const u8, _len: usize) {}

#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn invalidate_range(_start: *const u8, _len: usize) {}
