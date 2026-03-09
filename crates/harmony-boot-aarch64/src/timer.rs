// SPDX-License-Identifier: GPL-2.0-or-later
//! ARM Generic Timer driver for monotonic millisecond clock.
//!
//! Every ARMv8 core has a built-in counter accessible via `CNTPCT_EL0` (count)
//! and `CNTFRQ_EL0` (frequency).  No peripheral initialisation is needed --
//! firmware populates the frequency register before OS entry.
//!
//! The public [`now_ms`] function returns a monotonic millisecond timestamp
//! suitable for the unikernel event loop.

/// Convert a raw counter value to milliseconds given the timer frequency.
///
/// Uses 128-bit intermediate arithmetic to avoid overflow even at high
/// uptimes (e.g. 24 hours at 62.5 MHz).  Returns 0 if `freq` is zero.
pub fn counter_to_ms(count: u64, freq: u64) -> u64 {
    if freq == 0 {
        return 0;
    }
    ((count as u128 * 1000) / freq as u128) as u64
}

// ── Hardware access (aarch64 only) ────────────────────────────────────

/// Cached timer frequency read from `CNTFRQ_EL0` during [`init`].
#[cfg(target_arch = "aarch64")]
static mut TIMER_FREQ: u64 = 0;

/// Read `CNTFRQ_EL0` and cache the result in [`TIMER_FREQ`].
///
/// # Safety
///
/// Must be called exactly once during early boot, before any calls to
/// [`freq`], [`counter`], or [`now_ms`].
#[cfg(target_arch = "aarch64")]
pub unsafe fn init() {
    let f: u64;
    core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f);
    TIMER_FREQ = f;
}

/// Return the cached timer frequency in Hz.
#[cfg(target_arch = "aarch64")]
pub fn freq() -> u64 {
    unsafe { TIMER_FREQ }
}

/// Read the current value of the physical counter (`CNTPCT_EL0`).
#[cfg(target_arch = "aarch64")]
pub fn counter() -> u64 {
    let count: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) count) };
    count
}

/// Return the current monotonic time in milliseconds.
#[cfg(target_arch = "aarch64")]
pub fn now_ms() -> u64 {
    counter_to_ms(counter(), freq())
}

// ── Tests (run on host) ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_count_is_zero_ms() {
        assert_eq!(counter_to_ms(0, 62_500_000), 0);
    }

    #[test]
    fn one_second_at_62_5_mhz() {
        assert_eq!(counter_to_ms(62_500_000, 62_500_000), 1000);
    }

    #[test]
    fn large_count_no_overflow() {
        // 24 hours at 62.5 MHz: 24 * 3600 * 62_500_000 = 5_400_000_000_000
        let count: u64 = 24 * 3600 * 62_500_000;
        let ms = counter_to_ms(count, 62_500_000);
        assert_eq!(ms, 24 * 3600 * 1000); // 86_400_000 ms
    }

    #[test]
    fn zero_freq_returns_zero() {
        assert_eq!(counter_to_ms(1000, 0), 0);
    }

    #[test]
    fn fractional_ms_truncates() {
        // At 62.5 MHz, 1 ms = 62_500 ticks.  62_499 ticks < 1 ms -> 0.
        assert_eq!(counter_to_ms(62_499, 62_500_000), 0);
    }
}
