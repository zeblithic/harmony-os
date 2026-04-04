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

#[cfg(target_arch = "aarch64")]
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Cached timer frequency read from `CNTFRQ_EL0` during [`init`].
#[cfg(target_arch = "aarch64")]
static TIMER_FREQ: AtomicU64 = AtomicU64::new(0);

/// Monotonic tick counter — incremented by the IRQ handler on each timer tick.
#[cfg(target_arch = "aarch64")]
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Cached reload value for `rearm()` — set by `enable_tick()`.
#[cfg(target_arch = "aarch64")]
static RELOAD_VALUE: AtomicU32 = AtomicU32::new(0);

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
    TIMER_FREQ.store(f, Ordering::Relaxed);
}

/// Return the cached timer frequency in Hz.
#[cfg(target_arch = "aarch64")]
pub fn freq() -> u64 {
    TIMER_FREQ.load(Ordering::Relaxed)
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

/// Arm the physical timer to fire periodic interrupts at `hz` Hz.
///
/// Computes the reload value from the cached timer frequency, writes
/// `CNTP_TVAL_EL0` (countdown), and enables the timer with interrupts
/// unmasked via `CNTP_CTL_EL0`.
///
/// # Panics
///
/// Panics if `hz` is 0 or if `init()` has not been called.
#[cfg(target_arch = "aarch64")]
pub fn enable_tick(hz: u32) {
    assert!(hz > 0, "tick frequency must be > 0");
    let f = freq();
    assert!(f > 0, "timer::init() must be called before enable_tick()");
    let reload = (f / hz as u64) as u32;
    RELOAD_VALUE.store(reload, Ordering::Relaxed);
    unsafe {
        // Load countdown register — fires interrupt when it reaches 0.
        core::arch::asm!("msr cntp_tval_el0, {}", in(reg) reload as u64);
        // Enable timer, unmask interrupt (ENABLE=1, IMASK=0).
        core::arch::asm!("msr cntp_ctl_el0, {}", in(reg) 1_u64);
    }
}

/// Reload the countdown timer for the next tick.
///
/// Called by the IRQ handler after each tick. Writes `CNTP_TVAL_EL0`
/// with the cached reload value, restarting the countdown from *now*.
#[cfg(target_arch = "aarch64")]
pub fn rearm() {
    let reload = RELOAD_VALUE.load(Ordering::Relaxed);
    unsafe {
        core::arch::asm!("msr cntp_tval_el0, {}", in(reg) reload as u64);
    }
}

/// Timer tick callback — called by the IRQ handler on each timer interrupt.
///
/// Increments the tick counter, rearms the timer. Every 100 ticks (once
/// per second), prints the tick count. At tick 500, prints the scheduler
/// verification line with both task counters (if tasks are running).
#[cfg(target_arch = "aarch64")]
pub fn on_tick() {
    let count = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    rearm();

    // Print tick count once per second (every 100 ticks) for boot verification.
    if count % 100 == 0 {
        print_tick(count);
    }

    // At tick 500 (5 seconds), print scheduler verification if tasks are running.
    if count == 500 {
        print_sched_verification();
    }
}

/// Minimal serial print for IRQ context — no allocator, no formatting.
/// Writes "[Tick] NNNNN\r\n" via PL011.
#[cfg(target_arch = "aarch64")]
fn print_tick(count: u64) {
    use crate::pl011;

    for &b in b"[Tick] " {
        unsafe { pl011::write_byte(b) };
    }
    print_u64(count);
    unsafe {
        pl011::write_byte(b'\r');
        pl011::write_byte(b'\n');
    }
}

/// Print scheduler verification line: "[Sched] Task 0: N, Task 1: M".
/// Called exactly once at tick 500. Uses the same IRQ-safe serial write
/// approach as `print_tick` — no allocator, no fmt.
#[cfg(target_arch = "aarch64")]
fn print_sched_verification() {
    use crate::sched;

    if sched::num_tasks() < 2 {
        return;
    }

    let (c0, c1) = sched::task_counters();

    use crate::pl011;

    // "[Sched] Task 0: "
    for &b in b"[Sched] Task 0: " {
        unsafe { pl011::write_byte(b) };
    }
    print_u64(c0);

    // ", Task 1: "
    for &b in b", Task 1: " {
        unsafe { pl011::write_byte(b) };
    }
    print_u64(c1);

    unsafe {
        pl011::write_byte(b'\r');
        pl011::write_byte(b'\n');
    }
}

/// Print a u64 as decimal to PL011. IRQ-safe (no allocator).
#[cfg(target_arch = "aarch64")]
fn print_u64(val: u64) {
    use crate::pl011;

    let mut buf = [0u8; 20]; // u64 max is 20 digits
    let mut n = val;
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    for &b in &buf[i..] {
        unsafe { pl011::write_byte(b) };
    }
}

/// Return the number of timer ticks since interrupts were enabled.
#[cfg(target_arch = "aarch64")]
pub fn tick_count() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed)
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

    #[test]
    fn reload_value_100hz_at_62_5_mhz() {
        // 62,500,000 Hz / 100 Hz = 625,000 ticks per interval
        let freq: u64 = 62_500_000;
        let hz: u32 = 100;
        let reload = (freq / hz as u64) as u32;
        assert_eq!(reload, 625_000);
    }

    #[test]
    fn reload_value_100hz_at_54_mhz() {
        // QEMU virt often reports 54 MHz
        let freq: u64 = 54_000_000;
        let hz: u32 = 100;
        let reload = (freq / hz as u64) as u32;
        assert_eq!(reload, 540_000);
    }

    #[test]
    fn reload_value_fits_u32() {
        // Even at 1 GHz / 100 Hz = 10,000,000 — fits in u32
        let freq: u64 = 1_000_000_000;
        let hz: u32 = 100;
        let reload = freq / hz as u64;
        assert!(reload <= u32::MAX as u64);
    }
}
