// SPDX-License-Identifier: GPL-2.0-or-later
//! Minimal PIT (8254) Channel 2 timer for monotonic milliseconds.
//!
//! Uses the "read-back" method: load a full 16-bit countdown, then
//! read the current count to measure elapsed ticks. No interrupts.

use x86_64::instructions::port::Port;

/// PIT oscillator frequency in Hz.
const PIT_FREQUENCY: u64 = 1_193_182;

/// PIT I/O ports.
const CHANNEL_2: u16 = 0x42;
const COMMAND: u16 = 0x43;
/// Port 0x61 controls the Channel 2 gate.
const PORT_61: u16 = 0x61;

/// Monotonic millisecond timer using PIT Channel 2.
pub struct PitTimer {
    accumulated_ticks: u64,
    last_count: u16,
}

impl PitTimer {
    /// Initialize PIT Channel 2 in mode 0 (one-shot), counting down
    /// from 0xFFFF (~54.9ms at 1.193182 MHz).
    pub fn init() -> Self {
        unsafe {
            // Enable Channel 2 gate (bit 0 of port 0x61), disable speaker (bit 1).
            let mut port61: Port<u8> = Port::new(PORT_61);
            let val = port61.read();
            port61.write((val | 0x01) & !0x02);

            // Command: Channel 2, lobyte/hibyte, mode 0 (one-shot), binary.
            // 0b10_11_000_0 = 0xB0
            Port::new(COMMAND).write(0xB0u8);

            // Load count = 0xFFFF (maximum countdown).
            let mut ch2: Port<u8> = Port::new(CHANNEL_2);
            ch2.write(0xFFu8); // low byte
            ch2.write(0xFFu8); // high byte
        }

        let initial = Self::read_count();

        PitTimer {
            accumulated_ticks: 0,
            last_count: initial,
        }
    }

    /// Read the current 16-bit count from Channel 2.
    fn read_count() -> u16 {
        unsafe {
            // Latch Channel 2: command 0b10_00_000_0 = 0x80
            Port::new(COMMAND).write(0x80u8);
            let mut ch2: Port<u8> = Port::new(CHANNEL_2);
            let lo = ch2.read() as u16;
            let hi = ch2.read() as u16;
            (hi << 8) | lo
        }
    }

    /// Return monotonic milliseconds since `init()`.
    ///
    /// Must be called at least once per ~55ms to avoid missing a
    /// counter wraparound. The spin-loop event loop calls this every
    /// iteration, so this is easily satisfied.
    pub fn now_ms(&mut self) -> u64 {
        let current = Self::read_count();

        // The counter counts DOWN. Elapsed = last - current.
        // If current > last, the counter wrapped around (passed 0).
        let elapsed = if current <= self.last_count {
            self.last_count - current
        } else {
            // Wrapped: last_count ticks down to 0, then 0xFFFF down to current.
            self.last_count + (0xFFFF - current) + 1
        };

        self.accumulated_ticks += elapsed as u64;
        self.last_count = current;

        // Reload the counter if it's getting low, to avoid
        // reaching 0 and stopping (mode 0 stops at terminal count).
        if current < 1000 {
            unsafe {
                Port::new(COMMAND).write(0xB0u8);
                let mut ch2: Port<u8> = Port::new(CHANNEL_2);
                ch2.write(0xFFu8);
                ch2.write(0xFFu8);
            }
            self.last_count = Self::read_count();
        }

        // Convert accumulated ticks to milliseconds.
        self.accumulated_ticks * 1000 / PIT_FREQUENCY
    }
}
