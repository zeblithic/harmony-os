// SPDX-License-Identifier: GPL-2.0-or-later
//! Aarch64 syscall trap handler — TrapFrame and SVC dispatch.
//!
//! The exception vector table (in `vectors.rs`) saves registers into a
//! `TrapFrame` and calls into the Rust handlers defined here.

// Hardware functions are only compiled for aarch64; suppress warnings on
// the host test runner.
#![cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]

/// Saved register state on exception entry.
///
/// The assembly vector table saves X0-X30, ELR_EL1, and SPSR_EL1 in
/// this exact layout. The struct must be `#[repr(C)]` so field offsets
/// match the assembly push order.
#[repr(C)]
pub struct TrapFrame {
    /// General-purpose registers X0-X30.
    pub x: [u64; 31],
    /// Exception Link Register — the PC to return to.
    pub elr: u64,
    /// Saved Processor State Register.
    pub spsr: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn trap_frame_size() {
        // 31 registers * 8 bytes + ELR (8) + SPSR (8) = 264 bytes
        assert_eq!(mem::size_of::<TrapFrame>(), 264);
    }

    #[test]
    fn trap_frame_x8_offset() {
        // X8 (syscall number) is at index 8 in the x array
        // Offset = 8 * 8 = 64 bytes from start
        assert_eq!(mem::offset_of!(TrapFrame, x) + 8 * 8, 64);
    }

    #[test]
    fn trap_frame_elr_offset() {
        // ELR comes after 31 u64s = 248 bytes
        assert_eq!(mem::offset_of!(TrapFrame, elr), 248);
    }

    #[test]
    fn trap_frame_spsr_offset() {
        // SPSR comes after ELR = 256 bytes
        assert_eq!(mem::offset_of!(TrapFrame, spsr), 256);
    }
}
