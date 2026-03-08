// SPDX-License-Identifier: GPL-2.0-or-later

//! # Harmony OS (Ring 3)
//!
//! Full operating system built on the microkernel foundation.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod elf;
pub mod linuxulator;

#[cfg(test)]
mod tests {
    #[test]
    fn ring3_placeholder() {
        assert!(true);
    }
}
