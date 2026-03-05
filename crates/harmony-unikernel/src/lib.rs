// SPDX-License-Identifier: GPL-2.0-or-later

//! # Harmony Unikernel (Ring 1)
//!
//! A minimal bootable image that compiles the Harmony protocol stack,
//! a network driver, and an event loop into a single binary. Boots
//! directly on bare metal (multiboot2/UEFI) or a hypervisor (VirtIO).
//!
//! ## Architecture
//!
//! - Single address space, no processes, no syscall boundary
//! - Ring 0 state machines called directly as Rust function calls
//! - Platform traits implemented for the target hardware
//! - Minimal async executor drives the event loop
//!
//! ## Targets
//!
//! - Bare-metal x86_64/aarch64 (SUNDRAGON appliances)
//! - VirtIO on QEMU/KVM/Firecracker (cloud edge, development)

// TODO: Switch to #![no_std] once platform traits are defined in Ring 0.
// The unikernel will use `alloc` for heap but not `std`.
// #![no_std]
// extern crate alloc;

#[cfg(test)]
mod tests {
    #[test]
    fn ring1_placeholder() {
        // Ring 1 scaffold compiles and runs
        assert!(true);
    }
}
