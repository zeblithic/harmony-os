// SPDX-License-Identifier: GPL-2.0-or-later

//! # Harmony Microkernel (Ring 2)
//!
//! Adds three capabilities to the unikernel foundation:
//! - **Process isolation** — per-process virtual address spaces
//! - **9P IPC** — every kernel object is a file in a 9P namespace
//! - **Capability enforcement** — no ambient authority, UCAN delegation
//!
//! ## Three Kernel Responsibilities
//!
//! The microkernel does exactly three things in privileged mode:
//! 1. Memory management (capability-gated regions)
//! 2. Scheduling + 9P IPC dispatch
//! 3. Capability enforcement (UCAN verification)
//!
//! Everything else — routing, storage, compute, drivers — runs as
//! unprivileged userspace 9P server processes.

// TODO: Switch to #![no_std] once kernel foundations are in place.
// #![no_std]
// extern crate alloc;

#[cfg(test)]
mod tests {
    #[test]
    fn ring2_placeholder() {
        // Ring 2 scaffold compiles and runs
        assert!(true);
    }
}
