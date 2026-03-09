// SPDX-License-Identifier: GPL-2.0-or-later
//! aarch64 UEFI boot stub for Harmony unikernel.

#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]

#[cfg(not(test))]
extern crate alloc;

mod pl011;

#[cfg(target_os = "uefi")]
use core::fmt::Write;
#[cfg(target_os = "uefi")]
use uefi::prelude::*;

#[cfg(target_os = "uefi")]
#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    uefi::println!("[UEFI] Booting Harmony aarch64...");

    // ── Exit boot services ── UEFI console is no longer available after this.
    let _memory_map = unsafe { uefi::boot::exit_boot_services(None) };

    // ── Initialise PL011 UART (115200 8N1, FIFO enabled) ──
    unsafe { pl011::init() };

    let mut serial =
        harmony_unikernel::SerialWriter::new(|byte| unsafe { pl011::write_byte(byte) });
    let _ = writeln!(serial, "[PL011] Serial initialized: 115200 8N1");

    // We cannot return Status::SUCCESS after ExitBootServices — the UEFI
    // runtime no longer owns control flow. Loop forever (subsequent tasks
    // will replace this with a proper event loop / idle halt).
    loop {
        core::hint::spin_loop();
    }
}
