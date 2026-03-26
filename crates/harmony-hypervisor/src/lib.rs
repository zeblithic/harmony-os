// SPDX-License-Identifier: GPL-2.0-or-later
#![cfg_attr(not(test), no_std)]
extern crate alloc;

pub mod stage2;
pub mod trap;
pub mod vcpu;
pub mod vmid;
