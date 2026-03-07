// SPDX-License-Identifier: GPL-2.0-or-later
#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod event_loop;
pub mod platform;
pub mod serial;

pub use event_loop::{PeerInfo, RuntimeAction, UnikernelRuntime};
pub use platform::entropy::KernelEntropy;
pub use platform::persistence::MemoryState;
pub use serial::SerialWriter;
