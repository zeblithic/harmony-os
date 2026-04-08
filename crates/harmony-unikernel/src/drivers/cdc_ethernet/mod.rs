// SPDX-License-Identifier: GPL-2.0-or-later

//! USB CDC-ECM/NCM Ethernet class driver.
//!
//! Sans-I/O driver that parses CDC descriptors, encodes/decodes Ethernet
//! frames (ECM passthrough or NCM NTH16/NDP16), and implements
//! [`NetworkDevice`] for Ring 2 integration via `VirtioNetServer`.

pub mod ncm;
pub mod notification;

pub use notification::{CdcError, CdcNotification};
