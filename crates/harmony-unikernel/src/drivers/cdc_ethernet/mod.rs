// SPDX-License-Identifier: GPL-2.0-or-later

//! USB CDC-ECM/NCM Ethernet class driver.

pub mod codec;
pub mod ncm;
pub mod notification;

pub use codec::CdcCodec;
pub use notification::{CdcError, CdcNotification};
