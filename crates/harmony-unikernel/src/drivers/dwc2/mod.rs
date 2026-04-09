// SPDX-License-Identifier: GPL-2.0-or-later
//! DWC2 OTG USB device controller driver.
pub mod fifo;
pub mod regs;
pub mod types;
pub use types::{DeviceSpeed, Dwc2Action, Dwc2Error, Dwc2Event, GadgetEvent, GadgetRequest, UsbDeviceState};
