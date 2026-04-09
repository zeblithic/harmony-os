// SPDX-License-Identifier: GPL-2.0-or-later

//! Hardware driver abstractions and implementations.
//!
//! All drivers use the [`RegisterBank`] trait for MMIO access,
//! enabling full unit testing without hardware.

pub mod cdc_ethernet;
pub mod console;
pub mod dma_pool;
pub mod dwc2;
pub mod dwc_usb;
pub mod ecm_gadget;
pub mod font_8x16;
pub mod framebuffer;
pub mod genet;
pub mod gpio;
pub mod hid_boot;
pub mod input_event;
pub mod mass_storage;
pub mod nvme;
pub mod pl011;
pub mod register_bank;
pub mod sdhci;
pub mod spi_bus;
pub mod tpm;

pub use register_bank::RegisterBank;
