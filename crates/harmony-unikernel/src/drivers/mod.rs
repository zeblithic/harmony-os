// SPDX-License-Identifier: GPL-2.0-or-later

//! Hardware driver abstractions and implementations.
//!
//! All drivers use the [`RegisterBank`] trait for MMIO access,
//! enabling full unit testing without hardware.

pub mod console;
pub mod dma_pool;
pub mod dwc_usb;
pub mod font_8x16;
pub mod framebuffer;
pub mod genet;
pub mod gpio;
pub mod mass_storage;
pub mod nvme;
pub mod pl011;
pub mod register_bank;
pub mod sdhci;
pub mod spi_bus;

pub use register_bank::RegisterBank;
