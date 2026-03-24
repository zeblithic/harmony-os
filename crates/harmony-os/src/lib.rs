// SPDX-License-Identifier: GPL-2.0-or-later

//! # Harmony OS (Ring 3)
//!
//! Full operating system built on the microkernel foundation.

#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
pub mod config_applicator;
#[cfg(feature = "std")]
pub mod disk_book_store;
pub mod elf;
pub mod elf_loader;
pub mod linuxulator;
#[cfg(feature = "std")]
pub mod mesh_nar_source;
#[cfg(feature = "std")]
pub mod nar_publisher;
pub mod narinfo;
pub mod nix_base32;
#[cfg(feature = "std")]
pub mod nix_binary_cache;
#[cfg(feature = "std")]
pub mod nix_store_fetcher;
#[cfg(feature = "std")]
pub mod persistent_nar_store;
