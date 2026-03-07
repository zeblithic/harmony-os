// SPDX-License-Identifier: GPL-2.0-or-later
//! Athenaeum — 32-bit content-addressed chunk system.
//!
//! Translates 256-bit CID-addressed blobs into 32-bit-addressed
//! mini-blobs optimized for CPU cache lines and register widths.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod addr;
mod hash;
mod athenaeum;
mod book;

pub use addr::{ChunkAddr, Algorithm, Depth};
pub use athenaeum::{Athenaeum, CollisionError, MissingChunkError};
pub use book::{Book, BookEntry, BookError};
