// SPDX-License-Identifier: GPL-2.0-or-later
//! ChunkAddr — 32-bit content-addressed chunk identifier.

/// Hash algorithm selector for address derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Algorithm {
    Sha256Msb = 0,
    Sha256Lsb = 1,
    Sha224Msb = 2,
    Sha224Lsb = 3,
}

/// Chunk nesting depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Depth {
    Blob = 0,
    Bundle1 = 1,
    Bundle2 = 2,
    Bundle3 = 3,
}

/// A 32-bit content-addressed chunk identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChunkAddr(pub(crate) u32);
