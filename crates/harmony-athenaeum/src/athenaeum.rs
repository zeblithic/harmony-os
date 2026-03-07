// SPDX-License-Identifier: GPL-2.0-or-later
//! Athenaeum — blob chunking and collision resolution.

/// Error when all 4 algorithms produce collisions for a chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollisionError {
    pub chunk_index: usize,
}

/// Error when a chunk is missing during reassembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingChunkError {
    pub chunk_index: usize,
}

/// An athenaeum — maps a blob into content-addressed chunks.
pub struct Athenaeum;
