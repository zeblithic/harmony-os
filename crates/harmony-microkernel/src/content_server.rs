// SPDX-License-Identifier: GPL-2.0-or-later
//! ContentServer — content-addressed 9P file server for Ring 2.
//!
//! Exposes a virtual filesystem:
//!
//! ```text
//! /
//! ├── blobs/       — one file per stored blob, named by hex CID
//! ├── chunks/      — one file per stored chunk, named by hex hash_bits
//! └── ingest       — write-only file; write blob bytes, close to finalize
//! ```

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use harmony_athenaeum::ChunkAddr;
use harmony_athenaeum::Athenaeum;

use crate::{Fid, QPath, OpenMode, FileType, FileStat, IpcError, FileServer};

// ── QPath constants ─────────────────────────────────────────────────

const ROOT: QPath = 0;
const BLOBS_DIR: QPath = 1;
const CHUNKS_DIR: QPath = 2;
const INGEST: QPath = 3;
const BLOB_QPATH_BASE: QPath = 0x1000;
const CHUNK_QPATH_BASE: QPath = 0x100_0000;

// ── Node taxonomy ───────────────────────────────────────────────────

/// What kind of virtual-filesystem node a fid points at.
#[derive(Debug, Clone)]
enum NodeKind {
    Root,
    BlobsDir,
    ChunksDir,
    Ingest,
    Blob([u8; 32]),
    Chunk(ChunkAddr),
}

// ── Per-fid state ───────────────────────────────────────────────────

/// Tracks every fid's position in the namespace tree plus open state.
#[derive(Debug, Clone)]
struct FidState {
    qpath: QPath,
    node: NodeKind,
    is_open: bool,
    mode: Option<OpenMode>,
}

// ── Ingest pipeline ─────────────────────────────────────────────────

/// Tracks the state of an in-progress blob ingest via the `/ingest` file.
#[derive(Debug)]
enum IngestState {
    /// Accumulating bytes from successive writes.
    Writing(Vec<u8>),
    /// SHA-256 computed, blob + chunks stored, awaiting clunk.
    Finalized(Vec<u8>),
    /// Clunked — no longer active.
    Done,
}

// ── ContentServer ───────────────────────────────────────────────────

/// A content-addressed 9P file server backed by Athenaeum.
///
/// Stores blobs (identified by 256-bit CID) and their constituent
/// chunks (identified by `ChunkAddr`). New content enters via the
/// `/ingest` pseudo-file: write the raw blob bytes, then clunk to
/// finalize. The server chunks the data, computes the CID, and stores
/// both the blob manifest and individual chunk data.
pub struct ContentServer {
    /// Chunk data indexed by (hash_bits, raw ChunkAddr fields).
    /// Uses a Vec because ChunkAddr does not implement Ord.
    chunks: Vec<(ChunkAddr, Vec<u8>)>,
    /// Blob manifests indexed by 256-bit CID.
    blobs: BTreeMap<[u8; 32], Athenaeum>,
    /// Active fid → state mapping.
    fids: BTreeMap<Fid, FidState>,
    /// Per-fid ingest buffers for the `/ingest` pseudo-file.
    ingest_buffers: BTreeMap<Fid, IngestState>,
}

impl ContentServer {
    /// Create a new, empty ContentServer with fid 0 attached to the root.
    pub fn new() -> Self {
        let mut fids = BTreeMap::new();
        fids.insert(0, FidState {
            qpath: ROOT,
            node: NodeKind::Root,
            is_open: false,
            mode: None,
        });
        Self {
            chunks: Vec::new(),
            blobs: BTreeMap::new(),
            fids,
            ingest_buffers: BTreeMap::new(),
        }
    }

    /// Compute the QPath for a blob given its CID.
    fn blob_qpath(cid: &[u8; 32]) -> QPath {
        let bits = u32::from_le_bytes([cid[0], cid[1], cid[2], cid[3]]);
        BLOB_QPATH_BASE + bits as u64
    }

    /// Compute the QPath for a chunk given its address.
    fn chunk_qpath(addr: &ChunkAddr) -> QPath {
        CHUNK_QPATH_BASE + addr.hash_bits() as u64
    }

    /// Number of blobs currently stored.
    pub fn blob_count(&self) -> usize {
        self.blobs.len()
    }

    /// Number of chunks currently stored.
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }
}

impl Default for ContentServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_content_server_has_root_fid() {
        let server = ContentServer::new();
        let state = server.fids.get(&0).unwrap();
        assert_eq!(state.qpath, ROOT);
        assert!(!state.is_open);
    }

    #[test]
    fn new_content_server_is_empty() {
        let server = ContentServer::new();
        assert_eq!(server.blob_count(), 0);
        assert_eq!(server.chunk_count(), 0);
        assert!(server.ingest_buffers.is_empty());
    }

    #[test]
    fn default_matches_new() {
        let server = ContentServer::default();
        assert_eq!(server.blob_count(), 0);
        assert_eq!(server.chunk_count(), 0);
        assert!(server.fids.contains_key(&0));
    }

    #[test]
    fn blob_qpath_deterministic() {
        let cid = [0xAB; 32];
        let q1 = ContentServer::blob_qpath(&cid);
        let q2 = ContentServer::blob_qpath(&cid);
        assert_eq!(q1, q2);
        assert!(q1 >= BLOB_QPATH_BASE);
    }

    #[test]
    fn chunk_qpath_above_base() {
        use harmony_athenaeum::{ChunkAddr, Depth};
        let addr = ChunkAddr::from_data(b"test chunk data for qpath", Depth::Blob, 0);
        let q = ContentServer::chunk_qpath(&addr);
        assert!(q >= CHUNK_QPATH_BASE);
    }
}
