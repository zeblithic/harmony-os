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

    /// Find a chunk by its `hash_bits` value.
    fn find_chunk(&self, hash_bits: u32) -> Option<&ChunkAddr> {
        self.chunks
            .iter()
            .find(|(addr, _)| addr.hash_bits() == hash_bits)
            .map(|(addr, _)| addr)
    }
}

impl Default for ContentServer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Hex helpers ─────────────────────────────────────────────────────

/// Parse a 64-character hex string into a 32-byte CID.
fn parse_hex_cid(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut cid = [0u8; 32];
    for i in 0..32 {
        cid[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(cid)
}

/// Format a 32-byte CID as 64-character lowercase hex.
pub(crate) fn format_cid_hex(cid: &[u8; 32]) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::with_capacity(64);
    for byte in cid {
        write!(s, "{:02x}", byte).unwrap();
    }
    s
}

/// Format a `ChunkAddr`'s `hash_bits` as 8-character lowercase hex.
pub(crate) fn format_addr_hex(addr: &ChunkAddr) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::with_capacity(8);
    write!(s, "{:08x}", addr.hash_bits()).unwrap();
    s
}

// ── FileServer impl ────────────────────────────────────────────────

impl FileServer for ContentServer {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        let parent_node = state.node.clone();

        if self.fids.contains_key(&new_fid) {
            return Err(IpcError::InvalidFid);
        }

        let (qpath, node) = match &parent_node {
            NodeKind::Root => match name {
                "blobs" => (BLOBS_DIR, NodeKind::BlobsDir),
                "chunks" => (CHUNKS_DIR, NodeKind::ChunksDir),
                "ingest" => (INGEST, NodeKind::Ingest),
                _ => return Err(IpcError::NotFound),
            },
            NodeKind::BlobsDir => {
                let cid = parse_hex_cid(name).ok_or(IpcError::NotFound)?;
                if !self.blobs.contains_key(&cid) {
                    return Err(IpcError::NotFound);
                }
                (Self::blob_qpath(&cid), NodeKind::Blob(cid))
            }
            NodeKind::ChunksDir => {
                if name.len() != 8 {
                    return Err(IpcError::NotFound);
                }
                let hash_bits =
                    u32::from_str_radix(name, 16).map_err(|_| IpcError::NotFound)?;
                let addr = *self.find_chunk(hash_bits).ok_or(IpcError::NotFound)?;
                (Self::chunk_qpath(&addr), NodeKind::Chunk(addr))
            }
            // Leaf nodes are not directories — cannot walk into them.
            NodeKind::Blob(_) | NodeKind::Chunk(_) | NodeKind::Ingest => {
                return Err(IpcError::NotDirectory);
            }
        };

        self.fids.insert(
            new_fid,
            FidState {
                qpath,
                node,
                is_open: false,
                mode: None,
            },
        );
        Ok(qpath)
    }

    fn open(&mut self, _fid: Fid, _mode: OpenMode) -> Result<(), IpcError> {
        Err(IpcError::NotSupported)
    }

    fn read(&mut self, _fid: Fid, _offset: u64, _count: u32) -> Result<Vec<u8>, IpcError> {
        Err(IpcError::NotSupported)
    }

    fn write(&mut self, _fid: Fid, _offset: u64, _data: &[u8]) -> Result<u32, IpcError> {
        Err(IpcError::NotSupported)
    }

    fn clunk(&mut self, _fid: Fid) -> Result<(), IpcError> {
        Err(IpcError::NotSupported)
    }

    fn stat(&mut self, _fid: Fid) -> Result<FileStat, IpcError> {
        Err(IpcError::NotSupported)
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

    // ── walk() tests ────────────────────────────────────────────────

    #[test]
    fn walk_root_to_blobs() {
        let mut server = ContentServer::new();
        let qpath = server.walk(0, 1, "blobs").unwrap();
        assert_eq!(qpath, BLOBS_DIR);
    }

    #[test]
    fn walk_root_to_chunks() {
        let mut server = ContentServer::new();
        let qpath = server.walk(0, 1, "chunks").unwrap();
        assert_eq!(qpath, CHUNKS_DIR);
    }

    #[test]
    fn walk_root_to_ingest() {
        let mut server = ContentServer::new();
        let qpath = server.walk(0, 1, "ingest").unwrap();
        assert_eq!(qpath, INGEST);
    }

    #[test]
    fn walk_root_not_found() {
        let mut server = ContentServer::new();
        assert_eq!(server.walk(0, 1, "nonexistent"), Err(IpcError::NotFound));
    }

    #[test]
    fn walk_invalid_source_fid() {
        let mut server = ContentServer::new();
        assert_eq!(server.walk(99, 1, "blobs"), Err(IpcError::InvalidFid));
    }

    #[test]
    fn walk_duplicate_new_fid() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "blobs").unwrap();
        assert_eq!(server.walk(0, 1, "chunks"), Err(IpcError::InvalidFid));
    }

    #[test]
    fn walk_from_non_directory() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "ingest").unwrap();
        assert_eq!(server.walk(1, 2, "anything"), Err(IpcError::NotDirectory));
    }

    #[test]
    fn walk_blobs_dir_missing_cid() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "blobs").unwrap();
        let fake_cid = "aa".repeat(32); // 64 hex chars
        assert_eq!(server.walk(1, 2, &fake_cid), Err(IpcError::NotFound));
    }
}
