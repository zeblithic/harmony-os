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

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let state = self.fids.get_mut(&fid).ok_or(IpcError::InvalidFid)?;
        if state.is_open {
            return Err(IpcError::PermissionDenied);
        }
        match &state.node {
            NodeKind::Root | NodeKind::BlobsDir | NodeKind::ChunksDir => {
                if matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
                    return Err(IpcError::IsDirectory);
                }
            }
            NodeKind::Blob(_) | NodeKind::Chunk(_) => {
                if matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
                    return Err(IpcError::ReadOnly);
                }
            }
            NodeKind::Ingest => {
                if !matches!(mode, OpenMode::ReadWrite) {
                    return Err(IpcError::PermissionDenied);
                }
                self.ingest_buffers.insert(fid, IngestState::Writing(Vec::new()));
            }
        }
        // Re-borrow mutably after the match (ingest_buffers insert released the borrow).
        let state = self.fids.get_mut(&fid).unwrap();
        state.is_open = true;
        state.mode = Some(mode);
        Ok(())
    }

    fn read(&mut self, _fid: Fid, _offset: u64, _count: u32) -> Result<Vec<u8>, IpcError> {
        Err(IpcError::NotSupported)
    }

    fn write(&mut self, fid: Fid, _offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if !state.is_open {
            return Err(IpcError::NotOpen);
        }
        match &state.node {
            NodeKind::Root | NodeKind::BlobsDir | NodeKind::ChunksDir => {
                Err(IpcError::IsDirectory)
            }
            NodeKind::Blob(_) | NodeKind::Chunk(_) => {
                Err(IpcError::ReadOnly)
            }
            NodeKind::Ingest => {
                let buf = self.ingest_buffers.get_mut(&fid).ok_or(IpcError::InvalidArgument)?;
                match buf {
                    IngestState::Writing(ref mut v) => {
                        v.extend_from_slice(data);
                        Ok(data.len() as u32)
                    }
                    _ => Err(IpcError::InvalidArgument), // Already finalized
                }
            }
        }
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        if fid == 0 {
            return Err(IpcError::PermissionDenied);
        }
        self.fids.remove(&fid).ok_or(IpcError::InvalidFid)?;
        self.ingest_buffers.remove(&fid);
        Ok(())
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        match &state.node {
            NodeKind::Root => Ok(FileStat {
                qpath: ROOT,
                name: Arc::from("store"),
                size: 0,
                file_type: FileType::Directory,
            }),
            NodeKind::BlobsDir => Ok(FileStat {
                qpath: BLOBS_DIR,
                name: Arc::from("blobs"),
                size: 0,
                file_type: FileType::Directory,
            }),
            NodeKind::ChunksDir => Ok(FileStat {
                qpath: CHUNKS_DIR,
                name: Arc::from("chunks"),
                size: 0,
                file_type: FileType::Directory,
            }),
            NodeKind::Ingest => Ok(FileStat {
                qpath: INGEST,
                name: Arc::from("ingest"),
                size: 0,
                file_type: FileType::Regular,
            }),
            NodeKind::Blob(cid) => {
                let ath = self.blobs.get(cid).ok_or(IpcError::NotFound)?;
                Ok(FileStat {
                    qpath: Self::blob_qpath(cid),
                    name: Arc::from(format_cid_hex(cid).as_str()),
                    size: ath.blob_size as u64,
                    file_type: FileType::Regular,
                })
            }
            NodeKind::Chunk(addr) => {
                let (_, data) = self
                    .chunks
                    .iter()
                    .find(|(a, _)| *a == *addr)
                    .ok_or(IpcError::NotFound)?;
                Ok(FileStat {
                    qpath: Self::chunk_qpath(addr),
                    name: Arc::from(format_addr_hex(addr).as_str()),
                    size: data.len() as u64,
                    file_type: FileType::Regular,
                })
            }
        }
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        if self.fids.contains_key(&new_fid) {
            return Err(IpcError::InvalidFid);
        }
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        let qpath = state.qpath;
        let node = state.node.clone();
        self.fids.insert(new_fid, FidState {
            qpath,
            node,
            is_open: false,
            mode: None,
        });
        Ok(qpath)
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

    // ── open/clunk/clone_fid/stat tests ────────────────────────────────

    #[test]
    fn open_and_clunk_ingest() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        server.clunk(1).unwrap();
    }

    #[test]
    fn open_ingest_read_only_rejected() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "ingest").unwrap();
        assert_eq!(server.open(1, OpenMode::Read), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn open_directory_write_rejected() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "blobs").unwrap();
        assert_eq!(server.open(1, OpenMode::Write), Err(IpcError::IsDirectory));
    }

    #[test]
    fn open_directory_read_ok() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "blobs").unwrap();
        server.open(1, OpenMode::Read).unwrap();
    }

    #[test]
    fn double_open_rejected() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        assert_eq!(server.open(1, OpenMode::ReadWrite), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn clunk_root_rejected() {
        let mut server = ContentServer::new();
        assert_eq!(server.clunk(0), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn clunk_invalid_fid() {
        let mut server = ContentServer::new();
        assert_eq!(server.clunk(99), Err(IpcError::InvalidFid));
    }

    #[test]
    fn clone_fid_root() {
        let mut server = ContentServer::new();
        let qpath = server.clone_fid(0, 5).unwrap();
        assert_eq!(qpath, ROOT);
    }

    #[test]
    fn stat_root() {
        let mut server = ContentServer::new();
        let stat = server.stat(0).unwrap();
        assert_eq!(stat.file_type, FileType::Directory);
        assert_eq!(&*stat.name, "store");
    }

    #[test]
    fn stat_ingest() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "ingest").unwrap();
        let stat = server.stat(1).unwrap();
        assert_eq!(stat.file_type, FileType::Regular);
        assert_eq!(&*stat.name, "ingest");
    }

    #[test]
    fn stat_blobs_dir() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "blobs").unwrap();
        let stat = server.stat(1).unwrap();
        assert_eq!(stat.file_type, FileType::Directory);
        assert_eq!(&*stat.name, "blobs");
    }

    // ── write() tests ─────────────────────────────────────────────────

    #[test]
    fn write_to_ingest_accumulates() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        let written = server.write(1, 0, b"hello").unwrap();
        assert_eq!(written, 5);
        let written = server.write(1, 0, b" world").unwrap();
        assert_eq!(written, 6);
    }

    #[test]
    fn write_to_directory_rejected() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "blobs").unwrap();
        server.open(1, OpenMode::Read).unwrap();
        assert_eq!(server.write(1, 0, b"data"), Err(IpcError::IsDirectory));
    }

    #[test]
    fn write_without_open_rejected() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "ingest").unwrap();
        assert_eq!(server.write(1, 0, b"data"), Err(IpcError::NotOpen));
    }
}
