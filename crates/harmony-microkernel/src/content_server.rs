// SPDX-License-Identifier: GPL-2.0-or-later
//! ContentServer — content-addressed 9P file server for Ring 2.
//!
//! Exposes a virtual filesystem:
//!
//! ```text
//! /
//! ├── blobs/       — one file per stored blob, named by hex CID
//! ├── pages/       — one file per stored page, named by hex hash_bits
//! └── ingest       — ctl-file; write blob bytes, read to finalize (returns CID + metadata)
//! ```

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use harmony_athenaeum::{sha256_hash, Book, PageAddr, BOOK_MAX_SIZE};

use crate::{Fid, FileServer, FileStat, FileType, IpcError, OpenMode, QPath};

/// Maximum concurrent ingest sessions. Each session can buffer up to
/// `BOOK_MAX_SIZE` (1 MB), so this caps ingest memory at 4 MB.
const MAX_CONCURRENT_INGESTS: usize = 4;

// ── QPath constants ─────────────────────────────────────────────────

const ROOT: QPath = 0;
const BLOBS_DIR: QPath = 1;
const PAGES_DIR: QPath = 2;
const INGEST: QPath = 3;
/// Blob QPaths: `BLOB_QPATH_BASE | u64_from_cid[0..8] & 0x7FFF_FFFF_FFFF_FFFF`.
/// Bit 32 is always set (via OR), so minimum blob QPath is `0x1_0000_0000`.
/// Page QPaths: `0x1000_0000 + hash_bits` (hash_bits is 28 bits, max 0x0FFF_FFFF).
/// These ranges are disjoint: pages top out at 0x1FFF_FFFF, blobs start at 0x1_0000_0000.
const BLOB_QPATH_BASE: QPath = 0x1_0000_0000;
const PAGE_QPATH_BASE: QPath = 0x1000_0000;

// ── Node taxonomy ───────────────────────────────────────────────────

/// What kind of virtual-filesystem node a fid points at.
#[derive(Debug, Clone)]
enum NodeKind {
    Root,
    BlobsDir,
    PagesDir,
    Ingest,
    Blob([u8; 32]),
    Page(PageAddr),
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
    /// Finalized — cached response available for re-reading.
    /// The response is retained so that partial reads (small `count` or
    /// nonzero `offset`) can be retried without losing data.
    Done(Vec<u8>),
}

// ── ContentServer ───────────────────────────────────────────────────

/// A content-addressed 9P file server backed by Book/PageAddr.
///
/// Stores blobs (identified by 256-bit CID) and their constituent
/// pages (identified by `PageAddr`). New content enters via the
/// `/ingest` pseudo-file: write the raw blob bytes, then **read** to
/// finalize. The server pages the data, computes the CID, and stores
/// both the blob manifest and individual page data. Clunking the
/// ingest fid without reading first silently discards the buffer.
pub struct ContentServer {
    /// Page data keyed by `hash_bits` (28-bit address).
    /// O(log n) lookups instead of linear scan through a Vec.
    pages: BTreeMap<u32, (PageAddr, Vec<u8>)>,
    /// Blob manifests indexed by 256-bit CID.
    blobs: BTreeMap<[u8; 32], Book>,
    /// Active fid → state mapping.
    fids: BTreeMap<Fid, FidState>,
    /// Per-fid ingest buffers for the `/ingest` pseudo-file.
    ingest_buffers: BTreeMap<Fid, IngestState>,
}

impl ContentServer {
    /// Create a new, empty ContentServer with fid 0 attached to the root.
    pub fn new() -> Self {
        let mut fids = BTreeMap::new();
        fids.insert(
            0,
            FidState {
                qpath: ROOT,
                node: NodeKind::Root,
                is_open: false,
                mode: None,
            },
        );
        Self {
            pages: BTreeMap::new(),
            blobs: BTreeMap::new(),
            fids,
            ingest_buffers: BTreeMap::new(),
        }
    }

    /// Compute the QPath for a blob given its CID.
    ///
    /// Uses 8 CID bytes (63 usable bits) to minimise collision probability.
    /// With 32 bits the birthday bound was ~65K blobs; with 63 bits it's ~3 billion.
    fn blob_qpath(cid: &[u8; 32]) -> QPath {
        let bits = u64::from_le_bytes(cid[0..8].try_into().unwrap());
        BLOB_QPATH_BASE | (bits & 0x7FFF_FFFF_FFFF_FFFF)
    }

    /// Compute the QPath for a page given its address.
    fn page_qpath(addr: &PageAddr) -> QPath {
        PAGE_QPATH_BASE + addr.hash_bits() as u64
    }

    /// Number of blobs currently stored.
    pub fn blob_count(&self) -> usize {
        self.blobs.len()
    }

    /// Number of pages currently stored.
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// Find a page by its `hash_bits` value.
    ///
    /// Returns the first page whose 28-bit `hash_bits` matches. Within a
    /// single `Book`, addresses are unique by construction (collision
    /// resolution). Across independently ingested blobs a hash_bits collision
    /// is theoretically possible; in that case the first stored match wins.
    /// The `/pages/<addr>` namespace inherits this: two pages sharing
    /// hash_bits would map to the same filename and only the first is reachable.
    fn find_page(&self, hash_bits: u32) -> Option<&PageAddr> {
        self.pages.get(&hash_bits).map(|(addr, _)| addr)
    }

    /// Finalize an ingest: page the blob, store pages + metadata, return 40-byte response.
    fn finalize_ingest(&mut self, fid: Fid) -> Result<Vec<u8>, IpcError> {
        let buf = self
            .ingest_buffers
            .get_mut(&fid)
            .ok_or(IpcError::InvalidArgument)?;
        // Peek before transitioning — errors must not poison the fid.
        // Note: BOOK_MAX_SIZE is enforced in write(), so no size check needed here.
        match buf {
            IngestState::Writing(v) if v.is_empty() => {
                return Err(IpcError::InvalidArgument); // read before write
            }
            IngestState::Writing(_) => {} // validation passed, proceed
            IngestState::Done(ref response) => return Ok(response.clone()),
        }
        // All peeks passed — safe to transition.
        match core::mem::replace(buf, IngestState::Done(Vec::new())) {
            IngestState::Writing(data) => {
                let cid = sha256_hash(&data);

                // Dedup: skip if blob already exists.
                if self.blobs.contains_key(&cid) {
                    // Drop blob data early — only the CID is needed from here.
                    // Avoids holding up to 1 MB during the response build.
                    drop(data);
                    let book = &self.blobs[&cid];
                    let response = match self.build_ingest_response(&cid, book) {
                        Ok(r) => r,
                        Err(e) => {
                            // Restore with empty buffer. In practice unreachable:
                            // the Book was valid when first stored.
                            *self.ingest_buffers.get_mut(&fid).unwrap() =
                                IngestState::Writing(Vec::new());
                            return Err(e);
                        }
                    };
                    *self.ingest_buffers.get_mut(&fid).unwrap() =
                        IngestState::Done(response.clone());
                    return Ok(response);
                }

                // from_blob can fail with BookError::AllAlgorithmsCollide
                // (28-bit address space exhaustion). Size is enforced in write(),
                // so ResourceExhausted maps to the remaining failure mode.
                let book = match Book::from_blob(cid, &data) {
                    Ok(book) => book,
                    Err(_) => {
                        // Restore buffer so the fid isn't poisoned.
                        *self.ingest_buffers.get_mut(&fid).unwrap() =
                            IngestState::Writing(data);
                        return Err(IpcError::ResourceExhausted);
                    }
                };

                // Build response before committing pages — if this fails,
                // no side effects have occurred and we can restore the buffer.
                let response = match self.build_ingest_response(&cid, &book) {
                    Ok(r) => r,
                    Err(e) => {
                        *self.ingest_buffers.get_mut(&fid).unwrap() =
                            IngestState::Writing(data);
                        return Err(e);
                    }
                };

                // Split blob into 4KB page buffers (zero-padded).
                let page_bufs = book.page_data_from_blob(&data);

                // Two-pass page commit: validate first, then insert.
                // Detects cross-blob hash_bits collisions (different data at the
                // same 28-bit address) that would corrupt blob reassembly.
                // Uses algo 0 (Sha256Msb) as the default storage address.
                let mut to_insert = Vec::new();
                for (i, variants) in book.pages.iter().enumerate() {
                    let addr = *variants.first().expect("Book: page must have variants");
                    let hb = addr.hash_bits();
                    let page_data = &page_bufs[i];

                    if let Some((_, existing)) = self.pages.get(&hb) {
                        if *existing != *page_data {
                            // Cross-blob collision: same hash_bits, different content.
                            // Storing would silently corrupt reassembly for this blob.
                            // Conflict (not ResourceExhausted) distinguishes this from
                            // capacity errors — callers know the data is valid but clashes
                            // with existing page state.
                            //
                            // This is permanent for this blob on this server instance:
                            // the colliding page at `hb` won't change. Retrying the
                            // same blob data will always fail. The fid is restored to
                            // Writing so the caller can re-open for different data.
                            *self.ingest_buffers.get_mut(&fid).unwrap() =
                                IngestState::Writing(data);
                            return Err(IpcError::Conflict);
                        }
                        // Same content at same address — cross-blob dedup, skip.
                    } else {
                        to_insert.push((hb, addr, page_data.clone()));
                    }
                }

                // All validated — commit pages and blob (infallible from here).
                for (hb, addr, page_data) in to_insert {
                    self.pages.insert(hb, (addr, page_data));
                }

                self.blobs.insert(cid, book);
                // Cache response so partial/multiple reads work.
                *self.ingest_buffers.get_mut(&fid).unwrap() =
                    IngestState::Done(response.clone());
                Ok(response)
            }
            IngestState::Done(_) => unreachable!(), // handled by peek above
        }
    }

    /// Serialise the ingest response.
    ///
    /// ```text
    /// [0..32]  — 256-bit CID (raw bytes)
    /// [32..36] — page_count  as u32 little-endian
    /// [36..40] — blob_size   as u32 little-endian
    /// ```
    fn build_ingest_response(&self, cid: &[u8; 32], book: &Book) -> Result<Vec<u8>, IpcError> {
        let page_count =
            u32::try_from(book.page_count()).map_err(|_| IpcError::ResourceExhausted)?;
        let blob_size: u32 = book.blob_size;
        let mut response = Vec::with_capacity(40);
        response.extend_from_slice(cid);
        response.extend_from_slice(&page_count.to_le_bytes());
        response.extend_from_slice(&blob_size.to_le_bytes());
        Ok(response)
    }

    /// Read blob data by reassembling from stored pages.
    ///
    /// Note: reassembles the full blob on every call (O(N) page lookups,
    /// O(blob_size) allocation). Callers reading large blobs in small
    /// pieces should prefer a single large read or cache locally.
    fn read_blob(&self, cid: &[u8; 32], offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        let book = self.blobs.get(cid).ok_or(IpcError::NotFound)?;
        let pages = &self.pages;
        let data = book
            .reassemble(|idx| {
                let addr = *book.pages[idx as usize]
                    .first()
                    .expect("Book: page must have variants");
                pages.get(&addr.hash_bits()).map(|(_, d)| d.clone())
            })
            .map_err(|_| IpcError::NotFound)?;
        Ok(slice_data(&data, offset, count))
    }

    /// Read raw page data.
    fn read_page_data(
        &self,
        addr: &PageAddr,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>, IpcError> {
        let (_, data) = self
            .pages
            .get(&addr.hash_bits())
            .ok_or(IpcError::NotFound)?;
        Ok(slice_data(data, offset, count))
    }
}

impl Default for ContentServer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Slice helper ────────────────────────────────────────────────

/// Extract a sub-slice from `data` bounded by `offset` and `count`, clamped to data length.
fn slice_data(data: &[u8], offset: u64, count: u32) -> Vec<u8> {
    let off = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(data.len());
    let end = off.saturating_add(count as usize).min(data.len());
    data[off..end].to_vec()
}

// ── Hex helpers ─────────────────────────────────────────────────────

/// Parse a 64-character hex string into a 32-byte CID.
fn parse_hex_cid(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
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

/// Format a `PageAddr`'s `hash_bits` as an 8-character zero-padded lowercase hex string.
///
/// This is the canonical filename used under `/pages/` — e.g. `hash_bits = 0x0FFFFFFF`
/// → `"0fffffff"`. Clients must use this exact 8-character format when walking.
pub(crate) fn format_addr_hex(addr: &PageAddr) -> alloc::string::String {
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
                "pages" => (PAGES_DIR, NodeKind::PagesDir),
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
            NodeKind::PagesDir => {
                if name.len() != 8 {
                    return Err(IpcError::NotFound);
                }
                // Enforce lowercase hex to match the canonical format produced
                // by format_addr_hex (e.g. "0fffffff", not "0FFFFFFF").
                if name.bytes().any(|b| b.is_ascii_uppercase()) {
                    return Err(IpcError::NotFound);
                }
                let hash_bits =
                    u32::from_str_radix(name, 16).map_err(|_| IpcError::NotFound)?;
                let addr = *self.find_page(hash_bits).ok_or(IpcError::NotFound)?;
                (Self::page_qpath(&addr), NodeKind::Page(addr))
            }
            // Leaf nodes are not directories — cannot walk into them.
            NodeKind::Blob(_) | NodeKind::Page(_) | NodeKind::Ingest => {
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
            NodeKind::Root | NodeKind::BlobsDir | NodeKind::PagesDir => {
                if matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
                    return Err(IpcError::IsDirectory);
                }
            }
            NodeKind::Blob(_) | NodeKind::Page(_) => {
                if matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
                    return Err(IpcError::ReadOnly);
                }
            }
            NodeKind::Ingest => {
                // Ingest requires ReadWrite: writes accumulate blob data,
                // then a read triggers finalization and returns the CID.
                if !matches!(mode, OpenMode::ReadWrite) {
                    return Err(IpcError::PermissionDenied);
                }
                if self.ingest_buffers.len() >= MAX_CONCURRENT_INGESTS {
                    return Err(IpcError::ResourceExhausted);
                }
                self.ingest_buffers
                    .insert(fid, IngestState::Writing(Vec::new()));
            }
        }
        // Re-borrow mutably after the match (ingest_buffers insert released the borrow).
        let state = self.fids.get_mut(&fid).unwrap();
        state.is_open = true;
        state.mode = Some(mode);
        Ok(())
    }

    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if !state.is_open {
            return Err(IpcError::NotOpen);
        }
        if matches!(state.mode, Some(OpenMode::Write)) {
            return Err(IpcError::PermissionDenied);
        }
        match &state.node {
            NodeKind::Root | NodeKind::BlobsDir | NodeKind::PagesDir => {
                Err(IpcError::IsDirectory)
            }
            NodeKind::Ingest => {
                let response = self.finalize_ingest(fid)?;
                Ok(slice_data(&response, offset, count))
            }
            NodeKind::Blob(cid) => {
                let cid = *cid;
                self.read_blob(&cid, offset, count)
            }
            NodeKind::Page(addr) => {
                let addr = *addr;
                self.read_page_data(&addr, offset, count)
            }
        }
    }

    // NOTE: `_offset` is intentionally ignored for the ingest ctl-file.
    // Writes are always appended to the accumulation buffer regardless of
    // the requested offset, matching Plan 9 ctl-file conventions.
    fn write(&mut self, fid: Fid, _offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if !state.is_open {
            return Err(IpcError::NotOpen);
        }
        if matches!(state.mode, Some(OpenMode::Read)) {
            return Err(IpcError::PermissionDenied);
        }
        match &state.node {
            NodeKind::Root | NodeKind::BlobsDir | NodeKind::PagesDir => {
                Err(IpcError::IsDirectory)
            }
            NodeKind::Blob(_) | NodeKind::Page(_) => Err(IpcError::ReadOnly),
            NodeKind::Ingest => {
                let buf = self
                    .ingest_buffers
                    .get_mut(&fid)
                    .ok_or(IpcError::InvalidArgument)?;
                match buf {
                    IngestState::Writing(ref mut v) => {
                        let written =
                            u32::try_from(data.len()).map_err(|_| IpcError::ResourceExhausted)?;
                        if v.len().saturating_add(data.len()) > BOOK_MAX_SIZE {
                            return Err(IpcError::ResourceExhausted);
                        }
                        v.extend_from_slice(data);
                        Ok(written)
                    }
                    IngestState::Done(_) => Err(IpcError::InvalidArgument), // Already finalized
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
            NodeKind::PagesDir => Ok(FileStat {
                qpath: PAGES_DIR,
                name: Arc::from("pages"),
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
                let book = self.blobs.get(cid).ok_or(IpcError::NotFound)?;
                Ok(FileStat {
                    qpath: Self::blob_qpath(cid),
                    name: Arc::from(format_cid_hex(cid).as_str()),
                    size: book.blob_size as u64,
                    file_type: FileType::Regular,
                })
            }
            NodeKind::Page(addr) => {
                let (_, data) = self
                    .pages
                    .get(&addr.hash_bits())
                    .ok_or(IpcError::NotFound)?;
                Ok(FileStat {
                    qpath: Self::page_qpath(addr),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use harmony_athenaeum::PAGE_SIZE;

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
        assert_eq!(server.page_count(), 0);
        assert!(server.ingest_buffers.is_empty());
    }

    #[test]
    fn default_matches_new() {
        let server = ContentServer::default();
        assert_eq!(server.blob_count(), 0);
        assert_eq!(server.page_count(), 0);
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
    fn page_qpath_above_base() {
        let data = [0u8; PAGE_SIZE];
        let addr = PageAddr::from_data(&data, harmony_athenaeum::Algorithm::Sha256Msb);
        let q = ContentServer::page_qpath(&addr);
        assert!(q >= PAGE_QPATH_BASE);
    }

    #[test]
    fn qpath_ranges_are_disjoint() {
        // Maximum page QPath assuming 28-bit hash_bits (max 0x0FFF_FFFF).
        let max_page_qpath = PAGE_QPATH_BASE + 0x0FFF_FFFF;
        assert!(
            max_page_qpath < BLOB_QPATH_BASE,
            "page and blob QPath ranges overlap"
        );
    }

    // ── walk() tests ────────────────────────────────────────────────

    #[test]
    fn walk_root_to_blobs() {
        let mut server = ContentServer::new();
        let qpath = server.walk(0, 1, "blobs").unwrap();
        assert_eq!(qpath, BLOBS_DIR);
    }

    #[test]
    fn walk_root_to_pages() {
        let mut server = ContentServer::new();
        let qpath = server.walk(0, 1, "pages").unwrap();
        assert_eq!(qpath, PAGES_DIR);
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
    fn walk_root_chunks_not_found() {
        // Old "chunks" path no longer exists — must use "pages".
        let mut server = ContentServer::new();
        assert_eq!(server.walk(0, 1, "chunks"), Err(IpcError::NotFound));
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
        assert_eq!(server.walk(0, 1, "pages"), Err(IpcError::InvalidFid));
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

    #[test]
    fn walk_blobs_dir_multibyte_utf8_rejected() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "blobs").unwrap();
        // 62 ASCII chars + 'é' (2-byte UTF-8) = 64 bytes but not valid ASCII hex.
        // Must not panic — should return NotFound.
        let mut bad = alloc::string::String::from("aa".repeat(31));
        bad.push('é'); // 2 bytes in UTF-8
        assert_eq!(bad.len(), 64);
        assert_eq!(server.walk(1, 2, &bad), Err(IpcError::NotFound));
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
        assert_eq!(
            server.open(1, OpenMode::Read),
            Err(IpcError::PermissionDenied)
        );
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
        assert_eq!(
            server.open(1, OpenMode::ReadWrite),
            Err(IpcError::PermissionDenied)
        );
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

    #[test]
    fn stat_pages_dir() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "pages").unwrap();
        let stat = server.stat(1).unwrap();
        assert_eq!(stat.file_type, FileType::Directory);
        assert_eq!(&*stat.name, "pages");
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
        // Mode check (Read) fires before node-type check (IsDirectory)
        assert_eq!(server.write(1, 0, b"data"), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn write_without_open_rejected() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "ingest").unwrap();
        assert_eq!(server.write(1, 0, b"data"), Err(IpcError::NotOpen));
    }

    // ── read() tests ──────────────────────────────────────────────────

    #[test]
    fn ingest_and_read_back_metadata() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        let blob_data = alloc::vec![0xABu8; PAGE_SIZE];
        server.write(1, 0, &blob_data).unwrap();

        let response = server.read(1, 0, 256).unwrap();
        assert_eq!(response.len(), 40);

        let cid: [u8; 32] = response[..32].try_into().unwrap();
        let page_count = u32::from_le_bytes(response[32..36].try_into().unwrap());
        let blob_size = u32::from_le_bytes(response[36..40].try_into().unwrap());

        assert_eq!(cid, harmony_athenaeum::sha256_hash(&blob_data));
        assert_eq!(page_count, 1);
        assert_eq!(blob_size, PAGE_SIZE as u32);
        assert_eq!(server.blob_count(), 1);
        assert_eq!(server.page_count(), 1);
    }

    #[test]
    fn ingest_second_read_returns_cached_response() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        server.write(1, 0, &[0xCDu8; 100]).unwrap();
        let first = server.read(1, 0, 256).unwrap();
        assert_eq!(first.len(), 40);
        // Response is cached — subsequent reads return the same data.
        let second = server.read(1, 0, 256).unwrap();
        assert_eq!(second, first);
    }

    #[test]
    fn ingest_read_before_write_rejected() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        assert_eq!(server.read(1, 0, 256), Err(IpcError::InvalidArgument));
    }

    #[test]
    fn ingest_read_before_write_does_not_poison_fid() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        // Read before write — should fail but NOT poison the fid.
        assert_eq!(server.read(1, 0, 256), Err(IpcError::InvalidArgument));
        // Fid should still be usable: write then read to finalize.
        let blob_data = alloc::vec![0xBBu8; PAGE_SIZE];
        server.write(1, 0, &blob_data).unwrap();
        let response = server.read(1, 0, 256).unwrap();
        assert_eq!(response.len(), 40);
    }

    #[test]
    fn ingest_read_honors_offset_and_count() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        let blob_data = alloc::vec![0xCCu8; PAGE_SIZE];
        server.write(1, 0, &blob_data).unwrap();
        // Read only bytes 32..40 (page_count + blob_size portion of response)
        let slice = server.read(1, 32, 8).unwrap();
        assert_eq!(slice.len(), 8);
        let page_count = u32::from_le_bytes(slice[0..4].try_into().unwrap());
        let blob_size = u32::from_le_bytes(slice[4..8].try_into().unwrap());
        assert_eq!(page_count, 1);
        assert_eq!(blob_size, PAGE_SIZE as u32);
    }

    #[test]
    fn ingest_partial_reads_across_multiple_calls() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        let blob_data = alloc::vec![0xDDu8; PAGE_SIZE];
        server.write(1, 0, &blob_data).unwrap();
        // First read: CID only (first 32 bytes)
        let cid_bytes = server.read(1, 0, 32).unwrap();
        assert_eq!(cid_bytes.len(), 32);
        // Second read: metadata only (bytes 32..40) — response is cached
        let meta = server.read(1, 32, 8).unwrap();
        assert_eq!(meta.len(), 8);
        // Verify metadata is consistent
        let page_count = u32::from_le_bytes(meta[0..4].try_into().unwrap());
        let blob_size = u32::from_le_bytes(meta[4..8].try_into().unwrap());
        assert_eq!(page_count, 1);
        assert_eq!(blob_size, PAGE_SIZE as u32);
    }

    #[test]
    fn read_blob_by_cid() {
        let mut server = ContentServer::new();
        let blob_data = alloc::vec![0x42u8; 8000];
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        server.write(1, 0, &blob_data).unwrap();
        let response = server.read(1, 0, 256).unwrap();
        let cid_hex = format_cid_hex(&response[..32].try_into().unwrap());
        server.clunk(1).unwrap();

        server.walk(0, 2, "blobs").unwrap();
        server.walk(2, 3, &cid_hex).unwrap();
        server.open(3, OpenMode::Read).unwrap();
        let read_back = server.read(3, 0, 16384).unwrap();
        assert_eq!(read_back, blob_data);
    }

    #[test]
    fn read_blob_with_offset() {
        let mut server = ContentServer::new();
        let blob_data = alloc::vec![0xEFu8; PAGE_SIZE];
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        server.write(1, 0, &blob_data).unwrap();
        let response = server.read(1, 0, 256).unwrap();
        let cid_hex = format_cid_hex(&response[..32].try_into().unwrap());
        server.clunk(1).unwrap();

        server.walk(0, 2, "blobs").unwrap();
        server.walk(2, 3, &cid_hex).unwrap();
        server.open(3, OpenMode::Read).unwrap();
        let slice = server.read(3, 100, 50).unwrap();
        assert_eq!(slice.len(), 50);
        assert_eq!(slice, alloc::vec![0xEFu8; 50]);
    }

    #[test]
    fn read_directory_returns_is_directory() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "blobs").unwrap();
        server.open(1, OpenMode::Read).unwrap();
        assert_eq!(server.read(1, 0, 256), Err(IpcError::IsDirectory));
    }

    #[test]
    fn ingest_dedup_same_blob() {
        let mut server = ContentServer::new();
        let blob_data = alloc::vec![0xAAu8; PAGE_SIZE];

        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        server.write(1, 0, &blob_data).unwrap();
        server.read(1, 0, 256).unwrap();
        server.clunk(1).unwrap();
        assert_eq!(server.page_count(), 1);

        server.walk(0, 2, "ingest").unwrap();
        server.open(2, OpenMode::ReadWrite).unwrap();
        server.write(2, 0, &blob_data).unwrap();
        server.read(2, 0, 256).unwrap();
        server.clunk(2).unwrap();
        assert_eq!(server.page_count(), 1); // No new pages
        assert_eq!(server.blob_count(), 1); // No new blob
    }

    #[test]
    fn ingest_concurrent_limit_enforced() {
        let mut server = ContentServer::new();
        // Open MAX_CONCURRENT_INGESTS ingest fids — all should succeed.
        for i in 0..MAX_CONCURRENT_INGESTS {
            let fid = (i + 1) as Fid;
            server.walk(0, fid, "ingest").unwrap();
            server.open(fid, OpenMode::ReadWrite).unwrap();
        }
        // One more should be rejected.
        let extra_fid = (MAX_CONCURRENT_INGESTS + 1) as Fid;
        server.walk(0, extra_fid, "ingest").unwrap();
        assert_eq!(
            server.open(extra_fid, OpenMode::ReadWrite),
            Err(IpcError::ResourceExhausted)
        );
        // Clunking one frees a slot.
        server.clunk(1).unwrap();
        server.open(extra_fid, OpenMode::ReadWrite).unwrap();
    }

    #[test]
    fn ingest_oversized_blob_rejected_at_write_time() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        // Write up to exactly BOOK_MAX_SIZE — should succeed.
        let max = alloc::vec![0u8; BOOK_MAX_SIZE];
        server.write(1, 0, &max).unwrap();
        // One more byte exceeds the limit — rejected eagerly at write time.
        assert_eq!(
            server.write(1, 0, &[0xFF]),
            Err(IpcError::ResourceExhausted)
        );
    }

    #[test]
    fn ingest_oversized_write_does_not_poison_fid() {
        let mut server = ContentServer::new();
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        // Fill to exactly BOOK_MAX_SIZE.
        let max = alloc::vec![0u8; BOOK_MAX_SIZE];
        server.write(1, 0, &max).unwrap();
        // Exceed limit — rejected at write time.
        assert_eq!(
            server.write(1, 0, &[0xFF]),
            Err(IpcError::ResourceExhausted)
        );
        // Fid is NOT poisoned — the valid data is still in the buffer.
        // Reading should finalize successfully with the BOOK_MAX_SIZE data.
        let response = server.read(1, 0, 256).unwrap();
        assert_eq!(response.len(), 40);
    }

    #[test]
    fn ingest_detects_cross_blob_page_collision() {
        let mut server = ContentServer::new();

        // Determine what hash_bits a known blob's page would get.
        let blob_data = alloc::vec![0xFFu8; PAGE_SIZE];
        let cid = sha256_hash(&blob_data);
        let book = Book::from_blob(cid, &blob_data).unwrap();
        let addr = book.pages[0][0]; // algo 0
        let target_hb = addr.hash_bits();

        // Plant a conflicting page at that address with different data.
        let conflict = alloc::vec![0x00u8; PAGE_SIZE];
        server.pages.insert(target_hb, (addr, conflict));

        // Ingest the blob — should detect the collision and reject.
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        server.write(1, 0, &blob_data).unwrap();
        assert_eq!(server.read(1, 0, 256), Err(IpcError::Conflict));

        // Blob was not stored (no side effects from the failed ingest).
        assert_eq!(server.blob_count(), 0);
    }

    #[test]
    fn page_size_matches_book() {
        // Validate that PAGE_SIZE matches Book's behavior:
        // a blob of exactly PAGE_SIZE bytes should produce exactly 1 page.
        let data = alloc::vec![0xAAu8; PAGE_SIZE];
        let cid = harmony_athenaeum::sha256_hash(&data);
        let book = harmony_athenaeum::Book::from_blob(cid, &data).unwrap();
        assert_eq!(book.page_count(), 1);
        // A blob of PAGE_SIZE + 1 should produce exactly 2 pages.
        let data2 = alloc::vec![0xBBu8; PAGE_SIZE + 1];
        let cid2 = harmony_athenaeum::sha256_hash(&data2);
        let book2 = harmony_athenaeum::Book::from_blob(cid2, &data2).unwrap();
        assert_eq!(book2.page_count(), 2);
    }

    #[test]
    fn read_page_by_address() {
        let mut server = ContentServer::new();
        let blob_data = alloc::vec![0x77u8; PAGE_SIZE]; // single page
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        server.write(1, 0, &blob_data).unwrap();
        server.read(1, 0, 256).unwrap();
        server.clunk(1).unwrap();

        // Get the page address from storage
        assert_eq!(server.page_count(), 1);
        let (addr, _) = server.pages.values().next().unwrap();
        let addr_hex = format_addr_hex(addr);

        // Walk to the page and read it
        server.walk(0, 2, "pages").unwrap();
        server.walk(2, 3, &addr_hex).unwrap();
        server.open(3, OpenMode::Read).unwrap();
        let page_data = server.read(3, 0, 8192).unwrap();
        // All pages are exactly PAGE_SIZE (4KB), zero-padded
        assert_eq!(page_data.len(), PAGE_SIZE);
        assert_eq!(&page_data[..blob_data.len()], &blob_data[..]);
    }

    #[test]
    fn stat_blob_after_ingest() {
        let mut server = ContentServer::new();
        let blob_data = alloc::vec![0x55u8; PAGE_SIZE];
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        server.write(1, 0, &blob_data).unwrap();
        let response = server.read(1, 0, 256).unwrap();
        let cid_hex = format_cid_hex(&response[..32].try_into().unwrap());
        server.clunk(1).unwrap();

        server.walk(0, 2, "blobs").unwrap();
        server.walk(2, 3, &cid_hex).unwrap();
        let stat = server.stat(3).unwrap();
        assert_eq!(stat.file_type, FileType::Regular);
        assert_eq!(stat.size, PAGE_SIZE as u64);
        assert_eq!(&*stat.name, &*cid_hex);
    }

    #[test]
    fn stat_page_after_ingest() {
        let mut server = ContentServer::new();
        let blob_data = alloc::vec![0x33u8; PAGE_SIZE];
        server.walk(0, 1, "ingest").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        server.write(1, 0, &blob_data).unwrap();
        server.read(1, 0, 256).unwrap();
        server.clunk(1).unwrap();

        let (addr, page_data) = server.pages.values().next().unwrap();
        let addr_hex = format_addr_hex(addr);
        let expected_size = page_data.len() as u64;

        server.walk(0, 2, "pages").unwrap();
        server.walk(2, 3, &addr_hex).unwrap();
        let stat = server.stat(3).unwrap();
        assert_eq!(stat.file_type, FileType::Regular);
        assert_eq!(stat.size, expected_size);
        assert_eq!(&*stat.name, &*addr_hex);
    }
}
