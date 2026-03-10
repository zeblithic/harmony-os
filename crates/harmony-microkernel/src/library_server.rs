// SPDX-License-Identifier: GPL-2.0-or-later

//! LibraryServer -- read-only 9P file server for the virtual `/lib` namespace.
//!
//! Maps library filenames (e.g. `"ld-musl-aarch64.so.1"`) to raw ELF bytes.
//! The Linuxulator mounts this server at `/lib/` so that the dynamic linker
//! can resolve shared libraries via standard `open("/lib/libc.so")` calls.
//!
//! Design: flat namespace, no directories, no write support. Minimal surface.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{Fid, FileServer, FileStat, FileType, IpcError, OpenMode, QPath};

// ── Per-fid state ───────────────────────────────────────────────────

/// Tracks each fid's association with a library entry and open state.
#[derive(Debug, Clone)]
struct FidState {
    /// The library name this fid was walked to.
    name: Arc<str>,
    /// Stable file identity derived from the library name.
    qpath: QPath,
    /// Whether `open()` has been called on this fid.
    is_open: bool,
}

// ── LibraryServer ───────────────────────────────────────────────────

/// A read-only 9P file server that serves ELF library bytes.
///
/// The manifest is populated at construction time and is immutable
/// thereafter. Each entry maps a filename to its raw bytes.
pub struct LibraryServer {
    /// Library name -> raw ELF bytes.
    manifest: BTreeMap<Arc<str>, Vec<u8>>,
    /// Active fid -> state mapping.
    fids: BTreeMap<Fid, FidState>,
}

impl LibraryServer {
    /// Create a new LibraryServer with the given manifest.
    ///
    /// The manifest maps library filenames to their raw ELF bytes.
    /// Fid 0 is reserved as the root fid (representing the `/lib/`
    /// directory itself) but is not pre-allocated -- walks originate
    /// from the namespace layer which provides the root fid via
    /// `clone_fid`.
    pub fn new(manifest: BTreeMap<Arc<str>, Vec<u8>>) -> Self {
        Self {
            manifest,
            fids: BTreeMap::new(),
        }
    }

    /// Compute a stable QPath from a library name.
    ///
    /// Uses a simple FNV-1a hash to produce a 64-bit identifier.
    /// Collisions are unlikely given the small number of libraries
    /// in a typical manifest.
    fn qpath_for(name: &str) -> QPath {
        // FNV-1a 64-bit
        let mut h: u64 = 0xcbf29ce484222325;
        for b in name.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        // Ensure non-zero (zero is conventionally the root).
        h | 1
    }
}

impl FileServer for LibraryServer {
    fn walk(&mut self, _fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let key: Arc<str> = Arc::from(name);
        if !self.manifest.contains_key(&key) {
            return Err(IpcError::NotFound);
        }
        let qpath = Self::qpath_for(name);
        self.fids.insert(
            new_fid,
            FidState {
                name: key,
                qpath,
                is_open: false,
            },
        );
        Ok(qpath)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let state = self.fids.get_mut(&fid).ok_or(IpcError::InvalidFid)?;
        if mode != OpenMode::Read {
            return Err(IpcError::ReadOnly);
        }
        state.is_open = true;
        Ok(())
    }

    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if !state.is_open {
            return Err(IpcError::NotOpen);
        }
        let data = self
            .manifest
            .get(&state.name)
            .ok_or(IpcError::NotFound)?;
        let off = offset as usize;
        if off >= data.len() {
            return Ok(Vec::new());
        }
        let end = (off + count as usize).min(data.len());
        Ok(data[off..end].to_vec())
    }

    fn write(&mut self, _fid: Fid, _offset: u64, _data: &[u8]) -> Result<u32, IpcError> {
        Err(IpcError::ReadOnly)
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        self.fids.remove(&fid).ok_or(IpcError::InvalidFid)?;
        Ok(())
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        let data = self
            .manifest
            .get(&state.name)
            .ok_or(IpcError::NotFound)?;
        Ok(FileStat {
            qpath: state.qpath,
            name: Arc::clone(&state.name),
            size: data.len() as u64,
            file_type: FileType::Regular,
        })
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        if self.fids.contains_key(&new_fid) {
            return Err(IpcError::InvalidFid);
        }
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        let qpath = state.qpath;
        let cloned = FidState {
            name: Arc::clone(&state.name),
            qpath,
            is_open: false,
        };
        self.fids.insert(new_fid, cloned);
        Ok(qpath)
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a LibraryServer with a single test library.
    fn test_server() -> LibraryServer {
        let mut manifest = BTreeMap::new();
        manifest.insert(Arc::from("libc.so"), vec![0x7f, b'E', b'L', b'F', 1, 2, 3, 4]);
        manifest.insert(
            Arc::from("ld-musl-aarch64.so.1"),
            vec![0x7f, b'E', b'L', b'F', 5, 6, 7, 8, 9, 10],
        );
        LibraryServer::new(manifest)
    }

    #[test]
    fn walk_existing_library() {
        let mut srv = test_server();
        let result = srv.walk(0, 1, "libc.so");
        assert!(result.is_ok());
        let qpath = result.unwrap();
        assert_ne!(qpath, 0, "qpath should be non-zero");
    }

    #[test]
    fn walk_nonexistent_library() {
        let mut srv = test_server();
        let result = srv.walk(0, 1, "nonexistent.so");
        assert_eq!(result, Err(IpcError::NotFound));
    }

    #[test]
    fn open_and_read() {
        let mut srv = test_server();
        srv.walk(0, 1, "libc.so").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 0, 1024).unwrap();
        assert_eq!(data, vec![0x7f, b'E', b'L', b'F', 1, 2, 3, 4]);
    }

    #[test]
    fn read_with_offset() {
        let mut srv = test_server();
        srv.walk(0, 1, "ld-musl-aarch64.so.1").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 4, 3).unwrap();
        assert_eq!(data, vec![5, 6, 7]);
    }

    #[test]
    fn read_past_eof() {
        let mut srv = test_server();
        srv.walk(0, 1, "libc.so").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        // Offset == file length
        let data = srv.read(1, 8, 100).unwrap();
        assert!(data.is_empty());
        // Offset far past EOF
        let data = srv.read(1, 9999, 100).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn stat_returns_size() {
        let mut srv = test_server();
        srv.walk(0, 1, "libc.so").unwrap();
        let st = srv.stat(1).unwrap();
        assert_eq!(st.size, 8);
        assert_eq!(&*st.name, "libc.so");
        assert_eq!(st.file_type, FileType::Regular);
    }

    #[test]
    fn clunk_releases_fid() {
        let mut srv = test_server();
        srv.walk(0, 1, "libc.so").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        srv.clunk(1).unwrap();
        // Subsequent read should fail with InvalidFid
        assert_eq!(srv.read(1, 0, 100), Err(IpcError::InvalidFid));
    }

    #[test]
    fn write_rejected() {
        let mut srv = test_server();
        srv.walk(0, 1, "libc.so").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let result = srv.write(1, 0, &[0xDE, 0xAD]);
        assert_eq!(result, Err(IpcError::ReadOnly));
    }

    #[test]
    fn read_without_open() {
        let mut srv = test_server();
        srv.walk(0, 1, "libc.so").unwrap();
        // Do NOT call open
        let result = srv.read(1, 0, 100);
        assert_eq!(result, Err(IpcError::NotOpen));
    }

    #[test]
    fn clone_fid_duplicates_state() {
        let mut srv = test_server();
        srv.walk(0, 1, "libc.so").unwrap();
        let qpath = srv.clone_fid(1, 2).unwrap();
        // Clone should produce same qpath
        assert_eq!(qpath, LibraryServer::qpath_for("libc.so"));
        // The cloned fid should be walkable to stat but not yet open
        let st = srv.stat(2).unwrap();
        assert_eq!(&*st.name, "libc.so");
        assert_eq!(srv.read(2, 0, 100), Err(IpcError::NotOpen));
    }

    #[test]
    fn clone_fid_invalid_source() {
        let mut srv = test_server();
        assert_eq!(srv.clone_fid(99, 1), Err(IpcError::InvalidFid));
    }

    #[test]
    fn clone_fid_duplicate_target() {
        let mut srv = test_server();
        srv.walk(0, 1, "libc.so").unwrap();
        srv.walk(0, 2, "libc.so").unwrap();
        // Target fid 2 already in use
        assert_eq!(srv.clone_fid(1, 2), Err(IpcError::InvalidFid));
    }

    #[test]
    fn open_write_mode_rejected() {
        let mut srv = test_server();
        srv.walk(0, 1, "libc.so").unwrap();
        assert_eq!(srv.open(1, OpenMode::Write), Err(IpcError::ReadOnly));
        assert_eq!(srv.open(1, OpenMode::ReadWrite), Err(IpcError::ReadOnly));
    }

    #[test]
    fn read_partial_at_end() {
        let mut srv = test_server();
        srv.walk(0, 1, "libc.so").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        // Request more bytes than available from offset 6
        let data = srv.read(1, 6, 100).unwrap();
        assert_eq!(data, vec![3, 4]);
    }
}
