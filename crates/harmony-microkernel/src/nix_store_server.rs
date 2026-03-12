// SPDX-License-Identifier: GPL-2.0-or-later

//! NixStoreServer — read-only 9P file server for `/nix/store`.
//!
//! Maps Nix store paths to their NAR-archived contents. Each imported
//! store path is parsed into a `NarArchive` for directory traversal,
//! while the original NAR blob is retained for zero-copy file reads.
//!
//! Design: multi-level namespace (store → store-path → NAR tree),
//! no write support. FidTracker-based lifecycle management.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fid_tracker::FidTracker;
use crate::nar::{NarArchive, NarEntry, NarError};
use crate::{Fid, FileServer, FileStat, FileType, IpcError, OpenMode, QPath};

#[cfg(feature = "std")]
use std::sync::Mutex;

// ── Types ─────────────────────────────────────────────────────────────

/// A single imported store path: the raw NAR blob (for zero-copy reads)
/// plus the parsed archive (for directory traversal).
struct StorePath {
    nar_blob: Vec<u8>,
    archive: NarArchive,
}

/// Per-fid payload identifying what a fid points to.
#[derive(Clone)]
enum NixFidPayload {
    /// The root `/nix/store` directory itself.
    Root,
    /// A store path root (e.g. `/nix/store/abc123-hello`).
    StorePathRoot { name: Arc<str> },
    /// An entry inside a store path's NAR tree.
    Entry {
        store_name: Arc<str>,
        path: Arc<str>,
    },
}

/// A read-only 9P file server backed by NAR archives.
///
/// Store paths are imported via `import_nar` and served as a virtual
/// filesystem rooted at `/nix/store`.
pub struct NixStoreServer {
    store_paths: BTreeMap<Arc<str>, StorePath>,
    tracker: FidTracker<NixFidPayload>,
    misses: Vec<Arc<str>>,
}

// ── Helpers ───────────────────────────────────────────────────────────

/// FNV-1a 64-bit hash, OR'd with 1 to ensure non-zero.
fn qpath_for(path: &str) -> QPath {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in path.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h | 1
}

/// Map a `NarEntry` to the corresponding `FileType`.
///
/// Symlinks are reported as `Regular` because `FileType` has no symlink
/// variant. The server returns symlink targets as opaque byte content;
/// symlink resolution is the Linuxulator's responsibility (it already
/// needs `readlink` for Linux compat). When `FileType::Symlink` is
/// added, this mapping should be updated.
fn file_type_of(entry: &NarEntry) -> FileType {
    match entry {
        NarEntry::Directory { .. } => FileType::Directory,
        NarEntry::Regular { .. } | NarEntry::Symlink { .. } => FileType::Regular,
    }
}

/// Compute the logical size of a `NarEntry`.
fn size_of(entry: &NarEntry) -> u64 {
    match entry {
        NarEntry::Regular { contents_len, .. } => *contents_len as u64,
        NarEntry::Symlink { target } => target.len() as u64,
        // Convention: directories report size 0 (matches LibraryServer, ContentServer).
        NarEntry::Directory { .. } => 0,
    }
}

/// Extract the final path component (the part after the last `/`).
fn final_component(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

// ── NixStoreServer ────────────────────────────────────────────────────

impl Default for NixStoreServer {
    fn default() -> Self {
        Self::new()
    }
}

impl NixStoreServer {
    /// Create a new, empty `NixStoreServer`.
    pub fn new() -> Self {
        Self {
            store_paths: BTreeMap::new(),
            tracker: FidTracker::new(0, NixFidPayload::Root),
            misses: Vec::new(),
        }
    }

    /// Import a NAR archive as a store path.
    ///
    /// `name` is the store path name (e.g. `"abc123-hello"`).
    /// `nar_bytes` is the raw NAR blob.
    ///
    /// # Errors
    ///
    /// Returns `NarError::InvalidString` if `name` is malformed (empty,
    /// contains `/`, `\0`, `\n`, `\r`, or is `.`/`..`).
    /// Returns `NarError::DuplicateEntry` if `name` is already imported.
    /// All other `NarError` variants come from parsing the NAR blob itself.
    pub fn import_nar(&mut self, name: &str, nar_bytes: Vec<u8>) -> Result<(), NarError> {
        // Validate store-path name — same constraints as NAR entry names.
        // Listings use '\n' as separator, so newlines would create ambiguous output.
        if name.is_empty()
            || name.contains('/')
            || name.contains('\0')
            || name.contains('\n')
            || name.contains('\r')
            || name == "."
            || name == ".."
        {
            return Err(NarError::InvalidString);
        }
        // Check for duplicates before the expensive parse.
        if self.store_paths.contains_key(name) {
            return Err(NarError::DuplicateEntry);
        }
        let archive = NarArchive::parse(&nar_bytes)?;
        let key: Arc<str> = Arc::from(name);
        self.store_paths.insert(
            key,
            StorePath {
                nar_blob: nar_bytes,
                archive,
            },
        );
        Ok(())
    }

    /// Drain all recorded miss events (store path names that were walked
    /// but not found). The fetcher calls this periodically to discover
    /// which store paths need fetching.
    pub fn drain_misses(&mut self) -> Vec<Arc<str>> {
        core::mem::take(&mut self.misses)
    }

    /// Build the full path string for qpath computation from a payload.
    fn full_path(payload: &NixFidPayload) -> String {
        match payload {
            NixFidPayload::Root => String::from("store"),
            NixFidPayload::StorePathRoot { name } => {
                let mut s = String::from("store/");
                s.push_str(name);
                s
            }
            NixFidPayload::Entry { store_name, path } => {
                let mut s = String::from("store/");
                s.push_str(store_name);
                s.push('/');
                s.push_str(path);
                s
            }
        }
    }

    /// Read bytes from a NAR entry (file contents, directory listing,
    /// or symlink target).
    fn read_entry_data(
        &self,
        sp: &StorePath,
        entry: &NarEntry,
        offset: u64,
        count: u32,
    ) -> Vec<u8> {
        match entry {
            NarEntry::Regular {
                contents_offset,
                contents_len,
                ..
            } => {
                let off = usize::try_from(offset).unwrap_or(usize::MAX);
                if off >= *contents_len {
                    return Vec::new();
                }
                let start = contents_offset.saturating_add(off);
                let end = start
                    .saturating_add(count as usize)
                    .min(contents_offset.saturating_add(*contents_len));
                sp.nar_blob[start..end].to_vec()
            }
            NarEntry::Symlink { target } => {
                let bytes = target.as_bytes();
                let off = usize::try_from(offset).unwrap_or(usize::MAX);
                if off >= bytes.len() {
                    return Vec::new();
                }
                let end = off.saturating_add(count as usize).min(bytes.len());
                bytes[off..end].to_vec()
            }
            NarEntry::Directory { entries } => {
                let mut listing = String::new();
                for name in entries.keys() {
                    listing.push_str(name);
                    listing.push('\n');
                }
                let bytes = listing.as_bytes();
                let off = usize::try_from(offset).unwrap_or(usize::MAX);
                if off >= bytes.len() {
                    return Vec::new();
                }
                let end = off.saturating_add(count as usize).min(bytes.len());
                bytes[off..end].to_vec()
            }
        }
    }
}

impl FileServer for NixStoreServer {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let entry = self.tracker.get(fid)?;
        let payload = entry.payload.clone();

        let new_payload = match &payload {
            NixFidPayload::Root => {
                // Walk from root to a store path.
                let key: Arc<str> = Arc::from(name);
                if !self.store_paths.contains_key(&key) {
                    self.misses.push(Arc::clone(&key));
                    return Err(IpcError::NotFound);
                }
                NixFidPayload::StorePathRoot { name: key }
            }
            NixFidPayload::StorePathRoot { name: store_name } => {
                // Walk from store path root into the NAR tree.
                let sp = self.store_paths.get(store_name).ok_or(IpcError::NotFound)?;
                // The store path root entry must be a directory.
                match &sp.archive.root {
                    NarEntry::Directory { entries } => {
                        if !entries.contains_key(name) {
                            return Err(IpcError::NotFound);
                        }
                    }
                    _ => return Err(IpcError::NotDirectory),
                }
                NixFidPayload::Entry {
                    store_name: Arc::clone(store_name),
                    path: Arc::from(name),
                }
            }
            NixFidPayload::Entry { store_name, path } => {
                // Walk deeper into the NAR tree.
                let sp = self.store_paths.get(store_name).ok_or(IpcError::NotFound)?;
                let current = sp.archive.lookup(path).ok_or(IpcError::NotFound)?;
                match current {
                    NarEntry::Directory { entries } => {
                        if !entries.contains_key(name) {
                            return Err(IpcError::NotFound);
                        }
                    }
                    _ => return Err(IpcError::NotDirectory),
                }
                let mut child_path = String::new();
                child_path.push_str(path);
                child_path.push('/');
                child_path.push_str(name);
                NixFidPayload::Entry {
                    store_name: Arc::clone(store_name),
                    path: Arc::from(child_path.as_str()),
                }
            }
        };

        let qp = qpath_for(&Self::full_path(&new_payload));
        self.tracker.insert(new_fid, qp, new_payload)?;
        Ok(qp)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let entry = self.tracker.begin_open(fid)?;
        if mode != OpenMode::Read {
            return Err(IpcError::ReadOnly);
        }
        entry.mark_open(mode);
        Ok(())
    }

    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.is_open() {
            return Err(IpcError::NotOpen);
        }
        let payload = entry.payload.clone();

        match &payload {
            NixFidPayload::Root => {
                // Root directory listing: sorted store path names.
                let mut listing = String::new();
                for name in self.store_paths.keys() {
                    listing.push_str(name);
                    listing.push('\n');
                }
                let bytes = listing.as_bytes();
                let off = usize::try_from(offset).unwrap_or(usize::MAX);
                if off >= bytes.len() {
                    return Ok(Vec::new());
                }
                let end = off.saturating_add(count as usize).min(bytes.len());
                Ok(bytes[off..end].to_vec())
            }
            NixFidPayload::StorePathRoot { name } => {
                let sp = self.store_paths.get(name).ok_or(IpcError::NotFound)?;
                let nar_entry = &sp.archive.root;
                Ok(self.read_entry_data(sp, nar_entry, offset, count))
            }
            NixFidPayload::Entry { store_name, path } => {
                let sp = self.store_paths.get(store_name).ok_or(IpcError::NotFound)?;
                let nar_entry = sp.archive.lookup(path).ok_or(IpcError::NotFound)?;
                Ok(self.read_entry_data(sp, nar_entry, offset, count))
            }
        }
    }

    fn write(&mut self, _fid: Fid, _offset: u64, _data: &[u8]) -> Result<u32, IpcError> {
        Err(IpcError::ReadOnly)
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        if fid == 0 {
            return Ok(());
        }
        self.tracker.clunk(fid)
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let entry = self.tracker.get(fid)?;
        let payload = entry.payload.clone();

        match &payload {
            NixFidPayload::Root => Ok(FileStat {
                qpath: 0,
                name: Arc::from("store"),
                size: 0, // directories report size 0 (codebase convention)
                file_type: FileType::Directory,
            }),
            NixFidPayload::StorePathRoot { name } => {
                let sp = self.store_paths.get(name).ok_or(IpcError::NotFound)?;
                let nar_entry = &sp.archive.root;
                let qp = entry.qpath;
                Ok(FileStat {
                    qpath: qp,
                    name: Arc::clone(name),
                    size: size_of(nar_entry),
                    file_type: file_type_of(nar_entry),
                })
            }
            NixFidPayload::Entry {
                store_name, path, ..
            } => {
                let sp = self.store_paths.get(store_name).ok_or(IpcError::NotFound)?;
                let nar_entry = sp.archive.lookup(path).ok_or(IpcError::NotFound)?;
                let qp = entry.qpath;
                let component = final_component(path);
                Ok(FileStat {
                    qpath: qp,
                    name: Arc::from(component),
                    size: size_of(nar_entry),
                    file_type: file_type_of(nar_entry),
                })
            }
        }
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        self.tracker.clone_fid(fid, new_fid)
    }
}

/// Thread-safe wrapper around `NixStoreServer`.
///
/// The kernel holds this as a `Box<dyn FileServer>`, while the fetcher
/// thread holds a clone of the inner `Arc<Mutex<NixStoreServer>>` for
/// `drain_misses()` and `import_nar()` calls.
#[cfg(feature = "std")]
pub struct SharedNixStoreServer {
    pub inner: Arc<Mutex<NixStoreServer>>,
}

#[cfg(feature = "std")]
impl FileServer for SharedNixStoreServer {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        self.inner.lock().unwrap().walk(fid, new_fid, name)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        self.inner.lock().unwrap().open(fid, mode)
    }

    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        self.inner.lock().unwrap().read(fid, offset, count)
    }

    fn write(&mut self, fid: Fid, offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        self.inner.lock().unwrap().write(fid, offset, data)
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        self.inner.lock().unwrap().clunk(fid)
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        self.inner.lock().unwrap().stat(fid)
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        self.inner.lock().unwrap().clone_fid(fid, new_fid)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nar::tests::{nar_directory_with_files, nar_regular_file, nar_symlink};
    use std::sync::Mutex;

    /// Helper: create a NixStoreServer with one directory store path.
    fn test_server() -> NixStoreServer {
        let mut srv = NixStoreServer::new();
        srv.import_nar("abc123-hello", nar_directory_with_files())
            .unwrap();
        srv
    }

    #[test]
    fn stat_root() {
        let mut srv = test_server();
        let st = srv.stat(0).unwrap();
        assert_eq!(&*st.name, "store");
        assert_eq!(st.file_type, FileType::Directory);
        assert_eq!(st.size, 0); // directories report size 0 (codebase convention)
        assert_eq!(st.qpath, 0);
    }

    #[test]
    fn walk_to_store_path() {
        let mut srv = test_server();
        let qp = srv.walk(0, 1, "abc123-hello").unwrap();
        assert_ne!(qp, 0);
        let st = srv.stat(1).unwrap();
        assert_eq!(&*st.name, "abc123-hello");
        assert_eq!(st.file_type, FileType::Directory);
    }

    #[test]
    fn walk_nonexistent_store_path() {
        let mut srv = test_server();
        assert_eq!(srv.walk(0, 1, "nonexistent"), Err(IpcError::NotFound));
    }

    #[test]
    fn walk_into_nar_tree() {
        let mut srv = test_server();
        // root → store path → bin → hello
        srv.walk(0, 1, "abc123-hello").unwrap();
        srv.walk(1, 2, "bin").unwrap();
        srv.walk(2, 3, "hello").unwrap();

        let st = srv.stat(3).unwrap();
        assert_eq!(&*st.name, "hello");
        assert_eq!(st.file_type, FileType::Regular);
        assert_eq!(st.size, b"#!/bin/sh\necho hello\n".len() as u64);
    }

    #[test]
    fn read_file_contents() {
        let mut srv = test_server();
        // Walk to README.
        srv.walk(0, 1, "abc123-hello").unwrap();
        srv.walk(1, 2, "README").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 1024).unwrap();
        assert_eq!(data, b"Hello, world!\n");
    }

    #[test]
    fn read_with_offset() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello").unwrap();
        srv.walk(1, 2, "README").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        // "Hello, world!\n" — offset 5 should give ", world!\n"
        let data = srv.read(2, 5, 1024).unwrap();
        assert_eq!(data, b", world!\n");
    }

    #[test]
    fn read_past_eof() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello").unwrap();
        srv.walk(1, 2, "README").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 9999, 1024).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn write_rejected() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello").unwrap();
        srv.walk(1, 2, "README").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        assert_eq!(srv.write(2, 0, &[0xDE, 0xAD]), Err(IpcError::ReadOnly));
    }

    #[test]
    fn read_without_open() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello").unwrap();
        srv.walk(1, 2, "README").unwrap();
        // Do NOT call open.
        assert_eq!(srv.read(2, 0, 100), Err(IpcError::NotOpen));
    }

    #[test]
    fn open_write_mode_rejected() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello").unwrap();
        srv.walk(1, 2, "README").unwrap();
        assert_eq!(srv.open(2, OpenMode::Write), Err(IpcError::ReadOnly));
        assert_eq!(srv.open(2, OpenMode::ReadWrite), Err(IpcError::ReadOnly));
    }

    #[test]
    fn clunk_releases_fid() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello").unwrap();
        srv.clunk(1).unwrap();
        assert_eq!(srv.stat(1), Err(IpcError::InvalidFid));
    }

    #[test]
    fn clunk_root_is_no_op() {
        let mut srv = test_server();
        srv.clunk(0).unwrap();
        // Root should still be functional.
        srv.walk(0, 1, "abc123-hello").unwrap();
        let st = srv.stat(1).unwrap();
        assert_eq!(&*st.name, "abc123-hello");
    }

    #[test]
    fn clone_fid_works() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello").unwrap();
        let qp = srv.clone_fid(1, 2).unwrap();
        let st = srv.stat(2).unwrap();
        assert_eq!(&*st.name, "abc123-hello");
        assert_eq!(st.qpath, qp);
    }

    #[test]
    fn walk_through_file_rejected() {
        let mut srv = test_server();
        srv.walk(0, 1, "abc123-hello").unwrap();
        srv.walk(1, 2, "README").unwrap();
        // README is a regular file, not a directory — can't walk through it.
        assert_eq!(srv.walk(2, 3, "something"), Err(IpcError::NotDirectory));
    }

    #[test]
    fn read_directory_listing() {
        let mut srv = test_server();
        // Open the store path root (which is a directory).
        srv.walk(0, 1, "abc123-hello").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 0, 4096).unwrap();
        let listing = core::str::from_utf8(&data).unwrap();
        // BTreeMap gives sorted order: README before bin.
        assert_eq!(listing, "README\nbin\n");
    }

    #[test]
    fn multiple_store_paths() {
        let mut srv = NixStoreServer::new();
        srv.import_nar("abc123-hello", nar_directory_with_files())
            .unwrap();
        srv.import_nar("def456-world", nar_regular_file(b"world content", false))
            .unwrap();

        // Verify root stat reflects both.
        let st = srv.stat(0).unwrap();
        assert_eq!(st.size, 0); // directories report size 0

        // Walk to first store path.
        srv.walk(0, 1, "abc123-hello").unwrap();
        let st1 = srv.stat(1).unwrap();
        assert_eq!(&*st1.name, "abc123-hello");

        // Walk to second store path.
        srv.walk(0, 2, "def456-world").unwrap();
        let st2 = srv.stat(2).unwrap();
        assert_eq!(&*st2.name, "def456-world");
        assert_eq!(st2.file_type, FileType::Regular);

        // Read from second store path (it's a regular file at the root).
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 1024).unwrap();
        assert_eq!(data, b"world content");
    }

    #[test]
    fn import_duplicate_store_path_rejected() {
        let mut srv = NixStoreServer::new();
        srv.import_nar("abc123-hello", nar_directory_with_files())
            .unwrap();
        // Second import of the same name is rejected.
        assert_eq!(
            srv.import_nar("abc123-hello", nar_regular_file(b"other", false)),
            Err(NarError::DuplicateEntry)
        );
    }

    #[test]
    fn import_rejects_invalid_store_path_names() {
        let mut srv = NixStoreServer::new();
        let nar = nar_regular_file(b"data", false);
        assert_eq!(
            srv.import_nar("foo\nbar", nar.clone()),
            Err(NarError::InvalidString)
        );
        assert_eq!(
            srv.import_nar("", nar.clone()),
            Err(NarError::InvalidString)
        );
        assert_eq!(
            srv.import_nar("a/b", nar.clone()),
            Err(NarError::InvalidString)
        );
        assert_eq!(srv.import_nar(".", nar), Err(NarError::InvalidString));
    }

    #[test]
    fn read_symlink_target() {
        let mut srv = NixStoreServer::new();
        srv.import_nar("sym-link", nar_symlink("/nix/store/abc123-bash/bin/bash"))
            .unwrap();

        srv.walk(0, 1, "sym-link").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 0, 1024).unwrap();
        assert_eq!(data, b"/nix/store/abc123-bash/bin/bash");
    }

    #[test]
    fn read_root_listing() {
        let mut srv = NixStoreServer::new();
        srv.import_nar("aaa-first", nar_regular_file(b"a", false))
            .unwrap();
        srv.import_nar("zzz-last", nar_regular_file(b"z", false))
            .unwrap();

        srv.open(0, OpenMode::Read).unwrap();
        let data = srv.read(0, 0, 4096).unwrap();
        let listing = core::str::from_utf8(&data).unwrap();
        assert_eq!(listing, "aaa-first\nzzz-last\n");
    }

    #[test]
    fn walk_miss_is_recorded() {
        let mut srv = NixStoreServer::new();
        // Walk to a non-existent store path.
        assert_eq!(srv.walk(0, 1, "nonexistent-pkg"), Err(IpcError::NotFound));
        // The miss should be recorded.
        let misses = srv.drain_misses();
        assert_eq!(misses.len(), 1);
        assert_eq!(&*misses[0], "nonexistent-pkg");
    }

    #[test]
    fn drain_misses_clears_list() {
        let mut srv = NixStoreServer::new();
        assert_eq!(srv.walk(0, 1, "miss-one"), Err(IpcError::NotFound));
        assert_eq!(srv.walk(0, 2, "miss-two"), Err(IpcError::NotFound));
        // First drain returns both.
        let misses = srv.drain_misses();
        assert_eq!(misses.len(), 2);
        // Second drain returns empty.
        let misses2 = srv.drain_misses();
        assert!(misses2.is_empty());
    }

    #[test]
    fn drain_misses_on_empty_server() {
        let mut srv = NixStoreServer::new();
        let misses = srv.drain_misses();
        assert!(misses.is_empty());
    }

    #[test]
    fn duplicate_misses_are_recorded() {
        let mut srv = NixStoreServer::new();
        assert_eq!(srv.walk(0, 1, "same-pkg"), Err(IpcError::NotFound));
        assert_eq!(srv.walk(0, 2, "same-pkg"), Err(IpcError::NotFound));
        let misses = srv.drain_misses();
        assert_eq!(misses.len(), 2);
        assert_eq!(&*misses[0], "same-pkg");
        assert_eq!(&*misses[1], "same-pkg");
    }

    #[test]
    fn shared_wrapper_delegates_walk_and_stat() {
        use alloc::sync::Arc;

        let inner = NixStoreServer::new();
        let shared_inner = Arc::new(Mutex::new(inner));
        shared_inner
            .lock()
            .unwrap()
            .import_nar("abc123-hello", nar_directory_with_files())
            .unwrap();

        let mut wrapper = SharedNixStoreServer {
            inner: Arc::clone(&shared_inner),
        };

        // Walk and stat through the wrapper.
        let qp = wrapper.walk(0, 1, "abc123-hello").unwrap();
        assert_ne!(qp, 0);
        let st = wrapper.stat(1).unwrap();
        assert_eq!(&*st.name, "abc123-hello");
        assert_eq!(st.file_type, FileType::Directory);

        // Verify the inner server's state changed (fid was allocated).
        let inner_st = shared_inner.lock().unwrap().stat(1).unwrap();
        assert_eq!(&*inner_st.name, "abc123-hello");
    }

    #[test]
    fn existing_store_path_walk_does_not_record_miss() {
        let mut srv = test_server(); // has "abc123-hello"
        srv.walk(0, 1, "abc123-hello").unwrap();
        let misses = srv.drain_misses();
        assert!(misses.is_empty());
    }

    // ── Kernel integration tests ─────────────────────────────────────

    mod kernel_integration {
        use super::*;
        use crate::echo::EchoServer;
        use crate::kernel::Kernel;
        use crate::vm::buddy::BuddyAllocator;
        use crate::vm::manager::AddressSpaceManager;
        use crate::vm::mock::MockPageTable;
        use crate::vm::PhysAddr;
        use harmony_identity::PrivateIdentity;
        use harmony_unikernel::KernelEntropy;

        fn make_test_entropy() -> KernelEntropy<impl FnMut(&mut [u8])> {
            let mut seed = 42u64;
            KernelEntropy::new(move |buf: &mut [u8]| {
                for b in buf.iter_mut() {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    *b = (seed >> 33) as u8;
                }
            })
        }

        fn make_test_vm() -> AddressSpaceManager<MockPageTable> {
            let buddy = BuddyAllocator::new(PhysAddr(0x10_0000), 64).unwrap();
            AddressSpaceManager::new(buddy)
        }

        /// Create a kernel with a NixStoreServer mounted at `/nix/store`
        /// and a client process that can access it.
        fn setup_kernel_with_nix_store() -> (Kernel<MockPageTable>, u32, u32) {
            let mut entropy = make_test_entropy();
            let kernel_id = PrivateIdentity::generate(&mut entropy);
            let mut kernel = Kernel::new(kernel_id, make_test_vm());

            // Build and populate the nix store server.
            let mut nix = NixStoreServer::new();
            nix.import_nar("abc123-hello", nar_directory_with_files())
                .unwrap();

            // pid 0 = nix store server
            let server_pid = kernel
                .spawn_process("nix-store", Box::new(nix), &[], None)
                .unwrap();

            // pid 1 = client with /nix/store mounted to the nix server
            let client_pid = kernel
                .spawn_process(
                    "client",
                    Box::new(EchoServer::new()),
                    &[("/nix/store", server_pid, 0)],
                    None,
                )
                .unwrap();

            // Grant client access to the nix store server.
            kernel
                .grant_endpoint_cap(&mut entropy, client_pid, server_pid, 0)
                .unwrap();

            (kernel, client_pid, server_pid)
        }

        #[test]
        fn walk_open_read_through_kernel() {
            let (mut kernel, client, _server) = setup_kernel_with_nix_store();

            // Walk the full path in one call — kernel splits into components:
            // /nix/store → (namespace resolve) → abc123-hello → bin → hello
            kernel
                .walk(client, "/nix/store/abc123-hello/bin/hello", 0, 1, 0)
                .unwrap();

            // Open the file for reading.
            kernel.open(client, 1, OpenMode::Read).unwrap();

            // Read the file contents and verify.
            let data = kernel.read(client, 1, 0, 256).unwrap();
            assert_eq!(data, b"#!/bin/sh\necho hello\n");
        }

        #[test]
        fn stat_file_through_kernel() {
            let (mut kernel, client, _server) = setup_kernel_with_nix_store();

            kernel
                .walk(client, "/nix/store/abc123-hello/bin/hello", 0, 1, 0)
                .unwrap();

            let stat = kernel.stat(client, 1).unwrap();
            assert_eq!(&*stat.name, "hello");
            assert_eq!(stat.file_type, FileType::Regular);
            assert_eq!(stat.size, b"#!/bin/sh\necho hello\n".len() as u64);
        }

        #[test]
        fn walk_to_store_path_root_through_kernel() {
            let (mut kernel, client, _server) = setup_kernel_with_nix_store();

            // Walk to a store path root (directory).
            kernel
                .walk(client, "/nix/store/abc123-hello", 0, 1, 0)
                .unwrap();

            let stat = kernel.stat(client, 1).unwrap();
            assert_eq!(&*stat.name, "abc123-hello");
            assert_eq!(stat.file_type, FileType::Directory);
        }

        #[test]
        fn read_readme_through_kernel() {
            let (mut kernel, client, _server) = setup_kernel_with_nix_store();

            // Walk to README (two components after namespace: abc123-hello, README).
            kernel
                .walk(client, "/nix/store/abc123-hello/README", 0, 1, 0)
                .unwrap();

            kernel.open(client, 1, OpenMode::Read).unwrap();

            let data = kernel.read(client, 1, 0, 256).unwrap();
            assert_eq!(data, b"Hello, world!\n");
        }

        #[test]
        fn walk_nonexistent_path_through_kernel() {
            let (mut kernel, client, _server) = setup_kernel_with_nix_store();

            let result = kernel.walk(client, "/nix/store/nonexistent-pkg/bin/foo", 0, 1, 0);
            assert!(result.is_err());
        }

        #[test]
        fn walk_to_mount_root_through_kernel() {
            let (mut kernel, client, _server) = setup_kernel_with_nix_store();

            // Walk to the mount root itself (/nix/store with no further path).
            kernel.walk(client, "/nix/store", 0, 1, 0).unwrap();

            let stat = kernel.stat(client, 1).unwrap();
            assert_eq!(&*stat.name, "store");
            assert_eq!(stat.file_type, FileType::Directory);
            assert_eq!(stat.size, 0); // directories report size 0
        }
    }
}
