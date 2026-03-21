// SPDX-License-Identifier: GPL-2.0-or-later

//! DiskBookStore — write-through persistent [`BookStore`] backed by a directory.
//!
//! Each book is stored as a file named by the CID's hex encoding. On
//! construction, the store scans its directory and loads all existing books
//! into an in-memory cache. Subsequent inserts write to both disk and memory.
//!
//! The [`BookStore::get`] method returns `&[u8]`, requiring the store to own
//! the data — hence the in-memory cache. The disk layer provides durability
//! across process restarts.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use harmony_content::book::BookStore;
use harmony_content::cid::{ContentFlags, ContentId};
use harmony_content::error::ContentError;

/// A content-addressed book store that persists to a directory.
///
/// Acts as a write-through cache: all data lives in memory (for `&[u8]`
/// returns) and is also written to disk (for persistence across restarts).
///
/// # Durability guarantees
///
/// Disk write failures in [`BookStore::store`] and [`BookStore::insert`]
/// are **best-effort**: if the write fails, data remains in the in-memory
/// cache (available this session) but will not survive a restart. This is
/// a constraint of the [`BookStore`] trait, which has no `Result` return
/// on `store()` and no I/O error variant in `ContentError`. Callers that
/// require strict durability should verify persistence via [`Self::is_persisted`].
///
/// On reload, files whose size does not match the CID's `payload_size()`
/// are skipped (catches truncation from crashes or partial writes).
///
/// Implements the [`BookStore`] trait.
pub struct DiskBookStore {
    dir: PathBuf,
    cache: HashMap<ContentId, Vec<u8>>,
}

impl DiskBookStore {
    /// Open or create a persistent book store at the given directory.
    ///
    /// Creates the directory if it doesn't exist, then scans for existing
    /// book files (named as 64-char hex CIDs) and loads them into memory.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;

        let mut cache = HashMap::new();

        for entry in std::fs::read_dir(dir)? {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("[disk-book-store] error reading dir entry: {e}, skipping");
                    continue;
                }
            };
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            // CID hex is exactly 64 characters (32 bytes).
            if name.len() != 64 {
                continue;
            }
            let cid_bytes: [u8; 32] = match hex::decode(&name) {
                Ok(bytes) => match bytes.try_into() {
                    Ok(arr) => arr,
                    Err(_) => continue,
                },
                Err(_) => continue,
            };
            let cid = ContentId::from_bytes(cid_bytes);
            let data = match std::fs::read(&path) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("[disk-book-store] failed to read {name}: {e}, skipping");
                    continue;
                }
            };

            // Size check: the CID encodes the payload size. If the file
            // is truncated or corrupted, skip it rather than serving bad data.
            let expected_size = cid.payload_size() as usize;
            if data.len() != expected_size {
                eprintln!(
                    "[disk-book-store] size mismatch for {name}: expected {expected_size}, got {}, skipping",
                    data.len()
                );
                continue;
            }
            cache.insert(cid, data);
        }

        Ok(Self {
            dir: dir.to_path_buf(),
            cache,
        })
    }

    /// Number of books in the store.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Check whether a specific CID has been persisted to disk.
    ///
    /// Returns `true` only if the file exists on disk. Use this to verify
    /// durability after an insert if strict persistence is required.
    pub fn is_persisted(&self, cid: &ContentId) -> bool {
        let cid_hex = hex::encode(cid.to_bytes());
        self.dir.join(&cid_hex).exists()
    }

    /// Write a book to disk. Best-effort — logs on failure.
    fn persist(&self, cid: &ContentId, data: &[u8]) {
        let cid_hex = hex::encode(cid.to_bytes());
        let path = self.dir.join(&cid_hex);
        if let Err(e) = std::fs::write(&path, data) {
            eprintln!("[disk-book-store] failed to persist {cid_hex}: {e}");
        }
    }
}

impl BookStore for DiskBookStore {
    fn insert_with_flags(
        &mut self,
        data: &[u8],
        flags: ContentFlags,
    ) -> Result<ContentId, ContentError> {
        let cid = ContentId::for_book(data, flags)?;
        if !self.cache.contains_key(&cid) {
            self.persist(&cid, data);
            self.cache.insert(cid, data.to_vec());
        }
        Ok(cid)
    }

    fn store(&mut self, cid: ContentId, data: Vec<u8>) {
        if !self.cache.contains_key(&cid) {
            self.persist(&cid, &data);
            self.cache.insert(cid, data);
        }
    }

    fn get(&self, cid: &ContentId) -> Option<&[u8]> {
        self.cache.get(cid).map(|v| v.as_slice())
    }

    fn contains(&self, cid: &ContentId) -> bool {
        self.cache.contains_key(cid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn new_creates_directory() {
        let tmp = TempDir::new().unwrap();
        let store_dir = tmp.path().join("books");
        assert!(!store_dir.exists());

        let _store = DiskBookStore::open(&store_dir).unwrap();
        assert!(store_dir.is_dir());
    }

    #[test]
    fn insert_and_get_round_trip() {
        let tmp = TempDir::new().unwrap();
        let mut store = DiskBookStore::open(tmp.path()).unwrap();

        let data = b"hello persistent book store";
        let cid = store.insert(data.as_slice()).unwrap();

        assert_eq!(store.get(&cid).unwrap(), data.as_slice());
        assert!(store.contains(&cid));
    }

    #[test]
    fn insert_persists_to_disk() {
        let tmp = TempDir::new().unwrap();
        let mut store = DiskBookStore::open(tmp.path()).unwrap();

        let data = b"persisted data";
        let cid = store.insert(data.as_slice()).unwrap();

        let cid_hex = hex::encode(cid.to_bytes());
        let book_path = tmp.path().join(&cid_hex);
        assert!(book_path.exists(), "book file should exist on disk");
        assert_eq!(std::fs::read(&book_path).unwrap(), data.as_slice());
    }

    #[test]
    fn reload_from_disk() {
        let tmp = TempDir::new().unwrap();
        let data = b"survives restart";
        let cid;

        {
            let mut store = DiskBookStore::open(tmp.path()).unwrap();
            cid = store.insert(data.as_slice()).unwrap();
        }

        // Create a fresh store from the same directory — should reload.
        let store2 = DiskBookStore::open(tmp.path()).unwrap();
        assert!(store2.contains(&cid));
        assert_eq!(store2.get(&cid).unwrap(), data.as_slice());
    }

    #[test]
    fn store_precomputed_cid_round_trip() {
        let tmp = TempDir::new().unwrap();
        let mut store = DiskBookStore::open(tmp.path()).unwrap();

        let data = b"bundle data";
        let cid = ContentId::for_book(data, ContentFlags::default()).unwrap();

        store.store(cid, data.to_vec());

        assert_eq!(store.get(&cid).unwrap(), data.as_slice());
        assert!(store.contains(&cid));
    }

    #[test]
    fn store_precomputed_persists_to_disk() {
        let tmp = TempDir::new().unwrap();
        let data = b"precomputed persist";
        let cid = ContentId::for_book(data, ContentFlags::default()).unwrap();

        {
            let mut store = DiskBookStore::open(tmp.path()).unwrap();
            store.store(cid, data.to_vec());
        }

        // Reload from disk.
        let store2 = DiskBookStore::open(tmp.path()).unwrap();
        assert!(store2.contains(&cid));
        assert_eq!(store2.get(&cid).unwrap(), data.as_slice());
    }

    #[test]
    fn contains_false_for_unknown_cid() {
        let tmp = TempDir::new().unwrap();
        let store = DiskBookStore::open(tmp.path()).unwrap();

        let cid = ContentId::for_book(b"not stored", ContentFlags::default()).unwrap();
        assert!(!store.contains(&cid));
        assert!(store.get(&cid).is_none());
    }

    #[test]
    fn duplicate_insert_idempotent() {
        let tmp = TempDir::new().unwrap();
        let mut store = DiskBookStore::open(tmp.path()).unwrap();

        let data = b"same data twice";
        let cid1 = store.insert(data.as_slice()).unwrap();
        let cid2 = store.insert(data.as_slice()).unwrap();

        assert_eq!(cid1, cid2);
        // Only one file on disk.
        let file_count = std::fs::read_dir(tmp.path()).unwrap().count();
        assert_eq!(file_count, 1);
    }

    #[test]
    fn reload_preserves_multiple_books() {
        let tmp = TempDir::new().unwrap();
        let cids: Vec<ContentId>;

        {
            let mut store = DiskBookStore::open(tmp.path()).unwrap();
            let c1 = store.insert(b"book one".as_slice()).unwrap();
            let c2 = store.insert(b"book two".as_slice()).unwrap();
            let c3 = store.insert(b"book three".as_slice()).unwrap();
            cids = vec![c1, c2, c3];
        }

        let store2 = DiskBookStore::open(tmp.path()).unwrap();
        for cid in &cids {
            assert!(store2.contains(cid), "book {cid:?} should survive reload");
        }
        assert_eq!(store2.get(&cids[0]).unwrap(), b"book one");
        assert_eq!(store2.get(&cids[1]).unwrap(), b"book two");
        assert_eq!(store2.get(&cids[2]).unwrap(), b"book three");
    }

    #[test]
    fn non_hex_files_ignored_on_reload() {
        let tmp = TempDir::new().unwrap();

        {
            let mut store = DiskBookStore::open(tmp.path()).unwrap();
            store.insert(b"real book".as_slice()).unwrap();
        }

        // Create a non-hex junk file — should be silently skipped.
        std::fs::write(tmp.path().join("not-a-book.txt"), b"junk").unwrap();

        // Should load without error, only the real book.
        let store2 = DiskBookStore::open(tmp.path()).unwrap();
        assert_eq!(store2.len(), 1);
    }

    #[test]
    fn len_and_is_empty() {
        let tmp = TempDir::new().unwrap();
        let mut store = DiskBookStore::open(tmp.path()).unwrap();

        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        store.insert(b"data".as_slice()).unwrap();
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn truncated_file_skipped_on_reload() {
        let tmp = TempDir::new().unwrap();
        let data = b"full book data here";
        let cid;

        {
            let mut store = DiskBookStore::open(tmp.path()).unwrap();
            cid = store.insert(data.as_slice()).unwrap();
        }

        // Truncate the file on disk (simulates partial write / crash).
        let cid_hex = hex::encode(cid.to_bytes());
        let path = tmp.path().join(&cid_hex);
        std::fs::write(&path, b"tru").unwrap(); // 3 bytes instead of 19

        // Reload should skip the truncated file.
        let store2 = DiskBookStore::open(tmp.path()).unwrap();
        assert!(!store2.contains(&cid), "truncated book should be skipped");
        assert_eq!(store2.len(), 0);
    }
}
