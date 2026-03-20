// SPDX-License-Identifier: GPL-2.0-or-later

//! PersistentNarStore — disk-backed persistence for [`NixStoreServer`].
//!
//! Stores raw NAR archives as files in a directory (`<name>.nar`). On
//! construction, scans the directory and imports all stored NARs into a
//! fresh [`NixStoreServer`]. New NARs are written to disk before being
//! imported, ensuring crash safety (orphaned files are preferable to
//! lost data).
//!
//! This is the Ring 3 persistence layer — Ring 2 (microkernel) has no
//! filesystem, so `NixStoreServer` itself remains a pure in-memory 9P
//! server.

use std::io;
use std::path::{Path, PathBuf};

use harmony_microkernel::nix_store_server::NixStoreServer;

/// Disk-backed persistence for [`NixStoreServer`] NAR archives.
///
/// Each imported NAR is stored as `<dir>/<store_path_name>.nar`. On
/// [`open`](Self::open), the directory is scanned and all valid `.nar`
/// files are imported into a fresh `NixStoreServer`. Corrupted files
/// are logged and skipped rather than failing the entire load.
pub struct PersistentNarStore {
    dir: PathBuf,
}

impl PersistentNarStore {
    /// Open or create a persistent NAR store at the given directory,
    /// returning the store handle and a populated `NixStoreServer`.
    ///
    /// Any `.nar` files in the directory are loaded into the server.
    /// Files that fail to parse are logged and skipped.
    pub fn open(dir: &Path) -> io::Result<(Self, NixStoreServer)> {
        std::fs::create_dir_all(dir)?;

        let mut server = NixStoreServer::new();

        for entry in std::fs::read_dir(dir)? {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("[persistent-nar-store] error reading dir entry: {e}, skipping");
                    continue;
                }
            };
            let path = entry.path();

            // Only process .nar files.
            if path.extension().map_or(true, |ext| ext != "nar") {
                continue;
            }
            if !path.is_file() {
                continue;
            }

            let name = match path.file_stem().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            let nar_bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!(
                        "[persistent-nar-store] failed to read {}: {e}, skipping",
                        path.display()
                    );
                    continue;
                }
            };
            if let Err(e) = server.import_nar(&name, nar_bytes) {
                eprintln!(
                    "[persistent-nar-store] skipping {}: {:?}",
                    path.display(),
                    e
                );
            }
        }

        Ok((
            Self {
                dir: dir.to_path_buf(),
            },
            server,
        ))
    }

    /// Persist a NAR to disk, then import into the server.
    ///
    /// Validates the name for path safety, writes the file (crash safety:
    /// orphaned file > lost data), then imports into the server. On import
    /// failure for a *newly created* file, the file is cleaned up. If the
    /// file already existed (duplicate import), it is left intact.
    pub fn persist_and_import(
        &self,
        server: &mut NixStoreServer,
        name: &str,
        nar_bytes: Vec<u8>,
    ) -> io::Result<()> {
        // Validate name before any disk I/O — prevents path traversal.
        // Replicates the safety-critical subset of NixStoreServer::import_nar
        // validation so that no writes occur outside the store directory.
        if name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || name.contains('\0')
            || name.contains('\n')
            || name.contains('\r')
            || name == "."
            || name == ".."
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsafe store path name: {name:?}"),
            ));
        }

        let path = self.dir.join(format!("{name}.nar"));

        // Gate on server state, not disk state. If the server already has
        // this path imported, it's a true duplicate — skip the write and
        // let import_nar reject it. If the server doesn't have it (even
        // if a corrupted file exists on disk from a prior crash), we must
        // write the valid data to disk.
        let already_imported = server.has_store_path(name);
        if !already_imported {
            std::fs::write(&path, &nar_bytes)?;
        }

        // Import into server.
        server.import_nar(name, nar_bytes).map_err(|e| {
            // Only clean up if we wrote the file in this call.
            // Cleanup failure is benign: if remove_file fails, the next
            // open() will attempt to re-import the file from disk. If
            // the data is valid, it gets imported normally; if corrupted,
            // the parse-error skip path handles it.
            if !already_imported {
                let _ = std::fs::remove_file(&path);
            }
            io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}"))
        })
    }

    /// Path to the store directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harmony_microkernel::{FileServer, OpenMode};
    use tempfile::TempDir;

    // ── NAR construction helper ────────────────────────────────────

    fn nar_string(s: &[u8]) -> Vec<u8> {
        let len = s.len() as u64;
        let padded_len = (s.len() + 7) & !7;
        let mut buf = Vec::with_capacity(8 + padded_len);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(s);
        buf.resize(buf.len() + (padded_len - s.len()), 0);
        buf
    }

    fn build_test_nar(contents: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&nar_string(b"nix-archive-1"));
        buf.extend_from_slice(&nar_string(b"("));
        buf.extend_from_slice(&nar_string(b"type"));
        buf.extend_from_slice(&nar_string(b"regular"));
        buf.extend_from_slice(&nar_string(b"contents"));
        buf.extend_from_slice(&nar_string(contents));
        buf.extend_from_slice(&nar_string(b")"));
        buf
    }

    // ── Tests ──────────────────────────────────────────────────────

    #[test]
    fn open_creates_directory() {
        let tmp = TempDir::new().unwrap();
        let store_dir = tmp.path().join("nar-store");
        assert!(!store_dir.exists());

        let (_store, _server) = PersistentNarStore::open(&store_dir).unwrap();
        assert!(store_dir.is_dir());
    }

    #[test]
    fn persist_and_import() {
        let tmp = TempDir::new().unwrap();
        let (store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();

        let nar = build_test_nar(b"hello persistent nix");
        store
            .persist_and_import(&mut server, "abc123-hello", nar)
            .unwrap();

        // NAR file should exist on disk.
        assert!(tmp.path().join("abc123-hello.nar").exists());

        // Store path should be available in the server.
        let qp = server.walk(0, 1, "abc123-hello").unwrap();
        assert_ne!(qp, 0);

        // Read the file contents.
        server.open(1, OpenMode::Read).unwrap();
        let data = server.read(1, 0, 1024).unwrap();
        assert_eq!(data, b"hello persistent nix");
    }

    #[test]
    fn reload_on_open() {
        let tmp = TempDir::new().unwrap();
        let nar = build_test_nar(b"survives restart");

        {
            let (store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();
            store
                .persist_and_import(&mut server, "rst123-reboot", nar.clone())
                .unwrap();
        }

        // Reopen — data should be reloaded.
        let (_store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();
        let qp = server.walk(0, 1, "rst123-reboot").unwrap();
        assert_ne!(qp, 0);

        server.open(1, OpenMode::Read).unwrap();
        let data = server.read(1, 0, 1024).unwrap();
        assert_eq!(data, b"survives restart");
    }

    #[test]
    fn multiple_nars_round_trip() {
        let tmp = TempDir::new().unwrap();

        {
            let (store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();
            store
                .persist_and_import(&mut server, "aaa123-first", build_test_nar(b"first pkg"))
                .unwrap();
            store
                .persist_and_import(&mut server, "bbb456-second", build_test_nar(b"second pkg"))
                .unwrap();
        }

        // Reload and verify both.
        let (_store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();

        server.walk(0, 1, "aaa123-first").unwrap();
        server.open(1, OpenMode::Read).unwrap();
        assert_eq!(server.read(1, 0, 1024).unwrap(), b"first pkg");

        server.walk(0, 2, "bbb456-second").unwrap();
        server.open(2, OpenMode::Read).unwrap();
        assert_eq!(server.read(2, 0, 1024).unwrap(), b"second pkg");
    }

    #[test]
    fn duplicate_import_rejected_preserves_original() {
        let tmp = TempDir::new().unwrap();
        let (store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();

        let nar = build_test_nar(b"original");
        store
            .persist_and_import(&mut server, "dup123-dupe", nar.clone())
            .unwrap();

        // Second import of same name should fail.
        let result = store.persist_and_import(&mut server, "dup123-dupe", nar);
        assert!(result.is_err());

        // P0 regression: the original .nar file must still exist on disk.
        let nar_path = tmp.path().join("dup123-dupe.nar");
        assert!(
            nar_path.exists(),
            "original .nar file must survive duplicate rejection"
        );

        // And the data must survive a restart.
        let (_store2, mut server2) = PersistentNarStore::open(tmp.path()).unwrap();
        server2.walk(0, 1, "dup123-dupe").unwrap();
        server2.open(1, OpenMode::Read).unwrap();
        assert_eq!(server2.read(1, 0, 1024).unwrap(), b"original");
    }

    #[test]
    fn path_traversal_rejected() {
        let tmp = TempDir::new().unwrap();
        let (store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();

        let nar = build_test_nar(b"malicious");

        // Names with path separators must be rejected before any disk write.
        assert!(store
            .persist_and_import(&mut server, "../escape", nar.clone())
            .is_err());
        assert!(store
            .persist_and_import(&mut server, "foo/bar", nar.clone())
            .is_err());
        assert!(store
            .persist_and_import(&mut server, "/tmp/evil", nar.clone())
            .is_err());

        // No files should have been created outside the store directory.
        assert!(!tmp.path().join("..").join("escape.nar").exists());
    }

    #[test]
    fn corrupted_nar_skipped_on_reload() {
        let tmp = TempDir::new().unwrap();

        {
            let (store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();
            store
                .persist_and_import(&mut server, "good123-valid", build_test_nar(b"valid data"))
                .unwrap();
        }

        // Write a corrupted .nar file.
        std::fs::write(tmp.path().join("bad456-corrupt.nar"), b"not a nar").unwrap();

        // Reload should skip the corrupted file but load the valid one.
        let (_store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();
        server.walk(0, 1, "good123-valid").unwrap();
        server.open(1, OpenMode::Read).unwrap();
        assert_eq!(server.read(1, 0, 1024).unwrap(), b"valid data");

        // Corrupted one should not be present.
        assert_eq!(
            server.walk(0, 2, "bad456-corrupt"),
            Err(harmony_microkernel::IpcError::NotFound)
        );
    }

    #[test]
    fn corrupted_file_overwritten_on_re_persist() {
        let tmp = TempDir::new().unwrap();
        let nar = build_test_nar(b"valid data");

        // Simulate a crash that left a corrupted .nar file on disk.
        std::fs::write(tmp.path().join("crash1-pkg.nar"), b"truncated garbage").unwrap();

        // open() skips the corrupted file (parse failure).
        let (store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();
        assert_eq!(
            server.walk(0, 1, "crash1-pkg"),
            Err(harmony_microkernel::IpcError::NotFound)
        );

        // Re-persist with valid data — should overwrite the corrupted file.
        store
            .persist_and_import(&mut server, "crash1-pkg", nar)
            .unwrap();

        // Data should be available in memory.
        server.walk(0, 2, "crash1-pkg").unwrap();
        server.open(2, OpenMode::Read).unwrap();
        assert_eq!(server.read(2, 0, 1024).unwrap(), b"valid data");

        // AND survive a restart (corrupted file was overwritten).
        let (_store2, mut server2) = PersistentNarStore::open(tmp.path()).unwrap();
        server2.walk(0, 1, "crash1-pkg").unwrap();
        server2.open(1, OpenMode::Read).unwrap();
        assert_eq!(server2.read(1, 0, 1024).unwrap(), b"valid data");
    }

    #[test]
    fn non_nar_files_ignored() {
        let tmp = TempDir::new().unwrap();

        {
            let (store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();
            store
                .persist_and_import(&mut server, "abc123-real", build_test_nar(b"real"))
                .unwrap();
        }

        // Create non-.nar files — should be silently ignored.
        std::fs::write(tmp.path().join("readme.txt"), b"not a nar").unwrap();
        std::fs::write(tmp.path().join("data.json"), b"{}").unwrap();

        let (_store, mut server) = PersistentNarStore::open(tmp.path()).unwrap();
        server.walk(0, 1, "abc123-real").unwrap();
    }
}
