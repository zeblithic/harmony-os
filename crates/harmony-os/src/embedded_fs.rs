// SPDX-License-Identifier: GPL-2.0-or-later
//! EmbeddedFs — read-only in-memory filesystem for pre-registered static files.
//!
//! Serves `(path → &'static [u8])` entries so that the Linuxulator can expose
//! embedded binaries (dropbear, busybox) and config files through the standard
//! `open`/`read`/`execve` syscall surface without any backing storage.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// A single file registered in the [`EmbeddedFs`].
#[derive(Clone)]
pub struct EmbeddedFile {
    /// Raw file contents backed by a `'static` byte slice (e.g. from `include_bytes!`).
    pub data: &'static [u8],
    /// Whether the file should be reported as executable (mode bit 0o111).
    pub executable: bool,
}

/// In-memory filesystem with static files and a writable scratch layer.
///
/// Files are registered at construction time with absolute paths like
/// `/usr/bin/dropbear`. Directory existence is derived automatically: any
/// path component that is a prefix of a registered file is considered an
/// existing directory.
///
/// The scratch layer supports runtime file creation (e.g. dropbear host
/// key generation). Scratch files are heap-allocated and lost on reboot.
#[derive(Clone)]
pub struct EmbeddedFs {
    files: BTreeMap<String, EmbeddedFile>,
    /// Runtime-created files (writable scratch layer).
    pub scratch: BTreeMap<String, Vec<u8>>,
}

impl EmbeddedFs {
    /// Create an empty filesystem.
    pub fn new() -> Self {
        Self {
            files: BTreeMap::new(),
            scratch: BTreeMap::new(),
        }
    }

    /// Register a file at `path` with the given static byte slice.
    ///
    /// Overwrites any previous entry at the same path.
    pub fn add_file(&mut self, path: &str, data: &'static [u8], executable: bool) {
        self.files
            .insert(path.to_string(), EmbeddedFile { data, executable });
    }

    /// Look up a static file by exact path. Returns `None` for directories,
    /// scratch files, or paths that were never registered.
    pub fn get(&self, path: &str) -> Option<&EmbeddedFile> {
        self.files.get(path)
    }

    /// Read a file's contents — checks scratch layer first, then static.
    pub fn read_data(&self, path: &str) -> Option<&[u8]> {
        if let Some(data) = self.scratch.get(path) {
            return Some(data);
        }
        self.files.get(path).map(|f| f.data)
    }

    /// Create or overwrite a file in the scratch layer.
    pub fn write_scratch(&mut self, path: &str, data: Vec<u8>) {
        self.scratch.insert(path.to_string(), data);
    }

    /// Rename a scratch file. Returns false if `old` doesn't exist in scratch.
    pub fn rename_scratch(&mut self, old: &str, new: &str) -> bool {
        if let Some(data) = self.scratch.remove(old) {
            self.scratch.insert(new.to_string(), data);
            true
        } else {
            false
        }
    }

    /// Return `true` if `path` names a registered file (static or scratch)
    /// **or** a directory that is a prefix of at least one registered file.
    pub fn exists(&self, path: &str) -> bool {
        if self.files.contains_key(path) || self.scratch.contains_key(path) {
            return true;
        }
        // A path is a directory if any registered path starts with
        // `<path>/` (exact prefix followed by a separator).
        let dir_prefix = if path.ends_with('/') {
            path.to_string()
        } else {
            let mut p = path.to_string();
            p.push('/');
            p
        };
        self.files.keys().any(|k| k.starts_with(&dir_prefix))
            || self.scratch.keys().any(|k| k.starts_with(&dir_prefix))
    }

    /// List the immediate children of the directory at `path`.
    ///
    /// Returns the names (not full paths) of direct children, sorted and
    /// deduplicated. Returns an empty `Vec` for non-existent or leaf paths.
    pub fn readdir(&self, path: &str) -> Vec<String> {
        let dir_prefix = if path.ends_with('/') {
            path.to_string()
        } else {
            let mut p = path.to_string();
            p.push('/');
            p
        };

        let mut children: Vec<String> = Vec::new();

        for key in self.files.keys() {
            if let Some(rest) = key.strip_prefix(&dir_prefix) {
                // Take only the first path component of the remainder.
                let child = match rest.find('/') {
                    Some(slash) => &rest[..slash],
                    None => rest,
                };
                let child = child.to_string();
                if !children.contains(&child) {
                    children.push(child);
                }
            }
        }

        children.sort();
        children
    }
}

impl Default for EmbeddedFs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static HELLO: &[u8] = b"hello, world";
    static KEY: &[u8] = b"\x00\x01\x02\x03";

    #[test]
    fn add_and_get_file() {
        let mut fs = EmbeddedFs::new();
        fs.add_file("/usr/bin/dropbear", HELLO, true);

        let f = fs.get("/usr/bin/dropbear").expect("file should be present");
        assert_eq!(f.data, HELLO);
        assert!(f.executable);

        fs.add_file("/etc/dropbear/host_key", KEY, false);
        let k = fs
            .get("/etc/dropbear/host_key")
            .expect("key file should be present");
        assert_eq!(k.data, KEY);
        assert!(!k.executable);
    }

    #[test]
    fn missing_file_returns_none() {
        let mut fs = EmbeddedFs::new();
        fs.add_file("/usr/bin/dropbear", HELLO, true);

        assert!(fs.get("/usr/bin/busybox").is_none());
        assert!(fs.get("/").is_none());
        assert!(fs.get("").is_none());
    }

    #[test]
    fn exists_checks_files_and_directories() {
        let mut fs = EmbeddedFs::new();
        fs.add_file("/usr/bin/dropbear", HELLO, true);
        fs.add_file("/etc/dropbear/host_key", KEY, false);

        // Registered files exist.
        assert!(fs.exists("/usr/bin/dropbear"));
        assert!(fs.exists("/etc/dropbear/host_key"));

        // Parent directories are derived.
        assert!(fs.exists("/usr/bin"));
        assert!(fs.exists("/usr"));
        assert!(fs.exists("/etc/dropbear"));
        assert!(fs.exists("/etc"));

        // Non-existent paths do not exist.
        assert!(!fs.exists("/usr/bin/busybox"));
        assert!(!fs.exists("/var"));
        assert!(!fs.exists("/etc/ssh"));
    }

    #[test]
    fn readdir_lists_immediate_children() {
        let mut fs = EmbeddedFs::new();
        fs.add_file("/usr/bin/dropbear", HELLO, true);
        fs.add_file("/usr/bin/busybox", HELLO, true);
        fs.add_file("/usr/lib/libdropbear.so", HELLO, false);
        fs.add_file("/etc/dropbear/host_key", KEY, false);

        // Direct children of /usr/bin — two files, sorted.
        let children = fs.readdir("/usr/bin");
        assert_eq!(children, vec!["busybox", "dropbear"]);

        // Direct children of /usr — two subdirs, no duplicates.
        let children = fs.readdir("/usr");
        assert_eq!(children, vec!["bin", "lib"]);

        // Direct children of /etc/dropbear — one file.
        let children = fs.readdir("/etc/dropbear");
        assert_eq!(children, vec!["host_key"]);

        // Non-existent directory — empty.
        let children = fs.readdir("/var");
        assert!(children.is_empty());

        // Leaf file — empty (it's not a directory).
        let children = fs.readdir("/usr/bin/dropbear");
        assert!(children.is_empty());
    }
}
