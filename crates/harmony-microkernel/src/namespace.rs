// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-process namespace (mount table + path resolution).

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use crate::Fid;

/// A mount point maps a path prefix to a target process.
#[derive(Debug, Clone)]
pub struct MountPoint {
    pub target_pid: u32,
    pub root_fid: Fid,
}

/// Per-process namespace — a mount table mapping path prefixes to servers.
#[derive(Debug, Clone)]
pub struct Namespace {
    mounts: BTreeMap<Arc<str>, MountPoint>,
}

impl Default for Namespace {
    fn default() -> Self {
        Self::new()
    }
}

impl Namespace {
    pub fn new() -> Self {
        Namespace { mounts: BTreeMap::new() }
    }

    /// Mount a server at `path`. Subsequent resolves matching this prefix
    /// will route to `target_pid`.
    ///
    /// Returns `Err(InvalidArgument)` if `path` does not start with `/`,
    /// or if a mount already exists at `path`.
    pub fn mount(&mut self, path: &str, target_pid: u32, root_fid: Fid) -> Result<(), crate::IpcError> {
        if !path.starts_with('/') {
            return Err(crate::IpcError::InvalidArgument);
        }
        if self.mounts.contains_key(path) {
            return Err(crate::IpcError::InvalidArgument);
        }
        self.mounts.insert(Arc::from(path), MountPoint { target_pid, root_fid });
        Ok(())
    }

    /// Resolve `path` to a mount point and remainder.
    ///
    /// Finds the longest matching prefix. Returns `None` if no mount matches.
    /// The prefix must match at a "/" boundary or exactly (no partial matches).
    pub fn resolve<'a>(&'a self, path: &'a str) -> Option<(&'a MountPoint, &'a str)> {
        let mut best: Option<(&MountPoint, &str)> = None;
        let mut best_len = 0;

        for (prefix, mount) in &self.mounts {
            let prefix_str: &str = prefix;
            if prefix_str == "/" {
                if path.starts_with('/') && 1 > best_len {
                    best = Some((mount, &path[1..]));
                    best_len = 1;
                }
                continue;
            }
            if path == prefix_str {
                // Exact match — remainder is empty
                if prefix_str.len() > best_len {
                    best = Some((mount, ""));
                    best_len = prefix_str.len();
                }
            } else if let Some(after) = path.strip_prefix(prefix_str) {
                // Check for "/" boundary after prefix to avoid partial matches
                if let Some(remainder) = after.strip_prefix('/') {
                    if prefix_str.len() > best_len {
                        best = Some((mount, remainder));
                        best_len = prefix_str.len();
                    }
                }
            }
        }

        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_simple_mount() {
        let mut ns = Namespace::new();
        ns.mount("/echo", 1, 0).unwrap();
        let (mp, remainder) = ns.resolve("/echo/hello").unwrap();
        assert_eq!(mp.target_pid, 1);
        assert_eq!(remainder, "hello");
    }

    #[test]
    fn resolve_mount_root() {
        let mut ns = Namespace::new();
        ns.mount("/echo", 1, 0).unwrap();
        // Accessing the mount point itself — remainder is empty
        let (mp, remainder) = ns.resolve("/echo").unwrap();
        assert_eq!(mp.target_pid, 1);
        assert_eq!(remainder, "");
    }

    #[test]
    fn resolve_nested_path() {
        let mut ns = Namespace::new();
        ns.mount("/dev/serial", 0, 0).unwrap();
        let (mp, remainder) = ns.resolve("/dev/serial").unwrap();
        assert_eq!(mp.target_pid, 0);
        assert_eq!(remainder, "");
    }

    #[test]
    fn resolve_longest_prefix_match() {
        let mut ns = Namespace::new();
        ns.mount("/a", 1, 0).unwrap();
        ns.mount("/a/b", 2, 0).unwrap();
        // "/a/b/c" should match "/a/b" (longer), not "/a"
        let (mp, remainder) = ns.resolve("/a/b/c").unwrap();
        assert_eq!(mp.target_pid, 2);
        assert_eq!(remainder, "c");
    }

    #[test]
    fn resolve_unmounted_path() {
        let ns = Namespace::new();
        assert!(ns.resolve("/nonexistent").is_none());
    }

    #[test]
    fn resolve_partial_prefix_no_match() {
        let mut ns = Namespace::new();
        ns.mount("/echo", 1, 0).unwrap();
        // "/echooo" should NOT match "/echo" — must be exact prefix + "/" boundary
        assert!(ns.resolve("/echooo").is_none());
    }

    #[test]
    fn resolve_root_mount() {
        let mut ns = Namespace::new();
        ns.mount("/", 0, 0).unwrap();
        ns.mount("/echo", 1, 0).unwrap();
        // Longer prefix wins over root
        let (mp, remainder) = ns.resolve("/echo/hello").unwrap();
        assert_eq!(mp.target_pid, 1);
        assert_eq!(remainder, "hello");
        // Falls through to root for unmatched paths
        let (mp, remainder) = ns.resolve("/other").unwrap();
        assert_eq!(mp.target_pid, 0);
        assert_eq!(remainder, "other");
    }

    #[test]
    fn mount_rejects_path_without_leading_slash() {
        let mut ns = Namespace::new();
        assert_eq!(ns.mount("echo", 1, 0), Err(crate::IpcError::InvalidArgument));
    }

    #[test]
    fn mount_preserves_root_fid() {
        let mut ns = Namespace::new();
        ns.mount("/data", 3, 42).unwrap();
        let (mp, _) = ns.resolve("/data/file").unwrap();
        assert_eq!(mp.root_fid, 42);
    }
}
