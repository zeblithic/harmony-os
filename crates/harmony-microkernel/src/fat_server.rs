// SPDX-License-Identifier: GPL-2.0-or-later

//! FatServer — read-only 9P file server for FAT32 filesystems.
//!
//! Wraps a [`Fat32`] parser to expose files and directories via
//! the [`FileServer`] trait. Supports walk, open, read, stat,
//! clunk, and clone_fid. All write operations are rejected.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::block_device::BlockDevice;
use crate::fat32::Fat32;
use crate::fid_tracker::FidTracker;
use crate::{Fid, FileServer, FileStat, FileType, IpcError, OpenMode, QPath};

/// What kind of node a fid points at in the FAT32 filesystem.
#[derive(Debug, Clone)]
enum NodeKind {
    RootDir,
    SubDir {
        cluster: u32,
        name: Arc<str>,
    },
    File {
        cluster: u32,
        size: u32,
        name: Arc<str>,
    },
}

/// Read-only 9P file server for FAT32 filesystems.
///
/// Wraps a [`Fat32`] parser. Walk resolves names via directory reads
/// with case-insensitive matching. Write operations are rejected.
pub struct FatServer<D: BlockDevice> {
    fat: Fat32<D>,
    tracker: FidTracker<NodeKind>,
}

impl<D: BlockDevice> FatServer<D> {
    /// Create a new FatServer by parsing the FAT32 filesystem on `block_dev`.
    pub fn new(block_dev: D) -> Result<Self, IpcError> {
        let fat = Fat32::new(block_dev)?;
        let tracker = FidTracker::new(0, NodeKind::RootDir);
        Ok(Self { fat, tracker })
    }
}

impl<D: BlockDevice> FileServer for FatServer<D> {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let entry = self.tracker.get(fid)?;
        let dir_cluster = match &entry.payload {
            NodeKind::RootDir => self.fat.root_cluster,
            NodeKind::SubDir { cluster, .. } => *cluster,
            NodeKind::File { .. } => return Err(IpcError::NotDirectory),
        };

        let dir_entries = self.fat.read_dir(dir_cluster)?;
        let found = dir_entries
            .into_iter()
            .find(|e| e.name.eq_ignore_ascii_case(name))
            .ok_or(IpcError::NotFound)?;

        let qpath = found.start_cluster as QPath;
        let node = if found.is_dir {
            NodeKind::SubDir {
                cluster: found.start_cluster,
                name: Arc::from(found.name.as_str()),
            }
        } else {
            NodeKind::File {
                cluster: found.start_cluster,
                size: found.size,
                name: Arc::from(found.name.as_str()),
            }
        };

        self.tracker.insert(new_fid, qpath, node)?;
        Ok(qpath)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        if matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
            return Err(IpcError::PermissionDenied);
        }
        let entry = self.tracker.begin_open(fid)?;
        entry.mark_open(mode);
        Ok(())
    }

    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.is_open() {
            return Err(IpcError::NotOpen);
        }
        match &entry.payload {
            NodeKind::RootDir | NodeKind::SubDir { .. } => Err(IpcError::IsDirectory),
            NodeKind::File { cluster, size, .. } => {
                let cluster = *cluster;
                let size = *size;
                self.fat.read_file_range(cluster, size, offset, count)
            }
        }
    }

    fn write(&mut self, _fid: Fid, _offset: u64, _data: &[u8]) -> Result<u32, IpcError> {
        Err(IpcError::PermissionDenied)
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        self.tracker.clunk(fid)
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let entry = self.tracker.get(fid)?;
        match &entry.payload {
            NodeKind::RootDir => Ok(FileStat {
                qpath: 0,
                name: Arc::from("/"),
                size: 0,
                file_type: FileType::Directory,
            }),
            NodeKind::SubDir { cluster, name } => Ok(FileStat {
                qpath: *cluster as QPath,
                name: Arc::clone(name),
                size: 0,
                file_type: FileType::Directory,
            }),
            NodeKind::File {
                cluster,
                size,
                name,
            } => Ok(FileStat {
                qpath: *cluster as QPath,
                name: Arc::clone(name),
                size: *size as u64,
                file_type: FileType::Regular,
            }),
        }
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        self.tracker.clone_fid(fid, new_fid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fat32::build_fat32_image;

    fn make_fat_server() -> FatServer<crate::block_device::MemoryBlockDevice> {
        let dev = build_fat32_image();
        FatServer::new(dev).unwrap()
    }

    #[test]
    fn walk_to_file() {
        let mut srv = make_fat_server();
        let qpath = srv.walk(0, 1, "config.txt").unwrap();
        assert_eq!(qpath, 4); // start cluster 4
    }

    #[test]
    fn walk_to_lfn_file() {
        let mut srv = make_fat_server();
        let qpath = srv.walk(0, 1, "bcm2712-rpi-5-b.dtb").unwrap();
        assert_eq!(qpath, 5); // start cluster 5
    }

    #[test]
    fn walk_case_insensitive() {
        let mut srv = make_fat_server();
        let qpath = srv.walk(0, 1, "CONFIG.TXT").unwrap();
        assert_eq!(qpath, 4);
    }

    #[test]
    fn walk_to_subdir_then_file() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "overlays").unwrap();
        let qpath = srv.walk(1, 2, "readme.txt").unwrap();
        assert_eq!(qpath, 7); // start cluster 7
    }

    #[test]
    fn walk_nonexistent() {
        let mut srv = make_fat_server();
        assert_eq!(srv.walk(0, 1, "nope.txt"), Err(IpcError::NotFound));
    }

    #[test]
    fn walk_into_file_rejected() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "config.txt").unwrap();
        assert_eq!(srv.walk(1, 2, "sub"), Err(IpcError::NotDirectory));
    }

    #[test]
    fn read_file_contents() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "config.txt").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 0, 100).unwrap();
        assert_eq!(&data, b"hello world");
    }

    #[test]
    fn read_file_with_offset() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "config.txt").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 6, 5).unwrap();
        assert_eq!(&data, b"world");
    }

    #[test]
    fn read_multi_cluster_file() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "bcm2712-rpi-5-b.dtb").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 0, 600).unwrap();
        assert_eq!(data.len(), 600);
        assert!(data[..512].iter().all(|&b| b == 0xAA));
        assert!(data[512..].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn read_directory_rejected() {
        let mut srv = make_fat_server();
        srv.open(0, OpenMode::Read).unwrap();
        assert_eq!(srv.read(0, 0, 100), Err(IpcError::IsDirectory));
    }

    #[test]
    fn write_rejected() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "config.txt").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        assert_eq!(srv.write(1, 0, b"nope"), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn open_write_mode_rejected() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "config.txt").unwrap();
        assert_eq!(
            srv.open(1, OpenMode::Write),
            Err(IpcError::PermissionDenied)
        );
    }

    #[test]
    fn stat_file() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "config.txt").unwrap();
        let st = srv.stat(1).unwrap();
        assert_eq!(&*st.name, "config.txt");
        assert_eq!(st.size, 11);
        assert_eq!(st.file_type, FileType::Regular);
        assert_eq!(st.qpath, 4);
    }

    #[test]
    fn stat_directory() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "overlays").unwrap();
        let st = srv.stat(1).unwrap();
        assert_eq!(&*st.name, "overlays");
        assert_eq!(st.size, 0);
        assert_eq!(st.file_type, FileType::Directory);
    }

    #[test]
    fn stat_root() {
        let mut srv = make_fat_server();
        let st = srv.stat(0).unwrap();
        assert_eq!(&*st.name, "/");
        assert_eq!(st.file_type, FileType::Directory);
    }

    #[test]
    fn clone_fid_works() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "config.txt").unwrap();
        let qpath = srv.clone_fid(1, 2).unwrap();
        assert_eq!(qpath, 4);
        let st = srv.stat(2).unwrap();
        assert_eq!(&*st.name, "config.txt");
    }

    #[test]
    fn clunk_and_reuse() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "config.txt").unwrap();
        srv.clunk(1).unwrap();
        // Reuse fid 1
        let qpath = srv.walk(0, 1, "overlays").unwrap();
        assert_eq!(qpath, 3);
    }
}
