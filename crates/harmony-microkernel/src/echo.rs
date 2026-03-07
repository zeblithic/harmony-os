// SPDX-License-Identifier: GPL-2.0-or-later
//! EchoServer — a trivial FileServer for testing IPC.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

use crate::{Fid, QPath, FileServer, FileStat, FileType, IpcError, OpenMode};

// ── QPath constants ─────────────────────────────────────────────────

const ROOT: QPath = 0;
const HELLO: QPath = 1;
const ECHO: QPath = 2;

const HELLO_GREETING: &[u8] = b"Hello from echo server!";

// ── Per-fid state ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct FidState {
    qpath: QPath,
    is_open: bool,
    mode: Option<OpenMode>,
}

// ── EchoServer ──────────────────────────────────────────────────────

/// A minimal `FileServer` with a root directory, a read-only "hello"
/// file, and a writable "echo" file that returns whatever was last written.
pub struct EchoServer {
    fids: BTreeMap<Fid, FidState>,
    echo_data: Vec<u8>,
}

impl EchoServer {
    /// Create a new EchoServer with fid 0 pre-attached to the root directory.
    pub fn new() -> Self {
        let mut fids = BTreeMap::new();
        fids.insert(0, FidState {
            qpath: ROOT,
            is_open: false,
            mode: None,
        });
        Self {
            fids,
            echo_data: Vec::new(),
        }
    }
}

impl Default for EchoServer {
    fn default() -> Self {
        Self::new()
    }
}

impl FileServer for EchoServer {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;

        // Can only walk from the root directory.
        if state.qpath != ROOT {
            return Err(IpcError::NotDirectory);
        }

        if self.fids.contains_key(&new_fid) {
            return Err(IpcError::InvalidFid);
        }

        let qpath = match name {
            "hello" => HELLO,
            "echo" => ECHO,
            _ => return Err(IpcError::NotFound),
        };

        self.fids.insert(new_fid, FidState {
            qpath,
            is_open: false,
            mode: None,
        });

        Ok(qpath)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let state = self.fids.get_mut(&fid).ok_or(IpcError::InvalidFid)?;
        if state.is_open {
            return Err(IpcError::PermissionDenied);
        }
        // Reject incompatible modes at open time (9P semantics).
        if state.qpath == ROOT && matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
            return Err(IpcError::IsDirectory);
        }
        if state.qpath == HELLO && matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
            return Err(IpcError::ReadOnly);
        }
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

        let data: &[u8] = match state.qpath {
            ROOT => return Err(IpcError::IsDirectory),
            HELLO => HELLO_GREETING,
            ECHO => &self.echo_data,
            _ => return Err(IpcError::NotFound),
        };

        let offset = offset as usize;
        if offset >= data.len() {
            return Ok(Vec::new());
        }
        let end = core::cmp::min(offset + count as usize, data.len());
        Ok(data[offset..end].to_vec())
    }

    /// Write to the echo file. Replaces the entire buffer (offset is
    /// intentionally ignored — this is a simple echo device, not a
    /// seekable file).
    fn write(&mut self, fid: Fid, _offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if !state.is_open {
            return Err(IpcError::NotOpen);
        }
        if matches!(state.mode, Some(OpenMode::Read)) {
            return Err(IpcError::PermissionDenied);
        }

        match state.qpath {
            ROOT => Err(IpcError::IsDirectory),
            HELLO => Err(IpcError::ReadOnly),
            ECHO => {
                let len = u32::try_from(data.len())
                    .map_err(|_| IpcError::ResourceExhausted)?;
                self.echo_data = data.to_vec();
                Ok(len)
            }
            _ => Err(IpcError::NotFound),
        }
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        self.fids.remove(&fid).ok_or(IpcError::InvalidFid)?;
        Ok(())
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        if self.fids.contains_key(&new_fid) {
            return Err(IpcError::InvalidFid);
        }
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        let qpath = state.qpath;
        self.fids.insert(new_fid, FidState {
            qpath,
            is_open: false,
            mode: None,
        });
        Ok(qpath)
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;

        match state.qpath {
            ROOT => Ok(FileStat {
                qpath: ROOT,
                name: Arc::from("/"),
                size: 0,
                file_type: FileType::Directory,
            }),
            HELLO => Ok(FileStat {
                qpath: HELLO,
                name: Arc::from("hello"),
                size: HELLO_GREETING.len() as u64,
                file_type: FileType::Regular,
            }),
            ECHO => Ok(FileStat {
                qpath: ECHO,
                name: Arc::from("echo"),
                size: self.echo_data.len() as u64,
                file_type: FileType::Regular,
            }),
            _ => Err(IpcError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_hello() {
        let mut server = EchoServer::new();
        let qpath = server.walk(0, 1, "hello").unwrap();
        assert_eq!(qpath, HELLO);
    }

    #[test]
    fn walk_echo() {
        let mut server = EchoServer::new();
        let qpath = server.walk(0, 1, "echo").unwrap();
        assert_eq!(qpath, ECHO);
    }

    #[test]
    fn walk_invalid_name() {
        let mut server = EchoServer::new();
        let err = server.walk(0, 1, "nonexistent").unwrap_err();
        assert_eq!(err, IpcError::NotFound);
    }

    #[test]
    fn walk_from_invalid_fid() {
        let mut server = EchoServer::new();
        let err = server.walk(99, 1, "hello").unwrap_err();
        assert_eq!(err, IpcError::InvalidFid);
    }

    #[test]
    fn read_hello() {
        let mut server = EchoServer::new();
        server.walk(0, 1, "hello").unwrap();
        server.open(1, OpenMode::Read).unwrap();
        let data = server.read(1, 0, 256).unwrap();
        assert_eq!(data, b"Hello from echo server!");
    }

    #[test]
    fn read_without_open() {
        let mut server = EchoServer::new();
        server.walk(0, 1, "hello").unwrap();
        let err = server.read(1, 0, 256).unwrap_err();
        assert_eq!(err, IpcError::NotOpen);
    }

    #[test]
    fn write_then_read_echo() {
        let mut server = EchoServer::new();
        server.walk(0, 1, "echo").unwrap();
        server.open(1, OpenMode::ReadWrite).unwrap();
        let written = server.write(1, 0, b"test data").unwrap();
        assert_eq!(written, 9);
        let data = server.read(1, 0, 256).unwrap();
        assert_eq!(data, b"test data");
    }

    #[test]
    fn open_hello_write_mode_rejected() {
        let mut server = EchoServer::new();
        server.walk(0, 1, "hello").unwrap();
        // Write mode rejected at open time — matches 9P semantics
        assert_eq!(server.open(1, OpenMode::Write), Err(IpcError::ReadOnly));
    }

    #[test]
    fn open_hello_readwrite_mode_rejected() {
        let mut server = EchoServer::new();
        server.walk(0, 1, "hello").unwrap();
        assert_eq!(server.open(1, OpenMode::ReadWrite), Err(IpcError::ReadOnly));
    }

    #[test]
    fn clunk_releases_fid() {
        let mut server = EchoServer::new();
        server.walk(0, 1, "hello").unwrap();
        server.clunk(1).unwrap();
        let err = server.open(1, OpenMode::Read).unwrap_err();
        assert_eq!(err, IpcError::InvalidFid);
    }

    #[test]
    fn read_denied_in_write_mode() {
        let mut server = EchoServer::new();
        server.walk(0, 1, "echo").unwrap();
        server.open(1, OpenMode::Write).unwrap();
        assert_eq!(server.read(1, 0, 256), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn write_denied_in_read_mode() {
        let mut server = EchoServer::new();
        server.walk(0, 1, "echo").unwrap();
        server.open(1, OpenMode::Read).unwrap();
        assert_eq!(
            server.write(1, 0, b"nope"),
            Err(IpcError::PermissionDenied)
        );
    }

    #[test]
    fn walk_duplicate_fid_rejected() {
        let mut server = EchoServer::new();
        server.walk(0, 1, "hello").unwrap();
        assert_eq!(server.walk(0, 1, "echo"), Err(IpcError::InvalidFid));
    }

    #[test]
    fn read_directory_returns_is_directory() {
        let mut server = EchoServer::new();
        server.open(0, OpenMode::Read).unwrap();
        assert_eq!(server.read(0, 0, 256), Err(IpcError::IsDirectory));
    }

    #[test]
    fn open_directory_write_rejected() {
        let mut server = EchoServer::new();
        // Write mode on a directory is rejected at open time
        assert_eq!(server.open(0, OpenMode::Write), Err(IpcError::IsDirectory));
        assert_eq!(server.open(0, OpenMode::ReadWrite), Err(IpcError::IsDirectory));
    }

    #[test]
    fn double_open_rejected() {
        let mut server = EchoServer::new();
        server.walk(0, 1, "hello").unwrap();
        server.open(1, OpenMode::Read).unwrap();
        assert_eq!(server.open(1, OpenMode::ReadWrite), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn stat_root() {
        let mut server = EchoServer::new();
        let stat = server.stat(0).unwrap();
        assert_eq!(stat.file_type, FileType::Directory);
        assert_eq!(&*stat.name, "/");
    }

    #[test]
    fn stat_hello() {
        let mut server = EchoServer::new();
        server.walk(0, 1, "hello").unwrap();
        let stat = server.stat(1).unwrap();
        assert_eq!(stat.file_type, FileType::Regular);
        assert_eq!(&*stat.name, "hello");
    }
}
