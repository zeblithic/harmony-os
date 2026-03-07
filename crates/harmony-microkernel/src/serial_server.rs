// SPDX-License-Identifier: GPL-2.0-or-later
//! KernelSerialServer — serial output as a FileServer.
//!
//! Exposes a single writable file `log`. Write bytes to it and they
//! accumulate in an internal buffer (or go to a real serial port in
//! the boot crate).

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{Fid, FileServer, FileStat, FileType, IpcError, OpenMode, QPath};

const QPATH_ROOT: QPath = 0;
const QPATH_LOG: QPath = 1;

// TODO: FidState and open/clunk/clone_fid are duplicated with EchoServer.
// Extract a shared FidTracker helper when a third server appears.
struct FidState {
    qpath: QPath,
    is_open: bool,
    mode: Option<OpenMode>,
}

/// A FileServer that captures writes to a buffer.
///
/// In tests, call `buffer()` to inspect what was written.
/// In the boot crate, the buffer can be drained to a real serial port.
///
/// **Note:** The internal buffer grows without bound on each write.
/// For long-running bare-metal use, the caller should periodically
/// drain via `buffer()` or impose an external write budget.
pub struct SerialServer {
    fids: BTreeMap<Fid, FidState>,
    buf: Vec<u8>,
}

impl Default for SerialServer {
    fn default() -> Self {
        Self::new()
    }
}

impl SerialServer {
    pub fn new() -> Self {
        let mut fids = BTreeMap::new();
        fids.insert(0, FidState { qpath: QPATH_ROOT, is_open: false, mode: None });
        SerialServer { fids, buf: Vec::new() }
    }

    /// Access the accumulated write buffer.
    pub fn buffer(&self) -> &[u8] {
        &self.buf
    }
}

impl FileServer for SerialServer {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if state.qpath != QPATH_ROOT {
            return Err(IpcError::NotDirectory);
        }
        if self.fids.contains_key(&new_fid) {
            return Err(IpcError::InvalidFid);
        }
        if name != "log" {
            return Err(IpcError::NotFound);
        }
        self.fids.insert(new_fid, FidState { qpath: QPATH_LOG, is_open: false, mode: None });
        Ok(QPATH_LOG)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let state = self.fids.get_mut(&fid).ok_or(IpcError::InvalidFid)?;
        if state.is_open {
            return Err(IpcError::PermissionDenied);
        }
        // Reject write modes on directories at open time (9P semantics).
        if state.qpath == QPATH_ROOT && matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
            return Err(IpcError::IsDirectory);
        }
        state.is_open = true;
        state.mode = Some(mode);
        Ok(())
    }

    /// Read from the log buffer. Offset is honored so callers can
    /// page through the accumulated log. Write offset is still ignored
    /// (append-only).
    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if !state.is_open {
            return Err(IpcError::NotOpen);
        }
        if state.qpath == QPATH_ROOT {
            return Err(IpcError::IsDirectory);
        }
        if matches!(state.mode, Some(OpenMode::Write)) {
            return Err(IpcError::PermissionDenied);
        }
        let start = core::cmp::min(offset.min(usize::MAX as u64) as usize, self.buf.len());
        let end = core::cmp::min(start + count as usize, self.buf.len());
        Ok(self.buf[start..end].to_vec())
    }

    /// Write appends data to the log buffer. Offset is intentionally
    /// ignored — this is an append-only log.
    fn write(&mut self, fid: Fid, _offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if !state.is_open {
            return Err(IpcError::NotOpen);
        }
        if state.qpath == QPATH_ROOT {
            return Err(IpcError::IsDirectory);
        }
        if matches!(state.mode, Some(OpenMode::Read)) {
            return Err(IpcError::PermissionDenied);
        }
        let len = u32::try_from(data.len())
            .map_err(|_| IpcError::ResourceExhausted)?;
        self.buf.extend_from_slice(data);
        Ok(len)
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        if fid == 0 {
            return Err(IpcError::PermissionDenied);
        }
        self.fids.remove(&fid).ok_or(IpcError::InvalidFid)?;
        Ok(())
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        if self.fids.contains_key(&new_fid) {
            return Err(IpcError::InvalidFid);
        }
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        let qpath = state.qpath;
        self.fids.insert(new_fid, FidState { qpath, is_open: false, mode: None });
        Ok(qpath)
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        let (name, file_type, size) = match state.qpath {
            QPATH_ROOT => ("/", FileType::Directory, 0),
            QPATH_LOG => ("log", FileType::Regular, self.buf.len() as u64),
            _ => return Err(IpcError::NotFound),
        };
        Ok(FileStat {
            qpath: state.qpath,
            name: Arc::from(name),
            size,
            file_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_to_log() {
        let mut srv = SerialServer::new();
        let qpath = srv.walk(0, 1, "log").unwrap();
        assert_eq!(qpath, 1);
    }

    #[test]
    fn write_captures_data() {
        let mut srv = SerialServer::new();
        srv.walk(0, 1, "log").unwrap();
        srv.open(1, OpenMode::Write).unwrap();
        srv.write(1, 0, b"hello serial").unwrap();
        assert_eq!(srv.buffer(), b"hello serial");
    }

    #[test]
    fn multiple_writes_append() {
        let mut srv = SerialServer::new();
        srv.walk(0, 1, "log").unwrap();
        srv.open(1, OpenMode::Write).unwrap();
        srv.write(1, 0, b"hello ").unwrap();
        srv.write(1, 0, b"world").unwrap();
        assert_eq!(srv.buffer(), b"hello world");
    }

    #[test]
    fn read_returns_buffer() {
        let mut srv = SerialServer::new();
        srv.walk(0, 1, "log").unwrap();
        srv.open(1, OpenMode::ReadWrite).unwrap();
        srv.write(1, 0, b"data").unwrap();
        let data = srv.read(1, 0, 256).unwrap();
        assert_eq!(data, b"data");
    }

    #[test]
    fn walk_invalid_name() {
        let mut srv = SerialServer::new();
        assert_eq!(srv.walk(0, 1, "nonexistent"), Err(IpcError::NotFound));
    }

    #[test]
    fn read_directory_denied() {
        let mut srv = SerialServer::new();
        srv.open(0, OpenMode::Read).unwrap();
        assert_eq!(srv.read(0, 0, 256), Err(IpcError::IsDirectory));
    }

    #[test]
    fn open_directory_write_rejected() {
        let mut srv = SerialServer::new();
        // Write mode on a directory is rejected at open time
        assert_eq!(srv.open(0, OpenMode::Write), Err(IpcError::IsDirectory));
        assert_eq!(srv.open(0, OpenMode::ReadWrite), Err(IpcError::IsDirectory));
    }

    #[test]
    fn read_denied_in_write_mode() {
        let mut srv = SerialServer::new();
        srv.walk(0, 1, "log").unwrap();
        srv.open(1, OpenMode::Write).unwrap();
        srv.write(1, 0, b"data").unwrap();
        assert_eq!(srv.read(1, 0, 256), Err(IpcError::PermissionDenied));
    }
}
