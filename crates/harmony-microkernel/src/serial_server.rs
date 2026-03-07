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

struct FidState {
    qpath: QPath,
    is_open: bool,
}

/// A FileServer that captures writes to a buffer.
///
/// In tests, call `buffer()` to inspect what was written.
/// In the boot crate, the buffer can be drained to a real serial port.
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
        fids.insert(0, FidState { qpath: QPATH_ROOT, is_open: false });
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
        if name != "log" {
            return Err(IpcError::NotFound);
        }
        self.fids.insert(new_fid, FidState { qpath: QPATH_LOG, is_open: false });
        Ok(QPATH_LOG)
    }

    fn open(&mut self, fid: Fid, _mode: OpenMode) -> Result<(), IpcError> {
        let state = self.fids.get_mut(&fid).ok_or(IpcError::InvalidFid)?;
        state.is_open = true;
        Ok(())
    }

    fn read(&mut self, fid: Fid, _offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if !state.is_open {
            return Err(IpcError::NotOpen);
        }
        let end = core::cmp::min(self.buf.len(), count as usize);
        Ok(self.buf[..end].to_vec())
    }

    fn write(&mut self, fid: Fid, _offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if !state.is_open {
            return Err(IpcError::NotOpen);
        }
        self.buf.extend_from_slice(data);
        Ok(data.len() as u32)
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        self.fids.remove(&fid).ok_or(IpcError::InvalidFid)?;
        Ok(())
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
}
