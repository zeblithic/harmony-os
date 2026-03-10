// SPDX-License-Identifier: GPL-2.0-or-later

//! UartServer — 9P file server for a PL011 UART.
//!
//! Exposes a single character device file `uart0` with stream semantics
//! (offset ignored on both read and write).

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use harmony_unikernel::drivers::pl011::Pl011Driver;
use harmony_unikernel::drivers::RegisterBank;

use crate::{Fid, FileServer, FileStat, FileType, IpcError, OpenMode, QPath};

const QPATH_ROOT: QPath = 0;
const QPATH_UART0: QPath = 1;

struct FidState {
    qpath: QPath,
    is_open: bool,
    mode: Option<OpenMode>,
}

/// A 9P file server wrapping a [`Pl011Driver`] and [`RegisterBank`].
///
/// Walk to `"uart0"` to get a character device fid.
/// Read polls the RX FIFO and returns buffered data (offset ignored).
/// Write sends bytes to the TX FIFO (offset ignored).
pub struct UartServer<B: RegisterBank, const N: usize> {
    driver: Pl011Driver<N>,
    bank: B,
    fids: BTreeMap<Fid, FidState>,
}

impl<B: RegisterBank, const N: usize> UartServer<B, N> {
    /// Create a new UartServer with the given driver and register bank.
    ///
    /// The caller should have already called `driver.init()` before
    /// constructing the server.
    pub fn new(driver: Pl011Driver<N>, bank: B) -> Self {
        let mut fids = BTreeMap::new();
        fids.insert(
            0,
            FidState {
                qpath: QPATH_ROOT,
                is_open: false,
                mode: None,
            },
        );
        Self { driver, bank, fids }
    }
}

impl<B: RegisterBank, const N: usize> FileServer for UartServer<B, N> {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        if state.qpath != QPATH_ROOT {
            return Err(IpcError::NotDirectory);
        }
        if self.fids.contains_key(&new_fid) {
            return Err(IpcError::InvalidFid);
        }
        if name != "uart0" {
            return Err(IpcError::NotFound);
        }
        self.fids.insert(
            new_fid,
            FidState {
                qpath: QPATH_UART0,
                is_open: false,
                mode: None,
            },
        );
        Ok(QPATH_UART0)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let state = self.fids.get_mut(&fid).ok_or(IpcError::InvalidFid)?;
        if state.is_open {
            return Err(IpcError::PermissionDenied);
        }
        if state.qpath == QPATH_ROOT && matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
            return Err(IpcError::IsDirectory);
        }
        state.is_open = true;
        state.mode = Some(mode);
        Ok(())
    }

    fn read(&mut self, fid: Fid, _offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
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
        // Poll hardware, then drain ring buffer.
        self.driver.poll_rx(&self.bank);
        let max = count as usize;
        let mut buf = alloc::vec![0u8; max.min(self.driver.rx_available())];
        self.driver.read_buffered(&mut buf);
        Ok(buf)
    }

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
        let len = u32::try_from(data.len()).map_err(|_| IpcError::ResourceExhausted)?;
        self.driver.write_bytes(&mut self.bank, data);
        Ok(len)
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        if fid == 0 {
            return Ok(()); // Root fid is permanent.
        }
        self.fids.remove(&fid).ok_or(IpcError::InvalidFid)?;
        Ok(())
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        let (name, file_type) = match state.qpath {
            QPATH_ROOT => ("uart", FileType::Directory),
            QPATH_UART0 => ("uart0", FileType::Regular),
            _ => return Err(IpcError::NotFound),
        };
        Ok(FileStat {
            qpath: state.qpath,
            name: Arc::from(name),
            size: 0, // stream device
            file_type,
        })
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        if self.fids.contains_key(&new_fid) {
            return Err(IpcError::InvalidFid);
        }
        let state = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        let qpath = state.qpath;
        self.fids.insert(
            new_fid,
            FidState {
                qpath,
                is_open: false,
                mode: None,
            },
        );
        Ok(qpath)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harmony_unikernel::drivers::register_bank::mock::MockRegisterBank;

    const UARTFR: usize = 0x018;
    const UARTDR: usize = 0x000;
    const UARTFR_RXFE: u32 = 1 << 4;

    fn test_server() -> UartServer<MockRegisterBank, 256> {
        let driver = Pl011Driver::new();
        let bank = MockRegisterBank::new();
        UartServer::new(driver, bank)
    }

    #[test]
    fn walk_to_uart0() {
        let mut srv = test_server();
        let qpath = srv.walk(0, 1, "uart0").unwrap();
        assert_eq!(qpath, QPATH_UART0);
    }

    #[test]
    fn walk_invalid_name() {
        let mut srv = test_server();
        assert_eq!(srv.walk(0, 1, "nonexistent"), Err(IpcError::NotFound));
    }

    #[test]
    fn write_sends_to_driver() {
        let mut srv = test_server();
        // Configure FR to return 0 (FIFO not full) for TX.
        srv.bank.on_read(UARTFR, vec![0]);

        srv.walk(0, 1, "uart0").unwrap();
        srv.open(1, OpenMode::Write).unwrap();
        let n = srv.write(1, 0, b"Hi").unwrap();
        assert_eq!(n, 2);

        let data_writes: Vec<u32> = srv
            .bank
            .writes
            .iter()
            .filter(|(off, _)| *off == UARTDR)
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(data_writes, vec![b'H' as u32, b'i' as u32]);
    }

    #[test]
    fn read_returns_rx_data() {
        let mut srv = test_server();
        // Pre-load RX FIFO with data.
        srv.bank.on_read(UARTFR, vec![0, 0, UARTFR_RXFE]);
        srv.bank.on_read(UARTDR, vec![b'X' as u32, b'Y' as u32]);

        srv.walk(0, 1, "uart0").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 0, 256).unwrap();
        assert_eq!(data, b"XY");
    }

    #[test]
    fn read_empty_returns_empty_vec() {
        let mut srv = test_server();
        // RX FIFO is empty.
        srv.bank.on_read(UARTFR, vec![UARTFR_RXFE]);

        srv.walk(0, 1, "uart0").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 0, 256).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn write_denied_in_read_mode() {
        let mut srv = test_server();
        srv.walk(0, 1, "uart0").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        assert_eq!(srv.write(1, 0, b"nope"), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn read_denied_in_write_mode() {
        let mut srv = test_server();
        srv.walk(0, 1, "uart0").unwrap();
        srv.open(1, OpenMode::Write).unwrap();
        assert_eq!(srv.read(1, 0, 256), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn stat_root() {
        let mut srv = test_server();
        let st = srv.stat(0).unwrap();
        assert_eq!(&*st.name, "uart");
        assert_eq!(st.file_type, FileType::Directory);
    }

    #[test]
    fn stat_uart0() {
        let mut srv = test_server();
        srv.walk(0, 1, "uart0").unwrap();
        let st = srv.stat(1).unwrap();
        assert_eq!(&*st.name, "uart0");
        assert_eq!(st.file_type, FileType::Regular);
        assert_eq!(st.size, 0); // stream device
    }

    #[test]
    fn clunk_root_is_noop() {
        let mut srv = test_server();
        srv.clunk(0).unwrap();
        // Root should still work.
        srv.walk(0, 1, "uart0").unwrap();
    }

    #[test]
    fn clunk_releases_fid() {
        let mut srv = test_server();
        srv.walk(0, 1, "uart0").unwrap();
        srv.clunk(1).unwrap();
        assert_eq!(srv.stat(1), Err(IpcError::InvalidFid));
    }

    #[test]
    fn clone_fid_duplicates_state() {
        let mut srv = test_server();
        srv.walk(0, 1, "uart0").unwrap();
        let qpath = srv.clone_fid(1, 2).unwrap();
        assert_eq!(qpath, QPATH_UART0);
        // Cloned fid should be stat-able but not open
        let st = srv.stat(2).unwrap();
        assert_eq!(&*st.name, "uart0");
        assert_eq!(srv.read(2, 0, 256), Err(IpcError::NotOpen));
    }

    #[test]
    fn readwrite_mode_allows_both() {
        let mut srv = test_server();
        // FR sequence: 0 (TX not full for write), then RXFE (RX empty for read)
        srv.bank.on_read(UARTFR, vec![0, UARTFR_RXFE]);

        srv.walk(0, 1, "uart0").unwrap();
        srv.open(1, OpenMode::ReadWrite).unwrap();
        // Write should succeed
        let n = srv.write(1, 0, b"A").unwrap();
        assert_eq!(n, 1);
        // Read should succeed (returns empty since no RX data)
        let data = srv.read(1, 0, 256).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn walk_from_non_root_rejected() {
        let mut srv = test_server();
        srv.walk(0, 1, "uart0").unwrap();
        // Fid 1 is uart0 (not a directory) — walk should fail
        assert_eq!(srv.walk(1, 2, "uart0"), Err(IpcError::NotDirectory));
    }
}
