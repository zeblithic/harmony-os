// SPDX-License-Identifier: GPL-2.0-or-later

//! GenetServer — 9P file server for a BCM54213PE GENET Ethernet interface.
//!
//! Exposes a directory `genet0` with five files:
//! - `data`  — read/write raw Ethernet frames (packet-per-operation)
//! - `mac`   — read-only MAC address ("aa:bb:cc:dd:ee:ff\n")
//! - `mtu`   — read-only MTU ("1500\n")
//! - `stats` — read-only interface statistics
//! - `link`  — read-only link status ("up\n" or "down\n")

extern crate alloc;

use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use harmony_unikernel::drivers::genet::{GenetDriver, GenetError};
use harmony_unikernel::drivers::RegisterBank;

use crate::fid_tracker::FidTracker;
use crate::{Fid, FileServer, FileStat, FileType, IpcError, OpenMode, QPath};

// QPath assignments
const QPATH_ROOT: QPath = 0;
const QPATH_DIR: QPath = 1; // /dev/net/genet0/ directory
const QPATH_DATA: QPath = 2;
const QPATH_MAC: QPath = 3;
const QPATH_MTU: QPath = 4;
const QPATH_STATS: QPath = 5;
const QPATH_LINK: QPath = 6;

/// A 9P file server wrapping a [`GenetDriver`] and [`RegisterBank`].
///
/// Walk to `"genet0"` to enter the device directory, then walk to
/// individual files (`data`, `mac`, `mtu`, `stats`, `link`).
pub struct GenetServer<B: RegisterBank, const RX: usize, const TX: usize> {
    driver: GenetDriver<RX, TX>,
    bank: B,
    tracker: FidTracker<()>,
    /// MDIO poll count for link status reads.
    mdio_polls: u32,
}

impl<B: RegisterBank, const RX: usize, const TX: usize> GenetServer<B, RX, TX> {
    /// Create a new GenetServer with an already-initialized driver.
    pub fn new(driver: GenetDriver<RX, TX>, bank: B) -> Self {
        Self {
            driver,
            bank,
            tracker: FidTracker::new(QPATH_ROOT, ()),
            mdio_polls: 100,
        }
    }

    fn is_directory(qpath: QPath) -> bool {
        matches!(qpath, QPATH_ROOT | QPATH_DIR)
    }

    fn is_read_only(qpath: QPath) -> bool {
        matches!(qpath, QPATH_MAC | QPATH_MTU | QPATH_STATS | QPATH_LINK)
    }

    fn child_qpath(parent: QPath, name: &str) -> Result<QPath, IpcError> {
        match (parent, name) {
            (QPATH_ROOT, "genet0") => Ok(QPATH_DIR),
            (QPATH_DIR, "data") => Ok(QPATH_DATA),
            (QPATH_DIR, "mac") => Ok(QPATH_MAC),
            (QPATH_DIR, "mtu") => Ok(QPATH_MTU),
            (QPATH_DIR, "stats") => Ok(QPATH_STATS),
            (QPATH_DIR, "link") => Ok(QPATH_LINK),
            _ => Err(IpcError::NotFound),
        }
    }

    /// Slice `bytes` starting at `offset`, returning at most `max` bytes.
    /// Returns an empty vec if offset is past the end — signaling EOF to 9P clients.
    fn slice_at_offset(bytes: &[u8], offset: u64, max: usize) -> Vec<u8> {
        let start = (offset.min(usize::MAX as u64) as usize).min(bytes.len());
        let end = start.saturating_add(max).min(bytes.len());
        bytes[start..end].to_vec()
    }

    fn qpath_name(qpath: QPath) -> &'static str {
        match qpath {
            QPATH_ROOT => "/",
            QPATH_DIR => "genet0",
            QPATH_DATA => "data",
            QPATH_MAC => "mac",
            QPATH_MTU => "mtu",
            QPATH_STATS => "stats",
            QPATH_LINK => "link",
            _ => "?",
        }
    }
}

impl<B: RegisterBank, const RX: usize, const TX: usize> FileServer for GenetServer<B, RX, TX> {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let entry = self.tracker.get(fid)?;
        if entry.is_open() {
            return Err(IpcError::PermissionDenied); // 9P: cannot walk from an open fid
        }
        if !Self::is_directory(entry.qpath) {
            return Err(IpcError::NotDirectory);
        }
        let parent_qpath = entry.qpath; // Copy before mutating tracker
        let qpath = Self::child_qpath(parent_qpath, name)?;
        // 9P2000: new_fid may equal fid (in-place walk replaces the binding)
        if new_fid == fid {
            // In-place walk: replace existing entry
            let entry = self.tracker.get_mut(fid)?;
            entry.qpath = qpath;
            entry.reset_open_state();
        } else {
            self.tracker.insert(new_fid, qpath, ())?;
        }
        Ok(qpath)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let entry = self.tracker.begin_open(fid)?;
        if Self::is_directory(entry.qpath) {
            return Err(IpcError::IsDirectory);
        }
        if Self::is_read_only(entry.qpath) && matches!(mode, OpenMode::Write | OpenMode::ReadWrite)
        {
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
        if Self::is_directory(entry.qpath) {
            return Err(IpcError::IsDirectory);
        }
        if matches!(entry.mode(), Some(OpenMode::Write)) {
            return Err(IpcError::PermissionDenied);
        }

        let qpath = entry.qpath; // Copy before match to avoid borrow conflict
        let max = count as usize;
        match qpath {
            QPATH_DATA => {
                // Streaming semantics: offset is ignored, each read returns
                // the next pending frame (or empty if none available).
                // Guard: poll_rx is destructive (advances consumer index),
                // so a zero-count read must not consume a frame.
                if max == 0 {
                    return Ok(Vec::new());
                }
                match self.driver.poll_rx(&mut self.bank) {
                    Some(frame) => {
                        if frame.data.len() > max {
                            // Frame too large for caller's buffer.
                            // The frame is already consumed from the DMA ring —
                            // returning truncated data would give the caller a
                            // structurally invalid Ethernet frame with no indication.
                            return Err(IpcError::InvalidArgument);
                        }
                        Ok(frame.data)
                    }
                    None => Ok(Vec::new()),
                }
            }
            QPATH_MAC => {
                let m = self.driver.mac();
                let s = format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                    m[0], m[1], m[2], m[3], m[4], m[5]
                );
                let bytes = s.into_bytes();
                Ok(Self::slice_at_offset(&bytes, offset, max))
            }
            QPATH_MTU => {
                let bytes = b"1500\n";
                Ok(Self::slice_at_offset(bytes, offset, max))
            }
            QPATH_STATS => {
                let stats = self.driver.stats();
                let s = format!(
                    "rx_packets: {}\ntx_packets: {}\nrx_errors: {}\ntx_errors: {}\n",
                    stats.rx_packets, stats.tx_packets, stats.rx_errors, stats.tx_errors
                );
                let bytes = s.into_bytes();
                Ok(Self::slice_at_offset(&bytes, offset, max))
            }
            QPATH_LINK => {
                let up = self
                    .driver
                    .link_status(&mut self.bank, self.mdio_polls)
                    .map_err(|_e: GenetError| {
                        // MdioTimeout / MdioReadFail: PHY bus unresponsive or NACK;
                        // no perfect IpcError variant — ResourceExhausted is the
                        // closest available approximation.
                        IpcError::ResourceExhausted
                    })?;
                let bytes: &[u8] = if up { b"up\n" } else { b"down\n" };
                Ok(Self::slice_at_offset(bytes, offset, max))
            }
            _ => Err(IpcError::NotFound),
        }
    }

    fn write(&mut self, fid: Fid, _offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.is_open() {
            return Err(IpcError::NotOpen);
        }
        if Self::is_directory(entry.qpath) {
            return Err(IpcError::IsDirectory);
        }
        if matches!(entry.mode(), Some(OpenMode::Read)) {
            return Err(IpcError::PermissionDenied);
        }

        let qpath = entry.qpath; // Copy before match to avoid borrow conflict
        match qpath {
            QPATH_DATA => {
                self.driver.send(&mut self.bank, data).map_err(|e| match e {
                    GenetError::TxRingFull => IpcError::ResourceExhausted,
                    _ => IpcError::InvalidArgument,
                })?;
                Ok(data.len() as u32)
            }
            _ => Err(IpcError::ReadOnly),
        }
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        self.tracker.clunk(fid)
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let qpath = self.tracker.get(fid)?.qpath;
        let name = Self::qpath_name(qpath);
        let file_type = if Self::is_directory(qpath) {
            FileType::Directory
        } else {
            FileType::Regular
        };
        Ok(FileStat {
            qpath,
            name: Arc::from(name),
            size: match qpath {
                QPATH_MAC => 18, // "aa:bb:cc:dd:ee:ff\n"
                QPATH_MTU => 5,  // "1500\n"
                _ => 0,          // stream or dynamic content
            },
            file_type,
        })
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        self.tracker.clone_fid(fid, new_fid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harmony_unikernel::drivers::genet::GenetDriver;
    use harmony_unikernel::drivers::register_bank::mock::MockRegisterBank;

    // Re-export register constants needed for mock setup
    // (These match the constants in genet.rs — we need the DMA status
    // offsets to set up the mock for init)
    const TDMA_OFF: usize = 0x4000;
    const RDMA_OFF: usize = 0x2000;
    const DMA_RINGS_SIZE: usize = 0x40 * 17;
    const DMA_STATUS: usize = DMA_RINGS_SIZE + 0x04;
    const DMA_STATUS_DISABLED: u32 = 1 << 0; // matches genet::DMA_STATUS_DISABLED
    const DMA_DESC_BASE_OFFSET: usize = 0x10; // matches genet::DMA_DESC_BASE_OFFSET

    // UMAC MDIO register for link status tests
    const UMAC_MDIO_CMD: usize = 0x0800 + 0x614;
    const BMSR_LSTATUS: u32 = 0x0004;

    const TEST_MAC: [u8; 6] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];

    fn test_server() -> GenetServer<MockRegisterBank, 256, 256> {
        let mut bank = MockRegisterBank::new();
        bank.on_read(TDMA_OFF + DMA_STATUS, alloc::vec![DMA_STATUS_DISABLED]);
        bank.on_read(RDMA_OFF + DMA_STATUS, alloc::vec![DMA_STATUS_DISABLED]);
        let driver = GenetDriver::init(&mut bank, TEST_MAC, 10).unwrap();
        GenetServer::new(driver, bank)
    }

    // ── Walk tests ────────────────────────────────────────────────

    #[test]
    fn walk_to_genet0_directory() {
        let mut srv = test_server();
        let qpath = srv.walk(0, 1, "genet0").unwrap();
        assert_eq!(qpath, QPATH_DIR);
    }

    #[test]
    fn walk_to_data_file() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        let qpath = srv.walk(1, 2, "data").unwrap();
        assert_eq!(qpath, QPATH_DATA);
    }

    #[test]
    fn walk_to_all_files() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        assert_eq!(srv.walk(1, 2, "data").unwrap(), QPATH_DATA);
        assert_eq!(srv.walk(1, 3, "mac").unwrap(), QPATH_MAC);
        assert_eq!(srv.walk(1, 4, "mtu").unwrap(), QPATH_MTU);
        assert_eq!(srv.walk(1, 5, "stats").unwrap(), QPATH_STATS);
        assert_eq!(srv.walk(1, 6, "link").unwrap(), QPATH_LINK);
    }

    #[test]
    fn walk_in_place_replaces_fid() {
        let mut srv = test_server();
        // Walk fid 0 (root) to genet0, in place (new_fid == fid)
        let qpath = srv.walk(0, 0, "genet0").unwrap();
        assert_eq!(qpath, QPATH_DIR);
        // Fid 0 is now genet0 directory, can walk to children
        assert_eq!(srv.walk(0, 1, "data").unwrap(), QPATH_DATA);
    }

    #[test]
    fn walk_invalid_name() {
        let mut srv = test_server();
        assert_eq!(srv.walk(0, 1, "nonexistent"), Err(IpcError::NotFound));
    }

    #[test]
    fn walk_from_open_fid_rejected() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "data").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        // 9P forbids walking from an open fid
        assert_eq!(srv.walk(2, 3, "mac"), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn walk_from_file_rejected() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "data").unwrap();
        assert_eq!(srv.walk(2, 3, "mac"), Err(IpcError::NotDirectory));
    }

    // ── Open tests ────────────────────────────────────────────────

    #[test]
    fn open_read_only_files_reject_write() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "mac").unwrap();
        assert_eq!(srv.open(2, OpenMode::Write), Err(IpcError::ReadOnly));
        assert_eq!(srv.open(2, OpenMode::ReadWrite), Err(IpcError::ReadOnly));
    }

    #[test]
    fn open_directory_rejected() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        assert_eq!(srv.open(1, OpenMode::Read), Err(IpcError::IsDirectory));
        assert_eq!(srv.open(1, OpenMode::Write), Err(IpcError::IsDirectory));
        assert_eq!(srv.open(1, OpenMode::ReadWrite), Err(IpcError::IsDirectory));
    }

    #[test]
    fn open_data_readwrite() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "data").unwrap();
        assert!(srv.open(2, OpenMode::ReadWrite).is_ok());
    }

    // ── Stat tests ────────────────────────────────────────────────

    #[test]
    fn stat_root() {
        let mut srv = test_server();
        let st = srv.stat(0).unwrap();
        assert_eq!(&*st.name, "/");
        assert_eq!(st.file_type, FileType::Directory);
    }

    #[test]
    fn stat_genet0_directory() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        let st = srv.stat(1).unwrap();
        assert_eq!(&*st.name, "genet0");
        assert_eq!(st.file_type, FileType::Directory);
    }

    #[test]
    fn stat_data_file() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "data").unwrap();
        let st = srv.stat(2).unwrap();
        assert_eq!(&*st.name, "data");
        assert_eq!(st.file_type, FileType::Regular);
        assert_eq!(st.size, 0); // streaming — size unknown
    }

    #[test]
    fn stat_fixed_size_files() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();

        srv.walk(1, 2, "mac").unwrap();
        assert_eq!(srv.stat(2).unwrap().size, 18); // "aa:bb:cc:dd:ee:ff\n"

        srv.walk(1, 3, "mtu").unwrap();
        assert_eq!(srv.stat(3).unwrap().size, 5); // "1500\n"

        srv.walk(1, 4, "stats").unwrap();
        assert_eq!(srv.stat(4).unwrap().size, 0); // dynamic

        srv.walk(1, 5, "link").unwrap();
        assert_eq!(srv.stat(5).unwrap().size, 0); // dynamic
    }

    // ── Clunk tests ───────────────────────────────────────────────

    #[test]
    fn clunk_root_rejected() {
        let mut srv = test_server();
        assert_eq!(srv.clunk(0), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn clunk_releases_fid() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.clunk(1).unwrap();
        assert_eq!(srv.stat(1), Err(IpcError::InvalidFid));
    }

    // ── Clone fid tests ───────────────────────────────────────────

    #[test]
    fn clone_fid_duplicates() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        let qpath = srv.clone_fid(1, 2).unwrap();
        assert_eq!(qpath, QPATH_DIR);
        let st = srv.stat(2).unwrap();
        assert_eq!(&*st.name, "genet0");
    }

    // ── Read control files ────────────────────────────────────────

    #[test]
    fn read_mac() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "mac").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 256).unwrap();
        assert_eq!(data, b"de:ad:be:ef:ca:fe\n");
    }

    #[test]
    fn read_mac_with_offset() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "mac").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        // Full content is "de:ad:be:ef:ca:fe\n" (18 bytes)
        let chunk1 = srv.read(2, 0, 10).unwrap();
        let chunk2 = srv.read(2, 10, 10).unwrap();
        assert_eq!(chunk1, b"de:ad:be:e");
        assert_eq!(chunk2, b"f:ca:fe\n");
        // Past end returns empty (EOF)
        let eof = srv.read(2, 18, 10).unwrap();
        assert!(eof.is_empty());
    }

    #[test]
    fn read_mtu() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "mtu").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 256).unwrap();
        assert_eq!(data, b"1500\n");
    }

    #[test]
    fn read_mtu_with_offset() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "mtu").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let chunk = srv.read(2, 3, 256).unwrap();
        assert_eq!(chunk, b"0\n");
    }

    #[test]
    fn read_link_down() {
        let mut srv = test_server();
        // MDIO returns 0 (no link)
        srv.bank.on_read(UMAC_MDIO_CMD, alloc::vec![0]);
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "link").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 256).unwrap();
        assert_eq!(data, b"down\n");
    }

    #[test]
    fn read_link_up() {
        let mut srv = test_server();
        // MDIO returns BMSR_LSTATUS (link up)
        srv.bank.on_read(UMAC_MDIO_CMD, alloc::vec![BMSR_LSTATUS]);
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "link").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 256).unwrap();
        assert_eq!(data, b"up\n");
    }

    #[test]
    fn read_stats_format() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "stats").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 1024).unwrap();
        let text = core::str::from_utf8(&data).unwrap();
        assert!(text.contains("rx_packets: 0"));
        assert!(text.contains("tx_packets: 0"));
        assert!(text.contains("rx_errors: 0"));
        assert!(text.contains("tx_errors: 0"));
    }

    // ── Write to read-only files ──────────────────────────────────

    #[test]
    fn write_to_mac_rejected() {
        let mut srv = test_server();
        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "mac").unwrap();
        // Can't even open in write mode
        assert_eq!(srv.open(2, OpenMode::Write), Err(IpcError::ReadOnly));
    }

    // ── Data file TX/RX ───────────────────────────────────────────

    // GENET driver register constants for mock setup
    const DEFAULT_RING: usize = 16;
    const DMA_RING_SIZE: usize = 0x40;
    const RING_CONS_INDEX: usize = 0x0C;
    const RING_PROD_INDEX: usize = 0x08;
    const DMA_DESC_LENGTH_STATUS: usize = 0x00;
    const DMA_SOP: u32 = 0x2000;
    const DMA_EOP: u32 = 0x4000;
    const DMA_BUFLENGTH_SHIFT: u32 = 16;

    #[test]
    fn write_data_sends_frame() {
        let mut srv = test_server();

        // Set up TX ring as available
        let tx_ring_base = TDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        srv.bank
            .on_read(tx_ring_base + RING_CONS_INDEX, alloc::vec![0]);

        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "data").unwrap();
        srv.open(2, OpenMode::Write).unwrap();
        let n = srv.write(2, 0, &[0xAA; 64]).unwrap();
        assert_eq!(n, 64);
    }

    #[test]
    fn read_data_returns_rx_frame() {
        let mut srv = test_server();

        // Set up RX ring with one frame
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        srv.bank
            .on_read(rx_ring_base + RING_PROD_INDEX, alloc::vec![1]);

        let desc_base = RDMA_OFF + DMA_RINGS_SIZE + DMA_DESC_BASE_OFFSET;
        let len_status = (64u32 << DMA_BUFLENGTH_SHIFT) | DMA_SOP | DMA_EOP;
        srv.bank
            .on_read(desc_base + DMA_DESC_LENGTH_STATUS, alloc::vec![len_status]);

        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "data").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 2048).unwrap();
        assert_eq!(data.len(), 64);
    }

    #[test]
    fn read_data_undersized_buffer_returns_error() {
        let mut srv = test_server();

        // Set up RX ring with one 64-byte frame
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        srv.bank
            .on_read(rx_ring_base + RING_PROD_INDEX, alloc::vec![1]);

        let desc_base = RDMA_OFF + DMA_RINGS_SIZE + DMA_DESC_BASE_OFFSET;
        let len_status = (64u32 << DMA_BUFLENGTH_SHIFT) | DMA_SOP | DMA_EOP;
        srv.bank
            .on_read(desc_base + DMA_DESC_LENGTH_STATUS, alloc::vec![len_status]);

        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "data").unwrap();
        srv.open(2, OpenMode::Read).unwrap();

        // Read with buffer smaller than frame — must error, not truncate
        assert_eq!(srv.read(2, 0, 32), Err(IpcError::InvalidArgument));
    }

    #[test]
    fn read_data_zero_count_does_not_consume_frame() {
        let mut srv = test_server();

        // Set up RX ring with one frame
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        srv.bank
            .on_read(rx_ring_base + RING_PROD_INDEX, alloc::vec![1, 1]);

        let desc_base = RDMA_OFF + DMA_RINGS_SIZE + DMA_DESC_BASE_OFFSET;
        let len_status = (64u32 << DMA_BUFLENGTH_SHIFT) | DMA_SOP | DMA_EOP;
        srv.bank
            .on_read(desc_base + DMA_DESC_LENGTH_STATUS, alloc::vec![len_status]);

        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "data").unwrap();
        srv.open(2, OpenMode::Read).unwrap();

        // Zero-count read must not consume the frame
        let data = srv.read(2, 0, 0).unwrap();
        assert!(data.is_empty());

        // The frame should still be available
        let data = srv.read(2, 0, 2048).unwrap();
        assert_eq!(data.len(), 64);
    }

    #[test]
    fn read_data_returns_empty_when_no_frames() {
        let mut srv = test_server();

        // RX ring empty (prod == cons == 0)
        let rx_ring_base = RDMA_OFF + DEFAULT_RING * DMA_RING_SIZE;
        srv.bank
            .on_read(rx_ring_base + RING_PROD_INDEX, alloc::vec![0]);

        srv.walk(0, 1, "genet0").unwrap();
        srv.walk(1, 2, "data").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 2048).unwrap();
        assert!(data.is_empty());
    }
}
