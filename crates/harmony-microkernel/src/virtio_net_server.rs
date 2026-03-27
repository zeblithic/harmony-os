// SPDX-License-Identifier: GPL-2.0-or-later

//! VirtioNetServer — 9P file server for a generic [`NetworkDevice`].
//!
//! Exposes a directory named by `name` with five files:
//! - `data`  — read/write raw Ethernet frames (packet-per-operation)
//! - `mac`   — read-only MAC address ("aa:bb:cc:dd:ee:ff\n")
//! - `mtu`   — read-only MTU ("1500\n")
//! - `stats` — read-only interface statistics
//! - `link`  — read-only link status ("up\n" or "down\n")

extern crate alloc;

use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fid_tracker::FidTracker;
use crate::net_device::NetworkDevice;
use crate::{Fid, FileServer, FileStat, FileType, IpcError, OpenMode, QPath};

// QPath assignments
const QPATH_ROOT: QPath = 0;
const QPATH_DIR: QPath = 1; // /dev/net/<name>/ directory
const QPATH_DATA: QPath = 2;
const QPATH_MAC: QPath = 3;
const QPATH_MTU: QPath = 4;
const QPATH_STATS: QPath = 5;
const QPATH_LINK: QPath = 6;

/// A 9P file server wrapping any [`NetworkDevice`].
///
/// Walk to `name` (e.g. `"virtio0"`) to enter the device directory, then walk
/// to individual files (`data`, `mac`, `mtu`, `stats`, `link`).
pub struct VirtioNetServer<N: NetworkDevice> {
    device: N,
    tracker: FidTracker<()>,
    name: &'static str,
    tx_packets: u64,
    rx_packets: u64,
    tx_bytes: u64,
    rx_bytes: u64,
}

impl<N: NetworkDevice> VirtioNetServer<N> {
    /// Create a new `VirtioNetServer` wrapping `device` and advertising it as `name`.
    pub fn new(device: N, name: &'static str) -> Self {
        Self {
            device,
            tracker: FidTracker::new(QPATH_ROOT, ()),
            name,
            tx_packets: 0,
            rx_packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
        }
    }

    fn is_directory(qpath: QPath) -> bool {
        matches!(qpath, QPATH_ROOT | QPATH_DIR)
    }

    fn is_read_only(qpath: QPath) -> bool {
        matches!(qpath, QPATH_MAC | QPATH_MTU | QPATH_STATS | QPATH_LINK)
    }

    fn child_qpath(&self, parent: QPath, name: &str) -> Result<QPath, IpcError> {
        match (parent, name) {
            (QPATH_ROOT, n) if n == self.name => Ok(QPATH_DIR),
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

    fn qpath_name(&self, qpath: QPath) -> &str {
        match qpath {
            QPATH_ROOT => "/",
            QPATH_DIR => self.name,
            QPATH_DATA => "data",
            QPATH_MAC => "mac",
            QPATH_MTU => "mtu",
            QPATH_STATS => "stats",
            QPATH_LINK => "link",
            _ => "?",
        }
    }
}

impl<N: NetworkDevice> FileServer for VirtioNetServer<N> {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let entry = self.tracker.get(fid)?;
        if entry.is_open() {
            return Err(IpcError::PermissionDenied); // 9P: cannot walk from an open fid
        }
        if !Self::is_directory(entry.qpath) {
            return Err(IpcError::NotDirectory);
        }
        let parent_qpath = entry.qpath; // Copy before mutating tracker
        let qpath = self.child_qpath(parent_qpath, name)?;
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
                // Guard: poll_tx is destructive (advances consumer index),
                // so a zero-count read must not consume a frame.
                if max == 0 {
                    return Ok(Vec::new());
                }
                // 2048 matches VirtioNetDevice's internal staging buffer size,
                // preventing silent truncation for VLAN-tagged or jumbo frames.
                let mut buf = [0u8; 2048];
                match self.device.poll_tx(&mut buf) {
                    Some(n) => {
                        if n > max {
                            // Frame too large for caller's buffer.
                            // The frame is already consumed from the queue —
                            // returning truncated data would give the caller a
                            // structurally invalid Ethernet frame with no indication.
                            return Err(IpcError::InvalidArgument);
                        }
                        self.tx_packets += 1;
                        self.tx_bytes += n as u64;
                        Ok(buf[..n].to_vec())
                    }
                    None => Ok(Vec::new()),
                }
            }
            QPATH_MAC => {
                let m = self.device.mac();
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
                let s = format!(
                    "rx_packets: {}\ntx_packets: {}\nrx_bytes: {}\ntx_bytes: {}\n",
                    self.rx_packets, self.tx_packets, self.rx_bytes, self.tx_bytes,
                );
                let bytes = s.into_bytes();
                Ok(Self::slice_at_offset(&bytes, offset, max))
            }
            QPATH_LINK => {
                let bytes: &[u8] = if self.device.link_up() {
                    b"up\n"
                } else {
                    b"down\n"
                };
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
                if self.device.push_rx(data) {
                    self.rx_packets += 1;
                    self.rx_bytes += data.len() as u64;
                    Ok(data.len() as u32)
                } else {
                    Err(IpcError::ResourceExhausted)
                }
            }
            _ => Err(IpcError::ReadOnly),
        }
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        self.tracker.clunk(fid)
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let qpath = self.tracker.get(fid)?.qpath;
        let name = self.qpath_name(qpath);
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
    use alloc::collections::VecDeque;
    use alloc::vec;

    struct MockNetDevice {
        mac: [u8; 6],
        link: bool,
        tx_queue: VecDeque<Vec<u8>>,
        rx_log: Vec<Vec<u8>>,
    }

    impl MockNetDevice {
        fn new(mac: [u8; 6]) -> Self {
            Self {
                mac,
                link: true,
                tx_queue: VecDeque::new(),
                rx_log: Vec::new(),
            }
        }
    }

    impl NetworkDevice for MockNetDevice {
        fn poll_tx(&mut self, out: &mut [u8]) -> Option<usize> {
            let frame = self.tx_queue.pop_front()?;
            let n = frame.len().min(out.len());
            out[..n].copy_from_slice(&frame[..n]);
            Some(n)
        }

        fn push_rx(&mut self, frame: &[u8]) -> bool {
            self.rx_log.push(frame.to_vec());
            true
        }

        fn mac(&self) -> [u8; 6] {
            self.mac
        }

        fn link_up(&self) -> bool {
            self.link
        }
    }

    const TEST_MAC: [u8; 6] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
    const DEV_NAME: &str = "virtio0";

    fn test_server() -> VirtioNetServer<MockNetDevice> {
        VirtioNetServer::new(MockNetDevice::new(TEST_MAC), DEV_NAME)
    }

    // ── Walk tests ────────────────────────────────────────────────

    #[test]
    fn walk_to_device_directory() {
        let mut srv = test_server();
        let qpath = srv.walk(0, 1, DEV_NAME).unwrap();
        assert_eq!(qpath, QPATH_DIR);
    }

    #[test]
    fn walk_to_data_file() {
        let mut srv = test_server();
        srv.walk(0, 1, DEV_NAME).unwrap();
        let qpath = srv.walk(1, 2, "data").unwrap();
        assert_eq!(qpath, QPATH_DATA);
    }

    #[test]
    fn walk_to_all_files() {
        let mut srv = test_server();
        srv.walk(0, 1, DEV_NAME).unwrap();
        assert_eq!(srv.walk(1, 2, "data").unwrap(), QPATH_DATA);
        assert_eq!(srv.walk(1, 3, "mac").unwrap(), QPATH_MAC);
        assert_eq!(srv.walk(1, 4, "mtu").unwrap(), QPATH_MTU);
        assert_eq!(srv.walk(1, 5, "stats").unwrap(), QPATH_STATS);
        assert_eq!(srv.walk(1, 6, "link").unwrap(), QPATH_LINK);
    }

    #[test]
    fn walk_in_place_replaces_fid() {
        let mut srv = test_server();
        // Walk fid 0 (root) to device dir, in place (new_fid == fid)
        let qpath = srv.walk(0, 0, DEV_NAME).unwrap();
        assert_eq!(qpath, QPATH_DIR);
        // Fid 0 is now the device directory, can walk to children
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
        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.walk(1, 2, "data").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        // 9P forbids walking from an open fid
        assert_eq!(srv.walk(2, 3, "mac"), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn walk_from_file_rejected() {
        let mut srv = test_server();
        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.walk(1, 2, "data").unwrap();
        assert_eq!(srv.walk(2, 3, "mac"), Err(IpcError::NotDirectory));
    }

    // ── Open tests ────────────────────────────────────────────────

    #[test]
    fn open_read_only_files_reject_write() {
        let mut srv = test_server();
        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.walk(1, 2, "mac").unwrap();
        assert_eq!(srv.open(2, OpenMode::Write), Err(IpcError::ReadOnly));
        assert_eq!(srv.open(2, OpenMode::ReadWrite), Err(IpcError::ReadOnly));
    }

    #[test]
    fn open_directory_rejected() {
        let mut srv = test_server();
        srv.walk(0, 1, DEV_NAME).unwrap();
        assert_eq!(srv.open(1, OpenMode::Read), Err(IpcError::IsDirectory));
        assert_eq!(srv.open(1, OpenMode::Write), Err(IpcError::IsDirectory));
        assert_eq!(srv.open(1, OpenMode::ReadWrite), Err(IpcError::IsDirectory));
    }

    #[test]
    fn open_data_readwrite() {
        let mut srv = test_server();
        srv.walk(0, 1, DEV_NAME).unwrap();
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
    fn stat_device_directory() {
        let mut srv = test_server();
        srv.walk(0, 1, DEV_NAME).unwrap();
        let st = srv.stat(1).unwrap();
        assert_eq!(&*st.name, DEV_NAME);
        assert_eq!(st.file_type, FileType::Directory);
    }

    #[test]
    fn stat_data_file() {
        let mut srv = test_server();
        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.walk(1, 2, "data").unwrap();
        let st = srv.stat(2).unwrap();
        assert_eq!(&*st.name, "data");
        assert_eq!(st.file_type, FileType::Regular);
        assert_eq!(st.size, 0); // streaming — size unknown
    }

    #[test]
    fn stat_fixed_size_files() {
        let mut srv = test_server();
        srv.walk(0, 1, DEV_NAME).unwrap();

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
        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.clunk(1).unwrap();
        assert_eq!(srv.stat(1), Err(IpcError::InvalidFid));
    }

    // ── Clone fid tests ───────────────────────────────────────────

    #[test]
    fn clone_fid_duplicates() {
        let mut srv = test_server();
        srv.walk(0, 1, DEV_NAME).unwrap();
        let qpath = srv.clone_fid(1, 2).unwrap();
        assert_eq!(qpath, QPATH_DIR);
        let st = srv.stat(2).unwrap();
        assert_eq!(&*st.name, DEV_NAME);
    }

    // ── Read control files ────────────────────────────────────────

    #[test]
    fn read_mac() {
        let mut srv = test_server();
        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.walk(1, 2, "mac").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 256).unwrap();
        assert_eq!(data, b"de:ad:be:ef:ca:fe\n");
    }

    #[test]
    fn read_mac_with_offset() {
        let mut srv = test_server();
        srv.walk(0, 1, DEV_NAME).unwrap();
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
        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.walk(1, 2, "mtu").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 256).unwrap();
        assert_eq!(data, b"1500\n");
    }

    #[test]
    fn read_mtu_with_offset() {
        let mut srv = test_server();
        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.walk(1, 2, "mtu").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let chunk = srv.read(2, 3, 256).unwrap();
        assert_eq!(chunk, b"0\n");
    }

    #[test]
    fn read_link_up() {
        let mut srv = test_server();
        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.walk(1, 2, "link").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 256).unwrap();
        assert_eq!(data, b"up\n");
    }

    #[test]
    fn read_link_down() {
        let mut srv = VirtioNetServer::new(
            MockNetDevice {
                mac: TEST_MAC,
                link: false,
                tx_queue: VecDeque::new(),
                rx_log: Vec::new(),
            },
            DEV_NAME,
        );
        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.walk(1, 2, "link").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 256).unwrap();
        assert_eq!(data, b"down\n");
    }

    #[test]
    fn read_stats_format() {
        let mut srv = test_server();
        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.walk(1, 2, "stats").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 1024).unwrap();
        let text = core::str::from_utf8(&data).unwrap();
        assert!(text.contains("rx_packets: 0"));
        assert!(text.contains("tx_packets: 0"));
        assert!(text.contains("rx_bytes: 0"));
        assert!(text.contains("tx_bytes: 0"));
    }

    // ── Write to read-only files ──────────────────────────────────

    #[test]
    fn write_to_mac_rejected() {
        let mut srv = test_server();
        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.walk(1, 2, "mac").unwrap();
        // Can't even open in write mode
        assert_eq!(srv.open(2, OpenMode::Write), Err(IpcError::ReadOnly));
    }

    // ── Data file TX/RX ───────────────────────────────────────────

    #[test]
    fn write_data_pushes_rx_frame() {
        let mut srv = test_server();
        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.walk(1, 2, "data").unwrap();
        srv.open(2, OpenMode::Write).unwrap();
        let n = srv.write(2, 0, &[0xAA; 64]).unwrap();
        assert_eq!(n, 64);
        assert_eq!(srv.device.rx_log.len(), 1);
        assert_eq!(srv.device.rx_log[0], vec![0xAA; 64]);
    }

    #[test]
    fn read_data_returns_tx_frame() {
        let mut srv = test_server();
        srv.device.tx_queue.push_back(vec![0xBB; 60]);

        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.walk(1, 2, "data").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 2048).unwrap();
        assert_eq!(data.len(), 60);
        assert_eq!(data, vec![0xBB; 60]);
    }

    #[test]
    fn read_data_undersized_buffer_returns_error() {
        let mut srv = test_server();
        srv.device.tx_queue.push_back(vec![0xCC; 64]);

        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.walk(1, 2, "data").unwrap();
        srv.open(2, OpenMode::Read).unwrap();

        // Read with buffer smaller than frame — must error, not truncate
        assert_eq!(srv.read(2, 0, 32), Err(IpcError::InvalidArgument));
    }

    #[test]
    fn read_data_zero_count_does_not_consume_frame() {
        let mut srv = test_server();
        srv.device.tx_queue.push_back(vec![0xDD; 64]);

        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.walk(1, 2, "data").unwrap();
        srv.open(2, OpenMode::Read).unwrap();

        // Zero-count read must not consume the frame
        let empty = srv.read(2, 0, 0).unwrap();
        assert!(empty.is_empty());

        // The frame should still be available
        let data = srv.read(2, 0, 2048).unwrap();
        assert_eq!(data.len(), 64);
    }

    #[test]
    fn read_data_returns_empty_when_no_frames() {
        let mut srv = test_server();
        // tx_queue is empty — no frames pending
        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.walk(1, 2, "data").unwrap();
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 2048).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn stats_increment_on_tx_and_rx() {
        let mut srv = test_server();
        // Enqueue two frames to "poll_tx" from
        srv.device.tx_queue.push_back(vec![0x01; 60]);
        srv.device.tx_queue.push_back(vec![0x02; 100]);

        srv.walk(0, 1, DEV_NAME).unwrap();
        srv.walk(1, 2, "data").unwrap();
        srv.open(2, OpenMode::ReadWrite).unwrap();

        // Read (poll_tx) two frames — increments tx_packets/tx_bytes
        srv.read(2, 0, 2048).unwrap();
        srv.read(2, 0, 2048).unwrap();

        // Write (push_rx) one frame — increments rx_packets/rx_bytes
        srv.write(2, 0, &[0xAA; 42]).unwrap();

        // Check stats
        srv.walk(0, 3, DEV_NAME).unwrap();
        srv.walk(3, 4, "stats").unwrap();
        srv.open(4, OpenMode::Read).unwrap();
        let raw = srv.read(4, 0, 1024).unwrap();
        let text = core::str::from_utf8(&raw).unwrap();
        assert!(text.contains("tx_packets: 2"), "got: {text}");
        assert!(text.contains("tx_bytes: 160"), "got: {text}");
        assert!(text.contains("rx_packets: 1"), "got: {text}");
        assert!(text.contains("rx_bytes: 42"), "got: {text}");
    }
}
