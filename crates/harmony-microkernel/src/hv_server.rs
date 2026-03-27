// SPDX-License-Identifier: GPL-2.0-or-later

//! HvServer — 9P file server for VM lifecycle management.
//!
//! Exposes a directory named by `name` (e.g. `"vm1"`) with two files:
//! - `ctl`    — read/write VM control (read: current state, write: commands)
//! - `config` — read-only VM configuration (vmid and MAC address)

extern crate alloc;

use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fid_tracker::FidTracker;
use crate::hv_manager::{VmCommand, VmState};
use crate::{Fid, FileServer, FileStat, FileType, IpcError, OpenMode, QPath};

// QPath assignments
const QPATH_ROOT: QPath = 0;
const QPATH_DIR: QPath = 1; // /dev/hv/<name>/ directory
const QPATH_CTL: QPath = 2;
const QPATH_CONFIG: QPath = 3;

/// A 9P file server for VM lifecycle control.
///
/// Walk to `name` (e.g. `"vm1"`) to enter the VM directory, then walk
/// to individual files (`ctl`, `config`).
pub struct HvServer {
    vmid: u8,
    mac: [u8; 6],
    state: VmState,
    name: &'static str,
    tracker: FidTracker<()>,
    pending: Option<VmCommand>,
}

impl HvServer {
    /// Create a new `HvServer` for a VM with the given `vmid`, `mac`, and `name`.
    pub fn new(vmid: u8, mac: [u8; 6], name: &'static str) -> Self {
        Self {
            vmid,
            mac,
            state: VmState::Created,
            name,
            tracker: FidTracker::new(QPATH_ROOT, ()),
            pending: None,
        }
    }

    /// Take the pending command, if any. Clears the pending slot.
    pub fn take_pending_command(&mut self) -> Option<VmCommand> {
        self.pending.take()
    }

    /// Update the VM state (e.g. after a hypervisor event).
    pub fn update_state(&mut self, state: VmState) {
        self.state = state;
    }

    fn is_directory(qpath: QPath) -> bool {
        matches!(qpath, QPATH_ROOT | QPATH_DIR)
    }

    fn is_read_only(qpath: QPath) -> bool {
        matches!(qpath, QPATH_CONFIG)
    }

    fn child_qpath(&self, parent: QPath, name: &str) -> Result<QPath, IpcError> {
        match (parent, name) {
            (QPATH_ROOT, n) if n == self.name => Ok(QPATH_DIR),
            (QPATH_DIR, "ctl") => Ok(QPATH_CTL),
            (QPATH_DIR, "config") => Ok(QPATH_CONFIG),
            _ => Err(IpcError::NotFound),
        }
    }

    fn qpath_name(&self, qpath: QPath) -> &str {
        match qpath {
            QPATH_ROOT => "/",
            QPATH_DIR => self.name,
            QPATH_CTL => "ctl",
            QPATH_CONFIG => "config",
            _ => "?",
        }
    }

    /// Slice `bytes` starting at `offset`, returning at most `max` bytes.
    /// Returns an empty vec if offset is past the end — signaling EOF to 9P clients.
    fn slice_at_offset(bytes: &[u8], offset: u64, max: usize) -> Vec<u8> {
        let start = (offset.min(usize::MAX as u64) as usize).min(bytes.len());
        let end = start.saturating_add(max).min(bytes.len());
        bytes[start..end].to_vec()
    }
}

fn parse_hex(s: &str) -> Option<u64> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

// Commands are case-sensitive (all lower-case per Plan 9 convention).
fn parse_ctl_command(data: &[u8]) -> Result<VmCommand, IpcError> {
    let s = core::str::from_utf8(data).map_err(|_| IpcError::InvalidArgument)?;
    let s = s.trim();
    if s == "destroy" {
        return Ok(VmCommand::Destroy);
    }
    if let Some(rest) = s.strip_prefix("start ") {
        let mut parts = rest.split_whitespace();
        let entry_s = parts.next().ok_or(IpcError::InvalidArgument)?;
        let dtb_s = parts.next().ok_or(IpcError::InvalidArgument)?;
        if parts.next().is_some() {
            return Err(IpcError::InvalidArgument); // too many args
        }
        let entry_ipa = parse_hex(entry_s).ok_or(IpcError::InvalidArgument)?;
        let dtb_ipa = parse_hex(dtb_s).ok_or(IpcError::InvalidArgument)?;
        return Ok(VmCommand::Start { entry_ipa, dtb_ipa });
    }
    Err(IpcError::InvalidArgument)
}

impl FileServer for HvServer {
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
            QPATH_CTL => {
                let bytes = self.state.as_str().as_bytes();
                Ok(Self::slice_at_offset(bytes, offset, max))
            }
            QPATH_CONFIG => {
                let m = self.mac;
                let s = format!(
                    "vmid: {}\nmac: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                    self.vmid, m[0], m[1], m[2], m[3], m[4], m[5]
                );
                let bytes = s.into_bytes();
                Ok(Self::slice_at_offset(&bytes, offset, max))
            }
            _ => Err(IpcError::NotFound),
        }
    }

    fn write(&mut self, fid: Fid, offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        // Ctl commands are atomic, not seekable — reject non-zero offsets.
        if offset != 0 {
            return Err(IpcError::InvalidArgument);
        }
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
            QPATH_CTL => {
                if self.pending.is_some() {
                    return Err(IpcError::NotReady);
                }
                let cmd = parse_ctl_command(data)?;
                self.pending = Some(cmd);
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
        let name = self.qpath_name(qpath);
        let file_type = if Self::is_directory(qpath) {
            FileType::Directory
        } else {
            FileType::Regular
        };
        Ok(FileStat {
            qpath,
            name: Arc::from(name),
            size: 0, // dynamic content
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

    fn make_server() -> HvServer {
        HvServer::new(1, [0x02, 0x00, 0x00, 0x00, 0x00, 0x01], "vm1")
    }

    fn walk_to_ctl(srv: &mut HvServer) -> Fid {
        srv.walk(0, 1, "vm1").unwrap();
        srv.walk(1, 2, "ctl").unwrap();
        2
    }

    fn walk_to_config(srv: &mut HvServer) -> Fid {
        srv.walk(0, 3, "vm1").unwrap();
        srv.walk(3, 4, "config").unwrap();
        4
    }

    // ── Walk tests ────────────────────────────────────────────────

    #[test]
    fn walk_to_ctl_and_config() {
        let mut srv = make_server();
        let dir_qpath = srv.walk(0, 1, "vm1").unwrap();
        assert_eq!(dir_qpath, QPATH_DIR);
        let ctl_qpath = srv.walk(1, 2, "ctl").unwrap();
        assert_eq!(ctl_qpath, QPATH_CTL);
        let config_qpath = srv.walk(1, 3, "config").unwrap();
        assert_eq!(config_qpath, QPATH_CONFIG);
    }

    #[test]
    fn walk_wrong_name_fails() {
        let mut srv = make_server();
        assert_eq!(srv.walk(0, 1, "wrong"), Err(IpcError::NotFound));
    }

    // ── Open tests ────────────────────────────────────────────────

    #[test]
    fn open_ctl_readwrite() {
        let mut srv = make_server();
        walk_to_ctl(&mut srv);
        assert!(srv.open(2, OpenMode::ReadWrite).is_ok());
    }

    #[test]
    fn open_config_write_fails() {
        let mut srv = make_server();
        walk_to_config(&mut srv);
        assert_eq!(srv.open(4, OpenMode::Write), Err(IpcError::ReadOnly));
        assert_eq!(srv.open(4, OpenMode::ReadWrite), Err(IpcError::ReadOnly));
    }

    // ── Read ctl tests ────────────────────────────────────────────

    #[test]
    fn read_ctl_created() {
        let mut srv = make_server();
        walk_to_ctl(&mut srv);
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 256).unwrap();
        assert_eq!(data, b"created\n");
    }

    #[test]
    fn read_ctl_running() {
        let mut srv = make_server();
        srv.update_state(VmState::Running);
        walk_to_ctl(&mut srv);
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 256).unwrap();
        assert_eq!(data, b"running\n");
    }

    #[test]
    fn read_ctl_halted() {
        let mut srv = make_server();
        srv.update_state(VmState::Halted);
        walk_to_ctl(&mut srv);
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 0, 256).unwrap();
        assert_eq!(data, b"halted\n");
    }

    #[test]
    fn read_ctl_with_offset() {
        let mut srv = make_server();
        // "created\n" is 8 bytes; offset 4 → "ted\n", count 3 → "ted"
        walk_to_ctl(&mut srv);
        srv.open(2, OpenMode::Read).unwrap();
        let data = srv.read(2, 4, 3).unwrap();
        assert_eq!(data, b"ted");
    }

    // ── Write ctl tests ───────────────────────────────────────────

    #[test]
    fn write_ctl_start() {
        let mut srv = make_server();
        walk_to_ctl(&mut srv);
        srv.open(2, OpenMode::Write).unwrap();
        let n = srv.write(2, 0, b"start 0x40000000 0x44000000").unwrap();
        assert_eq!(n, 27);
        assert_eq!(
            srv.take_pending_command(),
            Some(VmCommand::Start {
                entry_ipa: 0x40000000,
                dtb_ipa: 0x44000000,
            })
        );
    }

    #[test]
    fn write_ctl_start_no_prefix() {
        let mut srv = make_server();
        walk_to_ctl(&mut srv);
        srv.open(2, OpenMode::Write).unwrap();
        srv.write(2, 0, b"start 40000000 44000000").unwrap();
        assert_eq!(
            srv.take_pending_command(),
            Some(VmCommand::Start {
                entry_ipa: 0x40000000,
                dtb_ipa: 0x44000000,
            })
        );
    }

    #[test]
    fn write_ctl_destroy() {
        let mut srv = make_server();
        walk_to_ctl(&mut srv);
        srv.open(2, OpenMode::Write).unwrap();
        srv.write(2, 0, b"destroy").unwrap();
        assert_eq!(srv.take_pending_command(), Some(VmCommand::Destroy));
    }

    #[test]
    fn write_ctl_bad_command() {
        let mut srv = make_server();
        walk_to_ctl(&mut srv);
        srv.open(2, OpenMode::Write).unwrap();
        assert_eq!(srv.write(2, 0, b"invalid"), Err(IpcError::InvalidArgument));
    }

    #[test]
    fn write_ctl_bad_hex() {
        let mut srv = make_server();
        walk_to_ctl(&mut srv);
        srv.open(2, OpenMode::Write).unwrap();
        assert_eq!(
            srv.write(2, 0, b"start 0xZZZZ 0x0"),
            Err(IpcError::InvalidArgument)
        );
    }

    // ── Read config tests ─────────────────────────────────────────

    #[test]
    fn read_config_format() {
        let mut srv = make_server();
        walk_to_config(&mut srv);
        srv.open(4, OpenMode::Read).unwrap();
        let data = srv.read(4, 0, 256).unwrap();
        let text = core::str::from_utf8(&data).unwrap();
        assert_eq!(text, "vmid: 1\nmac: 02:00:00:00:00:01\n");
    }

    // ── Pending command tests ─────────────────────────────────────

    #[test]
    fn take_pending_clears() {
        let mut srv = make_server();
        walk_to_ctl(&mut srv);
        srv.open(2, OpenMode::Write).unwrap();
        srv.write(2, 0, b"destroy").unwrap();
        assert_eq!(srv.take_pending_command(), Some(VmCommand::Destroy));
        assert_eq!(srv.take_pending_command(), None);
    }

    // ── Stat tests ────────────────────────────────────────────────

    #[test]
    fn stat_returns_metadata() {
        let mut srv = make_server();
        // Stat root
        let st = srv.stat(0).unwrap();
        assert_eq!(&*st.name, "/");
        assert_eq!(st.file_type, FileType::Directory);

        // Stat dir: walk 0 → fid 1 (vm1 directory)
        srv.walk(0, 1, "vm1").unwrap();
        let st = srv.stat(1).unwrap();
        assert_eq!(&*st.name, "vm1");
        assert_eq!(st.file_type, FileType::Directory);

        // Stat ctl: walk fid 1 → fid 2 (ctl)
        srv.walk(1, 2, "ctl").unwrap();
        let st = srv.stat(2).unwrap();
        assert_eq!(&*st.name, "ctl");
        assert_eq!(st.file_type, FileType::Regular);
        assert_eq!(st.size, 0);

        // Stat config: walk fid 1 → fid 3 (config)
        srv.walk(1, 3, "config").unwrap();
        let st = srv.stat(3).unwrap();
        assert_eq!(&*st.name, "config");
        assert_eq!(st.file_type, FileType::Regular);
        assert_eq!(st.size, 0);
    }

    // ── Clone fid tests ───────────────────────────────────────────

    #[test]
    fn clone_fid_works() {
        let mut srv = make_server();
        srv.walk(0, 1, "vm1").unwrap();
        let qpath = srv.clone_fid(1, 2).unwrap();
        assert_eq!(qpath, QPATH_DIR);
        let st = srv.stat(2).unwrap();
        assert_eq!(&*st.name, "vm1");
    }

    // ── Clunk tests ───────────────────────────────────────────────

    #[test]
    fn clunk_releases_fid() {
        let mut srv = make_server();
        srv.walk(0, 1, "vm1").unwrap();
        srv.clunk(1).unwrap();
        // After clunk, fid 1 is gone; walk again with same fid should succeed
        let qpath = srv.walk(0, 1, "vm1").unwrap();
        assert_eq!(qpath, QPATH_DIR);
    }
}
