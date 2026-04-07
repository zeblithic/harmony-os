// SPDX-License-Identifier: GPL-2.0-or-later

//! HID boot protocol 9P server.
//!
//! Wraps a [`HidBootDriver`] and exposes input events via 9P:
//! - `/hid0/events` — read-only, returns serialized [`InputEvent`] structs
//! - `/hid0/info` — read-only, returns device type string
//!
//! Unlike hardware-facing servers (SdServer, GenetServer), HidServer
//! has no `RegisterBank` generic — the HID driver is pure byte-in /
//! events-out with no register access.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fid_tracker::FidTracker;
use crate::{slice_at_offset, Fid, FileStat, FileType, IpcError, OpenMode, QPath};

use harmony_unikernel::drivers::hid_boot::{HidAction, HidBootDriver, HidError};
use harmony_unikernel::drivers::input_event::InputEvent;

// ── QPath constants ─────────────────────────────────────────────

const QPATH_ROOT: QPath = 0;
const QPATH_EVENTS: QPath = 1;
const QPATH_INFO: QPath = 2;

// ── Event ring buffer ───────────────────────────────────────────

const EVENT_RING_SIZE: usize = 256;

struct EventRing {
    buf: [InputEvent; EVENT_RING_SIZE],
    head: usize, // next write position
    tail: usize, // next read position
    count: usize,
}

impl EventRing {
    fn new() -> Self {
        Self {
            buf: [InputEvent::syn(); EVENT_RING_SIZE],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    fn push(&mut self, event: InputEvent) {
        self.buf[self.head] = event;
        self.head = (self.head + 1) % EVENT_RING_SIZE;
        if self.count == EVENT_RING_SIZE {
            // Overflow: drop oldest by advancing tail.
            self.tail = (self.tail + 1) % EVENT_RING_SIZE;
        } else {
            self.count += 1;
        }
    }

    fn drain(&mut self, max_events: usize) -> Vec<InputEvent> {
        let n = self.count.min(max_events);
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.buf[self.tail]);
            self.tail = (self.tail + 1) % EVENT_RING_SIZE;
            self.count -= 1;
        }
        out
    }

    fn len(&self) -> usize {
        self.count
    }
}

// ── HidServer ───────────────────────────────────────────────────

/// 9P file server for a HID boot protocol device.
///
/// Wraps a [`HidBootDriver`] and an event ring buffer. The caller
/// feeds xHCI transfer completions via [`process_actions`]; consumers
/// read events via 9P `read("/hid0/events")`.
pub struct HidServer {
    driver: HidBootDriver,
    events: EventRing,
    tracker: FidTracker<()>,
    device_type: &'static str,
}

impl HidServer {
    /// Create a new HID server.
    ///
    /// `device_type` should be "keyboard" or "mouse" — determines
    /// what `/hid0/info` returns.
    pub fn new(device_type: &'static str) -> Self {
        Self {
            driver: HidBootDriver::new(),
            events: EventRing::new(),
            tracker: FidTracker::new(QPATH_ROOT, ()),
            device_type,
        }
    }

    /// Get a mutable reference to the inner driver (for bind/set_protocol).
    pub fn driver_mut(&mut self) -> &mut HidBootDriver {
        &mut self.driver
    }

    /// Process a list of HidActions: push EmitInputEvent to the ring
    /// buffer and return remaining actions (SendSetProtocol,
    /// QueueInterruptIn) for the caller to execute.
    pub fn process_actions(&mut self, actions: Vec<HidAction>) -> Vec<HidAction> {
        let mut remaining = Vec::new();
        for action in actions {
            match action {
                HidAction::EmitInputEvent(ev) => {
                    self.events.push(ev);
                }
                other => remaining.push(other),
            }
        }
        remaining
    }

    /// Feed interrupt completion data from xHCI to the driver, then
    /// process the resulting actions. Returns non-event actions for
    /// the caller to execute (QueueInterruptIn, etc.).
    pub fn handle_interrupt_data(&mut self, data: &[u8]) -> Result<Vec<HidAction>, HidError> {
        let actions = self.driver.handle_interrupt_data(data)?;
        Ok(self.process_actions(actions))
    }

    /// Number of events waiting in the ring buffer.
    pub fn pending_events(&self) -> usize {
        self.events.len()
    }
}

impl crate::FileServer for HidServer {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let entry = self.tracker.get(fid)?;
        if entry.qpath != QPATH_ROOT {
            return Err(IpcError::NotDirectory);
        }
        let qpath = match name {
            "events" => QPATH_EVENTS,
            "info" => QPATH_INFO,
            _ => return Err(IpcError::NotFound),
        };
        self.tracker.insert(new_fid, qpath, ())?;
        Ok(qpath)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let entry = self.tracker.begin_open(fid)?;
        // Reject opening directories.
        if entry.qpath == QPATH_ROOT {
            return Err(IpcError::IsDirectory);
        }
        // All files are read-only.
        if mode != OpenMode::Read {
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
        match entry.qpath {
            QPATH_EVENTS => {
                // Drain events — offset is ignored (stream semantics).
                let max_events = (count as usize) / 5; // 5 bytes per event
                if max_events == 0 {
                    return Ok(Vec::new());
                }
                let events = self.events.drain(max_events);
                let mut buf = Vec::with_capacity(events.len() * 5);
                for ev in &events {
                    buf.extend_from_slice(&ev.to_bytes());
                }
                Ok(buf)
            }
            QPATH_INFO => {
                let info = alloc::format!("{}\n", self.device_type);
                Ok(slice_at_offset(info.as_bytes(), offset, count as usize))
            }
            _ => Err(IpcError::InvalidFid),
        }
    }

    fn write(&mut self, fid: Fid, _offset: u64, _data: &[u8]) -> Result<u32, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.is_open() {
            return Err(IpcError::NotOpen);
        }
        // All files are read-only.
        Err(IpcError::PermissionDenied)
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        self.tracker.clunk(fid)
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let entry = self.tracker.get(fid)?;
        match entry.qpath {
            QPATH_ROOT => Ok(FileStat {
                qpath: QPATH_ROOT,
                name: Arc::from("hid0"),
                size: 0,
                file_type: FileType::Directory,
            }),
            QPATH_EVENTS => Ok(FileStat {
                qpath: QPATH_EVENTS,
                name: Arc::from("events"),
                size: (self.events.len() * 5) as u64,
                file_type: FileType::Regular,
            }),
            QPATH_INFO => Ok(FileStat {
                qpath: QPATH_INFO,
                name: Arc::from("info"),
                size: (self.device_type.len() + 1) as u64, // +1 for newline
                file_type: FileType::Regular,
            }),
            _ => Err(IpcError::InvalidFid),
        }
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        self.tracker.clone_fid(fid, new_fid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileServer, OpenMode};
    use harmony_unikernel::drivers::input_event::*;

    fn make_keyboard_server() -> HidServer {
        let mut server = HidServer::new("keyboard");
        let actions = server.driver_mut().bind(1, 3, 0).unwrap();
        server.process_actions(actions);
        let actions = server.driver_mut().set_protocol_complete().unwrap();
        server.process_actions(actions);
        server
    }

    fn make_mouse_server() -> HidServer {
        let mut server = HidServer::new("mouse");
        let actions = server.driver_mut().bind(2, 5, 0).unwrap();
        server.process_actions(actions);
        let actions = server.driver_mut().set_protocol_complete().unwrap();
        server.process_actions(actions);
        server
    }

    // ── Walk tests ──────────────────────────────────────────────

    #[test]
    fn walk_events() {
        let mut s = make_keyboard_server();
        let qpath = s.walk(0, 1, "events").unwrap();
        assert_eq!(qpath, QPATH_EVENTS);
    }

    #[test]
    fn walk_info() {
        let mut s = make_keyboard_server();
        let qpath = s.walk(0, 1, "info").unwrap();
        assert_eq!(qpath, QPATH_INFO);
    }

    #[test]
    fn walk_nonexistent() {
        let mut s = make_keyboard_server();
        assert_eq!(s.walk(0, 1, "nope"), Err(IpcError::NotFound));
    }

    #[test]
    fn walk_from_non_root() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "events").unwrap();
        assert_eq!(s.walk(1, 2, "anything"), Err(IpcError::NotDirectory));
    }

    // ── Read tests ──────────────────────────────────────────────

    #[test]
    fn read_info_keyboard() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "info").unwrap();
        s.open(1, OpenMode::Read).unwrap();
        let data = s.read(1, 0, 256).unwrap();
        assert_eq!(data, b"keyboard\n");
    }

    #[test]
    fn read_info_mouse() {
        let mut s = make_mouse_server();
        s.walk(0, 1, "info").unwrap();
        s.open(1, OpenMode::Read).unwrap();
        let data = s.read(1, 0, 256).unwrap();
        assert_eq!(data, b"mouse\n");
    }

    #[test]
    fn read_events_empty() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "events").unwrap();
        s.open(1, OpenMode::Read).unwrap();
        let data = s.read(1, 0, 256).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn read_events_with_data() {
        let mut s = make_keyboard_server();
        // Generate a key press
        s.handle_interrupt_data(&[0, 0, 0x04, 0, 0, 0, 0, 0])
            .unwrap();
        s.walk(0, 1, "events").unwrap();
        s.open(1, OpenMode::Read).unwrap();
        let data = s.read(1, 0, 256).unwrap();
        // KEY_A press + SYN_REPORT = 2 events * 5 bytes = 10 bytes
        assert_eq!(data.len(), 10);
        let ev0 = InputEvent::from_bytes(&data[0..5]).unwrap();
        assert_eq!(ev0, InputEvent::key(KEY_A, true));
        let ev1 = InputEvent::from_bytes(&data[5..10]).unwrap();
        assert_eq!(ev1, InputEvent::syn());
    }

    #[test]
    fn read_events_drains() {
        let mut s = make_keyboard_server();
        s.handle_interrupt_data(&[0, 0, 0x04, 0, 0, 0, 0, 0])
            .unwrap();
        s.walk(0, 1, "events").unwrap();
        s.open(1, OpenMode::Read).unwrap();
        let data1 = s.read(1, 0, 256).unwrap();
        assert!(!data1.is_empty());
        // Second read should be empty — events were drained
        let data2 = s.read(1, 0, 256).unwrap();
        assert!(data2.is_empty());
    }

    #[test]
    fn event_ring_overflow() {
        let mut s = make_keyboard_server();
        // Push 257 events via alternating key press/release
        for i in 0..129 {
            let usage = 0x04 + (i % 26) as u8; // cycle through A-Z
            s.handle_interrupt_data(&[0, 0, usage, 0, 0, 0, 0, 0])
                .unwrap();
            s.handle_interrupt_data(&[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        }
        // Ring holds at most 256 events — oldest were dropped
        assert!(s.pending_events() <= EVENT_RING_SIZE);
        s.walk(0, 1, "events").unwrap();
        s.open(1, OpenMode::Read).unwrap();
        // Can read up to 256 events
        let data = s.read(1, 0, 5 * 256).unwrap();
        assert!(data.len() <= 5 * 256);
        assert!(data.len() > 0);
    }

    // ── Write rejected ──────────────────────────────────────────

    #[test]
    fn write_events_rejected() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "events").unwrap();
        s.open(1, OpenMode::Read).unwrap();
        assert_eq!(
            s.write(1, 0, &[0, 0, 0, 0, 0]),
            Err(IpcError::PermissionDenied)
        );
    }

    #[test]
    fn open_write_mode_rejected() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "events").unwrap();
        assert_eq!(s.open(1, OpenMode::Write), Err(IpcError::ReadOnly));
    }

    #[test]
    fn open_root_directory_rejected() {
        let mut s = make_keyboard_server();
        assert_eq!(s.open(0, OpenMode::Read), Err(IpcError::IsDirectory));
    }

    // ── Stat tests ──────────────────────────────────────────────

    #[test]
    fn stat_root() {
        let mut s = make_keyboard_server();
        let stat = s.stat(0).unwrap();
        assert_eq!(stat.file_type, FileType::Directory);
        assert_eq!(&*stat.name, "hid0");
    }

    #[test]
    fn stat_events() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "events").unwrap();
        let stat = s.stat(1).unwrap();
        assert_eq!(&*stat.name, "events");
        assert_eq!(stat.file_type, FileType::Regular);
    }

    #[test]
    fn stat_info() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "info").unwrap();
        let stat = s.stat(1).unwrap();
        assert_eq!(&*stat.name, "info");
        assert_eq!(stat.size, 9); // "keyboard\n"
    }

    // ── Clunk tests ─────────────────────────────────────────────

    #[test]
    fn clunk_root_rejected() {
        let mut s = make_keyboard_server();
        assert_eq!(s.clunk(0), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn clunk_walked_fid() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "events").unwrap();
        s.clunk(1).unwrap();
    }

    // ── Clone tests ─────────────────────────────────────────────

    #[test]
    fn clone_fid_works() {
        let mut s = make_keyboard_server();
        s.walk(0, 1, "events").unwrap();
        let qpath = s.clone_fid(1, 2).unwrap();
        assert_eq!(qpath, QPATH_EVENTS);
    }
}
