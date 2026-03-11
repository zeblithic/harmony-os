# FidTracker Extraction Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extract the duplicated FidState/fid-lifecycle boilerplate from 8 FileServer implementations into a shared `FidTracker<T>` helper.

**Architecture:** A generic `FidTracker<T>` owns the `BTreeMap<Fid, FidEntry<T>>` and implements the common fid lifecycle operations (insert, clone, clunk, begin_open). Each server stores its own per-fid payload as `T` (most use `()`, LibraryServer uses `Arc<str>`, ContentServer uses `NodeKind`). Servers delegate the generic parts to the tracker and retain control over namespace resolution, mode validation, and I/O.

**Tech Stack:** Rust, `no_std` compatible (`alloc` only), harmony-microkernel crate.

---

## Background

All 8 FileServer implementations in `crates/harmony-microkernel/src/` define their own `FidState` struct and duplicate the same fid lifecycle code (~55 lines each, ~444 lines total). The TODO in `serial_server.rs:17-18` called for extraction "when a third server appears" — we now have 8.

### Servers and their FidState variations

| Server | File | Payload beyond `{qpath, is_open, mode}` |
|--------|------|----------------------------------------|
| EchoServer | `echo.rs` | None |
| SerialServer | `serial_server.rs` | None |
| GenetServer | `genet_server.rs` | None |
| SdServer | `sd_server.rs` | None |
| UartServer | `uart_server.rs` | None |
| GpioServer | `gpio_server.rs` | None |
| LibraryServer | `library_server.rs` | `name: Arc<str>` (replaces mode) |
| ContentServer | `content_server.rs` | `node: NodeKind` |

### Key behavioral differences

- **clunk fid 0:** 7 servers return `Err(PermissionDenied)`, LibraryServer returns `Ok(())`
- **open validation:** each server has different mode restrictions per qpath/node-kind
- **clunk cleanup:** ContentServer removes `ingest_buffers` entry on clunk

### FidTracker API

```rust
pub struct FidEntry<T: Clone> {
    pub qpath: QPath,
    pub is_open: bool,
    pub mode: Option<OpenMode>,
    pub payload: T,
}

pub struct FidTracker<T: Clone> {
    fids: BTreeMap<Fid, FidEntry<T>>,
}

impl<T: Clone> FidTracker<T> {
    pub fn new(root_qpath: QPath, root_payload: T) -> Self;
    pub fn get(&self, fid: Fid) -> Result<&FidEntry<T>, IpcError>;
    pub fn get_mut(&mut self, fid: Fid) -> Result<&mut FidEntry<T>, IpcError>;
    pub fn insert(&mut self, new_fid: Fid, qpath: QPath, payload: T) -> Result<(), IpcError>;
    pub fn begin_open(&mut self, fid: Fid) -> Result<&mut FidEntry<T>, IpcError>;
    pub fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError>;
    pub fn clunk(&mut self, fid: Fid) -> Result<(), IpcError>;
    pub fn contains(&self, fid: Fid) -> bool;
}
```

### How servers use it

**walk():** `tracker.get(fid)?` to validate source → resolve name → `tracker.insert(new_fid, qpath, payload)?`

**open():** `tracker.begin_open(fid)?` → server-specific mode validation → `entry.mark_open(mode)`

**clone_fid():** `tracker.clone_fid(fid, new_fid)?` (fully delegated)

**clunk():** `tracker.clunk(fid)?` + optional server-specific cleanup

**read/write/stat:** `tracker.get(fid)?` or `tracker.get_mut(fid)?` then server-specific logic

---

### Task 1: Create FidTracker module with types and constructor

**Files:**
- Create: `crates/harmony-microkernel/src/fid_tracker.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs:16` (add `pub mod fid_tracker;`)

**Step 1: Write the failing test**

Add `fid_tracker.rs` with the test module and first test:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! Shared fid lifecycle tracker for 9P file servers.
//!
//! Owns the `BTreeMap<Fid, FidEntry<T>>` and implements the common
//! fid operations (insert, clone, clunk, begin_open) so that individual
//! `FileServer` implementations only handle namespace resolution,
//! mode validation, and I/O.

extern crate alloc;

use alloc::collections::BTreeMap;
use crate::{Fid, IpcError, OpenMode, QPath};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_root_fid() {
        let tracker: FidTracker<()> = FidTracker::new(0, ());
        let entry = tracker.get(0).unwrap();
        assert_eq!(entry.qpath, 0);
        assert!(!entry.is_open);
        assert_eq!(entry.mode, None);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-microkernel fid_tracker::tests::new_creates_root_fid`
Expected: FAIL — `FidTracker` and `FidEntry` not defined

**Step 3: Write minimal implementation**

Add above the test module in `fid_tracker.rs`:

```rust
/// Per-fid state tracked by [`FidTracker`].
///
/// `T` is a server-specific payload (e.g. `()` for simple servers,
/// `NodeKind` for ContentServer, `Arc<str>` for LibraryServer).
#[derive(Debug, Clone)]
pub struct FidEntry<T: Clone> {
    /// Stable file identity (like an inode number).
    pub qpath: QPath,
    /// Whether `open()` has been called on this fid.
    pub is_open: bool,
    /// The mode passed to `open()`, if open.
    pub mode: Option<OpenMode>,
    /// Server-specific data associated with this fid.
    pub payload: T,
}

impl<T: Clone> FidEntry<T> {
    /// Mark this entry as open with the given mode.
    ///
    /// Call this *after* server-specific mode validation succeeds.
    pub fn mark_open(&mut self, mode: OpenMode) {
        self.is_open = true;
        self.mode = Some(mode);
    }
}

/// Shared fid lifecycle tracker for 9P file servers.
///
/// Manages the `BTreeMap<Fid, FidEntry<T>>` and provides the common
/// operations that are identical across all `FileServer` implementations:
/// insert (for walk), clone_fid, clunk, and begin_open.
pub struct FidTracker<T: Clone> {
    fids: BTreeMap<Fid, FidEntry<T>>,
}

impl<T: Clone> FidTracker<T> {
    /// Create a new tracker with fid 0 pre-attached to the root.
    pub fn new(root_qpath: QPath, root_payload: T) -> Self {
        let mut fids = BTreeMap::new();
        fids.insert(
            0,
            FidEntry {
                qpath: root_qpath,
                is_open: false,
                mode: None,
                payload: root_payload,
            },
        );
        Self { fids }
    }

    /// Look up a fid. Returns `InvalidFid` if not found.
    pub fn get(&self, fid: Fid) -> Result<&FidEntry<T>, IpcError> {
        self.fids.get(&fid).ok_or(IpcError::InvalidFid)
    }

    /// Look up a fid mutably. Returns `InvalidFid` if not found.
    pub fn get_mut(&mut self, fid: Fid) -> Result<&mut FidEntry<T>, IpcError> {
        self.fids.get_mut(&fid).ok_or(IpcError::InvalidFid)
    }

    /// Check whether a fid exists.
    pub fn contains(&self, fid: Fid) -> bool {
        self.fids.contains_key(&fid)
    }
}
```

**Step 4: Register the module**

In `crates/harmony-microkernel/src/lib.rs`, add after the existing module declarations (around line 16):

```rust
pub mod fid_tracker;
```

**Step 5: Run test to verify it passes**

Run: `cargo test -p harmony-microkernel fid_tracker::tests::new_creates_root_fid`
Expected: PASS

**Step 6: Commit**

```bash
git add crates/harmony-microkernel/src/fid_tracker.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(microkernel): add FidTracker module with FidEntry type and constructor"
```

---

### Task 2: Add insert, clunk, clone_fid, begin_open methods

**Files:**
- Modify: `crates/harmony-microkernel/src/fid_tracker.rs`

**Step 1: Write failing tests**

Add to the test module:

```rust
    #[test]
    fn insert_new_fid() {
        let mut tracker: FidTracker<()> = FidTracker::new(0, ());
        tracker.insert(1, 42, ()).unwrap();
        let entry = tracker.get(1).unwrap();
        assert_eq!(entry.qpath, 42);
        assert!(!entry.is_open);
    }

    #[test]
    fn insert_duplicate_fid_rejected() {
        let mut tracker: FidTracker<()> = FidTracker::new(0, ());
        tracker.insert(1, 42, ()).unwrap();
        assert_eq!(tracker.insert(1, 99, ()), Err(IpcError::InvalidFid));
    }

    #[test]
    fn insert_fid_zero_rejected() {
        let mut tracker: FidTracker<()> = FidTracker::new(0, ());
        // Fid 0 is pre-allocated as root — inserting it again must fail.
        assert_eq!(tracker.insert(0, 99, ()), Err(IpcError::InvalidFid));
    }

    #[test]
    fn clunk_removes_fid() {
        let mut tracker: FidTracker<()> = FidTracker::new(0, ());
        tracker.insert(1, 42, ()).unwrap();
        tracker.clunk(1).unwrap();
        assert!(!tracker.contains(1));
    }

    #[test]
    fn clunk_root_rejected() {
        let mut tracker: FidTracker<()> = FidTracker::new(0, ());
        assert_eq!(tracker.clunk(0), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn clunk_unknown_fid_rejected() {
        let mut tracker: FidTracker<()> = FidTracker::new(0, ());
        assert_eq!(tracker.clunk(99), Err(IpcError::InvalidFid));
    }

    #[test]
    fn clone_fid_creates_closed_copy() {
        let mut tracker: FidTracker<()> = FidTracker::new(0, ());
        tracker.insert(1, 42, ()).unwrap();
        // Open the source fid first
        let entry = tracker.begin_open(1).unwrap();
        entry.mark_open(OpenMode::Read);

        let qpath = tracker.clone_fid(1, 2).unwrap();
        assert_eq!(qpath, 42);
        let cloned = tracker.get(2).unwrap();
        assert_eq!(cloned.qpath, 42);
        assert!(!cloned.is_open, "cloned fid must be closed");
        assert_eq!(cloned.mode, None);
    }

    #[test]
    fn clone_fid_duplicate_new_fid_rejected() {
        let mut tracker: FidTracker<()> = FidTracker::new(0, ());
        tracker.insert(1, 42, ()).unwrap();
        assert_eq!(tracker.clone_fid(1, 1), Err(IpcError::InvalidFid));
    }

    #[test]
    fn clone_fid_unknown_source_rejected() {
        let mut tracker: FidTracker<()> = FidTracker::new(0, ());
        assert_eq!(tracker.clone_fid(99, 1), Err(IpcError::InvalidFid));
    }

    #[test]
    fn begin_open_rejects_already_open() {
        let mut tracker: FidTracker<()> = FidTracker::new(0, ());
        tracker.insert(1, 42, ()).unwrap();
        let entry = tracker.begin_open(1).unwrap();
        entry.mark_open(OpenMode::Read);
        assert_eq!(tracker.begin_open(1).map(|_| ()), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn begin_open_unknown_fid_rejected() {
        let mut tracker: FidTracker<()> = FidTracker::new(0, ());
        assert_eq!(tracker.begin_open(99).map(|_| ()), Err(IpcError::InvalidFid));
    }

    #[test]
    fn mark_open_sets_state() {
        let mut tracker: FidTracker<()> = FidTracker::new(0, ());
        tracker.insert(1, 42, ()).unwrap();
        let entry = tracker.begin_open(1).unwrap();
        entry.mark_open(OpenMode::ReadWrite);
        let entry = tracker.get(1).unwrap();
        assert!(entry.is_open);
        assert_eq!(entry.mode, Some(OpenMode::ReadWrite));
    }

    #[test]
    fn clone_fid_preserves_payload() {
        let mut tracker: FidTracker<u32> = FidTracker::new(0, 100);
        tracker.insert(1, 42, 999).unwrap();
        tracker.clone_fid(1, 2).unwrap();
        let cloned = tracker.get(2).unwrap();
        assert_eq!(cloned.payload, 999);
    }
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel fid_tracker::tests`
Expected: FAIL — `insert`, `clunk`, `clone_fid`, `begin_open` not defined

**Step 3: Write the implementation**

Add to `impl<T: Clone> FidTracker<T>` block, after `contains`:

```rust
    /// Insert a new fid with the given qpath and payload.
    ///
    /// Returns `InvalidFid` if `new_fid` is already in use.
    /// The new entry starts closed (`is_open: false`, `mode: None`).
    pub fn insert(
        &mut self,
        new_fid: Fid,
        qpath: QPath,
        payload: T,
    ) -> Result<(), IpcError> {
        if self.fids.contains_key(&new_fid) {
            return Err(IpcError::InvalidFid);
        }
        self.fids.insert(
            new_fid,
            FidEntry {
                qpath,
                is_open: false,
                mode: None,
                payload,
            },
        );
        Ok(())
    }

    /// Validate that a fid exists and is not already open.
    ///
    /// Returns a mutable reference to the entry so the server can
    /// perform mode validation, then call [`FidEntry::mark_open`].
    ///
    /// Returns `InvalidFid` if the fid does not exist, or
    /// `PermissionDenied` if it is already open.
    pub fn begin_open(&mut self, fid: Fid) -> Result<&mut FidEntry<T>, IpcError> {
        let entry = self.fids.get_mut(&fid).ok_or(IpcError::InvalidFid)?;
        if entry.is_open {
            return Err(IpcError::PermissionDenied);
        }
        Ok(entry)
    }

    /// Clone a fid: create `new_fid` as a closed duplicate of `fid`.
    ///
    /// The payload is cloned from the source. The new entry starts
    /// closed regardless of the source's open state.
    ///
    /// Returns `InvalidFid` if `new_fid` already exists or `fid` is unknown.
    pub fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        if self.fids.contains_key(&new_fid) {
            return Err(IpcError::InvalidFid);
        }
        let source = self.fids.get(&fid).ok_or(IpcError::InvalidFid)?;
        let qpath = source.qpath;
        let payload = source.payload.clone();
        self.fids.insert(
            new_fid,
            FidEntry {
                qpath,
                is_open: false,
                mode: None,
                payload,
            },
        );
        Ok(qpath)
    }

    /// Release a fid. Rejects clunking fid 0 (the root).
    ///
    /// Returns `PermissionDenied` for fid 0, `InvalidFid` if unknown.
    /// Servers that need cleanup on clunk (e.g. ContentServer's ingest
    /// buffers) should do so after calling this method.
    pub fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        if fid == 0 {
            return Err(IpcError::PermissionDenied);
        }
        self.fids.remove(&fid).ok_or(IpcError::InvalidFid)?;
        Ok(())
    }
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel fid_tracker::tests`
Expected: PASS (all 14 tests)

**Step 5: Run full workspace tests**

Run: `cargo test --workspace`
Expected: All 661+ tests pass

**Step 6: Commit**

```bash
git add crates/harmony-microkernel/src/fid_tracker.rs
git commit -m "feat(fid_tracker): add insert, clunk, clone_fid, begin_open lifecycle methods"
```

---

### Task 3: Migrate EchoServer to FidTracker

**Files:**
- Modify: `crates/harmony-microkernel/src/echo.rs`

The EchoServer is the simplest server with payload `T = ()`. This validates the API.

**Step 1: Replace FidState and BTreeMap with FidTracker**

Remove lines 6, 22-27 (`use alloc::collections::BTreeMap` and the `FidState` struct).

Replace the `EchoServer` struct and `new()`:

```rust
use crate::fid_tracker::{FidEntry, FidTracker};

pub struct EchoServer {
    tracker: FidTracker<()>,
    echo_data: Vec<u8>,
}

impl EchoServer {
    pub fn new() -> Self {
        Self {
            tracker: FidTracker::new(ROOT, ()),
            echo_data: Vec::new(),
        }
    }
}
```

**Step 2: Rewrite walk()**

```rust
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let entry = self.tracker.get(fid)?;
        if entry.qpath != ROOT {
            return Err(IpcError::NotDirectory);
        }

        let qpath = match name {
            "hello" => HELLO,
            "echo" => ECHO,
            _ => return Err(IpcError::NotFound),
        };

        self.tracker.insert(new_fid, qpath, ())?;
        Ok(qpath)
    }
```

**Step 3: Rewrite open()**

```rust
    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let entry = self.tracker.begin_open(fid)?;
        if entry.qpath == ROOT && matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
            return Err(IpcError::IsDirectory);
        }
        if entry.qpath == HELLO && matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
            return Err(IpcError::ReadOnly);
        }
        entry.mark_open(mode);
        Ok(())
    }
```

**Step 4: Rewrite read() and write()**

Replace `self.fids.get(&fid).ok_or(IpcError::InvalidFid)?` with `self.tracker.get(fid)?` and access fields via `entry.is_open`, `entry.mode`, `entry.qpath`.

```rust
    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.is_open {
            return Err(IpcError::NotOpen);
        }
        if matches!(entry.mode, Some(OpenMode::Write)) {
            return Err(IpcError::PermissionDenied);
        }

        let data: &[u8] = match entry.qpath {
            ROOT => return Err(IpcError::IsDirectory),
            HELLO => HELLO_GREETING,
            ECHO => &self.echo_data,
            _ => return Err(IpcError::NotFound),
        };

        let offset = offset.min(usize::MAX as u64) as usize;
        if offset >= data.len() {
            return Ok(Vec::new());
        }
        let end = core::cmp::min(offset.saturating_add(count as usize), data.len());
        Ok(data[offset..end].to_vec())
    }

    fn write(&mut self, fid: Fid, _offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.is_open {
            return Err(IpcError::NotOpen);
        }
        if matches!(entry.mode, Some(OpenMode::Read)) {
            return Err(IpcError::PermissionDenied);
        }

        match entry.qpath {
            ROOT => Err(IpcError::IsDirectory),
            HELLO => Err(IpcError::ReadOnly),
            ECHO => {
                let len = u32::try_from(data.len()).map_err(|_| IpcError::ResourceExhausted)?;
                self.echo_data = data.to_vec();
                Ok(len)
            }
            _ => Err(IpcError::NotFound),
        }
    }
```

**Step 5: Rewrite clunk(), clone_fid(), stat()**

```rust
    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        self.tracker.clunk(fid)
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        self.tracker.clone_fid(fid, new_fid)
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let entry = self.tracker.get(fid)?;
        match entry.qpath {
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
```

**Step 6: Remove unused imports**

Remove `use alloc::collections::BTreeMap;` from echo.rs. Keep `alloc::sync::Arc` and `alloc::vec::Vec`.

**Step 7: Run tests**

Run: `cargo test -p harmony-microkernel echo::tests`
Expected: All 15 existing echo tests pass

Run: `cargo test --workspace`
Expected: All tests pass

**Step 8: Commit**

```bash
git add crates/harmony-microkernel/src/echo.rs
git commit -m "refactor(echo): migrate EchoServer to shared FidTracker"
```

---

### Task 4: Migrate SerialServer to FidTracker

**Files:**
- Modify: `crates/harmony-microkernel/src/serial_server.rs`

Identical pattern to EchoServer. Also removes the original TODO.

**Step 1: Replace FidState with FidTracker**

Remove the `FidState` struct (lines 19-23) and the TODO comment (lines 17-18).
Remove `use alloc::collections::BTreeMap;`.
Add `use crate::fid_tracker::{FidEntry, FidTracker};`.

Replace `SerialServer`:

```rust
pub struct SerialServer {
    tracker: FidTracker<()>,
    buf: Vec<u8>,
}
```

Replace `new()`:

```rust
    pub fn new() -> Self {
        SerialServer {
            tracker: FidTracker::new(QPATH_ROOT, ()),
            buf: Vec::new(),
        }
    }
```

**Step 2: Rewrite FileServer methods**

Same pattern as EchoServer — replace `self.fids.get(...)` with `self.tracker.get(...)`, delegate clunk/clone_fid entirely.

```rust
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let entry = self.tracker.get(fid)?;
        if entry.qpath != QPATH_ROOT {
            return Err(IpcError::NotDirectory);
        }
        if name != "log" {
            return Err(IpcError::NotFound);
        }
        self.tracker.insert(new_fid, QPATH_LOG, ())?;
        Ok(QPATH_LOG)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let entry = self.tracker.begin_open(fid)?;
        if entry.qpath == QPATH_ROOT && matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
            return Err(IpcError::IsDirectory);
        }
        entry.mark_open(mode);
        Ok(())
    }

    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.is_open {
            return Err(IpcError::NotOpen);
        }
        if entry.qpath == QPATH_ROOT {
            return Err(IpcError::IsDirectory);
        }
        if matches!(entry.mode, Some(OpenMode::Write)) {
            return Err(IpcError::PermissionDenied);
        }
        let start = core::cmp::min(offset.min(usize::MAX as u64) as usize, self.buf.len());
        let end = core::cmp::min(start.saturating_add(count as usize), self.buf.len());
        Ok(self.buf[start..end].to_vec())
    }

    fn write(&mut self, fid: Fid, _offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.is_open {
            return Err(IpcError::NotOpen);
        }
        if entry.qpath == QPATH_ROOT {
            return Err(IpcError::IsDirectory);
        }
        if matches!(entry.mode, Some(OpenMode::Read)) {
            return Err(IpcError::PermissionDenied);
        }
        let len = u32::try_from(data.len()).map_err(|_| IpcError::ResourceExhausted)?;
        self.buf.extend_from_slice(data);
        Ok(len)
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        self.tracker.clunk(fid)
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        self.tracker.clone_fid(fid, new_fid)
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let entry = self.tracker.get(fid)?;
        let (name, file_type, size) = match entry.qpath {
            QPATH_ROOT => ("/", FileType::Directory, 0),
            QPATH_LOG => ("log", FileType::Regular, self.buf.len() as u64),
            _ => return Err(IpcError::NotFound),
        };
        Ok(FileStat {
            qpath: entry.qpath,
            name: Arc::from(name),
            size,
            file_type,
        })
    }
```

**Step 3: Run tests**

Run: `cargo test -p harmony-microkernel serial_server::tests`
Expected: All 7 existing tests pass

Run: `cargo test --workspace`
Expected: All tests pass

**Step 4: Commit**

```bash
git add crates/harmony-microkernel/src/serial_server.rs
git commit -m "refactor(serial): migrate SerialServer to FidTracker, remove extraction TODO"
```

---

### Task 5: Migrate UartServer, GpioServer, SdServer, GenetServer

**Files:**
- Modify: `crates/harmony-microkernel/src/uart_server.rs`
- Modify: `crates/harmony-microkernel/src/gpio_server.rs`
- Modify: `crates/harmony-microkernel/src/sd_server.rs`
- Modify: `crates/harmony-microkernel/src/genet_server.rs`

All four follow the exact same pattern as EchoServer/SerialServer. For each server:

1. Remove `FidState` struct definition
2. Remove `use alloc::collections::BTreeMap;`
3. Add `use crate::fid_tracker::{FidEntry, FidTracker};`
4. Replace `fids: BTreeMap<Fid, FidState>` with `tracker: FidTracker<()>`
5. Replace `new()` to use `FidTracker::new(ROOT_QPATH, ())`
6. Rewrite `walk()`: `tracker.get(fid)?` + `tracker.insert(new_fid, qpath, ())?`
7. Rewrite `open()`: `tracker.begin_open(fid)?` + mode validation + `entry.mark_open(mode)`
8. Rewrite `read()`/`write()`: `tracker.get(fid)?` with field access
9. Delegate `clunk()` to `tracker.clunk(fid)`
10. Delegate `clone_fid()` to `tracker.clone_fid(fid, new_fid)`
11. Rewrite `stat()`: `tracker.get(fid)?` with field access

The only server-specific logic is:
- **UartServer**: `walk` resolves `"uart"` to `QPATH_UART`, read/write interact with `UartPort`
- **GpioServer**: `walk` resolves `"gpioN"` to pin qpaths, read/write interact with `GpioController`
- **SdServer**: `walk` resolves `"block"` to `QPATH_BLOCK`, read/write interact with `SdController`
- **GenetServer**: `walk` resolves `"eth0"` to `QPATH_ETH0`, read/write interact with `GenetDevice`

**Run after each server migration:**

Run: `cargo test --workspace`
Expected: All tests pass

**Commit after all four:**

```bash
git add crates/harmony-microkernel/src/uart_server.rs crates/harmony-microkernel/src/gpio_server.rs crates/harmony-microkernel/src/sd_server.rs crates/harmony-microkernel/src/genet_server.rs
git commit -m "refactor(servers): migrate Uart, Gpio, Sd, Genet servers to FidTracker"
```

---

### Task 6: Migrate LibraryServer to FidTracker

**Files:**
- Modify: `crates/harmony-microkernel/src/library_server.rs`

LibraryServer is the first outlier: `T = Arc<str>` (library name), no `mode` field, and clunk on fid 0 returns `Ok(())` instead of `Err`.

**Step 1: Replace FidState with FidTracker**

Remove the `FidState` struct (lines 23-30).
Remove `use alloc::collections::BTreeMap;` from the alloc imports (keep the one for `manifest`).
Add `use crate::fid_tracker::FidTracker;`.

Replace struct:

```rust
pub struct LibraryServer {
    manifest: BTreeMap<Arc<str>, Vec<u8>>,
    tracker: FidTracker<Arc<str>>,
}
```

Replace `new()`:

```rust
    pub fn new(manifest: BTreeMap<Arc<str>, Vec<u8>>) -> Self {
        Self {
            manifest,
            tracker: FidTracker::new(0, Arc::from("")),
        }
    }
```

**Step 2: Rewrite walk()**

LibraryServer uses `name.is_empty()` to check for directory (root name = ""). With FidTracker, this is `entry.payload.is_empty()`:

```rust
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.payload.is_empty() {
            return Err(IpcError::InvalidFid);
        }
        let key: Arc<str> = Arc::from(name);
        if !self.manifest.contains_key(&key) {
            return Err(IpcError::NotFound);
        }
        let qpath = Self::qpath_for(name);
        self.tracker.insert(new_fid, qpath, key)?;
        Ok(qpath)
    }
```

**Step 3: Rewrite open()**

LibraryServer is read-only and doesn't check `is_open`. Use `get_mut` directly instead of `begin_open`:

```rust
    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let entry = self.tracker.get_mut(fid)?;
        if mode != OpenMode::Read {
            return Err(IpcError::ReadOnly);
        }
        entry.is_open = true;
        Ok(())
    }
```

**Step 4: Rewrite read()**

```rust
    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.is_open {
            return Err(IpcError::NotOpen);
        }
        if entry.payload.is_empty() {
            return Err(IpcError::IsDirectory);
        }
        let data = self.manifest.get(&*entry.payload).ok_or(IpcError::NotFound)?;
        let off = offset as usize;
        if off >= data.len() {
            return Ok(Vec::new());
        }
        let end = (off + count as usize).min(data.len());
        Ok(data[off..end].to_vec())
    }
```

**Step 5: Rewrite clunk()**

LibraryServer returns `Ok(())` for fid 0 instead of erroring. Handle this before delegating:

```rust
    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        if fid == 0 {
            return Ok(());
        }
        self.tracker.clunk(fid)
    }
```

**Step 6: Rewrite clone_fid() and stat()**

```rust
    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        self.tracker.clone_fid(fid, new_fid)
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let entry = self.tracker.get(fid)?;
        if entry.payload.is_empty() {
            return Ok(FileStat {
                qpath: 0,
                name: Arc::from("lib"),
                size: 0,
                file_type: FileType::Directory,
            });
        }
        let data = self.manifest.get(&*entry.payload).ok_or(IpcError::NotFound)?;
        Ok(FileStat {
            qpath: entry.qpath,
            name: Arc::clone(&entry.payload),
            size: data.len() as u64,
            file_type: FileType::Regular,
        })
    }
```

**Step 7: Run tests**

Run: `cargo test -p harmony-microkernel library_server::tests`
Expected: All existing library_server tests pass

Run: `cargo test --workspace`
Expected: All tests pass

**Step 8: Commit**

```bash
git add crates/harmony-microkernel/src/library_server.rs
git commit -m "refactor(library): migrate LibraryServer to FidTracker<Arc<str>>"
```

---

### Task 7: Migrate ContentServer to FidTracker

**Files:**
- Modify: `crates/harmony-microkernel/src/content_server.rs`

ContentServer is the most complex: `T = NodeKind`, has an `ingest_buffers` side map that needs cleanup on clunk, and has multi-level directory walks.

**Step 1: Replace FidState with FidTracker**

Remove the `FidState` struct (lines 60-65).
Remove `use alloc::collections::BTreeMap;` from the alloc imports (keep BTreeMap — still used for `pages`, `blobs`, `ingest_buffers`).
Add `use crate::fid_tracker::FidTracker;`.

Replace struct — `fids: BTreeMap<Fid, FidState>` becomes `tracker: FidTracker<NodeKind>`:

```rust
pub struct ContentServer {
    pages: BTreeMap<u32, (PageAddr, Vec<u8>)>,
    blobs: BTreeMap<[u8; 32], Book>,
    tracker: FidTracker<NodeKind>,
    ingest_buffers: BTreeMap<Fid, IngestState>,
}
```

Replace `new()`:

```rust
    pub fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
            blobs: BTreeMap::new(),
            tracker: FidTracker::new(ROOT, NodeKind::Root),
            ingest_buffers: BTreeMap::new(),
        }
    }
```

**Step 2: Rewrite walk()**

```rust
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let entry = self.tracker.get(fid)?;
        let parent_node = entry.payload.clone();

        let (qpath, node) = match &parent_node {
            NodeKind::Root => match name {
                "blobs" => (BLOBS_DIR, NodeKind::BlobsDir),
                "pages" => (PAGES_DIR, NodeKind::PagesDir),
                "ingest" => (INGEST, NodeKind::Ingest),
                _ => return Err(IpcError::NotFound),
            },
            NodeKind::BlobsDir => {
                let cid = parse_hex_cid(name).ok_or(IpcError::NotFound)?;
                if !self.blobs.contains_key(&cid) {
                    return Err(IpcError::NotFound);
                }
                (Self::blob_qpath(&cid), NodeKind::Blob(cid))
            }
            NodeKind::PagesDir => {
                if name.len() != 8 {
                    return Err(IpcError::NotFound);
                }
                if name.bytes().any(|b| b.is_ascii_uppercase()) {
                    return Err(IpcError::NotFound);
                }
                let hash_bits =
                    u32::from_str_radix(name, 16).map_err(|_| IpcError::NotFound)?;
                let addr = *self.find_page(hash_bits).ok_or(IpcError::NotFound)?;
                (Self::page_qpath(&addr), NodeKind::Page(addr))
            }
            NodeKind::Blob(_) | NodeKind::Page(_) | NodeKind::Ingest => {
                return Err(IpcError::NotDirectory);
            }
        };

        self.tracker.insert(new_fid, qpath, node)?;
        Ok(qpath)
    }
```

**Step 3: Rewrite open()**

ContentServer's open has complex node-specific validation and inserts into `ingest_buffers`. Use `begin_open` for the common is_open check, then do server-specific validation. However, ContentServer also needs to re-borrow after inserting into `ingest_buffers`.

```rust
    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let entry = self.tracker.begin_open(fid)?;
        match &entry.payload {
            NodeKind::Root | NodeKind::BlobsDir | NodeKind::PagesDir => {
                if matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
                    return Err(IpcError::IsDirectory);
                }
            }
            NodeKind::Blob(_) | NodeKind::Page(_) => {
                if matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
                    return Err(IpcError::ReadOnly);
                }
            }
            NodeKind::Ingest => {
                if !matches!(mode, OpenMode::ReadWrite) {
                    return Err(IpcError::PermissionDenied);
                }
                if self.ingest_buffers.len() >= MAX_CONCURRENT_INGESTS {
                    return Err(IpcError::ResourceExhausted);
                }
                self.ingest_buffers
                    .insert(fid, IngestState::Writing(Vec::new()));
                // Re-borrow after ingest_buffers insert.
                let entry = self.tracker.get_mut(fid).unwrap();
                entry.mark_open(mode);
                return Ok(());
            }
        }
        entry.mark_open(mode);
        Ok(())
    }
```

**Note:** The `Ingest` branch needs to insert into `ingest_buffers` (which borrows `self`), then re-borrow `tracker`. This is why it has a separate `return Ok(())` path with a re-borrow. This matches the original code's pattern at line 472.

**Step 4: Rewrite read(), write(), clunk(), clone_fid(), stat()**

Replace all `self.fids.get(&fid).ok_or(IpcError::InvalidFid)?` with `self.tracker.get(fid)?`, and access `entry.qpath`, `entry.is_open`, `entry.mode`, `entry.payload` (instead of `state.node`).

For `clunk`, keep the `ingest_buffers.remove` cleanup:

```rust
    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        self.tracker.clunk(fid)?;
        self.ingest_buffers.remove(&fid);
        Ok(())
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        self.tracker.clone_fid(fid, new_fid)
    }
```

For `stat`, replace `state.node` with `entry.payload`:

```rust
    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let entry = self.tracker.get(fid)?;
        match &entry.payload {
            // ... same match arms as before, using entry.payload instead of state.node ...
        }
    }
```

For `read` and `write`, replace `state.is_open`/`state.mode`/`state.node` with `entry.is_open`/`entry.mode`/`entry.payload`.

**Step 5: Remove FidState struct and unused BTreeMap import for fids**

The `BTreeMap` import is still needed for `pages`, `blobs`, and `ingest_buffers`.

**Step 6: Run tests**

Run: `cargo test -p harmony-microkernel content_server::tests`
Expected: All existing content_server tests pass

Run: `cargo test --workspace`
Expected: All tests pass

**Step 7: Commit**

```bash
git add crates/harmony-microkernel/src/content_server.rs
git commit -m "refactor(content): migrate ContentServer to FidTracker<NodeKind>"
```

---

### Task 8: Final verification

**Step 1: Verify no FidState structs remain**

Run: `grep -rn "struct FidState" crates/harmony-microkernel/src/`
Expected: No matches

**Step 2: Run full test suite**

Run: `cargo test --workspace`
Expected: All 661+ tests pass (count should be same plus ~14 new FidTracker tests)

**Step 3: Run clippy**

Run: `cargo clippy --workspace`
Expected: Zero warnings

**Step 4: Commit any remaining cleanup**

If clippy finds unused imports or other issues from the migration, fix and commit:

```bash
git commit -m "chore: clean up unused imports after FidTracker migration"
```
