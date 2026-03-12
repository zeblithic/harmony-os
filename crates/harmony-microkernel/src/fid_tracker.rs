// SPDX-License-Identifier: GPL-2.0-or-later

//! Generic fid lifecycle tracker shared by all `FileServer` implementations.
//!
//! Every 9P file server needs to map `Fid` handles to per-file state
//! (qpath, open/closed, open mode, plus server-specific payload). This
//! module extracts that boilerplate into a single generic helper.

extern crate alloc;

use alloc::collections::BTreeMap;

use crate::{Fid, IpcError, OpenMode, QPath};

// ── Per-fid entry ──────────────────────────────────────────────────

/// State tracked for each fid: its qpath, open status, and an
/// arbitrary server-specific payload of type `T`.
///
/// `is_open` and `mode` are encapsulated — mutate only through
/// `mark_open` and `reset_open_state` to maintain lifecycle invariants.
#[derive(Debug, Clone)]
pub struct FidEntry<T: Clone> {
    pub qpath: QPath,
    is_open: bool,
    mode: Option<OpenMode>,
    pub payload: T,
}

impl<T: Clone> FidEntry<T> {
    /// Whether this fid has been opened.
    pub fn is_open(&self) -> bool {
        self.is_open
    }

    /// The mode this fid was opened with, if any.
    pub fn mode(&self) -> Option<OpenMode> {
        self.mode
    }

    /// Mark this fid as open with the given mode.
    pub fn mark_open(&mut self, mode: OpenMode) {
        self.is_open = true;
        self.mode = Some(mode);
    }

    /// Reset open state to closed. Used by in-place walk (9P2000:
    /// `new_fid == fid` replaces the binding, resetting the fid to
    /// a walked-but-not-opened state).
    pub fn reset_open_state(&mut self) {
        self.is_open = false;
        self.mode = None;
    }
}

// ── FidTracker ─────────────────────────────────────────────────────

/// A `BTreeMap`-backed tracker that owns the fid → entry mapping for a
/// `FileServer`.  Created with fid 0 pre-attached to a root qpath.
#[derive(Debug, Clone)]
pub struct FidTracker<T: Clone> {
    fids: BTreeMap<Fid, FidEntry<T>>,
}

impl<T: Clone> FidTracker<T> {
    /// Create a new tracker with fid 0 pre-attached to `root_qpath`.
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

    /// Look up an entry by fid.  Returns `InvalidFid` if the fid is
    /// not present.
    pub fn get(&self, fid: Fid) -> Result<&FidEntry<T>, IpcError> {
        self.fids.get(&fid).ok_or(IpcError::InvalidFid)
    }

    /// Mutable look-up by fid.
    pub fn get_mut(&mut self, fid: Fid) -> Result<&mut FidEntry<T>, IpcError> {
        self.fids.get_mut(&fid).ok_or(IpcError::InvalidFid)
    }

    /// Returns `true` if the tracker contains `fid`.
    #[cfg(test)]
    pub fn contains(&self, fid: Fid) -> bool {
        self.fids.contains_key(&fid)
    }

    /// Insert a new fid with the given qpath and payload.
    /// Returns `InvalidFid` if `new_fid` is already in use.
    /// The new entry starts closed (is_open: false, mode: None).
    pub fn insert(&mut self, new_fid: Fid, qpath: QPath, payload: T) -> Result<(), IpcError> {
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
    /// Returns mutable ref so server can do mode validation, then call mark_open.
    /// Returns InvalidFid if missing, PermissionDenied if already open.
    pub fn begin_open(&mut self, fid: Fid) -> Result<&mut FidEntry<T>, IpcError> {
        let entry = self.fids.get_mut(&fid).ok_or(IpcError::InvalidFid)?;
        if entry.is_open {
            return Err(IpcError::PermissionDenied);
        }
        Ok(entry)
    }

    /// Clone a fid: create new_fid as a closed duplicate of fid.
    /// Payload is cloned. New entry is always closed.
    /// Returns InvalidFid if new_fid exists or fid is unknown.
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
    /// Returns PermissionDenied for fid 0, InvalidFid if unknown.
    pub fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        if fid == 0 {
            return Err(IpcError::PermissionDenied);
        }
        self.fids.remove(&fid).ok_or(IpcError::InvalidFid)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_root_fid() {
        let tracker: FidTracker<()> = FidTracker::new(42, ());

        // fid 0 must exist
        assert!(tracker.contains(0));

        let entry = tracker.get(0).expect("fid 0 should exist");
        assert_eq!(entry.qpath, 42);
        assert!(!entry.is_open());
        assert_eq!(entry.mode(), None);
    }

    #[test]
    fn insert_new_fid() {
        let mut tracker: FidTracker<()> = FidTracker::new(0, ());
        tracker.insert(1, 42, ()).unwrap();
        let entry = tracker.get(1).unwrap();
        assert_eq!(entry.qpath, 42);
        assert!(!entry.is_open());
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
        let entry = tracker.begin_open(1).unwrap();
        entry.mark_open(OpenMode::Read);
        let qpath = tracker.clone_fid(1, 2).unwrap();
        assert_eq!(qpath, 42);
        let cloned = tracker.get(2).unwrap();
        assert_eq!(cloned.qpath, 42);
        assert!(!cloned.is_open);
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
        assert_eq!(
            tracker.begin_open(1).map(|_| ()),
            Err(IpcError::PermissionDenied)
        );
    }

    #[test]
    fn begin_open_unknown_fid_rejected() {
        let mut tracker: FidTracker<()> = FidTracker::new(0, ());
        assert_eq!(
            tracker.begin_open(99).map(|_| ()),
            Err(IpcError::InvalidFid)
        );
    }

    #[test]
    fn mark_open_sets_state() {
        let mut tracker: FidTracker<()> = FidTracker::new(0, ());
        tracker.insert(1, 42, ()).unwrap();
        let entry = tracker.begin_open(1).unwrap();
        entry.mark_open(OpenMode::ReadWrite);
        let entry = tracker.get(1).unwrap();
        assert!(entry.is_open());
        assert_eq!(entry.mode(), Some(OpenMode::ReadWrite));
    }

    #[test]
    fn reset_open_state_clears_open_and_mode() {
        let mut tracker: FidTracker<()> = FidTracker::new(0, ());
        tracker.insert(1, 42, ()).unwrap();
        let entry = tracker.begin_open(1).unwrap();
        entry.mark_open(OpenMode::ReadWrite);
        // Now reset (used by in-place walk)
        let entry = tracker.get_mut(1).unwrap();
        entry.reset_open_state();
        assert!(!entry.is_open());
        assert_eq!(entry.mode(), None);
    }

    #[test]
    fn clone_fid_preserves_payload() {
        let mut tracker: FidTracker<u32> = FidTracker::new(0, 100);
        tracker.insert(1, 42, 999).unwrap();
        tracker.clone_fid(1, 2).unwrap();
        let cloned = tracker.get(2).unwrap();
        assert_eq!(cloned.payload, 999);
    }
}
