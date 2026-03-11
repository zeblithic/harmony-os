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
#[derive(Debug, Clone)]
pub struct FidEntry<T: Clone> {
    pub qpath: QPath,
    pub is_open: bool,
    pub mode: Option<OpenMode>,
    pub payload: T,
}

impl<T: Clone> FidEntry<T> {
    /// Mark this fid as open with the given mode.
    pub fn mark_open(&mut self, mode: OpenMode) {
        self.is_open = true;
        self.mode = Some(mode);
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
    pub fn contains(&self, fid: Fid) -> bool {
        self.fids.contains_key(&fid)
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
        assert!(!entry.is_open);
        assert_eq!(entry.mode, None);
    }
}
