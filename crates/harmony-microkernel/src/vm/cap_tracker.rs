// SPDX-License-Identifier: GPL-2.0-or-later
//! Capability tracker — per-process VM budget and permission enforcement.
//!
//! Uses a hybrid tracking strategy: only frames with non-empty
//! [`FrameClassification`] (ENCRYPTED, EPHEMERAL, or both) get B-tree entries.
//! Public/durable frames are tracked only via budget accounting, keeping the
//! B-tree proportional to "interesting" frames rather than total RAM.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{FrameClassification, MemoryZone, PhysAddr, VmError, PAGE_SHIFT, PAGE_SIZE};

// ── Per-frame metadata ──────────────────────────────────────────────

/// Metadata for a tracked physical frame.
///
/// Only frames with non-empty classification are stored in the B-tree.
#[derive(Debug, Clone)]
pub struct FrameMeta {
    /// The PID that originally allocated the frame.
    pub owner_pid: u32,
    /// Security classification bits (ENCRYPTED, EPHEMERAL, etc.).
    pub classification: FrameClassification,
    /// PIDs that currently have this frame mapped.
    pub mapped_by: Vec<u32>,
}

// ── Per-process budget ──────────────────────────────────────────────

/// Memory budget for a single process.
///
/// Enforces both a byte-count limit and classification restrictions.
#[derive(Debug, Clone)]
pub struct MemoryBudget {
    /// Maximum bytes this process may map.
    pub limit: usize,
    /// Currently mapped bytes.
    pub used: usize,
    /// Which frame classifications this process is allowed to map.
    pub allowed_classes: FrameClassification,
    /// Per-zone usage tracking, indexed by MemoryZone as usize.
    zone_usage: [usize; 4],
}

impl MemoryBudget {
    /// Create a new budget with `used` starting at zero.
    pub fn new(limit: usize, allowed_classes: FrameClassification) -> Self {
        Self {
            limit,
            used: 0,
            allowed_classes,
            zone_usage: [0; 4],
        }
    }

    /// Returns `true` if mapping `additional` more bytes stays within budget.
    pub fn can_map(&self, additional: usize) -> bool {
        self.used
            .checked_add(additional)
            .is_some_and(|total| total <= self.limit)
    }

    /// Returns the number of bytes this process has mapped in the given zone.
    pub fn zone_used(&self, zone: MemoryZone) -> usize {
        self.zone_usage[zone as usize]
    }

    /// Add `bytes` to the usage counter for `zone`.
    pub(crate) fn add_zone_usage(&mut self, zone: MemoryZone, bytes: usize) {
        self.zone_usage[zone as usize] += bytes;
    }

    /// Subtract `bytes` from the usage counter for `zone` (saturating).
    pub(crate) fn sub_zone_usage(&mut self, zone: MemoryZone, bytes: usize) {
        self.zone_usage[zone as usize] = self.zone_usage[zone as usize].saturating_sub(bytes);
    }
}

// ── Capability tracker ──────────────────────────────────────────────

/// Tracks per-process memory budgets and per-frame classification metadata.
///
/// The B-tree only contains entries for frames with non-empty classification,
/// keeping overhead proportional to "interesting" (encrypted/ephemeral) frames.
#[derive(Debug, Default)]
pub struct CapTracker {
    /// frame_number → metadata (only frames with non-empty classification).
    frame_meta: BTreeMap<u64, FrameMeta>,
    /// pid → memory budget.
    budgets: BTreeMap<u32, MemoryBudget>,
}

impl CapTracker {
    /// Create an empty capability tracker.
    pub fn new() -> Self {
        Self {
            frame_meta: BTreeMap::new(),
            budgets: BTreeMap::new(),
        }
    }

    /// Register (or replace) a process budget.
    pub fn set_budget(&mut self, pid: u32, budget: MemoryBudget) {
        self.budgets.insert(pid, budget);
    }

    /// Remove a process budget (e.g. on process destroy).
    pub fn remove_budget(&mut self, pid: u32) {
        self.budgets.remove(&pid);
    }

    /// Check whether `pid` is allowed to map `size` bytes with the given
    /// classification.
    ///
    /// Returns `Ok(())` if the mapping is permitted, or an appropriate
    /// [`VmError`] otherwise.
    pub fn check_budget(
        &self,
        pid: u32,
        size: usize,
        classification: FrameClassification,
    ) -> Result<(), VmError> {
        let budget = self.budgets.get(&pid).ok_or(VmError::NoSuchProcess(pid))?;

        if !budget.can_map(size) {
            return Err(VmError::BudgetExceeded {
                limit: budget.limit as u64,
                used: budget.used as u64,
                requested: size as u64,
            });
        }

        // Only enforce classification checks for non-empty classifications.
        if !classification.is_empty() && !budget.allowed_classes.contains(classification) {
            return Err(VmError::ClassificationDenied(classification));
        }

        Ok(())
    }

    /// Record that `pid` has mapped the frame at `paddr` with the given
    /// classification.
    ///
    /// Adds `PAGE_SIZE` to the process's budget usage. If `classification` is
    /// non-empty, creates or updates the B-tree entry for the frame.
    pub fn record_mapping(
        &mut self,
        paddr: PhysAddr,
        pid: u32,
        classification: FrameClassification,
    ) {
        // Update budget usage.
        if let Some(budget) = self.budgets.get_mut(&pid) {
            budget.used += PAGE_SIZE as usize;
            let zone = MemoryZone::from(classification);
            budget.add_zone_usage(zone, PAGE_SIZE as usize);
        }

        // Only track frames with non-empty classification in the B-tree.
        if !classification.is_empty() {
            let frame_num = paddr.as_u64() >> PAGE_SHIFT;
            let meta = self
                .frame_meta
                .entry(frame_num)
                .or_insert_with(|| FrameMeta {
                    owner_pid: pid,
                    classification,
                    mapped_by: Vec::new(),
                });
            if !meta.mapped_by.contains(&pid) {
                meta.mapped_by.push(pid);
            }
            // Merge classification bits (a frame mapped ENCRYPTED by one
            // process and EPHEMERAL by another is both).
            meta.classification |= classification;
        }
    }

    /// Remove a mapping of the frame at `paddr` for `pid`.
    ///
    /// Subtracts `PAGE_SIZE` from the process's budget usage and returns the
    /// frame's classification (empty if not tracked). Removes the B-tree entry
    /// once no PIDs reference the frame.
    pub fn remove_mapping(&mut self, paddr: PhysAddr, pid: u32) -> FrameClassification {
        let frame_num = paddr.as_u64() >> PAGE_SHIFT;

        // Determine the zone for this frame BEFORE any B-tree cleanup.
        let zone = self
            .frame_meta
            .get(&frame_num)
            .map(|meta| MemoryZone::from(meta.classification))
            .unwrap_or(MemoryZone::PublicDurable);

        // Update budget usage.
        if let Some(budget) = self.budgets.get_mut(&pid) {
            budget.used = budget.used.saturating_sub(PAGE_SIZE as usize);
            budget.sub_zone_usage(zone, PAGE_SIZE as usize);
        }

        let Some(meta) = self.frame_meta.get_mut(&frame_num) else {
            return FrameClassification::empty();
        };

        let classification = meta.classification;

        // Remove this PID from mapped_by.
        meta.mapped_by.retain(|&p| p != pid);

        // If no PIDs remain, remove the B-tree entry entirely.
        if meta.mapped_by.is_empty() {
            self.frame_meta.remove(&frame_num);
        }

        classification
    }

    /// Look up the classification of a physical frame.
    ///
    /// Returns [`FrameClassification::empty()`] if the frame is not tracked
    /// (i.e. it has no special classification).
    pub fn frame_classification(&self, paddr: PhysAddr) -> FrameClassification {
        let frame_num = paddr.as_u64() >> PAGE_SHIFT;
        self.frame_meta
            .get(&frame_num)
            .map_or(FrameClassification::empty(), |m| m.classification)
    }

    /// Return all frames whose classification contains `class`, along with
    /// the PIDs that have each frame mapped.
    ///
    /// Useful for revocation cascades (e.g. "revoke all ENCRYPTED frames").
    pub fn frames_with_classification(
        &self,
        class: FrameClassification,
    ) -> Vec<(PhysAddr, Vec<u32>)> {
        self.frame_meta
            .iter()
            .filter(|(_, meta)| meta.classification.contains(class))
            .map(|(&frame_num, meta)| (PhysAddr(frame_num << PAGE_SHIFT), meta.mapped_by.clone()))
            .collect()
    }

    /// Read-only access to a process's budget.
    pub fn budget(&self, pid: u32) -> Option<&MemoryBudget> {
        self.budgets.get(&pid)
    }

    /// Number of frames currently tracked in the B-tree.
    ///
    /// Only frames with non-empty classification are counted.
    pub fn tracked_frame_count(&self) -> usize {
        self.frame_meta.len()
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Page-aligned address helper.
    fn paddr(frame: u64) -> PhysAddr {
        PhysAddr(frame << PAGE_SHIFT)
    }

    #[test]
    fn budget_enforcement() {
        let mut tracker = CapTracker::new();
        let budget = MemoryBudget::new(2 * PAGE_SIZE as usize, FrameClassification::all());
        tracker.set_budget(1, budget);

        // Within budget.
        assert!(tracker
            .check_budget(1, PAGE_SIZE as usize, FrameClassification::empty())
            .is_ok());

        // At limit.
        assert!(tracker
            .check_budget(1, 2 * PAGE_SIZE as usize, FrameClassification::empty())
            .is_ok());

        // Over budget.
        let err = tracker
            .check_budget(1, 3 * PAGE_SIZE as usize, FrameClassification::empty())
            .unwrap_err();
        assert!(
            matches!(err, VmError::BudgetExceeded { .. }),
            "expected BudgetExceeded, got {:?}",
            err
        );
    }

    #[test]
    fn budget_tracks_usage() {
        let mut tracker = CapTracker::new();
        tracker.set_budget(
            1,
            MemoryBudget::new(10 * PAGE_SIZE as usize, FrameClassification::all()),
        );

        assert_eq!(tracker.budget(1).unwrap().used, 0);

        tracker.record_mapping(paddr(0), 1, FrameClassification::empty());
        assert_eq!(tracker.budget(1).unwrap().used, PAGE_SIZE as usize);

        tracker.record_mapping(paddr(1), 1, FrameClassification::empty());
        assert_eq!(tracker.budget(1).unwrap().used, 2 * PAGE_SIZE as usize);

        tracker.remove_mapping(paddr(0), 1);
        assert_eq!(tracker.budget(1).unwrap().used, PAGE_SIZE as usize);
    }

    #[test]
    fn classification_denied() {
        let mut tracker = CapTracker::new();
        // Process with empty allowed_classes — no special frames permitted.
        tracker.set_budget(
            1,
            MemoryBudget::new(10 * PAGE_SIZE as usize, FrameClassification::empty()),
        );

        // Public frame: fine.
        assert!(tracker
            .check_budget(1, PAGE_SIZE as usize, FrameClassification::empty())
            .is_ok());

        // Encrypted frame: denied.
        let err = tracker
            .check_budget(1, PAGE_SIZE as usize, FrameClassification::ENCRYPTED)
            .unwrap_err();
        assert!(
            matches!(err, VmError::ClassificationDenied(_)),
            "expected ClassificationDenied, got {:?}",
            err
        );
    }

    #[test]
    fn encrypted_frames_tracked() {
        let mut tracker = CapTracker::new();
        tracker.set_budget(
            1,
            MemoryBudget::new(10 * PAGE_SIZE as usize, FrameClassification::all()),
        );

        // Public frame — no B-tree entry.
        tracker.record_mapping(paddr(0), 1, FrameClassification::empty());
        assert_eq!(tracker.tracked_frame_count(), 0);

        // Encrypted frame — B-tree entry created.
        tracker.record_mapping(paddr(1), 1, FrameClassification::ENCRYPTED);
        assert_eq!(tracker.tracked_frame_count(), 1);
        assert_eq!(
            tracker.frame_classification(paddr(1)),
            FrameClassification::ENCRYPTED,
        );
    }

    #[test]
    fn remove_mapping_returns_classification() {
        let mut tracker = CapTracker::new();
        tracker.set_budget(
            1,
            MemoryBudget::new(10 * PAGE_SIZE as usize, FrameClassification::all()),
        );

        tracker.record_mapping(paddr(5), 1, FrameClassification::ENCRYPTED);
        assert_eq!(tracker.tracked_frame_count(), 1);

        let class = tracker.remove_mapping(paddr(5), 1);
        assert_eq!(class, FrameClassification::ENCRYPTED);
        assert_eq!(tracker.tracked_frame_count(), 0);
    }

    #[test]
    fn shared_mapping_tracking() {
        let mut tracker = CapTracker::new();
        tracker.set_budget(
            1,
            MemoryBudget::new(10 * PAGE_SIZE as usize, FrameClassification::all()),
        );
        tracker.set_budget(
            2,
            MemoryBudget::new(10 * PAGE_SIZE as usize, FrameClassification::all()),
        );

        // Two PIDs map the same encrypted frame.
        tracker.record_mapping(paddr(10), 1, FrameClassification::ENCRYPTED);
        tracker.record_mapping(paddr(10), 2, FrameClassification::ENCRYPTED);
        assert_eq!(tracker.tracked_frame_count(), 1);

        // Remove PID 1 — frame still tracked (PID 2 holds it).
        let class = tracker.remove_mapping(paddr(10), 1);
        assert_eq!(class, FrameClassification::ENCRYPTED);
        assert_eq!(tracker.tracked_frame_count(), 1);

        // Remove PID 2 — frame fully unmapped, B-tree entry removed.
        let class = tracker.remove_mapping(paddr(10), 2);
        assert_eq!(class, FrameClassification::ENCRYPTED);
        assert_eq!(tracker.tracked_frame_count(), 0);
    }

    #[test]
    fn no_such_process() {
        let tracker = CapTracker::new();
        let err = tracker
            .check_budget(99, PAGE_SIZE as usize, FrameClassification::empty())
            .unwrap_err();
        assert_eq!(err, VmError::NoSuchProcess(99));
    }

    #[test]
    fn remove_budget_on_destroy() {
        let mut tracker = CapTracker::new();
        tracker.set_budget(
            1,
            MemoryBudget::new(PAGE_SIZE as usize, FrameClassification::empty()),
        );
        assert!(tracker.budget(1).is_some());

        tracker.remove_budget(1);
        assert!(tracker.budget(1).is_none());
    }

    #[test]
    fn frames_with_classification_query() {
        let mut tracker = CapTracker::new();
        tracker.set_budget(
            1,
            MemoryBudget::new(100 * PAGE_SIZE as usize, FrameClassification::all()),
        );

        // 4 frames with different classifications.
        tracker.record_mapping(paddr(0), 1, FrameClassification::ENCRYPTED);
        tracker.record_mapping(paddr(1), 1, FrameClassification::EPHEMERAL);
        tracker.record_mapping(
            paddr(2),
            1,
            FrameClassification::ENCRYPTED | FrameClassification::EPHEMERAL,
        );
        tracker.record_mapping(paddr(3), 1, FrameClassification::ENCRYPTED);

        // Query ENCRYPTED — should return frames 0, 2, 3 (all that contain ENCRYPTED).
        let encrypted = tracker.frames_with_classification(FrameClassification::ENCRYPTED);
        assert_eq!(encrypted.len(), 3, "expected 3 ENCRYPTED frames");

        // Query EPHEMERAL — should return frames 1 and 2.
        let ephemeral = tracker.frames_with_classification(FrameClassification::EPHEMERAL);
        assert_eq!(ephemeral.len(), 2, "expected 2 EPHEMERAL frames");
    }

    #[test]
    fn zone_budget_tracking() {
        let mut tracker = CapTracker::new();
        tracker.set_budget(
            1,
            MemoryBudget::new(10 * PAGE_SIZE as usize, FrameClassification::all()),
        );

        // Map some frames in different zones.
        tracker.record_mapping(paddr(0), 1, FrameClassification::empty()); // public durable
        tracker.record_mapping(paddr(1), 1, FrameClassification::EPHEMERAL); // public ephemeral
        tracker.record_mapping(paddr(2), 1, FrameClassification::ENCRYPTED); // kernel durable

        let budget = tracker.budget(1).unwrap();
        assert_eq!(budget.used, 3 * PAGE_SIZE as usize);
        assert_eq!(
            budget.zone_used(MemoryZone::PublicDurable),
            PAGE_SIZE as usize,
        );
        assert_eq!(
            budget.zone_used(MemoryZone::PublicEphemeral),
            PAGE_SIZE as usize,
        );
        assert_eq!(
            budget.zone_used(MemoryZone::KernelDurable),
            PAGE_SIZE as usize,
        );
        assert_eq!(budget.zone_used(MemoryZone::KernelEphemeral), 0);
    }

    #[test]
    fn zone_usage_decreases_on_unmap() {
        let mut tracker = CapTracker::new();
        tracker.set_budget(
            1,
            MemoryBudget::new(10 * PAGE_SIZE as usize, FrameClassification::all()),
        );

        tracker.record_mapping(paddr(0), 1, FrameClassification::ENCRYPTED);
        assert_eq!(
            tracker
                .budget(1)
                .unwrap()
                .zone_used(MemoryZone::KernelDurable),
            PAGE_SIZE as usize,
        );

        tracker.remove_mapping(paddr(0), 1);
        assert_eq!(
            tracker
                .budget(1)
                .unwrap()
                .zone_used(MemoryZone::KernelDurable),
            0,
        );
    }
}
