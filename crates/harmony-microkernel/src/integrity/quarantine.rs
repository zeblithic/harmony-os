// SPDX-License-Identifier: GPL-2.0-or-later
//! Quarantine registry — holds frames with suspected integrity violations.
//!
//! Quarantined frames are unmapped from all processes but NOT freed. A
//! privileged admin process can inspect records for forensic investigation.

use alloc::vec::Vec;

use crate::vm::{MemoryZone, PhysAddr};

/// A record of a quarantined frame.
#[derive(Debug, Clone)]
pub struct QuarantineRecord {
    pub paddr: PhysAddr,
    pub expected_hash: [u8; 32],
    pub actual_hash: [u8; 32],
    pub owner_pid: u32,
    pub mapped_pids: Vec<u32>,
    pub timestamp: u64,
    pub zone: MemoryZone,
}

/// Registry of quarantined frames pending investigation.
#[derive(Debug, Default)]
pub struct QuarantineRegistry {
    records: Vec<QuarantineRecord>,
}

impl QuarantineRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, record: QuarantineRecord) {
        self.records.push(record);
    }

    pub fn release(&mut self, paddr: PhysAddr) -> Option<QuarantineRecord> {
        let pos = self.records.iter().position(|r| r.paddr == paddr)?;
        Some(self.records.swap_remove(pos))
    }

    pub fn is_quarantined(&self, paddr: PhysAddr) -> bool {
        self.records.iter().any(|r| r.paddr == paddr)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn records(&self) -> &[QuarantineRecord] {
        &self.records
    }

    /// Enrich a quarantine record with the list of processes that had the
    /// frame mapped. Called by the Kernel layer which has access to the
    /// CapTracker (Lyll itself doesn't know about process mappings).
    pub fn set_mapped_pids(&mut self, paddr: PhysAddr, pids: Vec<u32>) {
        if let Some(record) = self.records.iter_mut().find(|r| r.paddr == paddr) {
            record.mapped_pids = pids;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{MemoryZone, PhysAddr};

    #[test]
    fn quarantine_empty_initially() {
        let q = QuarantineRegistry::new();
        assert_eq!(q.len(), 0);
        assert!(q.records().is_empty());
    }

    #[test]
    fn quarantine_add_and_lookup() {
        let mut q = QuarantineRegistry::new();
        q.add(QuarantineRecord {
            paddr: PhysAddr(0x1000),
            expected_hash: [0xAA; 32],
            actual_hash: [0xBB; 32],
            owner_pid: 1,
            mapped_pids: vec![1, 2],
            timestamp: 100,
            zone: MemoryZone::PublicDurable,
        });
        assert_eq!(q.len(), 1);
        assert!(q.is_quarantined(PhysAddr(0x1000)));
        assert!(!q.is_quarantined(PhysAddr(0x2000)));
    }

    #[test]
    fn quarantine_release_removes_record() {
        let mut q = QuarantineRegistry::new();
        q.add(QuarantineRecord {
            paddr: PhysAddr(0x1000),
            expected_hash: [0; 32],
            actual_hash: [1; 32],
            owner_pid: 1,
            mapped_pids: vec![1],
            timestamp: 0,
            zone: MemoryZone::PublicEphemeral,
        });
        assert_eq!(q.len(), 1);

        let released = q.release(PhysAddr(0x1000));
        assert!(released.is_some());
        assert_eq!(q.len(), 0);
        assert!(!q.is_quarantined(PhysAddr(0x1000)));
    }

    #[test]
    fn quarantine_release_nonexistent_returns_none() {
        let mut q = QuarantineRegistry::new();
        assert!(q.release(PhysAddr(0x9000)).is_none());
    }

    #[test]
    fn set_mapped_pids_enriches_record() {
        let mut q = QuarantineRegistry::new();
        q.add(QuarantineRecord {
            paddr: PhysAddr(0x1000),
            expected_hash: [0xAA; 32],
            actual_hash: [0xBB; 32],
            owner_pid: 1,
            mapped_pids: Vec::new(),
            timestamp: 0,
            zone: MemoryZone::PublicDurable,
        });
        assert!(q.records()[0].mapped_pids.is_empty());

        q.set_mapped_pids(PhysAddr(0x1000), vec![1, 3, 7]);
        assert_eq!(q.records()[0].mapped_pids, vec![1, 3, 7]);
    }
}
