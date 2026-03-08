// SPDX-License-Identifier: GPL-2.0-or-later
//! Lyll — the probabilistic memory auditor.
//!
//! Lyll spot-checks public memory frames at a configurable sampling rate.
//! For durable (content-addressed) frames, she verifies against immutable CIDs.
//! For ephemeral (writable) frames, she verifies against write-barrier snapshots.
//! She also co-verifies Nakaiah's state before every private memory operation.

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::vm::{ContentHash, MemoryZone, PhysAddr, ViolationReason};

use super::quarantine::{QuarantineRecord, QuarantineRegistry};
use super::IntegrityVerdict;

/// How a frame's expected hash is determined.
#[derive(Debug, Clone)]
pub enum HashEntry {
    /// CID-derived — immutable, set at map time.
    CidBacked { cid: [u8; 32] },
    /// Snapshot — updated on every write via write barrier.
    Snapshot { hash: [u8; 32], generation: u64 },
}

impl HashEntry {
    pub fn expected_hash(&self) -> [u8; 32] {
        match self {
            Self::CidBacked { cid } => *cid,
            Self::Snapshot { hash, .. } => *hash,
        }
    }
}

/// Configuration for Lyll's sampling behavior.
#[derive(Debug, Clone)]
pub struct LyllConfig {
    /// Percentage of public frames to sample (1-100).
    pub sampling_rate_percent: u8,
    /// Timer ticks between periodic sweeps of ephemeral frames.
    pub sweep_interval_ticks: u64,
}

/// Internal metadata for a registered frame.
#[derive(Debug, Clone)]
struct FrameRecord {
    entry: HashEntry,
    owner_pid: u32,
}

/// Lyll — the probabilistic memory auditor.
pub struct Lyll {
    hash_registry: BTreeMap<PhysAddr, FrameRecord>,
    nakaiah_state_hash: ContentHash,
    sampled_frames: BTreeSet<PhysAddr>,
    pub(crate) quarantine: QuarantineRegistry,
    state_hash: ContentHash,
    config: LyllConfig,
    tick_counter: u64,
}

impl Lyll {
    pub fn new(config: LyllConfig) -> Self {
        Self {
            hash_registry: BTreeMap::new(),
            nakaiah_state_hash: ContentHash::ZERO,
            sampled_frames: BTreeSet::new(),
            quarantine: QuarantineRegistry::new(),
            state_hash: ContentHash::ZERO,
            config,
            tick_counter: 0,
        }
    }

    pub fn register_frame(&mut self, paddr: PhysAddr, entry: HashEntry, owner_pid: u32) {
        self.hash_registry
            .insert(paddr, FrameRecord { entry, owner_pid });
    }

    pub fn unregister_frame(&mut self, paddr: PhysAddr) {
        self.hash_registry.remove(&paddr);
        self.sampled_frames.remove(&paddr);
    }

    /// Update a snapshot entry's hash. CID-backed entries are immutable and silently ignored.
    pub fn update_snapshot(&mut self, paddr: PhysAddr, new_hash: [u8; 32]) {
        if let Some(record) = self.hash_registry.get_mut(&paddr) {
            if let HashEntry::Snapshot {
                ref mut hash,
                ref mut generation,
            } = record.entry
            {
                *hash = new_hash;
                *generation += 1;
            }
        }
    }

    pub fn expected_hash(&self, paddr: PhysAddr) -> Option<[u8; 32]> {
        self.hash_registry
            .get(&paddr)
            .map(|r| r.entry.expected_hash())
    }

    pub fn registry_len(&self) -> usize {
        self.hash_registry.len()
    }

    pub fn sampled_count(&self) -> usize {
        self.sampled_frames.len()
    }

    pub fn sampled_frames(&self) -> &BTreeSet<PhysAddr> {
        &self.sampled_frames
    }

    pub fn state_hash(&self) -> ContentHash {
        self.state_hash
    }

    pub fn set_state_hash(&mut self, hash: ContentHash) {
        self.state_hash = hash;
    }

    pub fn set_nakaiah_state_hash(&mut self, hash: ContentHash) {
        self.nakaiah_state_hash = hash;
    }

    pub fn nakaiah_state_hash(&self) -> ContentHash {
        self.nakaiah_state_hash
    }

    /// Verify a frame's content integrity during a spot-check.
    pub fn verify_frame(
        &mut self,
        paddr: PhysAddr,
        actual_hash: [u8; 32],
        timestamp: u64,
    ) -> IntegrityVerdict {
        let Some(record) = self.hash_registry.get(&paddr) else {
            return IntegrityVerdict::Allow;
        };

        let expected = record.entry.expected_hash();
        if actual_hash == expected {
            return IntegrityVerdict::Allow;
        }

        let zone = match record.entry {
            HashEntry::CidBacked { .. } => MemoryZone::PublicDurable,
            HashEntry::Snapshot { .. } => MemoryZone::PublicEphemeral,
        };

        self.quarantine.add(QuarantineRecord {
            paddr,
            expected_hash: expected,
            actual_hash,
            owner_pid: record.owner_pid,
            mapped_pids: Vec::new(),
            timestamp,
            zone,
        });

        IntegrityVerdict::Quarantine {
            paddr,
            reason: ViolationReason::ContentTampered,
        }
    }

    /// Co-verify Nakaiah's state before a private memory operation.
    pub fn co_verify_nakaiah(&self, nakaiah_current_hash: ContentHash) -> IntegrityVerdict {
        if nakaiah_current_hash == self.nakaiah_state_hash {
            IntegrityVerdict::Allow
        } else {
            IntegrityVerdict::Panic {
                reason: ViolationReason::GuardianStateCorrupted,
            }
        }
    }

    pub fn add_sample(&mut self, paddr: PhysAddr) {
        self.sampled_frames.insert(paddr);
    }

    pub fn remove_sample(&mut self, paddr: PhysAddr) {
        self.sampled_frames.remove(&paddr);
    }

    pub fn config(&self) -> &LyllConfig {
        &self.config
    }

    /// Increment tick counter and return whether a sweep is due.
    pub fn tick(&mut self) -> bool {
        self.tick_counter += 1;
        self.tick_counter % self.config.sweep_interval_ticks == 0
    }

    pub fn all_registered_frames(&self) -> Vec<PhysAddr> {
        self.hash_registry.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{ContentHash, MemoryZone, PhysAddr};

    fn test_config() -> LyllConfig {
        LyllConfig {
            sampling_rate_percent: 5,
            sweep_interval_ticks: 10,
        }
    }

    // Task 4 tests: core lifecycle
    #[test]
    fn new_lyll_is_empty() {
        let lyll = Lyll::new(test_config());
        assert_eq!(lyll.registry_len(), 0);
        assert_eq!(lyll.sampled_count(), 0);
    }

    #[test]
    fn register_cid_backed_frame() {
        let mut lyll = Lyll::new(test_config());
        let hash = ContentHash([0xAA; 32]);
        lyll.register_frame(PhysAddr(0x1000), HashEntry::CidBacked { cid: hash.0 }, 1);
        assert_eq!(lyll.registry_len(), 1);
        assert_eq!(lyll.expected_hash(PhysAddr(0x1000)), Some(hash.0));
    }

    #[test]
    fn register_snapshot_frame() {
        let mut lyll = Lyll::new(test_config());
        lyll.register_frame(
            PhysAddr(0x2000),
            HashEntry::Snapshot {
                hash: [0xBB; 32],
                generation: 0,
            },
            1,
        );
        assert_eq!(lyll.registry_len(), 1);
        assert_eq!(lyll.expected_hash(PhysAddr(0x2000)), Some([0xBB; 32]));
    }

    #[test]
    fn update_snapshot_increments_generation() {
        let mut lyll = Lyll::new(test_config());
        lyll.register_frame(
            PhysAddr(0x1000),
            HashEntry::Snapshot {
                hash: [0; 32],
                generation: 0,
            },
            1,
        );
        lyll.update_snapshot(PhysAddr(0x1000), [0xFF; 32]);
        assert_eq!(lyll.expected_hash(PhysAddr(0x1000)), Some([0xFF; 32]));
    }

    #[test]
    fn update_cid_backed_is_noop() {
        let mut lyll = Lyll::new(test_config());
        lyll.register_frame(
            PhysAddr(0x1000),
            HashEntry::CidBacked { cid: [0xAA; 32] },
            1,
        );
        lyll.update_snapshot(PhysAddr(0x1000), [0xFF; 32]);
        assert_eq!(lyll.expected_hash(PhysAddr(0x1000)), Some([0xAA; 32]));
    }

    #[test]
    fn unregister_frame_removes_entry() {
        let mut lyll = Lyll::new(test_config());
        lyll.register_frame(PhysAddr(0x1000), HashEntry::CidBacked { cid: [0; 32] }, 1);
        assert_eq!(lyll.registry_len(), 1);
        lyll.unregister_frame(PhysAddr(0x1000));
        assert_eq!(lyll.registry_len(), 0);
        assert_eq!(lyll.expected_hash(PhysAddr(0x1000)), None);
    }

    // Task 5 tests: spot-check, co-verification, sweep
    #[test]
    fn verify_frame_matching_hash_allows() {
        let mut lyll = Lyll::new(test_config());
        let hash = [0xAA; 32];
        lyll.register_frame(PhysAddr(0x1000), HashEntry::CidBacked { cid: hash }, 1);
        let verdict = lyll.verify_frame(PhysAddr(0x1000), hash, 0);
        assert_eq!(verdict, IntegrityVerdict::Allow);
    }

    #[test]
    fn verify_frame_mismatched_hash_quarantines() {
        let mut lyll = Lyll::new(test_config());
        lyll.register_frame(
            PhysAddr(0x1000),
            HashEntry::CidBacked { cid: [0xAA; 32] },
            1,
        );
        let verdict = lyll.verify_frame(PhysAddr(0x1000), [0xBB; 32], 42);
        assert!(matches!(
            verdict,
            IntegrityVerdict::Quarantine {
                reason: ViolationReason::ContentTampered,
                ..
            }
        ));
        assert!(lyll.quarantine.is_quarantined(PhysAddr(0x1000)));
        assert_eq!(lyll.quarantine.records()[0].timestamp, 42);
    }

    #[test]
    fn quarantine_zone_matches_entry_type() {
        let mut lyll = Lyll::new(test_config());
        // Snapshot entry → PublicEphemeral zone in quarantine.
        lyll.register_frame(
            PhysAddr(0x1000),
            HashEntry::Snapshot {
                hash: [0xAA; 32],
                generation: 0,
            },
            1,
        );
        lyll.verify_frame(PhysAddr(0x1000), [0xBB; 32], 0);
        assert_eq!(
            lyll.quarantine.records()[0].zone,
            MemoryZone::PublicEphemeral
        );

        // CidBacked entry → PublicDurable zone in quarantine.
        lyll.register_frame(
            PhysAddr(0x2000),
            HashEntry::CidBacked { cid: [0xCC; 32] },
            2,
        );
        lyll.verify_frame(PhysAddr(0x2000), [0xDD; 32], 0);
        assert_eq!(lyll.quarantine.records()[1].zone, MemoryZone::PublicDurable);
    }

    #[test]
    fn verify_unknown_frame_allows() {
        let mut lyll = Lyll::new(test_config());
        let verdict = lyll.verify_frame(PhysAddr(0x9999), [0; 32], 0);
        assert_eq!(verdict, IntegrityVerdict::Allow);
    }

    #[test]
    fn co_verify_nakaiah_matching_allows() {
        let mut lyll = Lyll::new(test_config());
        let hash = ContentHash([0xCC; 32]);
        lyll.set_nakaiah_state_hash(hash);
        assert_eq!(lyll.co_verify_nakaiah(hash), IntegrityVerdict::Allow);
    }

    #[test]
    fn co_verify_nakaiah_mismatched_panics() {
        let mut lyll = Lyll::new(test_config());
        lyll.set_nakaiah_state_hash(ContentHash([0xCC; 32]));
        let verdict = lyll.co_verify_nakaiah(ContentHash([0xDD; 32]));
        assert!(matches!(
            verdict,
            IntegrityVerdict::Panic {
                reason: ViolationReason::GuardianStateCorrupted
            }
        ));
    }

    #[test]
    fn sampling_add_and_remove() {
        let mut lyll = Lyll::new(test_config());
        lyll.add_sample(PhysAddr(0x1000));
        lyll.add_sample(PhysAddr(0x2000));
        assert_eq!(lyll.sampled_count(), 2);
        assert!(lyll.sampled_frames().contains(&PhysAddr(0x1000)));
        lyll.remove_sample(PhysAddr(0x1000));
        assert_eq!(lyll.sampled_count(), 1);
        assert!(!lyll.sampled_frames().contains(&PhysAddr(0x1000)));
    }

    #[test]
    fn tick_triggers_sweep_at_interval() {
        let mut lyll = Lyll::new(LyllConfig {
            sampling_rate_percent: 5,
            sweep_interval_ticks: 3,
        });
        assert!(!lyll.tick()); // tick 1
        assert!(!lyll.tick()); // tick 2
        assert!(lyll.tick()); // tick 3 — sweep due
        assert!(!lyll.tick()); // tick 4
        assert!(!lyll.tick()); // tick 5
        assert!(lyll.tick()); // tick 6 — sweep due again
    }

    #[test]
    fn unregister_also_removes_from_samples() {
        let mut lyll = Lyll::new(test_config());
        lyll.register_frame(PhysAddr(0x1000), HashEntry::CidBacked { cid: [0; 32] }, 1);
        lyll.add_sample(PhysAddr(0x1000));
        assert_eq!(lyll.sampled_count(), 1);
        lyll.unregister_frame(PhysAddr(0x1000));
        assert_eq!(lyll.sampled_count(), 0);
        assert_eq!(lyll.registry_len(), 0);
    }

    #[test]
    fn config_accessible() {
        let lyll = Lyll::new(test_config());
        assert_eq!(lyll.config().sampling_rate_percent, 5);
        assert_eq!(lyll.config().sweep_interval_ticks, 10);
    }

    #[test]
    fn all_registered_frames_returns_all_addrs() {
        let mut lyll = Lyll::new(test_config());
        lyll.register_frame(PhysAddr(0x1000), HashEntry::CidBacked { cid: [0; 32] }, 1);
        lyll.register_frame(PhysAddr(0x2000), HashEntry::CidBacked { cid: [1; 32] }, 2);
        let all = lyll.all_registered_frames();
        assert_eq!(all.len(), 2);
        assert!(all.contains(&PhysAddr(0x1000)));
        assert!(all.contains(&PhysAddr(0x2000)));
    }
}
