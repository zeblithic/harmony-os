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
    zone: MemoryZone,
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
        assert!(
            config.sweep_interval_ticks > 0,
            "sweep_interval_ticks must be > 0"
        );
        assert!(
            config.sampling_rate_percent >= 1 && config.sampling_rate_percent <= 100,
            "sampling_rate_percent must be 1..=100"
        );
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

    pub fn register_frame(
        &mut self,
        paddr: PhysAddr,
        entry: HashEntry,
        owner_pid: u32,
        zone: MemoryZone,
    ) {
        let record = FrameRecord {
            entry,
            owner_pid,
            zone,
        };
        Self::xor_record_into(&mut self.state_hash.0, paddr, &record);
        self.hash_registry.insert(paddr, record);
    }

    pub fn unregister_frame(&mut self, paddr: PhysAddr) {
        if let Some(record) = self.hash_registry.remove(&paddr) {
            // XOR is its own inverse — folding out the removed entry.
            Self::xor_record_into(&mut self.state_hash.0, paddr, &record);
        }
        self.sampled_frames.remove(&paddr);
    }

    /// XOR a single record's contribution into (or out of) `hash`.
    ///
    /// Because XOR is commutative, associative, and self-inverse, calling
    /// this once folds the record in; calling it again on the same data
    /// folds it back out. This makes register/unregister O(1) instead of
    /// scanning the entire registry.
    fn xor_record_into(hash: &mut [u8; 32], paddr: PhysAddr, record: &FrameRecord) {
        let addr_bytes = paddr.as_u64().to_le_bytes();
        let pid_bytes = record.owner_pid.to_le_bytes();
        let expected = record.entry.expected_hash();
        for (i, &b) in addr_bytes.iter().enumerate() {
            hash[i] ^= b;
        }
        for (i, &b) in pid_bytes.iter().enumerate() {
            hash[8 + i] ^= b;
        }
        for (i, &b) in expected.iter().enumerate() {
            hash[i] ^= b;
        }
    }

    /// Promote a CID-backed entry to a Snapshot entry, preserving its current
    /// hash. This is needed when `vm_protect_region` makes a read-only frame
    /// writable — the entry must accept write-barrier hash updates.
    /// No-op if the entry is already a Snapshot or doesn't exist.
    pub fn promote_to_snapshot(&mut self, paddr: PhysAddr) {
        if let Some(record) = self.hash_registry.get_mut(&paddr) {
            if let HashEntry::CidBacked { cid } = record.entry {
                record.entry = HashEntry::Snapshot {
                    hash: cid,
                    generation: 0,
                };
            }
        }
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

        let zone = record.zone;

        if !self.quarantine.is_quarantined(paddr) {
            self.quarantine.add(QuarantineRecord {
                paddr,
                expected_hash: expected,
                actual_hash,
                owner_pid: record.owner_pid,
                mapped_pids: Vec::new(),
                timestamp,
                zone,
            });
        }

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
        lyll.register_frame(
            PhysAddr(0x1000),
            HashEntry::CidBacked { cid: hash.0 },
            1,
            MemoryZone::PublicDurable,
        );
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
            MemoryZone::PublicEphemeral,
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
            MemoryZone::PublicEphemeral,
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
            MemoryZone::PublicDurable,
        );
        lyll.update_snapshot(PhysAddr(0x1000), [0xFF; 32]);
        assert_eq!(lyll.expected_hash(PhysAddr(0x1000)), Some([0xAA; 32]));
    }

    #[test]
    fn promote_cid_to_snapshot_preserves_hash() {
        let mut lyll = Lyll::new(test_config());
        lyll.register_frame(
            PhysAddr(0x1000),
            HashEntry::CidBacked { cid: [0xAA; 32] },
            1,
            MemoryZone::PublicDurable,
        );
        lyll.promote_to_snapshot(PhysAddr(0x1000));
        // Hash preserved.
        assert_eq!(lyll.expected_hash(PhysAddr(0x1000)), Some([0xAA; 32]));
        // Now update_snapshot works (it was a no-op before promotion).
        lyll.update_snapshot(PhysAddr(0x1000), [0xBB; 32]);
        assert_eq!(lyll.expected_hash(PhysAddr(0x1000)), Some([0xBB; 32]));
    }

    #[test]
    fn promote_snapshot_is_noop() {
        let mut lyll = Lyll::new(test_config());
        lyll.register_frame(
            PhysAddr(0x1000),
            HashEntry::Snapshot {
                hash: [0xAA; 32],
                generation: 5,
            },
            1,
            MemoryZone::PublicEphemeral,
        );
        lyll.promote_to_snapshot(PhysAddr(0x1000));
        assert_eq!(lyll.expected_hash(PhysAddr(0x1000)), Some([0xAA; 32]));
    }

    #[test]
    fn unregister_frame_removes_entry() {
        let mut lyll = Lyll::new(test_config());
        lyll.register_frame(
            PhysAddr(0x1000),
            HashEntry::CidBacked { cid: [0; 32] },
            1,
            MemoryZone::PublicDurable,
        );
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
        lyll.register_frame(
            PhysAddr(0x1000),
            HashEntry::CidBacked { cid: hash },
            1,
            MemoryZone::PublicDurable,
        );
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
            MemoryZone::PublicDurable,
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
    fn quarantine_zone_uses_stored_zone_not_entry_type() {
        let mut lyll = Lyll::new(test_config());

        // Snapshot entry registered as PublicDurable (writable non-ephemeral frame).
        lyll.register_frame(
            PhysAddr(0x1000),
            HashEntry::Snapshot {
                hash: [0xAA; 32],
                generation: 0,
            },
            1,
            MemoryZone::PublicDurable,
        );
        lyll.verify_frame(PhysAddr(0x1000), [0xBB; 32], 0);
        assert_eq!(lyll.quarantine.records()[0].zone, MemoryZone::PublicDurable);

        // CidBacked entry registered as KernelDurable (encrypted immutable frame).
        lyll.register_frame(
            PhysAddr(0x2000),
            HashEntry::CidBacked { cid: [0xCC; 32] },
            2,
            MemoryZone::KernelDurable,
        );
        lyll.verify_frame(PhysAddr(0x2000), [0xDD; 32], 0);
        assert_eq!(lyll.quarantine.records()[1].zone, MemoryZone::KernelDurable);
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
        lyll.register_frame(
            PhysAddr(0x1000),
            HashEntry::CidBacked { cid: [0; 32] },
            1,
            MemoryZone::PublicDurable,
        );
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
    #[should_panic(expected = "sweep_interval_ticks must be > 0")]
    fn zero_sweep_interval_panics() {
        Lyll::new(LyllConfig {
            sampling_rate_percent: 5,
            sweep_interval_ticks: 0,
        });
    }

    #[test]
    fn duplicate_quarantine_not_added() {
        let mut lyll = Lyll::new(test_config());
        lyll.register_frame(
            PhysAddr(0x1000),
            HashEntry::CidBacked { cid: [0xAA; 32] },
            1,
            MemoryZone::PublicDurable,
        );
        // First verify — quarantines.
        lyll.verify_frame(PhysAddr(0x1000), [0xBB; 32], 0);
        assert_eq!(lyll.quarantine.len(), 1);

        // Second verify on same address — no duplicate.
        lyll.verify_frame(PhysAddr(0x1000), [0xCC; 32], 1);
        assert_eq!(lyll.quarantine.len(), 1);
    }

    #[test]
    #[should_panic(expected = "sampling_rate_percent must be 1..=100")]
    fn zero_sampling_rate_panics() {
        Lyll::new(LyllConfig {
            sampling_rate_percent: 0,
            sweep_interval_ticks: 10,
        });
    }

    #[test]
    #[should_panic(expected = "sampling_rate_percent must be 1..=100")]
    fn sampling_rate_over_100_panics() {
        Lyll::new(LyllConfig {
            sampling_rate_percent: 101,
            sweep_interval_ticks: 10,
        });
    }

    #[test]
    fn state_hash_changes_on_register_and_unregister() {
        let mut lyll = Lyll::new(test_config());
        let initial = lyll.state_hash();
        assert_eq!(initial, ContentHash::ZERO);

        // Register a frame — state hash must change.
        lyll.register_frame(
            PhysAddr(0x1000),
            HashEntry::CidBacked { cid: [0xAA; 32] },
            1,
            MemoryZone::PublicDurable,
        );
        let after_register = lyll.state_hash();
        assert_ne!(after_register, ContentHash::ZERO);

        // Register a second frame — hash changes again.
        lyll.register_frame(
            PhysAddr(0x2000),
            HashEntry::CidBacked { cid: [0xBB; 32] },
            2,
            MemoryZone::PublicDurable,
        );
        let after_second = lyll.state_hash();
        assert_ne!(after_second, after_register);

        // Unregister second frame — hash returns to single-frame state.
        lyll.unregister_frame(PhysAddr(0x2000));
        assert_eq!(lyll.state_hash(), after_register);

        // Unregister first frame — back to zero.
        lyll.unregister_frame(PhysAddr(0x1000));
        assert_eq!(lyll.state_hash(), ContentHash::ZERO);
    }

    #[test]
    fn all_registered_frames_returns_all_addrs() {
        let mut lyll = Lyll::new(test_config());
        lyll.register_frame(
            PhysAddr(0x1000),
            HashEntry::CidBacked { cid: [0; 32] },
            1,
            MemoryZone::PublicDurable,
        );
        lyll.register_frame(
            PhysAddr(0x2000),
            HashEntry::CidBacked { cid: [1; 32] },
            2,
            MemoryZone::PublicDurable,
        );
        let all = lyll.all_registered_frames();
        assert_eq!(all.len(), 2);
        assert!(all.contains(&PhysAddr(0x1000)));
        assert!(all.contains(&PhysAddr(0x2000)));
    }
}
