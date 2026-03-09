// SPDX-License-Identifier: GPL-2.0-or-later
//! Nakaiah — the deterministic memory bodyguard.
//!
//! Nakaiah verifies every single access to encrypted (kernel-space) memory:
//! content integrity (hash check) and authorization (capability chain).
//! She maintains a hash-chained access log for accountability and
//! randomly checks in on Lyll to verify Lyll's behavior.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::vm::{AccessOp, ContentHash, PhysAddr, ViolationReason};

use super::IntegrityVerdict;

/// A capability chain authorizing access to a private frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapChain {
    /// Frame owner — full access (read, write, execute).
    Owner,
    /// Read-only delegation from another process.
    ReadOnly { granted_by: u32 },
    /// Read-write delegation from another process.
    ReadWrite { granted_by: u32 },
}

impl CapChain {
    pub fn permits(&self, op: AccessOp) -> bool {
        match self {
            Self::Owner => true,
            Self::ReadOnly { .. } => matches!(op, AccessOp::Read),
            Self::ReadWrite { .. } => matches!(op, AccessOp::Read | AccessOp::Write),
        }
    }
}

/// A single entry in Nakaiah's append-only access log.
#[derive(Debug, Clone)]
pub struct AccessLogEntry {
    pub receipt: AccessReceipt,
    pub prev_hash: [u8; 32],
}

/// Receipt of a single access to a private frame.
#[derive(Debug, Clone)]
pub struct AccessReceipt {
    pub pid: u32,
    pub paddr: PhysAddr,
    pub operation: AccessOp,
    pub timestamp: u64,
}

/// Nakaiah — the deterministic memory bodyguard.
pub struct Nakaiah {
    integrity_registry: BTreeMap<PhysAddr, [u8; 32]>,
    capability_chains: BTreeMap<(u32, PhysAddr), CapChain>,
    access_log: Vec<AccessLogEntry>,
    state_hash: ContentHash,
    lyll_state_hash: ContentHash,
    /// Check-in rate in basis points (100 = 1%, 10000 = 100%).
    lyll_checkin_rate_bps: u32,
}

impl Nakaiah {
    /// Create a new Nakaiah. `lyll_checkin_rate_bps` is in basis points
    /// (100 = 1% of operations trigger a Lyll check-in).
    pub fn new(lyll_checkin_rate_bps: u32) -> Self {
        Self {
            integrity_registry: BTreeMap::new(),
            capability_chains: BTreeMap::new(),
            access_log: Vec::new(),
            state_hash: ContentHash::ZERO,
            lyll_state_hash: ContentHash::ZERO,
            lyll_checkin_rate_bps,
        }
    }

    pub fn register_frame(&mut self, paddr: PhysAddr, content_hash: [u8; 32]) {
        self.integrity_registry.insert(paddr, content_hash);
        self.recompute_state_hash();
    }

    pub fn unregister_frame(&mut self, paddr: PhysAddr) {
        self.integrity_registry.remove(&paddr);
        self.capability_chains.retain(|&(_, p), _| p != paddr);
        self.recompute_state_hash();
    }

    pub fn update_hash(&mut self, paddr: PhysAddr, new_hash: [u8; 32]) {
        if let Some(stored) = self.integrity_registry.get_mut(&paddr) {
            *stored = new_hash;
        }
    }

    pub fn expected_hash(&self, paddr: PhysAddr) -> Option<[u8; 32]> {
        self.integrity_registry.get(&paddr).copied()
    }

    pub fn integrity_registry_len(&self) -> usize {
        self.integrity_registry.len()
    }

    pub fn grant_access(&mut self, pid: u32, paddr: PhysAddr, chain: CapChain) {
        self.capability_chains.insert((pid, paddr), chain);
        self.recompute_state_hash();
    }

    pub fn revoke_access(&mut self, pid: u32, paddr: PhysAddr) {
        self.capability_chains.remove(&(pid, paddr));
        self.recompute_state_hash();
    }

    /// Recompute `state_hash` from the registry and capability chain contents.
    ///
    /// Uses a simple fold over the sorted registries (BTreeMap guarantees
    /// deterministic iteration order). This is a placeholder — will be
    /// replaced with BLAKE3 once the crypto integration is wired up.
    fn recompute_state_hash(&mut self) {
        let mut hash = [0u8; 32];
        // Fold in integrity registry entries.
        for (&paddr, content_hash) in &self.integrity_registry {
            let addr_bytes = paddr.as_u64().to_le_bytes();
            for (i, &b) in addr_bytes.iter().enumerate() {
                hash[i] ^= b;
            }
            for (i, &b) in content_hash.iter().enumerate() {
                hash[i] ^= b;
            }
        }
        // Fold in capability chain keys for structural completeness.
        for &(pid, paddr) in self.capability_chains.keys() {
            let pid_bytes = pid.to_le_bytes();
            let addr_bytes = paddr.as_u64().to_le_bytes();
            for (i, &b) in pid_bytes.iter().enumerate() {
                hash[12 + i] ^= b;
            }
            for (i, &b) in addr_bytes.iter().enumerate() {
                hash[16 + i] ^= b;
            }
        }
        self.state_hash = ContentHash(hash);
    }

    pub fn has_access(&self, pid: u32, paddr: PhysAddr, op: AccessOp) -> bool {
        self.capability_chains
            .get(&(pid, paddr))
            .is_some_and(|chain| chain.permits(op))
    }

    /// Verify a frame access: content integrity + authorization.
    pub fn verify_access(
        &self,
        pid: u32,
        paddr: PhysAddr,
        op: AccessOp,
        actual_hash: [u8; 32],
    ) -> IntegrityVerdict {
        if let Some(&expected) = self.integrity_registry.get(&paddr) {
            if actual_hash != expected {
                return IntegrityVerdict::Kill {
                    pid,
                    reason: ViolationReason::ContentTampered,
                };
            }
        }

        if !self.has_access(pid, paddr, op) {
            return IntegrityVerdict::Kill {
                pid,
                reason: ViolationReason::UnauthorizedAccess,
            };
        }

        IntegrityVerdict::Allow
    }

    pub fn append_receipt(&mut self, receipt: AccessReceipt) {
        let prev_hash = self
            .access_log
            .last()
            .map(simple_hash_entry)
            .unwrap_or([0u8; 32]);

        self.access_log.push(AccessLogEntry { receipt, prev_hash });
    }

    pub fn access_log_len(&self) -> usize {
        self.access_log.len()
    }

    pub fn access_log(&self) -> &[AccessLogEntry] {
        &self.access_log
    }

    pub fn state_hash(&self) -> ContentHash {
        self.state_hash
    }

    pub fn set_state_hash(&mut self, hash: ContentHash) {
        self.state_hash = hash;
    }

    pub fn set_lyll_state_hash(&mut self, hash: ContentHash) {
        self.lyll_state_hash = hash;
    }

    pub fn lyll_state_hash(&self) -> ContentHash {
        self.lyll_state_hash
    }

    pub fn check_in_on_lyll(&self, lyll_current_hash: ContentHash) -> IntegrityVerdict {
        if lyll_current_hash == self.lyll_state_hash {
            IntegrityVerdict::Allow
        } else {
            IntegrityVerdict::Panic {
                reason: ViolationReason::GuardianStateCorrupted,
            }
        }
    }

    pub fn lyll_checkin_rate_bps(&self) -> u32 {
        self.lyll_checkin_rate_bps
    }
}

/// Simple deterministic hash of a log entry for chaining.
///
/// NOTE: This is a placeholder XOR-based hash, NOT collision-resistant.
/// Will be replaced with BLAKE3 once the crypto integration is wired up.
fn simple_hash_entry(entry: &AccessLogEntry) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let pid_bytes = entry.receipt.pid.to_le_bytes();
    let addr_bytes = entry.receipt.paddr.as_u64().to_le_bytes();
    let ts_bytes = entry.receipt.timestamp.to_le_bytes();
    let op_byte = entry.receipt.operation as u8;

    for (i, &b) in pid_bytes.iter().enumerate() {
        hash[i] ^= b;
    }
    for (i, &b) in addr_bytes.iter().enumerate() {
        hash[4 + i] ^= b;
    }
    for (i, &b) in ts_bytes.iter().enumerate() {
        hash[12 + i] ^= b;
    }
    hash[20] ^= op_byte;
    for (i, &b) in entry.prev_hash.iter().enumerate() {
        hash[i] ^= b;
    }

    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{AccessOp, ContentHash, PhysAddr};

    fn test_nakaiah() -> Nakaiah {
        Nakaiah::new(100)
    }

    // Task 6 tests: core lifecycle
    #[test]
    fn new_nakaiah_is_empty() {
        let n = test_nakaiah();
        assert_eq!(n.integrity_registry_len(), 0);
        assert_eq!(n.access_log_len(), 0);
    }

    #[test]
    fn register_and_lookup_frame() {
        let mut n = test_nakaiah();
        n.register_frame(PhysAddr(0x1000), [0xAA; 32]);
        assert_eq!(n.integrity_registry_len(), 1);
        assert_eq!(n.expected_hash(PhysAddr(0x1000)), Some([0xAA; 32]));
    }

    #[test]
    fn unregister_frame_removes() {
        let mut n = test_nakaiah();
        n.register_frame(PhysAddr(0x1000), [0xAA; 32]);
        n.unregister_frame(PhysAddr(0x1000));
        assert_eq!(n.integrity_registry_len(), 0);
    }

    #[test]
    fn grant_and_check_capability() {
        let mut n = test_nakaiah();
        n.register_frame(PhysAddr(0x1000), [0; 32]);
        n.grant_access(1, PhysAddr(0x1000), CapChain::Owner);
        assert!(n.has_access(1, PhysAddr(0x1000), AccessOp::Read));
        assert!(n.has_access(1, PhysAddr(0x1000), AccessOp::Write));
    }

    #[test]
    fn no_capability_denies_access() {
        let n = test_nakaiah();
        assert!(!n.has_access(1, PhysAddr(0x1000), AccessOp::Read));
    }

    #[test]
    fn read_only_capability_denies_write() {
        let mut n = test_nakaiah();
        n.register_frame(PhysAddr(0x1000), [0; 32]);
        n.grant_access(1, PhysAddr(0x1000), CapChain::ReadOnly { granted_by: 0 });
        assert!(n.has_access(1, PhysAddr(0x1000), AccessOp::Read));
        assert!(!n.has_access(1, PhysAddr(0x1000), AccessOp::Write));
        assert!(!n.has_access(1, PhysAddr(0x1000), AccessOp::Execute));
    }

    #[test]
    fn revoke_access_removes_capability() {
        let mut n = test_nakaiah();
        n.register_frame(PhysAddr(0x1000), [0; 32]);
        n.grant_access(1, PhysAddr(0x1000), CapChain::Owner);
        assert!(n.has_access(1, PhysAddr(0x1000), AccessOp::Read));
        n.revoke_access(1, PhysAddr(0x1000));
        assert!(!n.has_access(1, PhysAddr(0x1000), AccessOp::Read));
    }

    #[test]
    fn access_log_appends_and_chains() {
        let mut n = test_nakaiah();
        n.append_receipt(AccessReceipt {
            pid: 1,
            paddr: PhysAddr(0x1000),
            operation: AccessOp::Read,
            timestamp: 100,
        });
        assert_eq!(n.access_log_len(), 1);
        n.append_receipt(AccessReceipt {
            pid: 2,
            paddr: PhysAddr(0x2000),
            operation: AccessOp::Write,
            timestamp: 200,
        });
        assert_eq!(n.access_log_len(), 2);
        let log = n.access_log();
        assert_eq!(log[0].prev_hash, [0u8; 32]);
        assert_ne!(log[1].prev_hash, [0u8; 32]);
    }

    #[test]
    fn state_hash_roundtrip() {
        let mut n = test_nakaiah();
        let hash = ContentHash([0xFF; 32]);
        n.set_state_hash(hash);
        assert_eq!(n.state_hash(), hash);
    }

    // Task 7 tests: verification and check-in
    #[test]
    fn verify_access_valid_allows() {
        let mut n = test_nakaiah();
        let hash = [0xAA; 32];
        n.register_frame(PhysAddr(0x1000), hash);
        n.grant_access(1, PhysAddr(0x1000), CapChain::Owner);
        let verdict = n.verify_access(1, PhysAddr(0x1000), AccessOp::Read, hash);
        assert_eq!(verdict, IntegrityVerdict::Allow);
    }

    #[test]
    fn verify_access_tampered_content_kills() {
        let mut n = test_nakaiah();
        n.register_frame(PhysAddr(0x1000), [0xAA; 32]);
        n.grant_access(1, PhysAddr(0x1000), CapChain::Owner);
        let verdict = n.verify_access(1, PhysAddr(0x1000), AccessOp::Read, [0xBB; 32]);
        assert!(matches!(
            verdict,
            IntegrityVerdict::Kill {
                pid: 1,
                reason: ViolationReason::ContentTampered
            }
        ));
    }

    #[test]
    fn verify_access_unauthorized_kills() {
        let mut n = test_nakaiah();
        n.register_frame(PhysAddr(0x1000), [0xAA; 32]);
        let verdict = n.verify_access(1, PhysAddr(0x1000), AccessOp::Read, [0xAA; 32]);
        assert!(matches!(
            verdict,
            IntegrityVerdict::Kill {
                pid: 1,
                reason: ViolationReason::UnauthorizedAccess
            }
        ));
    }

    #[test]
    fn verify_access_read_only_write_kills() {
        let mut n = test_nakaiah();
        let hash = [0xAA; 32];
        n.register_frame(PhysAddr(0x1000), hash);
        n.grant_access(1, PhysAddr(0x1000), CapChain::ReadOnly { granted_by: 0 });
        assert_eq!(
            n.verify_access(1, PhysAddr(0x1000), AccessOp::Read, hash),
            IntegrityVerdict::Allow
        );
        assert!(matches!(
            n.verify_access(1, PhysAddr(0x1000), AccessOp::Write, hash),
            IntegrityVerdict::Kill {
                reason: ViolationReason::UnauthorizedAccess,
                ..
            }
        ));
    }

    #[test]
    fn verify_access_read_write_cap() {
        let mut n = test_nakaiah();
        let hash = [0; 32];
        n.register_frame(PhysAddr(0x1000), hash);
        n.grant_access(1, PhysAddr(0x1000), CapChain::ReadWrite { granted_by: 0 });
        assert_eq!(
            n.verify_access(1, PhysAddr(0x1000), AccessOp::Read, hash),
            IntegrityVerdict::Allow
        );
        assert_eq!(
            n.verify_access(1, PhysAddr(0x1000), AccessOp::Write, hash),
            IntegrityVerdict::Allow
        );
        assert!(matches!(
            n.verify_access(1, PhysAddr(0x1000), AccessOp::Execute, hash),
            IntegrityVerdict::Kill { .. }
        ));
    }

    #[test]
    fn update_hash_changes_expected() {
        let mut n = test_nakaiah();
        n.register_frame(PhysAddr(0x1000), [0xAA; 32]);
        n.update_hash(PhysAddr(0x1000), [0xBB; 32]);
        assert_eq!(n.expected_hash(PhysAddr(0x1000)), Some([0xBB; 32]));
    }

    #[test]
    fn check_in_on_lyll_matching_allows() {
        let mut n = test_nakaiah();
        let hash = ContentHash([0xCC; 32]);
        n.set_lyll_state_hash(hash);
        assert_eq!(n.check_in_on_lyll(hash), IntegrityVerdict::Allow);
    }

    #[test]
    fn check_in_on_lyll_mismatched_panics() {
        let mut n = test_nakaiah();
        n.set_lyll_state_hash(ContentHash([0xCC; 32]));
        let verdict = n.check_in_on_lyll(ContentHash([0xDD; 32]));
        assert!(matches!(
            verdict,
            IntegrityVerdict::Panic {
                reason: ViolationReason::GuardianStateCorrupted
            }
        ));
    }

    #[test]
    fn unregister_frame_also_revokes_access() {
        let mut n = test_nakaiah();
        n.register_frame(PhysAddr(0x1000), [0; 32]);
        n.grant_access(1, PhysAddr(0x1000), CapChain::Owner);
        n.grant_access(2, PhysAddr(0x1000), CapChain::ReadOnly { granted_by: 1 });
        assert!(n.has_access(1, PhysAddr(0x1000), AccessOp::Read));
        assert!(n.has_access(2, PhysAddr(0x1000), AccessOp::Read));
        n.unregister_frame(PhysAddr(0x1000));
        assert!(!n.has_access(1, PhysAddr(0x1000), AccessOp::Read));
        assert!(!n.has_access(2, PhysAddr(0x1000), AccessOp::Read));
    }

    #[test]
    fn state_hash_changes_on_structural_mutations() {
        let mut n = test_nakaiah();
        assert_eq!(n.state_hash(), ContentHash::ZERO);

        // Register a frame — state hash must change.
        n.register_frame(PhysAddr(0x1000), [0xAA; 32]);
        let after_register = n.state_hash();
        assert_ne!(after_register, ContentHash::ZERO);

        // Grant access — hash changes again (capability chain added).
        n.grant_access(1, PhysAddr(0x1000), CapChain::Owner);
        let after_grant = n.state_hash();
        assert_ne!(after_grant, after_register);

        // Revoke access — hash changes back (capability chain removed).
        n.revoke_access(1, PhysAddr(0x1000));
        assert_eq!(n.state_hash(), after_register);

        // Unregister frame — back to zero.
        n.unregister_frame(PhysAddr(0x1000));
        assert_eq!(n.state_hash(), ContentHash::ZERO);
    }

    #[test]
    fn access_log_hash_chain_integrity() {
        let mut n = test_nakaiah();
        for i in 0..5 {
            n.append_receipt(AccessReceipt {
                pid: 1,
                paddr: PhysAddr(0x1000),
                operation: AccessOp::Read,
                timestamp: i * 100,
            });
        }
        assert_eq!(n.access_log_len(), 5);
        let log = n.access_log();
        assert_eq!(log[0].prev_hash, [0; 32]);
        for i in 1..5 {
            assert_ne!(log[i].prev_hash, [0; 32]);
        }
    }
}
