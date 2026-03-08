// SPDX-License-Identifier: GPL-2.0-or-later
//! Memory integrity subsystem — Lyll (auditor) and Nakaiah (bodyguard).
//!
//! This module defines the event-driven communication protocol between the
//! Kernel and the integrity guardians. The Kernel emits [`IntegrityEvent`]s;
//! guardians return [`IntegrityVerdict`]s.

use crate::vm::{AccessOp, ContentHash, FrameClassification, PhysAddr, ViolationReason};

pub mod lyll;
pub mod nakaiah;
pub mod quarantine;

/// Events emitted by the Kernel to the integrity subsystem.
#[derive(Debug, Clone)]
pub enum IntegrityEvent {
    FrameMapped {
        pid: u32,
        paddr: PhysAddr,
        class: FrameClassification,
        content_hash: ContentHash,
    },
    FrameAccessing {
        pid: u32,
        paddr: PhysAddr,
        operation: AccessOp,
    },
    FrameUnmapped {
        paddr: PhysAddr,
        class: FrameClassification,
    },
    FrameWritten {
        paddr: PhysAddr,
        new_hash: ContentHash,
    },
    TimerTick,
}

/// Verdicts returned by the integrity subsystem to the Kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityVerdict {
    Allow,
    Quarantine {
        paddr: PhysAddr,
        reason: ViolationReason,
    },
    Kill {
        pid: u32,
        reason: ViolationReason,
    },
    Panic {
        reason: ViolationReason,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{ContentHash, FrameClassification, PhysAddr, ViolationReason};

    #[test]
    fn integrity_event_frame_mapped() {
        let event = IntegrityEvent::FrameMapped {
            pid: 1,
            paddr: PhysAddr(0x1000),
            class: FrameClassification::empty(),
            content_hash: ContentHash::ZERO,
        };
        assert!(matches!(event, IntegrityEvent::FrameMapped { pid: 1, .. }));
    }

    #[test]
    fn integrity_verdict_variants() {
        let allow = IntegrityVerdict::Allow;
        assert!(matches!(allow, IntegrityVerdict::Allow));

        let kill = IntegrityVerdict::Kill {
            pid: 42,
            reason: ViolationReason::ContentTampered,
        };
        assert!(matches!(kill, IntegrityVerdict::Kill { pid: 42, .. }));

        let quarantine = IntegrityVerdict::Quarantine {
            paddr: PhysAddr(0x2000),
            reason: ViolationReason::ContentTampered,
        };
        assert!(matches!(quarantine, IntegrityVerdict::Quarantine { .. }));

        let panic = IntegrityVerdict::Panic {
            reason: ViolationReason::GuardianStateCorrupted,
        };
        assert!(matches!(panic, IntegrityVerdict::Panic { .. }));
    }

    // ── Task 8: Bidirectional mutual verification integration tests ──

    use super::lyll::{HashEntry, Lyll, LyllConfig};
    use super::nakaiah::{AccessReceipt, CapChain, Nakaiah};

    fn test_lyll() -> Lyll {
        Lyll::new(LyllConfig {
            sampling_rate_percent: 5,
            sweep_interval_ticks: 10,
        })
    }

    fn test_nakaiah() -> Nakaiah {
        Nakaiah::new(100)
    }

    #[test]
    fn full_private_access_cycle() {
        let mut lyll = test_lyll();
        let mut nakaiah = test_nakaiah();

        let paddr = PhysAddr(0x1000);
        let hash = [0xAA; 32];
        lyll.register_frame(paddr, HashEntry::CidBacked { cid: hash }, 1);
        nakaiah.register_frame(paddr, hash);
        nakaiah.grant_access(1, paddr, CapChain::Owner);

        lyll.set_nakaiah_state_hash(nakaiah.state_hash());
        nakaiah.set_lyll_state_hash(lyll.state_hash());

        let verdict = lyll.co_verify_nakaiah(nakaiah.state_hash());
        assert_eq!(verdict, IntegrityVerdict::Allow);

        let verdict = nakaiah.verify_access(1, paddr, crate::vm::AccessOp::Read, hash);
        assert_eq!(verdict, IntegrityVerdict::Allow);
    }

    #[test]
    fn compromised_nakaiah_detected_by_lyll() {
        let mut lyll = test_lyll();
        let mut nakaiah = test_nakaiah();

        lyll.set_nakaiah_state_hash(nakaiah.state_hash());

        nakaiah.set_state_hash(ContentHash([0xFF; 32]));

        let verdict = lyll.co_verify_nakaiah(nakaiah.state_hash());
        assert!(matches!(
            verdict,
            IntegrityVerdict::Panic {
                reason: ViolationReason::GuardianStateCorrupted
            }
        ));
    }

    #[test]
    fn compromised_lyll_detected_by_nakaiah() {
        let mut lyll = test_lyll();
        let mut nakaiah = test_nakaiah();

        nakaiah.set_lyll_state_hash(lyll.state_hash());

        lyll.set_state_hash(ContentHash([0xFF; 32]));

        let verdict = nakaiah.check_in_on_lyll(lyll.state_hash());
        assert!(matches!(
            verdict,
            IntegrityVerdict::Panic {
                reason: ViolationReason::GuardianStateCorrupted
            }
        ));
    }

    #[test]
    fn mutual_state_update_cycle() {
        let mut lyll = test_lyll();
        let mut nakaiah = test_nakaiah();

        lyll.set_nakaiah_state_hash(nakaiah.state_hash());
        nakaiah.set_lyll_state_hash(lyll.state_hash());

        let new_lyll_hash = ContentHash([0x11; 32]);
        let new_nakaiah_hash = ContentHash([0x22; 32]);
        lyll.set_state_hash(new_lyll_hash);
        nakaiah.set_state_hash(new_nakaiah_hash);

        lyll.set_nakaiah_state_hash(nakaiah.state_hash());
        nakaiah.set_lyll_state_hash(lyll.state_hash());

        assert_eq!(
            lyll.co_verify_nakaiah(nakaiah.state_hash()),
            IntegrityVerdict::Allow
        );
        assert_eq!(
            nakaiah.check_in_on_lyll(lyll.state_hash()),
            IntegrityVerdict::Allow
        );
    }

    #[test]
    fn lyll_not_actually_sampling_detected() {
        let mut lyll = test_lyll();

        lyll.register_frame(PhysAddr(0x1000), HashEntry::CidBacked { cid: [0; 32] }, 1);
        lyll.register_frame(PhysAddr(0x2000), HashEntry::CidBacked { cid: [1; 32] }, 1);

        let registered = lyll.all_registered_frames();
        let has_any_samples = registered.iter().any(|p| lyll.sampled_frames().contains(p));

        assert!(
            !has_any_samples,
            "Lyll should have no samples (not doing her job)"
        );
    }

    #[test]
    fn quarantine_record_forensics() {
        let mut lyll = test_lyll();
        lyll.register_frame(
            PhysAddr(0x1000),
            HashEntry::CidBacked { cid: [0xAA; 32] },
            42,
        );

        let verdict = lyll.verify_frame(PhysAddr(0x1000), [0xBB; 32], 999);
        assert!(matches!(verdict, IntegrityVerdict::Quarantine { .. }));

        let records = lyll.quarantine.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].paddr, PhysAddr(0x1000));
        assert_eq!(records[0].expected_hash, [0xAA; 32]);
        assert_eq!(records[0].actual_hash, [0xBB; 32]);
        assert_eq!(records[0].owner_pid, 42);
        assert_eq!(records[0].timestamp, 999);
    }

    #[test]
    fn nakaiah_access_log_receipt_after_verified_access() {
        let mut nakaiah = test_nakaiah();
        let paddr = PhysAddr(0x1000);
        let hash = [0xAA; 32];
        nakaiah.register_frame(paddr, hash);
        nakaiah.grant_access(1, paddr, CapChain::Owner);

        // Verify access, then append receipt.
        let verdict = nakaiah.verify_access(1, paddr, crate::vm::AccessOp::Read, hash);
        assert_eq!(verdict, IntegrityVerdict::Allow);
        nakaiah.append_receipt(AccessReceipt {
            pid: 1,
            paddr,
            operation: crate::vm::AccessOp::Read,
            timestamp: 500,
        });

        assert_eq!(nakaiah.access_log_len(), 1);
        assert_eq!(nakaiah.access_log()[0].receipt.timestamp, 500);
    }
}
