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
    Kill { pid: u32, reason: ViolationReason },
    Panic { reason: ViolationReason },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{FrameClassification, PhysAddr};

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
}
