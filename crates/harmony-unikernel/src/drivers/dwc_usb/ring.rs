// SPDX-License-Identifier: GPL-2.0-or-later

//! xHCI ring state machines — CommandRing and EventRing.

#![allow(dead_code)] // Used by XhciDriver in subsequent tasks

extern crate alloc;
use alloc::vec::Vec;

use super::trb::{Trb, LINK_TOGGLE_CYCLE, TRB_LINK};
use super::types::XhciError;

/// Number of TRB entries in the command ring (63 usable + 1 Link).
pub const COMMAND_RING_SIZE: usize = 64;
/// Number of usable command slots (last slot is the Link TRB).
const COMMAND_RING_USABLE: usize = COMMAND_RING_SIZE - 1;

/// Number of TRB entries in the event ring.
pub const EVENT_RING_SIZE: usize = 256;

/// TRB size in bytes.
const TRB_SIZE: u64 = 16;

/// Command ring state — host enqueues commands, controller dequeues.
pub struct CommandRing {
    base_phys: u64,
    enqueue_index: u16,
    cycle_bit: bool,
    pending_count: u16,
}

impl CommandRing {
    /// Create a new command ring at the given physical base address.
    pub fn new(base_phys: u64) -> Self {
        Self {
            base_phys,
            enqueue_index: 0,
            cycle_bit: true,
            pending_count: 0,
        }
    }

    /// Enqueue a command TRB. Returns (phys_addr, trb) pairs to write.
    ///
    /// Normally returns 1 pair. When the enqueue fills the last usable
    /// slot, returns 2 pairs: the command TRB + the Link TRB at slot 63.
    pub fn enqueue(&mut self, trb_type: u8, parameter: u64) -> Result<Vec<(u64, Trb)>, XhciError> {
        if self.pending_count >= COMMAND_RING_SIZE as u16 {
            return Err(XhciError::CommandRingFull);
        }

        let phys = self.base_phys + (self.enqueue_index as u64) * TRB_SIZE;
        let mut trb = Trb {
            parameter,
            status: 0,
            control: (trb_type as u32) << 10,
        };
        trb.set_cycle_bit(self.cycle_bit);

        let mut entries = Vec::with_capacity(2);
        entries.push((phys, trb));

        self.enqueue_index += 1;
        self.pending_count += 1;

        // If we just wrote to the last usable slot, append Link TRB and wrap
        if self.enqueue_index >= COMMAND_RING_USABLE as u16 {
            let link_phys = self.base_phys + (COMMAND_RING_USABLE as u64) * TRB_SIZE;
            let mut link = Trb {
                parameter: self.base_phys, // points back to ring base
                status: 0,
                control: (TRB_LINK as u32) << 10 | LINK_TOGGLE_CYCLE,
            };
            link.set_cycle_bit(self.cycle_bit);
            entries.push((link_phys, link));

            self.enqueue_index = 0;
            self.cycle_bit = !self.cycle_bit;
        }

        Ok(entries)
    }

    /// Record that one command completed (decrements pending count).
    pub fn complete_one(&mut self) {
        self.pending_count = self.pending_count.saturating_sub(1);
    }

    /// CRCR register value: base address | cycle bit.
    pub fn crcr_value(&self) -> u64 {
        self.base_phys | (self.cycle_bit as u64)
    }
}

/// Event ring state — controller enqueues events, host dequeues.
pub struct EventRing {
    base_phys: u64,
    dequeue_index: u16,
    cycle_bit: bool,
}

impl EventRing {
    /// Create a new event ring at the given physical base address.
    pub fn new(base_phys: u64) -> Self {
        Self {
            base_phys,
            dequeue_index: 0,
            cycle_bit: true,
        }
    }

    /// Check if a TRB's cycle bit matches the expected Consumer Cycle State.
    pub fn should_process(&self, trb_cycle_bit: bool) -> bool {
        trb_cycle_bit == self.cycle_bit
    }

    /// Advance the dequeue pointer by one slot.
    pub fn advance(&mut self) {
        self.dequeue_index += 1;
        if self.dequeue_index >= EVENT_RING_SIZE as u16 {
            self.dequeue_index = 0;
            self.cycle_bit = !self.cycle_bit;
        }
    }

    /// Current dequeue pointer physical address (for ERDP update).
    pub fn dequeue_pointer(&self) -> u64 {
        self.base_phys + (self.dequeue_index as u64) * TRB_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x1000_0000;

    #[test]
    fn command_ring_enqueue_returns_correct_phys() {
        let mut ring = CommandRing::new(BASE);
        let entries = ring.enqueue(23, 0).unwrap(); // TRB_NOOP_CMD
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, BASE); // first TRB at base
    }

    #[test]
    fn command_ring_enqueue_advances_index() {
        let mut ring = CommandRing::new(BASE);
        ring.enqueue(23, 0).unwrap();
        let entries = ring.enqueue(23, 0).unwrap();
        assert_eq!(entries[0].0, BASE + 16); // second TRB at base + 16
    }

    #[test]
    fn command_ring_enqueue_sets_cycle_bit() {
        let mut ring = CommandRing::new(BASE);
        let entries = ring.enqueue(23, 0).unwrap();
        assert!(entries[0].1.cycle_bit(), "initial cycle bit should be true");
    }

    #[test]
    fn command_ring_wrap_generates_link_trb() {
        let mut ring = CommandRing::new(BASE);
        // Enqueue 63 commands to fill all usable slots
        for i in 0..63 {
            let entries = ring.enqueue(23, i as u64).unwrap();
            if i < 62 {
                assert_eq!(entries.len(), 1, "non-wrap enqueue should produce 1 entry");
            } else {
                // Last enqueue (index 62) should also produce the Link TRB at index 63
                assert_eq!(
                    entries.len(),
                    2,
                    "wrap enqueue should produce command + link"
                );
                let link = &entries[1];
                assert_eq!(link.0, BASE + 63 * 16, "link TRB at slot 63");
                assert_eq!(link.1.trb_type(), TRB_LINK);
                assert_eq!(link.1.parameter, BASE, "link points back to base");
            }
        }
    }

    #[test]
    fn command_ring_cycle_toggles_on_wrap() {
        let mut ring = CommandRing::new(BASE);
        for _ in 0..63 {
            ring.enqueue(23, 0).unwrap();
        }
        // After wrap, cycle bit should have toggled
        let entries = ring.enqueue(23, 0).unwrap();
        assert!(!entries[0].1.cycle_bit(), "cycle should toggle after wrap");
    }

    #[test]
    fn command_ring_second_lap_uses_toggled_cycle() {
        let mut ring = CommandRing::new(BASE);
        // Fill first lap
        for _ in 0..63 {
            ring.enqueue(23, 0).unwrap();
            ring.complete_one();
        }
        // Second lap — first enqueue should use toggled cycle bit (false)
        let entries = ring.enqueue(23, 0).unwrap();
        assert!(!entries[0].1.cycle_bit());
        assert_eq!(entries[0].0, BASE); // back at base
    }

    #[test]
    fn command_ring_full_returns_error() {
        let mut ring = CommandRing::new(BASE);
        for _ in 0..64 {
            ring.enqueue(23, 0).unwrap();
        }
        // Ring is full (64 pending across two laps, no completions)
        assert_eq!(ring.enqueue(23, 0), Err(XhciError::CommandRingFull));
    }

    #[test]
    fn command_ring_crcr_value() {
        let ring = CommandRing::new(BASE);
        // Initial: base + cycle bit 1
        assert_eq!(ring.crcr_value(), BASE | 1);
    }

    #[test]
    fn event_ring_should_process_matches_cycle() {
        let ring = EventRing::new(BASE);
        assert!(ring.should_process(true), "initial CCS is true");
        assert!(
            !ring.should_process(false),
            "mismatched cycle should reject"
        );
    }

    #[test]
    fn event_ring_advance_wraps_at_256() {
        let mut ring = EventRing::new(BASE);
        for i in 0..255 {
            ring.advance();
            assert!(
                ring.should_process(true),
                "cycle should stay true before wrap (i={})",
                i
            );
        }
        // 256th advance wraps to 0 and toggles cycle
        ring.advance();
        assert!(
            ring.should_process(false),
            "cycle should toggle after 256 advances"
        );
    }

    #[test]
    fn event_ring_dequeue_pointer() {
        let mut ring = EventRing::new(BASE);
        assert_eq!(ring.dequeue_pointer(), BASE);
        ring.advance();
        assert_eq!(ring.dequeue_pointer(), BASE + 16);
        ring.advance();
        assert_eq!(ring.dequeue_pointer(), BASE + 32);
    }
}
