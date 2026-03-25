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
#[derive(Debug, PartialEq, Eq)]
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
        if self.pending_count >= COMMAND_RING_USABLE as u16 {
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

/// Number of TRB entries in the transfer ring (63 usable + 1 Link).
pub const TRANSFER_RING_SIZE: usize = 64;
/// Number of usable transfer slots (last slot is the Link TRB).
const TRANSFER_RING_USABLE: usize = TRANSFER_RING_SIZE - 1;

/// Transfer ring state — per-endpoint data transfer.
#[derive(Debug, PartialEq, Eq)]
pub struct TransferRing {
    base_phys: u64,
    enqueue_index: u16,
    cycle_bit: bool,
}

impl TransferRing {
    /// Create a new transfer ring at the given physical base address.
    pub fn new(base_phys: u64) -> Self {
        Self {
            base_phys,
            enqueue_index: 0,
            cycle_bit: true,
        }
    }

    /// Enqueue a single TRB, handling Link TRB wrap if needed.
    fn enqueue_one(
        &mut self,
        trb_type: u8,
        parameter: u64,
        status: u32,
        extra_flags: u32,
    ) -> Result<Vec<(u64, Trb)>, XhciError> {
        let phys = self.base_phys + (self.enqueue_index as u64) * TRB_SIZE;
        let mut trb = Trb {
            parameter,
            status,
            control: (trb_type as u32) << 10 | extra_flags,
        };
        trb.set_cycle_bit(self.cycle_bit);

        let mut entries = Vec::with_capacity(2);
        entries.push((phys, trb));

        self.enqueue_index += 1;

        if self.enqueue_index >= TRANSFER_RING_USABLE as u16 {
            let link_phys = self.base_phys + (TRANSFER_RING_USABLE as u64) * TRB_SIZE;
            let mut link = Trb {
                parameter: self.base_phys,
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

    /// Enqueue a control IN transfer (Setup + Data + Status).
    ///
    /// Returns TRB entries to write to DMA. May include Link TRBs
    /// if the ring wraps mid-sequence.
    pub fn enqueue_control_in(
        &mut self,
        setup_packet: [u8; 8],
        data_buf_phys: u64,
        data_len: u16,
    ) -> Result<Vec<(u64, Trb)>, XhciError> {
        use super::trb::{
            DIR_IN, IDT, IOC, ISP, TRB_DATA_STAGE, TRB_SETUP_STAGE, TRB_STATUS_STAGE, TRT_IN,
        };

        let mut all_entries = Vec::new();

        // 1. Setup TRB: parameter = setup packet as u64 LE, status = 8
        let setup_param = u64::from_le_bytes(setup_packet);
        let setup_entries = self.enqueue_one(TRB_SETUP_STAGE, setup_param, 8, TRT_IN | IDT)?;
        all_entries.extend(setup_entries);

        // 2. Data TRB: parameter = data buffer phys, status = data_len, DIR_IN + ISP
        // ISP ensures a Transfer Event on short packets (device returns less than requested).
        let data_entries =
            self.enqueue_one(TRB_DATA_STAGE, data_buf_phys, data_len as u32, DIR_IN | ISP)?;
        all_entries.extend(data_entries);

        // 3. Status TRB: direction OUT (no DIR_IN), IOC
        let status_entries = self.enqueue_one(TRB_STATUS_STAGE, 0, 0, IOC)?;
        all_entries.extend(status_entries);

        Ok(all_entries)
    }
}

/// Event ring state — controller enqueues events, host dequeues.
#[derive(Debug, PartialEq, Eq)]
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
    use super::super::trb::{
        DIR_IN, IDT, IOC, ISP, TRB_DATA_STAGE, TRB_LINK, TRB_NOOP_CMD, TRB_SETUP_STAGE,
        TRB_STATUS_STAGE, TRT_IN,
    };
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
        for _ in 0..COMMAND_RING_USABLE {
            ring.enqueue(23, 0).unwrap();
        }
        // Free a slot so we can enqueue on the second lap
        ring.complete_one();
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
        for _ in 0..COMMAND_RING_USABLE {
            ring.enqueue(23, 0).unwrap();
        }
        // Ring is full (63 pending = all usable slots, no completions)
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

    // ── TransferRing tests ──────────────────────────────────────────

    #[test]
    fn transfer_ring_enqueue_control_returns_3_trbs() {
        let mut ring = TransferRing::new(BASE);
        let setup = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00]; // GET_DESCRIPTOR(Device)
        let entries = ring.enqueue_control_in(setup, 0xA000_0000, 18).unwrap();
        // Should be exactly 3 TRBs (Setup, Data, Status) — no Link TRB at start
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].1.trb_type(), TRB_SETUP_STAGE);
        assert_eq!(entries[1].1.trb_type(), TRB_DATA_STAGE);
        assert_eq!(entries[2].1.trb_type(), TRB_STATUS_STAGE);
    }

    #[test]
    fn transfer_ring_setup_trb_flags() {
        let mut ring = TransferRing::new(BASE);
        let setup = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00];
        let entries = ring.enqueue_control_in(setup, 0xA000_0000, 18).unwrap();
        let ctrl = entries[0].1.control;
        // Should have: TRT_IN, IDT, cycle bit
        assert_ne!(ctrl & TRT_IN, 0, "Setup TRB should have TRT_IN");
        assert_ne!(ctrl & IDT, 0, "Setup TRB should have IDT (Immediate Data)");
        assert!(
            entries[0].1.cycle_bit(),
            "Setup TRB should have cycle bit set"
        );
        // Setup TRB parameter = 8-byte setup packet as u64 LE
        let pkt_bytes = entries[0].1.parameter.to_le_bytes();
        assert_eq!(&pkt_bytes, &setup);
        // Setup TRB status = 8 (transfer length)
        assert_eq!(entries[0].1.status, 8);
    }

    #[test]
    fn transfer_ring_data_trb_fields() {
        let mut ring = TransferRing::new(BASE);
        let setup = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00];
        let entries = ring.enqueue_control_in(setup, 0xA000_0000, 18).unwrap();
        let data_trb = &entries[1].1;
        assert_eq!(
            data_trb.parameter, 0xA000_0000,
            "Data TRB parameter = data buffer phys"
        );
        assert_eq!(data_trb.status, 18, "Data TRB status = data length");
        assert_ne!(data_trb.control & DIR_IN, 0, "Data TRB should have DIR_IN");
        assert_ne!(data_trb.control & ISP, 0, "Data TRB should have ISP");
        // No IOC on Data TRB (only on Status)
        assert_eq!(data_trb.control & IOC, 0, "Data TRB should NOT have IOC");
    }

    #[test]
    fn transfer_ring_status_trb_flags() {
        let mut ring = TransferRing::new(BASE);
        let setup = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00];
        let entries = ring.enqueue_control_in(setup, 0xA000_0000, 18).unwrap();
        let status_trb = &entries[2].1;
        assert_ne!(status_trb.control & IOC, 0, "Status TRB should have IOC");
        // Direction OUT (no DIR_IN flag) — opposite of data phase
        assert_eq!(
            status_trb.control & DIR_IN,
            0,
            "Status TRB should NOT have DIR_IN (direction OUT)"
        );
    }

    #[test]
    fn transfer_ring_phys_addresses_sequential() {
        let mut ring = TransferRing::new(BASE);
        let setup = [0; 8];
        let entries = ring.enqueue_control_in(setup, 0xA000, 18).unwrap();
        assert_eq!(entries[0].0, BASE); // Setup at index 0
        assert_eq!(entries[1].0, BASE + 16); // Data at index 1
        assert_eq!(entries[2].0, BASE + 32); // Status at index 2
    }

    #[test]
    fn transfer_ring_control_in_wraps_mid_sequence() {
        let mut ring = TransferRing::new(BASE);
        // Advance to index 61 by enqueuing 61 dummy TRBs
        for _ in 0..61 {
            ring.enqueue_one(TRB_NOOP_CMD, 0, 0, 0).unwrap();
        }
        // Now at index 61. Control transfer needs 3 slots (61, 62, wrap+0).
        // Data TRB at index 62 triggers Link TRB at 63, then Status wraps to 0.
        let setup = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00];
        let entries = ring.enqueue_control_in(setup, 0xA000, 18).unwrap();

        // Should have: Setup(61) + Data(62) + Link(63) + Status(0)
        assert!(
            entries.len() >= 4,
            "wrap should produce at least 4 entries (3 TRBs + Link), got {}",
            entries.len()
        );

        let types: alloc::vec::Vec<u8> = entries.iter().map(|e| e.1.trb_type()).collect();
        assert_eq!(types[0], TRB_SETUP_STAGE);
        assert_eq!(types[1], TRB_DATA_STAGE);
        assert_eq!(types[2], TRB_LINK);
        assert_eq!(types[3], TRB_STATUS_STAGE);

        // Status TRB should be at the base (wrapped around)
        assert_eq!(entries[3].0, BASE);
    }
}
