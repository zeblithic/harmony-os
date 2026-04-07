// SPDX-License-Identifier: GPL-2.0-or-later

//! USB Mass Storage Bulk-Only Transport (BOT) sans-I/O state machine.
//!
//! [`MassStorageBus`] sequences the CBW → data → CSW protocol phases
//! required by the USB Mass Storage Class Bulk-Only Transport
//! specification. Callers drive the machine by calling:
//!
//! 1. [`MassStorageBus::start_init`] — begin the init sequence
//! 2. [`MassStorageBus::handle_bulk_out_complete`] — after each CBW is sent
//! 3. [`MassStorageBus::handle_bulk_in_complete`] — after each bulk-IN transfer
//!
//! The machine emits [`MsAction`] variants telling the caller what to do next
//! (send a CBW, start a bulk-IN, return a result, etc.).

extern crate alloc;

use alloc::vec::Vec;

use harmony_unikernel::drivers::mass_storage::{
    parse_csw, parse_read_capacity, MassStorageDevice, MassStorageError,
};

// ── Errors ───────────────────────────────────────────────────────

/// Errors produced by [`MassStorageBus`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsError {
    /// The operation is not valid in the current state.
    InvalidState,
    /// The device reported a non-zero CSW status.
    CommandFailed {
        /// The raw bCSWStatus value from the device.
        status: u8,
    },
    /// The CSW signature is invalid.
    InvalidCsw,
    /// The response was shorter than expected.
    ResponseTooShort,
}

impl From<MassStorageError> for MsError {
    fn from(e: MassStorageError) -> Self {
        match e {
            MassStorageError::InvalidCsw => MsError::InvalidCsw,
            MassStorageError::CommandFailed { status } => MsError::CommandFailed { status },
            MassStorageError::ResponseTooShort => MsError::ResponseTooShort,
        }
    }
}

// ── Actions ──────────────────────────────────────────────────────

/// Actions emitted by [`MassStorageBus`] for the caller to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsAction {
    /// Perform a bulk-OUT transfer of `data` on `endpoint`.
    BulkOut {
        /// Endpoint DCI for bulk-OUT.
        endpoint: u8,
        /// The 31-byte CBW to send.
        data: [u8; 31],
    },
    /// Perform a bulk-IN transfer of `length` bytes on `endpoint`.
    BulkIn {
        /// Endpoint DCI for bulk-IN.
        endpoint: u8,
        /// Number of bytes to receive.
        length: u16,
    },
    /// Initialization complete — device is ready.
    InitComplete {
        /// Logical block size in bytes.
        block_size: u32,
        /// Total number of logical blocks on the device.
        capacity_blocks: u32,
    },
    /// A read operation completed successfully.
    ReadComplete(Vec<u8>),
}

// ── Private state enums ──────────────────────────────────────────

/// High-level state of the bus (init pipeline or steady-state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BusState {
    Uninitialized,
    InitInquiry,
    InitTestUnitReady,
    InitReadCapacity,
    Ready,
    Reading,
}

/// Current transfer phase within one command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferPhase {
    SendingCbw,
    ReceivingData,
    ReceivingCsw,
}

// ── MassStorageBus ───────────────────────────────────────────────

/// Sans-I/O state machine for USB Mass Storage Bulk-Only Transport.
///
/// Sequences the INQUIRY → TEST UNIT READY → READ CAPACITY init
/// pipeline, then handles READ(10) commands.
pub struct MassStorageBus {
    device: MassStorageDevice,
    state: BusState,
    phase: TransferPhase,
    block_size: u32,
    capacity_blocks: u32,
    pending_data_len: u32,
    stashed_data: Vec<u8>,
}

impl MassStorageBus {
    /// Create a new bus state machine.
    ///
    /// `slot_id`, `bulk_in_ep`, and `bulk_out_ep` are passed directly
    /// to [`MassStorageDevice::new`].
    pub fn new(slot_id: u8, bulk_in_ep: u8, bulk_out_ep: u8) -> Self {
        Self {
            device: MassStorageDevice::new(slot_id, bulk_in_ep, bulk_out_ep),
            state: BusState::Uninitialized,
            phase: TransferPhase::SendingCbw,
            block_size: 0,
            capacity_blocks: 0,
            pending_data_len: 0,
            stashed_data: Vec::new(),
        }
    }

    /// Logical block size in bytes. Valid only after [`MsAction::InitComplete`].
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Total number of logical blocks on the device. Valid only after
    /// [`MsAction::InitComplete`].
    pub fn capacity_blocks(&self) -> u32 {
        self.capacity_blocks
    }

    /// Begin the initialization sequence.
    ///
    /// Emits [`MsAction::BulkOut`] with the INQUIRY CBW.
    pub fn start_init(&mut self) -> Result<MsAction, MsError> {
        if self.state != BusState::Uninitialized {
            return Err(MsError::InvalidState);
        }
        let (cbw, _dir, data_len) = self.device.build_inquiry_cbw();
        self.state = BusState::InitInquiry;
        self.phase = TransferPhase::SendingCbw;
        self.pending_data_len = data_len;
        self.stashed_data.clear();
        Ok(MsAction::BulkOut {
            endpoint: self.device.bulk_out_ep,
            data: cbw,
        })
    }

    /// Begin a READ(10) for one sector at `lba`.
    ///
    /// Returns [`MsError::InvalidState`] if the bus is not [`BusState::Ready`].
    pub fn start_read(&mut self, lba: u32) -> Result<MsAction, MsError> {
        if self.state != BusState::Ready {
            return Err(MsError::InvalidState);
        }
        let (cbw, _dir, data_len) = self.device.build_read_cbw(lba, 1, self.block_size);
        self.state = BusState::Reading;
        self.phase = TransferPhase::SendingCbw;
        self.pending_data_len = data_len;
        self.stashed_data.clear();
        Ok(MsAction::BulkOut {
            endpoint: self.device.bulk_out_ep,
            data: cbw,
        })
    }

    /// Called by the caller after a bulk-OUT (CBW) transfer completes.
    ///
    /// If the current command has a data phase, returns
    /// [`MsAction::BulkIn`] for the data. Otherwise, goes directly
    /// to the CSW phase.
    pub fn handle_bulk_out_complete(&mut self) -> Result<MsAction, MsError> {
        if self.phase != TransferPhase::SendingCbw {
            return Err(MsError::InvalidState);
        }
        if self.pending_data_len == 0 {
            // No data phase — go straight to CSW.
            self.phase = TransferPhase::ReceivingCsw;
            Ok(MsAction::BulkIn {
                endpoint: self.device.bulk_in_ep,
                length: 13,
            })
        } else {
            self.phase = TransferPhase::ReceivingData;
            Ok(MsAction::BulkIn {
                endpoint: self.device.bulk_in_ep,
                length: u16::try_from(self.pending_data_len).map_err(|_| MsError::InvalidState)?,
            })
        }
    }

    /// Called by the caller after a bulk-IN transfer completes.
    ///
    /// Handles both the data phase and the CSW phase, advancing
    /// the state machine and returning the next action.
    pub fn handle_bulk_in_complete(&mut self, data: &[u8]) -> Result<MsAction, MsError> {
        match self.phase {
            TransferPhase::ReceivingData => {
                self.stashed_data = data.to_vec();
                self.phase = TransferPhase::ReceivingCsw;
                Ok(MsAction::BulkIn {
                    endpoint: self.device.bulk_in_ep,
                    length: 13,
                })
            }
            TransferPhase::ReceivingCsw => {
                let csw = parse_csw(data)?;
                if csw.status != 0 {
                    return Err(MsError::CommandFailed { status: csw.status });
                }
                self.advance_after_csw()
            }
            TransferPhase::SendingCbw => Err(MsError::InvalidState),
        }
    }

    /// Advance the high-level state after a successful CSW.
    fn advance_after_csw(&mut self) -> Result<MsAction, MsError> {
        match self.state {
            BusState::InitInquiry => {
                // Send TEST UNIT READY next.
                let (cbw, _dir, data_len) = self.device.build_test_unit_ready_cbw();
                self.state = BusState::InitTestUnitReady;
                self.phase = TransferPhase::SendingCbw;
                self.pending_data_len = data_len;
                self.stashed_data.clear();
                Ok(MsAction::BulkOut {
                    endpoint: self.device.bulk_out_ep,
                    data: cbw,
                })
            }
            BusState::InitTestUnitReady => {
                // Send READ CAPACITY next.
                let (cbw, _dir, data_len) = self.device.build_read_capacity_cbw();
                self.state = BusState::InitReadCapacity;
                self.phase = TransferPhase::SendingCbw;
                self.pending_data_len = data_len;
                self.stashed_data.clear();
                Ok(MsAction::BulkOut {
                    endpoint: self.device.bulk_out_ep,
                    data: cbw,
                })
            }
            BusState::InitReadCapacity => {
                // Parse stashed READ CAPACITY data.
                let (last_lba, block_size) = parse_read_capacity(&self.stashed_data)?;
                self.block_size = block_size;
                self.capacity_blocks = last_lba.saturating_add(1);
                self.state = BusState::Ready;
                self.phase = TransferPhase::SendingCbw;
                Ok(MsAction::InitComplete {
                    block_size: self.block_size,
                    capacity_blocks: self.capacity_blocks,
                })
            }
            BusState::Reading => {
                let data = core::mem::take(&mut self.stashed_data);
                self.state = BusState::Ready;
                self.phase = TransferPhase::SendingCbw;
                Ok(MsAction::ReadComplete(data))
            }
            _ => Err(MsError::InvalidState),
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const BULK_IN_EP: u8 = 5;
    const BULK_OUT_EP: u8 = 4;

    /// CSW signature "USBS" in little-endian.
    const CSW_SIGNATURE: u32 = 0x5342_5355;

    fn make_csw(tag: u32) -> Vec<u8> {
        make_csw_with_status(tag, 0)
    }

    fn make_csw_with_status(tag: u32, status: u8) -> Vec<u8> {
        let mut csw = vec![0u8; 13];
        csw[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        csw[4..8].copy_from_slice(&tag.to_le_bytes());
        // data residue = 0
        csw[8..12].copy_from_slice(&0u32.to_le_bytes());
        csw[12] = status;
        csw
    }

    fn make_inquiry_response() -> Vec<u8> {
        let mut resp = vec![0u8; 36];
        resp[0] = 0x00; // peripheral_type = 0 (direct-access block device)
        resp[1] = 0x80; // removable media bit set
        resp
    }

    fn make_read_capacity_response() -> Vec<u8> {
        let mut resp = vec![0u8; 8];
        // last_lba = 999, big-endian
        resp[0..4].copy_from_slice(&999u32.to_be_bytes());
        // block_size = 512, big-endian
        resp[4..8].copy_from_slice(&512u32.to_be_bytes());
        resp
    }

    /// Extract the SCSI opcode from the action (CBW byte 15).
    fn extract_opcode(action: &MsAction) -> u8 {
        match action {
            MsAction::BulkOut { data, .. } => data[15],
            _ => panic!("expected BulkOut, got {action:?}"),
        }
    }

    /// Extract the CBW tag from the action (CBW bytes 4–7, little-endian).
    fn extract_tag(action: &MsAction) -> u32 {
        match action {
            MsAction::BulkOut { data, .. } => {
                u32::from_le_bytes([data[4], data[5], data[6], data[7]])
            }
            _ => panic!("expected BulkOut, got {action:?}"),
        }
    }

    /// Drive the bus through the full init sequence, asserting success.
    fn init_bus(bus: &mut MassStorageBus) {
        // INQUIRY
        let cbw_action = bus.start_init().unwrap();
        let inquiry_tag = extract_tag(&cbw_action);
        let bulk_in = bus.handle_bulk_out_complete().unwrap();
        let MsAction::BulkIn { length: 36, .. } = bulk_in else {
            panic!("expected BulkIn(36)");
        };
        // receive inquiry data
        let csw_req = bus
            .handle_bulk_in_complete(&make_inquiry_response())
            .unwrap();
        let MsAction::BulkIn { length: 13, .. } = csw_req else {
            panic!("expected BulkIn(13) for CSW");
        };
        // receive CSW → next CBW (TUR)
        let tur_cbw = bus.handle_bulk_in_complete(&make_csw(inquiry_tag)).unwrap();
        assert_eq!(extract_opcode(&tur_cbw), 0x00, "TUR opcode");

        // TEST UNIT READY (no data phase)
        let tur_tag = extract_tag(&tur_cbw);
        let csw_req = bus.handle_bulk_out_complete().unwrap();
        let MsAction::BulkIn { length: 13, .. } = csw_req else {
            panic!("expected BulkIn(13) for TUR CSW");
        };
        let rc_cbw = bus.handle_bulk_in_complete(&make_csw(tur_tag)).unwrap();
        assert_eq!(extract_opcode(&rc_cbw), 0x25, "READ_CAPACITY opcode");

        // READ CAPACITY
        let rc_tag = extract_tag(&rc_cbw);
        let bulk_in = bus.handle_bulk_out_complete().unwrap();
        let MsAction::BulkIn { length: 8, .. } = bulk_in else {
            panic!("expected BulkIn(8)");
        };
        let csw_req = bus
            .handle_bulk_in_complete(&make_read_capacity_response())
            .unwrap();
        let MsAction::BulkIn { length: 13, .. } = csw_req else {
            panic!("expected BulkIn(13) for RC CSW");
        };
        let init_complete = bus.handle_bulk_in_complete(&make_csw(rc_tag)).unwrap();
        let MsAction::InitComplete {
            block_size: 512,
            capacity_blocks: 1000,
        } = init_complete
        else {
            panic!("expected InitComplete{{block_size:512, capacity_blocks:1000}}, got {init_complete:?}");
        };
    }

    // ── Test 1 ───────────────────────────────────────────────────

    #[test]
    fn start_init_returns_inquiry_cbw() {
        let mut bus = MassStorageBus::new(1, BULK_IN_EP, BULK_OUT_EP);
        let action = bus.start_init().unwrap();
        assert_eq!(extract_opcode(&action), 0x12, "INQUIRY opcode");
        let MsAction::BulkOut { endpoint, .. } = action else {
            panic!("expected BulkOut");
        };
        assert_eq!(endpoint, BULK_OUT_EP);
    }

    // ── Test 2 ───────────────────────────────────────────────────

    #[test]
    fn init_inquiry_sequence() {
        let mut bus = MassStorageBus::new(1, BULK_IN_EP, BULK_OUT_EP);
        let cbw_action = bus.start_init().unwrap();
        let inquiry_tag = extract_tag(&cbw_action);

        // After CBW out, expect BulkIn(36) for inquiry data.
        let bulk_in = bus.handle_bulk_out_complete().unwrap();
        let MsAction::BulkIn { endpoint, length } = bulk_in else {
            panic!("expected BulkIn");
        };
        assert_eq!(endpoint, BULK_IN_EP);
        assert_eq!(length, 36);

        // After inquiry data, expect BulkIn(13) for CSW.
        let csw_req = bus
            .handle_bulk_in_complete(&make_inquiry_response())
            .unwrap();
        let MsAction::BulkIn { length: 13, .. } = csw_req else {
            panic!("expected BulkIn(13) for CSW");
        };

        // After CSW, expect next CBW — TUR with opcode 0x00.
        let tur_cbw = bus.handle_bulk_in_complete(&make_csw(inquiry_tag)).unwrap();
        assert_eq!(extract_opcode(&tur_cbw), 0x00, "TUR opcode");
    }

    // ── Test 3 ───────────────────────────────────────────────────

    #[test]
    fn init_test_unit_ready_no_data_phase() {
        let mut bus = MassStorageBus::new(1, BULK_IN_EP, BULK_OUT_EP);
        // Advance through INQUIRY.
        let cbw_action = bus.start_init().unwrap();
        let inquiry_tag = extract_tag(&cbw_action);
        bus.handle_bulk_out_complete().unwrap();
        bus.handle_bulk_in_complete(&make_inquiry_response())
            .unwrap();
        let tur_cbw = bus.handle_bulk_in_complete(&make_csw(inquiry_tag)).unwrap();
        let tur_tag = extract_tag(&tur_cbw);

        // TUR has no data phase: handle_bulk_out_complete goes straight to CSW.
        let csw_req = bus.handle_bulk_out_complete().unwrap();
        let MsAction::BulkIn { length: 13, .. } = csw_req else {
            panic!("expected BulkIn(13) for TUR CSW, no data phase");
        };

        // After TUR CSW, expect READ CAPACITY CBW (opcode 0x25).
        let rc_cbw = bus.handle_bulk_in_complete(&make_csw(tur_tag)).unwrap();
        assert_eq!(extract_opcode(&rc_cbw), 0x25, "READ_CAPACITY opcode");
    }

    // ── Test 4 ───────────────────────────────────────────────────

    #[test]
    fn init_read_capacity_returns_init_complete() {
        let mut bus = MassStorageBus::new(1, BULK_IN_EP, BULK_OUT_EP);
        // Drive through INQUIRY and TUR.
        let cbw_action = bus.start_init().unwrap();
        let inquiry_tag = extract_tag(&cbw_action);
        bus.handle_bulk_out_complete().unwrap();
        bus.handle_bulk_in_complete(&make_inquiry_response())
            .unwrap();
        let tur_cbw = bus.handle_bulk_in_complete(&make_csw(inquiry_tag)).unwrap();
        let tur_tag = extract_tag(&tur_cbw);
        bus.handle_bulk_out_complete().unwrap();
        let rc_cbw = bus.handle_bulk_in_complete(&make_csw(tur_tag)).unwrap();
        let rc_tag = extract_tag(&rc_cbw);

        // READ CAPACITY: CBW → BulkIn(8) → data → BulkIn(13) → CSW → InitComplete.
        let data_req = bus.handle_bulk_out_complete().unwrap();
        let MsAction::BulkIn { length: 8, .. } = data_req else {
            panic!("expected BulkIn(8)");
        };
        let csw_req = bus
            .handle_bulk_in_complete(&make_read_capacity_response())
            .unwrap();
        let MsAction::BulkIn { length: 13, .. } = csw_req else {
            panic!("expected BulkIn(13)");
        };
        let action = bus.handle_bulk_in_complete(&make_csw(rc_tag)).unwrap();

        match action {
            MsAction::InitComplete {
                block_size,
                capacity_blocks,
            } => {
                assert_eq!(block_size, 512);
                assert_eq!(capacity_blocks, 1000);
            }
            _ => panic!("expected InitComplete, got {action:?}"),
        }
    }

    // ── Test 5 ───────────────────────────────────────────────────

    #[test]
    fn full_init_sequence() {
        let mut bus = MassStorageBus::new(1, BULK_IN_EP, BULK_OUT_EP);
        init_bus(&mut bus);
        assert_eq!(bus.block_size(), 512);
        assert_eq!(bus.capacity_blocks(), 1000);
    }

    // ── Test 6 ───────────────────────────────────────────────────

    #[test]
    fn start_read_before_init_fails() {
        let mut bus = MassStorageBus::new(1, BULK_IN_EP, BULK_OUT_EP);
        assert_eq!(bus.start_read(0).unwrap_err(), MsError::InvalidState);
    }

    // ── Test 7 ───────────────────────────────────────────────────

    #[test]
    fn read_sequence() {
        let mut bus = MassStorageBus::new(1, BULK_IN_EP, BULK_OUT_EP);
        init_bus(&mut bus);

        // READ(10) at LBA 42.
        let cbw_action = bus.start_read(42).unwrap();

        // Verify it's a READ(10) (opcode 0x28) and LBA bytes.
        let MsAction::BulkOut { ref data, endpoint } = cbw_action else {
            panic!("expected BulkOut");
        };
        assert_eq!(endpoint, BULK_OUT_EP);
        assert_eq!(data[15], 0x28, "READ(10) opcode");
        // LBA 42 = 0x0000_002A, bytes at CDB[2..6]
        assert_eq!(&data[17..21], &42u32.to_be_bytes());

        let read_tag = extract_tag(&cbw_action);

        // After CBW, expect BulkIn(512).
        let data_req = bus.handle_bulk_out_complete().unwrap();
        let MsAction::BulkIn { length: 512, .. } = data_req else {
            panic!("expected BulkIn(512)");
        };

        // Provide fake sector data.
        let sector_data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let csw_req = bus.handle_bulk_in_complete(&sector_data).unwrap();
        let MsAction::BulkIn { length: 13, .. } = csw_req else {
            panic!("expected BulkIn(13) for CSW");
        };

        // Provide CSW → expect ReadComplete.
        let result = bus.handle_bulk_in_complete(&make_csw(read_tag)).unwrap();
        match result {
            MsAction::ReadComplete(data) => assert_eq!(data, sector_data),
            _ => panic!("expected ReadComplete, got {result:?}"),
        }
    }

    // ── Test 8 ───────────────────────────────────────────────────

    #[test]
    fn read_csw_failed_status() {
        let mut bus = MassStorageBus::new(1, BULK_IN_EP, BULK_OUT_EP);
        init_bus(&mut bus);

        let cbw_action = bus.start_read(0).unwrap();
        let read_tag = extract_tag(&cbw_action);
        bus.handle_bulk_out_complete().unwrap();
        let sector_data = vec![0u8; 512];
        bus.handle_bulk_in_complete(&sector_data).unwrap();

        let err = bus
            .handle_bulk_in_complete(&make_csw_with_status(read_tag, 1))
            .unwrap_err();
        assert_eq!(err, MsError::CommandFailed { status: 1 });
    }

    // ── Test 9 ───────────────────────────────────────────────────

    #[test]
    fn read_csw_invalid_signature() {
        let mut bus = MassStorageBus::new(1, BULK_IN_EP, BULK_OUT_EP);
        init_bus(&mut bus);

        bus.start_read(0).unwrap();
        bus.handle_bulk_out_complete().unwrap();
        bus.handle_bulk_in_complete(&[0u8; 512]).unwrap();

        // Garbage CSW.
        let garbage = [0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = bus.handle_bulk_in_complete(&garbage).unwrap_err();
        assert_eq!(err, MsError::InvalidCsw);
    }

    // ── Test 10 ──────────────────────────────────────────────────

    #[test]
    fn multiple_sequential_reads() {
        let mut bus = MassStorageBus::new(1, BULK_IN_EP, BULK_OUT_EP);
        init_bus(&mut bus);

        for i in 0u32..2 {
            let cbw_action = bus.start_read(i * 10).unwrap();
            let read_tag = extract_tag(&cbw_action);
            bus.handle_bulk_out_complete().unwrap();
            let data = vec![i as u8; 512];
            bus.handle_bulk_in_complete(&data).unwrap();
            let result = bus.handle_bulk_in_complete(&make_csw(read_tag)).unwrap();
            match result {
                MsAction::ReadComplete(d) => assert_eq!(d, data),
                _ => panic!("expected ReadComplete"),
            }
        }

        // Verify tags incremented (first read after init has tag > 3).
        let action1 = bus.start_read(0).unwrap();
        let tag1 = extract_tag(&action1);
        // Reset state by driving to completion.
        bus.handle_bulk_out_complete().unwrap();
        bus.handle_bulk_in_complete(&[0u8; 512]).unwrap();
        bus.handle_bulk_in_complete(&make_csw(tag1)).unwrap();

        let action2 = bus.start_read(0).unwrap();
        let tag2 = extract_tag(&action2);
        assert!(tag2 > tag1, "tags should increment: {tag1} < {tag2}");
    }

    // ── Test 11 ──────────────────────────────────────────────────

    #[test]
    fn double_start_read_while_busy() {
        let mut bus = MassStorageBus::new(1, BULK_IN_EP, BULK_OUT_EP);
        init_bus(&mut bus);

        // First read (in progress — CBW not yet sent).
        bus.start_read(0).unwrap();
        // Second start_read while already in Reading state.
        let err = bus.start_read(1).unwrap_err();
        assert_eq!(err, MsError::InvalidState);
    }
}
