# USB Mass Storage Block Device Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire up the existing Ring 1 `MassStorageDevice` into a Ring 2 `BlockDevice` implementation so `FatServer` can read files from USB flash drives.

**Architecture:** A sans-I/O `MassStorageBus` state machine in Ring 2 sequences the BOT protocol (CBW→data→CSW). A `BulkTransport` trait abstracts bulk transfer execution. `MassStorageBlockDevice<T: BulkTransport>` implements `BlockDevice` by driving the bus through the transport. Reuses existing `FatServer` — no new FileServer.

**Tech Stack:** Rust (no_std), harmony-unikernel Ring 1 types, harmony-microkernel Ring 2 infrastructure

---

## File Structure

| File | Responsibility |
|------|----------------|
| Create: `crates/harmony-microkernel/src/mass_storage_bus.rs` | Sans-I/O state machine: sequences INQUIRY→TUR→READ_CAPACITY init and READ(10) block reads. Returns `MsAction` variants. |
| Create: `crates/harmony-microkernel/src/mass_storage_block.rs` | `BulkTransport` trait, `MassStorageBlockDevice<T>` implementing `BlockDevice`, `MockBulkTransport` test helper. |
| Modify: `crates/harmony-microkernel/src/lib.rs` | Add `pub mod mass_storage_bus;` and `pub mod mass_storage_block;` |

---

### Task 1: MassStorageBus — Types, Init Sequence, and Tests

**Files:**
- Create: `crates/harmony-microkernel/src/mass_storage_bus.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs`

This task builds the sans-I/O state machine that sequences BOT protocol transfers. It covers the `MsAction`/`MsError` types, the init sequence (INQUIRY → TEST UNIT READY → READ CAPACITY), and the read sequence.

**Reference files you'll need to read:**
- `crates/harmony-unikernel/src/drivers/mass_storage.rs` — `MassStorageDevice` API, `parse_csw`, `parse_read_capacity`, `CswStatus`, `MassStorageError`, `DataDirection`
- `crates/harmony-microkernel/src/lib.rs` — `IpcError` enum

**Key Ring 1 API you'll use:**
- `MassStorageDevice::new(slot_id: u8, bulk_in_ep: u8, bulk_out_ep: u8)` — constructor
- `device.build_inquiry_cbw() -> ([u8; 31], DataDirection, u32)` — returns (cbw, dir, data_len)
- `device.build_test_unit_ready_cbw() -> ([u8; 31], DataDirection, u32)` — data_len=0, dir=None
- `device.build_read_capacity_cbw() -> ([u8; 31], DataDirection, u32)` — data_len=8
- `device.build_read_cbw(lba, sector_count, block_size) -> ([u8; 31], DataDirection, u32)`
- `parse_csw(data: &[u8]) -> Result<CswStatus, MassStorageError>` — free function
- `parse_read_capacity(data: &[u8]) -> Result<(u32, u32), MassStorageError>` — returns (last_lba, block_size)
- `CswStatus { tag: u32, data_residue: u32, status: u8 }` — status 0=Passed, 1=Failed, 2=PhaseError

- [ ] **Step 1: Create the module file with types**

Create `crates/harmony-microkernel/src/mass_storage_bus.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! Sans-I/O state machine for USB Mass Storage Bulk-Only Transport.
//!
//! Sequences the multi-step BOT protocol: CBW out → data in → CSW in.
//! Wraps a [`MassStorageDevice`] for building CBWs and parsing responses.
//! The caller executes bulk transfers and feeds completions back.

extern crate alloc;
use alloc::vec::Vec;

use harmony_unikernel::drivers::mass_storage::{
    parse_csw, parse_read_capacity, DataDirection, MassStorageDevice, MassStorageError,
};

// ── Error type ──────────────────────────────────────────────────

/// Errors from the mass storage bus state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsError {
    /// Called a method in the wrong state (e.g. start_read before init).
    InvalidState,
    /// CSW indicated command failure (status 1 or 2).
    CommandFailed { status: u8 },
    /// CSW had invalid signature or was too short.
    InvalidCsw,
    /// SCSI response was too short to parse.
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

// ── Action type ─────────────────────────────────────────────────

/// Actions the caller must execute on behalf of the state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsAction {
    /// Send this 31-byte CBW via bulk OUT.
    BulkOut { endpoint: u8, data: [u8; 31] },
    /// Read this many bytes via bulk IN.
    BulkIn { endpoint: u8, length: u16 },
    /// Initialization completed — device is ready for reads.
    InitComplete {
        block_size: u32,
        capacity_blocks: u32,
    },
    /// A read operation completed — here is the sector data.
    ReadComplete(Vec<u8>),
}

// ── State enums ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BusState {
    Uninitialized,
    InitInquiry,
    InitTestUnitReady,
    InitReadCapacity,
    Ready,
    Reading,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferPhase {
    SendingCbw,
    ReceivingData,
    ReceivingCsw,
}

// ── MassStorageBus ──────────────────────────────────────────────

/// Sans-I/O state machine for USB mass storage BOT protocol.
pub struct MassStorageBus {
    device: MassStorageDevice,
    state: BusState,
    phase: TransferPhase,
    block_size: u32,
    capacity_blocks: u32,
    pending_data_len: u32,
}

impl MassStorageBus {
    /// Create a new bus wrapping the given mass storage device.
    pub fn new(slot_id: u8, bulk_in_ep: u8, bulk_out_ep: u8) -> Self {
        Self {
            device: MassStorageDevice::new(slot_id, bulk_in_ep, bulk_out_ep),
            state: BusState::Uninitialized,
            phase: TransferPhase::SendingCbw,
            block_size: 0,
            capacity_blocks: 0,
            pending_data_len: 0,
        }
    }

    /// Cached block size from READ CAPACITY (0 before init completes).
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Cached capacity in blocks from READ CAPACITY (0 before init completes).
    pub fn capacity_blocks(&self) -> u32 {
        self.capacity_blocks
    }

    /// Start the device initialization sequence (INQUIRY → TUR → READ CAPACITY).
    ///
    /// Returns the first action: `BulkOut` with the INQUIRY CBW.
    pub fn start_init(&mut self) -> Result<MsAction, MsError> {
        if self.state != BusState::Uninitialized {
            return Err(MsError::InvalidState);
        }
        let (cbw, _dir, data_len) = self.device.build_inquiry_cbw();
        self.state = BusState::InitInquiry;
        self.phase = TransferPhase::SendingCbw;
        self.pending_data_len = data_len;
        Ok(MsAction::BulkOut {
            endpoint: self.device.bulk_out_ep,
            data: cbw,
        })
    }

    /// Start a single-sector read at the given LBA.
    ///
    /// Only valid when `state == Ready`. Returns `BulkOut` with the READ(10) CBW.
    pub fn start_read(&mut self, lba: u32) -> Result<MsAction, MsError> {
        if self.state != BusState::Ready {
            return Err(MsError::InvalidState);
        }
        let (cbw, _dir, data_len) = self.device.build_read_cbw(lba, 1, self.block_size);
        self.state = BusState::Reading;
        self.phase = TransferPhase::SendingCbw;
        self.pending_data_len = data_len;
        Ok(MsAction::BulkOut {
            endpoint: self.device.bulk_out_ep,
            data: cbw,
        })
    }

    /// The caller has completed the bulk OUT transfer (CBW sent).
    ///
    /// Returns the next action: `BulkIn` for the data phase (or CSW
    /// if there's no data phase, e.g. TEST UNIT READY).
    pub fn handle_bulk_out_complete(&mut self) -> Result<MsAction, MsError> {
        if self.phase != TransferPhase::SendingCbw {
            return Err(MsError::InvalidState);
        }
        if self.pending_data_len == 0 {
            // No data phase (TEST UNIT READY) — go straight to CSW.
            self.phase = TransferPhase::ReceivingCsw;
            Ok(MsAction::BulkIn {
                endpoint: self.device.bulk_in_ep,
                length: 13,
            })
        } else {
            self.phase = TransferPhase::ReceivingData;
            Ok(MsAction::BulkIn {
                endpoint: self.device.bulk_in_ep,
                length: self.pending_data_len as u16,
            })
        }
    }

    /// The caller has completed a bulk IN transfer.
    ///
    /// If we were in `ReceivingData`, this is the SCSI response data —
    /// we store it and request the CSW. If we were in `ReceivingCsw`,
    /// this is the 13-byte CSW — we parse it and advance state.
    pub fn handle_bulk_in_complete(&mut self, data: &[u8]) -> Result<MsAction, MsError> {
        match self.phase {
            TransferPhase::ReceivingData => {
                // Data received — now read the CSW.
                // We don't need to store init data (INQUIRY response is
                // informational, READ CAPACITY is parsed in CSW phase).
                // For reads, we hold the data to return in ReadComplete.
                // Store in a field? No — we pass it through. The caller
                // will get ReadComplete after CSW. We need to stash it.
                //
                // Actually: for init steps we parse inline. For reads
                // we need to buffer. Let's handle each state:
                self.phase = TransferPhase::ReceivingCsw;
                self.stash_data(data);
                Ok(MsAction::BulkIn {
                    endpoint: self.device.bulk_in_ep,
                    length: 13,
                })
            }
            TransferPhase::ReceivingCsw => {
                let csw = parse_csw(data)?;
                if csw.status != 0 {
                    return Err(MsError::CommandFailed {
                        status: csw.status,
                    });
                }
                self.advance_after_csw()
            }
            TransferPhase::SendingCbw => Err(MsError::InvalidState),
        }
    }

    // ── Private helpers ─────────────────────────────────────────

    fn stash_data(&mut self, _data: &[u8]) {
        // Placeholder — will be replaced with actual stash logic below.
    }

    fn advance_after_csw(&mut self) -> Result<MsAction, MsError> {
        // Placeholder — will be replaced with actual advance logic below.
        Err(MsError::InvalidState)
    }
}
```

Wait — the above has placeholder methods. Let me reconsider. The state machine needs to buffer data between the data phase and CSW phase. For init, READ CAPACITY data (8 bytes) needs to be parsed after CSW confirms success. For reads, sector data (512 bytes) needs to be returned in `ReadComplete`.

The clean approach: add a `stashed_data: Vec<u8>` field to `MassStorageBus`.

Here is the **complete** file to create at `crates/harmony-microkernel/src/mass_storage_bus.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! Sans-I/O state machine for USB Mass Storage Bulk-Only Transport.
//!
//! Sequences the multi-step BOT protocol: CBW out → data in → CSW in.
//! Wraps a [`MassStorageDevice`] for building CBWs and parsing responses.
//! The caller executes bulk transfers and feeds completions back.

extern crate alloc;
use alloc::vec::Vec;

use harmony_unikernel::drivers::mass_storage::{
    parse_csw, parse_read_capacity, DataDirection, MassStorageDevice, MassStorageError,
};

// ── Error type ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsError {
    InvalidState,
    CommandFailed { status: u8 },
    InvalidCsw,
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

// ── Action type ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsAction {
    BulkOut { endpoint: u8, data: [u8; 31] },
    BulkIn { endpoint: u8, length: u16 },
    InitComplete {
        block_size: u32,
        capacity_blocks: u32,
    },
    ReadComplete(Vec<u8>),
}

// ── State enums ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BusState {
    Uninitialized,
    InitInquiry,
    InitTestUnitReady,
    InitReadCapacity,
    Ready,
    Reading,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferPhase {
    SendingCbw,
    ReceivingData,
    ReceivingCsw,
}

// ── MassStorageBus ──────────────────────────────────────────────

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

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    pub fn capacity_blocks(&self) -> u32 {
        self.capacity_blocks
    }

    pub fn start_init(&mut self) -> Result<MsAction, MsError> {
        if self.state != BusState::Uninitialized {
            return Err(MsError::InvalidState);
        }
        let (cbw, _dir, data_len) = self.device.build_inquiry_cbw();
        self.state = BusState::InitInquiry;
        self.phase = TransferPhase::SendingCbw;
        self.pending_data_len = data_len;
        Ok(MsAction::BulkOut {
            endpoint: self.device.bulk_out_ep,
            data: cbw,
        })
    }

    pub fn start_read(&mut self, lba: u32) -> Result<MsAction, MsError> {
        if self.state != BusState::Ready {
            return Err(MsError::InvalidState);
        }
        let (cbw, _dir, data_len) = self.device.build_read_cbw(lba, 1, self.block_size);
        self.state = BusState::Reading;
        self.phase = TransferPhase::SendingCbw;
        self.pending_data_len = data_len;
        Ok(MsAction::BulkOut {
            endpoint: self.device.bulk_out_ep,
            data: cbw,
        })
    }

    pub fn handle_bulk_out_complete(&mut self) -> Result<MsAction, MsError> {
        if self.phase != TransferPhase::SendingCbw {
            return Err(MsError::InvalidState);
        }
        if self.pending_data_len == 0 {
            self.phase = TransferPhase::ReceivingCsw;
            Ok(MsAction::BulkIn {
                endpoint: self.device.bulk_in_ep,
                length: 13,
            })
        } else {
            self.phase = TransferPhase::ReceivingData;
            Ok(MsAction::BulkIn {
                endpoint: self.device.bulk_in_ep,
                length: self.pending_data_len as u16,
            })
        }
    }

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
                    return Err(MsError::CommandFailed {
                        status: csw.status,
                    });
                }
                self.advance_after_csw()
            }
            TransferPhase::SendingCbw => Err(MsError::InvalidState),
        }
    }

    fn advance_after_csw(&mut self) -> Result<MsAction, MsError> {
        match self.state {
            BusState::InitInquiry => {
                // INQUIRY done — advance to TEST UNIT READY.
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
                // TUR done — advance to READ CAPACITY.
                let (cbw, _dir, data_len) = self.device.build_read_capacity_cbw();
                self.state = BusState::InitReadCapacity;
                self.phase = TransferPhase::SendingCbw;
                self.pending_data_len = data_len;
                Ok(MsAction::BulkOut {
                    endpoint: self.device.bulk_out_ep,
                    data: cbw,
                })
            }
            BusState::InitReadCapacity => {
                // READ CAPACITY done — parse stashed data.
                let (last_lba, block_size) = parse_read_capacity(&self.stashed_data)?;
                self.block_size = block_size;
                self.capacity_blocks = last_lba.saturating_add(1);
                self.state = BusState::Ready;
                self.stashed_data.clear();
                Ok(MsAction::InitComplete {
                    block_size,
                    capacity_blocks: self.capacity_blocks,
                })
            }
            BusState::Reading => {
                // READ done — return sector data.
                let data = core::mem::take(&mut self.stashed_data);
                self.state = BusState::Ready;
                Ok(MsAction::ReadComplete(data))
            }
            _ => Err(MsError::InvalidState),
        }
    }
}
```

- [ ] **Step 2: Register the module**

Add to `crates/harmony-microkernel/src/lib.rs`, after the `pub mod hid_server;` line:

```rust
pub mod mass_storage_block;
pub mod mass_storage_bus;
```

(Alphabetical order: `mass_storage_block` before `mass_storage_bus`. We'll create the `mass_storage_block.rs` file in Task 2 — for now create an empty placeholder so the module declaration compiles.)

Create `crates/harmony-microkernel/src/mass_storage_block.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! USB mass storage `BlockDevice` adapter.
//!
//! Placeholder — implementation in Task 2.
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo test -p harmony-microkernel --no-run`
Expected: compiles with no errors.

- [ ] **Step 4: Write the init sequence tests**

Add to the bottom of `crates/harmony-microkernel/src/mass_storage_bus.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SLOT_ID: u8 = 1;
    const BULK_IN_EP: u8 = 5;
    const BULK_OUT_EP: u8 = 4;

    /// CSW signature "USBS" in little-endian.
    const CSW_SIGNATURE: u32 = 0x5342_5355;

    /// Build a 13-byte CSW with status=0 (passed).
    fn make_csw(tag: u32) -> Vec<u8> {
        let mut csw = vec![0u8; 13];
        csw[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        csw[4..8].copy_from_slice(&tag.to_le_bytes());
        // data_residue = 0, status = 0
        csw
    }

    /// Build a 13-byte CSW with a given status.
    fn make_csw_with_status(tag: u32, status: u8) -> Vec<u8> {
        let mut csw = make_csw(tag);
        csw[12] = status;
        csw
    }

    /// Build a minimal 36-byte INQUIRY response.
    fn make_inquiry_response() -> Vec<u8> {
        let mut data = vec![0u8; 36];
        data[0] = 0x00; // direct access block device
        data[1] = 0x80; // removable
        data
    }

    /// Build an 8-byte READ CAPACITY response.
    /// last_lba=999, block_size=512
    fn make_read_capacity_response() -> Vec<u8> {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&999u32.to_be_bytes());
        data[4..8].copy_from_slice(&512u32.to_be_bytes());
        data
    }

    fn make_bus() -> MassStorageBus {
        MassStorageBus::new(SLOT_ID, BULK_IN_EP, BULK_OUT_EP)
    }

    /// Extract the SCSI opcode from a BulkOut CBW action.
    fn extract_opcode(action: &MsAction) -> u8 {
        match action {
            MsAction::BulkOut { data, .. } => data[15], // CDB starts at byte 15
            _ => panic!("expected BulkOut"),
        }
    }

    /// Extract the CBW tag from a BulkOut action.
    fn extract_tag(action: &MsAction) -> u32 {
        match action {
            MsAction::BulkOut { data, .. } => {
                u32::from_le_bytes([data[4], data[5], data[6], data[7]])
            }
            _ => panic!("expected BulkOut"),
        }
    }

    // ── Init tests ──────────────────────────────────────────────

    #[test]
    fn start_init_returns_inquiry_cbw() {
        let mut bus = make_bus();
        let action = bus.start_init().unwrap();
        assert_eq!(extract_opcode(&action), 0x12); // SCSI_INQUIRY
        match &action {
            MsAction::BulkOut { endpoint, .. } => assert_eq!(*endpoint, BULK_OUT_EP),
            _ => panic!("expected BulkOut"),
        }
    }

    #[test]
    fn init_inquiry_sequence() {
        let mut bus = make_bus();
        let cbw_action = bus.start_init().unwrap();
        let tag = extract_tag(&cbw_action);

        // CBW sent → expect BulkIn for 36-byte INQUIRY data.
        let action = bus.handle_bulk_out_complete().unwrap();
        assert_eq!(
            action,
            MsAction::BulkIn {
                endpoint: BULK_IN_EP,
                length: 36,
            }
        );

        // INQUIRY data received → expect BulkIn for 13-byte CSW.
        let action = bus
            .handle_bulk_in_complete(&make_inquiry_response())
            .unwrap();
        assert_eq!(
            action,
            MsAction::BulkIn {
                endpoint: BULK_IN_EP,
                length: 13,
            }
        );

        // CSW received → should advance to TEST UNIT READY (next BulkOut).
        let action = bus.handle_bulk_in_complete(&make_csw(tag)).unwrap();
        assert_eq!(extract_opcode(&action), 0x00); // SCSI_TEST_UNIT_READY
    }

    #[test]
    fn init_test_unit_ready_no_data_phase() {
        let mut bus = make_bus();
        // Drive through INQUIRY.
        let cbw = bus.start_init().unwrap();
        let inq_tag = extract_tag(&cbw);
        bus.handle_bulk_out_complete().unwrap();
        bus.handle_bulk_in_complete(&make_inquiry_response())
            .unwrap();
        let tur_action = bus.handle_bulk_in_complete(&make_csw(inq_tag)).unwrap();
        let tur_tag = extract_tag(&tur_action);

        // TUR CBW sent → no data phase, goes straight to CSW.
        let action = bus.handle_bulk_out_complete().unwrap();
        assert_eq!(
            action,
            MsAction::BulkIn {
                endpoint: BULK_IN_EP,
                length: 13,
            }
        );

        // CSW received → should advance to READ CAPACITY.
        let action = bus.handle_bulk_in_complete(&make_csw(tur_tag)).unwrap();
        assert_eq!(extract_opcode(&action), 0x25); // SCSI_READ_CAPACITY_10
    }

    #[test]
    fn init_read_capacity_returns_init_complete() {
        let mut bus = make_bus();
        // Drive through INQUIRY + TUR.
        let cbw = bus.start_init().unwrap();
        let tag1 = extract_tag(&cbw);
        bus.handle_bulk_out_complete().unwrap();
        bus.handle_bulk_in_complete(&make_inquiry_response())
            .unwrap();
        let tur = bus.handle_bulk_in_complete(&make_csw(tag1)).unwrap();
        let tag2 = extract_tag(&tur);
        bus.handle_bulk_out_complete().unwrap();
        let rc_cbw = bus.handle_bulk_in_complete(&make_csw(tag2)).unwrap();
        let tag3 = extract_tag(&rc_cbw);

        // READ CAPACITY CBW sent → expect BulkIn for 8-byte data.
        let action = bus.handle_bulk_out_complete().unwrap();
        assert_eq!(
            action,
            MsAction::BulkIn {
                endpoint: BULK_IN_EP,
                length: 8,
            }
        );

        // Data received → expect CSW.
        let action = bus
            .handle_bulk_in_complete(&make_read_capacity_response())
            .unwrap();
        assert_eq!(
            action,
            MsAction::BulkIn {
                endpoint: BULK_IN_EP,
                length: 13,
            }
        );

        // CSW → InitComplete.
        let action = bus.handle_bulk_in_complete(&make_csw(tag3)).unwrap();
        assert_eq!(
            action,
            MsAction::InitComplete {
                block_size: 512,
                capacity_blocks: 1000, // last_lba(999) + 1
            }
        );

        // Verify cached values.
        assert_eq!(bus.block_size(), 512);
        assert_eq!(bus.capacity_blocks(), 1000);
    }

    /// Helper: drive a bus through the full init sequence to Ready state.
    fn init_bus(bus: &mut MassStorageBus) {
        let cbw = bus.start_init().unwrap();
        let tag1 = extract_tag(&cbw);
        bus.handle_bulk_out_complete().unwrap();
        bus.handle_bulk_in_complete(&make_inquiry_response())
            .unwrap();
        let tur = bus.handle_bulk_in_complete(&make_csw(tag1)).unwrap();
        let tag2 = extract_tag(&tur);
        bus.handle_bulk_out_complete().unwrap();
        let rc = bus.handle_bulk_in_complete(&make_csw(tag2)).unwrap();
        let tag3 = extract_tag(&rc);
        bus.handle_bulk_out_complete().unwrap();
        bus.handle_bulk_in_complete(&make_read_capacity_response())
            .unwrap();
        bus.handle_bulk_in_complete(&make_csw(tag3)).unwrap();
    }

    #[test]
    fn full_init_sequence() {
        let mut bus = make_bus();
        init_bus(&mut bus);
        assert_eq!(bus.block_size(), 512);
        assert_eq!(bus.capacity_blocks(), 1000);
    }

    #[test]
    fn start_read_before_init_fails() {
        let mut bus = make_bus();
        assert_eq!(bus.start_read(0), Err(MsError::InvalidState));
    }

    // ── Read tests ──────────────────────────────────────────────

    #[test]
    fn read_sequence() {
        let mut bus = make_bus();
        init_bus(&mut bus);

        let cbw_action = bus.start_read(42).unwrap();
        let tag = extract_tag(&cbw_action);
        assert_eq!(extract_opcode(&cbw_action), 0x28); // SCSI_READ_10

        // Verify LBA is 42 in big-endian at CDB[2..6] = CBW[17..21].
        match &cbw_action {
            MsAction::BulkOut { data, .. } => {
                let lba = u32::from_be_bytes([data[17], data[18], data[19], data[20]]);
                assert_eq!(lba, 42);
            }
            _ => panic!("expected BulkOut"),
        }

        // CBW sent → BulkIn for 512-byte data.
        let action = bus.handle_bulk_out_complete().unwrap();
        assert_eq!(
            action,
            MsAction::BulkIn {
                endpoint: BULK_IN_EP,
                length: 512,
            }
        );

        // Data received → BulkIn for CSW.
        let sector_data = vec![0xAAu8; 512];
        let action = bus.handle_bulk_in_complete(&sector_data).unwrap();
        assert_eq!(
            action,
            MsAction::BulkIn {
                endpoint: BULK_IN_EP,
                length: 13,
            }
        );

        // CSW → ReadComplete with sector data.
        let action = bus.handle_bulk_in_complete(&make_csw(tag)).unwrap();
        assert_eq!(action, MsAction::ReadComplete(vec![0xAAu8; 512]));
    }

    #[test]
    fn read_csw_failed_status() {
        let mut bus = make_bus();
        init_bus(&mut bus);

        let cbw_action = bus.start_read(0).unwrap();
        let tag = extract_tag(&cbw_action);
        bus.handle_bulk_out_complete().unwrap();
        bus.handle_bulk_in_complete(&vec![0u8; 512]).unwrap();

        let result = bus.handle_bulk_in_complete(&make_csw_with_status(tag, 1));
        assert_eq!(result, Err(MsError::CommandFailed { status: 1 }));
    }

    #[test]
    fn read_csw_invalid_signature() {
        let mut bus = make_bus();
        init_bus(&mut bus);

        bus.start_read(0).unwrap();
        bus.handle_bulk_out_complete().unwrap();
        bus.handle_bulk_in_complete(&vec![0u8; 512]).unwrap();

        let garbage_csw = vec![0xFFu8; 13];
        let result = bus.handle_bulk_in_complete(&garbage_csw);
        assert_eq!(result, Err(MsError::InvalidCsw));
    }

    #[test]
    fn multiple_sequential_reads() {
        let mut bus = make_bus();
        init_bus(&mut bus);

        // Read 1.
        let cbw1 = bus.start_read(10).unwrap();
        let tag1 = extract_tag(&cbw1);
        bus.handle_bulk_out_complete().unwrap();
        bus.handle_bulk_in_complete(&vec![0x11u8; 512]).unwrap();
        let result1 = bus.handle_bulk_in_complete(&make_csw(tag1)).unwrap();
        assert_eq!(result1, MsAction::ReadComplete(vec![0x11u8; 512]));

        // Read 2 — tag should increment.
        let cbw2 = bus.start_read(20).unwrap();
        let tag2 = extract_tag(&cbw2);
        assert!(tag2 > tag1);
        bus.handle_bulk_out_complete().unwrap();
        bus.handle_bulk_in_complete(&vec![0x22u8; 512]).unwrap();
        let result2 = bus.handle_bulk_in_complete(&make_csw(tag2)).unwrap();
        assert_eq!(result2, MsAction::ReadComplete(vec![0x22u8; 512]));
    }

    #[test]
    fn double_start_read_while_busy() {
        let mut bus = make_bus();
        init_bus(&mut bus);

        bus.start_read(0).unwrap();
        // Bus is now in Reading state — second start_read should fail.
        assert_eq!(bus.start_read(1), Err(MsError::InvalidState));
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel mass_storage_bus -- --nocapture`
Expected: 11 tests pass.

- [ ] **Step 6: Run full workspace tests to check no regressions**

Run: `cargo test --workspace`
Expected: all tests pass (535+ existing + 11 new).

- [ ] **Step 7: Run clippy**

Run: `cargo clippy --workspace --all-targets`
Expected: no warnings.

- [ ] **Step 8: Run nightly rustfmt**

Run: `rustup run nightly cargo fmt --all`
Expected: clean formatting.

- [ ] **Step 9: Commit**

```bash
git add crates/harmony-microkernel/src/mass_storage_bus.rs crates/harmony-microkernel/src/mass_storage_block.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(microkernel): add MassStorageBus sans-I/O state machine

BOT protocol sequencer: INQUIRY → TEST UNIT READY → READ CAPACITY
init, plus READ(10) for block reads. 11 unit tests."
```

---

### Task 2: MassStorageBlockDevice — Transport Trait, BlockDevice Adapter, and Tests

**Files:**
- Modify: `crates/harmony-microkernel/src/mass_storage_block.rs` (replace placeholder)

This task builds the `BulkTransport` trait, `MockBulkTransport`, and `MassStorageBlockDevice<T>` that implements `BlockDevice` by driving the `MassStorageBus`.

**Reference files you'll need to read:**
- `crates/harmony-microkernel/src/mass_storage_bus.rs` — `MassStorageBus`, `MsAction`, `MsError` (from Task 1)
- `crates/harmony-microkernel/src/block_device.rs` — `BlockDevice` trait: `read_block(&mut self, lba: u32, buf: &mut [u8; 512]) -> Result<(), IpcError>`, `capacity_blocks(&self) -> u32`
- `crates/harmony-microkernel/src/lib.rs` — `IpcError` enum

**Key types from Task 1:**
- `MassStorageBus::new(slot_id, bulk_in_ep, bulk_out_ep)`
- `bus.start_init() -> Result<MsAction, MsError>`
- `bus.start_read(lba) -> Result<MsAction, MsError>`
- `bus.handle_bulk_out_complete() -> Result<MsAction, MsError>`
- `bus.handle_bulk_in_complete(data) -> Result<MsAction, MsError>`
- `bus.capacity_blocks() -> u32`
- `MsAction::BulkOut { endpoint: u8, data: [u8; 31] }`
- `MsAction::BulkIn { endpoint: u8, length: u16 }`
- `MsAction::InitComplete { block_size, capacity_blocks }`
- `MsAction::ReadComplete(Vec<u8>)`

- [ ] **Step 1: Write the full module**

Replace the placeholder `crates/harmony-microkernel/src/mass_storage_block.rs` with:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! USB mass storage [`BlockDevice`] adapter.
//!
//! Provides a [`BulkTransport`] trait for abstracting bulk transfer
//! execution, and [`MassStorageBlockDevice`] which implements
//! [`BlockDevice`] by driving a [`MassStorageBus`] through the transport.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::block_device::BlockDevice;
use crate::mass_storage_bus::{MassStorageBus, MsAction, MsError};
use crate::IpcError;

// ── BulkTransport trait ─────────────────────────────────────────

/// Abstraction for executing USB bulk transfers.
///
/// Real implementations wrap the xHCI driver. Test implementations
/// return canned responses.
pub trait BulkTransport {
    /// Send data via bulk OUT to the given endpoint.
    fn bulk_out(&mut self, endpoint: u8, data: &[u8]) -> Result<(), IpcError>;

    /// Receive data via bulk IN from the given endpoint.
    /// `buf` is pre-sized to the expected length. Returns the number
    /// of bytes actually received.
    fn bulk_in(&mut self, endpoint: u8, buf: &mut [u8]) -> Result<usize, IpcError>;
}

// ── MassStorageBlockDevice ──────────────────────────────────────

/// Implements [`BlockDevice`] for a USB mass storage device.
///
/// Drives a [`MassStorageBus`] state machine through a [`BulkTransport`]
/// to execute BOT protocol transfers.
pub struct MassStorageBlockDevice<T: BulkTransport> {
    bus: MassStorageBus,
    transport: T,
}

impl<T: BulkTransport> MassStorageBlockDevice<T> {
    /// Create a new mass storage block device.
    ///
    /// Call [`init`] before using as a `BlockDevice`.
    pub fn new(slot_id: u8, bulk_in_ep: u8, bulk_out_ep: u8, transport: T) -> Self {
        Self {
            bus: MassStorageBus::new(slot_id, bulk_in_ep, bulk_out_ep),
            transport,
        }
    }

    /// Initialize the device: INQUIRY → TEST UNIT READY → READ CAPACITY.
    ///
    /// Must be called before `read_block`. Drives the bus state machine
    /// through the full init sequence using the transport.
    pub fn init(&mut self) -> Result<(), IpcError> {
        let mut action = self.bus.start_init().map_err(ms_to_ipc)?;
        loop {
            match action {
                MsAction::BulkOut { endpoint, data } => {
                    self.transport.bulk_out(endpoint, &data)?;
                    action = self.bus.handle_bulk_out_complete().map_err(ms_to_ipc)?;
                }
                MsAction::BulkIn { endpoint, length } => {
                    let mut buf = vec![0u8; length as usize];
                    let n = self.transport.bulk_in(endpoint, &mut buf)?;
                    buf.truncate(n);
                    action = self.bus.handle_bulk_in_complete(&buf).map_err(ms_to_ipc)?;
                }
                MsAction::InitComplete { .. } => return Ok(()),
                MsAction::ReadComplete(_) => {
                    // Should not happen during init.
                    return Err(IpcError::InvalidArgument);
                }
            }
        }
    }
}

impl<T: BulkTransport> BlockDevice for MassStorageBlockDevice<T> {
    fn read_block(&mut self, lba: u32, buf: &mut [u8; 512]) -> Result<(), IpcError> {
        let mut action = self.bus.start_read(lba).map_err(ms_to_ipc)?;
        loop {
            match action {
                MsAction::BulkOut { endpoint, data } => {
                    self.transport.bulk_out(endpoint, &data)?;
                    action = self.bus.handle_bulk_out_complete().map_err(ms_to_ipc)?;
                }
                MsAction::BulkIn { endpoint, length } => {
                    let mut recv_buf = vec![0u8; length as usize];
                    let n = self.transport.bulk_in(endpoint, &mut recv_buf)?;
                    recv_buf.truncate(n);
                    action = self
                        .bus
                        .handle_bulk_in_complete(&recv_buf)
                        .map_err(ms_to_ipc)?;
                }
                MsAction::ReadComplete(data) => {
                    let copy_len = data.len().min(512);
                    buf[..copy_len].copy_from_slice(&data[..copy_len]);
                    return Ok(());
                }
                MsAction::InitComplete { .. } => {
                    // Should not happen during read.
                    return Err(IpcError::InvalidArgument);
                }
            }
        }
    }

    fn capacity_blocks(&self) -> u32 {
        self.bus.capacity_blocks()
    }
}

/// Map `MsError` to `IpcError` for the `BlockDevice` interface.
fn ms_to_ipc(e: MsError) -> IpcError {
    match e {
        MsError::InvalidState => IpcError::InvalidArgument,
        MsError::CommandFailed { .. } => IpcError::NotFound,
        MsError::InvalidCsw => IpcError::InvalidArgument,
        MsError::ResponseTooShort => IpcError::InvalidArgument,
    }
}

// ── MockBulkTransport ───────────────────────────────────────────

/// Test-only bulk transport that returns pre-queued responses.
#[cfg(test)]
pub(crate) struct MockBulkTransport {
    /// Records all data sent via `bulk_out`.
    pub out_log: Vec<Vec<u8>>,
    /// Pre-queued responses for `bulk_in` calls (FIFO).
    pub in_responses: alloc::collections::VecDeque<Vec<u8>>,
}

#[cfg(test)]
impl MockBulkTransport {
    pub fn new() -> Self {
        Self {
            out_log: Vec::new(),
            in_responses: alloc::collections::VecDeque::new(),
        }
    }

    /// Queue a response that will be returned by the next `bulk_in` call.
    pub fn queue_response(&mut self, data: Vec<u8>) {
        self.in_responses.push_back(data);
    }
}

#[cfg(test)]
impl BulkTransport for MockBulkTransport {
    fn bulk_out(&mut self, _endpoint: u8, data: &[u8]) -> Result<(), IpcError> {
        self.out_log.push(data.to_vec());
        Ok(())
    }

    fn bulk_in(&mut self, _endpoint: u8, buf: &mut [u8]) -> Result<usize, IpcError> {
        let response = self
            .in_responses
            .pop_front()
            .ok_or(IpcError::NotFound)?;
        let copy_len = response.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&response[..copy_len]);
        Ok(copy_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOT_ID: u8 = 1;
    const BULK_IN_EP: u8 = 5;
    const BULK_OUT_EP: u8 = 4;
    const CSW_SIGNATURE: u32 = 0x5342_5355;

    fn make_csw(tag: u32) -> Vec<u8> {
        let mut csw = vec![0u8; 13];
        csw[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        csw[4..8].copy_from_slice(&tag.to_le_bytes());
        csw
    }

    fn make_csw_with_status(tag: u32, status: u8) -> Vec<u8> {
        let mut csw = make_csw(tag);
        csw[12] = status;
        csw
    }

    fn make_inquiry_response() -> Vec<u8> {
        let mut data = vec![0u8; 36];
        data[0] = 0x00;
        data[1] = 0x80;
        data
    }

    fn make_read_capacity_response() -> Vec<u8> {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&999u32.to_be_bytes());
        data[4..8].copy_from_slice(&512u32.to_be_bytes());
        data
    }

    /// Extract CBW tag from the Nth bulk OUT in the log.
    fn out_log_tag(mock: &MockBulkTransport, index: usize) -> u32 {
        let cbw = &mock.out_log[index];
        u32::from_le_bytes([cbw[4], cbw[5], cbw[6], cbw[7]])
    }

    /// Extract SCSI opcode from the Nth bulk OUT in the log.
    fn out_log_opcode(mock: &MockBulkTransport, index: usize) -> u8 {
        mock.out_log[index][15]
    }

    /// Queue the full init sequence responses into the mock transport.
    /// Returns the tags that will be in the CBWs (predicted from
    /// MassStorageDevice's auto-incrementing counter starting at 1).
    fn queue_init_responses(mock: &mut MockBulkTransport) {
        // INQUIRY: data(36) + CSW
        mock.queue_response(make_inquiry_response());
        mock.queue_response(make_csw(1));
        // TEST UNIT READY: CSW only (no data phase)
        mock.queue_response(make_csw(2));
        // READ CAPACITY: data(8) + CSW
        mock.queue_response(make_read_capacity_response());
        mock.queue_response(make_csw(3));
    }

    fn make_initialized_device() -> MassStorageBlockDevice<MockBulkTransport> {
        let mut mock = MockBulkTransport::new();
        queue_init_responses(&mut mock);
        let mut dev = MassStorageBlockDevice::new(SLOT_ID, BULK_IN_EP, BULK_OUT_EP, mock);
        dev.init().unwrap();
        dev
    }

    // ── Init tests ──────────────────────────────────────────────

    #[test]
    fn init_succeeds() {
        let mut mock = MockBulkTransport::new();
        queue_init_responses(&mut mock);
        let mut dev = MassStorageBlockDevice::new(SLOT_ID, BULK_IN_EP, BULK_OUT_EP, mock);
        dev.init().unwrap();
    }

    #[test]
    fn init_failure_csw_failed() {
        let mut mock = MockBulkTransport::new();
        // INQUIRY succeeds.
        mock.queue_response(make_inquiry_response());
        mock.queue_response(make_csw(1));
        // TEST UNIT READY CSW = failed.
        mock.queue_response(make_csw_with_status(2, 1));
        let mut dev = MassStorageBlockDevice::new(SLOT_ID, BULK_IN_EP, BULK_OUT_EP, mock);
        assert!(dev.init().is_err());
    }

    #[test]
    fn capacity_blocks_after_init() {
        let dev = make_initialized_device();
        assert_eq!(dev.capacity_blocks(), 1000); // last_lba(999) + 1
    }

    // ── Read tests ──────────────────────────────────────────────

    #[test]
    fn read_block_returns_sector_data() {
        let mut dev = make_initialized_device();
        // Queue READ response: 512 bytes data + CSW.
        // After init, next tag is 4.
        let sector = vec![0xBBu8; 512];
        dev.transport.queue_response(sector);
        dev.transport.queue_response(make_csw(4));

        let mut buf = [0u8; 512];
        dev.read_block(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn read_block_verifies_cbw_sent() {
        let mut dev = make_initialized_device();
        let sector = vec![0u8; 512];
        dev.transport.queue_response(sector);
        dev.transport.queue_response(make_csw(4));

        let mut buf = [0u8; 512];
        dev.read_block(42, &mut buf).unwrap();

        // The read CBW is the 4th bulk OUT (after 3 init CBWs).
        assert_eq!(out_log_opcode(&dev.transport, 3), 0x28); // SCSI_READ_10
        // Verify LBA = 42 in big-endian at CDB[2..6] = CBW[17..21].
        let cbw = &dev.transport.out_log[3];
        let lba = u32::from_be_bytes([cbw[17], cbw[18], cbw[19], cbw[20]]);
        assert_eq!(lba, 42);
    }

    #[test]
    fn read_block_before_init_fails() {
        let mock = MockBulkTransport::new();
        let mut dev = MassStorageBlockDevice::new(SLOT_ID, BULK_IN_EP, BULK_OUT_EP, mock);
        let mut buf = [0u8; 512];
        assert!(dev.read_block(0, &mut buf).is_err());
    }

    #[test]
    fn read_block_csw_failure() {
        let mut dev = make_initialized_device();
        let sector = vec![0u8; 512];
        dev.transport.queue_response(sector);
        dev.transport.queue_response(make_csw_with_status(4, 1));

        let mut buf = [0u8; 512];
        assert!(dev.read_block(0, &mut buf).is_err());
    }

    #[test]
    fn sequential_reads() {
        let mut dev = make_initialized_device();

        // Read 1: LBA 10
        dev.transport.queue_response(vec![0x11u8; 512]);
        dev.transport.queue_response(make_csw(4));
        let mut buf1 = [0u8; 512];
        dev.read_block(10, &mut buf1).unwrap();
        assert!(buf1.iter().all(|&b| b == 0x11));

        // Read 2: LBA 20
        dev.transport.queue_response(vec![0x22u8; 512]);
        dev.transport.queue_response(make_csw(5));
        let mut buf2 = [0u8; 512];
        dev.read_block(20, &mut buf2).unwrap();
        assert!(buf2.iter().all(|&b| b == 0x22));

        // Verify both CBWs had correct LBAs.
        let cbw1 = &dev.transport.out_log[3]; // 4th OUT
        let lba1 = u32::from_be_bytes([cbw1[17], cbw1[18], cbw1[19], cbw1[20]]);
        assert_eq!(lba1, 10);
        let cbw2 = &dev.transport.out_log[4]; // 5th OUT
        let lba2 = u32::from_be_bytes([cbw2[17], cbw2[18], cbw2[19], cbw2[20]]);
        assert_eq!(lba2, 20);
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel mass_storage_block -- --nocapture`
Expected: 8 tests pass.

- [ ] **Step 3: Run full workspace tests**

Run: `cargo test --workspace`
Expected: all tests pass (535+ existing + 11 bus + 8 block = 554+).

- [ ] **Step 4: Run clippy**

Run: `cargo clippy --workspace --all-targets`
Expected: no warnings.

- [ ] **Step 5: Run nightly rustfmt**

Run: `rustup run nightly cargo fmt --all`
Expected: clean formatting.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-microkernel/src/mass_storage_block.rs
git commit -m "feat(microkernel): add MassStorageBlockDevice with BulkTransport trait

BlockDevice adapter that drives MassStorageBus through a BulkTransport.
MockBulkTransport for testing. 8 integration tests."
```

---
