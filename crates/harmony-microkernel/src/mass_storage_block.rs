// SPDX-License-Identifier: GPL-2.0-or-later

//! USB mass storage [`BlockDevice`] adapter.
//!
//! Provides a [`BulkTransport`] trait for performing bulk-OUT/IN transfers
//! and a [`MassStorageBlockDevice`] that drives a [`MassStorageBus`] state
//! machine through a caller-supplied transport.

extern crate alloc;

use alloc::vec;

use crate::block_device::BlockDevice;
use crate::mass_storage_bus::{MassStorageBus, MsAction, MsError};
use crate::IpcError;

// ── BulkTransport trait ──────────────────────────────────────────────

/// Transport layer for USB Bulk-Only Transfer.
///
/// Implementors perform the actual hardware (or mock) bulk-OUT and
/// bulk-IN transfers. The [`MassStorageBlockDevice`] uses this trait
/// to drive the [`MassStorageBus`] state machine.
pub trait BulkTransport {
    /// Perform a bulk-OUT transfer: send `data` on `endpoint`.
    fn bulk_out(&mut self, endpoint: u8, data: &[u8]) -> Result<(), IpcError>;

    /// Perform a bulk-IN transfer: receive into `buf` on `endpoint`.
    ///
    /// Returns the number of bytes actually received.
    fn bulk_in(&mut self, endpoint: u8, buf: &mut [u8]) -> Result<usize, IpcError>;
}

// ── Error conversion ─────────────────────────────────────────────────

fn ms_to_ipc(e: MsError) -> IpcError {
    match e {
        MsError::InvalidState => IpcError::InvalidArgument,
        MsError::CommandFailed { .. } => IpcError::NotFound,
        MsError::InvalidCsw => IpcError::InvalidArgument,
        MsError::ResponseTooShort => IpcError::InvalidArgument,
    }
}

// ── MassStorageBlockDevice ───────────────────────────────────────────

/// USB Mass Storage [`BlockDevice`] adapter.
///
/// Wraps a [`MassStorageBus`] and a [`BulkTransport`], providing a
/// synchronous [`BlockDevice`] interface. Call [`Self::init`] once
/// before any reads.
pub struct MassStorageBlockDevice<T: BulkTransport> {
    bus: MassStorageBus,
    transport: T,
}

impl<T: BulkTransport> MassStorageBlockDevice<T> {
    /// Create a new device. Call [`Self::init`] before reading.
    pub fn new(slot_id: u8, bulk_in_ep: u8, bulk_out_ep: u8, transport: T) -> Self {
        Self {
            bus: MassStorageBus::new(slot_id, bulk_in_ep, bulk_out_ep),
            transport,
        }
    }

    /// Drive the bus through the full INQUIRY → TEST UNIT READY →
    /// READ CAPACITY initialization sequence.
    ///
    /// Must be called exactly once before [`BlockDevice::read_block`].
    pub fn init(&mut self) -> Result<(), IpcError> {
        let first = self.bus.start_init().map_err(ms_to_ipc)?;
        self.drive_to_init_complete(first)
    }

    /// Execute a transport operation, resetting the bus if it fails.
    fn transport_out(&mut self, endpoint: u8, data: &[u8]) -> Result<(), IpcError> {
        if let Err(e) = self.transport.bulk_out(endpoint, data) {
            self.bus.reset_after_transport_error();
            return Err(e);
        }
        Ok(())
    }

    /// Execute a transport read, resetting the bus if it fails.
    fn transport_in(&mut self, endpoint: u8, buf: &mut [u8]) -> Result<usize, IpcError> {
        match self.transport.bulk_in(endpoint, buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                self.bus.reset_after_transport_error();
                Err(e)
            }
        }
    }

    /// Drive the bus action loop until `InitComplete` is received.
    fn drive_to_init_complete(&mut self, first_action: MsAction) -> Result<(), IpcError> {
        let mut action = first_action;
        loop {
            action = match action {
                MsAction::BulkOut { endpoint, data } => {
                    self.transport_out(endpoint, &data)?;
                    self.bus.handle_bulk_out_complete().map_err(ms_to_ipc)?
                }
                MsAction::BulkIn { endpoint, length } => {
                    let mut buf = vec![0u8; length as usize];
                    let n = self.transport_in(endpoint, &mut buf)?;
                    buf.truncate(n);
                    self.bus.handle_bulk_in_complete(&buf).map_err(ms_to_ipc)?
                }
                MsAction::InitComplete { .. } => return Ok(()),
                MsAction::ReadComplete(_) => {
                    unreachable!("ReadComplete during init sequence")
                }
            };
        }
    }

    /// Drive the bus action loop until `ReadComplete` is received,
    /// copying the sector data into `buf`.
    fn drive_to_read_complete(
        &mut self,
        first_action: MsAction,
        buf: &mut [u8; 512],
    ) -> Result<(), IpcError> {
        let mut action = first_action;
        loop {
            action = match action {
                MsAction::BulkOut { endpoint, data } => {
                    self.transport_out(endpoint, &data)?;
                    self.bus.handle_bulk_out_complete().map_err(ms_to_ipc)?
                }
                MsAction::BulkIn { endpoint, length } => {
                    let mut recv = vec![0u8; length as usize];
                    let n = self.transport_in(endpoint, &mut recv)?;
                    recv.truncate(n);
                    self.bus.handle_bulk_in_complete(&recv).map_err(ms_to_ipc)?
                }
                MsAction::ReadComplete(data) => {
                    if data.len() != 512 {
                        return Err(IpcError::InvalidArgument);
                    }
                    buf.copy_from_slice(&data);
                    return Ok(());
                }
                MsAction::InitComplete { .. } => {
                    unreachable!("InitComplete during read sequence")
                }
            };
        }
    }
}

impl<T: BulkTransport> BlockDevice for MassStorageBlockDevice<T> {
    fn read_block(&mut self, lba: u32, buf: &mut [u8; 512]) -> Result<(), IpcError> {
        let first = self.bus.start_read(lba).map_err(ms_to_ipc)?;
        self.drive_to_read_complete(first, buf)
    }

    fn capacity_blocks(&self) -> u32 {
        self.bus.capacity_blocks()
    }
}

// ── MockBulkTransport ────────────────────────────────────────────────

#[cfg(test)]
pub(crate) struct MockBulkTransport {
    pub out_log: Vec<Vec<u8>>,
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
        let response = self.in_responses.pop_front().ok_or(IpcError::NotFound)?;
        let n = response.len().min(buf.len());
        buf[..n].copy_from_slice(&response[..n]);
        Ok(n)
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// CSW signature "USBS" in little-endian.
    const CSW_SIGNATURE: u32 = 0x5342_5355;

    fn make_csw(tag: u32) -> Vec<u8> {
        make_csw_with_status(tag, 0)
    }

    fn make_csw_with_status(tag: u32, status: u8) -> Vec<u8> {
        let mut csw = vec![0u8; 13];
        csw[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        csw[4..8].copy_from_slice(&tag.to_le_bytes());
        csw[8..12].copy_from_slice(&0u32.to_le_bytes());
        csw[12] = status;
        csw
    }

    fn make_inquiry_response() -> Vec<u8> {
        let mut resp = vec![0u8; 36];
        resp[0] = 0x00; // direct-access block device
        resp[1] = 0x80; // removable media
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

    /// Extract the CBW tag from the Nth OUT transfer (CBW bytes 4–7, LE).
    fn out_log_tag(mock: &MockBulkTransport, index: usize) -> u32 {
        let data = &mock.out_log[index];
        u32::from_le_bytes([data[4], data[5], data[6], data[7]])
    }

    /// Extract the SCSI opcode from the Nth OUT transfer (CBW byte 15).
    fn out_log_opcode(mock: &MockBulkTransport, index: usize) -> u8 {
        mock.out_log[index][15]
    }

    /// Queue all 3 init responses into `mock`:
    ///   - INQUIRY data (36 bytes) + CSW (tag=1)
    ///   - TUR CSW (tag=2, no data phase)
    ///   - READ CAPACITY data (8 bytes) + CSW (tag=3)
    fn queue_init_responses(mock: &mut MockBulkTransport) {
        // INQUIRY data + CSW (tag=1)
        mock.queue_response(make_inquiry_response());
        mock.queue_response(make_csw(1));
        // TUR CSW (no data phase, tag=2)
        mock.queue_response(make_csw(2));
        // READ CAPACITY data + CSW (tag=3)
        mock.queue_response(make_read_capacity_response());
        mock.queue_response(make_csw(3));
    }

    /// Create a fully initialized device ready for reads.
    fn make_initialized_device() -> MassStorageBlockDevice<MockBulkTransport> {
        let mut mock = MockBulkTransport::new();
        queue_init_responses(&mut mock);
        let mut dev = MassStorageBlockDevice::new(1, 5, 4, mock);
        dev.init().expect("init should succeed");
        dev
    }

    // ── Test 12 ─────────────────────────────────────────────────────

    #[test]
    fn init_succeeds() {
        let mut mock = MockBulkTransport::new();
        queue_init_responses(&mut mock);
        let mut dev = MassStorageBlockDevice::new(1, 5, 4, mock);
        assert!(dev.init().is_ok());
    }

    // ── Test 13 ─────────────────────────────────────────────────────

    #[test]
    fn init_failure_csw_failed() {
        let mut mock = MockBulkTransport::new();
        // INQUIRY data + CSW ok
        mock.queue_response(make_inquiry_response());
        mock.queue_response(make_csw(1));
        // TUR CSW with failure status=1
        mock.queue_response(make_csw_with_status(2, 1));
        let mut dev = MassStorageBlockDevice::new(1, 5, 4, mock);
        assert_eq!(dev.init(), Err(IpcError::NotFound));
    }

    // ── Test 14 ─────────────────────────────────────────────────────

    #[test]
    fn capacity_blocks_after_init() {
        let dev = make_initialized_device();
        // last_lba=999, so capacity=1000
        assert_eq!(dev.capacity_blocks(), 1000);
    }

    // ── Test 15 ─────────────────────────────────────────────────────

    #[test]
    fn read_block_returns_sector_data() {
        let mut dev = make_initialized_device();
        // Queue 512 bytes of 0xBB + CSW tag=4
        dev.transport.queue_response(vec![0xBBu8; 512]);
        dev.transport.queue_response(make_csw(4));

        let mut buf = [0u8; 512];
        dev.read_block(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB));
    }

    // ── Test 16 ─────────────────────────────────────────────────────

    #[test]
    fn read_block_verifies_cbw_sent() {
        let mut dev = make_initialized_device();
        dev.transport.queue_response(vec![0u8; 512]);
        dev.transport.queue_response(make_csw(4));

        let mut buf = [0u8; 512];
        dev.read_block(42, &mut buf).unwrap();

        // out_log[3] is the 4th OUT (index 3): INQUIRY, TUR, RC, READ
        assert_eq!(out_log_opcode(&dev.transport, 3), 0x28, "READ(10) opcode");
        // LBA 42 = 0x0000_002A, big-endian at CBW bytes 17..21
        let lba_bytes = &dev.transport.out_log[3][17..21];
        assert_eq!(lba_bytes, &42u32.to_be_bytes());
    }

    // ── Test 17 ─────────────────────────────────────────────────────

    #[test]
    fn read_block_before_init_fails() {
        let mock = MockBulkTransport::new();
        let mut dev = MassStorageBlockDevice::new(1, 5, 4, mock);
        let mut buf = [0u8; 512];
        assert_eq!(
            dev.read_block(0, &mut buf),
            Err(IpcError::InvalidArgument),
            "read before init should fail"
        );
    }

    // ── Test 18 ─────────────────────────────────────────────────────

    #[test]
    fn read_block_csw_failure() {
        let mut dev = make_initialized_device();
        dev.transport.queue_response(vec![0u8; 512]);
        dev.transport.queue_response(make_csw_with_status(4, 1));

        let mut buf = [0u8; 512];
        assert_eq!(dev.read_block(0, &mut buf), Err(IpcError::NotFound));
    }

    // ── Test 19 ─────────────────────────────────────────────────────

    #[test]
    fn sequential_reads() {
        let mut dev = make_initialized_device();

        // First read: LBA 10, data=0xAA
        dev.transport.queue_response(vec![0xAAu8; 512]);
        dev.transport.queue_response(make_csw(4));
        let mut buf1 = [0u8; 512];
        dev.read_block(10, &mut buf1).unwrap();
        assert!(buf1.iter().all(|&b| b == 0xAA));

        // Second read: LBA 20, data=0xCC, tag=5
        dev.transport.queue_response(vec![0xCCu8; 512]);
        dev.transport.queue_response(make_csw(5));
        let mut buf2 = [0u8; 512];
        dev.read_block(20, &mut buf2).unwrap();
        assert!(buf2.iter().all(|&b| b == 0xCC));

        // Verify LBAs in CBW out_log (index 3 = first read, index 4 = second read)
        let lba1 = &dev.transport.out_log[3][17..21];
        assert_eq!(lba1, &10u32.to_be_bytes(), "first read LBA");
        let lba2 = &dev.transport.out_log[4][17..21];
        assert_eq!(lba2, &20u32.to_be_bytes(), "second read LBA");

        // Verify tags auto-incremented
        let tag1 = out_log_tag(&dev.transport, 3);
        let tag2 = out_log_tag(&dev.transport, 4);
        assert!(tag2 > tag1, "tags should increment: {tag1} < {tag2}");
    }

    // ── Test 20 ─────────────────────────────────────────────────────

    #[test]
    fn read_recovers_after_transport_error() {
        let mut dev = make_initialized_device();

        // First read — transport fails on data bulk IN (no response queued).
        dev.transport.queue_response(vec![0u8; 512]); // data phase
                                                      // No CSW queued — the data-phase read will succeed, but CSW read
                                                      // will fail because in_responses is empty.
        let mut buf = [0u8; 512];
        assert!(dev.read_block(0, &mut buf).is_err());

        // Second read should succeed — bus was reset by transport error.
        dev.transport.queue_response(vec![0xAAu8; 512]);
        dev.transport.queue_response(make_csw(5)); // tag 5: init used 1-3, failed read used 4
        let mut buf2 = [0u8; 512];
        dev.read_block(1, &mut buf2).unwrap();
        assert!(buf2.iter().all(|&b| b == 0xAA));
    }
}
