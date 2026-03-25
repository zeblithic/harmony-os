// SPDX-License-Identifier: GPL-2.0-or-later

//! USB Mass Storage Bulk-Only Transport (BBB) class driver.
//!
//! This is a sans-I/O driver: it builds CBW byte arrays and parses
//! CSW/SCSI responses. The caller is responsible for orchestrating
//! the actual bulk transfers via the xHCI driver.
//!
//! ## Protocol Overview
//!
//! Every USB mass storage operation consists of:
//! 1. **CBW** (Command Block Wrapper, 31 bytes) — sent as bulk OUT
//! 2. **Data phase** (optional) — bulk IN or OUT depending on command
//! 3. **CSW** (Command Status Wrapper, 13 bytes) — received as bulk IN
//!
//! ## Usage Example (READ)
//!
//! ```rust,ignore
//! let mut dev = MassStorageDevice::new(slot_id, bulk_in_ep, bulk_out_ep);
//! let (cbw, _dir, _len) = dev.build_read_cbw(lba, 1);
//! // Caller: bulk_out(cbw), bulk_in(512 bytes), bulk_in(13 bytes → csw)
//! let csw = parse_csw(&csw_buf)?;
//! ```

// ── CBW/CSW constants ────────────────────────────────────────────

/// CBW signature "USBC" in little-endian.
const CBW_SIGNATURE: u32 = 0x4342_5355;

/// CSW signature "USBS" in little-endian.
const CSW_SIGNATURE: u32 = 0x5342_5355;

/// Direction flag for bulk IN (device-to-host).
const CBW_FLAG_IN: u8 = 0x80;

/// Direction flag for bulk OUT (host-to-device).
const CBW_FLAG_OUT: u8 = 0x00;

// ── SCSI opcodes ─────────────────────────────────────────────────

const SCSI_INQUIRY: u8 = 0x12;
const SCSI_TEST_UNIT_READY: u8 = 0x00;
const SCSI_READ_CAPACITY_10: u8 = 0x25;
const SCSI_READ_10: u8 = 0x28;
const SCSI_WRITE_10: u8 = 0x2A;
const SCSI_REQUEST_SENSE: u8 = 0x03;
const SCSI_MODE_SENSE_6: u8 = 0x1A;

// ── Types ────────────────────────────────────────────────────────

/// Data transfer direction for the data phase of a CBW.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDirection {
    /// Device-to-host (bulk IN).
    In,
    /// Host-to-device (bulk OUT).
    Out,
    /// No data phase.
    None,
}

/// A USB mass storage device using Bulk-Only Transport (BBB).
///
/// Tracks connection endpoints and the monotonic CBW tag counter.
/// All transfer scheduling is performed by the caller.
pub struct MassStorageDevice {
    /// xHCI slot ID for this device.
    pub slot_id: u8,
    /// Bulk IN endpoint DCI (e.g. 5 for EP2 IN).
    pub bulk_in_ep: u8,
    /// Bulk OUT endpoint DCI (e.g. 4 for EP2 OUT).
    pub bulk_out_ep: u8,
    /// Next CBW tag value (starts at 1, auto-increments).
    next_tag: u32,
}

/// Parsed Command Status Wrapper (CSW).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CswStatus {
    /// Tag from the corresponding CBW.
    pub tag: u32,
    /// Number of bytes not transferred (dCSWDataResidue).
    pub data_residue: u32,
    /// Status code: 0 = Passed, 1 = Failed, 2 = Phase Error.
    pub status: u8,
}

/// Parsed SCSI INQUIRY response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InquiryResponse {
    /// Peripheral device type (data[0] & 0x1F).
    pub peripheral_type: u8,
    /// Removable media bit (data[1] & 0x80).
    pub removable: bool,
    /// Vendor identification string (bytes 8–15).
    pub vendor: [u8; 8],
    /// Product identification string (bytes 16–31).
    pub product: [u8; 16],
    /// Product revision level (bytes 32–35).
    pub revision: [u8; 4],
}

/// Parsed SCSI REQUEST SENSE data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenseData {
    /// Sense key (data[2] & 0x0F).
    pub sense_key: u8,
    /// Additional Sense Code (data[12]).
    pub asc: u8,
    /// Additional Sense Code Qualifier (data[13]).
    pub ascq: u8,
}

/// Parsed SCSI MODE SENSE(6) response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeSenseData {
    /// Write-protect bit from device-specific parameter byte (data[2] & 0x80).
    pub write_protected: bool,
    /// Mode data length field (data[0]).
    pub mode_data_length: u8,
}

/// Errors from mass storage driver operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MassStorageError {
    /// CSW signature is not 0x53425355 ("USBS").
    InvalidCsw,
    /// CSW tag does not match the expected CBW tag.
    CswTagMismatch {
        /// Tag value sent in the CBW.
        expected: u32,
        /// Tag value received in the CSW.
        got: u32,
    },
    /// Command failed: status 1 (Failed) or 2 (Phase Error).
    CommandFailed {
        /// The raw bCSWStatus value.
        status: u8,
    },
    /// Response buffer is shorter than the required minimum.
    ResponseTooShort,
}

// ── MassStorageDevice ────────────────────────────────────────────

impl MassStorageDevice {
    /// Create a new mass storage device handle.
    ///
    /// `slot_id` is the xHCI slot, `bulk_in_ep` and `bulk_out_ep` are
    /// endpoint DCIs. The CBW tag counter starts at 1.
    pub fn new(slot_id: u8, bulk_in_ep: u8, bulk_out_ep: u8) -> Self {
        Self {
            slot_id,
            bulk_in_ep,
            bulk_out_ep,
            next_tag: 1,
        }
    }

    /// Build a raw 31-byte Command Block Wrapper (CBW).
    ///
    /// Fills the CBW fields, zero-pads the SCSI command to 16 bytes,
    /// and increments `next_tag` for the next call.
    fn build_cbw(&mut self, command: &[u8], data_len: u32, direction: DataDirection) -> [u8; 31] {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1);

        let flags = match direction {
            DataDirection::In => CBW_FLAG_IN,
            DataDirection::Out | DataDirection::None => CBW_FLAG_OUT,
        };

        let cb_len = command.len() as u8;

        let mut cbw = [0u8; 31];

        // dCBWSignature (LE)
        cbw[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
        // dCBWTag (LE)
        cbw[4..8].copy_from_slice(&tag.to_le_bytes());
        // dCBWDataTransferLength (LE)
        cbw[8..12].copy_from_slice(&data_len.to_le_bytes());
        // bmCBWFlags
        cbw[12] = flags;
        // bCBWLUN — always 0
        cbw[13] = 0;
        // bCBWCBLength
        cbw[14] = cb_len;
        // CBWCB[16] — SCSI command, zero-padded
        let copy_len = command.len().min(16);
        cbw[15..15 + copy_len].copy_from_slice(&command[..copy_len]);

        cbw
    }

    // ── CBW builders ─────────────────────────────────────────────

    /// Build a SCSI INQUIRY CBW.
    ///
    /// Returns `(cbw, DataDirection::In, 36)`.
    pub fn build_inquiry_cbw(&mut self) -> ([u8; 31], DataDirection, u32) {
        // INQUIRY CDB: opcode, flags=0, page=0, alloc_len=36, control=0
        let cdb = [SCSI_INQUIRY, 0x00, 0x00, 0x00, 36u8, 0x00];
        let cbw = self.build_cbw(&cdb, 36, DataDirection::In);
        (cbw, DataDirection::In, 36)
    }

    /// Build a SCSI TEST UNIT READY CBW.
    ///
    /// Returns `(cbw, DataDirection::None, 0)`.
    pub fn build_test_unit_ready_cbw(&mut self) -> ([u8; 31], DataDirection, u32) {
        let cdb = [SCSI_TEST_UNIT_READY, 0x00, 0x00, 0x00, 0x00, 0x00];
        let cbw = self.build_cbw(&cdb, 0, DataDirection::None);
        (cbw, DataDirection::None, 0)
    }

    /// Build a SCSI READ CAPACITY(10) CBW.
    ///
    /// Returns `(cbw, DataDirection::In, 8)`.
    pub fn build_read_capacity_cbw(&mut self) -> ([u8; 31], DataDirection, u32) {
        // READ CAPACITY(10): 10-byte CDB, all zeros except opcode
        let cdb = [SCSI_READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let cbw = self.build_cbw(&cdb, 8, DataDirection::In);
        (cbw, DataDirection::In, 8)
    }

    /// Build a SCSI READ(10) CBW.
    ///
    /// `lba` is the starting logical block address (big-endian in CDB).
    /// `sector_count` is the number of 512-byte sectors to read.
    ///
    /// Returns `(cbw, DataDirection::In, sector_count * 512)`.
    pub fn build_read_cbw(
        &mut self,
        lba: u32,
        sector_count: u16,
    ) -> ([u8; 31], DataDirection, u32) {
        let data_len = u32::from(sector_count) * 512;
        let lba_bytes = lba.to_be_bytes();
        let count_bytes = sector_count.to_be_bytes();
        // READ(10) CDB layout:
        //   [0]     opcode
        //   [1]     flags (RDPROTECT, DPO, FUA, etc.) — 0
        //   [2..6]  LBA (big-endian)
        //   [6]     group number — 0
        //   [7..9]  transfer length (big-endian)
        //   [9]     control — 0
        let cdb = [
            SCSI_READ_10,
            0x00,
            lba_bytes[0],
            lba_bytes[1],
            lba_bytes[2],
            lba_bytes[3],
            0x00,
            count_bytes[0],
            count_bytes[1],
            0x00,
        ];
        let cbw = self.build_cbw(&cdb, data_len, DataDirection::In);
        (cbw, DataDirection::In, data_len)
    }

    /// Build a SCSI WRITE(10) CBW.
    ///
    /// `lba` is the starting logical block address (big-endian in CDB).
    /// `sector_count` is the number of 512-byte sectors to write.
    ///
    /// Returns `(cbw, DataDirection::Out, sector_count * 512)`.
    pub fn build_write_cbw(
        &mut self,
        lba: u32,
        sector_count: u16,
    ) -> ([u8; 31], DataDirection, u32) {
        let data_len = u32::from(sector_count) * 512;
        let lba_bytes = lba.to_be_bytes();
        let count_bytes = sector_count.to_be_bytes();
        // WRITE(10) CDB layout identical to READ(10) except opcode
        let cdb = [
            SCSI_WRITE_10,
            0x00,
            lba_bytes[0],
            lba_bytes[1],
            lba_bytes[2],
            lba_bytes[3],
            0x00,
            count_bytes[0],
            count_bytes[1],
            0x00,
        ];
        let cbw = self.build_cbw(&cdb, data_len, DataDirection::Out);
        (cbw, DataDirection::Out, data_len)
    }

    /// Build a SCSI REQUEST SENSE CBW.
    ///
    /// Returns `(cbw, DataDirection::In, 18)`.
    pub fn build_request_sense_cbw(&mut self) -> ([u8; 31], DataDirection, u32) {
        // REQUEST SENSE CDB: opcode, flags=0, reserved, alloc_len=18, control=0
        let cdb = [SCSI_REQUEST_SENSE, 0x00, 0x00, 0x00, 18u8, 0x00];
        let cbw = self.build_cbw(&cdb, 18, DataDirection::In);
        (cbw, DataDirection::In, 18)
    }

    /// Build a SCSI MODE SENSE(6) CBW.
    ///
    /// `page` selects which mode page to retrieve (stored in CDB[2]).
    /// Uses allocation length 192 to accommodate variable-length responses.
    ///
    /// Returns `(cbw, DataDirection::In, 192)`.
    pub fn build_mode_sense_cbw(&mut self, page: u8) -> ([u8; 31], DataDirection, u32) {
        // MODE SENSE(6) CDB: opcode, flags, page code, subpage=0, alloc_len=192, control=0
        let cdb = [SCSI_MODE_SENSE_6, 0x00, page, 0x00, 192u8, 0x00];
        let cbw = self.build_cbw(&cdb, 192, DataDirection::In);
        (cbw, DataDirection::In, 192)
    }
}

// ── Parsers ──────────────────────────────────────────────────────

/// Parse a 13-byte Command Status Wrapper (CSW).
///
/// Validates the "USBS" signature and returns an error for wrong
/// signature, too-short buffer, or status > 2 (invalid).
///
/// Note: callers that need tag validation should compare `csw.tag`
/// against the tag from their CBW.
pub fn parse_csw(data: &[u8]) -> Result<CswStatus, MassStorageError> {
    if data.len() < 13 {
        return Err(MassStorageError::ResponseTooShort);
    }

    let sig = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if sig != CSW_SIGNATURE {
        return Err(MassStorageError::InvalidCsw);
    }

    let tag = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let data_residue = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let status = data[12];

    if status > 2 {
        return Err(MassStorageError::InvalidCsw);
    }

    Ok(CswStatus {
        tag,
        data_residue,
        status,
    })
}

/// Parse a SCSI INQUIRY response.
///
/// Requires at least 36 bytes. Extracts peripheral type, removable
/// media flag, vendor ID, product ID, and revision level.
pub fn parse_inquiry(data: &[u8]) -> Result<InquiryResponse, MassStorageError> {
    if data.len() < 36 {
        return Err(MassStorageError::ResponseTooShort);
    }

    let peripheral_type = data[0] & 0x1F;
    let removable = (data[1] & 0x80) != 0;

    let mut vendor = [0u8; 8];
    vendor.copy_from_slice(&data[8..16]);

    let mut product = [0u8; 16];
    product.copy_from_slice(&data[16..32]);

    let mut revision = [0u8; 4];
    revision.copy_from_slice(&data[32..36]);

    Ok(InquiryResponse {
        peripheral_type,
        removable,
        vendor,
        product,
        revision,
    })
}

/// Parse a SCSI READ CAPACITY(10) response.
///
/// Requires at least 8 bytes. Both fields are big-endian on the wire.
///
/// Returns `(last_lba, block_size)` where `last_lba` is the address
/// of the last logical block and `block_size` is in bytes.
pub fn parse_read_capacity(data: &[u8]) -> Result<(u32, u32), MassStorageError> {
    if data.len() < 8 {
        return Err(MassStorageError::ResponseTooShort);
    }

    let last_lba = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let block_size = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    Ok((last_lba, block_size))
}

/// Parse a SCSI REQUEST SENSE response.
///
/// Requires at least 18 bytes. Extracts sense key (nibble),
/// Additional Sense Code (ASC), and Additional Sense Code Qualifier (ASCQ).
pub fn parse_request_sense(data: &[u8]) -> Result<SenseData, MassStorageError> {
    if data.len() < 18 {
        return Err(MassStorageError::ResponseTooShort);
    }

    let sense_key = data[2] & 0x0F;
    let asc = data[12];
    let ascq = data[13];

    Ok(SenseData {
        sense_key,
        asc,
        ascq,
    })
}

/// Parse a SCSI MODE SENSE(6) response.
///
/// Requires at least 4 bytes. Extracts the mode data length and
/// the write-protect flag from the device-specific parameter byte.
pub fn parse_mode_sense(data: &[u8]) -> Result<ModeSenseData, MassStorageError> {
    if data.len() < 4 {
        return Err(MassStorageError::ResponseTooShort);
    }

    let mode_data_length = data[0];
    let write_protected = (data[2] & 0x80) != 0;

    Ok(ModeSenseData {
        write_protected,
        mode_data_length,
    })
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: extract the CBW tag from a raw CBW byte array.
    fn cbw_tag(cbw: &[u8; 31]) -> u32 {
        u32::from_le_bytes([cbw[4], cbw[5], cbw[6], cbw[7]])
    }

    // Helper: extract the data transfer length from a CBW.
    fn cbw_data_len(cbw: &[u8; 31]) -> u32 {
        u32::from_le_bytes([cbw[8], cbw[9], cbw[10], cbw[11]])
    }

    // Helper: extract direction flags byte from a CBW.
    fn cbw_flags(cbw: &[u8; 31]) -> u8 {
        cbw[12]
    }

    // Helper: extract the SCSI opcode from a CBW.
    fn cbw_scsi_opcode(cbw: &[u8; 31]) -> u8 {
        cbw[15]
    }

    // Helper: verify CBW signature bytes.
    fn cbw_has_valid_signature(cbw: &[u8; 31]) -> bool {
        let sig = u32::from_le_bytes([cbw[0], cbw[1], cbw[2], cbw[3]]);
        sig == CBW_SIGNATURE
    }

    fn make_device() -> MassStorageDevice {
        MassStorageDevice::new(1, 5, 4)
    }

    // ── INQUIRY CBW ──────────────────────────────────────────────

    #[test]
    fn inquiry_cbw_valid_signature() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_inquiry_cbw();
        assert!(cbw_has_valid_signature(&cbw));
    }

    #[test]
    fn inquiry_cbw_correct_opcode() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_inquiry_cbw();
        assert_eq!(cbw_scsi_opcode(&cbw), SCSI_INQUIRY);
    }

    #[test]
    fn inquiry_cbw_correct_data_length() {
        let mut dev = make_device();
        let (cbw, _, len) = dev.build_inquiry_cbw();
        assert_eq!(len, 36);
        assert_eq!(cbw_data_len(&cbw), 36);
    }

    #[test]
    fn inquiry_cbw_direction_in() {
        let mut dev = make_device();
        let (cbw, dir, _) = dev.build_inquiry_cbw();
        assert_eq!(dir, DataDirection::In);
        assert_eq!(cbw_flags(&cbw), CBW_FLAG_IN);
    }

    // ── TEST UNIT READY CBW ──────────────────────────────────────

    #[test]
    fn test_unit_ready_cbw_valid_signature() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_test_unit_ready_cbw();
        assert!(cbw_has_valid_signature(&cbw));
    }

    #[test]
    fn test_unit_ready_cbw_correct_opcode() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_test_unit_ready_cbw();
        assert_eq!(cbw_scsi_opcode(&cbw), SCSI_TEST_UNIT_READY);
    }

    #[test]
    fn test_unit_ready_cbw_no_data() {
        let mut dev = make_device();
        let (cbw, dir, len) = dev.build_test_unit_ready_cbw();
        assert_eq!(dir, DataDirection::None);
        assert_eq!(len, 0);
        assert_eq!(cbw_data_len(&cbw), 0);
    }

    #[test]
    fn test_unit_ready_cbw_direction_out() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_test_unit_ready_cbw();
        // No-data transfers use CBW_FLAG_OUT per spec
        assert_eq!(cbw_flags(&cbw), CBW_FLAG_OUT);
    }

    // ── READ CAPACITY CBW ────────────────────────────────────────

    #[test]
    fn read_capacity_cbw_valid_signature() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_read_capacity_cbw();
        assert!(cbw_has_valid_signature(&cbw));
    }

    #[test]
    fn read_capacity_cbw_correct_opcode() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_read_capacity_cbw();
        assert_eq!(cbw_scsi_opcode(&cbw), SCSI_READ_CAPACITY_10);
    }

    #[test]
    fn read_capacity_cbw_correct_data_length() {
        let mut dev = make_device();
        let (cbw, _, len) = dev.build_read_capacity_cbw();
        assert_eq!(len, 8);
        assert_eq!(cbw_data_len(&cbw), 8);
    }

    #[test]
    fn read_capacity_cbw_direction_in() {
        let mut dev = make_device();
        let (cbw, dir, _) = dev.build_read_capacity_cbw();
        assert_eq!(dir, DataDirection::In);
        assert_eq!(cbw_flags(&cbw), CBW_FLAG_IN);
    }

    // ── READ(10) CBW ─────────────────────────────────────────────

    #[test]
    fn read_cbw_valid_signature() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_read_cbw(0, 1);
        assert!(cbw_has_valid_signature(&cbw));
    }

    #[test]
    fn read_cbw_correct_opcode() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_read_cbw(0, 1);
        assert_eq!(cbw_scsi_opcode(&cbw), SCSI_READ_10);
    }

    #[test]
    fn read_cbw_lba_big_endian_encoding() {
        let mut dev = make_device();
        let lba: u32 = 0x0102_0304;
        let (cbw, _, _) = dev.build_read_cbw(lba, 1);
        // LBA is at CDB[2..6] → CBW bytes [17..21]
        assert_eq!(cbw[17], 0x01);
        assert_eq!(cbw[18], 0x02);
        assert_eq!(cbw[19], 0x03);
        assert_eq!(cbw[20], 0x04);
    }

    #[test]
    fn read_cbw_sector_count_big_endian_encoding() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_read_cbw(0, 0x0102);
        // count is at CDB[7..9] → CBW bytes [22..24]
        assert_eq!(cbw[22], 0x01);
        assert_eq!(cbw[23], 0x02);
    }

    #[test]
    fn read_cbw_data_length_is_sectors_times_512() {
        let mut dev = make_device();
        let (cbw, _, len) = dev.build_read_cbw(0, 4);
        assert_eq!(len, 4 * 512);
        assert_eq!(cbw_data_len(&cbw), 4 * 512);
    }

    #[test]
    fn read_cbw_direction_in() {
        let mut dev = make_device();
        let (cbw, dir, _) = dev.build_read_cbw(0, 1);
        assert_eq!(dir, DataDirection::In);
        assert_eq!(cbw_flags(&cbw), CBW_FLAG_IN);
    }

    // ── WRITE(10) CBW ────────────────────────────────────────────

    #[test]
    fn write_cbw_valid_signature() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_write_cbw(0, 1);
        assert!(cbw_has_valid_signature(&cbw));
    }

    #[test]
    fn write_cbw_correct_opcode() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_write_cbw(0, 1);
        assert_eq!(cbw_scsi_opcode(&cbw), SCSI_WRITE_10);
    }

    #[test]
    fn write_cbw_direction_out_flag() {
        let mut dev = make_device();
        let (cbw, dir, _) = dev.build_write_cbw(0, 1);
        assert_eq!(dir, DataDirection::Out);
        assert_eq!(cbw_flags(&cbw), CBW_FLAG_OUT);
    }

    #[test]
    fn write_cbw_data_length_is_sectors_times_512() {
        let mut dev = make_device();
        let (cbw, _, len) = dev.build_write_cbw(0, 3);
        assert_eq!(len, 3 * 512);
        assert_eq!(cbw_data_len(&cbw), 3 * 512);
    }

    #[test]
    fn write_cbw_lba_big_endian_encoding() {
        let mut dev = make_device();
        let lba: u32 = 0xDEAD_BEEF;
        let (cbw, _, _) = dev.build_write_cbw(lba, 1);
        assert_eq!(cbw[17], 0xDE);
        assert_eq!(cbw[18], 0xAD);
        assert_eq!(cbw[19], 0xBE);
        assert_eq!(cbw[20], 0xEF);
    }

    // ── REQUEST SENSE CBW ────────────────────────────────────────

    #[test]
    fn request_sense_cbw_valid_signature() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_request_sense_cbw();
        assert!(cbw_has_valid_signature(&cbw));
    }

    #[test]
    fn request_sense_cbw_correct_opcode() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_request_sense_cbw();
        assert_eq!(cbw_scsi_opcode(&cbw), SCSI_REQUEST_SENSE);
    }

    #[test]
    fn request_sense_cbw_correct_data_length() {
        let mut dev = make_device();
        let (cbw, _, len) = dev.build_request_sense_cbw();
        assert_eq!(len, 18);
        assert_eq!(cbw_data_len(&cbw), 18);
    }

    #[test]
    fn request_sense_cbw_direction_in() {
        let mut dev = make_device();
        let (cbw, dir, _) = dev.build_request_sense_cbw();
        assert_eq!(dir, DataDirection::In);
        assert_eq!(cbw_flags(&cbw), CBW_FLAG_IN);
    }

    // ── MODE SENSE CBW ───────────────────────────────────────────

    #[test]
    fn mode_sense_cbw_valid_signature() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_mode_sense_cbw(0x3F);
        assert!(cbw_has_valid_signature(&cbw));
    }

    #[test]
    fn mode_sense_cbw_correct_opcode() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_mode_sense_cbw(0x3F);
        assert_eq!(cbw_scsi_opcode(&cbw), SCSI_MODE_SENSE_6);
    }

    #[test]
    fn mode_sense_cbw_correct_data_length() {
        let mut dev = make_device();
        let (cbw, _, len) = dev.build_mode_sense_cbw(0x3F);
        assert_eq!(len, 192);
        assert_eq!(cbw_data_len(&cbw), 192);
    }

    #[test]
    fn mode_sense_cbw_page_in_cdb() {
        let mut dev = make_device();
        let page: u8 = 0x08; // Caching page
        let (cbw, _, _) = dev.build_mode_sense_cbw(page);
        // Page is at CDB[2] → CBW byte [17]
        assert_eq!(cbw[17], page);
    }

    #[test]
    fn mode_sense_cbw_direction_in() {
        let mut dev = make_device();
        let (cbw, dir, _) = dev.build_mode_sense_cbw(0x3F);
        assert_eq!(dir, DataDirection::In);
        assert_eq!(cbw_flags(&cbw), CBW_FLAG_IN);
    }

    // ── CBW tag auto-increment ───────────────────────────────────

    #[test]
    fn tag_starts_at_one() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_inquiry_cbw();
        assert_eq!(cbw_tag(&cbw), 1);
    }

    #[test]
    fn tag_increments_across_sequential_builds() {
        let mut dev = make_device();
        let (cbw1, _, _) = dev.build_inquiry_cbw();
        let (cbw2, _, _) = dev.build_test_unit_ready_cbw();
        assert_eq!(cbw_tag(&cbw1), 1);
        assert_eq!(cbw_tag(&cbw2), 2);
    }

    #[test]
    fn tag_increments_across_different_command_types() {
        let mut dev = make_device();
        let (cbw1, _, _) = dev.build_read_cbw(0, 1);
        let (cbw2, _, _) = dev.build_write_cbw(0, 1);
        let (cbw3, _, _) = dev.build_read_capacity_cbw();
        assert_eq!(cbw_tag(&cbw1), 1);
        assert_eq!(cbw_tag(&cbw2), 2);
        assert_eq!(cbw_tag(&cbw3), 3);
    }

    // ── CSW parser ───────────────────────────────────────────────

    #[test]
    fn parse_csw_valid_passed() {
        let mut data = [0u8; 13];
        data[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        data[4..8].copy_from_slice(&42u32.to_le_bytes()); // tag = 42
        data[8..12].copy_from_slice(&0u32.to_le_bytes()); // residue = 0
        data[12] = 0; // Passed

        let csw = parse_csw(&data).unwrap();
        assert_eq!(csw.tag, 42);
        assert_eq!(csw.data_residue, 0);
        assert_eq!(csw.status, 0);
    }

    #[test]
    fn parse_csw_wrong_signature() {
        let mut data = [0u8; 13];
        data[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        assert_eq!(parse_csw(&data), Err(MassStorageError::InvalidCsw));
    }

    #[test]
    fn parse_csw_too_short() {
        let data = [0u8; 12];
        assert_eq!(parse_csw(&data), Err(MassStorageError::ResponseTooShort));
    }

    #[test]
    fn parse_csw_status_failed() {
        let mut data = [0u8; 13];
        data[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        data[12] = 1; // Failed
        let csw = parse_csw(&data).unwrap();
        assert_eq!(csw.status, 1);
    }

    #[test]
    fn parse_csw_status_phase_error() {
        let mut data = [0u8; 13];
        data[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        data[12] = 2; // Phase Error
        let csw = parse_csw(&data).unwrap();
        assert_eq!(csw.status, 2);
    }

    #[test]
    fn parse_csw_status_invalid() {
        let mut data = [0u8; 13];
        data[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        data[12] = 3; // Invalid — reserved
        assert_eq!(parse_csw(&data), Err(MassStorageError::InvalidCsw));
    }

    #[test]
    fn parse_csw_data_residue_decoded() {
        let mut data = [0u8; 13];
        data[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        data[8..12].copy_from_slice(&0x0000_0200u32.to_le_bytes()); // 512 bytes residue
        data[12] = 0;
        let csw = parse_csw(&data).unwrap();
        assert_eq!(csw.data_residue, 512);
    }

    // ── INQUIRY parser ───────────────────────────────────────────

    #[test]
    fn parse_inquiry_too_short() {
        let data = [0u8; 35];
        assert_eq!(
            parse_inquiry(&data),
            Err(MassStorageError::ResponseTooShort)
        );
    }

    #[test]
    fn parse_inquiry_peripheral_type() {
        let mut data = [0u8; 36];
        data[0] = 0x1F; // all peripheral type bits set
        let resp = parse_inquiry(&data).unwrap();
        assert_eq!(resp.peripheral_type, 0x1F);
    }

    #[test]
    fn parse_inquiry_peripheral_type_masked() {
        let mut data = [0u8; 36];
        data[0] = 0xFF; // upper bits should be masked out
        let resp = parse_inquiry(&data).unwrap();
        assert_eq!(resp.peripheral_type, 0x1F);
    }

    #[test]
    fn parse_inquiry_removable_set() {
        let mut data = [0u8; 36];
        data[1] = 0x80;
        let resp = parse_inquiry(&data).unwrap();
        assert!(resp.removable);
    }

    #[test]
    fn parse_inquiry_removable_not_set() {
        let mut data = [0u8; 36];
        data[1] = 0x00;
        let resp = parse_inquiry(&data).unwrap();
        assert!(!resp.removable);
    }

    #[test]
    fn parse_inquiry_vendor_extraction() {
        let mut data = [0u8; 36];
        let vendor = *b"SEAGATE ";
        data[8..16].copy_from_slice(&vendor);
        let resp = parse_inquiry(&data).unwrap();
        assert_eq!(resp.vendor, vendor);
    }

    #[test]
    fn parse_inquiry_product_extraction() {
        let mut data = [0u8; 36];
        let product = *b"ST2000LM015     ";
        data[16..32].copy_from_slice(&product);
        let resp = parse_inquiry(&data).unwrap();
        assert_eq!(resp.product, product);
    }

    #[test]
    fn parse_inquiry_revision_extraction() {
        let mut data = [0u8; 36];
        let revision = *b"SDM1";
        data[32..36].copy_from_slice(&revision);
        let resp = parse_inquiry(&data).unwrap();
        assert_eq!(resp.revision, revision);
    }

    // ── READ CAPACITY parser ─────────────────────────────────────

    #[test]
    fn parse_read_capacity_too_short() {
        let data = [0u8; 7];
        assert_eq!(
            parse_read_capacity(&data),
            Err(MassStorageError::ResponseTooShort)
        );
    }

    #[test]
    fn parse_read_capacity_big_endian_last_lba() {
        let mut data = [0u8; 8];
        data[0..4].copy_from_slice(&0x00FF_FFFFu32.to_be_bytes()); // last_lba
        data[4..8].copy_from_slice(&512u32.to_be_bytes()); // block_size
        let (last_lba, block_size) = parse_read_capacity(&data).unwrap();
        assert_eq!(last_lba, 0x00FF_FFFF);
        assert_eq!(block_size, 512);
    }

    #[test]
    fn parse_read_capacity_big_endian_block_size() {
        let mut data = [0u8; 8];
        data[0..4].copy_from_slice(&0u32.to_be_bytes());
        data[4..8].copy_from_slice(&4096u32.to_be_bytes());
        let (_, block_size) = parse_read_capacity(&data).unwrap();
        assert_eq!(block_size, 4096);
    }

    // ── REQUEST SENSE parser ─────────────────────────────────────

    #[test]
    fn parse_request_sense_too_short() {
        let data = [0u8; 17];
        assert_eq!(
            parse_request_sense(&data),
            Err(MassStorageError::ResponseTooShort)
        );
    }

    #[test]
    fn parse_request_sense_key() {
        let mut data = [0u8; 18];
        data[2] = 0x0B; // Aborted Command sense key = 0x0B
        let sense = parse_request_sense(&data).unwrap();
        assert_eq!(sense.sense_key, 0x0B);
    }

    #[test]
    fn parse_request_sense_key_masked() {
        let mut data = [0u8; 18];
        data[2] = 0xFF; // high nibble should be masked out
        let sense = parse_request_sense(&data).unwrap();
        assert_eq!(sense.sense_key, 0x0F);
    }

    #[test]
    fn parse_request_sense_asc_and_ascq() {
        let mut data = [0u8; 18];
        data[12] = 0x3A; // ASC: Medium Not Present
        data[13] = 0x00; // ASCQ: No additional info
        let sense = parse_request_sense(&data).unwrap();
        assert_eq!(sense.asc, 0x3A);
        assert_eq!(sense.ascq, 0x00);
    }

    // ── MODE SENSE parser ────────────────────────────────────────

    #[test]
    fn parse_mode_sense_too_short() {
        let data = [0u8; 3];
        assert_eq!(
            parse_mode_sense(&data),
            Err(MassStorageError::ResponseTooShort)
        );
    }

    #[test]
    fn parse_mode_sense_write_protected_set() {
        let mut data = [0u8; 4];
        data[2] = 0x80; // write-protect bit set
        let ms = parse_mode_sense(&data).unwrap();
        assert!(ms.write_protected);
    }

    #[test]
    fn parse_mode_sense_write_protected_not_set() {
        let mut data = [0u8; 4];
        data[2] = 0x00;
        let ms = parse_mode_sense(&data).unwrap();
        assert!(!ms.write_protected);
    }

    #[test]
    fn parse_mode_sense_mode_data_length() {
        let mut data = [0u8; 4];
        data[0] = 0x1F; // mode data length = 31
        let ms = parse_mode_sense(&data).unwrap();
        assert_eq!(ms.mode_data_length, 0x1F);
    }

    // ── CBW LUN and CB length fields ─────────────────────────────

    #[test]
    fn cbw_lun_is_zero() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_inquiry_cbw();
        assert_eq!(cbw[13], 0, "bCBWLUN must be 0");
    }

    #[test]
    fn cbw_cb_length_set_correctly_for_6byte_cdb() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_inquiry_cbw();
        assert_eq!(cbw[14], 6, "bCBWCBLength for 6-byte CDB");
    }

    #[test]
    fn cbw_cb_length_set_correctly_for_10byte_cdb() {
        let mut dev = make_device();
        let (cbw, _, _) = dev.build_read_cbw(0, 1);
        assert_eq!(cbw[14], 10, "bCBWCBLength for 10-byte CDB");
    }
}
