# USB Mass Storage BBB Class Driver — Design Spec

## Goal

Implement the USB Mass Storage Bulk-Only Transport (BBB) protocol as a
sans-I/O driver. Builds CBW/CSW byte arrays and parses SCSI responses,
enabling the caller to read/write sectors on USB storage devices via
the xHCI bulk transfer API.

## Background

USB mass storage devices use the Bulk-Only Transport (BBB) protocol:
every operation is a CBW (Command Block Wrapper) sent as a bulk OUT,
optionally followed by a data phase (bulk IN or OUT), then a CSW
(Command Status Wrapper) received as bulk IN. The command block inside
the CBW contains a SCSI command.

## BBB Protocol

### CBW (Command Block Wrapper) — 31 bytes, bulk OUT

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 4 | dCBWSignature | 0x55534243 ("USBC") |
| 4 | 4 | dCBWTag | monotonic counter |
| 8 | 4 | dCBWDataTransferLength | expected data bytes |
| 12 | 1 | bmCBWFlags | 0x80=IN, 0x00=OUT |
| 13 | 1 | bCBWLUN | 0 (always) |
| 14 | 1 | bCBWCBLength | SCSI command length (6-16) |
| 15 | 16 | CBWCB | SCSI command block, zero-padded |

### CSW (Command Status Wrapper) — 13 bytes, bulk IN

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 4 | dCSWSignature | 0x53425355 ("USBS") |
| 4 | 4 | dCSWTag | must match CBW tag |
| 8 | 4 | dCSWDataResidue | bytes not transferred |
| 12 | 1 | bCSWStatus | 0=Passed, 1=Failed, 2=Phase Error |

## New File

`crates/harmony-unikernel/src/drivers/mass_storage.rs`

## Types

```rust
pub struct MassStorageDevice {
    pub slot_id: u8,
    pub bulk_in_ep: u8,   // endpoint DCI (odd, e.g. 5)
    pub bulk_out_ep: u8,  // endpoint DCI (even, e.g. 4)
    next_tag: u32,
}

pub enum DataDirection { In, Out, None }

pub struct CswStatus {
    pub tag: u32,
    pub data_residue: u32,
    pub status: u8,
}

pub struct InquiryResponse {
    pub peripheral_type: u8,
    pub removable: bool,
    pub vendor: [u8; 8],
    pub product: [u8; 16],
    pub revision: [u8; 4],
}

pub struct SenseData {
    pub sense_key: u8,
    pub asc: u8,     // Additional Sense Code
    pub ascq: u8,    // Additional Sense Code Qualifier
}

pub struct ModeSenseData {
    pub write_protected: bool,
    pub mode_data_length: u8,
}

pub enum MassStorageError {
    InvalidCsw,
    CswTagMismatch { expected: u32, got: u32 },
    CommandFailed { status: u8 },
    ResponseTooShort,
}
```

## CBW Builders

Each returns `([u8; 31], DataDirection, u32)` — CBW bytes, data
direction, expected data transfer length.

| Method | SCSI Op | Data |
|--------|---------|------|
| `build_inquiry_cbw` | 0x12 | 36B IN |
| `build_test_unit_ready_cbw` | 0x00 | None |
| `build_read_capacity_cbw` | 0x25 | 8B IN |
| `build_read_cbw(lba, count)` | 0x28 | count×512B IN |
| `build_write_cbw(lba, count)` | 0x2A | count×512B OUT |
| `build_request_sense_cbw` | 0x03 | 18B IN |
| `build_mode_sense_cbw(page)` | 0x1A | 192B IN |

Internal helper: `build_cbw(&mut self, command: &[u8], data_len: u32,
direction: DataDirection) -> [u8; 31]` handles signature, tag
increment, flags, padding.

## Response Parsers

- `parse_csw(data: &[u8]) -> Result<CswStatus, MassStorageError>`
- `parse_inquiry(data: &[u8]) -> Result<InquiryResponse, MassStorageError>`
- `parse_read_capacity(data: &[u8]) -> Result<(u32, u32), MassStorageError>` — (last_lba, block_size)
- `parse_request_sense(data: &[u8]) -> Result<SenseData, MassStorageError>`
- `parse_mode_sense(data: &[u8]) -> Result<ModeSenseData, MassStorageError>`

## Caller Flow (READ example)

```
1. let (cbw, dir, len) = device.build_read_cbw(lba, 1);
2. xhci.bulk_transfer_out(slot, out_ep, cbw_phys, 31) → actions
3. [execute actions, wait for TransferEvent]
4. xhci.bulk_transfer_in(slot, in_ep, data_phys, 512) → actions
5. [execute actions, wait for TransferEvent]
6. xhci.bulk_transfer_in(slot, in_ep, csw_phys, 13) → actions
7. [execute actions, wait for TransferEvent]
8. let csw = parse_csw(&csw_buf)?;
```

## Testing

- CBW format: signature, tag, data length, direction flag, SCSI opcode
- CBW tag auto-increment across sequential builds
- CSW parser: valid data, wrong signature, too short, invalid status
- INQUIRY parse: vendor/product/revision extraction
- READ CAPACITY parse: big-endian last_lba + block_size
- REQUEST SENSE parse: sense key, ASC, ASCQ
- MODE SENSE parse: write-protect flag
- READ(10) CBW: big-endian LBA + sector count
- WRITE(10) CBW: OUT direction flag + correct data length

## Out of Scope

- Multi-LUN support
- Bulk-only mass storage reset
- Scatter-gather / multi-TRB transfers
- Filesystem parsing
- Hot-plug detection
