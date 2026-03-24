// SPDX-License-Identifier: GPL-2.0-or-later

//! SdServer — 9P file server for an SD card block device.
//!
//! Exposes a single block device `sd0`. Reads and writes honor the
//! offset parameter and must be 512-byte aligned.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use harmony_unikernel::drivers::sdhci::SdhciDriver;
use harmony_unikernel::drivers::RegisterBank;

use crate::fid_tracker::FidTracker;
use crate::{Fid, FileServer, FileStat, FileType, IpcError, OpenMode, QPath};

const QPATH_ROOT: QPath = 0;
const QPATH_SD0: QPath = 1;
const BLOCK_SIZE: u64 = 512;

/// A 9P file server wrapping an [`SdhciDriver`] and [`RegisterBank`].
///
/// Walk to `"sd0"` to get a block device fid.
/// Read and write offsets must be 512-byte aligned.
/// Writes must supply exactly 512 bytes.
pub struct SdServer<B: RegisterBank> {
    driver: SdhciDriver,
    bank: B,
    tracker: FidTracker<()>,
}

impl<B: RegisterBank> SdServer<B> {
    /// Create a new SdServer with the given driver and register bank.
    ///
    /// The caller should have already called `driver.init_card()` before
    /// constructing the server so that `card_info()` is available.
    pub fn new(driver: SdhciDriver, bank: B) -> Self {
        Self {
            driver,
            bank,
            tracker: FidTracker::new(QPATH_ROOT, ()),
        }
    }
}

impl<B: RegisterBank> FileServer for SdServer<B> {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let entry = self.tracker.get(fid)?;
        if entry.qpath != QPATH_ROOT {
            return Err(IpcError::NotDirectory);
        }
        if name != "sd0" {
            return Err(IpcError::NotFound);
        }
        self.tracker.insert(new_fid, QPATH_SD0, ())?;
        Ok(QPATH_SD0)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        let entry = self.tracker.begin_open(fid)?;
        if entry.qpath == QPATH_ROOT && matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
            return Err(IpcError::IsDirectory);
        }
        entry.mark_open(mode);
        Ok(())
    }

    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.is_open() {
            return Err(IpcError::NotOpen);
        }
        if entry.qpath == QPATH_ROOT {
            return Err(IpcError::IsDirectory);
        }
        if matches!(entry.mode(), Some(OpenMode::Write)) {
            return Err(IpcError::PermissionDenied);
        }
        if offset % BLOCK_SIZE != 0 {
            return Err(IpcError::InvalidArgument);
        }
        let lba = u32::try_from(offset / BLOCK_SIZE).map_err(|_| IpcError::InvalidArgument)?;
        let mut buf = [0u8; 512];
        self.driver
            .read_single_block(&mut self.bank, lba, &mut buf)
            .map_err(|_| IpcError::NotFound)?;
        let n = (count as usize).min(512);
        Ok(buf[..n].to_vec())
    }

    fn write(&mut self, fid: Fid, offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.is_open() {
            return Err(IpcError::NotOpen);
        }
        if entry.qpath == QPATH_ROOT {
            return Err(IpcError::IsDirectory);
        }
        if matches!(entry.mode(), Some(OpenMode::Read)) {
            return Err(IpcError::PermissionDenied);
        }
        if offset % BLOCK_SIZE != 0 {
            return Err(IpcError::InvalidArgument);
        }
        if data.len() != 512 {
            return Err(IpcError::InvalidArgument);
        }
        let lba = u32::try_from(offset / BLOCK_SIZE).map_err(|_| IpcError::InvalidArgument)?;
        let buf: &[u8; 512] = data.try_into().map_err(|_| IpcError::InvalidArgument)?;
        self.driver
            .write_single_block(&mut self.bank, lba, buf)
            .map_err(|_| IpcError::NotFound)?;
        Ok(512)
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        self.tracker.clunk(fid)
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let qpath = self.tracker.get(fid)?.qpath;
        match qpath {
            QPATH_ROOT => Ok(FileStat {
                qpath: QPATH_ROOT,
                name: Arc::from("/"),
                size: 0,
                file_type: FileType::Directory,
            }),
            QPATH_SD0 => {
                let size = self
                    .driver
                    .card_info()
                    .map(|info| info.capacity_blocks as u64 * BLOCK_SIZE)
                    .unwrap_or(0);
                Ok(FileStat {
                    qpath: QPATH_SD0,
                    name: Arc::from("sd0"),
                    size,
                    file_type: FileType::Regular,
                })
            }
            _ => Err(IpcError::NotFound),
        }
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        self.tracker.clone_fid(fid, new_fid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harmony_unikernel::drivers::register_bank::mock::MockRegisterBank;
    use harmony_unikernel::drivers::sdhci::SdhciDriver;

    // ── SDHCI register offsets (duplicated for test setup) ───────
    const SDHCI_PRESENT_STATE: usize = 0x24;
    const SDHCI_INT_STATUS: usize = 0x30;
    const SDHCI_RESPONSE_0: usize = 0x10;
    const SDHCI_BUFFER_DATA: usize = 0x20;

    const INT_CMD_COMPLETE: u32 = 1 << 0;
    const INT_TRANSFER_COMPLETE: u32 = 1 << 1;
    const INT_BUFFER_READ_READY: u32 = 1 << 5;
    const INT_BUFFER_WRITE_READY: u32 = 1 << 4;

    /// Create a test server with a pre-initialized card.
    fn test_server(capacity_blocks: u32) -> SdServer<MockRegisterBank> {
        let mut driver = SdhciDriver::new();
        // Inject card info directly via init_card on a mock
        // that provides a full successful init sequence.
        let mut init_bank = MockRegisterBank::new();
        setup_init_card_mock(&mut init_bank, capacity_blocks);
        driver.init_card(&mut init_bank).unwrap();

        let bank = MockRegisterBank::new();
        SdServer::new(driver, bank)
    }

    /// Set up the mock for a successful init_card call.
    ///
    /// The CMD9 (SEND_CSD) response uses CSD v2.0 with C_SIZE=1000,
    /// giving capacity_blocks = (1000 + 1) * 1024 = 1_025_024 blocks.
    fn setup_init_card_mock(bank: &mut MockRegisterBank, _capacity: u32) {
        // We need the full init sequence to pass (9 commands total):
        // CMD0, CMD8, CMD55, ACMD41, CMD2, CMD3, CMD9, CMD7, CMD16
        const SDHCI_RESPONSE_1: usize = 0x14;
        const SDHCI_RESPONSE_2: usize = 0x18;
        const SDHCI_RESPONSE_3: usize = 0x1C;

        // C_SIZE = 1000 for CMD9 CSD v2.0 response
        const C_SIZE: u32 = 1000;

        // SDHCI_PRESENT_STATE: one value (0 = not busy), sticky for all 9 commands
        bank.on_read(SDHCI_PRESENT_STATE, vec![0]);

        // SDHCI_INT_STATUS: INT_CMD_COMPLETE, sticky for all 8 commands with responses
        // (CMD0 has no response, all others do)
        bank.on_read(SDHCI_INT_STATUS, vec![INT_CMD_COMPLETE]);

        // SDHCI_RESPONSE_0: one value per command that reads a response
        // CMD8(R48), CMD55(R48), ACMD41(R48), CMD2(R136), CMD3(R48), CMD9(R136),
        // CMD7(R48b), CMD16(R48) = 8 reads
        bank.on_read(
            SDHCI_RESPONSE_0,
            vec![
                0x1AA,      // CMD8: voltage pattern echo
                0x0120,     // CMD55: R1 status
                0xC0100000, // ACMD41: ready bit 31 + CCS bit 30 = SDHC
                0,          // CMD2: R2 word 0
                0xAAAA0000, // CMD3: RCA in bits [31:16]
                0,          // CMD9: R2 word 0
                0,          // CMD7: R1b status
                0,          // CMD16: R1 status
            ],
        );

        // SDHCI_RESPONSE_1: read by CMD2 (R136) then CMD9 (R136)
        // CMD9: C_SIZE in bits [29:8] encodes 1000 → (1000+1)*1024 = 1_025_024 blocks
        bank.on_read(SDHCI_RESPONSE_1, vec![0, C_SIZE << 8]);

        // SDHCI_RESPONSE_2: read by CMD2 then CMD9 (both zero)
        bank.on_read(SDHCI_RESPONSE_2, vec![0, 0]);

        // SDHCI_RESPONSE_3: read by CMD2 then CMD9
        // CMD9: CSD version = 1 (CSD v2.0) in bits [23:22] → value = 1 << 22
        bank.on_read(SDHCI_RESPONSE_3, vec![0, 1 << 22]);
    }

    /// Program the server's bank for a successful read_single_block.
    fn setup_read_mock(srv: &mut SdServer<MockRegisterBank>, data: &[u8; 512]) {
        srv.bank.on_read(SDHCI_PRESENT_STATE, vec![0]);
        srv.bank.on_read(
            SDHCI_INT_STATUS,
            vec![
                INT_CMD_COMPLETE,
                INT_BUFFER_READ_READY,
                INT_TRANSFER_COMPLETE,
            ],
        );
        srv.bank.on_read(SDHCI_RESPONSE_0, vec![0]);
        let words: Vec<u32> = (0..128)
            .map(|i| {
                let off = i * 4;
                data[off] as u32
                    | (data[off + 1] as u32) << 8
                    | (data[off + 2] as u32) << 16
                    | (data[off + 3] as u32) << 24
            })
            .collect();
        srv.bank.on_read(SDHCI_BUFFER_DATA, words);
    }

    /// Program the server's bank for a successful write_single_block.
    fn setup_write_mock(srv: &mut SdServer<MockRegisterBank>) {
        srv.bank.on_read(SDHCI_PRESENT_STATE, vec![0]);
        srv.bank.on_read(
            SDHCI_INT_STATUS,
            vec![
                INT_CMD_COMPLETE,
                INT_BUFFER_WRITE_READY,
                INT_TRANSFER_COMPLETE,
            ],
        );
        srv.bank.on_read(SDHCI_RESPONSE_0, vec![0]);
    }

    // ── Walk tests ──────────────────────────────────────────────────

    #[test]
    fn walk_to_sd0() {
        let mut srv = test_server(1024);
        let qpath = srv.walk(0, 1, "sd0").unwrap();
        assert_eq!(qpath, QPATH_SD0);
    }

    #[test]
    fn walk_invalid_name() {
        let mut srv = test_server(1024);
        assert_eq!(srv.walk(0, 1, "foo"), Err(IpcError::NotFound));
    }

    // ── Read tests ──────────────────────────────────────────────────

    #[test]
    fn read_block_at_offset_zero() {
        let mut srv = test_server(1024);
        srv.walk(0, 1, "sd0").unwrap();
        srv.open(1, OpenMode::Read).unwrap();

        let mut expected = [0u8; 512];
        for (i, b) in expected.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }
        setup_read_mock(&mut srv, &expected);

        let data = srv.read(1, 0, 512).unwrap();
        assert_eq!(data.len(), 512);
        assert_eq!(&data[..], &expected[..]);

        // Verify LBA 0 was passed as argument
        assert!(srv.bank.writes.iter().any(|&(off, val)| {
            // SDHCI_ARGUMENT = 0x08
            off == 0x08 && val == 0
        }));
    }

    #[test]
    fn read_block_at_offset_512() {
        let mut srv = test_server(1024);
        srv.walk(0, 1, "sd0").unwrap();
        srv.open(1, OpenMode::Read).unwrap();

        let expected = [0xAA; 512];
        setup_read_mock(&mut srv, &expected);

        let data = srv.read(1, 512, 512).unwrap();
        assert_eq!(data.len(), 512);
        assert_eq!(&data[..], &expected[..]);

        // Verify LBA 1 was passed as argument
        assert!(srv
            .bank
            .writes
            .iter()
            .any(|&(off, val)| { off == 0x08 && val == 1 }));
    }

    #[test]
    fn read_unaligned_offset_rejected() {
        let mut srv = test_server(1024);
        srv.walk(0, 1, "sd0").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        assert_eq!(srv.read(1, 100, 512), Err(IpcError::InvalidArgument));
    }

    #[test]
    fn read_partial_count() {
        let mut srv = test_server(1024);
        srv.walk(0, 1, "sd0").unwrap();
        srv.open(1, OpenMode::Read).unwrap();

        let expected = [0x42; 512];
        setup_read_mock(&mut srv, &expected);

        // Request only 128 bytes — should get first 128 of the block
        let data = srv.read(1, 0, 128).unwrap();
        assert_eq!(data.len(), 128);
        assert_eq!(&data[..], &expected[..128]);
    }

    // ── Write tests ─────────────────────────────────────────────────

    #[test]
    fn write_block_at_offset_zero() {
        let mut srv = test_server(1024);
        srv.walk(0, 1, "sd0").unwrap();
        srv.open(1, OpenMode::Write).unwrap();

        setup_write_mock(&mut srv);

        let data = [0xBB; 512];
        let n = srv.write(1, 0, &data).unwrap();
        assert_eq!(n, 512);

        // Verify LBA 0 was passed
        assert!(srv
            .bank
            .writes
            .iter()
            .any(|&(off, val)| { off == 0x08 && val == 0 }));
    }

    #[test]
    fn write_unaligned_rejected() {
        let mut srv = test_server(1024);
        srv.walk(0, 1, "sd0").unwrap();
        srv.open(1, OpenMode::Write).unwrap();

        let data = [0u8; 512];
        assert_eq!(srv.write(1, 100, &data), Err(IpcError::InvalidArgument));
    }

    #[test]
    fn write_wrong_size_rejected() {
        let mut srv = test_server(1024);
        srv.walk(0, 1, "sd0").unwrap();
        srv.open(1, OpenMode::Write).unwrap();

        let data = [0u8; 256];
        assert_eq!(srv.write(1, 0, &data), Err(IpcError::InvalidArgument));
    }

    // ── Stat tests ──────────────────────────────────────────────────

    #[test]
    fn stat_root() {
        let mut srv = test_server(1024);
        let st = srv.stat(0).unwrap();
        assert_eq!(&*st.name, "/");
        assert_eq!(st.file_type, FileType::Directory);
        assert_eq!(st.size, 0);
    }

    #[test]
    fn stat_sd0() {
        let mut srv = test_server(2048);
        srv.walk(0, 1, "sd0").unwrap();
        let st = srv.stat(1).unwrap();
        assert_eq!(&*st.name, "sd0");
        assert_eq!(st.file_type, FileType::Regular);
        // CMD9 CSD v2.0 mock: C_SIZE=1000 → capacity = (1000+1)*1024 = 1_025_024 blocks
        // size = capacity_blocks * 512 = 524_812_288 bytes
        const C_SIZE: u64 = 1000;
        assert_eq!(st.size, (C_SIZE + 1) * 1024 * 512);
    }

    #[test]
    fn stat_sd0_with_known_capacity() {
        // Directly construct with known card info to test size calculation.
        let mut driver = SdhciDriver::new();
        // Initialize to get a CardInfo stored
        let mut init_bank = MockRegisterBank::new();
        setup_init_card_mock(&mut init_bank, 0);
        driver.init_card(&mut init_bank).unwrap();

        let bank = MockRegisterBank::new();
        let mut srv = SdServer::new(driver, bank);
        srv.walk(0, 1, "sd0").unwrap();

        let st = srv.stat(1).unwrap();
        // CMD9 CSD v2.0 mock: C_SIZE=1000 → capacity = (1000+1)*1024 = 1_025_024 blocks
        // size = capacity_blocks * 512 = 524_812_288 bytes
        const C_SIZE: u64 = 1000;
        assert_eq!(st.size, (C_SIZE + 1) * 1024 * 512);
    }

    // ── Mode enforcement tests ──────────────────────────────────────

    #[test]
    fn write_denied_in_read_mode() {
        let mut srv = test_server(1024);
        srv.walk(0, 1, "sd0").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = [0u8; 512];
        assert_eq!(srv.write(1, 0, &data), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn read_denied_in_write_mode() {
        let mut srv = test_server(1024);
        srv.walk(0, 1, "sd0").unwrap();
        srv.open(1, OpenMode::Write).unwrap();
        assert_eq!(srv.read(1, 0, 512), Err(IpcError::PermissionDenied));
    }

    // ── Clunk / clone tests ─────────────────────────────────────────

    #[test]
    fn clunk_root_rejected() {
        let mut srv = test_server(1024);
        assert_eq!(srv.clunk(0), Err(IpcError::PermissionDenied));
        // Root should still work after rejected clunk
        srv.walk(0, 1, "sd0").unwrap();
    }

    #[test]
    fn clone_fid_duplicates() {
        let mut srv = test_server(1024);
        srv.walk(0, 1, "sd0").unwrap();
        let qpath = srv.clone_fid(1, 2).unwrap();
        assert_eq!(qpath, QPATH_SD0);
        let st = srv.stat(2).unwrap();
        assert_eq!(&*st.name, "sd0");
        // Cloned fid should not be open
        assert_eq!(srv.read(2, 0, 512), Err(IpcError::NotOpen));
    }
}
