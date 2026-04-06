// SPDX-License-Identifier: GPL-2.0-or-later

//! Block device abstraction layer.
//!
//! Provides a `BlockDevice` trait for uniform 512-byte sector I/O,
//! an MBR partition table parser, and adapters for SDHCI and
//! partition-offset wrapping.

extern crate alloc;

use crate::IpcError;

use harmony_unikernel::drivers::sdhci::SdhciDriver;
use harmony_unikernel::drivers::RegisterBank;

/// Uniform interface for 512-byte sector I/O.
pub trait BlockDevice {
    /// Read a single 512-byte sector at the given LBA.
    fn read_block(&mut self, lba: u32, buf: &mut [u8; 512]) -> Result<(), IpcError>;

    /// Total number of 512-byte sectors on the device.
    fn capacity_blocks(&self) -> u32;
}

// ── MBR types ────────────────────────────────────────────────────────

/// A single entry from the MBR partition table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrEntry {
    pub partition_type: u8,
    pub start_lba: u32,
    pub size_sectors: u32,
}

/// Parse the MBR at LBA 0, returning up to 4 partition entries.
///
/// Returns `InvalidArgument` if the boot signature (0x55AA) is missing.
/// Empty entries (partition_type 0) are returned as `None`.
/// FAT32 partition types are 0x0B (CHS) and 0x0C (LBA).
pub fn parse_mbr(block_dev: &mut dyn BlockDevice) -> Result<[Option<MbrEntry>; 4], IpcError> {
    let mut sector = [0u8; 512];
    block_dev.read_block(0, &mut sector)?;

    if sector[510] != 0x55 || sector[511] != 0xAA {
        return Err(IpcError::InvalidArgument);
    }

    let mut entries = [None; 4];
    for (i, entry) in entries.iter_mut().enumerate() {
        let base = 0x1BE + i * 16;
        let ptype = sector[base + 4];
        if ptype == 0 {
            continue;
        }
        let start_lba = u32::from_le_bytes([
            sector[base + 8],
            sector[base + 9],
            sector[base + 10],
            sector[base + 11],
        ]);
        let size_sectors = u32::from_le_bytes([
            sector[base + 12],
            sector[base + 13],
            sector[base + 14],
            sector[base + 15],
        ]);
        *entry = Some(MbrEntry {
            partition_type: ptype,
            start_lba,
            size_sectors,
        });
    }

    Ok(entries)
}

// ── PartitionBlockDevice ─────────────────────────────────────────────

/// Wraps a `BlockDevice`, adding a base LBA offset for partition access.
///
/// All reads are translated: `read_block(lba)` becomes
/// `inner.read_block(base_lba + lba)`. Reads past `partition_size`
/// are rejected with `InvalidArgument`.
pub struct PartitionBlockDevice<D: BlockDevice> {
    inner: D,
    base_lba: u32,
    partition_size: u32,
}

impl<D: BlockDevice> PartitionBlockDevice<D> {
    pub fn new(inner: D, base_lba: u32, partition_size: u32) -> Self {
        Self {
            inner,
            base_lba,
            partition_size,
        }
    }
}

impl<D: BlockDevice> BlockDevice for PartitionBlockDevice<D> {
    fn read_block(&mut self, lba: u32, buf: &mut [u8; 512]) -> Result<(), IpcError> {
        if lba >= self.partition_size {
            return Err(IpcError::InvalidArgument);
        }
        let physical_lba = self
            .base_lba
            .checked_add(lba)
            .ok_or(IpcError::InvalidArgument)?;
        self.inner.read_block(physical_lba, buf)
    }

    fn capacity_blocks(&self) -> u32 {
        self.partition_size
    }
}

// ── SdhciBlockDevice adapter ─────────────────────────────────────────

/// Adapts an [`SdhciDriver`] + [`RegisterBank`] pair to the
/// [`BlockDevice`] trait.
///
/// The caller must have called `driver.init_card()` before
/// constructing this adapter.
pub struct SdhciBlockDevice<B: RegisterBank> {
    driver: SdhciDriver,
    pub(crate) bank: B,
}

impl<B: RegisterBank> SdhciBlockDevice<B> {
    pub fn new(driver: SdhciDriver, bank: B) -> Self {
        Self { driver, bank }
    }
}

impl<B: RegisterBank> BlockDevice for SdhciBlockDevice<B> {
    /// Note: all SDHCI driver errors (DMA timeout, CRC, card removal) map to
    /// `IpcError::NotFound` to match the existing SdServer I/O error convention.
    fn read_block(&mut self, lba: u32, buf: &mut [u8; 512]) -> Result<(), IpcError> {
        self.driver
            .read_single_block(&mut self.bank, lba, buf)
            .map_err(|_| IpcError::NotFound)
    }

    fn capacity_blocks(&self) -> u32 {
        self.driver
            .card_info()
            .map(|info| info.capacity_blocks)
            .unwrap_or(0)
    }
}

// ── MemoryBlockDevice (test helper) ──────────────────────────────────

/// In-memory block device for testing. Pre-populate `sectors` with
/// synthetic disk images (MBR, FAT32, etc.).
#[cfg(test)]
pub(crate) struct MemoryBlockDevice {
    pub sectors: Vec<[u8; 512]>,
}

#[cfg(test)]
impl BlockDevice for MemoryBlockDevice {
    fn read_block(&mut self, lba: u32, buf: &mut [u8; 512]) -> Result<(), IpcError> {
        let sector = self.sectors.get(lba as usize).ok_or(IpcError::NotFound)?;
        buf.copy_from_slice(sector);
        Ok(())
    }

    fn capacity_blocks(&self) -> u32 {
        self.sectors.len() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use harmony_unikernel::drivers::register_bank::mock::MockRegisterBank;
    use harmony_unikernel::drivers::sdhci::SdhciDriver;

    // SDHCI register offsets for test setup
    const SDHCI_PRESENT_STATE: usize = 0x24;
    const SDHCI_INT_STATUS: usize = 0x30;
    const SDHCI_RESPONSE_0: usize = 0x10;
    const SDHCI_RESPONSE_1: usize = 0x14;
    const SDHCI_RESPONSE_2: usize = 0x18;
    const SDHCI_RESPONSE_3: usize = 0x1C;
    const SDHCI_BUFFER_DATA: usize = 0x20;
    const INT_CMD_COMPLETE: u32 = 1 << 0;
    const INT_BUFFER_READ_READY: u32 = 1 << 5;
    const INT_TRANSFER_COMPLETE: u32 = 1 << 1;

    /// Set up MockRegisterBank for a successful init_card() call.
    /// CMD9 CSD v2.0 with C_SIZE=1000 → capacity = (1000+1)*1024 = 1_025_024 blocks.
    fn setup_init_card_mock(bank: &mut MockRegisterBank) {
        const C_SIZE: u32 = 1000;
        bank.on_read(SDHCI_PRESENT_STATE, vec![0]);
        bank.on_read(SDHCI_INT_STATUS, vec![INT_CMD_COMPLETE]);
        bank.on_read(
            SDHCI_RESPONSE_0,
            vec![0x1AA, 0x0120, 0xC0100000, 0, 0xAAAA0000, 0, 0, 0],
        );
        bank.on_read(SDHCI_RESPONSE_1, vec![0, C_SIZE << 8]);
        bank.on_read(SDHCI_RESPONSE_2, vec![0, 0]);
        bank.on_read(SDHCI_RESPONSE_3, vec![0, 1 << 22]);
    }

    /// Set up MockRegisterBank for a successful read_single_block.
    fn setup_read_mock(bank: &mut MockRegisterBank, data: &[u8; 512]) {
        bank.on_read(SDHCI_PRESENT_STATE, vec![0]);
        bank.on_read(
            SDHCI_INT_STATUS,
            vec![
                INT_CMD_COMPLETE,
                INT_BUFFER_READ_READY,
                INT_TRANSFER_COMPLETE,
            ],
        );
        bank.on_read(SDHCI_RESPONSE_0, vec![0]);
        let words: Vec<u32> = (0..128)
            .map(|i| {
                let off = i * 4;
                data[off] as u32
                    | (data[off + 1] as u32) << 8
                    | (data[off + 2] as u32) << 16
                    | (data[off + 3] as u32) << 24
            })
            .collect();
        bank.on_read(SDHCI_BUFFER_DATA, words);
    }

    fn make_sdhci_block_device() -> SdhciBlockDevice<MockRegisterBank> {
        let mut driver = SdhciDriver::new();
        let mut init_bank = MockRegisterBank::new();
        setup_init_card_mock(&mut init_bank);
        driver.init_card(&mut init_bank).unwrap();
        let bank = MockRegisterBank::new();
        SdhciBlockDevice::new(driver, bank)
    }

    #[test]
    fn memory_block_device_reads_sector() {
        let mut sector = [0u8; 512];
        sector[0] = 0xAA;
        sector[511] = 0xBB;
        let mut dev = MemoryBlockDevice {
            sectors: vec![sector],
        };
        let mut buf = [0u8; 512];
        dev.read_block(0, &mut buf).unwrap();
        assert_eq!(buf[0], 0xAA);
        assert_eq!(buf[511], 0xBB);
    }

    #[test]
    fn memory_block_device_out_of_range() {
        let mut dev = MemoryBlockDevice {
            sectors: vec![[0u8; 512]],
        };
        let mut buf = [0u8; 512];
        assert_eq!(dev.read_block(1, &mut buf), Err(IpcError::NotFound));
    }

    #[test]
    fn memory_block_device_capacity() {
        let dev = MemoryBlockDevice {
            sectors: vec![[0u8; 512]; 10],
        };
        assert_eq!(dev.capacity_blocks(), 10);
    }

    #[test]
    fn partition_wrapper_adds_base_lba() {
        let mut sectors = vec![[0u8; 512]; 200];
        sectors[105][0] = 0x42;
        let inner = MemoryBlockDevice { sectors };
        let mut part = PartitionBlockDevice::new(inner, 100, 50);
        let mut buf = [0u8; 512];
        part.read_block(5, &mut buf).unwrap();
        assert_eq!(buf[0], 0x42);
    }

    #[test]
    fn partition_wrapper_bounds_check() {
        let inner = MemoryBlockDevice {
            sectors: vec![[0u8; 512]; 200],
        };
        let mut part = PartitionBlockDevice::new(inner, 100, 50);
        let mut buf = [0u8; 512];
        assert_eq!(
            part.read_block(50, &mut buf),
            Err(IpcError::InvalidArgument)
        );
    }

    #[test]
    fn partition_wrapper_capacity() {
        let inner = MemoryBlockDevice {
            sectors: vec![[0u8; 512]; 200],
        };
        let part = PartitionBlockDevice::new(inner, 100, 50);
        assert_eq!(part.capacity_blocks(), 50);
    }

    #[test]
    fn parse_mbr_finds_fat32_partition() {
        let mut mbr = [0u8; 512];
        // Boot signature
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        // Partition entry 0 at offset 0x1BE
        mbr[0x1BE + 4] = 0x0C; // FAT32 LBA
                               // start_lba = 2048 (little-endian at offset 8)
        mbr[0x1BE + 8] = 0x00;
        mbr[0x1BE + 9] = 0x08;
        mbr[0x1BE + 10] = 0x00;
        mbr[0x1BE + 11] = 0x00;
        // size = 1_000_000 = 0x000F4240 (little-endian at offset 12)
        mbr[0x1BE + 12] = 0x40;
        mbr[0x1BE + 13] = 0x42;
        mbr[0x1BE + 14] = 0x0F;
        mbr[0x1BE + 15] = 0x00;

        let mut dev = MemoryBlockDevice { sectors: vec![mbr] };
        let entries = parse_mbr(&mut dev).unwrap();

        let e = entries[0].unwrap();
        assert_eq!(e.partition_type, 0x0C);
        assert_eq!(e.start_lba, 2048);
        assert_eq!(e.size_sectors, 1_000_000);
        assert!(entries[1].is_none());
        assert!(entries[2].is_none());
        assert!(entries[3].is_none());
    }

    #[test]
    fn parse_mbr_invalid_signature() {
        let mbr = [0u8; 512]; // no 0x55AA
        let mut dev = MemoryBlockDevice { sectors: vec![mbr] };
        assert_eq!(parse_mbr(&mut dev), Err(IpcError::InvalidArgument));
    }

    #[test]
    fn parse_mbr_empty_entries() {
        let mut mbr = [0u8; 512];
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        let mut dev = MemoryBlockDevice { sectors: vec![mbr] };
        let entries = parse_mbr(&mut dev).unwrap();
        assert!(entries.iter().all(|e| e.is_none()));
    }

    #[test]
    fn parse_mbr_multiple_partitions() {
        let mut mbr = [0u8; 512];
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        // Partition 0: FAT32 CHS
        mbr[0x1BE + 4] = 0x0B;
        mbr[0x1BE + 8..0x1BE + 12].copy_from_slice(&100u32.to_le_bytes());
        mbr[0x1BE + 12..0x1BE + 16].copy_from_slice(&500u32.to_le_bytes());
        // Partition 1: FAT32 LBA
        mbr[0x1CE + 4] = 0x0C;
        mbr[0x1CE + 8..0x1CE + 12].copy_from_slice(&600u32.to_le_bytes());
        mbr[0x1CE + 12..0x1CE + 16].copy_from_slice(&1000u32.to_le_bytes());

        let mut dev = MemoryBlockDevice { sectors: vec![mbr] };
        let entries = parse_mbr(&mut dev).unwrap();

        let e0 = entries[0].unwrap();
        assert_eq!(e0.partition_type, 0x0B);
        assert_eq!(e0.start_lba, 100);
        let e1 = entries[1].unwrap();
        assert_eq!(e1.partition_type, 0x0C);
        assert_eq!(e1.start_lba, 600);
    }

    #[test]
    fn sdhci_adapter_reads_block() {
        let mut dev = make_sdhci_block_device();
        let mut expected = [0u8; 512];
        expected[0] = 0xDE;
        expected[511] = 0xAD;
        setup_read_mock(&mut dev.bank, &expected);

        let mut buf = [0u8; 512];
        dev.read_block(0, &mut buf).unwrap();
        assert_eq!(buf[0], 0xDE);
        assert_eq!(buf[511], 0xAD);
    }

    #[test]
    fn sdhci_adapter_capacity() {
        let dev = make_sdhci_block_device();
        // CMD9 CSD v2.0: C_SIZE=1000 → (1000+1)*1024 = 1_025_024
        assert_eq!(dev.capacity_blocks(), 1_025_024);
    }
}
