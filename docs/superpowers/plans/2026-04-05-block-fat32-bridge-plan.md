# Block Device Abstraction and Read-Only FAT32 FileServer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a `BlockDevice` trait, MBR parser, FAT32 parser with LFN support, and a read-only `FatServer` implementing `FileServer` — exposing FAT32 partitions through the 9P namespace.

**Architecture:** Three new files in harmony-microkernel: `block_device.rs` (trait + adapters + MBR parser), `fat32.rs` (FAT32 parser with LFN), `fat_server.rs` (FileServer impl wrapping Fat32). All tested via in-memory `MemoryBlockDevice` with synthetic FAT32 images. No boot code changes.

**Tech Stack:** Rust, harmony-microkernel crate, `FidTracker<T>` for fid management, `SdhciDriver` + `RegisterBank` from harmony-unikernel

---

## File Structure

| File | Change | Responsibility |
|------|--------|---------------|
| `crates/harmony-microkernel/src/block_device.rs` | Create | `BlockDevice` trait, `MemoryBlockDevice` (test), `SdhciBlockDevice`, `PartitionBlockDevice`, MBR parser |
| `crates/harmony-microkernel/src/fat32.rs` | Create | FAT32 BPB parsing, cluster chains, directory reading with LFN, file range reads, `build_fat32_image()` test helper |
| `crates/harmony-microkernel/src/fat_server.rs` | Create | `FatServer` implementing `FileServer` — walk/open/read/stat/clunk/clone over FAT32 |
| `crates/harmony-microkernel/src/lib.rs` | Modify | Register new modules |

---

### Task 1: BlockDevice Trait, Adapters, and MBR Parser

**Files:**
- Create: `crates/harmony-microkernel/src/block_device.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs:18` (add module registration)

**Context:** The `SdhciDriver` in harmony-unikernel exposes `read_single_block(&mut bank, lba, &mut buf)` and `card_info() -> Option<&CardInfo>` where `CardInfo` has `capacity_blocks: u32`. The `RegisterBank` trait and `MockRegisterBank` are in `harmony_unikernel::drivers`. The `SdServer` in `sd_server.rs` shows the existing pattern for wrapping SDHCI — but it directly embeds the driver. We're adding an abstraction layer so `Fat32` can work with any block device. `IpcError` is in `crate::IpcError`.

- [ ] **Step 1: Write the failing tests**

Create `crates/harmony-microkernel/src/block_device.rs` with the trait definition, type stubs, and all tests. The implementations are empty stubs that won't compile:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! Block device abstraction layer.
//!
//! Provides a `BlockDevice` trait for uniform 512-byte sector I/O,
//! an MBR partition table parser, and adapters for SDHCI and
//! partition-offset wrapping.

extern crate alloc;

use crate::IpcError;

/// Uniform interface for 512-byte sector I/O.
pub trait BlockDevice {
    /// Read a single 512-byte sector at the given LBA.
    fn read_block(&mut self, lba: u32, buf: &mut [u8; 512]) -> Result<(), IpcError>;

    /// Total number of 512-byte sectors on the device.
    fn capacity_blocks(&self) -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_block_device_reads_sector() {
        let mut sector = [0u8; 512];
        sector[0] = 0xAA;
        sector[511] = 0xBB;
        let mut dev = MemoryBlockDevice { sectors: vec![sector] };
        let mut buf = [0u8; 512];
        dev.read_block(0, &mut buf).unwrap();
        assert_eq!(buf[0], 0xAA);
        assert_eq!(buf[511], 0xBB);
    }

    #[test]
    fn memory_block_device_out_of_range() {
        let mut dev = MemoryBlockDevice { sectors: vec![[0u8; 512]] };
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
        assert_eq!(part.read_block(50, &mut buf), Err(IpcError::InvalidArgument));
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
}
```

Register the module. Add to `crates/harmony-microkernel/src/lib.rs` after the `pub mod echo;` line:

```rust
pub mod block_device;
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel -- block_device::tests`

Expected: FAIL — `MemoryBlockDevice`, `PartitionBlockDevice`, and `parse_mbr` are not defined.

- [ ] **Step 3: Implement MemoryBlockDevice, PartitionBlockDevice, and MBR parser**

Add these implementations above the `#[cfg(test)]` block in `block_device.rs`:

```rust
use alloc::vec::Vec;

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
        self.inner.read_block(self.base_lba + lba, buf)
    }

    fn capacity_blocks(&self) -> u32 {
        self.partition_size
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel -- block_device::tests`

Expected: All 9 tests PASS.

- [ ] **Step 5: Write the failing SdhciBlockDevice tests**

Add these tests to the `mod tests` block in `block_device.rs`:

```rust
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
            vec![INT_CMD_COMPLETE, INT_BUFFER_READ_READY, INT_TRANSFER_COMPLETE],
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
```

- [ ] **Step 6: Run tests to verify SdhciBlockDevice tests fail**

Run: `cargo test -p harmony-microkernel -- block_device::tests::sdhci`

Expected: FAIL — `SdhciBlockDevice` is not defined.

- [ ] **Step 7: Implement SdhciBlockDevice**

Add this above the `#[cfg(test)]` block, after `PartitionBlockDevice`:

```rust
// ── SdhciBlockDevice adapter ─────────────────────────────────────────

use harmony_unikernel::drivers::sdhci::SdhciDriver;
use harmony_unikernel::drivers::RegisterBank;

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
```

Move the `use` statements for `harmony_unikernel` to the top of the file (after `use crate::IpcError;`).

- [ ] **Step 8: Run all block_device tests**

Run: `cargo test -p harmony-microkernel -- block_device::tests`

Expected: All 11 tests PASS.

- [ ] **Step 9: Run the full workspace test suite**

Run: `cargo test -p harmony-microkernel`

Expected: All tests PASS (existing + 11 new).

- [ ] **Step 10: Commit**

```bash
git add crates/harmony-microkernel/src/block_device.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(block_device): BlockDevice trait, adapters, and MBR parser"
```

---

### Task 2: FAT32 Parser with LFN Support

**Files:**
- Create: `crates/harmony-microkernel/src/fat32.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs` (add module registration)

**Context:** The `BlockDevice` trait from Task 1 provides `read_block(lba, &mut [u8; 512])`. The FAT32 parser reads a BPB from sector 0 of the partition (the `BlockDevice` should already be scoped to the partition via `PartitionBlockDevice`). The parser supports FAT32 only (not FAT12/16), 512-byte sectors only, directory entries with 8.3 short names and VFAT long file names (LFN). A `build_fat32_image()` test helper constructs synthetic disk images in a `MemoryBlockDevice`.

**FAT32 disk layout used in tests (sectors_per_cluster=1, reserved=2, 2 FATs of 1 sector each):**
```
Sector 0: BPB (BIOS Parameter Block)
Sector 1: (reserved, unused)
Sector 2: FAT #1 (128 entries × 4 bytes = 512 bytes)
Sector 3: FAT #2 (copy of FAT #1)
Sector 4: Cluster 2 — root directory
Sector 5: Cluster 3 — overlays/ subdirectory
Sector 6: Cluster 4 — config.txt data ("hello world")
Sector 7: Cluster 5 — bcm2712-rpi-5-b.dtb data (first 512 bytes, 0xAA fill)
Sector 8: Cluster 6 — bcm2712-rpi-5-b.dtb data (remaining 88 bytes 0xBB + padding)
Sector 9: Cluster 7 — readme.txt data ("overlay file")
```

- [ ] **Step 1: Write the failing tests**

Create `crates/harmony-microkernel/src/fat32.rs` with the struct stubs and all tests:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! Read-only FAT32 filesystem parser.
//!
//! Supports FAT32 only (not FAT12/16), 512-byte sectors, 8.3 short
//! names, and VFAT long file names (LFN). No write support.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::block_device::BlockDevice;
use crate::IpcError;

/// A parsed directory entry (file or subdirectory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub start_cluster: u32,
    pub size: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_device::MemoryBlockDevice;

    #[test]
    fn parse_bpb_valid() {
        let mut dev = build_fat32_image();
        let fat = Fat32::new(dev).unwrap();
        assert_eq!(fat.sectors_per_cluster, 1);
        assert_eq!(fat.reserved_sectors, 2);
        assert_eq!(fat.root_cluster, 2);
        assert_eq!(fat.data_start_lba, 4); // 2 reserved + 2 FATs * 1 sector
    }

    #[test]
    fn parse_bpb_not_fat32() {
        let mut dev = build_fat32_image();
        // Corrupt: set fat_size_32 to 0 (not FAT32)
        dev.sectors[0][36] = 0;
        dev.sectors[0][37] = 0;
        dev.sectors[0][38] = 0;
        dev.sectors[0][39] = 0;
        assert_eq!(Fat32::new(dev), Err(IpcError::InvalidArgument));
    }

    #[test]
    fn parse_bpb_bad_sector_size() {
        let mut dev = build_fat32_image();
        // Set bytes_per_sector to 1024
        dev.sectors[0][11] = 0x00;
        dev.sectors[0][12] = 0x04;
        assert_eq!(Fat32::new(dev), Err(IpcError::InvalidArgument));
    }

    #[test]
    fn cluster_chain_end() {
        let mut dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        // Cluster 2 (root dir) → EOC
        assert_eq!(fat.next_cluster(2).unwrap(), None);
    }

    #[test]
    fn cluster_chain_continues() {
        let mut dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        // Cluster 5 → 6 (bcm2712 file spans two clusters)
        assert_eq!(fat.next_cluster(5).unwrap(), Some(6));
        // Cluster 6 → EOC
        assert_eq!(fat.next_cluster(6).unwrap(), None);
    }

    #[test]
    fn read_dir_short_names() {
        let mut dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        let entries = fat.read_dir(2).unwrap(); // root dir
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"config.txt"));
        assert!(names.contains(&"overlays"));
    }

    #[test]
    fn read_dir_lfn() {
        let mut dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        let entries = fat.read_dir(2).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"bcm2712-rpi-5-b.dtb"));
    }

    #[test]
    fn read_dir_mixed() {
        let mut dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        let entries = fat.read_dir(2).unwrap();
        // Should have exactly 3 entries: bcm2712 (LFN), config.txt (short), overlays (short dir)
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn read_dir_skips_deleted() {
        let mut dev = build_fat32_image();
        // Mark config.txt entry as deleted (it's at a known offset in sector 4)
        // The root dir has: 2 LFN entries + 1 8.3 for bcm2712, then config.txt, then overlays
        // Each entry is 32 bytes. LFN1 at 0, LFN2 at 32, 8.3 at 64, config at 96, overlays at 128
        // Actually LFN entries are stored in reverse: last first.
        // On disk: LFN seq 2 at offset 0, LFN seq 1 at offset 32, 8.3 at offset 64, config at 96
        dev.sectors[4][96] = 0xE5; // mark config.txt as deleted
        let mut fat = Fat32::new(dev).unwrap();
        let entries = fat.read_dir(2).unwrap();
        assert_eq!(entries.len(), 2); // bcm2712 + overlays
        assert!(!entries.iter().any(|e| e.name == "config.txt"));
    }

    #[test]
    fn read_dir_skips_volume_label() {
        let mut dev = build_fat32_image();
        // Insert a volume label entry before config.txt by modifying its attr
        // Actually, let's corrupt the config.txt entry to be a volume label
        dev.sectors[4][96 + 11] = 0x08; // attr = volume label
        let mut fat = Fat32::new(dev).unwrap();
        let entries = fat.read_dir(2).unwrap();
        assert_eq!(entries.len(), 2); // bcm2712 + overlays (config became label, skipped)
    }

    #[test]
    fn read_dir_end_marker() {
        let mut dev = build_fat32_image();
        // Place end marker before overlays entry (offset 128)
        dev.sectors[4][128] = 0x00;
        let mut fat = Fat32::new(dev).unwrap();
        let entries = fat.read_dir(2).unwrap();
        assert_eq!(entries.len(), 2); // bcm2712 + config.txt (overlays hidden by end marker)
    }

    #[test]
    fn read_dir_subdirectory_entry() {
        let mut dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        let entries = fat.read_dir(2).unwrap();
        let overlays = entries.iter().find(|e| e.name == "overlays").unwrap();
        assert!(overlays.is_dir);
        assert_eq!(overlays.start_cluster, 3);
    }

    #[test]
    fn read_dir_subdir_contents() {
        let mut dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        let entries = fat.read_dir(3).unwrap(); // overlays dir at cluster 3
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "readme.txt");
        assert_eq!(entries[0].size, 12);
    }

    #[test]
    fn read_file_single_cluster() {
        let mut dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        // config.txt: cluster 4, size 11, "hello world"
        let data = fat.read_file_range(4, 11, 0, 11).unwrap();
        assert_eq!(&data, b"hello world");
    }

    #[test]
    fn read_file_multi_cluster() {
        let mut dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        // bcm2712: clusters 5→6, size 600
        let data = fat.read_file_range(5, 600, 0, 600).unwrap();
        assert_eq!(data.len(), 600);
        assert!(data[..512].iter().all(|&b| b == 0xAA));
        assert!(data[512..600].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn read_file_with_offset() {
        let mut dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        // Read "world" from config.txt (offset 6, count 5)
        let data = fat.read_file_range(4, 11, 6, 5).unwrap();
        assert_eq!(&data, b"world");
    }

    #[test]
    fn read_file_offset_spans_clusters() {
        let mut dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        // Read 10 bytes starting at offset 508 of bcm2712 (crosses cluster boundary)
        let data = fat.read_file_range(5, 600, 508, 10).unwrap();
        assert_eq!(data.len(), 10);
        assert!(data[..4].iter().all(|&b| b == 0xAA)); // last 4 bytes of cluster 5
        assert!(data[4..].iter().all(|&b| b == 0xBB)); // first 6 bytes of cluster 6
    }

    #[test]
    fn read_file_clamped_to_size() {
        let mut dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        // Request 1000 bytes but file is only 11
        let data = fat.read_file_range(4, 11, 0, 1000).unwrap();
        assert_eq!(data.len(), 11);
    }

    #[test]
    fn read_file_offset_past_end() {
        let mut dev = build_fat32_image();
        let mut fat = Fat32::new(dev).unwrap();
        let data = fat.read_file_range(4, 11, 100, 5).unwrap();
        assert!(data.is_empty());
    }
}
```

Register the module. Add to `crates/harmony-microkernel/src/lib.rs` after `pub mod echo;`:

```rust
pub mod fat32;
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel -- fat32::tests`

Expected: FAIL — `Fat32`, `build_fat32_image` are not defined.

- [ ] **Step 3: Implement the `build_fat32_image()` test helper**

Add this `#[cfg(test)]` function at module level (above `mod tests`, below `DirEntry`):

```rust
/// Build a synthetic FAT32 image for testing.
///
/// Layout (sectors_per_cluster=1, reserved=2, 2 FATs of 1 sector each):
/// - Sector 0: BPB
/// - Sector 1: reserved
/// - Sector 2: FAT #1
/// - Sector 3: FAT #2
/// - Sector 4: Cluster 2 — root directory
/// - Sector 5: Cluster 3 — overlays/ subdirectory
/// - Sector 6: Cluster 4 — config.txt ("hello world")
/// - Sector 7: Cluster 5 — bcm2712-rpi-5-b.dtb (first 512 bytes, 0xAA)
/// - Sector 8: Cluster 6 — bcm2712-rpi-5-b.dtb (88 bytes 0xBB + padding)
/// - Sector 9: Cluster 7 — readme.txt ("overlay file")
///
/// FAT chain: [2]=EOC, [3]=EOC, [4]=EOC, [5]→6, [6]=EOC, [7]=EOC
#[cfg(test)]
pub(crate) fn build_fat32_image() -> crate::block_device::MemoryBlockDevice {
    let mut sectors = vec![[0u8; 512]; 64];

    // ── Sector 0: BPB ────────────────────────────────────────────
    let bpb = &mut sectors[0];
    bpb[0] = 0xEB; bpb[1] = 0x58; bpb[2] = 0x90; // jump
    bpb[3..11].copy_from_slice(b"MSDOS5.0");       // OEM name
    bpb[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes_per_sector
    bpb[13] = 1;                                    // sectors_per_cluster
    bpb[14..16].copy_from_slice(&2u16.to_le_bytes()); // reserved_sectors
    bpb[16] = 2;                                    // num_fats
    // bpb[17..19] root_entry_count = 0 (FAT32)
    // bpb[19..21] total_sectors_16 = 0 (FAT32)
    bpb[21] = 0xF8;                                 // media type
    // bpb[22..24] fat_size_16 = 0 (FAT32)
    bpb[32..36].copy_from_slice(&64u32.to_le_bytes()); // total_sectors_32
    bpb[36..40].copy_from_slice(&1u32.to_le_bytes());  // fat_size_32
    bpb[44..48].copy_from_slice(&2u32.to_le_bytes());  // root_cluster
    bpb[510] = 0x55; bpb[511] = 0xAA;               // boot signature

    // ── Sectors 2-3: FAT tables ──────────────────────────────────
    let fat = &mut sectors[2];
    // Each FAT entry is 4 bytes, little-endian
    fat[0..4].copy_from_slice(&0x0FFFFFF8u32.to_le_bytes());  // FAT[0] media
    fat[4..8].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes());  // FAT[1] reserved
    fat[8..12].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes()); // FAT[2] root dir EOC
    fat[12..16].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes()); // FAT[3] overlays EOC
    fat[16..20].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes()); // FAT[4] config.txt EOC
    fat[20..24].copy_from_slice(&6u32.to_le_bytes());          // FAT[5] → cluster 6
    fat[24..28].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes()); // FAT[6] bcm2712 EOC
    fat[28..32].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes()); // FAT[7] readme EOC
    // Copy to FAT #2
    sectors[3] = sectors[2];

    // ── Sector 4: Root directory (cluster 2) ─────────────────────
    let root = &mut sectors[4];

    // Entry 0 (offset 0): LFN sequence 2 (last) for "bcm2712-rpi-5-b.dtb"
    // Full name: "bcm2712-rpi-5-b.dtb" = 19 chars
    // LFN entry 2 (seq 0x42): chars 14-19 = '-','b','.','d','t','b' then null+pad
    root[0] = 0x42; // sequence: last (0x40) | 2
    // Bytes 1-10: chars 14-18 as UTF-16LE: '-','b','.','d','t'
    root[1] = 0x2D; root[2] = 0x00; // '-'
    root[3] = 0x62; root[4] = 0x00; // 'b'
    root[5] = 0x2E; root[6] = 0x00; // '.'
    root[7] = 0x64; root[8] = 0x00; // 'd'
    root[9] = 0x74; root[10] = 0x00; // 't'
    root[11] = 0x0F; // attr = LFN
    root[12] = 0x00; // type
    root[13] = 0x00; // checksum (ignored for now)
    // Bytes 14-25: chars 19 = 'b', then null, then 0xFFFF padding
    root[14] = 0x62; root[15] = 0x00; // 'b'
    root[16] = 0x00; root[17] = 0x00; // null terminator
    root[18] = 0xFF; root[19] = 0xFF; // padding
    root[20] = 0xFF; root[21] = 0xFF;
    root[22] = 0xFF; root[23] = 0xFF;
    root[24] = 0xFF; root[25] = 0xFF;
    // Byte 26-27: first cluster (always 0 for LFN)
    root[26] = 0x00; root[27] = 0x00;
    // Bytes 28-31: more padding
    root[28] = 0xFF; root[29] = 0xFF;
    root[30] = 0xFF; root[31] = 0xFF;

    // Entry 1 (offset 32): LFN sequence 1 for "bcm2712-rpi-5-b.dtb"
    // Chars 1-13: 'b','c','m','2','7','1','2','-','r','p','i','-','5'
    root[32] = 0x01; // sequence 1
    root[33] = 0x62; root[34] = 0x00; // 'b'
    root[35] = 0x63; root[36] = 0x00; // 'c'
    root[37] = 0x6D; root[38] = 0x00; // 'm'
    root[39] = 0x32; root[40] = 0x00; // '2'
    root[41] = 0x37; root[42] = 0x00; // '7'
    root[43] = 0x0F; // attr = LFN
    root[44] = 0x00;
    root[45] = 0x00; // checksum
    root[46] = 0x31; root[47] = 0x00; // '1'
    root[48] = 0x32; root[49] = 0x00; // '2'
    root[50] = 0x2D; root[51] = 0x00; // '-'
    root[52] = 0x72; root[53] = 0x00; // 'r'
    root[54] = 0x70; root[55] = 0x00; // 'p'
    root[56] = 0x69; root[57] = 0x00; // 'i'
    root[58] = 0x00; root[59] = 0x00; // cluster (0 for LFN)
    root[60] = 0x2D; root[61] = 0x00; // '-'
    root[62] = 0x35; root[63] = 0x00; // '5'

    // Entry 2 (offset 64): 8.3 entry for bcm2712 file
    root[64..72].copy_from_slice(b"BCM271~1");  // name
    root[72..75].copy_from_slice(b"DTB");        // ext
    root[75] = 0x20;                             // attr = ARCHIVE
    // cluster high (offset 84-85) = 0
    root[84] = 0x00; root[85] = 0x00;
    // cluster low (offset 90-91) = 5
    root[90] = 0x05; root[91] = 0x00;
    // size (offset 92-95) = 600
    root[92..96].copy_from_slice(&600u32.to_le_bytes());

    // Entry 3 (offset 96): 8.3 entry for config.txt
    root[96..104].copy_from_slice(b"CONFIG  ");  // name
    root[104..107].copy_from_slice(b"TXT");      // ext
    root[107] = 0x20;                            // attr = ARCHIVE
    root[116] = 0x00; root[117] = 0x00;         // cluster high = 0
    root[122] = 0x04; root[123] = 0x00;         // cluster low = 4
    root[124..128].copy_from_slice(&11u32.to_le_bytes()); // size = 11

    // Entry 4 (offset 128): 8.3 entry for overlays/ directory
    root[128..136].copy_from_slice(b"OVERLAYS");
    root[136..139].copy_from_slice(b"   ");      // no extension
    root[139] = 0x10;                            // attr = DIRECTORY
    root[148] = 0x00; root[149] = 0x00;         // cluster high = 0
    root[154] = 0x03; root[155] = 0x00;         // cluster low = 3
    root[156..160].copy_from_slice(&0u32.to_le_bytes()); // size = 0

    // ── Sector 5: overlays/ subdirectory (cluster 3) ─────────────
    let subdir = &mut sectors[5];

    // Entry 0: "." (self)
    subdir[0..8].copy_from_slice(b".       ");
    subdir[8..11].copy_from_slice(b"   ");
    subdir[11] = 0x10; // DIRECTORY
    subdir[26] = 0x03; subdir[27] = 0x00; // cluster 3

    // Entry 1: ".." (parent)
    subdir[32..40].copy_from_slice(b"..      ");
    subdir[40..43].copy_from_slice(b"   ");
    subdir[43] = 0x10; // DIRECTORY
    subdir[58] = 0x02; subdir[59] = 0x00; // cluster 2

    // Entry 2: readme.txt
    subdir[64..72].copy_from_slice(b"README  ");
    subdir[72..75].copy_from_slice(b"TXT");
    subdir[75] = 0x20; // ARCHIVE
    subdir[84] = 0x00; subdir[85] = 0x00; // cluster high
    subdir[90] = 0x07; subdir[91] = 0x00; // cluster low = 7
    subdir[92..96].copy_from_slice(&12u32.to_le_bytes()); // size = 12

    // ── Sector 6: config.txt data (cluster 4) ────────────────────
    sectors[6][..11].copy_from_slice(b"hello world");

    // ── Sector 7: bcm2712 data part 1 (cluster 5) ───────────────
    sectors[7] = [0xAA; 512];

    // ── Sector 8: bcm2712 data part 2 (cluster 6) ───────────────
    sectors[8][..88].fill(0xBB);

    // ── Sector 9: readme.txt data (cluster 7) ───────────────────
    sectors[9][..12].copy_from_slice(b"overlay file");

    crate::block_device::MemoryBlockDevice { sectors }
}
```

- [ ] **Step 4: Implement the Fat32 struct and all methods**

Add between `DirEntry` and the `build_fat32_image` function:

```rust
/// Read-only FAT32 filesystem parser.
///
/// Reads BPB metadata on construction, then provides on-demand
/// cluster chain following, directory listing, and file range reads.
/// All I/O goes through the provided `BlockDevice`.
pub struct Fat32<D: BlockDevice> {
    block_dev: D,
    pub(crate) sectors_per_cluster: u8,
    pub(crate) reserved_sectors: u16,
    num_fats: u8,
    fat_size_32: u32,
    pub(crate) root_cluster: u32,
    pub(crate) data_start_lba: u32,
}

impl<D: BlockDevice> Fat32<D> {
    /// Parse the BPB from sector 0 and initialize the parser.
    ///
    /// Takes ownership of `block_dev` for subsequent reads.
    /// Returns `InvalidArgument` if the volume is not valid FAT32.
    pub fn new(mut block_dev: D) -> Result<Self, IpcError> {
        let mut bpb = [0u8; 512];
        block_dev.read_block(0, &mut bpb)?;

        let bytes_per_sector = u16::from_le_bytes([bpb[11], bpb[12]]);
        if bytes_per_sector != 512 {
            return Err(IpcError::InvalidArgument);
        }

        let sectors_per_cluster = bpb[13];
        if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
            return Err(IpcError::InvalidArgument);
        }

        let reserved_sectors = u16::from_le_bytes([bpb[14], bpb[15]]);
        let num_fats = bpb[16];
        let fat_size_32 = u32::from_le_bytes([bpb[36], bpb[37], bpb[38], bpb[39]]);
        if fat_size_32 == 0 {
            return Err(IpcError::InvalidArgument);
        }

        let root_cluster = u32::from_le_bytes([bpb[44], bpb[45], bpb[46], bpb[47]]);
        if root_cluster < 2 {
            return Err(IpcError::InvalidArgument);
        }

        let total_sectors_32 = u32::from_le_bytes([bpb[32], bpb[33], bpb[34], bpb[35]]);
        if total_sectors_32 == 0 {
            return Err(IpcError::InvalidArgument);
        }

        let data_start_lba = reserved_sectors as u32 + num_fats as u32 * fat_size_32;

        Ok(Self {
            block_dev,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            fat_size_32,
            root_cluster,
            data_start_lba,
        })
    }

    /// Follow the FAT chain: given a cluster, return the next cluster
    /// or `None` if this is the end of the chain (>= 0x0FFFFFF8).
    pub fn next_cluster(&mut self, cluster: u32) -> Result<Option<u32>, IpcError> {
        let fat_offset = cluster as u64 * 4;
        let fat_sector = self.reserved_sectors as u32 + (fat_offset / 512) as u32;
        let entry_offset = (fat_offset % 512) as usize;

        let mut sector = [0u8; 512];
        self.block_dev.read_block(fat_sector, &mut sector)?;

        let raw = u32::from_le_bytes([
            sector[entry_offset],
            sector[entry_offset + 1],
            sector[entry_offset + 2],
            sector[entry_offset + 3],
        ]) & 0x0FFFFFFF;

        if raw >= 0x0FFFFFF8 {
            Ok(None)
        } else if raw < 2 {
            Err(IpcError::InvalidArgument)
        } else {
            Ok(Some(raw))
        }
    }

    /// Read an entire cluster into `buf`.
    ///
    /// `buf` must be exactly `sectors_per_cluster * 512` bytes.
    pub fn read_cluster(&mut self, cluster: u32, buf: &mut [u8]) -> Result<(), IpcError> {
        let cluster_size = self.sectors_per_cluster as usize * 512;
        if buf.len() != cluster_size {
            return Err(IpcError::InvalidArgument);
        }

        let start_lba = self.data_start_lba + (cluster - 2) * self.sectors_per_cluster as u32;
        let mut sector_buf = [0u8; 512];
        for i in 0..self.sectors_per_cluster as u32 {
            self.block_dev.read_block(start_lba + i, &mut sector_buf)?;
            let offset = i as usize * 512;
            buf[offset..offset + 512].copy_from_slice(&sector_buf);
        }
        Ok(())
    }

    /// Read directory entries from a directory starting at `start_cluster`.
    ///
    /// Follows the cluster chain, parses 32-byte entries, reassembles
    /// LFN sequences, and skips deleted (0xE5), volume label (0x08),
    /// and dot/dotdot entries.
    pub fn read_dir(&mut self, start_cluster: u32) -> Result<Vec<DirEntry>, IpcError> {
        let cluster_size = self.sectors_per_cluster as usize * 512;
        let mut cluster_buf = alloc::vec![0u8; cluster_size];
        let mut entries = Vec::new();
        let mut lfn_buf: Vec<(u8, [u16; 13])> = Vec::new();
        let mut cluster = start_cluster;

        loop {
            self.read_cluster(cluster, &mut cluster_buf)?;

            for i in (0..cluster_size).step_by(32) {
                let entry = &cluster_buf[i..i + 32];

                if entry[0] == 0x00 {
                    return Ok(entries); // end of directory
                }
                if entry[0] == 0xE5 {
                    lfn_buf.clear();
                    continue; // deleted
                }

                let attr = entry[11];

                if attr == 0x0F {
                    // LFN entry
                    let seq = entry[0];
                    let mut chars = [0u16; 13];
                    for j in 0..5 {
                        chars[j] =
                            u16::from_le_bytes([entry[1 + j * 2], entry[2 + j * 2]]);
                    }
                    for j in 0..6 {
                        chars[5 + j] =
                            u16::from_le_bytes([entry[14 + j * 2], entry[15 + j * 2]]);
                    }
                    for j in 0..2 {
                        chars[11 + j] =
                            u16::from_le_bytes([entry[28 + j * 2], entry[29 + j * 2]]);
                    }
                    lfn_buf.push((seq, chars));
                    continue;
                }

                // Skip volume labels
                if attr & 0x08 != 0 && attr & 0x10 == 0 {
                    lfn_buf.clear();
                    continue;
                }

                // Skip . and .. entries
                if entry[0] == b'.' {
                    lfn_buf.clear();
                    continue;
                }

                let name = if !lfn_buf.is_empty() {
                    reassemble_lfn(&mut lfn_buf)
                } else {
                    parse_short_name(entry)
                };

                let is_dir = attr & 0x10 != 0;
                let hi = u16::from_le_bytes([entry[20], entry[21]]) as u32;
                let lo = u16::from_le_bytes([entry[26], entry[27]]) as u32;
                let start_cluster = (hi << 16) | lo;
                let size =
                    u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);

                entries.push(DirEntry {
                    name,
                    is_dir,
                    start_cluster,
                    size,
                });
            }

            match self.next_cluster(cluster)? {
                Some(next) => cluster = next,
                None => return Ok(entries),
            }
        }
    }

    /// Read `count` bytes starting at `offset` from a file's cluster chain.
    ///
    /// Follows the chain from `start_cluster`, skipping clusters to
    /// reach `offset`, then reads data. Clamps to `file_size`.
    /// Returns an empty vec if `offset >= file_size`.
    pub fn read_file_range(
        &mut self,
        start_cluster: u32,
        file_size: u32,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>, IpcError> {
        let file_size = file_size as u64;
        if offset >= file_size {
            return Ok(Vec::new());
        }

        let cluster_size = self.sectors_per_cluster as u64 * 512;
        let end = (offset + count as u64).min(file_size);
        let bytes_to_read = (end - offset) as usize;

        // Skip clusters to reach the one containing `offset`
        let clusters_to_skip = offset / cluster_size;
        let mut cluster = start_cluster;
        for _ in 0..clusters_to_skip {
            cluster = self
                .next_cluster(cluster)?
                .ok_or(IpcError::InvalidArgument)?;
        }

        let mut result = Vec::with_capacity(bytes_to_read);
        let mut cluster_buf = alloc::vec![0u8; cluster_size as usize];
        let mut pos_in_cluster = (offset % cluster_size) as usize;

        while result.len() < bytes_to_read {
            self.read_cluster(cluster, &mut cluster_buf)?;
            let available = cluster_size as usize - pos_in_cluster;
            let needed = bytes_to_read - result.len();
            let to_copy = available.min(needed);
            result.extend_from_slice(
                &cluster_buf[pos_in_cluster..pos_in_cluster + to_copy],
            );
            pos_in_cluster = 0;

            if result.len() < bytes_to_read {
                cluster = self
                    .next_cluster(cluster)?
                    .ok_or(IpcError::InvalidArgument)?;
            }
        }

        Ok(result)
    }
}

/// Reassemble a long file name from collected LFN entry fragments.
fn reassemble_lfn(lfn_buf: &mut Vec<(u8, [u16; 13])>) -> String {
    lfn_buf.sort_by_key(|(seq, _)| seq & 0x1F);

    let mut utf16: Vec<u16> = Vec::new();
    for (_, chars) in lfn_buf.iter() {
        for &c in chars {
            if c == 0x0000 || c == 0xFFFF {
                break;
            }
            utf16.push(c);
        }
    }
    lfn_buf.clear();

    String::from_utf16(&utf16).unwrap_or_else(|_| {
        utf16
            .iter()
            .map(|&c| if c < 128 { c as u8 as char } else { '?' })
            .collect()
    })
}

/// Parse an 8.3 directory entry name into a lowercase "name.ext" string.
fn parse_short_name(entry: &[u8]) -> String {
    let name_part: String = entry[0..8]
        .iter()
        .copied()
        .take_while(|&b| b != b' ')
        .map(|b| (b as char).to_ascii_lowercase())
        .collect();
    let ext_part: String = entry[8..11]
        .iter()
        .copied()
        .take_while(|&b| b != b' ')
        .map(|b| (b as char).to_ascii_lowercase())
        .collect();

    if ext_part.is_empty() {
        name_part
    } else {
        alloc::format!("{}.{}", name_part, ext_part)
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel -- fat32::tests`

Expected: All 17 tests PASS.

- [ ] **Step 6: Run the full crate test suite**

Run: `cargo test -p harmony-microkernel`

Expected: All tests PASS (existing + 17 new).

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-microkernel/src/fat32.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(fat32): read-only FAT32 parser with LFN support"
```

---

### Task 3: FatServer — FileServer Implementation

**Files:**
- Create: `crates/harmony-microkernel/src/fat_server.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs` (add module registration)

**Context:** `FatServer` wraps a `Fat32<D>` to expose FAT32 files via the `FileServer` trait. Uses `FidTracker<NodeKind>` (same pattern as `ContentServer`, `SdServer`). Root fid 0 is pre-attached to the root directory. Walk resolves names via `fat.read_dir()` with case-insensitive matching. Read-only: `write()` returns `PermissionDenied`, `open()` rejects `Write`/`ReadWrite`.

The `build_fat32_image()` helper from `fat32.rs` is `#[cfg(test)] pub(crate)`, importable as `crate::fat32::build_fat32_image`.

- [ ] **Step 1: Write the failing tests**

Create `crates/harmony-microkernel/src/fat_server.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! FatServer — read-only 9P file server for FAT32 filesystems.
//!
//! Wraps a [`Fat32`] parser to expose files and directories via
//! the [`FileServer`] trait. Supports walk, open, read, stat,
//! clunk, and clone_fid. All write operations are rejected.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::block_device::BlockDevice;
use crate::fat32::Fat32;
use crate::fid_tracker::FidTracker;
use crate::{Fid, FileServer, FileStat, FileType, IpcError, OpenMode, QPath};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fat32::build_fat32_image;

    fn make_fat_server() -> FatServer<crate::block_device::MemoryBlockDevice> {
        let dev = build_fat32_image();
        FatServer::new(dev).unwrap()
    }

    #[test]
    fn walk_to_file() {
        let mut srv = make_fat_server();
        let qpath = srv.walk(0, 1, "config.txt").unwrap();
        assert_eq!(qpath, 4); // start cluster 4
    }

    #[test]
    fn walk_to_lfn_file() {
        let mut srv = make_fat_server();
        let qpath = srv.walk(0, 1, "bcm2712-rpi-5-b.dtb").unwrap();
        assert_eq!(qpath, 5); // start cluster 5
    }

    #[test]
    fn walk_case_insensitive() {
        let mut srv = make_fat_server();
        let qpath = srv.walk(0, 1, "CONFIG.TXT").unwrap();
        assert_eq!(qpath, 4);
    }

    #[test]
    fn walk_to_subdir_then_file() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "overlays").unwrap();
        let qpath = srv.walk(1, 2, "readme.txt").unwrap();
        assert_eq!(qpath, 7); // start cluster 7
    }

    #[test]
    fn walk_nonexistent() {
        let mut srv = make_fat_server();
        assert_eq!(srv.walk(0, 1, "nope.txt"), Err(IpcError::NotFound));
    }

    #[test]
    fn walk_into_file_rejected() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "config.txt").unwrap();
        assert_eq!(srv.walk(1, 2, "sub"), Err(IpcError::NotDirectory));
    }

    #[test]
    fn read_file_contents() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "config.txt").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 0, 100).unwrap();
        assert_eq!(&data, b"hello world");
    }

    #[test]
    fn read_file_with_offset() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "config.txt").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 6, 5).unwrap();
        assert_eq!(&data, b"world");
    }

    #[test]
    fn read_multi_cluster_file() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "bcm2712-rpi-5-b.dtb").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        let data = srv.read(1, 0, 600).unwrap();
        assert_eq!(data.len(), 600);
        assert!(data[..512].iter().all(|&b| b == 0xAA));
        assert!(data[512..].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn read_directory_rejected() {
        let mut srv = make_fat_server();
        srv.open(0, OpenMode::Read).unwrap();
        assert_eq!(srv.read(0, 0, 100), Err(IpcError::IsDirectory));
    }

    #[test]
    fn write_rejected() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "config.txt").unwrap();
        srv.open(1, OpenMode::Read).unwrap();
        assert_eq!(srv.write(1, 0, b"nope"), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn open_write_mode_rejected() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "config.txt").unwrap();
        assert_eq!(srv.open(1, OpenMode::Write), Err(IpcError::PermissionDenied));
    }

    #[test]
    fn stat_file() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "config.txt").unwrap();
        let st = srv.stat(1).unwrap();
        assert_eq!(&*st.name, "config.txt");
        assert_eq!(st.size, 11);
        assert_eq!(st.file_type, FileType::Regular);
        assert_eq!(st.qpath, 4);
    }

    #[test]
    fn stat_directory() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "overlays").unwrap();
        let st = srv.stat(1).unwrap();
        assert_eq!(&*st.name, "overlays");
        assert_eq!(st.size, 0);
        assert_eq!(st.file_type, FileType::Directory);
    }

    #[test]
    fn stat_root() {
        let mut srv = make_fat_server();
        let st = srv.stat(0).unwrap();
        assert_eq!(&*st.name, "/");
        assert_eq!(st.file_type, FileType::Directory);
    }

    #[test]
    fn clone_fid_works() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "config.txt").unwrap();
        let qpath = srv.clone_fid(1, 2).unwrap();
        assert_eq!(qpath, 4);
        let st = srv.stat(2).unwrap();
        assert_eq!(&*st.name, "config.txt");
    }

    #[test]
    fn clunk_and_reuse() {
        let mut srv = make_fat_server();
        srv.walk(0, 1, "config.txt").unwrap();
        srv.clunk(1).unwrap();
        // Reuse fid 1
        let qpath = srv.walk(0, 1, "overlays").unwrap();
        assert_eq!(qpath, 3);
    }
}
```

Register the module. Add to `crates/harmony-microkernel/src/lib.rs` after `pub mod fat32;`:

```rust
pub mod fat_server;
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel -- fat_server::tests`

Expected: FAIL — `FatServer` and `NodeKind` are not defined.

- [ ] **Step 3: Implement FatServer**

Add above the `#[cfg(test)]` block:

```rust
/// What kind of node a fid points at in the FAT32 filesystem.
#[derive(Debug, Clone)]
enum NodeKind {
    RootDir,
    SubDir {
        cluster: u32,
        name: Arc<str>,
    },
    File {
        cluster: u32,
        size: u32,
        name: Arc<str>,
    },
}

/// Read-only 9P file server for FAT32 filesystems.
///
/// Wraps a [`Fat32`] parser. Walk resolves names via directory reads
/// with case-insensitive matching. Write operations are rejected.
pub struct FatServer<D: BlockDevice> {
    fat: Fat32<D>,
    tracker: FidTracker<NodeKind>,
}

impl<D: BlockDevice> FatServer<D> {
    /// Create a new FatServer by parsing the FAT32 filesystem on `block_dev`.
    pub fn new(block_dev: D) -> Result<Self, IpcError> {
        let fat = Fat32::new(block_dev)?;
        let tracker = FidTracker::new(0, NodeKind::RootDir);
        Ok(Self { fat, tracker })
    }
}

impl<D: BlockDevice> FileServer for FatServer<D> {
    fn walk(&mut self, fid: Fid, new_fid: Fid, name: &str) -> Result<QPath, IpcError> {
        let entry = self.tracker.get(fid)?;
        let dir_cluster = match &entry.payload {
            NodeKind::RootDir => self.fat.root_cluster,
            NodeKind::SubDir { cluster, .. } => *cluster,
            NodeKind::File { .. } => return Err(IpcError::NotDirectory),
        };

        let dir_entries = self.fat.read_dir(dir_cluster)?;
        let found = dir_entries
            .into_iter()
            .find(|e| e.name.eq_ignore_ascii_case(name))
            .ok_or(IpcError::NotFound)?;

        let qpath = found.start_cluster as QPath;
        let node = if found.is_dir {
            NodeKind::SubDir {
                cluster: found.start_cluster,
                name: Arc::from(found.name.as_str()),
            }
        } else {
            NodeKind::File {
                cluster: found.start_cluster,
                size: found.size,
                name: Arc::from(found.name.as_str()),
            }
        };

        self.tracker.insert(new_fid, qpath, node)?;
        Ok(qpath)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        if matches!(mode, OpenMode::Write | OpenMode::ReadWrite) {
            return Err(IpcError::PermissionDenied);
        }
        let entry = self.tracker.begin_open(fid)?;
        entry.mark_open(mode);
        Ok(())
    }

    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        let entry = self.tracker.get(fid)?;
        if !entry.is_open() {
            return Err(IpcError::NotOpen);
        }
        match &entry.payload {
            NodeKind::RootDir | NodeKind::SubDir { .. } => Err(IpcError::IsDirectory),
            NodeKind::File { cluster, size, .. } => {
                let cluster = *cluster;
                let size = *size;
                self.fat.read_file_range(cluster, size, offset, count)
            }
        }
    }

    fn write(&mut self, _fid: Fid, _offset: u64, _data: &[u8]) -> Result<u32, IpcError> {
        Err(IpcError::PermissionDenied)
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        self.tracker.clunk(fid)
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        let entry = self.tracker.get(fid)?;
        match &entry.payload {
            NodeKind::RootDir => Ok(FileStat {
                qpath: 0,
                name: Arc::from("/"),
                size: 0,
                file_type: FileType::Directory,
            }),
            NodeKind::SubDir { cluster, name } => Ok(FileStat {
                qpath: *cluster as QPath,
                name: Arc::clone(name),
                size: 0,
                file_type: FileType::Directory,
            }),
            NodeKind::File {
                cluster,
                size,
                name,
            } => Ok(FileStat {
                qpath: *cluster as QPath,
                name: Arc::clone(name),
                size: *size as u64,
                file_type: FileType::Regular,
            }),
        }
    }

    fn clone_fid(&mut self, fid: Fid, new_fid: Fid) -> Result<QPath, IpcError> {
        self.tracker.clone_fid(fid, new_fid)
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel -- fat_server::tests`

Expected: All 17 tests PASS.

- [ ] **Step 5: Run the full crate test suite**

Run: `cargo test -p harmony-microkernel`

Expected: All tests PASS (existing + 11 block_device + 17 fat32 + 17 fat_server = 45 new).

- [ ] **Step 6: Run workspace tests and clippy**

Run: `cargo test --workspace && cargo clippy --workspace`

Expected: All tests PASS, no clippy warnings.

- [ ] **Step 7: Format with nightly rustfmt**

Run: `cargo +nightly fmt --all`

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-microkernel/src/fat_server.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(fat_server): read-only FatServer exposing FAT32 via 9P FileServer"
```
