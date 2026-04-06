# Block Device Abstraction and Read-Only FAT32 FileServer

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Bead:** harmony-os-8e4

**Goal:** Introduce a `BlockDevice` trait, MBR partition parser, FAT32 filesystem parser (with LFN support), and a read-only `FatServer` implementing `FileServer` — so FAT32 partitions on SD cards are accessible through the 9P namespace.

**Prerequisite:** SDHCI driver (`sdhci.rs`) and `SdServer` (`sd_server.rs`) are functional. The `FileServer` trait, `FidTracker`, and kernel process model are stable (PRs #116-#118 merged).

---

## Architecture

Three new files in `harmony-microkernel`, matching the existing separation of concerns:

1. **`block_device.rs`** — `BlockDevice` trait, `SdhciBlockDevice` adapter, `PartitionBlockDevice` offset wrapper, MBR parser, and `MemoryBlockDevice` (test-only).

2. **`fat32.rs`** — FAT32 filesystem parser. Reads BPB, follows cluster chains, parses directory entries (8.3 + LFN), reads file data ranges. Stateless except for cached BPB metadata. All I/O goes through `BlockDevice`.

3. **`fat_server.rs`** — `FatServer` implementing `FileServer`. Wraps `Fat32` to expose files and directories via 9P walk/open/read/stat/clunk operations. Uses `FidTracker<NodeKind>` for fid management.

No boot code changes. No changes to existing files (kernel.rs, namespace.rs, sd_server.rs, lib.rs). The Kernel is not yet in the boot path (harmony-os-5gh). `FatServer` is exercised via `cargo test` in std.

### Data Flow

```
SdhciDriver + RegisterBank
  → SdhciBlockDevice (impl BlockDevice)
    → PartitionBlockDevice { inner, base_lba, partition_size }
      → Fat32 { block_dev, bpb metadata }
        → FatServer (impl FileServer)
          → mounted in 9P namespace by caller via spawn_process()
```

### Data Flow (future, after harmony-os-5gh wiring)

```
Boot code discovers SD card via FDT
  → init_card() on SdhciDriver
  → SdhciBlockDevice wraps driver + bank
  → parse_mbr() finds FAT32 partition (type 0x0B/0x0C)
  → PartitionBlockDevice wraps with base_lba offset
  → FatServer::new(partition_block_dev) parses BPB
  → kernel.spawn_process("fat", Box::new(fat_server), &[...])
  → mounted at caller-chosen path (e.g., "/boot/")
```

---

## BlockDevice Trait

### Interface

```rust
pub trait BlockDevice {
    fn read_block(&mut self, lba: u32, buf: &mut [u8; 512]) -> Result<(), IpcError>;
    fn capacity_blocks(&self) -> u32;
}
```

Mutable `self` because SDHCI PIO reads are stateful (driver tracks command/transfer state). Uses `IpcError` for consistency with the microkernel crate. Two methods — the minimum needed for read-only filesystem access.

### SdhciBlockDevice Adapter

```rust
pub struct SdhciBlockDevice<B: RegisterBank> {
    driver: SdhciDriver,
    bank: B,
}

impl<B: RegisterBank> SdhciBlockDevice<B> {
    pub fn new(driver: SdhciDriver, bank: B) -> Self { ... }
}

impl<B: RegisterBank> BlockDevice for SdhciBlockDevice<B> {
    fn read_block(&mut self, lba: u32, buf: &mut [u8; 512]) -> Result<(), IpcError> {
        self.driver.read_single_block(&mut self.bank, lba, buf)
            .map_err(|_| IpcError::NotFound)
    }

    fn capacity_blocks(&self) -> u32 {
        self.driver.card_info().map(|i| i.capacity_blocks).unwrap_or(0)
    }
}
```

Thin wrapper delegating to existing `SdhciDriver::read_single_block()`. Error mapping matches `SdServer` convention.

### PartitionBlockDevice Wrapper

```rust
pub struct PartitionBlockDevice<D: BlockDevice> {
    inner: D,
    base_lba: u32,
    partition_size: u32,
}

impl<D: BlockDevice> PartitionBlockDevice<D> {
    pub fn new(inner: D, base_lba: u32, partition_size: u32) -> Self { ... }
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
```

Adds `base_lba` to all reads. Bounds-checks `lba < partition_size` before delegating. Reusable for any partition on any block device.

### MemoryBlockDevice (Test Only)

```rust
#[cfg(test)]
pub struct MemoryBlockDevice {
    pub sectors: Vec<[u8; 512]>,
}

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

Pre-populated with synthetic FAT32 images. Eliminates SDHCI register mock complexity for filesystem tests.

---

## MBR Parser

### Types

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrEntry {
    pub partition_type: u8,
    pub start_lba: u32,
    pub size_sectors: u32,
}
```

### Function

```rust
pub fn parse_mbr(block_dev: &mut dyn BlockDevice) -> Result<[Option<MbrEntry>; 4], IpcError>
```

**Implementation:**
1. Read LBA 0 into a 512-byte buffer
2. Validate boot signature: bytes 510-511 must be `0x55, 0xAA`. Return `IpcError::InvalidArgument` if not.
3. For each of the 4 partition table entries at offsets 0x1BE, 0x1CE, 0x1DE, 0x1EE (16 bytes each):
   - Extract `partition_type` from byte 4
   - Extract `start_lba` from bytes 8-11 (little-endian u32)
   - Extract `size_sectors` from bytes 12-15 (little-endian u32)
   - If `partition_type == 0`, entry is empty → `None`
   - Otherwise → `Some(MbrEntry { ... })`

**FAT32 partition types:** `0x0B` (FAT32 with CHS addressing) and `0x0C` (FAT32 with LBA addressing). The caller checks `partition_type` to find the right entry.

---

## FAT32 Parser

### BPB (BIOS Parameter Block)

Parsed from sector 0 of the partition (not disk LBA 0 — the `BlockDevice` passed to `Fat32` should already be partition-scoped via `PartitionBlockDevice`).

**Extracted fields:**
- `bytes_per_sector: u16` — offset 11, must be 512
- `sectors_per_cluster: u8` — offset 13 (1, 2, 4, 8, 16, 32, 64)
- `reserved_sectors: u16` — offset 14
- `num_fats: u8` — offset 16 (typically 2)
- `fat_size_32: u32` — offset 36 (sectors per FAT)
- `root_cluster: u32` — offset 44 (usually 2)

**Derived values:**
- `fat_start_lba = reserved_sectors`
- `data_start_lba = reserved_sectors + (num_fats * fat_size_32)`
- `cluster_size = sectors_per_cluster * 512` (in bytes)

**Validation:**
- `bytes_per_sector` must be 512 (only size we support)
- `sectors_per_cluster` must be a power of 2 in range 1..=128
- `root_cluster` must be >= 2
- Total sectors (offset 32, u32) must be non-zero (FAT32 indicator — FAT16 uses offset 19)

### Fat32 Struct

```rust
pub struct Fat32<D: BlockDevice> {
    block_dev: D,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    num_fats: u8,
    fat_size_32: u32,
    root_cluster: u32,
    data_start_lba: u32,
}
```

No caching. Every `read_block` call goes directly to the `BlockDevice`. Caching is a future optimization if profiling shows it's needed.

### Core Operations

**`Fat32::new(block_dev) -> Result<Self, IpcError>`**

Reads sector 0, parses BPB, validates, returns initialized struct.

**`next_cluster(cluster: u32) -> Result<Option<u32>, IpcError>`**

Reads the FAT entry for `cluster`:
1. `fat_offset = cluster * 4`
2. `fat_sector = reserved_sectors + (fat_offset / 512)`
3. `entry_offset = fat_offset % 512`
4. Read the sector, extract little-endian u32 at `entry_offset`
5. Mask to 28 bits (`& 0x0FFFFFFF`)
6. If `>= 0x0FFFFFF8` → end of chain → `Ok(None)`
7. If `< 2` → `Err(InvalidArgument)` (bad FAT entry)
8. Otherwise → `Ok(Some(value))`

**`read_cluster(cluster: u32, buf: &mut [u8]) -> Result<(), IpcError>`**

Reads `sectors_per_cluster` consecutive sectors starting at:
`data_start_lba + (cluster - 2) * sectors_per_cluster`

`buf` must be exactly `cluster_size` bytes.

**`read_dir(start_cluster: u32) -> Result<Vec<DirEntry>, IpcError>`**

Iterates all clusters in the directory chain. For each cluster, processes 32-byte directory entries:

1. If first byte is `0x00` → end of directory, stop
2. If first byte is `0xE5` → deleted entry, skip
3. If attribute byte (offset 11) is `0x0F` → LFN entry, push to pending LFN buffer
4. If attribute byte has `0x08` set → volume label, skip
5. Otherwise → short (8.3) entry:
   - If pending LFN buffer is non-empty, reassemble LFN (see below), clear buffer
   - Otherwise, build name from 8.3 fields (bytes 0-7 name, 8-10 extension, trimmed, lowercased, dot-separated)
   - `is_dir` = attribute byte has `0x10` set
   - `start_cluster` = `(DIR_FstClusHI << 16) | DIR_FstClusLO` (offsets 20-21, 26-27)
   - `size` = little-endian u32 at offset 28

**`read_file_range(start_cluster: u32, file_size: u32, offset: u64, count: u32) -> Result<Vec<u8>, IpcError>`**

Reads `count` bytes starting at `offset` from a file's cluster chain:
1. Skip `offset / cluster_size` clusters in the chain
2. Start reading at `offset % cluster_size` within the first relevant cluster
3. Read clusters until `count` bytes collected or end of chain reached
4. Clamp to `file_size` (don't read past reported file end)

### LFN Reassembly

LFN entries (attribute `0x0F`) precede the associated 8.3 entry in reverse sequence order:

1. Sequence number in byte 0: `0x41` = last fragment (sequence 1), `0x42` = last fragment (sequence 2), etc. Bit 6 set = last logical entry. Sequence number (bits 0-4) indicates the position (1-based, last fragment stored first on disk).
2. Each LFN entry contains 13 UTF-16LE code units across three fields:
   - Bytes 1-10: characters 1-5 (5 code units)
   - Bytes 14-25: characters 6-11 (6 code units)
   - Bytes 28-31: characters 12-13 (2 code units)
3. Collect fragments in sequence order, concatenate UTF-16LE code units
4. Convert to UTF-8. Non-ASCII characters that fail conversion are replaced with `?` (boot partition files are ASCII in practice)
5. Trim trailing `0xFFFF` padding and null terminators

### DirEntry

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub start_cluster: u32,
    pub size: u32,
}
```

---

## FatServer

### FileServer Implementation

```rust
pub struct FatServer<D: BlockDevice> {
    fat: Fat32<D>,
    tracker: FidTracker<NodeKind>,
}

#[derive(Debug, Clone)]
enum NodeKind {
    RootDir,
    SubDir { cluster: u32, name: Arc<str> },
    File { cluster: u32, size: u32, name: Arc<str> },
}
```

`name` is populated during `walk()` and used by `stat()` to return the filename.

**QPath assignment:**
- Root directory → qpath `0`
- Subdirectories → qpath from start cluster number (clusters are unique identifiers)
- Files → qpath from start cluster number

**`FatServer::new(block_dev: D) -> Result<Self, IpcError>`**

Calls `Fat32::new(block_dev)`, initializes `FidTracker` with root fid 0 mapped to `NodeKind::RootDir`.

### 9P Operations

**`walk(fid, new_fid, name)`**

1. Get `NodeKind` for `fid` from tracker
2. Determine directory cluster: `RootDir` → `fat.root_cluster`, `SubDir { cluster }` → `cluster`
3. If `fid` is a `File` → return `IpcError::NotDirectory`
4. Call `fat.read_dir(cluster)`, find entry matching `name` (case-insensitive comparison for FAT32 compatibility)
5. If not found → `IpcError::NotFound`
6. If entry `is_dir` → insert `new_fid` as `SubDir { cluster: entry.start_cluster }`, qpath = cluster
7. If entry is file → insert `new_fid` as `File { cluster: entry.start_cluster, size: entry.size }`, qpath = cluster

**`open(fid, mode)`**

1. If mode is `Write` or `ReadWrite` → `IpcError::PermissionDenied` (read-only filesystem)
2. Mark fid as open via `FidTracker::begin_open()`

**`read(fid, offset, count)`**

1. Verify fid is open
2. If `RootDir` or `SubDir` → `IpcError::IsDirectory`
3. If `File { cluster, size }` → call `fat.read_file_range(cluster, size, offset, count)`

**`stat(fid)`**

1. Get `NodeKind` for fid
2. `RootDir` → `FileStat { qpath: 0, name: "/", size: 0, file_type: Directory }`
3. `SubDir` → `FileStat { qpath: cluster, name: <from walk>, size: 0, file_type: Directory }`
4. `File` → `FileStat { qpath: cluster, name: <from walk>, size, file_type: Regular }`

**`clunk(fid)`** — delegates to `FidTracker::clunk(fid)`.

**`clone_fid(fid, new_fid)`** — delegates to `FidTracker::clone_fid(fid, new_fid)`.

---

## Testing

### BlockDevice + MBR Tests (`block_device.rs`)

- **sdhci_adapter_reads_block:** Create `SdhciBlockDevice` with mock bank, verify `read_block` delegates to `read_single_block` with correct LBA.
- **sdhci_adapter_capacity:** Verify `capacity_blocks()` returns `card_info().capacity_blocks`.
- **partition_wrapper_adds_base_lba:** Create `PartitionBlockDevice` with base_lba=100. Read LBA 5. Verify inner sees LBA 105.
- **partition_wrapper_bounds_check:** Create partition with size=50. Read LBA 50. Verify `InvalidArgument` error.
- **partition_wrapper_capacity:** Verify `capacity_blocks()` returns partition_size.
- **parse_mbr_finds_fat32_partition:** Synthetic MBR with one FAT32 (type 0x0C) partition at LBA 2048, size 1_000_000. Verify parsed entry matches.
- **parse_mbr_invalid_signature:** MBR without 0x55AA at bytes 510-511 → error.
- **parse_mbr_empty_entries:** All 4 entries type 0x00 → all None.
- **parse_mbr_multiple_partitions:** Two FAT32 entries, verify both parsed.

### FAT32 Parser Tests (`fat32.rs`)

- **parse_bpb_valid:** Synthetic BPB sector with known fields. Verify extracted metadata.
- **parse_bpb_not_fat32:** BPB with total_sectors_16 non-zero and fat_size_32 == 0 → error.
- **parse_bpb_bad_sector_size:** BPB with bytes_per_sector != 512 → error.
- **read_dir_short_names:** Directory with two 8.3 entries ("README  TXT", "DATA    BIN"). Verify parsed as "readme.txt", "data.bin".
- **read_dir_lfn:** Directory with LFN entries for "bcm2712-rpi-5-b.dtb" followed by 8.3 entry. Verify reassembled name.
- **read_dir_mixed:** Directory with both LFN and short-name-only entries. Verify all parsed correctly.
- **read_dir_skips_deleted:** Entry with first byte 0xE5 skipped.
- **read_dir_skips_volume_label:** Entry with attribute 0x08 skipped.
- **read_dir_end_marker:** Entry with first byte 0x00 terminates iteration (entries after it ignored).
- **read_dir_subdirectory_entry:** Entry with attribute 0x10 has `is_dir: true`.
- **read_file_single_cluster:** File fits in one cluster. Read returns correct bytes.
- **read_file_multi_cluster:** File spans 3 clusters via FAT chain. Verify data concatenated correctly.
- **read_file_with_offset:** Read starting at offset 100 in a multi-cluster file. Verify correct bytes returned.
- **read_file_clamped_to_size:** Read past file_size returns only up to file_size bytes.
- **cluster_chain_end:** FAT entry 0x0FFFFFF8 returns `None` from `next_cluster`.
- **cluster_chain_continues:** FAT entry with valid cluster number returns `Some(cluster)`.

### FatServer Tests (`fat_server.rs`)

All use a `build_fat32_image()` helper that constructs a valid FAT32 image in a `MemoryBlockDevice`:
- BPB with sectors_per_cluster=1, reserved_sectors=2, 2 FATs, root_cluster=2
- FAT table with cluster chains
- Root directory with: "config.txt" (short name), "bcm2712-rpi-5-b.dtb" (LFN), "overlays/" (subdirectory)
- Subdirectory "overlays/" with: "dwc2.dtbo" (short name)
- File data in allocated clusters

Tests:
- **walk_to_file:** Walk root → "config.txt". Verify qpath matches file's start cluster.
- **walk_to_lfn_file:** Walk root → "bcm2712-rpi-5-b.dtb". Verify LFN resolved.
- **walk_to_subdir_then_file:** Walk root → "overlays" → "dwc2.dtbo". Verify nested walk.
- **walk_nonexistent:** Walk root → "nope.txt" → `NotFound`.
- **walk_into_file_rejected:** Walk to "config.txt", then walk into it → `NotDirectory`.
- **read_file_contents:** Open "config.txt" + read(offset=0, count=all) → correct bytes.
- **read_file_with_offset:** Read from middle of file → correct substring.
- **read_directory_rejected:** Open root dir in Read mode, attempt read → `IsDirectory`.
- **write_rejected:** Open file, attempt write → `PermissionDenied`.
- **stat_file:** stat "config.txt" → correct name, size, Regular.
- **stat_directory:** stat "overlays" → correct name, size=0, Directory.
- **stat_root:** stat root fid → name="/", Directory.
- **clone_fid_works:** Clone a file fid, stat the clone → same qpath and name.
- **clunk_and_reuse:** Clunk a fid, walk again to get new fid at same qpath.

### Out of Scope

- Write support (no file creation, modification, or deletion)
- FAT12/FAT16 (only FAT32)
- GPT partition tables (MBR only)
- Block caching (every read hits the block device)
- NVMe `BlockDevice` adapter (trait supports it, adapter is separate work)
- Boot code wiring (harmony-os-5gh)
- ext4/btrfs
- Concurrent access (sequential model)
- fsinfo sector (read-only, no free cluster tracking needed)
- On-target integration testing
