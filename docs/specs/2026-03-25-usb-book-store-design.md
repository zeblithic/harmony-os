# USB CAS Book Store — Design Spec

## Goal

Implement a content-addressed book store backed by raw USB mass storage
sectors. Any USB drive plugged into a mesh node becomes a persistent
shared library: books ingested from the mesh are written to USB, books
already on USB are available to mesh peers.

## Background

The `BookStore` trait (harmony-content) provides key-value storage
keyed by `ContentId`. `MemoryBookStore` is ephemeral, `DiskBookStore`
uses filesystem files. This implementation stores books directly on
USB sectors via the mass storage BBB driver — no filesystem needed.

## On-Disk Layout

512-byte sectors assumed (parameterized by `block_size` from
`parse_read_capacity`).

```
Sector 0:       Superblock (magic, version, book_count, block_size, next_free)
Sectors 1-256:  Index (40-byte entries: CID + start_sector + byte_length)
Sector 257+:    Data (books written contiguously)
```

### Superblock (sector 0, first 32 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | Magic: `"HRMBOOKS"` |
| 8 | 2 | Version: 1 (u16 LE) |
| 10 | 4 | book_count (u32 LE) |
| 14 | 4 | block_size (u32 LE) |
| 18 | 4 | next_free_sector (u32 LE) |
| 22 | 10 | Reserved (zeros) |

### Index (sectors 1-256)

Each entry is 40 bytes: `CID[32] + start_sector[4] + byte_length[4]`.

At 512 bytes/sector: 12 entries per sector × 256 sectors = **3,072 max
books**.

Index entries are written sequentially. Empty entries have all-zero CID.

### Data (sector 257+)

Books written contiguously starting at `next_free_sector` (initially
257). Each book occupies `ceil(byte_length / block_size)` sectors.

## Sans-I/O Pattern

`UsbBookStore` does not perform I/O directly. Methods that need disk
access return `UsbStoreAction` values. The caller executes these via
the mass storage CBW/xHCI pipeline.

```rust
pub enum UsbStoreAction {
    /// Read sectors from USB device.
    ReadSectors { start_lba: u32, count: u16 },
    /// Write data to USB device starting at the given LBA.
    WriteSectors { start_lba: u32, data: Vec<u8> },
}
```

## Core Type

```rust
pub struct UsbBookStore {
    cache: HashMap<ContentId, Vec<u8>>,
    index: Vec<IndexEntry>,
    next_free_sector: u32,
    block_size: u32,
    book_count: u32,
    pending_writes: Vec<UsbStoreAction>,
}

struct IndexEntry {
    cid: ContentId,
    start_sector: u32,
    byte_length: u32,
}
```

## Lifecycle

### Initialization (cold start)

1. `UsbBookStore::new(block_size) -> (Self, Vec<UsbStoreAction>)`
   Returns actions to read superblock (sector 0) and full index
   (sectors 1-256).

2. Caller reads the sectors, calls:
   - `load_superblock(data) -> Result<(), UsbStoreError>` — validates
     magic, version, populates book_count/next_free_sector
   - `load_index(data) -> Vec<UsbStoreAction>` — parses index entries,
     returns `ReadSectors` actions for each book's data

3. For each book, caller reads data and calls:
   - `load_book(cid, data)` — inserts into cache

### Fresh drive

If `load_superblock` finds wrong magic, call
`format(block_size) -> Vec<UsbStoreAction>` which returns writes for a
fresh superblock and zeroed index.

### Write path

On `insert_with_flags` or `store` with a new CID:
1. Add to in-memory cache
2. Compute sectors needed: `ceil(data.len() / block_size)`
3. Append `IndexEntry` to index
4. Queue `WriteSectors` for: book data, updated index entry sector,
   updated superblock
5. Advance `next_free_sector`

Caller retrieves queued writes via `drain_pending_writes()`.

## BookStore Trait

```rust
impl BookStore for UsbBookStore {
    fn get(&self, cid) -> Option<&[u8]>     // cache lookup
    fn contains(&self, cid) -> bool          // cache check
    fn insert_with_flags(&mut self, data, flags) -> Result<ContentId, ContentError>
    fn store(&mut self, cid, data)           // add + queue write
}
```

`insert_with_flags` and `store` are synchronous for the cache (data
immediately available via `get`) but write actions are deferred until
the caller calls `drain_pending_writes()`.

## Additional Methods

- `drain_pending_writes() -> Vec<UsbStoreAction>` — retrieve and clear
  queued write actions
- `format(block_size) -> Vec<UsbStoreAction>` — initialize fresh drive
- `book_count() -> u32` — number of stored books
- `is_full() -> bool` — index capacity reached (3,072 entries)

## Error Type

```rust
pub enum UsbStoreError {
    /// Superblock magic doesn't match "HRMBOOKS".
    InvalidMagic,
    /// Superblock version is not supported.
    UnsupportedVersion,
    /// Index is full (3,072 entries).
    IndexFull,
    /// Data too short for expected structure.
    DataTooShort,
}
```

## Mesh Integration

Once loaded, `UsbBookStore` plugs into `NarPublisher::with_store()`:
- Books ingested from mesh → stored to USB (persistent across reboots)
- Books on USB → announced to mesh peers via Zenoh
- USB drive becomes a shared persistent library for the mesh

## Constants

```rust
const MAGIC: &[u8; 8] = b"HRMBOOKS";
const VERSION: u16 = 1;
const INDEX_START_SECTOR: u32 = 1;
const INDEX_SECTOR_COUNT: u16 = 256;
const DATA_START_SECTOR: u32 = 257;
const INDEX_ENTRY_SIZE: usize = 40;
const MAX_BOOKS: usize = 3072;
```

## Testing

- Superblock: serialize → parse round-trip, magic validation, wrong
  magic → InvalidMagic
- Index: serialize/parse entries, max capacity check
- Write path: insert book → correct WriteSectors (data + index + super)
- Load path: superblock → index → books → cache populated
- BookStore trait: get/contains/insert/store after load
- Idempotent insert: duplicate CID → no duplicate writes
- Full round-trip: new → insert → drain writes → reload → recovered
- Format: produces superblock + zeroed index writes
- is_full: returns true at 3,072 entries

## Out of Scope

- Deletion / space reclamation
- Multiple USB drives
- Wear leveling
- Filesystem compatibility (FAT32/ext4)
- Auto-discovery of USB devices
- Block sizes other than 512 (parameterized but tested with 512)
