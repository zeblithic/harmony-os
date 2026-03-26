// SPDX-License-Identifier: GPL-2.0-or-later

//! UsbBookStore — content-addressed [`BookStore`] backed by raw USB sectors.
//!
//! Books are stored directly on a USB mass storage device with no filesystem.
//! The layout is:
//!
//! - Sector 0: Superblock (magic, version, book_count, block_size, next_free)
//! - Sectors 1-256: Index (40-byte entries: CID + start_sector + byte_length)
//! - Sector 257+: Data (books written contiguously)
//!
//! This module is **sans-I/O**: all methods that require disk access return
//! [`UsbStoreAction`] values. The caller executes these via the USB pipeline
//! (mass storage CBW/xHCI).

use std::collections::HashMap;

use harmony_content::book::BookStore;
use harmony_content::cid::{ContentFlags, ContentId};
use harmony_content::error::ContentError;

// --- Constants ---------------------------------------------------------------

const MAGIC: &[u8; 8] = b"HRMBOOKS";
const VERSION: u16 = 1;
const INDEX_START_SECTOR: u32 = 1;
const INDEX_SECTOR_COUNT: u16 = 256;
const DATA_START_SECTOR: u32 = 257;
const INDEX_ENTRY_SIZE: usize = 40;
/// Max books for the default 512-byte block size (used in tests).
#[cfg(test)]
const MAX_BOOKS_512: usize = (512 / INDEX_ENTRY_SIZE) * INDEX_SECTOR_COUNT as usize;

// --- Action type -------------------------------------------------------------

/// I/O operations returned by [`UsbBookStore`] methods for the caller to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsbStoreAction {
    /// Read `count` sectors from the USB device starting at `start_lba`.
    ReadSectors { start_lba: u32, count: u16 },
    /// Write `data` to the USB device starting at `start_lba`.
    ///
    /// `data.len()` is always a multiple of the store's `block_size`.
    WriteSectors { start_lba: u32, data: Vec<u8> },
}

// --- Error type --------------------------------------------------------------

/// Errors that can occur while loading or validating USB store metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsbStoreError {
    /// Superblock magic doesn't match `"HRMBOOKS"`.
    InvalidMagic,
    /// Superblock version is not supported (expected `VERSION = 1`).
    UnsupportedVersion,
    /// Superblock fields contain invalid values (zero block_size,
    /// next_free_sector in reserved area, etc.).
    CorruptedSuperblock,
    /// Data buffer is too short for the expected structure.
    DataTooShort,
}

// --- Internal types ----------------------------------------------------------

/// A parsed entry from the on-disk index.
struct IndexEntry {
    cid: ContentId,
    start_sector: u32,
    byte_length: u32,
}

// --- Main type ---------------------------------------------------------------

/// Content-addressed book store backed by raw USB mass storage sectors.
///
/// Acts as a write-through cache: all book data lives in memory (so that
/// [`BookStore::get`] can return `&[u8]`) and is also queued for writing to
/// USB sectors for persistence across power cycles.
///
/// # Usage
///
/// ```ignore
/// // Cold start: issue reads, then feed data back
/// let (mut store, init_actions) = UsbBookStore::new(512);
/// // ... execute ReadSectors actions, then:
/// store.load_superblock(&sector0_data)?;
/// let book_reads = store.load_index(&index_data);
/// // ... execute book_reads, then:
/// store.load_book(cid, book_data);
///
/// // Insert a book (synchronous for cache, deferred for USB writes)
/// let cid = store.insert(b"my book data")?;
/// let writes = store.drain_pending_writes();
/// // ... execute WriteSectors actions ...
/// ```
pub struct UsbBookStore {
    cache: HashMap<ContentId, Vec<u8>>,
    index: Vec<IndexEntry>,
    next_free_sector: u32,
    block_size: u32,
    book_count: u32,
    pending_writes: Vec<UsbStoreAction>,
}

impl UsbBookStore {
    // --- Construction / Lifecycle --------------------------------------------

    /// Create a new store for a USB device with the given sector size.
    ///
    /// Returns the store (with no books loaded yet) and the [`UsbStoreAction`]s
    /// needed to read the superblock and full index from the device.
    ///
    /// Call [`Self::load_superblock`] and [`Self::load_index`] with the data
    /// read by those actions before using the store.
    pub fn new(block_size: u32) -> (Self, Vec<UsbStoreAction>) {
        assert!(
            block_size >= INDEX_ENTRY_SIZE as u32,
            "block_size must be at least {INDEX_ENTRY_SIZE}"
        );
        let store = UsbBookStore {
            cache: HashMap::new(),
            index: Vec::new(),
            next_free_sector: DATA_START_SECTOR,
            block_size,
            book_count: 0,
            pending_writes: Vec::new(),
        };
        let actions = vec![
            UsbStoreAction::ReadSectors {
                start_lba: 0,
                count: 1,
            },
            UsbStoreAction::ReadSectors {
                start_lba: INDEX_START_SECTOR,
                count: INDEX_SECTOR_COUNT,
            },
        ];
        (store, actions)
    }

    /// Validate the superblock and populate `book_count`, `block_size`, and
    /// `next_free_sector` from the on-disk values.
    ///
    /// `data` must be at least 32 bytes (the first 32 bytes of sector 0).
    pub fn load_superblock(&mut self, data: &[u8]) -> Result<(), UsbStoreError> {
        if data.len() < 32 {
            return Err(UsbStoreError::DataTooShort);
        }
        if &data[0..8] != MAGIC.as_slice() {
            return Err(UsbStoreError::InvalidMagic);
        }
        let version = u16::from_le_bytes(data[8..10].try_into().unwrap());
        if version != VERSION {
            return Err(UsbStoreError::UnsupportedVersion);
        }
        // Parse and validate all fields into locals before committing,
        // so self is untouched if any check fails.
        let book_count = u32::from_le_bytes(data[10..14].try_into().unwrap());
        let block_size = u32::from_le_bytes(data[14..18].try_into().unwrap());
        if block_size < INDEX_ENTRY_SIZE as u32 {
            return Err(UsbStoreError::CorruptedSuperblock);
        }
        let max = (block_size as usize / INDEX_ENTRY_SIZE) * INDEX_SECTOR_COUNT as usize;
        if book_count as usize > max {
            return Err(UsbStoreError::CorruptedSuperblock);
        }
        let next_free = u32::from_le_bytes(data[18..22].try_into().unwrap());
        if next_free < DATA_START_SECTOR {
            return Err(UsbStoreError::CorruptedSuperblock);
        }
        // All validated — commit atomically.
        self.book_count = book_count;
        self.block_size = block_size;
        self.next_free_sector = next_free;
        Ok(())
    }

    /// Parse index entries from the raw index sector data.
    ///
    /// Returns a list of [`UsbStoreAction::ReadSectors`] actions for each book
    /// found in the index. The caller should execute these reads and then call
    /// [`Self::load_book`] for each result.
    ///
    /// `data` should be the raw bytes of sectors 1-256 (`256 * block_size`
    /// bytes).
    /// Parse the index and return `(ContentId, ReadSectors)` pairs so the
    /// caller can match each read action to the CID it should `load_book` with.
    /// Returns `(cid, byte_length, ReadSectors)` so callers can trim
    /// sector-padded reads back to the actual book content.
    pub fn load_index(&mut self, data: &[u8]) -> Vec<(ContentId, u32, UsbStoreAction)> {
        self.index.clear();
        let mut actions = Vec::new();
        let bs = self.block_size as usize;
        let entries_per_sector = bs / INDEX_ENTRY_SIZE;

        // Walk sector by sector, then entry by entry within each sector.
        // Each sector has `entries_per_sector` entries followed by padding.
        for sector in 0..INDEX_SECTOR_COUNT as usize {
            let sector_base = sector * bs;
            if sector_base >= data.len() {
                break;
            }
            for slot in 0..entries_per_sector {
                let offset = sector_base + slot * INDEX_ENTRY_SIZE;
                if offset + INDEX_ENTRY_SIZE > data.len() {
                    break;
                }
                if let Some(entry) =
                    Self::parse_index_entry(&data[offset..offset + INDEX_ENTRY_SIZE])
                {
                    let sectors_needed = entry.byte_length.div_ceil(self.block_size);
                    let Ok(count) = u16::try_from(sectors_needed) else {
                        eprintln!(
                            "[usb-book-store] book at sector {} too large ({} sectors), skipping",
                            entry.start_sector, sectors_needed
                        );
                        continue;
                    };
                    let cid = entry.cid;
                    let byte_length = entry.byte_length;
                    actions.push((
                        cid,
                        byte_length,
                        UsbStoreAction::ReadSectors {
                            start_lba: entry.start_sector,
                            count,
                        },
                    ));
                    self.index.push(entry);
                }
            }
        }
        actions
    }

    /// Insert a book into the in-memory cache after its data has been read
    /// from USB (as requested by [`Self::load_index`]).
    ///
    /// Verifies the content hash matches the expected CID. Returns `false`
    /// (and skips the insert) if the data doesn't match — indicating disk
    /// corruption or a caller pairing error.
    pub fn load_book(&mut self, cid: ContentId, data: Vec<u8>) -> bool {
        if !cid.verify_hash(&data) {
            eprintln!(
                "[usb-book-store] CID hash mismatch on load, skipping {:?}",
                hex::encode(cid.to_bytes())
            );
            return false;
        }
        self.cache.insert(cid, data);
        true
    }

    /// Initialize a fresh USB drive: creates a zeroed superblock and index.
    ///
    /// Returns a new store and the [`UsbStoreAction`]s to write the superblock
    /// and the full zeroed index to the device.
    pub fn format(block_size: u32) -> (Self, Vec<UsbStoreAction>) {
        assert!(
            block_size >= INDEX_ENTRY_SIZE as u32,
            "block_size must be at least {INDEX_ENTRY_SIZE}"
        );
        let store = UsbBookStore {
            cache: HashMap::new(),
            index: Vec::new(),
            next_free_sector: DATA_START_SECTOR,
            block_size,
            book_count: 0,
            pending_writes: Vec::new(),
        };

        let superblock = store.serialize_superblock();
        let zeroed_index = vec![0u8; block_size as usize * INDEX_SECTOR_COUNT as usize];

        let actions = vec![
            UsbStoreAction::WriteSectors {
                start_lba: 0,
                data: superblock,
            },
            UsbStoreAction::WriteSectors {
                start_lba: INDEX_START_SECTOR,
                data: zeroed_index,
            },
        ];
        (store, actions)
    }

    // --- Write management ----------------------------------------------------

    /// Retrieve and clear all queued write actions.
    ///
    /// The caller should execute these [`UsbStoreAction::WriteSectors`] actions
    /// against the USB device to persist data written via [`BookStore::insert`]
    /// or [`BookStore::store`].
    pub fn drain_pending_writes(&mut self) -> Vec<UsbStoreAction> {
        std::mem::take(&mut self.pending_writes)
    }

    // --- Queries -------------------------------------------------------------

    /// Number of books stored on this USB drive.
    pub fn book_count(&self) -> u32 {
        self.book_count
    }

    /// Returns `true` if the index is at maximum capacity (3,072 entries).
    /// Maximum number of books the index can hold for this block_size.
    pub fn max_books(&self) -> usize {
        (self.block_size as usize / INDEX_ENTRY_SIZE) * INDEX_SECTOR_COUNT as usize
    }

    pub fn is_full(&self) -> bool {
        // Check both: book_count (from superblock) and index.len() (actual
        // parsed entries). They can diverge after a partial write / corruption.
        let max = self.max_books();
        self.book_count as usize >= max || self.index.len() >= max
    }

    // --- Serialization helpers -----------------------------------------------

    /// Serialize the superblock into a `block_size`-byte buffer.
    ///
    /// The first 32 bytes are the superblock fields; the rest are zeroed padding.
    fn serialize_superblock(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.block_size as usize];
        buf[0..8].copy_from_slice(MAGIC.as_slice());
        buf[8..10].copy_from_slice(&VERSION.to_le_bytes());
        buf[10..14].copy_from_slice(&self.book_count.to_le_bytes());
        buf[14..18].copy_from_slice(&self.block_size.to_le_bytes());
        buf[18..22].copy_from_slice(&self.next_free_sector.to_le_bytes());
        // bytes [22..32] remain zero (reserved)
        buf
    }

    /// Serialize a single 40-byte index entry.
    fn serialize_index_entry(entry: &IndexEntry) -> [u8; INDEX_ENTRY_SIZE] {
        let mut buf = [0u8; INDEX_ENTRY_SIZE];
        buf[0..32].copy_from_slice(&entry.cid.to_bytes());
        buf[32..36].copy_from_slice(&entry.start_sector.to_le_bytes());
        buf[36..40].copy_from_slice(&entry.byte_length.to_le_bytes());
        buf
    }

    /// Parse a single 40-byte slice as an index entry.
    ///
    /// Returns `None` for all-zero CID (empty/unused slot).
    fn parse_index_entry(data: &[u8]) -> Option<IndexEntry> {
        debug_assert_eq!(data.len(), INDEX_ENTRY_SIZE);
        let cid_bytes: [u8; 32] = data[0..32].try_into().ok()?;
        if cid_bytes == [0u8; 32] {
            return None;
        }
        let cid = ContentId::from_bytes(cid_bytes);
        let start_sector = u32::from_le_bytes(data[32..36].try_into().ok()?);
        let byte_length = u32::from_le_bytes(data[36..40].try_into().ok()?);
        // Reject entries pointing into superblock or index area.
        if start_sector < DATA_START_SECTOR || byte_length == 0 {
            return None;
        }
        Some(IndexEntry {
            cid,
            start_sector,
            byte_length,
        })
    }

    // --- Internal write helper -----------------------------------------------

    /// Queue all USB write actions needed to persist a newly added book.
    ///
    /// Assumes the book has already been added to `self.index` and
    /// `self.book_count` / `self.next_free_sector` have been updated.
    ///
    /// Queues three [`UsbStoreAction::WriteSectors`] actions:
    /// 1. The book's data (padded to a sector boundary).
    /// 2. The index sector containing the new entry.
    /// 3. The updated superblock (sector 0).
    fn queue_book_write(&mut self, start_sector: u32, data: &[u8]) {
        let sectors_needed = (data.len() as u32).div_ceil(self.block_size);

        // 1. Book data padded to sector boundary.
        // Multiply in usize to avoid u32 overflow for near-4GiB books.
        let mut padded = data.to_vec();
        padded.resize(sectors_needed as usize * self.block_size as usize, 0);
        self.pending_writes.push(UsbStoreAction::WriteSectors {
            start_lba: start_sector,
            data: padded,
        });

        // 2. The index sector containing the new entry.
        // Use index.len() rather than book_count — they can diverge if
        // the superblock's book_count doesn't match actual parsed entries.
        let entry_index = self.index.len() - 1;
        let entries_per_sector = self.block_size as usize / INDEX_ENTRY_SIZE;
        let sector_offset = entry_index / entries_per_sector;
        let index_sector = INDEX_START_SECTOR + sector_offset as u32;
        let sector_start_entry = sector_offset * entries_per_sector;

        let mut sector_data = vec![0u8; self.block_size as usize];
        for i in 0..entries_per_sector {
            let idx = sector_start_entry + i;
            if idx < self.index.len() {
                let entry_bytes = Self::serialize_index_entry(&self.index[idx]);
                let offset = i * INDEX_ENTRY_SIZE;
                sector_data[offset..offset + INDEX_ENTRY_SIZE].copy_from_slice(&entry_bytes);
            }
        }
        self.pending_writes.push(UsbStoreAction::WriteSectors {
            start_lba: index_sector,
            data: sector_data,
        });

        // 3. Updated superblock.
        self.pending_writes.push(UsbStoreAction::WriteSectors {
            start_lba: 0,
            data: self.serialize_superblock(),
        });
    }
}

// --- BookStore trait ---------------------------------------------------------

impl BookStore for UsbBookStore {
    /// Insert a book into the USB store.
    ///
    /// Returns `ContentError::PayloadTooLarge` in two cases:
    /// - **Index full**: `size` = book_count, `max` = max_books() (small, e.g. 3072).
    ///   The store has no room for more entries.
    /// - **Book too large**: `size` = data.len(), `max` = u32::MAX.
    ///   Individual book exceeds the 4 GiB sector-addressing limit.
    fn insert_with_flags(
        &mut self,
        data: &[u8],
        flags: ContentFlags,
    ) -> Result<ContentId, ContentError> {
        if data.is_empty() {
            return Err(ContentError::EmptyData);
        }
        let cid = ContentId::for_book(data, flags)?;
        if !self.cache.contains_key(&cid) {
            if self.is_full() {
                return Err(ContentError::PayloadTooLarge {
                    size: self.book_count as usize,
                    max: self.max_books(),
                });
            }
            let byte_length =
                u32::try_from(data.len()).map_err(|_| ContentError::PayloadTooLarge {
                    size: data.len(),
                    max: u32::MAX as usize,
                })?;
            let sectors_needed = byte_length.div_ceil(self.block_size);
            // Reject books that would be unloadable on cold restart
            // (load_index ReadSectors.count is u16).
            if sectors_needed > u16::MAX as u32 {
                return Err(ContentError::PayloadTooLarge {
                    size: data.len(),
                    max: u16::MAX as usize * self.block_size as usize,
                });
            }
            let start_sector = self.next_free_sector;
            let new_next = self.next_free_sector.checked_add(sectors_needed).ok_or(
                ContentError::PayloadTooLarge {
                    size: data.len(),
                    max: u32::MAX as usize,
                },
            )?;

            self.index.push(IndexEntry {
                cid,
                start_sector,
                byte_length,
            });
            self.book_count += 1;
            self.next_free_sector = new_next;

            self.cache.insert(cid, data.to_vec());
            self.queue_book_write(start_sector, data);
        }
        Ok(cid)
    }

    fn insert(&mut self, data: &[u8]) -> Result<ContentId, ContentError> {
        self.insert_with_flags(data, ContentFlags::default())
    }

    fn store(&mut self, cid: ContentId, data: Vec<u8>) {
        if data.is_empty() {
            eprintln!("[usb-book-store] zero-length book rejected");
            return;
        }
        if !self.cache.contains_key(&cid) {
            if self.is_full() {
                eprintln!("[usb-book-store] index full, cannot store book");
                return;
            }
            let Ok(byte_length) = u32::try_from(data.len()) else {
                eprintln!("[usb-book-store] book too large for u32 byte_length, skipping");
                return;
            };
            let sectors_needed = byte_length.div_ceil(self.block_size);
            if sectors_needed > u16::MAX as u32 {
                eprintln!("[usb-book-store] book too large for u16 sector count, skipping");
                return;
            }
            let start_sector = self.next_free_sector;
            let Some(new_next) = self.next_free_sector.checked_add(sectors_needed) else {
                eprintln!("[usb-book-store] next_free_sector overflow, skipping");
                return;
            };

            self.index.push(IndexEntry {
                cid,
                start_sector,
                byte_length,
            });
            self.book_count += 1;
            self.next_free_sector = new_next;

            let data_ref = &*data;
            self.queue_book_write(start_sector, data_ref);
            self.cache.insert(cid, data);
        }
    }

    fn get(&self, cid: &ContentId) -> Option<&[u8]> {
        self.cache.get(cid).map(|v| v.as_slice())
    }

    fn contains(&self, cid: &ContentId) -> bool {
        self.cache.contains_key(cid)
    }
}

// --- Tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK_SIZE: u32 = 512;

    // Helper: produce a fake USB "disk" that covers sectors 0 through a
    // reasonable upper bound, seeded from a set of write actions.
    fn apply_writes(disk: &mut Vec<u8>, block_size: u32, actions: &[UsbStoreAction]) {
        for action in actions {
            if let UsbStoreAction::WriteSectors { start_lba, data } = action {
                let offset = *start_lba as usize * block_size as usize;
                let end = offset + data.len();
                if disk.len() < end {
                    disk.resize(end, 0);
                }
                disk[offset..end].copy_from_slice(data);
            }
        }
    }

    // Helper: read sectors from our fake disk.
    fn read_sectors(disk: &[u8], block_size: u32, start_lba: u32, count: u16) -> Vec<u8> {
        let offset = start_lba as usize * block_size as usize;
        let len = count as usize * block_size as usize;
        let end = (offset + len).min(disk.len());
        let mut buf = vec![0u8; len];
        if offset < disk.len() {
            let available = end - offset;
            buf[..available].copy_from_slice(&disk[offset..end]);
        }
        buf
    }

    // --- Superblock serialize/parse round-trip -------------------------------

    #[test]
    fn superblock_round_trip() {
        let (mut store, _) = UsbBookStore::new(BLOCK_SIZE);
        store.book_count = 7;
        store.next_free_sector = 300;

        let bytes = store.serialize_superblock();

        let (mut store2, _) = UsbBookStore::new(BLOCK_SIZE);
        store2.load_superblock(&bytes).unwrap();

        assert_eq!(store2.book_count, 7);
        assert_eq!(store2.block_size, BLOCK_SIZE);
        assert_eq!(store2.next_free_sector, 300);
    }

    // --- Invalid magic -------------------------------------------------------

    #[test]
    fn invalid_magic_returns_error() {
        let mut buf = vec![0u8; 32];
        buf[0..8].copy_from_slice(b"BADMAGIC");

        let (mut store, _) = UsbBookStore::new(BLOCK_SIZE);
        let err = store.load_superblock(&buf).unwrap_err();
        assert_eq!(err, UsbStoreError::InvalidMagic);
    }

    // --- Index entry serialize/parse round-trip ------------------------------

    #[test]
    fn index_entry_round_trip() {
        let data = b"index entry test book";
        let cid = ContentId::for_book(data, ContentFlags::default()).unwrap();
        let entry = IndexEntry {
            cid,
            start_sector: 300,
            byte_length: data.len() as u32,
        };
        let bytes = UsbBookStore::serialize_index_entry(&entry);
        let parsed = UsbBookStore::parse_index_entry(&bytes).unwrap();

        assert_eq!(parsed.cid, entry.cid);
        assert_eq!(parsed.start_sector, 300);
        assert_eq!(parsed.byte_length, data.len() as u32);
    }

    // --- All-zero CID → None -------------------------------------------------

    #[test]
    fn all_zero_cid_entry_returns_none() {
        let zero_entry = [0u8; INDEX_ENTRY_SIZE];
        assert!(UsbBookStore::parse_index_entry(&zero_entry).is_none());
    }

    // --- new() returns correct ReadSectors actions ---------------------------

    #[test]
    fn new_returns_read_actions() {
        let (_, actions) = UsbBookStore::new(BLOCK_SIZE);
        assert_eq!(actions.len(), 2);

        assert_eq!(
            actions[0],
            UsbStoreAction::ReadSectors {
                start_lba: 0,
                count: 1
            }
        );
        assert_eq!(
            actions[1],
            UsbStoreAction::ReadSectors {
                start_lba: INDEX_START_SECTOR,
                count: INDEX_SECTOR_COUNT,
            }
        );
    }

    // --- format() returns correct WriteSectors actions -----------------------

    #[test]
    fn format_returns_write_actions() {
        let (store, actions) = UsbBookStore::format(BLOCK_SIZE);
        assert_eq!(actions.len(), 2);

        // First action: superblock at sector 0
        if let UsbStoreAction::WriteSectors { start_lba, data } = &actions[0] {
            assert_eq!(*start_lba, 0);
            assert_eq!(data.len(), BLOCK_SIZE as usize);
            assert_eq!(&data[0..8], MAGIC.as_slice());
        } else {
            panic!("expected WriteSectors for superblock");
        }

        // Second action: zeroed index at sector 1
        if let UsbStoreAction::WriteSectors { start_lba, data } = &actions[1] {
            assert_eq!(*start_lba, INDEX_START_SECTOR);
            assert_eq!(
                data.len(),
                BLOCK_SIZE as usize * INDEX_SECTOR_COUNT as usize
            );
            assert!(data.iter().all(|&b| b == 0), "index should be all zeros");
        } else {
            panic!("expected WriteSectors for index");
        }

        assert_eq!(store.book_count(), 0);
        assert_eq!(store.next_free_sector, DATA_START_SECTOR);
    }

    // --- load_superblock + load_index + load_book → get() works -------------

    #[test]
    fn load_path_populates_cache() {
        // Format a fresh disk.
        let (mut store, format_writes) = UsbBookStore::format(BLOCK_SIZE);
        let mut disk = vec![0u8; 600 * BLOCK_SIZE as usize];
        apply_writes(&mut disk, BLOCK_SIZE, &format_writes);

        // Insert a book to populate index on "disk".
        let book_data = b"hello usb book store";
        let cid = store.insert(book_data).unwrap();
        let writes = store.drain_pending_writes();
        apply_writes(&mut disk, BLOCK_SIZE, &writes);

        // Now simulate a cold reload.
        let (mut store2, init_actions) = UsbBookStore::new(BLOCK_SIZE);
        for action in &init_actions {
            if let UsbStoreAction::ReadSectors { start_lba, count } = action {
                let data = read_sectors(&disk, BLOCK_SIZE, *start_lba, *count);
                if *start_lba == 0 {
                    store2.load_superblock(&data).unwrap();
                } else {
                    let book_reads = store2.load_index(&data);
                    // Execute book reads — use byte_length to trim padding
                    for (book_cid, byte_len, book_action) in &book_reads {
                        if let UsbStoreAction::ReadSectors {
                            start_lba: blba,
                            count: bcnt,
                        } = book_action
                        {
                            let book_bytes = read_sectors(&disk, BLOCK_SIZE, *blba, *bcnt);
                            let trimmed = book_bytes[..*byte_len as usize].to_vec();
                            assert!(store2.load_book(*book_cid, trimmed), "CID hash mismatch");
                        }
                    }
                }
            }
        }

        assert!(store2.contains(&cid));
        assert_eq!(store2.get(&cid).unwrap(), book_data);
        assert_eq!(store2.book_count(), 1);
    }

    // --- insert_with_flags → cache hit + pending WriteSectors ----------------

    #[test]
    fn insert_with_flags_queues_writes() {
        let (mut store, _) = UsbBookStore::format(BLOCK_SIZE);
        let _ = store.drain_pending_writes(); // clear format writes

        let data = b"content for usb sector storage";
        let flags = ContentFlags::default();
        let cid = store.insert_with_flags(data, flags).unwrap();

        // Cache populated immediately
        assert_eq!(store.get(&cid).unwrap(), data);

        let writes = store.drain_pending_writes();
        // Expect 3 writes: data, index sector, superblock
        assert_eq!(writes.len(), 3);

        // 1. Data write at DATA_START_SECTOR
        if let UsbStoreAction::WriteSectors {
            start_lba,
            data: wdata,
        } = &writes[0]
        {
            assert_eq!(*start_lba, DATA_START_SECTOR);
            assert_eq!(wdata.len() % BLOCK_SIZE as usize, 0);
            assert_eq!(&wdata[..data.len()], data.as_ref());
        } else {
            panic!("expected WriteSectors for book data");
        }

        // 2. Index sector write
        if let UsbStoreAction::WriteSectors {
            start_lba,
            data: idata,
        } = &writes[1]
        {
            assert_eq!(*start_lba, INDEX_START_SECTOR);
            assert_eq!(idata.len(), BLOCK_SIZE as usize);
        } else {
            panic!("expected WriteSectors for index");
        }

        // 3. Superblock update
        if let UsbStoreAction::WriteSectors { start_lba, .. } = &writes[2] {
            assert_eq!(*start_lba, 0);
        } else {
            panic!("expected WriteSectors for superblock");
        }
    }

    // --- store() → same write pattern ----------------------------------------

    #[test]
    fn store_queues_writes() {
        let (mut store, _) = UsbBookStore::format(BLOCK_SIZE);
        let _ = store.drain_pending_writes();

        let data = b"store with precomputed cid";
        let cid = ContentId::for_book(data, ContentFlags::default()).unwrap();

        store.store(cid, data.to_vec());

        assert_eq!(store.get(&cid).unwrap(), data);

        let writes = store.drain_pending_writes();
        assert_eq!(writes.len(), 3);

        if let UsbStoreAction::WriteSectors { start_lba, .. } = &writes[0] {
            assert_eq!(*start_lba, DATA_START_SECTOR);
        } else {
            panic!("expected WriteSectors for book data");
        }
    }

    // --- Idempotent insert: duplicate CID → no new writes --------------------

    #[test]
    fn duplicate_insert_is_idempotent() {
        let (mut store, _) = UsbBookStore::format(BLOCK_SIZE);
        let _ = store.drain_pending_writes();

        let data = b"same book twice";
        let cid1 = store.insert(data).unwrap();
        let _ = store.drain_pending_writes();

        let cid2 = store.insert(data).unwrap();
        let writes = store.drain_pending_writes();

        assert_eq!(cid1, cid2);
        assert_eq!(writes.len(), 0, "no writes on duplicate insert");
        assert_eq!(store.book_count(), 1);
    }

    // --- is_full at MAX_BOOKS ------------------------------------------------

    #[test]
    fn is_full_at_max_books() {
        let (mut store, _) = UsbBookStore::new(BLOCK_SIZE);
        assert!(!store.is_full());

        // Manually inflate book_count to the limit
        store.book_count = MAX_BOOKS_512 as u32;
        assert!(store.is_full());

        store.book_count = MAX_BOOKS_512 as u32 - 1;
        assert!(!store.is_full());
    }

    // --- book_count tracks correctly -----------------------------------------

    #[test]
    fn book_count_tracks_correctly() {
        let (mut store, _) = UsbBookStore::format(BLOCK_SIZE);
        let _ = store.drain_pending_writes();

        assert_eq!(store.book_count(), 0);

        store.insert(b"book one").unwrap();
        assert_eq!(store.book_count(), 1);

        store.insert(b"book two").unwrap();
        assert_eq!(store.book_count(), 2);

        // Duplicate should not increment
        store.insert(b"book one").unwrap();
        assert_eq!(store.book_count(), 2);
    }

    // --- Full round-trip: format → insert → reload → recovered --------------

    #[test]
    fn full_round_trip() {
        let block_size = BLOCK_SIZE;
        let mut disk = vec![0u8; 1000 * block_size as usize];

        // 1. Format
        let (mut store, format_writes) = UsbBookStore::format(block_size);
        apply_writes(&mut disk, block_size, &format_writes);
        let _ = store.drain_pending_writes();

        // 2. Insert books
        let books: &[&[u8]] = &[
            b"the quick brown fox",
            b"jumped over the lazy dog",
            b"content addressed storage on USB",
        ];
        let mut cids = Vec::new();
        for &book in books {
            let cid = store.insert(book).unwrap();
            cids.push((cid, book));
            let writes = store.drain_pending_writes();
            apply_writes(&mut disk, block_size, &writes);
        }

        // 3. Reload from disk
        let (mut store2, init_actions) = UsbBookStore::new(block_size);

        // Read superblock
        let sb_data = read_sectors(&disk, block_size, 0, 1);
        store2.load_superblock(&sb_data).unwrap();

        // Read and parse index
        let idx_data = read_sectors(&disk, block_size, INDEX_START_SECTOR, INDEX_SECTOR_COUNT);
        let book_reads = store2.load_index(&idx_data);

        // Each action is paired with its CID + byte_length for trimming.
        let _ = init_actions;
        for (book_cid, byte_len, book_action) in &book_reads {
            if let UsbStoreAction::ReadSectors { start_lba, count } = book_action {
                let raw = read_sectors(&disk, block_size, *start_lba, *count);
                let trimmed = raw[..*byte_len as usize].to_vec();
                assert!(store2.load_book(*book_cid, trimmed), "CID hash mismatch");
            }
        }

        // 4. Verify all books recovered
        for &(cid, original) in &cids {
            assert!(store2.contains(&cid), "book should be in reloaded store");
            assert_eq!(
                store2.get(&cid).unwrap(),
                original,
                "book data should match"
            );
        }
        assert_eq!(store2.book_count(), 3);
    }

    // --- Unsupported version -------------------------------------------------

    #[test]
    fn unsupported_version_returns_error() {
        let (store, _) = UsbBookStore::new(BLOCK_SIZE);
        let mut bytes = store.serialize_superblock();
        // Overwrite version with 99
        let ver: u16 = 99;
        bytes[8..10].copy_from_slice(&ver.to_le_bytes());
        // Also write valid magic since serialize_superblock writes it
        bytes[0..8].copy_from_slice(MAGIC.as_slice());

        let (mut store2, _) = UsbBookStore::new(BLOCK_SIZE);
        let err = store2.load_superblock(&bytes).unwrap_err();
        assert_eq!(err, UsbStoreError::UnsupportedVersion);
    }

    // --- DataTooShort --------------------------------------------------------

    #[test]
    fn data_too_short_returns_error() {
        let (mut store, _) = UsbBookStore::new(BLOCK_SIZE);
        let short = vec![0u8; 16]; // less than 32
        let err = store.load_superblock(&short).unwrap_err();
        assert_eq!(err, UsbStoreError::DataTooShort);
    }

    // --- next_free_sector advances correctly ---------------------------------

    #[test]
    fn next_free_sector_advances() {
        let (mut store, _) = UsbBookStore::format(BLOCK_SIZE);
        let _ = store.drain_pending_writes();

        assert_eq!(store.next_free_sector, DATA_START_SECTOR);

        // Insert 1-byte book → 1 sector
        store.insert(b"x").unwrap();
        assert_eq!(store.next_free_sector, DATA_START_SECTOR + 1);

        // Insert exactly block_size bytes → 1 sector
        let one_sector = vec![0xAAu8; BLOCK_SIZE as usize];
        store.insert(&one_sector).unwrap();
        assert_eq!(store.next_free_sector, DATA_START_SECTOR + 2);

        // Insert block_size+1 bytes → 2 sectors
        let two_sectors = vec![0xBBu8; BLOCK_SIZE as usize + 1];
        store.insert(&two_sectors).unwrap();
        assert_eq!(store.next_free_sector, DATA_START_SECTOR + 4);
    }

    // --- Multiple entries in same index sector --------------------------------

    #[test]
    fn multiple_entries_in_same_index_sector() {
        // At 512 bytes/sector, 12 entries per sector. The first 12 books all
        // live in index sector 1. The 13th book triggers a new index sector.
        let (mut store, _) = UsbBookStore::format(BLOCK_SIZE);
        let _ = store.drain_pending_writes();

        let entries_per_sector = BLOCK_SIZE as usize / INDEX_ENTRY_SIZE;
        assert_eq!(entries_per_sector, 12);

        for i in 0..entries_per_sector {
            let data = format!("book number {i:03}");
            store.insert(data.as_bytes()).unwrap();
            let writes = store.drain_pending_writes();
            // Index write should still target sector 1 for the first 12 books
            if let UsbStoreAction::WriteSectors { start_lba, .. } = &writes[1] {
                assert_eq!(*start_lba, INDEX_START_SECTOR);
            }
        }

        // 13th book should write to index sector 2
        store.insert(b"the thirteenth book").unwrap();
        let writes = store.drain_pending_writes();
        if let UsbStoreAction::WriteSectors { start_lba, .. } = &writes[1] {
            assert_eq!(*start_lba, INDEX_START_SECTOR + 1);
        }
    }

    // --- store() is also idempotent ------------------------------------------

    #[test]
    fn store_idempotent() {
        let (mut store, _) = UsbBookStore::format(BLOCK_SIZE);
        let _ = store.drain_pending_writes();

        let data = b"stored once";
        let cid = ContentId::for_book(data, ContentFlags::default()).unwrap();

        store.store(cid, data.to_vec());
        let _ = store.drain_pending_writes();
        assert_eq!(store.book_count(), 1);

        // Second store call: same CID, no new writes
        store.store(cid, data.to_vec());
        let writes2 = store.drain_pending_writes();
        assert_eq!(writes2.len(), 0);
        assert_eq!(store.book_count(), 1);
    }
}
