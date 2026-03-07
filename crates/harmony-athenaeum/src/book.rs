// SPDX-License-Identifier: GPL-2.0-or-later
//! Book — portable athenaeum metadata serialization.

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use crate::addr::ChunkAddr;
use crate::athenaeum::{Athenaeum, CollisionError, MAX_BLOB_SIZE, chunk_blob};

/// Error when parsing a book from bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BookError {
    TooShort,
    InvalidChecksum,
}

/// A single blob entry in a book.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookEntry {
    pub cid: [u8; 32],
    pub blob_size: u32,
    pub chunks: Vec<ChunkAddr>,
}

/// A book — portable collection of athenaeum metadata.
///
/// Can describe one or more blobs. A 4KB book chunk holds up to
/// 3 full 256-chunk (1MB) blob entries.
///
/// # Cross-blob consistency
///
/// Use [`Book::from_blobs`] to build a Book where all chunks across
/// all blobs are collision-free and content-deduplicated. Identical
/// chunks shared between blobs naturally reuse the same address.
///
/// The simpler [`Book::from_athenaeum`] / [`Book::add_athenaeum`]
/// methods copy pre-built chunk mappings without cross-validation —
/// use them only for single-blob books or when cross-consistency
/// is handled externally.
///
/// # Future: Encyclopedia / Volumes
///
/// For collections larger than ~3 blobs, a higher-level structure
/// (using depth-01 Bundle addresses to reference Books) could bundle
/// multiple cross-consistent Books. The depth field already supports
/// this nesting. Not yet implemented — get Book-level resolution
/// right first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Book {
    pub entries: Vec<BookEntry>,
}

impl Book {
    /// Build a cross-consistent Book from multiple blobs.
    ///
    /// All chunks across all blobs share a single address space:
    /// - Identical chunks across blobs reuse the same address (content dedup)
    /// - Different chunks that would collide are re-addressed via the
    ///   power-of-choice algorithm (same as within-blob resolution)
    ///
    /// This is the preferred constructor for multi-blob Books.
    pub fn from_blobs(blobs: &[([u8; 32], &[u8])]) -> Result<Self, CollisionError> {
        let mut entries = Vec::new();
        let mut used_addrs = BTreeSet::new();
        let mut content_cache = BTreeMap::new();

        for &(cid, data) in blobs {
            if data.len() > MAX_BLOB_SIZE {
                return Err(CollisionError::BlobTooLarge { size: data.len() });
            }
            let blob_size = u32::try_from(data.len())
                .expect("blob_size exceeds u32::MAX");
            let chunks = chunk_blob(data, &mut used_addrs, &mut content_cache)?;
            entries.push(BookEntry { cid, blob_size, chunks });
        }

        Ok(Book { entries })
    }

    /// Create a book from a single pre-built athenaeum.
    ///
    /// No cross-blob resolution is performed. For multi-blob books
    /// with cross-consistency guarantees, use [`Book::from_blobs`].
    pub fn from_athenaeum(ath: &Athenaeum) -> Self {
        let blob_size = u32::try_from(ath.blob_size)
            .expect("blob_size exceeds u32::MAX");
        Book {
            entries: alloc::vec![BookEntry {
                cid: ath.cid,
                blob_size,
                chunks: ath.chunks.clone(),
            }],
        }
    }

    /// Append a pre-built athenaeum without cross-blob resolution.
    ///
    /// For multi-blob books with cross-consistency guarantees, use
    /// [`Book::from_blobs`] instead.
    pub fn add_athenaeum(&mut self, ath: &Athenaeum) {
        let blob_size = u32::try_from(ath.blob_size)
            .expect("blob_size exceeds u32::MAX");
        self.entries.push(BookEntry {
            cid: ath.cid,
            blob_size,
            chunks: ath.chunks.clone(),
        });
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for entry in &self.entries {
            buf.extend_from_slice(&entry.cid);
            buf.extend_from_slice(&entry.blob_size.to_le_bytes());
            let count = entry.chunks.len() as u16;
            buf.extend_from_slice(&count.to_le_bytes());
            buf.extend_from_slice(&[0u8; 2]); // reserved
            for chunk in &entry.chunks {
                buf.extend_from_slice(&chunk.0.to_le_bytes());
            }
        }
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, BookError> {
        let mut entries = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            // Header: 32 (CID) + 4 (blob_size) + 2 (count) + 2 (reserved) = 40 bytes
            if pos + 40 > data.len() {
                return Err(BookError::TooShort);
            }
            let mut cid = [0u8; 32];
            cid.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;

            let blob_size = u32::from_le_bytes(
                data[pos..pos + 4].try_into().map_err(|_| BookError::TooShort)?,
            );
            pos += 4;

            let count = u16::from_le_bytes(
                data[pos..pos + 2].try_into().map_err(|_| BookError::TooShort)?,
            ) as usize;
            pos += 4; // count (2) + reserved (2)

            let chunk_bytes = count * 4;
            if pos + chunk_bytes > data.len() {
                return Err(BookError::TooShort);
            }

            let mut chunks = Vec::with_capacity(count);
            for _ in 0..count {
                let raw = u32::from_le_bytes(
                    data[pos..pos + 4].try_into().map_err(|_| BookError::TooShort)?,
                );
                let addr = ChunkAddr(raw);
                if !addr.verify_checksum() {
                    return Err(BookError::InvalidChecksum);
                }
                chunks.push(addr);
                pos += 4;
            }

            entries.push(BookEntry { cid, blob_size, chunks });
        }

        Ok(Book { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Athenaeum;
    use crate::hash::sha256_hash;

    #[test]
    fn round_trip_single_blob() {
        let data = vec![0xABu8; 4096 * 4];
        let cid = sha256_hash(b"test");
        let ath = Athenaeum::from_blob(cid, &data).unwrap();
        let book = Book::from_athenaeum(&ath);
        let bytes = book.to_bytes();
        let restored = Book::from_bytes(&bytes).unwrap();
        assert_eq!(restored.entries.len(), 1);
        assert_eq!(restored.entries[0].cid, cid);
        assert_eq!(restored.entries[0].chunks.len(), 4);
        assert_eq!(restored.entries[0].blob_size, data.len() as u32);
    }

    #[test]
    fn round_trip_preserves_addresses() {
        let data = vec![1u8; 4096 * 2];
        let cid = sha256_hash(b"preserve");
        let ath = Athenaeum::from_blob(cid, &data).unwrap();
        let book = Book::from_athenaeum(&ath);
        let bytes = book.to_bytes();
        let restored = Book::from_bytes(&bytes).unwrap();
        for (orig, rest) in ath.chunks.iter().zip(restored.entries[0].chunks.iter()) {
            assert_eq!(orig.0, rest.0);
        }
    }

    #[test]
    fn empty_book() {
        let book = Book { entries: Vec::new() };
        let bytes = book.to_bytes();
        assert!(bytes.is_empty());
        let restored = Book::from_bytes(&bytes).unwrap();
        assert!(restored.entries.is_empty());
    }

    #[test]
    fn invalid_bytes_too_short() {
        assert!(Book::from_bytes(&[0xFF; 3]).is_err());
    }

    #[test]
    fn invalid_bytes_truncated_chunks() {
        // Valid header claiming 10 chunks, but no chunk data follows
        let mut buf = vec![0u8; 40]; // 32 CID + 4 blob_size + 2 count + 2 reserved
        buf[36] = 10; // count = 10
        assert_eq!(Book::from_bytes(&buf), Err(BookError::TooShort));
    }

    #[test]
    fn multi_blob_book() {
        let cid1 = sha256_hash(b"blob1");
        let cid2 = sha256_hash(b"blob2");
        let ath1 = Athenaeum::from_blob(cid1, &vec![1u8; 4096]).unwrap();
        let ath2 = Athenaeum::from_blob(cid2, &vec![2u8; 4096]).unwrap();
        let mut book = Book::from_athenaeum(&ath1);
        book.add_athenaeum(&ath2);
        let bytes = book.to_bytes();
        // 2 entries x (40 header + 1 chunk x 4) = 88 bytes
        assert_eq!(bytes.len(), 88);
        let restored = Book::from_bytes(&bytes).unwrap();
        assert_eq!(restored.entries.len(), 2);
        assert_eq!(restored.entries[0].cid, cid1);
        assert_eq!(restored.entries[1].cid, cid2);
    }

    #[test]
    fn from_blobs_no_cross_collisions() {
        // Two blobs with unique chunks — all addresses must be distinct
        let mut data1 = vec![0u8; 4096 * 4];
        let mut data2 = vec![0u8; 4096 * 4];
        for (i, chunk) in data1.chunks_mut(4096).enumerate() {
            chunk[0] = i as u8;
            chunk[1] = 0xAA;
        }
        for (i, chunk) in data2.chunks_mut(4096).enumerate() {
            chunk[0] = i as u8;
            chunk[1] = 0xBB;
        }
        let cid1 = sha256_hash(b"cross1");
        let cid2 = sha256_hash(b"cross2");

        let book = Book::from_blobs(&[(cid1, &data1), (cid2, &data2)]).unwrap();
        assert_eq!(book.entries.len(), 2);

        // Collect ALL hash_bits across both entries — no duplicates
        let all_addrs: Vec<u32> = book.entries.iter()
            .flat_map(|e| e.chunks.iter().map(|a| a.hash_bits()))
            .collect();
        let mut deduped = all_addrs.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(all_addrs.len(), deduped.len(), "cross-blob collision detected");
    }

    #[test]
    fn from_blobs_cross_dedup_shared_chunks() {
        // Two blobs that share a chunk — the shared chunk should have
        // the same address in both entries
        let shared_chunk = vec![0x42u8; 4096];
        let unique1 = vec![0xAAu8; 4096];
        let unique2 = vec![0xBBu8; 4096];
        let mut data1 = Vec::new();
        data1.extend_from_slice(&shared_chunk);
        data1.extend_from_slice(&unique1);
        let mut data2 = Vec::new();
        data2.extend_from_slice(&shared_chunk);
        data2.extend_from_slice(&unique2);

        let cid1 = sha256_hash(b"dedup1");
        let cid2 = sha256_hash(b"dedup2");
        let book = Book::from_blobs(&[(cid1, &data1), (cid2, &data2)]).unwrap();

        // First chunk of each blob is identical content — same address
        assert_eq!(book.entries[0].chunks[0], book.entries[1].chunks[0]);
        // Second chunks are different — different addresses
        assert_ne!(book.entries[0].chunks[1], book.entries[1].chunks[1]);
    }

    #[test]
    fn from_blobs_round_trip() {
        let mut data1 = vec![0u8; 4096 * 2];
        let mut data2 = vec![0u8; 4096 * 3];
        for (i, b) in data1.iter_mut().enumerate() {
            *b = (i as u32 ^ 0xAA) as u8;
        }
        for (i, b) in data2.iter_mut().enumerate() {
            *b = (i as u32 ^ 0xBB) as u8;
        }
        let cid1 = sha256_hash(b"rt1");
        let cid2 = sha256_hash(b"rt2");

        let book = Book::from_blobs(&[(cid1, &data1), (cid2, &data2)]).unwrap();
        let bytes = book.to_bytes();
        let restored = Book::from_bytes(&bytes).unwrap();
        assert_eq!(book, restored);
    }

    #[test]
    fn book_fits_in_4kb() {
        // A full 256-chunk blob: 40 header + 256*4 = 1064 bytes per entry
        // 4096 / 1064 ~ 3.8, so 3 full entries fit
        let cid = sha256_hash(b"big");
        let data = vec![0u8; 4096 * 256]; // 1MB
        let ath = Athenaeum::from_blob(cid, &data).unwrap();
        let book = Book::from_athenaeum(&ath);
        let bytes = book.to_bytes();
        assert!(bytes.len() <= 4096, "single 1MB blob book = {} bytes", bytes.len());
    }
}
