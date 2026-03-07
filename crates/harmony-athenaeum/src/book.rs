// SPDX-License-Identifier: GPL-2.0-or-later
//! Book — portable athenaeum metadata serialization.

use alloc::vec::Vec;
use crate::addr::ChunkAddr;
use crate::athenaeum::Athenaeum;

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
/// ~3-4 full 256-chunk blob entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Book {
    pub entries: Vec<BookEntry>,
}

impl Book {
    /// Create a book from a single athenaeum.
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

    /// Add another athenaeum to this book.
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
