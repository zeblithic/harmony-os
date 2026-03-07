// SPDX-License-Identifier: GPL-2.0-or-later
//! Athenaeum — blob chunking and collision resolution.

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::addr::{Algorithm, ChunkAddr, Depth};

/// Maximum blob size (1MB).
pub const MAX_BLOB_SIZE: usize = 1024 * 1024;

/// Standard chunk size (4KB).
pub(crate) const CHUNK_SIZE: usize = 4096;

/// All algorithms in priority order for collision resolution.
const ALGORITHMS: [Algorithm; 4] = [
    Algorithm::Sha256Msb,
    Algorithm::Sha256Lsb,
    Algorithm::Sha224Msb,
    Algorithm::Sha224Lsb,
];

/// Error when chunking a blob fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollisionError {
    /// All 4 algorithms produced collisions for this chunk.
    AllAlgorithmsCollide { chunk_index: usize },
    /// Blob exceeds `MAX_BLOB_SIZE`.
    BlobTooLarge { size: usize },
}

/// Error when a chunk is missing during reassembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingChunkError {
    pub chunk_index: usize,
}

/// An athenaeum — maps a blob into content-addressed chunks.
pub struct Athenaeum {
    /// 256-bit CID of the source blob.
    pub cid: [u8; 32],
    /// Ordered chunk addresses.
    pub chunks: Vec<ChunkAddr>,
    /// Original blob size (needed for reassembly to trim padding on last chunk).
    pub blob_size: usize,
}

impl Athenaeum {
    /// Build an athenaeum by chunking a blob and resolving collisions.
    ///
    /// Splits `data` into CHUNK_SIZE (4KB) pieces. The last chunk is
    /// padded to the smallest power-of-two size >= its length. For each
    /// chunk, tries algorithms in order until a collision-free address
    /// is found.
    pub fn from_blob(cid: [u8; 32], data: &[u8]) -> Result<Self, CollisionError> {
        if data.len() > MAX_BLOB_SIZE {
            return Err(CollisionError::BlobTooLarge { size: data.len() });
        }

        let mut used_addrs = BTreeSet::new();
        let mut content_cache = BTreeMap::new();
        let chunks = chunk_blob(data, &mut used_addrs, &mut content_cache)?;

        Ok(Athenaeum {
            cid,
            chunks,
            blob_size: data.len(),
        })
    }

    /// Reconstruct the original blob from chunks.
    ///
    /// Calls `fetch` for each chunk address in order. The returned data
    /// is concatenated and truncated to `blob_size`.
    pub fn reassemble(
        &self,
        fetch: impl Fn(ChunkAddr) -> Option<Vec<u8>>,
    ) -> Result<Vec<u8>, MissingChunkError> {
        let mut result = Vec::with_capacity(self.blob_size);
        for (i, &addr) in self.chunks.iter().enumerate() {
            let chunk = fetch(addr).ok_or(MissingChunkError { chunk_index: i })?;
            result.extend_from_slice(&chunk);
        }
        result.truncate(self.blob_size);
        Ok(result)
    }
}

/// Chunk a blob into addressed pieces, resolving collisions against
/// cumulative state. Identical chunks across calls reuse the same address
/// (content deduplication).
///
/// This is the shared core used by both `Athenaeum::from_blob()` (fresh state
/// per blob) and `Book::from_blobs()` (shared state across blobs).
pub(crate) fn chunk_blob(
    data: &[u8],
    used_addrs: &mut BTreeSet<u32>,
    content_cache: &mut BTreeMap<[u8; 32], ChunkAddr>,
) -> Result<Vec<ChunkAddr>, CollisionError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut chunks = Vec::new();
    for (i, chunk_data) in data.chunks(CHUNK_SIZE).enumerate() {
        let size_exp = chunk_size_exponent(chunk_data.len());
        let padded_size = CHUNK_SIZE >> (size_exp as usize);
        let mut padded = alloc::vec![0u8; padded_size];
        padded[..chunk_data.len()].copy_from_slice(chunk_data);

        // If we've already seen identical content, reuse the address.
        let content_hash = crate::hash::sha256_hash(&padded);
        if let Some(&cached) = content_cache.get(&content_hash) {
            chunks.push(cached);
            continue;
        }

        let addr =
            address_with_collision_resolution(&padded, Depth::Blob, size_exp, used_addrs)
                .ok_or(CollisionError::AllAlgorithmsCollide { chunk_index: i })?;

        used_addrs.insert(addr.hash_bits());
        content_cache.insert(content_hash, addr);
        chunks.push(addr);
    }

    Ok(chunks)
}

/// Try all 4 algorithms to find a collision-free address.
fn address_with_collision_resolution(
    data: &[u8],
    depth: Depth,
    size_exp: u8,
    used: &BTreeSet<u32>,
) -> Option<ChunkAddr> {
    for &algo in &ALGORITHMS {
        let addr = ChunkAddr::from_data_with_algorithm(data, depth, size_exp, algo);
        if !used.contains(&addr.hash_bits()) {
            return Some(addr);
        }
    }
    None
}

/// Find the size exponent for a chunk: the largest `exp` where `4096 >> exp >= len`.
///
/// Returns 0 for full 4KB chunks, up to 7 for 32-byte chunks.
fn chunk_size_exponent(len: usize) -> u8 {
    // Full-size chunks are the common case
    if len > 2048 {
        return 0;
    }
    for exp in 1..8u8 {
        let size = CHUNK_SIZE >> (exp as usize);
        if size < len {
            return exp - 1;
        }
    }
    7 // minimum 32 bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cid() -> [u8; 32] {
        crate::hash::sha256_hash(b"test blob cid")
    }

    #[test]
    fn chunk_size_exponent_full() {
        assert_eq!(chunk_size_exponent(4096), 0);
        assert_eq!(chunk_size_exponent(2049), 0);
    }

    #[test]
    fn chunk_size_exponent_half() {
        assert_eq!(chunk_size_exponent(2048), 1);
        assert_eq!(chunk_size_exponent(1025), 1);
    }

    #[test]
    fn chunk_size_exponent_small() {
        assert_eq!(chunk_size_exponent(32), 7);
        assert_eq!(chunk_size_exponent(1), 7);
    }

    #[test]
    fn chunk_size_exponent_boundary() {
        assert_eq!(chunk_size_exponent(33), 6); // needs 64
        assert_eq!(chunk_size_exponent(64), 6);
        assert_eq!(chunk_size_exponent(65), 5); // needs 128
    }

    #[test]
    fn from_blob_single_chunk() {
        let data = vec![0xABu8; 4096];
        let ath = Athenaeum::from_blob(test_cid(), &data).unwrap();
        assert_eq!(ath.chunks.len(), 1);
        assert_eq!(ath.chunks[0].size_bytes(), 4096);
        assert_eq!(ath.chunks[0].depth(), Depth::Blob);
    }

    #[test]
    fn from_blob_multiple_chunks() {
        let data = vec![0u8; 4096 * 4];
        let ath = Athenaeum::from_blob(test_cid(), &data).unwrap();
        assert_eq!(ath.chunks.len(), 4);
    }

    #[test]
    fn from_blob_last_chunk_padded() {
        let data = vec![0u8; 4096 + 100];
        let ath = Athenaeum::from_blob(test_cid(), &data).unwrap();
        assert_eq!(ath.chunks.len(), 2);
        // Last chunk should be 128 bytes (smallest power-of-two >= 100)
        assert_eq!(ath.chunks[1].size_bytes(), 128);
    }

    #[test]
    fn from_blob_no_address_collisions() {
        let mut data = vec![0u8; 4096 * 64];
        for (i, chunk) in data.chunks_mut(4096).enumerate() {
            chunk[0] = i as u8;
            chunk[1] = (i >> 8) as u8;
        }
        let ath = Athenaeum::from_blob(test_cid(), &data).unwrap();
        let mut addrs: Vec<u32> = ath.chunks.iter().map(|a| a.hash_bits()).collect();
        let orig_len = addrs.len();
        addrs.sort();
        addrs.dedup();
        assert_eq!(addrs.len(), orig_len, "duplicate addresses found");
    }

    #[test]
    fn from_blob_cid_preserved() {
        let cid = test_cid();
        let data = vec![1u8; 4096];
        let ath = Athenaeum::from_blob(cid, &data).unwrap();
        assert_eq!(ath.cid, cid);
    }

    #[test]
    fn reassemble_round_trip() {
        let mut data = vec![0u8; 4096 * 3];
        for (i, b) in data.iter_mut().enumerate() {
            let pos = i as u32;
            *b = (pos ^ (pos >> 8) ^ (pos >> 16)) as u8;
        }
        let ath = Athenaeum::from_blob(test_cid(), &data).unwrap();

        let reassembled = ath
            .reassemble(|addr| {
                let idx = ath.chunks.iter().position(|a| a.0 == addr.0)?;
                let start = idx * 4096;
                let end = core::cmp::min(start + 4096, data.len());
                let mut chunk = data[start..end].to_vec();
                chunk.resize(addr.size_bytes(), 0);
                Some(chunk)
            })
            .unwrap();

        assert_eq!(reassembled, data);
    }

    #[test]
    fn reassemble_partial_last_chunk() {
        // Non-aligned size: 4096 + 500 bytes
        let mut data = vec![0u8; 4096 + 500];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let ath = Athenaeum::from_blob(test_cid(), &data).unwrap();

        let reassembled = ath
            .reassemble(|addr| {
                let idx = ath.chunks.iter().position(|a| a.0 == addr.0)?;
                let start = idx * 4096;
                let end = core::cmp::min(start + 4096, data.len());
                let mut chunk = data[start..end].to_vec();
                chunk.resize(addr.size_bytes(), 0);
                Some(chunk)
            })
            .unwrap();

        assert_eq!(reassembled.len(), data.len());
        assert_eq!(reassembled, data);
    }

    #[test]
    fn reassemble_missing_chunk_fails() {
        let data = vec![1u8; 4096 * 2];
        let ath = Athenaeum::from_blob(test_cid(), &data).unwrap();
        let result = ath.reassemble(|_addr| None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().chunk_index, 0);
    }

    #[test]
    fn empty_blob() {
        let ath = Athenaeum::from_blob(test_cid(), &[]).unwrap();
        assert_eq!(ath.chunks.len(), 0);
        assert_eq!(ath.blob_size, 0);
    }

    #[test]
    fn max_blob_256_chunks() {
        let data = vec![0u8; 1024 * 1024];
        let ath = Athenaeum::from_blob(test_cid(), &data).unwrap();
        assert_eq!(ath.chunks.len(), 256);
    }

    #[test]
    fn blob_size_preserved() {
        let data = vec![0xFFu8; 5000];
        let ath = Athenaeum::from_blob(test_cid(), &data).unwrap();
        assert_eq!(ath.blob_size, 5000);
    }
}
