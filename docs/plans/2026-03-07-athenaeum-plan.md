# Athenaeum Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the Athenaeum crate — a compact content-addressed chunking system that translates 256-bit CID blobs into 32-bit-addressed mini-blobs.

**Architecture:** Standalone `no_std + alloc` crate with no kernel dependencies. Pure math on bytes and hashes. Depends on `sha2` directly (same version as harmony-crypto) for SHA-256 and SHA-224.

**Tech Stack:** Rust (no_std + alloc), sha2 0.10 (SHA-256, SHA-224)

**Design doc:** `docs/plans/2026-03-07-athenaeum-design.md`

---

## Codebase Orientation

### Repo: `zeblithic/harmony-os`

```
crates/
  harmony-athenaeum/         <-- WE ARE BUILDING THIS
    Cargo.toml
    src/
      lib.rs                 <-- Core types (ChunkAddr, Algorithm, Depth, Size)
      addr.rs                <-- ChunkAddr encoding/decoding, checksum
      hash.rs                <-- SHA-256/SHA-224 hashing, address derivation
      athenaeum.rs            <-- Athenaeum struct, chunking, collision resolution
      book.rs                <-- Book serialization/deserialization
```

### Workspace integration

The crate must be added to the workspace `Cargo.toml` members list and as a workspace dependency.

### Test commands

```bash
cargo test -p harmony-athenaeum            # Run all athenaeum tests
cargo test -p harmony-athenaeum test_name   # Run single test
cargo clippy --workspace                    # Lint
cargo test --workspace                      # All workspace tests
```

---

## Task 1: Scaffold Crate and Core Types

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Create: `crates/harmony-athenaeum/Cargo.toml`
- Create: `crates/harmony-athenaeum/src/lib.rs`

**Step 1: Add to workspace**

Add `harmony-athenaeum` to the workspace members and dependencies in the root `Cargo.toml`:

```toml
# In [workspace] members:
members = [
    "crates/harmony-unikernel",
    "crates/harmony-microkernel",
    "crates/harmony-athenaeum",
    "crates/harmony-os",
]

# In [workspace.dependencies]:
harmony-athenaeum = { path = "crates/harmony-athenaeum", default-features = false }
```

**Step 2: Create crate Cargo.toml**

```toml
[package]
name = "harmony-athenaeum"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
description = "32-bit content-addressed chunk system for on-device memory"

[features]
default = ["std"]
std = []

[dependencies]
sha2 = { version = "0.10", default-features = false }
```

**Step 3: Create lib.rs with core types**

```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! Athenaeum — 32-bit content-addressed chunk system.
//!
//! Translates 256-bit CID-addressed blobs into 32-bit-addressed
//! mini-blobs optimized for CPU cache lines and register widths.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod addr;
mod hash;
mod athenaeum;
mod book;

pub use addr::{ChunkAddr, Algorithm, Depth};
pub use athenaeum::{Athenaeum, CollisionError};
pub use book::{Book, BookError};
```

Create stub modules (`addr.rs`, `hash.rs`, `athenaeum.rs`, `book.rs`) with empty content so the crate compiles.

**Step 4: Verify it compiles**

Run: `cargo check -p harmony-athenaeum`
Expected: Compiles with no errors.

**Step 5: Commit**

```bash
git add Cargo.toml crates/harmony-athenaeum/
git commit -m "feat(athenaeum): scaffold crate with core type stubs"
```

---

## Task 2: ChunkAddr Encoding and Decoding

**Files:**
- Create: `crates/harmony-athenaeum/src/addr.rs`

This is the heart of the crate — the 32-bit address word with its 5 fields.

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_fields() {
        let addr = ChunkAddr::new(0x1FFFFF, Algorithm::Sha256Msb, Depth::Blob, 0, 0);
        assert_eq!(addr.hash_bits(), 0x1FFFFF);
        assert_eq!(addr.algorithm(), Algorithm::Sha256Msb);
        assert_eq!(addr.depth(), Depth::Blob);
        assert_eq!(addr.size_exponent(), 0);
        assert_eq!(addr.size_bytes(), 4096);
        assert!(addr.verify_checksum());
    }

    #[test]
    fn algorithm_variants() {
        for algo in [Algorithm::Sha256Msb, Algorithm::Sha256Lsb,
                     Algorithm::Sha224Msb, Algorithm::Sha224Lsb] {
            let addr = ChunkAddr::new(42, algo, Depth::Blob, 0, 0);
            assert_eq!(addr.algorithm(), algo);
            assert!(addr.verify_checksum());
        }
    }

    #[test]
    fn depth_variants() {
        for (depth, expected) in [
            (Depth::Blob, 0), (Depth::Bundle1, 1),
            (Depth::Bundle2, 2), (Depth::Bundle3, 3),
        ] {
            let addr = ChunkAddr::new(0, Algorithm::Sha256Msb, depth, 0, 0);
            assert_eq!(addr.depth() as u8, expected);
        }
    }

    #[test]
    fn size_exponent_all_values() {
        let expected_sizes = [4096, 2048, 1024, 512, 256, 128, 64, 32];
        for (exp, &expected) in expected_sizes.iter().enumerate() {
            let addr = ChunkAddr::new(0, Algorithm::Sha256Msb, Depth::Blob, exp as u8, 0);
            assert_eq!(addr.size_bytes(), expected);
        }
    }

    #[test]
    fn checksum_detects_single_bit_flip() {
        let addr = ChunkAddr::new(12345, Algorithm::Sha224Lsb, Depth::Bundle1, 3, 0);
        assert!(addr.verify_checksum());
        // Flip one bit in the hash field
        let corrupted = ChunkAddr(addr.0 ^ (1 << 20));
        assert!(!corrupted.verify_checksum());
    }

    #[test]
    fn checksum_xor_fold_of_28_bits() {
        // Manually verify: pack 28 bits, XOR-fold into 4 bits
        let addr = ChunkAddr::new(0, Algorithm::Sha256Msb, Depth::Blob, 0, 0);
        // All zeros: checksum should be 0
        assert_eq!(addr.checksum(), 0);
    }

    #[test]
    fn max_hash_bits_value() {
        let addr = ChunkAddr::new(0x1FFFFF, Algorithm::Sha224Lsb, Depth::Bundle3, 7, 0);
        assert_eq!(addr.hash_bits(), 0x1FFFFF);
        assert_eq!(addr.size_bytes(), 32);
        assert!(addr.verify_checksum());
    }

    #[test]
    fn from_raw_u32() {
        let addr = ChunkAddr::new(100, Algorithm::Sha256Lsb, Depth::Blob, 2, 0);
        let raw = addr.0;
        let restored = ChunkAddr(raw);
        assert_eq!(restored.hash_bits(), 100);
        assert_eq!(restored.algorithm(), Algorithm::Sha256Lsb);
        assert_eq!(restored.size_bytes(), 1024);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-athenaeum`
Expected: FAIL — types and methods don't exist yet.

**Step 3: Implement ChunkAddr**

Layout reminder:
```
bits 31-11: hash_bits (21 bits)
bits 10-9:  algorithm (2 bits)
bits 8-7:   depth (2 bits)
bits 6-4:   size_exponent (3 bits)
bits 3-0:   checksum (4 bits)
```

```rust
/// Hash algorithm selector for address derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Algorithm {
    Sha256Msb = 0,
    Sha256Lsb = 1,
    Sha224Msb = 2,
    Sha224Lsb = 3,
}

/// Chunk nesting depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Depth {
    Blob = 0,
    Bundle1 = 1,
    Bundle2 = 2,
    Bundle3 = 3,
}

/// A 32-bit content-addressed chunk identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChunkAddr(pub(crate) u32);

impl ChunkAddr {
    /// Construct a ChunkAddr from its component fields.
    /// The checksum is computed automatically from the other 28 bits.
    /// The `_checksum` parameter is ignored (pass 0).
    pub fn new(
        hash_bits: u32,
        algorithm: Algorithm,
        depth: Depth,
        size_exponent: u8,
        _checksum: u8,
    ) -> Self {
        let hash_bits = hash_bits & 0x1F_FFFF; // 21 bits
        let algo = (algorithm as u32) & 0x3;
        let dep = (depth as u32) & 0x3;
        let size = (size_exponent as u32) & 0x7;

        let bits28 = (hash_bits << 7) | (algo << 5) | (dep << 3) | size;
        let cksum = Self::compute_checksum(bits28);
        ChunkAddr((bits28 << 4) | cksum as u32)
    }

    pub fn hash_bits(&self) -> u32 { (self.0 >> 11) & 0x1F_FFFF }
    pub fn algorithm(&self) -> Algorithm { /* decode bits 10-9 */ }
    pub fn depth(&self) -> Depth { /* decode bits 8-7 */ }
    pub fn size_exponent(&self) -> u8 { ((self.0 >> 4) & 0x7) as u8 }
    pub fn size_bytes(&self) -> usize { 4096 >> self.size_exponent() }
    pub fn checksum(&self) -> u8 { (self.0 & 0xF) as u8 }

    pub fn verify_checksum(&self) -> bool {
        let bits28 = (self.0 >> 4) & 0x0FFF_FFFF;
        Self::compute_checksum(bits28) == self.checksum()
    }

    fn compute_checksum(bits28: u32) -> u8 {
        let mut c = 0u8;
        for i in 0..7 {
            c ^= ((bits28 >> (i * 4)) & 0xF) as u8;
        }
        c & 0xF
    }
}

impl core::fmt::Debug for ChunkAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ChunkAddr({:#010x} hash={} algo={:?} depth={:?} size={}B)",
            self.0, self.hash_bits(), self.algorithm(), self.depth(), self.size_bytes())
    }
}
```

Fill in `algorithm()` and `depth()` decoders using match on the 2-bit values, returning the enum variants. Use `unreachable!()` or a default for the impossible bit patterns (all 2-bit values are covered).

**Step 4: Run tests**

Run: `cargo test -p harmony-athenaeum`
Expected: All tests PASS.

**Step 5: Commit**

```bash
git add crates/harmony-athenaeum/src/addr.rs
git commit -m "feat(athenaeum): ChunkAddr 32-bit encoding with checksum"
```

---

## Task 3: Hash Functions (SHA-256 and SHA-224)

**Files:**
- Create: `crates/harmony-athenaeum/src/hash.rs`

Provides the 4 address derivation strategies.

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Algorithm;

    #[test]
    fn sha256_msb_deterministic() {
        let bits1 = derive_hash_bits(b"hello", Algorithm::Sha256Msb);
        let bits2 = derive_hash_bits(b"hello", Algorithm::Sha256Msb);
        assert_eq!(bits1, bits2);
    }

    #[test]
    fn sha256_msb_vs_lsb_differ() {
        let msb = derive_hash_bits(b"test data", Algorithm::Sha256Msb);
        let lsb = derive_hash_bits(b"test data", Algorithm::Sha256Lsb);
        // Extremely unlikely to be equal for non-trivial data
        assert_ne!(msb, lsb);
    }

    #[test]
    fn sha224_msb_vs_sha256_msb_differ() {
        let sha256 = derive_hash_bits(b"test data", Algorithm::Sha256Msb);
        let sha224 = derive_hash_bits(b"test data", Algorithm::Sha224Msb);
        assert_ne!(sha256, sha224);
    }

    #[test]
    fn hash_bits_fit_in_21_bits() {
        for algo in [Algorithm::Sha256Msb, Algorithm::Sha256Lsb,
                     Algorithm::Sha224Msb, Algorithm::Sha224Lsb] {
            let bits = derive_hash_bits(b"anything", algo);
            assert!(bits <= 0x1FFFFF, "hash bits exceed 21-bit max");
        }
    }

    #[test]
    fn different_data_different_bits() {
        let a = derive_hash_bits(b"alice", Algorithm::Sha256Msb);
        let b = derive_hash_bits(b"bob", Algorithm::Sha256Msb);
        assert_ne!(a, b);
    }

    #[test]
    fn full_hash_sha256_known_vector() {
        // SHA-256("abc") = ba7816bf...
        let hash = sha256_hash(b"abc");
        assert_eq!(hash[0], 0xba);
        assert_eq!(hash[1], 0x78);
    }

    #[test]
    fn full_hash_sha224_known_vector() {
        // SHA-224("abc") = 23097d22...
        let hash = sha224_hash(b"abc");
        assert_eq!(hash[0], 0x23);
        assert_eq!(hash[1], 0x09);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-athenaeum`
Expected: FAIL.

**Step 3: Implement hash functions**

```rust
use sha2::{Digest, Sha256, Sha224};
use crate::addr::Algorithm;

const HASH_BITS: u32 = 21;

pub(crate) fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub(crate) fn sha224_hash(data: &[u8]) -> [u8; 28] {
    let mut hasher = Sha224::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Extract 21 bits from a hash digest — MSB or LSB depending on algorithm.
fn extract_bits_msb(digest: &[u8]) -> u32 {
    // Take first 3 bytes (24 bits), shift right by 3 to get 21 bits
    let b0 = digest[0] as u32;
    let b1 = digest[1] as u32;
    let b2 = digest[2] as u32;
    ((b0 << 16) | (b1 << 8) | b2) >> 3
}

fn extract_bits_lsb(digest: &[u8]) -> u32 {
    let len = digest.len();
    let b0 = digest[len - 3] as u32;
    let b1 = digest[len - 2] as u32;
    let b2 = digest[len - 1] as u32;
    ((b0 << 16) | (b1 << 8) | b2) >> 3
}

/// Derive 21 hash address bits from chunk data using the specified algorithm.
pub(crate) fn derive_hash_bits(data: &[u8], algorithm: Algorithm) -> u32 {
    match algorithm {
        Algorithm::Sha256Msb => extract_bits_msb(&sha256_hash(data)),
        Algorithm::Sha256Lsb => extract_bits_lsb(&sha256_hash(data)),
        Algorithm::Sha224Msb => extract_bits_msb(&sha224_hash(data)),
        Algorithm::Sha224Lsb => extract_bits_lsb(&sha224_hash(data)),
    }
}
```

**Step 4: Run tests**

Run: `cargo test -p harmony-athenaeum`
Expected: All PASS.

**Step 5: Commit**

```bash
git add crates/harmony-athenaeum/src/hash.rs
git commit -m "feat(athenaeum): SHA-256/SHA-224 hash derivation with 4 strategies"
```

---

## Task 4: Address Derivation and Verification

**Files:**
- Modify: `crates/harmony-athenaeum/src/addr.rs` (add `from_data`, `verify`)

Connects ChunkAddr to the hash functions — derive an address from data, verify data matches an address.

**Step 1: Write failing tests**

```rust
#[test]
fn from_data_produces_valid_addr() {
    let data = b"hello athenaeum";
    let addr = ChunkAddr::from_data(data, Depth::Blob, 0);
    assert!(addr.verify_checksum());
    assert_eq!(addr.depth(), Depth::Blob);
    assert_eq!(addr.size_exponent(), 0);
    assert_eq!(addr.algorithm(), Algorithm::Sha256Msb); // default first choice
}

#[test]
fn verify_data_matches_address() {
    let data = b"verify me";
    let addr = ChunkAddr::from_data(data, Depth::Blob, 0);
    assert!(addr.verify_data(data));
    assert!(!addr.verify_data(b"wrong data"));
}

#[test]
fn from_data_with_size_exponent() {
    let data = &[0u8; 128]; // 128 bytes = size_exponent 5
    let addr = ChunkAddr::from_data(data, Depth::Blob, 5);
    assert_eq!(addr.size_bytes(), 128);
}

#[test]
fn from_data_deterministic() {
    let data = b"deterministic";
    let a1 = ChunkAddr::from_data(data, Depth::Blob, 0);
    let a2 = ChunkAddr::from_data(data, Depth::Blob, 0);
    assert_eq!(a1, a2);
}
```

**Step 2: Run tests, verify failure**

**Step 3: Implement**

```rust
impl ChunkAddr {
    /// Derive a ChunkAddr from chunk data.
    /// Uses SHA-256 MSBs (algorithm 00) as the default strategy.
    pub fn from_data(data: &[u8], depth: Depth, size_exponent: u8) -> Self {
        let hash_bits = crate::hash::derive_hash_bits(data, Algorithm::Sha256Msb);
        Self::new(hash_bits, Algorithm::Sha256Msb, depth, size_exponent, 0)
    }

    /// Derive a ChunkAddr with a specific algorithm (for collision resolution).
    pub fn from_data_with_algorithm(
        data: &[u8],
        depth: Depth,
        size_exponent: u8,
        algorithm: Algorithm,
    ) -> Self {
        let hash_bits = crate::hash::derive_hash_bits(data, algorithm);
        Self::new(hash_bits, algorithm, depth, size_exponent, 0)
    }

    /// Verify that `data` matches this address.
    pub fn verify_data(&self, data: &[u8]) -> bool {
        let expected = crate::hash::derive_hash_bits(data, self.algorithm());
        expected == self.hash_bits()
    }
}
```

**Step 4: Run tests — all pass**

**Step 5: Commit**

```bash
git add crates/harmony-athenaeum/src/addr.rs
git commit -m "feat(athenaeum): address derivation and verification from chunk data"
```

---

## Task 5: Athenaeum — Chunking and Collision Resolution

**Files:**
- Create: `crates/harmony-athenaeum/src/athenaeum.rs`

The main struct that chunks a blob and resolves collisions.

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn test_cid() -> [u8; 32] {
        crate::hash::sha256_hash(b"test blob cid")
    }

    #[test]
    fn from_blob_small() {
        let data = vec![0xABu8; 4096]; // exactly one 4KB chunk
        let ath = Athenaeum::from_blob(test_cid(), &data).unwrap();
        assert_eq!(ath.chunks.len(), 1);
        assert_eq!(ath.chunks[0].size_bytes(), 4096);
        assert_eq!(ath.chunks[0].depth(), Depth::Blob);
    }

    #[test]
    fn from_blob_multiple_chunks() {
        let data = vec![0u8; 4096 * 4]; // 4 chunks
        let ath = Athenaeum::from_blob(test_cid(), &data).unwrap();
        assert_eq!(ath.chunks.len(), 4);
    }

    #[test]
    fn from_blob_last_chunk_padded() {
        let data = vec![0u8; 4096 + 100]; // 1 full + 1 partial
        let ath = Athenaeum::from_blob(test_cid(), &data).unwrap();
        assert_eq!(ath.chunks.len(), 2);
        // Last chunk is padded to next power-of-two size boundary
    }

    #[test]
    fn from_blob_no_address_collisions() {
        // Use data that's diverse enough to test collision paths
        let mut data = vec![0u8; 4096 * 64];
        for (i, chunk) in data.chunks_mut(4096).enumerate() {
            chunk[0] = i as u8;
            chunk[1] = (i >> 8) as u8;
        }
        let ath = Athenaeum::from_blob(test_cid(), &data).unwrap();
        // All addresses must be unique
        let mut addrs: alloc::vec::Vec<(u32, u8)> = ath.chunks.iter()
            .map(|a| (a.hash_bits(), a.depth() as u8))
            .collect();
        addrs.sort();
        addrs.dedup();
        assert_eq!(addrs.len(), ath.chunks.len());
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
        let data = vec![42u8; 4096 * 3];
        let ath = Athenaeum::from_blob(test_cid(), &data).unwrap();
        // Store chunks in a map
        let mut store = alloc::collections::BTreeMap::new();
        for (i, addr) in ath.chunks.iter().enumerate() {
            let start = i * 4096;
            let end = core::cmp::min(start + 4096, data.len());
            let mut chunk = data[start..end].to_vec();
            // Pad to declared size
            chunk.resize(addr.size_bytes(), 0);
            store.insert(addr.0, chunk);
        }
        let reassembled = ath.reassemble(|addr| {
            store.get(&addr.0).cloned()
        }).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn reassemble_missing_chunk_fails() {
        let data = vec![1u8; 4096 * 2];
        let ath = Athenaeum::from_blob(test_cid(), &data).unwrap();
        let result = ath.reassemble(|_addr| None);
        assert!(result.is_err());
    }

    #[test]
    fn empty_blob() {
        let ath = Athenaeum::from_blob(test_cid(), &[]).unwrap();
        assert_eq!(ath.chunks.len(), 0);
    }

    #[test]
    fn max_blob_size() {
        // 1MB = 256 chunks of 4KB
        let data = vec![0u8; 1024 * 1024];
        let ath = Athenaeum::from_blob(test_cid(), &data).unwrap();
        assert_eq!(ath.chunks.len(), 256);
    }
}
```

**Step 2: Run tests, verify failure**

**Step 3: Implement**

```rust
use alloc::vec::Vec;
use alloc::collections::BTreeSet;
use crate::addr::{ChunkAddr, Algorithm, Depth};

/// Maximum blob size (1MB).
const MAX_BLOB_SIZE: usize = 1024 * 1024;

/// Standard chunk size (4KB).
const CHUNK_SIZE: usize = 4096;

/// All algorithms in priority order for collision resolution.
const ALGORITHMS: [Algorithm; 4] = [
    Algorithm::Sha256Msb,
    Algorithm::Sha256Lsb,
    Algorithm::Sha224Msb,
    Algorithm::Sha224Lsb,
];

/// Error when all 4 algorithms produce collisions for a chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollisionError {
    pub chunk_index: usize,
}

/// An athenaeum — maps a blob into content-addressed chunks.
pub struct Athenaeum {
    pub cid: [u8; 32],
    pub chunks: Vec<ChunkAddr>,
    /// Original blob size (needed for reassembly to trim padding).
    pub blob_size: usize,
}

impl Athenaeum {
    /// Build an athenaeum by chunking a blob and resolving collisions.
    pub fn from_blob(cid: [u8; 32], data: &[u8]) -> Result<Self, CollisionError> {
        if data.is_empty() {
            return Ok(Athenaeum { cid, chunks: Vec::new(), blob_size: 0 });
        }

        let mut chunks = Vec::new();
        let mut used_addrs = BTreeSet::new();

        for (i, chunk_data) in data.chunks(CHUNK_SIZE).enumerate() {
            // Pad partial last chunk to the smallest power-of-two >= its size
            let size_exp = chunk_size_exponent(chunk_data.len());
            let padded_size = 4096 >> size_exp;
            let mut padded = alloc::vec![0u8; padded_size];
            padded[..chunk_data.len()].copy_from_slice(chunk_data);

            let addr = address_with_collision_resolution(
                &padded, Depth::Blob, size_exp, &used_addrs
            ).ok_or(CollisionError { chunk_index: i })?;

            used_addrs.insert(addr.hash_bits());
            chunks.push(addr);
        }

        Ok(Athenaeum { cid, chunks, blob_size: data.len() })
    }

    /// Reconstruct the original blob from chunks.
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingChunkError {
    pub chunk_index: usize,
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

/// Find the smallest size exponent where 4096 >> exp >= len.
fn chunk_size_exponent(len: usize) -> u8 {
    for exp in 0..8u8 {
        if (4096 >> exp) >= len {
            // Keep going to find the tightest fit
        } else {
            return if exp > 0 { exp - 1 } else { 0 };
        }
    }
    7 // minimum 32 bytes
}
```

Note: The `chunk_size_exponent` function needs care — find the largest exponent where `4096 >> exp >= len`. Test edge cases (len=1, len=32, len=33, len=4096).

**Step 4: Run tests — all pass**

**Step 5: Commit**

```bash
git add crates/harmony-athenaeum/src/athenaeum.rs
git commit -m "feat(athenaeum): blob chunking with 4-algorithm collision resolution"
```

---

## Task 6: Book Serialization

**Files:**
- Create: `crates/harmony-athenaeum/src/book.rs`

Serialize/deserialize an athenaeum as a compact "book" — a portable hint.

**Step 1: Write failing tests**

```rust
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
        let book = Book { entries: alloc::vec::Vec::new() };
        let bytes = book.to_bytes();
        let restored = Book::from_bytes(&bytes).unwrap();
        assert!(restored.entries.is_empty());
    }

    #[test]
    fn invalid_bytes_rejected() {
        assert!(Book::from_bytes(&[0xFF; 3]).is_err());
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
        assert!(bytes.len() <= 4096, "book should fit in a single 4KB chunk");
        let restored = Book::from_bytes(&bytes).unwrap();
        assert_eq!(restored.entries.len(), 2);
    }
}
```

**Step 2: Run tests, verify failure**

**Step 3: Implement**

Book wire format (per entry):
```
[32 bytes: CID] [4 bytes: blob_size as u32] [2 bytes: chunk_count as u16] [2 bytes: reserved]
[chunk_count × 4 bytes: ChunkAddr values]
```

```rust
use alloc::vec::Vec;
use crate::addr::ChunkAddr;
use crate::athenaeum::Athenaeum;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BookError {
    TooShort,
    InvalidChunkCount,
}

pub struct BookEntry {
    pub cid: [u8; 32],
    pub blob_size: u32,
    pub chunks: Vec<ChunkAddr>,
}

pub struct Book {
    pub entries: Vec<BookEntry>,
}

impl Book {
    pub fn from_athenaeum(ath: &Athenaeum) -> Self {
        Book {
            entries: alloc::vec![BookEntry {
                cid: ath.cid,
                blob_size: ath.blob_size as u32,
                chunks: ath.chunks.clone(),
            }],
        }
    }

    pub fn add_athenaeum(&mut self, ath: &Athenaeum) {
        self.entries.push(BookEntry {
            cid: ath.cid,
            blob_size: ath.blob_size as u32,
            chunks: ath.chunks.clone(),
        });
    }

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

    pub fn from_bytes(data: &[u8]) -> Result<Self, BookError> {
        let mut entries = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            if pos + 40 > data.len() {
                return Err(BookError::TooShort);
            }
            let mut cid = [0u8; 32];
            cid.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;
            let blob_size = u32::from_le_bytes(
                data[pos..pos + 4].try_into().unwrap()
            );
            pos += 4;
            let count = u16::from_le_bytes(
                data[pos..pos + 2].try_into().unwrap()
            ) as usize;
            pos += 4; // count + reserved

            if pos + count * 4 > data.len() {
                return Err(BookError::TooShort);
            }
            let mut chunks = Vec::with_capacity(count);
            for _ in 0..count {
                let raw = u32::from_le_bytes(
                    data[pos..pos + 4].try_into().unwrap()
                );
                chunks.push(ChunkAddr(raw));
                pos += 4;
            }
            entries.push(BookEntry { cid, blob_size, chunks });
        }
        Ok(Book { entries })
    }
}
```

**Step 4: Run tests — all pass**

**Step 5: Commit**

```bash
git add crates/harmony-athenaeum/src/book.rs
git commit -m "feat(athenaeum): book serialization for portable athenaeum hints"
```

---

## Task 7: Public API Cleanup and Integration Test

**Files:**
- Modify: `crates/harmony-athenaeum/src/lib.rs` (finalize exports)
- Add integration test at bottom of `lib.rs` or in `tests/`

**Step 1: Write the integration test**

An end-to-end test that exercises the full workflow: chunk a 1MB blob, serialize to a book, deserialize, reassemble, verify.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_1mb_blob() {
        // Create a 1MB blob with varied content
        let mut data = alloc::vec![0u8; 1024 * 1024];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i.wrapping_mul(7).wrapping_add(13)) as u8;
        }

        // Chunk it
        let cid = hash::sha256_hash(&data);
        let ath = Athenaeum::from_blob(cid, &data).unwrap();
        assert_eq!(ath.chunks.len(), 256);

        // All addresses are unique
        let mut seen = alloc::collections::BTreeSet::new();
        for chunk in &ath.chunks {
            assert!(chunk.verify_checksum());
            assert!(seen.insert(chunk.hash_bits()));
        }

        // Serialize to book
        let book = Book::from_athenaeum(&ath);
        let book_bytes = book.to_bytes();
        assert!(book_bytes.len() <= 4096, "book fits in single 4KB chunk");

        // Deserialize book
        let restored_book = Book::from_bytes(&book_bytes).unwrap();
        assert_eq!(restored_book.entries[0].chunks.len(), 256);

        // Reassemble from chunks
        let reassembled = ath.reassemble(|addr| {
            let idx = ath.chunks.iter().position(|a| a.0 == addr.0)?;
            let start = idx * 4096;
            let end = core::cmp::min(start + 4096, data.len());
            Some(data[start..end].to_vec())
        }).unwrap();

        assert_eq!(reassembled, data);
    }

    #[test]
    fn verify_individual_chunks() {
        let data = alloc::vec![0xCDu8; 4096 * 4];
        let cid = hash::sha256_hash(&data);
        let ath = Athenaeum::from_blob(cid, &data).unwrap();

        for (i, addr) in ath.chunks.iter().enumerate() {
            let start = i * 4096;
            let end = core::cmp::min(start + 4096, data.len());
            let mut chunk = data[start..end].to_vec();
            chunk.resize(addr.size_bytes(), 0);
            assert!(addr.verify_data(&chunk),
                "chunk {} failed verification", i);
        }
    }
}
```

**Step 2: Ensure lib.rs exports are clean**

Verify that `pub use` statements expose: `ChunkAddr`, `Algorithm`, `Depth`, `Athenaeum`, `CollisionError`, `Book`, `BookError`, `MissingChunkError`. Also make `hash::sha256_hash` and `hash::sha224_hash` available if useful for callers building CIDs.

**Step 3: Run full test suite**

Run: `cargo test --workspace`
Run: `cargo clippy --workspace`
Expected: All pass, zero warnings.

**Step 4: Commit**

```bash
git add crates/harmony-athenaeum/
git commit -m "feat(athenaeum): integration tests and public API finalization"
```

---

## Task Summary

| Task | What | Key Deliverable |
|------|------|-----------------|
| 1 | Scaffold crate | Compiling crate with stubs |
| 2 | ChunkAddr encoding | 32-bit word with 5 fields + checksum |
| 3 | Hash functions | SHA-256/SHA-224 × MSB/LSB derivation |
| 4 | Address derivation | `from_data` + `verify_data` on ChunkAddr |
| 5 | Athenaeum chunking | Blob → chunks with collision resolution |
| 6 | Book serialization | Portable hint encode/decode |
| 7 | Integration test | End-to-end 1MB round-trip |
