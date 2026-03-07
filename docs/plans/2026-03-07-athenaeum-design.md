# Athenaeum Design

**Status:** Approved design
**Date:** 2026-03-07
**Scope:** harmony-os (crates/harmony-athenaeum)
**Bead:** harmony-ihy

## Goal

Design and implement the Athenaeum — a compact content-addressed chunking
system that translates 256-bit CID-addressed 1MB blobs into 32-bit-addressed
mini-blobs sized for CPU cache lines and register widths.

## Problem

The Harmony content layer operates on 1MB blobs identified by 256-bit CIDs.
This works at the network and storage tiers, but lower-level layers (Ring 1
unikernels, microcontrollers, DMA engines) can't efficiently operate on 1MB
units or feed 256-bit addresses into 32-bit/64-bit CPUs. We need a way to
break these blobs into cache-friendly pieces with addresses that fit in a
single machine register.

## Core Concept

The Athenaeum is a **local optimization lens** — a way to view a 256-bit
global blob through 32-bit locally-addressed 4KB (or smaller) pieces. Each
device builds its own athenaeum independently, and two devices may address
the same blob's chunks differently. The global truth is always the 256-bit
CID; the 32-bit addresses are ephemeral, local, and reconstructable.

An optional "book" (athenaeum metadata) can be shared as a portable hint —
"here's one way to slice this blob that worked for me" — but any device can
compute its own from the raw blob data.

## 32-bit Address Layout

Every chunk is identified by a single 32-bit word:

```
31                           11 10  9  8  7  6  5  4  3  2  1  0
+----------------------------+--+--+--------+-----------+
|  21 bits: hash address     |2b|2b| 3 bits |  4 bits   |
| (from selected algorithm)  |al|dp|  size  | checksum  |
+----------------------------+--+--+--------+-----------+
```

### Field Definitions

#### Hash Address (bits 31-11) — 21 bits

The content-derived address. Extracted from the chunk's hash using the
algorithm and bit selection specified by the algorithm field. 21 bits gives
~2M addressable slots per athenaeum — with a maximum of 256 chunks per blob
and 4 algorithm choices per chunk, collisions are essentially impossible.

#### Algorithm (bits 10-9) — 2 bits

Selects which hash and which end of the digest to use:

| Value | Algorithm | Bits Used |
|-------|-----------|-----------|
| `00`  | SHA-256   | Most significant 21 bits |
| `01`  | SHA-256   | Least significant 21 bits |
| `10`  | SHA-224   | Most significant 21 bits |
| `11`  | SHA-224   | Least significant 21 bits |

This is the **"power of choice"** — like having four names for the same
person (James / Englund / Jake / Zeblith). If two chunks collide under one
algorithm, try another. With 4 independent hash derivations, the probability
of all 4 colliding in a 21-bit space with 256 entries is vanishingly small.

#### Depth (bits 8-7) — 2 bits

Distinguishes raw data chunks from bundle (directory) chunks:

| Value | Meaning | Contains |
|-------|---------|----------|
| `00`  | Mini-blob | Raw data (up to 4KB) |
| `01`  | Level-1 bundle | Array of depth-00 addresses |
| `10`  | Level-2 bundle | Array of depth-01 addresses |
| `11`  | Level-3 bundle | Array of depth-10 addresses |

Maximum addressable data at each depth (fully packed, 4KB chunks):

- Depth 00: 4KB raw data
- Depth 01: 1024 x 4KB = 4MB
- Depth 10: 1024 x 4MB = 4GB
- Depth 11: 1024 x 4GB = 4TB

The practical sweet spot is depth 00 (mini-blobs) and depth 01 (first-level
bundles). Depths 10/11 are cheap insurance (2 bits) for future use cases
that need deeper nesting. Beyond depth 11, use the full 256-bit CID layer
or flat-pack the data.

#### Size (bits 6-4) — 3 bits

Chunk size as an exponential halving of 4KB: `4096 >> X` bytes, where X is
the 3-bit value.

| Value | Size | Use Case |
|-------|------|----------|
| `000` | 4096 bytes (4KB) | Standard chunk |
| `001` | 2048 bytes (2KB) | |
| `010` | 1024 bytes (1KB) | Athenaeum book metadata |
| `011` | 512 bytes | |
| `100` | 256 bytes | Small config/metadata |
| `101` | 128 bytes | |
| `110` | 64 bytes | Single cache line |
| `111` | 32 bytes | Single 256-bit value |

All chunks are zero-padded to their declared size for alignment. 32 bytes
is the minimum — enough for a single 256-bit address, and two fit on a
common 64-byte cache line.

#### Checksum (bits 3-0) — 4 bits

XOR-fold of the other 28 bits into 4-bit groups (seven groups XOR'd
together). Provides a quick integrity check on the address word itself —
catches any single-bit flip without needing to hash the chunk data.

- Detection rate: 93.75% on random single-bit corruption
- On 3 independent retries with independent corruption: 0.002% chance of
  all three failing
- Even if the checksum passes on corrupted data, higher layers
  (SHA-256/224 verification, CID verification on reassembly) will catch it

```rust
fn checksum(bits28: u32) -> u8 {
    let mut c = 0u8;
    for i in 0..7 {
        c ^= ((bits28 >> (i * 4)) & 0xF) as u8;
    }
    c & 0xF
}
```

## Collision Resolution

Collision resolution happens **per-athenaeum** (per-blob), not globally.
Each blob's chunks only need to be collision-free among themselves.

### Algorithm

When importing a blob into a local athenaeum:

1. Chunk the blob into pieces (typically 256 x 4KB for a 1MB blob)
2. For each chunk, try algorithm `00` (SHA-256 MSBs) first
3. If the 21-bit address collides with an already-assigned chunk in this
   athenaeum, try `01`, then `10`, then `11`
4. Record the chosen algorithm in the chunk's address word
5. If all 4 algorithms produce collisions (probability: ~2^-72 for 256
   chunks in a 21-bit space), the import fails — but this is essentially
   impossible in practice

Computing the athenaeum (step 2-4) is a one-time cost. Verification is
trivial: hash the chunk with the specified algorithm, compare the address
bits.

## Athenaeum Book (Metadata)

The "book" is a content-addressed chunk that maps a 256-bit CID to a
sequence of 32-bit chunk addresses. It is:

- **A portable hint**, not authoritative — any device can compute its own
- **Content-addressed itself** — identified by its own hash, like
  everything else in Harmony
- **Compact** — 256 chunks x 4 bytes = 1KB; fits in a single mini-blob
- **Multi-blob capable** — a 4KB book chunk holds up to 1024 entries,
  enough to describe 4 x 256-chunk blobs

### Book Structure

```
+---------------------------+
| 256-bit CID of blob 1     | 32 bytes
| count_1: u16              | 2 bytes
| padding: u16              | 2 bytes
| chunk_addr[0]: u32        | \
| chunk_addr[1]: u32        |  } count_1 entries
| ...                       | /
+---------------------------+
| 256-bit CID of blob 2     | (optional, if space permits)
| count_2: u16              |
| ...                       |
+---------------------------+
```

A book can be:
- Embedded within the 1MB blob itself (self-contained package)
- Stored independently as a mini-blob in the athenaeum
- Transmitted as a hint alongside the 256-bit CID

If no book is available, the device computes the chunk mapping from the raw
blob data directly.

## Architectural Boundary

```
        256-bit CID world (global, network, storage)
        ============================================
                          |
                    Athenaeum layer
                    (translation lens)
                          |
        ============================================
        32-bit address world (local, per-device, cache-optimized)
```

- **Below Athenaeum**: location-addressed (physical DMA, hardware registers)
- **Above Athenaeum**: content-addressed (256-bit CIDs, Zenoh, bundles)
- **Athenaeum itself**: the bridge — content-addressed at both levels, but
  translating between address widths

Ring 1 uses location-addressed heap for DMA. Athenaeum is a Ring 2+ concern
but implemented as a standalone `no_std` crate for maximum reuse.

## Crate Design

### Location

New crate: `crates/harmony-athenaeum/` in the harmony-os repo.

- `no_std` compatible with `alloc`
- Depends on `harmony-crypto` (SHA-256, SHA-224)
- No kernel/IPC/process dependencies — pure math on bytes and hashes
- Importable by the microkernel, unikernel, or any higher layer

### Public API (sketch)

```rust
/// A 32-bit content-addressed chunk identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChunkAddr(u32);

impl ChunkAddr {
    pub fn hash_bits(&self) -> u32;    // 21-bit address
    pub fn algorithm(&self) -> Algorithm;
    pub fn depth(&self) -> Depth;
    pub fn size_bytes(&self) -> usize; // 4096 >> size_field
    pub fn checksum(&self) -> u8;      // 4-bit XOR-fold
    pub fn verify_checksum(&self) -> bool;
}

/// Algorithm selector for hash derivation.
pub enum Algorithm {
    Sha256Msb = 0,
    Sha256Lsb = 1,
    Sha224Msb = 2,
    Sha224Lsb = 3,
}

/// Chunk nesting depth.
pub enum Depth {
    Blob = 0,      // Raw data
    Bundle1 = 1,   // Contains depth-0 addresses
    Bundle2 = 2,   // Contains depth-1 addresses
    Bundle3 = 3,   // Contains depth-2 addresses
}

/// Compute a ChunkAddr for a data slice, trying algorithms in order
/// to avoid collisions with `existing` addresses.
pub fn address_chunk(
    data: &[u8],
    depth: Depth,
    existing: &[ChunkAddr],
) -> Result<ChunkAddr, CollisionError>;

/// Verify that a chunk's data matches its address.
pub fn verify_chunk(addr: ChunkAddr, data: &[u8]) -> bool;

/// An athenaeum — maps a blob into content-addressed chunks.
pub struct Athenaeum {
    pub cid: [u8; 32],           // 256-bit CID of the source blob
    pub chunks: Vec<ChunkAddr>,  // Ordered chunk addresses
}

impl Athenaeum {
    /// Build an athenaeum by chunking a blob and resolving collisions.
    pub fn from_blob(cid: [u8; 32], data: &[u8]) -> Result<Self, CollisionError>;

    /// Serialize to a compact book (portable hint).
    pub fn to_book(&self) -> Vec<u8>;

    /// Deserialize from a book.
    pub fn from_book(data: &[u8]) -> Result<Self, ParseError>;

    /// Reconstruct the original blob from chunks.
    pub fn reassemble(&self, chunks: &dyn Fn(ChunkAddr) -> Option<Vec<u8>>) -> Result<Vec<u8>, MissingChunkError>;
}
```

## What This Design Does NOT Cover

- **Chunk storage backend** — How/where chunks are stored on device (memory,
  flash, network cache). That's the caller's concern.
- **Chunk transport** — How chunks move between devices. That's the Zenoh/
  Reticulum layer's concern.
- **Cache eviction** — Which chunks to keep/discard. That's the content
  layer's W-TinyLFU cache.
- **Hardware paging integration** — Mapping chunks into process address
  spaces via page tables. That's a future Ring 2 milestone.
