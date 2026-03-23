# GENET Ethernet DMA Ring Buffers

**Bead:** harmony-os-v2o
**Date:** 2026-03-23
**Status:** Draft

## Problem

The GENET Ethernet driver (BCM54213PE on RPi5) exists as a sans-I/O state
machine, but frame data handling is PIO-only. The `send` method writes
`DMA_DESC_LENGTH_STATUS` but not the address fields. The `poll_rx` method
reads descriptor metadata but returns placeholder zero-filled data. Real
hardware requires DMA ring buffers: pre-allocated memory whose physical
addresses are written into the descriptor address fields so the GENET DMA
engine can read/write frame data directly.

## Solution

Add a `DmaPool` struct that manages pre-allocated buffers with known physical
addresses. Extend `GenetDriver::send` and `poll_rx` to write/read
`DMA_DESC_ADDRESS_LO/HI`. Add aarch64 cache maintenance helpers for DMA
coherency. The sans-I/O driver stays testable with mock pool + mock register
bank.

## Design Decisions

### DmaPool as a separate struct, not a trait

The pool is a simple fixed-size array of pre-allocated buffers. No need for
trait abstraction — the platform layer constructs it with physical addresses,
and the driver uses it. Mock tests use heap addresses as "physical" addresses
(identity-mapped in the test arena pattern).

### Separate TX and RX pools

TX and RX have different ownership patterns: TX buffers are allocated on send
and freed on completion; RX buffers are pre-armed and recycled per-frame.
Separate pools keep ownership tracking simple and prevent TX exhaustion from
starving RX.

### 2048-byte buffers

Each buffer is 2048 bytes — enough for a max Ethernet frame (1536 bytes) with
alignment headroom. Matches the VirtIO-net `BUF_SIZE` pattern. Allocated from
4 KiB pages (one buffer per page, first 2048 bytes used).

### Cache maintenance in the boot crate, not the driver

The sans-I/O driver doesn't know about cache coherency. The MMIO integration
layer (boot crate) calls `cache::clean_range` before TX and
`cache::invalidate_range` after RX. This keeps the driver testable without
hardware.

### RX buffer pre-arming

At init time, all RX descriptors are pre-armed with buffer addresses. When a
frame is received, the consumed buffer is freed and a new one is allocated and
armed in its place. This ensures hardware always has buffers to write into.

### Descriptor write ordering

When arming a descriptor (TX send or RX re-arm), writes must be ordered:
1. Write `DMA_DESC_ADDRESS_LO` (buffer physical address low 32 bits)
2. Write `DMA_DESC_ADDRESS_HI` (buffer physical address high 32 bits)
3. Write `DMA_DESC_LENGTH_STATUS` **last** (transfers ownership to hardware)

The LENGTH_STATUS word contains the SOP/EOP flags that the DMA engine reads
to determine the descriptor is ready. Writing it last ensures the address
fields are visible to hardware before the ownership transfer. On aarch64,
register writes through MMIO (Device-nGnRnE memory) are naturally ordered,
so no explicit memory barrier is needed between RegisterBank writes.

### O(N) pool address lookup is acceptable

`poll_rx` finds a buffer index by scanning the pool for a matching physical
address. For 256-descriptor rings this is ~256 comparisons per RX frame —
negligible on Cortex-A76. An index-per-descriptor table could optimize this
but adds complexity without measurable benefit.

## Architecture

### DmaPool

```rust
// crates/harmony-unikernel/src/drivers/dma_pool.rs

/// Metadata for a single DMA-accessible buffer.
#[derive(Clone, Copy)]
pub struct DmaBuffer {
    pub virt: *mut u8,      // CPU-accessible address
    pub phys: u64,          // Physical address for hardware descriptors
}

/// Fixed-size pool of pre-allocated DMA buffers.
pub struct DmaPool<const N: usize> {
    buffers: [DmaBuffer; N],
    free: [bool; N],       // true = available
    buf_size: usize,
}
```

Methods:
- `new(buffers: [DmaBuffer; N], buf_size: usize) -> Self`
- `alloc(&mut self) -> Option<usize>` — returns buffer index, marks in-use
- `free(&mut self, index: usize) -> Result<(), DmaPoolError>` — marks available, error on double-free
- `get(&self, index: usize) -> &DmaBuffer` — lookup by index
- `find_by_phys(&self, phys: u64) -> Option<usize>` — O(N) scan for physical address match
- `buf_size(&self) -> usize` — buffer size

`DmaPoolError`:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaPoolError {
    DoubleFree(usize),
}
```

### GenetError Extension

Add a new variant to the existing `GenetError` enum:
```rust
pub enum GenetError {
    // ... existing variants ...
    /// No DMA buffers available in the pool.
    NoBuffers,
}
```

### Driver Changes

`GenetDriver::send` signature becomes:
```rust
pub fn send<const N: usize>(
    &mut self,
    bank: &mut impl RegisterBank,
    frame: &[u8],
    tx_pool: &mut DmaPool<N>,
) -> Result<(), GenetError>
```

Steps (after existing length/ring checks):
1. `tx_pool.alloc()` → buffer index (or `GenetError::NoBuffers`)
2. Copy `frame` to `tx_pool.get(index).virt` (unsafe ptr copy)
3. Write `DMA_DESC_ADDRESS_LO` = `tx_pool.get(index).phys as u32`
4. Write `DMA_DESC_ADDRESS_HI` = `(tx_pool.get(index).phys >> 32) as u32`
5. Write `DMA_DESC_LENGTH_STATUS` **last** (existing logic — ownership transfer)
6. Advance ring (existing logic)

`GenetDriver::poll_rx` signature becomes:
```rust
pub fn poll_rx<const N: usize>(
    &mut self,
    bank: &mut impl RegisterBank,
    rx_pool: &mut DmaPool<N>,
) -> Option<RxFrame>
```

Returns `Option<RxFrame>` (preserving the existing return type with `data` and
`status` fields).

Steps (after existing descriptor read/validation):
1. Read `DMA_DESC_ADDRESS_LO/HI` → physical address
2. `rx_pool.find_by_phys(phys)` → buffer index
3. Copy `length` bytes from `rx_pool.get(index).virt` into `RxFrame.data`
4. `rx_pool.free(index)` — return consumed buffer
5. Re-arm: `rx_pool.alloc()` → new buffer, write its address to the descriptor

Add `GenetDriver::arm_rx_descriptors` for initial setup:
```rust
pub fn arm_rx_descriptors<const N: usize>(
    &mut self,
    bank: &mut impl RegisterBank,
    rx_pool: &mut DmaPool<N>,
) -> Result<(), GenetError>
```
Called once after `init()`. For each RX descriptor, allocates a buffer and
writes its address to `DMA_DESC_ADDRESS_LO/HI`. Returns `GenetError::NoBuffers`
if the pool is exhausted before all descriptors are armed.

### TX Completion

Add `GenetDriver::reclaim_tx` method to free completed TX buffers:
```rust
pub fn reclaim_tx<const N: usize>(
    &mut self,
    bank: &mut impl RegisterBank,
    tx_pool: &mut DmaPool<N>,
)
```
Reads TX `RING_CONS_INDEX`, frees buffers for all descriptors between the old
and new consumer index. Called before `send` or on timer tick. Must track
buffer-index-per-descriptor internally (add `tx_buf_indices: [Option<usize>; TX_RING]`
to `GenetDriver`).

### Cache Coherency

```rust
// crates/harmony-boot-aarch64/src/cache.rs

/// Clean data cache lines covering [start, start+len) — CPU writes visible to device.
/// Call before TX DMA: ensures frame data written by CPU is visible to the GENET engine.
pub unsafe fn clean_range(start: *const u8, len: usize)

/// Invalidate data cache lines covering [start, start+len) — device writes visible to CPU.
/// Call after RX DMA: ensures CPU reads fresh frame data written by the GENET engine.
pub unsafe fn invalidate_range(start: *const u8, len: usize)
```

Implementation: iterate by cache line (64 bytes on Cortex-A76), `dc cvau` for
clean, `dc civac` for invalidate. `dsb sy` after the loop.

The MMIO integration layer calls these at the appropriate points:
- TX: `clean_range(buffer.virt, frame_len)` **after** copying frame data, **before** writing the descriptor
- RX: `invalidate_range(buffer.virt, frame_len)` **before** copying frame data to caller

### Pool Construction (Boot Crate)

The MMIO integration layer allocates DMA buffers from the bump allocator:
```rust
// In harmony-boot-aarch64 initialization
for i in 0..RING_SIZE {
    let frame = bump_alloc.alloc_frame()?;  // 4096 bytes
    // Identity-mapped: phys == virt
    buffers[i] = DmaBuffer { virt: frame.as_u64() as *mut u8, phys: frame.as_u64() };
}
let rx_pool = DmaPool::new(buffers, 2048);
// Repeat for tx_pool
```

## File Changes

| File | Change |
|------|--------|
| `crates/harmony-unikernel/src/drivers/dma_pool.rs` | New: DmaPool, DmaBuffer, DmaPoolError |
| `crates/harmony-unikernel/src/drivers/genet.rs` | Add NoBuffers variant, send/poll_rx gain pool params, write ADDRESS_LO/HI, arm_rx_descriptors, reclaim_tx, tx_buf_indices field |
| `crates/harmony-unikernel/src/drivers/mod.rs` | Add `pub mod dma_pool;` |
| `crates/harmony-boot-aarch64/src/cache.rs` | New: clean_range, invalidate_range |
| `crates/harmony-boot-aarch64/src/main.rs` | Add `mod cache;` |
| `crates/harmony-microkernel/src/genet_server.rs` | Update send/poll_rx calls to pass pool |

## What is NOT in Scope

- No interrupt-driven RX (polling only for Ring 1 unikernel)
- No scatter-gather (single buffer per descriptor, SOP+EOP)
- No multi-ring support (default ring 16 only)
- No MMIO RegisterBank implementation (that's the boot loop integration bead)
- No event loop wiring (that's harmony-os-7af)

## Testing

DmaPool unit tests:
- `pool_alloc_and_free` — alloc all, verify exhaustion, free one, alloc again
- `pool_double_free_returns_error` — freeing already-free buffer returns DmaPoolError
- `pool_get_returns_correct_buffer` — index lookup returns expected addresses
- `pool_find_by_phys` — scan finds correct index, returns None for unknown address

GenetDriver tests (MockRegisterBank + mock DmaPool):
- `send_writes_descriptor_addresses` — verify ADDRESS_LO/HI written to correct offsets
- `poll_rx_reads_descriptor_addresses` — verify RxFrame.data copied from pool buffer
- `send_no_buffers_returns_error` — exhausted pool → GenetError::NoBuffers
- `arm_rx_descriptors_fills_ring` — all RX descriptors get buffer addresses
- `reclaim_tx_frees_completed_buffers` — TX completion frees pool buffers
- Existing tests updated for new pool parameter (pass mock pool)

Cache tests (aarch64 cfg-gated):
- `clean_range_compiles` — verifies assembly syntax on aarch64
- `invalidate_range_compiles` — verifies assembly syntax on aarch64
