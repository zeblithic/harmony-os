# VirtIO-net RX Zero-Copy Investigation

**Bead:** harmony-os-drn (P4, task)
**Date:** 2026-04-03
**Status:** Investigated — no action needed

## Question

Can we eliminate the per-frame `Vec<u8>` heap allocation in the VirtIO-net RX path, the way we eliminated the TX stack buffer copy in PR #107?

## Current RX Data Flow

`receive_raw()` and `receive()` in `virtio/net.rs` both call `Virtqueue::read_buffer(desc_idx, len)`, which:

1. Allocates a `Vec<u8>` of `len` bytes (alloc 1)
2. Copies from the DMA buffer via `ptr::copy_nonoverlapping` (copy 1)
3. Returns the Vec

The caller then frees the descriptor and reposts a receive buffer. However, the full-frame Vec is **not** passed directly to consumers. Both methods strip headers via `.to_vec()` on a slice before returning:

- **`receive_raw()`** returns `buf[VIRTIO_NET_HDR_LEN..].to_vec()` — strips VirtIO header (alloc 2 + copy 2), drops the original Vec.
- **`receive()`** returns `eth[ETH_HEADER_LEN..].to_vec()` — strips VirtIO + Ethernet headers (alloc 2 + copy 2), drops the original Vec.

So the actual per-frame cost at the driver level is **2 allocs + 2 copies**. Downstream consumers add more:

- **smoltcp IP/ARP:** `netstack.ingest(frame: Vec<u8>)` — takes ownership of the header-stripped Vec, pushes into `VecDeque<Vec<u8>>` for smoltcp to read during `poll()`. Total: 2 allocs + 2 copies.
- **Harmony raw frames (Ring 1):** Receives the header-stripped frame, then `payload.to_vec()` into `harmony_packets` Vec for dispatch. Total: **3 allocs + 3 copies**.
- **Ring 3 `poll_network`:** Same `ingest(frame)` pattern as smoltcp. Total: 2 allocs + 2 copies.

## Why Zero-Copy RX Isn't Viable

The TX optimization (PR #107) worked because the intermediate stack buffer was *pure waste* — an extra 2KB allocation and memcpy with no purpose. The DMA buffer was the correct final destination, so we wrote directly into it.

The RX case is fundamentally different: **the DMA descriptor must be freed and reposted immediately** after reading. If we don't repost, the RX queue starves and the device drops frames. This means the data must be copied out of the DMA buffer before we release it. A heap Vec is the destination for that copy.

## Alternatives Considered

### Caller-provided buffer (`receive_raw_into(&mut self, buf: &mut [u8]) -> Option<usize>`)

Copy from DMA into a caller-provided slice instead of a new Vec, writing only the post-header payload (skipping the VirtIO header during the DMA read).

**Analysis:** This could eliminate one of the two current allocations — `read_buffer`'s full-frame Vec is currently allocated and immediately discarded after the header-stripped `.to_vec()`. A well-implemented `receive_raw_into` that writes directly to offset 0 of a caller buffer (skipping VirtIO headers during copy) would match the current 1 alloc + 1 copy for the smoltcp path.

**Problem:** The gain is modest (saving one transient ~1.5KB alloc per frame) and all consumers still need owned Vecs:
- `netstack.ingest()` takes `Vec<u8>` by value — caller would still need a Vec allocation
- Harmony path does `payload.to_vec()` — would still need a Vec allocation
- The intermediate full-frame Vec is short-lived and the allocator handles it efficiently
- Adds API complexity (caller must size the buffer correctly, handle partial reads) for marginal benefit.

### Pre-allocated buffer pool

Maintain a pool of reusable `[u8; 2048]` buffers. `receive_raw` borrows from the pool, copies from DMA, consumer returns the buffer when done.

**Problem:** Adds pool management complexity (lifecycle, sizing, exhaustion handling). The current heap allocator (`linked_list_allocator`) handles ~1.5KB allocs efficiently. This solves a problem we don't have evidence of.

### Borrow into DMA buffer (`receive_raw_ref() -> Option<BorrowedFrame<'_>>`)

Return a reference into the DMA buffer with a guard that frees/reposts on drop.

**Problem:** The descriptor is held until the consumer drops the guard. With 32 descriptors and a busy network, holding even a few frames while smoltcp processes them risks RX queue starvation. The borrow also prevents any other `&mut self` calls on the Virtqueue while held, blocking TX operations in the single-threaded event loop.

## Conclusion

The current approach is correct but not allocation-minimal. The actual per-frame cost is **2 allocs + 2 copies** at the driver level (one full-frame Vec from `read_buffer`, one header-stripped Vec from `.to_vec()`), with the Harmony raw path adding a third alloc+copy for `payload.to_vec()`.

A `receive_raw_into` API could eliminate the transient full-frame Vec, but the saving is modest (one short-lived ~1.5KB alloc per frame) and adds API complexity. The current approach is the simplest correct implementation.

**Revisit when:** Profiling (harmony-os-87o benchmarks) shows allocator pressure or RX processing latency as a bottleneck. If allocation pressure is confirmed, the first optimization target should be eliminating the intermediate `read_buffer` Vec by writing header-stripped data directly into the consumer's buffer.
