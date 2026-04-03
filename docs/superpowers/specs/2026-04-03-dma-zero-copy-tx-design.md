# VirtIO-net DMA Zero-Copy TX

**Bead:** harmony-os-742 (P3, task)
**Date:** 2026-04-03
**Status:** Design approved

## Problem

The VirtIO network driver's TX methods (`send_to`, `send_raw`) build complete frames in a 2KB stack buffer (`[0u8; BUF_SIZE]`), then `Virtqueue::submit_send()` copies the frame into a pre-allocated DMA buffer via `ptr::copy_nonoverlapping`. The DMA buffers already exist (32 x 2KB, page-aligned at `Virtqueue.buffers`) — the intermediate stack buffer and full-frame memcpy are unnecessary overhead.

This affects both Harmony raw frame sends (`send_to`) and smoltcp IP frame sends (`send_raw`). The `send()` trait method delegates to `send_to`, so it benefits automatically.

## Design

### Prepare/Commit API on Virtqueue

Two new methods on `Virtqueue` in `virtqueue.rs`:

**`prepare_send(&mut self) -> Option<(u16, *mut u8)>`**
- Calls `alloc_desc()` to allocate a free descriptor
- Returns `(desc_idx, buffer_ptr)` where `buffer_ptr` is `self.buffer_ptr(idx)` — a raw pointer to the descriptor's 2KB DMA buffer
- Returns `None` if no free descriptors
- Does NOT write the descriptor table entry or touch the available ring

**`commit_send(&mut self, idx: u16, len: usize)`**
- Writes the descriptor entry with volatile writes: `addr = buffer_phys(idx)`, `len`, `flags = 0`, `next = 0`
- Adds `idx` to the available ring at `avail.idx % queue_size`
- Memory fence (`Ordering::Release`)
- Increments `avail.idx` with volatile write

Design choices:
- Returns `*mut u8` instead of `&mut [u8]` to avoid a mutable borrow conflict — `commit_send` needs `&mut self` but a slice borrow from `prepare_send` would hold `&mut self`. The raw pointer is safe in practice because callers are already in unsafe context (MMIO writes).
- `submit_send` stays unchanged. It's a self-contained allocate-copy-commit path that still works for any caller that already has a complete buffer. The two paths share the descriptor pool and available ring with no conflict (single-threaded unikernel).

### VirtioNet TX Method Changes

**`send_to(&mut self, data: &[u8], dst_mac: Option<&[u8; 6]>) -> Result<(), PlatformError>`:**

1. `reclaim_tx()` (unchanged)
2. Compute `frame_len = VIRTIO_NET_HDR_LEN + ETH_HEADER_LEN + data.len()`
3. Check `frame_len <= BUF_SIZE`, return `SendFailed` if not
4. `tx_queue.prepare_send()` → `(idx, buf_ptr)`, return `SendFailed` if `None`
5. Write directly into `buf_ptr`:
   - Zero bytes `[0..VIRTIO_NET_HDR_LEN]` (VirtIO net header)
   - Copy dst MAC (or `BROADCAST_MAC`) to `[h..h+6]`
   - Copy src MAC (`self.mac`) to `[h+6..h+12]`
   - Copy `ETHERTYPE_HARMONY` to `[h+12..h+14]`
   - Copy payload to `[h+ETH_HEADER_LEN..h+ETH_HEADER_LEN+data.len()]`
6. `tx_queue.commit_send(idx, frame_len)`
7. Notify device via `mmio_write16(tx_notify_addr, 1)`

Where `h = VIRTIO_NET_HDR_LEN` (12).

**`send_raw(&mut self, frame: &[u8]) -> Result<(), PlatformError>`:**

Same prepare/commit pattern:
1. `reclaim_tx()`
2. Compute `total_len = VIRTIO_NET_HDR_LEN + frame.len()`
3. Check `total_len <= BUF_SIZE`
4. `tx_queue.prepare_send()` → `(idx, buf_ptr)`
5. Write directly into `buf_ptr`:
   - Zero bytes `[0..VIRTIO_NET_HDR_LEN]`
   - Copy `frame` to `[VIRTIO_NET_HDR_LEN..total_len]`
6. `tx_queue.commit_send(idx, total_len)`
7. Notify device

This eliminates the stack buffer for both paths. `send_raw` still does one memcpy (frame → DMA buffer) but skips the intermediate 2KB stack allocation.

**`send()` via NetworkInterface trait:** Still delegates to `send_to(data, None)`. No change.

### VirtIO Header Zeroing

The DMA buffers are zero-initialized at allocation (`alloc_zeroed`), but after a buffer is reused from a previous send, old data remains. The VirtIO net header (first 12 bytes) must be explicitly zeroed on every send. The payload region is overwritten by frame data, so no zeroing needed there.

Both `send_to` and `send_raw` write `ptr::write_bytes(buf_ptr, 0, VIRTIO_NET_HDR_LEN)` before filling in the frame.

### Edge Cases

- **Descriptor exhaustion:** `prepare_send()` returns `None` → `SendFailed`. Same behavior as today. No descriptor leak because the length check happens before `prepare_send`.
- **Oversized frames:** Checked before `prepare_send()` to avoid leaking a descriptor on rejection.
- **Reused DMA buffers:** VirtIO header zeroed explicitly. Payload region fully overwritten.
- **`submit_send` coexistence:** Both paths (`submit_send` and `prepare_send`/`commit_send`) share the descriptor pool. No conflict — single-threaded unikernel, never called concurrently.

## Files Changed

| File | Changes |
|------|---------|
| `crates/harmony-boot/src/virtio/virtqueue.rs` | `prepare_send()` and `commit_send()` methods |
| `crates/harmony-boot/src/virtio/net.rs` | Rewrite `send_to()` and `send_raw()` to use prepare/commit instead of stack buffer + `submit_send()` |

## Testing

**Unit tests (virtqueue.rs):**
- `prepare_send` returns valid index and non-null pointer
- `prepare_send` when all descriptors allocated returns `None`
- `prepare_send` + `commit_send` round-trip: write bytes via raw pointer, commit, verify descriptor table entry has correct physical address and length

**Unit tests (net.rs):**
- Existing `frame_header_unicast_mac` and `frame_header_broadcast_fallback` tests verify frame layout is correct — no changes needed, confirms no regression

**No new integration tests:** Frame layout on the wire is byte-identical. Existing QEMU boot test covers the full TX path end-to-end.

## Out of Scope

- RX zero-copy (avoiding Vec allocation in receive path) — tracked as harmony-os-drn (P4)
- Scatter-gather descriptors (chaining multiple buffers per frame) — not needed at current MTU
- `VIRTIO_F_INDIRECT_DESC` support — unnecessary complexity for 32-entry queue
- Benchmarking — tracked as harmony-os-87o (blocked by this bead)
