# VirtIO-net DMA Zero-Copy TX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the intermediate 2KB stack buffer copy in VirtIO-net TX by writing frames directly into DMA buffers via a prepare/commit API.

**Architecture:** Add `prepare_send()`/`commit_send()` to `Virtqueue` that split descriptor allocation from ring submission. Rewrite `VirtioNet::send_to()` and `send_raw()` to build frames directly in the DMA buffer returned by `prepare_send()`, then finalize with `commit_send()`.

**Tech Stack:** Rust (no_std), VirtIO 1.0 split virtqueues, raw pointers for DMA buffer access.

**Spec:** `docs/superpowers/specs/2026-04-03-dma-zero-copy-tx-design.md`

---

## File Structure

| File | Responsibility | Changes |
|------|---------------|---------|
| `crates/harmony-boot/src/virtio/virtqueue.rs` | Split virtqueue with static buffer pool | Add `prepare_send()` and `commit_send()` methods |
| `crates/harmony-boot/src/virtio/net.rs` | VirtIO network driver | Rewrite `send_to()` and `send_raw()` to use prepare/commit |

---

### Task 1: Add `prepare_send` and `commit_send` to Virtqueue

**Files:**
- Modify: `crates/harmony-boot/src/virtio/virtqueue.rs:230-266`

**Context:** `Virtqueue` currently has `submit_send(&mut self, data: &[u8]) -> Option<u16>` which allocates a descriptor, copies data into the DMA buffer, writes the descriptor table entry, and adds to the available ring — all in one call. We're splitting this into two phases so callers can write directly into the DMA buffer between the phases.

Key existing methods the new code uses:
- `alloc_desc(&mut self) -> Option<u16>` (line 174) — finds first free descriptor
- `buffer_ptr(&self, idx: u16) -> *mut u8` (line 192) — virtual pointer to descriptor's 2KB DMA buffer
- `buffer_phys(&self, idx: u16) -> u64` (line 197) — physical address for descriptor table entry

The available ring submission pattern (volatile writes + fence) is identical to the second half of `submit_send` (lines 247-262).

- [ ] **Step 1: Write failing tests for `prepare_send` and `commit_send`**

Add a test module at the bottom of `crates/harmony-boot/src/virtio/virtqueue.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a Virtqueue for testing.
    /// Uses phys_offset=0 so virtual == physical addresses.
    fn test_queue() -> Virtqueue {
        Virtqueue::new(0)
    }

    #[test]
    fn prepare_send_returns_valid_index_and_pointer() {
        let mut vq = test_queue();
        let (idx, ptr) = vq.prepare_send().expect("should allocate");
        assert!(idx < QUEUE_SIZE);
        assert!(!ptr.is_null());
    }

    #[test]
    fn prepare_send_exhaustion_returns_none() {
        let mut vq = test_queue();
        // Allocate all descriptors.
        for _ in 0..QUEUE_SIZE {
            assert!(vq.prepare_send().is_some());
        }
        // Next one should fail.
        assert!(vq.prepare_send().is_none());
    }

    #[test]
    fn prepare_commit_sets_descriptor_metadata() {
        let mut vq = test_queue();
        let (idx, buf_ptr) = vq.prepare_send().expect("should allocate");

        // Write known bytes into the DMA buffer via the raw pointer.
        let test_data = b"hello DMA";
        unsafe {
            core::ptr::copy_nonoverlapping(
                test_data.as_ptr(),
                buf_ptr,
                test_data.len(),
            );
        }

        vq.commit_send(idx, test_data.len());

        // Verify the descriptor table entry.
        unsafe {
            let desc = vq.desc.add(idx as usize);
            let addr = core::ptr::read_volatile(&(*desc).addr);
            let len = core::ptr::read_volatile(&(*desc).len);
            let flags = core::ptr::read_volatile(&(*desc).flags);

            // With phys_offset=0, buffer_phys == buffer_ptr as u64.
            assert_eq!(addr, vq.buffer_phys(idx));
            assert_eq!(len, test_data.len() as u32);
            assert_eq!(flags, 0); // device-readable (TX)
        }

        // Verify the available ring was advanced.
        unsafe {
            let avail_idx = core::ptr::read_volatile(&(*vq.avail).idx);
            assert_eq!(avail_idx, 1);
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-boot -- virtqueue::tests --nocapture 2>&1 | head -30`
Expected: compilation error — `prepare_send` and `commit_send` do not exist yet.

- [ ] **Step 3: Implement `prepare_send` and `commit_send`**

Add these two methods to the `impl Virtqueue` block, after `submit_send` (after line 266 in `virtqueue.rs`):

```rust
    /// Allocate a TX descriptor and return a raw pointer to its DMA buffer.
    ///
    /// The caller writes frame data directly into the returned buffer, then
    /// calls [`commit_send`] to finalize. This avoids the intermediate copy
    /// that [`submit_send`] performs.
    ///
    /// Returns `(desc_idx, buffer_ptr)` or `None` if no descriptors are free.
    ///
    /// # Safety contract
    ///
    /// The caller must:
    /// - Write at most `BUF_SIZE` bytes through the returned pointer
    /// - Call `commit_send(idx, len)` exactly once after writing
    pub fn prepare_send(&mut self) -> Option<(u16, *mut u8)> {
        let idx = self.alloc_desc()?;
        Some((idx, self.buffer_ptr(idx)))
    }

    /// Finalize a TX send started by [`prepare_send`].
    ///
    /// Writes the descriptor table entry and adds the descriptor to the
    /// available ring so the device can consume it.
    ///
    /// # Arguments
    ///
    /// * `idx` — Descriptor index returned by `prepare_send`.
    /// * `len` — Number of bytes written into the buffer.
    pub fn commit_send(&mut self, idx: u16, len: usize) {
        unsafe {
            // Volatile writes for descriptor table — device reads via DMA.
            let desc = self.desc.add(idx as usize);
            ptr::write_volatile(&raw mut (*desc).addr, self.buffer_phys(idx));
            ptr::write_volatile(&raw mut (*desc).len, len as u32);
            ptr::write_volatile(&raw mut (*desc).flags, 0u16);
            ptr::write_volatile(&raw mut (*desc).next, 0u16);

            // Volatile writes for avail ring — device reads via DMA.
            let avail_idx = ptr::read_volatile(&(*self.avail).idx);
            let ring_slot = &mut (*self.avail).ring[(avail_idx % self.queue_size) as usize];
            ptr::write_volatile(ring_slot, idx);

            // Ensure descriptor + data writes are visible before the device
            // sees the updated available index.
            fence(Ordering::Release);
            ptr::write_volatile(&mut (*self.avail).idx, avail_idx.wrapping_add(1));
        }
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-boot -- virtqueue::tests --nocapture`
Expected: all 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-boot/src/virtio/virtqueue.rs
git commit -m "feat(virtqueue): add prepare_send/commit_send for zero-copy TX"
```

---

### Task 2: Rewrite `send_to` to use prepare/commit

**Files:**
- Modify: `crates/harmony-boot/src/virtio/net.rs:406-435`

**Context:** `send_to` currently builds the complete frame (VirtIO header + Ethernet header + payload) in a `[0u8; BUF_SIZE]` stack buffer, then calls `submit_send` which copies the entire frame into the DMA buffer. After this task, `send_to` writes directly into the DMA buffer via `prepare_send`/`commit_send`.

The frame layout is:
- Bytes `[0..12]`: VirtIO net header (all zeros — no GSO, no checksum offload)
- Bytes `[12..18]`: Destination MAC (unicast or broadcast)
- Bytes `[18..24]`: Source MAC (`self.mac`)
- Bytes `[24..26]`: EtherType (`ETHERTYPE_HARMONY` = `[0x88, 0xB5]`)
- Bytes `[26..26+data.len()]`: Payload

Constants: `VIRTIO_NET_HDR_LEN = 12`, `ETH_HEADER_LEN = 14`.

- [ ] **Step 1: Run existing tests to confirm they pass before changes**

Run: `cargo test -p harmony-boot -- net::tests --nocapture`
Expected: all existing net tests pass (baseline).

- [ ] **Step 2: Rewrite `send_to` to use prepare/commit**

Replace the `send_to` method body at `crates/harmony-boot/src/virtio/net.rs:406-435` with:

```rust
    /// Send a Harmony raw payload with an explicit destination MAC.
    /// If `dst_mac` is `None`, falls back to broadcast.
    pub fn send_to(&mut self, data: &[u8], dst_mac: Option<&[u8; 6]>) -> Result<(), PlatformError> {
        self.reclaim_tx();

        let frame_len = VIRTIO_NET_HDR_LEN + ETH_HEADER_LEN + data.len();
        if frame_len > BUF_SIZE {
            return Err(PlatformError::SendFailed);
        }

        let (idx, buf) = self.tx_queue.prepare_send().ok_or(PlatformError::SendFailed)?;

        unsafe {
            let h = VIRTIO_NET_HDR_LEN;
            // Zero VirtIO net header (no GSO, no checksum offload).
            // Payload region is fully overwritten, so only the header needs zeroing.
            ptr::write_bytes(buf, 0, VIRTIO_NET_HDR_LEN);
            // Destination: unicast if known, broadcast otherwise.
            ptr::copy_nonoverlapping(
                dst_mac.unwrap_or(&BROADCAST_MAC).as_ptr(),
                buf.add(h),
                6,
            );
            // Source: our MAC.
            ptr::copy_nonoverlapping(self.mac.as_ptr(), buf.add(h + 6), 6);
            // EtherType: Harmony (0x88B5).
            ptr::copy_nonoverlapping(ETHERTYPE_HARMONY.as_ptr(), buf.add(h + 12), 2);
            // Payload.
            ptr::copy_nonoverlapping(data.as_ptr(), buf.add(h + ETH_HEADER_LEN), data.len());
        }

        self.tx_queue.commit_send(idx, frame_len);

        // Notify the device that a TX buffer is available.
        unsafe { mmio_write16(self.tx_notify_addr, 1) };
        Ok(())
    }
```

Note: add `use core::ptr;` to the imports at `net.rs:10` if not already present.

- [ ] **Step 3: Run tests to verify no regression**

Run: `cargo test -p harmony-boot -- net::tests --nocapture`
Expected: all existing net tests still pass. The frame layout is identical — only the buffer location changed.

- [ ] **Step 4: Run full workspace tests**

Run: `cargo test -p harmony-boot --nocapture`
Expected: all tests pass (virtqueue + net + neighbor tests).

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-boot/src/virtio/net.rs
git commit -m "perf(net): rewrite send_to to write directly into DMA buffer"
```

---

### Task 3: Rewrite `send_raw` to use prepare/commit

**Files:**
- Modify: `crates/harmony-boot/src/virtio/net.rs:380-404`

**Context:** `send_raw` sends a pre-built Ethernet frame (from smoltcp's `drain_tx` path). It only needs to prepend the 12-byte VirtIO net header. Currently allocates a `[0u8; BUF_SIZE]` stack buffer, copies the frame in, then `submit_send` copies again into DMA. After this task, it writes the VirtIO header and frame directly into the DMA buffer.

- [ ] **Step 1: Rewrite `send_raw` to use prepare/commit**

Replace the `send_raw` method body at `crates/harmony-boot/src/virtio/net.rs:380-404` with:

```rust
    /// Send a pre-built raw Ethernet frame (caller provides the full frame
    /// including Ethernet header). The VirtIO net header is prepended
    /// automatically.
    pub fn send_raw(&mut self, frame: &[u8]) -> Result<(), PlatformError> {
        self.reclaim_tx();

        let total_len = VIRTIO_NET_HDR_LEN + frame.len();
        if total_len > BUF_SIZE {
            return Err(PlatformError::SendFailed);
        }

        let (idx, buf) = self.tx_queue.prepare_send().ok_or(PlatformError::SendFailed)?;

        unsafe {
            // Zero VirtIO net header (no GSO, no checksum offload).
            ptr::write_bytes(buf, 0, VIRTIO_NET_HDR_LEN);
            // Copy pre-built Ethernet frame after the VirtIO header.
            ptr::copy_nonoverlapping(frame.as_ptr(), buf.add(VIRTIO_NET_HDR_LEN), frame.len());
        }

        self.tx_queue.commit_send(idx, total_len);

        // Notify the device that a TX buffer is available.
        unsafe { mmio_write16(self.tx_notify_addr, 1) };
        Ok(())
    }
```

- [ ] **Step 2: Run full test suite**

Run: `cargo test -p harmony-boot --nocapture`
Expected: all tests pass.

- [ ] **Step 3: Run clippy**

Run: `cargo clippy -p harmony-boot -- -D warnings`
Expected: no warnings.

- [ ] **Step 4: Run nightly rustfmt**

Run: `cargo +nightly fmt --all -- --check`
Expected: no formatting issues. If there are, run `cargo +nightly fmt --all` to fix.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-boot/src/virtio/net.rs
git commit -m "perf(net): rewrite send_raw to write directly into DMA buffer"
```
