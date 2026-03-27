# VirtIO-Net Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bridge the VirtIO-net device to the 9P namespace, enabling the kernel to read/write guest WiFi packets through standard `FileServer` operations.

**Architecture:** `NetworkDevice` trait in `harmony-microkernel`, `VirtioNetBridge` adapter in `harmony-hypervisor`, `VirtioNetServer<N: NetworkDevice>` 9P FileServer in `harmony-microkernel` following the `GenetServer` pattern exactly.

**Tech Stack:** Rust (no_std + alloc), existing `FileServer`/`FidTracker` from `harmony-microkernel`, existing `VirtioNetDevice` from `harmony-hypervisor`

**Spec:** `docs/superpowers/specs/2026-03-27-virtio-net-bridge-design.md`

---

## File Structure

### New files

| File | Crate | Responsibility |
|------|-------|---------------|
| `crates/harmony-microkernel/src/net_device.rs` | harmony-microkernel | `NetworkDevice` trait (4 methods) |
| `crates/harmony-microkernel/src/virtio_net_server.rs` | harmony-microkernel | 9P FileServer over `NetworkDevice` |
| `crates/harmony-hypervisor/src/virtio_net_bridge.rs` | harmony-hypervisor | `VirtioNetBridge` adapter |

### Modified files

| File | Change |
|------|--------|
| `crates/harmony-microkernel/src/lib.rs` | Add `pub mod net_device; pub mod virtio_net_server;` |
| `crates/harmony-hypervisor/src/lib.rs` | Add `pub mod virtio_net_bridge;` |

---

## Task 1: NetworkDevice trait

**Files:**
- Create: `crates/harmony-microkernel/src/net_device.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs`

**Context:**
- Simple trait with 4 methods: `poll_tx`, `push_rx`, `mac`, `link_up`
- Object-safe (no generics, no Self-returning methods)
- Lives in harmony-microkernel alongside FileServer

- [ ] **Step 1: Write the trait + a compile-time test**

```rust
// crates/harmony-microkernel/src/net_device.rs
// SPDX-License-Identifier: GPL-2.0-or-later
//! Network device abstraction for 9P network servers.

/// A network device that produces and consumes raw Ethernet frames.
pub trait NetworkDevice {
    /// Extract the next transmitted frame from the device.
    /// Writes the frame into `out` and returns the byte count,
    /// or None if no packet is pending.
    fn poll_tx(&mut self, out: &mut [u8]) -> Option<usize>;

    /// Inject a received frame into the device.
    /// Returns true if accepted, false if the device's RX buffer is full.
    fn push_rx(&mut self, frame: &[u8]) -> bool;

    /// The device's MAC address.
    fn mac(&self) -> [u8; 6];

    /// Whether the link is currently up.
    fn link_up(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify trait is object-safe.
    #[test]
    fn trait_is_object_safe() {
        fn _accepts_dyn(_dev: &dyn NetworkDevice) {}
    }
}
```

- [ ] **Step 2: Add `pub mod net_device;` to lib.rs**

The module should be unconditional (not behind a feature gate) since it's just a trait with no dependencies.

- [ ] **Step 3: Run tests**

Run: `cargo test -p harmony-microkernel`
Expected: All tests pass

- [ ] **Step 4: Run workspace checks**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: Clean

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/net_device.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(microkernel): add NetworkDevice trait for 9P network servers"
```

---

## Task 2: VirtioNetServer — 9P FileServer over NetworkDevice

**Files:**
- Create: `crates/harmony-microkernel/src/virtio_net_server.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs`

**Context:**
- Follow `GenetServer` pattern exactly — reference `crates/harmony-microkernel/src/genet_server.rs` lines 108-278
- Generic over `N: NetworkDevice` instead of hardcoded to GenetDriver
- QPaths: ROOT(0), DIR(1), DATA(2), MAC(3), MTU(4), STATS(5), LINK(6)
- Device name is dynamic (`self.name: &'static str`) — root-to-dir walk uses string comparison, not const pattern
- `data` read: streaming (offset ignored), zero-count guard, oversized-frame error
- Control file reads use `slice_at_offset` for proper offset/count handling
- Stats format: `"rx_packets: N\ntx_packets: N\nrx_bytes: N\ntx_bytes: N\n"` (rx first)
- Implements `clone_fid` delegating to `FidTracker`

**Tests (using a MockNetDevice):**

```rust
struct MockNetDevice {
    mac: [u8; 6],
    link: bool,
    tx_queue: VecDeque<Vec<u8>>,
    rx_log: Vec<Vec<u8>>,
}
```

Tests:
1. `walk_to_all_files` — walk root → dir → each of data/mac/mtu/stats/link, verify QPaths
2. `walk_wrong_name_fails` — walk root → "wrong" → NotFound
3. `open_data_readwrite` — open data R/W succeeds
4. `open_mac_write_fails` — open mac for Write → ReadOnly
5. `read_data_returns_frame` — mock has queued frame, read data → frame bytes
6. `read_data_empty_returns_eof` — mock empty, read data → empty vec
7. `read_data_zero_count` — read with count=0 returns empty without consuming frame
8. `read_data_oversized_frame` — frame larger than count → InvalidArgument
9. `write_data_injects_frame` — write to data, verify mock received frame
10. `write_data_full_returns_error` — mock returns false → ResourceExhausted
11. `read_mac_format` — read mac → "02:00:00:00:00:01\n"
12. `read_mac_with_offset` — read mac at offset 3 → partial string
13. `read_mtu` — "1500\n"
14. `read_stats_with_counters` — send/receive some packets, read stats, verify counts
15. `read_link_up` — "up\n"
16. `read_link_down` — mock link=false → "down\n"
17. `stat_returns_metadata` — stat on each file, verify FileType and name
18. `clone_fid_works` — clone_fid succeeds
19. `clunk_releases_fid` — clunk, then walk same fid → InvalidFid

- [ ] **Step 1: Create MockNetDevice and VirtioNetServer with all tests**

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-microkernel`
Expected: Compilation error — `virtio_net_server` module doesn't exist

- [ ] **Step 3: Implement VirtioNetServer**

Key implementation: mirror `GenetServer` lines 108-278 with these substitutions:
- `GenetDriver` → `N: NetworkDevice` (generic)
- `self.driver.poll_rx(...)` → `self.device.poll_tx(&mut buf)`
- `self.driver.send(...)` → `self.device.push_rx(data)`
- `self.driver.mac()` → `self.device.mac()`
- `self.driver.link_status(...)` → `self.device.link_up()`
- `self.driver.stats()` → format from `self.tx_packets/rx_packets/tx_bytes/rx_bytes`
- `(QPATH_ROOT, "genet0")` → `(QPATH_ROOT, n) if n == self.name`

Include the `slice_at_offset` helper (same implementation as GenetServer).

- [ ] **Step 4: Add `pub mod virtio_net_server;` to lib.rs**

This should be **unconditional** (no feature gate) — same as `genet_server`, which has the same dependency profile (`alloc`, `FidTracker`, `FileServer`). The `kernel` feature is for servers that depend on Ring 0 crates.

- [ ] **Step 5: Run tests**

Run: `cargo test -p harmony-microkernel`
Expected: All tests pass (existing + 19 new)

- [ ] **Step 6: Run workspace checks**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: Clean

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-microkernel/src/virtio_net_server.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(microkernel): add VirtioNetServer 9P FileServer over NetworkDevice"
```

---

## Task 3: VirtioNetBridge — adapter in harmony-hypervisor

**Files:**
- Create: `crates/harmony-hypervisor/src/virtio_net_bridge.rs`
- Modify: `crates/harmony-hypervisor/src/lib.rs`

**Context:**
- Borrowing adapter: holds `&mut VirtioNetDevice` + `&mut [u8]` + IPA params
- Implements `NetworkDevice` by delegating to `VirtioNetDevice` methods
- `harmony-hypervisor` already depends on `harmony-microkernel` (for PhysAddr, VmError), so it can import `NetworkDevice`
- Two `ipa_to_ptr` function pointers: `fn(u64) -> *const u8` for reads, `fn(u64) -> *mut u8` for writes

**Tests:**
1. `bridge_poll_tx_delegates` — set up a `VirtioNetDevice` with configured TX queue + shared memory containing a packet, wrap in `VirtioNetBridge`, call `poll_tx` through `NetworkDevice` trait, verify frame extracted
2. `bridge_push_rx_delegates` — set up RX queue with available buffer, call `push_rx` through trait, verify used ring updated
3. `bridge_mac_returns_device_mac` — verify `mac()` returns the device's MAC
4. `bridge_link_up_returns_true` — Phase 1: always true

For tests that need a fully configured VirtioNetDevice with queues: reuse the shared memory + MMIO init pattern from the existing `virtio_net.rs` tests (set up queue configs, call ensure_queues).

- [ ] **Step 1: Write tests**

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-hypervisor`
Expected: Compilation error — `virtio_net_bridge` module doesn't exist

- [ ] **Step 3: Implement VirtioNetBridge**

```rust
// crates/harmony-hypervisor/src/virtio_net_bridge.rs
// SPDX-License-Identifier: GPL-2.0-or-later
//! Borrowing adapter connecting VirtioNetDevice to the NetworkDevice trait.

use harmony_microkernel::net_device::NetworkDevice;
use crate::virtio_net::VirtioNetDevice;

pub struct VirtioNetBridge<'a> {
    device: &'a mut VirtioNetDevice,
    mem: &'a mut [u8],
    region_base_ipa: u64,
    ipa_to_ptr_read: fn(u64) -> *const u8,
    ipa_to_ptr_write: fn(u64) -> *mut u8,
}

impl<'a> VirtioNetBridge<'a> {
    pub fn new(
        device: &'a mut VirtioNetDevice,
        mem: &'a mut [u8],
        region_base_ipa: u64,
        ipa_to_ptr_read: fn(u64) -> *const u8,
        ipa_to_ptr_write: fn(u64) -> *mut u8,
    ) -> Self {
        Self { device, mem, region_base_ipa, ipa_to_ptr_read, ipa_to_ptr_write }
    }
}

impl NetworkDevice for VirtioNetBridge<'_> {
    fn poll_tx(&mut self, out: &mut [u8]) -> Option<usize> {
        self.device.poll_tx(self.mem, self.region_base_ipa, self.ipa_to_ptr_read, out)
    }
    fn push_rx(&mut self, frame: &[u8]) -> bool {
        self.device.push_rx(frame, self.mem, self.region_base_ipa, self.ipa_to_ptr_write)
    }
    fn mac(&self) -> [u8; 6] { self.device.mac }
    fn link_up(&self) -> bool { true }
}
```

- [ ] **Step 4: Add `pub mod virtio_net_bridge;` to lib.rs**

- [ ] **Step 5: Run tests**

Run: `cargo test -p harmony-hypervisor`
Expected: All tests pass (existing 85 + 4 new)

- [ ] **Step 6: Run workspace checks**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: Clean

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-hypervisor/src/virtio_net_bridge.rs crates/harmony-hypervisor/src/lib.rs
git commit -m "feat(hypervisor): add VirtioNetBridge adapter implementing NetworkDevice"
```

---

## Task 4: Integration test — VirtioNetServer<VirtioNetBridge> end-to-end

**Files:**
- Modify: `crates/harmony-hypervisor/src/virtio_net_bridge.rs` (add integration test)

**Context:**
- This test lives in `harmony-hypervisor` because it needs both `VirtioNetServer` (from microkernel) and `VirtioNetBridge` (from hypervisor)
- Full path: set up VirtioNetDevice with configured queues + shared memory TX packet → wrap in VirtioNetBridge → wrap in VirtioNetServer → walk/open/read `data` file → verify extracted Ethernet frame
- Also tests write path: walk/open/write `data` → verify frame injected into RX queue

- [ ] **Step 1: Write integration test**

```rust
#[test]
fn server_bridge_end_to_end_tx() {
    // 1. Set up VirtioNetDevice with configured TX queue + shared memory
    //    (reuse pattern from virtio_net.rs::poll_tx_extracts_frame)
    // 2. Write a TX packet into shared memory (12-byte hdr + 60-byte frame)
    // 3. Wrap device in VirtioNetBridge
    // 4. Wrap bridge in VirtioNetServer
    // 5. Walk to "virtio0" → "data", open for Read
    // 6. Read from data fid
    // 7. Verify: 60-byte Ethernet frame returned (virtio_net_hdr stripped)
    // 8. Verify: server.tx_packets == 1
}

#[test]
fn server_bridge_end_to_end_rx() {
    // 1. Set up VirtioNetDevice with configured RX queue + available buffer
    // 2. Wrap in VirtioNetBridge → VirtioNetServer
    // 3. Walk to "virtio0" → "data", open for Write
    // 4. Write 60-byte frame to data fid
    // 5. Verify: push_rx returned true (frame accepted)
    // 6. Verify: server.rx_packets == 1
}
```

- [ ] **Step 2: Run test**

Run: `cargo test -p harmony-hypervisor server_bridge_end_to_end`
Expected: PASS

- [ ] **Step 3: Run workspace checks**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: Clean

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-hypervisor/src/virtio_net_bridge.rs
git commit -m "test(hypervisor): add end-to-end VirtioNetServer<VirtioNetBridge> integration test"
```

---

## Dependencies

```
Task 1 (NetworkDevice trait)
  ↓
Task 2 (VirtioNetServer) ← depends on Task 1
  ↓
Task 3 (VirtioNetBridge) ← depends on Task 1 (implements trait)
  ↓
Task 4 (Integration test) ← depends on Tasks 2 + 3
```

Tasks 2 and 3 could be done in parallel (independent modules in different crates, both depend only on Task 1's trait).
