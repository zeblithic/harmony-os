# Neighbor Table Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace broadcast-only Harmony raw Ethernet TX with unicast when the destination peer's MAC is known via announce packet learning.

**Architecture:** A fixed-size `NeighborTable` in `main.rs` learns identity_hash → MAC mappings from inbound announce packets, and a new `VirtioNet::send_to()` method uses those mappings for unicast TX. The smoltcp IP path is unaffected — only the Harmony raw frame path (EtherType 0x88B5) changes.

**Tech Stack:** Rust, no_std, harmony-boot crate (Ring 1 event loop + VirtIO driver)

---

## File Structure

| File | Responsibility |
|------|---------------|
| `crates/harmony-boot/src/main.rs` | `NeighborEntry`, `NeighborTable` struct + methods, `extract_dest_hash()` helper, RX learning in event loop, unicast dispatch in `dispatch_actions` |
| `crates/harmony-boot/src/virtio/net.rs` | `send_to(data, dst_mac)` method on `VirtioNet` |

---

### Task 1: NeighborTable Data Structure + Tests

**Files:**
- Modify: `crates/harmony-boot/src/main.rs`

- [ ] **Step 1: Write failing tests for NeighborTable**

Add a `#[cfg(test)]` module at the bottom of `main.rs` (before the exception handlers section at ~line 2085). Place it after the closing brace of `kernel_continue` but before the exception handler functions.

```rust
// ---------------------------------------------------------------------------
// Neighbor table: maps Harmony identity hashes to Ethernet MAC addresses.
// Learned from received announce packets; used for unicast TX.
// ---------------------------------------------------------------------------

const NEIGHBOR_TABLE_SIZE: usize = 32;
const NEIGHBOR_TTL_MS: u64 = 300_000; // 5 minutes

#[derive(Clone)]
struct NeighborEntry {
    identity_hash: [u8; 16],
    mac: [u8; 6],
    last_seen_ms: u64,
}

struct NeighborTable {
    entries: [Option<NeighborEntry>; NEIGHBOR_TABLE_SIZE],
}

#[cfg(test)]
mod neighbor_tests {
    use super::*;

    #[test]
    fn learn_and_lookup() {
        let mut table = NeighborTable::new();
        let hash = [0xAA; 16];
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        table.learn(hash, mac, 1000);
        assert_eq!(table.lookup(&hash, 1000), Some(mac));
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let table = NeighborTable::new();
        let hash = [0xBB; 16];
        assert_eq!(table.lookup(&hash, 1000), None);
    }

    #[test]
    fn ttl_expiry() {
        let mut table = NeighborTable::new();
        let hash = [0xCC; 16];
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        table.learn(hash, mac, 1000);
        // Just before expiry: still valid
        assert_eq!(table.lookup(&hash, 1000 + NEIGHBOR_TTL_MS - 1), Some(mac));
        // At expiry: stale
        assert_eq!(table.lookup(&hash, 1000 + NEIGHBOR_TTL_MS), None);
    }

    #[test]
    fn update_existing_entry() {
        let mut table = NeighborTable::new();
        let hash = [0xDD; 16];
        let mac1 = [0x02, 0x00, 0x00, 0x00, 0x00, 0x03];
        let mac2 = [0x02, 0x00, 0x00, 0x00, 0x00, 0x04];
        table.learn(hash, mac1, 1000);
        table.learn(hash, mac2, 2000);
        assert_eq!(table.lookup(&hash, 2000), Some(mac2));
    }

    #[test]
    fn eviction_when_full() {
        let mut table = NeighborTable::new();
        // Fill all 32 slots
        for i in 0..NEIGHBOR_TABLE_SIZE {
            let mut hash = [0u8; 16];
            hash[0] = i as u8;
            let mac = [0x02, 0x00, 0x00, 0x00, 0x00, i as u8];
            table.learn(hash, mac, 1000 + i as u64);
        }
        // Add 33rd — should evict slot 0 (oldest, last_seen_ms=1000)
        let new_hash = [0xFF; 16];
        let new_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0xFF];
        table.learn(new_hash, new_mac, 2000);

        // New entry is findable
        assert_eq!(table.lookup(&new_hash, 2000), Some(new_mac));
        // Evicted entry is gone
        let evicted_hash = [0u8; 16]; // slot 0 had hash[0]=0
        assert_eq!(table.lookup(&evicted_hash, 2000), None);
        // Other entries still present
        let mut hash1 = [0u8; 16];
        hash1[0] = 1;
        assert_eq!(
            table.lookup(&hash1, 2000),
            Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
        );
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-boot --lib -- neighbor_tests`
Expected: FAIL — `NeighborTable::new()`, `learn()`, `lookup()` not implemented yet.

- [ ] **Step 3: Implement NeighborTable**

Add the implementation directly above the test module (after the constants and struct definitions):

```rust
impl NeighborTable {
    fn new() -> Self {
        Self {
            entries: [const { None }; NEIGHBOR_TABLE_SIZE],
        }
    }

    fn learn(&mut self, identity_hash: [u8; 16], mac: [u8; 6], now_ms: u64) {
        // Update existing entry if identity_hash matches
        for entry in self.entries.iter_mut().flatten() {
            if entry.identity_hash == identity_hash {
                entry.mac = mac;
                entry.last_seen_ms = now_ms;
                return;
            }
        }
        // Find first empty slot
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(NeighborEntry {
                    identity_hash,
                    mac,
                    last_seen_ms: now_ms,
                });
                return;
            }
        }
        // Table full — evict oldest entry
        let oldest_idx = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| e.as_ref().map_or(u64::MAX, |e| e.last_seen_ms))
            .map(|(i, _)| i)
            .unwrap(); // table is full, so unwrap is safe
        self.entries[oldest_idx] = Some(NeighborEntry {
            identity_hash,
            mac,
            last_seen_ms: now_ms,
        });
    }

    fn lookup(&self, identity_hash: &[u8; 16], now_ms: u64) -> Option<[u8; 6]> {
        for entry in self.entries.iter().flatten() {
            if entry.identity_hash == *identity_hash
                && now_ms.saturating_sub(entry.last_seen_ms) < NEIGHBOR_TTL_MS
            {
                return Some(entry.mac);
            }
        }
        None
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-boot --lib -- neighbor_tests`
Expected: All 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-boot/src/main.rs
git commit -m "feat(neighbor): add NeighborTable data structure with TDD tests"
```

---

### Task 2: learn_from_announce + extract_dest_hash Helpers + Tests

**Files:**
- Modify: `crates/harmony-boot/src/main.rs`

- [ ] **Step 1: Write failing tests for announce learning and dest hash extraction**

Add these tests to the existing `neighbor_tests` module:

```rust
#[test]
fn learn_from_announce_packet() {
    let mut table = NeighborTable::new();
    let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    // Build a minimal announce packet:
    // Byte 0: flags — packet_type=Announce (0x01), header_type=Type1 (bit 6=0)
    // Byte 1: hops
    // Bytes 2..18: destination_hash (the announcer's identity)
    // Byte 18: context
    let mut payload = [0u8; 19];
    payload[0] = 0x01; // packet_type=Announce (bits 1..0 = 01)
    payload[1] = 0x00; // hops
    let identity = [0xAA; 16];
    payload[2..18].copy_from_slice(&identity);

    table.learn_from_announce(&payload, src_mac, 5000);
    assert_eq!(table.lookup(&identity, 5000), Some(src_mac));
}

#[test]
fn learn_from_non_announce_does_nothing() {
    let mut table = NeighborTable::new();
    let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    // Build a data packet (packet_type=Data = 0x00)
    let mut payload = [0u8; 19];
    payload[0] = 0x00; // packet_type=Data
    let identity = [0xBB; 16];
    payload[2..18].copy_from_slice(&identity);

    table.learn_from_announce(&payload, src_mac, 5000);
    // Should NOT have learned anything
    assert_eq!(table.lookup(&identity, 5000), None);
}

#[test]
fn learn_from_short_packet_does_nothing() {
    let mut table = NeighborTable::new();
    let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x03];
    let short_payload = [0x01; 10]; // Announce flag but too short

    table.learn_from_announce(&short_payload, src_mac, 5000);
    // Table should be empty — no crash, no entry
    assert_eq!(table.lookup(&[0x01; 16], 5000), None);
}

#[test]
fn extract_dest_hash_type1() {
    // Type1: bit 6 of flags = 0, dest at bytes 2..18
    let mut packet = [0u8; 20];
    packet[0] = 0x00; // Type1 header
    let dest = [0x11; 16];
    packet[2..18].copy_from_slice(&dest);

    assert_eq!(extract_dest_hash(&packet), Some(dest));
}

#[test]
fn extract_dest_hash_type2() {
    // Type2: bit 6 of flags = 1, dest at bytes 18..34
    let mut packet = [0u8; 35];
    packet[0] = 0x40; // Type2 header (bit 6 set)
    let dest = [0x22; 16];
    packet[18..34].copy_from_slice(&dest);

    assert_eq!(extract_dest_hash(&packet), Some(dest));
}

#[test]
fn extract_dest_hash_short_packet() {
    let short = [0u8; 5];
    assert_eq!(extract_dest_hash(&short), None);

    // Type1 but not enough bytes for dest hash
    let mut short_type1 = [0u8; 17];
    short_type1[0] = 0x00;
    assert_eq!(extract_dest_hash(&short_type1), None);

    // Type2 but not enough bytes for dest hash
    let mut short_type2 = [0u8; 33];
    short_type2[0] = 0x40;
    assert_eq!(extract_dest_hash(&short_type2), None);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-boot --lib -- neighbor_tests`
Expected: FAIL — `learn_from_announce` and `extract_dest_hash` not defined.

- [ ] **Step 3: Implement learn_from_announce and extract_dest_hash**

Add these methods/functions alongside the `NeighborTable` impl block:

```rust
impl NeighborTable {
    // ... existing new/learn/lookup methods ...

    /// Learn a neighbor from an inbound Harmony frame if it's an announce packet.
    /// Announce packets (packet_type bits 1..0 == 0x01) carry the announcer's
    /// identity as the destination_hash in a Type1 header (bytes 2..18).
    fn learn_from_announce(&mut self, payload: &[u8], src_mac: [u8; 6], now_ms: u64) {
        // Minimum Type1 header: 1 (flags) + 1 (hops) + 16 (dest_hash) + 1 (context) = 19
        if payload.len() < 19 {
            return;
        }
        // Check packet_type == Announce (bits 1..0 of flags byte)
        let packet_type = payload[0] & 0x03;
        if packet_type != 0x01 {
            return;
        }
        let mut identity_hash = [0u8; 16];
        identity_hash.copy_from_slice(&payload[2..18]);
        self.learn(identity_hash, src_mac, now_ms);
    }
}

/// Extract the destination hash from an outbound Harmony/Reticulum packet.
/// Returns `None` if the packet is too short to contain a valid header.
fn extract_dest_hash(raw: &[u8]) -> Option<[u8; 16]> {
    if raw.len() < 2 {
        return None;
    }
    let header_type2 = (raw[0] & 0x40) != 0;
    let (offset, min_len) = if header_type2 {
        (18, 34) // Type2: transport_id at 2..18, dest_hash at 18..34
    } else {
        (2, 18) // Type1: dest_hash at 2..18
    };
    if raw.len() < min_len {
        return None;
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&raw[offset..offset + 16]);
    Some(hash)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-boot --lib -- neighbor_tests`
Expected: All 11 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-boot/src/main.rs
git commit -m "feat(neighbor): add learn_from_announce and extract_dest_hash helpers"
```

---

### Task 3: VirtioNet::send_to Method + Tests

**Files:**
- Modify: `crates/harmony-boot/src/virtio/net.rs`

- [ ] **Step 1: Write failing tests for send_to**

The `VirtioNet` struct requires VirtIO hardware to construct, so we can't unit-test `send_to` directly. Instead, test the frame-building logic by extracting testable assertions. Add a test module at the bottom of `virtio/net.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Build the Ethernet frame header the same way send_to does,
    /// and verify the destination MAC is placed correctly.
    #[test]
    fn frame_header_unicast_mac() {
        let our_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x99];
        let data = b"hello";

        let mut frame = [0u8; 128];
        // Destination MAC
        frame[0..6].copy_from_slice(&dst_mac);
        // Source MAC
        frame[6..12].copy_from_slice(&our_mac);
        // EtherType
        frame[12..14].copy_from_slice(&ETHERTYPE_HARMONY);
        // Payload
        frame[ETH_HEADER_LEN..ETH_HEADER_LEN + data.len()].copy_from_slice(data);

        assert_eq!(&frame[0..6], &dst_mac);
        assert_eq!(&frame[6..12], &our_mac);
        assert_eq!(&frame[12..14], &ETHERTYPE_HARMONY);
        assert_eq!(&frame[ETH_HEADER_LEN..ETH_HEADER_LEN + 5], b"hello");
    }

    #[test]
    fn frame_header_broadcast_fallback() {
        let mut frame = [0u8; 128];
        frame[0..6].copy_from_slice(&BROADCAST_MAC);

        assert_eq!(&frame[0..6], &[0xFF; 6]);
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p harmony-boot --lib -- virtio::net::tests`
Expected: PASS (these test frame layout, not the method itself — they validate our understanding of the format).

- [ ] **Step 3: Implement send_to on VirtioNet**

Add `send_to` as a new public method on `VirtioNet`, just after the existing `send_raw` method (~line 404):

```rust
    /// Send a Harmony raw payload with an explicit destination MAC.
    /// If `dst_mac` is `None`, falls back to broadcast.
    pub fn send_to(
        &mut self,
        data: &[u8],
        dst_mac: Option<&[u8; 6]>,
    ) -> Result<(), PlatformError> {
        self.reclaim_tx();

        let frame_len = VIRTIO_NET_HDR_LEN + ETH_HEADER_LEN + data.len();
        if frame_len > BUF_SIZE {
            return Err(PlatformError::SendFailed);
        }

        let mut frame = [0u8; BUF_SIZE];
        let h = VIRTIO_NET_HDR_LEN;
        // Destination: unicast if known, broadcast otherwise.
        frame[h..h + 6].copy_from_slice(dst_mac.unwrap_or(&BROADCAST_MAC));
        // Source: our MAC.
        frame[h + 6..h + 12].copy_from_slice(&self.mac);
        // EtherType: Harmony (0x88B5).
        frame[h + 12..h + 14].copy_from_slice(&ETHERTYPE_HARMONY);
        // Payload.
        frame[h + ETH_HEADER_LEN..h + ETH_HEADER_LEN + data.len()].copy_from_slice(data);

        match self.tx_queue.submit_send(&frame[..frame_len]) {
            Some(_) => {
                unsafe { mmio_write16(self.tx_notify_addr, 1) };
                Ok(())
            }
            None => Err(PlatformError::SendFailed),
        }
    }
```

- [ ] **Step 4: Run tests to verify everything still passes**

Run: `cargo test -p harmony-boot --lib`
Expected: All tests PASS (existing + new).

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-boot/src/virtio/net.rs
git commit -m "feat(virtio-net): add send_to method for unicast Harmony TX"
```

---

### Task 4: Wire RX Learning into Event Loop

**Files:**
- Modify: `crates/harmony-boot/src/main.rs`

- [ ] **Step 1: Initialize NeighborTable in the event loop**

In `kernel_continue`, just before the `loop {` at ~line 2007, add:

```rust
    let mut neighbor_table = NeighborTable::new();
```

- [ ] **Step 2: Add announce learning to the RX path**

Replace the Harmony RX handling block (~lines 2018-2022) from:

```rust
                    0x88B5 => {
                        // Raw Harmony — strip Ethernet header, feed to runtime
                        if frame.len() > ETH_HEADER_LEN {
                            harmony_packets.push(frame[ETH_HEADER_LEN..].to_vec());
                        }
                    }
```

to:

```rust
                    0x88B5 => {
                        // Raw Harmony — learn neighbor from announces, then
                        // strip Ethernet header and feed to runtime.
                        if frame.len() > ETH_HEADER_LEN {
                            let src_mac: [u8; 6] =
                                frame[6..12].try_into().unwrap();
                            let payload = &frame[ETH_HEADER_LEN..];
                            neighbor_table.learn_from_announce(
                                payload, src_mac, now,
                            );
                            harmony_packets.push(payload.to_vec());
                        }
                    }
```

- [ ] **Step 3: Verify compilation**

Run: `cargo build -p harmony-boot`
Expected: Compiles successfully. (The `neighbor_table` variable will have an "unused" warning until Task 5 wires the TX path — this is fine.)

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-boot/src/main.rs
git commit -m "feat(neighbor): learn MAC from announce packets in RX path"
```

---

### Task 5: Wire TX Unicast into dispatch_actions

**Files:**
- Modify: `crates/harmony-boot/src/main.rs`

- [ ] **Step 1: Add neighbor_table and now_ms parameters to dispatch_actions**

Change the `dispatch_actions` function signature (~line 817) from:

```rust
fn dispatch_actions(
    actions: &[RuntimeAction],
    virtio_net: &mut Option<virtio::net::VirtioNet>,
    netstack: &core::cell::RefCell<harmony_netstack::NetStack>,
    serial: &mut SerialWriter<impl FnMut(u8)>,
) {
```

to:

```rust
fn dispatch_actions(
    actions: &[RuntimeAction],
    virtio_net: &mut Option<virtio::net::VirtioNet>,
    netstack: &core::cell::RefCell<harmony_netstack::NetStack>,
    serial: &mut SerialWriter<impl FnMut(u8)>,
    neighbor_table: &NeighborTable,
    now_ms: u64,
) {
```

- [ ] **Step 2: Replace broadcast send with unicast lookup in the "eth0" arm**

Replace the "eth0"/"virtio0" match arm (~lines 831-834) from:

```rust
                "eth0" | "virtio0" => {
                    if let Some(ref mut net) = virtio_net {
                        let _ = harmony_platform::NetworkInterface::send(net, raw);
                    }
                }
```

to:

```rust
                "eth0" | "virtio0" => {
                    if let Some(ref mut net) = virtio_net {
                        let dst_mac = extract_dest_hash(raw)
                            .and_then(|hash| neighbor_table.lookup(&hash, now_ms));
                        let _ = net.send_to(raw, dst_mac.as_ref());
                    }
                }
```

- [ ] **Step 3: Update all call sites of dispatch_actions**

There are three call sites in the event loop. Update each one.

Call site 1 (~line 2035), change from:

```rust
            dispatch_actions(&actions, &mut virtio_net, &netstack, &mut serial);
```

to:

```rust
            dispatch_actions(&actions, &mut virtio_net, &netstack, &mut serial, &neighbor_table, now);
```

Call site 2 (~line 2057), change from:

```rust
            dispatch_actions(&actions, &mut virtio_net, &netstack, &mut serial);
```

to:

```rust
            dispatch_actions(&actions, &mut virtio_net, &netstack, &mut serial, &neighbor_table, now);
```

Call site 3 (~line 2062), change from:

```rust
            dispatch_actions(&actions, &mut virtio_net, &netstack, &mut serial);
```

to:

```rust
            dispatch_actions(&actions, &mut virtio_net, &netstack, &mut serial, &neighbor_table, now);
```

- [ ] **Step 4: Verify compilation and run all tests**

Run: `cargo build -p harmony-boot && cargo test -p harmony-boot --lib`
Expected: Compiles without warnings. All tests PASS.

- [ ] **Step 5: Run full workspace tests**

Run: `cargo test --workspace`
Expected: All tests pass across all crates.

- [ ] **Step 6: Run clippy**

Run: `cargo clippy --workspace`
Expected: No warnings related to neighbor table code.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-boot/src/main.rs
git commit -m "feat(neighbor): wire unicast TX via neighbor table in dispatch_actions"
```

---

## Task Dependency Graph

```
Task 1 (NeighborTable struct + tests)
  └── Task 2 (learn_from_announce + extract_dest_hash)
      ├── Task 3 (VirtioNet::send_to)  [independent of Task 2]
      └── Task 4 (RX learning in event loop)
          └── Task 5 (TX unicast in dispatch_actions)  [depends on Tasks 2, 3, 4]
```

Tasks 2 and 3 are independent and can be done in parallel.
