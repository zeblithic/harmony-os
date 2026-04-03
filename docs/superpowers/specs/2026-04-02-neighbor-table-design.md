# Neighbor Table for Unicast Ethernet TX

**Bead:** harmony-os-8ru (P3, feature)
**Date:** 2026-04-02
**Status:** Design approved

## Problem

The VirtIO network driver's `send()` method (EtherType 0x88B5 Harmony raw frames) hardcodes the destination MAC to `BROADCAST_MAC` (`FF:FF:FF:FF:FF:FF`) at `virtio/net.rs:432`. Every outbound Harmony raw frame floods the LAN, even when the destination peer is a known neighbor whose MAC we've already seen. This wastes bandwidth and is incorrect for unicast responses.

The smoltcp IP path (`drain_tx()` → `send_raw()`) is unaffected — smoltcp handles ARP and unicast MACs internally. Only the Harmony raw Ethernet path has this problem.

## Design

### NeighborTable Data Structure

A fixed-size, `no_std`-friendly table in `main.rs`:

```rust
const NEIGHBOR_TABLE_SIZE: usize = 32;
const NEIGHBOR_TTL_MS: u64 = 300_000; // 5 minutes

struct NeighborEntry {
    identity_hash: [u8; 16],  // Reticulum destination hash
    mac: [u8; 6],
    last_seen_ms: u64,
}

struct NeighborTable {
    entries: [Option<NeighborEntry>; NEIGHBOR_TABLE_SIZE],
}
```

**Methods:**

- `new()` — Returns table with all `None` entries.
- `learn(&mut self, identity_hash: [u8; 16], mac: [u8; 6], now_ms: u64)` — Insert or update an entry. If the identity_hash already exists, update MAC and timestamp. If not found, insert into the first `None` slot. If table is full, evict the entry with the oldest `last_seen_ms`.
- `lookup(&self, identity_hash: &[u8; 16], now_ms: u64) -> Option<[u8; 6]>` — Return MAC if found and `now_ms - last_seen_ms < NEIGHBOR_TTL_MS`. Returns `None` for stale or missing entries.

Design choices:
- Fixed 32-entry array, no heap allocation. ~750 bytes total. 32 is generous for a LAN segment.
- Time-based expiry checked at lookup time — no background cleanup.
- When table is full, evicts oldest entry (smallest `last_seen_ms`).
- 5-minute TTL aligns with Reticulum's announce interval.

### RX Learning Path

In the Ring 1 event loop (`main.rs` ~line 2018), when receiving a Harmony raw frame (EtherType 0x88B5), extract the source MAC before stripping the Ethernet header and attempt to learn:

```rust
0x88B5 => {
    if frame.len() > ETH_HEADER_LEN {
        let src_mac: [u8; 6] = frame[6..12].try_into().unwrap();
        let payload = &frame[ETH_HEADER_LEN..];
        neighbor_table.learn_from_announce(payload, src_mac, now);
        harmony_packets.push(payload.to_vec());
    }
}
```

**`learn_from_announce(&mut self, payload: &[u8], src_mac: [u8; 6], now_ms: u64)`:**
- Check minimum length (≥ 19 bytes for a Type1 header).
- Parse flags byte: `payload[0]`. Announce = `packet_type` bits 1..0 == `0x01`.
- If not an announce packet, return immediately (no learning from non-announce packets).
- Extract destination_hash from bytes 2..18 (announce packets are always Type1).
- Call `learn(destination_hash, src_mac, now_ms)`.

Design choices:
- Only learns from announce packets. Announce packets carry the announcer's identity as the destination_hash. Non-announce packets only contain the recipient's destination_hash (which is us), not the sender's identity.
- Inline flags byte parsing — two bytes checked, no dependency on the `harmony-reticulum` crate. Avoids coupling `main.rs` to the core repo's packet parser.

### TX Unicast Path

In `dispatch_actions`, when handling `RuntimeAction::SendOnInterface { interface_name: "eth0", raw, weight }`:

**Current behavior:**
```rust
let _ = harmony_platform::NetworkInterface::send(net, raw);
```

**New behavior:**
```rust
// Broadcast sends skip unicast lookup
if weight.is_some() {
    let _ = harmony_platform::NetworkInterface::send(net, raw);
} else {
    // Parse destination hash from outbound Harmony packet
    let dst_mac = extract_dest_hash(raw)
        .and_then(|hash| neighbor_table.lookup(&hash, now));
    net.send_to(raw, dst_mac.as_ref());
}
```

**`extract_dest_hash(raw: &[u8]) -> Option<[u8; 16]>`:**
- Free function, parses the flags byte to determine header type.
- Type1 (bit 6 of flags = 0): destination_hash at bytes 2..18. Requires `raw.len() >= 18`.
- Type2 (bit 6 of flags = 1): destination_hash at bytes 18..34. Requires `raw.len() >= 34`.
- Returns `None` if packet is too short.

**`VirtioNet::send_to(&mut self, data: &[u8], dst_mac: Option<&[u8; 6]>) -> Result<(), PlatformError>`:**
- New method on `VirtioNet`. Same as current `send()` but uses the provided MAC if `Some`, falls back to `BROADCAST_MAC` if `None`.
- The existing `NetworkInterface::send()` impl stays unchanged (always broadcasts) for compatibility.

**`dispatch_actions` signature change:**
- Adds `neighbor_table: &NeighborTable` and `now: u64` parameters. Both are available in the Ring 1 event loop caller.

### Edge Cases

- **Unknown destination:** `lookup` returns `None` → broadcast MAC. Same as current behavior, no regression.
- **Stale entry:** Peer left the LAN. After 5 min TTL, `lookup` returns `None` → broadcast. If peer is still around, their next announce refreshes the entry.
- **MAC change:** Peer reboots with different NIC/MAC. Next announce overwrites the old entry.
- **Table full:** 33rd unique peer → evict oldest `last_seen_ms` entry.
- **Type2 header on TX:** Destination hash at bytes 18..34. `extract_dest_hash` checks the header type flag.
- **Short/malformed packets:** Both `learn_from_announce` and `extract_dest_hash` check minimum length before parsing. Silently skip if too short.
- **Ring 3 unaffected:** Ring 3's `poll_network()` only handles smoltcp IP traffic (`drain_tx()` → `send_raw()`). Those frames already have correct unicast MACs from smoltcp's internal ARP. No changes needed.

## Files Changed

| File | Changes |
|------|---------|
| `crates/harmony-boot/src/main.rs` | `NeighborEntry`, `NeighborTable` struct + methods, `extract_dest_hash` helper, `learn_from_announce` in RX path, unicast lookup in `dispatch_actions`, pass table + timestamp to `dispatch_actions` |
| `crates/harmony-boot/src/virtio/net.rs` | `send_to(data, dst_mac)` method on `VirtioNet` |

## Testing

**Unit tests (main.rs inline module):**
- `NeighborTable::learn` + `lookup` round-trip: learn an entry, look it up, get correct MAC
- TTL expiry: learn entry, advance time ≥ 5 minutes, lookup returns `None`
- Update existing: learn same identity_hash with new MAC, lookup returns new MAC
- Eviction: fill all 32 entries, add 33rd → oldest evicted, 33rd is findable
- `learn_from_announce`: announce packet → entry created; data packet → no entry created
- `learn_from_announce`: short packet (< 19 bytes) → no entry created
- `extract_dest_hash`: Type1 packet → correct hash from bytes 2..18
- `extract_dest_hash`: Type2 packet → correct hash from bytes 18..34
- `extract_dest_hash`: short packet → returns `None`
- Broadcast weight: `weight.is_some()` → bypasses neighbor lookup (tested via dispatch logic, not table)

**Unit tests (virtio/net.rs):**
- `send_to` with `Some(mac)`: frame destination bytes match provided MAC
- `send_to` with `None`: frame destination bytes match `BROADCAST_MAC`

## Out of Scope

- Active neighbor probing (gratuitous ARP, neighbor solicitation) — passive learning only
- IPv6 neighbor discovery — not relevant for Harmony raw frames
- Persisting the table across reboots — in-memory only
- Exposing the table to Ring 3 / Linuxulator — smoltcp handles its own ARP
- Configurable TTL or table size — fixed constants are sufficient
- Learning from non-announce packets — would require runtime to expose sender identity
