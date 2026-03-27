# VirtIO-Net Bridge: micro-VM WiFi → Harmony Mesh

**Date:** 2026-03-27
**Status:** Draft
**Bead:** harmony-os-rl0
**Depends on:** harmony-os-ikw (hypervisor), harmony-os-48g (VirtIO data plane)
**Follow-ups:** harmony-os-1qf (GenetServer refactor to NetworkDevice trait)

## Problem

The EL2 micro-VM's `VirtioNetDevice` produces and consumes raw Ethernet frames via `poll_tx`/`push_rx`. The Harmony host's `NetStack` uses `FrameBuffer::ingest`/`drain_tx`. These two systems need to be connected so WiFi traffic flows between the guest VM and the Harmony mesh.

## Constraints

- **No new dependency edges.** `harmony-hypervisor` already depends on `harmony-microkernel`. No circular dependencies.
- **Follow `GenetServer` pattern.** The 9P server uses the same `FidTracker`, same file layout (`data`/`mac`/`mtu`/`stats`/`link`), same `FileServer` implementation style.
- **Sans-I/O.** The `NetworkDevice` trait and `VirtioNetBridge` are pure — no hardware access.
- **Borrowing adapter.** `VirtioNetBridge` borrows `VirtioNetDevice` + shared memory for a poll cycle, it doesn't own them.

## Architecture

```
Kernel Event Loop
  │
  ├─ read virtio0/data  →  VirtioNetServer.read()
  │                           → device.poll_tx(out_buf)
  │                             → VirtioNetBridge.poll_tx()
  │                               → VirtioNetDevice.poll_tx(mem, ...)
  │                           → returns raw Ethernet frame
  │                           → netstack.ingest(frame)
  │
  ├─ netstack.poll()    →  processes IP stack (smoltcp)
  │
  └─ netstack.drain_tx() → for each outbound frame:
      write virtio0/data  →  VirtioNetServer.write()
                                → device.push_rx(frame)
                                  → VirtioNetBridge.push_rx()
                                    → VirtioNetDevice.push_rx(frame, mem, ...)
```

Same flow as GENET — the kernel doesn't know whether the device is hardware or a VM.

## File Layout

| File | Crate | Responsibility |
|------|-------|---------------|
| `src/net_device.rs` | `harmony-microkernel` | `NetworkDevice` trait |
| `src/virtio_net_server.rs` | `harmony-microkernel` | 9P `FileServer` over `NetworkDevice` |
| `src/virtio_net_bridge.rs` | `harmony-hypervisor` | `VirtioNetBridge` adapter |

Modified:
- `harmony-microkernel/src/lib.rs` — add `pub mod net_device; pub mod virtio_net_server;`
- `harmony-hypervisor/src/lib.rs` — add `pub mod virtio_net_bridge;`

## NetworkDevice Trait

In `harmony-microkernel/src/net_device.rs`:

```rust
/// Abstraction over a network device that produces and consumes raw Ethernet frames.
/// Implemented by VirtioNetBridge (VM-backed) and potentially GenetServer (hardware).
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
```

Object-safe (`dyn NetworkDevice` works). All methods are sans-I/O.

## VirtioNetBridge

In `harmony-hypervisor/src/virtio_net_bridge.rs`:

```rust
use harmony_microkernel::net_device::NetworkDevice;
use crate::virtio_net::VirtioNetDevice;

/// Borrowing adapter that connects a VirtioNetDevice to the NetworkDevice trait.
///
/// Constructed by the kernel each poll cycle, borrowing the VM's device and
/// shared memory for the duration. Dropped when the cycle completes.
pub struct VirtioNetBridge<'a> {
    device: &'a mut VirtioNetDevice,
    mem: &'a mut [u8],
    region_base_ipa: u64,
    /// IPA-to-pointer for reads (poll_tx). Same underlying translation as
    /// ipa_to_ptr_write but with const pointer for type safety.
    ipa_to_ptr_read: fn(u64) -> *const u8,
    /// IPA-to-pointer for writes (push_rx).
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

    fn mac(&self) -> [u8; 6] {
        self.device.mac
    }

    fn link_up(&self) -> bool {
        true // Phase 1: always up
    }
}
```

Delegation-only — no new logic. The complexity is already in `VirtioNetDevice`.

## VirtioNetServer (9P FileServer)

In `harmony-microkernel/src/virtio_net_server.rs`. Follows `GenetServer` pattern exactly.

### Namespace

```
/dev/net/virtio0/
  ├── data   — R/W: read = poll_tx, write = push_rx
  ├── mac    — R:   "02:00:00:00:00:01\n"
  ├── mtu    — R:   "1500\n"
  ├── stats  — R:   "tx_packets: N\nrx_packets: N\ntx_bytes: N\nrx_bytes: N\n"
  ├── link   — R:   "up\n" or "down\n"
```

### Structure

```rust
use crate::net_device::NetworkDevice;
use crate::fid_tracker::FidTracker;
use crate::{FileServer, Fid, QPath, IpcError, OpenMode, FileStat, FileType};

const QPATH_ROOT: QPath = 0;
const QPATH_DIR: QPath = 1;
const QPATH_DATA: QPath = 2;
const QPATH_MAC: QPath = 3;
const QPATH_MTU: QPath = 4;
const QPATH_STATS: QPath = 5;
const QPATH_LINK: QPath = 6;

pub struct VirtioNetServer<N: NetworkDevice> {
    device: N,
    tracker: FidTracker<()>,
    name: &'static str,    // "virtio0", "virtio1", etc.
    tx_packets: u64,
    rx_packets: u64,
    tx_bytes: u64,
    rx_bytes: u64,
}
```

### FileServer Implementation

**walk:** `child_qpath(parent, name)` maps names to QPaths. Unlike `GenetServer` which uses a const pattern match for `"genet0"`, the root-to-directory walk compares against `self.name` (dynamic string: `"virtio0"`, `"virtio1"`, etc.):
```rust
fn child_qpath(&self, parent: QPath, name: &str) -> Result<QPath, IpcError> {
    match (parent, name) {
        (QPATH_ROOT, n) if n == self.name => Ok(QPATH_DIR),
        (QPATH_DIR, "data") => Ok(QPATH_DATA),
        // ... same as GenetServer for child files
    }
}
```

**open:** Same as `GenetServer` — data is R/W, mac/mtu/stats/link are read-only.

**clone_fid:** Delegate to `self.tracker.clone_fid(fid, new_fid)`, same as `GenetServer`. Required if the server is mounted as a namespace root.

**read on `data`:** Streaming semantics (offset ignored, same as `GenetServer`). If `count == 0`, return empty vec without consuming a frame. Call `device.poll_tx(&mut buf)`. If `Some(n)` and `n > count`, return `IpcError::InvalidArgument` (frame too large for client buffer — matches `GenetServer` behavior). Otherwise increment `tx_packets` and `tx_bytes`, return `buf[..n]`. If `None`, return empty vec (EOF — no pending frame).

**write on `data`:** Call `device.push_rx(data)`. If `true`, increment `rx_packets` and `rx_bytes`, return `data.len()` as bytes written. If `false`, return `IpcError::ResourceExhausted`.

**read on `mac`/`mtu`/`stats`/`link`:** Use `slice_at_offset(bytes, offset, count)` helper (same as `GenetServer`) for proper offset-based slicing and EOF signaling on chunked reads. Format strings:
- `mac`: `"02:00:00:00:00:01\n"` (from `device.mac()`)
- `mtu`: `"1500\n"`
- `stats`: `"rx_packets: N\ntx_packets: N\nrx_bytes: N\ntx_bytes: N\n"` (rx first, matching `GenetServer`'s field order)
- `link`: `"up\n"` or `"down\n"` from `device.link_up()`

**stat:** Return `FileStat` with appropriate `FileType` and name.

**clunk:** Release fid from tracker.

## Testing Strategy

| Layer | What | How |
|-------|------|-----|
| `NetworkDevice` trait | Compile-time check, mock implementation | `MockNetDevice` with `VecDeque<Vec<u8>>` for TX, `Vec<Vec<u8>>` log for RX |
| `VirtioNetBridge` | Delegates correctly to `VirtioNetDevice` | Set up configured VirtioNetDevice + shared memory with a TX packet, wrap in bridge, call `poll_tx` through trait |
| `VirtioNetServer` walk/open | 9P namespace traversal, open modes | Create server with `MockNetDevice`, walk to each file, verify QPaths |
| `VirtioNetServer` read `data` | Returns pending TX frame | Mock with queued frame, read from data fid, verify frame bytes |
| `VirtioNetServer` write `data` | Injects RX frame | Write to data fid, verify mock received the frame |
| `VirtioNetServer` read `mac` | Formatted MAC string | Read from mac fid, verify format |
| `VirtioNetServer` read `stats` | Counter formatting | Send/receive some packets, read stats, verify counts |
| `VirtioNetServer` read `link` | Link status string | Verify "up\n" / "down\n" |
| Integration | Full path: shared memory TX → data read → Ethernet frame | `VirtioNetServer<VirtioNetBridge>` with real VirtioNetDevice + shared memory (in `harmony-hypervisor` test suite, since it depends on both crates) |

All testable with `cargo test`.

## Out of Scope

- Kernel event loop integration (that's the kernel's responsibility, not this module's)
- `FrameBuffer` / `NetStack` wiring (the kernel reads `data` and calls `ingest` — that's kernel code)
- GIC interrupt injection for RX notification (harmony-os-04p)
- GenetServer refactor to `NetworkDevice` (harmony-os-1qf)
