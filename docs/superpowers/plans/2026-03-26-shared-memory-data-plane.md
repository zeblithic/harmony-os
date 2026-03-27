# Shared Memory Data Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add VirtIO-compatible split virtqueues and MMIO transport to `harmony-hypervisor`, enabling packet transfer between guest VMs and the Harmony host through shared memory.

**Architecture:** Three new modules in the existing `harmony-hypervisor` crate: `VirtQueue` (ring buffer logic on `&mut [u8]`), `VirtioMmio` (register emulation + config space), `VirtioNetDevice` (TX/RX packet operations). The hypervisor's `handle_data_abort` routes VirtIO MMIO IPA traps to the device model.

**Tech Stack:** Rust (no_std + alloc), existing `harmony-hypervisor` types (`AccessType`, `MmioResult`, `VmId`, `PhysAddr`), VirtIO 1.2 spec (split virtqueue, MMIO transport, virtio-net)

**Spec:** `docs/superpowers/specs/2026-03-26-shared-memory-data-plane-design.md`

**Scope:** This plan covers the pure Rust sans-I/O data plane only. Netstack integration (rl0), 9P VmServer (fej), and GIC interrupt injection (04p) are follow-up beads.

---

## File Structure

### New files in `crates/harmony-hypervisor/`

| File | Responsibility |
|------|---------------|
| `src/virtqueue.rs` | `VirtQueue`, `DescriptorChain`, `Descriptor`, `VirtQueueError` — split virtqueue on `&mut [u8]` |
| `src/virtio_mmio.rs` | `VirtioMmio`, `QueueConfig`, `MmioResponse` — MMIO register emulation + config space |
| `src/virtio_net.rs` | `VirtioNetDevice`, `VirtioNetHdr` — TX/RX packet ops, 12-byte header handling |

### Modified files

| File | Change |
|------|--------|
| `src/lib.rs` | Add `pub mod virtqueue; pub mod virtio_mmio; pub mod virtio_net;` |
| `src/trap.rs` | Add `VirtioQueueNotify` action variant |
| `src/vcpu.rs` | Add `VirtioNetDevice` to `Vm` struct |
| `src/platform/mod.rs` | Add `VIRTIO_NET_MMIO_IPA` and `VIRTIO_NET_MMIO_SIZE` constants |
| `src/hypervisor.rs` | Route VirtIO MMIO IPA range in `handle_data_abort`, create `VirtioNetDevice` in `hvc_vm_create` |

---

## Task 1: VirtQueue — split virtqueue on shared memory

**Files:**
- Create: `crates/harmony-hypervisor/src/virtqueue.rs`
- Modify: `crates/harmony-hypervisor/src/lib.rs` (add `pub mod virtqueue`)

**Context:**
- VirtIO 1.2 §2.7 split virtqueue: descriptor table (16 bytes × N), available ring (6 + 2×N), used ring (6 + 8×N)
- All operations take `&[u8]` or `&mut [u8]` — the shared memory region
- Little-endian wire format: use `u16::from_le_bytes`, `u32::from_le_bytes`, etc.
- Queue size max 256, must be power of 2
- Descriptor chain iteration capped at `queue_size` hops (cycle detection)

- [ ] **Step 1: Write failing tests for VirtQueue**

Tests to include:
- `new_rejects_non_power_of_2` — queue_size=3 fails
- `new_rejects_zero` — queue_size=0 fails
- `new_rejects_overflow` — queue_size that overflows region fails
- `pop_available_empty` — returns None when available ring idx == last_avail_idx
- `pop_available_single` — write a descriptor + available ring entry, pop it, verify head_id and descriptor fields
- `pop_available_chained` — two chained descriptors, iterate with next()
- `push_used_updates_ring` — push_used writes id+len to used ring and increments idx
- `pop_push_roundtrip` — pop an available descriptor, push it to used, verify used ring entry
- `chain_too_long_detected` — circular chain (desc 0 → desc 1 → desc 0) returns ChainTooLong
- `indirect_rejected` — descriptor with INDIRECT flag returns IndirectNotSupported
- `index_wrapping` — available ring idx wraps at u16::MAX correctly

Helper function for tests: `write_descriptor(mem, desc_offset, idx, addr, len, flags, next)` that writes a 16-byte descriptor at the correct offset. Similar helpers for available/used ring manipulation.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-hypervisor`
Expected: Compilation error — `virtqueue` module doesn't exist

- [ ] **Step 3: Implement VirtQueue**

Key implementation details:

```rust
// Constants
pub const MAX_QUEUE_SIZE: u16 = 256;
const DESC_SIZE: usize = 16;
const AVAIL_HEADER: usize = 4; // flags(2) + idx(2)
const USED_HEADER: usize = 4;  // flags(2) + idx(2)
const USED_ENTRY: usize = 8;   // id(4) + len(4)

// Descriptor flags
pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;
pub const VRING_DESC_F_INDIRECT: u16 = 4;

// Available ring flag
pub const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;
```

Memory access helpers (all little-endian):
- `read_u16(mem, offset)`, `write_u16(mem, offset, val)` — with bounds checks
- `read_u32(mem, offset)`, `write_u32(mem, offset, val)`
- `read_u64(mem, offset)`, `write_u64(mem, offset, val)`

`VirtQueue::new(queue_size, desc_offset, avail_offset, used_offset, region_len)`:
- Validate `queue_size` is power of 2 and ≤ 256
- Validate all three regions fit within `region_len`:
  - `desc_offset + queue_size * 16 <= region_len`
  - `avail_offset + 6 + 2 * queue_size <= region_len`
  - `used_offset + 6 + 8 * queue_size <= region_len`
- Return `RegionTooSmall` if any check fails

`VirtQueue::pop_available()`:
- Read `avail_idx = read_u16(mem, avail_offset + 2)`
- If `avail_idx == last_avail_idx`, return None
- Read `desc_head = read_u16(mem, avail_offset + 4 + (last_avail_idx % queue_size) * 2)`
- Increment `last_avail_idx`
- Return `(desc_head, DescriptorChain { head: desc_head, next: Some(desc_head), ... })`

`VirtQueue::push_used()`:
- Read current `used_idx = read_u16(mem, used_offset + 2)`
- Write `id` and `len` at `used_offset + 4 + (used_idx % queue_size) * 8`
- Write `used_idx + 1` at `used_offset + 2`

`VirtQueue::needs_notification()`:
- Read `avail_flags = read_u16(mem, avail_offset)`
- Return `avail_flags & VRING_AVAIL_F_NO_INTERRUPT == 0`

`DescriptorChain::next()`:
- Track `hops: u16` field on `DescriptorChain` (initialized to 0), return `Err(ChainTooLong)` if `hops > queue_size`
- If `self.next` is None, return `Ok(None)`
- Read descriptor at `desc_offset + self.next.unwrap() * 16`
- If flags has INDIRECT, return `Err(IndirectNotSupported)`
- If flags has NEXT, set `self.next = Some(desc.next)`, else `self.next = None`
- Increment hops
- Return `Ok(Some(desc))`

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-hypervisor`
Expected: All tests pass

- [ ] **Step 5: Run workspace-wide checks**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: Clean

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-hypervisor/src/virtqueue.rs crates/harmony-hypervisor/src/lib.rs
git commit -m "feat(hypervisor): add VirtQueue split virtqueue implementation"
```

---

## Task 2: VirtIO MMIO transport — register emulation and config space

**Files:**
- Create: `crates/harmony-hypervisor/src/virtio_mmio.rs`
- Modify: `crates/harmony-hypervisor/src/lib.rs` (add `pub mod virtio_mmio`)

**Context:**
- VirtIO 1.2 §4.2.2 MMIO register interface
- `handle_mmio(offset, access)` dispatches register reads/writes
- Config space at 0x100+: 6-byte MAC + 2-byte link status
- `MmioResponse` enum (ReadValue, WriteAck, QueueNotify, StatusChanged)
- DeviceFeatures: word 0 = F_MAC | F_STATUS, word 1 = F_VERSION_1 (bit 0)
- QueueNotify uses the **written value** as queue index (not queue_sel)
- QueueNum validated ≤ 256, power of 2

- [ ] **Step 1: Write failing tests for VirtioMmio**

Tests to include:
- `magic_value_reads_correctly` — offset 0x000 returns 0x74726976
- `version_reads_2` — offset 0x004 returns 2
- `device_id_reads_1` — offset 0x008 returns 1 (net)
- `vendor_id_reads_hv` — offset 0x00C returns 0x4856
- `device_features_word0` — write DeviceFeaturesSel=0, read DeviceFeatures → has F_MAC and F_STATUS
- `device_features_word1` — write DeviceFeaturesSel=1, read DeviceFeatures → has F_VERSION_1 (bit 0)
- `driver_features_accepted` — write DriverFeaturesSel + DriverFeatures, verify stored
- `queue_select_and_config` — select queue 0, set QueueNum, write addresses, set QueueReady
- `queue_num_max_returns_256` — offset 0x034 returns 256
- `queue_notify_returns_written_value` — write 1 to QueueNotify → QueueNotify { queue: 1 }
- `status_lifecycle` — write ACKNOWLEDGE(1), DRIVER(2), FEATURES_OK(8), DRIVER_OK(4) in sequence
- `config_generation_reads_zero` — offset 0x0FC returns 0
- `config_space_mac` — offsets 0x100-0x105 return MAC bytes
- `config_space_status` — offset 0x106 returns VIRTIO_NET_S_LINK_UP (1), 0x107 returns 0
- `unknown_offset_read_returns_zero` — unrecognized offset returns 0

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-hypervisor`
Expected: Compilation error — `virtio_mmio` module doesn't exist

- [ ] **Step 3: Implement VirtioMmio**

Key implementation details:

```rust
use crate::trap::AccessType;

// VirtIO MMIO register offsets
const REG_MAGIC: u32 = 0x000;
const REG_VERSION: u32 = 0x004;
const REG_DEVICE_ID: u32 = 0x008;
const REG_VENDOR_ID: u32 = 0x00C;
const REG_DEVICE_FEATURES: u32 = 0x010;
const REG_DEVICE_FEATURES_SEL: u32 = 0x014;
const REG_DRIVER_FEATURES: u32 = 0x020;
const REG_DRIVER_FEATURES_SEL: u32 = 0x024;
const REG_QUEUE_SEL: u32 = 0x030;
const REG_QUEUE_NUM_MAX: u32 = 0x034;
const REG_QUEUE_NUM: u32 = 0x038;
const REG_QUEUE_READY: u32 = 0x044;
const REG_QUEUE_NOTIFY: u32 = 0x050;
const REG_INTERRUPT_STATUS: u32 = 0x060;
const REG_INTERRUPT_ACK: u32 = 0x064;
const REG_STATUS: u32 = 0x070;
const REG_QUEUE_DESC_LOW: u32 = 0x080;
const REG_QUEUE_DESC_HIGH: u32 = 0x084;
const REG_QUEUE_AVAIL_LOW: u32 = 0x090;
const REG_QUEUE_AVAIL_HIGH: u32 = 0x094;
const REG_QUEUE_USED_LOW: u32 = 0x0A0;
const REG_QUEUE_USED_HIGH: u32 = 0x0A4;
const REG_CONFIG_GENERATION: u32 = 0x0FC;
const REG_CONFIG_BASE: u32 = 0x100;

// Feature bits
pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
pub const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

// Link status
pub const VIRTIO_NET_S_LINK_UP: u16 = 1;
```

`VirtioMmio::new(device_id, features, mac)`:
- Set device_features, store MAC + link status in config[0..8]

`VirtioMmio::handle_mmio(offset, access)`:
- Match on `(offset, access)`:
  - Read at known offset → return `MmioResponse::ReadValue(val)`
  - Write at known offset → update state, return `WriteAck` (or `QueueNotify`/`StatusChanged`)
  - Config space (offset >= 0x100) → read from `self.config[offset - 0x100]`
  - Unknown → read returns 0, write returns WriteAck

`selected_queue()` helper → `&mut self.queues[self.queue_sel as usize]` (clamped to 0..2)

Feature word selection logic:
- `DeviceFeatures` read: return `(self.device_features >> (self.device_features_sel * 32)) as u32`
  - sel=0 → bits [31:0] (F_MAC, F_STATUS), sel=1 → bits [63:32] (F_VERSION_1 appears as bit 0)
- `DriverFeatures` write: `self.driver_features |= (value as u64) << (self.driver_features_sel * 32)`

Config space reads (offset >= 0x100): return `self.config[(offset - 0x100) as usize]` as a single byte. Linux uses `readb` for config space when `VIRTIO_F_VERSION_1` is negotiated, so byte-width reads are sufficient.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-hypervisor`
Expected: All tests pass

- [ ] **Step 5: Run workspace-wide checks**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: Clean

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-hypervisor/src/virtio_mmio.rs crates/harmony-hypervisor/src/lib.rs
git commit -m "feat(hypervisor): add VirtIO MMIO transport with config space"
```

---

## Task 3: VirtIO net device — TX/RX packet operations

**Files:**
- Create: `crates/harmony-hypervisor/src/virtio_net.rs`
- Modify: `crates/harmony-hypervisor/src/lib.rs` (add `pub mod virtio_net`)

**Context:**
- Wraps VirtioMmio + two VirtQueues (RX=0, TX=1)
- 12-byte `virtio_net_hdr_v1` (with `num_buffers` field for F_VERSION_1)
- `poll_tx()` strips 12-byte header, writes raw Ethernet frame to caller's buffer
- `push_rx()` prepends 12-byte header (num_buffers=1), writes into guest RX buffer
- `handle_mmio()` delegates to VirtioMmio
- VirtQueues are constructed lazily from QueueConfig addresses when host calls poll_tx/push_rx
- `ipa_to_ptr` callback translates guest IPA → host pointer

- [ ] **Step 1: Write failing tests for VirtioNetDevice**

Tests to include:
- `new_creates_device_with_mac` — verify MAC is stored, mmio configured
- `handle_mmio_delegates_to_mmio` — magic value read works through VirtioNetDevice
- `poll_tx_empty_returns_none` — no queues configured, returns None
- `poll_tx_extracts_frame` — set up a configured TX queue in shared memory with a packet (12-byte hdr + Ethernet frame), verify poll_tx strips header and returns frame
- `push_rx_injects_frame` — set up a configured RX queue with an available buffer, push_rx writes header + frame, verify used ring updated
- `push_rx_full_queue_returns_false` — no available buffers, returns false
- `virtio_net_hdr_size_is_12` — `core::mem::size_of::<VirtioNetHdr>() == 12`
- `push_rx_oversized_frame_returns_false` — frame larger than posted RX buffer, returns false

**Test memory layout:** Allocate a `Vec<u8>` as fake shared memory. Descriptor `addr` fields point into this same Vec (identity mapping). The `ipa_to_ptr` callback is `|addr| addr as *const u8` (for TX) or `|addr| addr as *mut u8` (for RX). Place packet data buffers after the virtqueue structures in the same Vec.

**Note:** `poll_tx` and `push_rx` dereference raw pointers from `ipa_to_ptr` — these methods contain `unsafe` blocks. Tests use heap-backed memory where the `addr` field points to a valid region of the test Vec, so the unsafe is sound in test context.

**Assumption:** RX uses single-descriptor buffers (no chaining). Linux's `virtio-net` with `VIRTIO_F_VERSION_1` and no `VIRTIO_NET_F_MRG_RXBUF` posts single large buffers. If the buffer is too small for hdr + frame, `push_rx` returns false.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-hypervisor`
Expected: Compilation error — `virtio_net` module doesn't exist

- [ ] **Step 3: Implement VirtioNetDevice**

```rust
use crate::virtio_mmio::{MmioResponse, VirtioMmio, VIRTIO_NET_F_MAC, VIRTIO_NET_F_STATUS, VIRTIO_F_VERSION_1};
use crate::virtqueue::VirtQueue;
use crate::trap::AccessType;

pub const VIRTIO_NET_HDR_SIZE: usize = 12;

#[repr(C)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

pub struct VirtioNetDevice {
    pub mmio: VirtioMmio,
    pub mac: [u8; 6],
    rx_queue: Option<VirtQueue>,
    tx_queue: Option<VirtQueue>,
}
```

`VirtioNetDevice::new(mac)`:
- Create VirtioMmio with device_id=1, features=F_MAC|F_STATUS|F_VERSION_1, mac
- rx_queue and tx_queue start as None

`VirtioNetDevice::ensure_queues()`:
- If rx_queue is None and mmio.queues[0].ready, construct VirtQueue from QueueConfig addresses
- Same for tx_queue from mmio.queues[1]

`VirtioNetDevice::poll_tx(mem, ipa_to_ptr, out_buf)`:
- Call ensure_queues(); if tx_queue is None, return None
- Pop available from TX queue; if None, return None
- Iterate descriptor chain, gather buffer contents via ipa_to_ptr
- Skip first 12 bytes (virtio_net_hdr), copy rest to out_buf
- Push used with total consumed length
- Return Some(bytes_written)

`VirtioNetDevice::push_rx(frame, mem, ipa_to_ptr)`:
- Call ensure_queues(); if rx_queue is None, return false
- Pop available from RX queue; if None, return false
- Write 12-byte header (zeroed, num_buffers=1) + frame into first descriptor buffer via ipa_to_ptr
- Push used with total length (12 + frame.len())
- Return true

`VirtioNetDevice::handle_mmio(offset, access)`:
- Delegate to `self.mmio.handle_mmio(offset, access)`

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-hypervisor`
Expected: All tests pass

- [ ] **Step 5: Run workspace-wide checks**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: Clean

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-hypervisor/src/virtio_net.rs crates/harmony-hypervisor/src/lib.rs
git commit -m "feat(hypervisor): add VirtioNetDevice with TX/RX packet operations"
```

---

## Task 4: Hypervisor integration — IPA routing and action variant

**Files:**
- Modify: `crates/harmony-hypervisor/src/trap.rs` (add `VirtioQueueNotify` variant)
- Modify: `crates/harmony-hypervisor/src/platform/mod.rs` (add VirtIO MMIO IPA constants)
- Modify: `crates/harmony-hypervisor/src/vcpu.rs` (add `VirtioNetDevice` to `Vm`)
- Modify: `crates/harmony-hypervisor/src/hypervisor.rs` (IPA routing in handle_data_abort, create device in hvc_vm_create)

**Context:**
- New `VirtioQueueNotify { vmid, queue, pc_advance }` action variant
- VirtIO MMIO IPA at 0x0A00_0000 (one 4KiB page)
- `Vm` gains `virtio_net: VirtioNetDevice` field, created in `hvc_vm_create`
- `handle_data_abort` routes VirtIO MMIO IPA range to `vm.virtio_net.handle_mmio()`
- `MmioResponse` converted to `HypervisorAction` using trap context (`width`, `srt`)
- Default MAC: `[0x02, 0x00, 0x00, 0x00, 0x00, vmid.0]` (locally-administered, per-VM)

- [ ] **Step 1: Write failing tests**

Tests to include:
- `virtio_mmio_magic_via_hypervisor` — create VM, send DataAbort at VirtIO MMIO IPA offset 0x000 (read), verify MmioResult with read_value=0x74726976
- `virtio_mmio_write_via_hypervisor` — write to Status register (offset 0x070), verify MmioResult (WriteAck path)
- `virtio_queue_notify_via_hypervisor` — write to QueueNotify (offset 0x050), verify VirtioQueueNotify action returned
- `virtio_mmio_without_active_vm_errors` — DataAbort at VirtIO IPA with no active VM → NoActiveVm error
- `virtio_config_space_mac` — read offset 0x100 returns first MAC byte

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-hypervisor`
Expected: Compilation error — `VirtioQueueNotify` variant doesn't exist

- [ ] **Step 3: Implement integration**

**trap.rs** — add to `HypervisorAction`:
```rust
    /// Guest kicked a VirtIO queue — host should process pending descriptors.
    /// The platform shim must advance ELR_EL2 by `pc_advance` bytes
    /// (QueueNotify is a store instruction that faulted) and resume the guest.
    VirtioQueueNotify {
        vmid: VmId,
        queue: u16,
        pc_advance: u8,
    },
```

**platform/mod.rs** — add:
```rust
pub const VIRTIO_NET_MMIO_IPA: u64 = 0x0A00_0000;
pub const VIRTIO_NET_MMIO_SIZE: u64 = 0x1000;
```

**vcpu.rs** — add to `Vm`:
```rust
use crate::virtio_net::VirtioNetDevice;

pub struct Vm {
    pub id: VmId,
    pub vcpu: VCpuContext,
    pub stage2: Stage2PageTable,
    pub state: VmState,
    pub virtio_net: VirtioNetDevice,
}
```

**hypervisor.rs** — in `hvc_vm_create`, after creating the Vm:
```rust
let mac = [0x02, 0x00, 0x00, 0x00, 0x00, vmid.0];
let virtio_net = VirtioNetDevice::new(mac);
let vm = Vm { ..., virtio_net };
```

**hypervisor.rs** — in `handle_data_abort`, after UART check, before unknown-IPA fallthrough:
```rust
use crate::platform::{VIRTIO_NET_MMIO_IPA, VIRTIO_NET_MMIO_SIZE};
use crate::virtio_mmio::MmioResponse;

if (VIRTIO_NET_MMIO_IPA..VIRTIO_NET_MMIO_IPA + VIRTIO_NET_MMIO_SIZE).contains(&ipa) {
    let offset = (ipa - VIRTIO_NET_MMIO_IPA) as u32;
    let vm = self.vms.get_mut(&vmid.0)
        .ok_or(HypervisorError::InvalidVmId(vmid.0 as u64))?;
    let response = vm.virtio_net.handle_mmio(offset, access);
    return match response {
        MmioResponse::ReadValue(val) => Ok(HypervisorAction::MmioResult {
            emit: None, read_value: val, width, srt, pc_advance: 4,
        }),
        MmioResponse::WriteAck | MmioResponse::StatusChanged { .. } => {
            Ok(HypervisorAction::MmioResult {
                emit: None, read_value: 0, width, srt, pc_advance: 4,
            })
        }
        MmioResponse::QueueNotify { queue } => {
            Ok(HypervisorAction::VirtioQueueNotify { vmid, queue, pc_advance: 4 })
        }
    };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-hypervisor`
Expected: All tests pass

- [ ] **Step 5: Run workspace-wide checks**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: Clean

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-hypervisor/src/trap.rs crates/harmony-hypervisor/src/platform/mod.rs \
       crates/harmony-hypervisor/src/vcpu.rs crates/harmony-hypervisor/src/hypervisor.rs
git commit -m "feat(hypervisor): integrate VirtIO MMIO routing and VirtioQueueNotify action"
```

---

## Task 5: End-to-end integration test — Linux virtio-mmio probe + TX packet

**Files:**
- Modify: `crates/harmony-hypervisor/src/hypervisor.rs` (add integration test)

**Context:**
- This test replays the sequence that Linux's `virtio-mmio` driver performs at boot:
  1. Read magic, version, device ID
  2. Write Status lifecycle (ACKNOWLEDGE → DRIVER → FEATURES_OK → DRIVER_OK)
  3. Read/write features
  4. Configure both queues (desc/avail/used addresses, QueueNum, QueueReady)
  5. Write a TX packet descriptor into shared memory
  6. Kick QueueNotify → VirtioQueueNotify action
  7. Call poll_tx() → extract the raw Ethernet frame
- All through the hypervisor's handle() method, proving the full trap path works

- [ ] **Step 1: Write the integration test**

The test creates a VM, starts it, then feeds DataAbort events simulating the guest's virtio-mmio driver init sequence and a TX packet flow.

**Concrete MMIO access sequence (matches Linux `virtio-mmio` driver):**

```
Phase 1: Device Discovery
  READ  0x000 → expect 0x74726976 (magic)
  READ  0x004 → expect 2 (version)
  READ  0x008 → expect 1 (device_id = net)

Phase 2: Status Lifecycle
  WRITE 0x070 = 0 (reset)
  WRITE 0x070 = 1 (ACKNOWLEDGE)
  WRITE 0x070 = 3 (ACKNOWLEDGE | DRIVER)

Phase 3: Feature Negotiation
  WRITE 0x014 = 0 (DeviceFeaturesSel = word 0)
  READ  0x010 → expect has bits 5 (F_MAC) and 16 (F_STATUS)
  WRITE 0x014 = 1 (DeviceFeaturesSel = word 1)
  READ  0x010 → expect has bit 0 (F_VERSION_1)
  WRITE 0x024 = 0 (DriverFeaturesSel = word 0)
  WRITE 0x020 = (1<<5) | (1<<16)  (accept F_MAC + F_STATUS)
  WRITE 0x024 = 1
  WRITE 0x020 = 1  (accept F_VERSION_1)
  WRITE 0x070 = 0xB (FEATURES_OK | DRIVER | ACKNOWLEDGE)
  READ  0x070 → expect 0xB (FEATURES_OK still set)

Phase 4: Queue Configuration (RX = queue 0)
  WRITE 0x030 = 0 (QueueSel = RX)
  READ  0x034 → expect 256 (QueueNumMax)
  WRITE 0x038 = 16 (QueueNum = 16, power of 2)
  WRITE 0x080 = rx_desc_addr_low
  WRITE 0x084 = rx_desc_addr_high
  WRITE 0x090 = rx_avail_addr_low
  WRITE 0x094 = rx_avail_addr_high
  WRITE 0x0A0 = rx_used_addr_low
  WRITE 0x0A4 = rx_used_addr_high
  WRITE 0x044 = 1 (QueueReady)

Phase 5: Queue Configuration (TX = queue 1)
  WRITE 0x030 = 1 (QueueSel = TX)
  (same QueueNum, address, QueueReady sequence as RX)

Phase 6: Driver Ready
  WRITE 0x070 = 0xF (DRIVER_OK | FEATURES_OK | DRIVER | ACKNOWLEDGE)

Phase 7: TX Packet
  Write descriptor into TX shared memory: addr=packet_buf_ipa, len=12+60, flags=0
  Write available ring: idx=1, ring[0]=desc_idx
  WRITE 0x050 = 1 (QueueNotify, queue=TX)
  → expect VirtioQueueNotify { vmid, queue: 1, pc_advance: 4 }

Phase 8: Host reads packet
  Call vm.virtio_net.poll_tx(mem, ipa_to_ptr, &mut out_buf)
  → expect 60 bytes of Ethernet frame (12-byte hdr stripped)
  Verify out_buf matches the original frame data
```

The shared memory region for this test needs:
- RX queue structures (desc table + avail ring + used ring) at known offsets
- TX queue structures at known offsets
- A 72-byte packet buffer (12-byte virtio_net_hdr + 60-byte Ethernet frame)

- [ ] **Step 2: Run test to verify it passes**

Run: `cargo test -p harmony-hypervisor linux_virtio_mmio_probe_and_tx`
Expected: PASS

- [ ] **Step 3: Run workspace-wide checks**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: Clean

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-hypervisor/src/hypervisor.rs
git commit -m "test(hypervisor): add end-to-end Linux virtio-mmio probe + TX packet test"
```

---

## Dependencies

```
Task 1 (VirtQueue)
  ↓
Task 2 (VirtioMmio) ← standalone, but uses AccessType from trap.rs
  ↓
Task 3 (VirtioNetDevice) ← depends on Tasks 1 + 2
  ↓
Task 4 (Hypervisor integration) ← depends on Task 3
  ↓
Task 5 (Integration test) ← depends on Task 4
```

Tasks 1 and 2 could be done in parallel (independent modules), but Task 3 depends on both.
