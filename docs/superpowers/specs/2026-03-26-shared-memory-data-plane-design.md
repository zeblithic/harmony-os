# Shared Memory Data Plane — VirtIO-Compatible Ring Buffers

**Date:** 2026-03-26
**Status:** Draft
**Bead:** harmony-os-48g
**Follow-ups:** harmony-os-rl0 (netstack integration), harmony-os-fej (9P VmServer)

## Problem

The EL2 micro-VM runs unmodified Linux WiFi drivers. Packets produced by the guest's network stack need to reach the Harmony host — and vice versa — through shared memory. This spec defines the data plane: VirtIO-compatible split virtqueues with MMIO transport emulation, giving the guest Linux kernel a standard `virtio-net` device it can drive without custom code.

## Constraints

- **Sans-I/O.** All VirtIO logic is pure Rust operating on `&mut [u8]` slices. No hardware access.
- **VirtIO-compatible subset.** Enough for Linux's `virtio-net` driver in simplest mode. No indirect descriptors, no event index, no packed ring, no GSO, no checksum offload, no multiqueue.
- **Lives in `harmony-hypervisor`.** These are internal modules — not a separate crate. The hypervisor routes MMIO traps to the VirtIO device model.
- **`HVC_VM_MAP` is sufficient.** The shared memory region is a physical range mapped into both host and guest address spaces. No new hypervisor primitives needed.

## Architecture

```
Guest Linux
  virtio-net driver ←→ virtio-mmio transport
       ↓ (Stage-2 data abort)
Hypervisor (EL2)
  handle_data_abort → VirtioNetDevice.handle_mmio()
       ↓ (QueueNotify)
  HypervisorAction::VirtioQueueNotify { vmid, queue }
       ↓
Host Microkernel (EL1)
  VirtioNetDevice.poll_tx(mem, out_buf) → raw Ethernet frame
  VirtioNetDevice.push_rx(frame, mem) → guest receives packet
```

The MMIO register accesses are trapped via Stage-2 (same mechanism as the virtual UART). The actual packet data flows through shared memory virtqueues — never through the trap path.

### Address Space Convention

The shared memory region is mapped at a **fixed IPA** that is also identity-mapped on the host side. Both guest and host access the same physical pages. Descriptor `addr` fields in the virtqueue are guest IPAs within this shared region — the caller translates them using the known base offset: `host_va = shared_region_host_base + (descriptor_ipa - shared_region_guest_ipa)`. The `poll_tx` and `push_rx` methods take an `ipa_to_ptr` callback that encapsulates this translation.

## File Layout

New files in `crates/harmony-hypervisor/`:

| File | Responsibility |
|------|---------------|
| `src/virtqueue.rs` | Split virtqueue: descriptor table, available/used rings |
| `src/virtio_mmio.rs` | VirtIO MMIO transport: register emulation, device config space |
| `src/virtio_net.rs` | VirtIO net device: TX/RX queues, `virtio_net_hdr`, frame extraction |

Modified:
- `src/hypervisor.rs` — IPA routing for VirtIO MMIO, `VirtioQueueNotify` action
- `src/trap.rs` — new `VirtioQueueNotify` action variant
- `src/vcpu.rs` — `Vm` gains `VirtioNetDevice`
- `src/platform/mod.rs` — VirtIO MMIO IPA constant
- `src/lib.rs` — new module declarations

## VirtQueue (Split Virtqueue)

Implements VirtIO 1.2 §2.7.1 split virtqueue over a `&mut [u8]` region.

### Memory Layout

Per VirtIO 1.2 §2.7.6 and §2.7.8:

```
[Descriptor Table: 16 bytes × queue_size]
[Available Ring: 6 + 2 × queue_size bytes]
    (flags: u16, idx: u16, ring[queue_size]: u16, used_event: u16)
[padding to next page boundary]
[Used Ring: 6 + 8 × queue_size bytes]
    (flags: u16, idx: u16, ring[queue_size]: {id: u32, len: u32}, avail_event: u16)
```

The `used_event` and `avail_event` fields are always present in the struct layout even though we don't use `VIRTIO_F_EVENT_IDX`. Linux writes the full struct regardless of feature negotiation.

### Descriptor Format (16 bytes)

```rust
pub struct Descriptor {
    pub addr: u64,     // Guest IPA of buffer (within shared memory region)
    pub len: u32,      // Buffer length
    pub flags: u16,    // NEXT=1, WRITE=2, INDIRECT=4
    pub next: u16,     // Next descriptor in chain (if NEXT set)
}
```

Indirect descriptors (`flags & 4`) are rejected with an error — out of scope.

### Interface

```rust
pub struct VirtQueue {
    queue_size: u16,
    desc_offset: usize,
    avail_offset: usize,
    used_offset: usize,
    last_avail_idx: u16,
}

impl VirtQueue {
    /// Create a virtqueue over a shared memory region.
    /// Validates that the layout fits within the region and that
    /// queue_size is a power of 2 and ≤ MAX_QUEUE_SIZE (256).
    pub fn new(queue_size: u16, desc_offset: usize, avail_offset: usize,
               used_offset: usize) -> Result<Self, VirtQueueError>;

    /// Pop the next available descriptor chain from the guest.
    /// Returns the head descriptor index and a DescriptorChain iterator,
    /// or None if no new descriptors are available.
    pub fn pop_available(&mut self, mem: &[u8]) -> Option<(u16, DescriptorChain)>;

    /// Push a completed descriptor back to the used ring.
    /// `desc_id` is the head index returned by `pop_available`.
    pub fn push_used(&self, mem: &mut [u8], desc_id: u16, bytes_written: u32);

    /// Check if the guest wants a notification (interrupt).
    pub fn needs_notification(&self, mem: &[u8]) -> bool;
}
```

`DescriptorChain` iterates over chained descriptors:

```rust
pub struct DescriptorChain {
    head: u16,
    next: Option<u16>,
    queue_size: u16,
    desc_offset: usize,
}

impl DescriptorChain {
    /// The head descriptor index (pass this to push_used when done).
    pub fn head_id(&self) -> u16 { self.head }

    /// Advance to the next descriptor in the chain.
    /// Stops after `queue_size` hops to prevent infinite loops from
    /// malicious or corrupted descriptor chains (cycle detection).
    pub fn next(&mut self, mem: &[u8]) -> Result<Option<Descriptor>, VirtQueueError>;
}
```

### Error Type

```rust
pub enum VirtQueueError {
    /// Queue size is not a power of 2, or exceeds maximum (256).
    InvalidQueueSize(u16),
    /// Region too small for the requested queue layout.
    RegionTooSmall { needed: usize, available: usize },
    /// Descriptor has INDIRECT flag set (unsupported).
    IndirectNotSupported,
    /// Descriptor chain exceeds queue_size (cycle or corruption).
    ChainTooLong,
}
```

## VirtIO MMIO Transport

Emulates VirtIO 1.2 §4.2.2 MMIO register interface, including device config space.

### Register Map

| Offset | Name | R/W | Value |
|--------|------|-----|-------|
| 0x000 | MagicValue | R | `0x74726976` |
| 0x004 | Version | R | `2` |
| 0x008 | DeviceID | R | `1` (net) |
| 0x00C | VendorID | R | `0x4856` |
| 0x010 | DeviceFeatures | R | Per DeviceFeaturesSel |
| 0x014 | DeviceFeaturesSel | W | Feature word selector |
| 0x020 | DriverFeatures | W | Guest-accepted features |
| 0x024 | DriverFeaturesSel | W | Feature word selector |
| 0x030 | QueueSel | W | Queue index (0=RX, 1=TX) |
| 0x034 | QueueNumMax | R | 256 |
| 0x038 | QueueNum | W | Actual queue size (validated ≤ 256, power of 2) |
| 0x044 | QueueReady | R/W | Queue ready flag |
| 0x050 | QueueNotify | W | Queue kick (written value = queue index per VirtIO 1.2 §4.2.2) |
| 0x060 | InterruptStatus | R | Pending interrupt bits |
| 0x064 | InterruptACK | W | Acknowledge interrupts |
| 0x070 | Status | R/W | Device status |
| 0x080 | QueueDescLow | W | Descriptor table addr [31:0] |
| 0x084 | QueueDescHigh | W | Descriptor table addr [63:32] |
| 0x090 | QueueAvailLow | W | Available ring addr [31:0] |
| 0x094 | QueueAvailHigh | W | Available ring addr [63:32] |
| 0x0A0 | QueueUsedLow | W | Used ring addr [31:0] |
| 0x0A4 | QueueUsedHigh | W | Used ring addr [63:32] |
| 0x0FC | ConfigGeneration | R | `0` (config is static) |
| 0x100+ | Config Space | R | Device-specific config (see below) |

### Config Space Layout (virtio-net)

Starting at offset 0x100, per VirtIO 1.2 §5.1.4:

| Config Offset | Field | Size | Value |
|--------------|-------|------|-------|
| 0x100-0x105 | mac[0..6] | 6 bytes | Device MAC address |
| 0x106-0x107 | status | 2 bytes | `VIRTIO_NET_S_LINK_UP` (1) |

Read byte-by-byte by the guest driver. Linux reads `mac` when `VIRTIO_NET_F_MAC` is negotiated, and `status` when `VIRTIO_NET_F_STATUS` is negotiated.

### State Machine

```rust
pub struct VirtioMmio {
    device_id: u32,
    device_features: u64,
    driver_features: u64,
    status: u32,
    queue_sel: u32,
    queues: [QueueConfig; 2],
    interrupt_status: u32,
    device_features_sel: u32,
    driver_features_sel: u32,
    /// Device config space (MAC + link status).
    config: [u8; 8],
}

pub struct QueueConfig {
    pub num: u16,
    pub ready: bool,
    pub desc_addr: u64,
    pub avail_addr: u64,
    pub used_addr: u64,
}
```

### Response Type

```rust
pub enum MmioResponse {
    /// Register read — value to return to guest.
    ReadValue(u64),
    /// Write consumed, resume guest.
    WriteAck,
    /// Guest kicked a queue — host should process descriptors.
    QueueNotify { queue: u16 },
    /// Guest changed device status (for lifecycle tracking).
    StatusChanged { status: u32 },
}
```

**Note on `MmioResult` construction:** `MmioResponse` intentionally does not carry `width`, `srt`, or `pc_advance` — these come from the `TrapEvent::DataAbort` context in the caller (`handle_data_abort`). The caller combines `MmioResponse` with the trap metadata to produce the full `HypervisorAction::MmioResult`.

### Features Offered

```rust
const VIRTIO_NET_F_MAC: u64 = 1 << 5;       // Device has MAC address
const VIRTIO_NET_F_STATUS: u64 = 1 << 16;    // Link status available
const VIRTIO_F_VERSION_1: u64 = 1 << 32;     // VirtIO 1.0+ compliance
```

No checksum offload (`F_CSUM`), no GSO (`F_HOST_TSO4`), no multiqueue (`F_MQ`).

## VirtIO Net Device

```rust
pub struct VirtioNetDevice {
    pub mmio: VirtioMmio,
    pub mac: [u8; 6],
}
```

### virtio_net_hdr_v1 (12 bytes)

With `VIRTIO_F_VERSION_1` negotiated, Linux uses the 12-byte `virtio_net_hdr_v1`:

```rust
#[repr(C)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,       // Always GSO_NONE (0)
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,    // Set by device on RX, ignored on TX
}
```

Always 12 bytes. `gso_type = 0`, `num_buffers = 1` on RX (we never merge buffers).

### Packet Operations

```rust
impl VirtioNetDevice {
    /// Create a new VirtIO net device with the given MAC address.
    pub fn new(mac: [u8; 6]) -> Self;

    /// Extract the next transmitted Ethernet frame from the TX queue.
    /// Writes the frame (with 12-byte virtio_net_hdr stripped) into `out_buf`.
    /// Returns the number of bytes written, or None if no packets pending.
    pub fn poll_tx(
        &mut self,
        mem: &mut [u8],
        ipa_to_ptr: fn(u64) -> *const u8,
        out_buf: &mut [u8],
    ) -> Option<usize>;

    /// Inject a received Ethernet frame into the RX queue.
    /// Prepends the 12-byte virtio_net_hdr (zeroed, GSO_NONE, num_buffers=1).
    /// Returns false if the RX queue is full (no available buffers).
    pub fn push_rx(
        &mut self,
        frame: &[u8],
        mem: &mut [u8],
        ipa_to_ptr: fn(u64) -> *mut u8,
    ) -> bool;

    /// Handle an MMIO register access. Delegates to self.mmio,
    /// with config space reads returning MAC and link status.
    pub fn handle_mmio(
        &mut self,
        offset: u32,
        access: AccessType,
    ) -> MmioResponse;
}
```

## Hypervisor Integration

### New IPA Constant

```rust
// platform/mod.rs
pub const VIRTIO_NET_MMIO_IPA: u64 = 0x0A00_0000;
pub const VIRTIO_NET_MMIO_SIZE: u64 = 0x1000;
```

### New Action Variant

```rust
// trap.rs
pub enum HypervisorAction {
    // ... existing variants ...
    /// Guest kicked a VirtIO queue — host should process pending descriptors.
    /// The platform shim must advance ELR_EL2 by `pc_advance` bytes
    /// (QueueNotify is a store instruction that faulted) and resume the guest.
    VirtioQueueNotify { vmid: VmId, queue: u16, pc_advance: u8 },
}
```

### Data Abort Routing

In `handle_data_abort`, after UART check. `width`, `srt`, and `pc_advance` come from the `TrapEvent::DataAbort` context, not from `MmioResponse`:

```rust
if (VIRTIO_NET_MMIO_IPA..VIRTIO_NET_MMIO_IPA + VIRTIO_NET_MMIO_SIZE).contains(&ipa) {
    let offset = (ipa - VIRTIO_NET_MMIO_IPA) as u32;
    let vm = self.vms.get_mut(&vmid.0).ok_or(...)?;
    let response = vm.virtio_net.handle_mmio(offset, access);
    return match response {
        MmioResponse::ReadValue(val) => Ok(HypervisorAction::MmioResult {
            emit: None, read_value: val, width, srt, pc_advance: 4,
        }),
        MmioResponse::WriteAck => Ok(HypervisorAction::MmioResult {
            emit: None, read_value: 0, width, srt, pc_advance: 4,
        }),
        MmioResponse::QueueNotify { queue } => Ok(HypervisorAction::VirtioQueueNotify {
            vmid, queue, pc_advance: 4,
        }),
        MmioResponse::StatusChanged { .. } => Ok(HypervisorAction::MmioResult {
            emit: None, read_value: 0, width, srt, pc_advance: 4,
        }),
    };
}
```

### Vm Struct Change

```rust
pub struct Vm {
    pub id: VmId,
    pub vcpu: VCpuContext,
    pub stage2: Stage2PageTable,
    pub state: VmState,
    pub virtio_net: VirtioNetDevice,
}
```

## RX Notification Limitation

**Phase 1 does not support virtual interrupt injection** (that requires GIC virtualization, harmony-os-04p). This means:

- **TX works fully:** guest writes packet → QueueNotify trap → host processes queue.
- **RX is polling-only:** after `push_rx()` places a frame in the used ring, the guest discovers it the next time it polls (NAPI polling runs on TX completions and timer ticks). If the guest is completely idle with no TX traffic, RX packets will be delayed until the next timer-driven poll.

This is acceptable for Phase 1 because:
1. WiFi is bidirectional — TX traffic triggers NAPI polling which drains RX.
2. Linux's `virtio-net` uses NAPI with a timer fallback, so RX is never permanently stuck.
3. GIC interrupt injection (follow-up bead harmony-os-04p) will eliminate the polling delay.

## Testing Strategy

| Layer | What | How |
|-------|------|-----|
| VirtQueue unit | Descriptor parsing, index wrapping, full/empty, chained descriptors, INDIRECT rejection, head_id tracking | Heap-backed `Vec<u8>`, manually write descriptor tables |
| VirtioMmio unit | Register read/write sequences, device status state machine, queue configuration, config space reads (MAC + status) | Feed offset + access, verify state transitions and read values |
| VirtioNet unit | TX frame extraction (12-byte hdr strip), RX frame injection (12-byte hdr prepend), `num_buffers` field | Configured device + fake shared memory |
| Integration | Full Linux `virtio-mmio` probe → queue setup → TX packet → host reads frame | Replay Linux driver init sequence, verify extracted Ethernet frame |

All testable with `cargo test` — no hardware, no QEMU.

## Out of Scope

- `harmony-netstack` / `FrameBuffer` integration (harmony-os-rl0)
- 9P VmServer control plane (harmony-os-fej)
- Packed virtqueue (VirtIO 1.2 §2.8)
- Indirect descriptors
- Event index (VIRTIO_F_EVENT_IDX)
- Checksum offload (VIRTIO_NET_F_CSUM)
- GSO / TSO (VIRTIO_NET_F_HOST_TSO4)
- Multiqueue (VIRTIO_NET_F_MQ)
- Virtual interrupt injection (needs GIC, harmony-os-04p) — RX is polling-only
