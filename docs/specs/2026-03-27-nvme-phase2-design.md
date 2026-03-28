# NVMe Driver Phase 2: Admin Queue Commands — Design Spec

## Goal

Extend the Phase 1 NVMe driver with I/O queue creation, namespace
identification, and a reusable queue pair abstraction. Success = the
driver can create one I/O SQ+CQ pair, identify namespace 1, and report
the namespace size and LBA block size — proving the admin command
pipeline works for arbitrary commands, not just Identify Controller.

## Background

Phase 1 (harmony-os-yig) established the sans-I/O NVMe driver pattern:
`NvmeDriver<R: RegisterBank>` initializes the controller, sets up the
admin queue, and issues an Identify Controller command. All DMA is
caller-managed — the driver builds SQEs and returns `AdminCommand`
structs for the caller to execute.

Phase 2 extends the admin command pipeline with the three commands
required before block I/O: Create I/O Completion Queue, Create I/O
Submission Queue, and Identify Namespace. Phase 3 (harmony-os-87r)
will use the I/O queues to issue Read/Write commands.

## Design Decisions

- **QueuePair abstraction**: Extract a reusable `QueuePair` struct from
  the inline admin queue fields. The admin queue becomes `QueuePair`
  qid=0, I/O queues use the same struct. Eliminates duplicated
  tail/head/phase tracking.
- **Single I/O queue pair**: One SQ+CQ pair (qid=1). The unikernel has
  one core — multi-queue adds complexity with no benefit. Follow-up
  bead harmony-os-q93 tracks multi-queue support.
- **Minimum command set**: Create I/O CQ, Create I/O SQ, Identify
  Namespace. No Get/Set Features (harmony-os-dd4), no Delete/Abort
  (harmony-os-chv). YAGNI — defaults work for basic I/O.
- **Minimum namespace parsing**: NSZE, NCAP, NUSE, FLBAS, derived
  lba_size_bytes. No thin provisioning, no data protection. Just what
  Phase 3 needs for Read/Write LBA addressing.
- **New Ready state**: `Enabled → create_io_queues() → Ready`. Gates
  Phase 3 operations. Admin commands remain available in both Enabled
  and Ready states.
- **Single file**: Everything stays in `nvme.rs`. Phase 1 is ~817 lines,
  Phase 2 adds ~400. ~1200 lines is within reason for a driver module.
  Phase 3 is the natural split point if needed.

## QueuePair Struct

```rust
pub struct QueuePair {
    qid: u16,
    sq_tail: u16,
    cq_head: u16,
    cq_phase: bool,
    sq_phys: u64,
    cq_phys: u64,
    size: u16,
}
```

### Methods

```rust
impl QueuePair {
    pub fn new(qid: u16, sq_phys: u64, cq_phys: u64, size: u16) -> Self

    /// Build an AdminCommand from a 64-byte SQE.
    /// Computes sq_offset, advances tail (wrapping), returns doorbell info.
    pub fn submit(
        &mut self,
        sqe: [u8; 64],
        doorbell_stride: u8,
    ) -> AdminCommand

    /// Parse a 16-byte CQE. Returns Some(CompletionResult) on phase
    /// match, None on mismatch. Advances head, inverts phase on wrap.
    pub fn check_completion(
        &mut self,
        cqe: &[u8; 16],
        doorbell_stride: u8,
    ) -> Option<CompletionResult>
}
```

The existing `NvmeDriver::identify_controller()` and
`NvmeDriver::check_completion()` delegate to the admin `QueuePair`.
The driver-level methods are kept as thin wrappers that preserve the
existing public signatures:

```rust
// Wrapper preserves Result<Option<...>> return type from Phase 1.
pub fn check_completion(
    &mut self,
    cqe_bytes: &[u8; 16],
) -> Result<Option<CompletionResult>, NvmeError> {
    Ok(self.admin.check_completion(cqe_bytes, self.doorbell_stride))
}
```

Public API unchanged — all 13 Phase 1 tests pass without modification.

## NvmeDriver Struct Changes

```rust
pub struct NvmeDriver<R: RegisterBank> {
    bank: R,
    max_queue_entries: u16,
    doorbell_stride: u8,
    timeout_ms: u32,
    next_cid: u16,
    state: NvmeState,
    admin: QueuePair,           // qid=0
    io: Option<QueuePair>,      // qid=1, populated by activate_io_queues()
}

pub enum NvmeState {
    Uninitialized,
    Disabled,    // CC.EN=0, CSTS.RDY=0
    Enabled,     // CC.EN=1, CSTS.RDY=1, admin queue active
    Ready,       // I/O queues created and active
}
```

State transitions:
```
Uninitialized → init() → Disabled → setup_admin_queue() → Enabled
    → create_io_queues() + activate_io_queues() → Ready
```

All admin commands (`identify_controller`, `identify_namespace`,
`create_io_cq`, `create_io_sq`) accept both `Enabled` and `Ready`
states. Phase 1's `identify_controller()` state guard must be updated
from `state != Enabled` to `state != Enabled && state != Ready`.

## New Admin Commands

All require `Enabled` or `Ready` state. All follow the same pattern:
build 64-byte SQE, submit via admin `QueuePair`, return `AdminCommand`.

### Create I/O Completion Queue (opcode 0x05)

```rust
pub fn create_io_cq(
    &mut self,
    cq_phys: u64,
    size: u16,
) -> Result<AdminCommand, NvmeError>
```

SQE layout:

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 4 | CDW0 | opcode=0x05, CID=next_cid |
| 24 | 8 | PRP1 | cq_phys |
| 40 | 4 | CDW10 | QID=1 \| (size-1) << 16 |
| 44 | 4 | CDW11 | PC=1 \| IEN=1 \| IV=0 |
| rest | — | — | 0 |

CDW11 value: `0x0000_0003` (PC=bit0, IEN=bit1, IV=bits 31:16 = 0).

### Create I/O Submission Queue (opcode 0x01)

```rust
pub fn create_io_sq(
    &mut self,
    sq_phys: u64,
    size: u16,
) -> Result<AdminCommand, NvmeError>
```

SQE layout:

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 4 | CDW0 | opcode=0x01, CID=next_cid |
| 24 | 8 | PRP1 | sq_phys |
| 40 | 4 | CDW10 | QID=1 \| (size-1) << 16 |
| 44 | 4 | CDW11 | CQID=1 << 16 \| PC=1 |
| rest | — | — | 0 |

CDW11 value: `0x0001_0001` (PC=bit0, CQID=bits 31:16 = 1).

The CQ must be created before the SQ (NVMe spec requires the associated
CQ to exist).

### Identify Namespace (opcode 0x06, CNS=0)

```rust
pub fn identify_namespace(
    &mut self,
    nsid: u32,
    data_phys: u64,
) -> Result<AdminCommand, NvmeError>
```

SQE layout:

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 4 | CDW0 | opcode=0x06, CID=next_cid |
| 4 | 4 | NSID | nsid |
| 24 | 8 | PRP1 | data_phys |
| 40 | 4 | CDW10 | CNS=0x00 |
| rest | — | — | 0 |

### Convenience: create_io_queues()

```rust
pub fn create_io_queues(
    &mut self,
    sq_phys: u64,
    cq_phys: u64,
    size: u16,
) -> Result<[AdminCommand; 2], NvmeError>
```

Returns `[create_io_cq_cmd, create_io_sq_cmd]`. Requires `Enabled`
state. Clamps `size` to `max_queue_entries`.

After the caller executes both commands and confirms successful
completions, the caller calls:

```rust
pub fn activate_io_queues(
    &mut self,
    sq_phys: u64,
    cq_phys: u64,
    size: u16,
) -> Result<(), NvmeError>
```

This constructs `QueuePair::new(1, sq_phys, cq_phys, size)`, stores
it in `self.io`, and transitions to `Ready`. The split between
`create_io_queues()` (build commands) and `activate_io_queues()`
(record success) preserves the sans-I/O contract: the driver never
assumes commands succeeded until told.

## Identify Namespace Response Parser

```rust
pub fn parse_identify_namespace(data: &[u8; 4096]) -> IdentifyNamespace

pub struct IdentifyNamespace {
    pub nsze: u64,           // bytes 0-7: namespace size in logical blocks
    pub ncap: u64,           // bytes 8-15: namespace capacity
    pub nuse: u64,           // bytes 16-23: namespace utilization
    pub flbas: u8,           // byte 26, raw value (use bits 3:0 as LBA format index)
    pub lba_size_bytes: u32, // derived: 2^(LBAF[flbas].LBADS)
}
```

LBA Format table starts at byte 128. Each entry is 4 bytes. `flbas &
0x0F` indexes into the table. Byte 2 of each entry is `LBADS` (LBA
Data Size as a power of 2). `lba_size_bytes = 1 << lbads`.

Pure function — no driver state needed.

## Error Type

No new variants. Existing `NvmeError` covers all Phase 2 cases:
- `InvalidState` — wrong state for requested operation
- `Timeout` — poll_ready failures
- `CommandFailed { status }` — controller rejects a command
- `NoCompletion` — no CQE available

## Modified File

`crates/harmony-unikernel/src/drivers/nvme.rs`

## Testing

All tests use MockRegisterBank — no hardware needed.

### QueuePair unit tests
- submit computes correct sq_offset and advances tail
- submit wraps tail at queue boundary
- check_completion returns Some on phase match
- check_completion returns None on phase mismatch
- check_completion advances head, inverts phase on wrap
- Existing 13 Phase 1 tests pass unchanged (same public API)

### Create I/O CQ tests
- Correct SQE: opcode=0x05, QID=1, size, PC=1, IEN=1, PRP1
- Doorbell advances on admin SQ
- Rejects non-Enabled state

### Create I/O SQ tests
- Correct SQE: opcode=0x01, QID=1, CQID=1, PC=1, PRP1
- Doorbell advances on admin SQ

### create_io_queues tests
- Returns two commands: CQ first, SQ second
- Clamps size to max_queue_entries
- Rejects non-Enabled state

### activate_io_queues tests
- Stores QueuePair, transitions to Ready
- Rejects double activation
- Rejects non-Enabled state

### Identify Namespace tests
- Correct SQE: opcode=0x06, CNS=0, NSID field set
- Different NSIDs produce different SQEs
- Rejects Disabled state

### parse_identify_namespace tests
- Extracts NSZE, NCAP, NUSE, FLBAS from known buffer
- Derives lba_size_bytes=512 (LBADS=9)
- Derives lba_size_bytes=4096 (LBADS=12)

## Out of Scope

- Block I/O Read/Write commands (Phase 3 — harmony-os-87r)
- Get/Set Features (harmony-os-dd4)
- Delete I/O Queues, Abort, Firmware (harmony-os-chv)
- Multiple I/O queue pairs (harmony-os-q93)
- Interrupt coalescing (MSI-X)
- Multi-namespace support
- Scatter-gather PRP lists
- Controller reset / error recovery
