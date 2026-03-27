# NVMe Driver Phase 1: Controller Init + Identify — Design Spec

## Goal

Implement Phase 1 of a native no_std Rust NVMe driver: controller
initialization, admin queue setup, and Identify Controller command.
Success = reading the controller's model number and serial number from
a 4 KiB identify response, proving the full admin submission/completion
queue round-trip works.

## Background

NVMe controllers use paired ring buffers (submission queues and
completion queues) of fixed-size entries over PCIe MMIO. The driver
writes 64-byte Submission Queue Entries (SQEs), rings a doorbell
register, and the controller writes 16-byte Completion Queue Entries
(CQEs) with a phase bit for wrap detection. This maps directly to the
existing sans-I/O driver pattern used by xHCI and GENET.

Phase 1 covers controller init and the first admin command. Phases 2
(admin queue management) and 3 (block I/O) are tracked as separate
beads: harmony-os-n49 and harmony-os-87r.

## Design Decisions

- **Single file**: `nvme.rs` in `drivers/`, following the GENET pattern.
  Phase 2 can split into a `nvme/` module directory if needed.
- **Direct RegisterBank access**: No action-based API. Simpler than
  xHCI's approach. MockRegisterBank provides full testability.
- **32-bit register pairs for 64-bit regs**: Helper methods on the
  driver, no RegisterBank trait changes.
- **Caller-managed DMA**: The driver builds SQEs and returns them; the
  caller writes to DMA memory and reads CQEs. The driver never touches
  DMA directly.

## NvmeDriver Struct

```rust
pub struct NvmeDriver<R: RegisterBank> {
    bank: R,
    // Capabilities (read once during init)
    max_queue_entries: u16,  // CAP.MQES + 1
    doorbell_stride: u8,     // CAP.DSTRD (in 32-bit units)
    timeout_ms: u32,         // CAP.TO * 500
    // Admin queue state
    admin_sq_tail: u16,
    admin_cq_head: u16,
    admin_cq_phase: bool,
    admin_sq_phys: u64,
    admin_cq_phys: u64,
    admin_queue_size: u16,
    // Command tracking
    next_cid: u16,
    // State
    state: NvmeState,
}

pub enum NvmeState {
    Uninitialized,
    Disabled,    // CC.EN=0, CSTS.RDY=0
    Enabled,     // CC.EN=1, CSTS.RDY=1
}
```

## Register Map

| Offset | Size | Register | Purpose |
|--------|------|----------|---------|
| 0x00 | 8 | CAP | Controller Capabilities |
| 0x08 | 4 | VS | Version |
| 0x14 | 4 | CC | Controller Configuration |
| 0x1C | 4 | CSTS | Controller Status |
| 0x24 | 4 | AQA | Admin Queue Attributes |
| 0x28 | 8 | ASQ | Admin Submission Queue Base |
| 0x30 | 8 | ACQ | Admin Completion Queue Base |
| 0x1000+ | 4 | Doorbells | SQ tail / CQ head doorbells |

Doorbell offset: `0x1000 + (2 * qid + is_cq) * (4 << doorbell_stride)`.

64-bit registers (CAP, ASQ, ACQ) accessed as two 32-bit reads/writes
(low then high).

## Init Sequence

```rust
pub fn init(bank: R) -> Result<Self, NvmeError>
```

Follows NVMe spec §7.6.1:

1. Read **CAP** (64-bit at 0x00): extract MQES (bits 15:0), TO (bits
   31:24), DSTRD (bits 35:32), CSS (bits 44:37).
2. Verify CSS supports NVM command set (bit 0). Error if not.
3. Read **VS** (0x08): sanity check version ≥ 1.0 (non-fatal).
4. Disable controller: write CC.EN=0 (0x14). Poll CSTS.RDY (0x1C bit 0)
   until clear. Timeout after CAP.TO × 500ms.
5. Return driver in `Disabled` state.

## Admin Queue Setup

```rust
pub fn setup_admin_queue(
    &mut self,
    sq_phys: u64,
    cq_phys: u64,
    queue_size: u16,
) -> Result<(), NvmeError>
```

Caller allocates zeroed DMA memory: `queue_size * 64` bytes for SQ,
`queue_size * 16` bytes for CQ.

1. Verify state is `Disabled`.
2. Clamp `queue_size` to `max_queue_entries`.
3. Write **AQA** (0x24): `(size-1) << 16 | (size-1)`.
4. Write **ASQ** (0x28, 64-bit): `sq_phys`.
5. Write **ACQ** (0x30, 64-bit): `cq_phys`.
6. Write **CC** (0x14): EN=1, CSS=0, MPS=0, IOSQES=6, IOCQES=4.
   Value: `0x0046_0001`.
7. Poll **CSTS.RDY** until set. Timeout after CAP.TO × 500ms.
8. Set state to `Enabled`.

## Identify Controller Command

```rust
pub fn identify_controller(
    &mut self,
    data_phys: u64,
) -> Result<AdminCommand, NvmeError>
```

Returns an `AdminCommand` for the caller to execute:

```rust
pub struct AdminCommand {
    pub sqe: [u8; 64],
    pub sq_offset: u64,
    pub doorbell_offset: usize,
    pub doorbell_value: u32,
}
```

The caller writes `sqe` to DMA at `admin_sq_phys + sq_offset`, then
writes `doorbell_value` to the register at `doorbell_offset`.

### SQE Layout (64 bytes)

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 4 | CDW0 | opcode=0x06, CID=next_cid |
| 4 | 4 | NSID | 0 |
| 24 | 8 | PRP1 | data_phys |
| 40 | 4 | CDW10 | CNS=0x01 |
| rest | — | — | 0 |

CDW0 format: `opcode | (cid << 16)`.

## Completion Checking

```rust
pub fn check_completion(
    &mut self,
    cqe_bytes: &[u8; 16],
) -> Result<Option<CompletionResult>, NvmeError>
```

The caller reads 16 bytes from `admin_cq_phys + admin_cq_head * 16`
and passes them in.

```rust
pub struct Completion {
    pub cid: u16,
    pub status: u16,
    pub result: u32,
}
```

### CQE Layout (16 bytes)

| Offset | Size | Field | Purpose |
|--------|------|-------|---------|
| 0 | 4 | DW0 | Command-specific result |
| 8 | 2 | SQ Head | SQ head pointer |
| 12 | 2 | CID | Matches SQE CDW0.CID |
| 14 | 2 | Status | Bit 0 = phase, bits 15:1 = status |

Phase bit detection: if `status & 1 == admin_cq_phase`, the CQE is
valid. Returns `None` on phase mismatch. On valid completion, advances
`admin_cq_head`, inverts phase on wrap, and returns `Some(Completion)`
with the CQ head doorbell info for the caller to ring.

Completion includes doorbell info:

```rust
pub struct CompletionResult {
    pub completion: Completion,
    pub cq_doorbell_offset: usize,
    pub cq_doorbell_value: u32,
}
```

## Identify Response Parsing

```rust
pub fn parse_identify_controller(data: &[u8; 4096]) -> IdentifyController
```

Pure function — no driver state needed.

```rust
pub struct IdentifyController {
    pub serial_number: [u8; 20],    // bytes 4-23
    pub model_number: [u8; 40],     // bytes 24-63
    pub firmware_rev: [u8; 8],      // bytes 64-71
    pub max_data_transfer: u8,      // byte 77 (MDTS)
    pub num_namespaces: u32,        // bytes 516-519 (NN)
}
```

## Error Type

```rust
pub enum NvmeError {
    Timeout,
    UnsupportedCommandSet,
    InvalidState,
    CommandFailed { status: u16 },
    NoCompletion,
}
```

## New File

`crates/harmony-unikernel/src/drivers/nvme.rs`

## Modified File

`crates/harmony-unikernel/src/drivers/mod.rs` — add `pub mod nvme;`

## Testing

All tests use MockRegisterBank — no hardware needed.

- Init reads capabilities: mock CAP/VS/CSTS, verify parsed MQES,
  doorbell_stride, timeout
- Init disables controller: mock CC/CSTS, verify CC.EN=0 written,
  CSTS.RDY=0 polled
- Init times out: mock CSTS never clearing, verify Timeout error
- Init rejects unsupported CSS: mock CAP with CSS bit 0 clear, verify
  UnsupportedCommandSet
- Admin queue setup writes correct registers: verify AQA, ASQ lo/hi,
  ACQ lo/hi, CC values
- Admin queue clamps size to MQES: init with MQES=32, request 256,
  verify AQA uses 31
- Admin queue rejects wrong state: call before init, verify InvalidState
- Identify controller builds correct SQE: verify opcode, CNS, CID,
  PRP1 fields
- Identify controller doorbell: verify tail advances, doorbell offset
  correct
- Completion detects phase match: build CQE with matching phase, verify
  Some(Completion)
- Completion rejects phase mismatch: wrong phase, verify None
- Completion advances head and inverts phase on wrap
- Parse identify extracts fields: fake 4 KiB buffer with known
  serial/model/firmware

## Out of Scope

- I/O queue creation (Phase 2 — harmony-os-n49)
- Block read/write commands (Phase 3 — harmony-os-87r)
- Interrupt coalescing (MSI-X)
- Multi-namespace support
- Error recovery / controller reset
- PCIe BAR discovery / config space
- Power management (APST)
- NVMe over Fabrics
