# NVMe Driver Phase 3: Block I/O — Design Spec

## Goal

Add Read, Write, and Flush NVM I/O commands to the NVMe driver,
enabling single-block transfers through the I/O queue pair created in
Phase 2. Success = the driver can build Read/Write/Flush SQEs, submit
them via the I/O queue, and check completions — proving the full block
I/O round-trip works end-to-end.

## Background

Phase 1 (harmony-os-yig) established controller init and the Identify
Controller admin command. Phase 2 (harmony-os-n49) added the QueuePair
abstraction, I/O queue creation, and Identify Namespace. The driver is
now in `NvmeState::Ready` with both admin (qid=0) and I/O (qid=1)
queue pairs active.

Phase 3 adds the NVM I/O commands that use the I/O queue pair for
actual block storage. These are the first commands to go through the
I/O submission/completion queues rather than the admin queues.

## Design Decisions

- **Read + Write + Flush scope**: Three NVM I/O commands. No TRIM
  (harmony-os-ebp) or Write Zeroes. Flush ensures data integrity
  without adding significant complexity.
- **Single-PRP transfers**: Each Read/Write transfers exactly one LBA
  block using PRP1 only. No PRP2, no PRP lists. Max transfer = one
  block (512 or 4096 bytes). Multi-block transfers tracked in
  harmony-os-9vj.
- **Separate check_io_completion()**: New method for I/O queue
  completions, distinct from the admin `check_completion()`. Explicit
  API — caller always knows which queue they're checking.
- **Reuse AdminCommand struct**: The return type is the same SQE +
  doorbell info struct used by admin commands. The name is a Phase 1
  carryover but the struct is queue-agnostic.
- **Single file**: Everything stays in `nvme.rs`. Phase 2 is ~1450
  lines, Phase 3 adds ~200. ~1650 lines is the upper bound before
  considering a module split.

## I/O Command Builders

All three require `NvmeState::Ready`. All submit via `self.io`
QueuePair (not admin). All use `self.next_cid` for command IDs
(shared counter with admin commands — CIDs only need uniqueness
within a submission queue).

### Read (opcode 0x02)

```rust
pub fn read_block(
    &mut self,
    nsid: u32,
    lba: u64,
    data_phys: u64,
) -> Result<AdminCommand, NvmeError>
```

SQE layout:

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 4 | CDW0 | opcode=0x02, CID=next_cid |
| 4 | 4 | NSID | nsid |
| 24 | 8 | PRP1 | data_phys |
| 40 | 4 | CDW10 | Starting LBA (low 32 bits) |
| 44 | 4 | CDW11 | Starting LBA (high 32 bits) |
| 48 | 4 | CDW12 | NLB=0 (0-based, meaning 1 block) |
| rest | — | — | 0 |

### Write (opcode 0x01)

```rust
pub fn write_block(
    &mut self,
    nsid: u32,
    lba: u64,
    data_phys: u64,
) -> Result<AdminCommand, NvmeError>
```

SQE layout: identical to Read except opcode=0x01.

### Flush (opcode 0x00)

```rust
pub fn flush(&mut self, nsid: u32) -> Result<AdminCommand, NvmeError>
```

SQE layout:

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 4 | CDW0 | opcode=0x00, CID=next_cid |
| 4 | 4 | NSID | nsid |
| rest | — | — | 0 |

No PRP, no LBA, no NLB. The controller flushes all pending writes
for the specified namespace to non-volatile media.

## I/O Completion Checking

```rust
pub fn check_io_completion(
    &mut self,
    cqe_bytes: &[u8; 16],
) -> Result<Option<CompletionResult>, NvmeError>
```

Requires `Ready` state. Delegates to
`self.io.as_mut().unwrap().check_completion()`. Returns the same
`CompletionResult` as admin completions — the CQE format is identical.

The existing `check_completion()` stays admin-only.

## Error Type

No new variants. Existing `NvmeError` covers all Phase 3 cases:
- `InvalidState` — I/O commands before Ready state
- `CommandFailed { status }` — non-zero status on completion
- `Timeout` / `NoCompletion` — already exist

## Modified File

`crates/harmony-unikernel/src/drivers/nvme.rs`

## Testing

All tests use MockRegisterBank — no hardware needed.

### Read command tests
- Correct SQE: opcode=0x02, NSID, PRP1, LBA in CDW10/11, NLB=0 in CDW12
- Uses I/O queue doorbell (qid=1), not admin doorbell
- Rejects non-Ready state (Enabled, Disabled)
- Large LBA (>32 bits) correctly split across CDW10 and CDW11

### Write command tests
- Correct SQE: opcode=0x01, NSID, PRP1, LBA, NLB=0
- Uses I/O queue doorbell

### Flush command tests
- Correct SQE: opcode=0x00, NSID, no PRP, no LBA
- Uses I/O queue doorbell
- Rejects non-Ready state

### I/O completion tests
- check_io_completion returns Some on phase match
- check_io_completion returns None on phase mismatch
- check_io_completion rejects non-Ready state
- Uses I/O CQ doorbell offset (qid=1), not admin

### Integration test
- Full lifecycle: init → admin queue → create I/O queues → activate →
  read_block → check_io_completion → write_block → flush

## Out of Scope

- Dataset Management / TRIM (harmony-os-ebp)
- Write Zeroes (harmony-os-ebp)
- Multi-block transfers / PRP lists (harmony-os-9vj)
- Multiple I/O queue pairs (harmony-os-q93)
- Scatter-gather DMA
- Interrupt-driven completion (MSI-X)
- I/O queue depth tracking / backpressure
- Error recovery / controller reset
