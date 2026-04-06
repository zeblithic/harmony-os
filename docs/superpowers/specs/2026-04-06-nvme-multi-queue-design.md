# NVMe Multi-Queue Support: Multiple I/O Queue Pairs

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Bead:** harmony-os-q93

**Goal:** Extend the NVMe driver to support multiple I/O queue pairs for per-core parallel I/O. Currently limited to a single I/O queue pair (qid=1).

**Prerequisite:** NVMe Phase 3 (harmony-os-87r), multi-block PRP support (harmony-os-9vj), and TRIM/Write Zeroes (harmony-os-ebp) are all merged.

---

## Architecture

All changes are in one file: `crates/harmony-unikernel/src/drivers/nvme.rs`. The sans-I/O design is preserved — the driver builds command bytes and data buffers; the caller writes them to DMA memory and rings doorbells.

### Three changes to `NvmeDriver`

1. **`io: Option<QueuePair>` becomes `io_queues: Vec<QueuePair>`** — Stores 0..N I/O queue pairs. Index `i` in the Vec corresponds to the `i`-th activated pair. Empty until the first pair is activated.

2. **`pending_io: Option<(u64, u64, u16)>` becomes `pending_io: Vec<(u16, u64, u64, u16)>`** — Tracks multiple pending pairs awaiting activation. Each entry is `(qid, sq_phys, cq_phys, size)`. Consumed by `activate_io_queue_pair(qid)`.

3. **`create_io_cq` / `create_io_sq` gain a `qid: u16` parameter** — No longer hardcoded to 1. CDW10 bits 15:0 use the caller-provided qid. CDW11 of Create I/O SQ uses the same qid as CQID (each SQ is paired with the CQ of the same qid). Validation: qid must be >= 1 (qid=0 is the admin queue).

### State transitions

- `Enabled` + first `activate_io_queue_pair()` → `Ready`
- `Ready` + additional `activate_io_queue_pair()` calls → stays `Ready`
- `create_io_queue_pair` allowed in both `Enabled` and `Ready` states
- All I/O methods require `Ready` state + valid queue index

### I/O method signature change

Every I/O method gains a `queue_index: usize` parameter (0-based index into `io_queues`) as its first parameter after `&mut self`:

- `io_rw_command(queue_index, opcode, nsid, lba, pages)`
- `read_blocks(queue_index, nsid, lba, pages)`
- `write_blocks(queue_index, nsid, lba, pages)`
- `read_block(queue_index, nsid, lba, data_phys)`
- `write_block(queue_index, nsid, lba, data_phys)`
- `flush(queue_index, nsid)`
- `write_zeroes(queue_index, nsid, lba, block_count)`
- `dataset_management(queue_index, nsid, ranges)`
- `check_io_completion(queue_index, cqe_bytes)`

### What stays the same

- `QueuePair` struct — unchanged
- `AdminCommand` — unchanged
- Admin queue — unchanged (single pair at qid=0)
- Completion parsing — unchanged (QueuePair handles CQE parsing)
- MDTS, ONCS, all validation logic — unchanged
- PRP list / data_buffer sentinel protocols — unchanged

---

## Queue Creation API

### `create_io_cq` (modified)

```rust
pub fn create_io_cq(&mut self, qid: u16, cq_phys: u64, size: u16) -> Result<AdminCommand, NvmeError>
```

Now accepts `qid` instead of hardcoding 1. CDW10 bits 15:0 = qid, bits 31:16 = size-1. CDW11: PC=1, IEN=1, IV=0 (unchanged). Allowed in `Enabled` or `Ready` state. `qid == 0` returns `InvalidState`.

### `create_io_sq` (modified)

```rust
pub fn create_io_sq(&mut self, qid: u16, sq_phys: u64, size: u16) -> Result<AdminCommand, NvmeError>
```

Now accepts `qid`. CDW10 bits 15:0 = qid, bits 31:16 = size-1. CDW11 bits 15:0 = PC=1, bits 31:16 = CQID = qid (each SQ paired with matching CQ). Allowed in `Enabled` or `Ready` state. `qid == 0` returns `InvalidState`.

### `create_io_queue_pair` (replaces `create_io_queues`)

```rust
pub fn create_io_queue_pair(
    &mut self,
    qid: u16,
    sq_phys: u64,
    cq_phys: u64,
    size: u16,
) -> Result<[AdminCommand; 2], NvmeError>
```

Convenience method that calls `create_io_cq(qid, ...)` then `create_io_sq(qid, ...)`. Returns `[cq_cmd, sq_cmd]`. Caches `(qid, sq_phys, cq_phys, size)` in `pending_io`. Allowed in both `Enabled` and `Ready` states.

### `activate_io_queue_pair` (replaces `activate_io_queues`)

```rust
pub fn activate_io_queue_pair(&mut self, qid: u16) -> Result<(), NvmeError>
```

Finds and removes the entry in `pending_io` matching `qid`. Creates `QueuePair::new(qid, sq_phys, cq_phys, size)` and pushes it onto `io_queues`. If state is `Enabled`, transitions to `Ready`. If already `Ready`, stays `Ready`. Returns `InvalidState` if no matching pending entry or if state is `Disabled`.

### `io_queue_count` (new)

```rust
pub fn io_queue_count(&self) -> usize
```

Returns `self.io_queues.len()`.

---

## I/O Queue Selection

### Private helper

```rust
fn io_queue_mut(&mut self, queue_index: usize) -> Result<&mut QueuePair, NvmeError> {
    self.io_queues.get_mut(queue_index).ok_or(NvmeError::InvalidQueueIndex)
}
```

Replaces all `self.io.as_mut().ok_or(NvmeError::InvalidState)?` calls in I/O methods.

### Method changes

All I/O methods replace:
```rust
self.io.as_mut().ok_or(NvmeError::InvalidState)?
```
with:
```rust
self.io_queue_mut(queue_index)?
```

The state check (`self.state != NvmeState::Ready`) remains as a separate guard before the queue lookup. This means:
- Wrong state → `InvalidState`
- Right state but bad index → `InvalidQueueIndex`

---

## Error Types

One new variant added to `NvmeError`:

```rust
/// The specified I/O queue index is out of range.
InvalidQueueIndex,
```

Distinct from `InvalidState` — `InvalidState` means the driver is in the wrong lifecycle phase, while `InvalidQueueIndex` means the driver is in the right state but the requested queue doesn't exist.

---

## Testing

All tests use `MockRegisterBank`. No hardware, no DMA.

### New test helper

`ready_driver_multi(n: usize)` — Creates a driver with `n` I/O queue pairs (qids 1..=n). Calls `enabled_driver()` then `create_io_queue_pair` + `activate_io_queue_pair` for each.

### Multi-queue tests

1. **Create second queue pair** — After first pair activated (Ready), `create_io_queue_pair(2, ...)` succeeds, returns correct qid=2 in CDW10 of both CQ and SQ commands
2. **Activate second queue pair** — `activate_io_queue_pair(2)` succeeds, `io_queue_count() == 2`
3. **Three queue pairs** — Create and activate 3 pairs, `io_queue_count() == 3`
4. **Queue pair ordering** — Pairs accessible by index in activation order
5. **Doorbell offsets per qid** — qid=2 produces SQ doorbell `0x1000 + (2*2)*stride`, CQ doorbell `0x1000 + (2*2+1)*stride`. qid=3 similarly. Verified via I/O commands on different queues.
6. **I/O commands target correct queue** — `read_block(0, ...)` and `read_block(1, ...)` produce different doorbell offsets matching their respective queue pairs
7. **CID shared across queues** — CID increments globally; submitting to queue 0 then queue 1 produces sequential CIDs
8. **Invalid queue index** — `read_block(5, ...)` with only 2 queues → `InvalidQueueIndex`
9. **Completion on correct queue** — `check_io_completion(0, ...)` and `check_io_completion(1, ...)` track independent head/phase
10. **qid=0 rejected** — `create_io_queue_pair(0, ...)` → `InvalidState`
11. **Activate without create** — `activate_io_queue_pair(2)` with no pending qid=2 → `InvalidState`
12. **io_queue_count** — 0 before any activation, increments with each
13. **State transition** — First activation Enabled→Ready, subsequent stay Ready

### Existing test updates

All existing I/O tests get `0,` prepended as the `queue_index` argument. The `ready_driver()` helper is updated to use `create_io_queue_pair(1, ...)` + `activate_io_queue_pair(1)`. No behavioral changes — purely mechanical signature update.

---

## Scope Boundary

**In scope:**
- `io: Option<QueuePair>` → `io_queues: Vec<QueuePair>` on `NvmeDriver`
- `pending_io` from `Option<(u64, u64, u16)>` → `Vec<(u16, u64, u64, u16)>`
- `qid: u16` parameter on `create_io_cq`, `create_io_sq`
- `create_io_queue_pair` replacing `create_io_queues`
- `activate_io_queue_pair` replacing `activate_io_queues`
- `io_queue_count()` accessor
- `io_queue_mut()` private helper
- `NvmeError::InvalidQueueIndex` variant
- `queue_index: usize` parameter on all I/O methods and `check_io_completion`
- All 13 new tests listed above
- Mechanical update of all existing I/O tests to pass `queue_index: 0`

**Out of scope:**
- Set Features (Number of Queues) — tracked in harmony-os-chv
- Delete I/O Queue commands — tracked in harmony-os-chv
- Per-queue CID tracking — single global CID is correct (caller serializes submissions)
- Interrupt vector assignment per queue — needs MSI-X, separate concern
- Queue pair load balancing / CPU affinity — caller's responsibility
- `NvmeBlockDevice` adapter — separate bead
