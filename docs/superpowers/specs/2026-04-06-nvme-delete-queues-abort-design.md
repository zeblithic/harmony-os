# NVMe Delete I/O Queues and Abort Admin Commands

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Bead:** harmony-os-chv

**Goal:** Add Delete I/O Submission Queue (opcode 0x00), Delete I/O Completion Queue (opcode 0x04), and Abort (opcode 0x08) admin commands to the NVMe driver, completing the queue lifecycle (create + use + delete) and enabling error recovery via command abort.

**Prerequisite:** NVMe multi-queue support (harmony-os-q93) and Get/Set Features (harmony-os-dd4) are merged.

---

## Architecture

All changes are in one file: `crates/harmony-unikernel/src/drivers/nvme.rs`. The sans-I/O design is preserved — the driver builds command bytes; the caller writes them to DMA memory and rings doorbells.

### Five additions

1. **`delete_io_sq(qid)`** — Delete I/O Submission Queue admin command (opcode 0x00). Builds a 64-byte SQE with QID in CDW10 bits 15:0. No data transfer. Allowed in `Ready` state only. `qid == 0` rejected.

2. **`delete_io_cq(qid)`** — Delete I/O Completion Queue admin command (opcode 0x04). Same pattern as delete SQ. CDW10 bits 15:0 = QID. `Ready` state only. `qid == 0` rejected.

3. **`delete_io_queue_pair(qid)`** — Convenience method returning `[delete_sq_cmd, delete_cq_cmd]`. SQ deleted first per NVMe spec §5.4 ("the host shall delete all associated Submission Queues prior to deleting a Completion Queue"). Validates that `qid` exists in `io_queues`.

4. **`deactivate_io_queue_pair(qid)`** — Removes the QueuePair matching `qid` from `io_queues` after the caller confirms both delete completions succeeded. If `io_queues` becomes empty, transitions `Ready` → `Enabled`. Returns `InvalidState` if no matching qid or wrong state.

5. **`abort(sqid, cid)`** — Abort command (opcode 0x08). CDW10 bits 15:0 = SQID (queue containing the command to abort), bits 31:16 = CID (command to abort). Stateless — no driver bookkeeping. Allowed in `Enabled` or `Ready` state. No validation of SQID or CID — the controller owns that.

### What stays the same

- `QueuePair`, `AdminCommand`, `Completion`, `CompletionResult` — unchanged
- State machine — unchanged (delete uses existing `Ready` check; abort uses existing `Enabled`/`Ready` check)
- All existing admin and I/O commands — unchanged
- All existing tests — unchanged

---

## Delete I/O Submission Queue

### `delete_io_sq`

```rust
pub fn delete_io_sq(&mut self, qid: u16) -> Result<AdminCommand, NvmeError>
```

### SQE layout

| Bytes | Field | Value |
|-------|-------|-------|
| 0-3 | CDW0 | opcode (0x00) \| (CID << 16) |
| 40-43 | CDW10 | QID (bits 15:0) |

All other bytes zero (no PRP1, PRP2, CDW11). Allowed in `Ready` state only. `qid == 0` returns `InvalidState` (admin queue cannot be deleted).

---

## Delete I/O Completion Queue

### `delete_io_cq`

```rust
pub fn delete_io_cq(&mut self, qid: u16) -> Result<AdminCommand, NvmeError>
```

### SQE layout

| Bytes | Field | Value |
|-------|-------|-------|
| 0-3 | CDW0 | opcode (0x04) \| (CID << 16) |
| 40-43 | CDW10 | QID (bits 15:0) |

Same constraints as delete SQ: `Ready` state, `qid >= 1`.

---

## Delete Queue Pair (convenience)

### `delete_io_queue_pair`

```rust
pub fn delete_io_queue_pair(&mut self, qid: u16) -> Result<[AdminCommand; 2], NvmeError>
```

- Validates that `qid` exists in `io_queues` (returns `InvalidState` if not found)
- Calls `delete_io_sq(qid)` then `delete_io_cq(qid)`
- Returns `[delete_sq_cmd, delete_cq_cmd]` — SQ first per NVMe spec §5.4
- Does NOT remove from `io_queues` — that is `deactivate_io_queue_pair`'s job after the caller confirms completions

---

## Deactivate Queue Pair

### `deactivate_io_queue_pair`

```rust
pub fn deactivate_io_queue_pair(&mut self, qid: u16) -> Result<(), NvmeError>
```

- Requires `Ready` state (returns `InvalidState` otherwise)
- Finds and removes the QueuePair with matching `qid` from `io_queues`
- Returns `InvalidState` if no matching qid found
- If `io_queues` becomes empty after removal, transitions `Ready` → `Enabled`
- If `io_queues` still has entries, stays in `Ready`

This mirrors `activate_io_queue_pair` — activate adds to `io_queues` and transitions `Enabled` → `Ready`; deactivate removes from `io_queues` and transitions `Ready` → `Enabled` when empty.

---

## Abort

### `abort`

```rust
pub fn abort(&mut self, sqid: u16, cid: u16) -> Result<AdminCommand, NvmeError>
```

### SQE layout

| Bytes | Field | Value |
|-------|-------|-------|
| 0-3 | CDW0 | opcode (0x08) \| (own CID << 16) |
| 40-43 | CDW10 | SQID (bits 15:0) \| (CID-to-abort << 16) |

Note: CDW0 contains the abort command's own auto-incremented CID. CDW10 bits 31:16 contains the CID of the command being aborted — these are different values.

Allowed in `Enabled` or `Ready` state. SQID=0 is valid (aborting admin commands). No validation of SQID or CID values — the controller determines whether the abort target exists and returns appropriate status.

---

## Testing

All tests use `MockRegisterBank`. No hardware, no DMA.

### Delete I/O SQ tests

1. **Basic delete_io_sq** — Correct opcode (0x00), QID in CDW10 bits 15:0, all other SQE bytes zero, no prp_list, no data_buffer
2. **State validation** — Not `Ready` → `InvalidState`
3. **qid=0 rejected** — `delete_io_sq(0)` → `InvalidState`
4. **CID increment** — CID advances like other admin commands

### Delete I/O CQ tests

5. **Basic delete_io_cq** — Correct opcode (0x04), QID in CDW10 bits 15:0
6. **State validation** — Not `Ready` → `InvalidState`
7. **qid=0 rejected** — `delete_io_cq(0)` → `InvalidState`

### Delete Queue Pair tests

8. **delete_io_queue_pair basic** — Returns two commands: first has opcode 0x00 (SQ), second has opcode 0x04 (CQ), both with correct qid in CDW10
9. **delete_io_queue_pair unknown qid** — `delete_io_queue_pair(99)` with no such queue → `InvalidState`
10. **Ordering guarantee** — SQ delete (index 0) before CQ delete (index 1)

### Deactivate tests

11. **deactivate_io_queue_pair basic** — After deactivation, `io_queue_count()` decreases by 1
12. **deactivate last queue → Enabled** — Single queue, deactivate → state transitions `Ready` → `Enabled`
13. **deactivate one of many** — Two queues, deactivate one → state stays `Ready`, count is 1
14. **deactivate unknown qid** — `deactivate_io_queue_pair(99)` → `InvalidState`
15. **deactivate wrong state** — In `Enabled` state (no queues) → `InvalidState`

### Abort tests

16. **Basic abort** — Correct opcode (0x08), SQID in CDW10 bits 15:0, CID-to-abort in CDW10 bits 31:16
17. **Abort uses own CID** — CDW0 bits 31:16 contain the command's own auto-incremented CID, distinct from the abort target CID
18. **State validation** — Not `Enabled`/`Ready` → `InvalidState`
19. **Abort admin queue** — `abort(0, some_cid)` succeeds (SQID=0 is valid for aborting admin commands)

### Existing tests

No changes needed. Delete and Abort are new admin commands with no signature changes to existing methods.

---

## Scope Boundary

**In scope:**
- `delete_io_sq(qid)` admin command (opcode 0x00)
- `delete_io_cq(qid)` admin command (opcode 0x04)
- `delete_io_queue_pair(qid)` convenience method returning `[sq_cmd, cq_cmd]`
- `deactivate_io_queue_pair(qid)` — removes QueuePair, `Ready` → `Enabled` if last
- `abort(sqid, cid)` admin command (opcode 0x08)
- All 19 tests listed above

**Out of scope:**
- Firmware Commit / Download (opcodes 0x10 / 0x11) — separate bead
- Asynchronous Event Request (AER) — separate concern
- Queue re-creation after deletion — caller composes create + delete as needed
- Abort retry logic / timeout — caller's responsibility
- Enforcing "abort outstanding commands before deleting queue" — caller's responsibility
- `NvmeBlockDevice` adapter — separate bead
