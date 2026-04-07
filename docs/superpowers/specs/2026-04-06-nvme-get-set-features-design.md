# NVMe Get/Set Features Admin Commands

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Bead:** harmony-os-dd4

**Goal:** Add Get Features (opcode 0x0A) and Set Features (opcode 0x09) admin commands to the NVMe driver, with a typed helper for Number of Queues (FID 0x07) to negotiate I/O queue limits with the controller.

**Prerequisite:** NVMe Phase 2 (harmony-os-n49) is merged.

---

## Architecture

All changes are in one file: `crates/harmony-unikernel/src/drivers/nvme.rs`. The sans-I/O design is preserved — the driver builds command bytes; the caller writes them to DMA memory and rings doorbells.

### Three additions

1. **`get_features(fid, cdw11)`** — Generic Get Features admin command (opcode 0x0A). Builds a 64-byte SQE with the Feature Identifier in CDW10 bits 7:0 and the caller-provided CDW11. No data transfer (PRP1=PRP2=0). The controller's response arrives in the standard `Completion.result` (DW0). Allowed in `Enabled` or `Ready` state.

2. **`set_features(fid, cdw11)`** — Generic Set Features admin command (opcode 0x09). Same pattern — FID in CDW10, CDW11 carries feature-specific data. No data transfer for the features we care about. Allowed in `Enabled` or `Ready` state.

3. **`set_num_queues(nsqr, ncqr)` + `parse_num_queues()`** — Typed helper for FID 0x07 (Number of Queues). Accepts 1-based counts (min 1), converts to 0-based CDW11 encoding, delegates to `set_features`. Companion parser extracts the 0-based DW0 result into 1-based fields. Prevents the off-by-one footgun in the 0-based NVMe encoding.

### What stays the same

- `QueuePair`, `AdminCommand`, `Completion`, `CompletionResult` — unchanged
- State machine — unchanged (both commands use existing `Enabled`/`Ready` check)
- All existing admin and I/O commands — unchanged
- All existing tests — unchanged

---

## Generic Commands

### `get_features`

```rust
pub fn get_features(&mut self, fid: u8, cdw11: u32) -> Result<AdminCommand, NvmeError>
```

### SQE layout

| Bytes | Field | Value |
|-------|-------|-------|
| 0-3 | CDW0 | opcode (0x0A) \| (CID << 16) |
| 24-31 | PRP1 | 0 (no data transfer) |
| 32-39 | PRP2 | 0 |
| 40-43 | CDW10 | FID (bits 7:0), SEL=0 (bits 10:8, current value) |
| 44-47 | CDW11 | caller-provided |

Allowed in `Enabled` or `Ready` state. No FID or CDW11 validation — the caller and controller own that.

### `set_features`

```rust
pub fn set_features(&mut self, fid: u8, cdw11: u32) -> Result<AdminCommand, NvmeError>
```

### SQE layout

| Bytes | Field | Value |
|-------|-------|-------|
| 0-3 | CDW0 | opcode (0x09) \| (CID << 16) |
| 24-31 | PRP1 | 0 (no data transfer) |
| 32-39 | PRP2 | 0 |
| 40-43 | CDW10 | FID (bits 7:0) |
| 44-47 | CDW11 | caller-provided |

Allowed in `Enabled` or `Ready` state. No FID or CDW11 validation.

---

## Number of Queues (FID 0x07)

### Typed helper

```rust
pub fn set_num_queues(&mut self, nsqr: u16, ncqr: u16) -> Result<AdminCommand, NvmeError>
```

- Validation: `nsqr >= 1` and `ncqr >= 1` (returns `InvalidState` if either is 0)
- Converts to 0-based: `cdw11 = ((ncqr - 1) as u32) << 16 | (nsqr - 1) as u32`
- Delegates to `self.set_features(0x07, cdw11)`

### Result parser

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumberOfQueues {
    /// Number of I/O submission queues allocated (1-based).
    pub nsqr: u16,
    /// Number of I/O completion queues allocated (1-based).
    pub ncqr: u16,
}

pub fn parse_num_queues(completion: &Completion) -> NumberOfQueues
```

- `nsqr = (completion.result & 0xFFFF) as u16 + 1`
- `ncqr = (completion.result >> 16) as u16 + 1`

Standalone function, same pattern as `parse_identify_controller`. No error case — the bit math always produces valid values.

### CDW11 encoding (NVMe spec §5.21.1.7)

| Bits | Field | Meaning |
|------|-------|---------|
| 31:16 | NCQR | Number of I/O Completion Queues Requested (0-based) |
| 15:0 | NSQR | Number of I/O Submission Queues Requested (0-based) |

The completion DW0 uses the same layout for the *allocated* counts. The controller may allocate fewer than requested.

---

## Testing

All tests use `MockRegisterBank`. No hardware, no DMA.

### Get Features tests

1. **Basic get_features** — Correct opcode (0x0A), FID in CDW10 bits 7:0, CDW11 passed through, PRP1=0, PRP2=0, no prp_list, no data_buffer
2. **CDW11 passthrough** — Non-zero CDW11 appears in SQE bytes 44-47
3. **State validation** — Not `Enabled`/`Ready` -> `InvalidState`
4. **CID increment** — CID advances like other admin commands

### Set Features tests

5. **Basic set_features** — Correct opcode (0x09), FID in CDW10 bits 7:0, CDW11 passed through, PRP1=0, PRP2=0
6. **State validation** — Not `Enabled`/`Ready` -> `InvalidState`
7. **CID increment** — CID advances

### Number of Queues tests

8. **set_num_queues basic** — `set_num_queues(4, 4)` produces FID=0x07 in CDW10, CDW11=`0x0003_0003`
9. **set_num_queues asymmetric** — `set_num_queues(2, 8)` -> CDW11=`0x0007_0001`
10. **set_num_queues minimum** — `set_num_queues(1, 1)` -> CDW11=`0x0000_0000`
11. **set_num_queues zero nsqr** — `set_num_queues(0, 4)` -> `InvalidState`
12. **set_num_queues zero ncqr** — `set_num_queues(4, 0)` -> `InvalidState`
13. **parse_num_queues** — `completion.result = 0x0003_0007` -> `nsqr=8, ncqr=4`
14. **parse_num_queues minimum** — `completion.result = 0x0000_0000` -> `nsqr=1, ncqr=1`
15. **Doorbell/admin queue** — Commands use admin queue doorbells (not I/O)

### Existing tests

No changes needed. Get/Set Features are new admin commands with no signature changes to existing methods.

---

## Scope Boundary

**In scope:**
- `get_features(fid, cdw11)` generic admin command (opcode 0x0A)
- `set_features(fid, cdw11)` generic admin command (opcode 0x09)
- `set_num_queues(nsqr, ncqr)` typed helper for FID 0x07
- `NumberOfQueues` struct with 1-based fields
- `parse_num_queues(&Completion)` standalone parser
- All 15 tests listed above

**Out of scope:**
- Features requiring data transfer (e.g., LBA Range Type FID 0x03 uses a PRP buffer) — generic methods only handle CDW11-only features
- `get_num_queues()` typed helper — caller can use `get_features(0x07, 0)` and `parse_num_queues()` directly
- Temperature Threshold (FID 0x04), Interrupt Coalescing (FID 0x08), other FIDs — use generic methods
- Enforcing "Set Features before Create I/O Queue" ordering — caller's responsibility
- Delete I/O Queue commands — tracked in harmony-os-chv
- `NvmeBlockDevice` adapter — separate bead
