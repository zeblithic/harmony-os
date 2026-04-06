# NVMe Dataset Management (TRIM) and Write Zeroes

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Bead:** harmony-os-ebp

**Goal:** Add Dataset Management (TRIM/deallocate) and Write Zeroes NVM I/O commands to the NVMe driver, with ONCS capability checking. Completes the block device command set for production use.

**Prerequisite:** NVMe Phase 3 (harmony-os-87r) and multi-block PRP support (harmony-os-9vj) are both merged.

---

## Architecture

All changes are in one file: `crates/harmony-unikernel/src/drivers/nvme.rs`. The sans-I/O design is preserved — the driver builds command bytes and data buffers; the caller writes them to DMA memory and rings doorbells.

### Three additions

1. **ONCS (Optional NVM Command Support)** — New `oncs: u16` field on `NvmeDriver`, populated via `set_oncs()` (same pattern as `set_mdts()`). Parsed from Identify Controller bytes 256-257. The driver checks ONCS before building Write Zeroes or Dataset Management commands, returning `NvmeError::UnsupportedCommand` if the controller doesn't advertise support.

2. **Write Zeroes** (opcode 0x08) — Zeros an LBA range without data transfer. The controller generates zeros internally. No PRPs, no data buffers. CDW12 contains NLB (0-based block count). DEAC is always 0 (deterministic zeros — reads after Write Zeroes always return zero bytes).

3. **Dataset Management / TRIM** (opcode 0x09) — Tells the controller that specific LBA ranges are no longer in use. Uses a data buffer of 16-byte range descriptors pointed to by PRP1. CDW11 bit 2 (AD = Attribute Deallocate) is always set.

### What stays the same

- `QueuePair` — unchanged, still handles SQE submission and CQE parsing
- Completion checking — unchanged, these commands produce standard CQEs
- State machine — unchanged, both commands require `Ready` state
- `read_block`/`write_block`/`read_blocks`/`write_blocks` — unchanged
- `flush()` — unchanged
- PRP list logic — unchanged (Write Zeroes has no PRPs, TRIM uses `data_buffer` not `prp_list`)
- All existing tests — no changes needed

---

## ONCS Support

**ONCS** (Optional NVM Command Support) is bytes 256-257 of the Identify Controller response. Relevant bits:

| Bit | Command |
|-----|---------|
| 2 | Dataset Management |
| 3 | Write Zeroes |

### Storage

The `NvmeDriver` struct gains a new field:

```rust
oncs: u16,  // 0 = no optional commands, bits indicate support
```

Initialized to 0 in `NvmeDriver::init()`. Populated by `set_oncs(oncs: u16)` after the caller parses the Identify Controller response. Same sans-I/O pattern as `set_mdts()`.

### Accessors

```rust
pub fn set_oncs(&mut self, oncs: u16)
pub fn supports_write_zeroes(&self) -> bool       // (self.oncs >> 3) & 1 == 1
pub fn supports_dataset_management(&self) -> bool  // (self.oncs >> 2) & 1 == 1
```

### Identify Controller parsing

`parse_identify_controller()` gains extraction of bytes 256-257:

```rust
pub oncs: u16,  // added to IdentifyController struct
```

### Enforcement

Both `write_zeroes()` and `dataset_management()` check the corresponding ONCS bit before building the SQE. Missing support returns `NvmeError::UnsupportedCommand`.

---

## Write Zeroes Command

**Opcode:** 0x08 (NVM I/O command)

**Purpose:** Zero an LBA range. The controller writes zeros internally — no host data transfer, no PRPs.

### Public method

```rust
pub fn write_zeroes(
    &mut self,
    nsid: u32,
    lba: u64,
    block_count: u32,
) -> Result<AdminCommand, NvmeError>
```

### SQE layout

| Bytes | Field | Value |
|-------|-------|-------|
| 0-3 | CDW0 | opcode (0x08) \| (CID << 16) |
| 4-7 | NSID | nsid |
| 24-31 | PRP1 | 0 (unused) |
| 32-39 | PRP2 | 0 (unused) |
| 40-43 | CDW10 | LBA bits 31:0 |
| 44-47 | CDW11 | LBA bits 63:32 |
| 48-51 | CDW12 | NLB (bits 15:0) = block_count - 1; DEAC (bit 25) = 0 |

### Validation

| Check | Error |
|-------|-------|
| state != Ready | `InvalidState` |
| ONCS bit 3 not set | `UnsupportedCommand` |
| block_count == 0 | `TransferTooLarge` |
| block_count > 65536 | `TransferTooLarge` |
| lba + block_count overflows u64 | `TransferTooLarge` |

**MDTS does not apply** — the NVMe spec defines MDTS as the maximum data transfer size between host and controller. Write Zeroes transfers no data; the controller generates zeros internally. The 513-page PRP cap also does not apply (no PRPs). The only size limit is the 16-bit NLB field (max 65536 blocks).

### Result

`AdminCommand` with `prp_list: None`, `data_buffer: None`. No caller patching needed — just write the SQE and ring the doorbell.

---

## Dataset Management (TRIM) Command

**Opcode:** 0x09 (NVM I/O command)

**Purpose:** Inform the controller that specific LBA ranges are no longer in use (deallocate/TRIM). The controller may reclaim the underlying storage, improving future write performance and SSD wear leveling.

### Range descriptor

```rust
/// An LBA range for Dataset Management (TRIM/deallocate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DsmRange {
    /// Starting logical block address.
    pub lba: u64,
    /// Number of logical blocks in this range.
    pub block_count: u32,
}
```

Each range serializes to 16 bytes in the NVMe range descriptor format:

| Bytes | Field | Value |
|-------|-------|-------|
| 0-3 | Context Attributes | 0 (reserved for future use) |
| 4-7 | Length in LBAs | block_count (little-endian u32) |
| 8-15 | Starting LBA | lba (little-endian u64) |

### Public method

```rust
pub fn dataset_management(
    &mut self,
    nsid: u32,
    ranges: &[DsmRange],
) -> Result<AdminCommand, NvmeError>
```

### SQE layout

| Bytes | Field | Value |
|-------|-------|-------|
| 0-3 | CDW0 | opcode (0x09) \| (CID << 16) |
| 4-7 | NSID | nsid |
| 24-31 | PRP1 | sentinel (`u64::MAX`) — caller patches with DMA address |
| 32-39 | PRP2 | 0 |
| 40-43 | CDW10 | NR = ranges.len() - 1 (0-based range count) |
| 44-47 | CDW11 | 0x04 (AD bit = bit 2, Attribute Deallocate) |

### Data buffer

The driver serializes all ranges into contiguous 16-byte descriptors and returns them in `AdminCommand.data_buffer`. Maximum size: 256 ranges x 16 bytes = 4096 bytes (always fits in one 4 KiB page).

### Sentinel protocol for PRP1

The caller's execution sequence for a Dataset Management command:

1. Receive `AdminCommand` from `dataset_management()`
2. `data_buffer` is `Some`: allocate 4 KiB-aligned DMA memory, copy buffer bytes into it
3. Patch SQE bytes 24-31 (PRP1) with the physical address of the DMA region
4. Write SQE to submission queue
5. Ring doorbell

This differs from the multi-block PRP list protocol where PRP2 (bytes 32-39) is patched. The field name (`data_buffer` vs `prp_list`) makes the distinction unambiguous.

### Validation

| Check | Error |
|-------|-------|
| state != Ready | `InvalidState` |
| ONCS bit 2 not set | `UnsupportedCommand` |
| ranges.is_empty() | `TransferTooLarge` |
| ranges.len() > 256 | `TransferTooLarge` |

No per-range LBA validation — the controller validates LBA ranges against the namespace. No MDTS check — Dataset Management is a management command, not a data transfer.

---

## New AdminCommand field

```rust
pub struct AdminCommand {
    pub sqe: [u8; 64],
    pub sq_offset: u64,
    pub doorbell_offset: usize,
    pub doorbell_value: u32,
    pub prp_list: Option<Vec<u8>>,
    /// Optional data buffer for commands that need a host-memory descriptor
    /// (e.g., Dataset Management range list). The caller must write these bytes
    /// to a 4 KiB-aligned physical address, then patch SQE bytes 24-31 (PRP1)
    /// with that address before submitting.
    pub data_buffer: Option<Vec<u8>>,
}
```

The `data_buffer` field is initialized to `None` in `QueuePair::submit()`. Only `dataset_management()` sets it to `Some`.

---

## Error Types

One new variant added to `NvmeError`:

```rust
/// The command requires an optional NVM feature (ONCS) not supported by this controller.
UnsupportedCommand,
```

Existing `TransferTooLarge` is reused for block count and range count violations (same semantics — "the requested size is invalid").

---

## Testing

All tests use `MockRegisterBank`. No hardware, no DMA. Tests verify the bytes the driver produces.

### ONCS tests

1. **ONCS defaults** — `oncs` is 0 after init, `supports_write_zeroes()` and `supports_dataset_management()` both return false
2. **ONCS storage** — `set_oncs(0x0C)` (bits 2+3), both accessors return true
3. **ONCS partial** — `set_oncs(0x04)` (bit 2 only) → dataset_management=true, write_zeroes=false
4. **Identify Controller ONCS parsing** — `parse_identify_controller()` extracts bytes 256-257 correctly

### Write Zeroes tests

5. **Basic command** — Correct opcode (0x08), NSID, NLB in CDW12, LBA in CDW10-11, PRP1=0, PRP2=0, no data_buffer, no prp_list
6. **Unsupported** — ONCS bit 3 not set → `UnsupportedCommand`
7. **Zero blocks** — block_count=0 → `TransferTooLarge`
8. **Max blocks** — block_count=65536 → succeeds, NLB=65535 in CDW12
9. **Too many blocks** — block_count=65537 → `TransferTooLarge`
10. **LBA overflow** — lba=u64::MAX, block_count=2 → `TransferTooLarge`
11. **State validation** — not Ready → `InvalidState`
12. **CID increment** — CID advances like other commands

### Dataset Management tests

13. **Basic command** — Correct opcode (0x09), NR in CDW10, AD bit in CDW11, PRP1=sentinel, data_buffer contains serialized ranges
14. **Unsupported** — ONCS bit 2 not set → `UnsupportedCommand`
15. **Single range** — 1 range: NR=0, buffer=16 bytes, verify serialization byte-by-byte
16. **Multiple ranges** — 3 ranges: NR=2, buffer=48 bytes, verify all range descriptors
17. **Max ranges** — 256 ranges succeeds, NR=255
18. **Too many ranges** — 257 ranges → `TransferTooLarge`
19. **Empty ranges** — 0 ranges → `TransferTooLarge`
20. **State validation** — not Ready → `InvalidState`
21. **CID increment** — CID advances
22. **Range serialization** — Verify exact byte layout: context_attrs=0 (4 bytes), block_count LE (4 bytes), lba LE (8 bytes)

---

## Scope Boundary

**In scope:**
- `oncs: u16` field on `NvmeDriver` with `set_oncs()` and boolean accessors
- `oncs: u16` field on `IdentifyController`, parsed from bytes 256-257
- `NvmeError::UnsupportedCommand` variant
- `DsmRange` struct
- `data_buffer: Option<Vec<u8>>` field on `AdminCommand`
- `write_zeroes()` public method
- `dataset_management()` public method
- All 22 tests listed above

**Out of scope:**
- NVMe Compare command (ONCS bit 0) — no current use case
- Write Uncorrectable (ONCS bit 1) — destructive, no use case
- DEAC flag on Write Zeroes — deterministic zeros only
- FUA flag on Write Zeroes — unnecessary complexity
- Dataset Management attributes beyond AD (deallocate) — no use case for Integral Dataset or Content Latency hints
- `NvmeBlockDevice` adapter integration — separate bead
- Multi-page range buffers — 256 x 16 = 4096, always one page
