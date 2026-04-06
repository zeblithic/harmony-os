# NVMe Multi-Block Transfers via PRP Lists

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Bead:** harmony-os-9vj

**Goal:** Extend the NVMe driver's Read/Write commands to support multi-block transfers using PRP2 and PRP lists, with MDTS enforcement. Currently limited to one block per command (PRP1 only).

**Prerequisite:** NVMe Phase 3 (harmony-os-87r) — single-block I/O via submission/completion queues is functional and tested.

---

## Architecture

All changes are in one file: `crates/harmony-unikernel/src/drivers/nvme.rs`. The sans-I/O design is preserved — the driver builds command bytes and PRP list bytes; the caller writes them to DMA memory and rings doorbells.

### What changes

1. **`AdminCommand` gains `prp_list: Option<Vec<u8>>`** — When present, contains the PRP list bytes the caller must write to a 4 KiB-aligned physical address before submitting the SQE. The SQE's PRP2 field contains a sentinel (`u64::MAX`) that the caller replaces with the actual physical address of where they wrote the list.

2. **`io_rw_command()` signature changes** — From `(opcode, nsid, lba, data_phys)` to `(opcode, nsid, lba, pages: &[u64])`. The `pages` slice contains 4 KiB-aligned physical addresses of the data pages. `pages.len()` determines the NLB (Number of Logical Blocks) field in CDW12.

3. **`read_block`/`write_block` become wrappers** — They call `io_rw_command()` with a single-element slice `&[data_phys]`. The public API is unchanged for callers using single-block transfers.

4. **New `read_blocks`/`write_blocks` public methods** — Accept `nsid`, `lba`, and `pages: &[u64]` for multi-block transfers.

5. **MDTS stored in `NvmeDriver`** — New field `mdts: u8` populated from `IdentifyController.max_data_transfer`. New public method `max_transfer_blocks() -> Option<u32>` computes the block limit (returns `None` when MDTS=0, meaning no controller-imposed limit).

6. **New `NvmeError` variants** — `TransferTooLarge` and `UnalignedAddress`.

### What stays the same

- `QueuePair` — unchanged, still handles SQE submission and CQE parsing
- Completion checking — unchanged, multi-block completions are identical to single-block
- State machine — unchanged, I/O commands require `Ready` state
- `flush()` — unchanged, no data transfer
- All existing tests — compatible after updating `read_block`/`write_block` (they're wrappers now)

---

## PRP Logic

NVMe uses Physical Region Pages (PRPs) to describe data buffer locations. Each PRP entry is a 64-bit physical address, 4 KiB-aligned (when CC.MPS=0, which this driver uses).

### PRP rules by transfer size

| Pages | PRP1 | PRP2 | `AdminCommand.prp_list` |
|-------|------|------|-------------------------|
| 1 | `pages[0]` | 0 | `None` |
| 2 | `pages[0]` | `pages[1]` | `None` |
| 3+ | `pages[0]` | sentinel (`u64::MAX`) | `Some(pages[1..].as_le_bytes())` |

For the 3+ page case:
- The driver serializes `pages[1..]` as contiguous little-endian u64 values into the `prp_list` Vec.
- PRP2 is set to `u64::MAX` as a sentinel. The caller replaces it with the physical address of where they wrote the PRP list bytes.
- The PRP list must be written to 4 KiB-aligned DMA memory before the SQE is submitted.

### Sentinel protocol

The caller's execution sequence for a multi-block command:

1. Receive `AdminCommand` from `read_blocks()`/`write_blocks()`
2. If `prp_list` is `Some`:
   a. Allocate 4 KiB-aligned DMA memory for the PRP list
   b. Copy `prp_list` bytes into that DMA region
   c. Patch SQE bytes 32–39 (PRP2) with the physical address of the DMA region
3. Write SQE to `sq_phys + sq_offset`
4. Ring doorbell at `doorbell_offset` with `doorbell_value`

---

## MDTS Enforcement

**MDTS** (Maximum Data Transfer Size) is byte 77 of the Identify Controller response. When non-zero, the maximum transfer size in bytes is `2^mdts * 4096` (with MPS=0).

### Storage

The `NvmeDriver` struct gains a new field:

```rust
mdts: u8,  // 0 = no limit, >0 = max transfer = 2^mdts pages
```

This is populated by a new `set_mdts(mdts: u8)` method that the caller invokes after parsing the Identify Controller response. This keeps the driver's sans-I/O pattern — it doesn't parse the 4 KiB response itself.

### Public getter

```rust
pub fn max_transfer_blocks(&self) -> Option<u32> // None = no limit, Some(n) = max n blocks
```

Returns `None` when `mdts == 0`. Otherwise returns `Some(1 << mdts)` (number of 4 KiB pages).

### Enforcement

`io_rw_command()` checks `pages.len()` against the MDTS limit and returns `NvmeError::TransferTooLarge` if exceeded.

---

## Validation

All validation happens in `io_rw_command()`:

1. **State check** — Must be `NvmeState::Ready`
2. **Non-empty** — `pages` must not be empty
3. **Alignment** — Every address in `pages` must be 4 KiB-aligned (bits 11:0 == 0)
4. **MDTS** — `pages.len()` must not exceed `max_transfer_blocks()` (when MDTS > 0)
5. **LBA overflow** — `lba + pages.len() as u64` must not overflow u64

All checks return specific `NvmeError` variants. No panics.

---

## Error Types

Two new variants added to `NvmeError`:

```rust
/// The requested transfer exceeds the controller's MDTS.
TransferTooLarge,
/// One or more PRP addresses are not 4 KiB-aligned.
UnalignedAddress,
```

---

## Testing

All tests use `MockRegisterBank`. No hardware, no DMA. Tests verify the bytes the driver produces.

1. **Single-block backward compat** — `read_block(nsid, lba, phys)` produces identical SQE to current behavior: NLB=0 in CDW12, PRP1=phys, PRP2=0, `prp_list=None`
2. **Two-page transfer** — `read_blocks(nsid, lba, &[p0, p1])`: PRP1=p0, PRP2=p1, NLB=1, `prp_list=None`
3. **Three-page transfer** — `read_blocks(nsid, lba, &[p0, p1, p2])`: PRP1=p0, PRP2=sentinel, `prp_list=Some([p1, p2] as LE bytes)`, NLB=2
4. **Large transfer (8 pages)** — Verify PRP list contains all 7 remaining addresses, NLB=7
5. **Write variants** — Same PRP logic applies to `write_blocks()`
6. **MDTS enforcement** — Set MDTS=2 (max 4 pages), request 5 pages → `TransferTooLarge`
7. **MDTS=0 (no limit)** — 64 pages accepted without error
8. **Alignment validation** — Non-4KiB-aligned address → `UnalignedAddress`
9. **Empty pages slice** — Returns `TransferTooLarge` (0 blocks is below the minimum of 1)
10. **LBA overflow** — `lba=u64::MAX, pages.len()=2` → error
11. **State validation** — Multi-block commands rejected when not in `Ready` state
12. **CID increment** — Multi-block commands increment CID like single-block
13. **Doorbell values** — Same doorbell arithmetic as single-block (queue pair is unchanged)

---

## Scope Boundary

**In scope:**
- `io_rw_command()` refactor to accept `pages` slice
- PRP list construction in the driver
- MDTS storage, getter, and enforcement
- New `NvmeError` variants
- `read_blocks()`/`write_blocks()` public methods
- `read_block()`/`write_block()` become thin wrappers
- `AdminCommand.prp_list` field
- All tests listed above

**Out of scope:**
- `NvmeBlockDevice` adapter (BlockDevice trait impl) — separate bead
- DMA buffer management / allocator — separate concern
- FAT32 or FatServer integration
- Scatter-gather for non-contiguous buffers (the `pages` slice handles this naturally)
- SGL (Scatter-Gather List) support — PRP is sufficient for this tier
