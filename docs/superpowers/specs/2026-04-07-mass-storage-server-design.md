# USB Mass Storage Block Device

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Bead:** harmony-os-yko

**Goal:** Wire up the existing Ring 1 `MassStorageDevice` (CBW builders, SCSI parsers) into a Ring 2 `BlockDevice` implementation, enabling `FatServer` to read files from USB flash drives via the existing 9P filesystem path.

**Prerequisite:** xHCI Phase 3b (harmony-os-ho8) is merged. HID boot driver (harmony-os-yrg) is merged.

---

## Architecture

No new FileServer. Two new Ring 2 units plug into the existing `FatServer<PartitionBlockDevice<...>>` pipeline.

**Ring 1 — unchanged.** `MassStorageDevice` (CBW builders, SCSI parsers) and `BlockDevice` trait stay exactly as-is.

**Ring 2 — `MassStorageBus`** (`harmony-microkernel/src/mass_storage_bus.rs`)
Sans-I/O state machine that sequences the multi-step BOT (Bulk-Only Transport) protocol. Wraps a `MassStorageDevice` for building CBWs and parsing responses. Tracks both the high-level operation (init step or read) and the transfer phase (sending CBW, receiving data, receiving CSW). Two modes:
- Init mode: INQUIRY → TEST UNIT READY → READ CAPACITY(10). Caches block_size and capacity_blocks.
- Read mode: READ(10) CBW → data IN → CSW. Returns sector data.

**Ring 2 — `BulkTransport` trait + `MassStorageBlockDevice`** (`harmony-microkernel/src/mass_storage_block.rs`)
- `BulkTransport` trait abstracts bulk transfer execution.
- `MassStorageBlockDevice<T: BulkTransport>` implements `BlockDevice` by driving the `MassStorageBus` through the transport.
- `MockBulkTransport` for testing (queued canned responses).

**Integration stack:**
```
FatServer<PartitionBlockDevice<MassStorageBlockDevice<T>>>
    │              │                    │
    │              │                    └── drives MassStorageBus via BulkTransport
    │              └── adds partition LBA offset
    └── reads FAT32 directory entries and file data
```

Identical to the SD card path (`FatServer<PartitionBlockDevice<SdhciBlockDevice<B>>>`), just swapping the block device backend.

### What stays the same

- `MassStorageDevice` (Ring 1) — unchanged
- `BlockDevice` trait — unchanged
- `FatServer`, `Fat32`, `PartitionBlockDevice` — unchanged
- xHCI driver — unchanged
- All existing tests — unchanged

---

## MassStorageBus State Machine

The bus tracks two layers: the high-level operation and the transfer phase within it.

### States

```
Uninitialized
  → start_init() → InitInquiry/SendingCbw     [returns BulkOut(CBW)]

InitInquiry / InitTestUnitReady / InitReadCapacity
  (each goes through SendingCbw → ReceivingData → ReceivingCsw)
  → after CSW complete, advances to next init step
  → after ReadCapacity CSW → Ready               [returns InitComplete { block_size, capacity }]

Ready
  → start_read(lba) → Reading/SendingCbw        [returns BulkOut(CBW)]

Reading
  → SendingCbw → ReceivingData → ReceivingCsw
  → after CSW complete → Ready                   [returns ReadComplete(data)]
```

### Transfer Phases

Each operation cycles through:
1. **SendingCbw** — caller sends CBW via bulk OUT, calls `handle_bulk_out_complete()`
2. **ReceivingData** — caller reads data via bulk IN, calls `handle_bulk_in_complete(data)`. Skipped for TEST UNIT READY (no data phase).
3. **ReceivingCsw** — caller reads 13-byte CSW via bulk IN, calls `handle_bulk_in_complete(csw_bytes)`

### MsAction Enum

- `BulkOut { endpoint: u8, data: [u8; 31] }` — send CBW (always 31 bytes)
- `BulkIn { endpoint: u8, length: u16 }` — read response data or CSW
- `InitComplete { block_size: u32, capacity_blocks: u32 }` — init done, device ready
- `ReadComplete(Vec<u8>)` — sector data from a read operation
- `Error(MsError)` — CSW failure, invalid signature, or wrong-state call

### Internal State

- `device: MassStorageDevice` — Ring 1 CBW builder + parsers
- `state: BusState` — Uninitialized / InitInquiry / InitTestUnitReady / InitReadCapacity / Ready / Reading
- `phase: TransferPhase` — SendingCbw / ReceivingData / ReceivingCsw
- `block_size: u32` — from READ CAPACITY (0 until init complete)
- `capacity_blocks: u32` — last_lba + 1, saturating (0 until init complete)
- `pending_lba: u32` — LBA of current read operation

### Error Handling

- CSW status != 0 (command failed) → `MsAction::Error`
- Invalid CSW signature → `MsAction::Error`
- Wrong-state calls (e.g., `start_read` before init) → `MsAction::Error`
- No recovery (CLEAR_FEATURE, bulk-only reset) — fail the operation
- Caller-side bulk transfer failures are the caller's problem

---

## BulkTransport Trait & BlockDevice Adapter

### BulkTransport

```rust
pub trait BulkTransport {
    fn bulk_out(&mut self, endpoint: u8, data: &[u8]) -> Result<(), IpcError>;
    fn bulk_in(&mut self, endpoint: u8, buf: &mut [u8]) -> Result<usize, IpcError>;
}
```

Minimal interface. Real xHCI implementation handles TRB queueing, doorbell ringing, and completion polling internally. This bead only delivers `MockBulkTransport`.

### MassStorageBlockDevice

```rust
pub struct MassStorageBlockDevice<T: BulkTransport> {
    bus: MassStorageBus,
    transport: T,
}
```

**`init(&mut self) -> Result<(), IpcError>`** — Drives the bus through the full init sequence. For each `MsAction`:
- `BulkOut` → `transport.bulk_out()` → `bus.handle_bulk_out_complete()`
- `BulkIn` → allocate buffer, `transport.bulk_in()` → `bus.handle_bulk_in_complete(data)`
- `InitComplete` → done
- `Error` → return Err

**`BlockDevice` impl:**
- `read_block(lba, buf)` — Calls `bus.start_read(lba)`, drives CBW→data→CSW loop. On `ReadComplete(data)`, copies into `buf`.
- `capacity_blocks()` — Returns cached value from bus.

### MockBulkTransport (test only)

```rust
struct MockBulkTransport {
    out_log: Vec<Vec<u8>>,           // records all bulk OUT data
    in_responses: VecDeque<Vec<u8>>, // pre-queued bulk IN responses
}
```

Tests push canned responses (INQUIRY response, CSW bytes, sector data) into `in_responses`. The mock records outgoing data in `out_log` for CBW verification. Same pattern as `MockRegisterBank` for SDHCI.

---

## Testing

All tests use `MockBulkTransport`. No hardware, no xHCI, no DMA.

### MassStorageBus unit tests

1. **start_init returns BulkOut with INQUIRY CBW** — verify first action is bulk OUT with INQUIRY opcode
2. **init inquiry sequence** — bulk_out_complete → BulkIn(36) → inquiry data → BulkIn(13) → CSW → advances to TestUnitReady
3. **init test_unit_ready sequence** — no data phase: CBW out → CSW in directly
4. **init read_capacity sequence** — CBW out → data in (8 bytes) → CSW in → `InitComplete { block_size: 512, capacity_blocks }`
5. **full init sequence** — drive all three steps to completion, verify `InitComplete`
6. **start_read before init** — returns `Error`
7. **read sequence** — `start_read(lba)` → BulkOut(CBW) → complete → BulkIn(512) → data → BulkIn(13) → CSW → `ReadComplete(data)`
8. **read CSW failed status** — CSW with status=1 → `Error`
9. **read CSW invalid signature** — garbage CSW → `Error`
10. **multiple sequential reads** — two reads back-to-back, both succeed, tags increment
11. **double start_read while busy** — returns `Error` (wrong state)

### MassStorageBlockDevice integration tests

12. **init succeeds** — mock returns valid INQUIRY/CSW/TUR/CSW/ReadCap/CSW → init() returns Ok
13. **init failure** — mock returns failed CSW during TEST UNIT READY → init() returns Err
14. **capacity_blocks after init** — returns value from READ CAPACITY
15. **read_block returns sector data** — mock queued with responses → read_block returns correct data
16. **read_block verifies CBW sent** — check `out_log` contains correct READ(10) CBW with expected LBA
17. **read_block before init** — returns Err
18. **read_block CSW failure** — mock returns failed CSW → read_block returns Err
19. **sequential reads** — two read_block calls with different LBAs, both return correct data

---

## Scope Boundary

**In scope:**
- `MassStorageBus` sans-I/O state machine (`mass_storage_bus.rs` in Ring 2)
- Init sequence: INQUIRY → TEST UNIT READY → READ CAPACITY(10)
- Read sequence: READ(10) CBW → data IN → CSW
- `MsAction` enum and `MsError` error type
- `BulkTransport` trait (`mass_storage_block.rs` in Ring 2)
- `MassStorageBlockDevice<T: BulkTransport>` implementing `BlockDevice`
- `MockBulkTransport` test helper
- All 19 tests listed above

**Out of scope:**
- Write support (Ring 1 has `build_write_cbw` but no consumer)
- `XhciBulkTransport` (real xHCI integration — future bead)
- Error recovery (CLEAR_FEATURE, bulk-only reset)
- USB device enumeration / class driver dispatch
- Multiple USB mass storage devices simultaneously
- 4K block size support (assumes 512-byte sectors)
- REQUEST SENSE after failed commands
- MODE SENSE write-protect checking
- Any changes to Ring 1 `MassStorageDevice`
- Any changes to existing `BlockDevice`, `FatServer`, `PartitionBlockDevice`
