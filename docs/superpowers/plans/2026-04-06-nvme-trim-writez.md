# NVMe TRIM and Write Zeroes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Dataset Management (TRIM/deallocate) and Write Zeroes commands to the NVMe driver, with ONCS capability enforcement.

**Architecture:** All changes in `crates/harmony-unikernel/src/drivers/nvme.rs`. Sans-I/O pattern preserved — driver builds SQE bytes and data buffers, caller handles DMA. Three additions: ONCS capability field + enforcement, Write Zeroes command, Dataset Management command with structured range input.

**Tech Stack:** Rust, `no_std` (`alloc` for `Vec`), `MockRegisterBank` for testing.

**Spec:** `docs/superpowers/specs/2026-04-06-nvme-trim-writez-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `crates/harmony-unikernel/src/drivers/nvme.rs` | Modify | All changes — types, fields, methods, tests |

---

### Task 1: ONCS support — types, storage, accessors, and Identify Controller parsing

Add the `oncs` field to `NvmeDriver` and `IdentifyController`, the `UnsupportedCommand` error variant, and the `set_oncs()`/`supports_*()` accessors.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:174-182` (IdentifyController struct)
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:199-222` (NvmeError enum)
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:245-267` (NvmeDriver struct)
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:406-416` (init constructor)
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:311-355` (accessor impl block)
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:881-913` (parse_identify_controller)
- Test: same file, tests module

- [ ] **Step 1: Write tests for ONCS defaults, storage, partial support, and Identify Controller parsing**

Add these four tests at the end of the test module (before the closing `}`):

```rust
// ── ONCS tests ───────────────────────────────────────────────────────

#[test]
fn oncs_defaults_to_zero() {
    let driver = ready_driver();
    assert!(!driver.supports_write_zeroes());
    assert!(!driver.supports_dataset_management());
}

#[test]
fn set_oncs_stores_value() {
    let mut driver = ready_driver();
    driver.set_oncs(0x0C); // bits 2 + 3
    assert!(driver.supports_write_zeroes());
    assert!(driver.supports_dataset_management());
}

#[test]
fn oncs_partial_support() {
    let mut driver = ready_driver();
    driver.set_oncs(0x04); // bit 2 only
    assert!(!driver.supports_write_zeroes());
    assert!(driver.supports_dataset_management());
}

#[test]
fn parse_identify_controller_extracts_oncs() {
    let mut data = [0u8; 4096];
    // ONCS: bytes 256-257 (LE u16), set bits 2 and 3
    data[256] = 0x0C;
    data[257] = 0x00;
    let ic = parse_identify_controller(&data);
    assert_eq!(ic.oncs, 0x000C);
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test -p harmony-unikernel -- oncs 2>&1 | tail -20
```

Expected: 4 failures — `set_oncs`, `supports_write_zeroes`, `supports_dataset_management`, and `oncs` field don't exist yet.

- [ ] **Step 3: Add `UnsupportedCommand` error variant**

In the `NvmeError` enum (after the `UnalignedAddress` variant at line 221), add:

```rust
    /// The command requires an optional NVM feature (ONCS) not supported by this controller.
    UnsupportedCommand,
```

- [ ] **Step 4: Add `oncs` field to `IdentifyController`**

In the `IdentifyController` struct (after `num_namespaces` at line 181), add:

```rust
    /// Optional NVM Command Support (bytes 256-257).
    /// Bit 2 = Dataset Management, Bit 3 = Write Zeroes.
    pub oncs: u16,
```

- [ ] **Step 5: Parse ONCS in `parse_identify_controller()`**

In `parse_identify_controller()`, after the `num_namespaces` extraction (line 904) and before the struct literal (line 906), add:

```rust
    let oncs = u16::from_le_bytes([data[256], data[257]]);
```

And add `oncs,` to the `IdentifyController` struct literal (after `num_namespaces,`):

```rust
    IdentifyController {
        serial_number,
        model_number,
        firmware_rev,
        max_data_transfer,
        num_namespaces,
        oncs,
    }
```

- [ ] **Step 6: Update the `parse_identify_controller` doc comment table**

Add a row to the doc comment table on `parse_identify_controller()`:

```
/// | 256-257 | ONCS               |
```

- [ ] **Step 7: Add `oncs` field to `NvmeDriver` struct**

After the `mdts: u8` field (line 266), add:

```rust
    /// Optional NVM Command Support from Identify Controller.
    /// 0 = no optional commands. Bit 2 = Dataset Management, Bit 3 = Write Zeroes.
    oncs: u16,
```

- [ ] **Step 8: Initialize `oncs` in `NvmeDriver::init()`**

In the `Self { ... }` constructor (after `mdts: 0,` at line 416), add:

```rust
            oncs: 0,
```

- [ ] **Step 9: Add ONCS accessor methods**

In the public accessors impl block (after `max_transfer_pages()` ending around line 354), add:

```rust
    /// Set the ONCS value from Identify Controller bytes 256-257.
    ///
    /// Call this after parsing the Identify Controller response.
    pub fn set_oncs(&mut self, oncs: u16) {
        self.oncs = oncs;
    }

    /// Whether the controller supports Write Zeroes (ONCS bit 3).
    pub fn supports_write_zeroes(&self) -> bool {
        (self.oncs >> 3) & 1 == 1
    }

    /// Whether the controller supports Dataset Management (ONCS bit 2).
    pub fn supports_dataset_management(&self) -> bool {
        (self.oncs >> 2) & 1 == 1
    }
```

- [ ] **Step 10: Run tests to verify they pass**

```bash
cargo test -p harmony-unikernel -- oncs 2>&1 | tail -20
```

Expected: All 4 ONCS tests pass. Also run the full suite:

```bash
cargo test -p harmony-unikernel 2>&1 | tail -5
```

Expected: All existing tests still pass (the identify controller test will need the new `oncs` field — but it doesn't check `oncs`, so the zero default is fine). Verify the existing `parse_identify_controller_extracts_fields` test still passes (it doesn't set bytes 256-257, so `oncs` will be 0, which is fine since it doesn't assert on `oncs`).

- [ ] **Step 11: Run clippy**

```bash
cargo clippy -p harmony-unikernel 2>&1 | tail -10
```

Expected: No warnings.

- [ ] **Step 12: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add ONCS capability field, accessors, and Identify Controller parsing

Add oncs: u16 to NvmeDriver and IdentifyController, set_oncs(),
supports_write_zeroes(), supports_dataset_management(), and
UnsupportedCommand error variant. Parse ONCS from Identify Controller
bytes 256-257.

Part of harmony-os-ebp."
```

---

### Task 2: `data_buffer` field on `AdminCommand`

Add the `data_buffer: Option<Vec<u8>>` field to `AdminCommand` and initialize it to `None` in `QueuePair::submit()`.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:45-62` (AdminCommand struct)
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:156-171` (QueuePair::submit)

- [ ] **Step 1: Add `data_buffer` field to `AdminCommand`**

After the `prp_list` field (line 61), add:

```rust
    /// Optional data buffer for commands that need a host-memory descriptor
    /// (e.g., Dataset Management range list).  The caller must write these bytes
    /// to a 4 KiB-aligned physical address, then patch SQE bytes 24–31 (PRP1)
    /// with that address before submitting.
    pub data_buffer: Option<Vec<u8>>,
```

- [ ] **Step 2: Initialize `data_buffer` to `None` in `QueuePair::submit()`**

In the `AdminCommand` struct literal inside `submit()` (after `prp_list: None,` at line 169), add:

```rust
            data_buffer: None,
```

- [ ] **Step 3: Run full test suite**

```bash
cargo test -p harmony-unikernel 2>&1 | tail -5
```

Expected: All tests pass. No existing code inspects `data_buffer`, so this is a purely additive change.

- [ ] **Step 4: Run clippy**

```bash
cargo clippy -p harmony-unikernel 2>&1 | tail -10
```

Expected: No warnings.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add data_buffer field to AdminCommand

For commands that need a host-memory descriptor (e.g., TRIM range list).
The caller writes buffer bytes to DMA, then patches PRP1 in the SQE.
Initialized to None for all existing commands.

Part of harmony-os-ebp."
```

---

### Task 3: Write Zeroes command

Add `write_zeroes()` with all validation and tests.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:660-830` (Block I/O commands impl block)
- Test: same file, tests module

- [ ] **Step 1: Write tests for Write Zeroes**

Add these 8 tests at the end of the test module (before the closing `}`):

```rust
// ── Write Zeroes tests ───────────────────────────────────────────────

#[test]
fn write_zeroes_builds_correct_sqe() {
    let mut driver = ready_driver();
    driver.set_oncs(0x08); // bit 3 = Write Zeroes
    let cmd = driver.write_zeroes(1, 100, 16).unwrap();

    // Opcode = 0x08
    let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
    assert_eq!(cdw0 & 0xFF, 0x08);

    // NSID
    let nsid = u32::from_le_bytes(cmd.sqe[4..8].try_into().unwrap());
    assert_eq!(nsid, 1);

    // PRP1 = 0 (no data transfer)
    let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
    assert_eq!(prp1, 0);

    // PRP2 = 0 (no data transfer)
    let prp2 = u64::from_le_bytes(cmd.sqe[32..40].try_into().unwrap());
    assert_eq!(prp2, 0);

    // CDW10 = LBA low bits
    let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
    assert_eq!(cdw10, 100);

    // CDW11 = LBA high bits
    let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
    assert_eq!(cdw11, 0);

    // CDW12 = NLB (0-based) = 15, DEAC=0
    let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
    assert_eq!(cdw12, 15);

    // No data buffers
    assert!(cmd.prp_list.is_none());
    assert!(cmd.data_buffer.is_none());
}

#[test]
fn write_zeroes_rejects_unsupported() {
    let mut driver = ready_driver();
    // ONCS = 0 — Write Zeroes not supported
    assert_eq!(
        driver.write_zeroes(1, 0, 1).unwrap_err(),
        NvmeError::UnsupportedCommand
    );
}

#[test]
fn write_zeroes_rejects_zero_blocks() {
    let mut driver = ready_driver();
    driver.set_oncs(0x08);
    assert_eq!(
        driver.write_zeroes(1, 0, 0).unwrap_err(),
        NvmeError::TransferTooLarge
    );
}

#[test]
fn write_zeroes_accepts_max_blocks() {
    let mut driver = ready_driver();
    driver.set_oncs(0x08);
    let cmd = driver.write_zeroes(1, 0, 65536).unwrap();
    let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
    assert_eq!(cdw12, 65535); // NLB = 65536 - 1
}

#[test]
fn write_zeroes_rejects_too_many_blocks() {
    let mut driver = ready_driver();
    driver.set_oncs(0x08);
    assert_eq!(
        driver.write_zeroes(1, 0, 65537).unwrap_err(),
        NvmeError::TransferTooLarge
    );
}

#[test]
fn write_zeroes_rejects_lba_overflow() {
    let mut driver = ready_driver();
    driver.set_oncs(0x08);
    assert_eq!(
        driver.write_zeroes(1, u64::MAX, 2).unwrap_err(),
        NvmeError::TransferTooLarge
    );
}

#[test]
fn write_zeroes_rejects_non_ready_state() {
    let mut driver = enabled_driver();
    assert_eq!(
        driver.write_zeroes(1, 0, 1).unwrap_err(),
        NvmeError::InvalidState
    );
}

#[test]
fn write_zeroes_increments_cid() {
    let mut driver = ready_driver();
    driver.set_oncs(0x08);
    let cmd1 = driver.write_zeroes(1, 0, 1).unwrap();
    let cmd2 = driver.write_zeroes(1, 0, 1).unwrap();
    let cid1 = u32::from_le_bytes(cmd1.sqe[0..4].try_into().unwrap()) >> 16;
    let cid2 = u32::from_le_bytes(cmd2.sqe[0..4].try_into().unwrap()) >> 16;
    assert_eq!(cid2, cid1 + 1);
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test -p harmony-unikernel -- write_zeroes 2>&1 | tail -20
```

Expected: 8 failures — `write_zeroes` method doesn't exist yet.

- [ ] **Step 3: Implement `write_zeroes()`**

In the Block I/O commands impl block, after the `flush()` method (around line 829) and before the closing `}` of that impl block, add:

```rust
    /// Build an NVM Write Zeroes command (opcode 0x08).
    ///
    /// Zeros the LBA range `[lba, lba + block_count)` without data transfer.
    /// The controller generates zeros internally; no PRPs are used.
    /// DEAC (Deallocate) is always 0 — reads after Write Zeroes return
    /// deterministic zero bytes.
    ///
    /// Requires ONCS bit 3 (Write Zeroes support).
    pub fn write_zeroes(
        &mut self,
        nsid: u32,
        lba: u64,
        block_count: u32,
    ) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }
        if !self.supports_write_zeroes() {
            return Err(NvmeError::UnsupportedCommand);
        }
        if block_count == 0 || block_count > 65536 {
            return Err(NvmeError::TransferTooLarge);
        }
        if lba.checked_add(block_count as u64).is_none() {
            return Err(NvmeError::TransferTooLarge);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let nlb = (block_count - 1) & 0xFFFF;

        let mut sqe = [0u8; 64];
        // CDW0: opcode 0x08 | CID
        let cdw0: u32 = 0x08 | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
        // NSID
        sqe[4..8].copy_from_slice(&nsid.to_le_bytes());
        // PRP1 = 0, PRP2 = 0 (no data transfer)
        // (sqe is zero-initialized, so bytes 24-39 are already 0)
        // CDW10: LBA bits 31:0
        sqe[40..44].copy_from_slice(&(lba as u32).to_le_bytes());
        // CDW11: LBA bits 63:32
        sqe[44..48].copy_from_slice(&((lba >> 32) as u32).to_le_bytes());
        // CDW12: NLB (bits 15:0), DEAC=0 (bit 25)
        sqe[48..52].copy_from_slice(&nlb.to_le_bytes());

        let mut cmd = self
            .io
            .as_mut()
            .ok_or(NvmeError::InvalidState)?
            .submit(sqe, self.doorbell_stride);
        cmd.prp_list = None;
        cmd.data_buffer = None;
        Ok(cmd)
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p harmony-unikernel -- write_zeroes 2>&1 | tail -20
```

Expected: All 8 Write Zeroes tests pass.

```bash
cargo test -p harmony-unikernel 2>&1 | tail -5
```

Expected: All existing tests still pass.

- [ ] **Step 5: Run clippy**

```bash
cargo clippy -p harmony-unikernel 2>&1 | tail -10
```

Expected: No warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add Write Zeroes command (opcode 0x08)

Zeros an LBA range without data transfer. DEAC always 0 for
deterministic zeros. Validates ONCS bit 3, block count 1-65536,
and LBA overflow. 8 tests.

Part of harmony-os-ebp."
```

---

### Task 4: DsmRange type and Dataset Management command

Add the `DsmRange` struct and `dataset_management()` with range serialization and all validation.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs` (new struct near types section, new method in Block I/O impl)
- Test: same file, tests module

- [ ] **Step 1: Write tests for Dataset Management**

Add these 10 tests at the end of the test module (before the closing `}`):

```rust
// ── Dataset Management (TRIM) tests ──────────────────────────────────

#[test]
fn dataset_management_builds_correct_sqe() {
    let mut driver = ready_driver();
    driver.set_oncs(0x04); // bit 2 = Dataset Management
    let ranges = [DsmRange { lba: 100, block_count: 16 }];
    let cmd = driver.dataset_management(1, &ranges).unwrap();

    // Opcode = 0x09
    let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
    assert_eq!(cdw0 & 0xFF, 0x09);

    // NSID
    let nsid = u32::from_le_bytes(cmd.sqe[4..8].try_into().unwrap());
    assert_eq!(nsid, 1);

    // PRP1 = sentinel (caller patches with DMA address)
    let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
    assert_eq!(prp1, u64::MAX);

    // PRP2 = 0
    let prp2 = u64::from_le_bytes(cmd.sqe[32..40].try_into().unwrap());
    assert_eq!(prp2, 0);

    // CDW10 = NR (0-based) = 0
    let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
    assert_eq!(cdw10, 0);

    // CDW11 = 0x04 (AD bit)
    let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
    assert_eq!(cdw11, 0x04);

    // data_buffer present, prp_list absent
    assert!(cmd.data_buffer.is_some());
    assert!(cmd.prp_list.is_none());
}

#[test]
fn dataset_management_rejects_unsupported() {
    let mut driver = ready_driver();
    // ONCS = 0 — Dataset Management not supported
    let ranges = [DsmRange { lba: 0, block_count: 1 }];
    assert_eq!(
        driver.dataset_management(1, &ranges).unwrap_err(),
        NvmeError::UnsupportedCommand
    );
}

#[test]
fn dataset_management_single_range_serialization() {
    let mut driver = ready_driver();
    driver.set_oncs(0x04);
    let ranges = [DsmRange { lba: 0x0000_DEAD_BEEF_0000, block_count: 42 }];
    let cmd = driver.dataset_management(1, &ranges).unwrap();
    let buf = cmd.data_buffer.unwrap();

    assert_eq!(buf.len(), 16);
    // Context attributes: bytes 0-3 = 0
    assert_eq!(&buf[0..4], &[0, 0, 0, 0]);
    // Length in LBAs: bytes 4-7 = 42 LE
    assert_eq!(&buf[4..8], &42u32.to_le_bytes());
    // Starting LBA: bytes 8-15 = 0x0000_DEAD_BEEF_0000 LE
    assert_eq!(&buf[8..16], &0x0000_DEAD_BEEF_0000u64.to_le_bytes());
}

#[test]
fn dataset_management_multiple_ranges() {
    let mut driver = ready_driver();
    driver.set_oncs(0x04);
    let ranges = [
        DsmRange { lba: 100, block_count: 10 },
        DsmRange { lba: 500, block_count: 20 },
        DsmRange { lba: 1000, block_count: 30 },
    ];
    let cmd = driver.dataset_management(1, &ranges).unwrap();

    // CDW10 = NR = 2 (3 ranges, 0-based)
    let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
    assert_eq!(cdw10, 2);

    let buf = cmd.data_buffer.unwrap();
    assert_eq!(buf.len(), 48); // 3 * 16

    // Range 0
    assert_eq!(&buf[4..8], &10u32.to_le_bytes());
    assert_eq!(&buf[8..16], &100u64.to_le_bytes());

    // Range 1
    assert_eq!(&buf[20..24], &20u32.to_le_bytes());
    assert_eq!(&buf[24..32], &500u64.to_le_bytes());

    // Range 2
    assert_eq!(&buf[36..40], &30u32.to_le_bytes());
    assert_eq!(&buf[40..48], &1000u64.to_le_bytes());
}

#[test]
fn dataset_management_max_ranges() {
    let mut driver = ready_driver();
    driver.set_oncs(0x04);
    let ranges: Vec<DsmRange> = (0..256)
        .map(|i| DsmRange { lba: i as u64 * 100, block_count: 1 })
        .collect();
    let cmd = driver.dataset_management(1, &ranges).unwrap();

    // CDW10 = NR = 255
    let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
    assert_eq!(cdw10, 255);

    let buf = cmd.data_buffer.unwrap();
    assert_eq!(buf.len(), 256 * 16);
}

#[test]
fn dataset_management_rejects_too_many_ranges() {
    let mut driver = ready_driver();
    driver.set_oncs(0x04);
    let ranges: Vec<DsmRange> = (0..257)
        .map(|i| DsmRange { lba: i as u64, block_count: 1 })
        .collect();
    assert_eq!(
        driver.dataset_management(1, &ranges).unwrap_err(),
        NvmeError::TransferTooLarge
    );
}

#[test]
fn dataset_management_rejects_empty_ranges() {
    let mut driver = ready_driver();
    driver.set_oncs(0x04);
    assert_eq!(
        driver.dataset_management(1, &[]).unwrap_err(),
        NvmeError::TransferTooLarge
    );
}

#[test]
fn dataset_management_rejects_non_ready_state() {
    let mut driver = enabled_driver();
    let ranges = [DsmRange { lba: 0, block_count: 1 }];
    assert_eq!(
        driver.dataset_management(1, &ranges).unwrap_err(),
        NvmeError::InvalidState
    );
}

#[test]
fn dataset_management_increments_cid() {
    let mut driver = ready_driver();
    driver.set_oncs(0x04);
    let ranges = [DsmRange { lba: 0, block_count: 1 }];
    let cmd1 = driver.dataset_management(1, &ranges).unwrap();
    let cmd2 = driver.dataset_management(1, &ranges).unwrap();
    let cid1 = u32::from_le_bytes(cmd1.sqe[0..4].try_into().unwrap()) >> 16;
    let cid2 = u32::from_le_bytes(cmd2.sqe[0..4].try_into().unwrap()) >> 16;
    assert_eq!(cid2, cid1 + 1);
}

#[test]
fn dataset_management_range_serialization_byte_layout() {
    let mut driver = ready_driver();
    driver.set_oncs(0x04);
    let ranges = [DsmRange { lba: 0x0102_0304_0506_0708, block_count: 0x0A0B_0C0D }];
    let cmd = driver.dataset_management(1, &ranges).unwrap();
    let buf = cmd.data_buffer.unwrap();

    // 16 bytes total
    assert_eq!(buf.len(), 16);
    // Context attributes: 4 zero bytes
    assert_eq!(buf[0], 0);
    assert_eq!(buf[1], 0);
    assert_eq!(buf[2], 0);
    assert_eq!(buf[3], 0);
    // Length (LE u32): 0x0A0B0C0D → [0x0D, 0x0C, 0x0B, 0x0A]
    assert_eq!(buf[4], 0x0D);
    assert_eq!(buf[5], 0x0C);
    assert_eq!(buf[6], 0x0B);
    assert_eq!(buf[7], 0x0A);
    // Starting LBA (LE u64): 0x0102030405060708 → [08, 07, 06, 05, 04, 03, 02, 01]
    assert_eq!(buf[8], 0x08);
    assert_eq!(buf[9], 0x07);
    assert_eq!(buf[10], 0x06);
    assert_eq!(buf[11], 0x05);
    assert_eq!(buf[12], 0x04);
    assert_eq!(buf[13], 0x03);
    assert_eq!(buf[14], 0x02);
    assert_eq!(buf[15], 0x01);
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test -p harmony-unikernel -- dataset_management 2>&1 | tail -20
```

Expected: 10 failures — `DsmRange` and `dataset_management` don't exist yet.

- [ ] **Step 3: Add `DsmRange` struct**

Add this near the other type definitions, after the `IdentifyNamespace` struct (around line 197) and before the error type section:

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

- [ ] **Step 4: Implement `dataset_management()`**

In the Block I/O commands impl block, after the `write_zeroes()` method, add:

```rust
    /// Build an NVM Dataset Management command (opcode 0x09) for TRIM/deallocate.
    ///
    /// Informs the controller that the given LBA ranges are no longer in use.
    /// The AD (Attribute Deallocate) bit is always set.
    ///
    /// The serialized range descriptors are returned in
    /// [`AdminCommand::data_buffer`].  The caller must write these bytes to a
    /// 4 KiB-aligned physical address, then patch SQE bytes 24–31 (PRP1) with
    /// that address before submitting.
    ///
    /// Requires ONCS bit 2 (Dataset Management support).  Max 256 ranges.
    pub fn dataset_management(
        &mut self,
        nsid: u32,
        ranges: &[DsmRange],
    ) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }
        if !self.supports_dataset_management() {
            return Err(NvmeError::UnsupportedCommand);
        }
        if ranges.is_empty() || ranges.len() > 256 {
            return Err(NvmeError::TransferTooLarge);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        // Serialize range descriptors (16 bytes each).
        let mut buf = Vec::with_capacity(ranges.len() * 16);
        for range in ranges {
            // Context Attributes (4 bytes) — always 0
            buf.extend_from_slice(&0u32.to_le_bytes());
            // Length in LBAs (4 bytes)
            buf.extend_from_slice(&range.block_count.to_le_bytes());
            // Starting LBA (8 bytes)
            buf.extend_from_slice(&range.lba.to_le_bytes());
        }

        let mut sqe = [0u8; 64];
        // CDW0: opcode 0x09 | CID
        let cdw0: u32 = 0x09 | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
        // NSID
        sqe[4..8].copy_from_slice(&nsid.to_le_bytes());
        // PRP1 = sentinel — caller patches with DMA address of range buffer
        sqe[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        // PRP2 = 0
        // (sqe is zero-initialized, so bytes 32-39 are already 0)
        // CDW10: NR (Number of Ranges, 0-based)
        let nr = (ranges.len() as u32) - 1;
        sqe[40..44].copy_from_slice(&nr.to_le_bytes());
        // CDW11: AD bit (bit 2) = Attribute Deallocate
        sqe[44..48].copy_from_slice(&0x04u32.to_le_bytes());

        let mut cmd = self
            .io
            .as_mut()
            .ok_or(NvmeError::InvalidState)?
            .submit(sqe, self.doorbell_stride);
        cmd.prp_list = None;
        cmd.data_buffer = Some(buf);
        Ok(cmd)
    }
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cargo test -p harmony-unikernel -- dataset_management 2>&1 | tail -20
```

Expected: All 10 Dataset Management tests pass.

```bash
cargo test -p harmony-unikernel 2>&1 | tail -5
```

Expected: All tests pass (existing + new).

- [ ] **Step 6: Run clippy**

```bash
cargo clippy -p harmony-unikernel 2>&1 | tail -10
```

Expected: No warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add Dataset Management (TRIM) command (opcode 0x09)

DsmRange struct for structured range input, serialized to 16-byte NVMe
range descriptors. PRP1 sentinel for caller DMA patching. AD bit always
set. Validates ONCS bit 2, range count 1-256. 10 tests.

Part of harmony-os-ebp."
```

---

### Task 5: Final integration — format, full test run, verify

Run formatting, full test suite, and clippy one final time to confirm everything is clean.

**Files:**
- No modifications — verification only

- [ ] **Step 1: Run nightly rustfmt**

```bash
cargo +nightly fmt --all
```

- [ ] **Step 2: Run full test suite**

```bash
cargo test --workspace 2>&1 | tail -10
```

Expected: All tests pass across all crates. Pay attention to the test count — should be previous count + 22 new tests.

- [ ] **Step 3: Run clippy**

```bash
cargo clippy --workspace 2>&1 | tail -10
```

Expected: No warnings.

- [ ] **Step 4: Commit formatting changes (if any)**

If `cargo +nightly fmt` changed anything:

```bash
git add -A
git commit -m "style: apply nightly rustfmt

Part of harmony-os-ebp."
```

If no changes, skip this step.

- [ ] **Step 5: Verify test count**

```bash
cargo test -p harmony-unikernel 2>&1 | grep "test result"
```

Expected: 22 new tests (4 ONCS + 8 Write Zeroes + 10 Dataset Management) added to the existing count.
