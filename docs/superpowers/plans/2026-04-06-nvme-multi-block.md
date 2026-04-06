# NVMe Multi-Block Transfers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend NVMe Read/Write to support multi-block transfers using PRP2 and PRP lists, with MDTS enforcement.

**Architecture:** Refactor `io_rw_command()` to accept a slice of physical page addresses instead of a single address. The driver builds complete SQE bytes and optional PRP list bytes; the caller writes them to DMA memory. MDTS is stored from Identify Controller and enforced at command-build time. Existing `read_block`/`write_block` become thin wrappers.

**Tech Stack:** Rust (`no_std` + `alloc`), `MockRegisterBank` for testing.

**Spec:** `docs/superpowers/specs/2026-04-06-nvme-multi-block-design.md`

---

## File Structure

All changes are in one file:

- **Modify:** `crates/harmony-unikernel/src/drivers/nvme.rs`
  - Add `NvmeError::TransferTooLarge` and `NvmeError::UnalignedAddress` variants
  - Add `mdts: u8` field to `NvmeDriver`
  - Add `prp_list: Option<alloc::vec::Vec<u8>>` field to `AdminCommand`
  - Add `set_mdts()` and `max_transfer_blocks()` methods
  - Refactor `io_rw_command()` to accept `pages: &[u64]`
  - Add `read_blocks()`/`write_blocks()` public methods
  - Update `read_block()`/`write_block()` as wrappers
  - Add ~13 new tests

---

### Task 1: Add new error variants and MDTS storage

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:194-209` (NvmeError enum)
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:232-251` (NvmeDriver struct)
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:295-315` (accessors)
- Test: same file, `mod tests` section

- [ ] **Step 1: Write failing tests for MDTS storage and getter**

Add these tests after the existing `fn ready_driver()` helper (after line 1573). These tests go at the end of the test module, before the closing `}` of `mod tests` (before line 1855).

```rust
    // ── MDTS tests ───────────────────────────────────────────────────────

    #[test]
    fn mdts_defaults_to_zero() {
        let driver = ready_driver();
        assert_eq!(driver.max_transfer_blocks(), None);
    }

    #[test]
    fn set_mdts_stores_value() {
        let mut driver = ready_driver();
        driver.set_mdts(5);
        // MDTS=5 → max transfer = 2^5 = 32 pages
        assert_eq!(driver.max_transfer_blocks(), Some(32));
    }

    #[test]
    fn set_mdts_one_means_one_page() {
        let mut driver = ready_driver();
        driver.set_mdts(1);
        assert_eq!(driver.max_transfer_blocks(), Some(2));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test -p harmony-unikernel -- nvme::tests::mdts 2>&1 | tail -20
```

Expected: compilation errors — `max_transfer_blocks` and `set_mdts` don't exist yet.

- [ ] **Step 3: Add error variants, MDTS field, and accessors**

Add two new variants to `NvmeError` (after `NoCompletion` at line 208):

```rust
    /// The requested transfer exceeds the controller's MDTS.
    TransferTooLarge,
    /// One or more PRP addresses are not 4 KiB-aligned.
    UnalignedAddress,
```

Add `mdts` field to `NvmeDriver` struct (after `state: NvmeState` at line 250):

```rust
    /// Maximum Data Transfer Size exponent from Identify Controller.
    /// 0 = no controller-imposed limit. >0 = max transfer is 2^mdts pages.
    mdts: u8,
```

Initialize `mdts: 0` everywhere `NvmeDriver` is constructed. Find the constructor — it's in `NvmeDriver::init()`. Look for the struct literal that builds `NvmeDriver` (around line 370). Add `mdts: 0,` after `state: NvmeState::Disabled,`.

Add two new public methods in the accessors `impl` block (after `timeout_ms()` at line 314, before the closing `}` at line 316):

```rust
    /// Set the MDTS value from Identify Controller byte 77.
    ///
    /// Call this after parsing the Identify Controller response.
    /// `mdts = 0` means no controller-imposed limit.
    pub fn set_mdts(&mut self, mdts: u8) {
        self.mdts = mdts;
    }

    /// Maximum number of 4 KiB pages per transfer, or `None` if unlimited.
    ///
    /// Derived from MDTS: when non-zero, max pages = 2^mdts.
    pub fn max_transfer_blocks(&self) -> Option<u32> {
        if self.mdts == 0 {
            None
        } else {
            Some(1u32 << self.mdts)
        }
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p harmony-unikernel -- nvme::tests::mdts 2>&1 | tail -20
```

Expected: 3 tests pass.

- [ ] **Step 5: Run full NVMe test suite to check nothing broke**

```bash
cargo test -p harmony-unikernel -- nvme::tests 2>&1 | tail -5
```

Expected: all existing tests still pass (34 + 3 new = 37).

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add MDTS storage and new error variants

Add TransferTooLarge and UnalignedAddress to NvmeError.
Add mdts field to NvmeDriver with set_mdts() and
max_transfer_blocks() getter. Defaults to 0 (no limit).

Part of: harmony-os-9vj"
```

---

### Task 2: Add `prp_list` field to `AdminCommand`

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:44-55` (AdminCommand struct)
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:149-163` (QueuePair::submit)
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:625-653` (io_rw_command)
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:685-703` (flush)
- Test: same file, `mod tests` section

- [ ] **Step 1: Write a failing test verifying prp_list is None for single-block**

Add this test after the MDTS tests from Task 1:

```rust
    // ── PRP list tests ───────────────────────────────────────────────────

    #[test]
    fn read_block_has_no_prp_list() {
        let mut driver = ready_driver();
        let cmd = driver.read_block(1, 0, 0x1000).unwrap();
        assert!(cmd.prp_list.is_none());
    }
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p harmony-unikernel -- nvme::tests::read_block_has_no_prp_list 2>&1 | tail -10
```

Expected: compilation error — `prp_list` field doesn't exist on `AdminCommand`.

- [ ] **Step 3: Add `prp_list` field to `AdminCommand` and set it everywhere**

Add to `AdminCommand` struct (after `doorbell_value` at line 54):

```rust
    /// Optional PRP list bytes for multi-block transfers.
    ///
    /// When `Some`, the caller must write these bytes to a 4 KiB-aligned
    /// physical address, then patch SQE bytes 32–39 (PRP2) with that address
    /// before submitting the command.
    pub prp_list: Option<alloc::vec::Vec<u8>>,
```

Add `use alloc::vec::Vec;` at the top of the file, after the existing `use super::register_bank::RegisterBank;` (line 11):

```rust
use alloc::vec::Vec;
```

Update `QueuePair::submit()` (line 149-163) to include `prp_list: None`:

```rust
    pub fn submit(&mut self, sqe: [u8; 64], doorbell_stride: u8) -> AdminCommand {
        let sq_offset = (self.sq_tail as u64) * 64;
        self.sq_tail = (self.sq_tail + 1) % self.size;

        let stride = 4usize << doorbell_stride;
        let doorbell_offset = 0x1000 + (2 * self.qid as usize) * stride;
        let doorbell_value = self.sq_tail as u32;

        AdminCommand {
            sqe,
            sq_offset,
            doorbell_offset,
            doorbell_value,
            prp_list: None,
        }
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p harmony-unikernel -- nvme::tests::read_block_has_no_prp_list 2>&1 | tail -10
```

Expected: PASS.

- [ ] **Step 5: Run full NVMe test suite**

```bash
cargo test -p harmony-unikernel -- nvme::tests 2>&1 | tail -5
```

Expected: all 38 tests pass (37 + 1 new).

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add prp_list field to AdminCommand

AdminCommand now carries an optional Vec<u8> PRP list for
multi-block transfers. Currently always None — populated
in the next commit when io_rw_command is refactored.

Part of: harmony-os-9vj"
```

---

### Task 3: Refactor `io_rw_command` to accept `pages` slice

This is the core change. After this task, `io_rw_command` accepts `pages: &[u64]` instead of `data_phys: u64`, builds PRP1/PRP2/PRP-list correctly, and sets CDW12 NLB. The existing `read_block`/`write_block` become wrappers.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:625-679` (io_rw_command, read_block, write_block)
- Test: same file, `mod tests` section

- [ ] **Step 1: Write failing tests for multi-block PRP logic**

Add these tests after the `read_block_has_no_prp_list` test from Task 2:

```rust
    #[test]
    fn read_blocks_two_pages_uses_prp2() {
        let mut driver = ready_driver();
        let pages = [0x1_0000u64, 0x2_0000u64];
        let cmd = driver.read_blocks(1, 0, &pages).unwrap();

        // PRP1 = pages[0]
        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        assert_eq!(prp1, 0x1_0000);

        // PRP2 = pages[1]
        let prp2 = u64::from_le_bytes(cmd.sqe[32..40].try_into().unwrap());
        assert_eq!(prp2, 0x2_0000);

        // NLB = 1 (0-based: 2 blocks - 1)
        let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw12, 1);

        // No PRP list needed for 2 pages
        assert!(cmd.prp_list.is_none());
    }

    #[test]
    fn read_blocks_three_pages_builds_prp_list() {
        let mut driver = ready_driver();
        let pages = [0x1_0000u64, 0x2_0000u64, 0x3_0000u64];
        let cmd = driver.read_blocks(1, 0, &pages).unwrap();

        // PRP1 = pages[0]
        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        assert_eq!(prp1, 0x1_0000);

        // PRP2 = sentinel (u64::MAX) — caller replaces with list phys addr
        let prp2 = u64::from_le_bytes(cmd.sqe[32..40].try_into().unwrap());
        assert_eq!(prp2, u64::MAX);

        // NLB = 2 (0-based: 3 blocks - 1)
        let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw12, 2);

        // PRP list contains pages[1] and pages[2] as LE u64s
        let list = cmd.prp_list.as_ref().expect("3 pages needs PRP list");
        assert_eq!(list.len(), 16); // 2 entries × 8 bytes
        let entry0 = u64::from_le_bytes(list[0..8].try_into().unwrap());
        let entry1 = u64::from_le_bytes(list[8..16].try_into().unwrap());
        assert_eq!(entry0, 0x2_0000);
        assert_eq!(entry1, 0x3_0000);
    }

    #[test]
    fn read_blocks_eight_pages_prp_list_has_seven_entries() {
        let mut driver = ready_driver();
        let pages: Vec<u64> = (0..8).map(|i| (i + 1) * 0x1000).collect();
        let cmd = driver.read_blocks(1, 0, &pages).unwrap();

        // NLB = 7 (0-based: 8 blocks - 1)
        let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw12, 7);

        let list = cmd.prp_list.as_ref().expect("8 pages needs PRP list");
        // 7 entries × 8 bytes = 56 bytes
        assert_eq!(list.len(), 56);
        for i in 0..7 {
            let entry = u64::from_le_bytes(list[i * 8..(i + 1) * 8].try_into().unwrap());
            assert_eq!(entry, (i as u64 + 2) * 0x1000);
        }
    }

    #[test]
    fn write_blocks_two_pages_uses_prp2() {
        let mut driver = ready_driver();
        let pages = [0x1_0000u64, 0x2_0000u64];
        let cmd = driver.write_blocks(1, 0, &pages).unwrap();

        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x01); // Write opcode

        let prp2 = u64::from_le_bytes(cmd.sqe[32..40].try_into().unwrap());
        assert_eq!(prp2, 0x2_0000);

        let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw12, 1);
    }

    #[test]
    fn single_block_wrapper_still_works() {
        let mut driver = ready_driver();
        let cmd = driver.read_block(1, 100, 0xBEEF_0000).unwrap();

        // Same assertions as the existing read_block_builds_correct_sqe test
        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x02);
        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        assert_eq!(prp1, 0xBEEF_0000);
        let prp2 = u64::from_le_bytes(cmd.sqe[32..40].try_into().unwrap());
        assert_eq!(prp2, 0);
        let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw12, 0);
        assert!(cmd.prp_list.is_none());
    }

    #[test]
    fn read_blocks_cid_increments() {
        let mut driver = ready_driver();
        let cmd1 = driver.read_blocks(1, 0, &[0x1000, 0x2000]).unwrap();
        let cmd2 = driver.read_blocks(1, 10, &[0x3000, 0x4000]).unwrap();
        let cid1 = u32::from_le_bytes(cmd1.sqe[0..4].try_into().unwrap()) >> 16;
        let cid2 = u32::from_le_bytes(cmd2.sqe[0..4].try_into().unwrap()) >> 16;
        assert_eq!(cid2, cid1 + 1);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test -p harmony-unikernel -- nvme::tests::read_blocks 2>&1 | tail -20
```

Expected: compilation errors — `read_blocks` and `write_blocks` don't exist.

- [ ] **Step 3: Refactor `io_rw_command` and add new public methods**

Replace the entire block I/O `impl` block (lines 622-703, from `// ── Block I/O commands` through the closing `}` of the flush impl) with:

```rust
// ── Block I/O commands ───────────────────────────────────────────────────────

impl<R: RegisterBank> NvmeDriver<R> {
    /// Build an NVM I/O command (Read or Write) and submit via the I/O queue.
    ///
    /// `pages` is a slice of 4 KiB-aligned physical addresses, one per logical
    /// block to transfer.  PRP1/PRP2/PRP-list are set according to the NVMe spec:
    ///
    /// | Pages | PRP1       | PRP2       | prp_list                    |
    /// |-------|------------|------------|-----------------------------|
    /// | 1     | pages[0]   | 0          | None                        |
    /// | 2     | pages[0]   | pages[1]   | None                        |
    /// | 3+    | pages[0]   | u64::MAX   | Some(pages[1..] as LE u64s) |
    ///
    /// For the 3+ case, PRP2 is set to `u64::MAX` as a sentinel.  The caller
    /// must write the `prp_list` bytes to a 4 KiB-aligned physical address, then
    /// patch SQE bytes 32–39 with that address before submitting.
    fn io_rw_command(
        &mut self,
        opcode: u8,
        nsid: u32,
        lba: u64,
        pages: &[u64],
    ) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }
        if pages.is_empty() {
            return Err(NvmeError::TransferTooLarge);
        }
        for &addr in pages {
            if addr & 0xFFF != 0 {
                return Err(NvmeError::UnalignedAddress);
            }
        }
        if let Some(max) = self.max_transfer_blocks() {
            if pages.len() as u32 > max {
                return Err(NvmeError::TransferTooLarge);
            }
        }
        // Check LBA + block_count doesn't overflow u64.
        let block_count = pages.len() as u64;
        if lba.checked_add(block_count).is_none() {
            return Err(NvmeError::TransferTooLarge);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let nlb = (pages.len() as u32) - 1; // NLB is 0-based

        let mut sqe = [0u8; 64];
        let cdw0: u32 = (opcode as u32) | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
        sqe[4..8].copy_from_slice(&nsid.to_le_bytes());
        // PRP1 = first page
        sqe[24..32].copy_from_slice(&pages[0].to_le_bytes());
        // PRP2 depends on page count
        let prp_list = if pages.len() == 1 {
            sqe[32..40].copy_from_slice(&0u64.to_le_bytes());
            None
        } else if pages.len() == 2 {
            sqe[32..40].copy_from_slice(&pages[1].to_le_bytes());
            None
        } else {
            // 3+ pages: PRP2 = sentinel, build PRP list from pages[1..]
            sqe[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
            let mut list = Vec::with_capacity((pages.len() - 1) * 8);
            for &addr in &pages[1..] {
                list.extend_from_slice(&addr.to_le_bytes());
            }
            Some(list)
        };
        // LBA
        sqe[40..44].copy_from_slice(&(lba as u32).to_le_bytes());
        sqe[44..48].copy_from_slice(&((lba >> 32) as u32).to_le_bytes());
        // CDW12: NLB (0-based block count)
        sqe[48..52].copy_from_slice(&nlb.to_le_bytes());

        let mut cmd = self
            .io
            .as_mut()
            .ok_or(NvmeError::InvalidState)?
            .submit(sqe, self.doorbell_stride);
        cmd.prp_list = prp_list;
        Ok(cmd)
    }

    /// Build an NVM Read command for multiple logical blocks.
    ///
    /// `pages` contains one 4 KiB-aligned physical address per block.
    pub fn read_blocks(
        &mut self,
        nsid: u32,
        lba: u64,
        pages: &[u64],
    ) -> Result<AdminCommand, NvmeError> {
        self.io_rw_command(0x02, nsid, lba, pages)
    }

    /// Build an NVM Write command for multiple logical blocks.
    ///
    /// `pages` contains one 4 KiB-aligned physical address per block.
    pub fn write_blocks(
        &mut self,
        nsid: u32,
        lba: u64,
        pages: &[u64],
    ) -> Result<AdminCommand, NvmeError> {
        self.io_rw_command(0x01, nsid, lba, pages)
    }

    /// Build an NVM Read command (opcode 0x02) for one logical block.
    ///
    /// Thin wrapper around [`read_blocks`](Self::read_blocks) with a
    /// single-element page slice.
    pub fn read_block(
        &mut self,
        nsid: u32,
        lba: u64,
        data_phys: u64,
    ) -> Result<AdminCommand, NvmeError> {
        self.read_blocks(nsid, lba, &[data_phys])
    }

    /// Build an NVM Write command (opcode 0x01) for one logical block.
    ///
    /// Thin wrapper around [`write_blocks`](Self::write_blocks) with a
    /// single-element page slice.
    pub fn write_block(
        &mut self,
        nsid: u32,
        lba: u64,
        data_phys: u64,
    ) -> Result<AdminCommand, NvmeError> {
        self.write_blocks(nsid, lba, &[data_phys])
    }

    /// Build an NVM Flush command (opcode 0x00).
    ///
    /// Submits via the I/O queue (qid=1).  Flushes all pending writes
    /// for `nsid` to non-volatile media.  No data transfer.
    pub fn flush(&mut self, nsid: u32) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let mut sqe = [0u8; 64];
        let cdw0: u32 = (cid as u32) << 16;
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
        sqe[4..8].copy_from_slice(&nsid.to_le_bytes());

        Ok(self
            .io
            .as_mut()
            .ok_or(NvmeError::InvalidState)?
            .submit(sqe, self.doorbell_stride))
    }
}
```

- [ ] **Step 4: Run all new multi-block tests**

```bash
cargo test -p harmony-unikernel -- nvme::tests::read_blocks 2>&1 | tail -10
cargo test -p harmony-unikernel -- nvme::tests::write_blocks 2>&1 | tail -10
cargo test -p harmony-unikernel -- nvme::tests::single_block_wrapper 2>&1 | tail -10
```

Expected: all pass.

- [ ] **Step 5: Run full NVMe test suite to verify backward compat**

```bash
cargo test -p harmony-unikernel -- nvme::tests 2>&1 | tail -5
```

Expected: all tests pass. The existing `read_block_builds_correct_sqe`, `write_block_builds_correct_sqe`, etc. should still pass because the wrappers produce identical SQEs (NLB=0, PRP1 set, PRP2=0, no PRP list).

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): refactor io_rw_command for multi-block PRP support

io_rw_command now accepts pages: &[u64] instead of data_phys: u64.
Builds PRP1/PRP2/PRP-list per NVMe spec rules. CDW12 NLB is set
correctly. read_block/write_block become thin wrappers.
AdminCommand.prp_list carries the list bytes for 3+ page transfers.

Part of: harmony-os-9vj"
```

---

### Task 4: Add validation and MDTS enforcement tests

**Files:**
- Test: `crates/harmony-unikernel/src/drivers/nvme.rs` (mod tests section)

All validation logic was implemented in Task 3's `io_rw_command`. This task adds dedicated tests for each validation path.

- [ ] **Step 1: Write validation tests**

Add these tests after the Task 3 tests:

```rust
    // ── Validation tests ─────────────────────────────────────────────────

    #[test]
    fn read_blocks_rejects_empty_pages() {
        let mut driver = ready_driver();
        assert_eq!(
            driver.read_blocks(1, 0, &[]).unwrap_err(),
            NvmeError::TransferTooLarge
        );
    }

    #[test]
    fn read_blocks_rejects_unaligned_address() {
        let mut driver = ready_driver();
        // 0x1001 is not 4 KiB-aligned
        assert_eq!(
            driver.read_blocks(1, 0, &[0x1001]).unwrap_err(),
            NvmeError::UnalignedAddress
        );
    }

    #[test]
    fn read_blocks_rejects_unaligned_in_middle() {
        let mut driver = ready_driver();
        // First page aligned, second is not
        assert_eq!(
            driver.read_blocks(1, 0, &[0x1000, 0x2001]).unwrap_err(),
            NvmeError::UnalignedAddress
        );
    }

    #[test]
    fn read_blocks_enforces_mdts() {
        let mut driver = ready_driver();
        driver.set_mdts(2); // max 4 pages
        let pages: Vec<u64> = (0..5).map(|i| (i + 1) * 0x1000).collect();
        assert_eq!(
            driver.read_blocks(1, 0, &pages).unwrap_err(),
            NvmeError::TransferTooLarge
        );
    }

    #[test]
    fn read_blocks_at_mdts_limit_succeeds() {
        let mut driver = ready_driver();
        driver.set_mdts(2); // max 4 pages
        let pages: Vec<u64> = (0..4).map(|i| (i + 1) * 0x1000).collect();
        let cmd = driver.read_blocks(1, 0, &pages).unwrap();
        let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw12, 3); // NLB = 4-1 = 3
    }

    #[test]
    fn read_blocks_mdts_zero_allows_large_transfer() {
        let mut driver = ready_driver();
        // mdts=0 by default, no limit
        let pages: Vec<u64> = (0..64).map(|i| (i + 1) * 0x1000).collect();
        let cmd = driver.read_blocks(1, 0, &pages).unwrap();
        let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw12, 63); // NLB = 64-1
    }

    #[test]
    fn read_blocks_lba_overflow_rejected() {
        let mut driver = ready_driver();
        assert_eq!(
            driver
                .read_blocks(1, u64::MAX, &[0x1000, 0x2000])
                .unwrap_err(),
            NvmeError::TransferTooLarge
        );
    }

    #[test]
    fn read_blocks_rejects_non_ready_state() {
        let mut driver = enabled_driver();
        assert_eq!(
            driver.read_blocks(1, 0, &[0x1000]).unwrap_err(),
            NvmeError::InvalidState
        );
    }
```

- [ ] **Step 2: Run validation tests**

```bash
cargo test -p harmony-unikernel -- nvme::tests::read_blocks_rejects 2>&1 | tail -15
cargo test -p harmony-unikernel -- nvme::tests::read_blocks_enforces 2>&1 | tail -5
cargo test -p harmony-unikernel -- nvme::tests::read_blocks_at_mdts 2>&1 | tail -5
cargo test -p harmony-unikernel -- nvme::tests::read_blocks_mdts_zero 2>&1 | tail -5
cargo test -p harmony-unikernel -- nvme::tests::read_blocks_lba_overflow 2>&1 | tail -5
```

Expected: all pass (the implementation was done in Task 3).

- [ ] **Step 3: Run full NVMe test suite**

```bash
cargo test -p harmony-unikernel -- nvme::tests 2>&1 | tail -5
```

Expected: all tests pass (previous 44 + 8 new = 52).

- [ ] **Step 4: Run clippy**

```bash
cargo clippy -p harmony-unikernel -- -D warnings 2>&1 | tail -10
```

Expected: no warnings.

- [ ] **Step 5: Run nightly rustfmt**

```bash
cargo +nightly fmt --all -- --check 2>&1 | tail -10
```

Expected: no formatting issues. If there are, run `cargo +nightly fmt --all` and include the fix.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "test(nvme): add validation and MDTS enforcement tests

Cover empty pages, unaligned addresses, MDTS limit, MDTS=0 no-limit,
LBA overflow, and non-Ready state rejection for multi-block commands.

Part of: harmony-os-9vj"
```

---

### Task 5: Update integration test and final verification

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs` (integration test at ~line 1800)

- [ ] **Step 1: Add multi-block integration test**

Add this test after the existing `full_phase3_block_io_lifecycle` test (around line 1854, adjusting for inserted code):

```rust
    #[test]
    fn full_multi_block_lifecycle() {
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();

        driver.bank.on_read(REG_CSTS, vec![CSTS_RDY]);
        driver.setup_admin_queue(0x1_0000, 0x2_0000, 32).unwrap();

        let _ = driver.create_io_queues(0x3_0000, 0x4_0000, 32).unwrap();
        driver.activate_io_queues().unwrap();

        // Set MDTS=3 → max 8 pages
        driver.set_mdts(3);
        assert_eq!(driver.max_transfer_blocks(), Some(8));

        let make_cqe = |phase: bool| -> [u8; 16] {
            let mut cqe = [0u8; 16];
            let status_word: u16 = if phase { 0x0001 } else { 0x0000 };
            cqe[14..16].copy_from_slice(&status_word.to_le_bytes());
            cqe
        };

        // Multi-block read: 4 pages
        let pages: Vec<u64> = (0..4).map(|i| (i + 1) * 0x1000).collect();
        let read_cmd = driver.read_blocks(1, 0, &pages).unwrap();

        // Verify SQE
        let cdw0 = u32::from_le_bytes(read_cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x02); // Read opcode
        let cdw12 = u32::from_le_bytes(read_cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw12, 3); // NLB = 4-1
        let prp1 = u64::from_le_bytes(read_cmd.sqe[24..32].try_into().unwrap());
        assert_eq!(prp1, 0x1000);
        // 4 pages → PRP list with 3 entries
        let list = read_cmd.prp_list.as_ref().expect("4 pages needs PRP list");
        assert_eq!(list.len(), 24); // 3 × 8 bytes

        // Complete the read
        let cr = driver
            .check_io_completion(&make_cqe(true))
            .unwrap()
            .expect("read completion");
        assert_eq!(cr.completion.status, 0);

        // Multi-block write: 2 pages (no PRP list needed)
        let write_cmd = driver
            .write_blocks(1, 100, &[0x5000, 0x6000])
            .unwrap();
        let cdw0 = u32::from_le_bytes(write_cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x01); // Write opcode
        let cdw12 = u32::from_le_bytes(write_cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw12, 1); // NLB = 2-1
        assert!(write_cmd.prp_list.is_none());

        let cr = driver
            .check_io_completion(&make_cqe(true))
            .unwrap()
            .expect("write completion");
        assert_eq!(cr.completion.status, 0);

        // Single-block via wrapper still works
        let single_cmd = driver.read_block(1, 42, 0x7000).unwrap();
        let cdw12 = u32::from_le_bytes(single_cmd.sqe[48..52].try_into().unwrap());
        assert_eq!(cdw12, 0); // NLB = 1-1 = 0
        assert!(single_cmd.prp_list.is_none());

        // MDTS enforcement
        let too_many: Vec<u64> = (0..9).map(|i| (i + 1) * 0x1000).collect();
        assert_eq!(
            driver.read_blocks(1, 0, &too_many).unwrap_err(),
            NvmeError::TransferTooLarge
        );
    }
```

- [ ] **Step 2: Run integration test**

```bash
cargo test -p harmony-unikernel -- nvme::tests::full_multi_block_lifecycle 2>&1 | tail -10
```

Expected: PASS.

- [ ] **Step 3: Run full test suite, clippy, and fmt**

```bash
cargo test -p harmony-unikernel -- nvme::tests 2>&1 | tail -5
cargo clippy -p harmony-unikernel -- -D warnings 2>&1 | tail -10
cargo +nightly fmt --all -- --check 2>&1 | tail -10
```

Expected: all pass, zero warnings, no formatting issues.

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "test(nvme): add multi-block integration test

End-to-end lifecycle: init → admin → I/O queues → set MDTS →
multi-block read (PRP list) → multi-block write (PRP2) →
single-block wrapper → MDTS enforcement.

Part of: harmony-os-9vj"
```
