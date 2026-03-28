# NVMe Phase 3: Block I/O — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Read, Write, and Flush NVM I/O commands to the NVMe driver for single-block transfers via the I/O queue pair.

**Architecture:** Three new command builders (`read_block`, `write_block`, `flush`) submit SQEs via the I/O QueuePair (qid=1) instead of admin (qid=0). A new `check_io_completion()` method handles I/O CQE parsing. All sans-I/O — callers handle DMA.

**Tech Stack:** Rust (no_std), RegisterBank trait, MockRegisterBank for testing.

**Spec:** `docs/specs/2026-03-27-nvme-phase3-design.md`

**Existing code:** `crates/harmony-unikernel/src/drivers/nvme.rs` (~1460 lines, 41 passing tests)

**Test command:** `cargo test -p harmony-unikernel -- nvme`

**CI parity:** `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`

---

## File Structure

All changes are in a single file:

- **Modify:** `crates/harmony-unikernel/src/drivers/nvme.rs`
  - Add `ready_driver()` test helper
  - Add `read_block()` I/O command builder
  - Add `write_block()` I/O command builder
  - Add `flush()` I/O command builder
  - Add `check_io_completion()` method
  - Remove `#[allow(dead_code)]` from `io` field (now used)
  - Add ~18 new tests

---

### Task 1: ready_driver test helper and read_block command

Add a `ready_driver()` test helper that returns an `NvmeDriver` in `Ready` state, then implement `read_block()` — the first I/O command builder.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

**Context for implementer:** The existing `enabled_driver()` helper (line 863) returns a driver in `Enabled` state (admin queue active). Phase 3 commands require `Ready` state (I/O queues active). Build `ready_driver()` on top of `enabled_driver()` by calling `create_io_queues()` + `activate_io_queues()`. The `create_io_queues()` method takes `(sq_phys, cq_phys, size)` and `activate_io_queues()` takes no params (uses cached values from `create_io_queues`).

The I/O queue pair is `self.io: Option<QueuePair>` (qid=1). In `Ready` state it's always `Some`. Use `self.io.as_mut().unwrap().submit()` to submit via the I/O queue. The `submit()` method on `QueuePair` computes the I/O queue doorbell (qid=1: SQ doorbell at `0x1000 + 2*(4<<stride) = 0x1008` for stride=0).

Read SQE layout per NVMe spec: CDW0=opcode|CID<<16, CDW1(NSID)=bytes 4-7, PRP1=bytes 24-31, CDW10=LBA low 32 bits (bytes 40-43), CDW11=LBA high 32 bits (bytes 44-47), CDW12=NLB (bytes 48-51, 0-based so 0 means 1 block).

Also remove the `#[allow(dead_code)]` on the `io` field in the `NvmeDriver` struct since Phase 3 reads it.

- [ ] **Step 1: Write failing tests for read_block**

Add after Phase 2 integration tests, near the end of the test module:

```rust
// ── ready_driver helper ───────────────────────────────────────────────

/// Helper: produce a Ready driver with I/O queues active.
fn ready_driver() -> NvmeDriver<MockRegisterBank> {
    let mut driver = enabled_driver();
    let _ = driver
        .create_io_queues(0x3_0000, 0x4_0000, 32)
        .unwrap();
    driver.activate_io_queues().unwrap();
    driver
}

// ── Read command tests ────────────────────────────────────────────────

#[test]
fn read_block_builds_correct_sqe() {
    let mut driver = ready_driver();
    let cmd = driver.read_block(1, 100, 0xBEEF_0000).unwrap();

    // Opcode 0x02 (NVM Read)
    let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
    assert_eq!(cdw0 & 0xFF, 0x02);

    // NSID at bytes 4-7
    let nsid = u32::from_le_bytes(cmd.sqe[4..8].try_into().unwrap());
    assert_eq!(nsid, 1);

    // PRP1 at bytes 24-31
    let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
    assert_eq!(prp1, 0xBEEF_0000);

    // CDW10: LBA low 32 bits
    let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
    assert_eq!(cdw10, 100);

    // CDW11: LBA high 32 bits (0 for small LBA)
    let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
    assert_eq!(cdw11, 0);

    // CDW12: NLB=0 (1 block, 0-based)
    let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
    assert_eq!(cdw12, 0);
}

#[test]
fn read_block_uses_io_queue_doorbell() {
    let mut driver = ready_driver();
    let cmd = driver.read_block(1, 0, 0x1000).unwrap();

    // I/O SQ doorbell (qid=1, stride=0): 0x1000 + (2*1)*(4<<0) = 0x1008
    assert_eq!(cmd.doorbell_offset, 0x1008);
}

#[test]
fn read_block_rejects_enabled_state() {
    let mut driver = enabled_driver();
    assert_eq!(driver.state(), NvmeState::Enabled);
    assert_eq!(
        driver.read_block(1, 0, 0x1000).unwrap_err(),
        NvmeError::InvalidState
    );
}

#[test]
fn read_block_rejects_disabled_state() {
    let bank = mock_nvme_bank();
    let mut driver = NvmeDriver::init(bank).unwrap();
    assert_eq!(
        driver.read_block(1, 0, 0x1000).unwrap_err(),
        NvmeError::InvalidState
    );
}

#[test]
fn read_block_large_lba_splits_correctly() {
    let mut driver = ready_driver();
    // LBA = 0x1_ABCD_EF00 — needs both CDW10 and CDW11
    let lba: u64 = 0x1_ABCD_EF00;
    let cmd = driver.read_block(1, lba, 0x1000).unwrap();

    let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
    let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
    assert_eq!(cdw10, 0xABCD_EF00, "LBA low 32 bits");
    assert_eq!(cdw11, 0x0000_0001, "LBA high 32 bits");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel -- nvme::tests::read_block 2>&1 | tail -5`
Expected: compilation error — `read_block` not found.

- [ ] **Step 3: Remove `#[allow(dead_code)]` from `io` field and implement read_block**

First, find the `#[allow(dead_code)]` annotation on the `io` field in the `NvmeDriver` struct and remove it. The field is about to be actively used.

Then add a new impl block after the I/O queue creation section (after `activate_io_queues`):

```rust
// ── Block I/O commands ───────────────────────────────────────────────────

impl<R: RegisterBank> NvmeDriver<R> {
    /// Build an NVM Read command (opcode 0x02) for one logical block.
    ///
    /// Submits via the I/O queue (qid=1).  `data_phys` must be 4 KiB
    /// aligned (CC.MPS=0).  Returns an [`AdminCommand`] for the caller
    /// to execute.
    pub fn read_block(
        &mut self,
        nsid: u32,
        lba: u64,
        data_phys: u64,
    ) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let mut sqe = [0u8; 64];
        // CDW0: opcode=0x02, CID
        let cdw0: u32 = 0x02 | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
        // CDW1 (NSID): bytes 4-7
        sqe[4..8].copy_from_slice(&nsid.to_le_bytes());
        // PRP1: data_phys
        sqe[24..32].copy_from_slice(&data_phys.to_le_bytes());
        // CDW10: Starting LBA (low 32 bits)
        sqe[40..44].copy_from_slice(&(lba as u32).to_le_bytes());
        // CDW11: Starting LBA (high 32 bits)
        sqe[44..48].copy_from_slice(&((lba >> 32) as u32).to_le_bytes());
        // CDW12: NLB = 0 (0-based, meaning 1 block)
        sqe[48..52].copy_from_slice(&0u32.to_le_bytes());

        Ok(self.io.as_mut().unwrap().submit(sqe, self.doorbell_stride))
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-unikernel -- nvme::tests::read_block`
Expected: 5 tests pass.

- [ ] **Step 5: Run all NVMe tests**

Run: `cargo test -p harmony-unikernel -- nvme`
Expected: 46 tests pass (41 existing + 5 new).

- [ ] **Step 6: Run CI parity checks**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add read_block I/O command builder

NVM Read (opcode 0x02) for single-block transfers via I/O queue.
LBA split across CDW10/CDW11, NLB=0 (1 block). Requires Ready state."
```

---

### Task 2: write_block command

Add `write_block()` — identical to `read_block()` but with opcode 0x01.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

**Context for implementer:** This is a near-copy of `read_block()` from Task 1. The only difference is the opcode: NVM Write = 0x01 vs NVM Read = 0x02. Same SQE layout: NSID, PRP1, LBA in CDW10/11, NLB=0 in CDW12. Same state guard (Ready only). Same I/O queue submission.

- [ ] **Step 1: Write failing tests**

```rust
// ── Write command tests ───────────────────────────────────────────────

#[test]
fn write_block_builds_correct_sqe() {
    let mut driver = ready_driver();
    let cmd = driver.write_block(1, 200, 0xCAFE_0000).unwrap();

    // Opcode 0x01 (NVM Write)
    let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
    assert_eq!(cdw0 & 0xFF, 0x01);

    // NSID
    let nsid = u32::from_le_bytes(cmd.sqe[4..8].try_into().unwrap());
    assert_eq!(nsid, 1);

    // PRP1
    let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
    assert_eq!(prp1, 0xCAFE_0000);

    // LBA in CDW10/11
    let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
    assert_eq!(cdw10, 200);
    let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
    assert_eq!(cdw11, 0);

    // NLB=0
    let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
    assert_eq!(cdw12, 0);
}

#[test]
fn write_block_uses_io_queue_doorbell() {
    let mut driver = ready_driver();
    let cmd = driver.write_block(1, 0, 0x1000).unwrap();
    assert_eq!(cmd.doorbell_offset, 0x1008);
}

#[test]
fn write_block_rejects_enabled_state() {
    let mut driver = enabled_driver();
    assert_eq!(
        driver.write_block(1, 0, 0x1000).unwrap_err(),
        NvmeError::InvalidState
    );
}

#[test]
fn write_block_rejects_disabled_state() {
    let bank = mock_nvme_bank();
    let mut driver = NvmeDriver::init(bank).unwrap();
    assert_eq!(
        driver.write_block(1, 0, 0x1000).unwrap_err(),
        NvmeError::InvalidState
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel -- nvme::tests::write_block 2>&1 | tail -5`
Expected: compilation error.

- [ ] **Step 3: Implement write_block**

Add to the Block I/O commands impl block (same block as `read_block`):

```rust
    /// Build an NVM Write command (opcode 0x01) for one logical block.
    ///
    /// Submits via the I/O queue (qid=1).  `data_phys` must be 4 KiB
    /// aligned (CC.MPS=0).
    pub fn write_block(
        &mut self,
        nsid: u32,
        lba: u64,
        data_phys: u64,
    ) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let mut sqe = [0u8; 64];
        let cdw0: u32 = 0x01 | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
        sqe[4..8].copy_from_slice(&nsid.to_le_bytes());
        sqe[24..32].copy_from_slice(&data_phys.to_le_bytes());
        sqe[40..44].copy_from_slice(&(lba as u32).to_le_bytes());
        sqe[44..48].copy_from_slice(&((lba >> 32) as u32).to_le_bytes());
        sqe[48..52].copy_from_slice(&0u32.to_le_bytes());

        Ok(self.io.as_mut().unwrap().submit(sqe, self.doorbell_stride))
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-unikernel -- nvme::tests::write_block`
Expected: 4 tests pass.

- [ ] **Step 5: Run all NVMe tests + CI parity**

Run: `cargo test -p harmony-unikernel -- nvme && cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`
Expected: 50 tests pass, clean.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add write_block I/O command builder

NVM Write (opcode 0x01) for single-block transfers via I/O queue.
Same SQE layout as read_block with different opcode."
```

---

### Task 3: flush command

Add `flush()` — simpler than Read/Write since it has no PRP, LBA, or NLB fields.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

**Context for implementer:** Flush (opcode 0x00) is an NVM I/O command that goes through the I/O queue. It only needs CDW0 (opcode + CID) and NSID. No PRP, no LBA, no NLB. The controller returns a completion when all prior writes for the namespace are persisted. Same state guard (Ready) and I/O queue submission as Read/Write.

- [ ] **Step 1: Write failing tests**

```rust
// ── Flush command tests ───────────────────────────────────────────────

#[test]
fn flush_builds_correct_sqe() {
    let mut driver = ready_driver();
    let cmd = driver.flush(1).unwrap();

    // Opcode 0x00 (Flush)
    let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
    assert_eq!(cdw0 & 0xFF, 0x00);

    // NSID
    let nsid = u32::from_le_bytes(cmd.sqe[4..8].try_into().unwrap());
    assert_eq!(nsid, 1);

    // PRP1 must be zero (no data transfer)
    let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
    assert_eq!(prp1, 0);

    // CDW10/11/12 must be zero
    let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
    let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
    let cdw12 = u32::from_le_bytes(cmd.sqe[48..52].try_into().unwrap());
    assert_eq!(cdw10, 0);
    assert_eq!(cdw11, 0);
    assert_eq!(cdw12, 0);
}

#[test]
fn flush_uses_io_queue_doorbell() {
    let mut driver = ready_driver();
    let cmd = driver.flush(1).unwrap();
    assert_eq!(cmd.doorbell_offset, 0x1008);
}

#[test]
fn flush_rejects_enabled_state() {
    let mut driver = enabled_driver();
    assert_eq!(
        driver.flush(1).unwrap_err(),
        NvmeError::InvalidState
    );
}

#[test]
fn flush_rejects_disabled_state() {
    let bank = mock_nvme_bank();
    let mut driver = NvmeDriver::init(bank).unwrap();
    assert_eq!(
        driver.flush(1).unwrap_err(),
        NvmeError::InvalidState
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel -- nvme::tests::flush 2>&1 | tail -5`
Expected: compilation error.

- [ ] **Step 3: Implement flush**

Add to the Block I/O commands impl block:

```rust
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
        let cdw0: u32 = 0x00 | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
        sqe[4..8].copy_from_slice(&nsid.to_le_bytes());

        Ok(self.io.as_mut().unwrap().submit(sqe, self.doorbell_stride))
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-unikernel -- nvme::tests::flush`
Expected: 4 tests pass.

- [ ] **Step 5: Run all NVMe tests + CI parity**

Run: `cargo test -p harmony-unikernel -- nvme && cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`
Expected: 54 tests pass, clean.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add flush I/O command builder

NVM Flush (opcode 0x00) via I/O queue. No data transfer — flushes
pending writes for the namespace to non-volatile media."
```

---

### Task 4: check_io_completion method

Add `check_io_completion()` that delegates to the I/O QueuePair's completion checking.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

**Context for implementer:** The existing `check_completion()` (in the "Completion checking" impl block, around line 622) delegates to `self.admin.check_completion()`. The new `check_io_completion()` does the same but for `self.io`. It wraps the result in `Ok()` to match the `Result<Option<CompletionResult>, NvmeError>` return type. Requires `Ready` state. The I/O CQ doorbell for qid=1 with stride=0 is at `0x1000 + (2*1+1)*(4<<0) = 0x100C`.

- [ ] **Step 1: Write failing tests**

```rust
// ── I/O completion tests ──────────────────────────────────────────────

#[test]
fn check_io_completion_phase_match() {
    let mut driver = ready_driver();
    // Submit a read to advance the I/O queue state
    let _ = driver.read_block(1, 0, 0x1000).unwrap();

    // Build CQE with phase=1 (matches initial cq_phase=true)
    let mut cqe = [0u8; 16];
    cqe[0..4].copy_from_slice(&0x42u32.to_le_bytes()); // result
    cqe[12..14].copy_from_slice(&0u16.to_le_bytes()); // CID
    cqe[14..16].copy_from_slice(&0x0001u16.to_le_bytes()); // phase=1, status=0

    let cr = driver
        .check_io_completion(&cqe)
        .unwrap()
        .expect("phase matches");
    assert_eq!(cr.completion.result, 0x42);
    assert_eq!(cr.completion.status, 0);
    // I/O CQ doorbell (qid=1): 0x1000 + (2*1+1)*(4<<0) = 0x100C
    assert_eq!(cr.cq_doorbell_offset, 0x100C);
}

#[test]
fn check_io_completion_phase_mismatch() {
    let mut driver = ready_driver();
    // CQE with phase=0, but cq_phase starts at true → mismatch
    let mut cqe = [0u8; 16];
    cqe[14..16].copy_from_slice(&0x0000u16.to_le_bytes());

    let result = driver.check_io_completion(&cqe).unwrap();
    assert!(result.is_none());
}

#[test]
fn check_io_completion_rejects_enabled_state() {
    let mut driver = enabled_driver();
    let cqe = [0u8; 16];
    assert_eq!(
        driver.check_io_completion(&cqe).unwrap_err(),
        NvmeError::InvalidState
    );
}

#[test]
fn check_io_completion_uses_io_cq_doorbell() {
    let mut driver = ready_driver();
    let mut cqe = [0u8; 16];
    cqe[14..16].copy_from_slice(&0x0001u16.to_le_bytes()); // phase=1

    let cr = driver.check_io_completion(&cqe).unwrap().unwrap();
    // I/O CQ doorbell = 0x100C (qid=1, is_cq=true, stride=0)
    assert_eq!(cr.cq_doorbell_offset, 0x100C);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel -- nvme::tests::check_io_completion 2>&1 | tail -5`
Expected: compilation error.

- [ ] **Step 3: Implement check_io_completion**

Add to the Completion checking impl block — insert **after** the existing `check_completion()` method and **before** the closing `}` of that impl block:

```rust
    /// Parse a raw 16-byte I/O completion queue entry.
    ///
    /// Delegates to the I/O [`QueuePair`]'s completion checking.
    /// Requires [`NvmeState::Ready`].
    pub fn check_io_completion(
        &mut self,
        cqe_bytes: &[u8; 16],
    ) -> Result<Option<CompletionResult>, NvmeError> {
        if self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }
        Ok(self.io.as_mut().unwrap().check_completion(cqe_bytes, self.doorbell_stride))
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-unikernel -- nvme::tests::check_io_completion`
Expected: 4 tests pass.

- [ ] **Step 5: Run all NVMe tests + CI parity**

Run: `cargo test -p harmony-unikernel -- nvme && cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`
Expected: 58 tests pass, clean.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add check_io_completion for I/O queue CQEs

Delegates to I/O QueuePair. Separate from admin check_completion().
Requires Ready state."
```

---

### Task 5: Full Phase 3 integration test

Verify the complete block I/O lifecycle: init → admin queue → I/O queues → read → completion → write → completion → flush → completion.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

**Context for implementer:** This test exercises the entire Phase 1-3 pipeline. Use `mock_nvme_bank()` for init, then walk through every state transition. For completions, build synthetic 16-byte CQEs with matching phase bits. The phase bit starts at `true` (1) for a fresh QueuePair, so set bit 0 of the status word (bytes 14-15) to 1.

- [ ] **Step 1: Write integration test**

```rust
// ── Phase 3 integration test ──────────────────────────────────────────

#[test]
fn full_phase3_block_io_lifecycle() {
    // init → admin queue → I/O queues → read → complete → write → complete → flush → complete
    let bank = mock_nvme_bank();
    let mut driver = NvmeDriver::init(bank).unwrap();
    assert_eq!(driver.state(), NvmeState::Disabled);

    // Setup admin queue
    driver.bank.on_read(REG_CSTS, vec![CSTS_RDY]);
    driver.setup_admin_queue(0x1_0000, 0x2_0000, 32).unwrap();
    assert_eq!(driver.state(), NvmeState::Enabled);

    // Create and activate I/O queues
    let _ = driver
        .create_io_queues(0x3_0000, 0x4_0000, 32)
        .unwrap();
    driver.activate_io_queues().unwrap();
    assert_eq!(driver.state(), NvmeState::Ready);

    // Helper to build a CQE with matching phase
    let make_cqe = |phase: bool| -> [u8; 16] {
        let mut cqe = [0u8; 16];
        let status_word: u16 = if phase { 0x0001 } else { 0x0000 };
        cqe[14..16].copy_from_slice(&status_word.to_le_bytes());
        cqe
    };

    // Read block 42
    let read_cmd = driver.read_block(1, 42, 0xBEEF_0000).unwrap();
    let cdw0 = u32::from_le_bytes(read_cmd.sqe[0..4].try_into().unwrap());
    assert_eq!(cdw0 & 0xFF, 0x02); // NVM Read opcode
    assert_eq!(read_cmd.doorbell_offset, 0x1008); // I/O SQ doorbell

    // Check read completion
    let read_cr = driver
        .check_io_completion(&make_cqe(true))
        .unwrap()
        .expect("read completion");
    assert_eq!(read_cr.cq_doorbell_offset, 0x100C); // I/O CQ doorbell

    // Write block 42
    let write_cmd = driver.write_block(1, 42, 0xCAFE_0000).unwrap();
    let cdw0 = u32::from_le_bytes(write_cmd.sqe[0..4].try_into().unwrap());
    assert_eq!(cdw0 & 0xFF, 0x01); // NVM Write opcode

    // Check write completion
    let write_cr = driver
        .check_io_completion(&make_cqe(true))
        .unwrap()
        .expect("write completion");
    assert_eq!(write_cr.completion.status, 0);

    // Flush
    let flush_cmd = driver.flush(1).unwrap();
    let cdw0 = u32::from_le_bytes(flush_cmd.sqe[0..4].try_into().unwrap());
    assert_eq!(cdw0 & 0xFF, 0x00); // Flush opcode

    // Check flush completion
    let flush_cr = driver
        .check_io_completion(&make_cqe(true))
        .unwrap()
        .expect("flush completion");
    assert_eq!(flush_cr.completion.status, 0);
}
```

- [ ] **Step 2: Run integration test**

Run: `cargo test -p harmony-unikernel -- nvme::tests::full_phase3`
Expected: 1 test passes.

- [ ] **Step 3: Run full test suite + CI parity**

Run: `cargo test -p harmony-unikernel -- nvme && cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`
Expected: 59 tests pass, clean.

- [ ] **Step 4: Run full workspace tests**

Run: `cargo test --workspace`
Expected: all tests pass across all crates.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "test(nvme): add Phase 3 block I/O integration test

Full lifecycle: init → admin queue → I/O queues → read_block →
check_io_completion → write_block → check_io_completion → flush →
check_io_completion."
```
