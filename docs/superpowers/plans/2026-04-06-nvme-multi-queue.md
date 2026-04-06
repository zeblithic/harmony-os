# NVMe Multi-Queue Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the NVMe driver to support multiple I/O queue pairs for per-core parallel I/O.

**Architecture:** Replace `io: Option<QueuePair>` with `io_queues: Vec<QueuePair>`, add `qid` parameter to queue creation commands, add `queue_index` parameter to all I/O methods. Sans-I/O design preserved — driver builds command bytes, caller handles DMA and doorbells.

**Tech Stack:** Rust, `no_std` + `alloc`, `MockRegisterBank` for testing

**Spec:** `docs/superpowers/specs/2026-04-06-nvme-multi-queue-design.md`

---

## File Structure

All changes are in one file:

- **Modify:** `crates/harmony-unikernel/src/drivers/nvme.rs` — NVMe driver (implementation + tests in same file)

---

### Task 1: Add `InvalidQueueIndex` error variant and update driver storage fields

Add the new error variant, change `io` from `Option<QueuePair>` to `Vec<QueuePair>`, change `pending_io` from `Option<(u64, u64, u16)>` to `Vec<(u16, u64, u64, u16)>`, and update the `init()` constructor. This is a pure structural change — no I/O methods updated yet, so existing tests will break. We fix the tests in Task 4.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:221-243` (NvmeError enum)
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:266-291` (NvmeDriver struct)
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:446-459` (init constructor)

- [ ] **Step 1: Add `InvalidQueueIndex` to `NvmeError`**

In the `NvmeError` enum (around line 242), add the new variant after `UnsupportedCommand`:

```rust
    /// The command requires an optional NVM feature (ONCS) not supported by this controller.
    UnsupportedCommand,
    /// The specified I/O queue index is out of range.
    InvalidQueueIndex,
```

- [ ] **Step 2: Change `io` field from `Option<QueuePair>` to `Vec<QueuePair>`**

In the `NvmeDriver` struct, replace:

```rust
    /// I/O submission/completion queue pair (None until created).
    io: Option<QueuePair>,
```

with:

```rust
    /// I/O submission/completion queue pairs (empty until first pair activated).
    io_queues: Vec<QueuePair>,
```

- [ ] **Step 3: Change `pending_io` field**

In the `NvmeDriver` struct, replace:

```rust
    /// Pending I/O queue params cached by create_io_queues(), consumed by
    /// activate_io_queues().  Ensures software QueuePair matches hardware.
    pending_io: Option<(u64, u64, u16)>,
```

with:

```rust
    /// Pending I/O queue params cached by create_io_queue_pair(), consumed by
    /// activate_io_queue_pair().  Each entry: (qid, sq_phys, cq_phys, size).
    pending_io: Vec<(u16, u64, u64, u16)>,
```

- [ ] **Step 4: Update `init()` constructor**

In the `init()` method (around line 447-458), replace:

```rust
            io: None,
            pending_io: None,
```

with:

```rust
            io_queues: Vec::new(),
            pending_io: Vec::new(),
```

- [ ] **Step 5: Verify it compiles (tests will fail — that's expected)**

Run: `cargo build -p harmony-unikernel 2>&1 | head -40`

Expected: Compilation errors referencing `self.io`, `self.pending_io`, `create_io_queues`, `activate_io_queues` — these are expected and will be fixed in subsequent tasks. The struct and error enum should compile cleanly.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "refactor(nvme): change io/pending_io fields to Vec for multi-queue support"
```

---

### Task 2: Update queue creation and activation methods

Refactor `create_io_cq`, `create_io_sq` to accept `qid`, replace `create_io_queues` with `create_io_queue_pair`, replace `activate_io_queues` with `activate_io_queue_pair`, and add `io_queue_count`. Also add the private `io_queue_mut` helper.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:605-700` (I/O queue creation section)
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:704-797` (Block I/O commands — add helper)

- [ ] **Step 1: Update `create_io_cq` to accept `qid`**

Replace the existing `create_io_cq` method (around line 607-630):

```rust
    /// Build a Create I/O Completion Queue admin command (opcode 0x05).
    ///
    /// `qid` is the queue identifier (must be >= 1; qid=0 is the admin queue).
    pub fn create_io_cq(
        &mut self,
        qid: u16,
        cq_phys: u64,
        size: u16,
    ) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Enabled && self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }
        if qid == 0 {
            return Err(NvmeError::InvalidState);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let size = size.min(self.max_queue_entries);
        if size == 0 {
            return Err(NvmeError::InvalidState);
        }

        let mut sqe = [0u8; 64];
        let cdw0: u32 = 0x05 | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
        sqe[24..32].copy_from_slice(&cq_phys.to_le_bytes());
        let cdw10: u32 = (qid as u32) | (((size - 1) as u32) << 16);
        sqe[40..44].copy_from_slice(&cdw10.to_le_bytes());
        let cdw11: u32 = 0x0000_0003;
        sqe[44..48].copy_from_slice(&cdw11.to_le_bytes());

        Ok(self.admin.submit(sqe, self.doorbell_stride))
    }
```

- [ ] **Step 2: Update `create_io_sq` to accept `qid`**

Replace the existing `create_io_sq` method (around line 633-656):

```rust
    /// Build a Create I/O Submission Queue admin command (opcode 0x01).
    ///
    /// `qid` is the queue identifier (must be >= 1; qid=0 is the admin queue).
    /// The SQ is associated with the CQ of the same `qid`.
    pub fn create_io_sq(
        &mut self,
        qid: u16,
        sq_phys: u64,
        size: u16,
    ) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Enabled && self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }
        if qid == 0 {
            return Err(NvmeError::InvalidState);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let size = size.min(self.max_queue_entries);
        if size == 0 {
            return Err(NvmeError::InvalidState);
        }

        let mut sqe = [0u8; 64];
        let cdw0: u32 = 0x01 | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
        sqe[24..32].copy_from_slice(&sq_phys.to_le_bytes());
        let cdw10: u32 = (qid as u32) | (((size - 1) as u32) << 16);
        sqe[40..44].copy_from_slice(&cdw10.to_le_bytes());
        let cdw11: u32 = 0x0001 | ((qid as u32) << 16);
        sqe[44..48].copy_from_slice(&cdw11.to_le_bytes());

        Ok(self.admin.submit(sqe, self.doorbell_stride))
    }
```

Note: CDW11 for Create I/O SQ is now `PC=1 (bit 0) | CQID=qid (bits 31:16)` instead of hardcoded `0x0001_0001`.

- [ ] **Step 3: Replace `create_io_queues` with `create_io_queue_pair`**

Replace the existing `create_io_queues` method (around line 663-681):

```rust
    /// Build admin commands to create one I/O CQ+SQ pair.
    ///
    /// Returns `[create_cq_cmd, create_sq_cmd]`.  The caller must execute
    /// them in order, confirm both completions succeed, then call
    /// [`activate_io_queue_pair`] to record the result.
    ///
    /// Allowed in both `Enabled` and `Ready` states (to add more pairs).
    pub fn create_io_queue_pair(
        &mut self,
        qid: u16,
        sq_phys: u64,
        cq_phys: u64,
        size: u16,
    ) -> Result<[AdminCommand; 2], NvmeError> {
        if self.state != NvmeState::Enabled && self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }
        let size = size.min(self.max_queue_entries);
        let cq_cmd = self.create_io_cq(qid, cq_phys, size)?;
        let sq_cmd = self.create_io_sq(qid, sq_phys, size)?;
        self.pending_io.push((qid, sq_phys, cq_phys, size));
        Ok([cq_cmd, sq_cmd])
    }
```

- [ ] **Step 4: Replace `activate_io_queues` with `activate_io_queue_pair`**

Replace the existing `activate_io_queues` method (around line 690-699):

```rust
    /// Record that an I/O queue pair was successfully created on the controller.
    ///
    /// Call this after executing both commands from [`create_io_queue_pair`]
    /// and confirming successful completions.  Finds and consumes the pending
    /// entry for `qid`.  Transitions to [`NvmeState::Ready`] on first
    /// activation; stays `Ready` on subsequent activations.
    pub fn activate_io_queue_pair(&mut self, qid: u16) -> Result<(), NvmeError> {
        if self.state != NvmeState::Enabled && self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }

        let idx = self
            .pending_io
            .iter()
            .position(|&(q, _, _, _)| q == qid)
            .ok_or(NvmeError::InvalidState)?;
        let (qid, sq_phys, cq_phys, size) = self.pending_io.remove(idx);
        self.io_queues.push(QueuePair::new(qid, sq_phys, cq_phys, size));
        self.state = NvmeState::Ready;
        Ok(())
    }
```

- [ ] **Step 5: Add `io_queue_count` accessor and `io_queue_mut` helper**

Add these methods. The accessor goes in the public accessors section (after `doorbell_stride()`, around line 349). The helper goes at the top of the Block I/O impl block (around line 704):

Accessor (in the public accessors impl block):

```rust
    /// Return the number of active I/O queue pairs.
    pub fn io_queue_count(&self) -> usize {
        self.io_queues.len()
    }
```

Helper (at the top of the Block I/O impl block, before `io_rw_command`):

```rust
    /// Look up an I/O queue pair by index.
    fn io_queue_mut(&mut self, queue_index: usize) -> Result<&mut QueuePair, NvmeError> {
        self.io_queues
            .get_mut(queue_index)
            .ok_or(NvmeError::InvalidQueueIndex)
    }
```

- [ ] **Step 6: Verify it compiles (tests will still fail — expected)**

Run: `cargo build -p harmony-unikernel 2>&1 | head -40`

Expected: Errors in I/O methods (`self.io.as_mut()` no longer exists) and in tests (`create_io_queues`/`activate_io_queues` no longer exist). These are fixed in Tasks 3 and 4.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "refactor(nvme): add qid to queue creation, replace create/activate with queue_pair variants"
```

---

### Task 3: Add `queue_index` parameter to all I/O methods

Update `io_rw_command`, all public I/O methods, and `check_io_completion` to accept `queue_index: usize` and use `io_queue_mut()`. This is a mechanical change — every method that previously called `self.io.as_mut().ok_or(NvmeError::InvalidState)?` now calls `self.io_queue_mut(queue_index)?`.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:723-994` (io_rw_command through dataset_management)
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs:1031-1043` (check_io_completion)

- [ ] **Step 1: Update `io_rw_command`**

Replace the method signature and the queue submission line. Change (around line 723):

```rust
    fn io_rw_command(
        &mut self,
        opcode: u8,
        nsid: u32,
        lba: u64,
        pages: &[u64],
    ) -> Result<AdminCommand, NvmeError> {
```

to:

```rust
    fn io_rw_command(
        &mut self,
        queue_index: usize,
        opcode: u8,
        nsid: u32,
        lba: u64,
        pages: &[u64],
    ) -> Result<AdminCommand, NvmeError> {
```

And replace (around line 790-794):

```rust
        let mut cmd = self
            .io
            .as_mut()
            .ok_or(NvmeError::InvalidState)?
            .submit(sqe, self.doorbell_stride);
```

with:

```rust
        let mut cmd = self
            .io_queue_mut(queue_index)?
            .submit(sqe, self.doorbell_stride);
```

- [ ] **Step 2: Update `read_blocks` and `write_blocks`**

Replace (around line 802-821):

```rust
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
```

with:

```rust
    pub fn read_blocks(
        &mut self,
        queue_index: usize,
        nsid: u32,
        lba: u64,
        pages: &[u64],
    ) -> Result<AdminCommand, NvmeError> {
        self.io_rw_command(queue_index, 0x02, nsid, lba, pages)
    }

    /// Build an NVM Write command for multiple logical blocks.
    ///
    /// `pages` contains one 4 KiB-aligned physical address per block.
    pub fn write_blocks(
        &mut self,
        queue_index: usize,
        nsid: u32,
        lba: u64,
        pages: &[u64],
    ) -> Result<AdminCommand, NvmeError> {
        self.io_rw_command(queue_index, 0x01, nsid, lba, pages)
    }
```

- [ ] **Step 3: Update `read_block` and `write_block`**

Replace (around line 827-847):

```rust
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
```

with:

```rust
    pub fn read_block(
        &mut self,
        queue_index: usize,
        nsid: u32,
        lba: u64,
        data_phys: u64,
    ) -> Result<AdminCommand, NvmeError> {
        self.read_blocks(queue_index, nsid, lba, &[data_phys])
    }

    /// Build an NVM Write command (opcode 0x01) for one logical block.
    ///
    /// Thin wrapper around [`write_blocks`](Self::write_blocks) with a
    /// single-element page slice.
    pub fn write_block(
        &mut self,
        queue_index: usize,
        nsid: u32,
        lba: u64,
        data_phys: u64,
    ) -> Result<AdminCommand, NvmeError> {
        self.write_blocks(queue_index, nsid, lba, &[data_phys])
    }
```

- [ ] **Step 4: Update `flush`**

Replace (around line 853-871):

```rust
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
```

with:

```rust
    pub fn flush(&mut self, queue_index: usize, nsid: u32) -> Result<AdminCommand, NvmeError> {
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
            .io_queue_mut(queue_index)?
            .submit(sqe, self.doorbell_stride))
    }
```

- [ ] **Step 5: Update `write_zeroes`**

Replace the method signature (around line 881):

```rust
    pub fn write_zeroes(
        &mut self,
        nsid: u32,
        lba: u64,
        block_count: u32,
    ) -> Result<AdminCommand, NvmeError> {
```

with:

```rust
    pub fn write_zeroes(
        &mut self,
        queue_index: usize,
        nsid: u32,
        lba: u64,
        block_count: u32,
    ) -> Result<AdminCommand, NvmeError> {
```

And replace the queue submission (around line 920-924):

```rust
        let mut cmd = self
            .io
            .as_mut()
            .ok_or(NvmeError::InvalidState)?
            .submit(sqe, self.doorbell_stride);
```

with:

```rust
        let mut cmd = self
            .io_queue_mut(queue_index)?
            .submit(sqe, self.doorbell_stride);
```

- [ ] **Step 6: Update `dataset_management`**

Replace the method signature (around line 941):

```rust
    pub fn dataset_management(
        &mut self,
        nsid: u32,
        ranges: &[DsmRange],
    ) -> Result<AdminCommand, NvmeError> {
```

with:

```rust
    pub fn dataset_management(
        &mut self,
        queue_index: usize,
        nsid: u32,
        ranges: &[DsmRange],
    ) -> Result<AdminCommand, NvmeError> {
```

And replace the queue submission (around line 986-990):

```rust
        let mut cmd = self
            .io
            .as_mut()
            .ok_or(NvmeError::InvalidState)?
            .submit(sqe, self.doorbell_stride);
```

with:

```rust
        let mut cmd = self
            .io_queue_mut(queue_index)?
            .submit(sqe, self.doorbell_stride);
```

- [ ] **Step 7: Update `check_io_completion`**

Replace (around line 1031-1043):

```rust
    pub fn check_io_completion(
        &mut self,
        cqe_bytes: &[u8; 16],
    ) -> Result<Option<CompletionResult>, NvmeError> {
        if self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }
        Ok(self
            .io
            .as_mut()
            .ok_or(NvmeError::InvalidState)?
            .check_completion(cqe_bytes, self.doorbell_stride))
    }
```

with:

```rust
    pub fn check_io_completion(
        &mut self,
        queue_index: usize,
        cqe_bytes: &[u8; 16],
    ) -> Result<Option<CompletionResult>, NvmeError> {
        if self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }
        Ok(self
            .io_queue_mut(queue_index)?
            .check_completion(cqe_bytes, self.doorbell_stride))
    }
```

- [ ] **Step 8: Verify it compiles (tests will still fail — expected)**

Run: `cargo build -p harmony-unikernel 2>&1 | head -40`

Expected: Only test compilation errors remain (calling old method names, wrong argument counts). The driver code itself should compile.

- [ ] **Step 9: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "refactor(nvme): add queue_index parameter to all I/O methods"
```

---

### Task 4: Update all existing tests for new signatures

Mechanical update: rename `create_io_queues`→`create_io_queue_pair` (adding qid=1), rename `activate_io_queues`→`activate_io_queue_pair(1)`, add `queue_index: 0` to all I/O method calls, update queue creation tests to pass qid=1, and fix assertion changes (e.g., `driver.io.is_some()` → `driver.io_queue_count()`). Remove the test that asserts `create_io_queues` rejects Ready state (multi-queue allows this now). Update the `ready_driver()` helper.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs` (test module, lines ~1200-2860)

- [ ] **Step 1: Update `ready_driver()` helper**

Replace (around line 1863-1868):

```rust
    fn ready_driver() -> NvmeDriver<MockRegisterBank> {
        let mut driver = enabled_driver();
        let _ = driver.create_io_queues(0x3_0000, 0x4_0000, 32).unwrap();
        driver.activate_io_queues().unwrap();
        driver
    }
```

with:

```rust
    fn ready_driver() -> NvmeDriver<MockRegisterBank> {
        let mut driver = enabled_driver();
        let _ = driver
            .create_io_queue_pair(1, 0x3_0000, 0x4_0000, 32)
            .unwrap();
        driver.activate_io_queue_pair(1).unwrap();
        driver
    }
```

- [ ] **Step 2: Update `create_io_cq` / `create_io_sq` tests**

For `create_io_cq_builds_correct_sqe` (around line 1521), change:

```rust
        let cmd = driver.create_io_cq(cq_phys, 32).unwrap();
```

to:

```rust
        let cmd = driver.create_io_cq(1, cq_phys, 32).unwrap();
```

For `create_io_sq_builds_correct_sqe` (around line 1543), change:

```rust
        let cmd = driver.create_io_sq(sq_phys, 32).unwrap();
```

to:

```rust
        let cmd = driver.create_io_sq(1, sq_phys, 32).unwrap();
```

For `create_io_cq_rejects_disabled_state` (around line 1565), change:

```rust
            driver.create_io_cq(0x1000, 16).unwrap_err(),
```

to:

```rust
            driver.create_io_cq(1, 0x1000, 16).unwrap_err(),
```

For `create_io_cq_advances_admin_doorbell` (around line 1576), change:

```rust
        let cmd1 = driver.create_io_cq(0xAAAA_0000, 16).unwrap();
        let cmd2 = driver.create_io_cq(0xBBBB_0000, 16).unwrap();
```

to:

```rust
        let cmd1 = driver.create_io_cq(1, 0xAAAA_0000, 16).unwrap();
        let cmd2 = driver.create_io_cq(2, 0xBBBB_0000, 16).unwrap();
```

- [ ] **Step 3: Update `create_io_queues` / `activate_io_queues` tests**

Rename and update these tests. For `create_io_queues_returns_cq_first_sq_second` (around line 1587):

Rename to `create_io_queue_pair_returns_cq_first_sq_second` and change:

```rust
            .create_io_queues(0xBBBB_0000, 0xAAAA_0000, 32)
```

to:

```rust
            .create_io_queue_pair(1, 0xBBBB_0000, 0xAAAA_0000, 32)
```

For `create_io_queues_clamps_size` → rename to `create_io_queue_pair_clamps_size` and change:

```rust
            .create_io_queues(0xBBBB_0000, 0xAAAA_0000, 256)
```

to:

```rust
            .create_io_queue_pair(1, 0xBBBB_0000, 0xAAAA_0000, 256)
```

For `create_io_queues_rejects_disabled_state` → rename to `create_io_queue_pair_rejects_disabled_state` and change:

```rust
            driver.create_io_queues(0x1000, 0x2000, 16).unwrap_err(),
```

to:

```rust
            driver.create_io_queue_pair(1, 0x1000, 0x2000, 16).unwrap_err(),
```

**Remove** the `create_io_queues_rejects_ready_state` test entirely (around line 1624-1639). Multi-queue allows creating queue pairs in Ready state — this constraint no longer applies.

For `activate_io_queues_transitions_to_ready` → rename to `activate_io_queue_pair_transitions_to_ready` and replace:

```rust
    fn activate_io_queues_transitions_to_ready() {
        let mut driver = enabled_driver();
        assert_eq!(driver.state(), NvmeState::Enabled);

        let _ = driver
            .create_io_queues(0xBBBB_0000, 0xAAAA_0000, 32)
            .unwrap();
        driver.activate_io_queues().unwrap();

        assert_eq!(driver.state(), NvmeState::Ready);
        assert!(driver.io.is_some());
        let io = driver.io.as_ref().unwrap();
        assert_eq!(io.qid, 1);
        assert_eq!(io.size, 32);
    }
```

with:

```rust
    fn activate_io_queue_pair_transitions_to_ready() {
        let mut driver = enabled_driver();
        assert_eq!(driver.state(), NvmeState::Enabled);

        let _ = driver
            .create_io_queue_pair(1, 0xBBBB_0000, 0xAAAA_0000, 32)
            .unwrap();
        driver.activate_io_queue_pair(1).unwrap();

        assert_eq!(driver.state(), NvmeState::Ready);
        assert_eq!(driver.io_queue_count(), 1);
    }
```

For `activate_io_queues_rejects_double_activation` → rename to `activate_io_queue_pair_rejects_without_pending` and replace:

```rust
    fn activate_io_queues_rejects_double_activation() {
        let mut driver = enabled_driver();
        let _ = driver
            .create_io_queues(0xBBBB_0000, 0xAAAA_0000, 32)
            .unwrap();
        driver.activate_io_queues().unwrap();
        // Now Ready — second call should fail (state is Ready, not Enabled)
        assert_eq!(
            driver.activate_io_queues().unwrap_err(),
            NvmeError::InvalidState
        );
    }
```

with:

```rust
    fn activate_io_queue_pair_rejects_without_pending() {
        let mut driver = enabled_driver();
        let _ = driver
            .create_io_queue_pair(1, 0xBBBB_0000, 0xAAAA_0000, 32)
            .unwrap();
        driver.activate_io_queue_pair(1).unwrap();
        // Now Ready — activating qid=1 again should fail (no pending entry)
        assert_eq!(
            driver.activate_io_queue_pair(1).unwrap_err(),
            NvmeError::InvalidState
        );
    }
```

For `activate_io_queues_rejects_disabled_state` → rename to `activate_io_queue_pair_rejects_disabled_state` and change:

```rust
            driver.activate_io_queues().unwrap_err(),
```

to:

```rust
            driver.activate_io_queue_pair(1).unwrap_err(),
```

For `activate_io_queues_rejects_without_create` → rename to `activate_io_queue_pair_rejects_no_create` and change:

```rust
        // Enabled but create_io_queues not called — no pending_io
        assert_eq!(
            driver.activate_io_queues().unwrap_err(),
```

to:

```rust
        // Enabled but create_io_queue_pair not called — no pending_io
        assert_eq!(
            driver.activate_io_queue_pair(1).unwrap_err(),
```

- [ ] **Step 4: Update remaining tests that use `create_io_queues`/`activate_io_queues`**

There are three more tests that inline queue creation (not using `ready_driver()`). Search for `create_io_queues` in tests and update each:

Around line 1745:

```rust
            .create_io_queues(0xBBBB_0000, 0xAAAA_0000, 32)
```
→
```rust
            .create_io_queue_pair(1, 0xBBBB_0000, 0xAAAA_0000, 32)
```

And `driver.activate_io_queues().unwrap()` → `driver.activate_io_queue_pair(1).unwrap()` in the same test.

Repeat for around lines 1818-1820, 1841-1849, 2105-2106, and 2159-2160.

- [ ] **Step 5: Add `0,` queue_index to all I/O method calls in tests**

This is the bulk mechanical change. Every call to `driver.read_block(`, `driver.write_block(`, `driver.read_blocks(`, `driver.write_blocks(`, `driver.flush(`, `driver.write_zeroes(`, `driver.dataset_management(`, and `driver.check_io_completion(` needs `0,` inserted as the first argument after the opening parenthesis.

For example:

```rust
driver.read_block(1, 100, 0xBEEF_0000)     →  driver.read_block(0, 1, 100, 0xBEEF_0000)
driver.flush(1)                              →  driver.flush(0, 1)
driver.check_io_completion(&cqe)             →  driver.check_io_completion(0, &cqe)
driver.write_zeroes(1, 0, 1)                 →  driver.write_zeroes(0, 1, 0, 1)
driver.dataset_management(1, &ranges)        →  driver.dataset_management(0, 1, &ranges)
```

There are 61 such call sites. Update all of them.

- [ ] **Step 6: Run tests**

Run: `cargo test -p harmony-unikernel -- nvme 2>&1 | tail -30`

Expected: All existing tests pass. The count should be 103 (one test removed — `create_io_queues_rejects_ready_state`).

- [ ] **Step 7: Run clippy and format**

Run: `cargo clippy -p harmony-unikernel 2>&1 | tail -10`
Run: `cargo +nightly fmt --all`

Expected: No warnings, clean formatting.

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "refactor(nvme): update all existing tests for multi-queue signatures"
```

---

### Task 5: Add multi-queue tests

Write the 13 new tests that verify multi-queue behavior: creating multiple pairs, doorbell offsets per qid, commands targeting correct queues, independent completions, and error cases.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs` (test module)

- [ ] **Step 1: Add `ready_driver_multi` test helper**

Add after `ready_driver()` (around line 1868):

```rust
    fn ready_driver_multi(n: usize) -> NvmeDriver<MockRegisterBank> {
        let mut driver = enabled_driver();
        for i in 1..=n {
            let qid = i as u16;
            let sq_phys = 0x10_0000 + (i as u64) * 0x1_0000;
            let cq_phys = 0x20_0000 + (i as u64) * 0x1_0000;
            let _ = driver
                .create_io_queue_pair(qid, sq_phys, cq_phys, 32)
                .unwrap();
            driver.activate_io_queue_pair(qid).unwrap();
        }
        driver
    }
```

- [ ] **Step 2: Write multi-queue creation and activation tests**

Add a new test section after the existing `activate_io_queue_pair` tests:

```rust
    // ── Multi-queue tests ─────────────────────────────────────────────────────

    #[test]
    fn create_second_queue_pair_in_ready_state() {
        let mut driver = ready_driver(); // has qid=1, state=Ready
        let cmds = driver
            .create_io_queue_pair(2, 0x5_0000, 0x6_0000, 32)
            .unwrap();

        // CQ command has qid=2 in CDW10
        let cdw10_cq = u32::from_le_bytes(cmds[0].sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10_cq & 0xFFFF, 2);

        // SQ command has qid=2 in CDW10 and CQID=2 in CDW11
        let cdw10_sq = u32::from_le_bytes(cmds[1].sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10_sq & 0xFFFF, 2);
        let cdw11_sq = u32::from_le_bytes(cmds[1].sqe[44..48].try_into().unwrap());
        assert_eq!(cdw11_sq >> 16, 2, "CQID must match qid");
    }

    #[test]
    fn activate_second_queue_pair() {
        let mut driver = ready_driver();
        let _ = driver
            .create_io_queue_pair(2, 0x5_0000, 0x6_0000, 32)
            .unwrap();
        driver.activate_io_queue_pair(2).unwrap();
        assert_eq!(driver.io_queue_count(), 2);
        assert_eq!(driver.state(), NvmeState::Ready);
    }

    #[test]
    fn three_queue_pairs() {
        let driver = ready_driver_multi(3);
        assert_eq!(driver.io_queue_count(), 3);
        assert_eq!(driver.state(), NvmeState::Ready);
    }

    #[test]
    fn queue_pair_ordering() {
        let driver = ready_driver_multi(3);
        // Pairs stored in activation order: index 0=qid1, 1=qid2, 2=qid3
        assert_eq!(driver.io_queues[0].qid, 1);
        assert_eq!(driver.io_queues[1].qid, 2);
        assert_eq!(driver.io_queues[2].qid, 3);
    }
```

- [ ] **Step 3: Write doorbell offset and queue targeting tests**

```rust
    #[test]
    fn doorbell_offsets_per_qid() {
        let mut driver = ready_driver_multi(3);
        // DSTRD=0 → stride = 4 bytes
        // qid=1: SQ doorbell at 0x1000 + 2*1*4 = 0x1008, CQ at 0x1000 + 3*4 = 0x100C
        // qid=2: SQ doorbell at 0x1000 + 2*2*4 = 0x1010, CQ at 0x1000 + 5*4 = 0x1014
        // qid=3: SQ doorbell at 0x1000 + 2*3*4 = 0x1018, CQ at 0x1000 + 7*4 = 0x101C
        let cmd1 = driver.read_block(0, 1, 0, 0x1000).unwrap();
        let cmd2 = driver.read_block(1, 1, 0, 0x1000).unwrap();
        let cmd3 = driver.read_block(2, 1, 0, 0x1000).unwrap();

        assert_eq!(cmd1.doorbell_offset, 0x1008, "qid=1 SQ doorbell");
        assert_eq!(cmd2.doorbell_offset, 0x1010, "qid=2 SQ doorbell");
        assert_eq!(cmd3.doorbell_offset, 0x1018, "qid=3 SQ doorbell");
    }

    #[test]
    fn io_commands_target_correct_queue() {
        let mut driver = ready_driver_multi(2);
        let cmd_q0 = driver.read_block(0, 1, 42, 0xBEEF_0000).unwrap();
        let cmd_q1 = driver.read_block(1, 1, 42, 0xBEEF_0000).unwrap();
        // Different doorbell offsets confirm different queues
        assert_ne!(cmd_q0.doorbell_offset, cmd_q1.doorbell_offset);
        assert_eq!(cmd_q0.doorbell_offset, 0x1008); // qid=1
        assert_eq!(cmd_q1.doorbell_offset, 0x1010); // qid=2
    }

    #[test]
    fn cid_shared_across_queues() {
        let mut driver = ready_driver_multi(2);
        let cmd1 = driver.read_block(0, 1, 0, 0x1000).unwrap();
        let cmd2 = driver.read_block(1, 1, 0, 0x1000).unwrap();
        let cid1 = u16::from_le_bytes([cmd1.sqe[2], cmd1.sqe[3]]);
        let cid2 = u16::from_le_bytes([cmd2.sqe[2], cmd2.sqe[3]]);
        assert_eq!(cid2, cid1 + 1, "CID increments globally across queues");
    }
```

- [ ] **Step 4: Write error case and completion tests**

```rust
    #[test]
    fn invalid_queue_index_rejected() {
        let mut driver = ready_driver_multi(2);
        assert_eq!(
            driver.read_block(5, 1, 0, 0x1000).unwrap_err(),
            NvmeError::InvalidQueueIndex
        );
    }

    #[test]
    fn completion_on_independent_queues() {
        let mut driver = ready_driver_multi(2);

        // Build a CQE with phase=true (initial phase) and status=0
        let mut cqe0 = [0u8; 16];
        cqe0[14] = 0x01; // phase bit = 1 (matches initial cq_phase=true)

        let mut cqe1 = [0u8; 16];
        cqe1[14] = 0x01;

        // Complete on queue 0 (qid=1)
        let cr0 = driver.check_io_completion(0, &cqe0).unwrap().unwrap();
        // Complete on queue 1 (qid=2)
        let cr1 = driver.check_io_completion(1, &cqe1).unwrap().unwrap();

        // CQ doorbell offsets differ: qid=1 → 0x100C, qid=2 → 0x1014
        assert_eq!(cr0.cq_doorbell_offset, 0x100C, "qid=1 CQ doorbell");
        assert_eq!(cr1.cq_doorbell_offset, 0x1014, "qid=2 CQ doorbell");
    }

    #[test]
    fn qid_zero_rejected() {
        let mut driver = enabled_driver();
        assert_eq!(
            driver
                .create_io_queue_pair(0, 0x1000, 0x2000, 16)
                .unwrap_err(),
            NvmeError::InvalidState
        );
    }

    #[test]
    fn activate_without_create_rejected() {
        let mut driver = enabled_driver();
        assert_eq!(
            driver.activate_io_queue_pair(2).unwrap_err(),
            NvmeError::InvalidState
        );
    }

    #[test]
    fn io_queue_count_tracks_activations() {
        let mut driver = enabled_driver();
        assert_eq!(driver.io_queue_count(), 0);

        let _ = driver
            .create_io_queue_pair(1, 0x3_0000, 0x4_0000, 32)
            .unwrap();
        assert_eq!(driver.io_queue_count(), 0); // not activated yet

        driver.activate_io_queue_pair(1).unwrap();
        assert_eq!(driver.io_queue_count(), 1);

        let _ = driver
            .create_io_queue_pair(2, 0x5_0000, 0x6_0000, 32)
            .unwrap();
        driver.activate_io_queue_pair(2).unwrap();
        assert_eq!(driver.io_queue_count(), 2);
    }

    #[test]
    fn first_activation_transitions_enabled_to_ready() {
        let mut driver = enabled_driver();
        assert_eq!(driver.state(), NvmeState::Enabled);

        let _ = driver
            .create_io_queue_pair(1, 0x3_0000, 0x4_0000, 32)
            .unwrap();
        driver.activate_io_queue_pair(1).unwrap();
        assert_eq!(driver.state(), NvmeState::Ready);

        // Second activation stays Ready
        let _ = driver
            .create_io_queue_pair(2, 0x5_0000, 0x6_0000, 32)
            .unwrap();
        driver.activate_io_queue_pair(2).unwrap();
        assert_eq!(driver.state(), NvmeState::Ready);
    }
```

- [ ] **Step 5: Run all tests**

Run: `cargo test -p harmony-unikernel -- nvme 2>&1 | tail -30`

Expected: All tests pass. Count should be 103 (old) - 1 (removed) + 13 (new) = 115 NVMe tests.

- [ ] **Step 6: Run clippy and nightly format**

Run: `cargo clippy -p harmony-unikernel 2>&1 | tail -10`
Run: `cargo +nightly fmt --all`

Expected: No warnings, clean formatting.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "test(nvme): add multi-queue tests for queue creation, targeting, and completion"
```

---

## Summary

| Task | What | Tests |
|------|------|-------|
| 1 | Struct fields + error variant | (compile-only) |
| 2 | Queue creation/activation methods | (compile-only) |
| 3 | I/O method `queue_index` parameter | (compile-only) |
| 4 | Update all existing tests | 103 pass |
| 5 | New multi-queue tests | 13 new → 115 total |
