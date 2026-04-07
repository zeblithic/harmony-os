# NVMe Delete I/O Queues and Abort Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Delete I/O SQ/CQ, delete/deactivate queue pair lifecycle, and Abort admin commands to the NVMe driver.

**Architecture:** All changes in `crates/harmony-unikernel/src/drivers/nvme.rs`. Sans-I/O pattern: driver builds 64-byte SQEs, caller writes to DMA and rings doorbells. Delete commands mirror existing create commands; deactivate mirrors activate. Abort is a standalone admin command.

**Tech Stack:** Rust (no_std), `alloc::vec::Vec`, `MockRegisterBank` for tests.

---

## File Structure

- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`
  - New impl block after I/O queue creation (after line ~841): `delete_io_sq`, `delete_io_cq`, `delete_io_queue_pair`, `deactivate_io_queue_pair`
  - New impl block after Get/Set Features (after line ~703): `abort`
  - New test sections at end of `mod tests` (after line ~3432): 19 tests

No new files.

---

### Task 1: Delete I/O SQ and CQ Commands

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

This task adds the two low-level SQE builder methods `delete_io_sq` (opcode 0x00) and `delete_io_cq` (opcode 0x04), plus 7 tests.

- [ ] **Step 1: Write the failing tests for delete_io_sq**

Add at the end of `mod tests` (before the closing `}`), after the last Get/Set Features test:

```rust
    // ── Delete I/O Queue tests ──────────────────────────────────────────────

    #[test]
    fn delete_io_sq_builds_correct_sqe() {
        let mut driver = ready_driver();
        let cmd = driver.delete_io_sq(1).unwrap();

        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x00, "opcode must be 0x00 (Delete I/O SQ)");

        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10 & 0xFFFF, 1, "QID must be 1 in CDW10 bits 15:0");

        // All other SQE fields must be zero.
        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        let prp2 = u64::from_le_bytes(cmd.sqe[32..40].try_into().unwrap());
        assert_eq!(prp1, 0, "PRP1 must be 0");
        assert_eq!(prp2, 0, "PRP2 must be 0");

        let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
        assert_eq!(cdw11, 0, "CDW11 must be 0");

        assert!(cmd.prp_list.is_none(), "no PRP list");
        assert!(cmd.data_buffer.is_none(), "no data buffer");
    }

    #[test]
    fn delete_io_sq_rejects_wrong_state() {
        let mut driver = enabled_driver();
        match driver.delete_io_sq(1) {
            Err(NvmeError::InvalidState) => {}
            other => panic!("expected InvalidState in Enabled state, got {:?}", other),
        }
    }

    #[test]
    fn delete_io_sq_rejects_qid_zero() {
        let mut driver = ready_driver();
        match driver.delete_io_sq(0) {
            Err(NvmeError::InvalidState) => {}
            other => panic!("expected InvalidState for qid=0, got {:?}", other),
        }
    }

    #[test]
    fn delete_io_sq_increments_cid() {
        let mut driver = ready_driver();
        // ready_driver() consumes CIDs 0-3 (identify_ctrl, identify_ns,
        // create_io_cq, create_io_sq).  Next CID depends on the helper's
        // internal usage, so just check that two consecutive deletes increment.
        let cmd0 = driver.delete_io_sq(1).unwrap();
        let cid0 = (u32::from_le_bytes(cmd0.sqe[0..4].try_into().unwrap()) >> 16) as u16;

        let cmd1 = driver.delete_io_sq(1).unwrap();
        let cid1 = (u32::from_le_bytes(cmd1.sqe[0..4].try_into().unwrap()) >> 16) as u16;

        assert_eq!(cid1, cid0 + 1, "CID must increment");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel delete_io_sq 2>&1 | head -30`
Expected: FAIL — `delete_io_sq` method not found.

- [ ] **Step 3: Write the failing tests for delete_io_cq**

Add immediately after the delete_io_sq tests:

```rust
    #[test]
    fn delete_io_cq_builds_correct_sqe() {
        let mut driver = ready_driver();
        let cmd = driver.delete_io_cq(1).unwrap();

        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x04, "opcode must be 0x04 (Delete I/O CQ)");

        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10 & 0xFFFF, 1, "QID must be 1 in CDW10 bits 15:0");

        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        let prp2 = u64::from_le_bytes(cmd.sqe[32..40].try_into().unwrap());
        assert_eq!(prp1, 0, "PRP1 must be 0");
        assert_eq!(prp2, 0, "PRP2 must be 0");

        let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
        assert_eq!(cdw11, 0, "CDW11 must be 0");

        assert!(cmd.prp_list.is_none(), "no PRP list");
        assert!(cmd.data_buffer.is_none(), "no data buffer");
    }

    #[test]
    fn delete_io_cq_rejects_wrong_state() {
        let mut driver = enabled_driver();
        match driver.delete_io_cq(1) {
            Err(NvmeError::InvalidState) => {}
            other => panic!("expected InvalidState in Enabled state, got {:?}", other),
        }
    }

    #[test]
    fn delete_io_cq_rejects_qid_zero() {
        let mut driver = ready_driver();
        match driver.delete_io_cq(0) {
            Err(NvmeError::InvalidState) => {}
            other => panic!("expected InvalidState for qid=0, got {:?}", other),
        }
    }
```

- [ ] **Step 4: Implement delete_io_sq and delete_io_cq**

Add a new impl block after the I/O queue creation section (after the `activate_io_queue_pair` closing brace, before the `// ── Block I/O commands` comment). The exact insertion point is after the line `}` that closes the `impl<R: RegisterBank> NvmeDriver<R>` block containing `activate_io_queue_pair` (around line ~841):

```rust
// ── I/O queue deletion ─────────────────────────────────────────────────────

impl<R: RegisterBank> NvmeDriver<R> {
    /// Build a Delete I/O Submission Queue admin command (opcode 0x00).
    ///
    /// `qid` is the queue identifier of the SQ to delete (must be ≥ 1).
    /// The NVMe spec requires deleting all SQs associated with a CQ before
    /// deleting that CQ (§5.4).
    pub fn delete_io_sq(&mut self, qid: u16) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }
        if qid == 0 {
            return Err(NvmeError::InvalidState);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let mut sqe = [0u8; 64];

        // CDW0: opcode=0x00 | (CID << 16)
        let cdw0: u32 = 0x00 | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());

        // CDW10: QID in bits 15:0
        let cdw10: u32 = qid as u32;
        sqe[40..44].copy_from_slice(&cdw10.to_le_bytes());

        Ok(self.admin.submit(sqe, self.doorbell_stride))
    }

    /// Build a Delete I/O Completion Queue admin command (opcode 0x04).
    ///
    /// `qid` is the queue identifier of the CQ to delete (must be ≥ 1).
    /// All associated SQs must be deleted first (NVMe spec §5.4).
    pub fn delete_io_cq(&mut self, qid: u16) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }
        if qid == 0 {
            return Err(NvmeError::InvalidState);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let mut sqe = [0u8; 64];

        // CDW0: opcode=0x04 | (CID << 16)
        let cdw0: u32 = 0x04 | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());

        // CDW10: QID in bits 15:0
        let cdw10: u32 = qid as u32;
        sqe[40..44].copy_from_slice(&cdw10.to_le_bytes());

        Ok(self.admin.submit(sqe, self.doorbell_stride))
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p harmony-unikernel delete_io 2>&1 | tail -20`
Expected: 7 tests PASS.

- [ ] **Step 6: Run full test suite**

Run: `cargo test -p harmony-unikernel 2>&1 | tail -5`
Expected: All tests pass (no regressions).

- [ ] **Step 7: Run clippy and fmt**

Run: `cargo clippy -p harmony-unikernel -- -D warnings 2>&1 | tail -5`
Run: `cargo +nightly fmt --all -- --check 2>&1 | tail -5`
Expected: No warnings, no format issues.

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add Delete I/O SQ and Delete I/O CQ admin commands

Build SQE for Delete I/O Submission Queue (opcode 0x00) and Delete I/O
Completion Queue (opcode 0x04). Both require Ready state and qid >= 1.
7 tests verify opcode, CDW10 encoding, state validation, and CID increment."
```

---

### Task 2: Delete/Deactivate Queue Pair Lifecycle

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

This task adds `delete_io_queue_pair` (convenience) and `deactivate_io_queue_pair` (bookkeeping) to the impl block created in Task 1, plus 8 tests.

- [ ] **Step 1: Write the failing tests**

Add after the `delete_io_cq_rejects_qid_zero` test:

```rust
    // ── Delete/Deactivate Queue Pair tests ──────────────────────────────────

    #[test]
    fn delete_io_queue_pair_basic() {
        let mut driver = ready_driver();
        let cmds = driver.delete_io_queue_pair(1).unwrap();

        // First command: Delete I/O SQ (opcode 0x00)
        let cdw0_sq = u32::from_le_bytes(cmds[0].sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0_sq & 0xFF, 0x00, "first command must be Delete SQ");
        let cdw10_sq = u32::from_le_bytes(cmds[0].sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10_sq & 0xFFFF, 1, "SQ delete must target qid=1");

        // Second command: Delete I/O CQ (opcode 0x04)
        let cdw0_cq = u32::from_le_bytes(cmds[1].sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0_cq & 0xFF, 0x04, "second command must be Delete CQ");
        let cdw10_cq = u32::from_le_bytes(cmds[1].sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10_cq & 0xFFFF, 1, "CQ delete must target qid=1");
    }

    #[test]
    fn delete_io_queue_pair_unknown_qid() {
        let mut driver = ready_driver();
        match driver.delete_io_queue_pair(99) {
            Err(NvmeError::InvalidState) => {}
            other => panic!("expected InvalidState for unknown qid, got {:?}", other),
        }
    }

    #[test]
    fn delete_io_queue_pair_ordering() {
        let mut driver = ready_driver();
        let cmds = driver.delete_io_queue_pair(1).unwrap();

        let opcode0 = u32::from_le_bytes(cmds[0].sqe[0..4].try_into().unwrap()) & 0xFF;
        let opcode1 = u32::from_le_bytes(cmds[1].sqe[0..4].try_into().unwrap()) & 0xFF;
        assert_eq!(opcode0, 0x00, "index 0 = Delete SQ");
        assert_eq!(opcode1, 0x04, "index 1 = Delete CQ");
    }

    #[test]
    fn deactivate_io_queue_pair_basic() {
        let mut driver = ready_driver_multi(2);
        assert_eq!(driver.io_queue_count(), 2);

        driver.deactivate_io_queue_pair(1).unwrap();
        assert_eq!(driver.io_queue_count(), 1, "one queue removed");
        assert_eq!(driver.state(), NvmeState::Ready, "still Ready with one queue");
    }

    #[test]
    fn deactivate_last_queue_transitions_to_enabled() {
        let mut driver = ready_driver();
        assert_eq!(driver.io_queue_count(), 1);
        assert_eq!(driver.state(), NvmeState::Ready);

        driver.deactivate_io_queue_pair(1).unwrap();
        assert_eq!(driver.io_queue_count(), 0);
        assert_eq!(driver.state(), NvmeState::Enabled, "no queues → Enabled");
    }

    #[test]
    fn deactivate_one_of_many() {
        let mut driver = ready_driver_multi(3);
        assert_eq!(driver.io_queue_count(), 3);

        driver.deactivate_io_queue_pair(2).unwrap();
        assert_eq!(driver.io_queue_count(), 2);
        assert_eq!(driver.state(), NvmeState::Ready);
    }

    #[test]
    fn deactivate_unknown_qid() {
        let mut driver = ready_driver();
        match driver.deactivate_io_queue_pair(99) {
            Err(NvmeError::InvalidState) => {}
            other => panic!("expected InvalidState for unknown qid, got {:?}", other),
        }
    }

    #[test]
    fn deactivate_wrong_state() {
        let mut driver = enabled_driver();
        match driver.deactivate_io_queue_pair(1) {
            Err(NvmeError::InvalidState) => {}
            other => panic!("expected InvalidState in Enabled state, got {:?}", other),
        }
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel delete_io_queue_pair 2>&1 | head -20`
Run: `cargo test -p harmony-unikernel deactivate 2>&1 | head -20`
Expected: FAIL — methods not found.

- [ ] **Step 3: Implement delete_io_queue_pair and deactivate_io_queue_pair**

Add these two methods inside the same impl block created in Task 1 (after `delete_io_cq`, before the closing `}`):

```rust
    /// Build admin commands to delete one I/O CQ+SQ pair for the given `qid`.
    ///
    /// Returns `[delete_sq_cmd, delete_cq_cmd]` — SQ is deleted first per
    /// NVMe spec §5.4 ("the host shall delete all associated Submission Queues
    /// prior to deleting a Completion Queue").
    ///
    /// The caller must execute them in order, confirm both completions succeed,
    /// then call [`deactivate_io_queue_pair`] to remove the software state.
    pub fn delete_io_queue_pair(&mut self, qid: u16) -> Result<[AdminCommand; 2], NvmeError> {
        if self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }
        // Validate that this qid exists in io_queues.
        if !self.io_queues.iter().any(|q| q.qid == qid) {
            return Err(NvmeError::InvalidState);
        }
        let sq_cmd = self.delete_io_sq(qid)?;
        let cq_cmd = self.delete_io_cq(qid)?;
        Ok([sq_cmd, cq_cmd])
    }

    /// Record that the I/O queue pair identified by `qid` was successfully
    /// deleted on the controller.
    ///
    /// Call this after executing both commands from [`delete_io_queue_pair`]
    /// and confirming successful completions.  Removes the [`QueuePair`] from
    /// `io_queues`.  If no I/O queues remain, transitions back to
    /// [`NvmeState::Enabled`].
    pub fn deactivate_io_queue_pair(&mut self, qid: u16) -> Result<(), NvmeError> {
        if self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }

        let idx = self
            .io_queues
            .iter()
            .position(|q| q.qid == qid)
            .ok_or(NvmeError::InvalidState)?;
        self.io_queues.remove(idx);

        if self.io_queues.is_empty() {
            self.state = NvmeState::Enabled;
        }
        Ok(())
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-unikernel delete_io_queue_pair 2>&1 | tail -15`
Run: `cargo test -p harmony-unikernel deactivate 2>&1 | tail -15`
Expected: 8 tests PASS.

- [ ] **Step 5: Run full test suite**

Run: `cargo test -p harmony-unikernel 2>&1 | tail -5`
Expected: All tests pass (no regressions).

- [ ] **Step 6: Run clippy and fmt**

Run: `cargo clippy -p harmony-unikernel -- -D warnings 2>&1 | tail -5`
Run: `cargo +nightly fmt --all -- --check 2>&1 | tail -5`
Expected: No warnings, no format issues.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add delete_io_queue_pair and deactivate_io_queue_pair

Convenience delete_io_queue_pair(qid) returns [delete_sq, delete_cq] in
NVMe-required SQ-first order. deactivate_io_queue_pair(qid) removes the
QueuePair from io_queues and transitions Ready → Enabled when empty.
8 tests cover basic lifecycle, state transitions, and error cases."
```

---

### Task 3: Abort Command

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

This task adds the `abort` admin command (opcode 0x08) plus 4 tests.

- [ ] **Step 1: Write the failing tests**

Add after the deactivate tests:

```rust
    // ── Abort tests ─────────────────────────────────────────────────────────

    #[test]
    fn abort_builds_correct_sqe() {
        let mut driver = ready_driver();
        let cmd = driver.abort(1, 42).unwrap();

        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x08, "opcode must be 0x08 (Abort)");

        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10 & 0xFFFF, 1, "SQID must be 1 in CDW10 bits 15:0");
        assert_eq!(
            (cdw10 >> 16) as u16,
            42,
            "CID-to-abort must be 42 in CDW10 bits 31:16"
        );

        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        let prp2 = u64::from_le_bytes(cmd.sqe[32..40].try_into().unwrap());
        assert_eq!(prp1, 0, "PRP1 must be 0");
        assert_eq!(prp2, 0, "PRP2 must be 0");

        assert!(cmd.prp_list.is_none(), "no PRP list");
        assert!(cmd.data_buffer.is_none(), "no data buffer");
    }

    #[test]
    fn abort_uses_own_cid() {
        let mut driver = ready_driver();
        let cmd = driver.abort(1, 42).unwrap();

        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        let own_cid = (cdw0 >> 16) as u16;

        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        let target_cid = (cdw10 >> 16) as u16;

        assert_eq!(target_cid, 42, "target CID in CDW10");
        assert_ne!(
            own_cid, target_cid,
            "command's own CID must differ from abort target CID"
        );
    }

    #[test]
    fn abort_rejects_wrong_state() {
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();
        match driver.abort(0, 0) {
            Err(NvmeError::InvalidState) => {}
            other => panic!("expected InvalidState in Disabled state, got {:?}", other),
        }
    }

    #[test]
    fn abort_admin_queue() {
        let mut driver = enabled_driver();
        // SQID=0 is the admin queue — aborting admin commands is valid.
        let cmd = driver.abort(0, 5).unwrap();

        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10 & 0xFFFF, 0, "SQID=0 for admin queue");
        assert_eq!((cdw10 >> 16) as u16, 5, "CID-to-abort=5");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel abort 2>&1 | head -20`
Expected: FAIL — `abort` method not found.

- [ ] **Step 3: Implement abort**

Add a new impl block after the Get/Set Features section (after the `set_num_queues` closing brace at line ~703, before the `// ── I/O queue creation` comment):

```rust
// ── Abort command ────────────────────────────────────────────────────────────

impl<R: RegisterBank> NvmeDriver<R> {
    /// Build an Abort admin command (opcode 0x08).
    ///
    /// `sqid` identifies the submission queue containing the command to abort.
    /// Use 0 for the admin queue. `cid` is the Command Identifier of the
    /// command to abort.
    ///
    /// The controller may or may not honor the abort. The completion status
    /// indicates whether the target command was aborted.
    pub fn abort(&mut self, sqid: u16, cid: u16) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Enabled && self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }

        let own_cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let mut sqe = [0u8; 64];

        // CDW0: opcode=0x08 | (own CID << 16)
        let cdw0: u32 = 0x08 | ((own_cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());

        // CDW10: SQID in bits 15:0, CID-to-abort in bits 31:16
        let cdw10: u32 = (sqid as u32) | ((cid as u32) << 16);
        sqe[40..44].copy_from_slice(&cdw10.to_le_bytes());

        Ok(self.admin.submit(sqe, self.doorbell_stride))
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-unikernel abort 2>&1 | tail -15`
Expected: 4 tests PASS.

- [ ] **Step 5: Run full test suite**

Run: `cargo test -p harmony-unikernel 2>&1 | tail -5`
Expected: All tests pass (no regressions).

- [ ] **Step 6: Run clippy and fmt**

Run: `cargo clippy -p harmony-unikernel -- -D warnings 2>&1 | tail -5`
Run: `cargo +nightly fmt --all -- --check 2>&1 | tail -5`
Expected: No warnings, no format issues.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add Abort admin command (opcode 0x08)

Builds SQE with SQID in CDW10 bits 15:0 and CID-to-abort in bits 31:16.
Stateless — no driver bookkeeping. Works in Enabled or Ready state.
SQID=0 valid for aborting admin commands. 4 tests."
```
