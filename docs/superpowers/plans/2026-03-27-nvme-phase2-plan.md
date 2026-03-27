# NVMe Phase 2: Admin Queue Commands — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add QueuePair abstraction, Create I/O CQ/SQ commands, Identify Namespace, and Ready state to the NVMe driver.

**Architecture:** Refactor inline admin queue fields into a reusable `QueuePair` struct, then add three new admin command builders (Create I/O CQ, Create I/O SQ, Identify Namespace) plus a namespace response parser. All sans-I/O — the driver builds SQEs and returns `AdminCommand` structs; callers handle DMA.

**Tech Stack:** Rust (no_std), RegisterBank trait, MockRegisterBank for testing.

**Spec:** `docs/specs/2026-03-27-nvme-phase2-design.md`

**Existing code:** `crates/harmony-unikernel/src/drivers/nvme.rs` (~817 lines, 13 passing tests)

**Test command:** `cargo test -p harmony-unikernel -- nvme`

**CI parity:** `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`

---

## File Structure

All changes are in a single file:

- **Modify:** `crates/harmony-unikernel/src/drivers/nvme.rs`
  - Add `QueuePair` struct and methods
  - Refactor `NvmeDriver` to use `QueuePair` for admin queue
  - Add `NvmeState::Ready` variant
  - Add `create_io_cq()`, `create_io_sq()`, `create_io_queues()`, `activate_io_queues()`
  - Add `identify_namespace()` command builder
  - Add `IdentifyNamespace` struct and `parse_identify_namespace()` parser
  - Update `identify_controller()` state guard for Ready state
  - Add ~20 new tests

---

### Task 1: QueuePair struct and submit method

Extract the admin queue fields into a reusable `QueuePair` struct with a `submit()` method that computes SQ offset, advances tail, and returns doorbell info.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

**Context for implementer:** The existing `NvmeDriver` struct (line 120) has these admin queue fields that will move into `QueuePair`: `admin_sq_tail`, `admin_cq_head`, `admin_cq_phase`, `admin_sq_phys`, `admin_cq_phys`, `admin_queue_size`. The `doorbell_offset()` helper (line 174) computes doorbell MMIO offsets from qid and stride — `QueuePair` needs this same formula. The `AdminCommand` struct (line 45) is the return type.

- [ ] **Step 1: Write failing tests for QueuePair::submit**

Add these tests in the existing `#[cfg(test)] mod tests` block. Place them after the Phase 1 tests (after line 816) with a comment `// ── QueuePair unit tests ──`.

```rust
// ── QueuePair unit tests ───────────────────────────────────────────────

#[test]
fn queue_pair_submit_computes_offset_and_advances_tail() {
    let mut qp = QueuePair::new(0, 0x1_0000, 0x2_0000, 32);
    let sqe = [0xABu8; 64];
    let cmd = qp.submit(sqe, 0); // doorbell_stride=0

    // sq_offset = tail(0) * 64 = 0
    assert_eq!(cmd.sq_offset, 0);
    // doorbell for SQ of qid=0, stride=0: 0x1000 + (2*0+0)*(4<<0) = 0x1000
    assert_eq!(cmd.doorbell_offset, 0x1000);
    // doorbell value = new tail = 1
    assert_eq!(cmd.doorbell_value, 1);
    // SQE bytes preserved
    assert_eq!(cmd.sqe, [0xABu8; 64]);

    // Second submit: offset = 1*64 = 64, tail advances to 2
    let cmd2 = qp.submit([0xCDu8; 64], 0);
    assert_eq!(cmd2.sq_offset, 64);
    assert_eq!(cmd2.doorbell_value, 2);
}

#[test]
fn queue_pair_submit_wraps_tail() {
    let mut qp = QueuePair::new(0, 0x1_0000, 0x2_0000, 2);
    let _ = qp.submit([0u8; 64], 0); // tail: 0 → 1
    let cmd = qp.submit([0u8; 64], 0); // tail: 1 → 0 (wrap)
    assert_eq!(cmd.doorbell_value, 0);
    assert_eq!(cmd.sq_offset, 64); // offset was computed before wrap
}

#[test]
fn queue_pair_submit_uses_io_queue_doorbell() {
    // qid=1, doorbell_stride=0: SQ doorbell = 0x1000 + (2*1+0)*(4<<0) = 0x1008
    let mut qp = QueuePair::new(1, 0x3_0000, 0x4_0000, 16);
    let cmd = qp.submit([0u8; 64], 0);
    assert_eq!(cmd.doorbell_offset, 0x1008);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel -- nvme::tests::queue_pair_submit 2>&1 | tail -5`
Expected: compilation error — `QueuePair` not found.

- [ ] **Step 3: Implement QueuePair struct and submit method**

Add this after the `CompletionResult` struct (after line 69) and before the Error type section:

```rust
// ── Queue pair ───────────────────────────────────────────────────────────

/// A submission/completion queue pair.
///
/// Tracks the software-maintained tail, head, and phase pointers for one
/// SQ+CQ pair.  Both admin (qid=0) and I/O (qid≥1) queues use this struct.
pub struct QueuePair {
    qid: u16,
    sq_tail: u16,
    cq_head: u16,
    cq_phase: bool,
    sq_phys: u64,
    cq_phys: u64,
    size: u16,
}

impl QueuePair {
    /// Create a new queue pair with all pointers at zero and phase=true.
    pub fn new(qid: u16, sq_phys: u64, cq_phys: u64, size: u16) -> Self {
        Self {
            qid,
            sq_tail: 0,
            cq_head: 0,
            cq_phase: true,
            sq_phys,
            cq_phys,
            size,
        }
    }

    /// Compute the byte offset into the SQ buffer for the current tail,
    /// advance the tail (wrapping), and return an [`AdminCommand`] with
    /// the SQE and doorbell information.
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
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-unikernel -- nvme::tests::queue_pair_submit`
Expected: 3 tests pass.

- [ ] **Step 5: Run all existing NVMe tests to verify no regressions**

Run: `cargo test -p harmony-unikernel -- nvme`
Expected: all 13 Phase 1 tests + 3 new tests pass (16 total).

- [ ] **Step 6: Run CI parity checks**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add QueuePair struct with submit method

Extract reusable queue pair abstraction for NVMe submission queues.
Supports arbitrary qid, doorbell stride, and tail wrapping."
```

---

### Task 2: QueuePair check_completion method

Add a `check_completion()` method to `QueuePair` that handles phase-bit detection, CQ head advancement, and phase inversion on wrap.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

**Context for implementer:** The existing `NvmeDriver::check_completion()` (line 441) has the exact logic that needs to move into `QueuePair`. It parses a 16-byte CQE: bytes 14-15 are the status word (bit 0 = phase, bits 15:1 = status code), bytes 0-3 are DW0 (result), bytes 12-13 are CID. On phase match, it advances `cq_head` and inverts `cq_phase` on wrap. The `CompletionResult` struct (line 65) bundles the parsed completion with CQ doorbell info. The doorbell formula is `0x1000 + (2*qid + 1) * (4 << stride)` — note the `+1` for CQ vs SQ.

- [ ] **Step 1: Write failing tests for QueuePair::check_completion**

Add after the Task 1 tests:

```rust
#[test]
fn queue_pair_check_completion_phase_match() {
    let mut qp = QueuePair::new(0, 0x1_0000, 0x2_0000, 32);
    // CQE with phase=1 (matches initial cq_phase=true), CID=5, result=0x42
    let mut cqe = [0u8; 16];
    cqe[0..4].copy_from_slice(&0x42u32.to_le_bytes());
    cqe[12..14].copy_from_slice(&5u16.to_le_bytes());
    cqe[14..16].copy_from_slice(&0x0001u16.to_le_bytes()); // phase=1, status=0

    let cr = qp.check_completion(&cqe, 0).expect("phase matches");
    assert_eq!(cr.completion.cid, 5);
    assert_eq!(cr.completion.status, 0);
    assert_eq!(cr.completion.result, 0x42);
    // CQ doorbell for qid=0: 0x1000 + (2*0+1)*(4<<0) = 0x1004
    assert_eq!(cr.cq_doorbell_offset, 0x1004);
    assert_eq!(cr.cq_doorbell_value, 1); // head advanced to 1
}

#[test]
fn queue_pair_check_completion_phase_mismatch() {
    let mut qp = QueuePair::new(0, 0x1_0000, 0x2_0000, 32);
    // CQE with phase=0, but cq_phase=true → mismatch
    let mut cqe = [0u8; 16];
    cqe[14..16].copy_from_slice(&0x0000u16.to_le_bytes());

    assert!(qp.check_completion(&cqe, 0).is_none());
}

#[test]
fn queue_pair_check_completion_wraps_and_inverts_phase() {
    let mut qp = QueuePair::new(0, 0x1_0000, 0x2_0000, 2); // size=2

    let make_cqe = |phase: bool| -> [u8; 16] {
        let mut cqe = [0u8; 16];
        let status_word: u16 = if phase { 0x0001 } else { 0x0000 };
        cqe[14..16].copy_from_slice(&status_word.to_le_bytes());
        cqe
    };

    // head=0, phase=true → match, head→1
    let r1 = qp.check_completion(&make_cqe(true), 0).unwrap();
    assert_eq!(r1.cq_doorbell_value, 1);

    // head=1, phase=true → match, head wraps→0, phase inverts→false
    let r2 = qp.check_completion(&make_cqe(true), 0).unwrap();
    assert_eq!(r2.cq_doorbell_value, 0);

    // head=0, phase=false → match (inverted phase)
    let r3 = qp.check_completion(&make_cqe(false), 0).unwrap();
    assert_eq!(r3.cq_doorbell_value, 1);
}

#[test]
fn queue_pair_check_completion_io_queue_doorbell() {
    // qid=1, stride=0: CQ doorbell = 0x1000 + (2*1+1)*(4<<0) = 0x100C
    let mut qp = QueuePair::new(1, 0x3_0000, 0x4_0000, 16);
    let mut cqe = [0u8; 16];
    cqe[14..16].copy_from_slice(&0x0001u16.to_le_bytes());

    let cr = qp.check_completion(&cqe, 0).unwrap();
    assert_eq!(cr.cq_doorbell_offset, 0x100C);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel -- nvme::tests::queue_pair_check_completion 2>&1 | tail -5`
Expected: compilation error — `check_completion` not found on `QueuePair`.

- [ ] **Step 3: Implement QueuePair::check_completion**

Add this method to the `impl QueuePair` block, after `submit()`:

```rust
    /// Parse a 16-byte CQE and, if the phase bit matches, return the
    /// completion with CQ doorbell info.  Returns `None` on phase mismatch.
    pub fn check_completion(
        &mut self,
        cqe: &[u8; 16],
        doorbell_stride: u8,
    ) -> Option<CompletionResult> {
        let status_word = u16::from_le_bytes([cqe[14], cqe[15]]);
        let phase = (status_word & 0x0001) != 0;
        let status = status_word >> 1;

        if phase != self.cq_phase {
            return None;
        }

        let result = u32::from_le_bytes([cqe[0], cqe[1], cqe[2], cqe[3]]);
        let cid = u16::from_le_bytes([cqe[12], cqe[13]]);

        let next_head = self.cq_head + 1;
        if next_head >= self.size {
            self.cq_head = 0;
            self.cq_phase = !self.cq_phase;
        } else {
            self.cq_head = next_head;
        }

        let stride = 4usize << doorbell_stride;
        let cq_doorbell_offset = 0x1000 + (2 * self.qid as usize + 1) * stride;
        let cq_doorbell_value = self.cq_head as u32;

        Some(CompletionResult {
            completion: Completion {
                cid,
                status,
                result,
            },
            cq_doorbell_offset,
            cq_doorbell_value,
        })
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-unikernel -- nvme::tests::queue_pair_check_completion`
Expected: 4 tests pass.

- [ ] **Step 5: Run all NVMe tests**

Run: `cargo test -p harmony-unikernel -- nvme`
Expected: 20 tests pass (13 Phase 1 + 3 from Task 1 + 4 new).

- [ ] **Step 6: Run CI parity checks**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add QueuePair::check_completion with phase detection

CQ head advancement, phase inversion on wrap, and per-queue doorbell
offset calculation."
```

---

### Task 3: Refactor NvmeDriver to use QueuePair

Replace the inline admin queue fields with `QueuePair`. Delegate `identify_controller()` and `check_completion()` through `QueuePair` methods. All 13 Phase 1 tests must pass unchanged.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

**Context for implementer:** The `NvmeDriver` struct (line 120) currently has 6 admin queue fields: `admin_sq_tail`, `admin_cq_head`, `admin_cq_phase`, `admin_sq_phys`, `admin_cq_phys`, `admin_queue_size`. Replace all 6 with `admin: QueuePair`. The `init()` method (line 233) constructs the driver with zeroed admin fields — replace with `admin: QueuePair::new(0, 0, 0, 0)`. The `setup_admin_queue()` method (line 314) sets these fields after enabling the controller — replace with `self.admin = QueuePair::new(0, sq_phys, cq_phys, size)`. The `identify_controller()` method (line 377) builds an SQE and uses `admin_sq_tail` / `admin_queue_size` / `doorbell_offset(0, false)` — delegate SQE submission to `self.admin.submit()`. The `check_completion()` method (line 441) does CQE parsing — delegate to `self.admin.check_completion()` and wrap in `Ok()`.

Also add `NvmeState::Ready` variant and an `io: Option<QueuePair>` field (initialized to `None`). Update `identify_controller()` state guard to accept both `Enabled` and `Ready`.

**CRITICAL:** The `doorbell_offset()` helper method on `NvmeDriver` can be removed — `QueuePair` now computes doorbells internally. But keep `read64()`, `write64()`, and `poll_ready()` on `NvmeDriver` — they access `self.bank` which `QueuePair` doesn't have.

- [ ] **Step 1: Refactor NvmeDriver struct**

Replace the 6 admin fields with `admin: QueuePair` and add `io: Option<QueuePair>`. Add `Ready` to `NvmeState`:

```rust
pub enum NvmeState {
    Uninitialized,
    Disabled,
    Enabled,
    Ready,  // I/O queues created and active
}

pub struct NvmeDriver<R: RegisterBank> {
    bank: R,
    max_queue_entries: u16,
    doorbell_stride: u8,
    timeout_ms: u32,
    next_cid: u16,
    state: NvmeState,
    admin: QueuePair,
    io: Option<QueuePair>,
}
```

- [ ] **Step 1b: Update AdminCommand doc comment**

The `AdminCommand::sqe` doc comment (line 46) says `admin_sq_phys + sq_offset`. Update it to just `sq_phys + sq_offset` since `admin_sq_phys` is no longer a field.

- [ ] **Step 2: Update init() to construct QueuePair**

In `init()`, replace the admin field initialization:
```rust
// Old:
admin_sq_tail: 0,
admin_cq_head: 0,
admin_cq_phase: true,
admin_sq_phys: 0,
admin_cq_phys: 0,
admin_queue_size: 0,

// New:
admin: QueuePair::new(0, 0, 0, 0),
io: None,
```

- [ ] **Step 3: Update setup_admin_queue() to replace QueuePair**

Replace the step 8 field assignments:
```rust
// Old:
self.admin_sq_phys = sq_phys;
self.admin_cq_phys = cq_phys;
self.admin_queue_size = size;
self.admin_sq_tail = 0;
self.admin_cq_head = 0;
self.admin_cq_phase = true;

// New:
self.admin = QueuePair::new(0, sq_phys, cq_phys, size);
```

Also update the `size == 0` guard and clamping — these still use the local `size` variable, no change needed.

- [ ] **Step 4: Update identify_controller() to delegate to QueuePair**

Replace the SQE offset computation, tail advance, and doorbell calculation with `self.admin.submit()`:

```rust
pub fn identify_controller(&mut self, data_phys: u64) -> Result<AdminCommand, NvmeError> {
    if self.state != NvmeState::Enabled && self.state != NvmeState::Ready {
        return Err(NvmeError::InvalidState);
    }

    let cid = self.next_cid;
    self.next_cid = self.next_cid.wrapping_add(1);

    let mut sqe = [0u8; 64];
    let cdw0: u32 = 0x06 | ((cid as u32) << 16);
    sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
    sqe[24..32].copy_from_slice(&data_phys.to_le_bytes());
    sqe[40..44].copy_from_slice(&1u32.to_le_bytes());

    Ok(self.admin.submit(sqe, self.doorbell_stride))
}
```

- [ ] **Step 5: Update check_completion() to delegate to QueuePair**

Replace the entire body:

```rust
pub fn check_completion(
    &mut self,
    cqe_bytes: &[u8; 16],
) -> Result<Option<CompletionResult>, NvmeError> {
    Ok(self.admin.check_completion(cqe_bytes, self.doorbell_stride))
}
```

- [ ] **Step 6: Remove the old doorbell_offset() helper from NvmeDriver**

Delete the `doorbell_offset()` method (was at line 174). `QueuePair::submit()` and `QueuePair::check_completion()` now compute doorbells internally.

- [ ] **Step 7: Fix any test compilation issues**

Phase 1 tests that access `driver.admin_cq_head` or `driver.admin_cq_phase` directly now need to use the `QueuePair`. If any test references private fields, they'll need updating. Check the wrap test (originally line 740) — it accesses `driver.admin_cq_head` and `driver.admin_cq_phase`. These are now `driver.admin.cq_head` and `driver.admin.cq_phase`. Since `QueuePair` fields are not `pub`, either:
- Make the fields `pub(crate)` for test access, or
- Add accessor methods like `QueuePair::cq_head()` and `QueuePair::cq_phase()`

Use `pub(crate)` — it matches the existing pattern (Phase 1 tests already access private driver fields directly via `driver.admin_sq_tail`, `driver.bank.writes`, etc.).

Update the struct fields to `pub(crate)`:
```rust
pub struct QueuePair {
    pub(crate) qid: u16,
    pub(crate) sq_tail: u16,
    pub(crate) cq_head: u16,
    pub(crate) cq_phase: bool,
    pub(crate) sq_phys: u64,
    pub(crate) cq_phys: u64,
    pub(crate) size: u16,
}
```

Update test references:
- `driver.admin_cq_head` → `driver.admin.cq_head`
- `driver.admin_cq_phase` → `driver.admin.cq_phase`
- `driver.admin_queue_size` → `driver.admin.size`
- `driver.state` (unchanged — still on NvmeDriver)

- [ ] **Step 8: Run all NVMe tests**

Run: `cargo test -p harmony-unikernel -- nvme`
Expected: all 20 tests pass (13 Phase 1 + 7 QueuePair).

- [ ] **Step 9: Run CI parity checks**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`
Expected: clean.

- [ ] **Step 10: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "refactor(nvme): replace inline admin queue fields with QueuePair

NvmeDriver now holds admin: QueuePair and io: Option<QueuePair>.
identify_controller() and check_completion() delegate to QueuePair
methods. Add NvmeState::Ready variant for Phase 2. All Phase 1 tests
pass unchanged."
```

---

### Task 4: Create I/O CQ and Create I/O SQ commands

Add `create_io_cq()` and `create_io_sq()` command builders that produce `AdminCommand` structs for creating I/O queue pairs on the controller.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

**Context for implementer:** These follow the exact same pattern as `identify_controller()`: check state, build 64-byte SQE, call `self.admin.submit()`. The SQE layouts are in the spec. Create I/O CQ = opcode 0x05, CDW10 = `QID | (size-1) << 16`, CDW11 = `0x0000_0003` (PC + IEN). Create I/O SQ = opcode 0x01, CDW10 = `QID | (size-1) << 16`, CDW11 = `0x0001_0001` (PC + CQID=1). Both use PRP1 for the physical base address. CDW0 format: `opcode | (cid << 16)`.

- [ ] **Step 1: Write failing tests**

```rust
// ── Create I/O queue tests ────────────────────────────────────────────

#[test]
fn create_io_cq_builds_correct_sqe() {
    let mut driver = enabled_driver();
    let cq_phys: u64 = 0xAAAA_0000;
    let cmd = driver.create_io_cq(cq_phys, 32).unwrap();

    let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
    assert_eq!(cdw0 & 0xFF, 0x05, "opcode must be 0x05 (Create I/O CQ)");

    let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
    assert_eq!(prp1, cq_phys);

    // CDW10: QID=1 | (31 << 16) = 0x001F_0001
    let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
    assert_eq!(cdw10 & 0xFFFF, 1, "QID must be 1");
    assert_eq!(cdw10 >> 16, 31, "QSIZE must be size-1 = 31");

    // CDW11: PC=1, IEN=1, IV=0 → 0x0000_0003
    let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
    assert_eq!(cdw11, 0x0000_0003);
}

#[test]
fn create_io_sq_builds_correct_sqe() {
    let mut driver = enabled_driver();
    let sq_phys: u64 = 0xBBBB_0000;
    let cmd = driver.create_io_sq(sq_phys, 32).unwrap();

    let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
    assert_eq!(cdw0 & 0xFF, 0x01, "opcode must be 0x01 (Create I/O SQ)");

    let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
    assert_eq!(prp1, sq_phys);

    // CDW10: QID=1 | (31 << 16)
    let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
    assert_eq!(cdw10 & 0xFFFF, 1);
    assert_eq!(cdw10 >> 16, 31);

    // CDW11: PC=1, CQID=1<<16 → 0x0001_0001
    let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
    assert_eq!(cdw11, 0x0001_0001);
}

#[test]
fn create_io_cq_rejects_disabled_state() {
    let bank = mock_nvme_bank();
    let mut driver = NvmeDriver::init(bank).unwrap();
    // State is Disabled — should reject
    assert_eq!(
        driver.create_io_cq(0x1000, 16).unwrap_err(),
        NvmeError::InvalidState
    );
}

#[test]
fn create_io_cq_advances_admin_doorbell() {
    let mut driver = enabled_driver();
    let cmd1 = driver.create_io_cq(0xAAAA_0000, 16).unwrap();
    let cmd2 = driver.create_io_cq(0xBBBB_0000, 16).unwrap();
    // Doorbell values should be sequential (admin SQ tail advancing)
    assert_eq!(cmd1.doorbell_value, cmd2.doorbell_value - 1);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel -- nvme::tests::create_io 2>&1 | tail -5`
Expected: compilation error — `create_io_cq` not found.

- [ ] **Step 3: Implement create_io_cq and create_io_sq**

Add a new `impl` block after the Identify Controller section:

```rust
// ── I/O queue creation ───────────────────────────────────────────────────

impl<R: RegisterBank> NvmeDriver<R> {
    /// Build a Create I/O Completion Queue admin command (opcode 0x05).
    ///
    /// The caller allocates `size * 16` bytes of zeroed DMA memory and
    /// passes its physical address as `cq_phys`.
    pub fn create_io_cq(
        &mut self,
        cq_phys: u64,
        size: u16,
    ) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Enabled && self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let size = size.min(self.max_queue_entries);

        let mut sqe = [0u8; 64];
        // CDW0: opcode=0x05, CID
        let cdw0: u32 = 0x05 | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
        // PRP1: cq_phys
        sqe[24..32].copy_from_slice(&cq_phys.to_le_bytes());
        // CDW10: QID=1 | (size-1) << 16
        let cdw10: u32 = 1 | (((size - 1) as u32) << 16);
        sqe[40..44].copy_from_slice(&cdw10.to_le_bytes());
        // CDW11: PC=1, IEN=1, IV=0
        let cdw11: u32 = 0x0000_0003;
        sqe[44..48].copy_from_slice(&cdw11.to_le_bytes());

        Ok(self.admin.submit(sqe, self.doorbell_stride))
    }

    /// Build a Create I/O Submission Queue admin command (opcode 0x01).
    ///
    /// The caller allocates `size * 64` bytes of zeroed DMA memory and
    /// passes its physical address as `sq_phys`.  The associated CQ
    /// (qid=1) must be created first.
    pub fn create_io_sq(
        &mut self,
        sq_phys: u64,
        size: u16,
    ) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Enabled && self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let size = size.min(self.max_queue_entries);

        let mut sqe = [0u8; 64];
        // CDW0: opcode=0x01, CID
        let cdw0: u32 = 0x01 | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
        // PRP1: sq_phys
        sqe[24..32].copy_from_slice(&sq_phys.to_le_bytes());
        // CDW10: QID=1 | (size-1) << 16
        let cdw10: u32 = 1 | (((size - 1) as u32) << 16);
        sqe[40..44].copy_from_slice(&cdw10.to_le_bytes());
        // CDW11: PC=1, CQID=1<<16
        let cdw11: u32 = 0x0001_0001;
        sqe[44..48].copy_from_slice(&cdw11.to_le_bytes());

        Ok(self.admin.submit(sqe, self.doorbell_stride))
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-unikernel -- nvme::tests::create_io`
Expected: 4 tests pass.

- [ ] **Step 5: Run all NVMe tests + CI parity**

Run: `cargo test -p harmony-unikernel -- nvme && cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`
Expected: 24 tests pass, clippy + fmt clean.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add Create I/O CQ and Create I/O SQ commands

Opcode 0x05 (Create I/O CQ) and 0x01 (Create I/O SQ) admin command
builders. Both use hardcoded QID=1 and physically contiguous mode."
```

---

### Task 5: create_io_queues convenience method and activate_io_queues

Add the convenience `create_io_queues()` that returns both commands in order, and `activate_io_queues()` that records success and transitions to Ready.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

**Context for implementer:** `create_io_queues()` calls `create_io_cq()` then `create_io_sq()` and returns the pair as `[AdminCommand; 2]`. It clamps `size` to `max_queue_entries`. `activate_io_queues()` is a separate method because the sans-I/O contract means the driver can't know if the commands succeeded — the caller tells it by calling `activate_io_queues()` after confirming completions. `activate_io_queues()` requires `Enabled` state (not already `Ready`), constructs `QueuePair::new(1, sq_phys, cq_phys, size)`, stores it in `self.io`, and transitions to `Ready`.

- [ ] **Step 1: Write failing tests**

```rust
// ── create_io_queues + activate tests ─────────────────────────────────

#[test]
fn create_io_queues_returns_cq_first_sq_second() {
    let mut driver = enabled_driver();
    let cmds = driver.create_io_queues(0xBBBB_0000, 0xAAAA_0000, 32).unwrap();

    // First command is Create I/O CQ (opcode 0x05)
    let cdw0_cq = u32::from_le_bytes(cmds[0].sqe[0..4].try_into().unwrap());
    assert_eq!(cdw0_cq & 0xFF, 0x05);

    // Second command is Create I/O SQ (opcode 0x01)
    let cdw0_sq = u32::from_le_bytes(cmds[1].sqe[0..4].try_into().unwrap());
    assert_eq!(cdw0_sq & 0xFF, 0x01);
}

#[test]
fn create_io_queues_clamps_size() {
    let mut driver = enabled_driver(); // MQES+1 = 64
    let cmds = driver.create_io_queues(0xBBBB_0000, 0xAAAA_0000, 256).unwrap();

    // CDW10 of CQ: size-1 in upper 16 bits should be 63 (clamped to 64)
    let cdw10 = u32::from_le_bytes(cmds[0].sqe[40..44].try_into().unwrap());
    assert_eq!(cdw10 >> 16, 63);
}

#[test]
fn create_io_queues_rejects_disabled_state() {
    let bank = mock_nvme_bank();
    let mut driver = NvmeDriver::init(bank).unwrap();
    assert_eq!(
        driver.create_io_queues(0x1000, 0x2000, 16).unwrap_err(),
        NvmeError::InvalidState
    );
}

#[test]
fn create_io_queues_rejects_ready_state() {
    let mut driver = enabled_driver();
    driver.activate_io_queues(0xBBBB_0000, 0xAAAA_0000, 32).unwrap();
    assert_eq!(driver.state(), NvmeState::Ready);
    // Already has I/O queues — should reject
    assert_eq!(
        driver.create_io_queues(0xCCCC_0000, 0xDDDD_0000, 16).unwrap_err(),
        NvmeError::InvalidState
    );
}

#[test]
fn activate_io_queues_transitions_to_ready() {
    let mut driver = enabled_driver();
    assert_eq!(driver.state(), NvmeState::Enabled);

    driver.activate_io_queues(0xBBBB_0000, 0xAAAA_0000, 32).unwrap();

    assert_eq!(driver.state(), NvmeState::Ready);
    assert!(driver.io.is_some());
    let io = driver.io.as_ref().unwrap();
    assert_eq!(io.qid, 1);
    assert_eq!(io.size, 32);
}

#[test]
fn activate_io_queues_rejects_double_activation() {
    let mut driver = enabled_driver();
    driver.activate_io_queues(0xBBBB_0000, 0xAAAA_0000, 32).unwrap();
    // Now Ready — second call should fail
    assert_eq!(
        driver.activate_io_queues(0xCCCC_0000, 0xDDDD_0000, 16).unwrap_err(),
        NvmeError::InvalidState
    );
}

#[test]
fn activate_io_queues_rejects_disabled_state() {
    let bank = mock_nvme_bank();
    let mut driver = NvmeDriver::init(bank).unwrap();
    assert_eq!(
        driver.activate_io_queues(0x1000, 0x2000, 16).unwrap_err(),
        NvmeError::InvalidState
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel -- nvme::tests::create_io_queues 2>&1 | tail -5`
Run: `cargo test -p harmony-unikernel -- nvme::tests::activate_io_queues 2>&1 | tail -5`
Expected: compilation errors.

Note: `create_io_queues_rejects_ready_state` depends on `activate_io_queues` — both are implemented in Step 3, so all tests compile together.

- [ ] **Step 3: Implement create_io_queues and activate_io_queues**

Add to the I/O queue creation `impl` block:

```rust
    /// Build admin commands to create one I/O CQ+SQ pair (qid=1).
    ///
    /// Returns `[create_cq_cmd, create_sq_cmd]`.  The caller must execute
    /// them in order, confirm both completions succeed, then call
    /// [`activate_io_queues`] to record the result.
    pub fn create_io_queues(
        &mut self,
        sq_phys: u64,
        cq_phys: u64,
        size: u16,
    ) -> Result<[AdminCommand; 2], NvmeError> {
        // Only allow in Enabled state — not Ready (queues already exist)
        // or Disabled (admin queue not active).
        if self.state != NvmeState::Enabled {
            return Err(NvmeError::InvalidState);
        }
        let size = size.min(self.max_queue_entries);
        let cq_cmd = self.create_io_cq(cq_phys, size)?;
        let sq_cmd = self.create_io_sq(sq_phys, size)?;
        Ok([cq_cmd, sq_cmd])
    }

    /// Record that the I/O queues were successfully created on the
    /// controller.
    ///
    /// Call this after executing both commands from [`create_io_queues`]
    /// and confirming successful completions.  Transitions the driver to
    /// [`NvmeState::Ready`].
    pub fn activate_io_queues(
        &mut self,
        sq_phys: u64,
        cq_phys: u64,
        size: u16,
    ) -> Result<(), NvmeError> {
        if self.state != NvmeState::Enabled {
            return Err(NvmeError::InvalidState);
        }

        let size = size.min(self.max_queue_entries);
        self.io = Some(QueuePair::new(1, sq_phys, cq_phys, size));
        self.state = NvmeState::Ready;
        Ok(())
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-unikernel -- nvme`
Expected: 31 tests pass.

- [ ] **Step 5: Run CI parity checks**

Run: `cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add create_io_queues convenience and activate_io_queues

create_io_queues returns [CQ, SQ] command pair. activate_io_queues
records success and transitions to Ready state. Sans-I/O split:
driver builds commands, caller confirms success."
```

---

### Task 6: Identify Namespace command builder

Add `identify_namespace()` that builds an Identify Namespace SQE (opcode 0x06, CNS=0) with a caller-supplied NSID.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

**Context for implementer:** Same pattern as `identify_controller()`. The key difference: CDW1 (bytes 4-7 of the SQE) is the NSID field, and CDW10 is CNS=0x00 (Identify Namespace) instead of CNS=0x01 (Identify Controller). The NSID is passed as a parameter — typically 1 for the first namespace.

- [ ] **Step 1: Write failing tests**

```rust
// ── Identify Namespace tests ──────────────────────────────────────────

#[test]
fn identify_namespace_builds_correct_sqe() {
    let mut driver = enabled_driver();
    let data_phys: u64 = 0xFEED_0000;
    let cmd = driver.identify_namespace(1, data_phys).unwrap();

    // Opcode 0x06 (Identify)
    let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
    assert_eq!(cdw0 & 0xFF, 0x06);

    // NSID at bytes 4-7
    let nsid = u32::from_le_bytes(cmd.sqe[4..8].try_into().unwrap());
    assert_eq!(nsid, 1);

    // PRP1
    let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
    assert_eq!(prp1, data_phys);

    // CDW10: CNS=0x00
    let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
    assert_eq!(cdw10, 0x00);
}

#[test]
fn identify_namespace_different_nsids() {
    let mut driver = enabled_driver();
    let cmd1 = driver.identify_namespace(1, 0x1000).unwrap();
    let cmd2 = driver.identify_namespace(2, 0x2000).unwrap();

    let nsid1 = u32::from_le_bytes(cmd1.sqe[4..8].try_into().unwrap());
    let nsid2 = u32::from_le_bytes(cmd2.sqe[4..8].try_into().unwrap());
    assert_ne!(nsid1, nsid2);
    assert_eq!(nsid1, 1);
    assert_eq!(nsid2, 2);
}

#[test]
fn identify_namespace_rejects_disabled_state() {
    let bank = mock_nvme_bank();
    let mut driver = NvmeDriver::init(bank).unwrap();
    assert_eq!(
        driver.identify_namespace(1, 0x1000).unwrap_err(),
        NvmeError::InvalidState
    );
}

#[test]
fn identify_namespace_works_in_ready_state() {
    let mut driver = enabled_driver();
    driver.activate_io_queues(0xBBBB_0000, 0xAAAA_0000, 32).unwrap();
    assert_eq!(driver.state(), NvmeState::Ready);
    // Should succeed in Ready state
    driver.identify_namespace(1, 0x1000).unwrap();
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel -- nvme::tests::identify_namespace 2>&1 | tail -5`
Expected: compilation error — `identify_namespace` not found.

- [ ] **Step 3: Implement identify_namespace**

Add to the Identify Controller `impl` block (or a new one nearby):

```rust
    /// Build an Identify Namespace admin command (opcode 0x06, CNS=0).
    ///
    /// The caller must DMA-map a 4 KiB buffer and pass its physical
    /// address as `data_phys`.  `nsid` identifies the namespace (typically 1).
    pub fn identify_namespace(
        &mut self,
        nsid: u32,
        data_phys: u64,
    ) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Enabled && self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let mut sqe = [0u8; 64];
        // CDW0: opcode=0x06, CID
        let cdw0: u32 = 0x06 | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());
        // CDW1 (NSID): bytes 4-7
        sqe[4..8].copy_from_slice(&nsid.to_le_bytes());
        // PRP1: data_phys
        sqe[24..32].copy_from_slice(&data_phys.to_le_bytes());
        // CDW10: CNS=0x00 (Identify Namespace)
        sqe[40..44].copy_from_slice(&0u32.to_le_bytes());

        Ok(self.admin.submit(sqe, self.doorbell_stride))
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-unikernel -- nvme::tests::identify_namespace`
Expected: 4 tests pass.

- [ ] **Step 5: Run all NVMe tests + CI parity**

Run: `cargo test -p harmony-unikernel -- nvme && cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`
Expected: 35 tests pass, clean.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add Identify Namespace command builder

Opcode 0x06 with CNS=0x00 and caller-supplied NSID. Accepts both
Enabled and Ready states."
```

---

### Task 7: IdentifyNamespace parser

Add `IdentifyNamespace` struct and `parse_identify_namespace()` pure function that extracts NSZE, NCAP, NUSE, FLBAS, and derives `lba_size_bytes` from the LBA Format table.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

**Context for implementer:** Follows the exact same pattern as `parse_identify_controller()` (line 495). Pure function taking `&[u8; 4096]`, returning a struct. The LBA Format table starts at byte 128, each entry is 4 bytes. `flbas & 0x0F` indexes into the table. Byte 2 of the selected entry is `LBADS` — LBA Data Size as a power of 2. `lba_size_bytes = 1u32 << lbads`. Common values: LBADS=9 → 512 bytes, LBADS=12 → 4096 bytes.

- [ ] **Step 1: Write failing tests**

```rust
// ── parse_identify_namespace tests ────────────────────────────────────

#[test]
fn parse_identify_namespace_extracts_fields() {
    let mut data = [0u8; 4096];

    // NSZE: bytes 0-7
    data[0..8].copy_from_slice(&1024u64.to_le_bytes());
    // NCAP: bytes 8-15
    data[8..16].copy_from_slice(&1000u64.to_le_bytes());
    // NUSE: bytes 16-23
    data[16..24].copy_from_slice(&500u64.to_le_bytes());
    // FLBAS: byte 26 (index 0 into LBA format table)
    data[26] = 0x00;
    // LBA Format 0 at byte 128: bytes [MS(2), LBADS(1), RP(1)]
    // LBADS = byte 130 = 9 → 512 bytes
    data[130] = 9;

    let ns = parse_identify_namespace(&data);
    assert_eq!(ns.nsze, 1024);
    assert_eq!(ns.ncap, 1000);
    assert_eq!(ns.nuse, 500);
    assert_eq!(ns.flbas, 0);
    assert_eq!(ns.lba_size_bytes, 512);
}

#[test]
fn parse_identify_namespace_4k_sectors() {
    let mut data = [0u8; 4096];

    data[0..8].copy_from_slice(&2048u64.to_le_bytes());
    data[8..16].copy_from_slice(&2048u64.to_le_bytes());
    data[16..24].copy_from_slice(&100u64.to_le_bytes());
    // FLBAS: index 1
    data[26] = 0x01;
    // LBA Format 1 at byte 132 (128 + 1*4): LBADS at offset 2 = byte 134
    data[134] = 12; // 2^12 = 4096

    let ns = parse_identify_namespace(&data);
    assert_eq!(ns.flbas, 1);
    assert_eq!(ns.lba_size_bytes, 4096);
}

#[test]
fn parse_identify_namespace_flbas_uses_low_nibble() {
    let mut data = [0u8; 4096];
    data[0..8].copy_from_slice(&100u64.to_le_bytes());
    data[8..16].copy_from_slice(&100u64.to_le_bytes());
    data[16..24].copy_from_slice(&50u64.to_le_bytes());
    // FLBAS byte: 0x12 — low nibble is 2, high nibble (metadata) is 1
    data[26] = 0x12;
    // LBA Format 2 at byte 136 (128 + 2*4): LBADS at byte 138
    data[138] = 9;

    let ns = parse_identify_namespace(&data);
    assert_eq!(ns.flbas, 0x12, "raw byte preserved");
    assert_eq!(ns.lba_size_bytes, 512, "uses low nibble (index 2)");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel -- nvme::tests::parse_identify_namespace 2>&1 | tail -5`
Expected: compilation error — `parse_identify_namespace` and `IdentifyNamespace` not found.

- [ ] **Step 3: Implement IdentifyNamespace and parse_identify_namespace**

Add the struct near `IdentifyController` (around line 72):

```rust
/// Parsed fields from the 4 KiB Identify Namespace data structure.
#[derive(Debug, Clone)]
pub struct IdentifyNamespace {
    /// Namespace size in logical blocks (bytes 0-7).
    pub nsze: u64,
    /// Namespace capacity in logical blocks (bytes 8-15).
    pub ncap: u64,
    /// Namespace utilization in logical blocks (bytes 16-23).
    pub nuse: u64,
    /// Formatted LBA Size — raw byte 26 (bits 3:0 = LBA format index).
    pub flbas: u8,
    /// Logical block size in bytes, derived from LBAF[flbas & 0x0F].LBADS.
    pub lba_size_bytes: u32,
}
```

Add the parser function near `parse_identify_controller` (around line 516):

```rust
/// Parse the 4 KiB Identify Namespace data structure (NVMe spec §5.15.2.2).
///
/// | Bytes   | Field              |
/// |---------|--------------------|
/// | 0-7     | NSZE               |
/// | 8-15    | NCAP               |
/// | 16-23   | NUSE               |
/// | 26      | FLBAS              |
/// | 128+    | LBA Format table   |
pub fn parse_identify_namespace(data: &[u8; 4096]) -> IdentifyNamespace {
    let nsze = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let ncap = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let nuse = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let flbas = data[26];

    // LBA Format table starts at byte 128, 4 bytes per entry.
    // LBADS is at byte 2 of each entry.
    let fmt_index = (flbas & 0x0F) as usize;
    let lbads = data[128 + fmt_index * 4 + 2];
    let lba_size_bytes = 1u32 << lbads;

    IdentifyNamespace {
        nsze,
        ncap,
        nuse,
        flbas,
        lba_size_bytes,
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-unikernel -- nvme::tests::parse_identify_namespace`
Expected: 3 tests pass.

- [ ] **Step 5: Run all NVMe tests + CI parity**

Run: `cargo test -p harmony-unikernel -- nvme && cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`
Expected: 38 tests pass, clean.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add Identify Namespace response parser

IdentifyNamespace struct with NSZE, NCAP, NUSE, FLBAS, and derived
lba_size_bytes from the LBA Format table. Supports 512-byte and
4K sector sizes."
```

---

### Task 8: Final integration — verify identify_controller works in Ready state

Verify the full Phase 2 lifecycle works end-to-end: init → admin queue → identify controller → create I/O queues → activate → identify namespace (in Ready state). This is the integration test proving all pieces work together.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

- [ ] **Step 1: Write integration test**

```rust
// ── Phase 2 integration tests ─────────────────────────────────────────

#[test]
fn identify_controller_works_in_ready_state() {
    let mut driver = enabled_driver();
    driver.activate_io_queues(0xBBBB_0000, 0xAAAA_0000, 32).unwrap();
    assert_eq!(driver.state(), NvmeState::Ready);

    // identify_controller should still work in Ready state
    let cmd = driver.identify_controller(0xDEAD_0000).unwrap();
    let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
    assert_eq!(cdw0 & 0xFF, 0x06);
}

#[test]
fn full_phase2_lifecycle() {
    // init → admin queue → create I/O queues → activate → identify namespace
    let bank = mock_nvme_bank();
    let mut driver = NvmeDriver::init(bank).unwrap();
    assert_eq!(driver.state(), NvmeState::Disabled);

    driver.bank.on_read(REG_CSTS, vec![CSTS_RDY]);
    driver.setup_admin_queue(0x1_0000, 0x2_0000, 32).unwrap();
    assert_eq!(driver.state(), NvmeState::Enabled);

    let cmds = driver.create_io_queues(0xBBBB_0000, 0xAAAA_0000, 32).unwrap();
    // Verify we got CQ and SQ commands
    let op0 = u32::from_le_bytes(cmds[0].sqe[0..4].try_into().unwrap()) & 0xFF;
    let op1 = u32::from_le_bytes(cmds[1].sqe[0..4].try_into().unwrap()) & 0xFF;
    assert_eq!(op0, 0x05); // Create I/O CQ
    assert_eq!(op1, 0x01); // Create I/O SQ

    driver.activate_io_queues(0xBBBB_0000, 0xAAAA_0000, 32).unwrap();
    assert_eq!(driver.state(), NvmeState::Ready);

    // Identify namespace should work in Ready state
    let ns_cmd = driver.identify_namespace(1, 0xFEED_0000).unwrap();
    let ns_cdw0 = u32::from_le_bytes(ns_cmd.sqe[0..4].try_into().unwrap());
    assert_eq!(ns_cdw0 & 0xFF, 0x06);
    let ns_nsid = u32::from_le_bytes(ns_cmd.sqe[4..8].try_into().unwrap());
    assert_eq!(ns_nsid, 1);
}
```

- [ ] **Step 2: Run integration tests**

Run: `cargo test -p harmony-unikernel -- nvme::tests::full_phase2 nvme::tests::identify_controller_works`
Expected: 2 tests pass.

- [ ] **Step 3: Run full test suite + CI parity**

Run: `cargo test -p harmony-unikernel -- nvme && cargo clippy --workspace --all-targets -- -D warnings && rustup run nightly cargo fmt --all -- --check`
Expected: 40 tests pass, clean.

- [ ] **Step 4: Run full workspace tests**

Run: `cargo test --workspace`
Expected: all tests pass across all crates.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "test(nvme): add Phase 2 integration tests

Full lifecycle test: init → admin queue → create I/O queues →
activate → identify namespace. Verifies admin commands work in
both Enabled and Ready states."
```
