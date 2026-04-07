# NVMe Get/Set Features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Get Features (opcode 0x0A) and Set Features (opcode 0x09) admin commands to the NVMe driver, with a typed Number of Queues (FID 0x07) helper and parser.

**Architecture:** Two generic admin command builders (`get_features`, `set_features`) that accept an arbitrary FID + CDW11, plus a typed `set_num_queues` helper that converts 1-based counts to 0-based CDW11 encoding. A standalone `parse_num_queues` function extracts allocated queue counts from the completion DW0. All changes in one file.

**Tech Stack:** Rust (`no_std` + `alloc`), `MockRegisterBank` for testing.

**Spec:** `docs/superpowers/specs/2026-04-06-nvme-get-set-features-design.md`

---

## File Structure

All changes in a single file:

- **Modify:** `crates/harmony-unikernel/src/drivers/nvme.rs`
  - New `NumberOfQueues` struct (near other response structs, after line ~191)
  - New `get_features` and `set_features` methods on `NvmeDriver` (new impl block after Identify commands, around line ~609)
  - New `set_num_queues` method in the same impl block
  - New `parse_num_queues` standalone function (after `parse_identify_namespace`, around line ~1176)
  - 15 new tests (at end of `mod tests`)

---

### Task 1: Generic Get Features and Set Features

Add the two generic admin command builders and their tests. This is the foundation — the typed Number of Queues helper in Task 2 delegates to `set_features`.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

**Context for the implementer:** The file is a sans-I/O NVMe driver at `crates/harmony-unikernel/src/drivers/nvme.rs` (~3124 lines). Admin commands follow this pattern: check state is `Enabled` or `Ready`, allocate a CID, build a 64-byte SQE, and call `self.admin.submit(sqe, self.doorbell_stride)` which returns an `AdminCommand`. See `identify_controller` at line ~556 for the canonical example. Tests use `enabled_driver()` (line ~1325) which returns a driver in `Enabled` state with admin queue configured. The `MockRegisterBank` is at `crate::drivers::register_bank::mock::MockRegisterBank`.

- [ ] **Step 1: Write the failing tests for `get_features`**

Add these 4 tests at the end of `mod tests` (before the final closing `}`), under a new section comment:

```rust
    // ── Get/Set Features tests ──────────────────────────────────────────────

    #[test]
    fn get_features_builds_correct_sqe() {
        let mut driver = enabled_driver();
        let cmd = driver.get_features(0x07, 0x0003_0003).unwrap();

        // CDW0: opcode=0x0A, CID=0
        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x0A, "opcode must be 0x0A (Get Features)");
        assert_eq!((cdw0 >> 16) as u16, 0, "CID must be 0 for first command");

        // CDW10: FID=0x07 in bits 7:0, SEL=0 in bits 10:8
        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10 & 0xFF, 0x07, "FID must be 0x07");
        assert_eq!((cdw10 >> 8) & 0x07, 0, "SEL must be 0 (current value)");

        // CDW11: passthrough
        let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
        assert_eq!(cdw11, 0x0003_0003, "CDW11 must be passed through");

        // PRP1 and PRP2 must be zero (no data transfer)
        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        let prp2 = u64::from_le_bytes(cmd.sqe[32..40].try_into().unwrap());
        assert_eq!(prp1, 0, "PRP1 must be 0");
        assert_eq!(prp2, 0, "PRP2 must be 0");

        assert!(cmd.prp_list.is_none(), "no PRP list");
        assert!(cmd.data_buffer.is_none(), "no data buffer");
    }

    #[test]
    fn get_features_cdw11_passthrough() {
        let mut driver = enabled_driver();
        let cmd = driver.get_features(0x04, 0xCAFE_BABE).unwrap();

        let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
        assert_eq!(cdw11, 0xCAFE_BABE, "CDW11 must be passed through exactly");

        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10 & 0xFF, 0x04, "FID must be 0x04");
    }

    #[test]
    fn get_features_rejects_wrong_state() {
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();
        // Driver is in Disabled state — should reject.
        match driver.get_features(0x07, 0) {
            Err(NvmeError::InvalidState) => {}
            other => panic!("expected InvalidState, got {:?}", other),
        }
    }

    #[test]
    fn get_features_increments_cid() {
        let mut driver = enabled_driver();
        let cmd0 = driver.get_features(0x07, 0).unwrap();
        let cid0 = (u32::from_le_bytes(cmd0.sqe[0..4].try_into().unwrap()) >> 16) as u16;

        let cmd1 = driver.get_features(0x07, 0).unwrap();
        let cid1 = (u32::from_le_bytes(cmd1.sqe[0..4].try_into().unwrap()) >> 16) as u16;

        assert_eq!(cid1, cid0 + 1, "CID must increment");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel get_features 2>&1 | tail -5`
Expected: compilation error — `get_features` method does not exist.

- [ ] **Step 3: Implement `get_features`**

Add a new impl block after the Identify commands section (after line ~609, before the `// ── I/O queue creation` section at line ~611). Insert this section:

```rust
// ── Get/Set Features commands ────────────────────────────────────────────────

impl<R: RegisterBank> NvmeDriver<R> {
    /// Build a Get Features admin command (opcode 0x0A).
    ///
    /// `fid` is the Feature Identifier (byte, bits 7:0 of CDW10).
    /// `cdw11` is the feature-specific dword passed through to CDW11.
    /// SEL is always 0 (current value).
    ///
    /// The controller's response is returned in `Completion.result` (DW0).
    /// No data transfer — PRP1 and PRP2 are zero.
    pub fn get_features(&mut self, fid: u8, cdw11: u32) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Enabled && self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let mut sqe = [0u8; 64];

        // CDW0: opcode=0x0A | (CID << 16)
        let cdw0: u32 = 0x0A | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());

        // CDW10: FID in bits 7:0, SEL=0 in bits 10:8
        let cdw10: u32 = fid as u32;
        sqe[40..44].copy_from_slice(&cdw10.to_le_bytes());

        // CDW11: feature-specific
        sqe[44..48].copy_from_slice(&cdw11.to_le_bytes());

        Ok(self.admin.submit(sqe, self.doorbell_stride))
    }
}
```

- [ ] **Step 4: Run get_features tests to verify they pass**

Run: `cargo test -p harmony-unikernel get_features -- --nocapture 2>&1 | tail -10`
Expected: all 4 tests pass.

- [ ] **Step 5: Write the failing tests for `set_features`**

Add these 3 tests immediately after the `get_features` tests:

```rust
    #[test]
    fn set_features_builds_correct_sqe() {
        let mut driver = enabled_driver();
        let cmd = driver.set_features(0x07, 0x0003_0003).unwrap();

        // CDW0: opcode=0x09, CID=0
        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x09, "opcode must be 0x09 (Set Features)");
        assert_eq!((cdw0 >> 16) as u16, 0, "CID must be 0 for first command");

        // CDW10: FID=0x07 in bits 7:0
        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10 & 0xFF, 0x07, "FID must be 0x07");

        // CDW11: passthrough
        let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
        assert_eq!(cdw11, 0x0003_0003, "CDW11 must be passed through");

        // PRP1 and PRP2 must be zero
        let prp1 = u64::from_le_bytes(cmd.sqe[24..32].try_into().unwrap());
        let prp2 = u64::from_le_bytes(cmd.sqe[32..40].try_into().unwrap());
        assert_eq!(prp1, 0, "PRP1 must be 0");
        assert_eq!(prp2, 0, "PRP2 must be 0");

        assert!(cmd.prp_list.is_none(), "no PRP list");
        assert!(cmd.data_buffer.is_none(), "no data buffer");
    }

    #[test]
    fn set_features_rejects_wrong_state() {
        let bank = mock_nvme_bank();
        let mut driver = NvmeDriver::init(bank).unwrap();
        match driver.set_features(0x07, 0) {
            Err(NvmeError::InvalidState) => {}
            other => panic!("expected InvalidState, got {:?}", other),
        }
    }

    #[test]
    fn set_features_increments_cid() {
        let mut driver = enabled_driver();
        let cmd0 = driver.set_features(0x07, 0).unwrap();
        let cid0 = (u32::from_le_bytes(cmd0.sqe[0..4].try_into().unwrap()) >> 16) as u16;

        let cmd1 = driver.set_features(0x07, 0).unwrap();
        let cid1 = (u32::from_le_bytes(cmd1.sqe[0..4].try_into().unwrap()) >> 16) as u16;

        assert_eq!(cid1, cid0 + 1, "CID must increment");
    }
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel set_features 2>&1 | tail -5`
Expected: compilation error — `set_features` method does not exist.

- [ ] **Step 7: Implement `set_features`**

Add the `set_features` method inside the same impl block that contains `get_features` (the `// ── Get/Set Features commands` block):

```rust
    /// Build a Set Features admin command (opcode 0x09).
    ///
    /// `fid` is the Feature Identifier (byte, bits 7:0 of CDW10).
    /// `cdw11` is the feature-specific dword passed through to CDW11.
    ///
    /// The controller's response is returned in `Completion.result` (DW0).
    /// No data transfer — PRP1 and PRP2 are zero.
    pub fn set_features(&mut self, fid: u8, cdw11: u32) -> Result<AdminCommand, NvmeError> {
        if self.state != NvmeState::Enabled && self.state != NvmeState::Ready {
            return Err(NvmeError::InvalidState);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        let mut sqe = [0u8; 64];

        // CDW0: opcode=0x09 | (CID << 16)
        let cdw0: u32 = 0x09 | ((cid as u32) << 16);
        sqe[0..4].copy_from_slice(&cdw0.to_le_bytes());

        // CDW10: FID in bits 7:0
        let cdw10: u32 = fid as u32;
        sqe[40..44].copy_from_slice(&cdw10.to_le_bytes());

        // CDW11: feature-specific
        sqe[44..48].copy_from_slice(&cdw11.to_le_bytes());

        Ok(self.admin.submit(sqe, self.doorbell_stride))
    }
```

- [ ] **Step 8: Run all set_features and get_features tests**

Run: `cargo test -p harmony-unikernel features -- --nocapture 2>&1 | tail -15`
Expected: all 7 tests pass.

- [ ] **Step 9: Run full test suite**

Run: `cargo test -p harmony-unikernel 2>&1 | tail -5`
Expected: all tests pass (existing + 7 new).

- [ ] **Step 10: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add generic Get Features and Set Features admin commands"
```

---

### Task 2: Number of Queues typed helper and parser

Add `NumberOfQueues` struct, `set_num_queues` method, `parse_num_queues` function, and their tests.

**Files:**
- Modify: `crates/harmony-unikernel/src/drivers/nvme.rs`

**Context for the implementer:** This builds on Task 1's `set_features` method. The driver file is `crates/harmony-unikernel/src/drivers/nvme.rs`. After Task 1, there is a `// ── Get/Set Features commands` impl block containing `get_features` and `set_features`. The `set_num_queues` method goes in this same impl block — it delegates to `self.set_features(0x07, cdw11)`.

The `NumberOfQueues` struct goes near the other response types — after `IdentifyNamespace` (around line ~215, before `NvmeError`). The `parse_num_queues` standalone function goes after `parse_identify_namespace` (around line ~1176, before `// ── Tests`). This follows the existing pattern: `IdentifyController` struct is defined near the top, `parse_identify_controller` is defined near the bottom.

The `Completion` struct (line ~70) has a `result: u32` field — this is DW0 from the CQE and is where the controller puts the allocated queue counts.

The `enabled_driver()` test helper (line ~1325) returns a driver in `Enabled` state.

- [ ] **Step 1: Write the `NumberOfQueues` struct**

Add this struct after `IdentifyNamespace` (around line ~215), before the `// ── Error type` section:

```rust
/// Parsed result from Set Features — Number of Queues (FID 0x07).
///
/// Both fields are 1-based: a value of 1 means one queue.
/// The controller may allocate fewer queues than requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumberOfQueues {
    /// Number of I/O submission queues allocated (1-based).
    pub nsqr: u16,
    /// Number of I/O completion queues allocated (1-based).
    pub ncqr: u16,
}
```

- [ ] **Step 2: Write the `parse_num_queues` function**

Add this standalone function after `parse_identify_namespace` (around line ~1176), before `// ── Tests`:

```rust
/// Parse the Number of Queues result from a Set Features or Get Features
/// completion (FID 0x07).
///
/// The completion's DW0 (`completion.result`) encodes:
/// - Bits 15:0 — NSQR: allocated I/O submission queues (0-based)
/// - Bits 31:16 — NCQR: allocated I/O completion queues (0-based)
///
/// This function converts both to 1-based values.
pub fn parse_num_queues(completion: &Completion) -> NumberOfQueues {
    let nsqr = (completion.result & 0xFFFF) as u16 + 1;
    let ncqr = (completion.result >> 16) as u16 + 1;
    NumberOfQueues { nsqr, ncqr }
}
```

- [ ] **Step 3: Write the failing tests for `set_num_queues` and `parse_num_queues`**

Add these 8 tests after the Task 1 tests, in the same `// ── Get/Set Features tests` section:

```rust
    // ── Number of Queues (FID 0x07) tests ───────────────────────────────────

    #[test]
    fn set_num_queues_basic() {
        let mut driver = enabled_driver();
        let cmd = driver.set_num_queues(4, 4).unwrap();

        // Must be a Set Features command
        let cdw0 = u32::from_le_bytes(cmd.sqe[0..4].try_into().unwrap());
        assert_eq!(cdw0 & 0xFF, 0x09, "opcode must be 0x09 (Set Features)");

        // CDW10: FID=0x07
        let cdw10 = u32::from_le_bytes(cmd.sqe[40..44].try_into().unwrap());
        assert_eq!(cdw10 & 0xFF, 0x07, "FID must be 0x07 (Number of Queues)");

        // CDW11: NSQR=3 (4-1) in bits 15:0, NCQR=3 (4-1) in bits 31:16
        let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
        assert_eq!(cdw11, 0x0003_0003, "CDW11 = (ncqr-1)<<16 | (nsqr-1)");
    }

    #[test]
    fn set_num_queues_asymmetric() {
        let mut driver = enabled_driver();
        let cmd = driver.set_num_queues(2, 8).unwrap();

        let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
        // NSQR=1 (2-1), NCQR=7 (8-1) → 0x0007_0001
        assert_eq!(cdw11, 0x0007_0001, "CDW11 for nsqr=2, ncqr=8");
    }

    #[test]
    fn set_num_queues_minimum() {
        let mut driver = enabled_driver();
        let cmd = driver.set_num_queues(1, 1).unwrap();

        let cdw11 = u32::from_le_bytes(cmd.sqe[44..48].try_into().unwrap());
        assert_eq!(cdw11, 0x0000_0000, "CDW11 for nsqr=1, ncqr=1");
    }

    #[test]
    fn set_num_queues_zero_nsqr_rejected() {
        let mut driver = enabled_driver();
        match driver.set_num_queues(0, 4) {
            Err(NvmeError::InvalidState) => {}
            other => panic!("expected InvalidState for nsqr=0, got {:?}", other),
        }
    }

    #[test]
    fn set_num_queues_zero_ncqr_rejected() {
        let mut driver = enabled_driver();
        match driver.set_num_queues(4, 0) {
            Err(NvmeError::InvalidState) => {}
            other => panic!("expected InvalidState for ncqr=0, got {:?}", other),
        }
    }

    #[test]
    fn parse_num_queues_basic() {
        let completion = Completion {
            cid: 0,
            status: 0,
            result: 0x0003_0007, // NCQR=3 (0-based), NSQR=7 (0-based)
        };
        let nq = parse_num_queues(&completion);
        assert_eq!(nq.nsqr, 8, "NSQR 0-based 7 → 1-based 8");
        assert_eq!(nq.ncqr, 4, "NCQR 0-based 3 → 1-based 4");
    }

    #[test]
    fn parse_num_queues_minimum() {
        let completion = Completion {
            cid: 0,
            status: 0,
            result: 0x0000_0000, // Both 0-based 0 → 1-based 1
        };
        let nq = parse_num_queues(&completion);
        assert_eq!(nq.nsqr, 1);
        assert_eq!(nq.ncqr, 1);
    }

    #[test]
    fn get_set_features_use_admin_queue_doorbell() {
        let mut driver = enabled_driver();
        let get_cmd = driver.get_features(0x07, 0).unwrap();
        let set_cmd = driver.set_features(0x07, 0).unwrap();

        // Admin SQ doorbell offset: 0x1000 + (2*0) * 4 = 0x1000
        assert_eq!(
            get_cmd.doorbell_offset, 0x1000,
            "Get Features must use admin SQ doorbell"
        );
        assert_eq!(
            set_cmd.doorbell_offset, 0x1000,
            "Set Features must use admin SQ doorbell"
        );
    }
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `cargo test -p harmony-unikernel num_queues 2>&1 | tail -5`
Expected: compilation error — `set_num_queues` does not exist.

- [ ] **Step 5: Implement `set_num_queues`**

Add the `set_num_queues` method inside the `// ── Get/Set Features commands` impl block, after `set_features`:

```rust
    /// Build a Set Features — Number of Queues command (FID 0x07).
    ///
    /// `nsqr` is the number of I/O submission queues requested (1-based, min 1).
    /// `ncqr` is the number of I/O completion queues requested (1-based, min 1).
    ///
    /// The controller may allocate fewer than requested. Parse the completion
    /// with [`parse_num_queues`] to get the actual allocation.
    pub fn set_num_queues(&mut self, nsqr: u16, ncqr: u16) -> Result<AdminCommand, NvmeError> {
        if nsqr == 0 || ncqr == 0 {
            return Err(NvmeError::InvalidState);
        }
        let cdw11 = ((ncqr - 1) as u32) << 16 | (nsqr - 1) as u32;
        self.set_features(0x07, cdw11)
    }
```

- [ ] **Step 6: Run all new tests**

Run: `cargo test -p harmony-unikernel features num_queues admin_queue_doorbell -- --nocapture 2>&1 | tail -20`

This won't work as a combined filter. Instead run:

Run: `cargo test -p harmony-unikernel 2>&1 | tail -5`
Expected: all tests pass (existing + 15 new).

- [ ] **Step 7: Run clippy**

Run: `cargo clippy -p harmony-unikernel 2>&1 | tail -10`
Expected: no warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-unikernel/src/drivers/nvme.rs
git commit -m "feat(nvme): add Number of Queues helper and parser (FID 0x07)"
```

---

## Self-Review

**1. Spec coverage:**
- `get_features(fid, cdw11)` → Task 1, Step 3
- `set_features(fid, cdw11)` → Task 1, Step 7
- `set_num_queues(nsqr, ncqr)` → Task 2, Step 5
- `NumberOfQueues` struct → Task 2, Step 1
- `parse_num_queues(&Completion)` → Task 2, Step 2
- All 15 tests → Task 1 Steps 1/5 (7 tests) + Task 2 Step 3 (8 tests)
- No gaps.

**2. Placeholder scan:** No TBDs, TODOs, or "similar to Task N" references. Every step has complete code.

**3. Type consistency:**
- `get_features(fid: u8, cdw11: u32)` — consistent across definition (Step 3) and tests (Step 1)
- `set_features(fid: u8, cdw11: u32)` — consistent across definition (Step 7) and tests (Step 5)
- `set_num_queues(nsqr: u16, ncqr: u16)` — consistent across definition (Task 2, Step 5) and tests (Task 2, Step 3)
- `parse_num_queues(completion: &Completion) -> NumberOfQueues` — consistent across definition (Task 2, Step 2) and tests (Task 2, Step 3)
- `NumberOfQueues { nsqr: u16, ncqr: u16 }` — consistent across struct (Task 2, Step 1), parser (Task 2, Step 2), and tests
