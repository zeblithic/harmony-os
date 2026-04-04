# Phase 4: Blocking Syscall Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Linuxulator spin-wait blocking with scheduler-integrated blocking via Self-SGI yield, enabling multi-task I/O without CPU burn.

**Architecture:** When a syscall would block, the Linuxulator calls a `block_fn` callback that marks the task Blocked, triggers a GICv3 Self-SGI, and the existing IRQ handler context-switches to the next Ready task. The system task polls smoltcp and wakes blocked tasks. A separate ELF task (PID 2) runs the test binary.

**Tech Stack:** Rust (no_std), AArch64 assembly (GICv3 SGI), smoltcp networking, harmony-os Linuxulator

**Design spec:** `docs/superpowers/specs/2026-04-03-phase4-blocking-syscall-design.md`

---

## File Structure

| File | Responsibility | Changes |
|------|---------------|---------|
| `crates/harmony-boot-aarch64/src/sched.rs` | Scheduler primitives | Add WaitReason, TCB field, block_current, wake, wake_by_fd, for_each_blocked |
| `crates/harmony-boot-aarch64/src/gic.rs` | GIC driver | Add YIELD_SGI constant, send_sgi_self function |
| `crates/harmony-boot-aarch64/src/vectors.rs` | Exception vectors | Add YIELD_SGI arm in irq_dispatch |
| `crates/harmony-os/src/linuxulator.rs` | Linuxulator blocking | Add block_fn/wake_fn, rewrite block_until, update callers, add pipe wakes, add is_wait_ready |
| `crates/harmony-boot-aarch64/src/main.rs` | Boot integration | Add elf_task, refactor system_task, LINUXULATOR static, callback setup |
| `xtask/src/qemu_test.rs` | QEMU test | Update aarch64 milestones |

---

### Task 1: Scheduler Primitives

**Context:** The scheduler in `sched.rs` already has `TaskState::Blocked` (line 49) but nothing sets it. This task adds the mechanism: `WaitReason` enum, TCB field, `block_current()`, `wake()`, `wake_by_fd()`, and `for_each_blocked()`.

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/sched.rs`

**Reference:** Read `crates/harmony-boot-aarch64/src/sched.rs` fully before starting. Key locations:
- TaskState enum: lines 45-53
- TaskControlBlock struct: lines 56-79
- Static muts (TASKS, CURRENT, NUM_TASKS): lines 82-89
- schedule(): lines 210-248
- Test module with TEST_LOCK: lines 316-378

- [ ] **Step 1: Write failing tests for WaitReason and TCB wait_reason field**

Add these tests inside the existing `mod tests` block (after line 377, before the closing `}`):

```rust
#[test]
fn wait_reason_variants_distinct() {
    let reasons = [
        WaitReason::FdReadable(1),
        WaitReason::FdWritable(1),
        WaitReason::FdConnectDone(1),
        WaitReason::PollWait,
    ];
    for i in 0..reasons.len() {
        for j in (i + 1)..reasons.len() {
            assert_ne!(reasons[i], reasons[j]);
        }
    }
}

#[test]
fn tcb_wait_reason_default_none() {
    let _lock = TEST_LOCK.lock().unwrap();
    unsafe {
        NUM_TASKS = 1;
        TASKS[0] = MaybeUninit::new(TaskControlBlock {
            kernel_sp: 0,
            kernel_stack_base: 0x2_0000,
            kernel_stack_size: 8192,
            state: TaskState::Ready,
            preempt_count: 0,
            pid: 1,
            name: "test",
            entry: None,
            wait_reason: None,
        });
        assert!(TASKS[0].assume_init_ref().wait_reason.is_none());
        NUM_TASKS = 0;
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin 2>&1`
Expected: FAIL — `WaitReason` not found, `wait_reason` field not found on `TaskControlBlock`

- [ ] **Step 3: Add WaitReason enum and TCB field**

Add the `WaitReason` enum after the `TaskState` enum (after line 53):

```rust
/// What a Blocked task is waiting for. Stored in the TCB so the
/// system task's wake-check loop can evaluate readiness.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum WaitReason {
    /// Waiting for fd to become readable.
    FdReadable(i32),
    /// Waiting for fd to become writable.
    FdWritable(i32),
    /// Waiting for TCP connect to complete.
    FdConnectDone(i32),
    /// Waiting for any network activity (poll/select/epoll).
    /// Woken on any smoltcp state change; handler rechecks specific fds.
    PollWait,
}
```

Add `wait_reason` field to `TaskControlBlock` (after the `entry` field, before the closing `}`):

```rust
    /// What this task is waiting for when Blocked. None when Ready/Running/Dead.
    pub wait_reason: Option<WaitReason>,
```

Update `spawn_task` to initialize `wait_reason: None` in the `TaskControlBlock` constructor (in the `MaybeUninit::new(TaskControlBlock { ... })` block).

Update existing tests (`check_guard_page_detects_hit`) to include `wait_reason: None` in their TCB construction.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin 2>&1`
Expected: PASS (all tests including new ones)

- [ ] **Step 5: Write failing tests for block_current, wake, and wake_by_fd**

Add inside `mod tests`:

```rust
#[test]
fn block_current_sets_blocked_and_wait_reason() {
    let _lock = TEST_LOCK.lock().unwrap();
    unsafe {
        NUM_TASKS = 1;
        CURRENT = 0;
        TASKS[0] = MaybeUninit::new(TaskControlBlock {
            kernel_sp: 0x1000,
            kernel_stack_base: 0x2_0000,
            kernel_stack_size: 8192,
            state: TaskState::Running,
            preempt_count: 0,
            pid: 1,
            name: "test",
            entry: None,
            wait_reason: None,
        });

        block_current(WaitReason::FdReadable(5));

        let tcb = TASKS[0].assume_init_ref();
        assert_eq!(tcb.state, TaskState::Blocked);
        assert_eq!(tcb.wait_reason, Some(WaitReason::FdReadable(5)));

        NUM_TASKS = 0;
    }
}

#[test]
fn wake_transitions_blocked_to_ready() {
    let _lock = TEST_LOCK.lock().unwrap();
    unsafe {
        NUM_TASKS = 2;
        CURRENT = 0;
        TASKS[0] = MaybeUninit::new(TaskControlBlock {
            kernel_sp: 0x1000,
            kernel_stack_base: 0x2_0000,
            kernel_stack_size: 8192,
            state: TaskState::Running,
            preempt_count: 0,
            pid: 0,
            name: "running",
            entry: None,
            wait_reason: None,
        });
        TASKS[1] = MaybeUninit::new(TaskControlBlock {
            kernel_sp: 0x3000,
            kernel_stack_base: 0x4_0000,
            kernel_stack_size: 8192,
            state: TaskState::Blocked,
            preempt_count: 0,
            pid: 1,
            name: "blocked",
            entry: None,
            wait_reason: Some(WaitReason::FdReadable(3)),
        });

        wake(1);

        let tcb = TASKS[1].assume_init_ref();
        assert_eq!(tcb.state, TaskState::Ready);
        assert_eq!(tcb.wait_reason, None);

        NUM_TASKS = 0;
    }
}

#[test]
fn wake_ignores_non_blocked_task() {
    let _lock = TEST_LOCK.lock().unwrap();
    unsafe {
        NUM_TASKS = 1;
        TASKS[0] = MaybeUninit::new(TaskControlBlock {
            kernel_sp: 0x1000,
            kernel_stack_base: 0x2_0000,
            kernel_stack_size: 8192,
            state: TaskState::Ready,
            preempt_count: 0,
            pid: 0,
            name: "ready",
            entry: None,
            wait_reason: None,
        });

        wake(0);

        assert_eq!(TASKS[0].assume_init_ref().state, TaskState::Ready);

        NUM_TASKS = 0;
    }
}

#[test]
fn wake_by_fd_finds_matching_blocked_task() {
    let _lock = TEST_LOCK.lock().unwrap();
    unsafe {
        NUM_TASKS = 3;
        CURRENT = 0;
        TASKS[0] = MaybeUninit::new(TaskControlBlock {
            kernel_sp: 0,
            kernel_stack_base: 0x1_0000,
            kernel_stack_size: 8192,
            state: TaskState::Running,
            preempt_count: 0,
            pid: 0,
            name: "running",
            entry: None,
            wait_reason: None,
        });
        TASKS[1] = MaybeUninit::new(TaskControlBlock {
            kernel_sp: 0,
            kernel_stack_base: 0x2_0000,
            kernel_stack_size: 8192,
            state: TaskState::Blocked,
            preempt_count: 0,
            pid: 1,
            name: "blocked-r5",
            entry: None,
            wait_reason: Some(WaitReason::FdReadable(5)),
        });
        TASKS[2] = MaybeUninit::new(TaskControlBlock {
            kernel_sp: 0,
            kernel_stack_base: 0x3_0000,
            kernel_stack_size: 8192,
            state: TaskState::Blocked,
            preempt_count: 0,
            pid: 2,
            name: "blocked-w5",
            entry: None,
            wait_reason: Some(WaitReason::FdWritable(5)),
        });

        // Wake readable waiters on fd 5.
        wake_by_fd(5, 0);

        // Task 1 (FdReadable(5)) should be woken.
        assert_eq!(TASKS[1].assume_init_ref().state, TaskState::Ready);
        assert_eq!(TASKS[1].assume_init_ref().wait_reason, None);

        // Task 2 (FdWritable(5)) should still be blocked.
        assert_eq!(TASKS[2].assume_init_ref().state, TaskState::Blocked);
        assert_eq!(
            TASKS[2].assume_init_ref().wait_reason,
            Some(WaitReason::FdWritable(5))
        );

        NUM_TASKS = 0;
    }
}

#[test]
fn for_each_blocked_iterates_blocked_tasks() {
    let _lock = TEST_LOCK.lock().unwrap();
    unsafe {
        NUM_TASKS = 3;
        TASKS[0] = MaybeUninit::new(TaskControlBlock {
            kernel_sp: 0,
            kernel_stack_base: 0x1_0000,
            kernel_stack_size: 8192,
            state: TaskState::Running,
            preempt_count: 0,
            pid: 0,
            name: "running",
            entry: None,
            wait_reason: None,
        });
        TASKS[1] = MaybeUninit::new(TaskControlBlock {
            kernel_sp: 0,
            kernel_stack_base: 0x2_0000,
            kernel_stack_size: 8192,
            state: TaskState::Blocked,
            preempt_count: 0,
            pid: 1,
            name: "blocked",
            entry: None,
            wait_reason: Some(WaitReason::FdReadable(7)),
        });
        TASKS[2] = MaybeUninit::new(TaskControlBlock {
            kernel_sp: 0,
            kernel_stack_base: 0x3_0000,
            kernel_stack_size: 8192,
            state: TaskState::Ready,
            preempt_count: 0,
            pid: 2,
            name: "ready",
            entry: None,
            wait_reason: None,
        });

        let mut found = Vec::new();
        for_each_blocked(|idx, reason| {
            found.push((idx, reason));
        });

        assert_eq!(found.len(), 1);
        assert_eq!(found[0], (1, WaitReason::FdReadable(7)));

        NUM_TASKS = 0;
    }
}
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin 2>&1`
Expected: FAIL — `block_current`, `wake`, `wake_by_fd`, `for_each_blocked` not found

- [ ] **Step 7: Implement block_current, wake, wake_by_fd, for_each_blocked**

Add after `enter_scheduler` (after line 314, before the `#[cfg(test)]` module):

```rust
/// Block the current task with the given reason and yield the CPU.
///
/// On aarch64, triggers a Self-SGI which enters the IRQ handler,
/// saves the TrapFrame, calls `schedule()` (which skips Blocked tasks),
/// and context-switches to the next Ready task. When eventually woken
/// and rescheduled, execution resumes here — the caller continues
/// from where it left off (mid-syscall).
///
/// On non-aarch64 (host tests), just sets the state. No context switch.
///
/// # Safety
///
/// Must be called from a task context (not IRQ). The task must be Running.
pub unsafe fn block_current(reason: WaitReason) {
    let cur = CURRENT;
    let tcb = TASKS[cur].assume_init_mut();
    tcb.state = TaskState::Blocked;
    tcb.wait_reason = Some(reason);

    #[cfg(target_arch = "aarch64")]
    crate::gic::send_sgi_self(crate::gic::YIELD_SGI);

    // On aarch64: execution resumes here after wake + reschedule.
    // wake() already cleared wait_reason and set state = Ready,
    // then schedule() set state = Running.
}

/// Wake a blocked task, moving it from Blocked to Ready.
///
/// If the task is not Blocked, this is a no-op.
///
/// # Safety
///
/// Must only be called when task_idx < NUM_TASKS and the slot is initialized.
pub unsafe fn wake(task_idx: usize) {
    let tcb = TASKS[task_idx].assume_init_mut();
    if tcb.state == TaskState::Blocked {
        tcb.state = TaskState::Ready;
        tcb.wait_reason = None;
    }
}

/// Wake any blocked task waiting on the given fd and operation.
///
/// `op`: 0 = FdReadable, 1 = FdWritable.
///
/// # Safety
///
/// Must only be called when TASKS[0..NUM_TASKS] are initialized.
pub unsafe fn wake_by_fd(fd: i32, op: u8) {
    let n = NUM_TASKS;
    for i in 0..n {
        let tcb = TASKS[i].assume_init_mut();
        if tcb.state != TaskState::Blocked {
            continue;
        }
        let matches = match (tcb.wait_reason, op) {
            (Some(WaitReason::FdReadable(f)), 0) if f == fd => true,
            (Some(WaitReason::FdWritable(f)), 1) if f == fd => true,
            _ => false,
        };
        if matches {
            tcb.state = TaskState::Ready;
            tcb.wait_reason = None;
        }
    }
}

/// Iterate all blocked tasks, calling `f(task_index, wait_reason)` for each.
///
/// Used by the system task to check readiness and wake blocked tasks.
///
/// # Safety
///
/// Must only be called when TASKS[0..NUM_TASKS] are initialized.
pub unsafe fn for_each_blocked(mut f: impl FnMut(usize, WaitReason)) {
    let n = NUM_TASKS;
    for i in 0..n {
        let tcb = TASKS[i].assume_init_ref();
        if tcb.state == TaskState::Blocked {
            if let Some(reason) = tcb.wait_reason {
                f(i, reason);
            }
        }
    }
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin 2>&1`
Expected: PASS (all tests)

- [ ] **Step 9: Run clippy**

Run: `cd crates/harmony-boot-aarch64 && cargo clippy --target x86_64-apple-darwin 2>&1`
Expected: No warnings on new code

- [ ] **Step 10: Commit**

```bash
git add crates/harmony-boot-aarch64/src/sched.rs
git commit -m "feat(sched): add WaitReason, block_current, wake, wake_by_fd, for_each_blocked

Phase 4 scheduler primitives. block_current marks task Blocked with a
WaitReason and triggers Self-SGI on aarch64. wake/wake_by_fd move
Blocked→Ready. for_each_blocked iterates blocked tasks for the system
task's wake-check loop."
```

---

### Task 2: GIC Self-SGI Support

**Context:** The GIC driver in `gic.rs` handles interrupt acknowledgment and EOI. The IRQ dispatch in `vectors.rs` routes timer interrupts to `schedule()`. This task adds a Self-SGI mechanism so `block_current()` can trigger a reschedule through the existing IRQ path.

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/gic.rs`
- Modify: `crates/harmony-boot-aarch64/src/vectors.rs`

**Reference:** Read both files fully before starting.
- `gic.rs`: TIMER_INTID (line 34), SPURIOUS (line 37), ack() (lines 116-120), eoi() (lines 129-131)
- `vectors.rs`: irq_dispatch (lines 260-274)

- [ ] **Step 1: Add YIELD_SGI constant and send_sgi_self function to gic.rs**

Add after the `SPURIOUS` constant (after line 37):

```rust
/// SGI used for voluntary yield from block_current().
/// SGI 0 is reserved by convention; we use SGI 1.
pub const YIELD_SGI: u32 = 1;
```

Add after the `eoi` function (after line 131):

```rust
/// Send a Software Generated Interrupt to the current PE (self).
///
/// Used by `block_current()` to trigger a reschedule through the normal
/// IRQ handler path. The SGI fires immediately (tasks run with IRQs
/// unmasked), enters the IRQ handler, saves the TrapFrame, and calls
/// `schedule()`.
///
/// # Safety
///
/// Must be called with IRQs unmasked (PSTATE.I = 0).
#[cfg(target_arch = "aarch64")]
pub unsafe fn send_sgi_self(intid: u32) {
    // ICC_SGI1_EL1 format:
    //   [27:24] = INTID (SGI number, 0-15)
    //   [23:16] = Aff3 = 0
    //   [15:0]  = TargetList = 1 (PE 0, i.e., self on single-core)
    //   [40]    = IRM = 0 (use target list, not all-but-self)
    let val: u64 = ((intid as u64) & 0xF) << 24 | 1;
    core::arch::asm!(
        "msr ICC_SGI1_EL1, {}",
        "isb",
        in(reg) val,
    );
}
```

- [ ] **Step 2: Update irq_dispatch in vectors.rs to handle YIELD_SGI**

In `irq_dispatch` (line 260-274), add a match arm for `YIELD_SGI` after the `TIMER_INTID` arm:

Replace the existing `irq_dispatch` function:

```rust
#[cfg(target_arch = "aarch64")]
#[no_mangle]
extern "C" fn irq_dispatch(current_sp: usize) -> usize {
    let intid = gic::ack();
    let new_sp = match intid {
        gic::TIMER_INTID => {
            timer::on_tick();
            unsafe { sched::schedule(current_sp) }
        }
        gic::YIELD_SGI => {
            // Voluntary yield from block_current() — just reschedule,
            // no timer work. The task is already marked Blocked.
            unsafe { sched::schedule(current_sp) }
        }
        gic::SPURIOUS => current_sp,
        _ => current_sp,
    };
    if intid != gic::SPURIOUS {
        gic::eoi(intid);
    }
    new_sp
}
```

- [ ] **Step 3: Verify the boot crate compiles**

Run: `cd crates/harmony-boot-aarch64 && cargo clippy --target x86_64-apple-darwin 2>&1`
Expected: PASS (the aarch64-gated code won't compile on x86_64, but clippy should pass for non-gated code)

Also verify aarch64 compilation if cross-compile toolchain is available:
Run: `cd crates/harmony-boot-aarch64 && cargo check --target aarch64-unknown-uefi 2>&1`
Expected: PASS

- [ ] **Step 4: Run existing tests (no regressions)**

Run: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin 2>&1`
Expected: PASS (all existing + Task 1 tests)

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-boot-aarch64/src/gic.rs crates/harmony-boot-aarch64/src/vectors.rs
git commit -m "feat(gic): add Self-SGI yield mechanism for block_current

YIELD_SGI (SGI 1) + send_sgi_self triggers reschedule through the
existing IRQ handler path. irq_dispatch routes SGI 1 to schedule()
without calling on_tick()."
```

---

### Task 3: Linuxulator Callbacks and block_until Rewrite

**Context:** The Linuxulator in `linuxulator.rs` currently spin-waits via `block_until()` (lines 2589-2609) using `poll_fn` + `spin_loop()`. This task adds `block_fn`/`wake_fn` callback fields, their setters, and rewrites `block_until()` to call `block_fn` instead of spinning.

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

**Reference:** Read these sections before starting:
- Linuxulator struct fields: lines 2394-2495 (especially `poll_fn` at line 2494)
- `set_poll_fn()`: lines 2577-2581
- `block_until()`: lines 2589-2609
- `BlockResult` enum: lines 81-87

- [ ] **Step 1: Write a failing test for block_until calling block_fn**

Find the test module at the end of `linuxulator.rs`. Add:

```rust
#[test]
fn block_until_calls_block_fn() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let mut lx = make_test_linuxulator();
    static BLOCK_CALLED: AtomicBool = AtomicBool::new(false);

    lx.set_block_fn(|_op, _fd| {
        BLOCK_CALLED.store(true, Ordering::SeqCst);
    });

    BLOCK_CALLED.store(false, Ordering::SeqCst);
    let result = lx.block_until(0, 5); // op=0 (FdReadable), fd=5
    assert!(BLOCK_CALLED.load(Ordering::SeqCst));
    assert_eq!(result, BlockResult::Ready);
}

#[test]
fn block_until_returns_interrupted_without_block_fn() {
    let mut lx = make_test_linuxulator();
    // No block_fn set.
    let result = lx.block_until(0, 5);
    assert_eq!(result, BlockResult::Interrupted);
}
```

Note: `BlockResult` needs `#[derive(PartialEq)]` if it doesn't have it. Check and add if needed (line 81-87).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os -- block_until_calls 2>&1`
Expected: FAIL — `set_block_fn` not found, `block_until` signature mismatch

- [ ] **Step 3: Add block_fn and wake_fn fields to the Linuxulator struct**

In the Linuxulator struct definition (around line 2494, near the `poll_fn` field), add:

```rust
    /// Callback to block the current task. Called by block_until() instead
    /// of spin-waiting. Arguments: (op: u8, fd: i32) where op is:
    /// 0=FdReadable, 1=FdWritable, 2=FdConnectDone, 3=PollWait.
    /// The callback calls sched::block_current() which triggers a Self-SGI.
    block_fn: Option<fn(u8, i32)>,
    /// Callback to wake a task blocked on a specific fd. Called after
    /// pipe/eventfd writes for synchronous waking. Arguments: (fd: i32, op: u8)
    /// where op is 0=readable, 1=writable.
    wake_fn: Option<fn(i32, u8)>,
```

Initialize both to `None` wherever `Linuxulator::new()` or equivalent constructor sets fields.

- [ ] **Step 4: Add set_block_fn and set_wake_fn methods**

Add after `set_poll_fn` (after line 2581):

```rust
    /// Set the blocking callback. Called by block_until() to yield the CPU
    /// to the scheduler instead of spin-waiting.
    pub fn set_block_fn(&mut self, f: fn(u8, i32)) {
        self.block_fn = Some(f);
    }

    /// Set the wake callback. Called after pipe/eventfd writes to immediately
    /// wake any task blocked on the corresponding read end.
    pub fn set_wake_fn(&mut self, f: fn(i32, u8)) {
        self.wake_fn = Some(f);
    }
```

- [ ] **Step 5: Rewrite block_until**

Replace the existing `block_until` method (lines 2589-2609) with:

```rust
    /// Block the current task until woken by the system task's wake-check loop.
    ///
    /// If `block_fn` is set (scheduler available), calls it to yield the CPU.
    /// The task is marked Blocked, a Self-SGI triggers a context switch, and
    /// execution resumes here when woken. Returns `Ready`.
    ///
    /// If `block_fn` is not set (no scheduler), returns `Interrupted` so the
    /// caller can fall back to EAGAIN.
    fn block_until(&mut self, op: u8, fd: i32) -> BlockResult {
        if let Some(block) = self.block_fn {
            block(op, fd);
            // Execution resumes here after wake + reschedule.
            BlockResult::Ready
        } else {
            BlockResult::Interrupted
        }
    }
```

- [ ] **Step 6: Add poll_network and is_wait_ready public methods**

Add a public method for the system task to drive the network stack (near `set_poll_fn`):

```rust
    /// Drive the network stack. Called by the system task's event loop
    /// to move packets through smoltcp. Wraps the internal poll_fn.
    pub fn poll_network(&mut self) {
        if let Some(pf) = self.poll_fn {
            pf();
        }
    }
```

- [ ] **Step 7: Add public readiness check for the system task's wake loop**

Add a public method (near `is_fd_readable`/`is_fd_writable`, around line 8825):

```rust
    /// Check if a blocked task's wait condition is satisfied.
    ///
    /// Called by the system task's wake-check loop. `op` and `fd` match
    /// the values passed to `block_fn`:
    /// - 0 = FdReadable(fd)
    /// - 1 = FdWritable(fd)
    /// - 2 = FdConnectDone(fd)
    /// - 3 = PollWait (always returns true — caller handles network-change gating)
    pub fn is_wait_ready(&self, op: u8, fd: i32) -> bool {
        match op {
            0 => self.is_fd_readable(fd),
            1 => self.is_fd_writable(fd),
            2 => self.is_fd_connect_done(fd),
            3 => true,
            _ => false,
        }
    }
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cargo test -p harmony-os -- block_until 2>&1`
Expected: PASS

- [ ] **Step 9: Run full harmony-os test suite**

Run: `cargo test -p harmony-os 2>&1`
Expected: PASS (no regressions — existing tests still use the old block_until call pattern, which now fails to compile. Proceed to Step 10 if tests fail only due to old callers.)

Note: If existing tests call `block_until` with the old signature `(poll_fn, ready_check, fd)`, those tests will fail to compile. This is expected — Task 4 updates all callers. For now, temporarily stub the old tests if needed, or proceed to Task 4.

- [ ] **Step 10: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add block_fn/wake_fn callbacks, rewrite block_until

block_until now calls block_fn callback (scheduler yield) instead of
spin-waiting with poll_fn + spin_loop. Adds set_block_fn/set_wake_fn
setters and is_wait_ready public readiness check for system task."
```

---

### Task 4: Convert Single-fd Blocking Paths

**Context:** Six syscall handlers use `block_until` with the old spin-wait signature. This task converts them to the new `block_until(op, fd)` signature. It also adds synchronous pipe/eventfd wake calls.

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

**Reference:** Read these sections before starting:
- sys_read TCP path: around lines 3796-3850
- sys_write TCP path: around lines 3583-3628
- sys_accept4: around lines 4753-4874 (especially inline blocking loop at 4786-4818)
- sys_connect: search for `is_fd_connect_done` usage
- sys_recvfrom: around lines 5093-5214
- sys_sendto: around lines 4960-5090
- pipe_write_blocking: lines 2619-2666

**Operation type constants** to define near the top of the file (or near `BlockResult`):

```rust
/// block_until operation types — match WaitReason encoding.
const BLOCK_OP_READABLE: u8 = 0;
const BLOCK_OP_WRITABLE: u8 = 1;
const BLOCK_OP_CONNECT: u8 = 2;
const BLOCK_OP_POLL: u8 = 3;
```

- [ ] **Step 1: Add operation type constants**

Add the four `BLOCK_OP_*` constants near the `BlockResult` enum (around line 87):

```rust
const BLOCK_OP_READABLE: u8 = 0;
const BLOCK_OP_WRITABLE: u8 = 1;
const BLOCK_OP_CONNECT: u8 = 2;
const BLOCK_OP_POLL: u8 = 3;
```

- [ ] **Step 2: Convert sys_read TCP blocking path**

Find the TCP read path in sys_read (around line 3796-3850). The current pattern is:

```rust
// Old pattern (approximate):
if let Some(pf) = self.poll_fn {
    match self.block_until(pf, Self::is_fd_readable, fd) {
        BlockResult::Ready => { /* retry tcp_recv */ }
        BlockResult::Interrupted => return -EINTR as i64,
    }
}
```

Replace with:

```rust
if self.block_fn.is_some() {
    match self.block_until(BLOCK_OP_READABLE, fd) {
        BlockResult::Ready => { /* retry tcp_recv — keep existing retry logic */ }
        BlockResult::Interrupted => return -EINTR as i64,
    }
}
```

The retry logic after `BlockResult::Ready` stays the same — only the condition and `block_until` call change.

Also apply the same pattern to the **pipe read** path in sys_read (search for `PipeRead` in the sys_read function). The pipe read blocking follows the same pattern.

- [ ] **Step 3: Convert sys_write TCP blocking path**

Find the TCP write path in sys_write (around lines 3583-3628). Apply the same transformation:

```rust
// Old:
if let Some(pf) = self.poll_fn {
    match self.block_until(pf, Self::is_fd_writable, fd) {
// New:
if self.block_fn.is_some() {
    match self.block_until(BLOCK_OP_WRITABLE, fd) {
```

- [ ] **Step 4: Convert sys_accept4 inline blocking loop**

Find the inline blocking loop in sys_accept4 (around lines 4786-4818). The current code is an inline spin-wait loop. Replace with a `block_until` + retry loop:

```rust
// Old: inline spin-wait with poll_fn, is_fd_readable, deadline
// New:
if self.block_fn.is_some() {
    loop {
        match self.block_until(BLOCK_OP_READABLE, fd) {
            BlockResult::Ready => {
                match self.tcp.tcp_accept(tcp_handle) {
                    Ok(Some(accepted_handle)) => {
                        // Success — proceed with existing connection setup logic
                        break;
                    }
                    Ok(None) => {
                        // Spurious wake — no connection yet, re-block
                        continue;
                    }
                    Err(e) => {
                        return Self::map_net_error(e);
                    }
                }
            }
            BlockResult::Interrupted => return -EINTR as i64,
        }
    }
} else {
    return -EAGAIN as i64;
}
```

Preserve the existing connection setup logic (creating new fd, SocketState, etc.) that runs after a successful accept. Only the blocking mechanism changes.

- [ ] **Step 5: Convert sys_connect blocking path**

Find the connect blocking path (search for `is_fd_connect_done`). Replace:

```rust
// Old:
if let Some(pf) = self.poll_fn {
    match self.block_until(pf, Self::is_fd_connect_done, fd) {
// New:
if self.block_fn.is_some() {
    match self.block_until(BLOCK_OP_CONNECT, fd) {
```

- [ ] **Step 6: Convert sys_recvfrom and sys_sendto blocking paths**

Apply the same pattern to both:

For sys_recvfrom (TCP and UDP paths):
```rust
// Old: block_until(pf, Self::is_fd_readable, fd)
// New: block_until(BLOCK_OP_READABLE, fd)
```

For sys_sendto (TCP and UDP paths):
```rust
// Old: block_until(pf, Self::is_fd_writable, fd)
// New: block_until(BLOCK_OP_WRITABLE, fd)
```

In both cases, change the gate from `if let Some(pf) = self.poll_fn` to `if self.block_fn.is_some()`.

- [ ] **Step 7: Add synchronous pipe wake calls**

After every successful `sys_read` on a `PipeRead` fd, wake any task blocked on the write end:

```rust
// After successful pipe read (buffer space freed):
if let Some(wake) = self.wake_fn {
    if let Some(write_fd) = self.find_pipe_write_fd(pipe_id) {
        wake(write_fd, 1); // 1 = writable
    }
}
```

After every successful `sys_write` on a `PipeWrite` fd, wake any task blocked on the read end:

```rust
// After successful pipe write (data available):
if let Some(wake) = self.wake_fn {
    if let Some(read_fd) = self.find_pipe_read_fd(pipe_id) {
        wake(read_fd, 0); // 0 = readable
    }
}
```

You'll need helper methods `find_pipe_write_fd` and `find_pipe_read_fd` that scan the fd_table for the other end of a pipe. Add them as private methods:

```rust
/// Find the fd number for the write end of the pipe with the given pipe_id.
fn find_pipe_write_fd(&self, pipe_id: usize) -> Option<i32> {
    self.fd_table.iter().find_map(|(&fd, entry)| {
        if matches!(entry.kind, FdKind::PipeWrite(id) if id == pipe_id) {
            Some(fd)
        } else {
            None
        }
    })
}

/// Find the fd number for the read end of the pipe with the given pipe_id.
fn find_pipe_read_fd(&self, pipe_id: usize) -> Option<i32> {
    self.fd_table.iter().find_map(|(&fd, entry)| {
        if matches!(entry.kind, FdKind::PipeRead(id) if id == pipe_id) {
            Some(fd)
        } else {
            None
        }
    })
}
```

Note: Verify the exact `FdKind` variant names by reading the `FdKind` enum definition. Adjust if the names differ (e.g., `FdKind::Pipe { read: bool, id }` instead of separate variants).

- [ ] **Step 8: Run tests**

Run: `cargo test -p harmony-os 2>&1`
Expected: PASS (all tests including existing blocking tests, which may need updating if they use the old block_until signature directly)

If existing tests create a Linuxulator and call `block_until` with the old signature, update them to set `block_fn` and use the new signature. For tests that relied on `poll_fn` for blocking, set `block_fn` instead.

- [ ] **Step 9: Run clippy**

Run: `cargo clippy -p harmony-os 2>&1`
Expected: No warnings on changed code

- [ ] **Step 10: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): convert single-fd blocking to scheduler yield

sys_read, sys_write, sys_accept4, sys_connect, sys_recvfrom, sys_sendto
now call block_until(op, fd) instead of spin-waiting. Adds synchronous
pipe wake calls after successful read/write."
```

---

### Task 5: Convert Multi-fd Blocking and Pipes

**Context:** `sys_poll`, `sys_select`, `epoll_wait`, and `pipe_write_blocking` have their own spin-wait loops (not using `block_until`). This task converts them to use `block_until(BLOCK_OP_POLL, -1)` for poll/select/epoll and `block_until(BLOCK_OP_WRITABLE, fd)` for pipes.

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

**Reference:** Read these sections before starting:
- sys_poll: around lines 8444-8494
- sys_select: around lines 8573-8684
- epoll_wait: around lines 5610-5722
- pipe_write_blocking: lines 2619-2666

- [ ] **Step 1: Convert sys_poll blocking path**

Find the sys_poll blocking loop (around lines 8459-8493). The current code spin-waits with `poll_fn()` and `poll_check_once()`.

Replace the blocking path with:

```rust
// Blocking poll with scheduler yield.
if self.block_fn.is_some() {
    let start_ms = self.poll_fn.map_or(0, |pf| pf());
    let deadline = if timeout_ms > 0 {
        start_ms.saturating_add(timeout_ms as u64)
    } else {
        u64::MAX // Negative timeout = infinite wait
    };

    loop {
        match self.block_until(BLOCK_OP_POLL, -1) {
            BlockResult::Ready => {
                let ready = self.poll_check_once(fds_ptr, nfds, user_mem);
                if ready > 0 {
                    return ready;
                }
                // Check timeout (approximate — checked on each wake).
                if timeout_ms > 0 {
                    let now = self.poll_fn.map_or(deadline, |pf| pf());
                    if now >= deadline {
                        return 0;
                    }
                }
                // No fds ready, timeout not expired — re-block.
            }
            BlockResult::Interrupted => return 0,
        }
    }
} else {
    return 0; // No scheduler — non-blocking fallback.
}
```

Preserve the non-blocking path (`timeout_ms == 0`) that calls `poll_check_once` once and returns immediately.

- [ ] **Step 2: Convert sys_select blocking path**

Find the sys_select blocking loop (around lines 8617-8683). The current code saves fd_sets, spin-waits, and restores fd_sets on each iteration.

Replace the blocking path with the same pattern, preserving fd_set save/restore:

```rust
// Blocking select with scheduler yield.
if self.block_fn.is_some() {
    let start_ms = self.poll_fn.map_or(0, |pf| pf());
    let deadline = if timeout_ms > 0 {
        start_ms.saturating_add(timeout_ms as u64)
    } else {
        u64::MAX
    };

    // Save original fd_sets (select modifies them on each check).
    // Keep existing save logic.

    loop {
        // Restore fd_sets from saved copies before each check.
        // Keep existing restore logic.

        match self.block_until(BLOCK_OP_POLL, -1) {
            BlockResult::Ready => {
                let ready = self.select_check_once(/* existing args */);
                if ready > 0 {
                    return ready;
                }
                if timeout_ms > 0 {
                    let now = self.poll_fn.map_or(deadline, |pf| pf());
                    if now >= deadline {
                        // Timeout: clear all fd_sets (Linux convention).
                        // Keep existing clear logic.
                        return 0;
                    }
                }
            }
            BlockResult::Interrupted => {
                // Clear all fd_sets on timeout/interrupt.
                // Keep existing clear logic.
                return 0;
            }
        }
    }
} else {
    return 0;
}
```

The key change: replace `core::hint::spin_loop()` and the `poll_fn()` calls inside the loop with `block_until(BLOCK_OP_POLL, -1)`. Keep the fd_set save/restore and timeout checking logic.

- [ ] **Step 3: Convert epoll_wait to block properly**

Find epoll_wait (around lines 5610-5722). Currently it checks readiness once and returns. Add blocking when no events are ready and timeout is not zero.

After the existing readiness check (which collects `ready_count`), add:

```rust
// If no events ready and blocking requested, yield to scheduler.
if ready_count == 0 && timeout != 0 && self.block_fn.is_some() {
    let start_ms = self.poll_fn.map_or(0, |pf| pf());
    let deadline = if timeout > 0 {
        start_ms.saturating_add(timeout as u64)
    } else {
        u64::MAX // -1 = infinite wait
    };

    loop {
        match self.block_until(BLOCK_OP_POLL, -1) {
            BlockResult::Ready => {
                // Drive network stack if poll_fn available.
                if let Some(pf) = self.poll_fn {
                    let now_ms = pf() as i64;
                    self.tcp.tcp_poll(now_ms);
                }
                // Recheck all interest fds — reuse existing readiness logic.
                // Re-collect ready events into the output buffer.
                ready_count = 0;
                // ... (reuse the existing interest-list iteration and
                //      readiness checking code, writing to events buffer)
                if ready_count > 0 {
                    break;
                }
                if timeout > 0 {
                    let now = self.poll_fn.map_or(deadline, |pf| pf());
                    if now >= deadline {
                        break; // Return 0
                    }
                }
            }
            BlockResult::Interrupted => break,
        }
    }
}
```

Note: The readiness checking logic for epoll events already exists in the function. Extract it into a helper if it's not already factored, or inline the recheck. The subagent should read the existing code and reuse the readiness check pattern.

- [ ] **Step 4: Convert pipe_write_blocking**

Find pipe_write_blocking (lines 2619-2666). Replace the spin-wait loop with block_until:

```rust
fn pipe_write_blocking(&mut self, fd: i32, pipe_id: usize, buf_ptr: usize, count: usize, user_mem: &[u8]) -> i64 {
    let pipe_buf_cap = 65536; // PIPE_BUF_CAP
    let atomic_limit = 4096;  // PIPE_BUF

    loop {
        let buf = self.pipes.get_mut(&pipe_id);
        // Check if reader still exists.
        if !self.pipe_has_reader(pipe_id) {
            return -EPIPE as i64;
        }

        if let Some(buf) = buf {
            let space = pipe_buf_cap - buf.len();
            if count <= atomic_limit {
                // Atomic write: must fit entirely.
                if space >= count {
                    let data = &user_mem[buf_ptr..buf_ptr + count];
                    buf.extend_from_slice(data);
                    // Wake reader.
                    if let Some(wake) = self.wake_fn {
                        if let Some(read_fd) = self.find_pipe_read_fd(pipe_id) {
                            wake(read_fd, 0);
                        }
                    }
                    return count as i64;
                }
            } else {
                // Partial write OK.
                if space > 0 {
                    let write_len = count.min(space);
                    let data = &user_mem[buf_ptr..buf_ptr + write_len];
                    buf.extend_from_slice(data);
                    if let Some(wake) = self.wake_fn {
                        if let Some(read_fd) = self.find_pipe_read_fd(pipe_id) {
                            wake(read_fd, 0);
                        }
                    }
                    return write_len as i64;
                }
            }
        }

        // Buffer full — block until space available.
        if self.block_fn.is_some() {
            match self.block_until(BLOCK_OP_WRITABLE, fd) {
                BlockResult::Ready => continue, // Retry
                BlockResult::Interrupted => return -EINTR as i64,
            }
        } else {
            return -EAGAIN as i64;
        }
    }
}
```

Note: Read the existing `pipe_write_blocking` carefully and preserve its POSIX atomic-write semantics. The code above is a structural guide — adapt to match the existing field names, buffer access patterns, and error handling.

- [ ] **Step 5: Run tests**

Run: `cargo test -p harmony-os 2>&1`
Expected: PASS

- [ ] **Step 6: Run clippy**

Run: `cargo clippy -p harmony-os 2>&1`
Expected: No warnings on changed code

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): convert poll/select/epoll/pipe to scheduler yield

sys_poll, sys_select, epoll_wait now block via block_until(BLOCK_OP_POLL)
with recheck loops. pipe_write_blocking yields on full buffer. All spin-
wait loops in the Linuxulator are now replaced with scheduler yields."
```

---

### Task 6: Boot Integration — Task Architecture and Callbacks

**Context:** This is the integration task. The system task (PID 1) becomes a dedicated network poller + waker. A new ELF task (PID 2) runs the test binary. Callbacks are wired up between the boot crate and the Linuxulator.

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/main.rs`

**Reference:** Read `main.rs` fully before starting. Key sections:
- ConcreteRuntime type alias: line 45
- RUNTIME static: line 51
- qemu-virt task spawning block: lines 472-506
- idle_task: lines 904-908
- system_task: lines 915-930
- dispatch_action: search for `fn dispatch_action`
- ELF binary loading: search for `run_elf_binary` and `include_bytes!`
- SVC dispatch setup: search for `DISPATCH_FN` or `set_dispatch`
- Linuxulator creation and setup: search for `Linuxulator::new` or `linuxulator`

- [ ] **Step 1: Add LINUXULATOR static**

Find where `RUNTIME` is defined (line 51). Add a similar static for the Linuxulator. You'll need a concrete type alias for the Linuxulator (similar to `ConcreteRuntime`):

```rust
#[cfg(target_os = "uefi")]
type ConcreteLinuxulator = Linuxulator</* B and T type params from existing code */>;

#[cfg(target_os = "uefi")]
static mut LINUXULATOR: Option<ConcreteLinuxulator> = None;
```

Read the existing Linuxulator construction code to determine the exact generic parameters `B` and `T`. Use the same types that are currently used when creating the Linuxulator instance.

- [ ] **Step 2: Move Linuxulator to static and set up callbacks**

In the qemu-virt block (around lines 472-506), find where the Linuxulator is created. Move it to the static:

```rust
// After Linuxulator is created and configured:
linuxulator.set_block_fn(|op, fd| {
    let reason = match op {
        0 => sched::WaitReason::FdReadable(fd),
        1 => sched::WaitReason::FdWritable(fd),
        2 => sched::WaitReason::FdConnectDone(fd),
        3 => sched::WaitReason::PollWait,
        _ => unreachable!(),
    };
    unsafe { sched::block_current(reason); }
});

linuxulator.set_wake_fn(|fd, op| {
    unsafe { sched::wake_by_fd(fd, op); }
});

unsafe { LINUXULATOR = Some(linuxulator); }
```

Make sure the Linuxulator's `poll_fn` is still set (for the system task's smoltcp polling).

- [ ] **Step 3: Create elf_task function**

Add a new function (near idle_task and system_task):

```rust
#[cfg(all(feature = "qemu-virt", target_os = "uefi"))]
fn elf_task() -> ! {
    use core::fmt::Write;
    let mut serial =
        harmony_unikernel::SerialWriter::new(|byte| unsafe { pl011::write_byte(byte) });
    let _ = writeln!(serial, "[ELF] Task started");

    // Run the test ELF binary.
    // Move the existing ELF loading + trampoline logic here from the
    // qemu-virt block or system_task. This includes:
    // 1. Get the embedded ELF bytes (include_bytes!)
    // 2. Load ELF segments into memory
    // 3. Set up SVC dispatch (DISPATCH_FN) if not already set
    // 4. Call run_elf_binary(entry_point, stack_pointer)
    // 5. Handle return (exit_group)

    // After ELF exits, print and halt.
    let _ = writeln!(serial, "[ELF] Binary exited");
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}
```

Read the existing ELF loading code carefully (search for `run_elf_binary`, `include_bytes!`, ELF parsing) and move it into elf_task. The SVC dispatch function pointer (`DISPATCH_FN`) should be set up before tasks are spawned (in boot init), since the Linuxulator is now a static accessible from any task.

- [ ] **Step 4: Refactor system_task to be network poller + waker**

Replace the existing system_task (lines 915-930):

```rust
#[cfg(all(feature = "qemu-virt", target_os = "uefi"))]
fn system_task() -> ! {
    use core::fmt::Write;
    let mut serial =
        harmony_unikernel::SerialWriter::new(|byte| unsafe { pl011::write_byte(byte) });
    let _ = writeln!(serial, "[System] Event loop started");

    loop {
        let now = timer::now_ms();

        // 1. Poll smoltcp — drive the network stack.
        // Call the Linuxulator's poll_network() to move packets through smoltcp.
        let linuxulator = unsafe { LINUXULATOR.as_mut().unwrap() };
        linuxulator.poll_network();

        // 2. Run Harmony runtime (announces, heartbeats, peer discovery).
        let runtime = unsafe { RUNTIME.as_mut().unwrap() };
        let actions = runtime.tick(now);
        for action in &actions {
            dispatch_action(action, &mut serial);
        }

        // 3. Check blocked tasks — wake any whose I/O is ready.
        check_and_wake_blocked_tasks();

        // 4. Low-power wait until next interrupt.
        unsafe { core::arch::asm!("wfi") };
    }
}
```

- [ ] **Step 5: Implement check_and_wake_blocked_tasks**

Add as a module-level function:

```rust
#[cfg(all(feature = "qemu-virt", target_os = "uefi"))]
fn check_and_wake_blocked_tasks() {
    let linuxulator = unsafe { LINUXULATOR.as_ref().unwrap() };
    unsafe {
        sched::for_each_blocked(|idx, reason| {
            let (op, fd) = match reason {
                sched::WaitReason::FdReadable(fd) => (0u8, fd),
                sched::WaitReason::FdWritable(fd) => (1, fd),
                sched::WaitReason::FdConnectDone(fd) => (2, fd),
                sched::WaitReason::PollWait => (3, -1),
            };
            if linuxulator.is_wait_ready(op, fd) {
                sched::wake(idx);
            }
        });
    }
}
```

- [ ] **Step 6: Update task spawning to include ELF task**

In the qemu-virt block, update the task spawning section:

```rust
let _ = writeln!(serial, "[Sched] Spawned idle task (PID 0)");
unsafe { sched::spawn_task("idle", 0, idle_task, &mut bump) };

let _ = writeln!(serial, "[Sched] Spawned system task (PID 1)");
unsafe { sched::spawn_task("system", 1, system_task, &mut bump) };

let _ = writeln!(serial, "[Sched] Spawned elf task (PID 2)");
unsafe { sched::spawn_task("elf", 2, elf_task, &mut bump) };

let _ = writeln!(serial, "[Sched] Entering scheduler");
unsafe { sched::enter_scheduler() };
```

- [ ] **Step 7: Verify compilation**

Run: `cd crates/harmony-boot-aarch64 && cargo check --target aarch64-unknown-uefi 2>&1`
Expected: PASS

Run: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin 2>&1`
Expected: PASS (host tests don't exercise qemu-virt code)

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-boot-aarch64/src/main.rs
git commit -m "feat(boot): ELF task (PID 2) + system task as network poller/waker

System task now polls smoltcp and wakes blocked tasks. ELF binary runs
in its own task (PID 2). block_fn/wake_fn callbacks wired to scheduler
primitives. Three tasks at boot: idle, system, elf."
```

---

### Task 7: QEMU Test Milestone Updates

**Context:** Update the aarch64 QEMU test milestones to verify the new 3-task boot sequence.

**Files:**
- Modify: `xtask/src/qemu_test.rs`

**Reference:** Read `xtask/src/qemu_test.rs` lines 32-63 (aarch64_milestones function).

- [ ] **Step 1: Update aarch64_milestones**

Replace the `aarch64_milestones` function (lines 32-63):

```rust
fn aarch64_milestones() -> Vec<Milestone> {
    vec![
        Milestone {
            pattern: "[PL011] Serial initialized",
            description: "serial up",
        },
        Milestone {
            pattern: "[RNDR]",
            description: "hardware RNG available",
        },
        Milestone {
            pattern: "[Identity]",
            description: "PQ identity generated",
        },
        Milestone {
            pattern: "[Sched] Spawned idle task (PID 0)",
            description: "idle task spawned",
        },
        Milestone {
            pattern: "[Sched] Spawned system task (PID 1)",
            description: "system task spawned",
        },
        Milestone {
            pattern: "[Sched] Spawned elf task (PID 2)",
            description: "elf task spawned",
        },
        Milestone {
            pattern: "[Sched] Entering scheduler",
            description: "scheduler entry",
        },
        Milestone {
            pattern: "[System]",
            description: "system task running",
        },
        Milestone {
            pattern: "[ELF]",
            description: "elf task running",
        },
    ]
}
```

- [ ] **Step 2: Run xtask compilation check**

Run: `cargo build -p xtask 2>&1`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add xtask/src/qemu_test.rs
git commit -m "test(xtask): update aarch64 milestones for Phase 4 three-task boot

Adds milestones for ELF task spawn (PID 2) and ELF task running.
Proves three-task round-robin with idle, system, and elf tasks."
```

- [ ] **Step 4: Run full QEMU boot test (if environment supports it)**

Run: `cargo +nightly xtask qemu-test --target aarch64 --timeout 60 2>&1`
Expected: All 9 milestones pass

If the test fails, debug by reading the serial output. Common issues:
- ELF task panics on startup (check elf_task setup)
- System task panics accessing LINUXULATOR static (check initialization order)
- Blocked task never wakes (check block_fn/wake_fn wiring)
- Missing milestone print (check writeln! format strings match milestone patterns exactly)

---

## Post-Implementation Checklist

After all 7 tasks are complete:

- [ ] Run full test suite: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin`
- [ ] Run harmony-os tests: `cargo test -p harmony-os`
- [ ] Run clippy: `cd crates/harmony-boot-aarch64 && cargo clippy --target x86_64-apple-darwin`
- [ ] Run nightly rustfmt: `cargo +nightly fmt --all -- --check`
- [ ] Run QEMU boot test: `cargo +nightly xtask qemu-test --target aarch64 --timeout 60`
- [ ] Verify no spin_loop() references remain in blocking paths: `grep -n "spin_loop" crates/harmony-os/src/linuxulator.rs`
