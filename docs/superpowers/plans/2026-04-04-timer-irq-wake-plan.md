# Timer IRQ Wake Mechanism Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deadline-based task waking to the 100 Hz timer IRQ handler so that timed syscalls (futex, nanosleep, poll, select, epoll) wake with 10ms precision.

**Architecture:** Deadlines are absolute monotonic milliseconds stored on the TCB. On each timer tick, `check_deadlines(now_ms)` scans blocked tasks and wakes expired ones before `schedule()` runs. The linuxulator computes deadlines from syscall parameters and passes them through callbacks. A `woken_by_timeout` flag on the TCB tells the linuxulator how to translate the wake into a return value.

**Tech Stack:** Rust (no_std, aarch64), ARM Generic Timer, GICv3

**Spec:** `docs/superpowers/specs/2026-04-04-timer-irq-wake-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `crates/harmony-boot-aarch64/src/sched.rs` | Modify | TCB fields, WaitReason::Sleep, block_current, check_deadlines, consume_woken_by_timeout, wake clearing |
| `crates/harmony-boot-aarch64/src/vectors.rs` | Modify | Add check_deadlines call in irq_dispatch |
| `crates/harmony-boot-aarch64/src/main.rs` | Modify | Update callback closures |
| `crates/harmony-os/src/linuxulator.rs` | Modify | Callback types, block_until, setters, sys_futex, sys_nanosleep, poll/select/epoll deadline pass-through |

---

### Task 1: Scheduler Deadline Infrastructure

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/sched.rs`

This task adds all the scheduler-side deadline support: new TCB fields, `WaitReason::Sleep`, modified `block_current`, new `check_deadlines` and `consume_woken_by_timeout` functions, and clearing deadline in all wake paths.

- [ ] **Step 1: Write failing tests for check_deadlines and consume_woken_by_timeout**

Add these tests after the existing `futex_wake_returns_zero_when_no_waiters` test (after line 1011 in sched.rs). They will fail because the new fields and functions don't exist yet.

```rust
    #[test]
    fn check_deadlines_wakes_expired_task() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Running, None);
            put_tcb(1, TaskState::Blocked, Some(WaitReason::Futex(0x1000)));
            TASKS[1].assume_init_mut().deadline_ms = Some(100);
            NUM_TASKS = 2;
            CURRENT = 0;

            check_deadlines(100);

            let tcb = TASKS[1].assume_init_ref();
            assert_eq!(tcb.state, TaskState::Ready);
            assert!(tcb.woken_by_timeout);
            assert_eq!(tcb.deadline_ms, None);
            assert_eq!(tcb.wait_reason, None);
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn check_deadlines_ignores_future_deadline() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Running, None);
            put_tcb(1, TaskState::Blocked, Some(WaitReason::Futex(0x1000)));
            TASKS[1].assume_init_mut().deadline_ms = Some(200);
            NUM_TASKS = 2;
            CURRENT = 0;

            check_deadlines(100);

            let tcb = TASKS[1].assume_init_ref();
            assert_eq!(tcb.state, TaskState::Blocked);
            assert!(!tcb.woken_by_timeout);
            assert_eq!(tcb.deadline_ms, Some(200));
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn check_deadlines_ignores_no_deadline() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Running, None);
            put_tcb(1, TaskState::Blocked, Some(WaitReason::PollWait));
            // deadline_ms defaults to None from put_tcb
            NUM_TASKS = 2;
            CURRENT = 0;

            check_deadlines(u64::MAX);

            let tcb = TASKS[1].assume_init_ref();
            assert_eq!(tcb.state, TaskState::Blocked);
            assert!(!tcb.woken_by_timeout);
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn normal_wake_clears_deadline_and_flag() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Blocked, Some(WaitReason::Futex(0x1000)));
            TASKS[0].assume_init_mut().deadline_ms = Some(500);
            NUM_TASKS = 1;

            wake(0);

            let tcb = TASKS[0].assume_init_ref();
            assert_eq!(tcb.state, TaskState::Ready);
            assert_eq!(tcb.deadline_ms, None);
            assert!(!tcb.woken_by_timeout);
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn consume_woken_by_timeout_clears_flag() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Running, None);
            TASKS[0].assume_init_mut().woken_by_timeout = true;
            NUM_TASKS = 1;
            CURRENT = 0;

            let was = consume_woken_by_timeout();
            assert!(was);
            let was2 = consume_woken_by_timeout();
            assert!(!was2);
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn block_current_stores_deadline() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Running, None);
            NUM_TASKS = 1;
            CURRENT = 0;

            block_current(WaitReason::Futex(0x2000), Some(999));

            let tcb = TASKS[0].assume_init_ref();
            assert_eq!(tcb.state, TaskState::Blocked);
            assert_eq!(tcb.wait_reason, Some(WaitReason::Futex(0x2000)));
            assert_eq!(tcb.deadline_ms, Some(999));
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn wait_reason_sleep_variant() {
        assert_ne!(WaitReason::Sleep, WaitReason::PollWait);
        assert_eq!(WaitReason::Sleep, WaitReason::Sleep);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-boot-aarch64 -- check_deadlines wait_reason_sleep block_current_stores_deadline consume_woken_by_timeout normal_wake_clears_deadline`
Expected: Compilation errors — `deadline_ms`, `woken_by_timeout`, `check_deadlines`, `consume_woken_by_timeout`, `WaitReason::Sleep` don't exist yet.

- [ ] **Step 3: Add TCB fields and WaitReason::Sleep**

In `sched.rs`, add `WaitReason::Sleep` variant to the enum (after line 68):

```rust
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
    /// Waiting on a futex word at this address.
    Futex(u64),
    /// Pure time wait (nanosleep / clock_nanosleep). No fd or address —
    /// only the deadline on the TCB determines when to wake.
    Sleep,
}
```

Add two fields to `TaskControlBlock` after `clear_child_tid` (after line 103):

```rust
    /// Absolute monotonic deadline in ms. `None` = no timeout.
    /// Set by block_current, cleared by wake/check_deadlines.
    pub deadline_ms: Option<u64>,
    /// True if woken by deadline expiry (check_deadlines) rather than
    /// a normal wake (futex_wake, wake_by_fd, etc.).
    pub woken_by_timeout: bool,
```

- [ ] **Step 4: Update all TCB initializers with new fields**

In `spawn_task` (the `TASKS[n] = MaybeUninit::new(TaskControlBlock { ... })` block around line 189), add:

```rust
        deadline_ms: None,
        woken_by_timeout: false,
```

In `spawn_task_runtime` (the `TASKS[n] = MaybeUninit::new(TaskControlBlock { ... })` block around line 471), add:

```rust
        deadline_ms: None,
        woken_by_timeout: false,
```

In the test helper `put_tcb` (around line 784), add the same two fields:

```rust
    unsafe fn put_tcb(idx: usize, state: TaskState, wait_reason: Option<WaitReason>) {
        TASKS[idx] = MaybeUninit::new(TaskControlBlock {
            kernel_sp: 0,
            kernel_stack_base: 0x4_0000 + idx * 0x1_0000,
            kernel_stack_size: 8192,
            state,
            preempt_count: 0,
            pid: idx as u32,
            name: "test",
            entry: None,
            wait_reason,
            tls: 0,
            tid: idx as u32,
            clear_child_tid: 0,
            deadline_ms: None,
            woken_by_timeout: false,
        });
    }
```

Also update the explicit `TaskControlBlock` literal in `tcb_has_thread_fields` test (around line 929) and `check_guard_page_detects_hit` test (around line 749) to include both new fields with `deadline_ms: None, woken_by_timeout: false,`.

- [ ] **Step 5: Modify block_current to accept and store deadline_ms**

Change the signature and body of `block_current` (around line 505):

```rust
pub unsafe fn block_current(reason: WaitReason, deadline_ms: Option<u64>) {
    {
        let cur = CURRENT;
        let tcb = TASKS[cur].assume_init_mut();
        tcb.state = TaskState::Blocked;
        tcb.wait_reason = Some(reason);
        tcb.deadline_ms = deadline_ms;
```

The rest of the function body (TLS save, asm SGI, re-mask) stays identical.

- [ ] **Step 6: Update the existing block_current test**

The existing test `block_current_sets_blocked_and_wait_reason` (around line 833) calls `block_current(WaitReason::FdReadable(7))`. Add the deadline parameter:

```rust
    #[test]
    fn block_current_sets_blocked_and_wait_reason() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Running, None);
            NUM_TASKS = 1;
            CURRENT = 0;
            block_current(WaitReason::FdReadable(7), None);
            let tcb = TASKS[0].assume_init_ref();
            assert_eq!(tcb.state, TaskState::Blocked);
            assert_eq!(tcb.wait_reason, Some(WaitReason::FdReadable(7)));
            assert_eq!(tcb.deadline_ms, None);
            NUM_TASKS = 0;
        }
    }
```

- [ ] **Step 7: Add check_deadlines function**

Add this function after `block_current` (after the closing brace around line 539):

```rust
/// Check all blocked tasks for expired deadlines.
///
/// Called from `irq_dispatch` on every timer tick, before `schedule()`.
/// For each Blocked task with `deadline_ms <= now_ms`, transitions it to
/// Ready and sets `woken_by_timeout = true`. Newly-Ready tasks are
/// immediately eligible for `schedule()` on the same tick.
///
/// O(MAX_TASKS) per tick — negligible at current task counts.
///
/// # Safety
///
/// Must only be called from the IRQ handler path (non-reentrant, PSTATE.I set).
pub unsafe fn check_deadlines(now_ms: u64) {
    let n = NUM_TASKS;
    for i in 0..n {
        let tcb = TASKS[i].assume_init_mut();
        if tcb.state == TaskState::Blocked {
            if let Some(deadline) = tcb.deadline_ms {
                if now_ms >= deadline {
                    tcb.woken_by_timeout = true;
                    tcb.state = TaskState::Ready;
                    tcb.wait_reason = None;
                    tcb.deadline_ms = None;
                }
            }
        }
    }
}
```

- [ ] **Step 8: Add consume_woken_by_timeout function**

Add after `check_deadlines`:

```rust
/// Read and clear the woken_by_timeout flag for the current task.
///
/// Returns `true` if the task was woken by deadline expiry, `false` if
/// woken normally. Clears the flag after reading to prevent stale flags
/// on subsequent blocking operations.
///
/// # Safety
///
/// Must be called from the SVC dispatch path (same task context as the
/// blocking operation that set the flag). CURRENT must index a valid TCB.
pub unsafe fn consume_woken_by_timeout() -> bool {
    let tcb = TASKS[CURRENT].assume_init_mut();
    let was_timeout = tcb.woken_by_timeout;
    tcb.woken_by_timeout = false;
    was_timeout
}
```

- [ ] **Step 9: Clear deadline_ms in all wake paths**

In `wake()` (around line 552), add `tcb.deadline_ms = None;`:

```rust
pub unsafe fn wake(task_idx: usize) {
    let tcb = TASKS[task_idx].assume_init_mut();
    if tcb.state == TaskState::Blocked {
        tcb.state = TaskState::Ready;
        tcb.wait_reason = None;
        tcb.deadline_ms = None;
    }
}
```

In `wake_by_fd()` (around line 590), add `tcb.deadline_ms = None;`:

```rust
        if matches {
            tcb.state = TaskState::Ready;
            tcb.wait_reason = None;
            tcb.deadline_ms = None;
        }
```

In `futex_wake()` (around line 639), add `tcb.deadline_ms = None;`:

```rust
        if tcb.state == TaskState::Blocked && tcb.wait_reason == Some(WaitReason::Futex(uaddr)) {
            tcb.state = TaskState::Ready;
            tcb.wait_reason = None;
            tcb.deadline_ms = None;
            woken += 1;
        }
```

In `kill_threads_by_pid()` write phase (around line 702), add `tcb.deadline_ms = None;`:

```rust
        {
            let tcb = TASKS[i].assume_init_mut();
            tcb.clear_child_tid = 0;
            tcb.state = TaskState::Dead;
            tcb.wait_reason = None;
            tcb.deadline_ms = None;
        }
```

- [ ] **Step 10: Run all tests**

Run: `cargo test -p harmony-boot-aarch64`
Expected: All tests pass, including the 7 new tests.

- [ ] **Step 11: Commit**

```bash
git add crates/harmony-boot-aarch64/src/sched.rs
git commit -m "feat(sched): add deadline_ms, check_deadlines, consume_woken_by_timeout

Adds timer-based task wake infrastructure:
- deadline_ms and woken_by_timeout fields on TCB
- WaitReason::Sleep variant for pure time waits
- block_current accepts optional deadline parameter
- check_deadlines scans blocked tasks for expired deadlines
- consume_woken_by_timeout reads and clears the timeout flag
- All wake paths (wake, futex_wake, wake_by_fd, kill_threads)
  clear deadline_ms to prevent double-wake"
```

---

### Task 2: IRQ Dispatch Wiring

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/vectors.rs:344-358`

This task adds the `check_deadlines` call to the timer IRQ path so expired deadlines are processed on every tick.

- [ ] **Step 1: Add check_deadlines call in irq_dispatch**

In `vectors.rs`, modify the `TIMER_INTID` arm of `irq_dispatch` (around line 347-350):

```rust
        gic::TIMER_INTID => {
            timer::on_tick();
            unsafe { sched::check_deadlines(timer::now_ms()) };
            unsafe { sched::schedule(current_sp) }
        }
```

The existing code is:

```rust
        gic::TIMER_INTID => {
            timer::on_tick();
            unsafe { sched::schedule(current_sp) }
        }
```

Insert the `check_deadlines` call between `on_tick()` and `schedule()`.

- [ ] **Step 2: Run existing tests to verify nothing broke**

Run: `cargo test -p harmony-boot-aarch64`
Expected: All tests pass. (check_deadlines is not cfg-gated, but the irq_dispatch function is aarch64-only so host tests don't exercise this path. The function signature is validated at compile time.)

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-boot-aarch64/src/vectors.rs
git commit -m "feat(irq): call check_deadlines on every timer tick

Inserts sched::check_deadlines(timer::now_ms()) in the TIMER_INTID
arm of irq_dispatch, between on_tick() and schedule(). Expired
deadline tasks become Ready before the scheduler picks the next task."
```

---

### Task 3: Linuxulator Callback Interface + Main.rs Wiring

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`
- Modify: `crates/harmony-boot-aarch64/src/main.rs`

This task changes the callback function pointer types to support deadlines, adds the two new callbacks (`was_timeout_fn`, `now_ms_fn`), updates `block_until` to forward deadlines, updates the fork/clone snapshot, and wires everything in main.rs. All existing callers of `block_until` pass `None` as the deadline for now — specific syscalls will pass real deadlines in Tasks 4-6.

- [ ] **Step 1: Change callback type declarations in the Linuxulator struct**

In `linuxulator.rs`, modify the struct fields (around lines 2507-2527):

Change `block_fn` (line 2511):
```rust
    /// Callback to block the current task. Arguments: (op: u8, fd: i32, deadline_ms: Option<u64>)
    /// where op is: 0=FdReadable, 1=FdWritable, 2=FdConnectDone, 3=PollWait, 4=Sleep.
    block_fn: Option<fn(u8, i32, Option<u64>)>,
```

Change `futex_block_fn` (line 2521):
```rust
    /// Block current task on a futex address with optional deadline.
    futex_block_fn: Option<fn(u64, Option<u64>)>,
```

Add two new fields after `futex_wake_fn` (after line 2523):
```rust
    /// Check if the current task was woken by deadline expiry.
    /// Reads and clears the flag in one call.
    was_timeout_fn: Option<fn() -> bool>,
    /// Read current monotonic time in milliseconds.
    now_ms_fn: Option<fn() -> u64>,
```

- [ ] **Step 2: Add BLOCK_OP_SLEEP constant**

After the existing `BLOCK_OP_POLL` constant (line 94), add:

```rust
pub const BLOCK_OP_SLEEP: u8 = 4;
```

- [ ] **Step 3: Update constructor defaults**

In the `with_tcp_and_arena` constructor (around lines 2599-2607), add defaults for the new fields and update existing ones:

```rust
            block_fn: None,
```
stays as-is (the type changed, but `None` is still `None`).

```rust
            futex_block_fn: None,
```
stays as-is.

After `futex_wake_fn: None,` add:
```rust
            was_timeout_fn: None,
            now_ms_fn: None,
```

- [ ] **Step 4: Update setter methods**

Change `set_block_fn` (line 2628):
```rust
    pub fn set_block_fn(&mut self, f: fn(u8, i32, Option<u64>)) {
        self.block_fn = Some(f);
    }
```

Change `set_futex_block_fn` (line 2645):
```rust
    pub fn set_futex_block_fn(&mut self, f: fn(u64, Option<u64>)) {
        self.futex_block_fn = Some(f);
    }
```

Add two new setters after `set_futex_wake_fn`:
```rust
    /// Set the was-timeout callback. Called after a blocking operation
    /// resumes to check if the wake was due to deadline expiry.
    pub fn set_was_timeout_fn(&mut self, f: fn() -> bool) {
        self.was_timeout_fn = Some(f);
    }

    /// Set the now-ms callback. Returns current monotonic time in
    /// milliseconds. Used to compute absolute deadlines from relative
    /// timeouts in syscalls.
    pub fn set_now_ms_fn(&mut self, f: fn() -> u64) {
        self.now_ms_fn = Some(f);
    }
```

- [ ] **Step 5: Update block_until to forward deadline**

Change `block_until` (around line 2696):

```rust
    fn block_until(&mut self, op: u8, fd: i32, deadline_ms: Option<u64>) -> BlockResult {
        if let Some(block) = self.block_fn {
            block(op, fd, deadline_ms);
            BlockResult::Ready
        } else {
            BlockResult::Interrupted
        }
    }
```

- [ ] **Step 6: Update all block_until call sites to pass None**

There are 14 call sites. 11 are socket operations that should pass `None`. 3 are poll/select/epoll that will get real deadlines in Task 6, but for now pass `None` to keep them compiling.

Update each of these lines by appending `, None` as the third argument:

| Line | Before | After |
|------|--------|-------|
| 2797 | `self.block_until(BLOCK_OP_WRITABLE, fd)` | `self.block_until(BLOCK_OP_WRITABLE, fd, None)` |
| 3757 | `self.block_until(BLOCK_OP_WRITABLE, fd)` | `self.block_until(BLOCK_OP_WRITABLE, fd, None)` |
| 3847 | `self.block_until(BLOCK_OP_READABLE, fd)` | `self.block_until(BLOCK_OP_READABLE, fd, None)` |
| 3977 | `self.block_until(BLOCK_OP_READABLE, fd)` | `self.block_until(BLOCK_OP_READABLE, fd, None)` |
| 4952 | `self.block_until(BLOCK_OP_READABLE, fd)` | `self.block_until(BLOCK_OP_READABLE, fd, None)` |
| 5061 | `self.block_until(BLOCK_OP_CONNECT, fd)` | `self.block_until(BLOCK_OP_CONNECT, fd, None)` |
| 5146 | `self.block_until(BLOCK_OP_WRITABLE, fd)` | `self.block_until(BLOCK_OP_WRITABLE, fd, None)` |
| 5186 | `self.block_until(BLOCK_OP_WRITABLE, fd)` | `self.block_until(BLOCK_OP_WRITABLE, fd, None)` |
| 5215 | `self.block_until(BLOCK_OP_WRITABLE, fd)` | `self.block_until(BLOCK_OP_WRITABLE, fd, None)` |
| 5271 | `self.block_until(BLOCK_OP_READABLE, fd)` | `self.block_until(BLOCK_OP_READABLE, fd, None)` |
| 5315 | `self.block_until(BLOCK_OP_READABLE, fd)` | `self.block_until(BLOCK_OP_READABLE, fd, None)` |
| 5793 | `self.block_until(BLOCK_OP_POLL, -1)` | `self.block_until(BLOCK_OP_POLL, -1, None)` |
| 8796 | `self.block_until(BLOCK_OP_POLL, -1)` | `self.block_until(BLOCK_OP_POLL, -1, None)` |
| 9001 | `self.block_until(BLOCK_OP_POLL, -1)` | `self.block_until(BLOCK_OP_POLL, -1, None)` |

- [ ] **Step 7: Update the fork/clone snapshot**

In the fork/clone method that copies callbacks to the child (around lines 6266-6273), add the two new fields:

```rust
            block_fn: self.block_fn,
            wake_fn: self.wake_fn,
            spawn_fn: self.spawn_fn,
            futex_block_fn: self.futex_block_fn,
            futex_wake_fn: self.futex_wake_fn,
            was_timeout_fn: self.was_timeout_fn,
            now_ms_fn: self.now_ms_fn,
            get_current_tid_fn: self.get_current_tid_fn,
            set_clear_child_tid_fn: self.set_clear_child_tid_fn,
```

- [ ] **Step 8: Update existing tests that use block_fn and futex_block_fn**

In `block_until_calls_block_fn` test (around line 18210), update the closure and call:
```rust
    #[test]
    fn block_until_calls_block_fn() {
        use core::sync::atomic::{AtomicBool, Ordering};

        let mut lx = Linuxulator::new(MockBackend::new());
        static BLOCK_CALLED: AtomicBool = AtomicBool::new(false);

        lx.set_block_fn(|_op, _fd, _deadline| {
            BLOCK_CALLED.store(true, Ordering::SeqCst);
        });

        BLOCK_CALLED.store(false, Ordering::SeqCst);
        let result = lx.block_until(BLOCK_OP_READABLE, 5, None);
        assert!(BLOCK_CALLED.load(Ordering::SeqCst));
        assert_eq!(result, BlockResult::Ready);
    }
```

In `block_until_returns_interrupted_without_block_fn` test (around line 18227), update the call:
```rust
        let result = lx.block_until(BLOCK_OP_READABLE, 5, None);
```

In `futex_wait_blocks_when_value_matches` test (around line 12077), update the closure:
```rust
        lx.set_futex_block_fn(|_uaddr, _deadline| {
            BLOCKED.store(true, Ordering::SeqCst);
        });
```

- [ ] **Step 9: Wire callbacks in main.rs**

In `main.rs`, update the `set_block_fn` closure (around line 484):

```rust
        linuxulator.set_block_fn(|op, fd, deadline_ms| {
            let reason = match op {
                0 => sched::WaitReason::FdReadable(fd),
                1 => sched::WaitReason::FdWritable(fd),
                2 => sched::WaitReason::FdConnectDone(fd),
                3 => sched::WaitReason::PollWait,
                4 => sched::WaitReason::Sleep,
                _ => unreachable!(),
            };
            unsafe { sched::block_current(reason, deadline_ms) };
        });
```

Update `set_futex_block_fn` closure (around line 525):

```rust
        linuxulator.set_futex_block_fn(|uaddr, deadline_ms| {
            unsafe { sched::block_current(sched::WaitReason::Futex(uaddr), deadline_ms) };
        });
```

Add the two new callback wiring after `set_clear_child_tid_fn` (around line 538):

```rust
        // Timeout detection callback — reads and clears the woken_by_timeout flag.
        linuxulator.set_was_timeout_fn(|| unsafe { sched::consume_woken_by_timeout() });

        // Monotonic clock callback — used by linuxulator to compute deadlines.
        linuxulator.set_now_ms_fn(|| timer::now_ms());
```

- [ ] **Step 10: Run all tests**

Run: `cargo test --workspace`
Expected: All tests pass. The linuxulator tests compile with updated callback signatures, and the sched tests compile with the updated block_current call.

- [ ] **Step 11: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs crates/harmony-boot-aarch64/src/main.rs
git commit -m "feat: wire deadline-aware callbacks between linuxulator and scheduler

- block_fn and futex_block_fn now accept Option<u64> deadline parameter
- New was_timeout_fn and now_ms_fn callbacks for timeout detection
  and clock reading
- block_until forwards deadline to block_fn
- All existing callers pass None (real deadlines added in next commits)
- BLOCK_OP_SLEEP = 4 for nanosleep/clock_nanosleep
- Fork/clone snapshot includes new callbacks
- Main.rs closures updated to forward deadlines to sched::block_current"
```

---

### Task 4: sys_futex Timeout Support

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

This task wires the currently-ignored `_timeout` parameter in `sys_futex(FUTEX_WAIT)` to compute a deadline, pass it through `futex_block_fn`, and return `ETIMEDOUT` when the wake was a timeout.

- [ ] **Step 1: Write failing tests**

Add these tests after the existing `futex_wake_calls_wake_fn` test (after line 12103 in linuxulator.rs):

```rust
    #[test]
    fn futex_wait_timeout_returns_etimedout() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        static BLOCKED: AtomicBool = AtomicBool::new(false);
        lx.set_futex_block_fn(|_uaddr, _deadline| {
            BLOCKED.store(true, Ordering::SeqCst);
        });
        // was_timeout returns true — simulates timer IRQ waking via deadline
        lx.set_was_timeout_fn(|| true);
        // now_ms returns 1000
        lx.set_now_ms_fn(|| 1000);

        let mut val: u32 = 42;
        let uaddr = &mut val as *mut u32 as u64;

        // Build a timespec: 1 second, 0 nanoseconds
        let ts = [1i64.to_le_bytes(), 0i64.to_le_bytes()].concat();
        let timeout_ptr = ts.as_ptr() as u64;

        BLOCKED.store(false, Ordering::SeqCst);
        let result = lx.sys_futex(uaddr, 0, 42, timeout_ptr);
        assert!(BLOCKED.load(Ordering::SeqCst));
        assert_eq!(result, -110); // ETIMEDOUT
    }

    #[test]
    fn futex_wait_no_timeout_returns_zero() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        static BLOCKED: AtomicBool = AtomicBool::new(false);
        lx.set_futex_block_fn(|_uaddr, _deadline| {
            BLOCKED.store(true, Ordering::SeqCst);
        });
        // was_timeout returns false — normal wake
        lx.set_was_timeout_fn(|| false);

        let mut val: u32 = 42;
        let uaddr = &mut val as *mut u32 as u64;

        BLOCKED.store(false, Ordering::SeqCst);
        // timeout = 0 (null pointer) → no timeout
        let result = lx.sys_futex(uaddr, 0, 42, 0);
        assert!(BLOCKED.load(Ordering::SeqCst));
        assert_eq!(result, 0);
    }

    #[test]
    fn futex_wait_null_timeout_passes_none_deadline() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Track what deadline was passed to futex_block_fn.
        // Use u64::MAX as sentinel for "was called with None".
        static DEADLINE_SEEN: AtomicU64 = AtomicU64::new(0);
        lx.set_futex_block_fn(|_uaddr, deadline| {
            DEADLINE_SEEN.store(deadline.unwrap_or(u64::MAX), Ordering::SeqCst);
        });
        lx.set_was_timeout_fn(|| false);

        let mut val: u32 = 42;
        let uaddr = &mut val as *mut u32 as u64;

        DEADLINE_SEEN.store(0, Ordering::SeqCst);
        let _ = lx.sys_futex(uaddr, 0, 42, 0); // null timeout
        assert_eq!(DEADLINE_SEEN.load(Ordering::SeqCst), u64::MAX); // None
    }

    #[test]
    fn futex_wait_timeout_computes_deadline() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        static DEADLINE_SEEN: AtomicU64 = AtomicU64::new(0);
        lx.set_futex_block_fn(|_uaddr, deadline| {
            DEADLINE_SEEN.store(deadline.unwrap_or(u64::MAX), Ordering::SeqCst);
        });
        lx.set_was_timeout_fn(|| false);
        lx.set_now_ms_fn(|| 500); // current time = 500ms

        let mut val: u32 = 42;
        let uaddr = &mut val as *mut u32 as u64;

        // Build timespec: 2 seconds, 500_000_000 nanoseconds = 2500ms
        let ts = [2i64.to_le_bytes(), 500_000_000i64.to_le_bytes()].concat();
        let timeout_ptr = ts.as_ptr() as u64;

        DEADLINE_SEEN.store(0, Ordering::SeqCst);
        let _ = lx.sys_futex(uaddr, 0, 42, timeout_ptr);
        // Deadline should be 500 + 2500 = 3000ms
        assert_eq!(DEADLINE_SEEN.load(Ordering::SeqCst), 3000);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os -- futex_wait_timeout futex_wait_no_timeout futex_wait_null_timeout`
Expected: Tests fail — the implementation still ignores the timeout parameter.

- [ ] **Step 3: Implement sys_futex timeout logic**

Replace the `FUTEX_WAIT` arm in `sys_futex` (around lines 8715-8741):

```rust
            FUTEX_WAIT => {
                if uaddr == 0 {
                    return EFAULT;
                }
                // Parse timeout: _timeout is a pointer to struct timespec
                // { i64 tv_sec; i64 tv_nsec }, or 0 (null) for no timeout.
                // FUTEX_WAIT timeouts are relative (not absolute).
                let deadline_ms: Option<u64> = if _timeout != 0 && self.now_ms_fn.is_some() {
                    let ts_bytes = unsafe {
                        core::slice::from_raw_parts(_timeout as *const u8, 16)
                    };
                    let tv_sec = i64::from_le_bytes(ts_bytes[0..8].try_into().unwrap());
                    let tv_nsec = i64::from_le_bytes(ts_bytes[8..16].try_into().unwrap());
                    if tv_sec < 0 || !(0..1_000_000_000).contains(&tv_nsec) {
                        return EINVAL;
                    }
                    let timeout_ms = (tv_sec as u64)
                        .saturating_mul(1000)
                        .saturating_add((tv_nsec as u64) / 1_000_000);
                    let now = (self.now_ms_fn.unwrap())();
                    Some(now.saturating_add(timeout_ms))
                } else {
                    None
                };

                // Atomicity note: the read-compare-block sequence is safe on
                // single-core because SVC entry masks IRQs (PSTATE.I=1). No
                // other task can run between the value check and block_fn
                // (which calls block_current, which unmasks IRQs AFTER marking
                // the task Blocked). On multi-core this would need a spinlock.
                let current = unsafe { *(uaddr as *const u32) };
                if current != val {
                    return EAGAIN;
                }
                if let Some(block) = self.futex_block_fn {
                    block(uaddr, deadline_ms);
                    // Check if we were woken by timeout expiry.
                    if let Some(was_timeout) = self.was_timeout_fn {
                        if was_timeout() {
                            return ETIMEDOUT;
                        }
                    }
                    0 // Woken normally
                } else {
                    EAGAIN // No scheduler — can't block
                }
            }
```

Also add the `ETIMEDOUT` constant near the other errno constants at the top of the file. Search for existing `const EFAULT` or similar — it should be near the other errno definitions. Add:

```rust
const ETIMEDOUT: i64 = -110;
```

- [ ] **Step 4: Rename _timeout parameter**

Change the function signature from `_timeout: u64` to `timeout: u64` since it's no longer unused:

```rust
    fn sys_futex(&mut self, uaddr: u64, op: i32, val: u32, timeout: u64) -> i64 {
```

And update the reference from `_timeout` to `timeout` in the body.

- [ ] **Step 5: Run all tests**

Run: `cargo test -p harmony-os -- futex`
Expected: All futex tests pass, including the 4 new ones.

Run: `cargo test --workspace`
Expected: Full workspace passes.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(futex): wire FUTEX_WAIT timeout via deadline_ms

Parse the timeout pointer as struct timespec, compute an absolute
deadline in milliseconds, and pass it through futex_block_fn. After
wake, check was_timeout_fn and return ETIMEDOUT (-110) if the task
was woken by deadline expiry rather than FUTEX_WAKE."
```

---

### Task 5: sys_nanosleep / sys_clock_nanosleep Real Blocking

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

This task replaces the current "advance clock, return immediately" implementation with real blocking via `block_fn(BLOCK_OP_SLEEP, -1, deadline_ms)` when a scheduler is available. The sans-I/O fallback (no scheduler) preserves the existing clock-advance behavior for host tests.

- [ ] **Step 1: Write failing tests**

Add these tests in the test module (after the existing nanosleep-related tests, or at the end of the test module):

```rust
    #[test]
    fn nanosleep_blocks_with_correct_deadline() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let mut lx = Linuxulator::new(MockBackend::new());

        static DEADLINE_SEEN: AtomicU64 = AtomicU64::new(0);
        static OP_SEEN: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(255);

        lx.set_block_fn(|op, _fd, deadline| {
            OP_SEEN.store(op, Ordering::SeqCst);
            DEADLINE_SEEN.store(deadline.unwrap_or(u64::MAX), Ordering::SeqCst);
        });
        lx.set_now_ms_fn(|| 1000); // current time = 1000ms

        // nanosleep(500ms)
        let ts = [0i64.to_le_bytes(), 500_000_000i64.to_le_bytes()].concat();
        let req_ptr = ts.as_ptr() as u64;

        DEADLINE_SEEN.store(0, Ordering::SeqCst);
        OP_SEEN.store(255, Ordering::SeqCst);
        let result = lx.sys_nanosleep(req_ptr, 0);
        assert_eq!(result, 0);
        assert_eq!(OP_SEEN.load(Ordering::SeqCst), BLOCK_OP_SLEEP);
        assert_eq!(DEADLINE_SEEN.load(Ordering::SeqCst), 1500); // 1000 + 500
    }

    #[test]
    fn clock_nanosleep_abstime_uses_raw_value() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let mut lx = Linuxulator::new(MockBackend::new());

        static DEADLINE_SEEN: AtomicU64 = AtomicU64::new(0);

        lx.set_block_fn(|_op, _fd, deadline| {
            DEADLINE_SEEN.store(deadline.unwrap_or(u64::MAX), Ordering::SeqCst);
        });
        lx.set_now_ms_fn(|| 1000);

        // clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, 3 seconds)
        let ts = [3i64.to_le_bytes(), 0i64.to_le_bytes()].concat();
        let req_ptr = ts.as_ptr() as u64;

        DEADLINE_SEEN.store(0, Ordering::SeqCst);
        // clockid=1 (CLOCK_MONOTONIC), flags=1 (TIMER_ABSTIME)
        let result = lx.sys_clock_nanosleep(1, 1, req_ptr, 0);
        assert_eq!(result, 0);
        assert_eq!(DEADLINE_SEEN.load(Ordering::SeqCst), 3000); // 3 seconds = 3000ms
    }

    #[test]
    fn nanosleep_falls_back_without_block_fn() {
        let mut lx = Linuxulator::new(MockBackend::new());
        // No block_fn set — should fall back to clock advance behavior.

        let ts = [0i64.to_le_bytes(), 500_000_000i64.to_le_bytes()].concat();
        let req_ptr = ts.as_ptr() as u64;

        let result = lx.sys_nanosleep(req_ptr, 0);
        assert_eq!(result, 0);
        // monotonic_ns should have advanced by 500ms
        assert_eq!(lx.monotonic_ns, 500_000_000);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os -- nanosleep_blocks clock_nanosleep_abstime nanosleep_falls_back`
Expected: Tests fail — nanosleep doesn't call block_fn yet.

- [ ] **Step 3: Implement real blocking in sys_clock_nanosleep**

Replace `sys_clock_nanosleep` (around lines 6569-6639) with:

```rust
    fn sys_clock_nanosleep(
        &mut self,
        clockid: i32,
        flags: i32,
        req_ptr: u64,
        _rem_ptr: u64,
    ) -> i64 {
        if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
            return EINVAL;
        }

        const TIMER_ABSTIME: i32 = 1;
        if flags & !TIMER_ABSTIME != 0 {
            return EINVAL;
        }

        if req_ptr == 0 {
            return EFAULT;
        }
        let req_bytes = unsafe { core::slice::from_raw_parts(req_ptr as usize as *const u8, 16) };
        let tv_sec = i64::from_le_bytes(req_bytes[0..8].try_into().unwrap());
        let tv_nsec = i64::from_le_bytes(req_bytes[8..16].try_into().unwrap());
        if tv_sec < 0 || !(0..1_000_000_000).contains(&tv_nsec) {
            return EINVAL;
        }

        // If scheduler + clock are available, do a real blocking sleep.
        if self.block_fn.is_some() && self.now_ms_fn.is_some() {
            let now_ms = (self.now_ms_fn.unwrap())();
            let deadline_ms = if flags & TIMER_ABSTIME != 0 {
                // Absolute: convert timespec to ms directly.
                let abs_ms = (tv_sec as u64)
                    .saturating_mul(1000)
                    .saturating_add((tv_nsec as u64) / 1_000_000);
                // If target is already in the past, return immediately.
                if abs_ms <= now_ms {
                    return 0;
                }
                abs_ms
            } else {
                // Relative: deadline = now + duration.
                let duration_ms = (tv_sec as u64)
                    .saturating_mul(1000)
                    .saturating_add((tv_nsec as u64) / 1_000_000);
                if duration_ms == 0 {
                    return 0;
                }
                now_ms.saturating_add(duration_ms)
            };
            self.block_until(BLOCK_OP_SLEEP, -1, Some(deadline_ms));
            return 0;
        }

        // Fallback: sans-I/O mode (no scheduler). Advance the clock by the
        // requested duration and return immediately. Host tests rely on this.
        if flags & TIMER_ABSTIME != 0 {
            let abs_ns = (tv_sec as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add(tv_nsec as u64);
            let now = match clockid {
                CLOCK_REALTIME => self.realtime_ns,
                _ => self.monotonic_ns,
            };
            let delta_ns = abs_ns.saturating_sub(now);
            match clockid {
                CLOCK_REALTIME => {
                    self.realtime_ns = self.realtime_ns.wrapping_add(delta_ns);
                }
                _ => {
                    self.monotonic_ns = self.monotonic_ns.wrapping_add(delta_ns);
                }
            }
        } else {
            let duration_ns = (tv_sec as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add(tv_nsec as u64);
            match clockid {
                CLOCK_REALTIME => {
                    self.realtime_ns = self.realtime_ns.wrapping_add(duration_ns);
                }
                _ => {
                    self.monotonic_ns = self.monotonic_ns.wrapping_add(duration_ns);
                }
            }
        }
        0
    }
```

- [ ] **Step 4: Run all tests**

Run: `cargo test -p harmony-os -- nanosleep clock_nanosleep`
Expected: All nanosleep tests pass (new and existing).

Run: `cargo test --workspace`
Expected: Full workspace passes.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(nanosleep): real blocking sleep via scheduler deadline

When block_fn and now_ms_fn are set, nanosleep/clock_nanosleep
computes an absolute deadline and blocks via BLOCK_OP_SLEEP.
The timer IRQ check_deadlines wakes the task at the deadline.
Falls back to clock-advance behavior when no scheduler is available
(preserving host test semantics)."
```

---

### Task 6: poll/select/epoll Deadline Pass-Through

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

This task passes the already-computed deadline through `block_until` for poll, select, and epoll_wait, so the timer IRQ can wake these syscalls at their timeout even when no network event occurs.

- [ ] **Step 1: Write failing tests**

Add these tests in the test module:

```rust
    #[test]
    fn poll_passes_deadline_to_block_fn() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let mut lx = Linuxulator::new(MockBackend::new());

        static DEADLINE_SEEN: AtomicU64 = AtomicU64::new(0);
        // block_fn records the deadline. Only called once — first wake
        // triggers a timeout check that exits the loop.
        lx.set_block_fn(|_op, _fd, deadline| {
            DEADLINE_SEEN.store(deadline.unwrap_or(u64::MAX), Ordering::SeqCst);
        });
        lx.set_poll_fn(|| 1000); // always returns 1000ms (triggers timeout on re-check)
        lx.set_now_ms_fn(|| 1000);

        // Build a pollfd for a non-existent fd (will never be ready).
        // struct pollfd { int fd; short events; short revents; }
        let mut pollfd = [0u8; 8];
        pollfd[0..4].copy_from_slice(&999i32.to_ne_bytes()); // fd=999
        pollfd[4..6].copy_from_slice(&1i16.to_ne_bytes()); // POLLIN
        pollfd[6..8].copy_from_slice(&0i16.to_ne_bytes()); // revents=0
        let fds_ptr = pollfd.as_mut_ptr() as u64;

        DEADLINE_SEEN.store(0, Ordering::SeqCst);
        let _result = lx.sys_poll(fds_ptr, 1, 200); // 200ms timeout
        // deadline should be 1000 + 200 = 1200
        assert_eq!(DEADLINE_SEEN.load(Ordering::SeqCst), 1200);
    }

    #[test]
    fn poll_infinite_timeout_passes_none_deadline() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let mut lx = Linuxulator::new(MockBackend::new());

        static DEADLINE_SEEN: AtomicU64 = AtomicU64::new(0);
        lx.set_block_fn(|_op, _fd, deadline| {
            DEADLINE_SEEN.store(deadline.unwrap_or(u64::MAX), Ordering::SeqCst);
        });
        lx.set_poll_fn(|| 1000);
        lx.set_now_ms_fn(|| 1000);

        let mut pollfd = [0u8; 8];
        pollfd[0..4].copy_from_slice(&999i32.to_ne_bytes());
        pollfd[4..6].copy_from_slice(&1i16.to_ne_bytes());
        pollfd[6..8].copy_from_slice(&0i16.to_ne_bytes());
        let fds_ptr = pollfd.as_mut_ptr() as u64;

        DEADLINE_SEEN.store(0, Ordering::SeqCst);
        let _result = lx.sys_poll(fds_ptr, 1, -1); // infinite timeout
        // Should pass None → sentinel u64::MAX
        assert_eq!(DEADLINE_SEEN.load(Ordering::SeqCst), u64::MAX);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os -- poll_passes_deadline poll_infinite_timeout_passes_none`
Expected: Tests fail — block_until still passes `None` for poll.

- [ ] **Step 3: Pass deadline through block_until in sys_poll**

In `sys_poll` (around lines 8780-8813), the blocking path already computes a `deadline`. Lift it out and pass it through `block_until`. Replace the blocking section:

```rust
        // Blocking path: check readiness first, then yield if not ready.
        if self.block_fn.is_some() {
            // Initial check — return immediately if fds are already ready.
            let ready = self.poll_check_once(fds_ptr, nfds);
            if ready > 0 {
                return ready;
            }

            let start_ms = self.poll_fn.map_or(0, |pf| pf());
            let deadline = if timeout_ms > 0 {
                start_ms.saturating_add(timeout_ms as u64)
            } else {
                u64::MAX // Negative timeout = infinite wait
            };

            // Convert to Option for block_until: u64::MAX means no deadline.
            let deadline_opt = if deadline == u64::MAX { None } else { Some(deadline) };

            loop {
                match self.block_until(BLOCK_OP_POLL, -1, deadline_opt) {
                    BlockResult::Ready => {
                        let ready = self.poll_check_once(fds_ptr, nfds);
                        if ready > 0 {
                            return ready;
                        }
                        // Check timeout.
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
            // No scheduler — do one check and return.
            self.poll_check_once(fds_ptr, nfds)
        }
```

- [ ] **Step 4: Pass deadline through block_until in epoll_wait**

In the `epoll_wait` blocking section (around lines 5785-5811), apply the same pattern:

```rust
        if ready_count == 0 && timeout != 0 && self.block_fn.is_some() {
            let start_ms = self.poll_fn.map_or(0, |pf| pf());
            let deadline: u64 = if timeout > 0 {
                start_ms.saturating_add(timeout as u64)
            } else {
                u64::MAX // -1 = infinite wait
            };

            let deadline_opt = if deadline == u64::MAX { None } else { Some(deadline) };

            while let BlockResult::Ready = self.block_until(BLOCK_OP_POLL, -1, deadline_opt) {
```

The rest of the loop body stays the same.

- [ ] **Step 5: Pass deadline through block_until in select**

In the `select` blocking section (around lines 8968-9021), apply the same pattern:

```rust
        if self.block_fn.is_some() {
            // Initial check — return immediately if fds are already ready.
            let ready = self.select_check_once(nfds, readfds, writefds, exceptfds);
            if ready > 0 {
                return ready;
            }

            let start_ms = self.poll_fn.map_or(0, |pf| pf());
            let deadline = if timeout_ms == u64::MAX {
                u64::MAX // NULL timeout = infinite wait
            } else {
                start_ms.saturating_add(timeout_ms)
            };

            let deadline_opt = if deadline == u64::MAX { None } else { Some(deadline) };

            loop {
                // Restore input fd_sets before each check (previous iteration may have cleared bits).
```

And then in the `match` arm:

```rust
                match self.block_until(BLOCK_OP_POLL, -1, deadline_opt) {
```

The rest stays the same.

- [ ] **Step 6: Run all tests**

Run: `cargo test -p harmony-os -- poll_ select_ epoll_`
Expected: All poll/select/epoll tests pass, including the 2 new ones.

Run: `cargo test --workspace`
Expected: Full workspace passes.

- [ ] **Step 7: Run clippy and format**

Run: `cargo clippy --workspace`
Run: `cargo +nightly fmt --all`

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(poll/select/epoll): pass deadline through block_until

poll, select, and epoll_wait now pass their computed deadline to
block_until, which forwards it to block_fn → sched::block_current.
The timer IRQ check_deadlines wakes these tasks at their timeout
even when no network event fires. Infinite timeouts pass None."
```
