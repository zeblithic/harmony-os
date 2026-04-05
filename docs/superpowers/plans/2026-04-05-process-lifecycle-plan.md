# Process Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix process exit (exit_group from spawned thread, main-thread SYS_EXIT promoted to exit_group) and add blocking wait4, so timed syscalls and process lifecycle work correctly on harmony-os.

**Architecture:** Three changes: (1) `redirect_main_thread_to_boot()` in sched.rs patches the main thread's saved TrapFrame via TCB kernel_sp when a spawned thread calls exit_group; (2) the dispatch function in main.rs promotes main-thread SYS_EXIT to exit_group; (3) `WaitReason::WaitChild(pid)` and `wake_waiting_parent(child_pid)` in sched.rs enable blocking wait4 in the linuxulator.

**Tech Stack:** Rust, `no_std`, aarch64 bare metal, harmony-os scheduler

---

## File Map

| File | Role | Changes |
|------|------|---------|
| `crates/harmony-boot-aarch64/src/sched.rs` | Scheduler: task states, wake/block/dead | Add `WaitReason::WaitChild`, `wake_waiting_parent`, `redirect_main_thread_to_boot` |
| `crates/harmony-boot-aarch64/src/syscall.rs` | SVC handler: exit paths | Fix spawned-thread exit_group (TrapFrame patching), add `wake_waiting_parent` calls |
| `crates/harmony-boot-aarch64/src/main.rs` | Boot: callback wiring, dispatch fn | Promote main-thread SYS_EXIT to exit_group, add BLOCK_OP_WAIT decode, add WaitChild match arm |
| `crates/harmony-os/src/linuxulator.rs` | Linux syscall emulation | Add BLOCK_OP_WAIT constant, modify sys_wait4 to block |

---

### Task 1: Scheduler — WaitReason::WaitChild and wake_waiting_parent

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/sched.rs:56-71` (WaitReason enum)
- Modify: `crates/harmony-boot-aarch64/src/sched.rs` (new function after `futex_wake`, ~line 709)
- Test: `crates/harmony-boot-aarch64/src/sched.rs` (test module, after line 1300)

- [ ] **Step 1: Write failing tests for wake_waiting_parent**

Add these tests at the end of the `mod tests` block in `sched.rs` (before the closing `}`), after the `normal_wake_clears_deadline_and_flag` test at line 1300:

```rust
    // ── WaitChild / wake_waiting_parent tests ───────────────────────────────

    #[test]
    fn wake_waiting_parent_wakes_any_child() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            // Task 0: parent blocked waiting for any child (-1).
            put_tcb(0, TaskState::Blocked, Some(WaitReason::WaitChild(-1)));
            NUM_TASKS = 1;

            wake_waiting_parent(42); // child pid = 42

            let t0 = TASKS[0].assume_init_ref();
            assert_eq!(t0.state, TaskState::Ready);
            assert_eq!(t0.wait_reason, None);
            assert_eq!(t0.deadline_ms, None);

            NUM_TASKS = 0;
        }
    }

    #[test]
    fn wake_waiting_parent_matches_specific_pid() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            // Task 0: parent waiting for child pid=5 specifically.
            put_tcb(0, TaskState::Blocked, Some(WaitReason::WaitChild(5)));
            NUM_TASKS = 1;

            // Wrong pid — should NOT wake.
            wake_waiting_parent(3);
            assert_eq!(TASKS[0].assume_init_ref().state, TaskState::Blocked);

            // Correct pid — should wake.
            wake_waiting_parent(5);
            assert_eq!(TASKS[0].assume_init_ref().state, TaskState::Ready);
            assert_eq!(TASKS[0].assume_init_ref().wait_reason, None);

            NUM_TASKS = 0;
        }
    }

    #[test]
    fn wake_waiting_parent_ignores_non_waiting_tasks() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Ready, None);
            put_tcb(1, TaskState::Dead, None);
            put_tcb(2, TaskState::Blocked, Some(WaitReason::Futex(0x1000)));
            NUM_TASKS = 3;

            wake_waiting_parent(10);

            // All unchanged.
            assert_eq!(TASKS[0].assume_init_ref().state, TaskState::Ready);
            assert_eq!(TASKS[1].assume_init_ref().state, TaskState::Dead);
            assert_eq!(TASKS[2].assume_init_ref().state, TaskState::Blocked);
            assert_eq!(
                TASKS[2].assume_init_ref().wait_reason,
                Some(WaitReason::Futex(0x1000))
            );

            NUM_TASKS = 0;
        }
    }

    #[test]
    fn wake_waiting_parent_only_wakes_first_match() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            // Two parents both waiting for any child. Only the first should wake.
            put_tcb(0, TaskState::Blocked, Some(WaitReason::WaitChild(-1)));
            put_tcb(1, TaskState::Blocked, Some(WaitReason::WaitChild(-1)));
            NUM_TASKS = 2;

            wake_waiting_parent(7);

            assert_eq!(TASKS[0].assume_init_ref().state, TaskState::Ready);
            assert_eq!(TASKS[1].assume_init_ref().state, TaskState::Blocked);

            NUM_TASKS = 0;
        }
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-boot-aarch64 wake_waiting_parent 2>&1 | head -30`
Expected: Compilation errors — `WaitReason::WaitChild` and `wake_waiting_parent` don't exist yet.

- [ ] **Step 3: Add WaitChild variant to WaitReason**

In `sched.rs`, add the new variant to the `WaitReason` enum (after `Sleep` at line 70):

```rust
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
    /// Waiting on a futex word at this address.
    Futex(u64),
    /// Pure time wait — woken by the timer IRQ when deadline_ms expires.
    Sleep,
    /// Waiting for a child process to exit (wait4/waitpid).
    /// -1 = any child, >0 = specific child PID.
    WaitChild(i32),
}
```

- [ ] **Step 4: Add wake_waiting_parent function**

Add this function after `futex_wake` (after line 709):

```rust
/// Wake a parent task blocked in wait4 for the given child PID.
///
/// Scans all tasks for one that is `Blocked` with `WaitReason::WaitChild(target)`
/// where `target == -1` (any child) or `target == child_pid as i32`. Wakes
/// the first match only — a parent can only be blocked in one wait4 at a time.
///
/// Called from the exit path in syscall.rs when a child process or
/// the last thread of a process exits.
///
/// O(MAX_TASKS) scan, same cost as `check_deadlines`.
///
/// # Safety
///
/// Must only be called when TASKS[0..NUM_TASKS] are initialized.
pub unsafe fn wake_waiting_parent(child_pid: u32) {
    let n = NUM_TASKS;
    for i in 0..n {
        let tcb = TASKS[i].assume_init_mut();
        if tcb.state == TaskState::Blocked {
            if let Some(WaitReason::WaitChild(target)) = tcb.wait_reason {
                if target == -1 || target == child_pid as i32 {
                    tcb.state = TaskState::Ready;
                    tcb.wait_reason = None;
                    tcb.deadline_ms = None;
                    return;
                }
            }
        }
    }
}
```

- [ ] **Step 5: Fix compilation — add WaitChild arm to check_and_wake_blocked_tasks in main.rs**

In `main.rs`, the `check_and_wake_blocked_tasks` function (line 1247) uses `for_each_blocked` with a match on `WaitReason`. Add a `WaitChild` arm after the `Sleep` arm (after line 1283):

```rust
                sched::WaitReason::WaitChild(_) => {
                    // WaitChild tasks are woken by wake_waiting_parent() when a
                    // child exits. The system task has nothing to do here.
                }
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p harmony-boot-aarch64 wake_waiting_parent`
Expected: All 4 tests pass.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-boot-aarch64/src/sched.rs crates/harmony-boot-aarch64/src/main.rs
git commit -m "feat(sched): add WaitReason::WaitChild and wake_waiting_parent

Adds WaitChild(i32) variant for wait4 blocking (-1 = any child, >0 =
specific PID). wake_waiting_parent() scans tasks and wakes the first
matching parent. Adds WaitChild arm in check_and_wake_blocked_tasks."
```

---

### Task 2: Scheduler — redirect_main_thread_to_boot

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/sched.rs` (new function after `wake_waiting_parent`)
- Test: `crates/harmony-boot-aarch64/src/sched.rs` (test module)

- [ ] **Step 1: Write failing tests for redirect_main_thread_to_boot**

Add these tests at the end of the `mod tests` block in `sched.rs`:

```rust
    // ── redirect_main_thread_to_boot tests ──────────────────────────────────

    #[test]
    fn redirect_main_thread_patches_trapframe() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            // Allocate a TrapFrame on the heap to simulate a kernel stack.
            let frame = Box::new(TrapFrame {
                x: [0u64; 31],
                elr: 0xDEAD,
                spsr: 0,
                fpcr: 0,
                fpsr: 0,
                _pad: 0,
                q: [0u128; 32],
            });
            let frame_ptr = Box::into_raw(frame);

            // Task 0 (current, spawned thread) — pid=2, tid=3.
            put_tcb(0, TaskState::Running, None);
            TASKS[0].assume_init_mut().pid = 2;
            TASKS[0].assume_init_mut().tid = 3;

            // Task 1 (main thread) — pid=2, tid=0, Dead (killed by kill_threads_by_pid).
            put_tcb(1, TaskState::Dead, None);
            TASKS[1].assume_init_mut().pid = 2;
            TASKS[1].assume_init_mut().tid = 0;
            TASKS[1].assume_init_mut().kernel_sp = frame_ptr as usize;

            NUM_TASKS = 2;
            CURRENT = 0;

            redirect_main_thread_to_boot(2, 42, 0xB007, 0x5500, 0x1200);

            // Main thread's TrapFrame should be patched.
            let patched = &*frame_ptr;
            assert_eq!(patched.elr, 0xB007);
            assert_eq!(patched.x[0], 42); // exit_code
            assert_eq!(patched.x[1], 0x5500); // ret_sp
            assert_eq!(patched.x[2], 0x1200); // ret_lr

            // Main thread should be Ready now.
            assert_eq!(TASKS[1].assume_init_ref().state, TaskState::Ready);
            assert_eq!(TASKS[1].assume_init_ref().wait_reason, None);
            assert_eq!(TASKS[1].assume_init_ref().deadline_ms, None);

            // Clean up.
            let _ = Box::from_raw(frame_ptr);
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn redirect_main_thread_skips_current_task() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            let frame = Box::new(TrapFrame {
                x: [0u64; 31],
                elr: 0xAAAA,
                spsr: 0,
                fpcr: 0,
                fpsr: 0,
                _pad: 0,
                q: [0u128; 32],
            });
            let frame_ptr = Box::into_raw(frame);

            // Task 0 is CURRENT, pid=2, tid=0 — should be skipped even though
            // it matches pid and tid==0, because it's the calling task.
            put_tcb(0, TaskState::Running, None);
            TASKS[0].assume_init_mut().pid = 2;
            TASKS[0].assume_init_mut().tid = 0;
            TASKS[0].assume_init_mut().kernel_sp = frame_ptr as usize;

            NUM_TASKS = 1;
            CURRENT = 0;

            redirect_main_thread_to_boot(2, 1, 0xB007, 0x5500, 0x1100);

            // TrapFrame should NOT be patched — task was skipped.
            let patched = &*frame_ptr;
            assert_eq!(patched.elr, 0xAAAA);

            // Task should still be Running.
            assert_eq!(TASKS[0].assume_init_ref().state, TaskState::Running);

            let _ = Box::from_raw(frame_ptr);
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn redirect_main_thread_skips_wrong_pid() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            let frame = Box::new(TrapFrame {
                x: [0u64; 31],
                elr: 0xBBBB,
                spsr: 0,
                fpcr: 0,
                fpsr: 0,
                _pad: 0,
                q: [0u128; 32],
            });
            let frame_ptr = Box::into_raw(frame);

            // Task 0 (current) — pid=2, tid=3.
            put_tcb(0, TaskState::Running, None);
            TASKS[0].assume_init_mut().pid = 2;
            TASKS[0].assume_init_mut().tid = 3;

            // Task 1 — pid=9 (wrong), tid=0.
            put_tcb(1, TaskState::Dead, None);
            TASKS[1].assume_init_mut().pid = 9;
            TASKS[1].assume_init_mut().tid = 0;
            TASKS[1].assume_init_mut().kernel_sp = frame_ptr as usize;

            NUM_TASKS = 2;
            CURRENT = 0;

            redirect_main_thread_to_boot(2, 1, 0xB007, 0x5500, 0x1100);

            // TrapFrame should NOT be patched — wrong PID.
            let patched = &*frame_ptr;
            assert_eq!(patched.elr, 0xBBBB);
            assert_eq!(TASKS[1].assume_init_ref().state, TaskState::Dead);

            let _ = Box::from_raw(frame_ptr);
            NUM_TASKS = 0;
        }
    }

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-boot-aarch64 redirect_main_thread 2>&1 | head -20`
Expected: Compilation error — `redirect_main_thread_to_boot` doesn't exist.

- [ ] **Step 3: Implement redirect_main_thread_to_boot**

Add this function after `wake_waiting_parent` in `sched.rs`:

```rust
/// Redirect the main thread (tid==0) of a process to the boot return point.
///
/// Called by a spawned thread's exit_group path when it needs to redirect
/// the main thread to RETURN_ADDR. Finds the main thread's TCB (matching
/// `pid` and `tid == 0`, excluding CURRENT), follows `kernel_sp` to the
/// saved TrapFrame in memory, and patches:
/// - `elr` = `ret_addr` (boot code return point)
/// - `x[0]` = `exit_code`
/// - `x[1]` = `ret_sp` (saved kernel stack pointer)
/// - `x[2]` = `ret_lr` (saved kernel link register)
///
/// Marks the main thread `Ready` so the scheduler picks it up and erets
/// into the boot code.
///
/// No-op if no matching task is found (e.g., main thread already exited).
///
/// # Safety
///
/// - TASKS[0..NUM_TASKS] must be initialized.
/// - `ret_addr` must point to valid executable code.
/// - Must only be called from the SVC handler path (IRQs masked).
pub unsafe fn redirect_main_thread_to_boot(
    pid: u32,
    exit_code: i32,
    ret_addr: u64,
    ret_sp: u64,
    ret_lr: u64,
) {
    let n = NUM_TASKS;
    let cur = CURRENT;
    for i in 0..n {
        if i == cur {
            continue;
        }
        let tcb = TASKS[i].assume_init_mut();
        if tcb.pid == pid && tcb.tid == 0 {
            let frame = &mut *(tcb.kernel_sp as *mut crate::syscall::TrapFrame);
            frame.elr = ret_addr;
            frame.x[0] = exit_code as u64;
            frame.x[1] = ret_sp;
            frame.x[2] = ret_lr;
            tcb.state = TaskState::Ready;
            tcb.wait_reason = None;
            tcb.deadline_ms = None;
            return;
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-boot-aarch64 redirect_main_thread`
Expected: All 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-boot-aarch64/src/sched.rs
git commit -m "feat(sched): add redirect_main_thread_to_boot for exit_group

Scans tasks for the main thread (tid==0) of a given PID, patches its
saved TrapFrame to redirect ELR to boot code, and marks it Ready.
Used by spawned-thread exit_group to cleanly return control to boot."
```

---

### Task 3: Fix exit_group from spawned thread (syscall.rs)

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/syscall.rs:159-192` (spawned thread exit_group path)

This task modifies the `svc_handler` function's spawned-thread exit_group path to use `redirect_main_thread_to_boot` instead of just setting `PROCESS_EXITED = true`.

- [ ] **Step 1: Read the current spawned-thread exit_group code**

Read `crates/harmony-boot-aarch64/src/syscall.rs:154-193` to confirm the current code matches what we expect.

- [ ] **Step 2: Replace the spawned-thread exit_group path**

In `syscall.rs`, replace the spawned-thread exit_group block (lines 159-176, the `if result.exit_group && !PROCESS_EXITED` block and its associated comment) with:

```rust
                if result.exit_group {
                    // exit_group from a spawned thread: redirect the main
                    // thread to boot code via its saved TrapFrame.
                    PROCESS_EXITED = true;
                    EXIT_CODE = result.exit_code;
                    if RETURN_ADDR != 0 {
                        crate::sched::redirect_main_thread_to_boot(
                            pid,
                            result.exit_code,
                            RETURN_ADDR,
                            RETURN_SP,
                            RETURN_LR,
                        );
                    }
                }
```

This replaces the TODO comment with working code. The main thread's TrapFrame gets patched and the main thread is marked Ready, so the scheduler will eret into boot code on the next tick.

- [ ] **Step 3: Add wake_waiting_parent call to spawned-thread exit path**

After the `mark_current_dead()` call (line 183) and before the `core::arch::asm!("msr daifclr, #2")` line, add:

```rust
                crate::sched::wake_waiting_parent(pid);
```

This unblocks a parent process that may be waiting in wait4 for this child.

- [ ] **Step 4: Verify compilation**

Run: `cargo test -p harmony-boot-aarch64 --no-run 2>&1 | tail -5`
Expected: Compiles successfully.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-boot-aarch64/src/syscall.rs
git commit -m "fix(exit): spawned-thread exit_group redirects main thread via TrapFrame

Replaces the TODO(Phase 6) with redirect_main_thread_to_boot() which
patches the main thread's saved TrapFrame.elr to RETURN_ADDR and marks
it Ready. Also calls wake_waiting_parent() for wait4 support."
```

---

### Task 4: Promote main-thread SYS_EXIT to exit_group (main.rs + syscall.rs)

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/main.rs:552-574` (dispatch function)
- Modify: `crates/harmony-boot-aarch64/src/syscall.rs:196-205` (main thread exit TODO)

- [ ] **Step 1: Modify the dispatch function to promote SYS_EXIT from main thread**

In `main.rs`, the `dispatch` function at line 552 currently returns `exit_group: is_exit_group`. Change it so that when `is_exit` is true and the current task's `tid == 0`, it also sets `exit_group: true`:

```rust
        fn dispatch(syscall: LinuxSyscall) -> syscall::SyscallDispatchResult {
            let is_exit = matches!(syscall, LinuxSyscall::Exit { .. });
            let is_exit_group = matches!(syscall, LinuxSyscall::ExitGroup { .. });

            let lx = unsafe { LINUXULATOR.as_mut().unwrap() };
            let retval = lx.dispatch_syscall(syscall);

            if is_exit || is_exit_group {
                // Promote main-thread SYS_EXIT to exit_group: when the main
                // thread (tid=0) calls exit(), kill all sibling threads first.
                // This matches glibc/musl behavior (they emit exit_group).
                let promote_to_exit_group = is_exit
                    && unsafe { crate::sched::current_task_tid() } == 0;

                syscall::SyscallDispatchResult {
                    retval,
                    exited: true,
                    exit_code: lx.exit_code().unwrap_or(0),
                    exit_group: is_exit_group || promote_to_exit_group,
                }
            } else {
                syscall::SyscallDispatchResult {
                    retval,
                    exited: false,
                    exit_code: 0,
                    exit_group: false,
                }
            }
        }
```

- [ ] **Step 2: Remove the TODO comment and add wake_waiting_parent to main-thread exit path**

In `syscall.rs`, replace the TODO block at lines 196-205:

```rust
            // SYS_EXIT from main thread: per Linux semantics, only the
            // calling thread exits — other threads continue running.
            // We do NOT call kill_threads_by_pid here (exit_group
            // already handled that above for the exit_group case).
            //
            // TODO(Phase 6, harmony-os-g9i): the main thread still
            // redirects ELR to RETURN_ADDR below, which returns
            // control to boot code while spawned threads may still
            // be running. Correct behavior requires last-thread-exit
            // detection so the boot code is only notified when every
            // thread has exited.
```

With:

```rust
            // Main thread exit: the dispatch function in main.rs promotes
            // main-thread SYS_EXIT to exit_group, so by this point
            // kill_threads_by_pid has already been called above.
```

Also, add a `wake_waiting_parent` call before the ELR redirect block. After the `if !PROCESS_EXITED` block (around line 210) and before the `if RETURN_ADDR != 0` check, add:

```rust
            crate::sched::wake_waiting_parent(pid);
```

- [ ] **Step 3: Verify compilation and run existing tests**

Run: `cargo test -p harmony-boot-aarch64 --no-run 2>&1 | tail -5`
Expected: Compiles successfully.

Run: `cargo test -p harmony-boot-aarch64`
Expected: All existing tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-boot-aarch64/src/main.rs crates/harmony-boot-aarch64/src/syscall.rs
git commit -m "fix(exit): promote main-thread SYS_EXIT to exit_group

When the main thread (tid=0) calls SYS_EXIT, the dispatch function now
sets exit_group=true so kill_threads_by_pid runs before the ELR redirect.
Removes the second TODO(Phase 6) comment. Adds wake_waiting_parent()
calls to both exit paths for wait4 support."
```

---

### Task 5: Blocking wait4 in linuxulator

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs:93-97` (BLOCK_OP constants)
- Modify: `crates/harmony-os/src/linuxulator.rs:6464-6537` (sys_wait4)
- Modify: `crates/harmony-boot-aarch64/src/main.rs:484-494` (block_fn closure, BLOCK_OP decode)
- Test: `crates/harmony-os/src/linuxulator.rs` (test module)

- [ ] **Step 1: Write failing tests for blocking wait4**

Add these tests in the linuxulator test module, after the existing `test_wait4_consumes_child` test (after line 15361):

```rust
    // ── wait4 blocking tests ──────────────────────────────────────────

    #[test]
    fn test_wait4_wnohang_returns_zero_for_running_child() {
        let mut lx = Linuxulator::new(MockBackend::new());

        // Push a fake running child directly into the children vec.
        lx.children.push(super::ChildProcess {
            pid: 42,
            linuxulator: Linuxulator::new(MockBackend::new()),
        });

        let r = lx.dispatch_syscall(LinuxSyscall::Wait4 {
            pid: 42,
            wstatus: 0,
            options: 1, // WNOHANG
            rusage: 0,
        });
        // Child exists but hasn't exited → 0, not ECHILD.
        assert_eq!(r, 0);
    }

    #[test]
    fn test_wait4_any_child_wnohang_returns_zero_for_running_child() {
        let mut lx = Linuxulator::new(MockBackend::new());

        lx.children.push(super::ChildProcess {
            pid: 7,
            linuxulator: Linuxulator::new(MockBackend::new()),
        });

        let r = lx.dispatch_syscall(LinuxSyscall::Wait4 {
            pid: -1,
            wstatus: 0,
            options: 1, // WNOHANG
            rusage: 0,
        });
        // Any child, running → 0.
        assert_eq!(r, 0);
    }

    #[test]
    fn test_wait4_echild_for_unknown_pid() {
        let mut lx = Linuxulator::new(MockBackend::new());

        // No children at all.
        let r = lx.dispatch_syscall(LinuxSyscall::Wait4 {
            pid: 999,
            wstatus: 0,
            options: 0,
            rusage: 0,
        });
        // Unknown pid → ECHILD.
        assert_eq!(r, ECHILD);
    }

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os test_wait4_wnohang_returns_zero_for_running_child 2>&1 | tail -10`
Expected: The current code returns ECHILD for a running child without WNOHANG, but with WNOHANG it should return 0 if the child exists. Check if this already passes (it might, since the current code at line 6508-6509 returns 0 for WNOHANG when `has_matching_children` is true). If it already passes, the test validates existing correct behavior.

- [ ] **Step 3: Add BLOCK_OP_WAIT constant**

In `linuxulator.rs`, after the existing BLOCK_OP constants (after line 97):

```rust
/// Block operation: waiting for child process exit (wait4/waitpid).
/// The `fd` parameter carries the target PID (-1 = any child, >0 = specific).
/// Decoded by the block_fn closure in main.rs to WaitReason::WaitChild(pid).
pub const BLOCK_OP_WAIT: u8 = 5;
```

- [ ] **Step 4: Add BLOCK_OP_WAIT decode in main.rs block_fn closure**

In `main.rs`, the block_fn closure at line 484-494 decodes BLOCK_OP values to WaitReason. Add the new arm:

```rust
        linuxulator.set_block_fn(|op, fd, deadline_ms| {
            let reason = match op {
                0 => sched::WaitReason::FdReadable(fd),
                1 => sched::WaitReason::FdWritable(fd),
                2 => sched::WaitReason::FdConnectDone(fd),
                3 => sched::WaitReason::PollWait,
                4 => sched::WaitReason::Sleep,
                5 => sched::WaitReason::WaitChild(fd),
                _ => unreachable!(),
            };
            unsafe { sched::block_current(reason, deadline_ms) };
        });
```

- [ ] **Step 5: Modify sys_wait4 to block when no exited child available**

In `linuxulator.rs`, replace the `sys_wait4` function (lines 6464-6537) with:

```rust
    fn sys_wait4(&mut self, pid: i32, wstatus_ptr: u64, options: i32, rusage_ptr: u64) -> i64 {
        const WNOHANG: i32 = 1;

        if pid == 0 || pid < -1 {
            return ENOSYS; // process group wait not supported
        }

        // Reject unsupported options (WUNTRACED, WCONTINUED, __WALL, etc.)
        if options & !WNOHANG != 0 {
            return EINVAL;
        }

        loop {
            // Ensure any recently-exited child is recovered first.
            self.recover_child_state();

            // Check if the requested pid is a known child (active or exited).
            let has_matching_children = if pid == -1 {
                !self.children.is_empty() || !self.exited_children.is_empty()
            } else {
                self.children.iter().any(|c| c.pid == pid)
                    || self.exited_children.iter().any(|&(p, _, _)| p == pid)
            };

            let idx = if pid == -1 {
                if self.exited_children.is_empty() {
                    None
                } else {
                    Some(0)
                }
            } else {
                self.exited_children.iter().position(|&(p, _, _)| p == pid)
            };

            if let Some(i) = idx {
                // Found an exited child — consume and return.
                let (child_pid, exit_code, killed_by) = self.exited_children.remove(i);

                if wstatus_ptr != 0 {
                    let wstatus = match killed_by {
                        Some(sig) => sig & 0x7F,
                        None => ((exit_code & 0xFF) as u32) << 8,
                    };
                    let buf = unsafe {
                        core::slice::from_raw_parts_mut(wstatus_ptr as usize as *mut u8, 4)
                    };
                    buf.copy_from_slice(&wstatus.to_ne_bytes());
                }

                if rusage_ptr != 0 {
                    let buf = unsafe {
                        core::slice::from_raw_parts_mut(rusage_ptr as usize as *mut u8, 144)
                    };
                    buf.fill(0);
                }

                return child_pid as i64;
            }

            // No exited child found.
            if !has_matching_children {
                return ECHILD;
            }
            if options & WNOHANG != 0 {
                return 0;
            }

            // Block until a child exits. The scheduler wakes us via
            // wake_waiting_parent(child_pid). The fd parameter carries
            // the target PID for WaitReason::WaitChild(pid).
            self.block_until(BLOCK_OP_WAIT, pid, None);
        }
    }
```

- [ ] **Step 6: Run all tests**

Run: `cargo test --workspace 2>&1 | tail -20`
Expected: All tests pass. The existing wait4 tests should still pass because they use the sequential model (exited children are already available). The new WNOHANG test validates that a running child returns 0 instead of ECHILD.

- [ ] **Step 7: Run clippy**

Run: `cargo clippy --workspace 2>&1 | tail -20`
Expected: No warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs crates/harmony-boot-aarch64/src/main.rs
git commit -m "feat(wait4): blocking wait4 via WaitReason::WaitChild

sys_wait4 now loops: check exited_children, block if none found, re-check
after wake. BLOCK_OP_WAIT=5 decoded to WaitReason::WaitChild(pid) in the
block_fn closure. WNOHANG returns 0 for running children instead of ECHILD."
```

---

### Task 6: Final validation — full test suite + clippy + fmt

**Files:**
- All modified files

- [ ] **Step 1: Run full workspace tests**

Run: `cargo test --workspace`
Expected: All tests pass.

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace`
Expected: No warnings.

- [ ] **Step 3: Run nightly rustfmt**

Run: `cargo +nightly fmt --all -- --check`
Expected: No formatting issues. If there are issues, run `cargo +nightly fmt --all` to fix.

- [ ] **Step 4: Verify no TODO(Phase 6) comments remain**

Run: `grep -rn "TODO(Phase 6" crates/`
Expected: No matches — both TODOs have been replaced with working code.

- [ ] **Step 5: Commit any fmt fixes**

If fmt found issues:
```bash
cargo +nightly fmt --all
git add -A
git commit -m "style: apply nightly rustfmt"
```
