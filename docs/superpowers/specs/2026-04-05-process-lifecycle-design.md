# Process Lifecycle: exit_group Fix + Blocking wait4

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Bead:** harmony-os-g9i

**Goal:** Fix process exit so that exit_group from any thread cleanly returns to boot code, main-thread SYS_EXIT kills all sibling threads first, and wait4 blocks the parent until a child exits.

**Prerequisite:** Phase 5 + Timer IRQ wake (PR #115) merged — scheduler has task states, WaitReason, block_current, futex/deadline infrastructure.

---

## Architecture

Three changes to the process exit and wait paths:

1. **exit_group from spawned thread — direct TrapFrame patching.** When a spawned thread calls `exit_group`, it finds the main thread's TCB (tid==0 for the same PID), follows `kernel_sp` to the saved TrapFrame in memory, overwrites `elr` with `RETURN_ADDR`, sets `x[0..2]`, and marks it Ready. The main thread resumes directly into the boot return path on the next scheduler tick.

2. **Main-thread SYS_EXIT becomes exit_group.** When the main thread (tid==0) calls `SYS_EXIT`, the dispatcher promotes it to `exit_group` semantics — kill all sibling threads, then redirect ELR to boot code. This matches glibc/musl behavior (they emit `exit_group`, not `exit`) and avoids Zombie state or last-thread-exit detection.

3. **Blocking wait4 via WaitReason::WaitChild.** Parent blocks with `WaitReason::WaitChild(pid)` where pid is -1 (any child) or a specific PID. On child exit, `wake_waiting_parent(child_pid)` in sched.rs scans for a matching blocked parent and wakes it. The linuxulator owns process bookkeeping (exit codes, child lists); the scheduler owns task state transitions (wake/block/dead).

---

## Scheduler Changes (sched.rs)

### New WaitReason Variant

```rust
pub enum WaitReason {
    // ... existing variants ...
    /// Waiting for a child process to exit.
    /// -1 = any child, >0 = specific child PID.
    WaitChild(i32),
}
```

### New Function: `wake_waiting_parent(child_pid: u32)`

Scans all tasks for one that is `Blocked` with `WaitReason::WaitChild(target)` where `target == -1` or `target == child_pid as i32`. If found, wakes it (sets Ready, clears wait_reason and deadline_ms). O(MAX_TASKS) scan, same as `check_deadlines`. Only wakes the first match — a parent can only be blocked in one wait4 call at a time.

```rust
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

### New Function: `redirect_main_thread_to_boot(pid: u32, exit_code: i32, ret_addr: u64, ret_sp: u64, ret_lr: u64)`

Called from the exit_group path when a spawned thread needs to redirect the main thread to boot code. Scans tasks for matching `pid` and `tid == 0`. Follows `kernel_sp` to the saved TrapFrame in memory, writes:

- `elr` = `ret_addr`
- `x[0]` = `exit_code` (as u64)
- `x[1]` = `ret_sp`
- `x[2]` = `ret_lr`

Marks the main thread `Ready` (regardless of previous state — it may be Dead from `kill_threads_by_pid` or Blocked in a syscall).

```rust
pub unsafe fn redirect_main_thread_to_boot(
    pid: u32, exit_code: i32,
    ret_addr: u64, ret_sp: u64, ret_lr: u64,
) {
    let n = NUM_TASKS;
    for i in 0..n {
        let tcb = TASKS[i].assume_init_mut();
        if tcb.pid == pid && tcb.tid == 0 && i != CURRENT {
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

### Race Safety

Both `wake_waiting_parent` and `redirect_main_thread_to_boot` run from the SVC handler path, which executes with IRQs masked. Single-core + IRQ masking guarantees no concurrent scheduler or timer IRQ can modify task state during the scan. Same safety model as existing `kill_threads_by_pid`.

---

## Exit Path Changes (syscall.rs)

### Spawned Thread exit_group (TODO #1 Fix)

Current code at lines 159-192 handles spawned-thread exit_group by setting `PROCESS_EXITED = true` but cannot redirect the main thread's ELR. Replace with:

1. `kill_threads_by_pid(pid)` — already happens, marks all non-current threads Dead
2. `redirect_main_thread_to_boot(pid, exit_code, RETURN_ADDR, RETURN_SP, RETURN_LR)` — patches main thread's saved TrapFrame and marks it Ready
3. CLEARTID cleanup for self — already happens
4. `wake_waiting_parent(pid)` — unblock parent if blocked in wait4
5. `mark_current_dead()` + WFI loop — already happens

The main thread, now Ready with ELR pointing at boot code, gets picked up by the scheduler on the next tick.

### Main Thread SYS_EXIT Promoted to exit_group (TODO #2 Fix)

The promotion happens in the `dispatch` function in `main.rs` (lines 552-574), which already distinguishes `LinuxSyscall::Exit` from `LinuxSyscall::ExitGroup`. When `is_exit` is true and the current task's `tid == 0`, set `exit_group: true` in the `SyscallDispatchResult`. This causes `svc_handler` in `syscall.rs` to call `kill_threads_by_pid(pid)` before redirecting ELR — same path as an explicit `exit_group` call. No changes needed in `syscall.rs` for this case.

After killing threads and before the ELR redirect, call `wake_waiting_parent(pid)` to unblock any parent waiting in wait4.

### Both TODOs Removed

The two TODO(Phase 6) comment blocks are deleted entirely — the code they describe is now implemented.

---

## Linuxulator Changes

### New BLOCK_OP

```rust
pub const BLOCK_OP_WAIT: u8 = 5;
```

Decoded in the `main.rs` block_fn closure to `WaitReason::WaitChild(fd as i32)`, repurposing the `fd` parameter to carry the target PID.

### Modified sys_wait4

Current flow: check `exited_children` → return status or ECHILD.

New flow:

1. Call `recover_child_state()` (existing — moves exited children from `children` to `exited_children`)
2. Check `exited_children` for matching pid — if found, return immediately with status
3. Check `children` for matching pid — if no matching child exists at all, return `-ECHILD`
4. If WNOHANG, return 0
5. Call `block_fn(BLOCK_OP_WAIT, target_pid, None)` to block with `WaitReason::WaitChild(pid)`
6. After wake, go back to step 1 (re-check `exited_children`)

The `target_pid` is passed through the `fd` parameter (i32) of `block_fn`. For `pid == -1` (any child), pass `-1`. For specific pid, pass the pid value.

### No New Callback for Exit Notification

Cross-process exit notification (parent's linuxulator learning about child exit) is deferred to the SIGCHLD bead (harmony-os-96y). The current sequential fork model already populates `exited_children` via `recover_child_state()`. For concurrent threads (clone with CLONE_VM), there's no parent-child process relationship — threads share the same linuxulator instance.

### Callback Interface

**Modified callback:** `block_fn` — no signature change. The existing `fn(u8, i32, Option<u64>)` accommodates `BLOCK_OP_WAIT` with pid-as-fd.

**New callback:** None.

---

## IRQ Path and Scheduling

No changes to `vectors.rs` or the timer IRQ path. `WaitReason::WaitChild` tasks wait indefinitely (no deadline) and are woken only by `wake_waiting_parent`.

**main.rs:** The `check_and_wake_blocked_tasks` function needs a `WaitReason::WaitChild(_)` match arm that does nothing — wait4 tasks are only woken by child exit, not network activity. Same pattern as `WaitReason::Sleep`.

---

## Testing

### Scheduler Tests (sched.rs, host-side)

- `wake_waiting_parent_wakes_any_child`: Block a task with `WaitChild(-1)`, call `wake_waiting_parent(child_pid)`. Assert state=Ready, wait_reason=None.
- `wake_waiting_parent_matches_specific_pid`: Block with `WaitChild(5)`, call `wake_waiting_parent(5)`. Assert woken. Block another with `WaitChild(5)`, call `wake_waiting_parent(3)`. Assert still blocked.
- `wake_waiting_parent_ignores_non_waiting_tasks`: Ready/Dead/Blocked(Futex) tasks unchanged after `wake_waiting_parent` call.
- `redirect_main_thread_patches_trapframe`: Create a task with tid=0, place a TrapFrame at kernel_sp. Call `redirect_main_thread_to_boot`. Assert elr, x[0], x[1], x[2] patched correctly and state=Ready.
- `redirect_main_thread_skips_current_task`: Ensure redirect doesn't accidentally patch the calling task even if pid/tid match.

### Linuxulator Tests (linuxulator.rs, host-side)

- `wait4_returns_immediately_for_exited_child`: Push to `exited_children`, call sys_wait4. Assert returns child_pid and correct wstatus.
- `wait4_blocks_when_child_running`: Mock block_fn to capture arguments. Call sys_wait4 with running child. Assert block_fn called with BLOCK_OP_WAIT and correct pid.
- `wait4_wnohang_returns_zero`: Running child + WNOHANG flag. Assert returns 0, block_fn not called.
- `wait4_echild_when_no_children`: No children at all. Assert returns -ECHILD.
- `main_thread_exit_kills_all_threads`: Verify SYS_EXIT from main thread (tid==0) sets `exit_group: true` in dispatch result, triggering kill of all spawned threads.

### Out of Scope

- SIGCHLD delivery (harmony-os-96y)
- 9P namespace / UCAN capability inheritance (harmony-os-9kw)
- Zombie process state (not needed — exit_group kills all threads immediately)
- Process groups / sessions
- Multi-core races (single-core safe via IRQ masking)
- On-target integration testing (no test ELF modifications)
