# Phase 5: CLONE_VM/CLONE_THREAD + Futex + TLS Design

**Bead**: `harmony-os-0oo`
**Depends on**: Phase 4 (harmony-os-azy, PR #112) — merged
**Depends on**: FP/SIMD (harmony-os-6cm, PR #113) — pending
**Blocks**: Phase 6 (harmony-os-g9i) — process lifecycle

## Goal

Enable musl pthreads by implementing shared-address-space threads (CLONE_VM|CLONE_THREAD), futex synchronization (FUTEX_WAIT|FUTEX_WAKE), per-thread TLS (TPIDR_EL0), and thread exit cleanup (CLONE_CHILD_CLEARTID). This is the minimum surface for `pthread_create`, `pthread_join`, `pthread_mutex_*`, and `pthread_cond_*` to work.

## Architecture

Runtime task spawning via `spawn_task_runtime()` creates new scheduler tasks from within syscall context. `sys_clone` with the musl pthreads flags copies the parent's TrapFrame to a new task's kernel stack, sets up the child's stack pointer and TLS, and marks it Ready. All threads share the single global Linuxulator (fd table, sockets, pipes). Per-thread state (TID, TLS, clear_child_tid) lives in the scheduler's TCB. Futex reuses the Phase 4 blocking mechanism with a new `WaitReason::Futex(u64)` variant.

## Non-Goals (Deferred)

- **Per-process address spaces** — all tasks share the identity map. Fork without CLONE_VM stays ENOSYS.
- **fork() with COW** — requires page table duplication. Phase 6+.
- **Signal delivery to threads** — CLONE_SIGHAND shares handlers, but tkill/thread-directed signals are Phase 6.
- **FUTEX_REQUEUE / FUTEX_CMP_REQUEUE** — glibc-only, not needed by musl.
- **Robust futexes** — `set_robust_list` stays as no-op stub.
- **Stack/TCB reclamation for dead threads** — deferred.
- **Multiple processes** — one Linuxulator, multiple threads. Multi-process dispatch is Phase 6+.
- **CLONE_NEWNS / CLONE_NEWPID** — namespace isolation. Far future.

---

## 1. Runtime Task Spawning

### spawn_task_runtime

New function in `sched.rs`, callable from syscall context (after `enter_scheduler`):

```rust
pub unsafe fn spawn_task_runtime(
    name: &'static str,
    pid: u32,
    tid: u32,
    tls: u64,
    clear_child_tid: u64,
    trapframe: &TrapFrame,
    child_stack: u64,
) -> Option<usize>
```

**Mechanism:**
1. Mask IRQs (`msr daifset, #2`) — prevents race with timer/scheduler
2. Check `NUM_TASKS < MAX_TASKS` — return None if full
3. Allocate kernel stack from static `BUMP_ALLOCATOR` (guard page + stack pages, same as boot-time `spawn_task`)
4. Mark guard page via `mmu::mark_guard_page`
5. Copy parent's TrapFrame to child's kernel stack top
6. Modify child's TrapFrame:
   - `x[0] = 0` — clone returns 0 to child
   - SP register in the TrapFrame = `child_stack`
7. Fill TCB: `state = Ready`, `pid`, `tid`, `tls`, `clear_child_tid`, `wait_reason = None`, `preempt_count = 0`
8. Increment `NUM_TASKS`
9. Unmask IRQs (`msr daifclr, #2`)
10. Return task index

### BumpAllocator as static

Move from local variable in `main()` to `static mut BUMP_ALLOCATOR: Option<BumpAllocator>`. Populated during boot init, accessed by `spawn_task_runtime` with IRQs masked.

### Cross-crate callback

The Linuxulator can't call `sched::spawn_task_runtime` directly (wrong crate direction). Add `set_spawn_fn` on the Linuxulator:

```rust
spawn_fn: Option<fn(u32, u32, u64, u64, &TrapFrame, u64) -> Option<u32>>
```

Arguments: `(pid, tid, tls, clear_child_tid, parent_trapframe, child_stack)`. Returns `Some(tid)` on success or `None` (→ EAGAIN).

The boot crate sets this callback during init, same pattern as `block_fn`/`wake_fn`.

---

## 2. CLONE_VM/CLONE_THREAD in sys_clone

### Accepted flags

musl's `__clone` passes:
```
CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID
```

Accept this exact combination (plus SIGCHLD-only for existing fork path). Reject CLONE_VM without CLONE_THREAD|CLONE_FILES|CLONE_SIGHAND — no partial sharing.

### sys_clone flow (thread creation)

1. Validate flags — must include CLONE_VM|CLONE_THREAD|CLONE_FILES|CLONE_SIGHAND
2. Extract arguments: `child_stack`, `parent_tidptr`, `tls`, `child_tidptr`
3. Allocate new TID from monotonic counter (`next_tid`, starting from PID+1)
4. Call `spawn_fn(pid, tid, tls, child_tidptr, parent_trapframe, child_stack)`
5. If CLONE_PARENT_SETTID: write new TID to `*parent_tidptr`
6. If CLONE_CHILD_SETTID: write new TID to `*child_tidptr`
7. Return new TID to parent

### TrapFrame access

`sys_clone` needs the parent's TrapFrame to copy to the child. Store the current TrapFrame pointer in a static `CURRENT_TRAPFRAME: *const TrapFrame` before calling dispatch in the SVC handler. The Linuxulator reads it via a callback `get_trapframe_fn: Option<fn() -> *const TrapFrame>`.

### Shared state

All threads share the single global LINUXULATOR:
- Address space (identity map — all tasks already share)
- fd table, socket state, pipes, epolls
- Signal handlers

Per-thread state lives in the TCB (see section 3).

---

## 3. TLS — TPIDR_EL0 Context Switch

### TCB additions

```rust
pub struct TaskControlBlock {
    // ... existing fields ...
    pub tls: u64,              // TPIDR_EL0 value
    pub tid: u32,              // Linux Thread ID
    pub clear_child_tid: u64,  // Zero + futex_wake on thread exit
}
```

### Save/restore in schedule()

```rust
// Scoped borrow for outgoing task:
{
    let current_tcb = TASKS[cur].assume_init_mut();
    current_tcb.kernel_sp = current_sp;
    current_tcb.tls = read_tpidr_el0();  // save TLS
    if current_tcb.state == TaskState::Running {
        current_tcb.state = TaskState::Ready;
        current_tcb.preempt_count += 1;
    }
}

// When switching to new task:
let tcb = TASKS[idx].assume_init_mut();
CURRENT = idx;
tcb.state = TaskState::Running;
write_tpidr_el0(tcb.tls);  // restore TLS
return tcb.kernel_sp;
```

### Also needed in:
- `enter_scheduler()` — write TPIDR_EL0 from task 0's TCB before eret
- `block_current()` — save TPIDR_EL0 before the SGI (in the scoped borrow)

### gettid() update

Add `get_current_tid_fn: Option<fn() -> u32>` callback. Boot crate sets it to read `TASKS[CURRENT].tid`. Linuxulator's `sys_gettid` calls this instead of returning `self.pid`.

### Initialization

- Boot-time tasks: `tls = 0`, `tid = pid`, `clear_child_tid = 0`
- Spawned threads: `tls` from clone's argument, `tid` from monotonic counter, `clear_child_tid` from clone's `child_tidptr`

---

## 4. Futex — FUTEX_WAIT and FUTEX_WAKE

### New WaitReason variant

```rust
pub enum WaitReason {
    FdReadable(i32),
    FdWritable(i32),
    FdConnectDone(i32),
    PollWait,
    Futex(u64),  // uaddr
}
```

### Callbacks

Separate from fd blocking (u64 address doesn't fit in i32 fd parameter):

```rust
futex_block_fn: Option<fn(u64)>,           // block with WaitReason::Futex(uaddr)
futex_wake_fn: Option<fn(u64, u32) -> u32>, // (uaddr, max) -> num woken
```

Boot crate wiring:
```rust
linuxulator.set_futex_block_fn(|uaddr| {
    unsafe { sched::block_current(WaitReason::Futex(uaddr)); }
});
linuxulator.set_futex_wake_fn(|uaddr, max| {
    unsafe { sched::futex_wake(uaddr, max) }
});
```

### sched::futex_wake

```rust
pub unsafe fn futex_wake(uaddr: u64, max: u32) -> u32 {
    let mut woken = 0u32;
    let n = NUM_TASKS;
    for i in 0..n {
        if woken >= max { break; }
        let tcb = TASKS[i].assume_init_mut();
        if tcb.state == TaskState::Blocked
            && tcb.wait_reason == Some(WaitReason::Futex(uaddr))
        {
            tcb.state = TaskState::Ready;
            tcb.wait_reason = None;
            woken += 1;
        }
    }
    woken
}
```

### sys_futex implementation

```rust
fn sys_futex(&mut self, uaddr: u64, op: i32, val: u32) -> i64 {
    let cmd = op & 0x7f;  // mask FUTEX_PRIVATE_FLAG
    match cmd {
        FUTEX_WAIT => {
            if uaddr == 0 { return EFAULT; }
            let current = unsafe { *(uaddr as *const u32) };
            if current != val { return EAGAIN; }
            if let Some(block) = self.futex_block_fn {
                block(uaddr);
                0  // woken successfully
            } else {
                EAGAIN
            }
        }
        FUTEX_WAKE => {
            if let Some(wake) = self.futex_wake_fn {
                wake(uaddr, val) as i64
            } else {
                0
            }
        }
        _ => ENOSYS,
    }
}
```

### System task interaction

The system task's `check_and_wake_blocked_tasks` does NOT handle `Futex` — futex wakes are synchronous (the waking thread calls `futex_wake_fn` directly during its own syscall). Same pattern as pipe wakes.

---

## 5. Thread Exit and CLONE_CHILD_CLEARTID

### Exit path

When a thread's syscall dispatch returns `exited = true`, the SVC handler determines exit behavior:

- **Main thread (TID == PID):** `exit_group` semantics. Mark ALL tasks with matching PID as Dead. This kills all threads in the process.
- **Spawned thread (TID != PID):** Thread exit only.
  1. Read `clear_child_tid` from current TCB
  2. If nonzero: write 0 to `*clear_child_tid`, call `futex_wake(clear_child_tid, 1)`
  3. Mark current task Dead
  4. Unmask IRQs + trigger Self-SGI to switch away (same mechanism as `block_current` but terminal — task is Dead, never rescheduled)

### set_tid_address update

Currently returns `self.pid`. Phase 5:
1. Store the address in current task's `clear_child_tid` field (via `set_clear_child_tid_fn` callback)
2. Return current task's TID (via `get_current_tid_fn`)

### exit_group thread cleanup

`exit_group` must kill all threads, not just the calling thread. Add `kill_all_threads_fn: Option<fn(u32)>` callback that takes PID and marks all matching tasks as Dead. Alternatively, handle in the SVC handler directly since it has access to the scheduler.

---

## 6. QEMU Boot Test

### Milestones

No new milestones needed — the existing 9 milestones verify the 3-task boot. Thread creation happens within the ELF task's execution, not at boot.

If the test ELF exercises pthreads (creates a thread, joins it), the test passes implicitly by reaching normal exit. If it doesn't use pthreads, the QEMU test is unchanged.

### Host-side tests

- `sched.rs`: `spawn_task_runtime` sets up TCB correctly, `futex_wake` wakes matching tasks, TLS save/restore round-trips
- `linuxulator.rs`: `sys_clone` with thread flags calls `spawn_fn`, `sys_futex` WAIT/WAKE semantics, `set_tid_address` stores address and returns TID
