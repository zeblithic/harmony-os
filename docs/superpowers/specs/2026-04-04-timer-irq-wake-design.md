# Hybrid Timer IRQ Wake Mechanism

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Bead:** harmony-os-ltv

**Goal:** Add deadline-based task waking to the timer IRQ handler so that timed syscalls (futex, nanosleep, poll, select, epoll) wake with 10ms precision instead of blocking forever or relying on unrelated events.

**Prerequisite:** Phase 5 (PR #114) merged — scheduler has task states, WaitReason, block_current, futex infrastructure.

---

## Architecture

The ARM generic timer fires at 100 Hz (10ms ticks). On each tick, `irq_dispatch` calls `on_tick()` then `schedule()`. We insert a `check_deadlines(now_ms)` call between them. This function scans all Blocked tasks, compares their optional deadline against `now_ms`, and wakes expired ones. Newly-Ready tasks are immediately eligible for `schedule()` on the same tick.

Deadlines are absolute monotonic milliseconds, stored on the `TaskControlBlock`. The linuxulator computes deadlines from syscall-provided relative or absolute timeouts and passes them through the existing callback interface.

A `woken_by_timeout` flag on the TCB tells the linuxulator whether the wake was a timeout (return ETIMEDOUT / 0) or a normal condition (return success / check readiness).

---

## Scheduler Changes (sched.rs)

### New TCB Fields

```rust
pub struct TaskControlBlock {
    // ... existing fields ...
    /// Absolute monotonic deadline in ms. None = no timeout.
    pub deadline_ms: Option<u64>,
    /// True if woken by deadline expiry rather than normal wake.
    pub woken_by_timeout: bool,
}
```

Both fields default to `None` / `false` at task creation.

### Modified `block_current`

```rust
pub unsafe fn block_current(reason: WaitReason, deadline_ms: Option<u64>)
```

Stores `reason` and `deadline_ms` on the current task's TCB before yielding. The existing IRQ-mask → SGI → re-mask flow is unchanged.

### New `check_deadlines(now_ms: u64)`

Called from `irq_dispatch` on `TIMER_INTID`, after `on_tick()`, before `schedule()`.

```rust
pub unsafe fn check_deadlines(now_ms: u64) {
    for i in 0..MAX_TASKS {
        // skip if not initialized, not Blocked, or no deadline
        if let Some(deadline) = task.deadline_ms {
            if now_ms >= deadline {
                task.woken_by_timeout = true;
                task.state = TaskState::Ready;
                task.wait_reason = None;
                task.deadline_ms = None;
            }
        }
    }
}
```

O(MAX_TASKS) per tick. At current MAX_TASKS (16) this is negligible.

### New `WaitReason::Sleep`

```rust
pub enum WaitReason {
    // ... existing variants ...
    Sleep,  // Pure time wait (nanosleep / clock_nanosleep)
}
```

No address or fd — the task is only waiting for a deadline.

### Wake Semantics

- **Normal wake** (`wake()`, `futex_wake()`, `wake_by_fd()`): Clears `deadline_ms` to `None`, leaves `woken_by_timeout` as `false`. Prevents double-wake from a subsequent `check_deadlines`.
- **Timeout wake** (`check_deadlines`): Sets `woken_by_timeout = true`, clears `deadline_ms` and `wait_reason`.

### Timeout Flag Accessor

```rust
/// Read and clear the woken_by_timeout flag for the current task.
/// Must be called from the SVC dispatch path (same task context).
pub unsafe fn consume_woken_by_timeout() -> bool {
    let task = current_task_mut();
    let was_timeout = task.woken_by_timeout;
    task.woken_by_timeout = false;
    was_timeout
}
```

Read-and-clear in one call prevents stale flags.

---

## Callback Interface Changes

### Modified Callbacks

| Callback | Old Signature | New Signature |
|----------|--------------|---------------|
| `block_fn` | `fn(op: u8, fd: i32)` | `fn(op: u8, fd: i32, deadline_ms: Option<u64>)` |
| `futex_block_fn` | `fn(uaddr: u64)` | `fn(uaddr: u64, deadline_ms: Option<u64>)` |

### New Callbacks

| Callback | Signature | Purpose |
|----------|-----------|---------|
| `was_timeout_fn` | `fn() -> bool` | Calls `sched::consume_woken_by_timeout()` |
| `now_ms_fn` | `fn() -> u64` | Calls `timer::now_ms()` — linuxulator needs current time to compute deadlines |

### Wiring (main.rs)

Update existing closures to forward the deadline parameter:

```rust
linuxulator.set_block_fn(|op, fd, deadline_ms| {
    let reason = match op { /* same as before */ };
    unsafe { sched::block_current(reason, deadline_ms) };
});

linuxulator.set_futex_block_fn(|uaddr, deadline_ms| {
    unsafe { sched::block_current(sched::WaitReason::Futex(uaddr), deadline_ms) };
});

linuxulator.set_was_timeout_fn(|| unsafe { sched::consume_woken_by_timeout() });
linuxulator.set_now_ms_fn(|| timer::now_ms());
```

---

## IRQ Path Change (vectors.rs)

Single addition to `irq_dispatch`:

```rust
gic::TIMER_INTID => {
    timer::on_tick();
    unsafe { sched::check_deadlines(timer::now_ms()) };
    unsafe { sched::schedule(current_sp) }
}
```

`now_ms()` reads `CNTPCT_EL0` — a single register read, negligible cost.

---

## Linuxulator Syscall Changes

### sys_futex (FUTEX_WAIT)

- Parse `timeout` parameter as pointer to `struct timespec { tv_sec: i64, tv_nsec: i64 }`. Null pointer = no timeout.
- Compute deadline: `now_ms() + (sec * 1000 + nsec / 1_000_000)`.
- Call `futex_block_fn(uaddr, Some(deadline_ms))`.
- After wake: if `was_timeout_fn()` returns true, return `-ETIMEDOUT` (-110).
- Normal wake returns 0 (as before).

### sys_nanosleep / sys_clock_nanosleep

- Currently advances clock without blocking. Replace with real blocking.
- Compute deadline from timespec (relative for nanosleep, absolute if TIMER_ABSTIME).
- New block operation: `BLOCK_OP_SLEEP = 4`, maps to `WaitReason::Sleep`.
- Call `block_fn(BLOCK_OP_SLEEP, -1, Some(deadline_ms))`.
- After wake: return 0. (No signal support yet; if added later, return EINTR and write remaining time to `rmtp`.)

### poll / select / epoll_wait

- These already have yield-loop timeout logic with deadline comparison.
- Change: pass computed deadline through `block_fn(BLOCK_OP_POLL, -1, Some(deadline_ms))`.
- The timer IRQ wakes them at their deadline even if no network event fires.
- Infinite timeout (-1) passes `None` as deadline.
- After wake: existing loop re-checks readiness. If nothing ready, the outer loop's `now >= deadline` check triggers the timeout return path (already implemented).

---

## Precision

- **Worst-case latency:** 10ms (one tick period at 100 Hz).
- **Typical:** 0-10ms depending on where in the tick cycle the deadline falls.
- **Acceptable:** Linux HZ=100 has the same 10ms granularity. HZ=250 (4ms) and HZ=1000 (1ms) exist but aren't needed for our workloads.
- **Future:** If sub-tick precision is needed, reprogram `CNTP_TVAL_EL0` to fire early for the nearest deadline. Not in scope for this bead.

---

## Testing

### Scheduler Unit Tests (sched.rs, host-side)

- `check_deadlines_wakes_expired_task`: Blocked task with deadline_ms=Some(100). Call check_deadlines(100). Assert state=Ready, woken_by_timeout=true, deadline=None.
- `check_deadlines_ignores_future_deadline`: Same setup, check_deadlines(50). Assert still Blocked.
- `check_deadlines_ignores_no_deadline`: Blocked with deadline_ms=None. check_deadlines(u64::MAX). Assert still Blocked.
- `normal_wake_clears_deadline_and_flag`: Set deadline, call wake(). Assert deadline=None, woken_by_timeout=false.
- `consume_woken_by_timeout_clears_flag`: Set woken_by_timeout=true, call consume. Assert returns true, subsequent call returns false.

### Linuxulator Unit Tests (linuxulator.rs, host-side)

- `futex_wait_timeout_returns_etimedout`: Mock callbacks; was_timeout returns true. Verify sys_futex returns -ETIMEDOUT.
- `futex_wait_no_timeout_blocks_normally`: Null timeout pointer, was_timeout returns false. Verify returns 0.
- `futex_wait_null_timeout_passes_none`: Verify futex_block_fn receives deadline_ms=None when timeout pointer is null.
- `nanosleep_computes_correct_deadline`: Mock block_fn captures deadline. Call sys_nanosleep(500ms). Verify captured deadline = now_ms + 500.
- `clock_nanosleep_abstime_uses_raw_value`: With TIMER_ABSTIME flag, verify deadline = the raw timespec value (not now+value).
- `poll_passes_deadline_to_block_fn`: Mock block_fn captures deadline. Call sys_poll with 200ms timeout. Verify captured deadline = now_ms + 200.
- `poll_infinite_timeout_passes_none`: Call sys_poll with timeout=-1. Verify deadline_ms=None.

---

## Out of Scope

- Sub-tick precision (CNTP_TVAL reprogramming).
- Signal delivery (EINTR on nanosleep).
- FUTEX_WAIT_BITSET and other futex extensions.
- Multi-core deadline races (current design is single-core safe via IRQ masking).
- Modifying the test ELF binary for on-target integration testing.
