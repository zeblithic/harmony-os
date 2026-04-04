# Phase 4: Blocking Syscall Integration Design

**Bead**: `harmony-os-azy`
**Depends on**: Phase 3 (harmony-os-5eb, PR #111) — merged
**Blocks**: Phase 5 (harmony-os-0oo) — CLONE_VM/CLONE_THREAD + futex + TLS
**Blocks**: Phase 6 (harmony-os-g9i) — Process lifecycle

## Goal

Replace the Linuxulator's spin-wait blocking with scheduler-integrated blocking. When a syscall would block (read on empty socket, accept with no connection, poll with no ready fds, etc.), yield the CPU to other tasks via the scheduler. When the I/O condition becomes true, wake the blocked task and resume the syscall from where it left off.

This eliminates busy-waiting CPU burn and is required for correct multi-process behavior — without it, a blocking read in one task prevents all other tasks from running.

## Architecture

Phase 4 adds three scheduler primitives (`block_current`, `wake`, `wake_by_fd`) and a Self-SGI yield mechanism. The ELF binary moves from the system task to its own task (PID 2). The system task becomes a dedicated network poller and waker. All 6 Linuxulator blocking paths are converted from spin-wait to scheduler yield.

The core mechanism: when a syscall handler calls `block_current(reason)`, it marks the task Blocked, triggers a GICv3 Self-SGI, and the existing IRQ handler saves the TrapFrame, calls `schedule()` (which skips Blocked tasks), and context-switches to the next Ready task. The blocked task's entire kernel call stack is frozen in place on its kernel stack. When eventually woken and rescheduled, execution resumes from `block_current()`, and the syscall handler retries the I/O operation.

## Non-Goals (Deferred)

- **FP/SIMD context save** — deferred to Phase 5. No code uses floating-point. ELF binaries must not use FP/SIMD.
- **Stack reclamation** — Dead tasks leave kernel stack pages allocated. Phase 5+.
- **Blocked/wake with timeout** (`nanosleep`, precise `poll`/`select` timeouts) — requires timer IRQ wake checking (hybrid approach). Phase 5+. For Phase 4, `poll`/`select` with timeout check elapsed time on each spurious wake and return 0 if expired.
- **EL0 user isolation** — all tasks run in EL1. Phase 5.
- **fork()/CLONE_VM** — requires address space duplication. Phase 5.
- **Priority scheduling** — pure round-robin. Phase 5+.
- **Specialized task decomposition** — system task remains monolithic (runtime + network + waker). Requires smoltcp thread-safety.
- **Signal delivery** — no actual signal mechanism. `EINTR` returned on failure paths only. Phase 6 adds SIGCHLD.

---

## 1. Scheduler Primitives

### WaitReason

```rust
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum WaitReason {
    /// Waiting for fd to become readable.
    FdReadable(i32),
    /// Waiting for fd to become writable.
    FdWritable(i32),
    /// Waiting for TCP connect to complete.
    FdConnectDone(i32),
    /// Waiting for any network activity (poll/select).
    /// Woken on any smoltcp state change; handler rechecks specific fds.
    PollWait,
}
```

### TCB Addition

```rust
pub struct TaskControlBlock {
    // ... existing fields from Phase 3 ...
    pub wait_reason: Option<WaitReason>,
}
```

### block_current(reason)

Called from within a syscall handler to block the current task and yield the CPU.

```rust
pub unsafe fn block_current(reason: WaitReason) {
    let cur = CURRENT;
    let tcb = TASKS[cur].assume_init_mut();
    tcb.state = TaskState::Blocked;
    tcb.wait_reason = Some(reason);

    // Trigger Self-SGI. This enters the IRQ handler, which saves
    // the TrapFrame (capturing our state mid-block_current), calls
    // schedule() (which skips us — we're Blocked), and context-switches
    // to the next Ready task. When we're eventually woken and rescheduled,
    // the IRQ handler restores our TrapFrame and erets back here.
    gic::send_sgi_self(YIELD_SGI);

    // Execution resumes here after wake + reschedule.
    // Clear wait_reason — we're Running again.
    let tcb = TASKS[CURRENT].assume_init_mut();
    tcb.wait_reason = None;
}
```

### wake(task_idx)

Called by the system task (periodic polling) or synchronously from pipe/eventfd writes.

```rust
pub unsafe fn wake(task_idx: usize) {
    let tcb = TASKS[task_idx].assume_init_mut();
    if tcb.state == TaskState::Blocked {
        tcb.state = TaskState::Ready;
        tcb.wait_reason = None;
    }
}
```

### wake_by_fd(fd, op)

Convenience function for synchronous pipe/eventfd wakes. Scans all Blocked tasks for a matching WaitReason.

```rust
pub unsafe fn wake_by_fd(fd: i32, op: u8) {
    let n = NUM_TASKS;
    for i in 0..n {
        let tcb = TASKS[i].assume_init_mut();
        if tcb.state != TaskState::Blocked { continue; }
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
```

### Properties

- `block_current` is called from SVC context (within a syscall handler). The task's kernel stack holds the entire call chain: SVC entry → svc_handler → Linuxulator → sys_read → block_current. The Self-SGI freezes this state. On resume, the stack unwinds normally.
- `wake` and `wake_by_fd` are O(n) scans, n <= 64. Called from the system task's event loop (not IRQ context).
- No new assembly: the Self-SGI reuses the existing IRQ handler's TrapFrame save/restore path.

---

## 2. GIC Changes — Self-SGI

### New constant and function

```rust
/// SGI used for voluntary yield. SGI 0 is reserved by convention.
pub const YIELD_SGI: u32 = 1;

/// Send a Software Generated Interrupt to the current PE.
pub unsafe fn send_sgi_self(intid: u32) {
    // ICC_SGI1_EL1: IRM=0 (use target list), Aff3/2/1=0,
    // TargetList bit 0 = 1 (PE 0), INTID in bits [27:24].
    let val: u64 = ((intid as u64) & 0xF) << 24 | 1;
    core::arch::asm!("msr ICC_SGI1_EL1, {}", in(reg) val);
}
```

### IRQ dispatch update

```rust
pub unsafe fn irq_dispatch(current_sp: usize) -> usize {
    let intid = gic::ack();
    let new_sp = match intid {
        TIMER_INTID => {
            timer::on_tick();
            sched::schedule(current_sp)
        }
        YIELD_SGI => {
            // Voluntary yield from block_current() — just reschedule.
            sched::schedule(current_sp)
        }
        _ => current_sp,
    };
    gic::eoi(intid);
    new_sp
}
```

### Properties

- SGIs (0-15) are enabled by default in GICv3. No distributor/redistributor configuration changes needed.
- IRQs must be unmasked for the SGI to fire. Tasks run with PSTATE.I=0 (set by `INITIAL_SPSR`), so the SGI fires immediately after `send_sgi_self`.
- The IRQ handler treats the SGI identically to a timer interrupt: save TrapFrame, call `schedule()`, restore from the returned SP. The only difference is no `on_tick()` call.

---

## 3. Task Architecture

### Three tasks at boot

| Index | PID | Name | Role |
|-------|-----|------|------|
| 0 | 0 | idle | `wfi` loop, always Ready, fallback |
| 1 | 1 | system | Network poller + runtime + waker. Never blocks. |
| 2 | 2 | elf | Runs test ELF binary. Makes syscalls, can block. |

### System task (PID 1) — Phase 4

```rust
fn system_task() -> ! {
    let mut serial = SerialWriter::new(|b| unsafe { pl011::write_byte(b) });
    let _ = writeln!(serial, "[System] Event loop started");

    loop {
        let now = timer::now_ms();

        // 1. Poll smoltcp — move packets through the stack.
        poll_network(now);

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

### check_and_wake_blocked_tasks()

Iterates `TASKS[0..NUM_TASKS]`. For each Blocked task:

| WaitReason | Check | Wake if |
|------------|-------|---------|
| `FdReadable(fd)` | `is_fd_readable(fd)` | true |
| `FdWritable(fd)` | `is_fd_writable(fd)` | true |
| `FdConnectDone(fd)` | `is_fd_connect_done(fd)` | true |
| `PollWait` | network state changed this iteration | true |

The readiness functions (`is_fd_readable`, `is_fd_writable`, `is_fd_connect_done`) are existing Linuxulator methods. The system task accesses the Linuxulator via the same static used by the SVC handler.

### ELF task (PID 2)

```rust
fn elf_task() -> ! {
    // Set up Linuxulator dispatch for SVC handler.
    // Load test ELF, set up trampoline, jump to entry point.
    // (Logic moved from system task's inline ELF execution.)
}
```

The ELF task runs the binary, makes syscalls via SVC. When a syscall blocks, the Linuxulator calls `block_fn`, which calls `block_current`, which yields via Self-SGI. When woken, the syscall resumes and retries.

### Boot sequence change

```rust
// Phase 3:
// spawn idle (PID 0) → spawn system (PID 1) → enter_scheduler

// Phase 4:
// spawn idle (PID 0) → spawn system (PID 1) → spawn elf (PID 2) → enter_scheduler
```

---

## 4. Cross-Crate Callback Mechanism

### Problem

The scheduler is in `harmony-boot-aarch64`. The Linuxulator is in `harmony-os`. The boot crate depends on harmony-os (not the other way). The Linuxulator cannot directly call `sched::block_current()`.

### Solution: Callback functions

Following the existing `set_poll_fn()` pattern, add two new callbacks:

**`set_block_fn(fn(u8, i32))`** — Linuxulator calls this to block the current task.
- `u8` = operation type: 0=FdReadable, 1=FdWritable, 2=FdConnectDone, 3=PollWait
- `i32` = fd (-1 for PollWait)
- Boot crate sets this to a closure that converts to `WaitReason` and calls `sched::block_current()`

**`set_wake_fn(fn(i32, u8))`** — Linuxulator calls this for synchronous pipe/eventfd wakes.
- `i32` = fd that became ready
- `u8` = what became ready: 0=readable, 1=writable
- Boot crate sets this to a closure that calls `sched::wake_by_fd()`

### Setup

```rust
// In boot main.rs, before spawning tasks:
linuxulator.set_block_fn(|op, fd| {
    let reason = match op {
        0 => WaitReason::FdReadable(fd),
        1 => WaitReason::FdWritable(fd),
        2 => WaitReason::FdConnectDone(fd),
        3 => WaitReason::PollWait,
        _ => unreachable!(),
    };
    unsafe { sched::block_current(reason); }
});

linuxulator.set_wake_fn(|fd, op| {
    unsafe { sched::wake_by_fd(fd, op); }
});
```

### Why primitive types?

`WaitReason` is defined in the boot crate. The Linuxulator can't import it. Using `(u8, i32)` keeps the crates decoupled. An alternative would be defining `WaitReason` in harmony-microkernel (shared dependency), but that couples the microkernel to scheduler details. Primitives are simpler.

---

## 5. Linuxulator Changes

### block_until() — Core primitive replacement

Phase 3 (spin-wait):
```rust
fn block_until(&mut self, poll_fn: fn() -> u64,
               ready_check: fn(&Self, i32) -> bool, fd: i32) -> BlockResult {
    loop {
        poll_fn();
        if ready_check(self, fd) { return BlockResult::Ready; }
        core::hint::spin_loop();
        // ... 30s timeout check ...
    }
}
```

Phase 4 (scheduler yield):
```rust
fn block_until(&mut self, op: u8, fd: i32) -> BlockResult {
    if let Some(block) = self.block_fn {
        block(op, fd);
        // Execution resumes here after wake + reschedule.
        BlockResult::Ready
    } else {
        // No scheduler — fallback to EAGAIN.
        BlockResult::Interrupted
    }
}
```

The signature changes: `poll_fn` and `ready_check` parameters are removed. The operation type and fd are passed to the block callback. The 30-second timeout is removed — the task sleeps until genuinely woken.

### Callers updated

All 6 blocking paths converted:

| Path | Old | New |
|------|-----|-----|
| `sys_read` (TCP/pipe) | `block_until(pf, is_fd_readable, fd)` | `block_until(OP_READABLE, fd)` |
| `sys_write` (TCP/pipe) | `block_until(pf, is_fd_writable, fd)` | `block_until(OP_WRITABLE, fd)` |
| `sys_accept4` | Inline spin-wait loop | `block_until(OP_READABLE, fd)` + retry loop |
| `sys_connect` | `block_until(pf, is_fd_connect_done, fd)` | `block_until(OP_CONNECT, fd)` |
| `sys_recvfrom/sendto` | `block_until(pf, is_fd_readable/writable, fd)` | `block_until(OP_READABLE/WRITABLE, fd)` |
| `sys_poll/select` | Spin-wait with `poll_fn()` | `block_until(OP_POLL, -1)` + recheck loop |
| `epoll_wait` | Single check, no block | `block_until(OP_POLL, -1)` when timeout != 0 |
| `pipe_write_blocking` | Spin-wait with 30s deadline | `block_until(OP_WRITABLE, fd)` + retry loop |

### Synchronous pipe/eventfd wakes

After successful pipe operations, call `wake_fn` to immediately wake blocked tasks:

- `sys_read(pipe_read_fd)` succeeds → `wake_fn(write_end_fd, WRITABLE)` — writer can now write
- `sys_write(pipe_write_fd)` succeeds → `wake_fn(read_end_fd, READABLE)` — reader can now read
- `eventfd_write` succeeds → `wake_fn(eventfd_fd, READABLE)` — reader can now read

### poll_fn changes

`poll_fn` is no longer called from blocking loops (those yield instead of spinning). It remains set on the Linuxulator and is called by the system task's `poll_network(now)` step (see section 3) to drive smoltcp each iteration of the event loop.

### Timeout handling

For `sys_poll` and `sys_select` with a timeout:
- Record start time before first block
- On each wake (from PollWait), check elapsed time
- If timeout expired, return 0 (no ready fds) — same as Linux behavior
- If not expired, recheck fds and re-block if none ready

This is approximate — the task only wakes on network activity, not precisely at the deadline. Precise timeout waking (via timer IRQ) is deferred to a future phase.

---

## 6. QEMU Boot Test Updates

### Updated milestones

```rust
fn aarch64_milestones() -> Vec<Milestone> {
    vec![
        Milestone { pattern: "[PL011] Serial initialized", description: "serial up" },
        Milestone { pattern: "[RNDR]", description: "hardware RNG available" },
        Milestone { pattern: "[Identity]", description: "PQ identity generated" },
        Milestone { pattern: "[Sched] Spawned idle task (PID 0)", description: "idle task spawned" },
        Milestone { pattern: "[Sched] Spawned system task (PID 1)", description: "system task spawned" },
        Milestone { pattern: "[Sched] Spawned elf task (PID 2)", description: "elf task spawned" },
        Milestone { pattern: "[Sched] Entering scheduler", description: "scheduler entry" },
        Milestone { pattern: "[System]", description: "system task running" },
        Milestone { pattern: "[ELF]", description: "elf task running" },
    ]
}
```

### What the test proves

If `[ELF]` is reached:
1. Three tasks spawned with correct PIDs (0, 1, 2).
2. Scheduler round-robins between all three.
3. ELF task started executing its binary.
4. System task started its event loop (network polling + wake checking).

### Block/wake verification

The QEMU boot test proves task separation. Block/wake correctness is verified by host-side unit tests:

- `sched.rs`: `block_current` sets Blocked + wait_reason, `wake` transitions Blocked→Ready, `schedule` skips Blocked tasks, `wake_by_fd` finds matching tasks.
- `linuxulator.rs`: `block_until` calls `block_fn` instead of spinning, pipe write triggers `wake_fn`, poll/select re-block on spurious wake.

---

## 7. Known Limitations and Future Directions

### Deferred to Phase 5

1. **FP/SIMD context save** — no code uses FP. ELF binaries must not use floating-point.
2. **Stack reclamation** — Dead tasks leave kernel stack pages allocated.
3. **EL0 user isolation** — all tasks run in EL1.
4. **CLONE_VM / fork()** — requires address space duplication.
5. **Timeout-based blocking** — precise `nanosleep`, `poll`/`select` deadline waking via timer IRQ.

### Deferred to Phase 5+

6. **Priority scheduling** — pure round-robin.
7. **Specialized task decomposition** — system task remains monolithic.
8. **Hybrid timer IRQ wake mechanism** — timer checks timeouts, system task checks I/O.

### Phase 4 limitations

- **Wake latency** for network I/O depends on system task scheduling frequency (~30ms worst case with 3 tasks at 100 Hz).
- **Spurious wakeups** for poll/select — `PollWait` wakes on any network activity, handler rechecks and re-blocks.
- **Single Linuxulator instance** — all tasks share one. Phase 5's per-process isolation may need per-process fd tables.
- **Approximate timeouts** — poll/select timeout checked on spurious wakes only, not at precise deadlines.

### What Phase 4 delivers

- Scheduler primitives: `block_current(reason)`, `wake(task_idx)`, `wake_by_fd(fd, op)`.
- Self-SGI yield mechanism — zero new assembly, reuses existing IRQ handler path.
- ELF binary as a separate preemptible task (PID 2).
- System task as dedicated network poller + waker.
- All 6 Linuxulator blocking paths converted from spin-wait to scheduler yield.
- Synchronous pipe/eventfd waking.
- Cross-crate callback mechanism (block_fn, wake_fn) following existing poll_fn pattern.
- Foundation for Phase 5 (multi-process, FP) and Phase 6 (process lifecycle, signals).
