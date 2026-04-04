# Phase 3: Dynamic Scheduler Design

**Bead**: `harmony-os-5eb`
**Depends on**: Phase 2 (harmony-os-n9r, PR #110) — merged
**Blocks**: Phase 4 (harmony-os-azy) — blocking syscall integration

## Goal

Transform the Phase 2 proof-of-concept scheduler (fixed 2-task array, counter-incrementing test tasks) into a production scheduler with dynamic task management, proper lifecycle states, guard pages, and the event loop running as a preemptible scheduler task.

## Architecture

Phase 3 keeps the same core mechanism — SP-swap context switch via the IRQ handler — but replaces the fixed infrastructure around it. The boot sequence remains sequential through hardware init, then spawns two built-in tasks (idle + system) and enters the scheduler. The system task runs the existing event loop logic (Linuxulator, network polling). Each task gets a PID that bridges to the microkernel's Process struct.

## Non-Goals (Deferred)

- **FP/SIMD context save** — deferred to Phase 4. Tasks must not use floating-point.
- **Stack reclamation** — Dead tasks leave kernel stack pages allocated. Phase 4+ adds a frame free-list.
- **Blocked/wake mechanism** — `TaskState::Blocked` exists but nothing sets it or wakes from it. Phase 4 adds `block_current()` and `wake(task_idx)`.
- **EL0 user isolation** — all tasks run in EL1. Per-process page tables are Phase 5.
- **fork()/CLONE_VM** — requires address space duplication (Phase 5).
- **Priority scheduling** — pure round-robin. Priority is Phase 5+.
- **Specialized task decomposition** — the system task is monolithic (event loop + Linuxulator + network). Decomposing into separate network/Linuxulator/runtime tasks requires smoltcp thread-safety or proper serialization. Investigate in a future phase.

---

## 1. Task Storage and Lifecycle

### TaskControlBlock

```rust
pub struct TaskControlBlock {
    // Existing (Phase 2):
    pub kernel_sp: usize,
    pub kernel_stack_base: usize,
    pub kernel_stack_size: usize,
    pub state: TaskState,
    pub preempt_count: u64,
    // New (Phase 3):
    pub pid: u32,              // Microkernel Process ID (0 = idle, 1 = system)
    pub name: &'static str,    // Debug name ("idle", "system", "task-3", ...)
    pub entry: Option<fn() -> !>,  // Entry point (for debug/restart, not re-invoked)
}
```

### TaskState

```rust
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TaskState {
    Ready,
    Running,
    Blocked,   // Waiting on syscall/IPC (Phase 4 uses this)
    Dead,      // Exited, scheduler skips, slot reclaimable
}
```

### Storage

Fixed array with MAX_TASKS = 64:

```rust
static mut TASKS: [MaybeUninit<TaskControlBlock>; 64] = ...;
static mut NUM_TASKS: usize = 0;  // High-water mark
```

`spawn_task` fills the next slot and returns the task index. `NUM_TASKS` is the high-water mark — slots `0..NUM_TASKS` are initialized. Dead tasks leave holes that are skipped by the scheduler but not reused (reuse is a Phase 4+ optimization).

### spawn_task Signature Change

```rust
pub unsafe fn spawn_task(
    name: &'static str,
    pid: u32,
    entry: fn() -> !,
    bump: &mut BumpAllocator,
) -> usize  // Returns task index
```

### Task Exit

A trampoline wrapper around each task's entry point catches "return" (which shouldn't happen for `fn() -> !`, but provides safety). On exit, the trampoline marks the TCB as `Dead`. The scheduler will never schedule it again. Stack reclamation is deferred to Phase 4+.

---

## 2. Ready Queue and Scheduling

### Round-Robin with State Awareness

Phase 2's `(cur + 1) % NUM_TASKS` becomes a state-aware scan:

```rust
pub unsafe fn schedule(current_sp: usize) -> usize {
    let n = NUM_TASKS;
    if n <= 1 { return current_sp; }

    let cur = CURRENT;

    // Save current task. If it was marked Dead or Blocked by a syscall
    // before this tick, don't overwrite that state with Ready.
    let current_tcb = TASKS[cur].assume_init_mut();
    current_tcb.kernel_sp = current_sp;
    if current_tcb.state == TaskState::Running {
        current_tcb.state = TaskState::Ready;
    }
    current_tcb.preempt_count += 1;

    // Scan for next Ready task (round-robin).
    for offset in 1..=n {
        let idx = (cur + offset) % n;
        let tcb = TASKS[idx].assume_init_ref();
        if tcb.state == TaskState::Ready {
            CURRENT = idx;
            TASKS[idx].assume_init_mut().state = TaskState::Running;
            return TASKS[idx].assume_init_ref().kernel_sp;
        }
    }

    // No Ready task found — stay on current if still schedulable,
    // otherwise this is a system error (idle task should always be Ready).
    current_sp
}
```

### Properties

- O(n) scan worst case, n <= 64, runs in IRQ context at 100 Hz — trivial cost.
- Dead and Blocked tasks are naturally skipped.
- Idle task (index 0) is always Ready, so the "no Ready task" fallback is a safety net.
- No separate run queue data structure. A linked-list or bitmap would be O(1) but adds complexity for 64 tasks. Linear scan is simpler and fast enough.
- Phase 4 adds `wake(task_idx)` to move Blocked -> Ready when I/O completes.

---

## 3. Guard Pages

### Design

Each task's 8 KiB kernel stack gets a guard page — the page immediately below `kernel_stack_base`. If the stack overflows downward, it hits an inaccessible page and triggers a clean data abort.

### Allocation Strategy

Always allocate one extra page below the stack as the guard. The bump allocator hands out `pages_needed + 1` frames. The lowest frame becomes the guard (remapped as inaccessible), the remaining frames are the usable stack:

```
[guard page - inaccessible] [stack page 0] [stack page 1]
 ^                           ^              ^
 guard_addr                  base           base + PAGE_SIZE
                                            (stack grows down from top)
```

This guarantees the guard page is always in memory we own, regardless of what's below the allocation.

### Page Table Manipulation

New function in `mmu.rs`:

```rust
/// Mark a single page as inaccessible (guard page).
/// Walks the existing identity-map page tables and clears the valid bit
/// (bit 0) of the Level 3 descriptor for `addr`.
pub unsafe fn mark_guard_page(addr: u64)
```

### Data Abort Handling

The existing `el1_sync_handler` in `vectors.rs` handles synchronous exceptions. Add a check: if the exception class (ESR_EL1.EC) is a data abort and the faulting address (FAR_EL1) falls within any task's guard page range, print a diagnostic and halt:

```
[PANIC] stack overflow in task N "name" (PID P)
```

This is a fatal error — no recovery.

---

## 4. System Task and Idle Task

### Boot Flow Change

Boot init stays sequential (UEFI, MMU, GIC, heap, identity, smoltcp, Linuxulator). After init completes:

1. Store runtime/Linuxulator/serial into statics (existing pattern — PL011 base, GIC bases, timer freq are already statics).
2. Spawn idle task (index 0, PID 0).
3. Spawn system task (index 1, PID 1).
4. Enter scheduler via `enter_scheduler()` (same as Phase 2).

### Idle Task (Index 0, PID 0)

```rust
fn idle_task() -> ! {
    loop {
        core::arch::asm!("wfe");  // Wait For Event — low power
    }
}
```

Always Ready. The scheduler falls through to it when no other task is Ready. Minimal stack usage. PID 0 is a well-known sentinel — no microkernel Process created for it.

### System Task (Index 1, PID 1)

Entry point picks up where boot init left off — running the Linuxulator event loop:

```rust
fn system_task() -> ! {
    // Read runtime/linuxulator from statics populated by boot init.
    // Load and run the test ELF via Linuxulator.
    // Poll smoltcp network interface.
    // Handle 9P IPC.
    loop {
        // ... existing event loop logic ...
        core::arch::asm!("wfe");
    }
}
```

### Static State Access

The system task needs boot-time state (UnikernelRuntime, Linuxulator, serial). These move from local variables in `main.rs` to statics:

```rust
static mut RUNTIME: Option<UnikernelRuntime> = None;
static mut LINUXULATOR: Option<Linuxulator> = None;
```

Boot init populates these before spawning tasks. The system task reads them. This extends the existing pattern (PL011_BASE, GICD_BASE, GICR_BASE, TIMER_FREQ are already statics).

---

## 5. PID Bridging

### Lightweight Coupling

The boot crate's TCB stores a `pid: u32` field. The microkernel's `Kernel` stores a `BTreeMap<u32, Process>`. They share a PID value but no pointers or direct references.

### Well-Known PIDs

| PID | Task | Microkernel Process? |
|-----|------|---------------------|
| 0 | Idle | No — has no namespace or capabilities |
| 1 | System | Yes — root namespace, full kernel capabilities |
| 2+ | Future user tasks | Yes — spawned via `Kernel::spawn_process()` |

### PID Allocation

The microkernel's `Kernel` already has `next_pid: u32`. Reserve PIDs 0-1 as well-known. `Kernel::spawn_process()` hands out PIDs starting from 2 for future user tasks. The boot code passes the PID to `spawn_task` — the scheduler does not allocate PIDs.

### Lookup

- Task index → PID: `TASKS[idx].pid` (O(1))
- PID → task index: Linear scan of `TASKS[0..NUM_TASKS]` (O(n), n <= 64). Phase 4+ can add a `PID_TO_IDX` lookup table if needed.

### Exit Path (Phase 4)

When the Linuxulator handles an `exit()` syscall:
1. Look up task index by PID.
2. Mark the TCB as Dead.
3. Call `Kernel::destroy_process(pid)` to clean up the microkernel side.

Phase 3 won't exercise this full path (system task never exits), but the plumbing is in place.

---

## 6. QEMU Boot Test Updates

### New Milestones

Phase 2's counter-based verification (tick-500 `[Sched] Task 0: N, Task 1: M`) is replaced with lifecycle milestones:

```rust
fn aarch64_milestones() -> Vec<Milestone> {
    vec![
        Milestone { pattern: "[PL011] Serial initialized", description: "serial up" },
        Milestone { pattern: "[RNDR]", description: "hardware RNG available" },
        Milestone { pattern: "[Identity]", description: "PQ identity generated" },
        Milestone { pattern: "[Sched] Spawned idle task (PID 0)", description: "idle task spawned" },
        Milestone { pattern: "[Sched] Spawned system task (PID 1)", description: "system task spawned" },
        Milestone { pattern: "[Sched] Entering scheduler", description: "scheduler entry" },
        Milestone { pattern: "[System]", description: "system task running" },
    ]
}
```

### What the Test Proves

If the `[System]` milestone is reached:
1. The scheduler entered via `enter_scheduler()`.
2. Idle task (index 0) was created but system task (index 1) was picked by round-robin.
3. The system task's TrapFrame was correctly seeded and restored via `eret`.
4. The task is executing real code (not just incrementing a counter).

### Timer Changes

- Keep `[Tick] N` output every 100 ticks for liveness verification.
- Remove the tick-500 scheduler verification logic (`print_sched_verification`) from `timer.rs`.
- `on_tick()` simplifies to: increment counter, rearm, periodic tick print.

---

## 7. Known Limitations and Future Directions

### Carried to Phase 4

1. **No FP/SIMD context save** — tasks must not use floating-point.
2. **No stack reclamation** — Dead tasks leave kernel stack pages allocated.
3. **No Blocked/wake** — state exists, mechanism doesn't.
4. **EL1-only** — no EL0 user isolation.

### Carried to Phase 5+

5. **No fork()/CLONE_VM** — requires address space duplication.
6. **No priority scheduling** — pure round-robin.
7. **Monolithic system task** — investigate decomposing into specialized tasks (network, Linuxulator, runtime) once smoltcp thread-safety or proper serialization is addressed.

### What Phase 3 Delivers

- Dynamic scheduler managing up to 64 tasks with proper lifecycle (spawn -> ready -> running -> dead).
- Guard pages on all kernel stacks (stack overflow = clean abort, not silent corruption).
- Event loop running as a preemptible scheduler task instead of bare-metal inline code.
- PID bridging to the microkernel's Process model.
- Clean hooks for Phase 4: Blocked state, Dead state, pid field, guard pages protecting deeper call stacks.
