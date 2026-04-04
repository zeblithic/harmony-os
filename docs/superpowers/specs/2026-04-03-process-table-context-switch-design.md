# Phase 2: Process Table + Context Switch — Design Spec

## Goal

Prove preemptive context switching on aarch64 by timer-driving a round-robin
alternation between two kernel-mode tasks that increment separate counters.
Both counters nonzero after N ticks = proof that the mechanism works.

## Architecture

Builds on Phase 1's timer interrupt infrastructure (GICv3, 100 Hz tick,
TrapFrame save/restore in `el1_irq_handler`). A new `sched.rs` module in
`harmony-boot-aarch64` owns task state and the context switch decision.
The IRQ handler passes its stack pointer to the scheduler, which returns
a (possibly different) stack pointer; the assembly restores from whatever
it gets back. Per-task kernel stacks mean no TrapFrame copying.

## Tech Stack

- AArch64 assembly (global_asm in vectors.rs)
- Rust `no_std` (sched.rs in harmony-boot-aarch64)
- ARM Generic Timer + GICv3 (Phase 1 foundation)
- QEMU virt machine (gic-version=3)

---

## 1. TaskControlBlock

New file: `crates/harmony-boot-aarch64/src/sched.rs`

```rust
#[derive(Clone, Copy, PartialEq)]
pub enum TaskState {
    Ready,
    Running,
}

#[repr(C)]
pub struct TaskControlBlock {
    /// Saved SP_EL1 — points into this task's kernel stack at the base
    /// of a saved TrapFrame. The IRQ restore path loads registers from here.
    pub kernel_sp: usize,

    /// Base address of the allocated kernel stack (for future deallocation).
    pub kernel_stack_base: usize,

    /// Size of the kernel stack in bytes.
    pub kernel_stack_size: usize,

    /// Current scheduling state.
    pub state: TaskState,

    /// Per-task tick counter — incremented each time this task is preempted.
    /// Used for Phase 2 verification only.
    pub tick_count: u64,
}
```

### Scheduler statics

```rust
const MAX_TASKS: usize = 2;

static mut TASKS: [MaybeUninit<TaskControlBlock>; MAX_TASKS] = [MaybeUninit::uninit(); MAX_TASKS];
static mut CURRENT: usize = 0;
static mut NUM_TASKS: usize = 0;
```

These `unsafe` mutable statics are accessed only from the IRQ handler path.
AArch64 masks IRQs on exception entry (PSTATE.I is set), so the handler is
non-reentrant. No lock or atomic wrapper is needed.

## 2. Kernel Stack Allocation and Task Seeding

Each task gets an **8 KiB kernel stack** allocated from the bump allocator
(the same allocator used for page table frames and the test ELF user stack).

### Pre-filled TrapFrame

To make a new task resumable by the context switch, `spawn_task` writes a
TrapFrame at the top of its kernel stack as if the task had been preempted:

```
kernel_stack_top (high address)
  +-------------------------+
  | TrapFrame (272 bytes)   |  <-- kernel_sp points here
  |   x[0..30] = 0          |
  |   elr = entry_point     |  <-- PC where "eret" jumps
  |   spsr = 0x345          |  <-- EL1h, IRQ unmasked
  +-------------------------+
  | (unused stack space)    |
  |         ...             |
  +-------------------------+
kernel_stack_base (low address)
```

**SPSR value `0x345`:** `M[3:0] = 0b0101` (EL1h), `D=1, A=1, I=0, F=1`.
Debug, SError, and FIQ exceptions remain masked. **IRQ is unmasked** so the
task is preemptible by the timer.

### `spawn_task(entry: fn() -> !)`

1. Allocate 8 KiB (2 pages) from bump allocator.
2. Compute `stack_top = base + 8192`.
3. Compute `sp = stack_top - 272` (TrapFrame size, 16-byte aligned).
4. Zero-fill 272 bytes at `sp`.
5. Write `elr = entry as u64` at offset 248 from `sp`.
6. Write `spsr = 0x345_u64` at offset 256 from `sp`.
7. Create TCB with `kernel_sp = sp`, `state = Ready`, `tick_count = 0`.
8. Store in `TASKS[NUM_TASKS]`, increment `NUM_TASKS`.

## 3. IRQ Handler Assembly Changes

### Current flow (Phase 1)

```asm
el1_irq_handler:
    sub sp, sp, #272
    // save x0-x30, ELR, SPSR to [sp]
    bl irq_dispatch          // no args, no return
    // restore x0-x30, ELR, SPSR from [sp]
    add sp, sp, #272
    eret
```

### New flow (Phase 2)

```asm
el1_irq_handler:
    sub sp, sp, #272
    // save x0-x30, ELR, SPSR to [sp]
    mov x0, sp              // pass current SP as argument
    bl irq_dispatch          // returns new SP in x0
    mov sp, x0              // adopt returned SP (may be same or different)
    // restore x0-x30, ELR, SPSR from [sp]
    add sp, sp, #272
    eret
```

Three instructions change. The assembly does not know or care whether a
context switch happened — it restores from whatever SP it receives.

### `irq_dispatch` signature change

```rust
// Before:
extern "C" fn irq_dispatch()

// After:
extern "C" fn irq_dispatch(current_sp: usize) -> usize
```

Logic inside `irq_dispatch`:
1. `gic::ack()` to get INTID.
2. If INTID == TIMER_INTID: call `timer::on_tick()`, then `sched::schedule(current_sp)` to get `new_sp`.
3. If INTID is spurious (1023): `new_sp = current_sp` (no switch).
4. If INTID is anything else: EOI it, `new_sp = current_sp`.
5. EOI the interrupt (unless spurious).
6. Return `new_sp`.

### Sync handler unchanged

`el1_sync_handler` is **not modified**. SVCs do not trigger preemption in
Phase 2. Phase 4 adds voluntary yield via SVC using the same `schedule()`
function.

## 4. The `schedule()` Function

```rust
pub unsafe fn schedule(current_sp: usize) -> usize
```

1. Save `current_sp` into `TASKS[CURRENT].kernel_sp`.
2. Mark `TASKS[CURRENT].state = Ready`.
3. Increment `TASKS[CURRENT].tick_count`.
4. Advance `CURRENT = (CURRENT + 1) % NUM_TASKS`.
5. Mark `TASKS[CURRENT].state = Running`.
6. Return `TASKS[CURRENT].kernel_sp`.

If `NUM_TASKS <= 1`, returns `current_sp` unchanged (no switch possible).

This is pure round-robin with no priority. Phase 3 replaces this with a
real scheduling policy.

## 5. Test Tasks

Two functions in `sched.rs`:

```rust
static TASK0_COUNTER: AtomicU64 = AtomicU64::new(0);
static TASK1_COUNTER: AtomicU64 = AtomicU64::new(0);

fn task0() -> ! {
    loop { TASK0_COUNTER.fetch_add(1, Ordering::Relaxed); }
}

fn task1() -> ! {
    loop { TASK1_COUNTER.fetch_add(1, Ordering::Relaxed); }
}
```

Pure integer tight loops. No syscalls, no FP, no I/O.

### Counter access

```rust
pub fn task_counters() -> (u64, u64)
```

Returns `(TASK0_COUNTER.load(Relaxed), TASK1_COUNTER.load(Relaxed))`.
Called from `timer::on_tick()` for verification output.

## 6. Boot Integration

In `main.rs`, inside the existing `#[cfg(feature = "qemu-virt")]` block.
After GIC init, timer arm, but **before** unmasking IRQs:

1. `sched::spawn_task(task0)` — seed task 0.
2. `sched::spawn_task(task1)` — seed task 1.
3. Print `[Sched] Spawned 2 tasks`.
4. Unmask IRQs (`msr daifclr, #2`).
5. Enter scheduler: load task 0's `kernel_sp`, restore TrapFrame, `eret`.

Step 5 is a small assembly helper (`sched::enter_scheduler` or inline asm)
that performs the initial TrapFrame restore — identical to the IRQ handler's
restore path. This proves the full preemption loop from the very first tick.

### Existing boot tail

The test ELF load, GENET init, and event loop continue to run on non-scheduler
boots (e.g. RPi5 without the scheduler path, or future integration). The
scheduler entry is gated: if tasks were spawned, enter the scheduler; otherwise
fall through to the existing event loop. Phase 3 turns the event loop into a
scheduler task.

## 7. Verification

### Serial output

After 500 ticks (5 seconds at 100 Hz), `timer::on_tick()` reads both counters
and prints:

```
[Sched] Task 0: 83741926, Task 1: 79205183
```

Both values must be nonzero. The rough magnitude proves both tasks got
approximately equal CPU time (pure round-robin, identical workloads).

### QEMU boot test milestone

In `xtask/src/qemu_test.rs`, update `aarch64_milestones()`:

Replace or add after the identity milestone:
```rust
Milestone {
    pattern: "[Sched] Task 0:",
    description: "scheduler verified",
},
```

The `[Boot] Entering event loop` milestone is replaced since the scheduler
path does not enter the event loop. Earlier milestones (serial, RNG, identity)
continue to validate the boot path.

### Workspace tests

`cargo test --workspace` continues to pass. The `sched` module is
`#[cfg(target_arch = "aarch64")]` gated. No host-runnable unit tests for
assembly/scheduling logic — the QEMU boot test is the integration test.

## 8. Known Limitations and Forward References

### No FP/SIMD context save

Tasks **must not** use floating-point or NEON instructions. The context switch
saves only general-purpose registers (x0-x30), ELR_EL1, and SPSR_EL1.
FP/SIMD state (q0-q31, FPCR, FPSR — 528 bytes) is not saved or restored.

**Forward reference:** FP/SIMD context save will be added when tasks require
floating-point operations. Options are eager save (always save/restore 32
NEON regs on every switch) or lazy save (trap on first FP access via
CPACR_EL1.FPEN, save only when needed). Lazy save is more efficient at scale
but requires an additional exception class handler. This should be addressed
no later than Phase 4 (blocking syscalls) since general-purpose code linked
against musl/libc may use FP for memcpy/memset optimizations.

### Fixed task count

`MAX_TASKS = 2` is a compile-time constant. No dynamic spawn or exit.
Phase 3 adds dynamic task management with a proper run queue.

### No scheduling policy

Pure round-robin alternation. No priority, no fairness accounting, no
timeslice control. Phase 3 adds real scheduling policy.

### EL1 only

Both test tasks run at EL1 (kernel privilege). No EL0 user-mode isolation.
The existing test ELF (which runs at EL0) is temporarily bypassed when the
scheduler path is active under `qemu-virt`. Phase 3 reintegrates EL0 tasks.

### Mutable statics

Scheduler state uses `unsafe` mutable statics, safe because the IRQ handler
is non-reentrant (PSTATE.I masked on exception entry). Phase 3 should
evaluate wrapping these in a `Scheduler` struct with controlled access.

## 9. File Summary

| File | Action | Purpose |
|------|--------|---------|
| `crates/harmony-boot-aarch64/src/sched.rs` | Create | TCB, spawn, schedule, test tasks, enter_scheduler |
| `crates/harmony-boot-aarch64/src/vectors.rs` | Modify | IRQ handler: pass SP, use returned SP |
| `crates/harmony-boot-aarch64/src/vectors.rs` | Modify | `irq_dispatch` signature + scheduler call |
| `crates/harmony-boot-aarch64/src/timer.rs` | Modify | `on_tick` prints counters after 500 ticks |
| `crates/harmony-boot-aarch64/src/main.rs` | Modify | Spawn tasks, enter scheduler in qemu-virt block |
| `xtask/src/qemu_test.rs` | Modify | Update aarch64 milestones for scheduler output |
