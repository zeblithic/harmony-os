# Phase 2: Process Table + Context Switch — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove preemptive context switching on aarch64 by timer-driving round-robin alternation between two kernel-mode tasks that increment separate counters.

**Architecture:** A new `sched.rs` in the boot crate owns TaskControlBlocks with per-task 8 KiB kernel stacks. The existing IRQ handler passes its SP to `irq_dispatch`, which calls the scheduler; the scheduler returns the next task's SP. The assembly restores from the returned SP and `eret`s into the new task. Two EL1 counter loops prove both tasks get CPU time.

**Tech Stack:** AArch64 assembly (global_asm), Rust no_std, ARM Generic Timer + GICv3, QEMU virt

---

**Design spec:** `docs/superpowers/specs/2026-04-03-process-table-context-switch-design.md`

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `crates/harmony-boot-aarch64/src/sched.rs` | Create | TaskControlBlock, TaskState, spawn_task, schedule, enter_scheduler, test tasks, counters |
| `crates/harmony-boot-aarch64/src/vectors.rs` | Modify | IRQ handler: pass SP as x0, use returned x0 as new SP; irq_dispatch signature change |
| `crates/harmony-boot-aarch64/src/timer.rs` | Modify | on_tick prints scheduler verification after 500 ticks |
| `crates/harmony-boot-aarch64/src/main.rs` | Modify | Add `mod sched`, spawn tasks, enter scheduler in qemu-virt block |
| `xtask/src/qemu_test.rs` | Modify | Replace event loop milestone with scheduler verification milestone |

---

### Task 1: Create sched.rs with TaskControlBlock and TaskState

**Files:**
- Create: `crates/harmony-boot-aarch64/src/sched.rs`

This task creates the data structures only — no scheduling logic yet. The types will be used by all subsequent tasks.

- [ ] **Step 1: Create sched.rs with module header, TaskState, and TaskControlBlock**

Create `crates/harmony-boot-aarch64/src/sched.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! Preemptive round-robin scheduler for Phase 2 context switch validation.
//!
//! Owns per-task kernel stacks and [`TaskControlBlock`]s. The timer IRQ
//! handler calls [`schedule`] on each tick, which round-robins between
//! tasks by returning the next task's saved kernel SP. The IRQ assembly
//! restores registers from that SP and `eret`s into the new task.
//!
//! # Limitations (Phase 2)
//!
//! - Fixed task count (`MAX_TASKS = 2`), no dynamic spawn/exit.
//! - EL1-only tasks (no EL0 user mode).
//! - No FP/SIMD context save — tasks must not use floating-point.
//!   FP context switch will be added no later than Phase 4; see design spec
//!   section 8 for options (eager vs lazy save via CPACR_EL1.FPEN).
//! - No priority or fairness — pure round-robin alternation.
//! - Mutable statics are safe because the IRQ handler is non-reentrant
//!   (PSTATE.I is set on exception entry).

#![cfg_attr(not(target_arch = "aarch64"), allow(dead_code, unused_imports))]

use core::mem::MaybeUninit;

/// Maximum number of tasks. Fixed at 2 for Phase 2.
const MAX_TASKS: usize = 2;

/// Size of each task's kernel stack in bytes (8 KiB = 2 pages).
const KERNEL_STACK_SIZE: usize = 8192;

/// Size of the TrapFrame in bytes (31 GP regs + ELR + SPSR = 264,
/// padded to 272 for 16-byte alignment). Must match vectors.rs assembly.
const TRAPFRAME_SIZE: usize = 272;

/// Scheduling state for a task.
#[derive(Clone, Copy, PartialEq)]
pub enum TaskState {
    Ready,
    Running,
}

/// Per-task scheduling state. Stored in a fixed-size array, indexed by
/// task number (0 or 1 in Phase 2).
#[repr(C)]
pub struct TaskControlBlock {
    /// Saved SP_EL1 — points to the base of a TrapFrame on this task's
    /// kernel stack. The IRQ restore path loads registers from here.
    pub kernel_sp: usize,
    /// Base address of the allocated kernel stack (low address).
    pub kernel_stack_base: usize,
    /// Size of the kernel stack in bytes.
    pub kernel_stack_size: usize,
    /// Current scheduling state.
    pub state: TaskState,
    /// Number of times this task has been preempted (for verification).
    pub preempt_count: u64,
}

/// Task array — only accessed from the IRQ handler (non-reentrant).
static mut TASKS: [MaybeUninit<TaskControlBlock>; MAX_TASKS] =
    [MaybeUninit::uninit(), MaybeUninit::uninit()];

/// Index of the currently running task.
static mut CURRENT: usize = 0;

/// Number of tasks that have been spawned.
static mut NUM_TASKS: usize = 0;
```

- [ ] **Step 2: Register the module in main.rs**

Add `mod sched;` to `crates/harmony-boot-aarch64/src/main.rs` after the existing `mod gic;` line (line 16). The module list should read:

```rust
mod bump_alloc;
mod fdt_parse;
mod mmu;
mod pl011;
mod rndr;
mod timer;
mod gic;
mod sched;

mod platform;
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build --locked --target aarch64-unknown-uefi --release -p harmony-boot-aarch64`
Expected: Compiles with no errors (warnings about unused items are fine at this stage).

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-boot-aarch64/src/sched.rs crates/harmony-boot-aarch64/src/main.rs
git commit -m "feat(sched): add TaskControlBlock and TaskState data structures"
```

---

### Task 2: Implement spawn_task

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/sched.rs`

Adds `spawn_task()` which allocates an 8 KiB kernel stack from the bump allocator, pre-fills a TrapFrame at the top of the stack so the task is "resumable" by the context switch, and stores the TCB.

- [ ] **Step 1: Add the spawn_task function**

Add the following to the end of `crates/harmony-boot-aarch64/src/sched.rs`:

```rust
use crate::bump_alloc::BumpAllocator;
use crate::syscall::TrapFrame;

/// SPSR value for new tasks: EL1h (M=0b0101), D=1, A=1, I=0, F=1.
/// Debug, SError, and FIQ masked; IRQ **unmasked** so the task is preemptible.
const INITIAL_SPSR: u64 = 0x345;

/// Spawn a new task that will begin execution at `entry`.
///
/// Allocates an 8 KiB kernel stack from `bump`, writes a zeroed TrapFrame
/// at the top with `elr = entry` and `spsr = INITIAL_SPSR`, and records
/// the task in [`TASKS`].
///
/// # Safety
///
/// - Must be called before IRQs are unmasked (before `msr daifclr, #2`).
/// - `bump` must have at least 2 free frames.
/// - Must not be called more than [`MAX_TASKS`] times.
pub unsafe fn spawn_task(entry: fn() -> !, bump: &mut BumpAllocator) {
    let n = unsafe { NUM_TASKS };
    assert!(n < MAX_TASKS, "spawn_task: MAX_TASKS exceeded");

    // Allocate 2 contiguous pages (8 KiB) for the kernel stack.
    let page0 = bump.alloc_frame().expect("sched: kernel stack page 0").0 as usize;
    let page1 = bump.alloc_frame().expect("sched: kernel stack page 1").0 as usize;
    assert_eq!(page1, page0 + 4096, "kernel stack pages must be contiguous");

    let stack_top = page0 + KERNEL_STACK_SIZE;

    // Place a TrapFrame at the top of the stack.
    // kernel_sp points to the base of the TrapFrame (stack grows down).
    let sp = stack_top - TRAPFRAME_SIZE;

    // Zero the TrapFrame region, then set elr and spsr.
    let frame = sp as *mut TrapFrame;
    // Zero all 272 bytes (covers x[0..31], elr, spsr, and padding).
    core::ptr::write_bytes(frame as *mut u8, 0, TRAPFRAME_SIZE);
    (*frame).elr = entry as u64;
    (*frame).spsr = INITIAL_SPSR;

    TASKS[n] = MaybeUninit::new(TaskControlBlock {
        kernel_sp: sp,
        kernel_stack_base: page0,
        kernel_stack_size: KERNEL_STACK_SIZE,
        state: TaskState::Ready,
        preempt_count: 0,
    });
    NUM_TASKS = n + 1;
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo build --locked --target aarch64-unknown-uefi --release -p harmony-boot-aarch64`
Expected: Compiles. The `TrapFrame` import from `syscall.rs` works because it's `pub struct`.

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-boot-aarch64/src/sched.rs
git commit -m "feat(sched): implement spawn_task with kernel stack allocation and TrapFrame seeding"
```

---

### Task 3: Implement schedule() and test task counter functions

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/sched.rs`

Adds the `schedule()` function (called from IRQ handler) and the test task functions with their atomic counters.

- [ ] **Step 1: Add atomic counters and test task functions**

Add to `crates/harmony-boot-aarch64/src/sched.rs`, after the `spawn_task` function:

```rust
#[cfg(target_arch = "aarch64")]
use core::sync::atomic::{AtomicU64, Ordering};

/// Counter incremented by task 0 — proves it received CPU time.
#[cfg(target_arch = "aarch64")]
static TASK0_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Counter incremented by task 1 — proves it received CPU time.
#[cfg(target_arch = "aarch64")]
static TASK1_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Test task 0: tight loop incrementing its counter until preempted.
#[cfg(target_arch = "aarch64")]
pub fn task0() -> ! {
    loop {
        TASK0_COUNTER.fetch_add(1, Ordering::Relaxed);
    }
}

/// Test task 1: tight loop incrementing its counter until preempted.
#[cfg(target_arch = "aarch64")]
pub fn task1() -> ! {
    loop {
        TASK1_COUNTER.fetch_add(1, Ordering::Relaxed);
    }
}

/// Read both task counters (for verification output by timer::on_tick).
#[cfg(target_arch = "aarch64")]
pub fn task_counters() -> (u64, u64) {
    (
        TASK0_COUNTER.load(Ordering::Relaxed),
        TASK1_COUNTER.load(Ordering::Relaxed),
    )
}
```

- [ ] **Step 2: Add the schedule function**

Add to `crates/harmony-boot-aarch64/src/sched.rs`, after the counter functions:

```rust
/// Round-robin schedule — called from `irq_dispatch` on each timer tick.
///
/// Saves `current_sp` into the running task's TCB, advances to the next
/// Ready task, and returns that task's saved `kernel_sp`. If only one
/// task exists (or zero), returns `current_sp` unchanged.
///
/// # Safety
///
/// Must only be called from the IRQ handler path (non-reentrant, PSTATE.I set).
#[cfg(target_arch = "aarch64")]
pub unsafe fn schedule(current_sp: usize) -> usize {
    let n = NUM_TASKS;
    if n <= 1 {
        return current_sp;
    }

    let cur = CURRENT;

    // Save the interrupted task's SP and mark it Ready.
    let current_tcb = TASKS[cur].assume_init_mut();
    current_tcb.kernel_sp = current_sp;
    current_tcb.state = TaskState::Ready;
    current_tcb.preempt_count += 1;

    // Advance to next task (round-robin).
    let next = (cur + 1) % n;
    CURRENT = next;

    let next_tcb = TASKS[next].assume_init_mut();
    next_tcb.state = TaskState::Running;

    next_tcb.kernel_sp
}

/// Return the number of spawned tasks.
#[cfg(target_arch = "aarch64")]
pub fn num_tasks() -> usize {
    unsafe { NUM_TASKS }
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build --locked --target aarch64-unknown-uefi --release -p harmony-boot-aarch64`
Expected: Compiles.

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-boot-aarch64/src/sched.rs
git commit -m "feat(sched): implement schedule() round-robin and test task counter loops"
```

---

### Task 4: Modify IRQ handler assembly and irq_dispatch

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/vectors.rs:210-292`

Changes the IRQ handler assembly to pass SP as x0 and use the returned x0 as the new SP. Changes `irq_dispatch` to accept and return `usize`, calling `schedule()` on timer ticks.

- [ ] **Step 1: Modify the IRQ handler assembly**

In `crates/harmony-boot-aarch64/src/vectors.rs`, find the IRQ handler assembly block. Change lines 238-239 from:

```asm
    // Call Rust IRQ dispatch
    "bl irq_dispatch",
```

to:

```asm
    // Call Rust IRQ dispatch — pass current SP, receive (possibly new) SP
    "mov x0, sp",
    "bl irq_dispatch",
    "mov sp, x0",
```

This passes the current stack pointer (pointing at the TrapFrame base) as x0, and after the call, sets SP to the returned value. If no context switch happened, x0 == the original SP and nothing changes. If a switch happened, SP now points to the new task's kernel stack where its TrapFrame is waiting.

- [ ] **Step 2: Update the irq_dispatch function signature and body**

In the same file (`vectors.rs`), replace the `irq_dispatch` function (lines 277-292) with:

```rust
/// IRQ dispatch — called from `el1_irq_handler` assembly.
///
/// Acknowledges the interrupt via GIC, routes to the appropriate handler,
/// and signals end-of-interrupt. On timer ticks, calls the scheduler which
/// may return a different SP (context switch). Spurious interrupts (INTID
/// 1023) are silently ignored — writing 1023 to ICC_EOIR1_EL1 is UNPREDICTABLE.
///
/// # Arguments
///
/// - `current_sp`: the interrupted task's kernel SP (points at saved TrapFrame)
///
/// # Returns
///
/// The kernel SP to restore from — same as `current_sp` if no switch, or the
/// next task's SP if the scheduler decided to switch.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
extern "C" fn irq_dispatch(current_sp: usize) -> usize {
    let intid = gic::ack();
    let new_sp = match intid {
        gic::TIMER_INTID => {
            timer::on_tick();
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

- [ ] **Step 3: Add the sched import**

In `vectors.rs`, add `use crate::sched;` alongside the existing imports (around line 269-270). The imports should read:

```rust
use crate::gic;
use crate::sched;
use crate::timer;
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo build --locked --target aarch64-unknown-uefi --release -p harmony-boot-aarch64`
Expected: Compiles.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-boot-aarch64/src/vectors.rs
git commit -m "feat(vectors): pass SP through irq_dispatch for context switch support"
```

---

### Task 5: Add scheduler verification output to timer

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/timer.rs:113-121`

After 500 ticks (5 seconds at 100 Hz), `on_tick` reads both task counters and prints a verification line. This is the signal the QEMU boot test watches for.

- [ ] **Step 1: Modify on_tick to print scheduler verification**

In `crates/harmony-boot-aarch64/src/timer.rs`, replace the `on_tick` function (lines 113-121) with:

```rust
/// Timer tick callback — called by the IRQ handler on each timer interrupt.
///
/// Increments the tick counter, rearms the timer. Every 100 ticks (once
/// per second), prints the tick count. At tick 500, prints the scheduler
/// verification line with both task counters (if tasks are running).
#[cfg(target_arch = "aarch64")]
pub fn on_tick() {
    let count = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    rearm();

    // Print tick count once per second (every 100 ticks) for boot verification.
    if count % 100 == 0 {
        print_tick(count);
    }

    // At tick 500 (5 seconds), print scheduler verification if tasks are running.
    if count == 500 {
        print_sched_verification();
    }
}
```

- [ ] **Step 2: Add the print_sched_verification function**

Add after the existing `print_tick` function in `timer.rs`:

```rust
/// Print scheduler verification line: "[Sched] Task 0: N, Task 1: M".
/// Called exactly once at tick 500. Uses the same IRQ-safe serial write
/// approach as `print_tick` — no allocator, no fmt.
#[cfg(target_arch = "aarch64")]
fn print_sched_verification() {
    use crate::sched;

    if sched::num_tasks() < 2 {
        return;
    }

    let (c0, c1) = sched::task_counters();

    use crate::pl011;

    // "[Sched] Task 0: "
    for &b in b"[Sched] Task 0: " {
        unsafe { pl011::write_byte(b) };
    }
    print_u64(c0);

    // ", Task 1: "
    for &b in b", Task 1: " {
        unsafe { pl011::write_byte(b) };
    }
    print_u64(c1);

    unsafe {
        pl011::write_byte(b'\r');
        pl011::write_byte(b'\n');
    }
}

/// Print a u64 as decimal to PL011. IRQ-safe (no allocator).
#[cfg(target_arch = "aarch64")]
fn print_u64(val: u64) {
    use crate::pl011;

    let mut buf = [0u8; 20]; // u64 max is 20 digits
    let mut n = val;
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    for &b in &buf[i..] {
        unsafe { pl011::write_byte(b) };
    }
}
```

- [ ] **Step 3: Refactor print_tick to use print_u64**

Since `print_tick` has the same decimal-to-serial logic, refactor it to use `print_u64`. Replace the `print_tick` function (lines 126-155) with:

```rust
/// Minimal serial print for IRQ context — no allocator, no formatting.
/// Writes "[Tick] NNNNN\r\n" via PL011.
#[cfg(target_arch = "aarch64")]
fn print_tick(count: u64) {
    use crate::pl011;

    for &b in b"[Tick] " {
        unsafe { pl011::write_byte(b) };
    }
    print_u64(count);
    unsafe {
        pl011::write_byte(b'\r');
        pl011::write_byte(b'\n');
    }
}
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo build --locked --target aarch64-unknown-uefi --release -p harmony-boot-aarch64`
Expected: Compiles.

- [ ] **Step 5: Run workspace tests to confirm no regressions**

Run: `cargo test --workspace`
Expected: All tests pass (timer host tests are pure computation, not affected).

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-boot-aarch64/src/timer.rs
git commit -m "feat(timer): add scheduler verification output at tick 500"
```

---

### Task 6: Wire up boot sequence — spawn tasks and enter scheduler

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/main.rs:456-483`
- Modify: `crates/harmony-boot-aarch64/src/sched.rs` (add `enter_scheduler`)

This task spawns the two test tasks in the qemu-virt block, then enters the scheduler by loading task 0's TrapFrame and executing `eret`. This replaces the normal boot tail (test ELF + event loop) when the scheduler is active.

- [ ] **Step 1: Add enter_scheduler to sched.rs**

Add to the end of `crates/harmony-boot-aarch64/src/sched.rs`:

```rust
/// Enter the scheduler by loading task 0's TrapFrame and executing `eret`.
///
/// This is the initial entry into the scheduler loop. It loads the first
/// task's pre-filled TrapFrame exactly as the IRQ handler would on a
/// context switch: restore all GP registers, ELR, SPSR, then `eret` into
/// the task.
///
/// # Safety
///
/// - At least one task must have been spawned via [`spawn_task`].
/// - IRQs must already be unmasked so the task will be preempted.
/// - This function never returns.
#[cfg(target_arch = "aarch64")]
pub unsafe fn enter_scheduler() -> ! {
    assert!(NUM_TASKS > 0, "enter_scheduler: no tasks spawned");

    // Mark task 0 as Running.
    TASKS[0].assume_init_mut().state = TaskState::Running;
    CURRENT = 0;

    let sp = TASKS[0].assume_init_ref().kernel_sp;

    core::arch::asm!(
        // Set SP to task 0's kernel stack (TrapFrame base).
        "mov sp, {sp}",

        // Restore ELR and SPSR from the TrapFrame.
        "ldp x10, x11, [sp, #248]",
        "msr elr_el1, x10",
        "msr spsr_el1, x11",

        // Restore X0-X29.
        "ldp x0,  x1,  [sp, #0]",
        "ldp x2,  x3,  [sp, #16]",
        "ldp x4,  x5,  [sp, #32]",
        "ldp x6,  x7,  [sp, #48]",
        "ldp x8,  x9,  [sp, #64]",
        "ldp x10, x11, [sp, #80]",
        "ldp x12, x13, [sp, #96]",
        "ldp x14, x15, [sp, #112]",
        "ldp x16, x17, [sp, #128]",
        "ldp x18, x19, [sp, #144]",
        "ldp x20, x21, [sp, #160]",
        "ldp x22, x23, [sp, #176]",
        "ldp x24, x25, [sp, #192]",
        "ldp x26, x27, [sp, #208]",
        "ldp x28, x29, [sp, #224]",
        "ldr x30, [sp, #240]",

        // Deallocate TrapFrame and eret into the task.
        "add sp, sp, #272",
        "eret",

        sp = in(reg) sp,
        options(noreturn),
    );
}
```

- [ ] **Step 2: Modify main.rs to spawn tasks and enter scheduler**

In `crates/harmony-boot-aarch64/src/main.rs`, replace the existing `#[cfg(feature = "qemu-virt")]` block (lines 456-483) with:

```rust
    // ── Initialize GICv3 interrupt controller + timer interrupts ──
    // GIC and timer constants are only defined for qemu-virt. RPi5 uses
    // Apple AIC — interrupt support tracked by harmony-os-1hc.
    #[cfg(feature = "qemu-virt")]
    {
        unsafe {
            gic::init(
                platform::GICD_BASE as *mut u8,
                platform::GICR_BASE as *mut u8,
            )
        };
        let _ = writeln!(
            serial,
            "[GIC] GICv3 initialized: GICD={:#x} GICR={:#x}",
            platform::GICD_BASE,
            platform::GICR_BASE,
        );

        // Arm the physical timer at 100 Hz.
        timer::enable_tick(100);
        let _ = writeln!(
            serial,
            "[Timer] 100 Hz tick armed (reload={})",
            timer::freq() / 100,
        );

        // Spawn two test tasks for scheduler verification.
        unsafe { sched::spawn_task(sched::task0, &mut bump) };
        unsafe { sched::spawn_task(sched::task1, &mut bump) };
        let _ = writeln!(serial, "[Sched] Spawned 2 tasks");

        // Unmask IRQ exceptions.
        // From this point forward, el1_irq_handler fires on every timer tick.
        unsafe { core::arch::asm!("msr daifclr, #2") };
        let _ = writeln!(serial, "[IRQ] Interrupts unmasked");

        // Enter the scheduler — loads task 0's TrapFrame and erets into it.
        // This never returns.
        let _ = writeln!(serial, "[Sched] Entering scheduler");
        unsafe { sched::enter_scheduler() };
    }
```

**Important:** This block now ends with `enter_scheduler()` which never returns. The existing test ELF load, GENET init, and event loop code below this block will only run on RPi5 (where the `qemu-virt` cfg is not active). No changes needed to that code.

- [ ] **Step 3: Make task0 and task1 public**

If not already public in Task 3 (verify), ensure both functions in `sched.rs` are `pub fn task0` and `pub fn task1` so main.rs can reference them.

- [ ] **Step 4: Verify it compiles**

Run: `cargo build --locked --target aarch64-unknown-uefi --release -p harmony-boot-aarch64`
Expected: Compiles. Possible warning about unreachable code after `enter_scheduler()` — this is expected and correct.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-boot-aarch64/src/sched.rs crates/harmony-boot-aarch64/src/main.rs
git commit -m "feat(boot): spawn test tasks and enter scheduler on qemu-virt"
```

---

### Task 7: Update QEMU boot test milestones

**Files:**
- Modify: `xtask/src/qemu_test.rs:32-51`

The QEMU virt boot path now enters the scheduler instead of the event loop. Update the aarch64 milestones to expect the scheduler verification line.

- [ ] **Step 1: Update aarch64_milestones**

In `xtask/src/qemu_test.rs`, replace the `aarch64_milestones` function (lines 32-51) with:

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
            pattern: "[Sched] Spawned 2 tasks",
            description: "tasks spawned",
        },
        Milestone {
            pattern: "[Sched] Task 0:",
            description: "scheduler verified",
        },
    ]
}
```

Changes:
- Replaced `[Boot] Entering event loop` with `[Sched] Spawned 2 tasks` (fires immediately after spawn).
- Added `[Sched] Task 0:` as the final milestone (fires at tick 500 = 5 seconds).
- The test timeout (default 30 seconds) is plenty for 5 seconds of scheduler run.

- [ ] **Step 2: Verify xtask compiles**

Run: `cargo build -p xtask`
Expected: Compiles.

- [ ] **Step 3: Run the QEMU boot test locally (if QEMU available)**

Run: `cargo xtask qemu-test --target aarch64 --timeout 30`

Expected output (approximate):
```
[aarch64] BUILDING... ok (Xs)
[aarch64] BOOTING...
[aarch64] ✓ [PL011] Serial initialized ...
[aarch64] ✓ [RNDR] ...
[aarch64] ✓ [Identity] ...
[aarch64] ✓ [Sched] Spawned 2 tasks ...
[aarch64] ✓ [Sched] Task 0: ...
[aarch64] PASS (Xs)
```

The `[Sched] Task 0:` line proves both tasks got CPU time (both counters nonzero in the output).

- [ ] **Step 4: Run workspace tests**

Run: `cargo test --workspace`
Expected: All tests pass.

- [ ] **Step 5: Run nightly rustfmt**

Run: `cargo +nightly fmt --all`
Expected: No changes (or apply formatting if needed).

- [ ] **Step 6: Commit**

```bash
git add xtask/src/qemu_test.rs
git commit -m "test(xtask): update aarch64 milestones for scheduler verification"
```

---

## Self-Review Checklist

### Spec coverage

| Spec Section | Task(s) |
|---|---|
| 1. TaskControlBlock | Task 1 |
| 2. Kernel stack + TrapFrame seeding | Task 2 |
| 3. IRQ handler assembly changes | Task 4 |
| 4. schedule() function | Task 3 |
| 5. Test tasks + counters | Task 3 |
| 6. Boot integration | Task 6 |
| 7. Verification (serial + QEMU test) | Task 5, Task 7 |
| 8. Known limitations (FP/SIMD, fixed count, EL1-only) | Task 1 module doc |
| 9. File summary | All tasks match |

### Type consistency

- `TaskControlBlock` — defined in Task 1, used in Tasks 2, 3, 6. Fields consistent.
- `TaskState` — defined in Task 1, used in Tasks 2, 3, 6. Variants `Ready`/`Running` consistent.
- `spawn_task(entry: fn() -> !, bump: &mut BumpAllocator)` — defined in Task 2, called in Task 6.
- `schedule(current_sp: usize) -> usize` — defined in Task 3, called in Task 4.
- `task_counters() -> (u64, u64)` — defined in Task 3, called in Task 5.
- `num_tasks() -> usize` — defined in Task 3, called in Task 5.
- `enter_scheduler() -> !` — defined in Task 6, called in Task 6.
- `task0`, `task1` — defined as `pub fn` in Task 3, referenced in Task 6 as `sched::task0`, `sched::task1`.
- `irq_dispatch(current_sp: usize) -> usize` — changed in Task 4, called from assembly in Task 4.
- `TRAPFRAME_SIZE = 272` — defined in Task 1, used in Task 2. Matches assembly `sub sp, sp, #272`.
- `INITIAL_SPSR = 0x345` — defined in Task 2, used in Task 2.
