# Phase 3: Dynamic Scheduler Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform the Phase 2 proof-of-concept scheduler (fixed 2-task array, counter loops) into a production scheduler with dynamic task management (up to 64 tasks), proper lifecycle states (Ready/Running/Blocked/Dead), guard pages on all kernel stacks, and the event loop running as a preemptible scheduler task.

**Architecture:** Keep the same SP-swap context switch mechanism from Phase 2 (IRQ handler passes SP through `irq_dispatch` → `schedule()` → may return a different task's SP). Replace the fixed infrastructure: grow the task array to 64 slots, add Blocked/Dead states with a state-aware round-robin scan, allocate guard pages below each kernel stack, and move the boot event loop into a system task (PID 1) alongside an idle task (PID 0). PIDs bridge to the microkernel's Process struct via a lightweight integer field.

**Tech Stack:** Rust (no_std, aarch64-unknown-uefi), ARM Generic Timer (100 Hz), GICv3, AArch64 page tables (identity map), QEMU virt machine for testing.

**Spec:** `docs/superpowers/specs/2026-04-03-phase3-dynamic-scheduler-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `crates/harmony-boot-aarch64/src/sched.rs` | Modify | Task storage, spawn_task, schedule(), lifecycle states |
| `crates/harmony-boot-aarch64/src/main.rs` | Modify | RUNTIME static, idle/system tasks, boot flow rewrite |
| `crates/harmony-boot-aarch64/src/mmu.rs` | Modify | Guard page support (mark_guard_page) |
| `crates/harmony-boot-aarch64/src/syscall.rs` | Modify | Guard page detection in abort_handler |
| `crates/harmony-boot-aarch64/src/timer.rs` | Modify | Remove Phase 2 verification, simplify on_tick |
| `xtask/src/qemu_test.rs` | Modify | Update aarch64 boot milestones |

---

### Task 1: sched.rs — Data Structures and API

Update TaskControlBlock, TaskState, MAX_TASKS, and spawn_task signature. Keep Phase 2 test tasks temporarily so main.rs callers still compile.

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/sched.rs`
- Modify: `crates/harmony-boot-aarch64/src/main.rs:478-479` (spawn_task callers)

- [ ] **Step 1: Write host tests for new data structures**

Add these tests at the bottom of `crates/harmony-boot-aarch64/src/sched.rs` inside the existing `#[cfg(test)] mod tests` block (there isn't one yet in sched.rs — create it):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use harmony_microkernel::vm::PAGE_SIZE;

    #[test]
    fn task_state_has_four_variants() {
        let states = [
            TaskState::Ready,
            TaskState::Running,
            TaskState::Blocked,
            TaskState::Dead,
        ];
        for i in 0..states.len() {
            for j in (i + 1)..states.len() {
                assert_ne!(states[i], states[j]);
            }
        }
    }

    #[test]
    fn max_tasks_is_64() {
        assert_eq!(MAX_TASKS, 64);
    }

    #[test]
    fn check_guard_page_detects_hit() {
        unsafe {
            NUM_TASKS = 1;
            TASKS[0] = MaybeUninit::new(TaskControlBlock {
                kernel_sp: 0,
                kernel_stack_base: 0x2_0000,
                kernel_stack_size: 8192,
                state: TaskState::Ready,
                preempt_count: 0,
                pid: 7,
                name: "test-task",
                entry: None,
            });
        }
        // Guard page: [0x2_0000 - PAGE_SIZE, 0x2_0000)
        let guard_start = 0x2_0000 - PAGE_SIZE;
        assert_eq!(
            check_guard_page(guard_start + 100),
            Some(("test-task", 7))
        );
        // Outside guard page
        assert_eq!(check_guard_page(0x3_0000), None);
        // Below guard page
        assert_eq!(check_guard_page(guard_start - 1), None);
        // Cleanup
        unsafe { NUM_TASKS = 0 };
    }

    #[test]
    fn check_guard_page_empty_returns_none() {
        unsafe { NUM_TASKS = 0 };
        assert_eq!(check_guard_page(0x1000), None);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-boot-aarch64`
Expected: Compilation failure — `TaskState::Blocked` and `TaskState::Dead` don't exist yet, `check_guard_page` doesn't exist, `MAX_TASKS` is 2, TCB doesn't have `pid`/`name`/`entry`.

- [ ] **Step 3: Update TaskState enum**

In `crates/harmony-boot-aarch64/src/sched.rs`, replace the `TaskState` enum:

```rust
/// Scheduling state for a task.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TaskState {
    Ready,
    Running,
    /// Waiting on syscall/IPC. Phase 4 adds block_current() and wake().
    Blocked,
    /// Exited — scheduler skips. Stack reclamation deferred to Phase 4+.
    Dead,
}
```

- [ ] **Step 4: Update TaskControlBlock**

Replace the `TaskControlBlock` struct:

```rust
/// Per-task scheduling state. Stored in a fixed-size array, indexed by
/// task number (0..MAX_TASKS).
#[repr(C)]
pub struct TaskControlBlock {
    /// Saved SP_EL1 — points to the base of a TrapFrame on this task's
    /// kernel stack. The IRQ restore path loads registers from here.
    pub kernel_sp: usize,
    /// Base address of the allocated kernel stack (low address).
    /// Guard page lives at kernel_stack_base - PAGE_SIZE.
    pub kernel_stack_base: usize,
    /// Size of the kernel stack in bytes.
    pub kernel_stack_size: usize,
    /// Current scheduling state.
    pub state: TaskState,
    /// Number of times this task has been scheduled out.
    pub preempt_count: u64,
    /// Microkernel Process ID (0 = idle, 1 = system, 2+ = user).
    pub pid: u32,
    /// Debug name for diagnostic output.
    pub name: &'static str,
    /// Entry point (for debug; not re-invoked after initial start).
    pub entry: Option<fn() -> !>,
}
```

- [ ] **Step 5: Update MAX_TASKS and TASKS array**

Replace the constants and static:

```rust
/// Maximum number of tasks. Phase 3 expands from 2 to 64.
const MAX_TASKS: usize = 64;
```

Replace the TASKS array initialization:

```rust
/// Sentinel value for array initialization — MaybeUninit requires no init.
const UNINIT_TCB: MaybeUninit<TaskControlBlock> = MaybeUninit::uninit();

/// Task array — only accessed from the IRQ handler (non-reentrant).
static mut TASKS: [MaybeUninit<TaskControlBlock>; MAX_TASKS] = [UNINIT_TCB; MAX_TASKS];
```

- [ ] **Step 6: Update spawn_task signature and body**

Replace the entire `spawn_task` function:

```rust
/// Spawn a new task that will begin execution at `entry`.
///
/// Allocates an 8 KiB kernel stack from `bump`, writes a zeroed TrapFrame
/// at the top with `elr = entry` and `spsr = INITIAL_SPSR`, and records
/// the task in [`TASKS`].
///
/// Returns the task index (slot number in the TASKS array).
///
/// # Safety
///
/// - Must be called before IRQs are unmasked (before `enter_scheduler`).
/// - `bump` must have enough free frames for the kernel stack.
/// - Must not be called more than [`MAX_TASKS`] times.
pub unsafe fn spawn_task(
    name: &'static str,
    pid: u32,
    entry: fn() -> !,
    bump: &mut BumpAllocator,
) -> usize {
    let n = unsafe { NUM_TASKS };
    assert!(n < MAX_TASKS, "spawn_task: MAX_TASKS exceeded");

    let page_size = PAGE_SIZE as usize;
    let pages_needed = (KERNEL_STACK_SIZE + page_size - 1) / page_size;

    // Allocate contiguous pages for the kernel stack.
    let base = bump.alloc_frame().expect("sched: kernel stack frame 0").0 as usize;
    for i in 1..pages_needed {
        let frame = bump.alloc_frame().expect("sched: kernel stack frame").0 as usize;
        assert_eq!(
            frame,
            base + i * page_size,
            "kernel stack frames must be contiguous"
        );
    }

    let stack_size = pages_needed * page_size;
    let stack_top = base + stack_size;

    // Place a TrapFrame at the top of the stack.
    let sp = stack_top - TRAPFRAME_SIZE;

    let frame_ptr = sp as *mut TrapFrame;
    core::ptr::write_bytes(frame_ptr as *mut u8, 0, TRAPFRAME_SIZE);
    (*frame_ptr).elr = entry as u64;
    (*frame_ptr).spsr = INITIAL_SPSR;

    TASKS[n] = MaybeUninit::new(TaskControlBlock {
        kernel_sp: sp,
        kernel_stack_base: base,
        kernel_stack_size: stack_size,
        state: TaskState::Ready,
        preempt_count: 0,
        pid,
        name,
        entry: Some(entry),
    });
    NUM_TASKS = n + 1;
    n
}
```

- [ ] **Step 7: Add check_guard_page function**

Add this function after `num_tasks()` (before the `#[cfg(test)]` block), NOT cfg-gated so it's testable on host:

```rust
/// Check if a faulting address falls within any task's guard page.
///
/// The guard page is the PAGE_SIZE region immediately below each task's
/// `kernel_stack_base`. Returns `Some((name, pid))` if the address is
/// in a guard page, `None` otherwise. Used by the abort handler.
pub fn check_guard_page(addr: u64) -> Option<(&'static str, u32)> {
    let page_size = PAGE_SIZE as u64;
    let n = unsafe { NUM_TASKS };
    for i in 0..n {
        let tcb = unsafe { TASKS[i].assume_init_ref() };
        let guard_base = (tcb.kernel_stack_base as u64).wrapping_sub(page_size);
        let guard_top = tcb.kernel_stack_base as u64;
        if addr >= guard_base && addr < guard_top {
            return Some((tcb.name, tcb.pid));
        }
    }
    None
}
```

- [ ] **Step 8: Update main.rs spawn_task callers**

In `crates/harmony-boot-aarch64/src/main.rs`, inside the `#[cfg(feature = "qemu-virt")]` block (~line 478-479), replace:

```rust
        unsafe { sched::spawn_task(sched::task0, &mut bump) };
        unsafe { sched::spawn_task(sched::task1, &mut bump) };
```

With:

```rust
        unsafe { sched::spawn_task("test0", 0, sched::task0, &mut bump) };
        unsafe { sched::spawn_task("test1", 1, sched::task1, &mut bump) };
```

- [ ] **Step 9: Run tests to verify they pass**

Run: `cargo test -p harmony-boot-aarch64`
Expected: All tests pass, including the 4 new tests.

- [ ] **Step 10: Commit**

```bash
git add crates/harmony-boot-aarch64/src/sched.rs crates/harmony-boot-aarch64/src/main.rs
git commit -m "feat(sched): expand data structures for Phase 3 — Blocked/Dead states, PID, 64-task array"
```

---

### Task 2: sched.rs — State-Aware Scheduling

Rewrite `schedule()` to skip Dead and Blocked tasks using a round-robin scan.

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/sched.rs:187-212`

- [ ] **Step 1: Rewrite schedule()**

Replace the entire `schedule` function in `crates/harmony-boot-aarch64/src/sched.rs`:

```rust
/// State-aware round-robin scheduler — called from `irq_dispatch` on
/// each timer tick.
///
/// Saves `current_sp` into the running task's TCB, then scans forward
/// (round-robin) for the next Ready task. Blocked and Dead tasks are
/// skipped. If no Ready task is found, returns `current_sp` unchanged
/// (the idle task should always be Ready, so this is a safety net).
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

    // Save the interrupted task's SP. Only transition Running→Ready;
    // if a syscall already marked it Blocked or Dead, preserve that.
    let current_tcb = TASKS[cur].assume_init_mut();
    current_tcb.kernel_sp = current_sp;
    if current_tcb.state == TaskState::Running {
        current_tcb.state = TaskState::Ready;
    }
    current_tcb.preempt_count += 1;

    // Scan for next Ready task (round-robin).
    for offset in 1..=n {
        let idx = (cur + offset) % n;
        let tcb = TASKS[idx].assume_init_mut();
        if tcb.state == TaskState::Ready {
            CURRENT = idx;
            tcb.state = TaskState::Running;
            return tcb.kernel_sp;
        }
    }

    // No Ready task found — stay on current.
    current_sp
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo build -p harmony-boot-aarch64 --target aarch64-unknown-uefi --release --locked`
Expected: Build succeeds. The new schedule() is functionally equivalent to Phase 2 when all tasks are Ready (which is the case with test0/test1).

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-boot-aarch64/src/sched.rs
git commit -m "feat(sched): state-aware round-robin — skip Blocked and Dead tasks"
```

---

### Task 3: Guard Pages

Add `mark_guard_page()` to mmu.rs, update `spawn_task` to allocate a guard page below each kernel stack, and enhance the abort handler to detect guard page faults.

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/mmu.rs`
- Modify: `crates/harmony-boot-aarch64/src/sched.rs` (spawn_task allocation)
- Modify: `crates/harmony-boot-aarch64/src/syscall.rs` (abort_handler)

- [ ] **Step 1: Add mark_guard_page to mmu.rs**

Add this function at the end of `crates/harmony-boot-aarch64/src/mmu.rs`, before the `#[cfg(test)] mod tests` block:

```rust
/// Mark a single page as inaccessible (guard page).
///
/// Reads TTBR0_EL1 to reconstruct the page table, then unmaps the page
/// at `addr`. Any subsequent access triggers a data abort. A TLB
/// invalidation ensures the stale mapping is flushed.
///
/// # Safety
///
/// - `addr` must be page-aligned and currently mapped in the identity map.
/// - The MMU must be enabled (`init_and_enable` must have been called).
/// - Must not be called concurrently with other page table modifications.
#[cfg(target_arch = "aarch64")]
pub unsafe fn mark_guard_page(addr: u64) {
    let root: u64;
    core::arch::asm!("mrs {}, ttbr0_el1", out(reg) root);

    let mut pt = Aarch64PageTable::new(PhysAddr(root), identity_phys_to_virt);

    // Unmap the page. The no-op deallocator discards the frame address —
    // the bump allocator cannot free, and the frame stays reserved as a
    // guard (not reclaimable memory).
    let _ = pt.unmap(VirtAddr(addr), &mut |_| {});

    // TLB invalidate for this specific VA.
    // TLBI VALE1IS: invalidate by VA, last-level, EL1, Inner Shareable.
    // The register contains VA[47:12] (VA shifted right by 12).
    core::arch::asm!(
        "dsb ishst",
        "tlbi vale1is, {va}",
        "dsb ish",
        "isb",
        va = in(reg) addr >> 12,
    );
}
```

- [ ] **Step 2: Update spawn_task to allocate guard page**

In `crates/harmony-boot-aarch64/src/sched.rs`, in the `spawn_task` function, replace the stack allocation block (the section starting with `let base = bump.alloc_frame()...` through the contiguity loop) with:

```rust
    // Allocate guard page + stack pages (pages_needed + 1 total).
    // Guard page is the first (lowest) frame. If the stack overflows
    // downward into it, it triggers a clean data abort.
    let guard_frame = bump
        .alloc_frame()
        .expect("sched: guard page frame")
        .0 as usize;
    let base = bump
        .alloc_frame()
        .expect("sched: kernel stack frame 0")
        .0 as usize;
    assert_eq!(
        base,
        guard_frame + page_size,
        "guard page must be contiguous with stack"
    );
    for i in 1..pages_needed {
        let frame = bump
            .alloc_frame()
            .expect("sched: kernel stack frame")
            .0 as usize;
        assert_eq!(
            frame,
            base + i * page_size,
            "kernel stack frames must be contiguous"
        );
    }

    // Mark guard page as inaccessible in the page table.
    #[cfg(target_arch = "aarch64")]
    crate::mmu::mark_guard_page(guard_frame as u64);
```

- [ ] **Step 3: Enhance abort_handler for guard page detection**

In `crates/harmony-boot-aarch64/src/syscall.rs`, replace the `abort_handler` function:

```rust
/// Rust abort handler — called from the exception vector table asm.
///
/// Checks for stack overflow (guard page hit) first, then prints
/// diagnostic info (faulting address, PC, syndrome) to PL011 serial
/// and halts via panic.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn abort_handler(frame: &TrapFrame, esr: u64) -> ! {
    let ec = (esr >> 26) & 0x3F;
    let iss = esr & 0x1FF_FFFF;
    let far: u64;
    core::arch::asm!("mrs {}, far_el1", out(reg) far);

    // Check for stack overflow (guard page hit on data abort).
    if ec == 0x25 {
        if let Some((name, pid)) = crate::sched::check_guard_page(far) {
            panic!(
                "Stack overflow in task \"{}\" (PID {}): FAR={:#x} ELR={:#x} ESR={:#x}",
                name, pid, far, frame.elr, esr
            );
        }
    }

    let kind = match ec {
        0x21 => "Instruction Abort (current EL)",
        0x25 => "Data Abort (current EL)",
        _ => "Unhandled Synchronous Exception",
    };

    panic!(
        "{} at ELR={:#x} FAR={:#x} ESR={:#x} (EC={:#x} ISS={:#x})",
        kind, frame.elr, far, esr, ec, iss
    );
}
```

- [ ] **Step 4: Run tests and cross-compile**

Run: `cargo test -p harmony-boot-aarch64 && cargo build -p harmony-boot-aarch64 --target aarch64-unknown-uefi --release --locked`
Expected: Host tests pass (check_guard_page tests from Task 1). Cross-build succeeds.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-boot-aarch64/src/mmu.rs crates/harmony-boot-aarch64/src/sched.rs crates/harmony-boot-aarch64/src/syscall.rs
git commit -m "feat(sched): guard pages on kernel stacks — stack overflow triggers clean data abort"
```

---

### Task 4: Timer Simplification

Remove Phase 2's tick-500 scheduler verification from timer.rs and the `task_counters()` function from sched.rs.

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/timer.rs:113-127,131-189`
- Modify: `crates/harmony-boot-aarch64/src/sched.rs:168-175`

- [ ] **Step 1: Simplify on_tick in timer.rs**

In `crates/harmony-boot-aarch64/src/timer.rs`, replace the `on_tick` function:

```rust
/// Timer tick callback — called by the IRQ handler on each timer interrupt.
///
/// Increments the tick counter and rearms the timer. Every 100 ticks
/// (once per second), prints the tick count for liveness verification.
#[cfg(target_arch = "aarch64")]
pub fn on_tick() {
    let count = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    rearm();

    if count % 100 == 0 {
        print_tick(count);
    }
}
```

- [ ] **Step 2: Remove print_sched_verification from timer.rs**

Delete the entire `print_sched_verification` function (the function that calls `sched::num_tasks()` and `sched::task_counters()`). Also remove `use crate::sched;` from the imports at the top of the `print_sched_verification` function body (it's a local import inside the function).

- [ ] **Step 3: Remove task_counters from sched.rs**

In `crates/harmony-boot-aarch64/src/sched.rs`, delete the `task_counters()` function:

```rust
// DELETE this function:
/// Read both task counters (for verification output by timer::on_tick).
#[cfg(target_arch = "aarch64")]
pub fn task_counters() -> (u64, u64) { ... }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-boot-aarch64`
Expected: All tests pass. The timer host tests (counter_to_ms, reload values) are unaffected.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-boot-aarch64/src/timer.rs crates/harmony-boot-aarch64/src/sched.rs
git commit -m "refactor(timer): remove Phase 2 tick-500 verification, simplify on_tick"
```

---

### Task 5: Main.rs — System Task, Idle Task, and Boot Flow

Move `UnikernelRuntime` to a static, add idle and system task entry points, rewrite the qemu-virt scheduler block, and remove Phase 2 test tasks from sched.rs.

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/main.rs`
- Modify: `crates/harmony-boot-aarch64/src/sched.rs` (remove task0/task1/counters)

- [ ] **Step 1: Add RUNTIME static to main.rs**

In `crates/harmony-boot-aarch64/src/main.rs`, after the existing `ALLOCATOR` static (around line 41), add:

```rust
/// Global runtime — populated during boot, read by the system task.
/// Access is safe: boot init writes it once before spawning tasks;
/// the system task is the sole reader after that.
#[cfg(target_os = "uefi")]
static mut RUNTIME: Option<UnikernelRuntime> = None;
```

- [ ] **Step 2: Move runtime to static after setup**

In `main()`, after the line `let _ = writeln!(serial, "[Runtime] UnikernelRuntime created");` (~line 345), add:

```rust
    // Move runtime to static for access by the system scheduler task.
    unsafe { RUNTIME = Some(runtime) };
```

- [ ] **Step 3: Add idle_task and system_task**

In `crates/harmony-boot-aarch64/src/main.rs`, add these functions before the `dispatch_action` function (around line 882):

```rust
/// Idle task — executes WFE in a loop. Always Ready; the scheduler
/// falls through to it when no other task is schedulable.
#[cfg(feature = "qemu-virt")]
fn idle_task() -> ! {
    loop {
        unsafe { core::arch::asm!("wfe") };
    }
}

/// System task — runs the event loop that was previously inline in main().
/// Prints a startup message (QEMU test milestone), then polls the runtime
/// in a loop. Reads UnikernelRuntime from the RUNTIME static populated
/// during boot init.
#[cfg(feature = "qemu-virt")]
fn system_task() -> ! {
    use core::fmt::Write;
    let mut serial =
        harmony_unikernel::SerialWriter::new(|byte| unsafe { pl011::write_byte(byte) });
    let _ = writeln!(serial, "[System] Event loop started");

    loop {
        let now = timer::now_ms();
        let runtime = unsafe { RUNTIME.as_mut().unwrap() };
        let actions = runtime.tick(now);
        for action in &actions {
            dispatch_action(action, &mut serial);
        }
        unsafe { core::arch::asm!("wfe") };
    }
}
```

- [ ] **Step 4: Rewrite the qemu-virt scheduler block**

In `main()`, replace the `#[cfg(feature = "qemu-virt")]` block (the section that spawns test tasks and enters scheduler) with:

```rust
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

        // Spawn idle task (PID 0) and system task (PID 1).
        unsafe { sched::spawn_task("idle", 0, idle_task, &mut bump) };
        let _ = writeln!(serial, "[Sched] Spawned idle task (PID 0)");
        unsafe { sched::spawn_task("system", 1, system_task, &mut bump) };
        let _ = writeln!(serial, "[Sched] Spawned system task (PID 1)");

        // Enter the scheduler — loads task 0's TrapFrame and erets into it.
        // The eret atomically unmasks IRQs via SPSR (I=0 in INITIAL_SPSR),
        // so we do NOT use `msr daifclr` here.
        let _ = writeln!(serial, "[Sched] Entering scheduler (eret unmasks IRQs)");
        unsafe { sched::enter_scheduler() };
    }
```

- [ ] **Step 5: Fix non-qemu-virt event loop**

In `main()`, the event loop (the `loop { ... }` block near the end of main) uses `runtime` which was moved to the static. Add this line just before the `loop {` statement:

```rust
    let runtime = unsafe { RUNTIME.as_mut().unwrap() };
```

The existing `runtime.tick(now)` and `runtime.handle_packet(...)` calls then work via auto-deref on the mutable reference.

- [ ] **Step 6: Remove Phase 2 test tasks from sched.rs**

In `crates/harmony-boot-aarch64/src/sched.rs`, delete:

1. The `TASK0_COUNTER` and `TASK1_COUNTER` statics
2. The `task0()` function
3. The `task1()` function
4. The `use core::sync::atomic::{AtomicU64, Ordering};` import that was only used by the counters (check that `on_tick` in timer.rs still has its own import)

These are approximately lines 141-166 in the current file.

- [ ] **Step 7: Cross-compile to verify**

Run: `cargo build -p harmony-boot-aarch64 --target aarch64-unknown-uefi --release --locked`
Expected: Build succeeds. The qemu-virt path now spawns idle + system instead of test0 + test1.

- [ ] **Step 8: Run host tests**

Run: `cargo test -p harmony-boot-aarch64`
Expected: All tests pass. The sched.rs tests still work (they don't depend on task0/task1).

- [ ] **Step 9: Commit**

```bash
git add crates/harmony-boot-aarch64/src/main.rs crates/harmony-boot-aarch64/src/sched.rs
git commit -m "feat(boot): idle task (PID 0) + system task (PID 1) replace Phase 2 counter tasks"
```

---

### Task 6: QEMU Test Milestone Update

Update the aarch64 boot test milestones to match Phase 3's output.

**Files:**
- Modify: `xtask/src/qemu_test.rs:32-55`

- [ ] **Step 1: Update aarch64_milestones**

In `xtask/src/qemu_test.rs`, replace the `aarch64_milestones()` function:

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
            pattern: "[Sched] Entering scheduler",
            description: "scheduler entry",
        },
        Milestone {
            pattern: "[System]",
            description: "system task running",
        },
    ]
}
```

- [ ] **Step 2: Verify xtask compiles**

Run: `cargo build -p xtask`
Expected: Build succeeds.

- [ ] **Step 3: Commit**

```bash
git add xtask/src/qemu_test.rs
git commit -m "test(xtask): update aarch64 milestones for Phase 3 idle + system tasks"
```

---

### Task 7: Build, Format, and QEMU Verification

Run all quality gates and the QEMU boot test.

**Files:**
- Potentially modify any file (nightly rustfmt)

- [ ] **Step 1: Run workspace tests**

Run: `cargo test --workspace`
Expected: All tests pass (ignore pre-existing `extern crate alloc` errors for the boot crate on host — those are expected since the boot crate targets aarch64-unknown-uefi).

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace`
Expected: No new warnings from our changes.

- [ ] **Step 3: Run nightly rustfmt on boot crate**

Run: `cargo +nightly fmt --all`
Expected: Formats code. CI uses nightly rustfmt.

- [ ] **Step 4: Commit formatting changes (if any)**

```bash
git add -u
git commit -m "style: apply nightly rustfmt"
```

- [ ] **Step 5: Run QEMU boot test**

Run: `cargo xtask qemu-test --target aarch64 --timeout 30`
Expected output (milestones hit in order):
```
[aarch64] BUILDING... ok
[aarch64] BOOTING...
[aarch64] ✓ [PL011] Serial initialized ...
[aarch64] ✓ [RNDR] ...
[aarch64] ✓ [Identity] ...
[aarch64] ✓ [Sched] Spawned idle task (PID 0) ...
[aarch64] ✓ [Sched] Spawned system task (PID 1) ...
[aarch64] ✓ [Sched] Entering scheduler ...
[aarch64] ✓ [System] ...
[aarch64] PASS
```

The `[System]` milestone proves: idle task spawned, system task spawned, scheduler entered via `enter_scheduler()`, first timer tick switched from idle to system task, system task's TrapFrame correctly restored, system task executing real code (printing + runtime.tick loop).

- [ ] **Step 6: If QEMU test fails, debug**

If the test times out waiting for `[System]`:
1. Check serial output tail for panic messages
2. If stuck at `[Sched] Entering scheduler` — system task TrapFrame may be misseeded. Verify `spawn_task` writes correct `elr` for `system_task`.
3. If no timer ticks — GIC or timer init issue. Check `[Timer]` milestone.
4. If guard page panic — stack allocation issue. Check bump allocator has enough frames for guard pages (3 extra pages for idle + system guard pages).

If `cargo xtask qemu-test` itself fails to build, check that the test-elf was pre-built:
```bash
cd crates/harmony-test-elf && cargo build --target aarch64-unknown-linux-musl --release && cd ../..
```
