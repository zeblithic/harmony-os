// SPDX-License-Identifier: GPL-2.0-or-later
//! Preemptive round-robin scheduler for Phase 3.
//!
//! Owns per-task kernel stacks and [`TaskControlBlock`]s. The timer IRQ
//! handler calls [`schedule`] on each tick, which round-robins between
//! tasks by returning the next task's saved kernel SP. The IRQ assembly
//! restores registers from that SP and `eret`s into the new task.
//!
//! # Limitations (Phase 3)
//!
//! - EL1-only tasks (no EL0 user mode).
//! - No FP/SIMD context save — tasks must not use floating-point.
//!   FP context switch will be added no later than Phase 4; see design spec
//!   section 8 for options (eager vs lazy save via CPACR_EL1.FPEN).
//! - No priority or fairness — pure round-robin alternation.
//! - Mutable statics are safe because the IRQ handler is non-reentrant
//!   (PSTATE.I is set on exception entry).

#![cfg_attr(not(target_arch = "aarch64"), allow(dead_code, unused_imports))]

use core::mem::MaybeUninit;

use crate::bump_alloc::BumpAllocator;
use crate::syscall::TrapFrame;
use harmony_microkernel::vm::PAGE_SIZE;

// Compile-time guard: if TrapFrame ever grows (e.g. FP/SIMD), this fires.
const _: () = assert!(
    core::mem::size_of::<TrapFrame>() <= TRAPFRAME_SIZE,
    "TrapFrame grew past TRAPFRAME_SIZE — update sched.rs"
);

/// Maximum number of tasks.
pub const MAX_TASKS: usize = 64;

/// Minimum kernel stack size in bytes (8 KiB).
/// Actual allocation rounds up to whole pages — 2 pages at 4K, 1 page at 16K.
const KERNEL_STACK_SIZE: usize = 8192;

/// Size of the TrapFrame in bytes (31 GP regs + ELR + SPSR = 264,
/// padded to 272 for 16-byte alignment). Must match vectors.rs assembly.
const TRAPFRAME_SIZE: usize = 272;

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

/// Per-task scheduling state. Stored in a fixed-size array, indexed by task number.
#[repr(C)]
pub struct TaskControlBlock {
    /// Saved SP_EL1 — points to the base of a TrapFrame on this task's
    /// kernel stack. The IRQ restore path loads registers from here.
    pub kernel_sp: usize,
    /// Base address of the allocated kernel stack (low address).
    /// Used for guard-page setup and stack teardown on task exit.
    pub kernel_stack_base: usize,
    /// Size of the kernel stack in bytes.
    /// Used for guard-page setup and stack teardown on task exit.
    pub kernel_stack_size: usize,
    /// Current scheduling state.
    pub state: TaskState,
    /// Number of times this task has been preempted (for verification).
    pub preempt_count: u64,
    /// Microkernel Process ID (0 = idle, 1 = system, 2+ = user).
    pub pid: u32,
    /// Debug name for diagnostic output.
    pub name: &'static str,
    /// Entry point (for debug; not re-invoked after initial start).
    pub entry: Option<fn() -> !>,
}

/// Task array — only accessed from the IRQ handler (non-reentrant).
const UNINIT_TCB: MaybeUninit<TaskControlBlock> = MaybeUninit::uninit();
static mut TASKS: [MaybeUninit<TaskControlBlock>; MAX_TASKS] = [UNINIT_TCB; MAX_TASKS];

/// Index of the currently running task.
static mut CURRENT: usize = 0;

/// Number of tasks that have been spawned.
static mut NUM_TASKS: usize = 0;

/// SPSR value for new tasks: EL1h (M=0b0101), D=1, A=1, I=0, F=1.
/// Debug, SError, and FIQ masked; IRQ **unmasked** so the task is preemptible.
const INITIAL_SPSR: u64 = 0x345;

/// Spawn a new task that will begin execution at `entry`.
///
/// Allocates an 8 KiB kernel stack from `bump`, writes a zeroed TrapFrame
/// at the top with `elr = entry` and `spsr = INITIAL_SPSR`, and records
/// the task in [`TASKS`]. Returns the task index.
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

    let stack_size = pages_needed * page_size;
    let stack_top = base + stack_size;

    // Place a TrapFrame at the top of the stack.
    // kernel_sp points to the base of the TrapFrame (stack grows down).
    let sp = stack_top - TRAPFRAME_SIZE;

    // Zero the TrapFrame region, then set elr and spsr.
    let frame_ptr = sp as *mut TrapFrame;
    // Zero all 272 bytes (covers x[0..31], elr, spsr, and padding).
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

/// Check whether `addr` falls within the guard page of any spawned task's stack.
///
/// The guard page occupies the one page immediately below `kernel_stack_base`.
/// Returns `(name, pid)` of the matching task, or `None` if no match.
///
/// Not cfg-gated so it is accessible in host tests.
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
    // Scoped to end the mutable borrow before the scan loop — the loop
    // may revisit index `cur` at offset == n, and two live &mut refs to
    // the same TASKS slot is UB even in unsafe code.
    {
        let current_tcb = TASKS[cur].assume_init_mut();
        current_tcb.kernel_sp = current_sp;
        if current_tcb.state == TaskState::Running {
            current_tcb.state = TaskState::Ready;
            current_tcb.preempt_count += 1;
        }
    }

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

    // No Ready task found. This cannot happen when the idle task is
    // functioning (it is always Ready), but if it does, staying on
    // current_sp is the least-bad option — the eret resumes whatever
    // was interrupted.
    current_sp
}

/// Return the number of spawned tasks.
#[cfg(target_arch = "aarch64")]
pub fn num_tasks() -> usize {
    unsafe { NUM_TASKS }
}

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
/// - IRQs should be **masked** when calling — `eret` atomically unmasks
///   them via SPSR (I=0 in [`INITIAL_SPSR`]), avoiding a race window
///   between IRQ unmask and task context setup.
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

#[cfg(test)]
mod tests {
    use super::*;
    use harmony_microkernel::vm::PAGE_SIZE;
    use std::sync::Mutex;

    /// Serialize tests that mutate TASKS/NUM_TASKS globals.
    /// Prevents data races from the parallel test runner.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

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
        let _lock = TEST_LOCK.lock().unwrap();
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
        let guard_start = 0x2_0000 - PAGE_SIZE as usize;
        assert_eq!(
            check_guard_page(guard_start as u64 + 100),
            Some(("test-task", 7))
        );
        assert_eq!(check_guard_page(0x3_0000), None);
        assert_eq!(check_guard_page(guard_start as u64 - 1), None);
        unsafe { NUM_TASKS = 0 };
    }

    #[test]
    fn check_guard_page_empty_returns_none() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe { NUM_TASKS = 0 };
        assert_eq!(check_guard_page(0x1000), None);
    }
}
