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

use crate::bump_alloc::BumpAllocator;
use crate::syscall::TrapFrame;
use harmony_microkernel::vm::PAGE_SIZE;

// Compile-time guard: if TrapFrame ever grows (e.g. FP/SIMD), this fires.
const _: () = assert!(
    core::mem::size_of::<TrapFrame>() <= TRAPFRAME_SIZE,
    "TrapFrame grew past TRAPFRAME_SIZE — update sched.rs"
);

/// Maximum number of tasks. Fixed at 2 for Phase 2.
const MAX_TASKS: usize = 2;

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
}

/// Per-task scheduling state. Stored in a fixed-size array, indexed by
/// task number (0 or 1 in Phase 2).
#[repr(C)]
pub struct TaskControlBlock {
    /// Saved SP_EL1 — points to the base of a TrapFrame on this task's
    /// kernel stack. The IRQ restore path loads registers from here.
    pub kernel_sp: usize,
    /// Base address of the allocated kernel stack (low address).
    /// Phase 3: used for guard-page setup and stack teardown on task exit.
    pub kernel_stack_base: usize,
    /// Size of the kernel stack in bytes.
    /// Phase 3: used for guard-page setup and stack teardown on task exit.
    pub kernel_stack_size: usize,
    /// Current scheduling state.
    pub state: TaskState,
    /// Number of times this task has been preempted (for verification).
    /// Phase 3: used for scheduling fairness metrics.
    pub preempt_count: u64,
}

/// Task array — only accessed from the IRQ handler (non-reentrant).
static mut TASKS: [MaybeUninit<TaskControlBlock>; MAX_TASKS] =
    [MaybeUninit::uninit(), MaybeUninit::uninit()];

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
/// the task in [`TASKS`].
///
/// # Safety
///
/// - Must be called before IRQs are unmasked (before `enter_scheduler`).
/// - `bump` must have enough free frames for the kernel stack.
/// - Must not be called more than [`MAX_TASKS`] times.
pub unsafe fn spawn_task(entry: fn() -> !, bump: &mut BumpAllocator) {
    let n = unsafe { NUM_TASKS };
    assert!(n < MAX_TASKS, "spawn_task: MAX_TASKS exceeded");

    let page_size = PAGE_SIZE as usize;
    let pages_needed = (KERNEL_STACK_SIZE + page_size - 1) / page_size;

    // Allocate contiguous pages for the kernel stack.
    // No other allocations may occur between these calls — the bump
    // allocator must produce contiguous frames for a valid stack.
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
        kernel_stack_base: base,
        kernel_stack_size: stack_size,
        state: TaskState::Ready,
        preempt_count: 0,
    });
    NUM_TASKS = n + 1;
}

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
    // Phase 3 will add Blocked state — this assert catches scheduling a
    // non-Ready task, which would eret into a stale or invalid context.
    debug_assert_eq!(next_tcb.state, TaskState::Ready);
    next_tcb.state = TaskState::Running;

    next_tcb.kernel_sp
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
