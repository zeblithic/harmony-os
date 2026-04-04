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
