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
//! - Eager FP/SIMD context save: all 32 Q registers + FPCR + FPSR are
//!   saved/restored on every context switch.
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

/// Size of the TrapFrame in bytes (31 GP regs + ELR + SPSR + FPCR + FPSR
/// + padding + 32 Q regs = 800). Must match vectors.rs assembly.
const TRAPFRAME_SIZE: usize = 800;

/// Scheduling state for a task.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TaskState {
    Ready,
    Running,
    /// Waiting on syscall/IPC.
    Blocked,
    /// Exited — scheduler skips. Stack reclamation deferred to Phase 4+.
    Dead,
}

/// What a Blocked task is waiting for. Stored in the TCB so the
/// system task's wake-check loop can evaluate readiness.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum WaitReason {
    /// Waiting for fd to become readable.
    FdReadable(i32),
    /// Waiting for fd to become writable.
    FdWritable(i32),
    /// Waiting for TCP connect to complete.
    FdConnectDone(i32),
    /// Waiting for any network activity (poll/select/epoll).
    /// Woken on any smoltcp state change; handler rechecks specific fds.
    PollWait,
    /// Waiting on a futex word at this address.
    Futex(u64),
    /// Pure time wait — woken by the timer IRQ when deadline_ms expires.
    Sleep,
    /// Waiting for a child process to exit (wait4/waitpid).
    /// -1 = any child, >0 = specific child PID.
    WaitChild(i32),
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
    /// Number of times this task was preempted (Running→Ready by timer IRQ).
    /// Only incremented on actual preemption, not when a task is already
    /// Blocked or Dead at the time of the timer tick.
    pub preempt_count: u64,
    /// Microkernel Process ID (0 = idle, 1 = system, 2+ = user).
    pub pid: u32,
    /// Debug name for diagnostic output.
    pub name: &'static str,
    /// Entry point (for debug; not re-invoked after initial start).
    pub entry: Option<fn() -> !>,
    /// Why this task is Blocked. `None` when state is Ready/Running/Dead.
    pub wait_reason: Option<WaitReason>,
    /// TPIDR_EL0 value — per-thread TLS pointer. Saved/restored on context switch.
    pub tls: u64,
    /// Linux Thread ID. Main thread: TID == PID. Spawned threads: unique TID.
    pub tid: u32,
    /// Address to zero + futex_wake on thread exit (CLONE_CHILD_CLEARTID).
    /// 0 means no cleanup needed.
    pub clear_child_tid: u64,
    /// Absolute time (ms since boot) at which a blocked task should be
    /// unconditionally woken. `None` means no deadline — the task waits
    /// until explicitly woken by an I/O or futex event.
    pub deadline_ms: Option<u64>,
    /// Set to `true` by `check_deadlines` when the task is woken because
    /// its deadline expired. Cleared by `consume_woken_by_timeout`.
    pub woken_by_timeout: bool,
}

/// Task array — only accessed from the IRQ handler (non-reentrant).
const UNINIT_TCB: MaybeUninit<TaskControlBlock> = MaybeUninit::uninit();
static mut TASKS: [MaybeUninit<TaskControlBlock>; MAX_TASKS] = [UNINIT_TCB; MAX_TASKS];

/// Index of the currently running task.
static mut CURRENT: usize = 0;

/// Number of tasks that have been spawned.
static mut NUM_TASKS: usize = 0;

/// Bump allocator for runtime kernel stack allocation. Moved from
/// main()'s local variable so spawn_task_runtime can allocate after boot.
static mut BUMP_ALLOCATOR: Option<crate::bump_alloc::BumpAllocator> = None;

/// Initialize the bump allocator static. Called once during boot.
pub unsafe fn set_bump_allocator(bump: crate::bump_alloc::BumpAllocator) {
    BUMP_ALLOCATOR = Some(bump);
}

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
    let guard_frame = bump.alloc_frame().expect("sched: guard page frame").0 as usize;
    let base = bump.alloc_frame().expect("sched: kernel stack frame 0").0 as usize;
    assert_eq!(
        base,
        guard_frame + page_size,
        "guard page must be contiguous with stack"
    );
    for i in 1..pages_needed {
        let frame = bump.alloc_frame().expect("sched: kernel stack frame").0 as usize;
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
    // Zero all 800 bytes (covers x[0..31], elr, spsr, fpcr, fpsr, padding, q[0..32]).
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
        wait_reason: None,
        tls: 0,
        tid: 0, // Boot-time tasks: 0 = use Linuxulator PID for gettid()
        clear_child_tid: 0,
        deadline_ms: None,
        woken_by_timeout: false,
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
        #[cfg(target_arch = "aarch64")]
        {
            let tls: u64;
            core::arch::asm!("mrs {}, tpidr_el0", out(reg) tls);
            current_tcb.tls = tls;
        }
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
            #[cfg(target_arch = "aarch64")]
            core::arch::asm!("msr tpidr_el0, {}", in(reg) tcb.tls);
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
    let tls = TASKS[0].assume_init_ref().tls;

    #[cfg(target_arch = "aarch64")]
    core::arch::asm!("msr tpidr_el0, {}", in(reg) tls);

    core::arch::asm!(
        // Set SP to task 0's kernel stack (TrapFrame base).
        "mov sp, {sp}",

        // Restore Q0-Q31 from task 0's TrapFrame.
        "ldp q0,  q1,  [sp, #288]",
        "ldp q2,  q3,  [sp, #320]",
        "ldp q4,  q5,  [sp, #352]",
        "ldp q6,  q7,  [sp, #384]",
        "ldp q8,  q9,  [sp, #416]",
        "ldp q10, q11, [sp, #448]",
        "ldp q12, q13, [sp, #480]",
        "ldp q14, q15, [sp, #512]",
        "ldp q16, q17, [sp, #544]",
        "ldp q18, q19, [sp, #576]",
        "ldp q20, q21, [sp, #608]",
        "ldp q22, q23, [sp, #640]",
        "ldp q24, q25, [sp, #672]",
        "ldp q26, q27, [sp, #704]",
        "ldp q28, q29, [sp, #736]",
        "ldp q30, q31, [sp, #768]",
        // Restore FPCR and FPSR.
        "ldp x10, x11, [sp, #264]",
        "msr fpcr, x10",
        "msr fpsr, x11",

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
        "add sp, sp, #800",
        "eret",

        sp = in(reg) sp,
        options(noreturn),
    );
}

/// Spawn a new task at runtime (after scheduler is running).
///
/// Copies `parent_trapframe` to the new task's kernel stack, sets the
/// child's return value to 0 (x[0]), and marks it Ready. Called from
/// within syscall context (CLONE_VM/CLONE_THREAD).
///
/// # Safety
///
/// - Must be called from task context (not IRQ handler).
/// - `parent_trapframe` must point to a valid TrapFrame.
/// - IRQs will be temporarily masked.
#[cfg(target_arch = "aarch64")]
pub unsafe fn spawn_task_runtime(
    name: &'static str,
    pid: u32,
    tid: u32,
    tls: u64,
    clear_child_tid: u64,
    parent_trapframe: *const crate::syscall::TrapFrame,
    child_stack: u64,
) -> Option<usize> {
    use harmony_microkernel::vm::PAGE_SIZE;

    // Mask IRQs defensively. This function is always called from the SVC
    // dispatch path where IRQs are already masked by hardware (PSTATE.I=1),
    // but we mask explicitly in case that precondition ever changes.
    // We do NOT unmask on any exit path — the SVC epilogue writes
    // ELR_EL1/SPSR_EL1 then erets, and a timer IRQ in that window would
    // clobber those registers. The eret restores userspace PSTATE which
    // has IRQs unmasked. Same invariant as block_current's daifset.
    core::arch::asm!("msr daifset, #2");

    let n = NUM_TASKS;
    if n >= MAX_TASKS {
        return None;
    }

    let bump = match BUMP_ALLOCATOR.as_mut() {
        Some(b) => b,
        None => return None,
    };

    let page_size = PAGE_SIZE as usize;
    let pages_needed = (KERNEL_STACK_SIZE + page_size - 1) / page_size;

    // Allocate guard page + stack pages (same as boot-time spawn_task).
    // On OOM, return None instead of panicking — a panic with IRQs
    // masked leaves DAIF.I permanently set.
    macro_rules! alloc_or_return {
        ($bump:expr) => {
            match $bump.alloc_frame() {
                Some(f) => f.0 as usize,
                None => return None,
            }
        };
    }
    let guard_frame = alloc_or_return!(bump);
    let base = alloc_or_return!(bump);
    if base != guard_frame + page_size {
        return None;
    }
    for i in 1..pages_needed {
        let frame = alloc_or_return!(bump);
        if frame != base + i * page_size {
            return None;
        }
    }

    // Mark guard page as inaccessible.
    crate::mmu::mark_guard_page(guard_frame as u64);

    let stack_size = pages_needed * page_size;

    // Place the initial TrapFrame just below child_stack so that after
    // context switch the asm epilogue's `add sp, sp, #800` produces
    // SP = child_stack. musl's child clone wrapper does
    // `ldp x1, x0, [sp]` to load fn/arg that were stored at
    // child_stack by the parent's `stp x0, x3, [x1, #-16]!`.
    //
    // The kernel-allocated stack (base..base+stack_size) is retained
    // for guard-page infrastructure but is not used as the thread's
    // runtime stack — after the first eret the thread runs on
    // child_stack (the musl-allocated user stack).
    let sp = (child_stack as usize) - TRAPFRAME_SIZE;

    // Copy parent's TrapFrame to just below child_stack.
    core::ptr::copy_nonoverlapping(parent_trapframe as *const u8, sp as *mut u8, TRAPFRAME_SIZE);

    // Modify child's TrapFrame: clone() returns 0 to child.
    let child_frame = sp as *mut crate::syscall::TrapFrame;
    (*child_frame).x[0] = 0;

    TASKS[n] = MaybeUninit::new(TaskControlBlock {
        kernel_sp: sp,
        kernel_stack_base: base,
        kernel_stack_size: stack_size,
        state: TaskState::Ready,
        preempt_count: 0,
        pid,
        name,
        entry: None,
        wait_reason: None,
        tls,
        tid,
        clear_child_tid,
        deadline_ms: None,
        woken_by_timeout: false,
    });
    NUM_TASKS = n + 1;

    Some(n)
}

/// Block the current task, recording why it is waiting.
///
/// Sets `state = Blocked` and `wait_reason = Some(reason)` on the current
/// TCB. On aarch64, immediately yields via a self-directed SGI so the
/// scheduler can switch to another ready task. On host (non-aarch64) builds
/// the state change is visible but no context switch occurs (tests drive
/// the scheduler directly).
///
/// # Safety
///
/// - Must be called from task context (not from an IRQ handler).
/// - CURRENT must index a valid, initialised TCB.
/// - On aarch64: execution resumes here after the waker calls `wake()` and
///   the scheduler has rescheduled this task. `wait_reason` is already
///   cleared by `wake()` before the resume.
pub unsafe fn block_current(reason: WaitReason, deadline_ms: Option<u64>) {
    // Scoped to drop the &mut borrow before unmasking IRQs — the SGI
    // (or a timer IRQ after daifclr) enters schedule() which does its
    // own TASKS[cur].assume_init_mut(). Two live &mut refs to the same
    // slot is UB even in unsafe code. Same pattern as schedule().
    {
        let cur = CURRENT;
        let tcb = TASKS[cur].assume_init_mut();
        tcb.state = TaskState::Blocked;
        tcb.wait_reason = Some(reason);
        tcb.deadline_ms = deadline_ms;
        tcb.woken_by_timeout = false;
        #[cfg(target_arch = "aarch64")]
        {
            let tls: u64;
            core::arch::asm!("mrs {}, tpidr_el0", out(reg) tls);
            tcb.tls = tls;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // SVC exception entry masks IRQs (PSTATE.I=1). Unmask them so
        // the Self-SGI can actually fire and the IRQ handler can context-
        // switch us out. Without this, the SGI pends but never fires,
        // and block_current returns immediately — causing either incorrect
        // results (single-retry paths) or infinite loops (poll/select).
        core::arch::asm!("msr daifclr, #2");
        crate::gic::send_sgi_self(crate::gic::YIELD_SGI);
        // Execution resumes here after wake + reschedule.
        // Re-mask IRQs to restore the SVC handler's invariant. The SVC
        // restore assembly writes ELR_EL1/SPSR_EL1 then erets — a timer
        // IRQ in that window would clobber those registers, causing eret
        // to jump to the SVC assembly instead of user code.
        core::arch::asm!("msr daifset, #2");
    }
}

/// Scan all blocked tasks and wake any whose `deadline_ms` has expired.
///
/// Called from the timer IRQ handler on each tick. For each Blocked task
/// with a `deadline_ms` that satisfies `now_ms >= deadline`, the task is
/// transitioned to Ready, `woken_by_timeout` is set, and deadline fields
/// are cleared.
///
/// # Safety
///
/// - Must only be called from the IRQ handler path (non-reentrant, PSTATE.I set).
/// - All `TASKS[0..NUM_TASKS]` must be initialized.
pub unsafe fn check_deadlines(now_ms: u64) {
    let n = NUM_TASKS;
    for i in 0..n {
        let tcb = TASKS[i].assume_init_mut();
        if tcb.state == TaskState::Blocked {
            if let Some(deadline) = tcb.deadline_ms {
                if now_ms >= deadline {
                    tcb.woken_by_timeout = true;
                    tcb.state = TaskState::Ready;
                    tcb.wait_reason = None;
                    tcb.deadline_ms = None;
                }
            }
        }
    }
}

/// Read and clear the `woken_by_timeout` flag on the current task.
///
/// Returns `true` if the current task was woken by a timer deadline (i.e.,
/// `check_deadlines` fired before an explicit wake), then clears the flag.
/// Returns `false` if the task was woken by a normal wake call or the flag
/// was already cleared.
///
/// # Safety
///
/// - `CURRENT` must index a valid, initialized TCB.
/// - Must be called from task context (not IRQ handler).
pub unsafe fn consume_woken_by_timeout() -> bool {
    let tcb = TASKS[CURRENT].assume_init_mut();
    let was_timeout = tcb.woken_by_timeout;
    tcb.woken_by_timeout = false;
    was_timeout
}

/// Wake a specific blocked task, transitioning it to Ready.
///
/// If the task at `task_idx` is in `Blocked` state, transitions it to
/// `Ready` and clears `wait_reason`. If the task is not Blocked (e.g.,
/// already Ready, Running, or Dead) this is a no-op.
///
/// # Safety
///
/// - `task_idx` must be less than `NUM_TASKS`.
/// - Must only be called when the IRQ lock is held (i.e., from the system
///   task or from an IRQ handler), to avoid races with the scheduler.
pub unsafe fn wake(task_idx: usize) {
    let tcb = TASKS[task_idx].assume_init_mut();
    if tcb.state == TaskState::Blocked {
        tcb.state = TaskState::Ready;
        tcb.wait_reason = None;
        tcb.deadline_ms = None;
    }
}

/// Wake all blocked tasks waiting on `fd` for the given operation.
///
/// Scans all spawned tasks. For each Blocked task whose `wait_reason`
/// matches `fd` and `op`, transitions it to Ready and clears `wait_reason`.
///
/// `op` encoding: `0` = readable, `1` = writable. Also wakes any
/// `PollWait` task (poll/select/epoll waiting on multiple fds) since a
/// pipe or eventfd change may satisfy their wait condition.
/// `FdConnectDone` is not matched — use `for_each_blocked` for those.
///
/// # Safety
///
/// - Must only be called when the IRQ lock is held or IRQs are disabled,
///   to avoid races with the scheduler.
pub unsafe fn wake_by_fd(fd: i32, op: u8) {
    let n = NUM_TASKS;
    for i in 0..n {
        let tcb = TASKS[i].assume_init_mut();
        if tcb.state != TaskState::Blocked {
            continue;
        }
        let matches = match (tcb.wait_reason, op) {
            (Some(WaitReason::FdReadable(f)), 0) if f == fd => true,
            (Some(WaitReason::FdWritable(f)), 1) if f == fd => true,
            // PollWait tasks are waiting on ANY fd activity — a pipe
            // write that makes an fd readable should wake poll/select/epoll
            // tasks that may be watching that fd.
            (Some(WaitReason::PollWait), _) => true,
            _ => false,
        };
        if matches {
            tcb.state = TaskState::Ready;
            tcb.wait_reason = None;
            tcb.deadline_ms = None;
        }
    }
}

/// Iterate over all blocked tasks, calling `f(task_idx, wait_reason)` for each.
///
/// Provides a read-only view of blocked tasks for the system task's
/// wake-check loop. The closure receives the task index and a copy of
/// `WaitReason`. To wake a task from inside the closure, call `wake(i)`
/// — but note that modifying `TASKS` while iterating is safe here because
/// `for_each_blocked` takes a snapshot of `NUM_TASKS` upfront and accesses
/// each slot exactly once.
///
/// # Safety
///
/// - Must only be called when the IRQ lock is held or IRQs are disabled.
/// - `f` must not add or remove tasks (must not call `spawn_task`).
pub unsafe fn for_each_blocked(mut f: impl FnMut(usize, WaitReason)) {
    let n = NUM_TASKS;
    for i in 0..n {
        let tcb = TASKS[i].assume_init_ref();
        if tcb.state == TaskState::Blocked {
            if let Some(reason) = tcb.wait_reason {
                f(i, reason);
            }
        }
    }
}

/// Wake up to `max` tasks blocked on `WaitReason::Futex(uaddr)`.
///
/// Returns the number of tasks actually woken. Used by FUTEX_WAKE
/// and CLONE_CHILD_CLEARTID exit cleanup.
///
/// # Safety
///
/// Must only be called when TASKS[0..NUM_TASKS] are initialized.
pub unsafe fn futex_wake(uaddr: u64, max: u32) -> u32 {
    let mut woken = 0u32;
    let n = NUM_TASKS;
    for i in 0..n {
        if woken >= max {
            break;
        }
        let tcb = TASKS[i].assume_init_mut();
        if tcb.state == TaskState::Blocked && tcb.wait_reason == Some(WaitReason::Futex(uaddr)) {
            tcb.state = TaskState::Ready;
            tcb.wait_reason = None;
            tcb.deadline_ms = None;
            woken += 1;
        }
    }
    woken
}

/// Wake a parent task blocked in wait4 for the given child PID.
///
/// Scans all tasks for one that is `Blocked` with `WaitReason::WaitChild(target)`
/// where `target == -1` (any child) or `target == child_pid as i32`. Wakes
/// the first match only — a parent can only be blocked in one wait4 at a time.
///
/// Called from the exit path in syscall.rs when a child process or
/// the last thread of a process exits.
///
/// O(MAX_TASKS) scan, same cost as `check_deadlines`.
///
/// # Safety
///
/// Must only be called when TASKS[0..NUM_TASKS] are initialized.
pub unsafe fn wake_waiting_parent(child_pid: u32) {
    let n = NUM_TASKS;
    for i in 0..n {
        let tcb = TASKS[i].assume_init_mut();
        if tcb.state == TaskState::Blocked {
            if let Some(WaitReason::WaitChild(target)) = tcb.wait_reason {
                if target == -1 || target == child_pid as i32 {
                    tcb.state = TaskState::Ready;
                    tcb.wait_reason = None;
                    tcb.deadline_ms = None;
                    return;
                }
            }
        }
    }
}

/// Redirect the main thread (tid==0) of a process to the boot return point.
///
/// Called by a spawned thread's exit_group path when it needs to redirect
/// the main thread to RETURN_ADDR. Finds the main thread's TCB (matching
/// `pid` and `tid == 0`, excluding CURRENT), follows `kernel_sp` to the
/// saved TrapFrame in memory, and patches:
/// - `elr` = `ret_addr` (boot code return point)
/// - `x[0]` = `exit_code`
/// - `x[1]` = `ret_sp` (saved kernel stack pointer)
/// - `x[2]` = `ret_lr` (saved kernel link register)
///
/// Marks the main thread `Ready` so the scheduler picks it up and erets
/// into the boot code.
///
/// No-op if no matching task is found (e.g., main thread already exited).
///
/// # Safety
///
/// - TASKS[0..NUM_TASKS] must be initialized.
/// - `ret_addr` must point to valid executable code.
/// - Must only be called from the SVC handler path (IRQs masked).
pub unsafe fn redirect_main_thread_to_boot(
    pid: u32,
    exit_code: i32,
    ret_addr: u64,
    ret_sp: u64,
    ret_lr: u64,
) {
    let n = NUM_TASKS;
    let cur = CURRENT;
    for i in 0..n {
        if i == cur {
            continue;
        }
        let tcb = TASKS[i].assume_init_mut();
        // No state guard: the main thread is typically Dead here (killed by
        // kill_threads_by_pid before this call). We intentionally resurrect
        // it from Dead → Ready with a patched ELR pointing at boot code.
        if tcb.pid == pid && tcb.tid == 0 {
            let frame = &mut *(tcb.kernel_sp as *mut crate::syscall::TrapFrame);
            frame.elr = ret_addr;
            frame.x[0] = exit_code as u64;
            frame.x[1] = ret_sp;
            frame.x[2] = ret_lr;
            tcb.state = TaskState::Ready;
            tcb.wait_reason = None;
            tcb.deadline_ms = None;
            return;
        }
    }
}

/// Get the current task's TID.
pub unsafe fn current_task_tid() -> u32 {
    TASKS[CURRENT].assume_init_ref().tid
}

/// Get the current task's PID.
pub unsafe fn current_task_pid() -> u32 {
    TASKS[CURRENT].assume_init_ref().pid
}

/// Get the current task's clear_child_tid address.
pub unsafe fn current_task_clear_child_tid() -> u64 {
    TASKS[CURRENT].assume_init_ref().clear_child_tid
}

/// Set the current task's clear_child_tid address.
pub unsafe fn set_current_clear_child_tid(addr: u64) {
    TASKS[CURRENT].assume_init_mut().clear_child_tid = addr;
}

/// Mark the current task as Dead.
pub unsafe fn mark_current_dead() {
    let tcb = TASKS[CURRENT].assume_init_mut();
    tcb.state = TaskState::Dead;
    tcb.wait_reason = None;
}

/// Mark all tasks with the given PID as Dead (exit_group), except
/// the currently running task. The caller handles its own lifecycle
/// (main thread redirects via RETURN_ADDR, spawned thread does CLEARTID
/// + mark_current_dead). Skipping CURRENT prevents the main thread from
/// being marked Dead before its eret-to-RETURN_ADDR cleanup completes.
pub unsafe fn kill_threads_by_pid(pid: u32) {
    let n = NUM_TASKS;
    let cur = CURRENT;
    for i in 0..n {
        if i == cur {
            continue;
        }
        // Read phase — check if this task should be killed, extract
        // clear_child_tid. Scoped to drop the borrow before futex_wake
        // (which iterates TASKS and would alias this slot).
        let (should_kill, clear_addr) = {
            let tcb = TASKS[i].assume_init_ref();
            (
                tcb.pid == pid && tcb.state != TaskState::Dead,
                tcb.clear_child_tid,
            )
        };
        if !should_kill {
            continue;
        }
        // Write phase — mark Dead, clear fields.
        {
            let tcb = TASKS[i].assume_init_mut();
            tcb.clear_child_tid = 0;
            tcb.state = TaskState::Dead;
            tcb.wait_reason = None;
            tcb.deadline_ms = None;
        }
        // CLEARTID cleanup — no live borrow on TASKS[i].
        if clear_addr != 0 {
            *(clear_addr as *mut u32) = 0;
            futex_wake(clear_addr, 1);
        }
    }
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
                wait_reason: None,
                tls: 0,
                tid: 7,
                clear_child_tid: 0,
                deadline_ms: None,
                woken_by_timeout: false,
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

    // ── WaitReason tests ─────────────────────────────────────────────────────

    /// Helper: write a TCB into slot `idx` with the given state/wait_reason.
    unsafe fn put_tcb(idx: usize, state: TaskState, wait_reason: Option<WaitReason>) {
        TASKS[idx] = MaybeUninit::new(TaskControlBlock {
            kernel_sp: 0,
            kernel_stack_base: 0x4_0000 + idx * 0x1_0000,
            kernel_stack_size: 8192,
            state,
            preempt_count: 0,
            pid: idx as u32,
            name: "test",
            entry: None,
            wait_reason,
            tls: 0,
            tid: idx as u32,
            clear_child_tid: 0,
            deadline_ms: None,
            woken_by_timeout: false,
        });
    }

    #[test]
    fn wait_reason_variants_distinct() {
        let variants = [
            WaitReason::FdReadable(3),
            WaitReason::FdWritable(3),
            WaitReason::FdConnectDone(3),
            WaitReason::PollWait,
        ];
        for i in 0..variants.len() {
            for j in (i + 1)..variants.len() {
                assert_ne!(variants[i], variants[j]);
            }
        }
        // Same variant, same fd => equal.
        assert_eq!(WaitReason::FdReadable(5), WaitReason::FdReadable(5));
        // Same variant, different fd => not equal.
        assert_ne!(WaitReason::FdReadable(5), WaitReason::FdReadable(6));
    }

    #[test]
    fn tcb_wait_reason_default_none() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Ready, None);
            NUM_TASKS = 1;
            let tcb = TASKS[0].assume_init_ref();
            assert_eq!(tcb.wait_reason, None);
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn block_current_sets_blocked_and_wait_reason() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Running, None);
            NUM_TASKS = 1;
            CURRENT = 0;
            // block_current on non-aarch64 just mutates state — no SGI.
            block_current(WaitReason::FdReadable(7), None);
            let tcb = TASKS[0].assume_init_ref();
            assert_eq!(tcb.state, TaskState::Blocked);
            assert_eq!(tcb.wait_reason, Some(WaitReason::FdReadable(7)));
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn wake_transitions_blocked_to_ready() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Blocked, Some(WaitReason::FdWritable(4)));
            NUM_TASKS = 1;
            wake(0);
            let tcb = TASKS[0].assume_init_ref();
            assert_eq!(tcb.state, TaskState::Ready);
            assert_eq!(tcb.wait_reason, None);
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn wake_ignores_non_blocked_task() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Ready, None);
            NUM_TASKS = 1;
            wake(0);
            let tcb = TASKS[0].assume_init_ref();
            assert_eq!(tcb.state, TaskState::Ready);
            assert_eq!(tcb.wait_reason, None);
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn wake_by_fd_finds_matching_blocked_task() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            // Task 0: blocked waiting for fd 5 readable — should be woken (op=0).
            put_tcb(0, TaskState::Blocked, Some(WaitReason::FdReadable(5)));
            // Task 1: blocked waiting for fd 5 writable — should NOT be woken (op=0).
            put_tcb(1, TaskState::Blocked, Some(WaitReason::FdWritable(5)));
            // Task 2: blocked waiting for fd 9 readable — different fd, not woken.
            put_tcb(2, TaskState::Blocked, Some(WaitReason::FdReadable(9)));
            NUM_TASKS = 3;

            wake_by_fd(5, 0); // wake readable fd=5

            assert_eq!(TASKS[0].assume_init_ref().state, TaskState::Ready);
            assert_eq!(TASKS[0].assume_init_ref().wait_reason, None);
            assert_eq!(TASKS[1].assume_init_ref().state, TaskState::Blocked);
            assert_eq!(
                TASKS[1].assume_init_ref().wait_reason,
                Some(WaitReason::FdWritable(5))
            );
            assert_eq!(TASKS[2].assume_init_ref().state, TaskState::Blocked);

            NUM_TASKS = 0;
        }
    }

    #[test]
    fn for_each_blocked_iterates_blocked_tasks() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Running, None);
            put_tcb(1, TaskState::Blocked, Some(WaitReason::PollWait));
            put_tcb(2, TaskState::Ready, None);
            put_tcb(3, TaskState::Blocked, Some(WaitReason::FdConnectDone(2)));
            NUM_TASKS = 4;

            let mut visited: Vec<(usize, WaitReason)> = Vec::new();
            for_each_blocked(|idx, reason| visited.push((idx, reason)));

            assert_eq!(visited.len(), 2);
            assert!(visited.contains(&(1, WaitReason::PollWait)));
            assert!(visited.contains(&(3, WaitReason::FdConnectDone(2))));

            NUM_TASKS = 0;
        }
    }

    #[test]
    fn tcb_has_thread_fields() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            NUM_TASKS = 1;
            TASKS[0] = MaybeUninit::new(TaskControlBlock {
                kernel_sp: 0,
                kernel_stack_base: 0x1_0000,
                kernel_stack_size: 8192,
                state: TaskState::Ready,
                preempt_count: 0,
                pid: 1,
                name: "test",
                entry: None,
                wait_reason: None,
                tls: 0xDEAD_BEEF,
                tid: 42,
                clear_child_tid: 0xCAFE,
                deadline_ms: None,
                woken_by_timeout: false,
            });
            let tcb = TASKS[0].assume_init_ref();
            assert_eq!(tcb.tls, 0xDEAD_BEEF);
            assert_eq!(tcb.tid, 42);
            assert_eq!(tcb.clear_child_tid, 0xCAFE);
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn wait_reason_futex_variant() {
        assert_ne!(WaitReason::Futex(0x1000), WaitReason::Futex(0x2000));
        assert_eq!(WaitReason::Futex(0x1000), WaitReason::Futex(0x1000));
        assert_ne!(WaitReason::Futex(0x1000), WaitReason::FdReadable(1));
    }

    #[test]
    fn futex_wake_wakes_matching_tasks() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            // Use put_tcb helper for task setup.
            put_tcb(0, TaskState::Running, None);
            TASKS[0].assume_init_mut().tid = 1;
            TASKS[0].assume_init_mut().tls = 0;
            TASKS[0].assume_init_mut().clear_child_tid = 0;

            put_tcb(1, TaskState::Blocked, Some(WaitReason::Futex(0x1000)));
            TASKS[1].assume_init_mut().tid = 2;
            TASKS[1].assume_init_mut().tls = 0;
            TASKS[1].assume_init_mut().clear_child_tid = 0;

            put_tcb(2, TaskState::Blocked, Some(WaitReason::Futex(0x1000)));
            TASKS[2].assume_init_mut().tid = 3;
            TASKS[2].assume_init_mut().tls = 0;
            TASKS[2].assume_init_mut().clear_child_tid = 0;

            put_tcb(3, TaskState::Blocked, Some(WaitReason::Futex(0x2000)));
            TASKS[3].assume_init_mut().tid = 4;
            TASKS[3].assume_init_mut().tls = 0;
            TASKS[3].assume_init_mut().clear_child_tid = 0;

            NUM_TASKS = 4;
            CURRENT = 0;

            // Wake at most 1 task on 0x1000.
            let woken = futex_wake(0x1000, 1);
            assert_eq!(woken, 1);

            // Task 3 (0x2000) still blocked.
            assert_eq!(TASKS[3].assume_init_ref().state, TaskState::Blocked);

            NUM_TASKS = 0;
        }
    }

    #[test]
    fn futex_wake_returns_zero_when_no_waiters() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Running, None);
            TASKS[0].assume_init_mut().tid = 1;
            TASKS[0].assume_init_mut().tls = 0;
            TASKS[0].assume_init_mut().clear_child_tid = 0;
            NUM_TASKS = 1;
            CURRENT = 0;

            let woken = futex_wake(0x1000, 10);
            assert_eq!(woken, 0);
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn kill_threads_by_pid_marks_matching_dead_except_current() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            CURRENT = 0;

            put_tcb(0, TaskState::Running, None);
            TASKS[0].assume_init_mut().pid = 2;
            TASKS[0].assume_init_mut().tid = 0; // Main thread (CURRENT)
            TASKS[0].assume_init_mut().tls = 0;
            TASKS[0].assume_init_mut().clear_child_tid = 0;

            put_tcb(1, TaskState::Ready, None);
            TASKS[1].assume_init_mut().pid = 2;
            TASKS[1].assume_init_mut().tid = 3; // Spawned thread
            TASKS[1].assume_init_mut().tls = 0;
            TASKS[1].assume_init_mut().clear_child_tid = 0;

            put_tcb(2, TaskState::Ready, None);
            TASKS[2].assume_init_mut().pid = 1; // Different PID
            TASKS[2].assume_init_mut().tid = 1;
            TASKS[2].assume_init_mut().tls = 0;
            TASKS[2].assume_init_mut().clear_child_tid = 0;

            NUM_TASKS = 3;

            kill_threads_by_pid(2);

            // Task 0 (CURRENT) is skipped — still Running.
            assert_eq!(TASKS[0].assume_init_ref().state, TaskState::Running);
            // Task 1 (same PID, not CURRENT) is Dead.
            assert_eq!(TASKS[1].assume_init_ref().state, TaskState::Dead);
            // Task 2 (different PID) is untouched.
            assert_eq!(TASKS[2].assume_init_ref().state, TaskState::Ready);
            NUM_TASKS = 0;
        }
    }

    // ── Deadline / sleep tests ───────────────────────────────────────────────

    #[test]
    fn wait_reason_sleep_variant() {
        // Sleep is a pure time wait — no fd or address.
        let s = WaitReason::Sleep;
        assert_eq!(s, WaitReason::Sleep);
        assert_ne!(s, WaitReason::FdReadable(0));
        assert_ne!(s, WaitReason::PollWait);
    }

    #[test]
    fn block_current_stores_deadline() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Running, None);
            NUM_TASKS = 1;
            CURRENT = 0;
            block_current(WaitReason::Sleep, Some(1234));
            let tcb = TASKS[0].assume_init_ref();
            assert_eq!(tcb.state, TaskState::Blocked);
            assert_eq!(tcb.wait_reason, Some(WaitReason::Sleep));
            assert_eq!(tcb.deadline_ms, Some(1234));
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn block_current_clears_stale_woken_by_timeout() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Running, None);
            // Simulate a stale flag from a previous timeout wake.
            TASKS[0].assume_init_mut().woken_by_timeout = true;
            NUM_TASKS = 1;
            CURRENT = 0;

            block_current(WaitReason::Futex(0x1000), Some(500));

            let tcb = TASKS[0].assume_init_ref();
            assert_eq!(tcb.state, TaskState::Blocked);
            // The stale flag must be cleared on entry to blocking.
            assert!(!tcb.woken_by_timeout);
            assert_eq!(tcb.deadline_ms, Some(500));
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn check_deadlines_wakes_expired_task() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            // Task 0: blocked with deadline at 100ms — now is 150ms, should wake.
            put_tcb(0, TaskState::Blocked, Some(WaitReason::Sleep));
            TASKS[0].assume_init_mut().deadline_ms = Some(100);
            TASKS[0].assume_init_mut().woken_by_timeout = false;

            // Task 1: blocked with deadline at 200ms — now is 150ms, should NOT wake.
            put_tcb(1, TaskState::Blocked, Some(WaitReason::FdReadable(3)));
            TASKS[1].assume_init_mut().deadline_ms = Some(200);
            TASKS[1].assume_init_mut().woken_by_timeout = false;

            // Task 2: no deadline — should NOT be affected.
            put_tcb(2, TaskState::Blocked, Some(WaitReason::PollWait));
            TASKS[2].assume_init_mut().deadline_ms = None;
            TASKS[2].assume_init_mut().woken_by_timeout = false;

            NUM_TASKS = 3;

            check_deadlines(150);

            // Task 0: deadline expired → Ready, woken_by_timeout=true, fields cleared.
            let t0 = TASKS[0].assume_init_ref();
            assert_eq!(t0.state, TaskState::Ready);
            assert_eq!(t0.wait_reason, None);
            assert_eq!(t0.deadline_ms, None);
            assert!(t0.woken_by_timeout);

            // Task 1: deadline not yet expired → still Blocked.
            let t1 = TASKS[1].assume_init_ref();
            assert_eq!(t1.state, TaskState::Blocked);
            assert_eq!(t1.deadline_ms, Some(200));
            assert!(!t1.woken_by_timeout);

            // Task 2: no deadline → untouched.
            let t2 = TASKS[2].assume_init_ref();
            assert_eq!(t2.state, TaskState::Blocked);
            assert!(!t2.woken_by_timeout);

            NUM_TASKS = 0;
        }
    }

    #[test]
    fn check_deadlines_wakes_at_exact_deadline() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Blocked, Some(WaitReason::Sleep));
            TASKS[0].assume_init_mut().deadline_ms = Some(500);
            TASKS[0].assume_init_mut().woken_by_timeout = false;
            NUM_TASKS = 1;

            // Exactly at deadline — should wake (now_ms >= deadline).
            check_deadlines(500);

            let t0 = TASKS[0].assume_init_ref();
            assert_eq!(t0.state, TaskState::Ready);
            assert!(t0.woken_by_timeout);
            assert_eq!(t0.deadline_ms, None);

            NUM_TASKS = 0;
        }
    }

    #[test]
    fn check_deadlines_skips_non_blocked_tasks() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Ready, None);
            TASKS[0].assume_init_mut().deadline_ms = Some(1); // Would expire immediately
            TASKS[0].assume_init_mut().woken_by_timeout = false;

            put_tcb(1, TaskState::Running, None);
            TASKS[1].assume_init_mut().deadline_ms = Some(1);
            TASKS[1].assume_init_mut().woken_by_timeout = false;

            NUM_TASKS = 2;

            check_deadlines(9999);

            // Neither task should have woken_by_timeout set — only Blocked tasks are checked.
            assert!(!TASKS[0].assume_init_ref().woken_by_timeout);
            assert!(!TASKS[1].assume_init_ref().woken_by_timeout);

            NUM_TASKS = 0;
        }
    }

    #[test]
    fn consume_woken_by_timeout_reads_and_clears() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Ready, None);
            TASKS[0].assume_init_mut().woken_by_timeout = true;
            NUM_TASKS = 1;
            CURRENT = 0;

            // First call: returns true, clears the flag.
            assert!(consume_woken_by_timeout());
            // Second call: flag already cleared, returns false.
            assert!(!consume_woken_by_timeout());

            NUM_TASKS = 0;
        }
    }

    #[test]
    fn normal_wake_clears_deadline_and_flag() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            // Task blocked with a deadline — woken via wake() before deadline fires.
            put_tcb(0, TaskState::Blocked, Some(WaitReason::Sleep));
            TASKS[0].assume_init_mut().deadline_ms = Some(9999);
            TASKS[0].assume_init_mut().woken_by_timeout = false;
            NUM_TASKS = 1;

            wake(0);

            let t0 = TASKS[0].assume_init_ref();
            assert_eq!(t0.state, TaskState::Ready);
            assert_eq!(t0.wait_reason, None);
            assert_eq!(t0.deadline_ms, None);
            // woken_by_timeout must remain false (it was a normal wake, not timer).
            assert!(!t0.woken_by_timeout);

            NUM_TASKS = 0;
        }
    }

    // ── WaitChild / wake_waiting_parent tests ───────────────────────────────

    #[test]
    fn wake_waiting_parent_wakes_any_child() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Blocked, Some(WaitReason::WaitChild(-1)));
            NUM_TASKS = 1;

            wake_waiting_parent(42);

            let t0 = TASKS[0].assume_init_ref();
            assert_eq!(t0.state, TaskState::Ready);
            assert_eq!(t0.wait_reason, None);
            assert_eq!(t0.deadline_ms, None);

            NUM_TASKS = 0;
        }
    }

    #[test]
    fn wake_waiting_parent_matches_specific_pid() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Blocked, Some(WaitReason::WaitChild(5)));
            NUM_TASKS = 1;

            wake_waiting_parent(3);
            assert_eq!(TASKS[0].assume_init_ref().state, TaskState::Blocked);

            wake_waiting_parent(5);
            assert_eq!(TASKS[0].assume_init_ref().state, TaskState::Ready);
            assert_eq!(TASKS[0].assume_init_ref().wait_reason, None);

            NUM_TASKS = 0;
        }
    }

    #[test]
    fn wake_waiting_parent_ignores_non_waiting_tasks() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Ready, None);
            put_tcb(1, TaskState::Dead, None);
            put_tcb(2, TaskState::Blocked, Some(WaitReason::Futex(0x1000)));
            NUM_TASKS = 3;

            wake_waiting_parent(10);

            assert_eq!(TASKS[0].assume_init_ref().state, TaskState::Ready);
            assert_eq!(TASKS[1].assume_init_ref().state, TaskState::Dead);
            assert_eq!(TASKS[2].assume_init_ref().state, TaskState::Blocked);
            assert_eq!(
                TASKS[2].assume_init_ref().wait_reason,
                Some(WaitReason::Futex(0x1000))
            );

            NUM_TASKS = 0;
        }
    }

    #[test]
    fn wake_waiting_parent_only_wakes_first_match() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            put_tcb(0, TaskState::Blocked, Some(WaitReason::WaitChild(-1)));
            put_tcb(1, TaskState::Blocked, Some(WaitReason::WaitChild(-1)));
            NUM_TASKS = 2;

            wake_waiting_parent(7);

            assert_eq!(TASKS[0].assume_init_ref().state, TaskState::Ready);
            assert_eq!(TASKS[1].assume_init_ref().state, TaskState::Blocked);

            NUM_TASKS = 0;
        }
    }

    // ── redirect_main_thread_to_boot tests ──────────────────────────────────

    #[test]
    fn redirect_main_thread_patches_trapframe() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            // Allocate a TrapFrame on the heap to simulate a kernel stack.
            let frame = Box::new(crate::syscall::TrapFrame {
                x: [0u64; 31],
                elr: 0xDEAD,
                spsr: 0,
                fpcr: 0,
                fpsr: 0,
                _pad: 0,
                q: [0u128; 32],
            });
            let frame_ptr = Box::into_raw(frame);

            // Task 0 (current, spawned thread) — pid=2, tid=3.
            put_tcb(0, TaskState::Running, None);
            TASKS[0].assume_init_mut().pid = 2;
            TASKS[0].assume_init_mut().tid = 3;

            // Task 1 (main thread) — pid=2, tid=0, Dead (killed by kill_threads_by_pid).
            put_tcb(1, TaskState::Dead, None);
            TASKS[1].assume_init_mut().pid = 2;
            TASKS[1].assume_init_mut().tid = 0;
            TASKS[1].assume_init_mut().kernel_sp = frame_ptr as usize;

            NUM_TASKS = 2;
            CURRENT = 0;

            redirect_main_thread_to_boot(2, 42, 0xB007, 0x5500, 0x1200);

            // Main thread's TrapFrame should be patched.
            let patched = &*frame_ptr;
            assert_eq!(patched.elr, 0xB007);
            assert_eq!(patched.x[0], 42); // exit_code
            assert_eq!(patched.x[1], 0x5500); // ret_sp
            assert_eq!(patched.x[2], 0x1200); // ret_lr

            // Main thread should be Ready now.
            assert_eq!(TASKS[1].assume_init_ref().state, TaskState::Ready);
            assert_eq!(TASKS[1].assume_init_ref().wait_reason, None);
            assert_eq!(TASKS[1].assume_init_ref().deadline_ms, None);

            // Clean up.
            let _ = Box::from_raw(frame_ptr);
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn redirect_main_thread_skips_current_task() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            let frame = Box::new(crate::syscall::TrapFrame {
                x: [0u64; 31],
                elr: 0xAAAA,
                spsr: 0,
                fpcr: 0,
                fpsr: 0,
                _pad: 0,
                q: [0u128; 32],
            });
            let frame_ptr = Box::into_raw(frame);

            // Task 0 is CURRENT, pid=2, tid=0 — should be skipped even though
            // it matches pid and tid==0, because it's the calling task.
            put_tcb(0, TaskState::Running, None);
            TASKS[0].assume_init_mut().pid = 2;
            TASKS[0].assume_init_mut().tid = 0;
            TASKS[0].assume_init_mut().kernel_sp = frame_ptr as usize;

            NUM_TASKS = 1;
            CURRENT = 0;

            redirect_main_thread_to_boot(2, 1, 0xB007, 0x5500, 0x1100);

            // TrapFrame should NOT be patched — task was skipped.
            let patched = &*frame_ptr;
            assert_eq!(patched.elr, 0xAAAA);

            // Task should still be Running.
            assert_eq!(TASKS[0].assume_init_ref().state, TaskState::Running);

            let _ = Box::from_raw(frame_ptr);
            NUM_TASKS = 0;
        }
    }

    #[test]
    fn redirect_main_thread_skips_wrong_pid() {
        let _lock = TEST_LOCK.lock().unwrap();
        unsafe {
            let frame = Box::new(crate::syscall::TrapFrame {
                x: [0u64; 31],
                elr: 0xBBBB,
                spsr: 0,
                fpcr: 0,
                fpsr: 0,
                _pad: 0,
                q: [0u128; 32],
            });
            let frame_ptr = Box::into_raw(frame);

            // Task 0 (current) — pid=2, tid=3.
            put_tcb(0, TaskState::Running, None);
            TASKS[0].assume_init_mut().pid = 2;
            TASKS[0].assume_init_mut().tid = 3;

            // Task 1 — pid=9 (wrong), tid=0.
            put_tcb(1, TaskState::Dead, None);
            TASKS[1].assume_init_mut().pid = 9;
            TASKS[1].assume_init_mut().tid = 0;
            TASKS[1].assume_init_mut().kernel_sp = frame_ptr as usize;

            NUM_TASKS = 2;
            CURRENT = 0;

            redirect_main_thread_to_boot(2, 1, 0xB007, 0x5500, 0x1100);

            // TrapFrame should NOT be patched — wrong PID.
            let patched = &*frame_ptr;
            assert_eq!(patched.elr, 0xBBBB);
            assert_eq!(TASKS[1].assume_init_ref().state, TaskState::Dead);

            let _ = Box::from_raw(frame_ptr);
            NUM_TASKS = 0;
        }
    }
}
