// SPDX-License-Identifier: GPL-2.0-or-later
//! Aarch64 syscall trap handler — TrapFrame and SVC dispatch.
//!
//! The exception vector table (in `vectors.rs`) saves registers into a
//! `TrapFrame` and calls into the Rust handlers defined here.

// Hardware functions are only compiled for aarch64; suppress warnings on
// the host test runner.
#![cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]

/// Saved register state on exception entry (800 bytes).
///
/// The assembly vector table saves X0-X30, ELR_EL1, SPSR_EL1, FPCR,
/// FPSR, and Q0-Q31 (SIMD/FP) in this exact layout. The struct must
/// be `#[repr(C)]` so field offsets match the assembly push order.
#[repr(C)]
pub struct TrapFrame {
    /// General-purpose registers X0-X30.
    pub x: [u64; 31],
    /// Exception Link Register — the PC to return to.
    pub elr: u64,
    /// Saved Processor State Register.
    pub spsr: u64,
    /// Floating-Point Control Register.
    pub fpcr: u64,
    /// Floating-Point Status Register.
    pub fpsr: u64,
    /// Padding to align `q` to 16 bytes (required for `stp`/`ldp` of Q regs).
    _pad: u64,
    /// SIMD/FP registers Q0-Q31 (128 bits each).
    pub q: [u128; 32],
}

#[cfg_attr(not(target_arch = "aarch64"), allow(unused_imports))]
use harmony_os::linuxulator::LinuxSyscall;

/// Result from syscall dispatch.
pub struct SyscallDispatchResult {
    pub retval: i64,
    pub exited: bool,
    pub exit_code: i32,
    /// True for exit_group (kill all threads), false for thread-only exit.
    pub exit_group: bool,
}

/// Global dispatch function pointer. Set during boot before SVC is possible.
static mut DISPATCH_FN: Option<fn(LinuxSyscall) -> SyscallDispatchResult> = None;

/// Whether the Linux process has exited.
static mut PROCESS_EXITED: bool = false;
/// Exit code from the process.
static mut EXIT_CODE: i32 = 0;

/// Return address for the boot code after the ELF process exits.
/// Set before jumping to the ELF entry point.
static mut RETURN_ADDR: u64 = 0;
/// Saved kernel stack pointer to restore on ELF exit.
static mut RETURN_SP: u64 = 0;
/// Saved kernel link register — passed through TrapFrame x2 on exit.
/// Currently vestigial: the asm epilogue restores LR from the stack
/// rather than from x2.  Kept for defensive completeness.
static mut RETURN_LR: u64 = 0;

/// Pointer to the current task's TrapFrame during SVC dispatch.
/// Set by svc_handler before calling dispatch, read by spawn_fn callback
/// to copy the parent's register state to the child.
static mut CURRENT_TRAPFRAME: *const TrapFrame = core::ptr::null();

/// Get the current TrapFrame pointer.
///
/// # Safety
/// Must only be called from within the SVC dispatch path (i.e., from
/// a callback invoked by svc_handler). The pointer is only valid for
/// the duration of that dispatch.
pub unsafe fn current_trapframe() -> *const TrapFrame {
    CURRENT_TRAPFRAME
}

/// Install the syscall dispatch function.
///
/// # Safety
/// Must be called before the vector table is installed and before any
/// SVC instruction executes.
pub unsafe fn set_dispatch_fn(f: fn(LinuxSyscall) -> SyscallDispatchResult) {
    DISPATCH_FN = Some(f);
}

/// Check if the process has exited.
/// Currently unused — exit code is returned via the trampoline. Kept for
/// future polling-based execution models.
#[allow(dead_code)]
pub fn process_exited() -> bool {
    unsafe { PROCESS_EXITED }
}

/// Get the exit code.
/// Currently unused — exit code is returned via the trampoline.
#[allow(dead_code)]
pub fn exit_code() -> i32 {
    unsafe { EXIT_CODE }
}

/// Set the return context for process exit.
///
/// When exit_group fires, the SVC handler redirects ELR to `addr`,
/// restores SP from `sp`, and LR from `lr` via the TrapFrame.
///
/// # Safety
/// Must be called before the ELF entry point is invoked. `addr` must
/// point to valid executable code, and `sp` must be a valid stack pointer.
#[no_mangle]
pub unsafe extern "C" fn set_return_context(addr: u64, sp: u64, lr: u64) {
    RETURN_ADDR = addr;
    RETURN_SP = sp;
    RETURN_LR = lr;
}

/// Clear the return context after an ELF process exits.
///
/// Prevents stale `RETURN_ADDR` / `RETURN_SP` / `RETURN_LR` from
/// redirecting a subsequent `exit_group` to an invalid stack frame.
///
/// # Safety
/// Must be called after the ELF binary has exited and before any
/// new ELF binary is loaded.
pub unsafe fn reset_return_context() {
    RETURN_ADDR = 0;
    RETURN_SP = 0;
    RETURN_LR = 0;
    PROCESS_EXITED = false;
    EXIT_CODE = 0;
}

/// Rust SVC handler — called from the exception vector table asm.
///
/// Reads the syscall number from X8 and arguments from X0-X5,
/// maps to a `LinuxSyscall` via `from_aarch64`, dispatches, and
/// writes the return value back to X0 in the TrapFrame.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn svc_handler(frame: &mut TrapFrame) {
    // Store TrapFrame pointer for spawn_fn callback (clone reads parent state).
    CURRENT_TRAPFRAME = frame as *const TrapFrame;

    let nr = frame.x[8];
    let args = [
        frame.x[0], frame.x[1], frame.x[2], frame.x[3], frame.x[4], frame.x[5],
    ];

    let syscall = LinuxSyscall::from_aarch64(nr, args);

    if let Some(dispatch) = DISPATCH_FN {
        let result = dispatch(syscall);
        if result.exited {
            let tid = crate::sched::current_task_tid();
            let pid = crate::sched::current_task_pid();

            // For exit_group (from any thread), kill all threads first.
            if result.exit_group {
                crate::sched::kill_threads_by_pid(pid);
            }

            if tid != 0 {
                // Spawned thread exit — CLEARTID cleanup and die.
                let clear_addr = crate::sched::current_task_clear_child_tid();
                if clear_addr != 0 {
                    *(clear_addr as *mut u32) = 0;
                    crate::sched::futex_wake(clear_addr, 1);
                }
                crate::sched::mark_current_dead();
                // Trigger context switch away from this dead task.
                core::arch::asm!("msr daifclr, #2");
                crate::gic::send_sgi_self(crate::gic::YIELD_SGI);
                core::arch::asm!("msr daifset, #2");
                loop {
                    core::arch::asm!("wfi");
                }
            }

            // Main thread exit — kill any remaining threads.
            if !result.exit_group {
                // SYS_EXIT from main thread — also kill all threads.
                crate::sched::kill_threads_by_pid(pid);
            }

            // Existing exit_group behavior: redirect ELR to return address.
            if !PROCESS_EXITED {
                PROCESS_EXITED = true;
                EXIT_CODE = result.exit_code;
                if RETURN_ADDR != 0 {
                    // Redirect eret to the boot code's return point.
                    // The vector table restore sequence loads these from the
                    // TrapFrame before eret, so the binary never resumes.
                    frame.elr = RETURN_ADDR;
                    frame.x[0] = result.exit_code as u64;
                    frame.x[1] = RETURN_SP;
                    frame.x[2] = RETURN_LR;
                    return;
                }
            }
            // Fallback: halt if no return address was set.
            loop {
                core::arch::asm!("wfe");
            }
        }
        frame.x[0] = result.retval as u64;
    } else {
        // No dispatch function installed — return ENOSYS
        frame.x[0] = (-38i64) as u64;
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn trap_frame_size() {
        // 31 GP regs (248) + elr (8) + spsr (8) + fpcr (8) + fpsr (8)
        // + _pad (8) + 32 Q regs (512) = 800 bytes
        assert_eq!(mem::size_of::<TrapFrame>(), 800);
    }

    #[test]
    fn trap_frame_x8_offset() {
        // X8 (syscall number) is at index 8 in the x array
        // Offset = 8 * 8 = 64 bytes from start
        assert_eq!(mem::offset_of!(TrapFrame, x) + 8 * 8, 64);
    }

    #[test]
    fn trap_frame_elr_offset() {
        // ELR comes after 31 u64s = 248 bytes
        assert_eq!(mem::offset_of!(TrapFrame, elr), 248);
    }

    #[test]
    fn trap_frame_spsr_offset() {
        // SPSR comes after ELR = 256 bytes
        assert_eq!(mem::offset_of!(TrapFrame, spsr), 256);
    }

    #[test]
    fn trap_frame_fpcr_offset() {
        assert_eq!(mem::offset_of!(TrapFrame, fpcr), 264);
    }

    #[test]
    fn trap_frame_fpsr_offset() {
        assert_eq!(mem::offset_of!(TrapFrame, fpsr), 272);
    }

    #[test]
    fn trap_frame_q_offset() {
        assert_eq!(mem::offset_of!(TrapFrame, q), 288);
    }
}
