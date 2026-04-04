// SPDX-License-Identifier: GPL-2.0-or-later
//! Aarch64 syscall trap handler — TrapFrame and SVC dispatch.
//!
//! The exception vector table (in `vectors.rs`) saves registers into a
//! `TrapFrame` and calls into the Rust handlers defined here.

// Hardware functions are only compiled for aarch64; suppress warnings on
// the host test runner.
#![cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]

/// Saved register state on exception entry.
///
/// The assembly vector table saves X0-X30, ELR_EL1, and SPSR_EL1 in
/// this exact layout. The struct must be `#[repr(C)]` so field offsets
/// match the assembly push order.
#[repr(C)]
pub struct TrapFrame {
    /// General-purpose registers X0-X30.
    pub x: [u64; 31],
    /// Exception Link Register — the PC to return to.
    pub elr: u64,
    /// Saved Processor State Register.
    pub spsr: u64,
}

#[cfg_attr(not(target_arch = "aarch64"), allow(unused_imports))]
use harmony_os::linuxulator::LinuxSyscall;

/// Result from syscall dispatch.
pub struct SyscallDispatchResult {
    pub retval: i64,
    pub exited: bool,
    pub exit_code: i32,
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
    let nr = frame.x[8];
    let args = [
        frame.x[0], frame.x[1], frame.x[2], frame.x[3], frame.x[4], frame.x[5],
    ];

    let syscall = LinuxSyscall::from_aarch64(nr, args);

    if let Some(dispatch) = DISPATCH_FN {
        let result = dispatch(syscall);
        if result.exited {
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
        // 31 registers * 8 bytes + ELR (8) + SPSR (8) = 264 bytes
        assert_eq!(mem::size_of::<TrapFrame>(), 264);
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
}
