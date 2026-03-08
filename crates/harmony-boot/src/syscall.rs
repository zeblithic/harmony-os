// SPDX-License-Identifier: GPL-2.0-or-later
//! x86_64 syscall trap setup for the Linuxulator.
//!
//! Configures MSRs so the `syscall` instruction transfers control to
//! our handler, which dispatches to the Linuxulator.

use core::arch::asm;
use core::arch::naked_asm;

// ── MSR addresses ───────────────────────────────────────────────────

const IA32_EFER: u32 = 0xC000_0080;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;

const EFER_SCE: u64 = 1; // System Call Enable

/// Read a Model-Specific Register.
unsafe fn rdmsr(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") low,
        out("edx") high,
        options(nomem, nostack, preserves_flags),
    );
    (high as u64) << 32 | low as u64
}

/// Write a Model-Specific Register.
unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") low,
        in("edx") high,
        options(nomem, nostack, preserves_flags),
    );
}

// ── Syscall dispatch ────────────────────────────────────────────────

/// Result of a syscall dispatch.
pub struct SyscallResult {
    pub retval: i64,
    pub exited: bool,
    pub exit_code: i32,
}

/// Function pointer type for the syscall dispatcher.
pub type SyscallDispatchFn = fn(nr: u64, args: [u64; 6]) -> SyscallResult;

/// Global dispatch function. Set before enabling syscalls.
static mut DISPATCH_FN: Option<SyscallDispatchFn> = None;

/// Whether the Linux process has exited.
static mut PROCESS_EXITED: bool = false;
static mut EXIT_CODE: i32 = 0;

/// Install the syscall dispatch function.
///
/// # Safety
/// Must be called before `setup_msrs` and before any `syscall` executes.
pub unsafe fn set_dispatch_fn(f: SyscallDispatchFn) {
    DISPATCH_FN = Some(f);
}

/// Check if the process exited after a syscall.
pub fn process_exited() -> bool {
    unsafe { PROCESS_EXITED }
}

/// Get the exit code.
pub fn exit_code() -> i32 {
    unsafe { EXIT_CODE }
}

/// The Rust-side syscall handler. Called from the naked assembly trampoline.
#[no_mangle]
unsafe extern "C" fn rust_syscall_handler(
    nr: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> i64 {
    if let Some(dispatch) = DISPATCH_FN {
        let result = dispatch(nr, [arg1, arg2, arg3, arg4, arg5, arg6]);
        if result.exited {
            PROCESS_EXITED = true;
            EXIT_CODE = result.exit_code;
        }
        result.retval
    } else {
        -38 // ENOSYS
    }
}

// ── Naked syscall entry point ───────────────────────────────────────

/// The raw syscall entry point. The CPU jumps here on `syscall`.
///
/// Register state on entry (Linux x86_64 ABI):
///   RAX = syscall number
///   RDI = arg1, RSI = arg2, RDX = arg3
///   R10 = arg4, R8 = arg5, R9 = arg6
///   RCX = return RIP (saved by CPU)
///   R11 = return RFLAGS (saved by CPU)
#[unsafe(naked)]
#[no_mangle]
extern "C" fn syscall_entry() {
    naked_asm!(
        // Save registers that sysretq needs and callee-saved regs
        "push rcx",          // return RIP
        "push r11",          // return RFLAGS
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        // Set up arguments for rust_syscall_handler(nr, a1, a2, a3, a4, a5, a6)
        // SysV calling convention: rdi, rsi, rdx, rcx, r8, r9, [stack]
        //
        // Current:  RAX=nr, RDI=a1, RSI=a2, RDX=a3, R10=a4, R8=a5, R9=a6
        // Need:     RDI=nr, RSI=a1, RDX=a2, RCX=a3, R8=a4, R9=a5, [stack]=a6
        "push r9",           // save a6 for stack arg
        "mov r9, r8",        // r9 = a5
        "mov r8, r10",       // r8 = a4
        "mov rcx, rdx",      // rcx = a3
        "mov rdx, rsi",      // rdx = a2
        "mov rsi, rdi",      // rsi = a1
        "mov rdi, rax",      // rdi = nr

        // Push a6 as 7th arg (stack)
        // It's already on the stack from "push r9" above.
        // For 16-byte alignment: 8 pushes + 1 push = 9*8 = 72 bytes.
        // 72 is not 16-aligned, so push one more.
        "sub rsp, 8",        // align stack to 16 bytes

        "call rust_syscall_handler",

        // Return value is in RAX
        "add rsp, 16",       // pop alignment padding + a6

        // Restore callee-saved registers
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",           // return RFLAGS
        "pop rcx",           // return RIP

        "sysretq",
    );
}

// ── MSR setup ───────────────────────────────────────────────────────

/// Configure x86_64 MSRs for syscall interception.
///
/// # Safety
/// Must be called in Ring 0 with interrupts disabled.
/// The GDT must have a valid kernel code segment.
pub unsafe fn setup_msrs(kernel_cs: u16) {
    // Enable System Call Enable bit in EFER
    let efer = rdmsr(IA32_EFER);
    wrmsr(IA32_EFER, efer | EFER_SCE);

    // LSTAR — syscall entry point
    wrmsr(IA32_LSTAR, syscall_entry as u64);

    // STAR — kernel CS in bits 47:32
    let star = (kernel_cs as u64) << 32;
    wrmsr(IA32_STAR, star);

    // FMASK — clear IF (bit 9) on syscall entry to prevent interrupts
    wrmsr(IA32_FMASK, 0x200);
}
