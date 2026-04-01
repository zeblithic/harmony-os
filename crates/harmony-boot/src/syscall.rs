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
            // Halt — do not return to the binary after exit_group.
            // sysretq would jump to an undefined address.
            loop {
                core::arch::asm!("hlt");
            }
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
        // ── Save ALL registers preserved by the Linux syscall ABI ──
        //
        // The `syscall` instruction only clobbers RAX (return value),
        // RCX (saved RIP), and R11 (saved RFLAGS). The kernel must
        // preserve everything else: RBX, RBP, RSP, R12-R15 (callee-saved)
        // AND RDI, RSI, RDX, R8, R9, R10 (argument registers that
        // userspace expects to survive the syscall).
        //
        // We save RCX/R11 for sysretq, and all caller-saved argument
        // registers because rust_syscall_handler (SysV) will clobber them.
        "push rcx",          // return RIP (saved by syscall hw)
        "push r11",          // return RFLAGS (saved by syscall hw)
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // Argument registers — must survive the Rust call
        "push rdi",          // a1
        "push rsi",          // a2
        "push rdx",          // a3
        "push r10",          // a4
        "push r8",           // a5
        "push r9",           // a6

        // Force 16-byte stack alignment for SysV ABI.
        // 14 pushes (14*8 = 112 bytes) = even, so if RSP was 16-aligned
        // before the first push, it's still 16-aligned now.
        // But user RSP may not be aligned, so force it.
        "mov rbp, rsp",      // save frame pointer
        "and rsp, -16",      // force 16-byte alignment

        // Set up arguments for rust_syscall_handler(nr, a1, a2, a3, a4, a5, a6)
        // SysV calling convention: rdi, rsi, rdx, rcx, r8, r9, [stack]
        //
        // Current:  RAX=nr, RDI=a1, RSI=a2, RDX=a3, R10=a4, R8=a5, R9=a6
        // Need:     RDI=nr, RSI=a1, RDX=a2, RCX=a3, R8=a4, R9=a5, [stack]=a6
        "sub rsp, 8",        // alignment padding
        "push r9",           // a6 as 7th stack arg

        // Shuffle registers: Linux ABI → SysV calling convention
        "mov r9, r8",        // r9 = a5
        "mov r8, r10",       // r8 = a4
        "mov rcx, rdx",      // rcx = a3
        "mov rdx, rsi",      // rdx = a2
        "mov rsi, rdi",      // rsi = a1
        "mov rdi, rax",      // rdi = nr

        "call rust_syscall_handler",

        // Return value is in RAX. Restore frame pointer / stack.
        "mov rsp, rbp",

        // ── Restore ALL saved registers ──
        // Argument registers (in reverse push order)
        "pop r9",
        "pop r8",
        "pop r10",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        // Callee-saved registers
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",           // return RFLAGS
        "pop rcx",           // return RIP

        // Keep IF disabled (no IDT for hardware interrupts).
        "cli",

        // jmp back to caller
        "jmp rcx",
    );
}

// ── MSR setup ───────────────────────────────────────────────────────

/// Configure x86_64 MSRs for syscall interception.
///
/// # Arguments
/// - `kernel_cs`: Kernel code segment selector (SYSCALL loads this into CS)
/// - `user_cs_base`: Base selector for SYSRET. SYSRET sets CS = base+16, SS = base+8.
///   In our flat Ring 0 MVP, set this so base+16 resolves to a valid 64-bit code segment.
///
/// # Safety
/// Must be called in Ring 0 with interrupts disabled.
/// The GDT must have valid segments at both `kernel_cs` and `user_cs_base+16`.
pub unsafe fn setup_msrs(kernel_cs: u16, user_cs_base: u16) {
    // Enable System Call Enable bit in EFER
    let efer = rdmsr(IA32_EFER);
    wrmsr(IA32_EFER, efer | EFER_SCE);

    // LSTAR — syscall entry point
    wrmsr(IA32_LSTAR, syscall_entry as u64);

    // STAR — kernel CS in [47:32], user CS base in [63:48]
    // SYSCALL: CS = STAR[47:32], SS = STAR[47:32] + 8
    // SYSRET:  CS = STAR[63:48] + 16, SS = STAR[63:48] + 8
    let star = ((user_cs_base as u64) << 48) | ((kernel_cs as u64) << 32);
    wrmsr(IA32_STAR, star);

    // FMASK — clear IF (bit 9) on syscall entry to prevent interrupts
    wrmsr(IA32_FMASK, 0x200);
}

// ── FS base register ──────────────────────────────────────────────

const IA32_FS_BASE: u32 = 0xC000_0100;

/// Write the FS segment base register (for TLS).
///
/// # Safety
/// Must be called in Ring 0.
pub unsafe fn write_fs_base(addr: u64) {
    wrmsr(IA32_FS_BASE, addr);
}

/// Read the FS segment base register.
///
/// # Safety
/// Must be called in Ring 0.
#[allow(dead_code)] // Symmetric pair with write_fs_base; used when ARCH_GET_FS reads from MSR.
pub unsafe fn read_fs_base() -> u64 {
    rdmsr(IA32_FS_BASE)
}
