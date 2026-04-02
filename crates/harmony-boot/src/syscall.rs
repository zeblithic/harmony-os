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

/// Execve target: when set, the syscall handler jumps here instead of returning.
static mut EXECVE_ENTRY: u64 = 0;
static mut EXECVE_RSP: u64 = 0;

/// Set the execve target. The next syscall return will jump to `entry` with `rsp`.
///
/// # Safety
/// Must be called from the dispatch function during an execve syscall.
pub unsafe fn set_execve_target(entry: u64, rsp: u64) {
    EXECVE_ENTRY = entry;
    EXECVE_RSP = rsp;
}

// ── Fork context switching ─────────────────────────────────────────
//
// When fork creates a child, the assembly trampoline copies the parent's
// full register frame (14 registers + user RSP) to a static buffer and
// returns 0 so the code takes the child path.  When the child exits, the
// trampoline restores all registers and RSP from the buffer, sets RAX to
// the saved child_pid, and jumps to the parent's return RIP.
//
// The frame MUST be copied to a static buffer because the child reuses
// the parent's stack before exec and will overwrite the on-stack frame.

/// When set to 1, the trampoline copies the frame to the static buffer.
#[no_mangle]
static mut FORK_SAVE_PARENT: u64 = 0;

/// When set to 1, the trampoline restores from the static buffer.
#[no_mangle]
static mut FORK_RESTORE_PARENT: u64 = 0;

/// Saved return value (child_pid) to deliver to the parent on restore.
#[no_mangle]
static mut FORK_PARENT_RETVAL: u64 = 0;

/// Saved register frame for the parent context.
/// Layout matches syscall_entry push order:
///   [0]=r9  [1]=r8  [2]=r10 [3]=rdx [4]=rsi [5]=rdi
///   [6]=r15 [7]=r14 [8]=r13 [9]=r12 [10]=rbp [11]=rbx
///   [12]=r11 [13]=rcx(RIP) [14]=user_rsp
#[no_mangle]
static mut FORK_SAVED_FRAME: [u64; 15] = [0; 15];

/// Saved user stack content. The child reuses the parent's stack before
/// exec and corrupts local variables. We save from user_rsp upward,
/// clamped to the actual stack bounds to avoid reading past the allocation.
const FORK_STACK_SAVE_MAX: usize = 16 * 1024;
#[no_mangle]
static mut FORK_SAVED_STACK: [u8; FORK_STACK_SAVE_MAX] = [0; FORK_STACK_SAVE_MAX];

/// Actual number of bytes saved (clamped to stack bounds).
/// Set by Rust before the trampoline reads it; used by both save and restore.
#[no_mangle]
static mut FORK_STACK_SAVE_ACTUAL: u64 = 0;

/// Top of the user stack allocation. Set once during boot.
static mut USER_STACK_TOP: u64 = 0;

static mut FORK_DEPTH: usize = 0;

/// Set the user stack top address. Called once during boot.
///
/// # Safety
/// Must be called before any fork context switching.
pub unsafe fn set_user_stack_top(top: u64) {
    USER_STACK_TOP = top;
}

/// Signal the trampoline to save the parent context and return 0.
///
/// # Safety
/// Must be called from the dispatch function when a fork just created a child.
pub unsafe fn fork_save_context() {
    let d = FORK_DEPTH;
    assert!(d < 2, "only one level of fork nesting supported");
    FORK_DEPTH = d + 1;
    FORK_SAVE_PARENT = 1;
}

/// Signal the trampoline to restore the parent context.
///
/// # Safety
/// Must be called from the dispatch function when a fork child has exited.
pub unsafe fn fork_restore_context() {
    let d = FORK_DEPTH;
    assert!(d > 0, "fork_restore with no saved context");
    FORK_DEPTH = d - 1;
    FORK_RESTORE_PARENT = 1;
}

/// Restore the parent's user stack from the saved buffer.
///
/// # Safety
/// Must be called before `fork_restore_context` while the child's stack
/// is still active (the trampoline will switch RSP during restore).
pub unsafe fn fork_restore_stack() {
    let user_rsp = FORK_SAVED_FRAME[14];
    let actual = FORK_STACK_SAVE_ACTUAL as usize;
    if user_rsp != 0 && actual > 0 {
        core::ptr::copy_nonoverlapping(
            FORK_SAVED_STACK.as_ptr(),
            user_rsp as *mut u8,
            actual,
        );
    }
}

/// Current fork nesting depth.
pub fn fork_depth() -> usize {
    unsafe { FORK_DEPTH }
}

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
            loop {
                core::arch::asm!("hlt");
            }
        }
        // Check for pending execve — jump to the new binary.
        if EXECVE_ENTRY != 0 {
            let entry = EXECVE_ENTRY;
            let rsp = EXECVE_RSP;
            EXECVE_ENTRY = 0;
            EXECVE_RSP = 0;
            core::arch::asm!(
                "mov rsp, {rsp}",
                "jmp {entry}",
                rsp = in(reg) rsp,
                entry = in(reg) entry,
                options(noreturn),
            );
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
        "push rcx", // return RIP (saved by syscall hw)
        "push r11", // return RFLAGS (saved by syscall hw)
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // Argument registers — must survive the Rust call
        "push rdi", // a1
        "push rsi", // a2
        "push rdx", // a3
        "push r10", // a4
        "push r8",  // a5
        "push r9",  // a6
        // Force 16-byte stack alignment for SysV ABI.
        // 14 pushes (14*8 = 112 bytes) = even, so if RSP was 16-aligned
        // before the first push, it's still 16-aligned now.
        // But user RSP may not be aligned, so force it.
        "mov rbp, rsp", // save frame pointer
        "and rsp, -16", // force 16-byte alignment
        // Set up arguments for rust_syscall_handler(nr, a1, a2, a3, a4, a5, a6)
        // SysV calling convention: rdi, rsi, rdx, rcx, r8, r9, [stack]
        //
        // Current:  RAX=nr, RDI=a1, RSI=a2, RDX=a3, R10=a4, R8=a5, R9=a6
        // Need:     RDI=nr, RSI=a1, RDX=a2, RCX=a3, R8=a4, R9=a5, [stack]=a6
        "sub rsp, 8", // alignment padding
        "push r9",    // a6 as 7th stack arg
        // Shuffle registers: Linux ABI → SysV calling convention
        "mov r9, r8",   // r9 = a5
        "mov r8, r10",  // r8 = a4
        "mov rcx, rdx", // rcx = a3
        "mov rdx, rsi", // rdx = a2
        "mov rsi, rdi", // rsi = a1
        "mov rdi, rax", // rdi = nr
        "call rust_syscall_handler",
        // Return value is in RAX.
        //
        // ── Fork context switching ──
        // All symbol references use RIP-relative lea to avoid R_X86_64_32S
        // relocations that fail on x86_64-unknown-none.
        //
        // FORK_SAVE: copy 14 registers from the stack frame (at rbp) to
        // a static buffer, plus the user RSP. Save child_pid, return 0.
        "lea rcx, [rip + {fork_save}]",
        "cmp qword ptr [rcx], 1",
        "jne 2f",
        "mov qword ptr [rcx], 0",
        // Copy 14 registers (112 bytes) from frame at rbp to static buffer.
        "cld",
        "mov rcx, 112",
        "lea rsi, [rbp]",
        "lea rdi, [rip + {saved_frame}]",
        "rep movsb",
        // Save user RSP = rbp + 112 (stack position before first push).
        "lea rcx, [rbp + 112]",
        "lea rdi, [rip + {saved_frame}]",
        "mov [rdi + 112], rcx",
        // Save user stack from user_rsp upward, clamped to stack bounds.
        // user_rsp = rbp + 112. Save min(16384, stack_top - user_rsp) bytes.
        "cld",
        "lea rsi, [rbp + 112]",               // rsi = user_rsp
        "lea rdi, [rip + {user_stack_top}]",
        "mov rdi, [rdi]",                     // rdi = stack_top
        "sub rdi, rsi",                       // rdi = stack_top - user_rsp
        "mov rcx, 16384",
        "cmp rdi, rcx",
        "cmovb rcx, rdi",                    // rcx = min(16384, available)
        // Store actual size for restore.
        "lea rdi, [rip + {stack_save_actual}]",
        "mov [rdi], rcx",
        // Do the copy.
        "lea rdi, [rip + {saved_stack}]",      // dest: static buffer
        "rep movsb",
        // Save return value (child_pid).
        "lea rcx, [rip + {parent_retval}]",
        "mov [rcx], rax",
        // Return 0 to child path.
        "xor eax, eax",
        "jmp 3f",
        "2:",
        // FORK_RESTORE: load all registers from the static buffer,
        // restore RSP, set RAX=child_pid, jump to parent's RIP.
        // This path does NOT fall through to the normal pop sequence.
        "lea rcx, [rip + {fork_restore}]",
        "cmp qword ptr [rcx], 1",
        "jne 3f",
        "mov qword ptr [rcx], 0",
        // Use rcx as base pointer into the saved frame.
        "lea rcx, [rip + {saved_frame}]",
        "mov r9,  [rcx +  0]",
        "mov r8,  [rcx +  8]",
        "mov r10, [rcx + 16]",
        "mov rdx, [rcx + 24]",
        "mov rsi, [rcx + 32]",
        "mov rdi, [rcx + 40]",
        "mov r15, [rcx + 48]",
        "mov r14, [rcx + 56]",
        "mov r13, [rcx + 64]",
        "mov r12, [rcx + 72]",
        "mov rbp, [rcx + 80]",
        "mov rbx, [rcx + 88]",
        "mov r11, [rcx + 96]",
        // Load user RSP into rax (temp), return RIP into rcx.
        "mov rax, [rcx + 112]",  // rax = user RSP
        "mov rcx, [rcx + 104]",  // rcx = return RIP (clobbers base)
        // Switch to parent's stack.
        "mov rsp, rax",
        // Load return value (child_pid).
        "lea rax, [rip + {parent_retval}]",
        "mov rax, [rax]",
        // Jump to parent's return RIP.
        "cli",
        "jmp rcx",
        "3:",
        // ── Normal path: restore from stack frame ──
        "mov rsp, rbp",
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
        "pop r11", // return RFLAGS
        "pop rcx", // return RIP
        // Keep IF disabled (no IDT for hardware interrupts).
        "cli",
        // jmp back to caller
        "jmp rcx",
        // ── Symbol operands for fork statics ──
        fork_save = sym FORK_SAVE_PARENT,
        fork_restore = sym FORK_RESTORE_PARENT,
        parent_retval = sym FORK_PARENT_RETVAL,
        saved_frame = sym FORK_SAVED_FRAME,
        saved_stack = sym FORK_SAVED_STACK,
        stack_save_actual = sym FORK_STACK_SAVE_ACTUAL,
        user_stack_top = sym USER_STACK_TOP,
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
