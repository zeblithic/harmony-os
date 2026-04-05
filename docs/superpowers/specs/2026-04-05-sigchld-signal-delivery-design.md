# Signal Delivery Infrastructure (SIGCHLD)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Bead:** harmony-os-96y

**Goal:** Port signal frame infrastructure from x86_64 to aarch64, wire signal delivery into the boot code dispatch loop, and verify with SIGCHLD as the first real consumer.

**Prerequisite:** Phase 6 process lifecycle (PR #116) merged — exit_group, wait4, wake_waiting_parent all working.

---

## Architecture

Three layers of change, matching the existing separation of concerns:

1. **Linuxulator (harmony-os crate)** — aarch64 `SavedRegisters`, `setup_signal_frame()`, `rt_sigreturn` behind `#[cfg(target_arch = "aarch64")]`. x86_64 code stays intact behind `#[cfg(target_arch = "x86_64")]`. Signal policy (masks, delivery, handler table) unchanged — it's already architecture-neutral. New `SigInfo` struct for SIGCHLD-specific siginfo fields.

2. **Dispatch function (main.rs)** — After each `dispatch_syscall()`, check `pending_signal_return()` and `pending_handler_signal()`. If a handler needs invocation, snapshot the TrapFrame into `SavedRegisters`, call `setup_signal_frame()`, and pack the result into `SyscallDispatchResult`. If a signal return happened, pack restored registers into the result.

3. **SVC handler (syscall.rs)** — Read the new signal fields from `SyscallDispatchResult`. Patch TrapFrame for signal delivery (elr, sp, x0-x2, x30) or signal return (full register restore including SP_EL0 and FPSIMD).

### Data Flow

```
Signal delivery:
  svc_handler → dispatch() → lx.dispatch_syscall() → deliver_pending_signals()
                            → lx.pending_handler_signal() → Some(17)
                            → snapshot TrapFrame → SavedRegisters
                            → lx.setup_signal_frame(17, &saved, siginfo) → SignalHandlerSetup
                            ← SyscallDispatchResult { signal_setup: Some(...) }
             ← patch TrapFrame: elr=handler_pc, sp=frame_sp, x0=signum, x30=restorer
             ← eret → handler runs → ret → restorer → svc rt_sigreturn

Signal return:
  svc_handler → dispatch() → lx.dispatch_syscall(RtSigreturn)
                            → lx.pending_signal_return() → Some(SignalReturn)
                            ← SyscallDispatchResult { signal_return: Some(...) }
             ← restore TrapFrame from SavedRegisters (including SP_EL0, FPSIMD)
             ← eret → resume interrupted code
```

---

## aarch64 Signal Frame Format

### SavedRegisters (aarch64)

```rust
#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SavedRegisters {
    pub x: [u64; 31],    // x0-x30
    pub sp: u64,          // SP_EL0
    pub pc: u64,          // ELR_EL1 (interrupted PC)
    pub pstate: u64,      // SPSR_EL1
    pub fpcr: u64,
    pub fpsr: u64,
    pub q: [u128; 32],    // NEON/FP registers Q0-Q31
}
```

The x86_64 `SavedRegisters` (r8-r15, rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip, eflags) stays behind `#[cfg(target_arch = "x86_64")]`.

### rt_sigframe Layout on User Stack

```
+0:    siginfo_t (128 bytes)
         si_signo (i32, offset 0)
         si_code  (i32, offset 4) — CLD_EXITED=1, CLD_KILLED=2, SI_USER=0
         si_pid   (i32, offset 12) — sender/child PID
         si_status (i32, offset 16) — exit code or signal number
+128:  ucontext_t:
         uc_flags  (u64, offset 0)
         uc_link   (u64, offset 8)
         uc_stack  (24 bytes: ss_sp u64, ss_flags i32, pad, ss_size u64)
         uc_sigmask (u64) — saved signal mask
         __pad     (120 bytes) — sigset_t padding to 128 bytes
         sigcontext (offset 128+16+8+24+128 = 304 from ucontext start):
           fault_address (u64)
           regs[31] (x0-x30, 248 bytes)
           sp (u64)
           pc (u64)
           pstate (u64)
         __reserved[4096]:
           fpsimd_context (528 bytes):
             magic = FPSIMD_MAGIC (0x46508001)
             size = 528
             fpsr (u32)
             fpcr (u32)
             vregs[32] (128-bit each, 512 bytes)
           end marker: magic=0, size=0 (8 bytes)
```

Total frame size: 128 (siginfo) + ucontext header + sigcontext + __reserved. SP aligned to 16 bytes (aarch64 ABI, no red zone).

### SignalHandlerSetup (aarch64)

```rust
#[cfg(target_arch = "aarch64")]
pub struct SignalHandlerSetup {
    pub handler_pc: u64,   // Set ELR to this
    pub handler_sp: u64,   // Set SP_EL0 to this
    pub x0: u64,           // signum
    pub x1: u64,           // siginfo_t pointer (SA_SIGINFO) or 0
    pub x2: u64,           // ucontext_t pointer (SA_SIGINFO) or 0
    pub x30: u64,          // LR = sa_restorer (sigreturn trampoline)
}
```

x86_64 `SignalHandlerSetup` (handler_rip, handler_rsp, rdi, rsi, rdx) stays behind `#[cfg(target_arch = "x86_64")]`.

### Key Differences from x86_64

- No 128-byte red zone (aarch64 ABI has none)
- SP aligned to 16 bytes (not the `(base & !0xF) - 8` trick for x86_64 call convention)
- Restorer goes in x30 (LR), not pushed on stack as return address
- FPSIMD context in `__reserved` area with FPSIMD_MAGIC header
- sigcontext uses `regs[31]` array, not named r8/rdi/rsi fields
- SA_RESTORER assertion relaxed on aarch64 (musl still sets it, but convention is LR-based)

---

## SyscallDispatchResult Changes

```rust
pub struct SyscallDispatchResult {
    pub retval: i64,
    pub exited: bool,
    pub exit_code: i32,
    pub exit_group: bool,
    /// Signal handler to invoke — patch TrapFrame to jump to handler.
    pub signal_setup: Option<SignalHandlerSetup>,
    /// Register state to restore after rt_sigreturn.
    pub signal_return: Option<SavedRegisters>,
}
```

### dispatch() Signal Logic

After `lx.dispatch_syscall()`:

1. Check `lx.pending_signal_return()` first — if `Some`, the syscall was `rt_sigreturn`. Use the restored registers as the base state. Then also check `pending_handler_signal()` (rt_sigreturn may unmask a pending signal that gets immediately delivered).

2. Check `lx.pending_handler_signal()` — if `Some(signum)`, snapshot current TrapFrame (via `current_trapframe()`) into `SavedRegisters`, including SP_EL0 (via `read_sp_el0()`). Call `lx.setup_signal_frame(signum, &saved)`. Pack `SignalHandlerSetup` into result.

3. Edge case — signal delivery + signal return in same syscall: `rt_sigreturn` restores state AND may unmask a pending signal. Result carries ONLY `signal_setup` (not `signal_return`). The restored registers were already used as input to `setup_signal_frame`, so the signal frame contains the correct pre-signal state. When the new handler returns and does sigreturn, it resumes the original interrupted code.

### svc_handler Patching

```rust
if let Some(setup) = result.signal_setup {
    frame.elr = setup.handler_pc;
    frame.x[0] = setup.x0;       // signum
    frame.x[1] = setup.x1;       // siginfo_ptr
    frame.x[2] = setup.x2;       // ucontext_ptr
    frame.x[30] = setup.x30;     // LR = restorer
    write_sp_el0(setup.handler_sp);
} else if let Some(regs) = result.signal_return {
    frame.x = regs.x;
    frame.elr = regs.pc;
    frame.spsr = regs.pstate;
    frame.fpcr = regs.fpcr;
    frame.fpsr = regs.fpsr;
    frame.q = regs.q;
    write_sp_el0(regs.sp);
}
```

---

## SP_EL0 Handling

The user-space stack pointer (SP_EL0) is not in the TrapFrame — it's a separate system register. Two new helpers in `syscall.rs`:

- `read_sp_el0() -> u64` — `mrs x, sp_el0`. Called by `dispatch()` when building `SavedRegisters`.
- `write_sp_el0(val: u64)` — `msr sp_el0, x`. Called by `svc_handler` when applying signal setup or return.

Both are single-instruction inline asm behind `#[cfg(target_arch = "aarch64")]`, same safety model as `current_trapframe()`. Only valid within the SVC handler path (IRQs masked, EL1).

---

## SIGCHLD siginfo_t Population

### SigInfo Struct

```rust
pub struct SigInfo {
    pub si_code: i32,
    pub si_pid: i32,
    pub si_status: i32,
}
```

### Population

`deliver_pending_signals()` already identifies which signal to deliver. When it sets `pending_handler_signal`, it also stores `pending_siginfo: Option<SigInfo>`. Sources:

- **SIGCHLD from `recover_child_state()`**: `si_code = CLD_EXITED` (1) for normal exit or `CLD_KILLED` (2) for signal death. `si_pid` = child PID. `si_status` = exit code or killing signal.
- **kill()/tgkill()**: `si_code = SI_USER` (0). `si_pid` = sender PID (current process).
- **Other signals**: `si_code = 0`, rest zeroed.

`setup_signal_frame()` writes these at siginfo_t offsets: `si_code` at +4, `si_pid` at +12, `si_status` at +16.

### Linuxulator Changes

- New field: `pending_siginfo: Option<SigInfo>` (consumed alongside `pending_handler_signal`).
- `recover_child_state()`: When moving child to `exited_children` and queuing SIGCHLD, also store `SigInfo` with child's exit info.
- `queue_signal()`: Optionally accepts `SigInfo` (or a separate `queue_signal_with_info()` method).
- `deliver_pending_signals()`: When setting `pending_handler_signal`, also copies `pending_siginfo`.
- `setup_signal_frame()`: Add `siginfo: Option<&SigInfo>` parameter (existing `signum` and `regs` parameters unchanged). When `Some`, writes si_code/si_pid/si_status to siginfo_t. When `None`, only si_signo is written (preserving current behavior for non-SIGCHLD signals until their siginfo is wired up).

---

## Callback Interface

**Modified:** `SyscallDispatchResult` — two new `Option` fields (signal_setup, signal_return).

**New helpers:** `read_sp_el0()`, `write_sp_el0()` in syscall.rs.

**No new callbacks.** The existing `block_fn`/`spawn_fn`/`wake_fn` callbacks are unaffected. Signal delivery is purely within the dispatch → svc_handler path.

---

## IRQ Path and Scheduling

No changes to `vectors.rs`, `sched.rs`, or the timer IRQ path. Signals are delivered at syscall return boundaries only (inside `svc_handler`), not at IRQ return. This matches Linux's behavior for synchronous signal delivery.

Asynchronous signal delivery at IRQ return (e.g., SIGALRM from timer) is out of scope — tracked as future work if needed.

---

## Testing

### Linuxulator Tests (host-side, aarch64)

- **setup_signal_frame aarch64 layout**: Verify sigcontext has `regs[31]`/sp/pc/pstate at correct offsets. Verify FPSIMD_MAGIC header and vregs in `__reserved`. Verify restorer in setup's x30 field. Verify frame SP 16-byte aligned.
- **SigInfo population**: Verify `recover_child_state()` sets `pending_siginfo` with correct CLD_EXITED/CLD_KILLED, si_pid, si_status.
- **Signal delivery + return cycle**: Dispatch a kill signal with custom handler, verify `pending_handler_signal` set with correct siginfo, call `setup_signal_frame`, then simulate `rt_sigreturn` and verify registers restored.
- **rt_sigreturn unmasks pending signal**: Verify that when sigreturn restores a mask that unblocks a pending signal, `pending_handler_signal` is immediately set.
- **SA_ONSTACK on aarch64**: Verify alternate stack selection and on_alt_stack tracking.
- **SA_RESETHAND on aarch64**: Verify handler reset to SIG_DFL after delivery.

### x86_64 Tests Preserved

Existing `setup_signal_frame` tests stay behind `#[cfg(target_arch = "x86_64")]`. They continue passing on x86_64 hosts. No modifications.

### Out of Scope

- On-target integration testing (no test ELF modifications)
- SVE/SME register context (FPSIMD only)
- Real-time signals (32-64)
- Process groups / session signals
- Asynchronous signal delivery at IRQ return
- signalfd integration testing (likely already works via pending_signals bitmask)
- SIGCHLD from concurrent fork (requires PID namespace work)
- Multi-core races (single-core safe via IRQ masking)
