# rt_sigreturn + sigaltstack — Signal Handler Context Save/Restore (harmony-os-mtk)

Signal frame construction, handler invocation, and register restore
via rt_sigreturn. Completes the signal subsystem: signal state (5qu)
→ signal delivery (89m) → signalfd (jo0) → sigreturn (this bead).

## Context

The signal delivery bead (89m) introduced `pending_handler_signal`,
which tells the caller "signal N has a custom handler." But the caller
has no way to actually invoke the handler — it needs to:

1. Save current register state
2. Build a signal frame on the user stack
3. Set RIP to handler, set args (signum, siginfo, ucontext)
4. After handler returns via rt_sigreturn, restore registers

Without this, programs using custom signal handlers (bash SIGCHLD for
job control, musl internals) cannot function. systemd uses signalfd
instead of handlers, so this is primarily needed for bash and musl.

## Design

### Caller-Facing API

Two new public structs:

```rust
/// Register state the caller provides for signal frame construction.
pub struct SavedRegisters {
    pub r8: u64, pub r9: u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rdi: u64, pub rsi: u64, pub rbp: u64, pub rbx: u64,
    pub rdx: u64, pub rax: u64, pub rcx: u64, pub rsp: u64,
    pub rip: u64, pub eflags: u64,
}

/// Returned by setup_signal_frame — tells caller where to jump.
pub struct SignalHandlerSetup {
    pub handler_rip: u64,   // handler address
    pub handler_rsp: u64,   // top of signal frame (new RSP)
    pub rdi: u64,           // arg1 = signum
    pub rsi: u64,           // arg2 = &siginfo (SA_SIGINFO) or 0
    pub rdx: u64,           // arg3 = &ucontext (SA_SIGINFO) or 0
}

/// Returned by pending_signal_return — restored register state.
pub struct SignalReturn {
    pub regs: SavedRegisters,
}
```

Two new public methods:

```rust
/// Build signal frame on user stack. Called by caller after
/// pending_handler_signal() returns Some(signum).
/// Panics (debug_assert) if the handler lacks SA_RESTORER — modern
/// Linux requires it on x86_64, and both musl and glibc always set it.
pub fn setup_signal_frame(
    &mut self, signum: u32, regs: &SavedRegisters,
) -> SignalHandlerSetup

/// Consume pending signal return (set by rt_sigreturn).
pub fn pending_signal_return(&mut self) -> Option<SignalReturn>
```

### Two-Phase Signal Handler Flow

1. `dispatch_syscall()` → `deliver_pending_signals()` sets
   `pending_handler_signal = Some(signum)`
2. Caller checks `pending_handler_signal()` → `Some(10)`
3. Caller calls `setup_signal_frame(10, &current_regs)` →
   gets `SignalHandlerSetup`
4. Caller sets RIP/RSP/RDI/RSI/RDX, runs handler
5. Handler returns via sa_restorer trampoline → `rt_sigreturn` syscall
6. Linuxulator reads frame, restores signal_mask, sets
   `pending_signal_return`
7. Caller checks `pending_signal_return()` → restores registers

This matches the existing `pending_fork_child` / `pending_execve`
caller-communication pattern.

### Signal Frame Layout (x86_64)

The Linuxulator builds an `rt_sigframe` on the user stack (or
alternate stack if SA_ONSTACK):

```
High addresses (original RSP or alt stack top)
┌─────────────────────────────┐
│ sa_restorer return address  │  8 bytes (frame top)
├─────────────────────────────┤
│ struct siginfo_t            │  128 bytes (si_signo set, rest zeroed)
├─────────────────────────────┤
│ struct ucontext_t:          │
│   uc_flags      (u64)      │  0
│   uc_link       (u64)      │  0 (NULL)
│   uc_stack      (24 bytes) │  ss_sp, ss_flags, ss_size
│   struct sigcontext:        │
│     r8..r15     (8 × u64)  │  saved GPRs
│     rdi,rsi,rbp,rbx (4×u64)│
│     rdx,rax,rcx,rsp (4×u64)│
│     rip,eflags  (2 × u64)  │
│     cs,gs,fs,ss (zeroed)   │  4 × u16 + padding to u64
│     err,trapno  (zeroed)   │  2 × u64
│     oldmask     (u64)      │  saved signal_mask
│     cr2,fpstate (zeroed)   │  2 × u64 (fpstate = NULL)
│   uc_sigmask    (u64)      │  saved signal_mask
└─────────────────────────────┘
  ← 16-byte aligned, then -8 for retaddr = handler_rsp
```

- **sa_restorer**: placed as return address at frame top. When handler
  does `ret`, jumps to sa_restorer (musl/glibc `__restore_rt`:
  `mov $15,%rax; syscall`). If SA_RESTORER not set in flags, the
  Linuxulator panics via debug_assert — modern Linux requires
  SA_RESTORER on x86_64, and both musl and glibc always set it.
- **siginfo_t**: 128 bytes, only `si_signo` (u32 at offset 0) filled.
- **sigcontext GPR order**: matches Linux exactly for SA_SIGINFO
  handler compatibility.
- **fpstate = NULL**: no FP save area. Valid per Linux (NULL means
  default FP state).
- **RSP alignment**: frame base 16-byte aligned, minus 8 for return
  address, so RSP is 16n+8 when handler's prologue pushes rbp →
  16-aligned. This matches the x86_64 ABI call convention.

Total frame size: ~456 bytes, padded to 16-byte alignment.

### Signal Mask Management During Handler

**setup_signal_frame:**
1. Save current `signal_mask` into frame's `uc_sigmask`
2. Apply: `signal_mask |= action.mask | (1 << (signum - 1))`
3. If `SA_NODEFER`: don't add the signal itself to the mask
4. Enforce SIGKILL/SIGSTOP unblockable

**rt_sigreturn (sys_rt_sigreturn):**
1. Read `uc_sigmask` from frame
2. Restore: `signal_mask = saved_mask`
3. Enforce SIGKILL/SIGSTOP unblockable
4. `deliver_pending_signals()` runs at end of dispatch_syscall —
   now-unblocked signals fire

**SA_RESETHAND:** If set, reset handler to SIG_DFL in
`setup_signal_frame` after saving the action.

**SA_RESTART:** Stored in flags but not acted on by Linuxulator —
caller decides whether to restart interrupted syscall.

### rt_sigreturn Syscall

`rt_sigreturn` (x86_64: nr 15, aarch64: nr 139).

```rust
LinuxSyscall::RtSigreturn { rsp: u64 }
```

The caller passes current RSP so the Linuxulator can locate the
frame. This differs from normal syscalls — the kernel reads the
frame from the stack, not from register arguments.

`sys_rt_sigreturn(rsp)`:
1. Compute frame base from RSP (frame starts at known offset)
2. Read sigcontext GPRs → build `SavedRegisters`
3. Read `uc_sigmask` → restore `signal_mask`
4. Set `pending_signal_return = Some(SignalReturn { regs })`
5. Return value ignored — caller uses `pending_signal_return()`

After rt_sigreturn, `deliver_pending_signals()` runs as usual. If a
new signal fires, the caller handles both `pending_signal_return`
AND `pending_handler_signal` in sequence (restore first, then set
up new handler).

### sigaltstack Syscall

`sigaltstack` (x86_64: nr 131, aarch64: nr 132).

New Linuxulator fields:

```rust
alt_stack_sp: u64,      // ss_sp
alt_stack_size: u64,    // ss_size
alt_stack_flags: i32,   // SS_DISABLE (2) or 0
on_alt_stack: bool,     // currently executing on alt stack
```

Initialized: sp=0, size=0, flags=SS_DISABLE, on_alt_stack=false.

`sys_sigaltstack(ss_ptr, old_ss_ptr)`:
1. If `old_ss_ptr != 0`: write current config as `struct stack_t`
   (24 bytes). If `on_alt_stack`, OR in SS_ONSTACK to flags.
2. If `ss_ptr != 0`:
   - If `on_alt_stack`: return EPERM
   - Read `struct stack_t` from user memory
   - Unknown flags (not SS_DISABLE | SS_AUTODISARM): EINVAL
   - SS_DISABLE: clear config (sp=0, size=0, flags=SS_DISABLE)
   - Else: validate `ss_size >= MINSIGSTKSZ` (2048), ENOMEM if
     too small. Store sp/size/flags.
3. Return 0.

**Integration with setup_signal_frame:**
- If handler has SA_ONSTACK AND alt stack configured (not SS_DISABLE)
  AND not already on_alt_stack:
  - Place frame on alt stack: `frame_rsp = alt_stack_sp + alt_stack_size`
  - Set `on_alt_stack = true`
- Otherwise: place frame on main stack (current RSP)

**rt_sigreturn clears on_alt_stack:**
- `on_alt_stack = false` (returning to interrupted context)

### Fork/Execve Integration

**Fork (create_child):**
- Alt stack fields cloned from parent
- `on_alt_stack = false` for child
- `pending_signal_return = None`

**Execve (reset_for_execve):**
- Alt stack reset: sp=0, size=0, flags=SS_DISABLE
- `on_alt_stack = false`
- `pending_signal_return = None`

### Syscall Numbers

| Syscall | x86_64 | aarch64 |
|---------|--------|---------|
| rt_sigreturn | 15 | 139 |
| sigaltstack | 131 | 132 |

### Constants

```rust
const SS_ONSTACK: i32 = 1;
const SS_DISABLE: i32 = 2;
const SS_AUTODISARM: i32 = 1 << 31;
const MINSIGSTKSZ: u64 = 2048;
const SA_NOCLDSTOP: u64 = 1;
const SA_NOCLDWAIT: u64 = 2;
const SA_SIGINFO: u64 = 4;
const SA_ONSTACK: u64 = 0x08000000;
const SA_RESTART: u64 = 0x10000000;
const SA_NODEFER: u64 = 0x40000000;
const SA_RESETHAND: u64 = 0x80000000;
const SA_RESTORER: u64 = 0x04000000;
```

## File Changes

All in `crates/harmony-os/src/linuxulator.rs`:

- SavedRegisters struct: new (pub)
- SignalHandlerSetup struct: new (pub)
- SignalReturn struct: new (pub)
- Linuxulator: +alt_stack_sp, +alt_stack_size, +alt_stack_flags,
  +on_alt_stack, +pending_signal_return
- with_arena: initialize new fields
- create_child: clone alt stack, clear on_alt_stack/pending_signal_return
- reset_for_execve: reset alt stack, clear on_alt_stack/pending_signal_return
- setup_signal_frame: new public method
- pending_signal_return: new public method
- sys_rt_sigreturn: new handler
- sys_sigaltstack: new handler
- LinuxSyscall: +RtSigreturn, +Sigaltstack variants
- Syscall tables: +2 entries per arch
- dispatch_syscall: +2 arms
- SA_* / SS_* constants: new

## Test Plan

| Test | Behavior verified |
|------|-------------------|
| test_setup_signal_frame_basic | Custom handler + kill → setup_signal_frame writes frame, returns correct handler_rip/rsp |
| test_sigreturn_restores_registers | Setup frame → rt_sigreturn → pending_signal_return has original registers |
| test_sigreturn_restores_signal_mask | Handler mask applied during setup, original mask restored by sigreturn |
| test_signal_mask_blocks_during_handler | sa_mask ORed in + signal itself blocked during handler execution |
| test_sa_siginfo_three_arg | SA_SIGINFO handler gets siginfo/ucontext pointers in rsi/rdx |
| test_sa_resethand | Handler with SA_RESETHAND resets to SIG_DFL after delivery |
| test_sa_nodefer | SA_NODEFER: signal not auto-blocked during handler |
| test_sigreturn_delivers_unblocked | Signal pending during handler, unblocked by sigreturn → delivered |
| test_sigaltstack_set_and_get | Configure alt stack, read back via old_ss |
| test_sigaltstack_onstack | SA_ONSTACK handler + configured alt stack → frame placed on alt stack |
| test_sigaltstack_disable | SS_DISABLE clears alt stack config |
| test_sigaltstack_eperm_on_altstack | Can't reconfigure while on_alt_stack → EPERM |
| test_sigaltstack_too_small | ss_size < MINSIGSTKSZ → ENOMEM |
| test_sigreturn_clears_on_alt_stack | After sigreturn from alt stack handler, on_alt_stack = false |
| test_fork_inherits_alt_stack | Fork copies alt stack config |
| test_execve_resets_alt_stack | Execve clears alt stack to SS_DISABLE |
| test_restorer_as_return_addr | sa_restorer placed at frame top as return address |
| test_frame_rsp_alignment | handler_rsp is 16-byte aligned at function entry |

## Dependencies

| Bead | Relationship |
|------|-------------|
| harmony-os-5qu | Prerequisite (closed) — signal state |
| harmony-os-89m | Prerequisite (closed) — signal delivery |
| harmony-os-jo0 | Prerequisite (closed) — signalfd |
