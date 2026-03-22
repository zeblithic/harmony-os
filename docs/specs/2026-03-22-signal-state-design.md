# Signal State + rt_sigaction + rt_sigprocmask (harmony-os-5qu, part 1)

Store per-process signal handlers and blocked signal mask. Replace
the current no-op stubs with real state tracking. Foundation for
signal delivery (harmony-os-89m) and sigreturn (harmony-os-mtk).

## Context

The Linuxulator currently stubs rt_sigaction and rt_sigprocmask as
no-ops that return 0. NixOS binaries need real signal state:

- **bash** registers SIGCHLD handlers for job control, checks
  handler disposition via sigaction(sig, NULL, &oldact)
- **systemd** sets up signal masks and handlers during init
- **musl** calls rt_sigprocmask during thread setup

Without real state, programs that read back their signal configuration
get zeros, and the signal delivery bead (89m) has no handler table
to consult when deciding whether to invoke a handler, ignore, or
apply the default action.

## Design

### SignalAction Struct

```rust
#[derive(Clone, Copy)]
struct SignalAction {
    /// SIG_DFL (0), SIG_IGN (1), or handler function pointer.
    handler: u64,
    /// Signals to block during handler execution.
    mask: u64,
    /// Flags: SA_RESTART, SA_SIGINFO, SA_NOCLDSTOP, etc.
    /// Stored as u64 to match the kernel struct layout (sa_flags is
    /// unsigned long on both x86_64 and aarch64).
    flags: u64,
}
```

### New Linuxulator Fields

```rust
    /// Per-signal handler disposition (signals 1-64, index 0 = signal 1).
    signal_handlers: [SignalAction; 64],
    /// Blocked signal mask (bit N = signal N+1 is blocked).
    signal_mask: u64,
```

Initialized: all handlers `SIG_DFL` (zeros), mask 0 (nothing blocked).

### sys_rt_sigaction(signum, act_ptr, oldact_ptr, sigsetsize)

1. Validate `sigsetsize == 8` (Linux requires this for 64-signal sets).
   Return EINVAL otherwise.
2. Validate signum is 1-64. Return EINVAL if out of range.
3. Reject SIGKILL (9) and SIGSTOP (19) — return EINVAL.
4. If `oldact_ptr != 0`: write current SignalAction to user memory
   using the platform-specific `struct sigaction` layout.
5. If `act_ptr != 0`: read new SignalAction from user memory, store
   in `signal_handlers[signum - 1]`.
6. Return 0.

### Linux struct sigaction Layout

**x86_64** (32 bytes):
```
offset 0:  u64 sa_handler
offset 8:  u64 sa_flags     (stored as u64, only low 32 bits meaningful)
offset 16: u64 sa_restorer   (read: ignored; write: output 0)
offset 24: u64 sa_mask
```

**aarch64** (24 bytes):
```
offset 0:  u64 sa_handler
offset 8:  u64 sa_flags
offset 16: u64 sa_mask
```

Note: Linux's kernel-level `struct sigaction` (used by rt_sigaction)
differs from the libc-level `struct sigaction`. The kernel struct
uses `unsigned long` for all fields and has sa_restorer on x86_64.

### sys_rt_sigprocmask(how, set_ptr, oldset_ptr, sigsetsize)

1. Validate `sigsetsize == 8`. Return EINVAL otherwise.
2. If `oldset_ptr != 0`: write current `signal_mask` as u64 LE.
3. If `set_ptr != 0`: read u64 LE from user memory, apply:
   - `SIG_BLOCK` (0): `signal_mask |= set`
   - `SIG_UNBLOCK` (1): `signal_mask &= !set`
   - `SIG_SETMASK` (2): `signal_mask = set`
   - Other `how` values: return EINVAL
4. Enforce SIGKILL/SIGSTOP unblockable:
   `signal_mask &= !(1 << 8 | 1 << 18)` (bits for signals 9 and 19).
   Enforcement applies only to the new mask, not to the value written
   to `oldset` in step 2 (which reflects whatever was stored).
5. Return 0.

Pointer validation follows the existing direct-dereference pattern
(same as prlimit64, fstat, pipe2, etc.). All addresses in the flat
arena address space are valid. Null pointers are handled by the
explicit `!= 0` checks.

### LinuxSyscall Changes

Add fields to existing variants (currently fieldless):

```rust
RtSigaction {
    signum: i32,
    act: u64,
    oldact: u64,
    sigsetsize: u64,
},
RtSigprocmask {
    how: i32,
    set: u64,
    oldset: u64,
    sigsetsize: u64,
},
```

Update x86_64 and aarch64 syscall table mappings to pass arguments.
Syscall numbers unchanged (x86_64: 13/14, aarch64: 134/135).

### Fork/Execve Integration

**Fork (create_child):**
- `signal_handlers`: cloned from parent (child inherits handlers)
- `signal_mask`: copied from parent (child inherits blocked mask)

**Execve (reset_for_execve):**
- `signal_handlers`: all reset to SIG_DFL (Linux resets on exec)
- `signal_mask`: preserved (Linux preserves mask across exec)

### Constants

```rust
const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const SIGKILL: u32 = 9;
const SIGSTOP: u32 = 19;
const SIG_BLOCK: i32 = 0;
const SIG_UNBLOCK: i32 = 1;
const SIG_SETMASK: i32 = 2;
```

## File Changes

All changes in `crates/harmony-os/src/linuxulator.rs`:

- SignalAction struct: new
- Linuxulator struct: +signal_handlers, +signal_mask fields
- with_arena: initialize signal state
- create_child: clone signal_handlers, copy signal_mask
- reset_for_execve: reset handlers to SIG_DFL, preserve mask
- LinuxSyscall::RtSigaction: add fields
- LinuxSyscall::RtSigprocmask: add fields
- x86_64 table: update nr 13/14 to pass args
- aarch64 table: update nr 134/135 to pass args
- dispatch_syscall: update match arms to pass fields
- sys_rt_sigaction: replace stub with real implementation
- sys_rt_sigprocmask: replace stub with real implementation
- Signal constants: SIG_DFL, SIG_IGN, SIGKILL, SIGSTOP, etc.

## Test Plan

| Test | Behavior verified |
|------|-------------------|
| test_sigaction_set_and_get | Set handler for SIGUSR1 (10), read back via oldact |
| test_sigaction_reject_sigkill | sigaction(SIGKILL) → EINVAL |
| test_sigaction_reject_sigstop | sigaction(SIGSTOP) → EINVAL |
| test_sigaction_null_act_reads_only | act=null reads current handler without modifying |
| test_sigprocmask_block | SIG_BLOCK ORs bits into mask |
| test_sigprocmask_unblock | SIG_UNBLOCK clears bits from mask |
| test_sigprocmask_setmask | SIG_SETMASK replaces mask entirely |
| test_sigprocmask_cannot_block_sigkill | SIGKILL/SIGSTOP bits cleared after any operation |
| test_sigaction_bad_sigsetsize | sigsetsize != 8 → EINVAL |
| test_sigprocmask_bad_sigsetsize | sigsetsize != 8 → EINVAL |
| test_sigprocmask_invalid_how | how=99 → EINVAL |
| test_sigaction_invalid_signum | signum 0, 65, -1 → EINVAL |
| test_fork_inherits_signal_state | Set handler + mask, fork, child has same state |
| test_execve_resets_handlers_preserves_mask | Set handler + mask, execve, handlers reset but mask preserved |

Tests use stack-allocated buffers for pointer arguments, following
the existing pattern (e.g., `sys_prlimit64_writes_stack_limit`).

## Dependencies

| Bead | Relationship |
|------|-------------|
| harmony-os-89m | Blocked by this — signal delivery needs handler table |
| harmony-os-mtk | Blocked by 89m — sigreturn needs delivery |
