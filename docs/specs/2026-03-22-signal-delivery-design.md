# Signal Delivery — kill/tgkill + Syscall Boundary Delivery (harmony-os-89m)

Queue signals to processes via kill/tgkill, deliver pending signals
at syscall boundaries. SIG_DFL and SIG_IGN handled internally;
custom handlers reported to caller for future invocation.

## Context

Signal state (rt_sigaction/rt_sigprocmask) shipped in PR #48. The
handler table and blocked mask exist but no signals are ever queued
or delivered. NixOS boot needs:

- **SIGCHLD** auto-delivered to parent when child exits (systemd
  service lifecycle, bash job control)
- **SIGTERM/SIGINT** for process termination (systemctl stop, ^C)
- **kill(2)** for inter-process signaling

## Design

### Pending Signals Bitmask

New Linuxulator field:

```rust
    /// Pending signal bitmask (bit N = signal N+1 is pending).
    pending_signals: u64,
```

Standard signals (1-31): one-pending-per-signal (duplicates merged
into the bitmask). Matches Linux behavior. Real-time signal queuing
(32-64) deferred.

### Signal Delivery at Syscall Boundaries

`dispatch_syscall` calls `deliver_pending_signals()` after the
syscall match arm produces its result but before returning the i64.
The syscall result is returned regardless — the caller checks
`exited()` and `pending_handler_signal()` separately. Signal
delivery happens on the process that executed the syscall (the
deepest active child via `active_process()`).

This private method:

1. Compute deliverable: `pending_signals & !signal_mask`
2. If none: return
3. Find lowest set bit → signum
4. Clear the bit: `pending_signals &= !(1 << (signum-1))`
5. Look up handler disposition:
   - `SIG_IGN` → discard
   - `SIG_DFL` → apply default action (terminate or ignore)
   - Custom handler → set `pending_handler_signal` for caller

Only one signal is delivered per syscall return (lowest numbered
first). Multiple pending signals are delivered across subsequent
syscall returns.

### Default Signal Actions

| Action | Signals |
|--------|---------|
| Terminate | 1 (HUP), 2 (INT), 3 (QUIT), 4 (ILL), 6 (ABRT), 8 (FPE), 9 (KILL), 10 (USR1), 11 (SEGV), 12 (USR2), 13 (PIPE), 14 (ALRM), 15 (TERM), 16 (STKFLT), 26 (VTALRM), 27 (PROF), 29 (IO), 30 (PWR), 31 (SYS) |
| Ignore | 17 (CHLD), 18 (CONT), 23 (URG), 28 (WINCH) |
| Stop | 19 (STOP), 20 (TSTP), 21 (TTIN), 22 (TTOU) — treated as ignore (stop not supported) |

Real-time signals (32-64) default to terminate.

Terminate action: signal-killed processes need distinct encoding
from normal exits so `waitpid` WIFEXITED/WIFSIGNALED macros work.

New field to distinguish signal death from normal exit:

```rust
    /// If set, process was killed by this signal (for wstatus encoding).
    killed_by_signal: Option<u32>,
```

On signal terminate: `self.exit_code = Some(0)` and
`self.killed_by_signal = Some(signum)`.

In `wait4` wstatus encoding:
- Normal exit (killed_by_signal is None): `(exit_code & 0xFF) << 8`
- Signal kill (killed_by_signal is Some): `signum & 0x7F`
  (signal number in low 7 bits, no shift)

`recover_child_state` propagates `killed_by_signal` to
`exited_children` alongside the exit code.

SIGKILL (9) and SIGSTOP (19) special: always delivered regardless
of handler or mask. `deliver_pending_signals` checks for these
before applying the mask filter. SIGSTOP is treated as ignore
(stop not supported), but SIGKILL always terminates.

### Custom Handler Communication

For handlers that are neither SIG_DFL nor SIG_IGN, the Linuxulator
can't invoke them (sans-I/O — doesn't control the CPU). Instead:

```rust
    /// Signal with custom handler pending for caller invocation.
    pending_handler_signal: Option<u32>,
```

```rust
pub fn pending_handler_signal(&mut self) -> Option<u32> {
    self.pending_handler_signal.take()
}
```

The caller checks this after `dispatch_syscall` (same pattern as
`pending_fork_child`, `pending_execve`). For this bead, this is
just the communication mechanism — actual handler frame setup is
the sigreturn bead (harmony-os-mtk).

### SIGCHLD Auto-Delivery on Child Exit

When `recover_child_state` pops an exited child, it auto-queues
SIGCHLD to the parent:

```rust
self.pending_signals |= 1 << (SIGCHLD_NUM - 1);
```

This is the only auto-generated signal. All others come from
explicit `kill`/`tgkill` calls.

### kill Syscall

`sys_kill(pid, sig)`:

- `sig == 0`: null signal — check process exists, don't send
- `sig < 0 || sig > 64`: return EINVAL
- `pid == self.pid` or `pid == 0`: queue on self
- `pid` not found: return ESRCH
- `pid == -1` or `pid < -1`: return ENOSYS (process group not supported)

**Reachability in the sequential model:** The only process that
calls syscalls is the deepest active process (via `active_process()`).
A child cannot reach its parent. A parent cannot reach its child
while the child is active (the parent is suspended). So in practice,
`kill` only targets `self.pid` or returns ESRCH. When a parent
resumes after a child exits, it could kill another child that
doesn't exist yet. Cross-process kill within the tree is deferred
— for now, only self-signaling works. ESRCH for unknown PIDs.

Queue operation: `target.pending_signals |= 1 << (sig - 1)`

### tgkill Syscall

`sys_tgkill(tgid, tid, sig)`:

Single-threaded model: `tgid` and `tid` must both match a known
process PID. Otherwise ESRCH. Same signal queuing as kill.

`tid == 0`: EINVAL (Linux requires tid > 0 for tgkill).

### Fork/Execve Integration

- **Fork (create_child):** `pending_signals = 0` for child (Linux
  clears pending on fork). `pending_handler_signal = None`.
- **Execve (reset_for_execve):** `pending_signals` preserved
  (Linux preserves pending signals across exec). `pending_handler_signal = None`.

### Syscall Numbers

| Syscall | x86_64 | aarch64 |
|---------|--------|---------|
| kill | 62 | 129 |
| tgkill | 234 | 131 |

### Error Constants

```rust
const ESRCH: i64 = -3;  // already exists
```

No new errno constants needed — ESRCH, EINVAL, ENOSYS already exist.

## File Changes

All changes in `crates/harmony-os/src/linuxulator.rs`:

- Linuxulator struct: +pending_signals, +pending_handler_signal, +killed_by_signal fields
- with_arena: initialize both to 0/None
- create_child: pending_signals=0, pending_handler_signal=None
- reset_for_execve: clear pending_handler_signal (pending_signals preserved per Linux)
- recover_child_state: auto-queue SIGCHLD
- deliver_pending_signals: new private method
- default_signal_action: new private helper
- dispatch_syscall: call deliver_pending_signals before return
- sys_kill: new handler
- sys_tgkill: new handler
- LinuxSyscall::Kill variant: new
- LinuxSyscall::Tgkill variant: new
- x86_64 table: +2 entries (62, 234)
- aarch64 table: +2 entries (129, 131)
- dispatch_syscall: +2 arms
- SIGCHLD_NUM constant: new (consolidate with SIGCHLD in sys_clone — use one shared constant)
- wait4 wstatus: update to handle killed_by_signal encoding
- exited_children: expand from (pid, exit_code) to (pid, exit_code, Option<u32> killed_by_signal)

## Test Plan

| Test | Behavior verified |
|------|-------------------|
| test_kill_self_terminate | kill(self, SIGUSR1) with SIG_DFL → exit_code set |
| test_kill_sigchld_default_ignored | kill(self, SIGCHLD) with SIG_DFL → no effect |
| test_kill_sig_ign | Set SIG_IGN, kill → no effect |
| test_kill_blocked_stays_pending | Block signal, kill → pending; unblock → delivered |
| test_kill_invalid_sig | kill(pid, 65) → EINVAL |
| test_kill_null_signal | kill(pid, 0) → 0 |
| test_kill_no_such_process | kill(999, sig) → ESRCH |
| test_tgkill_self | tgkill(pid, pid, SIGUSR1) → terminate |
| test_sigchld_on_child_exit | Fork → child exits → parent SIGCHLD pending |
| test_kill_custom_handler_reported | Custom handler + kill → pending_handler_signal |
| test_sigkill_bypasses_mask | Block all signals, kill(self, SIGKILL) → still terminates |
| test_kill_process_group_enosys | kill(-1, sig) and kill(-2, sig) → ENOSYS |
| test_fork_clears_pending_signals | Queue signal, fork, child has no pending signals |

## Dependencies

| Bead | Relationship |
|------|-------------|
| harmony-os-5qu | Prerequisite (closed) — signal state |
| harmony-os-mtk | Blocked by this — sigreturn needs delivery |
