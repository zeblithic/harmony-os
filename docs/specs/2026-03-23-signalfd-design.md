# signalfd/signalfd4 — Signal Multiplexing (harmony-os-jo0)

File descriptor for reading pending signals as structs. systemd's
entire signal dispatch goes through signalfd instead of handlers.

## Context

systemd does not use rt_sigaction handlers for signal delivery.
Instead it creates a signalfd, blocks all signals via sigprocmask,
and reads `struct signalfd_siginfo` from the fd in its main epoll
loop. Without signalfd, systemd cannot receive SIGCHLD, SIGTERM,
or SIGHUP.

## Design

### signalfd4 Syscall

`signalfd4(fd, mask_ptr, sizemask, flags)`:

- `fd == -1`: create a new signalfd monitoring `mask`. Return new fd.
- `fd >= 0`: update existing signalfd's mask. Return `fd`.
- `mask_ptr`: pointer to u64 signal bitmask (which signals to monitor)
- `flags`: `SFD_CLOEXEC` (0x80000) and `SFD_NONBLOCK` (0x800) accepted.
  Unknown flags → EINVAL.

`signalfd` (old API) is `signalfd4` with `flags = 0`.

### FdKind::SignalFd

New variant:

```rust
FdKind::SignalFd { signalfd_id: usize }
```

Shared state:

```rust
struct SignalFdState {
    mask: u64,  // which signals this fd monitors
}
```

New Linuxulator fields:

```rust
    signalfds: BTreeMap<usize, SignalFdState>,
    next_signalfd_id: usize,
```

### Reading from a signalfd

`sys_read` on `FdKind::SignalFd`:

1. Find deliverable: `self.pending_signals & sigstate.mask`
   (No `!signal_mask` filter — signalfd reads blocked signals.)
2. If none: return EAGAIN.
3. Take lowest set bit → signum. Clear from `pending_signals`.
4. Write `struct signalfd_siginfo` (128 bytes) to user buffer.
   Only `ssi_signo` (u32 at offset 0) is set; rest zeroed.
5. Return 128 (bytes read).

Count must be >= 128 (sizeof signalfd_siginfo). If count < 128,
return EINVAL.

### struct signalfd_siginfo

128 bytes. Key fields:

```
offset 0:  u32 ssi_signo   — signal number
offset 4:  i32 ssi_errno   — 0
offset 8:  i32 ssi_code    — 0
offset 12: u32 ssi_pid     — 0
offset 16: u32 ssi_uid     — 0
offset 20: i32 ssi_fd      — 0
offset 24: u32 ssi_tid     — 0
...
offset 124: padding to 128 bytes
```

All fields zeroed except `ssi_signo`. Sufficient for systemd which
primarily dispatches on the signal number.

### Interaction with signal delivery

Signals consumed via signalfd `read()` are removed from
`pending_signals`. They are NOT delivered via `deliver_pending_signals`
because they're blocked (sigprocmask) and signalfd provides the
consumption path.

If a signal is both pending and matches a signalfd's mask, reading
the signalfd consumes it. If the signal is later unblocked (without
being consumed by signalfd), `deliver_pending_signals` handles it
normally.

### close_fd_entry

`FdKind::SignalFd` cleanup follows the existing pattern: scan
fd_table for remaining references, remove state when last fd closes.

### Fork/Execve

- **Fork**: signalfd state cloned (child inherits signalfds).
  `signalfds` map and `next_signalfd_id` cloned.
- **Execve**: FD_CLOEXEC signalfds closed. Non-CLOEXEC survive.
  Signalfd state for surviving fds preserved.

### Syscall Numbers

| Syscall | x86_64 | aarch64 |
|---------|--------|---------|
| signalfd | 282 | -- |
| signalfd4 | 289 | 74 |

aarch64 has no separate `signalfd` — only `signalfd4` at nr 74.

### Constants

```rust
const SFD_CLOEXEC: i32 = 0x80000;
const SFD_NONBLOCK: i32 = 0x800;
```

## File Changes

All in `crates/harmony-os/src/linuxulator.rs`:

- SignalFdState struct: new
- FdKind::SignalFd variant: new
- Linuxulator: +signalfds, +next_signalfd_id
- with_arena: initialize
- create_child: clone signalfds
- close_fd_entry: +SignalFd arm
- sys_read: +SignalFd arm (consume signal, write siginfo)
- sys_write: +SignalFd arm (return EINVAL)
- sys_fstat: +SignalFd arm (S_IFREG)
- sys_signalfd4: new handler
- LinuxSyscall: +SignalFd, +SignalFd4 variants
- Syscall tables + dispatch arms

## Test Plan

| Test | Behavior verified |
|------|-------------------|
| test_signalfd_create | signalfd4(-1, mask, 0) returns valid fd |
| test_signalfd_read_pending | Block + queue signal, read → correct ssi_signo |
| test_signalfd_no_pending_eagain | No pending → EAGAIN |
| test_signalfd_consumes_signal | After read, signal no longer pending |
| test_signalfd_update_mask | signalfd4(fd, new_mask, 0) updates mask |
| test_signalfd_cloexec | SFD_CLOEXEC sets FD_CLOEXEC |

## Dependencies

| Bead | Relationship |
|------|-------------|
| harmony-os-5qu | Prerequisite (closed) — signal state |
| harmony-os-89m | Prerequisite (closed) — signal delivery |
