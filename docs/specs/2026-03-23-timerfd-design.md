# timerfd — Timer File Descriptors for systemd (harmony-os-bdy)

File descriptor that fires when a timer expires. systemd uses timerfd
for all scheduling — timer units, watchdog, service timeouts.

## Context

systemd's main event loop uses three fd types: epoll (event mux),
signalfd (signal delivery), and timerfd (timer scheduling). With
signalfd shipped in PR #52, timerfd is the remaining piece.

## Design

### timerfd_create(clockid, flags)

Creates a new timer fd. Returns the fd number.

- `clockid`: CLOCK_MONOTONIC (1) or CLOCK_REALTIME (0). Other → EINVAL.
- `flags`: TFD_CLOEXEC (0x80000) and TFD_NONBLOCK (0x800).
  Unknown flags → EINVAL.

### timerfd_settime(fd, flags, new_value_ptr, old_value_ptr)

Arms or disarms a timer.

- `fd`: must be a TimerFd. Otherwise EINVAL.
- `flags`: TFD_TIMER_ABSTIME (1) — `it_value` is absolute time.
  Without flag, `it_value` is relative (added to current clock).
  Unknown flags → EINVAL.
- `new_value_ptr`: pointer to `struct itimerspec`:
  ```
  struct itimerspec {
      it_interval: timespec,  // repeat interval (0,0 = one-shot)
      it_value: timespec,     // first expiration (0,0 = disarm)
  }
  ```
  Each `timespec` is `{ tv_sec: i64, tv_nsec: i64 }` = 16 bytes.
  Total `itimerspec` = 32 bytes.
- `old_value_ptr`: if non-null, write the previous timer value.
  For now: write zeros (previous value tracking deferred).

`it_value == (0,0)` disarms the timer.

### timerfd_gettime(fd, curr_value_ptr)

Reads the current timer setting. Writes a `struct itimerspec` with:
- `it_value`: time remaining until next expiration (0,0 if disarmed)
- `it_interval`: the repeat interval

### FdKind::TimerFd

```rust
FdKind::TimerFd { timerfd_id: usize }
```

### TimerFdState

```rust
struct TimerFdState {
    clockid: i32,
    /// Absolute expiration time in nanoseconds (0 = disarmed).
    expiration_ns: u64,
    /// Repeat interval in nanoseconds (0 = one-shot).
    interval_ns: u64,
}
```

### Reading from a timerfd

`sys_read` on `FdKind::TimerFd`:

1. Count must be >= 8. If < 8: EINVAL.
2. If `expiration_ns == 0`: disarmed → EAGAIN.
3. Get current clock based on `clockid`.
4. If `current_ns < expiration_ns`: not expired → EAGAIN.
5. Compute expiration count:
   - One-shot (`interval_ns == 0`): count = 1, disarm (expiration = 0).
   - Repeating: count = 1 + (current_ns - expiration_ns) / interval_ns.
     Advance `expiration_ns` past current time.
6. Write u64 count (LE) to user buffer. Return 8.

### Sans-I/O Timer Model

The timer "fires" when the associated clock has advanced past
`expiration_ns`. Clocks advance via `clock_gettime`, `nanosleep`,
and `clock_nanosleep`. The expiration check happens lazily on
`read()`. In the always-ready epoll model, timerfd is always
"ready" — the actual check is on read.

### Fork/Execve

- **Fork**: timerfd state cloned.
- **Execve**: FD_CLOEXEC timerfds closed. Surviving ones preserved.

### Syscall Numbers

| Syscall | x86_64 | aarch64 |
|---------|--------|---------|
| timerfd_create | 283 | 85 |
| timerfd_settime | 286 | 86 |
| timerfd_gettime | 287 | 87 |

### Constants

```rust
const TFD_CLOEXEC: i32 = 0x80000;
const TFD_NONBLOCK: i32 = 0x800;
const TFD_TIMER_ABSTIME: i32 = 1;
```

## File Changes

All in `crates/harmony-os/src/linuxulator.rs`:

- TimerFdState struct: new
- FdKind::TimerFd variant: new
- Linuxulator: +timerfds, +next_timerfd_id
- with_arena + create_child: initialize/clone
- close_fd_entry: +TimerFd arm
- sys_read: +TimerFd arm (expiration check, count, consume)
- sys_write: +TimerFd arm (EINVAL)
- sys_fstat: +TimerFd arm
- sys_timerfd_create: new handler
- sys_timerfd_settime: new handler
- sys_timerfd_gettime: new handler
- LinuxSyscall: +3 variants
- Syscall tables + dispatch arms

## Test Plan

| Test | Behavior verified |
|------|-------------------|
| test_timerfd_create | timerfd_create returns valid fd |
| test_timerfd_read_disarmed_eagain | Disarmed timer → EAGAIN |
| test_timerfd_arm_and_expire | Arm + advance clock → read returns count=1 |
| test_timerfd_not_yet_expired | Arm + insufficient clock advance → EAGAIN |
| test_timerfd_repeating | Arm with interval + advance 3x → count=3 |
| test_timerfd_settime_disarm | Arm then disarm → EAGAIN |
| test_timerfd_cloexec | TFD_CLOEXEC sets FD_CLOEXEC |

## Dependencies

| Bead | Relationship |
|------|-------------|
| harmony-os-jo0 | Related (closed) — signalfd, same pattern |
