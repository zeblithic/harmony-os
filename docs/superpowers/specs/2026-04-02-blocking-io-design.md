# Blocking I/O for Linuxulator

**Bead:** harmony-os-cqy (P3, feature)
**Date:** 2026-04-02
**Status:** Design approved

## Problem

The Linuxulator always returns EAGAIN on `read()`/`write()`/`accept()`/`recvfrom()`/`sendto()` when no data is immediately available, regardless of the socket's blocking mode. This forces every program to use select/poll/epoll before I/O — programs that expect standard blocking behavior (most simple programs, musl's DNS resolver with `__res_msend`, shell pipelines) don't work correctly.

The spin-wait infrastructure already exists in select/poll (PR #103): call `poll_fn()` to drive the network stack, check readiness, spin with `core::hint::spin_loop()`, cap at 30s for the watchdog. This feature reuses that pattern inside individual syscalls.

## Design

### `block_until` Helper

New method on `Linuxulator`:

```rust
enum BlockResult {
    Ready,
    Interrupted, // watchdog timeout → caller returns EINTR
}

fn block_until(
    &mut self,
    poll_fn: fn() -> u64,
    ready_check: fn(&Self, i32) -> bool,
    fd: i32,
) -> BlockResult
```

The loop:
1. Call `poll_fn()` to drive network stack + get current time
2. Call `ready_check(self, fd)` — if true, return `BlockResult::Ready`
3. If 30s elapsed since entry, return `BlockResult::Interrupted`
4. `core::hint::spin_loop()` and repeat

Design choices:
- Uses function pointers (not closures) to avoid lifetime complexity with `&mut self`. The `ready_check` takes `&Self` and `fd`, delegates to `is_fd_readable` or `is_fd_writable`.
- Same 30s `MAX_BLOCK_MS` cap as select/poll, for watchdog compatibility.
- Does NOT reset the dispatch idle watchdog (same reasoning as UDP I/O — blocking I/O during a stuck session shouldn't keep it alive).

### Blocking Syscall Wiring

Each syscall that can block follows the same pattern: try once, if WouldBlock and blocking mode, call `block_until`, then retry exactly once. If the retry also fails, return the error.

**`sys_read` (TCP + pipes):**
- TCP: waits via `is_fd_readable(fd)` — true when `tcp_can_recv` or connection closing (EOF)
- Pipes: waits via `is_fd_readable(fd)` — true when buffer non-empty or write-end closed
- On `BlockResult::Interrupted`, return `EINTR` (-4)

**`sys_write` (TCP + pipes):**
- TCP: waits via `is_fd_writable(fd)` — true when `tcp_can_send` and connection alive
- Pipes: waits via `is_fd_writable(fd)` — needs enhancement to detect broken pipe (read-end closed → EPIPE)

**`sys_accept4` (TCP listeners):**
- If no pending connection and blocking mode, `block_until(poll_fn, is_fd_readable, fd)`
- `is_fd_readable` on a listener returns true when a connection is ready to accept
- Retry accept on Ready; return EINTR on Interrupted

**`sys_recvfrom` (UDP):**
- If WouldBlock and blocking mode, `block_until(poll_fn, is_fd_readable, fd)`
- Retry recvfrom on Ready

**`sys_sendto` (UDP):**
- If WouldBlock and blocking mode, `block_until(poll_fn, is_fd_writable, fd)`
- Retry sendto on Ready

**Pattern for all:** Try once → WouldBlock + blocking? → `block_until` → retry once → return result.

### `fcntl(F_SETFL)` and `F_GETFL`

Currently `F_SETFL` is a no-op. Both directions need fixing.

**FdEntry change:**
```rust
struct FdEntry {
    kind: FdKind,
    flags: i32,       // existing (cloexec etc.)
    nonblock: bool,   // NEW — blocking mode for this fd
}
```

`FdEntry.nonblock` is the source of truth for blocking mode:
- Initialized from `SOCK_NONBLOCK` at socket creation or `O_NONBLOCK` at `pipe2` creation
- Updated by `fcntl(F_SETFL)`
- Read by all blocking syscalls to decide spin-wait vs EAGAIN

**`F_GETFL`:**
- Returns `O_NONBLOCK` if `fd_entry.nonblock` is true, else 0
- Works for sockets, pipes, and all other fd types

**`F_SETFL`:**
- Extracts `O_NONBLOCK` from the flags argument
- Updates `fd_entry.nonblock`
- Ignores other flags (O_APPEND, O_ASYNC — not relevant)

**`SocketState.nonblock` becomes redundant.** Remove it — `FdEntry.nonblock` is authoritative. All code that currently reads `socket_state.nonblock` switches to `fd_entry.nonblock`.

### Pipe Writable Readiness

`is_fd_writable` currently returns `true` unconditionally for `PipeWrite`. For blocking write to detect broken pipes, enhance it:
- Check that a corresponding `PipeRead` fd still exists for the same `pipe_id`
- If no reader exists, the pipe is broken — `is_fd_writable` returns true (to unblock the spin-wait), and the subsequent `write` returns `EPIPE`

### Edge Cases

- **EOF on blocking read:** TCP `CloseWait`/`Closed` or pipe write-end closed → `is_fd_readable` returns true → retry read returns 0 (EOF). Correct — EOF is data, not an interruption.
- **TCP reset during blocking read:** Connection enters Closed → `is_fd_readable` true → retry `tcp_recv` returns `ConnectionReset` → `ECONNRESET`.
- **Connect + blocking write:** `connect()` already spin-waits until established, so immediate `write()` finds the connection ready.
- **Blocking accept + multiple connections:** `block_until` returns on first readiness. Accept returns one connection. Subsequent accept either gets another immediately or spin-waits again.
- **SOCK_NONBLOCK cleared via fcntl:** `fcntl(fd, F_SETFL, 0)` clears nonblock → socket starts blocking. Natural consequence of `FdEntry.nonblock` being authoritative.
- **sendto on connected UDP with blocking:** Same pattern — `block_until(is_fd_writable)` then retry.

### EINTR Semantics

When `block_until` returns `Interrupted` (30s watchdog timeout), the syscall returns `EINTR` (-4). This is semantically correct:
- Well-behaved programs retry on EINTR (musl, glibc wrappers all do)
- Gives us a clean mechanism for future signal delivery to interrupt blocking I/O
- EAGAIN on a blocking socket would confuse programs that check it to detect nonblocking mode

## Files Changed

| File | Changes |
|------|---------|
| `crates/harmony-os/src/linuxulator.rs` | `BlockResult` enum, `block_until` helper, `FdEntry.nonblock` field, remove `SocketState.nonblock`, wire blocking into sys_read/sys_write/sys_accept4/sys_recvfrom/sys_sendto, fix fcntl F_SETFL/F_GETFL, enhance pipe writable readiness |

## Testing

**Unit tests (harmony-os):**
- Blocking TCP read: connected pair, write one end, read other — returns data (not EAGAIN)
- Blocking TCP read timeout: read on empty socket → EINTR after timeout
- Blocking accept: listener + connect → accept returns fd (not EAGAIN)
- Blocking pipe read: write to pipe, read returns data; empty pipe → EINTR
- Blocking pipe EOF: close write-end → blocking read returns 0 (not EINTR)
- Nonblocking mode: `SOCK_NONBLOCK` sockets still return EAGAIN immediately
- fcntl F_SETFL: set O_NONBLOCK → EAGAIN; clear → blocking
- fcntl F_GETFL: reflects current nonblock state
- Blocking UDP recvfrom: send packet, recvfrom returns data
- Broken pipe: close read-end → blocking write returns EPIPE

## Out of Scope

- `SO_RCVTIMEO` / `SO_SNDTIMEO` per-socket timeouts — fixed 30s cap is sufficient for now
- Signal interruption from real signals (SIGALRM, etc.) — requires signal infrastructure beyond the watchdog
- Refactoring select/poll to use `block_until` — their multi-fd semantics don't fit the single-fd helper, and they already work
- `MSG_DONTWAIT` flag on recvfrom/sendto — can be added incrementally
