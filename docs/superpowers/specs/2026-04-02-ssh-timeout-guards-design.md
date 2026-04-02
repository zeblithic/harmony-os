# SSH Session Timeout Guards

**Bead:** harmony-os-fto (P2, bug)
**Date:** 2026-04-02
**Status:** Design approved

## Problem

The SSH relay loop (dropbear parent after fork) busy-spins on `select`/`read`/`write` with no idle timeout. `sys_select` always returns "all fds ready" immediately, ignoring the timeout parameter. If the SSH client hangs (network drop, closed laptop), the loop polls forever — in a unikernel with one-connection-at-a-time, this bricks the system until reboot.

### Why a traditional watchdog doesn't work

The PIT timer is poll-only (no interrupts — all PIC IRQs are masked to prevent triple-faults). There is no preemptive mechanism. However, the relay loop *does* yield to kernel code on every syscall (`select` → `read` → `write` → repeat), so the kernel gets control regularly via `dispatch()`. The fix is to make the kernel *use* that control to check time and readiness.

## Design

Three complementary layers, each addressing a different failure mode:

### Layer 1: Proper `select()` with Timeout and Readiness Checking

Rewrite `sys_select`, `sys_poll`, and `sys_ppoll` to spin-wait with actual fd readiness checking and timeout support.

**Poll callback:** Add a `poll_fn: fn() -> u64` field to the Linuxulator. Set it during init from `main.rs` to a function that calls `poll_network()` (VirtIO RX/TX + smoltcp processing) and returns `pit.now_ms()`. This gives the Linuxulator access to network polling and wall-clock time without coupling it to kernel internals.

**Readiness checking per fd kind:**

| FdKind | Readable | Writable |
|--------|----------|----------|
| `TcpSocket(h)` | `tcp_can_recv(h)` or state is CloseWait/Closed | `tcp_can_send(h)` and state is Established |
| `TcpListener(h)` | `tcp_accept` would succeed (state is Established) | N/A |
| `PipeRead(id)` | pipe buffer non-empty, OR write-end closed (EOF) | N/A |
| `PipeWrite(id)` | N/A | always true (unbounded buffer) |
| `Serial`/`Stdout`/`Stderr` | always true | always true |

This mirrors the existing `epoll_wait` readiness logic.

**Spin loop:**

```
parse timeout → deadline_ms (NULL → u64::MAX, {0,0} → check once)
loop {
    now = (poll_fn)()        // drives VirtIO + smoltcp, returns PIT ms
    ready = check_all_fds()  // per table above
    if ready > 0: write fdsets/revents to userspace, return ready
    if now >= deadline_ms: clear fdsets, return 0
    spin_loop_hint()
}
```

- `timeout=NULL`: blocks until an fd is ready (deadline = `u64::MAX`).
- `timeout={0,0}`: non-blocking, check once and return. Preserves current behavior for callers that expect instant return.
- `nfds=0` with a timeout: pure sleep that keeps the network stack alive.

**Mutability:** `sys_select`/`sys_poll` currently take `&self`. The spin loop calls `self.tcp.tcp_poll()` implicitly through `poll_fn` (which goes through the unsafe global path), so the Linuxulator method signature stays `&self` for readiness checking. The `poll_fn` callback handles mutation externally.

### Layer 2: smoltcp TCP Keepalive

Enable smoltcp's built-in TCP keepalive on accepted connections so dead remote hosts are detected and RST'd.

**Where to enable:** In `tcp_accept` in the netstack (`harmony-netstack`). When a new connection is accepted, configure keepalive on the new socket handle. All accepted TCP sockets get keepalive by default.

**Parameters:**
- Keepalive interval: 60 seconds (standard Linux default)
- smoltcp handles retransmission and eventual RST internally

**TcpProvider trait addition:**

```rust
fn tcp_set_keepalive(&mut self, handle: TcpHandle, interval_ms: Option<u64>);
```

`None` disables keepalive, `Some(ms)` enables it. The netstack implementation calls `smoltcp::socket::tcp::Socket::set_keep_alive(Some(Duration::from_millis(ms)))`.

**setsockopt wiring:** Wire `sys_setsockopt(SO_KEEPALIVE)` to call `tcp_set_keepalive`. Not strictly required (auto-enabled on accept) but provides correct Linux ABI behavior.

**Interaction with Layer 1:** The `select()` spin loop calls `poll_fn()` → `poll_network()` → `smoltcp.poll()`. Keepalive probes are sent/received during these polls. When smoltcp closes a dead connection, `tcp_can_recv` returns true (EOF state), `select()` returns "readable", and dropbear reads EOF and exits cleanly.

### Layer 3: Dispatch Idle Watchdog (Safety Net)

Track "last meaningful I/O" timestamp in `dispatch()`. If the gap exceeds a threshold, force-terminate the session.

**Meaningful I/O (resets timer):**
- `sys_read` on a TCP socket returns actual data (retval > 0)
- `sys_write` on a TCP socket sends actual data (retval > 0)
- `sys_accept` returns a new connection

Pipe I/O, EAGAIN returns, and metadata syscalls do NOT reset the timer.

**Implementation:**

```rust
// main.rs
static mut LAST_TCP_IO_MS: u64 = 0;
const IDLE_KILL_THRESHOLD_MS: u64 = 300_000; // 5 minutes
```

- Updated in `dispatch()` after `handle_syscall` returns, when a TCP read/write returned > 0.
- Checked at the top of `dispatch()`: if `LAST_TCP_IO_MS != 0 && now - LAST_TCP_IO_MS > threshold`, return `SyscallResult { exited: true, exit_code: 62 }`.
- Reset on `sys_accept` success (new session starts fresh).

**Interaction with Layer 1:** When `select()` is spin-waiting, dispatch isn't re-entered. The watchdog fires on the next syscall after select returns. If select returned due to timeout, dropbear makes at least one syscall to check its own idle timer — that's when the watchdog fires if needed.

## Files Changed

| File | Changes |
|------|---------|
| `crates/harmony-os/src/linuxulator.rs` | Rewrite `sys_select`, `sys_poll`, `sys_ppoll` with spin-wait + readiness. Add `poll_fn` field. Add `check_fd_readable`/`check_fd_writable` helpers. Wire `sys_setsockopt(SO_KEEPALIVE)`. |
| `crates/harmony-boot/src/main.rs` | Set `poll_fn` callback on Linuxulator init. Add `LAST_TCP_IO_MS` watchdog statics. Add watchdog check/update in `dispatch()`. |
| `crates/harmony-netstack/src/tcp.rs` | Add `tcp_set_keepalive` to `TcpProvider` trait. |
| `crates/harmony-netstack/src/stack.rs` | Implement `tcp_set_keepalive` (calls smoltcp `set_keep_alive`). Auto-enable keepalive in `tcp_accept`. |

## Testing

**QEMU integration:**
- `ssh -p 2222 root@localhost "echo alive"` — returns "alive", exit 0 (regression)
- Manual: connect SSH, go idle, confirm disconnect after threshold

**Unit-testable pieces:**
- Readiness checking logic (fd kind → readable/writable) against mock TcpProvider
- Timeout parsing (struct timeval → deadline_ms)
- `select` with `timeout={0,0}` returns immediately (non-blocking regression)

## Out of Scope

- `setitimer`/`timer_create` signal delivery — dropbear's `-I` works through `select()` timeout, not POSIX timers
- Per-socket configurable keepalive intervals — hardcoded 60s default is sufficient
- `sys_ppoll` signal mask handling — no signal infrastructure; same spin loop as `sys_poll`
- Preemptive timer interrupts — would require IDT/IST setup; the poll-based approach is sufficient
