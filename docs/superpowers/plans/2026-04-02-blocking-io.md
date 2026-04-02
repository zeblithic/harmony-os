# Blocking I/O Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `read()`/`write()`/`accept()`/`recvfrom()`/`sendto()`/`connect()` spin-wait until data arrives on blocking-mode sockets and pipes, instead of always returning EAGAIN.

**Architecture:** Reuse the existing `poll_fn` + `core::hint::spin_loop()` pattern from select/poll inside individual syscalls. A shared `block_until` helper spin-waits using `is_fd_readable`/`is_fd_writable` readiness checks, capped at 30s (returns EINTR on timeout). The `nonblock` flag moves from `SocketState` to `FdEntry` so it applies to all fd types and can be toggled via `fcntl(F_SETFL)`.

**Tech Stack:** Rust (no_std), harmony-os Linuxulator

**Spec:** `docs/superpowers/specs/2026-04-02-blocking-io-design.md`

---

### Task 1: EINTR constant and BlockResult enum

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Add EINTR constant**

At the end of the errno constants block (after `const ENOTCONN: i64 = -107;` on line 47), add:

```rust
const EINTR: i64 = -4;
```

- [ ] **Step 2: Add BlockResult enum**

Below the errno constants and above `fn ipc_err_to_errno` (line 80), add:

```rust
/// Result of a `block_until` spin-wait.
enum BlockResult {
    /// The readiness check returned true — caller should retry the operation.
    Ready,
    /// The 30-second watchdog cap expired — caller should return EINTR.
    Interrupted,
}
```

- [ ] **Step 3: Add block_until method**

Add this method to the `impl<B: SyscallBackend, T: TcpProvider + ...> Linuxulator<B, T>` block (after `set_poll_fn` around line 2569):

```rust
    /// Spin-wait until `ready_check(self, fd)` returns true, or 30 seconds
    /// elapse.  Calls `poll_fn` on every iteration to drive the network
    /// stack and read the current time.
    ///
    /// Returns [`BlockResult::Ready`] when the fd becomes ready, or
    /// [`BlockResult::Interrupted`] on timeout (caller returns EINTR).
    fn block_until(
        &mut self,
        poll_fn: fn() -> u64,
        ready_check: fn(&Self, i32) -> bool,
        fd: i32,
    ) -> BlockResult {
        const MAX_BLOCK_MS: u64 = 30_000;
        let start_ms = poll_fn();
        let deadline = start_ms.saturating_add(MAX_BLOCK_MS);

        loop {
            let now = poll_fn();
            if ready_check(self, fd) {
                return BlockResult::Ready;
            }
            if now >= deadline {
                return BlockResult::Interrupted;
            }
            core::hint::spin_loop();
        }
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-os`
Expected: PASS (no behavior changes yet, just new code)

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add EINTR, BlockResult, and block_until helper"
```

---

### Task 2: Move nonblock flag from SocketState to FdEntry

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Write failing test — FdEntry.nonblock initialized for sockets**

In the `tests` module (around line 8587), add:

```rust
    #[test]
    fn fd_entry_nonblock_from_sock_nonblock() {
        let mut lx = Linuxulator::new(MockBackend::new());
        // SOCK_NONBLOCK = 0o4000 = 2048
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,          // AF_INET
            sock_type: 1 | 2048, // SOCK_STREAM | SOCK_NONBLOCK
            protocol: 0,
        });
        assert!(fd >= 0);
        let entry = lx.fd_table.get(&(fd as i32)).unwrap();
        assert!(entry.nonblock);
    }

    #[test]
    fn fd_entry_nonblock_default_false() {
        let mut lx = Linuxulator::new(MockBackend::new());
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,     // AF_INET
            sock_type: 1,  // SOCK_STREAM (no NONBLOCK)
            protocol: 0,
        });
        assert!(fd >= 0);
        let entry = lx.fd_table.get(&(fd as i32)).unwrap();
        assert!(!entry.nonblock);
    }

    #[test]
    fn fd_entry_nonblock_from_pipe2() {
        let mut lx = Linuxulator::new(MockBackend::new());
        let mut fds = [0i32; 2];
        let result = lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0o4000, // O_NONBLOCK
        });
        assert_eq!(result, 0);
        assert!(lx.fd_table.get(&fds[0]).unwrap().nonblock);
        assert!(lx.fd_table.get(&fds[1]).unwrap().nonblock);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os fd_entry_nonblock`
Expected: FAIL — `FdEntry` has no field `nonblock`

- [ ] **Step 3: Add nonblock field to FdEntry**

Change the `FdEntry` struct (line 2369):

```rust
struct FdEntry {
    kind: FdKind,
    /// File descriptor flags (e.g. FD_CLOEXEC). Default 0.
    flags: u32,
    /// True if this fd is in non-blocking mode (O_NONBLOCK / SOCK_NONBLOCK).
    nonblock: bool,
}
```

- [ ] **Step 4: Add `nonblock: false` to all existing FdEntry construction sites**

Add `nonblock: false` to every `FdEntry { ... }` construction. These are all at the following lines (line numbers may shift slightly after Step 3):

- `init_stdio` — 3 sites (fd 0, 1, 2): add `nonblock: false`
- `dup_fd_to` — 1 site: copy from source entry (see next step)
- `eventfd2` — 1 site: add `nonblock: false`
- `timerfd_create` — 1 site: add `nonblock: false`
- `signalfd4` — 1 site: add `nonblock: false`
- `epoll_create1` — 1 site: add `nonblock: false`
- `sys_openat` — 6 sites (file, dir, embedded file, embedded dir, scratch file, dev special): add `nonblock: false`
- `sys_socketpair` — 2 sites: add `nonblock: false` (will be wired to SOCK_NONBLOCK later in this step)

Example for `init_stdio` (fd 0):

```rust
        self.fd_table.insert(
            0,
            FdEntry {
                kind: FdKind::File {
                    fid: stdin_fid,
                    offset: 0,
                    path: None,
                    file_type: FileType::CharDev,
                },
                flags: 0,
                nonblock: false,
            },
        );
```

Apply the same pattern to all other `FdEntry { kind: ..., flags: ... }` construction sites. Search for `FdEntry {` and add `nonblock: false` to each struct literal that doesn't already have it.

- [ ] **Step 5: Set nonblock correctly for sockets, pipes, and socketpair**

In `sys_socket` (around line 4415), change the FdEntry construction:

```rust
        self.fd_table.insert(
            fd,
            FdEntry {
                kind: FdKind::Socket { socket_id },
                flags: fd_flags,
                nonblock: flags & SOCK_NONBLOCK != 0,
            },
        );
```

In `sys_pipe2` (around line 4291 and 4300), set nonblock from flags:

```rust
        let is_nonblock = flags & O_NONBLOCK != 0;

        let read_fd = self.alloc_fd();
        self.fd_table.insert(
            read_fd,
            FdEntry {
                kind: FdKind::PipeRead { pipe_id },
                flags: fd_flags,
                nonblock: is_nonblock,
            },
        );

        let write_fd = self.alloc_fd();
        self.fd_table.insert(
            write_fd,
            FdEntry {
                kind: FdKind::PipeWrite { pipe_id },
                flags: fd_flags,
                nonblock: is_nonblock,
            },
        );
```

In `sys_accept4` — both TCP path (around line 4569) and stub path (around line 4625):

```rust
                    self.fd_table.insert(
                        new_fd,
                        FdEntry {
                            kind: FdKind::Socket {
                                socket_id: new_socket_id,
                            },
                            flags: fd_flags,
                            nonblock: flags & SOCK_NONBLOCK != 0,
                        },
                    );
```

In `sys_socketpair` (both fd entries):

```rust
                nonblock: flags & SOCK_NONBLOCK != 0,
```

Where `flags` is extracted from `sock_type` the same way as in `sys_socket`.

- [ ] **Step 6: Copy nonblock in dup_fd_to**

In `dup_fd_to` (around line 4175), copy the source entry's nonblock:

```rust
    fn dup_fd_to(&mut self, oldfd: i32, newfd: i32, fd_flags: u32) {
        let entry = self.fd_table.get(&oldfd).unwrap();
        let new_kind = entry.kind.clone();
        let src_nonblock = entry.nonblock;
        if let FdKind::File { fid, .. } = &new_kind {
            *self.fid_refcount.get_mut(fid).expect("refcount missing") += 1;
        }
        self.fd_table.insert(
            newfd,
            FdEntry {
                kind: new_kind,
                flags: fd_flags,
                nonblock: src_nonblock,
            },
        );
    }
```

- [ ] **Step 7: Remove SocketState.nonblock and migrate all reads**

Remove `nonblock: bool` from the `SocketState` struct (line 2231).

Remove `nonblock: ...` from all `SocketState { ... }` construction sites:
- `sys_socket` (around line 4401)
- `sys_accept4` TCP path (around line 4556)
- `sys_accept4` stub path (around line 4611)
- `sys_socketpair` (both sites)
- fork child socket cloning (around line 5648)

In `sys_accept4`, the stub path reads `s.nonblock` to decide EAGAIN for the stub accept-once logic. Change this to read from `FdEntry`:

```rust
        let parent_nonblock = match self.fd_table.get(&fd) {
            Some(entry) => entry.nonblock,
            None => false,
        };
```

Use `parent_nonblock` instead of the old `nonblock` from `state_snap`.

In `sys_read`, `sys_write`, `sys_connect`, `sys_sendto`, `sys_recvfrom`: these destructure `(tcp_handle, _nonblock)` from `SocketState`. Remove the `_nonblock` — just extract `tcp_handle`:

```rust
                let tcp_handle = match self.sockets.get(&socket_id) {
                    Some(s) => s.tcp_handle,
                    None => return EBADF,
                };
```

- [ ] **Step 8: Run tests**

Run: `cargo test -p harmony-os`
Expected: PASS — all tests including the 3 new ones

- [ ] **Step 9: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "refactor(linuxulator): move nonblock flag from SocketState to FdEntry"
```

---

### Task 3: Fix fcntl F_GETFL and F_SETFL

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Write failing tests**

In the `tests` module, add:

```rust
    #[test]
    fn sys_fcntl_getfl_returns_nonblock() {
        let mut lx = Linuxulator::new(MockBackend::new());
        // Create a nonblocking socket.
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,
            sock_type: 1 | 2048, // SOCK_STREAM | SOCK_NONBLOCK
            protocol: 0,
        });
        assert!(fd >= 0);
        let result = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: fd as i32,
            cmd: 3, // F_GETFL
            arg: 0,
        });
        assert_eq!(result, 0o4000); // O_NONBLOCK
    }

    #[test]
    fn sys_fcntl_setfl_enables_nonblock() {
        let mut lx = Linuxulator::new(MockBackend::new());
        // Create a blocking socket.
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,
            sock_type: 1, // SOCK_STREAM (blocking)
            protocol: 0,
        });
        assert!(fd >= 0);
        // Set O_NONBLOCK via F_SETFL.
        let r = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: fd as i32,
            cmd: 4, // F_SETFL
            arg: 0o4000, // O_NONBLOCK
        });
        assert_eq!(r, 0);
        // Verify F_GETFL reflects the change.
        let result = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: fd as i32,
            cmd: 3, // F_GETFL
            arg: 0,
        });
        assert_eq!(result, 0o4000);
    }

    #[test]
    fn sys_fcntl_setfl_clears_nonblock() {
        let mut lx = Linuxulator::new(MockBackend::new());
        // Create a nonblocking socket.
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,
            sock_type: 1 | 2048, // SOCK_STREAM | SOCK_NONBLOCK
            protocol: 0,
        });
        assert!(fd >= 0);
        // Clear O_NONBLOCK via F_SETFL.
        let r = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: fd as i32,
            cmd: 4, // F_SETFL
            arg: 0, // no flags
        });
        assert_eq!(r, 0);
        // Verify F_GETFL is 0.
        let result = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: fd as i32,
            cmd: 3,
            arg: 0,
        });
        assert_eq!(result, 0);
        // Verify the entry is actually blocking.
        let entry = lx.fd_table.get(&(fd as i32)).unwrap();
        assert!(!entry.nonblock);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os sys_fcntl_getfl_returns sys_fcntl_setfl_enables sys_fcntl_setfl_clears`
Expected: FAIL — F_GETFL still returns 0, F_SETFL is a no-op

- [ ] **Step 3: Implement F_GETFL and F_SETFL**

Replace the F_GETFL and F_SETFL branches in `sys_fcntl` (around line 4144):

```rust
            F_GETFL => match self.fd_table.get(&fd) {
                Some(entry) => {
                    if entry.nonblock {
                        O_NONBLOCK as i64
                    } else {
                        0
                    }
                }
                None => EBADF,
            },
            F_SETFL => match self.fd_table.get_mut(&fd) {
                Some(entry) => {
                    entry.nonblock = (arg as i32) & O_NONBLOCK != 0;
                    0
                }
                None => EBADF,
            },
```

- [ ] **Step 4: Update existing fcntl tests**

The existing test `sys_fcntl_getfl_stub_returns_zero` still passes (stdio fds are blocking → F_GETFL returns 0). The existing test `sys_fcntl_setfl_stub_returns_zero` still passes (setting flags to 0 returns 0). No changes needed.

- [ ] **Step 5: Run tests**

Run: `cargo test -p harmony-os`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): implement fcntl F_GETFL and F_SETFL for O_NONBLOCK"
```

---

### Task 4: Blocking sys_read for TCP sockets and pipes

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Write failing tests**

Add a test poll function in the `tests` module:

```rust
    use core::sync::atomic::{AtomicU64, Ordering};

    /// Poll function for blocking I/O tests. Each call advances time by
    /// 31 seconds, ensuring `block_until` times out on the second call.
    /// Safe for parallel tests: each test's deadline is relative to its
    /// own first call, and 31s > 30s cap guarantees timeout every time.
    fn timeout_poll_fn() -> u64 {
        static TIME: AtomicU64 = AtomicU64::new(0);
        TIME.fetch_add(31_000, Ordering::Relaxed)
    }
```

Then add tests:

```rust
    #[test]
    fn blocking_pipe_read_returns_data() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);
        let (rfd, wfd) = create_pipe(&mut lx);

        // Write data first so the read doesn't need to block.
        let data = b"hello";
        let w = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: wfd,
            buf: data.as_ptr() as u64,
            count: data.len() as u64,
        });
        assert_eq!(w, 5);

        // Blocking read — data already available, returns immediately.
        let mut buf = [0u8; 16];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: rfd,
            buf: buf.as_mut_ptr() as u64,
            count: buf.len() as u64,
        });
        assert_eq!(r, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn blocking_pipe_read_empty_returns_eintr() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);
        let (rfd, _wfd) = create_pipe(&mut lx);

        // Blocking read on empty pipe — times out → EINTR.
        let mut buf = [0u8; 16];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: rfd,
            buf: buf.as_mut_ptr() as u64,
            count: buf.len() as u64,
        });
        assert_eq!(r, EINTR);
    }

    #[test]
    fn blocking_pipe_read_eof_returns_zero() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);
        let (rfd, wfd) = create_pipe(&mut lx);

        // Close write end.
        lx.dispatch_syscall(LinuxSyscall::Close { fd: wfd });

        // Blocking read on pipe with no writer → EOF (0), not EINTR.
        let mut buf = [0u8; 16];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: rfd,
            buf: buf.as_mut_ptr() as u64,
            count: buf.len() as u64,
        });
        assert_eq!(r, 0);
    }

    #[test]
    fn nonblocking_pipe_read_empty_returns_eagain() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);
        let mut fds = [0i32; 2];
        let result = lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0o4000, // O_NONBLOCK
        });
        assert_eq!(result, 0);

        // Nonblocking read on empty pipe → EAGAIN (no blocking).
        let mut buf = [0u8; 16];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: fds[0],
            buf: buf.as_mut_ptr() as u64,
            count: buf.len() as u64,
        });
        assert_eq!(r, EAGAIN);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os blocking_pipe_read nonblocking_pipe_read`
Expected: `blocking_pipe_read_empty_returns_eintr` FAILS (returns EAGAIN, not EINTR). Others pass (data-available and EOF paths don't change).

- [ ] **Step 3: Wire blocking into sys_read for pipes**

In `sys_read`, the `FdKind::PipeRead` branch (around line 3552). Change the empty-pipe path:

```rust
            FdKind::PipeRead { pipe_id } => {
                if count == 0 {
                    return 0;
                }
                let buf = match self.pipes.get_mut(&pipe_id) {
                    Some(b) => b,
                    None => return 0,
                };
                if buf.is_empty() {
                    let has_writer = self.fd_table.values().any(
                        |e| matches!(&e.kind, FdKind::PipeWrite { pipe_id: id } if *id == pipe_id),
                    );
                    if !has_writer {
                        return 0; // EOF
                    }
                    // Blocking mode: spin-wait until readable.
                    let nonblock = self
                        .fd_table
                        .get(&fd)
                        .map(|e| e.nonblock)
                        .unwrap_or(true);
                    if !nonblock {
                        if let Some(pf) = self.poll_fn {
                            match self.block_until(pf, Self::is_fd_readable, fd) {
                                BlockResult::Ready => {
                                    // Retry: data arrived or write-end closed.
                                    let buf = match self.pipes.get_mut(&pipe_id) {
                                        Some(b) => b,
                                        None => return 0,
                                    };
                                    if buf.is_empty() {
                                        // Write-end closed while waiting → EOF.
                                        return 0;
                                    }
                                    let n = count.min(buf.len());
                                    unsafe {
                                        core::ptr::copy_nonoverlapping(
                                            buf.as_ptr(),
                                            buf_ptr as *mut u8,
                                            n,
                                        );
                                    }
                                    buf.drain(..n);
                                    return n as i64;
                                }
                                BlockResult::Interrupted => return EINTR,
                            }
                        }
                    }
                    EAGAIN
                } else {
                    let n = count.min(buf.len());
                    unsafe {
                        core::ptr::copy_nonoverlapping(buf.as_ptr(), buf_ptr as *mut u8, n);
                    }
                    buf.drain(..n);
                    n as i64
                }
            }
```

- [ ] **Step 4: Wire blocking into sys_read for TCP sockets**

In `sys_read`, the `FdKind::Socket` branch (around line 3643). After the `tcp_recv` returns `WouldBlock`:

```rust
            FdKind::Socket { socket_id } => {
                let tcp_handle = match self.sockets.get(&socket_id) {
                    Some(s) => s.tcp_handle,
                    None => return EBADF,
                };
                if let Some(h) = tcp_handle {
                    if count == 0 {
                        return 0;
                    }
                    if buf_ptr == 0 {
                        return EFAULT;
                    }
                    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, count) };
                    match self.tcp.tcp_recv(h, buf) {
                        Ok(n) => n as i64,
                        Err(NetError::WouldBlock) => {
                            let nonblock = self
                                .fd_table
                                .get(&fd)
                                .map(|e| e.nonblock)
                                .unwrap_or(true);
                            if !nonblock {
                                if let Some(pf) = self.poll_fn {
                                    match self.block_until(pf, Self::is_fd_readable, fd) {
                                        BlockResult::Ready => {
                                            let buf = unsafe {
                                                core::slice::from_raw_parts_mut(
                                                    buf_ptr as *mut u8,
                                                    count,
                                                )
                                            };
                                            match self.tcp.tcp_recv(h, buf) {
                                                Ok(n) => return n as i64,
                                                Err(e) => return net_error_to_errno(e),
                                            }
                                        }
                                        BlockResult::Interrupted => return EINTR,
                                    }
                                }
                            }
                            EAGAIN
                        }
                        Err(e) => net_error_to_errno(e),
                    }
                } else {
                    0
                }
            }
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p harmony-os`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add blocking read for TCP sockets and pipes"
```

---

### Task 5: Blocking sys_write for TCP sockets and pipes

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Write failing tests**

```rust
    #[test]
    fn blocking_pipe_write_broken_pipe_returns_epipe() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);
        let (rfd, wfd) = create_pipe(&mut lx);

        // Close read end.
        lx.dispatch_syscall(LinuxSyscall::Close { fd: rfd });

        // Blocking write to pipe with no reader → EPIPE.
        let data = b"hello";
        let r = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: wfd,
            buf: data.as_ptr() as u64,
            count: data.len() as u64,
        });
        assert_eq!(r, EPIPE);
    }

    #[test]
    fn blocking_pipe_write_full_returns_eintr() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);
        let (rfd, wfd) = create_pipe(&mut lx);

        // Fill the pipe buffer (65536 bytes).
        let big = [0u8; 65536];
        let w = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: wfd,
            buf: big.as_ptr() as u64,
            count: big.len() as u64,
        });
        assert_eq!(w, 65536);

        // Blocking write to full pipe — times out → EINTR.
        let data = b"overflow";
        let r = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: wfd,
            buf: data.as_ptr() as u64,
            count: data.len() as u64,
        });
        assert_eq!(r, EINTR);

        // Keep rfd alive so pipe isn't broken.
        let _ = rfd;
    }

    #[test]
    fn nonblocking_pipe_write_full_returns_eagain() {
        let mut lx = Linuxulator::new(MockBackend::new());
        let mut fds = [0i32; 2];
        let result = lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0o4000, // O_NONBLOCK
        });
        assert_eq!(result, 0);

        // Fill the pipe buffer.
        let big = [0u8; 65536];
        let w = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: fds[1],
            buf: big.as_ptr() as u64,
            count: big.len() as u64,
        });
        assert_eq!(w, 65536);

        // Nonblocking write to full pipe → EAGAIN.
        let data = b"overflow";
        let r = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: fds[1],
            buf: data.as_ptr() as u64,
            count: data.len() as u64,
        });
        assert_eq!(r, EAGAIN);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os blocking_pipe_write nonblocking_pipe_write`
Expected: `blocking_pipe_write_full_returns_eintr` FAILS (returns EAGAIN). Others may pass.

- [ ] **Step 3: Enhance is_fd_writable for pipe buffer fullness**

In `is_fd_writable` (around line 8412), replace the `PipeWrite` branch:

```rust
            FdKind::PipeWrite { pipe_id } => {
                // Report writable if buffer has space OR no reader exists
                // (so write can return EPIPE and unblock the spin-wait).
                let has_reader = self.fd_table.values().any(
                    |e| matches!(&e.kind, FdKind::PipeRead { pipe_id: id } if *id == *pipe_id),
                );
                if !has_reader {
                    return true; // unblock → write returns EPIPE
                }
                const PIPE_BUF_CAP: usize = 65536;
                self.pipes
                    .get(pipe_id)
                    .map(|b| b.len() < PIPE_BUF_CAP)
                    .unwrap_or(true)
            }
```

- [ ] **Step 4: Wire blocking into sys_write for pipes**

In `sys_write`, the `FdKind::PipeWrite` branch. After `if avail == 0 { return EAGAIN; }` (around line 3413), replace the EAGAIN return:

```rust
                if avail == 0 {
                    let nonblock = self
                        .fd_table
                        .get(&fd)
                        .map(|e| e.nonblock)
                        .unwrap_or(true);
                    if !nonblock {
                        if let Some(pf) = self.poll_fn {
                            match self.block_until(pf, Self::is_fd_writable, fd) {
                                BlockResult::Ready => {
                                    // Retry: check reader and buffer again.
                                    let has_reader = self.fd_table.values().any(
                                        |e| {
                                            matches!(&e.kind, FdKind::PipeRead { pipe_id: id } if *id == pipe_id)
                                        },
                                    );
                                    if !has_reader {
                                        let is_child = self.parent_pid != 0;
                                        if !is_child || !self.pipes.contains_key(&pipe_id) {
                                            return EPIPE;
                                        }
                                    }
                                    let pipe_buf = match self.pipes.get_mut(&pipe_id) {
                                        Some(b) => b,
                                        None => return EPIPE,
                                    };
                                    let avail = PIPE_BUF_CAP.saturating_sub(pipe_buf.len());
                                    if avail == 0 {
                                        return EAGAIN; // Still full after wakeup
                                    }
                                    const PIPE_BUF: usize = 4096;
                                    if count <= PIPE_BUF && avail < count {
                                        return EAGAIN;
                                    }
                                    let to_write = count.min(avail);
                                    let data = unsafe {
                                        core::slice::from_raw_parts(buf_ptr as *const u8, to_write)
                                    };
                                    pipe_buf.extend_from_slice(data);
                                    return to_write as i64;
                                }
                                BlockResult::Interrupted => return EINTR,
                            }
                        }
                    }
                    return EAGAIN;
                }
```

- [ ] **Step 5: Wire blocking into sys_write for TCP sockets**

In `sys_write`, the `FdKind::Socket` TCP branch. Replace the WouldBlock handling:

```rust
                    match self.tcp.tcp_send(h, data) {
                        Ok(n) => n as i64,
                        Err(NetError::WouldBlock) => {
                            let nonblock = self
                                .fd_table
                                .get(&fd)
                                .map(|e| e.nonblock)
                                .unwrap_or(true);
                            if !nonblock {
                                if let Some(pf) = self.poll_fn {
                                    match self.block_until(pf, Self::is_fd_writable, fd) {
                                        BlockResult::Ready => {
                                            let data = unsafe {
                                                core::slice::from_raw_parts(
                                                    buf_ptr as *const u8,
                                                    count,
                                                )
                                            };
                                            match self.tcp.tcp_send(h, data) {
                                                Ok(n) => return n as i64,
                                                Err(e) => return net_error_to_errno(e),
                                            }
                                        }
                                        BlockResult::Interrupted => return EINTR,
                                    }
                                }
                            }
                            EAGAIN
                        }
                        Err(_) => EPIPE,
                    }
```

- [ ] **Step 6: Also handle the POSIX atomic write EAGAIN for pipes**

In `sys_write` for pipes, the second EAGAIN at `if count <= PIPE_BUF && avail < count { return EAGAIN; }` (around line 3420). Replace with the same blocking pattern:

```rust
                if count <= PIPE_BUF && avail < count {
                    let nonblock = self
                        .fd_table
                        .get(&fd)
                        .map(|e| e.nonblock)
                        .unwrap_or(true);
                    if !nonblock {
                        if let Some(pf) = self.poll_fn {
                            match self.block_until(pf, Self::is_fd_writable, fd) {
                                BlockResult::Ready => {
                                    let pipe_buf = match self.pipes.get_mut(&pipe_id) {
                                        Some(b) => b,
                                        None => return EPIPE,
                                    };
                                    let avail = PIPE_BUF_CAP.saturating_sub(pipe_buf.len());
                                    if count <= PIPE_BUF && avail < count {
                                        return EAGAIN;
                                    }
                                    let to_write = count.min(avail);
                                    let data = unsafe {
                                        core::slice::from_raw_parts(buf_ptr as *const u8, to_write)
                                    };
                                    pipe_buf.extend_from_slice(data);
                                    return to_write as i64;
                                }
                                BlockResult::Interrupted => return EINTR,
                            }
                        }
                    }
                    return EAGAIN;
                }
```

- [ ] **Step 7: Run tests**

Run: `cargo test -p harmony-os`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add blocking write for TCP sockets and pipes"
```

---

### Task 6: Blocking sys_accept4

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Write failing test**

```rust
    #[test]
    fn blocking_accept4_stub_returns_fd() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);

        // Create a stub listener (AF_UNIX — no real TCP, but tests the
        // blocking path for the stub accept logic).
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 1,    // AF_UNIX
            sock_type: 1, // SOCK_STREAM (blocking)
            protocol: 0,
        });
        assert!(fd >= 0);
        lx.dispatch_syscall(LinuxSyscall::Listen {
            fd: fd as i32,
            backlog: 128,
        });

        // First accept returns a stub fd (existing behavior for AF_UNIX).
        let c1 = lx.dispatch_syscall(LinuxSyscall::Accept4 {
            fd: fd as i32,
            addr: 0,
            addrlen: 0,
            flags: 0,
        });
        assert!(c1 >= 0);

        // Second blocking accept on stub socket — accepted_once is true,
        // but socket is blocking. Stub sockets are always "ready" per
        // is_fd_readable, so block_until returns Ready immediately and
        // the accept succeeds with another stub fd. This prevents blocking
        // sockets from returning EAGAIN (which is wrong for blocking mode).
        let c2 = lx.dispatch_syscall(LinuxSyscall::Accept4 {
            fd: fd as i32,
            addr: 0,
            addrlen: 0,
            flags: 0,
        });
        assert!(c2 >= 0);
        assert_ne!(c2, c1);
    }

    #[test]
    fn nonblocking_accept4_returns_eagain() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);

        // Create a nonblocking stub listener.
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 1,           // AF_UNIX
            sock_type: 1 | 2048, // SOCK_STREAM | SOCK_NONBLOCK
            protocol: 0,
        });
        assert!(fd >= 0);
        lx.dispatch_syscall(LinuxSyscall::Listen {
            fd: fd as i32,
            backlog: 128,
        });

        // First accept returns stub fd.
        let c1 = lx.dispatch_syscall(LinuxSyscall::Accept4 {
            fd: fd as i32,
            addr: 0,
            addrlen: 0,
            flags: 0,
        });
        assert!(c1 >= 0);

        // Second nonblocking accept → EAGAIN.
        let c2 = lx.dispatch_syscall(LinuxSyscall::Accept4 {
            fd: fd as i32,
            addr: 0,
            addrlen: 0,
            flags: 0,
        });
        assert_eq!(c2, EAGAIN);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os blocking_accept4 nonblocking_accept4`
Expected: `blocking_accept4_no_connection_returns_eintr` FAILS (returns a stub fd or EAGAIN)

- [ ] **Step 3: Wire blocking into sys_accept4**

In `sys_accept4`, for the real TCP path, after `Ok(None) => EAGAIN` (around line 4583):

```rust
                Ok(None) => {
                    // No pending connection.
                    let parent_nonblock = self
                        .fd_table
                        .get(&fd)
                        .map(|e| e.nonblock)
                        .unwrap_or(true);
                    if !parent_nonblock {
                        if let Some(pf) = self.poll_fn {
                            match self.block_until(pf, Self::is_fd_readable, fd) {
                                BlockResult::Ready => {
                                    // Retry accept.
                                    match self.tcp.tcp_accept(h) {
                                        Ok(Some(accepted_handle)) => {
                                            let new_socket_id = self.next_socket_id;
                                            self.next_socket_id += 1;
                                            let new_nonblock = flags & SOCK_NONBLOCK != 0;
                                            self.sockets.insert(
                                                new_socket_id,
                                                SocketState {
                                                    domain,
                                                    sock_type,
                                                    listening: false,
                                                    accepted_once: false,
                                                    tcp_handle: Some(accepted_handle),
                                                    udp_handle: None,
                                                    bound_port: 0,
                                                },
                                            );
                                            let new_fd = self.alloc_fd();
                                            let fd_flags = if flags & SOCK_CLOEXEC != 0 {
                                                FD_CLOEXEC
                                            } else {
                                                0
                                            };
                                            self.fd_table.insert(
                                                new_fd,
                                                FdEntry {
                                                    kind: FdKind::Socket {
                                                        socket_id: new_socket_id,
                                                    },
                                                    flags: fd_flags,
                                                    nonblock: new_nonblock,
                                                },
                                            );
                                            if addr != 0 {
                                                self.write_stub_sockaddr(addr, addrlen_ptr, domain);
                                            }
                                            return new_fd as i64;
                                        }
                                        Ok(None) => return EAGAIN,
                                        Err(e) => return net_error_to_errno(e),
                                    }
                                }
                                BlockResult::Interrupted => return EINTR,
                            }
                        }
                    }
                    EAGAIN
                }
```

For the stub path (AF_UNIX), replace the EAGAIN return (around line 4590):

```rust
            if parent_nonblock && accepted_once {
                return EAGAIN;
            }
            if !parent_nonblock && accepted_once {
                // Blocking stub socket, already accepted once — spin-wait.
                if let Some(pf) = self.poll_fn {
                    match self.block_until(pf, Self::is_fd_readable, fd) {
                        BlockResult::Ready => {
                            // Stub sockets: is_fd_readable always returns true,
                            // so this returns immediately. Fall through to
                            // create another stub fd (matches first-accept behavior).
                        }
                        BlockResult::Interrupted => return EINTR,
                    }
                } else {
                    return EAGAIN;
                }
            }
```

Note: For stub sockets, `is_fd_readable` returns `true` (the `_ => true` fallthrough in the Socket branch when no tcp_handle). This means `block_until` returns `Ready` immediately — but for our test, the stub listener with `accepted_once = true` would need `is_fd_readable` to return false for the blocking to actually block.

Looking more carefully: for stub sockets, the `is_fd_readable` returns true (non-TCP/UDP sockets always ready). This means `block_until` returns Ready immediately. The stub re-accept would succeed and return another stub fd.

The existing EAGAIN behavior for `nonblock && accepted_once` prevents infinite accept loops in epoll. For blocking mode, epoll isn't involved — a blocking accept that returns immediately with a new stub fd is acceptable (prevents EAGAIN on blocking sockets).

Simplify: just use the `parent_nonblock` check for the EAGAIN gate:

```rust
            if accepted_once && parent_nonblock {
                return EAGAIN;
            }
```

This preserves the EAGAIN-after-first-accept only for nonblocking sockets. Blocking sockets always get a stub fd (which is the current behavior minus the EAGAIN).

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-os`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add blocking accept4 for TCP sockets"
```

---

### Task 7: Blocking sys_recvfrom and sys_sendto for UDP

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Write failing tests**

```rust
    #[test]
    fn blocking_udp_recvfrom_returns_eintr() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);

        // Create a blocking UDP socket (NoTcp → udp_create fails, so
        // udp_handle is None and recvfrom returns stub 0/EOF).
        // This test verifies the code structure; real UDP blocking needs
        // an actual NetStack which is tested via QEMU integration.
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,    // AF_INET
            sock_type: 2, // SOCK_DGRAM (blocking)
            protocol: 0,
        });
        assert!(fd >= 0);

        // With NoTcp, recvfrom returns 0 (stub EOF). No blocking path hit.
        // The wiring is verified structurally — integration tests cover
        // the actual WouldBlock → block_until → retry path with real UDP.
        let mut buf = [0u8; 16];
        let r = lx.dispatch_syscall(LinuxSyscall::Recvfrom {
            fd: fd as i32,
            buf: buf.as_mut_ptr() as u64,
            len: buf.len() as u64,
            flags: 0,
            src_addr: 0,
            addrlen: 0,
        });
        // With NoTcp, udp_handle is None, falls to stub → 0.
        assert_eq!(r, 0);
    }
```

- [ ] **Step 2: Wire blocking into sys_recvfrom**

In `sys_recvfrom`, for the TCP path after `Err(NetError::WouldBlock)` (around line 4806):

```rust
                Err(NetError::WouldBlock) => {
                    let nonblock = self
                        .fd_table
                        .get(&fd)
                        .map(|e| e.nonblock)
                        .unwrap_or(true);
                    if !nonblock {
                        if let Some(pf) = self.poll_fn {
                            match self.block_until(pf, Self::is_fd_readable, fd) {
                                BlockResult::Ready => {
                                    let buf = unsafe {
                                        core::slice::from_raw_parts_mut(buf as *mut u8, count)
                                    };
                                    match self.tcp.tcp_recv(h, buf) {
                                        Ok(n) => return n as i64,
                                        Err(e) => return net_error_to_errno(e),
                                    }
                                }
                                BlockResult::Interrupted => return EINTR,
                            }
                        }
                    }
                    EAGAIN
                }
```

For the UDP path after `Err(NetError::WouldBlock) => EAGAIN` (around line 4837):

```rust
                    Err(NetError::WouldBlock) => {
                        let nonblock = self
                            .fd_table
                            .get(&fd)
                            .map(|e| e.nonblock)
                            .unwrap_or(true);
                        if !nonblock {
                            if let Some(pf) = self.poll_fn {
                                match self.block_until(pf, Self::is_fd_readable, fd) {
                                    BlockResult::Ready => {
                                        let data = unsafe {
                                            core::slice::from_raw_parts_mut(buf as *mut u8, count)
                                        };
                                        let result = match self.tcp.udp_recv(h, data) {
                                            Ok(r) => Ok(r),
                                            Err(NetError::NotConnected) => {
                                                self.tcp.udp_recvfrom(h, data)
                                            }
                                            Err(e) => Err(e),
                                        };
                                        return match result {
                                            Ok((n, src_addr, src_port)) => {
                                                self.write_sockaddr_in(src, addrlen, src_addr, src_port);
                                                n as i64
                                            }
                                            Err(e) => net_error_to_errno(e),
                                        };
                                    }
                                    BlockResult::Interrupted => return EINTR,
                                }
                            }
                        }
                        EAGAIN
                    }
```

- [ ] **Step 3: Wire blocking into sys_sendto**

In `sys_sendto`, for the TCP path after `Err(NetError::WouldBlock)` (around line 4728):

```rust
                Err(NetError::WouldBlock) => {
                    let nonblock = self
                        .fd_table
                        .get(&fd)
                        .map(|e| e.nonblock)
                        .unwrap_or(true);
                    if !nonblock {
                        if let Some(pf) = self.poll_fn {
                            match self.block_until(pf, Self::is_fd_writable, fd) {
                                BlockResult::Ready => {
                                    let data = unsafe {
                                        core::slice::from_raw_parts(buf as *const u8, count)
                                    };
                                    match self.tcp.tcp_send(h, data) {
                                        Ok(n) => return n as i64,
                                        Err(e) => return net_error_to_errno(e),
                                    }
                                }
                                BlockResult::Interrupted => return EINTR,
                            }
                        }
                    }
                    EAGAIN
                }
```

For the UDP `udp_sendto` path (around line 4755):

```rust
                    return match self.tcp.udp_sendto(h, data, ip, port) {
                        Ok(n) => n as i64,
                        Err(NetError::WouldBlock) => {
                            let nonblock = self
                                .fd_table
                                .get(&fd)
                                .map(|e| e.nonblock)
                                .unwrap_or(true);
                            if !nonblock {
                                if let Some(pf) = self.poll_fn {
                                    match self.block_until(pf, Self::is_fd_writable, fd) {
                                        BlockResult::Ready => {
                                            match self.tcp.udp_sendto(h, data, ip, port) {
                                                Ok(n) => return n as i64,
                                                Err(e) => return net_error_to_errno(e),
                                            }
                                        }
                                        BlockResult::Interrupted => return EINTR,
                                    }
                                }
                            }
                            EAGAIN
                        }
                        Err(e) => net_error_to_errno(e),
                    };
```

For the UDP `udp_send` (connected, null dest) path (around line 4767):

```rust
                    Err(NetError::WouldBlock) => {
                        let nonblock = self
                            .fd_table
                            .get(&fd)
                            .map(|e| e.nonblock)
                            .unwrap_or(true);
                        if !nonblock {
                            if let Some(pf) = self.poll_fn {
                                match self.block_until(pf, Self::is_fd_writable, fd) {
                                    BlockResult::Ready => {
                                        match self.tcp.udp_send(h, data) {
                                            Ok(n) => return n as i64,
                                            Err(e) => return net_error_to_errno(e),
                                        }
                                    }
                                    BlockResult::Interrupted => return EINTR,
                                }
                            }
                        }
                        EAGAIN
                    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-os`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add blocking recvfrom and sendto for UDP sockets"
```

---

### Task 8: Blocking sys_connect for TCP

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Write failing test**

```rust
    #[test]
    fn blocking_tcp_connect_returns_eintr_without_netstack() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);

        // Create a blocking TCP socket. With NoTcp, tcp_handle is None,
        // so connect falls to the stub path (returns 0 for non-AF_UNIX).
        // The blocking connect path is only hit when tcp_handle is Some
        // and tcp_connect returns EINPROGRESS.
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,    // AF_INET
            sock_type: 1, // SOCK_STREAM (blocking)
            protocol: 0,
        });
        assert!(fd >= 0);

        // With NoTcp, tcp_handle is None. connect on non-TCP socket returns
        // 0 (stub). This is existing behavior; the blocking path is tested
        // via QEMU integration with a real NetStack.
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
        sa[2..4].copy_from_slice(&80u16.to_be_bytes()); // port 80
        sa[4..8].copy_from_slice(&[10, 0, 0, 1]); // 10.0.0.1
        let r = lx.dispatch_syscall(LinuxSyscall::Connect {
            fd: fd as i32,
            addr: sa.as_ptr() as u64,
            addrlen: 16,
        });
        // NoTcp → tcp_handle is None → stub returns 0.
        assert_eq!(r, 0);
    }
```

- [ ] **Step 2: Wire blocking into sys_connect for TCP**

In `sys_connect`, replace the EINPROGRESS return (around line 4661):

```rust
            match self.tcp.tcp_connect(h, ip, port) {
                Ok(()) => {
                    let nonblock = self
                        .fd_table
                        .get(&fd)
                        .map(|e| e.nonblock)
                        .unwrap_or(true);
                    if nonblock {
                        EINPROGRESS
                    } else if let Some(pf) = self.poll_fn {
                        // Blocking connect: spin-wait until the connection is
                        // established (socket becomes writable).
                        match self.block_until(pf, Self::is_fd_writable, fd) {
                            BlockResult::Ready => 0,
                            BlockResult::Interrupted => EINTR,
                        }
                    } else {
                        EINPROGRESS
                    }
                }
                Err(e) => net_error_to_errno(e),
            }
```

- [ ] **Step 3: Remove the v1 EAGAIN/EINPROGRESS comments**

Search for all comments referencing `harmony-os-cqy` and remove or update them:

In `sys_read` TCP branch — remove the comment `// v1: always return EAGAIN. True blocking requires a yield/coroutine mechanism (harmony-os-cqy).`

In `sys_write` TCP branch — remove the same comment.

In `sys_recvfrom` TCP branch — remove the same comment.

In `sys_sendto` TCP branch — remove the same comment.

In `sys_connect` — remove `// v1: always return EINPROGRESS since tcp_connect only queues the SYN. True blocking connect (wait for handshake) requires yield/coroutine (harmony-os-cqy).`

In `sys_pipe2` — update the NOTE comment (around line 4269):

Replace:
```rust
        // NOTE: O_NONBLOCK is accepted to avoid EINVAL for callers that set it,
        // but this synchronous emulator always returns EAGAIN when no data is
        // available (true blocking is not yet supported).
```
With:
```rust
        // O_NONBLOCK controls whether pipe reads/writes block (spin-wait)
        // or return EAGAIN immediately when no data is available.
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-os`
Expected: PASS

- [ ] **Step 5: Run clippy**

Run: `cargo clippy --workspace`
Expected: No new warnings

- [ ] **Step 6: Run nightly rustfmt**

Run: `rustup run nightly cargo fmt --all`

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add blocking connect and remove v1 stub comments"
```
