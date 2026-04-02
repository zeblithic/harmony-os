# SSH Session Timeout Guards Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent bricked unikernel when SSH clients hang by adding proper select() timeout/readiness, TCP keepalive, and an idle watchdog.

**Architecture:** Three layers: (1) rewrite sys_select/sys_poll with spin-wait + real fd readiness checking + timeout support, driven by a `poll_fn` callback; (2) enable smoltcp TCP keepalive on accepted sockets; (3) dispatch-level idle watchdog as safety net.

**Tech Stack:** Rust (no_std), smoltcp 0.11 TCP keepalive API, x86_64 PIT timer

---

### Task 1: Add `tcp_set_keepalive` to TcpProvider Trait

**Files:**
- Modify: `crates/harmony-netstack/src/tcp.rs:34-66` (TcpProvider trait)
- Modify: `crates/harmony-netstack/src/stack.rs:459-476` (NetStack impl)
- Modify: `crates/harmony-os/src/linuxulator.rs:134-177` (NoTcp impl)
- Modify: `crates/harmony-boot/src/main.rs:654-674` (RawPtrTcpProvider impl)

- [ ] **Step 1: Add method to TcpProvider trait**

In `crates/harmony-netstack/src/tcp.rs`, add after `tcp_can_send` (line 50):

```rust
    /// Configure TCP keepalive. `Some(ms)` enables with the given interval;
    /// `None` disables. No-op for invalid handles.
    fn tcp_set_keepalive(&mut self, handle: TcpHandle, interval_ms: Option<u64>);
```

- [ ] **Step 2: Implement in NetStack**

In `crates/harmony-netstack/src/stack.rs`, add after `tcp_can_send` impl (after line 471):

```rust
    fn tcp_set_keepalive(&mut self, handle: TcpHandle, interval_ms: Option<u64>) {
        if let Ok(h) = self.resolve_tcp(handle) {
            let duration = interval_ms.map(|ms| smoltcp::time::Duration::from_millis(ms));
            self.sockets.get_mut::<tcp::Socket>(h).set_keep_alive(duration);
        }
    }
```

- [ ] **Step 3: Implement in NoTcp stub**

In `crates/harmony-os/src/linuxulator.rs`, add after `tcp_can_send` in NoTcp impl (after line 172):

```rust
    fn tcp_set_keepalive(&mut self, _: TcpHandle, _: Option<u64>) {}
```

- [ ] **Step 4: Implement in RawPtrTcpProvider**

In `crates/harmony-boot/src/main.rs`, add after `tcp_can_send` in RawPtrTcpProvider impl (after line 662):

```rust
    fn tcp_set_keepalive(&mut self, h: harmony_netstack::TcpHandle, interval_ms: Option<u64>) {
        unsafe { (*self.0).tcp_set_keepalive(h, interval_ms) }
    }
```

- [ ] **Step 5: Verify compilation**

Run: `cargo test --workspace`
Expected: All tests pass (no behavioral change yet, just new method)

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-netstack/src/tcp.rs crates/harmony-netstack/src/stack.rs crates/harmony-os/src/linuxulator.rs crates/harmony-boot/src/main.rs
git commit -m "feat(netstack): add tcp_set_keepalive to TcpProvider trait"
```

---

### Task 2: Auto-Enable Keepalive on Accepted TCP Sockets

**Files:**
- Modify: `crates/harmony-netstack/src/stack.rs:295-340` (tcp_accept)

- [ ] **Step 1: Enable keepalive after successful accept**

In `crates/harmony-netstack/src/stack.rs`, in `tcp_accept`, after the accepted handle is returned successfully, add keepalive configuration. Find the final `Ok(Some(handle))` return at the end of `tcp_accept`. Just before that return, add:

```rust
        // Enable TCP keepalive on accepted connections (60s interval).
        // Detects dead peers when the remote host disappears without FIN.
        self.sockets
            .get_mut::<tcp::Socket>(smoltcp_handle)
            .set_keep_alive(Some(smoltcp::time::Duration::from_millis(60_000)));
```

Note: `smoltcp_handle` is the original handle that transitioned to Established (not the new listener replacement). This is the socket we want keepalive on.

- [ ] **Step 2: Verify compilation and tests**

Run: `cargo test --workspace`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-netstack/src/stack.rs
git commit -m "feat(netstack): auto-enable 60s TCP keepalive on accepted sockets"
```

---

### Task 3: Wire setsockopt(SO_KEEPALIVE) in Linuxulator

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs:4631-4643` (sys_setsockopt)

- [ ] **Step 1: Add SO_KEEPALIVE handling to sys_setsockopt**

Replace the current `sys_setsockopt` stub (lines 4631-4643) with:

```rust
    fn sys_setsockopt(
        &mut self,
        fd: i32,
        level: i32,
        optname: i32,
        optval: u64,
        optlen: u32,
    ) -> i64 {
        let socket_id = match self.require_socket(fd) {
            Ok(id) => id,
            Err(e) => return e,
        };

        const SOL_SOCKET: i32 = 1;
        const SO_KEEPALIVE: i32 = 9;

        if level == SOL_SOCKET && optname == SO_KEEPALIVE && optlen >= 4 {
            let val_bytes =
                unsafe { core::slice::from_raw_parts(optval as usize as *const u8, 4) };
            let val = i32::from_ne_bytes(val_bytes.try_into().unwrap());
            if let Some(h) = self.sockets.get(&socket_id).and_then(|s| s.tcp_handle) {
                let interval = if val != 0 { Some(60_000u64) } else { None };
                self.tcp.tcp_set_keepalive(h, interval);
            }
        }
        // All other options: silent success (existing behavior).
        0
    }
```

Note: `sys_setsockopt` signature changes from `&self` to `&mut self` because `tcp_set_keepalive` requires `&mut self` on the TcpProvider. Find the call site in `dispatch_syscall` and update accordingly (the match arm for `Setsockopt`).

- [ ] **Step 2: Update dispatch_syscall call site if needed**

Search for the `Setsockopt` match arm in `dispatch_syscall`. If it calls `self.sys_setsockopt(...)`, the `&mut self` receiver is already available since `dispatch_syscall` takes `&mut self`. No change needed at the call site — only the method signature changes.

- [ ] **Step 3: Verify compilation and tests**

Run: `cargo test --workspace`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): wire setsockopt(SO_KEEPALIVE) to smoltcp"
```

---

### Task 4: Add `poll_fn` Callback to Linuxulator

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs:2308-2402` (struct + constructor)
- Modify: `crates/harmony-boot/src/main.rs` (set poll_fn after Linuxulator creation)

- [ ] **Step 1: Add poll_fn field to Linuxulator struct**

In `crates/harmony-os/src/linuxulator.rs`, add to the `Linuxulator` struct (after `embedded_fs` field, line 2401):

```rust
    /// Network poll callback for blocking operations (select/poll).
    /// Drives VirtIO RX/TX + smoltcp processing and returns current
    /// time in milliseconds. Set by the kernel at init.
    poll_fn: Option<fn() -> u64>,
```

- [ ] **Step 2: Initialize to None in constructor**

In `with_tcp_and_arena` (line 2470), add before the closing brace:

```rust
            poll_fn: None,
```

- [ ] **Step 3: Add setter method**

After `with_tcp_and_arena`, add:

```rust
    /// Set the network poll callback. Called during blocking select/poll
    /// to drive the network stack and read the PIT timer.
    pub fn set_poll_fn(&mut self, f: fn() -> u64) {
        self.poll_fn = Some(f);
    }
```

- [ ] **Step 4: Create kernel poll function and wire it in main.rs**

In `crates/harmony-boot/src/main.rs`, inside the `kernel_continue` function, add a helper function (near `poll_network`, around line 700):

```rust
/// Network poll + PIT read, callable from Linuxulator during blocking ops.
fn kernel_poll_and_time() -> u64 {
    unsafe {
        poll_network();
        (*PIT_PTR).now_ms()
    }
}
```

Then find where the Linuxulator is created and `set_embedded_fs` is called. After `set_embedded_fs`, add:

```rust
                    lx.set_poll_fn(kernel_poll_and_time);
```

- [ ] **Step 5: Verify compilation and tests**

Run: `cargo test --workspace`
Expected: All tests pass (poll_fn not called yet)

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs crates/harmony-boot/src/main.rs
git commit -m "feat(linuxulator): add poll_fn callback for blocking select/poll"
```

---

### Task 5: Add fd Readiness Checking Helpers

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs` (new helper methods)

- [ ] **Step 1: Add is_fd_readable helper**

Add a private method to `impl<B: SyscallBackend, T: TcpProvider> Linuxulator<B, T>`, near the existing `sys_select`/`sys_poll` methods:

```rust
    /// Check if an fd is ready for reading (has data or EOF).
    fn is_fd_readable(&self, fd: i32) -> bool {
        let entry = match self.fd_table.get(&fd) {
            Some(e) => e,
            None => return false,
        };
        match &entry.kind {
            FdKind::PipeRead { pipe_id } => {
                let buf_nonempty = self
                    .pipes
                    .get(pipe_id)
                    .map(|b| !b.is_empty())
                    .unwrap_or(false);
                if buf_nonempty {
                    return true;
                }
                // EOF: write end is closed (no PipeWrite fd references this pipe_id).
                !self.fd_table.values().any(|e| {
                    matches!(&e.kind, FdKind::PipeWrite { pipe_id: pid } if *pid == *pipe_id)
                })
            }
            FdKind::Socket { socket_id } => {
                if let Some(state) = self.sockets.get(socket_id) {
                    if let Some(h) = state.tcp_handle {
                        let tcp_state = self.tcp.tcp_state(h);
                        // Listener: readable if a connection is ready to accept.
                        if state.listening {
                            return tcp_state == TcpSocketState::Established;
                        }
                        // Data socket: readable if recv buffer has data or EOF.
                        return self.tcp.tcp_can_recv(h)
                            || tcp_state == TcpSocketState::CloseWait
                            || tcp_state == TcpSocketState::Closed;
                    }
                }
                false
            }
            // Serial/stdout/stderr, eventfd, timerfd, signalfd, files: always readable.
            _ => true,
        }
    }

    /// Check if an fd is ready for writing (buffer space available).
    fn is_fd_writable(&self, fd: i32) -> bool {
        let entry = match self.fd_table.get(&fd) {
            Some(e) => e,
            None => return false,
        };
        match &entry.kind {
            FdKind::PipeWrite { .. } => true, // unbounded buffer
            FdKind::Socket { socket_id } => {
                if let Some(state) = self.sockets.get(socket_id) {
                    if let Some(h) = state.tcp_handle {
                        let tcp_state = self.tcp.tcp_state(h);
                        return !state.listening
                            && self.tcp.tcp_can_send(h)
                            && tcp_state == TcpSocketState::Established;
                    }
                }
                false
            }
            // Everything else: always writable.
            _ => true,
        }
    }
```

- [ ] **Step 2: Verify compilation and tests**

Run: `cargo test --workspace`
Expected: All tests pass (helpers not called yet)

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add is_fd_readable/is_fd_writable helpers"
```

---

### Task 6: Rewrite sys_select with Spin-Wait + Timeout

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs:7812-7856` (sys_select)

- [ ] **Step 1: Replace sys_select implementation**

Replace the current `sys_select` method (lines 7812-7856) with:

```rust
    /// Linux select(2): synchronous I/O multiplexing via fd_set bitmasks.
    ///
    /// Spin-waits until at least one fd is ready or the timeout expires.
    /// Calls poll_fn on each iteration to drive the network stack.
    fn sys_select(
        &self,
        nfds: i32,
        readfds: u64,
        writefds: u64,
        exceptfds: u64,
        timeout_ptr: u64,
    ) -> i64 {
        if !(0..=1024).contains(&nfds) {
            return EINVAL;
        }

        // Parse struct timeval { tv_sec: i64, tv_usec: i64 } → deadline.
        let deadline_ms: u64 = if timeout_ptr == 0 {
            u64::MAX // NULL → block forever
        } else {
            let tv = unsafe { core::slice::from_raw_parts(timeout_ptr as *const u8, 16) };
            let tv_sec = i64::from_ne_bytes(tv[0..8].try_into().unwrap());
            let tv_usec = i64::from_ne_bytes(tv[8..16].try_into().unwrap());
            let timeout_ms = (tv_sec as u64).saturating_mul(1000)
                .saturating_add((tv_usec as u64) / 1000);
            if timeout_ms == 0 {
                // {0,0} → non-blocking: check once and return.
                return self.select_check_once(nfds, readfds, writefds, exceptfds);
            }
            let now = self.poll_fn.map(|f| f()).unwrap_or(0);
            now.saturating_add(timeout_ms)
        };

        // Save copies of the input fd_sets (select overwrites them with results).
        let read_bytes = (nfds as usize).div_ceil(8);
        let mut saved_readfds = [0u8; 128];
        let mut saved_writefds = [0u8; 128];
        if readfds != 0 && read_bytes > 0 {
            let src = unsafe { core::slice::from_raw_parts(readfds as *const u8, read_bytes) };
            saved_readfds[..read_bytes].copy_from_slice(src);
        }
        if writefds != 0 && read_bytes > 0 {
            let src = unsafe { core::slice::from_raw_parts(writefds as *const u8, read_bytes) };
            saved_writefds[..read_bytes].copy_from_slice(src);
        }

        loop {
            // Drive the network stack and get current time.
            let now = self.poll_fn.map(|f| f()).unwrap_or(0);

            // Restore input fd_sets (previous iteration may have cleared bits).
            if readfds != 0 && read_bytes > 0 {
                let dst = unsafe { core::slice::from_raw_parts_mut(readfds as *mut u8, read_bytes) };
                dst.copy_from_slice(&saved_readfds[..read_bytes]);
            }
            if writefds != 0 && read_bytes > 0 {
                let dst = unsafe { core::slice::from_raw_parts_mut(writefds as *mut u8, read_bytes) };
                dst.copy_from_slice(&saved_writefds[..read_bytes]);
            }

            let ready = self.select_check_once(nfds, readfds, writefds, exceptfds);
            if ready > 0 {
                return ready;
            }

            // Timeout expired.
            if now >= deadline_ms {
                // Clear all fd_sets on timeout (Linux convention).
                if readfds != 0 {
                    unsafe { core::ptr::write_bytes(readfds as *mut u8, 0, read_bytes); }
                }
                if writefds != 0 {
                    unsafe { core::ptr::write_bytes(writefds as *mut u8, 0, read_bytes); }
                }
                if exceptfds != 0 {
                    unsafe { core::ptr::write_bytes(exceptfds as *mut u8, 0, read_bytes); }
                }
                return 0;
            }

            core::hint::spin_loop();
        }
    }

    /// Single-pass readiness check for select(). Clears bits for non-ready fds,
    /// returns count of ready fds.
    fn select_check_once(
        &self,
        nfds: i32,
        readfds: u64,
        writefds: u64,
        exceptfds: u64,
    ) -> i64 {
        let mut ready = 0i64;
        let bytes = (nfds as usize).div_ceil(8);

        // Check readfds: clear bits for fds that are NOT readable.
        if readfds != 0 {
            let set = unsafe { core::slice::from_raw_parts_mut(readfds as *mut u8, bytes) };
            for fd in 0..nfds {
                let byte_idx = fd as usize / 8;
                let bit_idx = fd as usize % 8;
                if set[byte_idx] & (1 << bit_idx) != 0 {
                    if self.is_fd_readable(fd) {
                        ready += 1;
                    } else {
                        set[byte_idx] &= !(1 << bit_idx);
                    }
                }
            }
        }

        // Check writefds: clear bits for fds that are NOT writable.
        if writefds != 0 {
            let set = unsafe { core::slice::from_raw_parts_mut(writefds as *mut u8, bytes) };
            for fd in 0..nfds {
                let byte_idx = fd as usize / 8;
                let bit_idx = fd as usize % 8;
                if set[byte_idx] & (1 << bit_idx) != 0 {
                    if self.is_fd_writable(fd) {
                        ready += 1;
                    } else {
                        set[byte_idx] &= !(1 << bit_idx);
                    }
                }
            }
        }

        // Clear exceptfds — we never report exceptional conditions.
        if exceptfds != 0 {
            unsafe { core::ptr::write_bytes(exceptfds as *mut u8, 0, bytes); }
        }

        ready
    }
```

- [ ] **Step 2: Verify compilation and tests**

Run: `cargo test --workspace`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): rewrite sys_select with spin-wait, readiness, and timeout"
```

---

### Task 7: Rewrite sys_poll and sys_ppoll with Spin-Wait + Timeout

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs:7773-7806` (sys_poll)

- [ ] **Step 1: Update dispatch_syscall call sites**

In `crates/harmony-os/src/linuxulator.rs`, the dispatch arms at line ~3232-3233 currently read:

```rust
            LinuxSyscall::Poll { fds, nfds, .. } => self.sys_poll(fds, nfds),
            LinuxSyscall::Ppoll { fds, nfds, .. } => self.sys_poll(fds, nfds),
```

Replace with:

```rust
            LinuxSyscall::Poll { fds, nfds, timeout } => self.sys_poll(fds, nfds, timeout),
            LinuxSyscall::Ppoll { fds, nfds, tmo_ptr, sigmask, .. } => {
                self.sys_ppoll(fds, nfds, tmo_ptr, sigmask)
            }
```

- [ ] **Step 2: Replace sys_poll implementation**

Replace the current `sys_poll` method (lines 7773-7806) with:

```rust
    /// Linux poll(2): synchronous I/O multiplexing via pollfd array.
    ///
    /// Spin-waits until at least one fd is ready or the timeout expires.
    fn sys_poll(&self, fds_ptr: u64, nfds: u64, timeout_ms: i32) -> i64 {
        const POLL_MAX_FDS: u64 = 1 << 20;
        if nfds > POLL_MAX_FDS {
            return EINVAL;
        }
        if fds_ptr == 0 && nfds > 0 {
            return EFAULT;
        }

        const POLLIN: i16 = 0x01;
        const POLLOUT: i16 = 0x04;
        const POLLERR: i16 = 0x08;
        const POLLHUP: i16 = 0x10;
        const POLLNVAL: i16 = 0x20;

        let deadline_ms: u64 = if timeout_ms < 0 {
            u64::MAX // negative → block forever
        } else if timeout_ms == 0 {
            // Non-blocking: check once.
            return self.poll_check_once(fds_ptr, nfds, POLLIN, POLLOUT, POLLERR, POLLHUP, POLLNVAL);
        } else {
            let now = self.poll_fn.map(|f| f()).unwrap_or(0);
            now.saturating_add(timeout_ms as u64)
        };

        loop {
            let now = self.poll_fn.map(|f| f()).unwrap_or(0);

            let ready = self.poll_check_once(fds_ptr, nfds, POLLIN, POLLOUT, POLLERR, POLLHUP, POLLNVAL);
            if ready > 0 {
                return ready;
            }

            if now >= deadline_ms {
                return 0;
            }

            core::hint::spin_loop();
        }
    }

    /// Single-pass readiness check for poll(). Writes revents and returns ready count.
    fn poll_check_once(
        &self,
        fds_ptr: u64,
        nfds: u64,
        pollin: i16,
        pollout: i16,
        _pollerr: i16,
        pollhup: i16,
        pollnval: i16,
    ) -> i64 {
        let mut ready_count = 0i64;
        for i in 0..nfds {
            let base = fds_ptr as usize + (i as usize) * 8;
            let fd_bytes = unsafe { core::slice::from_raw_parts(base as *const u8, 4) };
            let fd = i32::from_ne_bytes(fd_bytes.try_into().unwrap());
            let events_bytes = unsafe { core::slice::from_raw_parts((base + 4) as *const u8, 2) };
            let events = i16::from_ne_bytes(events_bytes.try_into().unwrap());

            let revents = if fd < 0 {
                0i16
            } else if !self.fd_table.contains_key(&fd) {
                pollnval
            } else {
                let mut r = 0i16;
                if events & pollin != 0 && self.is_fd_readable(fd) {
                    r |= pollin;
                }
                if events & pollout != 0 && self.is_fd_writable(fd) {
                    r |= pollout;
                }
                // Check for HUP on sockets (connection closed).
                if let Some(entry) = self.fd_table.get(&fd) {
                    if let FdKind::Socket { socket_id } = &entry.kind {
                        if let Some(state) = self.sockets.get(socket_id) {
                            if let Some(h) = state.tcp_handle {
                                let tcp_state = self.tcp.tcp_state(h);
                                if tcp_state == TcpSocketState::Closed
                                    || tcp_state == TcpSocketState::Closing
                                {
                                    r |= pollhup;
                                }
                            }
                        }
                    }
                }
                r
            };

            if revents != 0 {
                ready_count += 1;
            }
            let revents_out = unsafe { core::slice::from_raw_parts_mut((base + 6) as *mut u8, 2) };
            revents_out.copy_from_slice(&revents.to_ne_bytes());
        }
        ready_count
    }
```

- [ ] **Step 3: Update sys_ppoll to parse timespec and delegate**

Find `sys_ppoll` in the codebase. It should parse a `struct timespec { tv_sec: i64, tv_nsec: i64 }` and convert to milliseconds, then call `sys_poll`. Update it to pass the timeout through:

```rust
    fn sys_ppoll(&self, fds_ptr: u64, nfds: u64, timeout_ptr: u64, _sigmask: u64) -> i64 {
        let timeout_ms: i32 = if timeout_ptr == 0 {
            -1 // NULL → block forever
        } else {
            let ts = unsafe { core::slice::from_raw_parts(timeout_ptr as *const u8, 16) };
            let tv_sec = i64::from_ne_bytes(ts[0..8].try_into().unwrap());
            let tv_nsec = i64::from_ne_bytes(ts[8..16].try_into().unwrap());
            let ms = (tv_sec as i64).saturating_mul(1000)
                .saturating_add(tv_nsec / 1_000_000);
            ms.min(i32::MAX as i64) as i32
        };
        self.sys_poll(fds_ptr, nfds, timeout_ms)
    }
```

- [ ] **Step 4: Verify compilation and tests**

Run: `cargo test --workspace`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): rewrite sys_poll/sys_ppoll with spin-wait and readiness"
```

---

### Task 8: Add Dispatch Idle Watchdog

**Files:**
- Modify: `crates/harmony-boot/src/main.rs:1492-1540` (dispatch function)

- [ ] **Step 1: Add watchdog statics**

In `crates/harmony-boot/src/main.rs`, near the other static variables in `kernel_continue` (look for `static mut FORK_COUNT`), add:

```rust
        /// Last time a TCP read/write returned real data (ms). 0 = no session yet.
        static mut LAST_TCP_IO_MS: u64 = 0;
        /// Idle kill threshold: 5 minutes with no TCP I/O → force exit.
        const IDLE_KILL_THRESHOLD_MS: u64 = 300_000;
```

- [ ] **Step 2: Add watchdog check at top of dispatch**

In the `dispatch` function, after the `poll_network()` call at line 1509 and before the fork handling, add:

```rust
            // ── Idle watchdog ──────────────────────────────────────────
            // If no TCP I/O has occurred for IDLE_KILL_THRESHOLD_MS,
            // force-terminate the session. Prevents bricked unikernel
            // when SSH clients hang.
            unsafe {
                if LAST_TCP_IO_MS != 0 {
                    let now = (*PIT_PTR).now_ms();
                    if now.saturating_sub(LAST_TCP_IO_MS) > IDLE_KILL_THRESHOLD_MS {
                        serial_write_str(b"[WATCHDOG] idle timeout - killing session\n");
                        return syscall::SyscallResult {
                            retval: -1,
                            exited: true,
                            exit_code: 62,
                        };
                    }
                }
            }
```

- [ ] **Step 3: Add TCP I/O tracking after syscall return**

In the `dispatch` function, after `let retval = active.handle_syscall(nr, args);` (line 1529) and before the second `poll_network()` call, add:

```rust
            // Track TCP I/O for watchdog. Syscall numbers:
            // 0=read, 1=write, 17=pread64, 18=pwrite64, 43=accept, 44=sendto, 45=recvfrom
            const SYS_READ: u64 = 0;
            const SYS_WRITE: u64 = 1;
            const SYS_ACCEPT: u64 = 43;
            const SYS_ACCEPT4: u64 = 288;
            unsafe {
                match nr {
                    SYS_ACCEPT | SYS_ACCEPT4 if retval >= 0 => {
                        LAST_TCP_IO_MS = (*PIT_PTR).now_ms();
                    }
                    SYS_READ | SYS_WRITE if retval > 0 => {
                        // Only count if the fd is a TCP socket.
                        // args[0] is the fd for read/write.
                        let fd = args[0] as i32;
                        if let Some(ref lx) = LINUXULATOR {
                            let active = lx.active_process();
                            if active.fd_is_tcp_socket(fd) {
                                LAST_TCP_IO_MS = (*PIT_PTR).now_ms();
                            }
                        }
                    }
                    _ => {}
                }
            }
```

- [ ] **Step 4: Add fd_is_tcp_socket helper to Linuxulator**

In `crates/harmony-os/src/linuxulator.rs`, add a public method:

```rust
    /// Check if an fd is a TCP socket (for watchdog tracking).
    pub fn fd_is_tcp_socket(&self, fd: i32) -> bool {
        self.fd_table
            .get(&fd)
            .map(|e| {
                if let FdKind::Socket { socket_id } = &e.kind {
                    self.sockets
                        .get(socket_id)
                        .map(|s| s.tcp_handle.is_some())
                        .unwrap_or(false)
                } else {
                    false
                }
            })
            .unwrap_or(false)
    }
```

- [ ] **Step 5: Verify compilation and tests**

Run: `cargo test --workspace`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-boot/src/main.rs crates/harmony-os/src/linuxulator.rs
git commit -m "feat(boot): add dispatch idle watchdog (5min TCP inactivity → force exit)"
```

---

### Task 9: Format, Lint, and QEMU Integration Test

**Files:**
- All modified files

- [ ] **Step 1: Run nightly rustfmt**

Run: `cargo +nightly fmt --all`
Expected: All files formatted

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace`
Expected: No warnings

- [ ] **Step 3: Run all workspace tests**

Run: `cargo test --workspace`
Expected: All tests pass

- [ ] **Step 4: QEMU integration test**

Build the ring3 image and boot in QEMU:

```bash
cargo xtask build-image-ring3
```

Then test SSH still works:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@localhost "echo alive"
```

Expected: Returns "alive" with exit code 0.

Verify serial output shows `poll_fn` being called during the select spin-wait (the relay loop should now be slower/calmer, not a tight spin).

- [ ] **Step 5: Format check**

Run: `cargo +nightly fmt --all -- --check`
Expected: No formatting issues

- [ ] **Step 6: Commit any final fixes**

```bash
git add -A
git commit -m "chore: format and lint cleanup for ssh timeout guards"
```

- [ ] **Step 7: Push branch**

```bash
git push -u origin jake-os-ssh-timeout-guards
```
