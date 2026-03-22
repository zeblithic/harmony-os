# Linuxulator Process Table + Fork Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add sequential fork to the Linuxulator — parent suspends while child runs, pipes/eventfds shared, enabling systemd/nix-daemon fork patterns.

**Architecture:** Parent-owned `ChildProcess` with a child `Linuxulator<B>` instance. `active_process()` recursively finds the deepest running child. Pipes/eventfds are `mem::swap`'d to the child during execution and returned on exit. `SyscallBackend` gains `fork_backend()` to create fresh backend instances.

**Tech Stack:** Rust, `no_std` (`alloc` only), `BTreeMap` for all state

**Spec:** `docs/specs/2026-03-21-linuxulator-fork-design.md`

---

## File Structure

All changes in a single file:

| File | Responsibility |
|------|---------------|
| Modify: `crates/harmony-os/src/linuxulator.rs` | SyscallBackend +fork_backend, MockBackend/VmMockBackend impls, ChildProcess struct, Linuxulator +4 fields, create_child, sys_fork, sys_clone, active_process, pending_fork_child, recover_child_state, PID syscall updates, Clone derives, LinuxSyscall +4 variants, syscall tables, dispatch arms, 11 tests |

---

### Task 1: Prerequisites — derives, fork_backend, PID fields

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn test_fork_returns_pid_and_zero() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);
    lx.init_stdio().unwrap();

    // Fork
    let result = lx.dispatch_syscall(LinuxSyscall::Fork);
    assert!(result > 0, "fork should return child PID to parent, got {result}");
    let child_pid = result as i32;

    // pending_fork_child should return the child
    let (pid, _child) = lx.pending_fork_child().expect("should have pending child");
    assert_eq!(pid, child_pid);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-os fork_returns_pid 2>&1 | tail -10`
Expected: compile error — `LinuxSyscall::Fork` does not exist

- [ ] **Step 3: Add `#[derive(Clone)]` to SocketState and EpollState**

At `SocketState` (~line 1516), add `#[derive(Clone)]`:
```rust
#[derive(Clone)]
struct SocketState {
```

At `EpollState` (~line 1528), add `#[derive(Clone)]`:
```rust
#[derive(Clone)]
struct EpollState {
```

- [ ] **Step 4: Add `fork_backend` to SyscallBackend trait**

In `SyscallBackend` trait (~line 950), after `readdir`, add:

```rust
    /// Create a forked copy of this backend for a child process.
    ///
    /// Returns a fresh backend instance with its own fid namespace,
    /// connected to the same underlying server. Only callable on
    /// concrete types (not through `dyn SyscallBackend`).
    fn fork_backend(&self) -> Self
    where
        Self: Sized,
    {
        unimplemented!("fork not supported by this backend")
    }
```

- [ ] **Step 5: Implement fork_backend for MockBackend and VmMockBackend**

After `MockBackend::new()` (~line 1080), in the `impl SyscallBackend for MockBackend` block, add:

```rust
    fn fork_backend(&self) -> Self {
        MockBackend::new()
    }
```

In the `impl SyscallBackend for VmMockBackend` block, add:

```rust
    fn fork_backend(&self) -> Self {
        VmMockBackend::new(self.budget_pages)
    }
```

- [ ] **Step 6: Add ChildProcess struct and new Linuxulator fields**

After `EpollState` struct (~line 1532), add:

```rust
/// A child process created by fork/clone.
struct ChildProcess<B: SyscallBackend> {
    pid: i32,
    /// None while the child is running, Some(code) after exit_group.
    exit_code: Option<i32>,
    linuxulator: Linuxulator<B>,
}
```

In `Linuxulator` struct (~line 1545), add these fields before the closing brace:

```rust
    /// This process's PID.
    pid: i32,
    /// Parent's PID (0 for init).
    parent_pid: i32,
    /// Next PID to assign to a child.
    next_child_pid: i32,
    /// Children created by fork (active or exited, awaiting waitpid).
    children: Vec<ChildProcess<B>>,
```

- [ ] **Step 7: Initialize new fields in with_arena**

In `with_arena()` (~line 1598), add before the closing brace:

```rust
            pid: 1,
            parent_pid: 0,
            next_child_pid: 2,
            children: Vec::new(),
```

- [ ] **Step 8: Update PID-related syscalls**

Update `sys_getpid` (~line 4021):
```rust
    fn sys_getpid(&self) -> i64 {
        self.pid as i64
    }
```

Update `sys_getppid` (~line 4028):
```rust
    fn sys_getppid(&self) -> i64 {
        self.parent_pid as i64
    }
```

Update `sys_gettid` (~line 4035):
```rust
    fn sys_gettid(&self) -> i64 {
        self.pid as i64
    }
```

Update `sys_set_tid_address` (~line 3511):
```rust
    fn sys_set_tid_address(&self) -> i64 {
        self.pid as i64
    }
```

- [ ] **Step 9: Add LinuxSyscall::Fork variant and x86_64 table entry**

In the `LinuxSyscall` enum, before `Unknown` (~line 372), add:

```rust
    Fork,
    Vfork,
    Clone {
        flags: u64,
        child_stack: u64,
        parent_tid: u64,
        child_tid: u64,
        tls: u64,
    },
    Clone3 {
        args: u64,
        size: u64,
    },
```

In `from_x86_64` (~line 379), add:

```rust
            56 => LinuxSyscall::Clone {
                flags: args[0],
                child_stack: args[1],
                parent_tid: args[2],
                child_tid: args[3],
                tls: args[4],
            },
            57 => LinuxSyscall::Fork,
            58 => LinuxSyscall::Vfork,
            435 => LinuxSyscall::Clone3 {
                args: args[0],
                size: args[1],
            },
```

In `from_aarch64` (~line 673), add:

```rust
            220 => LinuxSyscall::Clone {
                flags: args[0],
                child_stack: args[1],
                parent_tid: args[2],
                tls: args[3],
                child_tid: args[4],
            },
            435 => LinuxSyscall::Clone3 {
                args: args[0],
                size: args[1],
            },
```

**IMPORTANT:** aarch64 clone has different argument order than x86_64! On aarch64: `flags, child_stack, parent_tid, tls, child_tid`. On x86_64: `flags, child_stack, parent_tid, child_tid, tls`. Both map to the same enum variant.

aarch64 has no `fork` or `vfork` syscalls — they use `clone` with `SIGCHLD`.

- [ ] **Step 10: Add dispatch arms (stubs returning ENOSYS for now)**

In `dispatch_syscall` (~line 1809), before `Unknown`:

```rust
            LinuxSyscall::Fork => self.sys_fork(),
            LinuxSyscall::Vfork => self.sys_fork(),
            LinuxSyscall::Clone { flags, .. } => self.sys_clone(flags),
            LinuxSyscall::Clone3 { .. } => ENOSYS,
```

Add stub implementations (will be filled in Task 2):

```rust
    /// Linux fork(2): create child process (sequential model).
    fn sys_fork(&mut self) -> i64 {
        ENOSYS // placeholder — implemented in Task 2
    }

    /// Linux clone(2): validate flags and delegate to fork.
    fn sys_clone(&mut self, _flags: u64) -> i64 {
        ENOSYS // placeholder — implemented in Task 2
    }
```

Add stub public methods (will be filled in Task 3):

```rust
    /// Return the deepest actively-running Linuxulator in the process tree.
    pub fn active_process(&mut self) -> &mut Linuxulator<B> {
        self // placeholder — implemented in Task 3
    }

    /// Check for a newly-forked child that needs its first syscall dispatched.
    pub fn pending_fork_child(&mut self) -> Option<(i32, &mut Linuxulator<B>)> {
        None // placeholder — implemented in Task 3
    }
```

- [ ] **Step 11: Run all tests to verify no regressions**

Run: `cargo test -p harmony-os 2>&1 | tail -10`
Expected: existing tests pass (the new test will fail — that's expected, we'll fix it in Task 2)

- [ ] **Step 12: Run clippy and fmt**

Run: `cargo clippy -p harmony-os -- -D warnings 2>&1 | tail -10`
Run: `cargo fmt --all -- --check`
Expected: clean (suppress dead_code warnings on stubs with `#[allow(unused)]` if needed)

- [ ] **Step 13: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add fork prerequisites — derives, fork_backend, PID fields, syscall variants"
```

---

### Task 2: Core fork — create_child + sys_fork + sys_clone

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Implement create_child**

After the stub `sys_clone`, add:

```rust
    /// Create a child Linuxulator with cloned state for fork.
    fn create_child(&mut self, child_pid: i32) -> Linuxulator<B> {
        let child_backend = self.backend.fork_backend();
        let mut child = Linuxulator {
            backend: child_backend,
            fd_table: self.fd_table.clone(),
            next_fid: self.next_fid,
            exit_code: None,
            arena: MemoryArena::new(1024 * 1024), // fresh 1 MiB arena
            fs_base: self.fs_base,
            vm_brk_base: 0,
            vm_brk_current: 0,
            getrandom_counter: 0, // reset for distinct random output
            cwd: self.cwd.clone(),
            monotonic_ns: self.monotonic_ns,
            realtime_ns: self.realtime_ns,
            fid_refcount: self.fid_refcount.clone(),
            // pipes and eventfds will be moved in via mem::swap in sys_fork
            pipes: BTreeMap::new(),
            next_pipe_id: self.next_pipe_id,
            eventfds: BTreeMap::new(),
            next_eventfd_id: self.next_eventfd_id,
            sockets: self.sockets.clone(),
            next_socket_id: self.next_socket_id,
            epolls: self.epolls.clone(),
            next_epoll_id: self.next_epoll_id,
            pid: child_pid,
            parent_pid: self.pid,
            next_child_pid: self.next_child_pid,
            children: Vec::new(),
        };
        // Move shared pipe/eventfd state to child
        core::mem::swap(&mut self.pipes, &mut child.pipes);
        core::mem::swap(&mut self.eventfds, &mut child.eventfds);
        child
    }
```

- [ ] **Step 2: Implement sys_fork**

Replace the stub `sys_fork`:

```rust
    /// Linux fork(2): create child process (sequential model).
    ///
    /// Creates a child Linuxulator and pushes it as an active child.
    /// The child's pipes/eventfds are shared with the parent (moved
    /// for the duration of child execution). Returns child_pid to the
    /// parent. The caller should check `pending_fork_child()` and
    /// dispatch to the child with return value 0.
    fn sys_fork(&mut self) -> i64 {
        let child_pid = self.next_child_pid;
        self.next_child_pid += 1;

        let child = self.create_child(child_pid);
        self.children.push(ChildProcess {
            pid: child_pid,
            exit_code: None,
            linuxulator: child,
        });

        child_pid as i64
    }
```

- [ ] **Step 3: Implement sys_clone**

Replace the stub `sys_clone`:

```rust
    /// Linux clone(2): validate flags and delegate to fork.
    ///
    /// Accepts SIGCHLD (17) optionally combined with CLONE_CHILD_SETTID
    /// and CLONE_CHILD_CLEARTID (musl's fork() wrapper). Threading
    /// flags (CLONE_VM, CLONE_THREAD, CLONE_FILES) return ENOSYS.
    fn sys_clone(&mut self, flags: u64) -> i64 {
        const SIGCHLD: u64 = 17;
        const CLONE_VM: u64 = 0x00000100;
        const CLONE_FILES: u64 = 0x00000400;
        const CLONE_THREAD: u64 = 0x00010000;
        const CLONE_CHILD_SETTID: u64 = 0x01000000;
        const CLONE_CHILD_CLEARTID: u64 = 0x00200000;

        // Reject threading flags
        if flags & (CLONE_VM | CLONE_FILES | CLONE_THREAD) != 0 {
            return ENOSYS;
        }

        // Accept SIGCHLD with optional TID flags (stubbed)
        let sig = flags & 0xFF; // signal is in low byte
        let known_flags = SIGCHLD | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;
        if sig != SIGCHLD || (flags & !known_flags) != 0 {
            return ENOSYS;
        }

        self.sys_fork()
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-os 2>&1 | tail -10`
Expected: the `test_fork_returns_pid_and_zero` test still fails (pending_fork_child is still a stub), but compilation succeeds and existing tests pass.

- [ ] **Step 5: Run clippy and fmt**

Run: `cargo clippy -p harmony-os -- -D warnings 2>&1 | tail -10`
Run: `cargo fmt --all -- --check`

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): implement create_child, sys_fork, sys_clone"
```

---

### Task 3: Process dispatch — active_process, pending_fork_child, recover_child_state

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Implement recover_child_state**

Add as a private method:

```rust
    /// Recover shared state (pipes/eventfds) from an exited child.
    ///
    /// Moves the child's pipe and eventfd maps back to the parent,
    /// updates ID allocators, and copies the exit code from the child's
    /// Linuxulator into the ChildProcess record (for future waitpid).
    fn recover_child_state(&mut self) {
        if let Some(child) = self.children.last_mut() {
            if child.linuxulator.exit_code.is_some() {
                // Propagate exit code to ChildProcess record (for waitpid)
                child.exit_code = child.linuxulator.exit_code;
                let c = &mut child.linuxulator;
                core::mem::swap(&mut self.pipes, &mut c.pipes);
                core::mem::swap(&mut self.eventfds, &mut c.eventfds);
                // Take the max of parent and child allocators
                self.next_pipe_id = self.next_pipe_id.max(c.next_pipe_id);
                self.next_eventfd_id = self.next_eventfd_id.max(c.next_eventfd_id);
                self.next_socket_id = self.next_socket_id.max(c.next_socket_id);
                self.next_epoll_id = self.next_epoll_id.max(c.next_epoll_id);
                self.next_child_pid = self.next_child_pid.max(c.next_child_pid);
            }
        }
    }
```

- [ ] **Step 2: Implement active_process**

Replace the stub:

```rust
    /// Return the deepest actively-running Linuxulator in the process tree.
    ///
    /// Recursively walks the child chain. If the deepest child has exited,
    /// recovers its shared state and returns the parent.
    pub fn active_process(&mut self) -> &mut Linuxulator<B> {
        // Check if the last child's Linuxulator has exited (exit_code set
        // by sys_exit_group on the child). If so, recover shared state
        // and propagate exit_code to ChildProcess for future waitpid.
        if let Some(child) = self.children.last() {
            if child.linuxulator.exit_code.is_some() {
                self.recover_child_state();
                return self;
            }
        }
        // If we have an active (non-exited) child, recurse into it
        if let Some(child) = self.children.last_mut() {
            if child.linuxulator.exit_code.is_none() {
                return child.linuxulator.active_process();
            }
        }
        self
    }
```

- [ ] **Step 3: Implement pending_fork_child**

Replace the stub:

```rust
    /// Check for a newly-forked child that needs its first syscall dispatched.
    ///
    /// Returns `Some((child_pid, &mut child_linuxulator))` if the last child
    /// has not yet exited. The caller should set the child's syscall return
    /// value to 0 (fork return for child) and begin dispatching to it.
    pub fn pending_fork_child(&mut self) -> Option<(i32, &mut Linuxulator<B>)> {
        if let Some(child) = self.children.last_mut() {
            if child.linuxulator.exit_code.is_none() {
                return Some((child.pid, &mut child.linuxulator));
            }
        }
        None
    }
```

- [ ] **Step 4: Run the test_fork_returns_pid_and_zero test**

Run: `cargo test -p harmony-os fork_returns_pid 2>&1 | tail -10`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `cargo test -p harmony-os 2>&1 | tail -10`
Expected: all pass. Some existing PID tests may need updating (they assert `== 1` but now `sys_getpid` returns `self.pid` which is still 1 for the init Linuxulator).

- [ ] **Step 6: Run clippy and fmt**

Run: `cargo clippy -p harmony-os -- -D warnings 2>&1 | tail -10`
Run: `cargo fmt --all -- --check`

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): implement active_process, pending_fork_child, recover_child_state"
```

---

### Task 4: Fork tests — all 11 spec tests

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Add all fork tests**

Add at the end of `mod tests`:

```rust
    // ── Fork tests ────────────────────────────────────────────────

    #[test]
    fn test_fork_child_exit_resumes_parent() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        let parent_pid = lx.dispatch_syscall(LinuxSyscall::Getpid) as i32;

        // Fork — returns child_pid to parent
        let child_pid = lx.dispatch_syscall(LinuxSyscall::Fork) as i32;
        assert!(child_pid > parent_pid);

        // Active process should be the child
        {
            let active = lx.active_process();
            assert_eq!(active.dispatch_syscall(LinuxSyscall::Getpid), child_pid as i64);
        }

        // Child exits
        {
            let active = lx.active_process();
            active.dispatch_syscall(LinuxSyscall::ExitGroup { code: 42 });
        }

        // Active process should be parent again
        {
            let active = lx.active_process();
            assert_eq!(active.dispatch_syscall(LinuxSyscall::Getpid), parent_pid as i64);
        }
    }

    #[test]
    fn test_fork_child_inherits_fds() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        // Create a pipe before forking
        let mut fds = [0i32; 2];
        lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0,
        });

        lx.dispatch_syscall(LinuxSyscall::Fork);

        // Child should have all parent's fds
        let child = lx.active_process();
        assert!(child.has_fd(0)); // stdin
        assert!(child.has_fd(1)); // stdout
        assert!(child.has_fd(2)); // stderr
        assert!(child.has_fd(fds[0])); // pipe read
        assert!(child.has_fd(fds[1])); // pipe write
    }

    #[test]
    fn test_fork_pipe_shared() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Create pipe
        let mut fds = [0i32; 2];
        lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0,
        });
        let read_fd = fds[0];
        let write_fd = fds[1];

        // Fork
        lx.dispatch_syscall(LinuxSyscall::Fork);

        // Child writes to pipe
        let msg = b"hello from child";
        {
            let child = lx.active_process();
            let r = child.dispatch_syscall(LinuxSyscall::Write {
                fd: write_fd,
                buf: msg.as_ptr() as u64,
                count: msg.len() as u64,
            });
            assert_eq!(r, msg.len() as i64);
            // Child exits
            child.dispatch_syscall(LinuxSyscall::ExitGroup { code: 0 });
        }

        // Parent reads from pipe — should see child's data
        let mut buf = [0u8; 64];
        let parent = lx.active_process();
        let r = parent.dispatch_syscall(LinuxSyscall::Read {
            fd: read_fd,
            buf: buf.as_mut_ptr() as u64,
            count: 64,
        });
        assert_eq!(r, msg.len() as i64);
        assert_eq!(&buf[..msg.len()], msg);
    }

    #[test]
    fn test_fork_child_gets_own_pid() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let parent_pid = lx.dispatch_syscall(LinuxSyscall::Getpid) as i32;
        let child_pid = lx.dispatch_syscall(LinuxSyscall::Fork) as i32;

        let child = lx.active_process();
        assert_eq!(child.dispatch_syscall(LinuxSyscall::Getpid), child_pid as i64);
        assert_eq!(child.dispatch_syscall(LinuxSyscall::Getppid), parent_pid as i64);
        assert_eq!(child.dispatch_syscall(LinuxSyscall::Gettid), child_pid as i64);
    }

    #[test]
    fn test_fork_nested() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let parent_pid = lx.dispatch_syscall(LinuxSyscall::Getpid) as i32;

        // Parent forks child
        let child_pid = lx.dispatch_syscall(LinuxSyscall::Fork) as i32;

        // Child forks grandchild
        {
            let child = lx.active_process();
            assert_eq!(child.dispatch_syscall(LinuxSyscall::Getpid), child_pid as i64);
            let grandchild_pid = child.dispatch_syscall(LinuxSyscall::Fork) as i32;
            assert!(grandchild_pid > child_pid);

            // Grandchild runs
            let gc = child.active_process();
            assert_eq!(gc.dispatch_syscall(LinuxSyscall::Getpid), grandchild_pid as i64);
            assert_eq!(gc.dispatch_syscall(LinuxSyscall::Getppid), child_pid as i64);
            gc.dispatch_syscall(LinuxSyscall::ExitGroup { code: 0 });
        }

        // Child should be active again (grandchild exited)
        {
            let child = lx.active_process();
            assert_eq!(child.dispatch_syscall(LinuxSyscall::Getpid), child_pid as i64);
            child.dispatch_syscall(LinuxSyscall::ExitGroup { code: 0 });
        }

        // Parent should be active again
        let parent = lx.active_process();
        assert_eq!(parent.dispatch_syscall(LinuxSyscall::Getpid), parent_pid as i64);
    }

    #[test]
    fn test_fork_clone_sigchld() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        const SIGCHLD: u64 = 17;
        const CLONE_CHILD_SETTID: u64 = 0x01000000;
        const CLONE_CHILD_CLEARTID: u64 = 0x00200000;

        // musl's fork() pattern: SIGCHLD | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID
        let r = lx.dispatch_syscall(LinuxSyscall::Clone {
            flags: SIGCHLD | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            child_stack: 0,
            parent_tid: 0,
            child_tid: 0,
            tls: 0,
        });
        assert!(r > 0, "clone(SIGCHLD) should return child PID, got {r}");

        // Child should be active
        let child = lx.active_process();
        assert_eq!(child.dispatch_syscall(LinuxSyscall::Getpid), r);
    }

    #[test]
    fn test_fork_clone_unsupported_flags() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        const CLONE_VM: u64 = 0x00000100;
        const SIGCHLD: u64 = 17;

        let r = lx.dispatch_syscall(LinuxSyscall::Clone {
            flags: CLONE_VM | SIGCHLD,
            child_stack: 0,
            parent_tid: 0,
            child_tid: 0,
            tls: 0,
        });
        assert_eq!(r, ENOSYS);
    }

    #[test]
    fn test_vfork_same_as_fork() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let child_pid = lx.dispatch_syscall(LinuxSyscall::Vfork) as i32;
        assert!(child_pid > 0);

        // Child is active
        let child = lx.active_process();
        assert_eq!(child.dispatch_syscall(LinuxSyscall::Getpid), child_pid as i64);

        // Child exits
        child.dispatch_syscall(LinuxSyscall::ExitGroup { code: 7 });

        // Parent resumes
        let parent = lx.active_process();
        assert_eq!(parent.dispatch_syscall(LinuxSyscall::Getpid), 1);
    }

    #[test]
    fn test_fork_eventfd_shared() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Create eventfd with initial value 0
        let efd = lx.dispatch_syscall(LinuxSyscall::EventFd2 {
            initval: 0,
            flags: 0,
        }) as i32;
        assert!(efd >= 0);

        // Fork
        lx.dispatch_syscall(LinuxSyscall::Fork);

        // Child writes value 42 to eventfd
        {
            let child = lx.active_process();
            let val: u64 = 42;
            let r = child.dispatch_syscall(LinuxSyscall::Write {
                fd: efd,
                buf: &val as *const u64 as u64,
                count: 8,
            });
            assert_eq!(r, 8);
            child.dispatch_syscall(LinuxSyscall::ExitGroup { code: 0 });
        }

        // Parent reads from eventfd — should see 42
        let mut val: u64 = 0;
        let parent = lx.active_process();
        let r = parent.dispatch_syscall(LinuxSyscall::Read {
            fd: efd,
            buf: &mut val as *mut u64 as u64,
            count: 8,
        });
        assert_eq!(r, 8);
        assert_eq!(val, 42);
    }

    #[test]
    fn test_fork_parent_creates_pipe_after_child_exit() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Create pipe before fork
        let mut fds1 = [0i32; 2];
        lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds1.as_mut_ptr() as u64,
            flags: 0,
        });

        // Fork, child exits immediately
        lx.dispatch_syscall(LinuxSyscall::Fork);
        {
            let child = lx.active_process();
            child.dispatch_syscall(LinuxSyscall::ExitGroup { code: 0 });
        }

        // Parent should be able to create new pipes (maps recovered)
        let parent = lx.active_process();
        let mut fds2 = [0i32; 2];
        let r = parent.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds2.as_mut_ptr() as u64,
            flags: 0,
        });
        assert_eq!(r, 0);
        assert!(parent.has_fd(fds2[0]));
        assert!(parent.has_fd(fds2[1]));

        // Original pipe should still work
        let msg = b"test";
        parent.dispatch_syscall(LinuxSyscall::Write {
            fd: fds1[1],
            buf: msg.as_ptr() as u64,
            count: 4,
        });
        let mut buf = [0u8; 4];
        let r = parent.dispatch_syscall(LinuxSyscall::Read {
            fd: fds1[0],
            buf: buf.as_mut_ptr() as u64,
            count: 4,
        });
        assert_eq!(r, 4);
        assert_eq!(&buf, b"test");
    }
```

Note: `test_fork_returns_pid_and_zero` was already written in Task 1 Step 1.

- [ ] **Step 2: Run all tests**

Run: `cargo test -p harmony-os 2>&1 | tail -15`
Expected: all pass including all 11 fork tests

- [ ] **Step 3: Run clippy and fmt**

Run: `cargo clippy -p harmony-os -- -D warnings 2>&1 | tail -10`
Run: `cargo fmt --all -- --check`

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "test(linuxulator): 11 fork tests — lifecycle, pipes, eventfds, nested, clone flags"
```

---

### Task 5: Final integration — full workspace, quality gates

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Run full workspace test suite**

Run: `cargo test --workspace 2>&1 | tail -10`
Expected: all tests pass

- [ ] **Step 2: Run clippy on workspace**

Run: `cargo clippy --workspace -- -D warnings 2>&1 | tail -20`
Expected: clean

- [ ] **Step 3: Run fmt check**

Run: `cargo fmt --all -- --check 2>&1 | tail -5`
Expected: clean

- [ ] **Step 4: Verify test count**

Run: `cargo test -p harmony-os 2>&1 | grep -E "test_fork_|test result"`
Expected: 11 fork tests visible, total count increased by 11

- [ ] **Step 5: Commit if any fixes were needed**

Only if quality gate fixes were required:

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "fix(linuxulator): quality gate fixes for fork implementation"
```
