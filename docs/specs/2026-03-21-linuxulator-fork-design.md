# Linuxulator Process Table + Fork (harmony-os-pfs, part 1)

Sequential fork with parent-owned children. Parent suspends while
child runs to completion, then resumes. Enough for systemd/nix-daemon
fork-then-exec patterns. No threading, no concurrent execution.

## Context

The Linuxulator is a single-process, synchronous syscall processor.
`getpid()` returns 1, there is no process table, no parent-child
relationship. NixOS boot requires `fork → exec → wait`:

- **systemd** forks service processes
- **nix-daemon** forks per-client handlers
- **bash** forks for subshells and pipelines

This bead adds fork/vfork/clone (bare fork only) and the process
table infrastructure. execve and waitpid are separate follow-up beads.

## Design

### Execution Model: Sequential Fork

When `fork()` is called:

1. `sys_fork` creates a `ChildProcess` with a new Linuxulator, pushes
   it to `self.children`, returns `child_pid` to parent.
2. Caller checks `pending_fork_child()` — finds the active child.
3. Caller switches to dispatching syscalls to the child with rax=0
   (child's fork return value).
4. Child runs until `exit_group(code)`.
5. Child's `exit_code` becomes `Some(code)`. `active_process()` now
   returns the parent. Caller resumes dispatching to parent.
6. Child's exit status is stored in `ChildProcess` for later `waitpid`.

The parent never runs concurrently with the child. This matches vfork
semantics and is sufficient for fork-then-exec patterns.

### WORM Memory Model

Harmony's write-once-read-many memory means fork doesn't need COW
page tables. Immutable pages are shared for free. Each process
allocates fresh pages for writes (stack, heap). Sequential execution
means no concurrent write contention.

The child gets a fresh `MemoryArena` (or fresh VM brk region). Read
mappings from the parent's ELF segments are shared implicitly through
the WORM store.

### Process Identity

New Linuxulator fields:

```rust
pid: i32,                                // this process's PID (1 for init)
parent_pid: i32,                         // parent's PID (0 for init)
next_child_pid: i32,                     // monotonic allocator, starts at 2
children: Vec<ChildProcess<B>>,          // children (active or exited)
```

```rust
struct ChildProcess<B: SyscallBackend> {
    pid: i32,
    exit_code: Option<i32>,              // None while running, Some after exit
    linuxulator: Linuxulator<B>,
}
```

`getpid()` returns `self.pid`. `getppid()` returns `self.parent_pid`.

### Caller-Side Dispatch

The caller's syscall loop changes from dispatching to a single
Linuxulator to dispatching to the "active process":

```rust
pub fn active_process(&mut self) -> &mut Linuxulator<B> {
    if let Some(child) = self.children.last_mut() {
        if child.exit_code.is_none() {
            return child.linuxulator.active_process();
        }
    }
    self
}
```

Recursively walks the child chain — handles nested forks.

After `sys_fork` returns, the caller checks:

```rust
pub fn pending_fork_child(&mut self) -> Option<(i32, &mut Linuxulator<B>)>
```

If `Some((child_pid, child))`: set child's rax=0, switch dispatch
target to child. The child becomes active until it exits.

### Shared State: Pipes and Eventfds

Pipes and eventfds must be shared between parent and child (they're
the primary IPC mechanism for fork patterns).

On fork, `sys_fork` moves (`mem::swap`) the parent's `pipes` and
`eventfds` maps into the child. When the child exits (detected by
`active_process` seeing `exit_code.is_some()`), the maps are moved
back to the parent.

Since execution is sequential, only one Linuxulator touches the maps
at a time. The child's fd table entries reference the same `pipe_id`
and `eventfd_id` values as the parent's.

### Cloned State

| State | Behavior |
|-------|----------|
| backend | `fork_backend()` — fresh instance, own fid namespace |
| fd_table | Deep clone (same pipe_id/eventfd_id/socket_id references) |
| pipes | Moved from parent during child execution, moved back on exit |
| eventfds | Same as pipes |
| sockets | Cloned (requires `#[derive(Clone)]` on `SocketState`) |
| epolls | Cloned (requires `#[derive(Clone)]` on `EpollState`; independent interest sets) |
| fid_refcount | Cloned |
| arena | Fresh (child gets own MemoryArena) |
| vm_brk_base / vm_brk_current | Reset to 0 (child establishes its own heap) |
| cwd | Cloned |
| fs_base | Cloned (TLS pointer) |
| pid | New unique value |
| parent_pid | Parent's pid |
| exit_code | None |
| next_child_pid | Inherited (global PID space) |
| children | Empty (child starts with no children of its own) |
| next_fid | Inherited (fid namespaces are per-backend, no collision risk since child has its own backend) |
| next_pipe_id | Inherited (shared pipe map means IDs must not collide; inheriting the counter ensures new pipes from either process get unique IDs) |
| next_eventfd_id | Same as next_pipe_id |
| next_socket_id | Inherited (child's cloned sockets map uses existing IDs; new sockets get fresh IDs) |
| next_epoll_id | Inherited |
| getrandom_counter | Reset to 0 (child should produce distinct random output) |
| monotonic_ns | Inherited (child continues from parent's clock position) |
| realtime_ns | Inherited |

**Prerequisite derives:** `SocketState` and `EpollState` need
`#[derive(Clone)]` added. `FdEntry` already derives `Clone`.

### SyscallBackend Changes

New required method:

```rust
fn fork_backend(&self) -> Self where Self: Sized;
```

Default implementation panics (`unimplemented!`). Each backend
implements it:

- **MockBackend**: returns `MockBackend::new()` (fresh mock)
- **VmMockBackend**: returns fresh instance with same config
- **DirectBackend** (harmony-boot): creates new client handle to
  same 9P server with fresh fid namespace

The `where Self: Sized` bound allows the method on a non-object-safe
trait without breaking existing `dyn SyscallBackend` usage in
`elf_loader.rs`. Note: `fork_backend` is intentionally non-dispatchable
through `dyn SyscallBackend` — it is only called via the concrete
generic `B` in `Linuxulator<B>`.

### Child Exit and State Recovery

When a child calls `exit_group`, its `exit_code` becomes `Some(code)`.
The next call to `active_process()` on the parent sees this and
returns the parent instead of the child.

State recovery is recursive — `active_process()` detects the exited
child and calls `recover_child_state()` internally before returning
the parent. This keeps the caller simple (it only calls
`active_process()` and never manages recovery itself).

```rust
fn recover_child_state(&mut self)
```

This private method:
1. Takes the last child's pipes/eventfds maps (mem::swap back)
2. Merges them into the parent's maps
3. Recovers next_pipe_id/next_eventfd_id (take the max of parent and child)

For nested forks, each level recovers its own child. When a
grandchild exits, the child's `active_process()` recovers the
grandchild's state. When the child later exits, the parent's
`active_process()` recovers the child's state. No caller involvement
needed beyond calling `active_process()`.

### Syscalls

| Syscall | x86_64 | aarch64 | Behavior |
|---------|--------|---------|----------|
| fork | 57 | -- | Create child with cloned state. Return child_pid to parent. aarch64 has no fork syscall. |
| vfork | 58 | -- | Same as fork in sequential model. aarch64 has no vfork. |
| clone | 56 | 220 | Accept `SIGCHLD` (17) optionally combined with `CLONE_CHILD_SETTID` (0x01000000) and `CLONE_CHILD_CLEARTID` (0x00200000) — these are what musl's `fork()` wrapper passes. The TID-write semantics are stubbed (ignored). Flags containing `CLONE_VM` (0x00000100), `CLONE_THREAD` (0x00010000), or `CLONE_FILES` (0x00000400) → ENOSYS (threading). child_stack arg ignored (sequential model uses own stack). SIGCHLD=17 on both x86_64 and aarch64. |
| clone3 | 435 | 435 | Return ENOSYS (future bead). |

**PID-related syscall updates:**
- `getpid()` returns `self.pid` (was hardcoded 1)
- `getppid()` returns `self.parent_pid` (new field, 0 for init)
- `gettid()` returns `self.pid` (single-threaded: TID = PID)
- `set_tid_address()` returns `self.pid` (was hardcoded 1; musl caches this)

### File Changes

All changes in `crates/harmony-os/src/linuxulator.rs`:

- SyscallBackend trait: +`fork_backend` method with default panic
- MockBackend: +`fork_backend` implementation
- VmMockBackend: +`fork_backend` implementation
- Linuxulator struct: +4 fields (pid, parent_pid, next_child_pid, children)
- Linuxulator::new/with_arena: initialize new fields
- ChildProcess struct: new
- sys_fork: new (creates child, pushes to children)
- sys_clone: new (validates flags, delegates to sys_fork)
- active_process: new public method
- pending_fork_child: new public method
- recover_child_state: new private method (called by active_process)
- create_child: new private method (clones fd table, forks backend, etc.)
- sys_exit_group: also set exit_code on the child record if we are a child
- sys_getpid: return self.pid
- sys_getppid: return self.parent_pid
- sys_gettid: return self.pid (was hardcoded 1)
- sys_set_tid_address: return self.pid (was hardcoded 1)
- SocketState: add #[derive(Clone)]
- EpollState: add #[derive(Clone)]
- LinuxSyscall enum: +4 variants (Fork, Vfork, Clone, Clone3)
- x86_64 table: +4 entries (56, 57, 58, 435)
- aarch64 table: +2 entries (220, 435)
- dispatch_syscall: +4 arms

## Test Plan

| Test | Behavior verified |
|------|-------------------|
| test_fork_returns_pid_and_zero | fork returns positive PID to parent; pending_fork_child returns child with pid |
| test_fork_child_exit_resumes_parent | child exit_group → active_process returns parent |
| test_fork_child_inherits_fds | child has same fds as parent (0/1/2 + pipe) |
| test_fork_pipe_shared | parent pipe → fork → child writes → child exits → parent reads data |
| test_fork_child_gets_own_pid | child getpid = child_pid, getppid = parent pid |
| test_fork_nested | fork → child forks grandchild → grandchild exits → child exits → parent |
| test_fork_clone_sigchld | clone(SIGCHLD) = fork semantics |
| test_fork_clone_unsupported_flags | clone(CLONE_VM) → ENOSYS |
| test_vfork_same_as_fork | vfork creates child, sequential, parent resumes |
| test_fork_eventfd_shared | eventfd written by child visible to parent |
| test_fork_parent_creates_pipe_after_child_exit | parent creates pipe after child exits — proves maps recovered |

## Dependencies

| Bead | Relationship |
|------|-------------|
| harmony-os-8hf | Prerequisite (closed) — socket/epoll fd infrastructure |
| harmony-os-pfs | Parent umbrella bead |
| execve sub-bead | Blocked by this — needs process model |
| waitpid sub-bead | Blocked by this — needs children + exit_code |
| harmony-os-5qu | Blocked by pfs — signals need process identity |
