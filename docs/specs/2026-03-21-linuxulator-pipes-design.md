# Linuxulator: pipe/pipe2/eventfd — Shell Pipeline IPC (harmony-os-5pq)

Adds pipe, pipe2, and eventfd syscalls to the Linuxulator, enabling
bash pipelines and systemd event signaling.

## Context

The Linuxulator implements ~43 Linux syscalls but lacks IPC primitives.
Bash cannot run pipelines (`cmd1 | cmd2`) without `pipe`/`pipe2`, and
systemd uses `eventfd` for lightweight inter-service signaling. These
are the first non-9P fd types in the Linuxulator.

## Design

### FdEntry Refactoring

The existing `FdEntry` has flat fields for 9P state (`fid`, `offset`,
`path`, `file_type`). Refactored to an `FdKind` enum that
distinguishes 9P files from internal IPC objects:

```rust
enum FdKind {
    File {
        fid: Fid,
        offset: u64,
        path: Option<String>,
        file_type: FileType,
    },
    PipeRead { pipe_id: usize },
    PipeWrite { pipe_id: usize },
    EventFd {
        counter: u64,
        semaphore: bool,
    },
}

struct FdEntry {
    kind: FdKind,
    flags: u32,  // FD_CLOEXEC — shared across all fd types
}
```

`flags` stays on `FdEntry` (FD_CLOEXEC applies to all fd types).
9P-specific fields move into `FdKind::File`. This pattern extends to
sockets (future bead) and any other non-9P fd type.

**Call sites requiring non-trivial branching post-refactor:**

| Method | Current behavior | Required change |
|--------|-----------------|-----------------|
| `sys_close` | Calls `release_fid(entry.fid)` | Match: File → release_fid; Pipe → scan for remaining refs, drop buffer if zero; EventFd → just remove |
| `dup_fd_to` | Accesses `entry.fid`, bumps `fid_refcount` | Match: File → bump refcount; Pipe/EventFd → clone variant (no fid) |
| `sys_lseek` | Accesses `entry.fid`, `entry.offset` | Match: File → existing logic; Pipe/EventFd → return ESPIPE (-29) |
| `sys_fstat` | Accesses `entry.file_type` | Match: File → existing 9P stat; Pipe → synthetic S_IFIFO stat; EventFd → synthetic stat |
| `sys_fchdir` | Accesses `entry.path` | Match: File → existing logic; Pipe/EventFd → return ENOTDIR |
| `sys_getdents64` | Accesses `entry.fid`, `entry.file_type` | Match: File → existing logic; Pipe/EventFd → return ENOTDIR |
| `sys_mmap` (file-backed) | Accesses `entry.fid` | Match: File → existing logic; Pipe/EventFd → return ENODEV |
| `sys_newfstatat` | Accesses `entry.fid` | Match: File → existing logic; Pipe/EventFd → return EBADF (can't stat by path from a pipe fd) |
| `sys_fcntl` | Accesses `entry.fid` for F_DUPFD | Match: same pattern as dup_fd_to |
| `insert_test_fd` (test helper) | Constructs FdEntry with flat fields | Add `insert_test_pipe_fd` helper for pipe tests |

Additionally, ~10 simpler call sites just need `entry.fid` →
`entry.kind.as_file().fid` or similar accessor changes.

### New Linuxulator State

```rust
pub struct Linuxulator<B: SyscallBackend> {
    // ... existing fields ...
    pipes: BTreeMap<usize, Vec<u8>>,  // pipe_id → shared buffer
    next_pipe_id: usize,              // monotonic allocator
}
```

Pipe buffers are simple `Vec<u8>` — writer appends, reader drains
from front. No capacity limit or backpressure (single-threaded model,
no concurrent reader/writer). The fork/process bead will add blocking
semantics when multi-process support lands.

### Syscall Specifications

**`pipe2(fds: *mut [i32; 2], flags: i32) -> i64`**
(x86_64: 293, aarch64: 59)

- Allocates a new pipe buffer in `self.pipes`
- Creates two fds: `fds[0]` = read end, `fds[1]` = write end
- Flags: `O_CLOEXEC` (0o2000000, existing constant) sets FD_CLOEXEC
  on both fds. `O_NONBLOCK` (0o4000) stored but no behavioral effect
  yet (single-threaded, no blocking).
- Invalid flags → EINVAL
- Returns 0 on success

**`pipe(fds: *mut [i32; 2]) -> i64`**
(x86_64: 22; aarch64 only has pipe2)

- Equivalent to `pipe2(fds, 0)`

**`eventfd2(initval: u32, flags: i32) -> i64`**
(x86_64: 290, aarch64: 19)

- Creates a single fd (FdKind::EventFd) with counter = initval
- Flags: `EFD_CLOEXEC` (0o2000000), `EFD_NONBLOCK` (0o4000),
  `EFD_SEMAPHORE` (1)
- Returns the new fd number on success

### Read/Write Behavior

**Pipes:**

| Operation | Behavior |
|-----------|----------|
| Read from PipeRead | Drain up to `count` bytes from front of buffer. Returns bytes read. |
| Read from PipeRead, buffer empty, write end exists | Returns EAGAIN (no blocking in single-threaded model) |
| Read from PipeRead, buffer empty, write end closed | Returns 0 (EOF) |
| Write to PipeWrite | Append to buffer. Returns `count`. |
| Write to PipeWrite, read end closed | Returns EPIPE |
| Read from PipeWrite / Write to PipeRead | Returns EBADF |

"Write end closed" = no fd in the fd_table references this pipe_id
as `PipeWrite`. Same logic for read end.

**Eventfd:**

| Operation | Behavior |
|-----------|----------|
| Read, counter > 0, default mode | Write 8-byte LE u64 (full counter) to buf, reset counter to 0, return 8 |
| Read, counter > 0, semaphore mode | Write 8-byte LE u64 (value 1) to buf, decrement counter by 1, return 8 |
| Read, counter == 0 | Return EAGAIN |
| Write, value == 0xFFFFFFFFFFFFFFFF | Return EINVAL |
| Write, counter + value > 0xFFFFFFFFFFFFFFFE | Return EAGAIN (overflow) |
| Write, normal | Read 8-byte LE u64 from buf, add to counter, return 8 |
| Read/write with buffer < 8 bytes | Return EINVAL |

### fstat for Pipes/Eventfd

**Pipes:** Returns synthetic stat with `S_IFIFO` (0o010000 | 0o644)
in the `st_mode` field. Linux reports pipes as FIFOs via fstat —
programs (bash, musl stdio) use this to detect pipe fds. Size 0,
qpath derived from fd number.

**Eventfd:** Returns synthetic stat with `S_IFREG` and size 0.

Note: the existing `FileType` enum has `Regular`, `Directory`,
`CharDev`. Rather than adding a `Fifo` variant to the microkernel's
type system (which has no concept of pipes), the pipe fstat path
writes `S_IFIFO` directly into the Linux stat buffer, bypassing the
`FileType` match in `write_linux_stat`.

### Pipe Lifecycle

- `pipe2`: allocates buffer, creates two fds
- `dup`/`dup2`/`dup3` on pipe fd: new fd references same `pipe_id`.
  Multiple readers or multiple writers are valid (same as Linux).
  No `fid_refcount` involvement — pipe lifetime managed by scanning
  fd_table for remaining references to the pipe_id.
- `close`: removes fd. If no remaining fds reference this pipe_id
  (neither read nor write end), remove the buffer from `self.pipes`.
- eventfd: cleanup on close is immediate (no shared state).

### Integration with sys_read/sys_write

`sys_read` and `sys_write` gain a match on `entry.kind` at the top:

```
sys_read(fd, buf, count):
    entry = fd_table[fd]
    match entry.kind:
        PipeRead { pipe_id } → drain from pipes[pipe_id]
        EventFd { .. } → read counter
        File { fid, offset, .. } → existing 9P read path
        PipeWrite { .. } → EBADF (can't read from write end)
```

Same pattern for `sys_write`. The 9P path is unchanged — just
nested one level deeper in the match.

### What This Bead Does NOT Include

- Blocking read/write (requires multi-process, fork bead)
- SIGPIPE delivery (requires signal bead)
- O_NONBLOCK behavioral difference (same as blocking until
  multi-process lands)
- poll/select/epoll integration (socket/epoll bead)
- Pipe capacity limits (Linux default 64KB — unnecessary without
  backpressure)

## Test Plan

### Pipe tests
- `pipe2_creates_read_write_fds` — pipe2 returns two valid fds
- `pipe_write_then_read` — write bytes, read them back
- `pipe_read_empty_eof` — close write end, read returns 0 (EOF)
- `pipe_write_no_reader_epipe` — close read end, write returns EPIPE
- `pipe_multiple_writes_accumulate` — multiple writes, single read
- `pipe_partial_read` — read fewer bytes, remainder persists
- `pipe2_cloexec_flag` — O_CLOEXEC sets FD_CLOEXEC on both fds
- `pipe2_invalid_flags` — unknown flags return EINVAL
- `pipe_dup_shares_buffer` — dup'd write end writes to same pipe
- `pipe_lseek_returns_espipe` — lseek on pipe fd returns ESPIPE
- `pipe_fstat_returns_fifo` — fstat reports S_IFIFO mode

### Eventfd tests
- `eventfd_init_and_read` — create with initval, read returns it
- `eventfd_semaphore_mode` — read returns 1, decrements by 1
- `eventfd_write_accumulates` — multiple writes add to counter
- `eventfd_read_zero_eagain` — counter=0 returns EAGAIN
- `eventfd_buffer_too_small` — <8 bytes returns EINVAL
- `eventfd_write_overflow_eagain` — overflow returns EAGAIN
- `eventfd_write_max_value_einval` — 0xFFFFFFFFFFFFFFFF returns EINVAL

### Regression tests
- `existing_file_io_unchanged` — 9P read/write still works after refactoring

## Dependencies

| Bead | Relationship |
|------|-------------|
| harmony-os-hbe | Parent — Linuxulator syscall coverage |
| harmony-os-8hf | Blocked by this — socket stubs + epoll |
| harmony-os-pfs | Blocked by 8hf — process management |
| harmony-os-5qu | Blocked by pfs — signal delivery |
