# Linuxulator Socket Stubs + Epoll Skeleton (harmony-os-8hf)

Minimal socket syscall stubs and an always-ready epoll implementation.
Enough for systemd's socket activation framework and nix-daemon's Unix
socket to initialize without crashing. No real networking — that comes
later via Reticulum/GENET integration.

## Context

The Linuxulator already supports file I/O (9P-backed), pipes, and
eventfds. The next syscall tier needed for NixOS boot is sockets and
epoll:

- **systemd** uses `epoll_create1` + `epoll_ctl` + `epoll_wait` as its
  core event loop. Without epoll, PID 1 fails immediately.
- **nix-daemon** opens a Unix socket for client connections. Without
  `socket` + `bind` + `listen`, nix-daemon exits on startup.
- **bash** uses `socket` for network builtins (`/dev/tcp`).

Both subsystems are stubs — sockets accept all operations but transfer
no data, epoll reports all registered fds as always-ready.

## Design

### New FdKind Variants

Two new variants, following the existing indirection pattern (like
EventFd → eventfd_id → eventfds map):

```rust
FdKind::Socket { socket_id: usize }
FdKind::Epoll { epoll_id: usize }
```

### Shared State

```rust
struct SocketState {
    domain: i32,      // AF_UNIX, AF_INET, AF_INET6
    sock_type: i32,   // SOCK_STREAM, SOCK_DGRAM (flags masked off)
    listening: bool,
}

struct EpollState {
    interests: BTreeMap<i32, (u32, u64)>,  // fd → (event mask, data)
}
```

New Linuxulator fields:

```rust
sockets: BTreeMap<usize, SocketState>,
next_socket_id: usize,
epolls: BTreeMap<usize, EpollState>,
next_epoll_id: usize,
```

### Socket Syscalls

All stubs — validate fd type, track minimal state, return success.
Wrong fd type → ENOTSOCK. Missing fd → EBADF.

| Syscall | x86_64 | aarch64 | Behavior |
|---------|--------|---------|----------|
| socket | 41 | 198 | Validate domain (AF_UNIX=1, AF_INET=2, AF_INET6=10). Mask SOCK_NONBLOCK/SOCK_CLOEXEC from type. Protocol arg ignored. Allocate socket_id + fd. Return fd. Unknown domain → EAFNOSUPPORT. |
| bind | 49 | 200 | Validate fd is Socket (ENOTSOCK). No-op, return 0. |
| listen | 50 | 201 | Validate fd is Socket (ENOTSOCK). Set listening=true. Return 0. |
| accept4 | 288 | 242 | Validate fd is Socket (ENOTSOCK) and listening (else EINVAL). Create new socket_id + fd. If flags contains SOCK_CLOEXEC (0x80000), set FD_CLOEXEC on new fd; SOCK_NONBLOCK accepted and ignored. If addr non-null: read `*addrlen` for buffer size, zero `min(*addrlen, 128)` bytes at addr, write 0 to `*addrlen`. Return new fd. |
| accept | 43 | 202 | Dispatch to accept4 with flags=0. |
| connect | 42 | 203 | Validate fd is Socket (ENOTSOCK). No-op, return 0. |
| sendto | 44 | 206 | Validate fd is Socket (ENOTSOCK). Return len (pretend sent). |
| recvfrom | 45 | 207 | Validate fd is Socket (ENOTSOCK). Return 0 (EOF). |
| setsockopt | 54 | 208 | Validate fd is Socket (ENOTSOCK). No-op, return 0. |
| getsockopt | 55 | 209 | Validate fd is Socket (ENOTSOCK). Write zeros to optval (up to optlen). Return 0. |
| shutdown | 48 | 210 | Validate fd is Socket (ENOTSOCK). No-op, return 0. |
| getsockname | 51 | 204 | Validate fd is Socket (ENOTSOCK). Zero sockaddr, write 0 to `*addrlen`. Return 0. |
| getpeername | 52 | 205 | Validate fd is Socket (ENOTSOCK). Zero sockaddr, write 0 to `*addrlen`. Return 0. |

### Epoll Syscalls

Always-ready model — `epoll_wait` returns all registered fds immediately.
Wrong fd type → EINVAL. Missing fd → EBADF.

| Syscall | x86_64 | aarch64 | Behavior |
|---------|--------|---------|----------|
| epoll_create1 | 291 | 20 | Validate flags (only EPOLL_CLOEXEC=0x80000; unknown flags → EINVAL). Allocate epoll_id + fd. Return fd. |
| epoll_ctl | 233 | 21 | Validate epfd is Epoll (EINVAL). Validate target fd exists (EBADF). Read `epoll_event` from event_ptr (events mask + u64 data). ADD(1): insert fd→(mask, data) (EEXIST if present). MOD(2): update (ENOENT if absent). DEL(3): remove (ENOENT if absent). |
| epoll_wait | 232 | -- | Validate epfd is Epoll (EINVAL). Validate maxevents>0 (EINVAL). Write interests as ready epoll_event structs (stored mask + stored data). Return min(count, maxevents). Empty → return 0. Timeout argument ignored (always returns immediately). x86_64 only. |
| epoll_pwait | 281 | 22 | Dispatch to epoll_wait, ignoring sigmask and sigsetsize args. On aarch64, nr 22 is epoll_pwait (not epoll_wait) — the only epoll wait variant available. |

**Note:** aarch64 Linux has no `epoll_wait` syscall — only `epoll_pwait`
(nr 22) with extra sigmask/sigsetsize arguments. x86_64 has both
`epoll_wait` (232) and `epoll_pwait` (281). Modern glibc may route
through `epoll_pwait` on x86_64 as well, so both are needed.

### epoll_event Layout

```
x86_64:  [u32 events][u64 data]  — 12 bytes (packed, no padding)
aarch64: [u32 events][4 pad][u64 data] — 16 bytes (natural alignment)
```

Linux ABI quirk: `struct epoll_event` is `__attribute__((packed))` on
x86_64 but naturally aligned on aarch64.

### Generic fd Operations on New Types

| Operation | Socket | Epoll |
|-----------|--------|-------|
| read | 0 (EOF) | EINVAL |
| write | count (discard) | EINVAL |
| fstat | S_IFSOCK (0o140000) \| 0o644 | S_IFREG \| 0o644, size 0 |
| lseek | ESPIPE | ESPIPE |
| mmap | ENODEV | ENODEV |
| ioctl FIONBIO | 0 (no-op) | EINVAL |
| ioctl other | EINVAL | EINVAL |

### close_fd_entry

Both Socket and Epoll follow the existing scan-for-remaining-references
pattern: scan `fd_table` for other fds with the same socket_id/epoll_id,
remove shared state only when the last reference is closed.

### Known Limitations

- **epoll spin:** Always-ready means systemd's event loop never blocks,
  causing a tight spin. Acceptable for stub — real blocking requires a
  yield/coroutine mechanism (future bead).
- **No data transfer:** Sockets accept all operations but sendto
  discards data and recvfrom returns EOF. Loopback IPC is a separate
  bead.
- **No address tracking:** bind/connect don't record sockaddr.
  getsockname/getpeername return zeroed sockaddr.
- **Shared offset semantics:** dup'd socket fds have independent state
  (same limitation as existing File dup).

### File Changes

All changes in `crates/harmony-os/src/linuxulator.rs`:

- LinuxSyscall enum: +17 variants (13 socket + 4 epoll)
- x86_64 syscall table: +17 entries
- aarch64 syscall table: +16 entries (no epoll_wait; nr 22 maps to EpollPwait only)
- dispatch_syscall: +17 arms
- FdKind enum: +2 variants (Socket, Epoll)
- Linuxulator struct: +4 fields
- Linuxulator::new(): initialize new fields
- close_fd_entry: +2 match arms
- sys_read: +2 match arms
- sys_write: +2 match arms
- sys_fstat: +2 match arms
- sys_lseek: +2 match arms (grouped with existing ESPIPE arms)
- sys_mmap: extend ENODEV guard
- sys_ioctl: restructure from flat request match to fd-type + request
  dispatch (check FdKind for FIONBIO on sockets, then fall through to
  existing request-based matching)
- New functions: sys_socket, sys_bind, sys_listen, sys_accept4,
  sys_connect, sys_sendto, sys_recvfrom, sys_setsockopt, sys_getsockopt,
  sys_shutdown, sys_getsockname, sys_getpeername,
  sys_epoll_create1, sys_epoll_ctl, sys_epoll_wait

## Test Plan

| Test | Behavior verified |
|------|-------------------|
| test_socket_create | socket() returns valid fd; unknown domain → EAFNOSUPPORT |
| test_socket_lifecycle | socket → bind → listen → accept → connect → shutdown → close chain succeeds |
| test_socket_read_write | read returns 0 (EOF), write returns count |
| test_socket_sendto_recvfrom | sendto returns len, recvfrom returns 0 |
| test_socket_setsockopt_getsockopt | setsockopt no-op succeeds, getsockopt writes zeros |
| test_socket_fstat | stat reports S_IFSOCK mode |
| test_socket_lseek_espipe | lseek returns ESPIPE |
| test_socket_mmap_enodev | mmap returns ENODEV |
| test_socket_accept_not_listening | accept before listen → EINVAL |
| test_socket_flags | SOCK_CLOEXEC sets FD_CLOEXEC, SOCK_NONBLOCK accepted |
| test_epoll_create_and_ctl | create + add/mod/del + EEXIST/ENOENT errors |
| test_epoll_wait_returns_ready | registered fds returned as ready with correct masks |
| test_epoll_wait_empty | no interests → returns 0 |
| test_epoll_wait_maxevents | returned count capped at maxevents |
| test_epoll_ctl_bad_fd | EBADF for non-existent target fd |
| test_epoll_read_write_einval | read/write on epoll fd return EINVAL |
| test_epoll_close_cleanup | close epoll, state cleaned up |
| test_socket_dup | dup socket fd, both work, close one doesn't affect other |
| test_socket_ops_wrong_fd_type | bind/listen/connect/sendto/recvfrom on pipe fd → ENOTSOCK |
| test_epoll_ops_wrong_fd_type | epoll_ctl/epoll_wait on non-epoll fd → EINVAL |
| test_epoll_data_roundtrip | epoll_ctl stores data field, epoll_wait returns it verbatim |
| test_socket_getsockname_getpeername | both zero sockaddr buffer, write 0 to addrlen |

## Dependencies

| Bead | Relationship |
|------|-------------|
| harmony-os-5pq | Prerequisite (closed) — pipe/eventfd fd infrastructure |
| harmony-os-pfs | Blocked by this — process management needs socket/epoll |
| harmony-os-hbe | Parent — overall syscall coverage tracker |
