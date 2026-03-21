# Linuxulator Socket Stubs + Epoll Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add minimal socket syscall stubs and an always-ready epoll skeleton so systemd and nix-daemon can initialize.

**Architecture:** Two new `FdKind` variants (`Socket`, `Epoll`) with shared state via indirection IDs, following the existing pipe/eventfd pattern. Socket stubs track domain/type/listening but transfer no data. Epoll tracks interest sets and returns all registered fds as always-ready.

**Tech Stack:** Rust, `no_std` (`alloc` only), `BTreeMap` for all state

**Spec:** `docs/specs/2026-03-21-linuxulator-sockets-epoll-design.md`

---

## File Structure

All changes in a single file:

| File | Responsibility |
|------|---------------|
| Modify: `crates/harmony-os/src/linuxulator.rs` | LinuxSyscall enum (+17 variants), syscall tables (+17/+16 entries), FdKind (+2 variants), Linuxulator struct (+4 fields), dispatch (+17 arms), existing syscall handlers (read/write/fstat/lseek/mmap/ioctl +2 match arms each), 15 new syscall handler functions, 22 new tests |

---

### Task 1: Data Structures — FdKind::Socket, SocketState, Linuxulator fields

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs:1200-1300`

- [ ] **Step 1: Write the failing test**

Add at end of `mod tests` (after line 7481):

```rust
#[test]
fn test_socket_create() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    // AF_INET (2), SOCK_STREAM (1), protocol 0
    let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
        domain: 2,
        sock_type: 1,
        protocol: 0,
    });
    assert!(fd >= 0, "socket() should return non-negative fd, got {fd}");
    assert!(lx.has_fd(fd as i32));

    // Unknown domain → EAFNOSUPPORT (-97)
    let err = lx.dispatch_syscall(LinuxSyscall::Socket {
        domain: 999,
        sock_type: 1,
        protocol: 0,
    });
    assert_eq!(err, -97); // EAFNOSUPPORT
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-os test_socket_create -- --nocapture 2>&1 | tail -20`
Expected: compile error — `LinuxSyscall::Socket` does not exist yet

- [ ] **Step 3: Add LinuxSyscall::Socket variant and EAFNOSUPPORT/ENOTSOCK constants**

In the `LinuxSyscall` enum (after `EventFd2` variant, before `Unknown`, ~line 271), add:

```rust
    Socket {
        domain: i32,
        sock_type: i32,
        protocol: i32,
    },
```

In the errno constants section (~line 32), add:

```rust
const EAFNOSUPPORT: i64 = -97;
const ENOTSOCK: i64 = -88;
const EEXIST: i64 = -17;
```

- [ ] **Step 4: Add SocketState struct and FdKind::Socket variant**

After `EventFdState` struct (~line 1221), add:

```rust
/// Shared state for a socket instance.
struct SocketState {
    domain: i32,
    sock_type: i32,
    listening: bool,
}
```

In the `FdKind` enum (~line 1214), add before the closing brace:

```rust
    /// Socket stub (no real networking).
    Socket { socket_id: usize },
```

- [ ] **Step 5: Add socket fields to Linuxulator struct**

After `next_eventfd_id` field (~line 1270), add:

```rust
    /// Socket state keyed by socket_id.
    sockets: BTreeMap<usize, SocketState>,
    /// Next socket_id to allocate.
    next_socket_id: usize,
```

In `with_arena()` initializer (~line 1298), add before the closing brace:

```rust
            sockets: BTreeMap::new(),
            next_socket_id: 0,
```

- [ ] **Step 6: Implement sys_socket**

Add after `sys_eventfd2` (~line 2074):

```rust
    // ── Socket stubs ──────────────────────────────────────────────

    /// Linux socket(2): create a socket stub fd.
    fn sys_socket(&mut self, domain: i32, sock_type: i32, _protocol: i32) -> i64 {
        const AF_UNIX: i32 = 1;
        const AF_INET: i32 = 2;
        const AF_INET6: i32 = 10;
        const SOCK_CLOEXEC: i32 = 0o2000000;
        const SOCK_NONBLOCK: i32 = 0o4000;

        match domain {
            AF_UNIX | AF_INET | AF_INET6 => {}
            _ => return EAFNOSUPPORT,
        }

        let flags = sock_type & (SOCK_CLOEXEC | SOCK_NONBLOCK);
        let base_type = sock_type & !(SOCK_CLOEXEC | SOCK_NONBLOCK);

        let socket_id = self.next_socket_id;
        self.next_socket_id += 1;
        self.sockets.insert(
            socket_id,
            SocketState {
                domain,
                sock_type: base_type,
                listening: false,
            },
        );

        let fd = self.alloc_fd();
        let fd_flags = if flags & SOCK_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        self.fd_table.insert(
            fd,
            FdEntry {
                kind: FdKind::Socket { socket_id },
                flags: fd_flags,
            },
        );
        fd as i64
    }
```

- [ ] **Step 7: Add Socket variant to dispatch_syscall**

In `dispatch_syscall` (~line 1592, before `Unknown`), add:

```rust
            LinuxSyscall::Socket {
                domain,
                sock_type,
                protocol,
            } => self.sys_socket(domain, sock_type, protocol),
```

- [ ] **Step 8: Add Socket arms to existing match statements**

In `close_fd_entry` (~line 1805), add before the closing brace:

```rust
            FdKind::Socket { socket_id } => {
                let still_referenced = self.fd_table.values().any(
                    |e| matches!(&e.kind, FdKind::Socket { socket_id: id } if *id == socket_id),
                );
                if !still_referenced {
                    self.sockets.remove(&socket_id);
                }
            }
```

In `sys_read` (~line 1692), in the `match kind` block, add an arm for Socket:

```rust
            FdKind::Socket { .. } => {
                // Stub: no data, return EOF.
                0
            }
```

In `sys_write` (~line 1597), in the `match kind` block, add an arm for Socket:

```rust
            FdKind::Socket { .. } => {
                // Stub: pretend all bytes written.
                count as i64
            }
```

In `sys_fstat` (~line 2077), add an arm for Socket (similar to PipeRead/PipeWrite):

```rust
            FdKind::Socket { .. } => {
                let stat = FileStat {
                    qpath: 0,
                    name: alloc::sync::Arc::from("socket"),
                    size: 0,
                    file_type: FileType::Regular, // ignored — mode_override used
                };
                // S_IFSOCK = 0o140000
                write_linux_stat_with_mode(statbuf_ptr, &stat, Some(0o140644));
                return 0;
            }
```

The existing `sys_lseek` at line 2666 already has `Some(_) => return ESPIPE` which catches all non-File fd kinds including Socket. No change needed.

In `sys_ioctl` (~line 2525), restructure to fd-type-aware dispatch:

```rust
    fn sys_ioctl(&self, fd: i32, request: u64) -> i64 {
        let entry = match self.fd_table.get(&fd) {
            Some(e) => e,
            None => return EBADF,
        };
        const TIOCGWINSZ: u64 = 0x5413;
        const FIONBIO: u64 = 0x5421;
        match (&entry.kind, request) {
            (FdKind::Socket { .. }, FIONBIO) => 0,
            (_, TIOCGWINSZ) => ENOTTY,
            _ => EINVAL,
        }
    }
```

The mmap ENODEV guard at line 2326 already handles `Some(_) => return ENODEV` for any non-File fd, so Socket is already covered. No change needed.

- [ ] **Step 9: Add x86_64 syscall table entry for socket (nr 41)**

In `from_x86_64` (~line 343, after `Getpid`), add:

```rust
            41 => LinuxSyscall::Socket {
                domain: args[0] as i32,
                sock_type: args[1] as i32,
                protocol: args[2] as i32,
            },
```

- [ ] **Step 10: Add aarch64 syscall table entry for socket (nr 198)**

In `from_aarch64` (~line 610, after `Gettid`), add:

```rust
            198 => LinuxSyscall::Socket {
                domain: args[0] as i32,
                sock_type: args[1] as i32,
                protocol: args[2] as i32,
            },
```

- [ ] **Step 11: Run test to verify it passes**

Run: `cargo test -p harmony-os test_socket_create -- --nocapture 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 12: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add FdKind::Socket + sys_socket stub"
```

---

### Task 2: Socket Lifecycle Syscalls — bind, listen, accept4, accept, connect, shutdown

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn test_socket_lifecycle() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    // Create socket
    let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
        domain: 1, // AF_UNIX
        sock_type: 1, // SOCK_STREAM
        protocol: 0,
    });
    assert!(fd >= 0);

    // bind — no-op stub
    let r = lx.dispatch_syscall(LinuxSyscall::Bind {
        fd: fd as i32,
        addr: 0,
        addrlen: 0,
    });
    assert_eq!(r, 0);

    // listen
    let r = lx.dispatch_syscall(LinuxSyscall::Listen {
        fd: fd as i32,
        backlog: 128,
    });
    assert_eq!(r, 0);

    // accept4 — creates new fd
    let client_fd = lx.dispatch_syscall(LinuxSyscall::Accept4 {
        fd: fd as i32,
        addr: 0,
        addrlen: 0,
        flags: 0,
    });
    assert!(client_fd >= 0);
    assert_ne!(client_fd, fd);
    assert!(lx.has_fd(client_fd as i32));

    // connect — no-op stub
    let r = lx.dispatch_syscall(LinuxSyscall::Connect {
        fd: client_fd as i32,
        addr: 0,
        addrlen: 0,
    });
    assert_eq!(r, 0);

    // shutdown — no-op stub
    let r = lx.dispatch_syscall(LinuxSyscall::Shutdown {
        fd: client_fd as i32,
        how: 2, // SHUT_RDWR
    });
    assert_eq!(r, 0);

    // close both
    assert_eq!(lx.dispatch_syscall(LinuxSyscall::Close { fd: client_fd as i32 }), 0);
    assert_eq!(lx.dispatch_syscall(LinuxSyscall::Close { fd: fd as i32 }), 0);
}

#[test]
fn test_socket_accept_not_listening() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
        domain: 2,
        sock_type: 1,
        protocol: 0,
    });
    assert!(fd >= 0);

    // accept without listen → EINVAL
    let r = lx.dispatch_syscall(LinuxSyscall::Accept4 {
        fd: fd as i32,
        addr: 0,
        addrlen: 0,
        flags: 0,
    });
    assert_eq!(r, EINVAL);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-os test_socket_lifecycle test_socket_accept_not_listening -- --nocapture 2>&1 | tail -20`
Expected: compile error — `LinuxSyscall::Bind` etc. do not exist

- [ ] **Step 3: Add LinuxSyscall variants**

In the `LinuxSyscall` enum, after `Socket`, add:

```rust
    Bind {
        fd: i32,
        addr: u64,
        addrlen: u32,
    },
    Listen {
        fd: i32,
        backlog: i32,
    },
    Accept4 {
        fd: i32,
        addr: u64,
        addrlen: u64,
        flags: i32,
    },
    Accept {
        fd: i32,
        addr: u64,
        addrlen: u64,
    },
    Connect {
        fd: i32,
        addr: u64,
        addrlen: u32,
    },
    Shutdown {
        fd: i32,
        how: i32,
    },
```

- [ ] **Step 4: Implement handler functions**

After `sys_socket`, add:

```rust
    /// Helper: validate fd is a Socket, return ENOTSOCK/EBADF otherwise.
    fn require_socket(&self, fd: i32) -> Result<usize, i64> {
        match self.fd_table.get(&fd) {
            Some(FdEntry { kind: FdKind::Socket { socket_id }, .. }) => Ok(*socket_id),
            Some(_) => Err(ENOTSOCK),
            None => Err(EBADF),
        }
    }

    /// Linux bind(2): stub — no-op.
    fn sys_bind(&self, fd: i32, _addr: u64, _addrlen: u32) -> i64 {
        match self.require_socket(fd) {
            Ok(_) => 0,
            Err(e) => e,
        }
    }

    /// Linux listen(2): mark socket as listening.
    fn sys_listen(&mut self, fd: i32, _backlog: i32) -> i64 {
        match self.require_socket(fd) {
            Ok(socket_id) => {
                if let Some(state) = self.sockets.get_mut(&socket_id) {
                    state.listening = true;
                }
                0
            }
            Err(e) => e,
        }
    }

    /// Linux accept4(2): create a new stub socket fd from a listening socket.
    fn sys_accept4(&mut self, fd: i32, addr: u64, addrlen_ptr: u64, flags: i32) -> i64 {
        let socket_id = match self.require_socket(fd) {
            Ok(id) => id,
            Err(e) => return e,
        };

        let listening = self
            .sockets
            .get(&socket_id)
            .map_or(false, |s| s.listening);
        if !listening {
            return EINVAL;
        }

        // Get parent domain/type for the new socket.
        let (domain, sock_type) = match self.sockets.get(&socket_id) {
            Some(s) => (s.domain, s.sock_type),
            None => return EINVAL,
        };

        // Zero the sockaddr if caller provided one.
        if addr != 0 && addrlen_ptr != 0 {
            let addrlen_bytes =
                unsafe { core::slice::from_raw_parts(addrlen_ptr as usize as *const u8, 4) };
            let addrlen = u32::from_ne_bytes([
                addrlen_bytes[0],
                addrlen_bytes[1],
                addrlen_bytes[2],
                addrlen_bytes[3],
            ]) as usize;
            let zero_len = addrlen.min(128);
            if zero_len > 0 {
                let addr_buf = unsafe {
                    core::slice::from_raw_parts_mut(addr as usize as *mut u8, zero_len)
                };
                addr_buf.fill(0);
            }
            // Write 0 to *addrlen.
            let addrlen_out = unsafe {
                core::slice::from_raw_parts_mut(addrlen_ptr as usize as *mut u8, 4)
            };
            addrlen_out.copy_from_slice(&0u32.to_ne_bytes());
        }

        // Create new socket state.
        let new_socket_id = self.next_socket_id;
        self.next_socket_id += 1;
        self.sockets.insert(
            new_socket_id,
            SocketState {
                domain,
                sock_type,
                listening: false,
            },
        );

        let new_fd = self.alloc_fd();
        const SOCK_CLOEXEC: i32 = 0o2000000;
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
            },
        );
        new_fd as i64
    }

    /// Linux connect(2): stub — no-op.
    fn sys_connect(&self, fd: i32, _addr: u64, _addrlen: u32) -> i64 {
        match self.require_socket(fd) {
            Ok(_) => 0,
            Err(e) => e,
        }
    }

    /// Linux shutdown(2): stub — no-op.
    fn sys_shutdown(&self, fd: i32, _how: i32) -> i64 {
        match self.require_socket(fd) {
            Ok(_) => 0,
            Err(e) => e,
        }
    }
```

- [ ] **Step 5: Add dispatch arms and syscall table entries**

In `dispatch_syscall`, add:

```rust
            LinuxSyscall::Bind { fd, addr, addrlen } => self.sys_bind(fd, addr, addrlen),
            LinuxSyscall::Listen { fd, backlog } => self.sys_listen(fd, backlog),
            LinuxSyscall::Accept4 {
                fd,
                addr,
                addrlen,
                flags,
            } => self.sys_accept4(fd, addr, addrlen, flags),
            LinuxSyscall::Accept { fd, addr, addrlen } => self.sys_accept4(fd, addr, addrlen, 0),
            LinuxSyscall::Connect { fd, addr, addrlen } => self.sys_connect(fd, addr, addrlen),
            LinuxSyscall::Shutdown { fd, how } => self.sys_shutdown(fd, how),
```

In `from_x86_64`, add:

```rust
            42 => LinuxSyscall::Connect {
                fd: args[0] as i32,
                addr: args[1],
                addrlen: args[2] as u32,
            },
            43 => LinuxSyscall::Accept {
                fd: args[0] as i32,
                addr: args[1],
                addrlen: args[2],
            },
            48 => LinuxSyscall::Shutdown {
                fd: args[0] as i32,
                how: args[1] as i32,
            },
            49 => LinuxSyscall::Bind {
                fd: args[0] as i32,
                addr: args[1],
                addrlen: args[2] as u32,
            },
            50 => LinuxSyscall::Listen {
                fd: args[0] as i32,
                backlog: args[1] as i32,
            },
            288 => LinuxSyscall::Accept4 {
                fd: args[0] as i32,
                addr: args[1],
                addrlen: args[2],
                flags: args[3] as i32,
            },
```

In `from_aarch64`, add:

```rust
            200 => LinuxSyscall::Bind {
                fd: args[0] as i32,
                addr: args[1],
                addrlen: args[2] as u32,
            },
            201 => LinuxSyscall::Listen {
                fd: args[0] as i32,
                backlog: args[1] as i32,
            },
            202 => LinuxSyscall::Accept {
                fd: args[0] as i32,
                addr: args[1],
                addrlen: args[2],
            },
            203 => LinuxSyscall::Connect {
                fd: args[0] as i32,
                addr: args[1],
                addrlen: args[2] as u32,
            },
            210 => LinuxSyscall::Shutdown {
                fd: args[0] as i32,
                how: args[1] as i32,
            },
            242 => LinuxSyscall::Accept4 {
                fd: args[0] as i32,
                addr: args[1],
                addrlen: args[2],
                flags: args[3] as i32,
            },
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p harmony-os test_socket_lifecycle test_socket_accept_not_listening -- --nocapture 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add bind/listen/accept4/connect/shutdown stubs"
```

---

### Task 3: Socket Data Syscalls — sendto, recvfrom, setsockopt, getsockopt, getsockname, getpeername

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn test_socket_sendto_recvfrom() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
        domain: 2,
        sock_type: 1,
        protocol: 0,
    }) as i32;

    let buf = [0u8; 64];
    // sendto returns len (pretend sent)
    let r = lx.dispatch_syscall(LinuxSyscall::Sendto {
        fd,
        buf: buf.as_ptr() as u64,
        len: 64,
        flags: 0,
        dest_addr: 0,
        addrlen: 0,
    });
    assert_eq!(r, 64);

    // recvfrom returns 0 (EOF)
    let r = lx.dispatch_syscall(LinuxSyscall::Recvfrom {
        fd,
        buf: buf.as_ptr() as u64,
        len: 64,
        flags: 0,
        src_addr: 0,
        addrlen: 0,
    });
    assert_eq!(r, 0);
}

#[test]
fn test_socket_setsockopt_getsockopt() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
        domain: 2,
        sock_type: 1,
        protocol: 0,
    }) as i32;

    // setsockopt — no-op
    let r = lx.dispatch_syscall(LinuxSyscall::Setsockopt {
        fd,
        level: 1,
        optname: 2,
        optval: 0,
        optlen: 0,
    });
    assert_eq!(r, 0);

    // getsockopt — writes zeros
    let mut val = [0xFFu8; 4];
    let mut optlen = 4u32;
    let r = lx.dispatch_syscall(LinuxSyscall::Getsockopt {
        fd,
        level: 1,
        optname: 2,
        optval: val.as_mut_ptr() as u64,
        optlen: &mut optlen as *mut u32 as u64,
    });
    assert_eq!(r, 0);
    assert_eq!(val, [0, 0, 0, 0]);
}

#[test]
fn test_socket_getsockname_getpeername() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
        domain: 2,
        sock_type: 1,
        protocol: 0,
    }) as i32;

    let mut addr = [0xFFu8; 16];
    let mut addrlen = 16u32;

    // getsockname
    let r = lx.dispatch_syscall(LinuxSyscall::Getsockname {
        fd,
        addr: addr.as_mut_ptr() as u64,
        addrlen: &mut addrlen as *mut u32 as u64,
    });
    assert_eq!(r, 0);
    assert_eq!(addrlen, 0);
    assert!(addr.iter().all(|&b| b == 0));

    // Reset for getpeername
    addr.fill(0xFF);
    addrlen = 16;

    let r = lx.dispatch_syscall(LinuxSyscall::Getpeername {
        fd,
        addr: addr.as_mut_ptr() as u64,
        addrlen: &mut addrlen as *mut u32 as u64,
    });
    assert_eq!(r, 0);
    assert_eq!(addrlen, 0);
    assert!(addr.iter().all(|&b| b == 0));
}

#[test]
fn test_socket_read_write() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
        domain: 2,
        sock_type: 1,
        protocol: 0,
    }) as i32;

    let buf = [0u8; 32];
    // read → 0 (EOF)
    let r = lx.dispatch_syscall(LinuxSyscall::Read {
        fd,
        buf: buf.as_ptr() as u64,
        count: 32,
    });
    assert_eq!(r, 0);

    // write → count (discard)
    let r = lx.dispatch_syscall(LinuxSyscall::Write {
        fd,
        buf: buf.as_ptr() as u64,
        count: 32,
    });
    assert_eq!(r, 32);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os test_socket_sendto test_socket_setsockopt test_socket_getsockname test_socket_read_write -- --nocapture 2>&1 | tail -20`
Expected: compile error — `LinuxSyscall::Sendto` etc. do not exist

- [ ] **Step 3: Add LinuxSyscall variants**

```rust
    Sendto {
        fd: i32,
        buf: u64,
        len: u64,
        flags: i32,
        dest_addr: u64,
        addrlen: u32,
    },
    Recvfrom {
        fd: i32,
        buf: u64,
        len: u64,
        flags: i32,
        src_addr: u64,
        addrlen: u64,
    },
    Setsockopt {
        fd: i32,
        level: i32,
        optname: i32,
        optval: u64,
        optlen: u32,
    },
    Getsockopt {
        fd: i32,
        level: i32,
        optname: i32,
        optval: u64,
        optlen: u64,
    },
    Getsockname {
        fd: i32,
        addr: u64,
        addrlen: u64,
    },
    Getpeername {
        fd: i32,
        addr: u64,
        addrlen: u64,
    },
```

- [ ] **Step 4: Implement handler functions**

```rust
    /// Linux sendto(2): stub — pretend all bytes sent.
    fn sys_sendto(&self, fd: i32, _buf: u64, len: u64, _flags: i32, _addr: u64, _addrlen: u32) -> i64 {
        match self.require_socket(fd) {
            Ok(_) => len as i64,
            Err(e) => e,
        }
    }

    /// Linux recvfrom(2): stub — return EOF (no data).
    fn sys_recvfrom(&self, fd: i32, _buf: u64, _len: u64, _flags: i32, _src: u64, _addrlen: u64) -> i64 {
        match self.require_socket(fd) {
            Ok(_) => 0,
            Err(e) => e,
        }
    }

    /// Linux setsockopt(2): stub — no-op.
    fn sys_setsockopt(&self, fd: i32, _level: i32, _optname: i32, _optval: u64, _optlen: u32) -> i64 {
        match self.require_socket(fd) {
            Ok(_) => 0,
            Err(e) => e,
        }
    }

    /// Linux getsockopt(2): stub — write zeros to optval.
    fn sys_getsockopt(&self, fd: i32, _level: i32, _optname: i32, optval: u64, optlen_ptr: u64) -> i64 {
        match self.require_socket(fd) {
            Ok(_) => {
                if optval != 0 && optlen_ptr != 0 {
                    let optlen_bytes = unsafe {
                        core::slice::from_raw_parts(optlen_ptr as usize as *const u8, 4)
                    };
                    let optlen = u32::from_ne_bytes([
                        optlen_bytes[0],
                        optlen_bytes[1],
                        optlen_bytes[2],
                        optlen_bytes[3],
                    ]) as usize;
                    if optlen > 0 {
                        let buf = unsafe {
                            core::slice::from_raw_parts_mut(optval as usize as *mut u8, optlen)
                        };
                        buf.fill(0);
                    }
                }
                0
            }
            Err(e) => e,
        }
    }

    /// Helper: zero a sockaddr buffer and set *addrlen to 0.
    fn zero_sockaddr(&self, addr: u64, addrlen_ptr: u64) {
        if addr != 0 && addrlen_ptr != 0 {
            let addrlen_bytes = unsafe {
                core::slice::from_raw_parts(addrlen_ptr as usize as *const u8, 4)
            };
            let addrlen = u32::from_ne_bytes([
                addrlen_bytes[0],
                addrlen_bytes[1],
                addrlen_bytes[2],
                addrlen_bytes[3],
            ]) as usize;
            let zero_len = addrlen.min(128);
            if zero_len > 0 {
                let buf = unsafe {
                    core::slice::from_raw_parts_mut(addr as usize as *mut u8, zero_len)
                };
                buf.fill(0);
            }
            let out = unsafe {
                core::slice::from_raw_parts_mut(addrlen_ptr as usize as *mut u8, 4)
            };
            out.copy_from_slice(&0u32.to_ne_bytes());
        }
    }

    /// Linux getsockname(2): stub — return zeroed sockaddr.
    fn sys_getsockname(&self, fd: i32, addr: u64, addrlen_ptr: u64) -> i64 {
        match self.require_socket(fd) {
            Ok(_) => {
                self.zero_sockaddr(addr, addrlen_ptr);
                0
            }
            Err(e) => e,
        }
    }

    /// Linux getpeername(2): stub — return zeroed sockaddr.
    fn sys_getpeername(&self, fd: i32, addr: u64, addrlen_ptr: u64) -> i64 {
        match self.require_socket(fd) {
            Ok(_) => {
                self.zero_sockaddr(addr, addrlen_ptr);
                0
            }
            Err(e) => e,
        }
    }
```

- [ ] **Step 5: Add dispatch arms and syscall table entries**

In `dispatch_syscall`:

```rust
            LinuxSyscall::Sendto { fd, buf, len, flags, dest_addr, addrlen } => {
                self.sys_sendto(fd, buf, len, flags, dest_addr, addrlen)
            }
            LinuxSyscall::Recvfrom { fd, buf, len, flags, src_addr, addrlen } => {
                self.sys_recvfrom(fd, buf, len, flags, src_addr, addrlen)
            }
            LinuxSyscall::Setsockopt { fd, level, optname, optval, optlen } => {
                self.sys_setsockopt(fd, level, optname, optval, optlen)
            }
            LinuxSyscall::Getsockopt { fd, level, optname, optval, optlen } => {
                self.sys_getsockopt(fd, level, optname, optval, optlen)
            }
            LinuxSyscall::Getsockname { fd, addr, addrlen } => {
                self.sys_getsockname(fd, addr, addrlen)
            }
            LinuxSyscall::Getpeername { fd, addr, addrlen } => {
                self.sys_getpeername(fd, addr, addrlen)
            }
```

In `from_x86_64`:

```rust
            44 => LinuxSyscall::Sendto {
                fd: args[0] as i32,
                buf: args[1],
                len: args[2],
                flags: args[3] as i32,
                dest_addr: args[4],
                addrlen: args[5] as u32,
            },
            45 => LinuxSyscall::Recvfrom {
                fd: args[0] as i32,
                buf: args[1],
                len: args[2],
                flags: args[3] as i32,
                src_addr: args[4],
                addrlen: args[5],
            },
            51 => LinuxSyscall::Getsockname {
                fd: args[0] as i32,
                addr: args[1],
                addrlen: args[2],
            },
            52 => LinuxSyscall::Getpeername {
                fd: args[0] as i32,
                addr: args[1],
                addrlen: args[2],
            },
            54 => LinuxSyscall::Setsockopt {
                fd: args[0] as i32,
                level: args[1] as i32,
                optname: args[2] as i32,
                optval: args[3],
                optlen: args[4] as u32,
            },
            55 => LinuxSyscall::Getsockopt {
                fd: args[0] as i32,
                level: args[1] as i32,
                optname: args[2] as i32,
                optval: args[3],
                optlen: args[4],
            },
```

In `from_aarch64`:

```rust
            204 => LinuxSyscall::Getsockname {
                fd: args[0] as i32,
                addr: args[1],
                addrlen: args[2],
            },
            205 => LinuxSyscall::Getpeername {
                fd: args[0] as i32,
                addr: args[1],
                addrlen: args[2],
            },
            206 => LinuxSyscall::Sendto {
                fd: args[0] as i32,
                buf: args[1],
                len: args[2],
                flags: args[3] as i32,
                dest_addr: args[4],
                addrlen: args[5] as u32,
            },
            207 => LinuxSyscall::Recvfrom {
                fd: args[0] as i32,
                buf: args[1],
                len: args[2],
                flags: args[3] as i32,
                src_addr: args[4],
                addrlen: args[5],
            },
            208 => LinuxSyscall::Setsockopt {
                fd: args[0] as i32,
                level: args[1] as i32,
                optname: args[2] as i32,
                optval: args[3],
                optlen: args[4] as u32,
            },
            209 => LinuxSyscall::Getsockopt {
                fd: args[0] as i32,
                level: args[1] as i32,
                optname: args[2] as i32,
                optval: args[3],
                optlen: args[4],
            },
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p harmony-os test_socket_sendto test_socket_setsockopt test_socket_getsockname test_socket_read_write -- --nocapture 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add sendto/recvfrom/setsockopt/getsockopt/getsockname/getpeername stubs"
```

---

### Task 4: Socket Edge Cases — flags, fstat, lseek, mmap, wrong fd type, dup

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn test_socket_flags() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    // SOCK_CLOEXEC (0o2000000) should set FD_CLOEXEC
    let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
        domain: 2,
        sock_type: 1 | 0o2000000, // SOCK_STREAM | SOCK_CLOEXEC
        protocol: 0,
    }) as i32;

    let flags = lx.dispatch_syscall(LinuxSyscall::Fcntl {
        fd,
        cmd: 1, // F_GETFD
        arg: 0,
    });
    assert_eq!(flags, FD_CLOEXEC as i64);

    // SOCK_NONBLOCK accepted without error
    let fd2 = lx.dispatch_syscall(LinuxSyscall::Socket {
        domain: 1,
        sock_type: 1 | 0o4000, // SOCK_STREAM | SOCK_NONBLOCK
        protocol: 0,
    });
    assert!(fd2 >= 0);
}

#[test]
fn test_socket_fstat() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
        domain: 2,
        sock_type: 1,
        protocol: 0,
    }) as i32;

    // 144 bytes for x86_64 stat struct
    let mut stat_buf = [0u8; 144];
    let r = lx.dispatch_syscall(LinuxSyscall::Fstat {
        fd,
        buf: stat_buf.as_mut_ptr() as u64,
    });
    assert_eq!(r, 0);

    // st_mode is at offset 24 (x86_64), 4 bytes LE.
    // S_IFSOCK | 0o644 = 0o140644 = 0xC1A4
    let mode = u32::from_ne_bytes([stat_buf[24], stat_buf[25], stat_buf[26], stat_buf[27]]);
    assert_eq!(mode, 0o140644);
}

#[test]
fn test_socket_lseek_espipe() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
        domain: 2,
        sock_type: 1,
        protocol: 0,
    }) as i32;

    let r = lx.dispatch_syscall(LinuxSyscall::Lseek {
        fd,
        offset: 0,
        whence: 0,
    });
    assert_eq!(r, ESPIPE);
}

#[test]
fn test_socket_ops_wrong_fd_type() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    // Create a pipe — use the read end as a non-socket fd.
    let mut fds = [0i32; 2];
    lx.dispatch_syscall(LinuxSyscall::Pipe2 {
        fds: fds.as_mut_ptr() as u64,
        flags: 0,
    });
    let pipe_fd = fds[0];

    // All socket ops should return ENOTSOCK on a pipe fd.
    assert_eq!(
        lx.dispatch_syscall(LinuxSyscall::Bind { fd: pipe_fd, addr: 0, addrlen: 0 }),
        ENOTSOCK
    );
    assert_eq!(
        lx.dispatch_syscall(LinuxSyscall::Listen { fd: pipe_fd, backlog: 1 }),
        ENOTSOCK
    );
    assert_eq!(
        lx.dispatch_syscall(LinuxSyscall::Connect { fd: pipe_fd, addr: 0, addrlen: 0 }),
        ENOTSOCK
    );
    assert_eq!(
        lx.dispatch_syscall(LinuxSyscall::Sendto {
            fd: pipe_fd, buf: 0, len: 0, flags: 0, dest_addr: 0, addrlen: 0
        }),
        ENOTSOCK
    );
    assert_eq!(
        lx.dispatch_syscall(LinuxSyscall::Recvfrom {
            fd: pipe_fd, buf: 0, len: 0, flags: 0, src_addr: 0, addrlen: 0
        }),
        ENOTSOCK
    );
    assert_eq!(
        lx.dispatch_syscall(LinuxSyscall::Shutdown { fd: pipe_fd, how: 0 }),
        ENOTSOCK
    );
}

#[test]
fn test_socket_dup() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
        domain: 2,
        sock_type: 1,
        protocol: 0,
    }) as i32;

    let fd2 = lx.dispatch_syscall(LinuxSyscall::Dup { oldfd: fd }) as i32;
    assert!(fd2 >= 0);
    assert_ne!(fd, fd2);

    // Both are valid
    assert!(lx.has_fd(fd));
    assert!(lx.has_fd(fd2));

    // Close original — dup should still work
    lx.dispatch_syscall(LinuxSyscall::Close { fd });
    assert!(!lx.has_fd(fd));
    assert!(lx.has_fd(fd2));

    // Dup'd socket still accepts operations
    let r = lx.dispatch_syscall(LinuxSyscall::Bind {
        fd: fd2,
        addr: 0,
        addrlen: 0,
    });
    assert_eq!(r, 0);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os test_socket_flags test_socket_fstat test_socket_lseek_espipe test_socket_ops_wrong_fd_type test_socket_dup -- --nocapture 2>&1 | tail -20`
Expected: PASS (all infrastructure is already in place from Tasks 1-3). If any fail, fix the match arm.

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "test(linuxulator): socket edge case tests — flags, fstat, lseek, wrong-fd-type, dup"
```

---

### Task 5: Epoll — FdKind::Epoll, EpollState, epoll_create1, epoll_ctl, epoll_wait, epoll_pwait

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn test_epoll_create_and_ctl() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    // Create epoll fd
    let epfd = lx.dispatch_syscall(LinuxSyscall::EpollCreate1 { flags: 0 });
    assert!(epfd >= 0);
    assert!(lx.has_fd(epfd as i32));

    // Create a pipe to register
    let mut fds = [0i32; 2];
    lx.dispatch_syscall(LinuxSyscall::Pipe2 {
        fds: fds.as_mut_ptr() as u64,
        flags: 0,
    });

    // EPOLL_CTL_ADD
    let mut event = EpollEventBuf::new(0x1, fds[0] as u64); // EPOLLIN
    let r = lx.dispatch_syscall(LinuxSyscall::EpollCtl {
        epfd: epfd as i32,
        op: 1, // ADD
        fd: fds[0],
        event: event.as_ptr(),
    });
    assert_eq!(r, 0);

    // EPOLL_CTL_ADD duplicate → EEXIST
    let r = lx.dispatch_syscall(LinuxSyscall::EpollCtl {
        epfd: epfd as i32,
        op: 1,
        fd: fds[0],
        event: event.as_ptr(),
    });
    assert_eq!(r, EEXIST);

    // EPOLL_CTL_MOD
    event.set_events(0x4); // EPOLLOUT
    let r = lx.dispatch_syscall(LinuxSyscall::EpollCtl {
        epfd: epfd as i32,
        op: 2, // MOD
        fd: fds[0],
        event: event.as_ptr(),
    });
    assert_eq!(r, 0);

    // EPOLL_CTL_DEL
    let r = lx.dispatch_syscall(LinuxSyscall::EpollCtl {
        epfd: epfd as i32,
        op: 3, // DEL
        fd: fds[0],
        event: 0,
    });
    assert_eq!(r, 0);

    // EPOLL_CTL_DEL again → ENOENT
    let r = lx.dispatch_syscall(LinuxSyscall::EpollCtl {
        epfd: epfd as i32,
        op: 3,
        fd: fds[0],
        event: 0,
    });
    assert_eq!(r, ENOENT);

    // EPOLL_CTL_MOD on removed → ENOENT
    let r = lx.dispatch_syscall(LinuxSyscall::EpollCtl {
        epfd: epfd as i32,
        op: 2,
        fd: fds[0],
        event: event.as_ptr(),
    });
    assert_eq!(r, ENOENT);
}

#[test]
fn test_epoll_wait_returns_ready() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    let epfd = lx.dispatch_syscall(LinuxSyscall::EpollCreate1 { flags: 0 }) as i32;

    // Create two pipes and register both
    let mut fds1 = [0i32; 2];
    let mut fds2 = [0i32; 2];
    lx.dispatch_syscall(LinuxSyscall::Pipe2 { fds: fds1.as_mut_ptr() as u64, flags: 0 });
    lx.dispatch_syscall(LinuxSyscall::Pipe2 { fds: fds2.as_mut_ptr() as u64, flags: 0 });

    let mut ev1 = EpollEventBuf::new(0x1, fds1[0] as u64); // EPOLLIN
    let mut ev2 = EpollEventBuf::new(0x4, fds2[0] as u64); // EPOLLOUT

    lx.dispatch_syscall(LinuxSyscall::EpollCtl {
        epfd, op: 1, fd: fds1[0], event: ev1.as_ptr(),
    });
    lx.dispatch_syscall(LinuxSyscall::EpollCtl {
        epfd, op: 1, fd: fds2[0], event: ev2.as_ptr(),
    });

    // Wait — all registered fds returned as ready
    let mut out = [EpollEventBuf::new(0, 0); 4];
    let n = lx.dispatch_syscall(LinuxSyscall::EpollWait {
        epfd,
        events: out[0].as_ptr(),
        maxevents: 4,
        timeout: -1,
    });
    assert_eq!(n, 2);

    // Verify events contain the registered data
    let returned: alloc::collections::BTreeSet<u64> = out[..2]
        .iter()
        .map(|e| e.data())
        .collect();
    assert!(returned.contains(&(fds1[0] as u64)));
    assert!(returned.contains(&(fds2[0] as u64)));
}

#[test]
fn test_epoll_wait_empty() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    let epfd = lx.dispatch_syscall(LinuxSyscall::EpollCreate1 { flags: 0 }) as i32;

    let mut out = [EpollEventBuf::new(0, 0); 4];
    let n = lx.dispatch_syscall(LinuxSyscall::EpollWait {
        epfd,
        events: out[0].as_ptr(),
        maxevents: 4,
        timeout: 0,
    });
    assert_eq!(n, 0);
}

#[test]
fn test_epoll_wait_maxevents() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    let epfd = lx.dispatch_syscall(LinuxSyscall::EpollCreate1 { flags: 0 }) as i32;

    // Register 3 pipes
    for _ in 0..3 {
        let mut fds = [0i32; 2];
        lx.dispatch_syscall(LinuxSyscall::Pipe2 { fds: fds.as_mut_ptr() as u64, flags: 0 });
        let mut ev = EpollEventBuf::new(0x1, fds[0] as u64);
        lx.dispatch_syscall(LinuxSyscall::EpollCtl {
            epfd, op: 1, fd: fds[0], event: ev.as_ptr(),
        });
    }

    // Wait with maxevents=2 → only 2 returned
    let mut out = [EpollEventBuf::new(0, 0); 4];
    let n = lx.dispatch_syscall(LinuxSyscall::EpollWait {
        epfd,
        events: out[0].as_ptr(),
        maxevents: 2,
        timeout: -1,
    });
    assert_eq!(n, 2);
}

#[test]
fn test_epoll_ctl_bad_fd() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    let epfd = lx.dispatch_syscall(LinuxSyscall::EpollCreate1 { flags: 0 }) as i32;

    let mut ev = EpollEventBuf::new(0x1, 999);
    // Target fd 999 doesn't exist → EBADF
    let r = lx.dispatch_syscall(LinuxSyscall::EpollCtl {
        epfd,
        op: 1,
        fd: 999,
        event: ev.as_ptr(),
    });
    assert_eq!(r, EBADF);
}

#[test]
fn test_epoll_read_write_einval() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    let epfd = lx.dispatch_syscall(LinuxSyscall::EpollCreate1 { flags: 0 }) as i32;

    let buf = [0u8; 8];
    let r = lx.dispatch_syscall(LinuxSyscall::Read {
        fd: epfd,
        buf: buf.as_ptr() as u64,
        count: 8,
    });
    assert_eq!(r, EINVAL);

    let r = lx.dispatch_syscall(LinuxSyscall::Write {
        fd: epfd,
        buf: buf.as_ptr() as u64,
        count: 8,
    });
    assert_eq!(r, EINVAL);
}

#[test]
fn test_epoll_close_cleanup() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    let epfd = lx.dispatch_syscall(LinuxSyscall::EpollCreate1 { flags: 0 }) as i32;
    assert!(lx.has_fd(epfd));

    lx.dispatch_syscall(LinuxSyscall::Close { fd: epfd });
    assert!(!lx.has_fd(epfd));
}

#[test]
fn test_epoll_ops_wrong_fd_type() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    // Use a pipe fd as the epfd argument → EINVAL
    let mut fds = [0i32; 2];
    lx.dispatch_syscall(LinuxSyscall::Pipe2 { fds: fds.as_mut_ptr() as u64, flags: 0 });

    let mut ev = EpollEventBuf::new(0x1, 0);
    let r = lx.dispatch_syscall(LinuxSyscall::EpollCtl {
        epfd: fds[0],
        op: 1,
        fd: fds[1],
        event: ev.as_ptr(),
    });
    assert_eq!(r, EINVAL);

    let mut out = [EpollEventBuf::new(0, 0); 4];
    let r = lx.dispatch_syscall(LinuxSyscall::EpollWait {
        epfd: fds[0],
        events: out[0].as_ptr(),
        maxevents: 4,
        timeout: 0,
    });
    assert_eq!(r, EINVAL);
}

#[test]
fn test_epoll_data_roundtrip() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    let epfd = lx.dispatch_syscall(LinuxSyscall::EpollCreate1 { flags: 0 }) as i32;

    let mut fds = [0i32; 2];
    lx.dispatch_syscall(LinuxSyscall::Pipe2 { fds: fds.as_mut_ptr() as u64, flags: 0 });

    // Store a distinctive data value
    let magic: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mut ev = EpollEventBuf::new(0x1, magic);
    lx.dispatch_syscall(LinuxSyscall::EpollCtl {
        epfd, op: 1, fd: fds[0], event: ev.as_ptr(),
    });

    let mut out = [EpollEventBuf::new(0, 0); 2];
    let n = lx.dispatch_syscall(LinuxSyscall::EpollWait {
        epfd,
        events: out[0].as_ptr(),
        maxevents: 2,
        timeout: -1,
    });
    assert_eq!(n, 1);
    assert_eq!(out[0].data(), magic);
    assert_eq!(out[0].events(), 0x1);
}
```

- [ ] **Step 2: Add EpollEventBuf test helper**

In the `#[cfg(test)] mod tests` section, add a helper struct:

```rust
    /// Test helper for reading/writing epoll_event structs.
    /// On x86_64: packed [u32 events][u64 data] = 12 bytes.
    /// On aarch64: [u32 events][4 pad][u64 data] = 16 bytes.
    #[derive(Clone, Copy)]
    #[repr(C)]
    struct EpollEventBuf {
        #[cfg(target_arch = "x86_64")]
        buf: [u8; 12],
        #[cfg(target_arch = "aarch64")]
        buf: [u8; 16],
    }

    impl EpollEventBuf {
        fn new(events: u32, data: u64) -> Self {
            let mut s = Self {
                #[cfg(target_arch = "x86_64")]
                buf: [0u8; 12],
                #[cfg(target_arch = "aarch64")]
                buf: [0u8; 16],
            };
            s.set_events(events);
            s.set_data(data);
            s
        }

        fn as_ptr(&self) -> u64 {
            self.buf.as_ptr() as u64
        }

        fn events(&self) -> u32 {
            u32::from_ne_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]])
        }

        fn set_events(&mut self, events: u32) {
            self.buf[0..4].copy_from_slice(&events.to_ne_bytes());
        }

        #[cfg(target_arch = "x86_64")]
        fn data(&self) -> u64 {
            u64::from_ne_bytes([
                self.buf[4], self.buf[5], self.buf[6], self.buf[7],
                self.buf[8], self.buf[9], self.buf[10], self.buf[11],
            ])
        }

        #[cfg(target_arch = "aarch64")]
        fn data(&self) -> u64 {
            u64::from_ne_bytes([
                self.buf[8], self.buf[9], self.buf[10], self.buf[11],
                self.buf[12], self.buf[13], self.buf[14], self.buf[15],
            ])
        }

        #[cfg(target_arch = "x86_64")]
        fn set_data(&mut self, data: u64) {
            self.buf[4..12].copy_from_slice(&data.to_ne_bytes());
        }

        #[cfg(target_arch = "aarch64")]
        fn set_data(&mut self, data: u64) {
            self.buf[8..16].copy_from_slice(&data.to_ne_bytes());
        }
    }
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p harmony-os test_epoll -- --nocapture 2>&1 | tail -30`
Expected: compile error — `LinuxSyscall::EpollCreate1` etc. do not exist

- [ ] **Step 4: Add EpollState struct and FdKind::Epoll variant**

After `SocketState` struct, add:

```rust
/// Shared state for an epoll instance.
struct EpollState {
    /// Registered fds: fd → (event mask, user data).
    interests: BTreeMap<i32, (u32, u64)>,
}
```

In `FdKind` enum, add:

```rust
    /// Epoll instance (always-ready stub).
    Epoll { epoll_id: usize },
```

Add epoll fields to `Linuxulator` struct:

```rust
    /// Epoll state keyed by epoll_id.
    epolls: BTreeMap<usize, EpollState>,
    /// Next epoll_id to allocate.
    next_epoll_id: usize,
```

Initialize in `with_arena()`:

```rust
            epolls: BTreeMap::new(),
            next_epoll_id: 0,
```

- [ ] **Step 5: Add Epoll arms to existing match statements**

In `close_fd_entry`:

```rust
            FdKind::Epoll { epoll_id } => {
                let still_referenced = self.fd_table.values().any(
                    |e| matches!(&e.kind, FdKind::Epoll { epoll_id: id } if *id == epoll_id),
                );
                if !still_referenced {
                    self.epolls.remove(&epoll_id);
                }
            }
```

In `sys_read`, add:

```rust
            FdKind::Epoll { .. } => EINVAL,
```

In `sys_write`, add:

```rust
            FdKind::Epoll { .. } => EINVAL,
```

In `sys_fstat`, add:

```rust
            FdKind::Epoll { .. } => {
                let stat = FileStat {
                    qpath: 0,
                    name: alloc::sync::Arc::from("epoll"),
                    size: 0,
                    file_type: FileType::Regular,
                };
                write_linux_stat(statbuf_ptr, &stat);
                return 0;
            }
```

The existing `sys_lseek` catch-all `Some(_) => return ESPIPE` already covers Epoll. No change needed.

- [ ] **Step 6: Add LinuxSyscall variants**

```rust
    EpollCreate1 {
        flags: i32,
    },
    EpollCtl {
        epfd: i32,
        op: i32,
        fd: i32,
        event: u64,
    },
    EpollWait {
        epfd: i32,
        events: u64,
        maxevents: i32,
        timeout: i32,
    },
    EpollPwait {
        epfd: i32,
        events: u64,
        maxevents: i32,
        timeout: i32,
        sigmask: u64,
        sigsetsize: u64,
    },
```

- [ ] **Step 7: Implement epoll syscall handlers**

```rust
    // ── Epoll ─────────────────────────────────────────────────────

    /// Linux epoll_create1(2): create an epoll instance.
    fn sys_epoll_create1(&mut self, flags: i32) -> i64 {
        const EPOLL_CLOEXEC: i32 = 0x80000;
        if flags & !EPOLL_CLOEXEC != 0 {
            return EINVAL;
        }

        let epoll_id = self.next_epoll_id;
        self.next_epoll_id += 1;
        self.epolls.insert(
            epoll_id,
            EpollState {
                interests: BTreeMap::new(),
            },
        );

        let fd = self.alloc_fd();
        let fd_flags = if flags & EPOLL_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        self.fd_table.insert(
            fd,
            FdEntry {
                kind: FdKind::Epoll { epoll_id },
                flags: fd_flags,
            },
        );
        fd as i64
    }

    /// Helper: validate fd is an Epoll, return EINVAL/EBADF otherwise.
    fn require_epoll(&self, epfd: i32) -> Result<usize, i64> {
        match self.fd_table.get(&epfd) {
            Some(FdEntry { kind: FdKind::Epoll { epoll_id }, .. }) => Ok(*epoll_id),
            Some(_) => Err(EINVAL),
            None => Err(EBADF),
        }
    }

    /// Linux epoll_ctl(2): add/modify/delete an fd in the interest set.
    fn sys_epoll_ctl(&mut self, epfd: i32, op: i32, fd: i32, event_ptr: u64) -> i64 {
        let epoll_id = match self.require_epoll(epfd) {
            Ok(id) => id,
            Err(e) => return e,
        };

        // Validate target fd exists (except for DEL, which Linux allows
        // with a stale fd in some cases, but we keep it strict).
        if !self.fd_table.contains_key(&fd) {
            return EBADF;
        }

        const EPOLL_CTL_ADD: i32 = 1;
        const EPOLL_CTL_DEL: i32 = 3;
        const EPOLL_CTL_MOD: i32 = 2;

        match op {
            EPOLL_CTL_ADD => {
                // Read epoll_event from user memory.
                let (events, data) = self.read_epoll_event(event_ptr);
                let state = match self.epolls.get_mut(&epoll_id) {
                    Some(s) => s,
                    None => return EINVAL,
                };
                if state.interests.contains_key(&fd) {
                    return EEXIST;
                }
                state.interests.insert(fd, (events, data));
                0
            }
            EPOLL_CTL_MOD => {
                let (events, data) = self.read_epoll_event(event_ptr);
                let state = match self.epolls.get_mut(&epoll_id) {
                    Some(s) => s,
                    None => return EINVAL,
                };
                if !state.interests.contains_key(&fd) {
                    return ENOENT;
                }
                state.interests.insert(fd, (events, data));
                0
            }
            EPOLL_CTL_DEL => {
                let state = match self.epolls.get_mut(&epoll_id) {
                    Some(s) => s,
                    None => return EINVAL,
                };
                if state.interests.remove(&fd).is_none() {
                    return ENOENT;
                }
                0
            }
            _ => EINVAL,
        }
    }

    /// Read an epoll_event struct from user memory.
    /// x86_64: packed [u32 events][u64 data] = 12 bytes.
    /// aarch64: [u32 events][4 pad][u64 data] = 16 bytes.
    fn read_epoll_event(&self, ptr: u64) -> (u32, u64) {
        let addr = ptr as usize;
        let events_bytes = unsafe { core::slice::from_raw_parts(addr as *const u8, 4) };
        let events = u32::from_ne_bytes([
            events_bytes[0],
            events_bytes[1],
            events_bytes[2],
            events_bytes[3],
        ]);

        #[cfg(target_arch = "x86_64")]
        let data_offset = 4; // packed
        #[cfg(target_arch = "aarch64")]
        let data_offset = 8; // naturally aligned
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let data_offset = 4; // default to packed

        let data_bytes =
            unsafe { core::slice::from_raw_parts((addr + data_offset) as *const u8, 8) };
        let data = u64::from_ne_bytes([
            data_bytes[0],
            data_bytes[1],
            data_bytes[2],
            data_bytes[3],
            data_bytes[4],
            data_bytes[5],
            data_bytes[6],
            data_bytes[7],
        ]);
        (events, data)
    }

    /// Write an epoll_event struct to user memory.
    fn write_epoll_event(&self, ptr: u64, events: u32, data: u64) {
        let addr = ptr as usize;
        let events_out = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, 4) };
        events_out.copy_from_slice(&events.to_ne_bytes());

        #[cfg(target_arch = "x86_64")]
        let data_offset = 4;
        #[cfg(target_arch = "aarch64")]
        let data_offset = 8;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let data_offset = 4;

        let data_out =
            unsafe { core::slice::from_raw_parts_mut((addr + data_offset) as *mut u8, 8) };
        data_out.copy_from_slice(&data.to_ne_bytes());
    }

    /// Size of one epoll_event struct in bytes.
    fn epoll_event_size(&self) -> usize {
        #[cfg(target_arch = "x86_64")]
        { 12 }
        #[cfg(target_arch = "aarch64")]
        { 16 }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        { 12 }
    }

    /// Linux epoll_wait(2): return all registered fds as ready.
    fn sys_epoll_wait(&self, epfd: i32, events_ptr: u64, maxevents: i32, _timeout: i32) -> i64 {
        let epoll_id = match self.require_epoll(epfd) {
            Ok(id) => id,
            Err(e) => return e,
        };

        if maxevents <= 0 {
            return EINVAL;
        }

        let state = match self.epolls.get(&epoll_id) {
            Some(s) => s,
            None => return EINVAL,
        };

        let event_size = self.epoll_event_size();
        let mut written = 0i64;
        for (&_fd, &(mask, data)) in state.interests.iter() {
            if written >= maxevents as i64 {
                break;
            }
            let offset = (written as usize) * event_size;
            self.write_epoll_event(events_ptr + offset as u64, mask, data);
            written += 1;
        }
        written
    }
```

- [ ] **Step 8: Add dispatch arms and syscall table entries**

In `dispatch_syscall`:

```rust
            LinuxSyscall::EpollCreate1 { flags } => self.sys_epoll_create1(flags),
            LinuxSyscall::EpollCtl {
                epfd,
                op,
                fd,
                event,
            } => self.sys_epoll_ctl(epfd, op, fd, event),
            LinuxSyscall::EpollWait {
                epfd,
                events,
                maxevents,
                timeout,
            } => self.sys_epoll_wait(epfd, events, maxevents, timeout),
            LinuxSyscall::EpollPwait {
                epfd,
                events,
                maxevents,
                timeout,
                ..
            } => self.sys_epoll_wait(epfd, events, maxevents, timeout),
```

In `from_x86_64`:

```rust
            232 => LinuxSyscall::EpollWait {
                epfd: args[0] as i32,
                events: args[1],
                maxevents: args[2] as i32,
                timeout: args[3] as i32,
            },
            233 => LinuxSyscall::EpollCtl {  // NOTE: this is x86_64 nr 233, not aarch64's 233 (Madvise)
                epfd: args[0] as i32,
                op: args[1] as i32,
                fd: args[2] as i32,
                event: args[3],
            },
            281 => LinuxSyscall::EpollPwait {
                epfd: args[0] as i32,
                events: args[1],
                maxevents: args[2] as i32,
                timeout: args[3] as i32,
                sigmask: args[4],
                sigsetsize: args[5],
            },
            291 => LinuxSyscall::EpollCreate1 {
                flags: args[0] as i32,
            },
```

In `from_aarch64`:

```rust
            20 => LinuxSyscall::EpollCreate1 {
                flags: args[0] as i32,
            },
            21 => LinuxSyscall::EpollCtl {
                epfd: args[0] as i32,
                op: args[1] as i32,
                fd: args[2] as i32,
                event: args[3],
            },
            22 => LinuxSyscall::EpollPwait {
                epfd: args[0] as i32,
                events: args[1],
                maxevents: args[2] as i32,
                timeout: args[3] as i32,
                sigmask: args[4],
                sigsetsize: args[5],
            },
```

- [ ] **Step 9: Run tests to verify they pass**

Run: `cargo test -p harmony-os test_epoll -- --nocapture 2>&1 | tail -30`
Expected: PASS (all 10 epoll tests)

- [ ] **Step 10: Run full test suite**

Run: `cargo test -p harmony-os 2>&1 | tail -10`
Expected: all tests pass, no warnings

- [ ] **Step 11: Run clippy and fmt**

Run: `cargo clippy -p harmony-os -- -D warnings 2>&1 | tail -20`
Run: `cargo fmt --all -- --check 2>&1 | tail -5`
Expected: clean

- [ ] **Step 12: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add epoll_create1/epoll_ctl/epoll_wait/epoll_pwait skeleton"
```

---

### Task 6: Final Integration — mmap guard, full test suite, quality gates

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Write mmap ENODEV test for socket**

```rust
#[test]
fn test_socket_mmap_enodev() {
    let mock = MockBackend::new();
    let mut lx = Linuxulator::new(mock);

    let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
        domain: 2,
        sock_type: 1,
        protocol: 0,
    }) as i32;

    let r = lx.dispatch_syscall(LinuxSyscall::Mmap {
        addr: 0,
        len: 4096,
        prot: 1, // PROT_READ
        flags: 2, // MAP_PRIVATE (NOT MAP_ANONYMOUS)
        fd,
        offset: 0,
    });
    assert_eq!(r, ENODEV);
}
```

- [ ] **Step 2: Run to verify it passes**

The existing mmap guard `Some(_) => return ENODEV` at line 2326 already handles this. Verify:

Run: `cargo test -p harmony-os test_socket_mmap_enodev -- --nocapture 2>&1 | tail -10`
Expected: PASS

- [ ] **Step 3: Run full workspace test suite**

Run: `cargo test --workspace 2>&1 | tail -10`
Expected: all tests pass

- [ ] **Step 4: Run clippy on workspace**

Run: `cargo clippy --workspace -- -D warnings 2>&1 | tail -20`
Expected: clean

- [ ] **Step 5: Run fmt check**

Run: `cargo fmt --all -- --check 2>&1 | tail -5`
Expected: clean

- [ ] **Step 6: Commit final test**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "test(linuxulator): mmap ENODEV test for socket fds"
```
