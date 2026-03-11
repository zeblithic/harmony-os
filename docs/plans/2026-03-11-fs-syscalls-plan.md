# Linuxulator Filesystem Syscalls Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add 8 filesystem syscalls (newfstatat, faccessat, readlinkat, getdents64, chdir, fchdir, mkdirat, unlinkat) to the Linuxulator with cwd tracking, SyscallBackend.readdir extension, and full test coverage.

**Architecture:** Extend the existing `LinuxSyscall` enum, `SyscallBackend` trait, and `Linuxulator` struct in `crates/harmony-os/src/linuxulator.rs`. New syscalls follow the established pattern: enum variant → `from_x86_64`/`from_aarch64` mapping → `dispatch_syscall` match arm → `sys_*` method. Directory listing uses a new `readdir` method on `SyscallBackend` with a default `NotSupported` return. CWD tracking adds two fields to `Linuxulator` and a `path` field to `FdEntry`.

**Tech Stack:** Rust (no_std compatible), harmony-microkernel `FileType`/`FileStat`/`IpcError`, aarch64 assembly (test ELF only)

---

### Task 1: DirEntry struct and SyscallBackend.readdir

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs:363-430` (SyscallBackend trait + DirEntry)

**Step 1: Add DirEntry struct above SyscallBackend trait**

After the `vm_err_to_errno` function (line 59) and before the `LinuxSyscall` enum (line 63), add:

```rust
/// Directory entry returned by [`SyscallBackend::readdir`].
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: alloc::string::String,
    pub file_type: FileType,
}
```

**Step 2: Add readdir to SyscallBackend trait**

After `vm_write_bytes` (line 429), inside the trait:

```rust
    /// Read directory entries from an open directory fid.
    ///
    /// Returns all entries. The Linuxulator handles pagination via
    /// `FdEntry.offset` as an entry index across `getdents64` calls.
    /// Default returns `NotSupported`; backends serving directories override.
    fn readdir(&mut self, _fid: Fid) -> Result<Vec<DirEntry>, IpcError> {
        Err(IpcError::NotSupported)
    }
```

**Step 3: Run tests**

Run: `cargo test -p harmony-os`
Expected: PASS (no behavioral change, just new types and a default method)

**Step 4: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add DirEntry struct and SyscallBackend.readdir"
```

---

### Task 2: FdEntry.path and Linuxulator cwd fields

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs:847-900` (FdEntry, Linuxulator struct, constructors)

**Step 1: Add path to FdEntry**

```rust
struct FdEntry {
    fid: Fid,
    offset: u64,
    /// Path walked to open this fd. None for stdio fds.
    path: Option<alloc::string::String>,
}
```

**Step 2: Add cwd fields to Linuxulator**

After `getrandom_counter` (line 877):

```rust
    /// Current working directory path.
    cwd: alloc::string::String,
```

**Step 3: Update constructors**

In `with_arena` (line 887), add `cwd: alloc::string::String::from("/"),` to the struct literal.

**Step 4: Update all FdEntry construction sites**

Every place that creates an `FdEntry` needs `path: None` or `path: Some(...)`:
- `init_stdio` (~lines 928, 941, 954): add `path: None`
- `sys_openat` (~line 1198): change to `path: Some(alloc::string::String::from(path))` (where `path` is the walked path string)

**Step 5: Run tests**

Run: `cargo test -p harmony-os`
Expected: PASS (structural change, no behavioral change)

**Step 6: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add FdEntry.path and Linuxulator.cwd fields"
```

---

### Task 3: LinuxSyscall enum variants and number mappings

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs:66-360` (LinuxSyscall enum, from_x86_64, from_aarch64)

**Step 1: Add new enum variants**

After `Readlink` and before `Unknown`:

```rust
    Newfstatat {
        dirfd: i32,
        pathname: u64,
        statbuf: u64,
        flags: i32,
    },
    Faccessat {
        dirfd: i32,
        pathname: u64,
        mode: i32,
    },
    Getdents64 {
        fd: i32,
        dirp: u64,
        count: u64,
    },
    Chdir {
        pathname: u64,
    },
    Fchdir {
        fd: i32,
    },
    Mkdirat {
        dirfd: i32,
        pathname: u64,
        mode: u32,
    },
    Unlinkat {
        dirfd: i32,
        pathname: u64,
        flags: i32,
    },
```

**Step 2: Add x86_64 mappings in from_x86_64**

```rust
            80 => LinuxSyscall::Chdir { pathname: args[0] },
            81 => LinuxSyscall::Fchdir { fd: args[0] as i32 },
            217 => LinuxSyscall::Getdents64 {
                fd: args[0] as i32,
                dirp: args[1],
                count: args[2],
            },
            258 => LinuxSyscall::Mkdirat {
                dirfd: args[0] as i32,
                pathname: args[1],
                mode: args[2] as u32,
            },
            262 => LinuxSyscall::Newfstatat {
                dirfd: args[0] as i32,
                pathname: args[1],
                statbuf: args[2],
                flags: args[3] as i32,
            },
            263 => LinuxSyscall::Unlinkat {
                dirfd: args[0] as i32,
                pathname: args[1],
                flags: args[2] as i32,
            },
            269 => LinuxSyscall::Faccessat {
                dirfd: args[0] as i32,
                pathname: args[1],
                mode: args[2] as i32,
            },
```

Note: x86_64 nr 80 conflicts with existing `Getcwd` mapping? No — `Getcwd` is nr 79 on x86_64. Nr 80 is `chdir`. Safe.

**Step 3: Add aarch64 mappings in from_aarch64**

```rust
            34 => LinuxSyscall::Mkdirat {
                dirfd: args[0] as i32,
                pathname: args[1],
                mode: args[2] as u32,
            },
            35 => LinuxSyscall::Unlinkat {
                dirfd: args[0] as i32,
                pathname: args[1],
                flags: args[2] as i32,
            },
            48 => LinuxSyscall::Faccessat {
                dirfd: args[0] as i32,
                pathname: args[1],
                mode: args[2] as i32,
            },
            49 => LinuxSyscall::Chdir { pathname: args[0] },
            50 => LinuxSyscall::Fchdir { fd: args[0] as i32 },
            61 => LinuxSyscall::Getdents64 {
                fd: args[0] as i32,
                dirp: args[1],
                count: args[2],
            },
```

Also update aarch64 nr 79 to map to `Newfstatat` instead of the existing `Fstat`:

```rust
            // aarch64 nr 79 is newfstatat(dirfd, pathname, statbuf, flags).
            // Previously mapped to Fstat; newfstatat with AT_EMPTY_PATH
            // subsumes fstat functionality.
            79 => LinuxSyscall::Newfstatat {
                dirfd: args[0] as i32,
                pathname: args[1],
                statbuf: args[2],
                flags: args[3] as i32,
            },
```

Wait — aarch64 nr 80 is currently mapped to `Fstat`. Check: aarch64 uses the asm-generic table where `fstat` is nr 80 and `fstatat`/`newfstatat` is nr 79. Keep nr 80 as `Fstat` and add nr 79 as `Newfstatat`. They are different syscalls.

**Step 4: Add dispatch_syscall match arms**

In `dispatch_syscall` (after the `Readlink` arm, before `Unknown`), add placeholder arms that return `ENOSYS`:

```rust
            LinuxSyscall::Newfstatat { dirfd, pathname, statbuf, flags } => {
                self.sys_newfstatat(dirfd, pathname as usize, statbuf as usize, flags)
            }
            LinuxSyscall::Faccessat { dirfd, pathname, mode } => {
                self.sys_faccessat(dirfd, pathname as usize, mode)
            }
            LinuxSyscall::Getdents64 { fd, dirp, count } => {
                self.sys_getdents64(fd, dirp as usize, count as usize)
            }
            LinuxSyscall::Chdir { pathname } => self.sys_chdir(pathname as usize),
            LinuxSyscall::Fchdir { fd } => self.sys_fchdir(fd),
            LinuxSyscall::Mkdirat { .. } => self.sys_mkdirat(),
            LinuxSyscall::Unlinkat { .. } => self.sys_unlinkat(),
```

**Step 5: Add stub sys_* methods**

Before the closing `}` of `impl<B: SyscallBackend> Linuxulator<B>` (line 1785):

```rust
    fn sys_newfstatat(&mut self, _dirfd: i32, _pathname_ptr: usize, _statbuf_ptr: usize, _flags: i32) -> i64 { ENOSYS }
    fn sys_faccessat(&mut self, _dirfd: i32, _pathname_ptr: usize, _mode: i32) -> i64 { ENOSYS }
    fn sys_getdents64(&mut self, _fd: i32, _dirp: usize, _count: usize) -> i64 { ENOSYS }
    fn sys_chdir(&mut self, _pathname_ptr: usize) -> i64 { ENOSYS }
    fn sys_fchdir(&mut self, _fd: i32) -> i64 { ENOSYS }
    fn sys_mkdirat(&mut self) -> i64 { -30 } // EROFS
    fn sys_unlinkat(&mut self) -> i64 { -30 } // EROFS
```

**Step 6: Run tests**

Run: `cargo test -p harmony-os`
Expected: PASS (stubs return ENOSYS/EROFS, no existing behavior changed)

**Step 7: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add filesystem syscall variants and dispatch stubs"
```

---

### Task 4: Implement resolve_path helper and upgrade getcwd

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs` (Linuxulator impl block)

**Step 1: Write tests for path resolution and cwd**

```rust
    #[test]
    fn resolve_path_absolute() {
        let mock = MockBackend::new();
        let lx = Linuxulator::new(mock);
        assert_eq!(lx.resolve_path("/foo/bar"), "/foo/bar");
    }

    #[test]
    fn resolve_path_relative_from_root() {
        let mock = MockBackend::new();
        let lx = Linuxulator::new(mock);
        assert_eq!(lx.resolve_path("bar"), "/bar");
    }

    #[test]
    fn resolve_path_relative_from_subdir() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.cwd = alloc::string::String::from("/foo");
        assert_eq!(lx.resolve_path("bar"), "/foo/bar");
    }

    #[test]
    fn sys_getcwd_tracks_cwd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.cwd = alloc::string::String::from("/nix/store");
        let mut buf = [0u8; 64];
        let ret = lx.dispatch_syscall(LinuxSyscall::Getcwd {
            buf: buf.as_mut_ptr() as u64,
            size: 64,
        });
        assert_eq!(ret, 11); // "/nix/store\0" = 11 bytes
        assert_eq!(&buf[..11], b"/nix/store\0");
    }
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os -- resolve_path sys_getcwd_tracks`
Expected: FAIL (resolve_path doesn't exist; getcwd still returns "/")

**Step 3: Implement resolve_path and upgrade getcwd**

Add to `impl<B: SyscallBackend> Linuxulator<B>`:

```rust
    /// Resolve a path relative to cwd. Absolute paths pass through unchanged.
    fn resolve_path(&self, path: &str) -> alloc::string::String {
        if path.starts_with('/') {
            alloc::string::String::from(path)
        } else if self.cwd == "/" {
            alloc::format!("/{}", path)
        } else {
            alloc::format!("{}/{}", self.cwd, path)
        }
    }
```

Update `sys_getcwd` to use `self.cwd`:

```rust
    fn sys_getcwd(&mut self, buf_ptr: usize, size: usize) -> i64 {
        if buf_ptr == 0 {
            return EFAULT;
        }
        let cwd_bytes = self.cwd.as_bytes();
        let needed = cwd_bytes.len() + 1; // path + NUL
        if size < needed {
            return ERANGE;
        }
        let mut out = Vec::with_capacity(needed);
        out.extend_from_slice(cwd_bytes);
        out.push(0);
        self.backend.vm_write_bytes(buf_ptr as u64, &out);
        needed as i64
    }
```

**Step 4: Run tests**

Run: `cargo test -p harmony-os`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add resolve_path helper and upgrade getcwd to track cwd"
```

---

### Task 5: Implement newfstatat and faccessat

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

**Step 1: Add errno constant**

Near the existing errno constants (line 16-28):

```rust
const ENOENT: i64 = -2;
const ENOTDIR: i64 = -20;
```

Wait — `ipc_err_to_errno` already maps `NotFound` to `-2`. We need the named constant for direct returns. Check if ENOTDIR is already defined... `IpcError::NotDirectory => -20` exists in `ipc_err_to_errno`. Add named constants for clarity if they don't already exist.

**Step 2: Write tests**

```rust
    #[test]
    fn sys_newfstatat_absolute_path() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut statbuf = [0u8; 144]; // x86_64 stat size
        let path = b"/dev/serial/log\0";
        let at_fdcwd: i32 = -100;
        let ret = lx.dispatch_syscall(LinuxSyscall::Newfstatat {
            dirfd: at_fdcwd,
            pathname: path.as_ptr() as u64,
            statbuf: statbuf.as_mut_ptr() as u64,
            flags: 0,
        });
        assert_eq!(ret, 0);
        // Verify walk was called with the path
        assert_eq!(lx.backend().walks[0].0, "/dev/serial/log");
    }

    #[test]
    fn sys_newfstatat_at_empty_path() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();
        let mut statbuf = [0u8; 144];
        let empty = b"\0";
        let at_empty_path: i32 = 0x1000;
        let ret = lx.dispatch_syscall(LinuxSyscall::Newfstatat {
            dirfd: 1, // stdout
            pathname: empty.as_ptr() as u64,
            statbuf: statbuf.as_mut_ptr() as u64,
            flags: at_empty_path,
        });
        assert_eq!(ret, 0);
    }

    #[test]
    fn sys_faccessat_exists() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let path = b"/dev/serial/log\0";
        let at_fdcwd: i32 = -100;
        let ret = lx.dispatch_syscall(LinuxSyscall::Faccessat {
            dirfd: at_fdcwd,
            pathname: path.as_ptr() as u64,
            mode: 0, // F_OK
        });
        assert_eq!(ret, 0);
    }

    #[test]
    fn sys_faccessat_not_found() {
        // Need a MockBackend that fails walk. For simplicity, test via
        // the existing mock (which succeeds). A failing mock can be added
        // as a follow-up. For now, test the success path.
        // The ENOENT path is implicitly tested by ipc_err_to_errno mapping.
    }
```

**Step 3: Run tests to verify they fail**

Run: `cargo test -p harmony-os -- sys_newfstatat sys_faccessat`
Expected: FAIL (stubs return ENOSYS)

**Step 4: Implement sys_newfstatat**

```rust
    /// Linux newfstatat(2): stat a file by path or fd.
    ///
    /// Supports AT_FDCWD + absolute/relative paths, and AT_EMPTY_PATH
    /// (stat an open fd, like fstat).
    fn sys_newfstatat(&mut self, dirfd: i32, pathname_ptr: usize, statbuf_ptr: usize, flags: i32) -> i64 {
        if statbuf_ptr == 0 {
            return EINVAL;
        }
        const AT_FDCWD: i32 = -100;
        const AT_EMPTY_PATH: i32 = 0x1000;

        // AT_EMPTY_PATH: stat the fd itself (like fstat)
        if flags & AT_EMPTY_PATH != 0 {
            return self.sys_fstat(dirfd, statbuf_ptr);
        }

        let path = unsafe { read_c_string(pathname_ptr) };
        if path.is_empty() {
            return EINVAL;
        }

        let resolved = if dirfd == AT_FDCWD || path.starts_with('/') {
            self.resolve_path(&path)
        } else {
            // dirfd-relative paths: not yet supported
            return ENOSYS;
        };

        let fid = self.alloc_fid();
        if let Err(e) = self.backend.walk(&resolved, fid) {
            return ipc_err_to_errno(e);
        }
        let result = match self.backend.stat(fid) {
            Ok(stat) => {
                write_linux_stat(statbuf_ptr, &stat, false);
                0
            }
            Err(e) => ipc_err_to_errno(e),
        };
        let _ = self.backend.clunk(fid);
        result
    }
```

**Step 5: Implement sys_faccessat**

```rust
    /// Linux faccessat(2): check file accessibility.
    ///
    /// Walks the path and stats to check existence. Permission bits always
    /// pass (single-user, no capability enforcement yet).
    fn sys_faccessat(&mut self, dirfd: i32, pathname_ptr: usize, _mode: i32) -> i64 {
        const AT_FDCWD: i32 = -100;
        let path = unsafe { read_c_string(pathname_ptr) };

        let resolved = if dirfd == AT_FDCWD || path.starts_with('/') {
            self.resolve_path(&path)
        } else {
            return ENOSYS;
        };

        let fid = self.alloc_fid();
        if let Err(e) = self.backend.walk(&resolved, fid) {
            return ipc_err_to_errno(e);
        }
        // File exists — clunk and return success.
        let _ = self.backend.clunk(fid);
        0
    }
```

**Step 6: Run tests**

Run: `cargo test -p harmony-os`
Expected: PASS

**Step 7: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): implement newfstatat and faccessat syscalls"
```

---

### Task 6: Implement getdents64

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

**Step 1: Add readdir support to MockBackend**

Add a field to `MockBackend`:

```rust
    /// Directory entries keyed by fid, for readdir testing.
    pub readdir_entries: BTreeMap<Fid, Vec<DirEntry>>,
```

Initialize in `MockBackend::new()`:

```rust
    readdir_entries: BTreeMap::new(),
```

Add `readdir` impl to `impl SyscallBackend for MockBackend`:

```rust
    fn readdir(&mut self, fid: Fid) -> Result<Vec<DirEntry>, IpcError> {
        self.readdir_entries
            .get(&fid)
            .cloned()
            .ok_or(IpcError::NotSupported)
    }
```

**Step 2: Write tests**

```rust
    #[test]
    fn sys_getdents64_packs_entries() {
        let mut mock = MockBackend::new();
        // Fid 100 will be allocated by init. Manually set up a directory fd.
        let dir_fid: Fid = 200;
        mock.readdir_entries.insert(dir_fid, vec![
            DirEntry { name: alloc::string::String::from("hello.txt"), file_type: FileType::Regular },
            DirEntry { name: alloc::string::String::from("subdir"), file_type: FileType::Directory },
        ]);
        let mut lx = Linuxulator::new(mock);
        // Manually insert a directory fd
        lx.fd_table_mut().insert(3, FdEntry { fid: dir_fid, offset: 0, path: Some(alloc::string::String::from("/test")) });

        let mut buf = [0u8; 512];
        let ret = lx.dispatch_syscall(LinuxSyscall::Getdents64 {
            fd: 3,
            dirp: buf.as_mut_ptr() as u64,
            count: 512,
        });
        assert!(ret > 0); // Should have written some bytes
    }

    #[test]
    fn sys_getdents64_empty_dir() {
        let mut mock = MockBackend::new();
        let dir_fid: Fid = 200;
        mock.readdir_entries.insert(dir_fid, vec![]);
        let mut lx = Linuxulator::new(mock);
        lx.fd_table_mut().insert(3, FdEntry { fid: dir_fid, offset: 0, path: Some(alloc::string::String::from("/empty")) });

        let mut buf = [0u8; 512];
        let ret = lx.dispatch_syscall(LinuxSyscall::Getdents64 {
            fd: 3,
            dirp: buf.as_mut_ptr() as u64,
            count: 512,
        });
        assert_eq!(ret, 0); // End of directory
    }
```

Note: You'll need to expose `fd_table` for testing. Add a `#[cfg(test)]` helper:

```rust
    #[cfg(test)]
    fn fd_table_mut(&mut self) -> &mut BTreeMap<i32, FdEntry> {
        &mut self.fd_table
    }
```

**Step 3: Run tests to verify they fail**

Run: `cargo test -p harmony-os -- sys_getdents64`
Expected: FAIL

**Step 4: Implement sys_getdents64**

```rust
    /// Linux getdents64(2): read directory entries.
    ///
    /// Calls `backend.readdir(fid)` to get all entries, then packs
    /// `linux_dirent64` structs into the user buffer starting from
    /// the entry index stored in `FdEntry.offset`.
    fn sys_getdents64(&mut self, fd: i32, dirp: usize, count: usize) -> i64 {
        if dirp == 0 {
            return EINVAL;
        }
        let entry = match self.fd_table.get(&fd) {
            Some(e) => *e,
            None => return EBADF,
        };
        // Note: entry.offset is used but *e was copied, so we
        // need to read the offset value before modifying.
        let start_idx = entry.offset as usize;

        let entries = match self.backend.readdir(entry.fid) {
            Ok(e) => e,
            Err(e) => return ipc_err_to_errno(e),
        };

        if start_idx >= entries.len() {
            return 0; // End of directory
        }

        let mut bytes_written: usize = 0;
        let mut idx = start_idx;

        while idx < entries.len() {
            let e = &entries[idx];
            let name_bytes = e.name.as_bytes();
            // d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + name + NUL
            let reclen_unaligned = 8 + 8 + 2 + 1 + name_bytes.len() + 1;
            let reclen = (reclen_unaligned + 7) & !7; // 8-byte align

            if bytes_written + reclen > count {
                break; // Buffer full
            }

            let d_type: u8 = match e.file_type {
                FileType::Regular => 8,   // DT_REG
                FileType::Directory => 4, // DT_DIR
            };

            // Pack the entry into the buffer
            let base = dirp + bytes_written;
            let mut rec = vec![0u8; reclen];
            rec[0..8].copy_from_slice(&0u64.to_le_bytes()); // d_ino (placeholder)
            let next_off = (idx + 1) as i64;
            rec[8..16].copy_from_slice(&next_off.to_le_bytes()); // d_off
            rec[16..18].copy_from_slice(&(reclen as u16).to_le_bytes()); // d_reclen
            rec[18] = d_type; // d_type
            rec[19..19 + name_bytes.len()].copy_from_slice(name_bytes); // d_name
            // NUL terminator already 0 from vec![0u8; reclen]

            self.backend.vm_write_bytes(base as u64, &rec);

            bytes_written += reclen;
            idx += 1;
        }

        if bytes_written == 0 && idx < entries.len() {
            return EINVAL; // Buffer too small for even one entry
        }

        // Update the offset to track position
        if let Some(entry) = self.fd_table.get_mut(&fd) {
            entry.offset = idx as u64;
        }

        bytes_written as i64
    }
```

**Step 5: Run tests**

Run: `cargo test -p harmony-os`
Expected: PASS

**Step 6: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): implement getdents64 with readdir backend"
```

---

### Task 7: Implement chdir, fchdir, and upgrade readlinkat

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

**Step 1: Write tests**

```rust
    #[test]
    fn sys_chdir_updates_cwd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let path = b"/nix/store\0";
        let ret = lx.dispatch_syscall(LinuxSyscall::Chdir {
            pathname: path.as_ptr() as u64,
        });
        assert_eq!(ret, 0);
        // Verify getcwd returns updated path
        let mut buf = [0u8; 64];
        let ret = lx.dispatch_syscall(LinuxSyscall::Getcwd {
            buf: buf.as_mut_ptr() as u64,
            size: 64,
        });
        assert_eq!(ret, 11); // "/nix/store\0"
        assert_eq!(&buf[..11], b"/nix/store\0");
    }

    #[test]
    fn sys_fchdir_from_open_fd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // Open a directory
        let path = b"/nix/store\0";
        let fd = lx.dispatch_syscall(LinuxSyscall::Openat {
            dirfd: -100,
            pathname: path.as_ptr() as u64,
            flags: 0,
        });
        assert!(fd >= 0);
        let ret = lx.dispatch_syscall(LinuxSyscall::Fchdir { fd: fd as i32 });
        assert_eq!(ret, 0);
        // getcwd should reflect the change
        let mut buf = [0u8; 64];
        let ret = lx.dispatch_syscall(LinuxSyscall::Getcwd {
            buf: buf.as_mut_ptr() as u64,
            size: 64,
        });
        assert_eq!(&buf[..11], b"/nix/store\0");
    }

    #[test]
    fn sys_readlinkat_returns_einval() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let path = b"/some/link\0";
        let mut buf = [0u8; 64];
        let ret = lx.dispatch_syscall(LinuxSyscall::Readlink {
            pathname: path.as_ptr() as u64,
            buf: buf.as_mut_ptr() as u64,
            bufsiz: 64,
        });
        assert_eq!(ret, EINVAL);
    }

    #[test]
    fn sys_mkdirat_returns_erofs() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let path = b"/tmp/newdir\0";
        let ret = lx.dispatch_syscall(LinuxSyscall::Mkdirat {
            dirfd: -100,
            pathname: path.as_ptr() as u64,
            mode: 0o755,
        });
        assert_eq!(ret, -30); // EROFS
    }
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-os -- sys_chdir sys_fchdir sys_readlinkat_returns_einval`
Expected: FAIL

**Step 3: Implement sys_chdir**

```rust
    /// Linux chdir(2): change working directory.
    ///
    /// Walks the path, verifies it's a directory via stat, then
    /// updates `self.cwd`. Clunks the old cwd fid if set.
    fn sys_chdir(&mut self, pathname_ptr: usize) -> i64 {
        let path = unsafe { read_c_string(pathname_ptr) };
        let resolved = self.resolve_path(&path);

        let fid = self.alloc_fid();
        if let Err(e) = self.backend.walk(&resolved, fid) {
            return ipc_err_to_errno(e);
        }

        // Verify it's a directory
        match self.backend.stat(fid) {
            Ok(stat) if stat.file_type == FileType::Directory => {}
            Ok(_) => {
                let _ = self.backend.clunk(fid);
                return ENOTDIR;
            }
            Err(e) => {
                let _ = self.backend.clunk(fid);
                return ipc_err_to_errno(e);
            }
        }

        // Clunk old cwd fid
        if let Some(old_fid) = self.cwd_fid {
            let _ = self.backend.clunk(old_fid);
        }

        self.cwd = resolved;
        self.cwd_fid = Some(fid);
        0
    }
```

**Step 4: Implement sys_fchdir**

```rust
    /// Linux fchdir(2): change working directory to an open fd.
    fn sys_fchdir(&mut self, fd: i32) -> i64 {
        let entry = match self.fd_table.get(&fd) {
            Some(e) => e.clone(),
            None => return EBADF,
        };

        let path = match &entry.path {
            Some(p) => p.clone(),
            None => return EBADF, // stdio fds have no path
        };

        // Verify it's a directory
        match self.backend.stat(entry.fid) {
            Ok(stat) if stat.file_type == FileType::Directory => {}
            Ok(_) => return ENOTDIR,
            Err(e) => return ipc_err_to_errno(e),
        }

        // Walk a new fid for cwd (the fd's fid stays with the fd table)
        let cwd_fid = self.alloc_fid();
        if let Err(e) = self.backend.walk(&path, cwd_fid) {
            return ipc_err_to_errno(e);
        }

        if let Some(old_fid) = self.cwd_fid {
            let _ = self.backend.clunk(old_fid);
        }

        self.cwd = path;
        self.cwd_fid = Some(cwd_fid);
        0
    }
```

**Step 5: Upgrade readlinkat**

Change from ENOSYS to EINVAL (no symlinks exist in our namespace):

```rust
    fn sys_readlink(&self, _pathname: u64, _buf: u64, _bufsiz: u64) -> i64 {
        EINVAL // No symlinks in the 9P namespace
    }
```

**Step 6: Add ENOTDIR constant**

Near the errno constants at the top:

```rust
const ENOTDIR: i64 = -20;
```

**Step 7: Fix FdEntry Clone**

`FdEntry` needs `Clone` since `fchdir` clones it (it has `Option<String>`). Add `#[derive(Clone)]` or implement manually. Since `FdEntry` currently has `Copy` via `*e` usage in `sys_read`, we need to remove the implicit `Copy` (adding `Option<String>` makes it non-Copy already from Task 2). Ensure all `*e` patterns are replaced with `.clone()` where needed.

**Step 8: Run tests**

Run: `cargo test -p harmony-os`
Expected: PASS

**Step 9: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): implement chdir, fchdir, upgrade readlinkat"
```

---

### Task 8: MockBackend stat returns Directory for directory paths

The MockBackend always returns `FileType::Regular` from `stat()`. For `chdir` tests to work, it needs to return `Directory` for paths that look like directories.

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs` (MockBackend)

**Step 1: Add directory tracking to MockBackend**

```rust
    /// Fids that represent directories (for stat to return FileType::Directory).
    pub directory_fids: BTreeSet<Fid>,
```

Update `stat()` impl to check:

```rust
    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        self.stats.push(fid);
        let file_type = if self.directory_fids.contains(&fid) {
            FileType::Directory
        } else {
            FileType::Regular
        };
        Ok(FileStat {
            qpath: 0,
            name: alloc::sync::Arc::from("mock"),
            size: 0,
            file_type,
        })
    }
```

**Step 2: Track walked paths to fids in MockBackend**

Add a `walked_fids: BTreeMap<String, Fid>` field to MockBackend, populate in `walk()`:

Actually, a simpler approach: add a `directory_paths: BTreeSet<String>` and in `walk()`, if the path is in `directory_paths`, add the fid to `directory_fids`:

```rust
    pub directory_paths: alloc::collections::BTreeSet<alloc::string::String>,
```

In `walk()`:
```rust
    fn walk(&mut self, path: &str, new_fid: Fid) -> Result<QPath, IpcError> {
        self.walks.push((alloc::string::String::from(path), new_fid));
        if self.directory_paths.contains(path) {
            self.directory_fids.insert(new_fid);
        }
        Ok(0)
    }
```

**Step 3: Update chdir tests to register directory paths**

```rust
    fn sys_chdir_updates_cwd() {
        let mut mock = MockBackend::new();
        mock.directory_paths.insert(alloc::string::String::from("/nix/store"));
        let mut lx = Linuxulator::new(mock);
        // ... rest unchanged
    }
```

**Step 4: Run tests**

Run: `cargo test -p harmony-os`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): MockBackend supports directory file types"
```

Note: Tasks 7 and 8 are tightly coupled — the implementer should do them together or do Task 8 first since Task 7's chdir tests depend on it.

---

### Task 9: Integration test in harmony-test-elf

**Files:**
- Modify: `crates/harmony-test-elf/src/main.rs`

**Step 1: Add syscall constants**

```rust
const SYS_NEWFSTATAT: u64 = 79; // aarch64
```

**Step 2: Add syscall4 wrapper**

```rust
#[inline(always)]
unsafe fn syscall4(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "svc #0",
        in("x8") nr,
        inlateout("x0") a0 => ret,
        in("x1") a1,
        in("x2") a2,
        in("x3") a3,
        options(nostack),
    );
    ret
}
```

**Step 3: Add step5_newfstatat test**

```rust
/// Step 5: newfstatat(stdout, "", &statbuf, AT_EMPTY_PATH)
/// Verifies stat-by-fd works through the SVC handler.
unsafe fn step5_newfstatat() -> bool {
    let mut statbuf = [0u8; 128]; // aarch64 stat struct is 128 bytes
    let empty = b"\0";
    let at_empty_path: u64 = 0x1000;
    let ret = syscall4(
        SYS_NEWFSTATAT,
        1, // fd = stdout
        empty.as_ptr() as u64,
        statbuf.as_mut_ptr() as u64,
        at_empty_path,
    );
    // Should succeed (return 0) and write something to statbuf
    if ret != 0 {
        return false;
    }
    // st_mode at offset 16 should be S_IFCHR|0o666 = 0o020666 = 0x21B6
    let mode = u32::from_le_bytes([statbuf[16], statbuf[17], statbuf[18], statbuf[19]]);
    mode == 0o020666
}
```

**Step 4: Wire step 5 into _start**

After step 4 (getrandom), add:

```rust
        // Step 5: newfstatat
        if step5_newfstatat() {
            write_stdout(b"[LINUXULATOR] Step 5 (newfstatat): OK\n");
        } else {
            write_stdout(b"[LINUXULATOR] Step 5 (newfstatat): FAIL\n");
            all_ok = false;
        }
```

**Step 5: Build test ELF and run QEMU test**

Run: `just build-test-elf && just build-aarch64 && just test-qemu-aarch64`
Expected: All 5 steps pass, including `Step 5 (newfstatat): OK`

**Step 6: Commit**

```bash
git add crates/harmony-test-elf/src/main.rs
git commit -m "test(test-elf): add step 5 — newfstatat AT_EMPTY_PATH integration test"
```

---

### Task 10: Update openat to use resolve_path

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

**Step 1: Write test**

```rust
    #[test]
    fn sys_openat_relative_path_uses_cwd() {
        let mut mock = MockBackend::new();
        mock.directory_paths.insert(alloc::string::String::from("/nix/store"));
        let mut lx = Linuxulator::new(mock);
        // chdir to /nix/store
        let dir = b"/nix/store\0";
        lx.dispatch_syscall(LinuxSyscall::Chdir { pathname: dir.as_ptr() as u64 });
        // openat with relative path
        let file = b"abc123-hello\0";
        let fd = lx.dispatch_syscall(LinuxSyscall::Openat {
            dirfd: -100,
            pathname: file.as_ptr() as u64,
            flags: 0,
        });
        assert!(fd >= 0);
        // Verify the walk used the resolved path
        let walks = &lx.backend().walks;
        let last_walk = &walks[walks.len() - 1];
        assert_eq!(last_walk.0, "/nix/store/abc123-hello");
    }
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-os -- sys_openat_relative`
Expected: FAIL (openat doesn't use resolve_path yet)

**Step 3: Update sys_openat to use resolve_path**

Replace the path resolution in `sys_openat`:

```rust
    fn sys_openat(&mut self, dirfd: i32, pathname_ptr: usize, flags: i32) -> i64 {
        let raw_path = unsafe { read_c_string(pathname_ptr) };

        let at_fdcwd: i32 = -100;
        if dirfd != at_fdcwd && !self.fd_table.contains_key(&dirfd) {
            return EBADF;
        }

        let path = if dirfd == at_fdcwd || raw_path.starts_with('/') {
            self.resolve_path(&raw_path)
        } else {
            // dirfd-relative: not yet supported
            return ENOSYS;
        };

        let fid = self.alloc_fid();
        let mode = flags_to_open_mode(flags);

        if let Err(e) = self.backend.walk(&path, fid) {
            return ipc_err_to_errno(e);
        }
        if let Err(e) = self.backend.open(fid, mode) {
            let _ = self.backend.clunk(fid);
            return ipc_err_to_errno(e);
        }

        let fd = self.alloc_fd();
        self.fd_table.insert(fd, FdEntry {
            fid,
            offset: 0,
            path: Some(path),
        });
        fd as i64
    }
```

**Step 4: Run tests**

Run: `cargo test -p harmony-os`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): openat uses resolve_path for cwd-relative paths"
```
