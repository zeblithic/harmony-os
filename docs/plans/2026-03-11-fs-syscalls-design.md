# Linuxulator Filesystem Syscalls Design

**Bead:** harmony-3j2
**Goal:** Add filesystem traversal syscalls to the Linuxulator so programs can stat files, list directories, and navigate the 9P namespace — prerequisite for NixOS store path resolution.

## Scope

Option B: full directory traversal. No symlink support (deferred — CAS/NDN naming model may subsume symlinks entirely).

## New Syscalls (8)

| Syscall | x86_64 | aarch64 | Implementation |
|---|---|---|---|
| `newfstatat` | 262 | 79 | Walk path via backend, stat fid, pack Linux stat struct. Supports `AT_EMPTY_PATH` (stat open fd) and `AT_FDCWD`. |
| `faccessat` | 269 | 48 | Walk + stat to check existence. F_OK only; permission bits always pass (single-user). |
| `readlinkat` | 267 | 78 | Returns EINVAL (no symlinks). Upgrade existing stub to proper dispatch. |
| `getdents64` | 217 | 61 | Call `backend.readdir(fid)`, pack `linux_dirent64` structs into user buffer. |
| `chdir` | 80 | 49 | Walk path, stat to verify directory, update `cwd`/`cwd_fid`. |
| `fchdir` | 81 | 50 | Look up fd, stat to verify directory, update cwd from fd's stored path. |
| `mkdirat` | 258 | 34 | Stub: returns EROFS (read-only filesystem). |
| `unlinkat` | 263 | 35 | Stub: returns EROFS. |

Existing `getcwd` upgraded from hardcoded `"/"` to return tracked cwd path.

## State Changes

### Linuxulator struct

Two new fields:

```rust
/// Current working directory path (starts as "/").
cwd: String,
/// 9P fid for the current working directory.
cwd_fid: Option<Fid>,
```

### FdEntry enhancement

Add `path: Option<String>` to track the path walked to open the fd. Needed for `fchdir` and diagnostic reporting. Populated on `openat`; `None` for stdio fds.

### Path resolution

`openat`/`newfstatat`/`faccessat` with relative paths and `AT_FDCWD`: prepend `self.cwd` to form absolute path before `backend.walk()`. Absolute paths pass through unchanged.

## SyscallBackend Extension

One new optional method (same pattern as `vm_mmap`):

```rust
pub struct DirEntry {
    pub name: String,
    pub file_type: FileType,
}

fn readdir(&mut self, fid: Fid) -> Result<Vec<DirEntry>, IpcError> {
    Err(IpcError::NotSupported)
}
```

Returns all entries at once. The Linuxulator uses `FdEntry.offset` as entry index for pagination across multiple `getdents64` calls.

### getdents64 packing

Each entry packed as `linux_dirent64`:

```
d_ino: u64     — qpath
d_off: i64     — offset to next entry
d_reclen: u16  — record length (8-byte aligned)
d_type: u8     — DT_REG=8, DT_DIR=4
d_name: [u8]   — null-terminated name
```

## Testing

**Unit tests (MockBackend):** ~13 tests covering stat-by-path, access checks, getdents64 packing/pagination/empty, chdir/fchdir/getcwd integration, relative path resolution, stub returns.

**Integration test (harmony-test-elf):** Add `newfstatat` with `AT_EMPTY_PATH` on stdout fd to validate end-to-end through SVC handler.

## Architecture Note: Symlinks

Deferred by design. In a CAS/NDN namespace, every name is already a content-addressed reference — symlinks as a distinct `FileType` may not be the right abstraction. This is a future design discussion for its own bead.
