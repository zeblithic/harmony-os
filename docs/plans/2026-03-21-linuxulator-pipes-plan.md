# Linuxulator Pipes/Eventfd Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add pipe, pipe2, and eventfd syscalls to the Linuxulator by refactoring FdEntry to support non-9P fd types.

**Architecture:** Refactor FdEntry into an FdKind enum (File/PipeRead/PipeWrite/EventFd), add pipe buffer state to Linuxulator, implement three new syscalls, update all existing call sites to handle non-File fd kinds.

**Tech Stack:** Rust, no_std compatible (alloc only), existing Linuxulator framework in harmony-os.

**Spec:** docs/specs/2026-03-21-linuxulator-pipes-design.md

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| crates/harmony-os/src/linuxulator.rs | Modify | All changes: FdEntry refactoring, new syscalls, tests |

This is a single 6565-line file. All changes are in this file.

## IMPORTANT: This file is 6565 lines. Subagents MUST:
- Read specific line ranges (not the whole file)
- Use Edit tool for surgical changes
- Run cargo test -p harmony-os linuxulator after each change
- Never rewrite large blocks; always use targeted edits

---

## Task 1: Refactor FdEntry to FdKind Enum

Core refactoring. No new features. Restructure FdEntry so that fid, offset, path, file_type are inside an FdKind::File variant, while flags remains on FdEntry. All existing tests must pass unchanged.

This task is large (31 .fid accesses, 14 .offset, 9 .file_type, 5 .path, 7 construction sites, ~15 test accesses). The subagent should:
1. Read the spec at docs/specs/2026-03-21-linuxulator-pipes-design.md for the full call-site table
2. Read linuxulator.rs lines 1150-1210 for struct definitions
3. Read linuxulator.rs lines 1250-1260 for insert_test_fd
4. Make changes methodically, compiling after each group of related edits

Key changes:
- Replace FdEntry struct (line 1160) with FdKind enum + new FdEntry
- Add pipes: BTreeMap and next_pipe_id: usize fields to Linuxulator struct
- Update all 7 FdEntry construction sites to use FdKind::File { ... }
- Update fid_for_fd (line 1378) to match on FdKind::File
- Update sys_close (line 1581) with FdKind match (pipe cleanup can be a TODO)
- Update dup_fd_to (line 1646) to clone kind, only bump refcount for File
- Update sys_write (line 1519): extract fid/offset from FdKind::File match
- Update sys_read (line 1544): same pattern
- Update sys_fstat (line 1734): match on FdKind::File for fid
- Update sys_lseek (line 2272): match on FdKind::File, return ESPIPE for others (add const ESPIPE: i64 = -29)
- Update sys_getdents64 (line 2494): match on FdKind::File
- Update sys_chdir/sys_fchdir (line 2614): match on FdKind::File
- Update sys_writev (line 1674): same pattern as sys_write
- Update sys_newfstatat: match on FdKind::File
- Update sys_fcntl F_DUPFD path
- Update ~15 test sites that access .fid directly: add a test_fid helper
- All offset mutation sites (lines 1532, 1562, 2311, 2566): use if let FdKind::File { ref mut offset, .. }

Run: cargo test -p harmony-os -- linuxulator
Expected: All existing tests PASS

Commit: refactor: FdEntry to FdKind enum for non-9P fd type support

---

## Task 2: Pipe State + sys_pipe2/sys_pipe

Add pipe buffer state to Linuxulator, implement pipe2 and pipe syscalls, add to dispatch table.

Key implementation:
- Add Pipe2 { fds: u64, flags: u64 } and Pipe { fds: u64 } variants to LinuxSyscall enum
- Add to from_x86_64: 22 = Pipe, 293 = Pipe2
- Add to from_aarch64: 59 = Pipe2
- Add to dispatch_syscall match
- Implement sys_pipe2: validate flags (O_CLOEXEC|O_NONBLOCK only), allocate pipe buffer, create two fds (PipeRead + PipeWrite), write fd numbers to user memory
- Add O_NONBLOCK constant if missing (0o4000)
- May need to extract alloc_fd helper from sys_openat's fd allocation logic

Tests:
- test_pipe2_creates_fds: pipe2 returns two valid fds
- test_pipe2_cloexec: O_CLOEXEC sets FD_CLOEXEC on both fds
- test_pipe2_invalid_flags: unknown flags return EINVAL

Run: cargo test -p harmony-os -- test_pipe2
Commit: feat: sys_pipe2/sys_pipe with pipe buffer allocation

---

## Task 3: Pipe Read/Write Integration + Lifecycle Tests

Wire pipes into sys_read, sys_write, sys_close.

Key implementation:
- In sys_read, add PipeRead arm: drain from front of buffer, return EAGAIN if empty with writer alive, return 0 (EOF) if empty with writer closed
- In sys_write, add PipeWrite arm: append to buffer, return EPIPE if reader closed
- Add EAGAIN (-11) and EPIPE (-32) errno constants
- In sys_close pipe arm: scan fd_table for remaining pipe references, remove buffer if none
- In sys_fstat: pipe fds return synthetic stat with S_IFIFO (0o010644 in st_mode)
- Handle PipeWrite in sys_read and PipeRead in sys_write as EBADF

Tests:
- test_pipe_write_then_read: write bytes, read them back
- test_pipe_read_eof_after_write_close: close write end, read returns 0
- test_pipe_write_epipe_after_read_close: close read end, write returns EPIPE
- test_pipe_partial_read: read fewer bytes, remainder persists
- test_pipe_fstat_returns_fifo: fstat reports S_IFIFO mode
- test_pipe_lseek_returns_espipe: lseek on pipe fd returns ESPIPE
- test_pipe_dup_shares_buffer: dup'd write end writes to same pipe

Run: cargo test -p harmony-os -- test_pipe
Commit: feat: pipe read/write/close/fstat integration

---

## Task 4: Eventfd Implementation

Add eventfd2 syscall with default and semaphore modes.

Key implementation:
- Add EventFd2 { initval: u64, flags: u64 } variant to LinuxSyscall
- Add to from_x86_64: 290. Add to from_aarch64: 19
- Implement sys_eventfd2: validate flags (EFD_CLOEXEC|EFD_NONBLOCK|EFD_SEMAPHORE), create fd with EventFd kind
- In sys_read, add EventFd arm: if count < 8 return EINVAL, if counter == 0 return EAGAIN, return counter (default) or 1 (semaphore), update counter
- In sys_write, add EventFd arm: if count < 8 return EINVAL, read u64 from user buf, if val == u64::MAX return EINVAL, if overflow return EAGAIN, add to counter
- EFD_SEMAPHORE constant = 1

Tests:
- test_eventfd_init_and_read: create with initval, read returns it, second read EAGAIN
- test_eventfd_semaphore: read returns 1 and decrements
- test_eventfd_write_accumulates: multiple writes add to counter
- test_eventfd_read_zero_eagain: counter=0 returns EAGAIN
- test_eventfd_buffer_too_small: count < 8 returns EINVAL
- test_eventfd_write_overflow: overflow returns EAGAIN
- test_eventfd_write_max_value_einval: u64::MAX returns EINVAL

Run: cargo test -p harmony-os -- test_eventfd
Commit: feat: sys_eventfd2 with default and semaphore modes

---

## Task 5: Quality Gates + Push + PR

- Run: cargo test --workspace (all tests PASS)
- Run: cargo clippy --workspace (no warnings)
- Run: cargo fmt --all -- --check (clean)
- Claim bead: bd update harmony-os-5pq --claim --status in_progress
- Push and create PR

Note: branch should have been created before Task 1.
