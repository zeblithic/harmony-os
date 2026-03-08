// SPDX-License-Identifier: GPL-2.0-or-later
//! Linuxulator — Linux syscall-to-9P translation layer for Ring 3.
//!
//! Translates Linux syscall numbers and arguments into 9P FileServer
//! operations via a [`SyscallBackend`] trait. Manages a POSIX-style
//! fd table that maps Linux file descriptors to 9P fids.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use harmony_microkernel::{Fid, FileStat, FileType, IpcError, OpenMode, QPath};

// ── Linux errno constants ───────────────────────────────────────────

const EBADF: i64 = -9;
const ENOSYS: i64 = -38;
const ENOMEM: i64 = -12;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const ESRCH: i64 = -3;

fn ipc_err_to_errno(e: IpcError) -> i64 {
    match e {
        IpcError::NotFound => -2,           // ENOENT
        IpcError::PermissionDenied => -13,  // EACCES
        IpcError::NotOpen => -9,            // EBADF
        IpcError::InvalidFid => -9,         // EBADF
        IpcError::NotDirectory => -20,      // ENOTDIR
        IpcError::IsDirectory => -21,       // EISDIR
        IpcError::ReadOnly => -30,          // EROFS
        IpcError::ResourceExhausted => -12, // ENOMEM
        IpcError::Conflict => -17,          // EEXIST
        IpcError::NotSupported => -38,      // ENOSYS
        IpcError::InvalidArgument => -22,   // EINVAL
    }
}

// ── SyscallBackend trait ────────────────────────────────────────────

/// Abstraction over 9P operations. The Linuxulator calls these to
/// fulfil Linux syscalls. Production implementations wrap the Kernel;
/// tests use [`MockBackend`].
pub trait SyscallBackend {
    fn walk(&mut self, path: &str, new_fid: Fid) -> Result<QPath, IpcError>;
    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError>;
    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError>;
    fn write(&mut self, fid: Fid, offset: u64, data: &[u8]) -> Result<u32, IpcError>;
    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError>;
    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError>;
}

// ── MockBackend ─────────────────────────────────────────────────────

/// Test double that records all 9P calls for assertion.
#[cfg(test)]
pub struct MockBackend {
    pub walks: Vec<(alloc::string::String, Fid)>,
    pub opens: Vec<(Fid, OpenMode)>,
    pub writes: Vec<(Fid, Vec<u8>)>,
    pub reads: Vec<(Fid, u64, u32)>,
    pub clunks: Vec<Fid>,
    pub stats: Vec<Fid>,
}

#[cfg(test)]
impl MockBackend {
    pub fn new() -> Self {
        Self {
            walks: Vec::new(),
            opens: Vec::new(),
            writes: Vec::new(),
            reads: Vec::new(),
            clunks: Vec::new(),
            stats: Vec::new(),
        }
    }
}

#[cfg(test)]
impl SyscallBackend for MockBackend {
    fn walk(&mut self, path: &str, new_fid: Fid) -> Result<QPath, IpcError> {
        self.walks
            .push((alloc::string::String::from(path), new_fid));
        Ok(0)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        self.opens.push((fid, mode));
        Ok(())
    }

    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        self.reads.push((fid, offset, count));
        Ok(Vec::new())
    }

    fn write(&mut self, fid: Fid, _offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        self.writes.push((fid, data.to_vec()));
        Ok(data.len() as u32)
    }

    fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
        self.clunks.push(fid);
        Ok(())
    }

    fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
        self.stats.push(fid);
        Ok(FileStat {
            qpath: 0,
            name: alloc::sync::Arc::from("mock"),
            size: 0,
            file_type: FileType::Regular,
        })
    }
}

// ── Memory arena ──────────────────────────────────────────────────

const PAGE_SIZE: usize = 4096;

struct MemoryArena {
    /// Backing allocation — boxed slice so it cannot be accidentally
    /// resized (which would invalidate the `base` pointer).
    _pages: alloc::boxed::Box<[u8]>,
    base: usize,
    brk_offset: usize,
    /// Tracked for future munmap implementation. Currently unused by
    /// sys_munmap (which is a no-op stub). Will drive deallocation when
    /// the VM layer (harmony-qv2) adds real page reclamation.
    mmap_regions: Vec<(usize, usize)>,
    mmap_top: usize,
}

impl MemoryArena {
    fn new(size: usize) -> Self {
        let size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        // Over-allocate by one page so we can align base up to a page boundary.
        // Vec<u8> has alignment 1 — the raw pointer is not guaranteed page-aligned.
        // Convert to Box<[u8]> immediately so the allocation cannot be resized.
        let pages = alloc::vec![0u8; size + PAGE_SIZE].into_boxed_slice();
        let raw_base = pages.as_ptr() as usize;
        let base = (raw_base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        // musl treats brk/mmap return values as signed — addresses in the upper
        // half of the 64-bit address space (>= 2^63) become negative i64 values,
        // which musl interprets as errors. Assert we're in the lower half.
        assert!(
            base <= i64::MAX as usize,
            "arena must be in lower address half for musl compatibility"
        );
        Self {
            _pages: pages,
            base,
            brk_offset: 0,
            mmap_regions: Vec::new(),
            mmap_top: size,
        }
    }
}

// ── Helper functions ────────────────────────────────────────────────

/// Read a null-terminated C string from process memory.
///
/// Returns an owned `String` to avoid a false `'static` lifetime on
/// memory that is actually owned by the process address space.
///
/// # Safety
/// `ptr` must point to valid memory containing a null-terminated string.
unsafe fn read_c_string(ptr: usize) -> alloc::string::String {
    const PATH_MAX: usize = 4096;
    let p = ptr as *const u8;
    let mut len = 0;
    while len < PATH_MAX && *p.add(len) != 0 {
        len += 1;
    }
    alloc::string::String::from(core::str::from_utf8_unchecked(
        core::slice::from_raw_parts(p, len),
    ))
}

/// Map Linux open(2) flags to 9P OpenMode.
fn flags_to_open_mode(flags: i32) -> OpenMode {
    let accmode = flags & 0x03;
    match accmode {
        0 => OpenMode::Read,
        1 => OpenMode::Write,
        2 => OpenMode::ReadWrite,
        _ => OpenMode::Read,
    }
}

/// Write a Linux x86_64 `struct stat` (144 bytes) to process memory.
///
/// Field layout follows the x86_64 Linux kernel struct stat:
///   offset  size  field
///   0       8     st_dev
///   8       8     st_ino
///   16      8     st_nlink
///   24      4     st_mode
///   28      4     st_uid
///   32      4     st_gid
///   36      4     (pad)
///   40      8     st_rdev
///   48      8     st_size
///   56      8     st_blksize
///   64      8     st_blocks
///   72-144        timestamps (zeroed for MVP)
fn write_linux_stat(buf_ptr: usize, stat: &FileStat, is_chardev: bool) {
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, 144) };
    buf.fill(0);

    // st_ino (offset 8, 8 bytes)
    buf[8..16].copy_from_slice(&stat.qpath.to_le_bytes());

    // st_nlink (offset 16, 8 bytes)
    buf[16..24].copy_from_slice(&1u64.to_le_bytes());

    // st_mode (offset 24, 4 bytes)
    let mode: u32 = if is_chardev {
        0o020000 | 0o666 // S_IFCHR | rw-rw-rw-
    } else {
        match stat.file_type {
            FileType::Regular => 0o100000 | 0o644,   // S_IFREG | rw-r--r--
            FileType::Directory => 0o040000 | 0o755, // S_IFDIR | rwxr-xr-x
        }
    };
    buf[24..28].copy_from_slice(&mode.to_le_bytes());

    // st_size (offset 48, 8 bytes)
    buf[48..56].copy_from_slice(&stat.size.to_le_bytes());

    // st_blksize (offset 56, 8 bytes)
    buf[56..64].copy_from_slice(&4096u64.to_le_bytes());

    // st_blocks (offset 64, 8 bytes)
    let blocks = stat.size.div_ceil(512);
    buf[64..72].copy_from_slice(&blocks.to_le_bytes());
}

// ── Linuxulator ─────────────────────────────────────────────────────

/// Per-fd state: the 9P fid and the current file offset.
#[derive(Clone, Copy)]
struct FdEntry {
    fid: Fid,
    offset: u64,
}

/// Linux syscall-to-9P translation engine.
///
/// Owns a POSIX-style fd table and dispatches Linux syscalls to a
/// [`SyscallBackend`]. Created once per Linux process.
pub struct Linuxulator<B: SyscallBackend> {
    backend: B,
    /// Maps Linux fd (0, 1, 2, ...) → 9P fid + file offset.
    fd_table: BTreeMap<i32, FdEntry>,
    /// Next fid to allocate for backend calls.
    next_fid: Fid,
    /// Set by sys_exit_group.
    exit_code: Option<i32>,
    /// Memory arena for brk/mmap.
    arena: MemoryArena,
    /// FS segment base register (TLS pointer for arch_prctl).
    fs_base: u64,
    /// Fids that represent character devices (stdio).
    /// Used by fstat to report S_IFCHR instead of S_IFREG.
    chardev_fids: Vec<Fid>,
}

impl<B: SyscallBackend> Linuxulator<B> {
    /// Create a new Linuxulator with default 1 MiB arena.
    pub fn new(backend: B) -> Self {
        Self::with_arena(backend, 1024 * 1024) // 1 MiB default
    }

    /// Create a new Linuxulator with a custom arena size.
    pub fn with_arena(backend: B, arena_size: usize) -> Self {
        Self {
            backend,
            fd_table: BTreeMap::new(),
            next_fid: 100, // avoid collision with server root fids
            exit_code: None,
            arena: MemoryArena::new(arena_size),
            fs_base: 0,
            chardev_fids: Vec::new(),
        }
    }

    /// Allocate the next fid for a backend call.
    fn alloc_fid(&mut self) -> Fid {
        let fid = self.next_fid;
        self.next_fid += 1;
        fid
    }

    /// Allocate the lowest available Linux fd.
    fn alloc_fd(&self) -> i32 {
        let mut fd = 0;
        while self.fd_table.contains_key(&fd) {
            fd += 1;
        }
        fd
    }

    /// Pre-populate fd 0 (stdin), 1 (stdout), 2 (stderr) by walking
    /// to the serial server and opening the log file.
    ///
    /// Expects SerialServer mounted at `/dev/serial` in the process namespace.
    pub fn init_stdio(&mut self) -> Result<(), IpcError> {
        // stdin (fd 0) — read mode
        let stdin_fid = self.alloc_fid();
        self.backend.walk("/dev/serial/log", stdin_fid)?;
        self.backend.open(stdin_fid, OpenMode::Read)?;
        self.fd_table.insert(0, FdEntry { fid: stdin_fid, offset: 0 });

        // stdout (fd 1) — write mode
        let stdout_fid = self.alloc_fid();
        self.backend.walk("/dev/serial/log", stdout_fid)?;
        self.backend.open(stdout_fid, OpenMode::Write)?;
        self.fd_table.insert(1, FdEntry { fid: stdout_fid, offset: 0 });

        // stderr (fd 2) — write mode
        let stderr_fid = self.alloc_fid();
        self.backend.walk("/dev/serial/log", stderr_fid)?;
        self.backend.open(stderr_fid, OpenMode::Write)?;
        self.fd_table.insert(2, FdEntry { fid: stderr_fid, offset: 0 });

        // Track stdio fids as character devices for fstat.
        self.chardev_fids
            .extend_from_slice(&[stdin_fid, stdout_fid, stderr_fid]);

        Ok(())
    }

    /// Check if a Linux fd is in the table.
    pub fn has_fd(&self, fd: i32) -> bool {
        self.fd_table.contains_key(&fd)
    }

    /// Whether the process has called exit_group.
    pub fn exited(&self) -> bool {
        self.exit_code.is_some()
    }

    /// The exit code, if the process has exited.
    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Access the backend (for test assertions).
    #[cfg(test)]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Mutable access to the backend (for integration tests).
    #[cfg(test)]
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Look up the fid for a Linux fd (for testing).
    #[cfg(test)]
    pub fn fid_for_fd(&self, fd: i32) -> Option<Fid> {
        self.fd_table.get(&fd).map(|e| e.fid)
    }

    /// Base address of the memory arena (for testing).
    #[cfg(test)]
    pub fn arena_base(&self) -> usize {
        self.arena.base
    }

    /// Dispatch a Linux syscall. Returns the syscall result (negative = errno).
    ///
    /// # Arguments
    /// - `nr`: Linux syscall number (x86_64 ABI)
    /// - `args`: syscall arguments [arg1, arg2, arg3, arg4, arg5, arg6]
    ///
    /// # Safety
    /// For `sys_write`, `args[1]` is treated as a pointer to user memory.
    /// In the MVP flat address space, this is a direct pointer dereference.
    pub fn handle_syscall(&mut self, nr: u64, args: [u64; 6]) -> i64 {
        match nr {
            0 => self.sys_read(args[0] as i32, args[1] as usize, args[2] as usize),
            1 => self.sys_write(args[0] as i32, args[1] as usize, args[2] as usize),
            3 => self.sys_close(args[0] as i32),
            5 => self.sys_fstat(args[0] as i32, args[1] as usize),
            9 => self.sys_mmap(
                args[0],
                args[1],
                args[2] as i32,
                args[3] as i32,
                args[4] as i32,
                args[5],
            ),
            11 => self.sys_munmap(args[0], args[1]),
            12 => self.sys_brk(args[0]),
            13 => self.sys_rt_sigaction(),
            14 => self.sys_rt_sigprocmask(),
            16 => self.sys_ioctl(args[0] as i32, args[1]),
            60 => self.sys_exit(args[0] as i32),
            158 => self.sys_arch_prctl(args[0] as i32, args[1]),
            218 => self.sys_set_tid_address(),
            231 => self.sys_exit_group(args[0] as i32),
            257 => self.sys_openat(args[0] as i32, args[1] as usize, args[2] as i32),
            273 => self.sys_set_robust_list(),
            302 => self.sys_prlimit64(args[0] as i32, args[1] as i32, args[2], args[3] as usize),
            334 => ENOSYS, // rseq — musl handles gracefully
            _ => ENOSYS,
        }
    }

    /// Linux write(2): write to a file descriptor.
    fn sys_write(&mut self, fd: i32, buf_ptr: usize, count: usize) -> i64 {
        // POSIX: write with count == 0 is a no-op.
        if count == 0 {
            return 0;
        }

        let entry = match self.fd_table.get_mut(&fd) {
            Some(e) => e,
            None => return EBADF,
        };
        let fid = entry.fid;
        let offset = entry.offset;

        // In the MVP flat address space, we can directly read from the pointer.
        // Safety: caller guarantees buf_ptr points to valid memory of at least
        // `count` bytes. This is the same trust model as a real kernel reading
        // from user space — except here there's no protection boundary.
        let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, count) };

        match self.backend.write(fid, offset, data) {
            Ok(n) => {
                self.fd_table.get_mut(&fd).unwrap().offset += n as u64;
                n as i64
            }
            Err(e) => ipc_err_to_errno(e),
        }
    }

    /// Linux read(2): read from a file descriptor.
    fn sys_read(&mut self, fd: i32, buf_ptr: usize, count: usize) -> i64 {
        if count == 0 {
            return 0;
        }

        let entry = match self.fd_table.get(&fd) {
            Some(e) => *e,
            None => return EBADF,
        };

        // 9P count is u32; cap to avoid silent truncation on large reads.
        let capped = count.min(u32::MAX as usize) as u32;

        match self.backend.read(entry.fid, entry.offset, capped) {
            Ok(data) => {
                let n = data.len().min(count);
                if n > 0 {
                    // Safety: caller guarantees buf_ptr points to valid memory of at
                    // least `count` bytes. Same trust model as sys_write.
                    unsafe {
                        core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr as *mut u8, n);
                    }
                    self.fd_table.get_mut(&fd).unwrap().offset += n as u64;
                }
                n as i64
            }
            Err(e) => ipc_err_to_errno(e),
        }
    }

    /// Linux close(2): close a file descriptor.
    fn sys_close(&mut self, fd: i32) -> i64 {
        let entry = match self.fd_table.remove(&fd) {
            Some(e) => e,
            None => return EBADF,
        };
        self.chardev_fids.retain(|&f| f != entry.fid);
        let _ = self.backend.clunk(entry.fid);
        0
    }

    /// Linux fstat(2): get file status.
    fn sys_fstat(&mut self, fd: i32, statbuf_ptr: usize) -> i64 {
        if statbuf_ptr == 0 {
            return EINVAL;
        }
        let fid = match self.fd_table.get(&fd) {
            Some(e) => e.fid,
            None => return EBADF,
        };
        let is_chardev = self.chardev_fids.contains(&fid);
        match self.backend.stat(fid) {
            Ok(stat) => {
                write_linux_stat(statbuf_ptr, &stat, is_chardev);
                0
            }
            Err(e) => ipc_err_to_errno(e),
        }
    }

    /// Linux openat(2): open a file relative to a directory fd.
    fn sys_openat(&mut self, dirfd: i32, pathname_ptr: usize, flags: i32) -> i64 {
        let path = unsafe { read_c_string(pathname_ptr) };

        let at_fdcwd: i32 = -100;
        // TODO: relative-path resolution relative to dirfd is not yet implemented.
        // All current callers use AT_FDCWD or absolute paths, so this is fine for
        // the MVP. A future implementation should resolve path components starting
        // from the fid mapped to dirfd.
        if dirfd != at_fdcwd && !self.fd_table.contains_key(&dirfd) {
            return EBADF;
        }

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
        self.fd_table.insert(fd, FdEntry { fid, offset: 0 });
        fd as i64
    }

    /// Linux exit(2): terminate the calling thread.
    ///
    /// In our single-threaded model, this is equivalent to exit_group.
    fn sys_exit(&mut self, code: i32) -> i64 {
        self.sys_exit_group(code)
    }

    /// Linux exit_group(2): terminate the process.
    fn sys_exit_group(&mut self, code: i32) -> i64 {
        self.exit_code = Some(code);
        0
    }

    /// Linux brk(2): adjust the program break.
    ///
    /// `addr == 0` probes the current break. Otherwise sets it to the
    /// requested address (page-aligned up). Returns the new break, or
    /// the current break unchanged if the request is invalid.
    fn sys_brk(&mut self, addr: u64) -> i64 {
        let base = self.arena.base as u64;
        if addr == 0 {
            return (base + self.arena.brk_offset as u64) as i64;
        }
        if addr < base {
            return (base + self.arena.brk_offset as u64) as i64;
        }
        let requested_offset = (addr - base) as usize;
        if requested_offset > self.arena.mmap_top {
            return (base + self.arena.brk_offset as u64) as i64;
        }
        self.arena.brk_offset = (requested_offset + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        (base + self.arena.brk_offset as u64) as i64
    }

    /// Linux mmap(2): map anonymous memory.
    ///
    /// Only `MAP_ANONYMOUS` is supported. Allocates from the top of the
    /// arena downward (opposite direction from brk). Returns the mapped
    /// address or a negative errno.
    ///
    /// `MAP_FIXED` is rejected with `ENOMEM` — the arena allocator cannot
    /// guarantee placement at an arbitrary address.
    fn sys_mmap(
        &mut self,
        addr: u64,
        length: u64,
        _prot: i32,
        flags: i32,
        _fd: i32,
        _offset: u64,
    ) -> i64 {
        let map_anonymous = 0x20;
        let map_fixed = 0x10;
        if length == 0 {
            return EINVAL;
        }
        if flags & map_anonymous == 0 {
            return EINVAL; // file-backed mmap not supported
        }
        if flags & map_fixed != 0 {
            return ENOMEM; // arena allocator cannot place at fixed address
        }
        let _ = addr; // hint addr is intentionally unused (no MAP_FIXED support)
        let len = ((length as usize) + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if len > self.arena.mmap_top.saturating_sub(self.arena.brk_offset) {
            return ENOMEM;
        }
        self.arena.mmap_top -= len;
        let ptr = self.arena.base + self.arena.mmap_top;
        // Safety: ptr is within the arena allocation and len bytes are available.
        unsafe {
            core::ptr::write_bytes(ptr as *mut u8, 0, len);
        }
        self.arena.mmap_regions.push((self.arena.mmap_top, len));
        ptr as i64
    }

    /// Linux munmap(2): unmap memory (stub — always succeeds).
    fn sys_munmap(&mut self, _addr: u64, _length: u64) -> i64 {
        0
    }

    /// Linux ioctl(2): device control.
    ///
    /// Validates the fd first. TIOCGWINSZ returns ENOTTY (no terminal).
    /// Unknown requests return EINVAL (not ENOSYS — ENOSYS means "syscall
    /// does not exist", while EINVAL means "unsupported request on this fd").
    fn sys_ioctl(&self, fd: i32, request: u64) -> i64 {
        if !self.fd_table.contains_key(&fd) {
            return EBADF;
        }
        const TIOCGWINSZ: u64 = 0x5413;
        match request {
            TIOCGWINSZ => ENOTTY,
            _ => EINVAL,
        }
    }

    /// Linux rt_sigaction(2): stub — no signal support.
    fn sys_rt_sigaction(&self) -> i64 {
        0
    }

    /// Linux rt_sigprocmask(2): stub — no signal support.
    fn sys_rt_sigprocmask(&self) -> i64 {
        0
    }

    /// Linux set_tid_address(2): return TID = 1 (single-threaded).
    fn sys_set_tid_address(&self) -> i64 {
        1
    }

    /// Linux set_robust_list(2): stub — no futex cleanup needed.
    fn sys_set_robust_list(&self) -> i64 {
        0
    }

    /// Linux prlimit64(2): query/set resource limits.
    ///
    /// Only RLIMIT_STACK is supported (returns 8 MiB). Unknown resources
    /// return EINVAL to prevent callers from reading uninitialized buffers.
    fn sys_prlimit64(&self, pid: i32, resource: i32, _new_limit: u64, old_limit_ptr: usize) -> i64 {
        const RLIMIT_STACK: i32 = 3;
        if pid != 0 {
            return ESRCH;
        }
        if resource == RLIMIT_STACK {
            if old_limit_ptr != 0 {
                let eight_mb = 8u64 * 1024 * 1024;
                unsafe {
                    core::ptr::write_unaligned(old_limit_ptr as *mut u64, eight_mb); // rlim_cur
                    core::ptr::write_unaligned((old_limit_ptr + 8) as *mut u64, eight_mb); // rlim_max
                }
            }
            return 0;
        }
        EINVAL // unknown resource
    }

    /// Linux arch_prctl(2): set/get architecture-specific thread state.
    ///
    /// ARCH_SET_FS records the FS base address (TLS pointer). On bare
    /// metal, the boot crate writes the actual IA32_FS_BASE MSR after
    /// this method returns (only when retval == 0). In unit tests, we
    /// just record the value.
    ///
    /// ARCH_GET_FS writes the stored FS base to the user pointer.
    fn sys_arch_prctl(&mut self, code: i32, addr: u64) -> i64 {
        const ARCH_SET_FS: i32 = 0x1002;
        const ARCH_GET_FS: i32 = 0x1003;
        match code {
            ARCH_SET_FS => {
                self.fs_base = addr;
                0
            }
            ARCH_GET_FS => {
                if addr != 0 {
                    unsafe {
                        core::ptr::write_unaligned(addr as *mut u64, self.fs_base);
                    }
                }
                0
            }
            _ => EINVAL,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn mock_backend_records_write() {
        let mut mock = MockBackend::new();
        mock.write(1, 0, b"hello").unwrap();
        assert_eq!(mock.writes.len(), 1);
        assert_eq!(mock.writes[0], (1, vec![b'h', b'e', b'l', b'l', b'o']));
    }

    #[test]
    fn mock_backend_records_walk() {
        let mut mock = MockBackend::new();
        let qpath = mock.walk("/dev/serial/log", 10).unwrap();
        assert_eq!(qpath, 0);
        assert_eq!(mock.walks.len(), 1);
        assert_eq!(mock.walks[0], ("/dev/serial/log".into(), 10));
    }

    #[test]
    fn linuxulator_init_creates_fd_table() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        // Should have fd 0, 1, 2
        assert!(lx.has_fd(0));
        assert!(lx.has_fd(1));
        assert!(lx.has_fd(2));
        assert!(!lx.has_fd(3));
    }

    #[test]
    fn init_stdio_walks_and_opens_serial() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        // Should have walked to /dev/serial/log three times
        // (stdin, stdout, stderr each get their own fid)
        assert_eq!(lx.backend().walks.len(), 3);
        assert_eq!(lx.backend().walks[0].0, "/dev/serial/log");

        // Should have opened all three
        assert_eq!(lx.backend().opens.len(), 3);
    }

    #[test]
    fn linuxulator_starts_not_exited() {
        let mock = MockBackend::new();
        let lx = Linuxulator::new(mock);
        assert!(!lx.exited());
        assert_eq!(lx.exit_code(), None);
    }

    #[test]
    fn sys_write_to_stdout() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        let msg = b"Hello\n";
        let result = lx.handle_syscall(1, [1, msg.as_ptr() as u64, 6, 0, 0, 0]);
        assert_eq!(result, 6); // 6 bytes written

        // Backend should have received the write
        let stdout_fid = lx.fid_for_fd(1).unwrap();
        let stdout_writes: Vec<_> = lx
            .backend()
            .writes
            .iter()
            .filter(|(fid, _)| *fid == stdout_fid)
            .collect();
        assert_eq!(stdout_writes.len(), 1);
        assert_eq!(stdout_writes[0].1, b"Hello\n");
    }

    #[test]
    fn sys_write_bad_fd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        let msg = b"test";
        let result = lx.handle_syscall(1, [99, msg.as_ptr() as u64, 4, 0, 0, 0]);
        assert_eq!(result, EBADF);
    }

    #[test]
    fn sys_exit_group_sets_flag() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let result = lx.handle_syscall(231, [42, 0, 0, 0, 0, 0]);
        assert_eq!(result, 0);
        assert!(lx.exited());
        assert_eq!(lx.exit_code(), Some(42));
    }

    #[test]
    fn unknown_syscall_returns_enosys() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let result = lx.handle_syscall(9999, [0, 0, 0, 0, 0, 0]);
        assert_eq!(result, ENOSYS);
    }

    #[test]
    fn ipc_err_to_errno_maps_all_variants() {
        assert_eq!(ipc_err_to_errno(IpcError::NotFound), -2);
        assert_eq!(ipc_err_to_errno(IpcError::PermissionDenied), -13);
        assert_eq!(ipc_err_to_errno(IpcError::NotOpen), -9);
        assert_eq!(ipc_err_to_errno(IpcError::InvalidFid), -9);
        assert_eq!(ipc_err_to_errno(IpcError::NotDirectory), -20);
        assert_eq!(ipc_err_to_errno(IpcError::IsDirectory), -21);
        assert_eq!(ipc_err_to_errno(IpcError::ReadOnly), -30);
        assert_eq!(ipc_err_to_errno(IpcError::ResourceExhausted), -12);
        assert_eq!(ipc_err_to_errno(IpcError::Conflict), -17);
        assert_eq!(ipc_err_to_errno(IpcError::NotSupported), -38);
        assert_eq!(ipc_err_to_errno(IpcError::InvalidArgument), -22);
    }

    #[test]
    fn sys_write_to_stderr() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        let msg = b"err";
        let result = lx.handle_syscall(1, [2, msg.as_ptr() as u64, 3, 0, 0, 0]);
        assert_eq!(result, 3);
    }

    // ── Memory arena tests ────────────────────────────────────────────

    #[test]
    fn arena_brk_probe_returns_base() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::with_arena(mock, 64 * 1024);
        let base = lx.handle_syscall(12, [0, 0, 0, 0, 0, 0]);
        assert!(base > 0);
        assert_eq!(base as usize, lx.arena_base());
    }

    #[test]
    fn arena_brk_extend_returns_new_brk() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::with_arena(mock, 64 * 1024);
        let base = lx.handle_syscall(12, [0, 0, 0, 0, 0, 0]) as u64;
        let new_brk = lx.handle_syscall(12, [base + 8192, 0, 0, 0, 0, 0]);
        assert_eq!(new_brk as u64, base + 8192);
    }

    #[test]
    fn arena_brk_aligns_to_4k() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::with_arena(mock, 64 * 1024);
        let base = lx.handle_syscall(12, [0, 0, 0, 0, 0, 0]) as u64;
        let new_brk = lx.handle_syscall(12, [base + 100, 0, 0, 0, 0, 0]);
        assert_eq!(new_brk as u64, base + 4096);
    }

    #[test]
    fn arena_mmap_anonymous_returns_valid_address() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::with_arena(mock, 64 * 1024);
        let base = lx.arena_base();
        let arena_size = 64 * 1024;
        let addr = lx.handle_syscall(9, [0, 4096, 3, 0x22, u64::MAX, 0]);
        assert!(addr > 0);
        let addr = addr as usize;
        assert!(addr >= base);
        assert!(addr < base + arena_size);
        assert_eq!(addr % 4096, 0);
    }

    #[test]
    fn arena_mmap_is_zero_filled() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::with_arena(mock, 64 * 1024);
        let addr = lx.handle_syscall(9, [0, 4096, 3, 0x22, u64::MAX, 0]) as usize;
        let slice = unsafe { core::slice::from_raw_parts(addr as *const u8, 4096) };
        assert!(slice.iter().all(|&b| b == 0));
    }

    #[test]
    fn arena_brk_cannot_exceed_mmap() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::with_arena(mock, 16 * 1024);
        let base = lx.handle_syscall(12, [0, 0, 0, 0, 0, 0]) as u64;
        let _addr = lx.handle_syscall(9, [0, 8192, 3, 0x22, u64::MAX, 0]);
        let result = lx.handle_syscall(12, [base + 16384, 0, 0, 0, 0, 0]) as u64;
        assert!(result < base + 16384);
    }

    #[test]
    fn arena_mmap_exhaustion_returns_enomem() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::with_arena(mock, 16 * 1024);
        let result = lx.handle_syscall(9, [0, 32768, 3, 0x22, u64::MAX, 0]);
        assert_eq!(result, ENOMEM);
    }

    #[test]
    fn arena_mmap_zero_length_returns_einval() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::with_arena(mock, 64 * 1024);
        let result = lx.handle_syscall(9, [0, 0, 3, 0x22, u64::MAX, 0]);
        assert_eq!(result, EINVAL);
    }

    #[test]
    fn arena_mmap_fixed_returns_enomem() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::with_arena(mock, 64 * 1024);
        // MAP_FIXED (0x10) | MAP_ANONYMOUS (0x20) = 0x30, with non-zero addr
        let result = lx.handle_syscall(9, [0x1000, 4096, 3, 0x30, u64::MAX, 0]);
        assert_eq!(result, ENOMEM);
    }

    #[test]
    fn arena_mmap_fixed_at_zero_also_returns_enomem() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::with_arena(mock, 64 * 1024);
        // MAP_FIXED with addr=0 should also be rejected
        let result = lx.handle_syscall(9, [0, 4096, 3, 0x30, u64::MAX, 0]);
        assert_eq!(result, ENOMEM);
    }

    #[test]
    fn arena_munmap_returns_success() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::with_arena(mock, 64 * 1024);
        let addr = lx.handle_syscall(9, [0, 4096, 3, 0x22, u64::MAX, 0]) as u64;
        let result = lx.handle_syscall(11, [addr, 4096, 0, 0, 0, 0]);
        assert_eq!(result, 0);
    }

    // ── sys_read tests ────────────────────────────────────────────────

    #[test]
    fn sys_read_copies_data_to_buffer() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();
        let mut buf = [0xFFu8; 64];
        let result = lx.handle_syscall(0, [0, buf.as_mut_ptr() as u64, 64, 0, 0, 0]);
        assert_eq!(result, 0); // MockBackend returns empty Vec
    }

    #[test]
    fn sys_read_bad_fd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut buf = [0u8; 64];
        let result = lx.handle_syscall(0, [99, buf.as_mut_ptr() as u64, 64, 0, 0, 0]);
        assert_eq!(result, EBADF);
    }

    #[test]
    fn sys_read_zero_count() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();
        let result = lx.handle_syscall(0, [0, 0, 0, 0, 0, 0]);
        assert_eq!(result, 0);
    }

    // ── sys_close tests ───────────────────────────────────────────────

    #[test]
    fn sys_close_removes_fd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();
        assert!(lx.has_fd(1));
        let result = lx.handle_syscall(3, [1, 0, 0, 0, 0, 0]);
        assert_eq!(result, 0);
        assert!(!lx.has_fd(1));
        assert_eq!(lx.backend().clunks.len(), 1);
    }

    #[test]
    fn sys_close_bad_fd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.handle_syscall(3, [99, 0, 0, 0, 0, 0]);
        assert_eq!(result, EBADF);
    }

    #[test]
    fn sys_close_cleans_chardev_fids() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();
        // Closing stdout should remove its fid from chardev_fids
        let stdout_fid = lx.fid_for_fd(1).unwrap();
        assert!(lx.chardev_fids.contains(&stdout_fid));
        lx.handle_syscall(3, [1, 0, 0, 0, 0, 0]);
        assert!(!lx.chardev_fids.contains(&stdout_fid));
    }

    // ── sys_openat tests ──────────────────────────────────────────────

    #[test]
    fn sys_openat_walks_and_opens() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();
        let path = b"/dev/serial/log\0";
        let at_fdcwd = (-100i32) as u64;
        let result = lx.handle_syscall(257, [at_fdcwd, path.as_ptr() as u64, 0, 0, 0, 0]);
        assert!(result >= 0);
        assert_eq!(result, 3); // first fd after stdin/stdout/stderr
        assert!(lx.backend().walks.len() > 3); // 3 from init_stdio + 1 from openat
        assert!(lx.has_fd(3));
    }

    // ── sys_exit tests ────────────────────────────────────────────────

    #[test]
    fn sys_exit_is_same_as_exit_group() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.handle_syscall(60, [7, 0, 0, 0, 0, 0]);
        assert_eq!(result, 0);
        assert!(lx.exited());
        assert_eq!(lx.exit_code(), Some(7));
    }

    // ── sys_fstat tests ──────────────────────────────────────────────

    #[test]
    fn sys_fstat_writes_stat_struct() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        let mut statbuf = [0u8; 144];
        let result = lx.handle_syscall(5, [1, statbuf.as_mut_ptr() as u64, 0, 0, 0, 0]);
        assert_eq!(result, 0);

        // st_mode at offset 24 should be S_IFCHR | 0o666 for stdio
        let st_mode = u32::from_le_bytes([statbuf[24], statbuf[25], statbuf[26], statbuf[27]]);
        let s_ifchr: u32 = 0o020000;
        assert_eq!(st_mode & 0o170000, s_ifchr);
    }

    #[test]
    fn sys_fstat_bad_fd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut statbuf = [0u8; 144];
        let result = lx.handle_syscall(5, [99, statbuf.as_mut_ptr() as u64, 0, 0, 0, 0]);
        assert_eq!(result, EBADF);
    }

    #[test]
    fn sys_fstat_null_ptr_returns_einval() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();
        let result = lx.handle_syscall(5, [1, 0, 0, 0, 0, 0]);
        assert_eq!(result, EINVAL);
    }

    // ── stub syscall tests ──────────────────────────────────────────

    #[test]
    fn sys_ioctl_tiocgwinsz_returns_enotty() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();
        let result = lx.handle_syscall(16, [1, 0x5413, 0, 0, 0, 0]); // ioctl(stdout, TIOCGWINSZ)
        assert_eq!(result, ENOTTY);
    }

    #[test]
    fn sys_ioctl_unknown_returns_einval() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();
        let result = lx.handle_syscall(16, [1, 0xFFFF, 0, 0, 0, 0]);
        assert_eq!(result, EINVAL);
    }

    #[test]
    fn sys_ioctl_bad_fd_returns_ebadf() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.handle_syscall(16, [99, 0x5413, 0, 0, 0, 0]);
        assert_eq!(result, EBADF);
    }

    #[test]
    fn sys_set_tid_address_returns_tid() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.handle_syscall(218, [0, 0, 0, 0, 0, 0]);
        assert_eq!(result, 1); // TID = 1
    }

    #[test]
    fn sys_set_robust_list_returns_zero() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.handle_syscall(273, [0, 0, 0, 0, 0, 0]);
        assert_eq!(result, 0);
    }

    #[test]
    fn sys_rt_sigaction_returns_zero() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.handle_syscall(13, [2, 0, 0, 8, 0, 0]); // sigaction(SIGINT, ...)
        assert_eq!(result, 0);
    }

    #[test]
    fn sys_rt_sigprocmask_returns_zero() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.handle_syscall(14, [0, 0, 0, 0, 0, 0]);
        assert_eq!(result, 0);
    }

    #[test]
    fn sys_prlimit64_writes_stack_limit() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut rlimit = [0u8; 16]; // rlim_cur (8) + rlim_max (8)
                                    // prlimit64(0, RLIMIT_STACK=3, NULL, &rlimit)
        let result = lx.handle_syscall(302, [0, 3, 0, rlimit.as_mut_ptr() as u64, 0, 0]);
        assert_eq!(result, 0);
        let rlim_cur = u64::from_le_bytes(rlimit[0..8].try_into().unwrap());
        assert_eq!(rlim_cur, 8 * 1024 * 1024); // 8 MiB
    }

    #[test]
    fn sys_rseq_returns_enosys() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.handle_syscall(334, [0, 0, 0, 0, 0, 0]);
        assert_eq!(result, ENOSYS);
    }

    // ── sys_arch_prctl tests ────────────────────────────────────────

    #[test]
    fn sys_arch_prctl_set_fs_returns_zero() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // ARCH_SET_FS = 0x1002
        let result = lx.handle_syscall(158, [0x1002, 0x12345678, 0, 0, 0, 0]);
        assert_eq!(result, 0);
    }

    #[test]
    fn sys_arch_prctl_unknown_code_returns_einval() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.handle_syscall(158, [0x9999, 0, 0, 0, 0, 0]);
        assert_eq!(result, EINVAL);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use harmony_identity::PrivateIdentity;
    use harmony_microkernel::echo::EchoServer;
    use harmony_microkernel::kernel::Kernel;
    use harmony_microkernel::serial_server::SerialServer;
    use harmony_unikernel::KernelEntropy;

    /// SyscallBackend backed by a real Ring 2 Kernel.
    struct KernelBackend<'a> {
        kernel: &'a mut Kernel,
        pid: u32,
    }

    impl<'a> KernelBackend<'a> {
        fn new(kernel: &'a mut Kernel, pid: u32) -> Self {
            Self { kernel, pid }
        }
    }

    impl SyscallBackend for KernelBackend<'_> {
        fn walk(&mut self, path: &str, new_fid: Fid) -> Result<QPath, IpcError> {
            self.kernel.walk(self.pid, path, 0, new_fid, 0)
        }
        fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
            self.kernel.open(self.pid, fid, mode)
        }
        fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
            self.kernel.read(self.pid, fid, offset, count)
        }
        fn write(&mut self, fid: Fid, offset: u64, data: &[u8]) -> Result<u32, IpcError> {
            self.kernel.write(self.pid, fid, offset, data)
        }
        fn clunk(&mut self, fid: Fid) -> Result<(), IpcError> {
            self.kernel.clunk(self.pid, fid)
        }
        fn stat(&mut self, fid: Fid) -> Result<FileStat, IpcError> {
            self.kernel.stat(self.pid, fid)
        }
    }

    fn test_entropy() -> KernelEntropy<impl FnMut(&mut [u8])> {
        let mut seed = 99u64;
        KernelEntropy::new(move |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (seed >> 33) as u8;
            }
        })
    }

    #[test]
    fn linuxulator_writes_hello_through_kernel_to_serial() {
        let mut entropy = test_entropy();
        let kernel_id = PrivateIdentity::generate(&mut entropy);
        let mut kernel = Kernel::new(kernel_id);

        // Spawn SerialServer
        let serial_pid = kernel
            .spawn_process("serial", Box::new(SerialServer::new()), &[])
            .unwrap();

        // Spawn a "linux process" with SerialServer mounted at /dev/serial
        let linux_pid = kernel
            .spawn_process(
                "hello-linux",
                Box::new(EchoServer::new()), // placeholder server
                &[("/dev/serial", serial_pid, 0)],
            )
            .unwrap();

        // Grant the linux process access to the serial server
        kernel
            .grant_endpoint_cap(&mut entropy, linux_pid, serial_pid, 0)
            .unwrap();

        // Create Linuxulator with KernelBackend
        let backend = KernelBackend::new(&mut kernel, linux_pid);
        let mut lx = Linuxulator::new(backend);
        lx.init_stdio().unwrap();

        // Simulate the hello binary's syscalls
        let msg = b"Hello\n";
        let result = lx.handle_syscall(1, [1, msg.as_ptr() as u64, 6, 0, 0, 0]);
        assert_eq!(result, 6);

        // Verify "Hello\n" reached the SerialServer's buffer
        // Read back through the kernel via the linux process
        let read_fid = 200;
        lx.backend_mut().walk("/dev/serial/log", read_fid).unwrap();
        lx.backend_mut().open(read_fid, OpenMode::Read).unwrap();
        let data = lx.backend_mut().read(read_fid, 0, 256).unwrap();
        assert_eq!(data, b"Hello\n");

        // Verify exit_group
        lx.handle_syscall(231, [0, 0, 0, 0, 0, 0]);
        assert!(lx.exited());
        assert_eq!(lx.exit_code(), Some(0));
    }

    #[test]
    fn linuxulator_full_fd_lifecycle() {
        let mut entropy = test_entropy();
        let kernel_id = PrivateIdentity::generate(&mut entropy);
        let mut kernel = Kernel::new(kernel_id);

        let serial_pid = kernel
            .spawn_process("serial", Box::new(SerialServer::new()), &[])
            .unwrap();

        let linux_pid = kernel
            .spawn_process(
                "hello-linux",
                Box::new(EchoServer::new()),
                &[("/dev/serial", serial_pid, 0)],
            )
            .unwrap();

        kernel
            .grant_endpoint_cap(&mut entropy, linux_pid, serial_pid, 0)
            .unwrap();

        let backend = KernelBackend::new(&mut kernel, linux_pid);
        let mut lx = Linuxulator::new(backend);
        lx.init_stdio().unwrap();

        // Write to stdout
        let msg = b"Hello\n";
        let result = lx.handle_syscall(1, [1, msg.as_ptr() as u64, 6, 0, 0, 0]);
        assert_eq!(result, 6);

        // fstat on stdout — should succeed
        let mut statbuf = [0u8; 144];
        let result = lx.handle_syscall(5, [1, statbuf.as_mut_ptr() as u64, 0, 0, 0, 0]);
        assert_eq!(result, 0);

        // Close stdout
        let result = lx.handle_syscall(3, [1, 0, 0, 0, 0, 0]);
        assert_eq!(result, 0);
        assert!(!lx.has_fd(1));

        // Write to closed fd should fail
        let result = lx.handle_syscall(1, [1, msg.as_ptr() as u64, 6, 0, 0, 0]);
        assert_eq!(result, -9); // EBADF

        // Exit
        lx.handle_syscall(231, [0, 0, 0, 0, 0, 0]);
        assert!(lx.exited());
    }
}
