// SPDX-License-Identifier: GPL-2.0-or-later
//! Linuxulator — Linux syscall-to-9P translation layer for Ring 3.
//!
//! Translates Linux syscall numbers and arguments into 9P FileServer
//! operations via a [`SyscallBackend`] trait. Manages a POSIX-style
//! fd table that maps Linux file descriptors to 9P fids.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use harmony_microkernel::vm::{FrameClassification, PageFlags, VmError};
use harmony_microkernel::{Fid, FileStat, FileType, IpcError, OpenMode, QPath};

// ── Linux errno constants ───────────────────────────────────────────

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const ESRCH: i64 = -3;
const EBADF: i64 = -9;
const EFAULT: i64 = -14;
const ENOMEM: i64 = -12;
const ENOTDIR: i64 = -20;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const ESPIPE: i64 = -29;
const EROFS: i64 = -30;
const ERANGE: i64 = -34;
const ENOSYS: i64 = -38;
const EOVERFLOW: i64 = -75;

fn ipc_err_to_errno(e: IpcError) -> i64 {
    match e {
        IpcError::NotFound => ENOENT,
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

fn vm_err_to_errno(e: VmError) -> i64 {
    match e {
        VmError::OutOfMemory | VmError::BudgetExceeded { .. } => ENOMEM,
        VmError::NotMapped(_) => EINVAL,
        VmError::RegionConflict(_) => EINVAL,
        VmError::NoSuchProcess(_) => ESRCH,
        VmError::ClassificationDenied(_) => EPERM,
        VmError::CapabilityInvalid => EPERM,
        VmError::Unaligned(_) => EINVAL,
        VmError::InvalidOrder(_) => EINVAL,
        VmError::PageTableError => ENOMEM,
        VmError::ProcessExists(_) => EINVAL,
    }
}

/// Directory entry returned by [`SyscallBackend::readdir`].
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: alloc::string::String,
    pub file_type: FileType,
}

// ── LinuxSyscall — CPU-agnostic syscall representation ──────────

/// CPU-agnostic Linux syscall. Each architecture maps its native
/// syscall numbers into this enum before the Linuxulator dispatches.
#[derive(Debug)]
pub enum LinuxSyscall {
    Read {
        fd: i32,
        buf: u64,
        count: u64,
    },
    Write {
        fd: i32,
        buf: u64,
        count: u64,
    },
    Close {
        fd: i32,
    },
    Fstat {
        fd: i32,
        buf: u64,
    },
    Mmap {
        addr: u64,
        len: u64,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: u64,
    },
    Mprotect {
        addr: u64,
        len: u64,
        prot: i32,
    },
    Munmap {
        addr: u64,
        len: u64,
    },
    Brk {
        addr: u64,
    },
    RtSigaction,
    RtSigprocmask,
    Ioctl {
        fd: i32,
        request: u64,
    },
    Exit {
        code: i32,
    },
    ArchPrctl {
        code: i32,
        addr: u64,
    },
    SetTidAddress,
    ExitGroup {
        code: i32,
    },
    Openat {
        dirfd: i32,
        pathname: u64,
        flags: i32,
    },
    SetRobustList,
    Prlimit64 {
        pid: i32,
        resource: i32,
        new_limit: u64,
        old_limit_buf: u64,
    },
    Rseq,
    Writev {
        fd: i32,
        iov: u64,
        iovcnt: i32,
    },
    Lseek {
        fd: i32,
        offset: i64,
        whence: i32,
    },
    Getrandom {
        buf: u64,
        buflen: u64,
        flags: u32,
    },
    Getcwd {
        buf: u64,
        size: u64,
    },
    Readlink {
        pathname: u64,
        buf: u64,
        bufsiz: u64,
    },
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
    Unknown {
        nr: u64,
    },
}

impl LinuxSyscall {
    /// Map x86_64 Linux syscall numbers to `LinuxSyscall`.
    pub fn from_x86_64(nr: u64, args: [u64; 6]) -> Self {
        match nr {
            0 => LinuxSyscall::Read {
                fd: args[0] as i32,
                buf: args[1],
                count: args[2],
            },
            1 => LinuxSyscall::Write {
                fd: args[0] as i32,
                buf: args[1],
                count: args[2],
            },
            3 => LinuxSyscall::Close { fd: args[0] as i32 },
            5 => LinuxSyscall::Fstat {
                fd: args[0] as i32,
                buf: args[1],
            },
            8 => LinuxSyscall::Lseek {
                fd: args[0] as i32,
                offset: args[1] as i64,
                whence: args[2] as i32,
            },
            9 => LinuxSyscall::Mmap {
                addr: args[0],
                len: args[1],
                prot: args[2] as i32,
                flags: args[3] as i32,
                fd: args[4] as i32,
                offset: args[5],
            },
            10 => LinuxSyscall::Mprotect {
                addr: args[0],
                len: args[1],
                prot: args[2] as i32,
            },
            11 => LinuxSyscall::Munmap {
                addr: args[0],
                len: args[1],
            },
            12 => LinuxSyscall::Brk { addr: args[0] },
            13 => LinuxSyscall::RtSigaction,
            14 => LinuxSyscall::RtSigprocmask,
            16 => LinuxSyscall::Ioctl {
                fd: args[0] as i32,
                request: args[1],
            },
            20 => LinuxSyscall::Writev {
                fd: args[0] as i32,
                iov: args[1],
                iovcnt: args[2] as i32,
            },
            60 => LinuxSyscall::Exit {
                code: args[0] as i32,
            },
            79 => LinuxSyscall::Getcwd {
                buf: args[0],
                size: args[1],
            },
            80 => LinuxSyscall::Chdir {
                pathname: args[0],
            },
            81 => LinuxSyscall::Fchdir {
                fd: args[0] as i32,
            },
            89 => LinuxSyscall::Readlink {
                pathname: args[0],
                buf: args[1],
                bufsiz: args[2],
            },
            158 => LinuxSyscall::ArchPrctl {
                code: args[0] as i32,
                addr: args[1],
            },
            217 => LinuxSyscall::Getdents64 {
                fd: args[0] as i32,
                dirp: args[1],
                count: args[2],
            },
            218 => LinuxSyscall::SetTidAddress,
            231 => LinuxSyscall::ExitGroup {
                code: args[0] as i32,
            },
            257 => LinuxSyscall::Openat {
                dirfd: args[0] as i32,
                pathname: args[1],
                flags: args[2] as i32,
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
            // x86_64 nr 267 is readlinkat(dirfd, pathname, buf, bufsiz).
            // Only AT_FDCWD is supported; explicit dirfds return ENOSYS
            // via the Unknown fallback.
            267 => {
                const AT_FDCWD: i32 = -100;
                if args[0] as i32 != AT_FDCWD {
                    LinuxSyscall::Unknown { nr: 267 }
                } else {
                    LinuxSyscall::Readlink {
                        pathname: args[1],
                        buf: args[2],
                        bufsiz: args[3],
                    }
                }
            }
            269 => LinuxSyscall::Faccessat {
                dirfd: args[0] as i32,
                pathname: args[1],
                mode: args[2] as i32,
            },
            273 => LinuxSyscall::SetRobustList,
            302 => LinuxSyscall::Prlimit64 {
                pid: args[0] as i32,
                resource: args[1] as i32,
                new_limit: args[2],
                old_limit_buf: args[3],
            },
            318 => LinuxSyscall::Getrandom {
                buf: args[0],
                buflen: args[1],
                flags: args[2] as u32,
            },
            334 => LinuxSyscall::Rseq,
            _ => LinuxSyscall::Unknown { nr },
        }
    }

    /// Map aarch64 Linux syscall numbers to `LinuxSyscall`.
    ///
    /// Reference: Linux kernel `include/uapi/asm-generic/unistd.h`
    /// (aarch64 uses the generic syscall table).
    pub fn from_aarch64(nr: u64, args: [u64; 6]) -> Self {
        match nr {
            17 => LinuxSyscall::Getcwd {
                buf: args[0],
                size: args[1],
            },
            29 => LinuxSyscall::Ioctl {
                fd: args[0] as i32,
                request: args[1],
            },
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
            49 => LinuxSyscall::Chdir {
                pathname: args[0],
            },
            50 => LinuxSyscall::Fchdir {
                fd: args[0] as i32,
            },
            56 => LinuxSyscall::Openat {
                dirfd: args[0] as i32,
                pathname: args[1],
                flags: args[2] as i32,
            },
            57 => LinuxSyscall::Close { fd: args[0] as i32 },
            61 => LinuxSyscall::Getdents64 {
                fd: args[0] as i32,
                dirp: args[1],
                count: args[2],
            },
            62 => LinuxSyscall::Lseek {
                fd: args[0] as i32,
                offset: args[1] as i64,
                whence: args[2] as i32,
            },
            63 => LinuxSyscall::Read {
                fd: args[0] as i32,
                buf: args[1],
                count: args[2],
            },
            64 => LinuxSyscall::Write {
                fd: args[0] as i32,
                buf: args[1],
                count: args[2],
            },
            66 => LinuxSyscall::Writev {
                fd: args[0] as i32,
                iov: args[1],
                iovcnt: args[2] as i32,
            },
            // aarch64 nr 78 is readlinkat(dirfd, pathname, buf, bufsiz).
            // readlinkat(dirfd, pathname, buf, bufsiz).  Only AT_FDCWD
            // is supported; explicit dirfds return ENOSYS until a full
            // implementation is added.
            78 => {
                const AT_FDCWD: i32 = -100;
                if args[0] as i32 != AT_FDCWD {
                    LinuxSyscall::Unknown { nr: 78 }
                } else {
                    LinuxSyscall::Readlink {
                        pathname: args[1],
                        buf: args[2],
                        bufsiz: args[3],
                    }
                }
            }
            79 => LinuxSyscall::Newfstatat {
                dirfd: args[0] as i32,
                pathname: args[1],
                statbuf: args[2],
                flags: args[3] as i32,
            },
            80 => LinuxSyscall::Fstat {
                fd: args[0] as i32,
                buf: args[1],
            },
            93 => LinuxSyscall::Exit {
                code: args[0] as i32,
            },
            94 => LinuxSyscall::ExitGroup {
                code: args[0] as i32,
            },
            96 => LinuxSyscall::SetTidAddress,
            99 => LinuxSyscall::SetRobustList,
            134 => LinuxSyscall::RtSigaction,
            135 => LinuxSyscall::RtSigprocmask,
            214 => LinuxSyscall::Brk { addr: args[0] },
            215 => LinuxSyscall::Munmap {
                addr: args[0],
                len: args[1],
            },
            222 => LinuxSyscall::Mmap {
                addr: args[0],
                len: args[1],
                prot: args[2] as i32,
                flags: args[3] as i32,
                fd: args[4] as i32,
                offset: args[5],
            },
            226 => LinuxSyscall::Mprotect {
                addr: args[0],
                len: args[1],
                prot: args[2] as i32,
            },
            261 => LinuxSyscall::Prlimit64 {
                pid: args[0] as i32,
                resource: args[1] as i32,
                new_limit: args[2],
                old_limit_buf: args[3],
            },
            278 => LinuxSyscall::Getrandom {
                buf: args[0],
                buflen: args[1],
                flags: args[2] as u32,
            },
            293 => LinuxSyscall::Rseq,
            _ => LinuxSyscall::Unknown { nr },
        }
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

    // ── VM operations (optional) ──────────────────────────────────

    /// Whether this backend supports VM operations.
    ///
    /// When `false`, the Linuxulator falls back to the MemoryArena for
    /// mmap/munmap/brk. When `true`, those syscalls delegate to the VM
    /// methods below.
    fn has_vm_support(&self) -> bool {
        false
    }

    /// Map a region of virtual memory. Returns the base virtual address.
    fn vm_mmap(
        &mut self,
        _vaddr: u64,
        _len: usize,
        _flags: PageFlags,
        _classification: FrameClassification,
    ) -> Result<u64, VmError> {
        Err(VmError::PageTableError)
    }

    /// Unmap a previously mapped region.
    fn vm_munmap(&mut self, _vaddr: u64, _len: usize) -> Result<(), VmError> {
        Err(VmError::PageTableError)
    }

    /// Change protection flags on a mapped region.
    fn vm_mprotect(&mut self, _vaddr: u64, _len: usize, _flags: PageFlags) -> Result<(), VmError> {
        Err(VmError::PageTableError)
    }

    /// Find a free virtual address region of at least `len` bytes.
    fn vm_find_free_region(&self, _len: usize) -> Result<u64, VmError> {
        Err(VmError::PageTableError)
    }

    /// Write bytes into a mapped VM region.
    ///
    /// Default implementation uses an unsafe pointer write, which works
    /// when the mapped address is directly accessible (arena, real VM
    /// with identity-mapped memory). Mock backends override this to
    /// record the write without dereferencing the simulated address.
    ///
    /// # Safety
    /// The default implementation dereferences `addr` as a raw pointer.
    /// Callers must ensure the region at `addr` is mapped and writable.
    fn vm_write_bytes(&mut self, addr: u64, data: &[u8]) {
        if !data.is_empty() {
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), addr as usize as *mut u8, data.len());
            }
        }
    }

    /// List directory entries for the given fid.
    ///
    /// Default implementation returns `IpcError::NotDirectory` — backends that
    /// expose a real filesystem override this.
    fn readdir(&mut self, _fid: Fid) -> Result<Vec<DirEntry>, IpcError> {
        Err(IpcError::NotDirectory)
    }
}

// ── MockBackend ─────────────────────────────────────────────────────

/// Test double that records all 9P calls for assertion.
///
/// Does NOT support VM operations (`has_vm_support()` returns `false`),
/// so the Linuxulator falls back to MemoryArena for mmap/munmap/brk.
/// Use [`VmMockBackend`] for tests that exercise the VM path.
#[cfg(test)]
pub struct MockBackend {
    pub walks: Vec<(alloc::string::String, Fid)>,
    pub opens: Vec<(Fid, OpenMode)>,
    pub writes: Vec<(Fid, Vec<u8>)>,
    pub reads: Vec<(Fid, u64, u32)>,
    pub clunks: Vec<Fid>,
    pub stats: Vec<Fid>,
    /// File content keyed by fid. Populated via `set_file_content` so that
    /// `read()` returns real data instead of an empty Vec.
    file_content: BTreeMap<Fid, Vec<u8>>,
    /// Directory entries keyed by fid, for readdir testing.
    pub readdir_entries: BTreeMap<Fid, Vec<DirEntry>>,
    /// Paths that are directories (for stat to return FileType::Directory).
    pub directory_paths: alloc::collections::BTreeSet<alloc::string::String>,
    /// Fids that represent directories.
    pub directory_fids: alloc::collections::BTreeSet<Fid>,
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
            file_content: BTreeMap::new(),
            readdir_entries: BTreeMap::new(),
            directory_paths: alloc::collections::BTreeSet::new(),
            directory_fids: alloc::collections::BTreeSet::new(),
        }
    }

    /// Register file content for a fid. Subsequent `read()` calls on this
    /// fid will return data from the content buffer at the requested offset.
    pub fn set_file_content(&mut self, fid: Fid, content: Vec<u8>) {
        self.file_content.insert(fid, content);
    }
}

/// VM-aware test double that records VM operations for assertion.
///
/// Returns `has_vm_support() == true` and records all VM calls. Uses a
/// simple monotonic address counter to simulate `find_free_region` and
/// `vm_mmap`.
#[cfg(test)]
pub struct VmMockBackend {
    pub walks: Vec<(alloc::string::String, Fid)>,
    pub opens: Vec<(Fid, OpenMode)>,
    pub writes: Vec<(Fid, Vec<u8>)>,
    pub reads: Vec<(Fid, u64, u32)>,
    pub clunks: Vec<Fid>,
    pub stats: Vec<Fid>,
    /// Recorded vm_mmap calls: (vaddr, len, flags, classification).
    pub vm_mmaps: Vec<(u64, usize, PageFlags, FrameClassification)>,
    /// Recorded vm_munmap calls: (vaddr, len).
    pub vm_munmaps: Vec<(u64, usize)>,
    /// Recorded vm_mprotect calls: (vaddr, len, flags).
    pub vm_mprotects: Vec<(u64, usize, PageFlags)>,
    /// Recorded vm_write_bytes calls: (addr, data).
    pub vm_writes: Vec<(u64, Vec<u8>)>,
    /// Next virtual address to hand out from find_free_region.
    next_vaddr: u64,
    /// Per-page budget remaining. When 0, vm_mmap returns BudgetExceeded.
    budget_pages: usize,
    /// File content keyed by fid.
    file_content: BTreeMap<Fid, Vec<u8>>,
}

#[cfg(test)]
impl VmMockBackend {
    pub fn new(budget_pages: usize) -> Self {
        Self {
            walks: Vec::new(),
            opens: Vec::new(),
            writes: Vec::new(),
            reads: Vec::new(),
            clunks: Vec::new(),
            stats: Vec::new(),
            vm_mmaps: Vec::new(),
            vm_munmaps: Vec::new(),
            vm_mprotects: Vec::new(),
            vm_writes: Vec::new(),
            next_vaddr: 0x1_0000, // start above null guard
            budget_pages,
            file_content: BTreeMap::new(),
        }
    }

    /// Register file content for a fid.
    pub fn set_file_content(&mut self, fid: Fid, content: Vec<u8>) {
        self.file_content.insert(fid, content);
    }
}

#[cfg(test)]
impl SyscallBackend for MockBackend {
    fn walk(&mut self, path: &str, new_fid: Fid) -> Result<QPath, IpcError> {
        self.walks
            .push((alloc::string::String::from(path), new_fid));
        if self.directory_paths.contains(path) {
            self.directory_fids.insert(new_fid);
        }
        Ok(0)
    }

    fn open(&mut self, fid: Fid, mode: OpenMode) -> Result<(), IpcError> {
        self.opens.push((fid, mode));
        Ok(())
    }

    fn read(&mut self, fid: Fid, offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        self.reads.push((fid, offset, count));
        // Return file content if registered for this fid.
        if let Some(content) = self.file_content.get(&fid) {
            let start = (offset as usize).min(content.len());
            let end = (start + count as usize).min(content.len());
            Ok(content[start..end].to_vec())
        } else {
            Ok(Vec::new())
        }
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

    fn readdir(&mut self, fid: Fid) -> Result<Vec<DirEntry>, IpcError> {
        self.readdir_entries
            .get(&fid)
            .cloned()
            .ok_or(IpcError::NotDirectory)
    }
}

#[cfg(test)]
impl SyscallBackend for VmMockBackend {
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
        if let Some(content) = self.file_content.get(&fid) {
            let start = (offset as usize).min(content.len());
            let end = (start + count as usize).min(content.len());
            Ok(content[start..end].to_vec())
        } else {
            Ok(Vec::new())
        }
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

    fn has_vm_support(&self) -> bool {
        true
    }

    fn vm_mmap(
        &mut self,
        vaddr: u64,
        len: usize,
        flags: PageFlags,
        classification: FrameClassification,
    ) -> Result<u64, VmError> {
        let aligned_len = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let pages = aligned_len / PAGE_SIZE;
        if pages > self.budget_pages {
            return Err(VmError::BudgetExceeded {
                limit: (self.budget_pages * PAGE_SIZE) as u64,
                used: 0,
                requested: len as u64,
            });
        }
        self.budget_pages -= pages;
        self.vm_mmaps
            .push((vaddr, aligned_len, flags, classification));
        // Advance next_vaddr past this mapping.
        let end = vaddr + aligned_len as u64;
        if end > self.next_vaddr {
            self.next_vaddr = end;
        }
        Ok(vaddr)
    }

    fn vm_munmap(&mut self, vaddr: u64, len: usize) -> Result<(), VmError> {
        let pages = len.div_ceil(PAGE_SIZE);
        self.budget_pages += pages;
        self.vm_munmaps.push((vaddr, len));
        Ok(())
    }

    fn vm_mprotect(&mut self, vaddr: u64, len: usize, flags: PageFlags) -> Result<(), VmError> {
        self.vm_mprotects.push((vaddr, len, flags));
        Ok(())
    }

    fn vm_find_free_region(&self, len: usize) -> Result<u64, VmError> {
        let aligned_len = ((len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)) as u64;
        let pages = aligned_len as usize / PAGE_SIZE;
        if pages > self.budget_pages {
            return Err(VmError::OutOfMemory);
        }
        Ok(self.next_vaddr)
    }

    fn vm_write_bytes(&mut self, addr: u64, data: &[u8]) {
        // Record but do NOT dereference — addresses are simulated.
        self.vm_writes.push((addr, data.to_vec()));
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
    alloc::string::String::from(core::str::from_utf8_unchecked(core::slice::from_raw_parts(
        p, len,
    )))
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

/// Write a Linux `struct stat` to process memory using the correct
/// layout for the current architecture.
///
/// x86_64 layout (144 bytes):
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
///
/// aarch64 layout (128 bytes, asm-generic):
///   offset  size  field
///   0       8     st_dev
///   8       8     st_ino
///   16      4     st_mode
///   20      4     st_nlink
///   24      4     st_uid
///   28      4     st_gid
///   32      8     st_rdev
///   40      8     __pad1
///   48      8     st_size
///   56      4     st_blksize
///   60      4     __pad2
///   64      8     st_blocks
///   72-128        timestamps (zeroed for MVP)
fn write_linux_stat(buf_ptr: usize, stat: &FileStat, is_chardev: bool) {
    let mode: u32 = if is_chardev {
        0o020000 | 0o666 // S_IFCHR | rw-rw-rw-
    } else {
        match stat.file_type {
            FileType::Regular => 0o100000 | 0o644,   // S_IFREG | rw-r--r--
            FileType::Directory => 0o040000 | 0o755, // S_IFDIR | rwxr-xr-x
        }
    };

    #[cfg(target_arch = "x86_64")]
    {
        let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, 144) };
        buf.fill(0);
        buf[8..16].copy_from_slice(&stat.qpath.to_le_bytes()); // st_ino
        buf[16..24].copy_from_slice(&1u64.to_le_bytes()); // st_nlink
        buf[24..28].copy_from_slice(&mode.to_le_bytes()); // st_mode
        buf[48..56].copy_from_slice(&stat.size.to_le_bytes()); // st_size
        buf[56..64].copy_from_slice(&4096u64.to_le_bytes()); // st_blksize
        let blocks = stat.size.div_ceil(512);
        buf[64..72].copy_from_slice(&blocks.to_le_bytes()); // st_blocks
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        // aarch64 and other targets use the asm-generic stat layout (128 bytes)
        let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, 128) };
        buf.fill(0);
        buf[8..16].copy_from_slice(&stat.qpath.to_le_bytes()); // st_ino
        buf[16..20].copy_from_slice(&mode.to_le_bytes()); // st_mode (u32)
        buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // st_nlink (u32)
        buf[48..56].copy_from_slice(&stat.size.to_le_bytes()); // st_size
        buf[56..60].copy_from_slice(&4096u32.to_le_bytes()); // st_blksize (u32)
        let blocks = stat.size.div_ceil(512);
        buf[64..72].copy_from_slice(&blocks.to_le_bytes()); // st_blocks
    }
}

// ── Linux PROT_* constants ───────────────────────────────────────────

const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;
const PROT_EXEC: i32 = 0x4;

/// Translate Linux PROT_* flags to `PageFlags`.
fn prot_to_page_flags(prot: i32) -> PageFlags {
    let mut flags = PageFlags::USER;
    if prot & PROT_READ != 0 {
        flags |= PageFlags::READABLE;
    }
    if prot & PROT_WRITE != 0 {
        flags |= PageFlags::WRITABLE;
    }
    if prot & PROT_EXEC != 0 {
        flags |= PageFlags::EXECUTABLE;
    }
    flags
}

// ── Linuxulator ─────────────────────────────────────────────────────

/// Per-fd state: the 9P fid and the current file offset.
#[derive(Clone)]
struct FdEntry {
    fid: Fid,
    offset: u64,
    path: Option<alloc::string::String>,
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
    /// Memory arena for brk/mmap (fallback when backend has no VM support).
    arena: MemoryArena,
    /// FS segment base register (TLS pointer for arch_prctl).
    fs_base: u64,
    /// Fids that represent character devices (stdio).
    /// Used by fstat to report S_IFCHR instead of S_IFREG.
    chardev_fids: Vec<Fid>,
    /// VM-backed brk: base address of the heap (0 = not yet established).
    vm_brk_base: u64,
    /// VM-backed brk: current program break.
    vm_brk_current: u64,
    /// Call counter for getrandom — ensures repeated calls to the same
    /// buffer address produce distinct output.
    getrandom_counter: u64,
    /// Current working directory (absolute path).
    cwd: alloc::string::String,
    /// 9P fid for the cwd, if one has been walked.
    cwd_fid: Option<Fid>,
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
            vm_brk_base: 0,
            vm_brk_current: 0,
            getrandom_counter: 0,
            cwd: alloc::string::String::from("/"),
            cwd_fid: None,
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

    /// Mutable access to the fd table (test-only).
    #[cfg(test)]
    fn fd_table_mut(&mut self) -> &mut BTreeMap<i32, FdEntry> {
        &mut self.fd_table
    }

    /// Resolve a path relative to `self.cwd`.
    ///
    /// Absolute paths (starting with `/`) pass through unchanged.
    /// Relative paths get `self.cwd` prepended.
    /// Normalises `.` and `..` segments so `chdir("..")` produces the
    /// correct parent path rather than forwarding `/foo/..` verbatim.
    fn resolve_path(&self, path: &str) -> alloc::string::String {
        let base = if path.starts_with('/') {
            alloc::string::String::from(path)
        } else if self.cwd == "/" {
            alloc::format!("/{}", path)
        } else {
            alloc::format!("{}/{}", self.cwd, path)
        };

        // Normalise . and ..
        let mut parts: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
        for seg in base.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                s => parts.push(s),
            }
        }
        if parts.is_empty() {
            alloc::string::String::from("/")
        } else {
            alloc::format!("/{}", parts.join("/"))
        }
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
        self.fd_table.insert(
            0,
            FdEntry {
                fid: stdin_fid,
                offset: 0,
                path: None,
            },
        );

        // stdout (fd 1) — write mode
        let stdout_fid = self.alloc_fid();
        self.backend.walk("/dev/serial/log", stdout_fid)?;
        self.backend.open(stdout_fid, OpenMode::Write)?;
        self.fd_table.insert(
            1,
            FdEntry {
                fid: stdout_fid,
                offset: 0,
                path: None,
            },
        );

        // stderr (fd 2) — write mode
        let stderr_fid = self.alloc_fid();
        self.backend.walk("/dev/serial/log", stderr_fid)?;
        self.backend.open(stderr_fid, OpenMode::Write)?;
        self.fd_table.insert(
            2,
            FdEntry {
                fid: stderr_fid,
                offset: 0,
                path: None,
            },
        );

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

    /// Handle a syscall identified by x86_64 syscall number.
    ///
    /// This is the original entry point. It maps the raw number to a
    /// `LinuxSyscall` and delegates to `dispatch_syscall`.
    pub fn handle_syscall(&mut self, nr: u64, args: [u64; 6]) -> i64 {
        let syscall = LinuxSyscall::from_x86_64(nr, args);
        self.dispatch_syscall(syscall)
    }

    /// Dispatch a CPU-agnostic `LinuxSyscall` to the appropriate handler.
    ///
    /// This is the architecture-independent entry point. Both `handle_syscall`
    /// (x86_64) and the aarch64 SVC handler call this method.
    ///
    /// # Safety
    /// For syscalls that take pointer arguments (Write, Read, Openat, Fstat,
    /// Prlimit64), the pointer values in the enum are treated as raw pointers
    /// to process memory. In the MVP flat address space, this is a direct
    /// dereference.
    pub fn dispatch_syscall(&mut self, syscall: LinuxSyscall) -> i64 {
        match syscall {
            LinuxSyscall::Read { fd, buf, count } => {
                self.sys_read(fd, buf as usize, count as usize)
            }
            LinuxSyscall::Write { fd, buf, count } => {
                self.sys_write(fd, buf as usize, count as usize)
            }
            LinuxSyscall::Close { fd } => self.sys_close(fd),
            LinuxSyscall::Fstat { fd, buf } => self.sys_fstat(fd, buf as usize),
            LinuxSyscall::Mmap {
                addr,
                len,
                prot,
                flags,
                fd,
                offset,
            } => self.sys_mmap(addr, len, prot, flags, fd, offset),
            LinuxSyscall::Mprotect { addr, len, prot } => self.sys_mprotect(addr, len, prot),
            LinuxSyscall::Munmap { addr, len } => self.sys_munmap(addr, len),
            LinuxSyscall::Brk { addr } => self.sys_brk(addr),
            LinuxSyscall::RtSigaction => self.sys_rt_sigaction(),
            LinuxSyscall::RtSigprocmask => self.sys_rt_sigprocmask(),
            LinuxSyscall::Ioctl { fd, request } => self.sys_ioctl(fd, request),
            LinuxSyscall::Exit { code } => self.sys_exit(code),
            #[cfg(target_arch = "x86_64")]
            LinuxSyscall::ArchPrctl { code, addr } => self.sys_arch_prctl(code, addr),
            #[cfg(not(target_arch = "x86_64"))]
            LinuxSyscall::ArchPrctl { .. } => ENOSYS,
            LinuxSyscall::SetTidAddress => self.sys_set_tid_address(),
            LinuxSyscall::ExitGroup { code } => self.sys_exit_group(code),
            LinuxSyscall::Openat {
                dirfd,
                pathname,
                flags,
            } => self.sys_openat(dirfd, pathname as usize, flags),
            LinuxSyscall::SetRobustList => self.sys_set_robust_list(),
            LinuxSyscall::Prlimit64 {
                pid,
                resource,
                new_limit,
                old_limit_buf,
            } => self.sys_prlimit64(pid, resource, new_limit, old_limit_buf as usize),
            LinuxSyscall::Rseq => ENOSYS,
            LinuxSyscall::Writev { fd, iov, iovcnt } => self.sys_writev(fd, iov as usize, iovcnt),
            LinuxSyscall::Lseek { fd, offset, whence } => self.sys_lseek(fd, offset, whence),
            LinuxSyscall::Getrandom { buf, buflen, flags } => {
                self.sys_getrandom(buf as usize, buflen as usize, flags)
            }
            LinuxSyscall::Getcwd { buf, size } => self.sys_getcwd(buf as usize, size as usize),
            LinuxSyscall::Readlink {
                pathname,
                buf,
                bufsiz,
            } => self.sys_readlink(pathname, buf, bufsiz),
            LinuxSyscall::Newfstatat {
                dirfd,
                pathname,
                statbuf,
                flags,
            } => self.sys_newfstatat(dirfd, pathname as usize, statbuf as usize, flags),
            LinuxSyscall::Faccessat {
                dirfd,
                pathname,
                mode,
            } => self.sys_faccessat(dirfd, pathname as usize, mode),
            LinuxSyscall::Getdents64 { fd, dirp, count } => {
                self.sys_getdents64(fd, dirp as usize, count as usize)
            }
            LinuxSyscall::Chdir { pathname } => self.sys_chdir(pathname as usize),
            LinuxSyscall::Fchdir { fd } => self.sys_fchdir(fd),
            LinuxSyscall::Mkdirat { .. } => self.sys_mkdirat(),
            LinuxSyscall::Unlinkat { .. } => self.sys_unlinkat(),
            LinuxSyscall::Unknown { .. } => ENOSYS,
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

        let (fid, file_offset) = match self.fd_table.get(&fd) {
            Some(e) => (e.fid, e.offset),
            None => return EBADF,
        };

        // 9P count is u32; cap to avoid silent truncation on large reads.
        let capped = count.min(u32::MAX as usize) as u32;

        match self.backend.read(fid, file_offset, capped) {
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
            return EFAULT;
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
        if pathname_ptr == 0 {
            return EFAULT;
        }
        let raw_path = unsafe { read_c_string(pathname_ptr) };
        if raw_path.is_empty() {
            return ENOENT;
        }

        const AT_FDCWD: i32 = -100;
        if dirfd != AT_FDCWD && !self.fd_table.contains_key(&dirfd) {
            return EBADF;
        }

        let path = if dirfd == AT_FDCWD || raw_path.starts_with('/') {
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
        self.fd_table.insert(
            fd,
            FdEntry {
                fid,
                offset: 0,
                path: Some(path),
            },
        );
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
    /// When the backend supports VM operations, brk allocates real frames
    /// via the VM layer. Otherwise falls back to the MemoryArena.
    ///
    /// `addr == 0` probes the current break. Otherwise sets it to the
    /// requested address (page-aligned up). Returns the new break, or
    /// the current break unchanged if the request is invalid.
    fn sys_brk(&mut self, addr: u64) -> i64 {
        if self.backend.has_vm_support() {
            return self.sys_brk_vm(addr);
        }
        self.sys_brk_arena(addr)
    }

    /// Arena-based brk (original implementation).
    fn sys_brk_arena(&mut self, addr: u64) -> i64 {
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

    /// VM-backed brk: allocates real frames through the backend.
    ///
    /// The heap starts at `vm_brk_base` and grows upward. On first call
    /// (addr == 0), returns the current brk. On subsequent calls, maps
    /// new pages for any growth and unmaps pages for shrinkage.
    fn sys_brk_vm(&mut self, addr: u64) -> i64 {
        // First call: establish the brk base if not yet set.
        if self.vm_brk_base == 0 {
            // Pick a base address for the heap.
            match self.backend.vm_find_free_region(PAGE_SIZE) {
                Ok(base) => {
                    self.vm_brk_base = base;
                    self.vm_brk_current = base;
                }
                Err(_) => return ENOMEM,
            }
        }

        if addr == 0 {
            return self.vm_brk_current as i64;
        }

        if addr < self.vm_brk_base {
            return self.vm_brk_current as i64;
        }

        // Page-align the requested address upward.
        let new_brk = (addr + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);

        if new_brk > self.vm_brk_current {
            // Growing: map new pages.
            let grow_len = (new_brk - self.vm_brk_current) as usize;
            let flags = PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::USER;
            match self.backend.vm_mmap(
                self.vm_brk_current,
                grow_len,
                flags,
                FrameClassification::empty(),
            ) {
                Ok(_) => {
                    self.vm_brk_current = new_brk;
                }
                Err(_) => return self.vm_brk_current as i64, // Linux returns old brk on failure
            }
        } else if new_brk < self.vm_brk_current {
            // Shrinking: unmap pages.
            let shrink_len = (self.vm_brk_current - new_brk) as usize;
            let _ = self.backend.vm_munmap(new_brk, shrink_len);
            self.vm_brk_current = new_brk;
        }

        self.vm_brk_current as i64
    }

    /// Linux mmap(2): map memory (anonymous or file-backed).
    ///
    /// When the backend supports VM operations, delegates to the VM layer.
    /// Otherwise uses the MemoryArena allocator.
    ///
    /// Supports both `MAP_ANONYMOUS` (zeroed pages) and file-backed mappings
    /// (reads file content from the backend via the fd table). Returns the
    /// mapped address or a negative errno.
    fn sys_mmap(
        &mut self,
        addr: u64,
        length: u64,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: u64,
    ) -> i64 {
        const MAP_ANONYMOUS: i32 = 0x20;
        const MAP_FIXED: i32 = 0x10;

        if length == 0 {
            return EINVAL;
        }

        // W^X enforcement: reject simultaneous write+execute.
        if prot & PROT_WRITE != 0 && prot & PROT_EXEC != 0 {
            return EINVAL;
        }

        // NOTE: Linux requires page-aligned mmap offsets because it maps
        // file pages directly from the page cache.  Our emulator reads
        // bytes via 9P and copies them, so sub-page offsets work correctly.
        // No alignment check here — callers (including the ELF loader)
        // may pass arbitrary file offsets.

        let is_anonymous = flags & MAP_ANONYMOUS != 0;

        // For file-backed mappings, validate the fd up front.
        let file_fid = if !is_anonymous {
            match self.fd_table.get(&fd) {
                Some(entry) => Some(entry.fid),
                None => return EBADF,
            }
        } else {
            None
        };

        if self.backend.has_vm_support() {
            if let Some(fid) = file_fid {
                // File-backed: map writable (without execute) so we can
                // copy data in, then mprotect to the caller's requested
                // permissions.  This avoids a transient W+X window.
                let write_prot = (prot | PROT_READ | PROT_WRITE) & !PROT_EXEC;
                let mapped = self.sys_mmap_vm(addr, length, write_prot, flags);
                if mapped < 0 {
                    return mapped;
                }
                let len = match (length as usize).checked_add(PAGE_SIZE - 1) {
                    Some(v) => v & !(PAGE_SIZE - 1),
                    None => return EINVAL,
                };
                // 9P read count is u32 — cap to avoid truncation.
                // Mappings > 4 GiB are not expected in practice (musl
                // .so files are a few MiB at most).
                let capped = len.min(u32::MAX as usize) as u32;
                match self.backend.read(fid, offset, capped) {
                    Ok(data) => {
                        let copy_len = data.len().min(len);
                        if copy_len > 0 {
                            self.backend
                                .vm_write_bytes(mapped as u64, &data[..copy_len]);
                        }
                        // Zero any tail bytes beyond file data (vm_mmap
                        // does not guarantee zeroed pages).  Write in
                        // page-sized chunks to bound transient allocation.
                        let tail = len - copy_len;
                        if tail > 0 {
                            let chunk = alloc::vec![0u8; PAGE_SIZE.min(tail)];
                            let mut written = 0usize;
                            while written < tail {
                                let n = chunk.len().min(tail - written);
                                self.backend.vm_write_bytes(
                                    mapped as u64 + (copy_len + written) as u64,
                                    &chunk[..n],
                                );
                                written += n;
                            }
                        }
                    }
                    Err(e) => {
                        let _ = self.backend.vm_munmap(mapped as u64, len);
                        return ipc_err_to_errno(e);
                    }
                }
                // Restore the caller's requested permissions.
                if write_prot != prot {
                    let page_flags = prot_to_page_flags(prot);
                    if let Err(e) = self.backend.vm_mprotect(mapped as u64, len, page_flags) {
                        let _ = self.backend.vm_munmap(mapped as u64, len);
                        return vm_err_to_errno(e);
                    }
                }
                return mapped;
            } else {
                // Anonymous: allocate with requested permissions directly.
                return self.sys_mmap_vm(addr, length, prot, flags);
            }
        }

        // Arena fallback path.
        if flags & MAP_FIXED != 0 {
            return ENOMEM; // arena allocator cannot place at fixed address
        }
        let _ = addr; // hint addr is intentionally unused (no MAP_FIXED support)
        let len = match (length as usize).checked_add(PAGE_SIZE - 1) {
            Some(v) => v & !(PAGE_SIZE - 1),
            None => return EINVAL,
        };
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

        // For file-backed arena mappings, read file content into the region.
        if let Some(fid) = file_fid {
            let capped = len.min(u32::MAX as usize) as u32;
            match self.backend.read(fid, offset, capped) {
                Ok(data) => {
                    let copy_len = data.len().min(len);
                    if copy_len > 0 {
                        unsafe {
                            core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, copy_len);
                        }
                    }
                }
                Err(e) => {
                    // Reclaim the arena allocation and return the error.
                    self.arena.mmap_top += len;
                    self.arena.mmap_regions.pop();
                    return ipc_err_to_errno(e);
                }
            }
        }

        ptr as i64
    }

    /// VM-backed mmap: allocates through the backend's VM layer.
    fn sys_mmap_vm(&mut self, addr: u64, length: u64, prot: i32, flags: i32) -> i64 {
        const MAP_FIXED: i32 = 0x10;

        let len = match (length as usize).checked_add(PAGE_SIZE - 1) {
            Some(v) => v & !(PAGE_SIZE - 1),
            None => return EINVAL,
        };
        let page_flags = prot_to_page_flags(prot);

        let vaddr = if flags & MAP_FIXED != 0 {
            // MAP_FIXED: use the exact address.
            if addr & (PAGE_SIZE as u64 - 1) != 0 {
                return EINVAL; // must be page-aligned
            }
            addr
        } else {
            // Non-fixed: find a free region.
            match self.backend.vm_find_free_region(len) {
                Ok(va) => va,
                Err(e) => return vm_err_to_errno(e),
            }
        };

        match self
            .backend
            .vm_mmap(vaddr, len, page_flags, FrameClassification::empty())
        {
            Ok(mapped_addr) => mapped_addr as i64,
            Err(e) => vm_err_to_errno(e),
        }
    }

    /// Linux munmap(2): unmap memory.
    ///
    /// When the backend supports VM, delegates to vm_munmap. Otherwise
    /// returns success (arena stub).
    fn sys_munmap(&mut self, addr: u64, length: u64) -> i64 {
        if self.backend.has_vm_support() {
            if length == 0 {
                return EINVAL;
            }
            let len = ((length as usize) + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            match self.backend.vm_munmap(addr, len) {
                Ok(()) => 0,
                Err(e) => vm_err_to_errno(e),
            }
        } else {
            0 // arena stub: always succeeds
        }
    }

    /// Linux mprotect(2): change protection on a memory region.
    ///
    /// Translates PROT_* flags to PageFlags and delegates to the backend.
    /// Returns 0 on success or a negative errno.
    fn sys_mprotect(&mut self, addr: u64, length: u64, prot: i32) -> i64 {
        if !self.backend.has_vm_support() {
            return 0; // no-op when running with arena
        }
        if length == 0 {
            return EINVAL;
        }
        if addr & (PAGE_SIZE as u64 - 1) != 0 {
            return EINVAL; // must be page-aligned
        }
        // W^X enforcement: reject simultaneous write+execute.
        if prot & PROT_WRITE != 0 && prot & PROT_EXEC != 0 {
            return EINVAL;
        }
        let len = match (length as usize).checked_add(PAGE_SIZE - 1) {
            Some(v) => v & !(PAGE_SIZE - 1),
            None => return EINVAL,
        };
        let page_flags = prot_to_page_flags(prot);
        match self.backend.vm_mprotect(addr, len, page_flags) {
            Ok(()) => 0,
            Err(e) => vm_err_to_errno(e),
        }
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
                    core::ptr::write_unaligned((old_limit_ptr + 8) as *mut u64, eight_mb);
                    // rlim_max
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

    /// Linux writev(2): write from multiple buffers (scatter-gather).
    ///
    /// Iterates `iovcnt` iovec structs at `iov_ptr`. Each iovec is 16 bytes:
    /// `iov_base: u64` + `iov_len: u64`. Calls `sys_write` for each buffer
    /// and returns the total bytes written.
    fn sys_writev(&mut self, fd: i32, iov_ptr: usize, iovcnt: i32) -> i64 {
        const IOV_MAX: i32 = 1024;
        if iovcnt == 0 {
            return 0; // Linux permits zero iovcnt.
        }
        if !(1..=IOV_MAX).contains(&iovcnt) {
            return EINVAL;
        }
        if !self.fd_table.contains_key(&fd) {
            return EBADF;
        }

        let mut total: i64 = 0;
        for i in 0..iovcnt as usize {
            let iov_addr = iov_ptr + i * 16;
            // Each iovec is { iov_base: *void, iov_len: size_t } — 16 bytes on 64-bit.
            let base = unsafe { core::ptr::read_unaligned(iov_addr as *const u64) } as usize;
            let len = unsafe { core::ptr::read_unaligned((iov_addr + 8) as *const u64) } as usize;

            if len == 0 {
                continue;
            }
            let result = self.sys_write(fd, base, len);
            if result < 0 {
                // If we haven't written anything yet, return the error.
                // Otherwise return what we've written so far (POSIX partial write).
                return if total == 0 { result } else { total };
            }
            total = total.saturating_add(result);
        }
        total
    }

    /// Linux lseek(2): reposition file offset.
    ///
    /// - SEEK_SET (0): set offset to `offset`
    /// - SEEK_CUR (1): set offset to current + `offset`
    /// - SEEK_END (2): set offset to file size + `offset`
    fn sys_lseek(&mut self, fd: i32, offset: i64, whence: i32) -> i64 {
        const SEEK_SET: i32 = 0;
        const SEEK_CUR: i32 = 1;
        const SEEK_END: i32 = 2;

        let (entry_fid, entry_offset) = match self.fd_table.get(&fd) {
            Some(e) => (e.fid, e.offset),
            None => return EBADF,
        };

        // Character devices (stdin/stdout/stderr) are not seekable.
        if self.chardev_fids.contains(&entry_fid) {
            return ESPIPE;
        }

        let new_offset = match whence {
            SEEK_SET => offset,
            SEEK_CUR => match (entry_offset as i64).checked_add(offset) {
                Some(v) => v,
                None => return EOVERFLOW,
            },
            SEEK_END => {
                let stat = match self.backend.stat(entry_fid) {
                    Ok(s) => s,
                    Err(e) => return ipc_err_to_errno(e),
                };
                // Guard against files larger than i64::MAX — the
                // `as i64` cast would wrap to negative.
                if stat.size > i64::MAX as u64 {
                    return EOVERFLOW;
                }
                match (stat.size as i64).checked_add(offset) {
                    Some(v) => v,
                    None => return EOVERFLOW,
                }
            }
            _ => return EINVAL,
        };

        if new_offset < 0 {
            return EINVAL;
        }

        self.fd_table.get_mut(&fd).unwrap().offset = new_offset as u64;
        new_offset
    }

    /// Linux getrandom(2): fill buffer with pseudo-random bytes.
    ///
    /// Uses a deterministic LCG seeded from the buffer address and a
    /// monotonic call counter so that repeated calls to the same address
    /// produce distinct output.  This is sufficient for ld-musl stack
    /// canaries and ASLR seeds in the Linuxulator environment (no real
    /// security boundary).
    fn sys_getrandom(&mut self, buf_ptr: usize, buflen: usize, _flags: u32) -> i64 {
        if buflen == 0 {
            return 0;
        }
        if buf_ptr == 0 {
            return EFAULT;
        }
        // Linux caps getrandom at 33554431 bytes (~32 MiB).  Guard
        // against `buflen as i64` wrapping to a negative error code.
        const GETRANDOM_MAX: usize = 33_554_431;
        if buflen > GETRANDOM_MAX {
            return EINVAL;
        }
        let counter = self.getrandom_counter;
        self.getrandom_counter = counter.wrapping_add(1);
        // Seed from address + counter, then iterate the LCG so each
        // byte depends on the previous state (not an independent seed
        // differing by 1, which would produce near-linear output).
        let mut state = (buf_ptr as u64)
            .wrapping_add(counter)
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        // Generate and write in page-sized chunks to bound transient
        // allocation (buflen can be up to ~32 MiB).
        const CHUNK: usize = 4096;
        let mut written = 0usize;
        while written < buflen {
            let n = CHUNK.min(buflen - written);
            let mut chunk = [0u8; CHUNK];
            for byte in chunk[..n].iter_mut() {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *byte = (state >> 33) as u8;
            }
            self.backend
                .vm_write_bytes(buf_ptr as u64 + written as u64, &chunk[..n]);
            written += n;
        }
        buflen as i64
    }

    /// Linux newfstatat(2): stat a file by path or fd.
    ///
    /// Supports AT_FDCWD + absolute/relative paths, and AT_EMPTY_PATH
    /// (stat an open fd, like fstat).
    fn sys_newfstatat(
        &mut self,
        dirfd: i32,
        pathname_ptr: usize,
        statbuf_ptr: usize,
        flags: i32,
    ) -> i64 {
        if statbuf_ptr == 0 {
            return EFAULT;
        }
        const AT_FDCWD: i32 = -100;
        const AT_EMPTY_PATH: i32 = 0x1000;

        if pathname_ptr == 0 {
            // AT_EMPTY_PATH with NULL pathname is valid (stat the fd)
            if flags & AT_EMPTY_PATH != 0 {
                return self.sys_fstat(dirfd, statbuf_ptr);
            }
            return EFAULT;
        }
        let path = unsafe { read_c_string(pathname_ptr) };

        // AT_EMPTY_PATH only triggers fd-stat when pathname is actually empty.
        // Non-empty pathname is resolved normally even with the flag set.
        if path.is_empty() {
            if flags & AT_EMPTY_PATH != 0 {
                return self.sys_fstat(dirfd, statbuf_ptr);
            }
            return ENOENT;
        }

        if dirfd != AT_FDCWD && !self.fd_table.contains_key(&dirfd) {
            return EBADF;
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

    /// Linux faccessat(2): check file accessibility.
    ///
    /// Walks the path and stats to check existence. Permission bits always
    /// pass (single-user, no capability enforcement yet).
    fn sys_faccessat(&mut self, dirfd: i32, pathname_ptr: usize, _mode: i32) -> i64 {
        if pathname_ptr == 0 {
            return EFAULT;
        }
        const AT_FDCWD: i32 = -100;
        let path = unsafe { read_c_string(pathname_ptr) };
        if path.is_empty() {
            return ENOENT;
        }

        if dirfd != AT_FDCWD && !self.fd_table.contains_key(&dirfd) {
            return EBADF;
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
        // File exists — clunk and return success.
        let _ = self.backend.clunk(fid);
        0
    }

    /// Linux getdents64(2): read directory entries.
    ///
    /// Calls `backend.readdir(fid)` to get all entries, then packs
    /// `linux_dirent64` structs into the user buffer starting from
    /// the entry index stored in `FdEntry.offset`.
    fn sys_getdents64(&mut self, fd: i32, dirp: usize, count: usize) -> i64 {
        if dirp == 0 {
            return EFAULT;
        }
        let entry = match self.fd_table.get(&fd) {
            Some(e) => e.clone(),
            None => return EBADF,
        };
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

            // Pack the entry into the buffer.
            let base = dirp + bytes_written;
            let mut rec = vec![0u8; reclen];
            let d_ino = (idx + 1) as u64; // non-zero placeholder; 0 means "deleted"
            rec[0..8].copy_from_slice(&d_ino.to_le_bytes()); // d_ino
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

        // Update the offset to track position.
        if let Some(entry) = self.fd_table.get_mut(&fd) {
            entry.offset = idx as u64;
        }

        bytes_written as i64
    }

    /// Linux chdir(2): change working directory.
    ///
    /// Walks the path, verifies it's a directory via stat, then
    /// updates `self.cwd`. Clunks the old cwd fid if set.
    fn sys_chdir(&mut self, pathname_ptr: usize) -> i64 {
        if pathname_ptr == 0 {
            return EFAULT;
        }
        let path = unsafe { read_c_string(pathname_ptr) };
        if path.is_empty() {
            return ENOENT;
        }
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

    /// Linux fchdir(2): change working directory to an open fd.
    fn sys_fchdir(&mut self, fd: i32) -> i64 {
        let entry = match self.fd_table.get(&fd) {
            Some(e) => e.clone(),
            None => return EBADF,
        };

        // Verify it's a directory before checking path — a valid non-directory
        // fd (e.g. stdio) should return ENOTDIR, not EBADF.
        match self.backend.stat(entry.fid) {
            Ok(stat) if stat.file_type == FileType::Directory => {}
            Ok(_) => return ENOTDIR,
            Err(e) => return ipc_err_to_errno(e),
        }

        let path = match &entry.path {
            Some(p) => p.clone(),
            // fd is confirmed directory but has no tracked path — implementation
            // limitation (all current directory fds have paths, so this is
            // effectively unreachable).
            None => return ENOSYS,
        };

        // Walk a new fid for cwd (the fd's fid stays with the fd table)
        let cwd_fid = self.alloc_fid();
        if let Err(e) = self.backend.walk(&path, cwd_fid) {
            let _ = self.backend.clunk(cwd_fid);
            return ipc_err_to_errno(e);
        }

        if let Some(old_fid) = self.cwd_fid {
            let _ = self.backend.clunk(old_fid);
        }

        self.cwd = path;
        self.cwd_fid = Some(cwd_fid);
        0
    }

    /// Linux mkdirat(2): create a directory relative to a directory fd.
    ///
    /// Returns EROFS — the Linuxulator filesystem is read-only.
    fn sys_mkdirat(&mut self) -> i64 {
        EROFS
    }

    /// Linux unlinkat(2): remove a file relative to a directory fd.
    ///
    /// Returns EROFS — the Linuxulator filesystem is read-only.
    fn sys_unlinkat(&mut self) -> i64 {
        EROFS
    }

    /// Linux getcwd(2): get current working directory.
    ///
    /// Returns the tracked current working directory path.
    /// The raw syscall returns the number of bytes written (including
    /// the null terminator), not the buffer pointer.  Musl calls the
    /// raw syscall and interprets the return value as a byte count.
    fn sys_getcwd(&mut self, buf_ptr: usize, size: usize) -> i64 {
        if buf_ptr == 0 {
            return EFAULT;
        }
        let cwd_bytes = self.cwd.as_bytes();
        let needed = cwd_bytes.len() + 1; // +1 for NUL terminator
        if size < needed {
            return ERANGE;
        }
        let mut out = Vec::with_capacity(needed);
        out.extend_from_slice(cwd_bytes);
        out.push(0);
        self.backend.vm_write_bytes(buf_ptr as u64, &out);
        needed as i64
    }

    /// Linux readlink(2): read the value of a symbolic link.
    ///
    /// Returns ENOSYS — no symlinks in the 9P namespace.
    /// Returning ENOSYS (rather than EINVAL) preserves the fallback
    /// behaviour that ld-musl relies on for /proc/self/exe and similar
    /// virtual paths: the runtime treats ENOSYS as "syscall not supported"
    /// and falls back gracefully, whereas EINVAL means "path is not a
    /// symlink" — a claim we cannot make without first walking the path.
    fn sys_readlink(&self, _pathname: u64, _buf: u64, _bufsiz: u64) -> i64 {
        ENOSYS
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

        // x86_64: 144 bytes, st_mode at offset 24
        // aarch64 (asm-generic): 128 bytes, st_mode at offset 16
        #[cfg(target_arch = "x86_64")]
        const STAT_SIZE: usize = 144;
        #[cfg(not(target_arch = "x86_64"))]
        const STAT_SIZE: usize = 128;
        #[cfg(target_arch = "x86_64")]
        const ST_MODE_OFFSET: usize = 24;
        #[cfg(not(target_arch = "x86_64"))]
        const ST_MODE_OFFSET: usize = 16;

        let mut statbuf = [0u8; STAT_SIZE];
        let result = lx.handle_syscall(5, [1, statbuf.as_mut_ptr() as u64, 0, 0, 0, 0]);
        assert_eq!(result, 0);

        // st_mode should be S_IFCHR | 0o666 for stdio
        let o = ST_MODE_OFFSET;
        let st_mode =
            u32::from_le_bytes([statbuf[o], statbuf[o + 1], statbuf[o + 2], statbuf[o + 3]]);
        let s_ifchr: u32 = 0o020000;
        assert_eq!(st_mode & 0o170000, s_ifchr);
    }

    #[test]
    fn sys_fstat_bad_fd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        #[cfg(target_arch = "x86_64")]
        let mut statbuf = [0u8; 144];
        #[cfg(not(target_arch = "x86_64"))]
        let mut statbuf = [0u8; 128];
        let result = lx.handle_syscall(5, [99, statbuf.as_mut_ptr() as u64, 0, 0, 0, 0]);
        assert_eq!(result, EBADF);
    }

    #[test]
    fn sys_fstat_null_ptr_returns_efault() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();
        let result = lx.handle_syscall(5, [1, 0, 0, 0, 0, 0]);
        assert_eq!(result, EFAULT);
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
    #[cfg(target_arch = "x86_64")]
    fn sys_arch_prctl_set_fs_returns_zero() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // ARCH_SET_FS = 0x1002
        let result = lx.handle_syscall(158, [0x1002, 0x12345678, 0, 0, 0, 0]);
        assert_eq!(result, 0);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_arch_prctl_unknown_code_returns_einval() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.handle_syscall(158, [0x9999, 0, 0, 0, 0, 0]);
        assert_eq!(result, EINVAL);
    }

    // ── VM-backed mmap/munmap/mprotect/brk tests ─────────────────────

    #[test]
    fn vm_mmap_allocates_via_backend() {
        let mock = VmMockBackend::new(16); // 16 pages budget
        let mut lx = Linuxulator::new(mock);

        // mmap 4096 bytes: PROT_READ|PROT_WRITE (3), MAP_ANONYMOUS|MAP_PRIVATE (0x22)
        let addr = lx.handle_syscall(9, [0, 4096, 3, 0x22, u64::MAX, 0]);
        assert!(addr > 0, "vm mmap should return a positive address");
        assert_eq!(addr as u64 % 4096, 0, "address must be page-aligned");

        // Backend should have recorded the mmap.
        assert_eq!(lx.backend().vm_mmaps.len(), 1);
        let (vaddr, len, flags, _class) = &lx.backend().vm_mmaps[0];
        assert_eq!(*len, 4096);
        assert!(flags.contains(PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::USER));
        assert_eq!(*vaddr, addr as u64);
    }

    #[test]
    fn vm_munmap_calls_backend() {
        let mock = VmMockBackend::new(16);
        let mut lx = Linuxulator::new(mock);

        let addr = lx.handle_syscall(9, [0, 4096, 3, 0x22, u64::MAX, 0]);
        assert!(addr > 0);

        let result = lx.handle_syscall(11, [addr as u64, 4096, 0, 0, 0, 0]);
        assert_eq!(result, 0);
        assert_eq!(lx.backend().vm_munmaps.len(), 1);
        assert_eq!(lx.backend().vm_munmaps[0], (addr as u64, 4096));
    }

    #[test]
    fn vm_mprotect_calls_backend() {
        let mock = VmMockBackend::new(16);
        let mut lx = Linuxulator::new(mock);

        let addr = lx.handle_syscall(9, [0, 4096, 1, 0x22, u64::MAX, 0]); // PROT_READ
        assert!(addr > 0);

        // mprotect to PROT_READ|PROT_WRITE
        let result = lx.handle_syscall(10, [addr as u64, 4096, 3, 0, 0, 0]);
        assert_eq!(result, 0);
        assert_eq!(lx.backend().vm_mprotects.len(), 1);
        let (vaddr, len, flags) = &lx.backend().vm_mprotects[0];
        assert_eq!(*vaddr, addr as u64);
        assert_eq!(*len, 4096);
        assert!(flags.contains(PageFlags::READABLE | PageFlags::WRITABLE));
    }

    #[test]
    fn vm_mmap_budget_exhaustion_returns_enomem() {
        let mock = VmMockBackend::new(2); // Only 2 pages budget
        let mut lx = Linuxulator::new(mock);

        // Request 16 pages — exceeds budget.
        let result = lx.handle_syscall(9, [0, 4096 * 16, 3, 0x22, u64::MAX, 0]);
        assert_eq!(result, ENOMEM);
    }

    #[test]
    fn vm_brk_expands_heap_via_backend() {
        let mock = VmMockBackend::new(16);
        let mut lx = Linuxulator::new(mock);

        // Probe initial brk.
        let base = lx.handle_syscall(12, [0, 0, 0, 0, 0, 0]);
        assert!(base > 0);

        // Expand by 8192.
        let new_brk = lx.handle_syscall(12, [base as u64 + 8192, 0, 0, 0, 0, 0]);
        assert_eq!(new_brk as u64, base as u64 + 8192);

        // Backend should have recorded a vm_mmap for the growth.
        assert_eq!(lx.backend().vm_mmaps.len(), 1);
        let (vaddr, len, _flags, _class) = &lx.backend().vm_mmaps[0];
        assert_eq!(*vaddr, base as u64);
        assert_eq!(*len, 8192);
    }

    #[test]
    fn vm_mprotect_unaligned_addr_returns_einval() {
        let mock = VmMockBackend::new(16);
        let mut lx = Linuxulator::new(mock);

        // Unaligned address
        let result = lx.handle_syscall(10, [0x1001, 4096, 3, 0, 0, 0]);
        assert_eq!(result, EINVAL);
    }

    #[test]
    fn vm_mprotect_zero_length_returns_einval() {
        let mock = VmMockBackend::new(16);
        let mut lx = Linuxulator::new(mock);

        let result = lx.handle_syscall(10, [0x1000, 0, 3, 0, 0, 0]);
        assert_eq!(result, EINVAL);
    }

    #[test]
    fn vm_mprotect_noop_without_vm_support() {
        let mock = MockBackend::new(); // No VM support
        let mut lx = Linuxulator::new(mock);

        // Should return 0 (no-op) even without VM support.
        let result = lx.handle_syscall(10, [0x1000, 4096, 3, 0, 0, 0]);
        assert_eq!(result, 0);
    }

    #[test]
    fn prot_to_page_flags_mapping() {
        use super::prot_to_page_flags;

        let flags = prot_to_page_flags(0x1); // PROT_READ
        assert!(flags.contains(PageFlags::READABLE));
        assert!(flags.contains(PageFlags::USER));
        assert!(!flags.contains(PageFlags::WRITABLE));
        assert!(!flags.contains(PageFlags::EXECUTABLE));

        let flags = prot_to_page_flags(0x3); // PROT_READ | PROT_WRITE
        assert!(flags.contains(PageFlags::READABLE | PageFlags::WRITABLE));

        let flags = prot_to_page_flags(0x7); // PROT_READ | PROT_WRITE | PROT_EXEC
        assert!(flags.contains(PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::EXECUTABLE));
    }

    #[test]
    fn from_x86_64_write() {
        let syscall = LinuxSyscall::from_x86_64(1, [1, 0x1000, 5, 0, 0, 0]);
        match syscall {
            LinuxSyscall::Write { fd, buf, count } => {
                assert_eq!(fd, 1);
                assert_eq!(buf, 0x1000);
                assert_eq!(count, 5);
            }
            other => panic!("expected Write, got {:?}", other),
        }
    }

    #[test]
    fn from_x86_64_read() {
        let syscall = LinuxSyscall::from_x86_64(0, [3, 0x2000, 128, 0, 0, 0]);
        match syscall {
            LinuxSyscall::Read { fd, buf, count } => {
                assert_eq!(fd, 3);
                assert_eq!(buf, 0x2000);
                assert_eq!(count, 128);
            }
            other => panic!("expected Read, got {:?}", other),
        }
    }

    #[test]
    fn from_x86_64_exit_group() {
        let syscall = LinuxSyscall::from_x86_64(231, [42, 0, 0, 0, 0, 0]);
        match syscall {
            LinuxSyscall::ExitGroup { code } => assert_eq!(code, 42),
            other => panic!("expected ExitGroup, got {:?}", other),
        }
    }

    #[test]
    fn from_x86_64_unknown() {
        let syscall = LinuxSyscall::from_x86_64(9999, [0; 6]);
        match syscall {
            LinuxSyscall::Unknown { nr } => assert_eq!(nr, 9999),
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn from_aarch64_write() {
        let syscall = LinuxSyscall::from_aarch64(64, [1, 0x1000, 5, 0, 0, 0]);
        match syscall {
            LinuxSyscall::Write { fd, buf, count } => {
                assert_eq!(fd, 1);
                assert_eq!(buf, 0x1000);
                assert_eq!(count, 5);
            }
            other => panic!("expected Write, got {:?}", other),
        }
    }

    #[test]
    fn from_aarch64_read() {
        let syscall = LinuxSyscall::from_aarch64(63, [3, 0x2000, 128, 0, 0, 0]);
        match syscall {
            LinuxSyscall::Read { fd, buf, count } => {
                assert_eq!(fd, 3);
                assert_eq!(buf, 0x2000);
                assert_eq!(count, 128);
            }
            other => panic!("expected Read, got {:?}", other),
        }
    }

    #[test]
    fn from_aarch64_exit_group() {
        let syscall = LinuxSyscall::from_aarch64(94, [42, 0, 0, 0, 0, 0]);
        match syscall {
            LinuxSyscall::ExitGroup { code } => assert_eq!(code, 42),
            other => panic!("expected ExitGroup, got {:?}", other),
        }
    }

    #[test]
    fn from_aarch64_mmap() {
        let syscall = LinuxSyscall::from_aarch64(222, [0x1000, 4096, 3, 0x22, (-1i64) as u64, 0]);
        match syscall {
            LinuxSyscall::Mmap {
                addr,
                len,
                prot,
                flags,
                fd,
                offset,
            } => {
                assert_eq!(addr, 0x1000);
                assert_eq!(len, 4096);
                assert_eq!(prot, 3);
                assert_eq!(flags, 0x22);
                assert_eq!(fd, -1);
                assert_eq!(offset, 0);
            }
            other => panic!("expected Mmap, got {:?}", other),
        }
    }

    #[test]
    fn from_aarch64_unknown() {
        let syscall = LinuxSyscall::from_aarch64(9999, [0; 6]);
        match syscall {
            LinuxSyscall::Unknown { nr } => assert_eq!(nr, 9999),
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn from_aarch64_arch_prctl_maps_to_unknown() {
        // arch_prctl is x86_64-specific; aarch64 has no equivalent
        let syscall = LinuxSyscall::from_aarch64(158, [0; 6]);
        assert!(matches!(syscall, LinuxSyscall::Unknown { nr: 158 }));
    }

    #[test]
    fn dispatch_write_via_enum() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        let msg = b"test";
        let result = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: 1,
            buf: msg.as_ptr() as u64,
            count: msg.len() as u64,
        });
        assert_eq!(result, msg.len() as i64);
    }

    // ── sys_writev tests ────────────────────────────────────────────

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_writev_single_iovec() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        let msg = b"Hello writev\n";
        // Build a single iovec: { iov_base: *msg, iov_len: 13 }
        let mut iov = [0u8; 16];
        iov[0..8].copy_from_slice(&(msg.as_ptr() as u64).to_le_bytes());
        iov[8..16].copy_from_slice(&(msg.len() as u64).to_le_bytes());

        // writev(stdout=1, iov, iovcnt=1)  — x86_64 nr=20
        let result = lx.handle_syscall(20, [1, iov.as_ptr() as u64, 1, 0, 0, 0]);
        assert_eq!(result, msg.len() as i64);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_writev_multiple_iovecs() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        let msg1 = b"Hello";
        let msg2 = b" world\n";
        // Build two iovecs (32 bytes total)
        let mut iovs = [0u8; 32];
        iovs[0..8].copy_from_slice(&(msg1.as_ptr() as u64).to_le_bytes());
        iovs[8..16].copy_from_slice(&(msg1.len() as u64).to_le_bytes());
        iovs[16..24].copy_from_slice(&(msg2.as_ptr() as u64).to_le_bytes());
        iovs[24..32].copy_from_slice(&(msg2.len() as u64).to_le_bytes());

        let result = lx.handle_syscall(20, [1, iovs.as_ptr() as u64, 2, 0, 0, 0]);
        assert_eq!(result, (msg1.len() + msg2.len()) as i64);

        // Verify both chunks were written to the backend
        let stdout_fid = lx.fid_for_fd(1).unwrap();
        let stdout_writes: Vec<_> = lx
            .backend()
            .writes
            .iter()
            .filter(|(fid, _)| *fid == stdout_fid)
            .collect();
        assert_eq!(stdout_writes.len(), 2);
        assert_eq!(stdout_writes[0].1, b"Hello");
        assert_eq!(stdout_writes[1].1, b" world\n");
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_writev_bad_fd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let msg = b"test";
        let mut iov = [0u8; 16];
        iov[0..8].copy_from_slice(&(msg.as_ptr() as u64).to_le_bytes());
        iov[8..16].copy_from_slice(&(msg.len() as u64).to_le_bytes());

        let result = lx.handle_syscall(20, [99, iov.as_ptr() as u64, 1, 0, 0, 0]);
        assert_eq!(result, EBADF);
    }

    // ── sys_lseek tests ────────────────────────────────────────────

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_lseek_set() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        // Open a file via openat to get fd 3
        let path = b"/dev/serial/log\0";
        let at_fdcwd = (-100i32) as u64;
        let fd = lx.handle_syscall(257, [at_fdcwd, path.as_ptr() as u64, 0, 0, 0, 0]);
        assert!(fd >= 0);

        // lseek(fd, 42, SEEK_SET=0)  — x86_64 nr=8
        let result = lx.handle_syscall(8, [fd as u64, 42, 0, 0, 0, 0]);
        assert_eq!(result, 42);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_lseek_cur() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        let path = b"/dev/serial/log\0";
        let at_fdcwd = (-100i32) as u64;
        let fd = lx.handle_syscall(257, [at_fdcwd, path.as_ptr() as u64, 0, 0, 0, 0]);
        assert!(fd >= 0);

        // First seek to position 10
        lx.handle_syscall(8, [fd as u64, 10, 0, 0, 0, 0]);
        // Then seek +5 from current (SEEK_CUR=1)
        let result = lx.handle_syscall(8, [fd as u64, 5, 1, 0, 0, 0]);
        assert_eq!(result, 15);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_lseek_bad_fd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let result = lx.handle_syscall(8, [99, 0, 0, 0, 0, 0]);
        assert_eq!(result, EBADF);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_lseek_bad_whence() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        // Open a file to get a seekable fd
        let path = b"/dev/serial/log\0";
        let at_fdcwd = (-100i32) as u64;
        let fd = lx.handle_syscall(257, [at_fdcwd, path.as_ptr() as u64, 0, 0, 0, 0]);
        assert!(fd >= 0);

        // whence=99 is invalid
        let result = lx.handle_syscall(8, [fd as u64, 0, 99, 0, 0, 0]);
        assert_eq!(result, EINVAL);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_lseek_stdio_returns_espipe() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        // stdin (0), stdout (1), stderr (2) are character devices — not seekable.
        for fd in 0..=2u64 {
            let result = lx.handle_syscall(8, [fd, 0, 0, 0, 0, 0]);
            assert_eq!(
                result, ESPIPE,
                "lseek on stdio fd {} should return ESPIPE",
                fd
            );
        }
    }

    // ── sys_getrandom tests ────────────────────────────────────────

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_getrandom_fills_buffer() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let mut buf = [0u8; 32];
        // getrandom(buf, 32, 0)  — x86_64 nr=318
        let result = lx.handle_syscall(318, [buf.as_mut_ptr() as u64, 32, 0, 0, 0, 0]);
        assert_eq!(result, 32);
        // At least some bytes should be non-zero (deterministic LCG output)
        assert!(
            buf.iter().any(|&b| b != 0),
            "getrandom should produce non-zero bytes"
        );
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_getrandom_zero_len() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let result = lx.handle_syscall(318, [0, 0, 0, 0, 0, 0]);
        assert_eq!(result, 0);
    }

    // ── sys_getcwd tests ───────────────────────────────────────────

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_getcwd_returns_root() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let mut buf = [0xFFu8; 64];
        // getcwd(buf, 64)  — x86_64 nr=79
        let result = lx.handle_syscall(79, [buf.as_mut_ptr() as u64, 64, 0, 0, 0, 0]);
        assert_eq!(result, 2); // raw syscall returns byte count, not pointer
        assert_eq!(buf[0], b'/');
        assert_eq!(buf[1], 0); // null terminator
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_getcwd_too_small() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let mut buf = [0u8; 1];
        let result = lx.handle_syscall(79, [buf.as_mut_ptr() as u64, 1, 0, 0, 0, 0]);
        assert_eq!(result, ERANGE);
    }

    // ── resolve_path tests ──────────────────────────────────────────

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
    fn resolve_path_normalises_dotdot() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.cwd = alloc::string::String::from("/nix/store");
        assert_eq!(lx.resolve_path(".."), "/nix");
    }

    #[test]
    fn resolve_path_normalises_dot() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.cwd = alloc::string::String::from("/nix/store");
        assert_eq!(lx.resolve_path("./pkg"), "/nix/store/pkg");
    }

    #[test]
    fn resolve_path_dotdot_at_root() {
        let mock = MockBackend::new();
        let lx = Linuxulator::new(mock);
        assert_eq!(lx.resolve_path("/.."), "/");
    }

    #[test]
    fn resolve_path_complex_dotdot() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.cwd = alloc::string::String::from("/a/b/c");
        assert_eq!(lx.resolve_path("../../d"), "/a/d");
    }

    // ── sys_getcwd upgraded tests ─────────────────────────────────────

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

    // ── sys_readlink tests ─────────────────────────────────────────

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_readlink_returns_enosys() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let path = b"/proc/self/exe\0";
        let mut buf = [0u8; 128];
        // readlink(path, buf, 128)  — x86_64 nr=89
        let result = lx.handle_syscall(
            89,
            [path.as_ptr() as u64, buf.as_mut_ptr() as u64, 128, 0, 0, 0],
        );
        assert_eq!(result, ENOSYS);
    }

    // ── sys_newfstatat tests ─────────────────────────────────────────

    #[test]
    fn sys_newfstatat_absolute_path() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        #[cfg(target_arch = "x86_64")]
        let mut statbuf = [0u8; 144];
        #[cfg(not(target_arch = "x86_64"))]
        let mut statbuf = [0u8; 128];
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
        #[cfg(target_arch = "x86_64")]
        let mut statbuf = [0u8; 144];
        #[cfg(not(target_arch = "x86_64"))]
        let mut statbuf = [0u8; 128];
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
    fn sys_newfstatat_at_empty_path_with_nonempty_pathname_resolves_path() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        #[cfg(target_arch = "x86_64")]
        let mut statbuf = [0u8; 144];
        #[cfg(not(target_arch = "x86_64"))]
        let mut statbuf = [0u8; 128];
        let path = b"/dev/serial/log\0";
        let at_empty_path: i32 = 0x1000;
        // AT_EMPTY_PATH with a non-empty path should resolve the path normally
        let ret = lx.dispatch_syscall(LinuxSyscall::Newfstatat {
            dirfd: -100,
            pathname: path.as_ptr() as u64,
            statbuf: statbuf.as_mut_ptr() as u64,
            flags: at_empty_path,
        });
        assert_eq!(ret, 0);
        // Verify the walk was called with the path (not an fstat on dirfd)
        assert_eq!(lx.backend().walks[0].0, "/dev/serial/log");
    }

    #[test]
    fn sys_newfstatat_null_pathname_without_at_empty_path() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        #[cfg(target_arch = "x86_64")]
        let mut statbuf = [0u8; 144];
        #[cfg(not(target_arch = "x86_64"))]
        let mut statbuf = [0u8; 128];
        let ret = lx.dispatch_syscall(LinuxSyscall::Newfstatat {
            dirfd: -100,
            pathname: 0, // NULL
            statbuf: statbuf.as_mut_ptr() as u64,
            flags: 0, // no AT_EMPTY_PATH
        });
        assert_eq!(ret, EFAULT);
    }

    // ── sys_faccessat tests ────────────────────────────────────────────

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
    fn sys_faccessat_null_pathname() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let ret = lx.dispatch_syscall(LinuxSyscall::Faccessat {
            dirfd: -100,
            pathname: 0,
            mode: 0,
        });
        assert_eq!(ret, EFAULT);
    }

    #[test]
    fn sys_faccessat_empty_pathname() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let empty = b"\0";
        let ret = lx.dispatch_syscall(LinuxSyscall::Faccessat {
            dirfd: -100,
            pathname: empty.as_ptr() as u64,
            mode: 0,
        });
        assert_eq!(ret, ENOENT);
    }

    // ── from_x86_64 mapping tests for new syscalls ─────────────────

    #[test]
    fn from_x86_64_writev() {
        let syscall = LinuxSyscall::from_x86_64(20, [1, 0x2000, 3, 0, 0, 0]);
        match syscall {
            LinuxSyscall::Writev { fd, iov, iovcnt } => {
                assert_eq!(fd, 1);
                assert_eq!(iov, 0x2000);
                assert_eq!(iovcnt, 3);
            }
            other => panic!("expected Writev, got {:?}", other),
        }
    }

    #[test]
    fn from_x86_64_lseek() {
        let syscall = LinuxSyscall::from_x86_64(8, [3, 100, 0, 0, 0, 0]);
        match syscall {
            LinuxSyscall::Lseek { fd, offset, whence } => {
                assert_eq!(fd, 3);
                assert_eq!(offset, 100);
                assert_eq!(whence, 0);
            }
            other => panic!("expected Lseek, got {:?}", other),
        }
    }

    #[test]
    fn from_x86_64_getcwd() {
        let syscall = LinuxSyscall::from_x86_64(79, [0x3000, 256, 0, 0, 0, 0]);
        match syscall {
            LinuxSyscall::Getcwd { buf, size } => {
                assert_eq!(buf, 0x3000);
                assert_eq!(size, 256);
            }
            other => panic!("expected Getcwd, got {:?}", other),
        }
    }

    #[test]
    fn from_x86_64_readlink() {
        let syscall = LinuxSyscall::from_x86_64(89, [0x1000, 0x2000, 128, 0, 0, 0]);
        match syscall {
            LinuxSyscall::Readlink {
                pathname,
                buf,
                bufsiz,
            } => {
                assert_eq!(pathname, 0x1000);
                assert_eq!(buf, 0x2000);
                assert_eq!(bufsiz, 128);
            }
            other => panic!("expected Readlink, got {:?}", other),
        }
    }

    #[test]
    fn from_x86_64_readlinkat_at_fdcwd() {
        let at_fdcwd = (-100i64) as u64;
        let syscall = LinuxSyscall::from_x86_64(267, [at_fdcwd, 0x1000, 0x2000, 128, 0, 0]);
        match syscall {
            LinuxSyscall::Readlink {
                pathname,
                buf,
                bufsiz,
            } => {
                assert_eq!(pathname, 0x1000);
                assert_eq!(buf, 0x2000);
                assert_eq!(bufsiz, 128);
            }
            other => panic!("expected Readlink, got {:?}", other),
        }
    }

    #[test]
    fn from_x86_64_readlinkat_at_fdcwd_zero_extended() {
        // Simulate 32-bit AT_FDCWD (-100 = 0xFFFFFF9C) zero-extended to 64 bits
        let at_fdcwd_zext: u64 = 0x00000000FFFFFF9C;
        let syscall = LinuxSyscall::from_x86_64(267, [at_fdcwd_zext, 0x1000, 0x2000, 128, 0, 0]);
        match syscall {
            LinuxSyscall::Readlink { .. } => {} // should match via i32 truncation
            other => panic!("expected Readlink for zero-extended AT_FDCWD, got {:?}", other),
        }
    }

    #[test]
    fn from_x86_64_readlinkat_explicit_dirfd() {
        let syscall = LinuxSyscall::from_x86_64(267, [5, 0x1000, 0x2000, 128, 0, 0]);
        match syscall {
            LinuxSyscall::Unknown { nr } => assert_eq!(nr, 267),
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn from_x86_64_getrandom() {
        let syscall = LinuxSyscall::from_x86_64(318, [0x4000, 32, 0, 0, 0, 0]);
        match syscall {
            LinuxSyscall::Getrandom { buf, buflen, flags } => {
                assert_eq!(buf, 0x4000);
                assert_eq!(buflen, 32);
                assert_eq!(flags, 0);
            }
            other => panic!("expected Getrandom, got {:?}", other),
        }
    }

    // ── from_aarch64 mapping tests for new syscalls ─────────────────

    #[test]
    fn from_aarch64_writev() {
        let syscall = LinuxSyscall::from_aarch64(66, [1, 0x2000, 3, 0, 0, 0]);
        match syscall {
            LinuxSyscall::Writev { fd, iov, iovcnt } => {
                assert_eq!(fd, 1);
                assert_eq!(iov, 0x2000);
                assert_eq!(iovcnt, 3);
            }
            other => panic!("expected Writev, got {:?}", other),
        }
    }

    #[test]
    fn from_aarch64_lseek() {
        let syscall = LinuxSyscall::from_aarch64(62, [3, 100, 0, 0, 0, 0]);
        match syscall {
            LinuxSyscall::Lseek { fd, offset, whence } => {
                assert_eq!(fd, 3);
                assert_eq!(offset, 100);
                assert_eq!(whence, 0);
            }
            other => panic!("expected Lseek, got {:?}", other),
        }
    }

    #[test]
    fn from_aarch64_getcwd() {
        let syscall = LinuxSyscall::from_aarch64(17, [0x3000, 256, 0, 0, 0, 0]);
        match syscall {
            LinuxSyscall::Getcwd { buf, size } => {
                assert_eq!(buf, 0x3000);
                assert_eq!(size, 256);
            }
            other => panic!("expected Getcwd, got {:?}", other),
        }
    }

    #[test]
    fn from_aarch64_readlink() {
        // aarch64 nr 78 = readlinkat(dirfd, pathname, buf, bufsiz).
        // Only AT_FDCWD (-100) is supported; other dirfds map to Unknown.
        let at_fdcwd = (-100i64) as u64;
        let syscall = LinuxSyscall::from_aarch64(78, [at_fdcwd, 0x1000, 0x2000, 128, 0, 0]);
        match syscall {
            LinuxSyscall::Readlink {
                pathname,
                buf,
                bufsiz,
            } => {
                assert_eq!(pathname, 0x1000);
                assert_eq!(buf, 0x2000);
                assert_eq!(bufsiz, 128);
            }
            other => panic!("expected Readlink, got {:?}", other),
        }
    }

    #[test]
    fn from_aarch64_getrandom() {
        let syscall = LinuxSyscall::from_aarch64(278, [0x4000, 32, 0, 0, 0, 0]);
        match syscall {
            LinuxSyscall::Getrandom { buf, buflen, flags } => {
                assert_eq!(buf, 0x4000);
                assert_eq!(buflen, 32);
                assert_eq!(flags, 0);
            }
            other => panic!("expected Getrandom, got {:?}", other),
        }
    }

    // ── File-backed mmap tests (arena path) ──────────────────────────

    #[test]
    fn file_backed_mmap_reads_content() {
        let mut mock = MockBackend::new();
        // Pre-register content for fid 100 (the first fid alloc_fid will return).
        let file_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        mock.set_file_content(100, file_data.clone());
        let mut lx = Linuxulator::with_arena(mock, 64 * 1024);

        // Open a file via openat to get an fd. This will use fid 100.
        let path = b"/lib/test.so\0";
        let at_fdcwd = (-100i32) as u64;
        let fd = lx.handle_syscall(257, [at_fdcwd, path.as_ptr() as u64, 0, 0, 0, 0]);
        assert!(fd >= 0, "openat should succeed, got {}", fd);

        // mmap with that fd (NOT MAP_ANONYMOUS). flags = MAP_PRIVATE (0x02).
        // PROT_READ | PROT_WRITE = 3
        let addr = lx.handle_syscall(9, [0, 4096, 3, 0x02, fd as u64, 0]);
        assert!(
            addr > 0,
            "file-backed mmap should return valid address, got {}",
            addr
        );

        // Verify the mapped memory contains the file content.
        let mapped = unsafe { core::slice::from_raw_parts(addr as usize as *const u8, 4096) };
        assert_eq!(
            &mapped[..8],
            &file_data[..],
            "file content should be copied into mapped region"
        );
        // Rest should be zero-filled.
        assert!(
            mapped[8..].iter().all(|&b| b == 0),
            "remaining bytes should be zero"
        );
    }

    #[test]
    fn file_backed_mmap_with_offset() {
        let mut mock = MockBackend::new();
        // File content: 16 bytes total.
        let file_data: Vec<u8> = (0..16).collect();
        mock.set_file_content(100, file_data);
        let mut lx = Linuxulator::with_arena(mock, 64 * 1024);

        let path = b"/lib/test.so\0";
        let at_fdcwd = (-100i32) as u64;
        let fd = lx.handle_syscall(257, [at_fdcwd, path.as_ptr() as u64, 0, 0, 0, 0]);
        assert!(fd >= 0);

        // mmap at file offset 8.
        let addr = lx.handle_syscall(9, [0, 4096, 3, 0x02, fd as u64, 8]);
        assert!(
            addr > 0,
            "file-backed mmap with offset should succeed, got {}",
            addr
        );

        // Should contain bytes 8..16 from the file (8 bytes), then zeros.
        let mapped = unsafe { core::slice::from_raw_parts(addr as usize as *const u8, 4096) };
        assert_eq!(
            &mapped[..8],
            &[8, 9, 10, 11, 12, 13, 14, 15],
            "should read from offset 8"
        );
        assert!(
            mapped[8..].iter().all(|&b| b == 0),
            "remaining bytes should be zero"
        );
    }

    #[test]
    fn file_backed_mmap_bad_fd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::with_arena(mock, 64 * 1024);

        // mmap with invalid fd (not MAP_ANONYMOUS). flags = MAP_PRIVATE (0x02).
        let result = lx.handle_syscall(9, [0, 4096, 3, 0x02, 99, 0]);
        assert_eq!(
            result, EBADF,
            "file-backed mmap with bad fd should return EBADF"
        );
    }

    // ── File-backed mmap tests (VM path) ─────────────────────────────

    #[test]
    fn vm_file_backed_mmap_reads_content() {
        let mut mock = VmMockBackend::new(16);
        let file_data = vec![0x7F, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00];
        mock.set_file_content(100, file_data.clone());
        let mut lx = Linuxulator::new(mock);

        // Open a file.
        let path = b"/lib/libc.so\0";
        let at_fdcwd = (-100i32) as u64;
        let fd = lx.handle_syscall(257, [at_fdcwd, path.as_ptr() as u64, 0, 0, 0, 0]);
        assert!(fd >= 0);

        // File-backed mmap via VM path.
        let addr = lx.handle_syscall(9, [0, 4096, 3, 0x02, fd as u64, 0]);
        assert!(
            addr > 0,
            "VM file-backed mmap should return valid address, got {}",
            addr
        );

        // VM path should have recorded a vm_mmap call.
        assert_eq!(lx.backend().vm_mmaps.len(), 1);

        // Backend read should have been called for the file content.
        let file_fid = lx.fid_for_fd(fd as i32).unwrap();
        let mmap_reads: Vec<_> = lx
            .backend()
            .reads
            .iter()
            .filter(|(fid, _, _)| *fid == file_fid)
            .collect();
        assert!(
            !mmap_reads.is_empty(),
            "mmap should read file content via backend"
        );

        // File data should have been written to the mapped address via vm_write_bytes.
        // Expect 2 writes: file content + zero-fill for the remainder of the page.
        assert_eq!(lx.backend().vm_writes.len(), 2);
        let (write_addr, write_data) = &lx.backend().vm_writes[0];
        assert_eq!(*write_addr, addr as u64);
        assert_eq!(write_data, &file_data);
        // Second write zeroes the tail (4096 - 8 = 4088 bytes).
        let (zero_addr, zero_data) = &lx.backend().vm_writes[1];
        assert_eq!(*zero_addr, addr as u64 + file_data.len() as u64);
        assert!(zero_data.iter().all(|&b| b == 0), "tail must be zeroed");
    }

    #[test]
    fn vm_file_backed_mmap_bad_fd() {
        let mock = VmMockBackend::new(16);
        let mut lx = Linuxulator::new(mock);

        // mmap with invalid fd (not MAP_ANONYMOUS).
        let result = lx.handle_syscall(9, [0, 4096, 3, 0x02, 99, 0]);
        assert_eq!(
            result, EBADF,
            "VM file-backed mmap with bad fd should return EBADF"
        );
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use harmony_identity::PrivateIdentity;
    use harmony_microkernel::echo::EchoServer;
    use harmony_microkernel::kernel::Kernel;
    use harmony_microkernel::serial_server::SerialServer;
    use harmony_microkernel::vm::buddy::BuddyAllocator;
    use harmony_microkernel::vm::cap_tracker::MemoryBudget;
    use harmony_microkernel::vm::manager::AddressSpaceManager;
    use harmony_microkernel::vm::mock::MockPageTable;
    use harmony_microkernel::vm::{PhysAddr, PAGE_SIZE as VM_PAGE_SIZE};
    use harmony_unikernel::KernelEntropy;

    /// Create a test VM manager with 64 frames.
    fn make_test_vm() -> AddressSpaceManager<MockPageTable> {
        let buddy = BuddyAllocator::new(PhysAddr(0x10_0000), 64).unwrap();
        AddressSpaceManager::new(buddy)
    }

    /// SyscallBackend backed by a real Ring 2 Kernel.
    struct KernelBackend<'a, P: harmony_microkernel::vm::page_table::PageTable> {
        kernel: &'a mut Kernel<P>,
        pid: u32,
    }

    impl<'a, P: harmony_microkernel::vm::page_table::PageTable> KernelBackend<'a, P> {
        fn new(kernel: &'a mut Kernel<P>, pid: u32) -> Self {
            Self { kernel, pid }
        }
    }

    impl<P: harmony_microkernel::vm::page_table::PageTable> SyscallBackend for KernelBackend<'_, P> {
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

        fn has_vm_support(&self) -> bool {
            self.kernel.has_vm_space(self.pid)
        }

        fn vm_mmap(
            &mut self,
            vaddr: u64,
            len: usize,
            flags: PageFlags,
            classification: FrameClassification,
        ) -> Result<u64, VmError> {
            use harmony_microkernel::vm::VirtAddr;
            self.kernel
                .vm_map_region(self.pid, VirtAddr(vaddr), len, flags, classification)?;
            Ok(vaddr)
        }

        fn vm_munmap(&mut self, vaddr: u64, len: usize) -> Result<(), VmError> {
            use harmony_microkernel::vm::VirtAddr;
            // TODO(harmony-qv2): partial unmap support. Currently unmaps the
            // entire region regardless of `len`. Real Linux allows unmapping
            // sub-ranges, splitting regions. Needed for ELF loaders.
            let _ = len;
            self.kernel.vm_unmap_region(self.pid, VirtAddr(vaddr))
        }

        fn vm_mprotect(
            &mut self,
            vaddr: u64,
            _len: usize,
            flags: PageFlags,
        ) -> Result<(), VmError> {
            use harmony_microkernel::vm::VirtAddr;
            // TODO(harmony-qv2): partial mprotect support. Currently changes
            // flags for the entire region regardless of `_len`.
            self.kernel
                .vm_protect_region(self.pid, VirtAddr(vaddr), flags)
        }

        fn vm_find_free_region(&self, len: usize) -> Result<u64, VmError> {
            self.kernel
                .vm_find_free_region(self.pid, len)
                .map(|va| va.as_u64())
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
        let mut kernel = Kernel::new(kernel_id, make_test_vm());

        // Spawn SerialServer
        let serial_pid = kernel
            .spawn_process("serial", Box::new(SerialServer::new()), &[], None)
            .unwrap();

        // Spawn a "linux process" with SerialServer mounted at /dev/serial
        let linux_pid = kernel
            .spawn_process(
                "hello-linux",
                Box::new(EchoServer::new()), // placeholder server
                &[("/dev/serial", serial_pid, 0)],
                None,
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
        let mut kernel = Kernel::new(kernel_id, make_test_vm());

        let serial_pid = kernel
            .spawn_process("serial", Box::new(SerialServer::new()), &[], None)
            .unwrap();

        let linux_pid = kernel
            .spawn_process(
                "hello-linux",
                Box::new(EchoServer::new()),
                &[("/dev/serial", serial_pid, 0)],
                None,
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

    // ── VM-backed syscall integration tests ──────────────────────────

    /// Create a kernel with a large frame pool and a VM-enabled process.
    #[allow(clippy::type_complexity)]
    fn setup_vm_kernel() -> (
        Kernel<MockPageTable>,
        u32, // serial_pid
        u32, // linux_pid (VM-enabled)
        KernelEntropy<impl FnMut(&mut [u8])>,
    ) {
        let mut entropy = test_entropy();
        let kernel_id = PrivateIdentity::generate(&mut entropy);
        // 256 frames = 1 MiB physical
        let buddy = BuddyAllocator::new(PhysAddr(0x10_0000), 256).unwrap();
        let vm = AddressSpaceManager::new(buddy);
        let mut kernel = Kernel::new(kernel_id, vm);

        let serial_pid = kernel
            .spawn_process("serial", Box::new(SerialServer::new()), &[], None)
            .unwrap();

        // Create a VM-enabled linux process.
        let budget = MemoryBudget::new(
            VM_PAGE_SIZE as usize * 64, // 64 pages budget
            FrameClassification::all(),
        );
        let page_table = MockPageTable::new(PhysAddr(0x20_0000));

        let linux_pid = kernel
            .spawn_process(
                "vm-linux",
                Box::new(EchoServer::new()),
                &[("/dev/serial", serial_pid, 0)],
                Some((budget, page_table)),
            )
            .unwrap();

        kernel
            .grant_endpoint_cap(&mut entropy, linux_pid, serial_pid, 0)
            .unwrap();

        (kernel, serial_pid, linux_pid, entropy)
    }

    #[test]
    fn vm_mmap_allocates_region() {
        let (mut kernel, _serial_pid, linux_pid, _entropy) = setup_vm_kernel();
        let backend = KernelBackend::new(&mut kernel, linux_pid);
        let mut lx = Linuxulator::new(backend);

        // mmap 1 page: PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE
        let addr = lx.handle_syscall(9, [0, 4096, 3, 0x22, u64::MAX, 0]);
        assert!(addr > 0, "mmap should return a valid address, got {}", addr);
        assert_eq!(addr as u64 % 4096, 0, "mmap address must be page-aligned");
    }

    #[test]
    fn vm_munmap_frees_region() {
        let (mut kernel, _serial_pid, linux_pid, _entropy) = setup_vm_kernel();
        let backend = KernelBackend::new(&mut kernel, linux_pid);
        let mut lx = Linuxulator::new(backend);

        // mmap then munmap
        let addr = lx.handle_syscall(9, [0, 4096, 3, 0x22, u64::MAX, 0]);
        assert!(addr > 0);
        let result = lx.handle_syscall(11, [addr as u64, 4096, 0, 0, 0, 0]);
        assert_eq!(result, 0, "munmap should succeed");
    }

    #[test]
    fn vm_mprotect_changes_flags() {
        let (mut kernel, _serial_pid, linux_pid, _entropy) = setup_vm_kernel();
        let backend = KernelBackend::new(&mut kernel, linux_pid);
        let mut lx = Linuxulator::new(backend);

        // mmap as read-only
        let addr = lx.handle_syscall(9, [0, 4096, 1, 0x22, u64::MAX, 0]); // PROT_READ
        assert!(addr > 0);

        // mprotect to read-write
        let result = lx.handle_syscall(10, [addr as u64, 4096, 3, 0, 0, 0]); // PROT_READ|PROT_WRITE
        assert_eq!(result, 0, "mprotect should succeed");
    }

    #[test]
    fn vm_mmap_budget_exhaustion() {
        let mut entropy = test_entropy();
        let kernel_id = PrivateIdentity::generate(&mut entropy);
        // 256 frames total
        let buddy = BuddyAllocator::new(PhysAddr(0x10_0000), 256).unwrap();
        let vm = AddressSpaceManager::new(buddy);
        let mut kernel = Kernel::new(kernel_id, vm);

        let serial_pid = kernel
            .spawn_process("serial", Box::new(SerialServer::new()), &[], None)
            .unwrap();

        // Tiny budget: only 2 pages
        let budget = MemoryBudget::new(VM_PAGE_SIZE as usize * 2, FrameClassification::all());
        let page_table = MockPageTable::new(PhysAddr(0x20_0000));

        let linux_pid = kernel
            .spawn_process(
                "budget-limited",
                Box::new(EchoServer::new()),
                &[("/dev/serial", serial_pid, 0)],
                Some((budget, page_table)),
            )
            .unwrap();

        kernel
            .grant_endpoint_cap(&mut entropy, linux_pid, serial_pid, 0)
            .unwrap();

        let backend = KernelBackend::new(&mut kernel, linux_pid);
        let mut lx = Linuxulator::new(backend);

        // Request 16 pages — exceeds the 2-page budget
        let result = lx.handle_syscall(9, [0, 4096 * 16, 3, 0x22, u64::MAX, 0]);
        assert_eq!(result, ENOMEM, "should return ENOMEM when budget exceeded");
    }

    #[test]
    fn vm_brk_expands_heap() {
        let (mut kernel, _serial_pid, linux_pid, _entropy) = setup_vm_kernel();
        let backend = KernelBackend::new(&mut kernel, linux_pid);
        let mut lx = Linuxulator::new(backend);

        // Probe initial brk (addr = 0).
        let base = lx.handle_syscall(12, [0, 0, 0, 0, 0, 0]);
        assert!(base > 0, "brk(0) should return a valid base address");

        // Expand by 8192 bytes.
        let new_brk = lx.handle_syscall(12, [base as u64 + 8192, 0, 0, 0, 0, 0]);
        assert_eq!(
            new_brk as u64,
            base as u64 + 8192,
            "brk should expand to requested address"
        );

        // Probe again — should still show the expanded brk.
        let probed = lx.handle_syscall(12, [0, 0, 0, 0, 0, 0]);
        assert_eq!(probed, new_brk);
    }

    #[test]
    fn test_elf_loading_with_real_vm() {
        use crate::elf::{parse_elf, SegmentFlags};
        use harmony_microkernel::vm::{FrameClassification, VirtAddr};

        let mut entropy = test_entropy();
        let kernel_id = PrivateIdentity::generate(&mut entropy);
        // Large frame pool for ELF loading.
        let buddy = BuddyAllocator::new(PhysAddr(0x10_0000), 256).unwrap();
        let vm = AddressSpaceManager::new(buddy);
        let mut kernel = Kernel::new(kernel_id, vm);

        // Build a minimal ELF with two PT_LOAD segments:
        // - .text at 0x401000 (R-X): 16 bytes of code
        // - .data at 0x402000 (RW-): 8 bytes of data + 24 bytes BSS (memsz > filesz)
        let code = [
            0x48, 0x31, 0xC0, 0xB0, 0x3C, 0x0F, 0x05,
            0xCC, // xor rax,rax; mov al,60; syscall; int3
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ]; // nop sled
        let data_bytes = [0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0x0A, 0x00]; // "Hello!\n\0"

        // Construct a 2-segment ELF: header (64) + 2 phdrs (112) + code (16) + data (8)
        let phdr_count = 2;
        let phdr_start: usize = 64;
        let code_offset = phdr_start + phdr_count * 56;
        let data_offset = code_offset + code.len();
        let total_size = data_offset + data_bytes.len();

        let mut elf = alloc::vec![0u8; total_size];

        // ELF header
        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());

        // e_machine — native machine type
        #[cfg(target_arch = "x86_64")]
        elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
        #[cfg(target_arch = "aarch64")]
        elf[18..20].copy_from_slice(&0xB7u16.to_le_bytes());
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        elf[24..32].copy_from_slice(&0x401000u64.to_le_bytes()); // e_entry
        elf[32..40].copy_from_slice(&(phdr_start as u64).to_le_bytes()); // e_phoff
        elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        elf[56..58].copy_from_slice(&(phdr_count as u16).to_le_bytes()); // e_phnum

        // Program header 1: .text (R-X)
        let ph1 = &mut elf[phdr_start..phdr_start + 56];
        ph1[0..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        ph1[4..8].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
        ph1[8..16].copy_from_slice(&(code_offset as u64).to_le_bytes()); // p_offset
        ph1[16..24].copy_from_slice(&0x401000u64.to_le_bytes()); // p_vaddr
        ph1[24..32].copy_from_slice(&0x401000u64.to_le_bytes()); // p_paddr
        ph1[32..40].copy_from_slice(&(code.len() as u64).to_le_bytes()); // p_filesz
        ph1[40..48].copy_from_slice(&(code.len() as u64).to_le_bytes()); // p_memsz
        ph1[48..56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align

        // Program header 2: .data (RW-) with BSS extension
        let ph2_start = phdr_start + 56;
        let ph2 = &mut elf[ph2_start..ph2_start + 56];
        ph2[0..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        ph2[4..8].copy_from_slice(&6u32.to_le_bytes()); // PF_R | PF_W
        ph2[8..16].copy_from_slice(&(data_offset as u64).to_le_bytes()); // p_offset
        ph2[16..24].copy_from_slice(&0x402000u64.to_le_bytes()); // p_vaddr
        ph2[24..32].copy_from_slice(&0x402000u64.to_le_bytes()); // p_paddr
        ph2[32..40].copy_from_slice(&(data_bytes.len() as u64).to_le_bytes()); // p_filesz
        ph2[40..48].copy_from_slice(&32u64.to_le_bytes()); // p_memsz (8 file + 24 BSS)
        ph2[48..56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align

        // Copy segment data.
        elf[code_offset..code_offset + code.len()].copy_from_slice(&code);
        elf[data_offset..data_offset + data_bytes.len()].copy_from_slice(&data_bytes);

        // Parse the ELF.
        let parsed = parse_elf(&elf).expect("ELF parsing should succeed");
        assert_eq!(parsed.entry_point, 0x401000);
        assert_eq!(parsed.segments.len(), 2);

        // Spawn a VM-enabled process.
        let budget = MemoryBudget::new(VM_PAGE_SIZE as usize * 32, FrameClassification::all());
        let page_table = MockPageTable::new(PhysAddr(0x20_0000));
        let pid = kernel
            .spawn_process(
                "elf-process",
                Box::new(EchoServer::new()),
                &[],
                Some((budget, page_table)),
            )
            .unwrap();

        // Convert ELF segment flags to PageFlags.
        fn seg_flags_to_page_flags(sf: &SegmentFlags) -> PageFlags {
            let mut pf = PageFlags::USER;
            if sf.read {
                pf |= PageFlags::READABLE;
            }
            if sf.write {
                pf |= PageFlags::WRITABLE;
            }
            if sf.execute {
                pf |= PageFlags::EXECUTABLE;
            }
            pf
        }

        // Map each PT_LOAD segment into the process address space.
        for seg in &parsed.segments {
            let page_aligned_vaddr = seg.vaddr & !(VM_PAGE_SIZE - 1);
            let page_aligned_memsz = ((seg.memsz + (seg.vaddr - page_aligned_vaddr) + VM_PAGE_SIZE
                - 1)
                & !(VM_PAGE_SIZE - 1)) as usize;
            let flags = seg_flags_to_page_flags(&seg.flags);

            kernel
                .vm_map_region(
                    pid,
                    VirtAddr(page_aligned_vaddr),
                    page_aligned_memsz,
                    flags,
                    FrameClassification::empty(),
                )
                .expect("mapping ELF segment should succeed");
        }

        // Verify the mappings exist with correct permissions via public API.

        // .text segment at 0x401000: should be R-X (USER | READABLE | EXECUTABLE)
        let (_, text_flags) = kernel
            .vm_translate(pid, VirtAddr(0x401000))
            .expect(".text page should be mapped");
        assert!(
            text_flags.contains(PageFlags::READABLE),
            ".text must be readable"
        );
        assert!(
            text_flags.contains(PageFlags::EXECUTABLE),
            ".text must be executable"
        );
        assert!(
            !text_flags.contains(PageFlags::WRITABLE),
            ".text must NOT be writable"
        );

        // .data segment at 0x402000: should be RW- (USER | READABLE | WRITABLE)
        let (_, data_flags) = kernel
            .vm_translate(pid, VirtAddr(0x402000))
            .expect(".data page should be mapped");
        assert!(
            data_flags.contains(PageFlags::READABLE),
            ".data must be readable"
        );
        assert!(
            data_flags.contains(PageFlags::WRITABLE),
            ".data must be writable"
        );
        assert!(
            !data_flags.contains(PageFlags::EXECUTABLE),
            ".data must NOT be executable"
        );

        // Verify .text and .data map to different physical frames.
        let (text_phys, _) = kernel.vm_translate(pid, VirtAddr(0x401000)).unwrap();
        let (data_phys, _) = kernel.vm_translate(pid, VirtAddr(0x402000)).unwrap();
        assert_ne!(
            text_phys, data_phys,
            ".text and .data must map to different physical frames"
        );

        // Verify unmapped regions between/around segments return None.
        assert!(
            kernel.vm_translate(pid, VirtAddr(0x400000)).is_none(),
            "Address before .text should not be mapped"
        );
        assert!(
            kernel.vm_translate(pid, VirtAddr(0x403000)).is_none(),
            "Address after .data should not be mapped"
        );

        // Verify the process's region count via the VM manager.
        let space = kernel.vm_manager().space(pid).unwrap();
        assert_eq!(
            space.regions.len(),
            2,
            "Process should have exactly 2 regions (text + data)"
        );
    }

    #[test]
    fn sys_getdents64_packs_entries() {
        let mut mock = MockBackend::new();
        let dir_fid: Fid = 200;
        mock.readdir_entries.insert(
            dir_fid,
            vec![
                DirEntry {
                    name: alloc::string::String::from("hello.txt"),
                    file_type: FileType::Regular,
                },
                DirEntry {
                    name: alloc::string::String::from("subdir"),
                    file_type: FileType::Directory,
                },
            ],
        );
        let mut lx = Linuxulator::new(mock);
        // Manually insert a directory fd.
        lx.fd_table_mut().insert(
            3,
            FdEntry {
                fid: dir_fid,
                offset: 0,
                path: Some(alloc::string::String::from("/test")),
            },
        );

        let mut buf = [0u8; 512];
        let ret = lx.dispatch_syscall(LinuxSyscall::Getdents64 {
            fd: 3,
            dirp: buf.as_mut_ptr() as u64,
            count: 512,
        });
        assert!(ret > 0, "should have written some bytes, got {ret}");

        // Verify first entry header: d_reclen at offset 16..18
        let reclen1 = u16::from_le_bytes([buf[16], buf[17]]) as usize;
        // d_type at offset 18
        assert_eq!(buf[18], 8, "first entry should be DT_REG");
        // d_name starts at offset 19
        assert_eq!(&buf[19..28], b"hello.txt");

        // Verify second entry starts at reclen1
        assert_eq!(buf[reclen1 + 18], 4, "second entry should be DT_DIR");
        assert_eq!(&buf[reclen1 + 19..reclen1 + 25], b"subdir");

        // Calling again should return 0 (end of directory).
        let ret2 = lx.dispatch_syscall(LinuxSyscall::Getdents64 {
            fd: 3,
            dirp: buf.as_mut_ptr() as u64,
            count: 512,
        });
        assert_eq!(ret2, 0, "second call should return 0 (end of dir)");
    }

    #[test]
    fn sys_getdents64_empty_dir() {
        let mut mock = MockBackend::new();
        let dir_fid: Fid = 200;
        mock.readdir_entries.insert(dir_fid, vec![]);
        let mut lx = Linuxulator::new(mock);
        lx.fd_table_mut().insert(
            3,
            FdEntry {
                fid: dir_fid,
                offset: 0,
                path: Some(alloc::string::String::from("/empty")),
            },
        );

        let mut buf = [0u8; 512];
        let ret = lx.dispatch_syscall(LinuxSyscall::Getdents64 {
            fd: 3,
            dirp: buf.as_mut_ptr() as u64,
            count: 512,
        });
        assert_eq!(ret, 0, "empty directory should return 0");
    }

    #[test]
    fn sys_getdents64_non_directory_returns_enotdir() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();
        // getdents64 on stdout (fd 1) — a regular file, not a directory
        let mut buf = [0u8; 256];
        let ret = lx.dispatch_syscall(LinuxSyscall::Getdents64 {
            fd: 1,
            dirp: buf.as_mut_ptr() as u64,
            count: 256,
        });
        assert_eq!(ret, ENOTDIR);
    }

    // ── sys_chdir tests ───────────────────────────────────────────

    #[test]
    fn sys_chdir_updates_cwd() {
        let mut mock = MockBackend::new();
        mock.directory_paths
            .insert(alloc::string::String::from("/nix/store"));
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
    fn sys_chdir_empty_path_returns_enoent() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let empty = b"\0";
        let ret = lx.dispatch_syscall(LinuxSyscall::Chdir {
            pathname: empty.as_ptr() as u64,
        });
        assert_eq!(ret, ENOENT);
    }

    // ── sys_fchdir tests ──────────────────────────────────────────

    #[test]
    fn sys_fchdir_from_open_fd() {
        let mut mock = MockBackend::new();
        mock.directory_paths
            .insert(alloc::string::String::from("/nix/store"));
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
        let _ret = lx.dispatch_syscall(LinuxSyscall::Getcwd {
            buf: buf.as_mut_ptr() as u64,
            size: 64,
        });
        assert_eq!(&buf[..11], b"/nix/store\0");
    }

    #[test]
    fn sys_fchdir_stdio_returns_enotdir() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();
        // fchdir(1) on stdout — valid fd but not a directory
        let ret = lx.dispatch_syscall(LinuxSyscall::Fchdir { fd: 1 });
        assert_eq!(ret, ENOTDIR);
    }

    // ── sys_readlinkat tests (dispatch_syscall) ───────────────────

    #[test]
    fn sys_readlinkat_returns_enosys() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let path = b"/some/link\0";
        let mut buf = [0u8; 64];
        let ret = lx.dispatch_syscall(LinuxSyscall::Readlink {
            pathname: path.as_ptr() as u64,
            buf: buf.as_mut_ptr() as u64,
            bufsiz: 64,
        });
        assert_eq!(ret, ENOSYS);
    }

    // ── sys_mkdirat tests ─────────────────────────────────────────

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

    #[test]
    fn sys_unlinkat_returns_erofs() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let path = b"/tmp/oldfile\0";
        let ret = lx.dispatch_syscall(LinuxSyscall::Unlinkat {
            dirfd: -100,
            pathname: path.as_ptr() as u64,
            flags: 0,
        });
        assert_eq!(ret, -30); // EROFS
    }

    // ── openat resolve_path tests ────────────────────────────────

    #[test]
    fn sys_openat_relative_path_uses_cwd() {
        let mut mock = MockBackend::new();
        mock.directory_paths
            .insert(alloc::string::String::from("/nix/store"));
        let mut lx = Linuxulator::new(mock);
        // chdir to /nix/store
        let dir = b"/nix/store\0";
        lx.dispatch_syscall(LinuxSyscall::Chdir {
            pathname: dir.as_ptr() as u64,
        });
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
}
